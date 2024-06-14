use crate::shared::Command;
use crate::utils::AsyncJoinOnDrop;
use futures::channel::{mpsc, oneshot};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{InboundRequestId, ResponseChannel};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::dummy::Behaviour;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm};
use std::collections::HashMap;
use std::future::{pending, Future};
use std::pin::Pin;
use tokio::task::yield_now;
use tracing::{error, trace};

pub type InboundRequestsHandler<Requests, Responses> =
    Box<dyn Fn(Requests) -> Pin<Box<dyn Future<Output = Responses> + Send>> + Send>;

#[derive(Debug)]
struct BootstrapNode {
    addresses: Vec<Multiaddr>,
}

impl Default for BootstrapNode {
    fn default() -> Self {
        BootstrapNode { addresses: vec![] }
    }
}

pub struct NetworkWorker {
    bootstrap_nodes: HashMap<PeerId, BootstrapNode>,
    command_receiver: mpsc::Receiver<Command>,
    swarm: Swarm<Behaviour>,
    redials: FuturesUnordered<AsyncJoinOnDrop<()>>,
    #[allow(clippy::type_complexity)]
    inbound_requests: FuturesUnordered<
        AsyncJoinOnDrop<(InboundRequestId, PeerId, ResponseChannel<Vec<u8>>, Vec<u8>)>,
    >,
    #[allow(clippy::type_complexity)]
    pending_outbound_requests: Option<oneshot::Sender<()>>,
}

impl NetworkWorker {
    pub(crate) fn new(
        command_receiver: mpsc::Receiver<Command>,
        swarm: Swarm<Behaviour>,
        bootstrap_nodes: Vec<Multiaddr>,
    ) -> Self {
        let mut grouped_bootstrap_nodes = HashMap::<PeerId, BootstrapNode>::new();
        for mut address in bootstrap_nodes {
            if let Some(Protocol::P2p(peer_id)) = address.pop() {
                grouped_bootstrap_nodes
                    .entry(peer_id)
                    .or_default()
                    .addresses
                    .push(address);
            }
        }

        Self {
            bootstrap_nodes: grouped_bootstrap_nodes,
            command_receiver,
            swarm,
            redials: FuturesUnordered::default(),
            inbound_requests: FuturesUnordered::default(),
            pending_outbound_requests: None,
        }
    }

    /// Drives the network worker
    pub async fn run(&mut self) {
        for (peer_id, bootstrap_node) in self.bootstrap_nodes.iter() {
            if let Err(error) = self.swarm.dial(
                DialOpts::peer_id(*peer_id)
                    .addresses(bootstrap_node.addresses.clone())
                    .build(),
            ) {
                error!(%error, %peer_id, "Failed to dial bootstrap node");
            }
        }

        loop {
            futures::select! {
                swarm_event = self.swarm.next() => {
                    if let Some(swarm_event) = swarm_event {
                        self.handle_swarm_event(swarm_event).await;
                    } else {
                        break;
                    }
                },
                _redial_result = self.redials.select_next_some() => {
                },
                _inbound_request_result = self.inbound_requests.select_next_some() => {
                },
                command = self.command_receiver.next() => {
                    if let Some(command) = command {
                        self.handle_command(command);
                    } else {
                        break;
                    }
                },
            }

            // Allow to exit from busy loop during graceful shutdown
            yield_now().await;
        }
    }

    async fn handle_swarm_event(&mut self, swarm_event: SwarmEvent<void::Void>) {
        match swarm_event {
            SwarmEvent::OutgoingConnectionError { .. } => {
                self.redials.push(AsyncJoinOnDrop::new(
                    tokio::spawn(async move {
                        pending::<()>().await;
                    }),
                    true,
                ));

                self.pending_outbound_requests.take();
            }
            other => {
                trace!("Other swarm event: {:?}", other);
            }
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Request { result_sender } => {
                self.pending_outbound_requests.replace(result_sender);
            }
        }
    }
}
