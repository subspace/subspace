use crate::network_worker::NetworkWorker;
use crate::shared::{Command, Shared};
use futures::channel::{mpsc, oneshot};
use futures::SinkExt;
use libp2p::identity::Keypair;
use libp2p::noise::Config as NoiseConfig;
use libp2p::yamux::Config as YamuxConfig;
use libp2p::{Multiaddr, SwarmBuilder};
use std::error::Error;
use std::sync::Arc;

/// Network configuration
pub struct NetworkConfig {
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<Multiaddr>,
    /// Keypair to use
    pub keypair: Keypair,
}

/// Implementation of a network
#[derive(Debug)]
#[must_use = "Network doesn't do anything if dropped"]
pub struct Network {
    shared: Arc<Shared>,
}

impl Clone for Network {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Network {
    pub fn new(config: NetworkConfig) -> Result<(Self, NetworkWorker), Box<dyn Error>> {
        let swarm = SwarmBuilder::with_existing_identity(config.keypair)
            .with_tokio()
            .with_tcp(Default::default(), NoiseConfig::new, YamuxConfig::default)?
            .with_dns()?
            .with_behaviour(move |_keypair| Ok(libp2p::swarm::dummy::Behaviour))
            .expect("Not fallible; qed")
            .build();

        let (command_sender, command_receiver) = mpsc::channel(1);
        let shared = Arc::new(Shared::new(command_sender));

        let network = Self { shared };
        let network_worker = NetworkWorker::new(command_receiver, swarm, config.bootstrap_nodes);

        Ok((network, network_worker))
    }

    /// Sends the generic request to the peer at specified address and awaits the result
    pub async fn request(&self) -> Result<(), ()> {
        let (result_sender, result_receiver) = oneshot::channel();
        let command = Command::Request { result_sender };

        self.shared
            .command_sender
            .clone()
            .send(command)
            .await
            .unwrap();

        result_receiver.await.map_err(|_| ())
    }
}
