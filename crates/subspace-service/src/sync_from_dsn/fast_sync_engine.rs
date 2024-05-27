#![allow(dead_code)]
// TODO: remove after adding the usage

// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! `SyncingEngine` is the actor responsible for syncing Substrate chain
//! to tip and keep the blockchain up to date with network updates.

use futures::channel::oneshot;
use futures::{FutureExt, StreamExt};
use prost::Message;
use sc_client_api::ProofProvider;
use sc_consensus::IncomingBlock;
use sc_network::request_responses::IfDisconnected;
use sc_network::types::ProtocolName;
use sc_network::{NetworkService, PeerId};
use sc_network_sync::pending_responses::{PendingResponses, ResponseEvent};
use sc_network_sync::schema::v1::{StateRequest, StateResponse};
use sc_network_sync::service::network::NetworkServiceProvider;
use sc_network_sync::service::{self};
use sc_network_sync::state_request_handler::generate_protocol_name;
use sc_network_sync::strategy::state::{StateStrategy, StateStrategyAction};
use sc_network_sync::strategy::StrategyKey;
use sc_network_sync::types::{BadPeer, OpaqueStateRequest, OpaqueStateResponse, PeerRequest};
use sp_blockchain::{Error as ClientError, HeaderBackend};
use sp_runtime::traits::{Block as BlockT, NumberFor};
use sp_runtime::Justifications;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

pub struct FastSyncingEngine<B: BlockT> {
    /// Syncing strategy.
    strategy: StateStrategy<B>,

    /// Network service.
    network_service_handle: service::network::NetworkServiceHandle,

    /// Network service join handle.
    network_service_join_handle: JoinHandle<()>,

    /// Pending responses
    pending_responses: PendingResponses<B>,

    /// Protocol name used to send out state requests
    state_request_protocol_name: ProtocolName,
}

impl<B> Drop for FastSyncingEngine<B>
where
    B: BlockT,
{
    fn drop(&mut self) {
        self.network_service_join_handle.abort()
    }
}

impl<B> FastSyncingEngine<B>
where
    B: BlockT,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new<Client>(
        client: Arc<Client>,
        fork_id: Option<&str>,
        target_header: B::Header,
        target_body: Option<Vec<B::Extrinsic>>,
        target_justifications: Option<Justifications>,
        skip_proof: bool,
        current_sync_peer: (PeerId, NumberFor<B>),
        network_service: Arc<NetworkService<B, <B as BlockT>::Hash>>,
    ) -> Result<Self, ClientError>
    where
        Client: HeaderBackend<B> + ProofProvider<B> + Send + Sync + 'static,
    {
        let (network_service_worker, network_service_handle) = NetworkServiceProvider::new();
        let networking_fut = network_service_worker.run(network_service);
        let network_service_join_handle = tokio::spawn(networking_fut);

        let state_request_protocol_name =
            generate_protocol_name(client.info().genesis_hash, fork_id).into();

        // Initialize syncing strategy.
        let strategy = StateStrategy::new(
            client.clone(),
            target_header,
            target_body,
            target_justifications,
            skip_proof,
            vec![current_sync_peer].into_iter(),
        );

        Ok(Self {
            strategy,
            network_service_handle,
            network_service_join_handle,
            pending_responses: PendingResponses::new(),
            state_request_protocol_name,
        })
    }

    // Downloads state and returns incoming block with state pre-populated and ready for importing
    pub async fn download_state(mut self) -> Result<IncomingBlock<B>, ClientError> {
        debug!("Starting state downloading");

        loop {
            // Process actions requested by a syncing strategy.
            let mut actions = self.strategy.actions().peekable();
            if actions.peek().is_none() {
                return Err(ClientError::Backend(
                    "Sync state download failed: no further actions".into(),
                ));
            }

            for action in actions {
                match action {
                    StateStrategyAction::SendStateRequest { peer_id, request } => {
                        self.send_state_request(peer_id, StrategyKey::State, request);
                    }
                    StateStrategyAction::DropPeer(BadPeer(peer_id, rep)) => {
                        self.pending_responses.remove(peer_id, StrategyKey::State);

                        trace!(%peer_id, "Peer dropped: {rep:?}");
                    }
                    StateStrategyAction::ImportBlocks { blocks, .. } => {
                        return blocks.into_iter().next().ok_or_else(|| {
                            ClientError::Application(
                                "StateStrategyAction::ImportBlocks didn't contain any blocks to import"
                                    .into(),
                            )
                        });
                    }
                    StateStrategyAction::Finished => {
                        return Err(ClientError::Backend(
                            "Sync state finished without blocks to import".into(),
                        ));
                    }
                }
            }

            let response_event = self.pending_responses.select_next_some().await;
            self.process_response_event(response_event);
        }
    }

    fn send_state_request(
        &mut self,
        peer_id: PeerId,
        key: StrategyKey,
        request: OpaqueStateRequest,
    ) {
        let (tx, rx) = oneshot::channel();

        self.pending_responses
            .insert(peer_id, key, PeerRequest::State, rx.boxed());

        match Self::encode_state_request(&request) {
            Ok(data) => {
                self.network_service_handle.start_request(
                    peer_id,
                    self.state_request_protocol_name.clone(),
                    data,
                    tx,
                    IfDisconnected::ImmediateError,
                );
            }
            Err(err) => {
                warn!("Failed to encode state request {request:?}: {err:?}",);
            }
        }
    }

    fn encode_state_request(request: &OpaqueStateRequest) -> Result<Vec<u8>, String> {
        let request: &StateRequest = request.0.downcast_ref().ok_or_else(|| {
            "Failed to downcast opaque state response during encoding, this is an implementation \
            bug"
            .to_string()
        })?;

        Ok(request.encode_to_vec())
    }

    fn decode_state_response(response: &[u8]) -> Result<OpaqueStateResponse, String> {
        let response = StateResponse::decode(response)
            .map_err(|error| format!("Failed to decode state response: {error}"))?;

        Ok(OpaqueStateResponse(Box::new(response)))
    }

    fn process_response_event(&mut self, response_event: ResponseEvent<B>) {
        let ResponseEvent {
            peer_id,
            request,
            response,
            ..
        } = response_event;

        match response {
            Ok(Ok((resp, _))) => match request {
                PeerRequest::Block(req) => {
                    error!("Unexpected PeerRequest::Block - {:?}", req);
                }
                PeerRequest::State => {
                    let response = match Self::decode_state_response(&resp[..]) {
                        Ok(proto) => proto,
                        Err(e) => {
                            debug!("Failed to decode state response from peer {peer_id:?}: {e:?}.",);
                            return;
                        }
                    };

                    self.strategy.on_state_response(peer_id, response);
                }
                PeerRequest::WarpProof => {
                    error!("Unexpected PeerRequest::WarpProof",);
                }
            },
            Ok(Err(e)) => {
                debug!("Request to peer {peer_id:?} failed: {e:?}.");
            }
            Err(oneshot::Canceled) => {
                trace!("Request to peer {peer_id:?} failed due to oneshot being canceled.",);
            }
        }
    }
}
