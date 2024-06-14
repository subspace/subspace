//! Data structures shared between node and node runner, facilitating exchange and creation of
//! queries, subscriptions, various events and shared information.

use futures::channel::{mpsc, oneshot};

#[derive(Debug)]
pub(crate) enum Command {
    Request { result_sender: oneshot::Sender<()> },
}

#[derive(Debug)]
pub(crate) struct Shared {
    /// Sender end of the channel for sending commands to the swarm.
    pub(crate) command_sender: mpsc::Sender<Command>,
}

impl Shared {
    pub(crate) fn new(command_sender: mpsc::Sender<Command>) -> Self {
        Self { command_sender }
    }
}
