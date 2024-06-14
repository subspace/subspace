use crate::network::{Network, NetworkConfig};
use futures::{select, FutureExt};
use libp2p::identity::Keypair;

#[tokio::test]
async fn basic() {
    let (_peer_1, mut peer_1_worker) = Network::new(NetworkConfig {
        bootstrap_nodes: vec![],
        keypair: Keypair::generate_ed25519(),
    })
    .unwrap();

    {
        let (peer_3, mut peer_3_worker) = Network::new(NetworkConfig {
            bootstrap_nodes: vec![
                "/ip4/127.0.0.1/tcp/0/p2p/12D3KooWDqEKc7sXcmLv9VHViKGBDx99g49ZrEcwrLMxXEi41CXf"
                    .parse()
                    .unwrap(),
            ],
            keypair: Keypair::generate_ed25519(),
        })
        .unwrap();

        select! {
            _ = peer_1_worker.run().fuse() => {},
            _ = peer_3_worker.run().fuse() => {},
            _ = peer_3.request().fuse() => {},
        }
    }
}
