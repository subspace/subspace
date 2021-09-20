// Pull imports from the parent module
use super::client::ClientConfig;
use super::*;

#[derive(NetworkBehaviour)]
#[behaviour(event_process = false, out_event = "ComposedEvent")]
pub struct ComposedBehaviour {
    kademlia: Kademlia<MemoryStore>,
}

pub enum ComposedEvent {
    Kademlia(KademliaEvent),
}

impl From<KademliaEvent> for ComposedEvent {
    fn from(event: KademliaEvent) -> Self {
        ComposedEvent::Kademlia(event)
    }
}

pub async fn create_bootstrap(config: ClientConfig) -> Swarm<ComposedBehaviour> {
    // TODO: Don't do this, here. Move this to a seperate method. That can be called by
    // dht::client::dht_listener.
    //
    // Read a RSA private key from disk, to create a bootstrap node's PeerID.
    // let key = identity::Keypair::rsa_from_pkcs8().unwrap();
    todo!()
}

pub async fn create_node(config: ClientConfig) -> Swarm<ComposedBehaviour> {
    // Generate IDs.
    let key = identity::Keypair::generate_ed25519();
    let peerid = PeerId::from_public_key(key.public());

    // Generate NOISE authentication keys.
    let auth_keys = Keypair::<X25519Spec>::new().into_authentic(&key).unwrap();

    // Create secure-TCP transport that uses tokio under the hood.
    let transport = TokioTcpConfig::new()
        .upgrade(upgrade::Version::V1)
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let behaviour = ComposedBehaviour {
        kademlia: Kademlia::new(peerid.clone(), MemoryStore::new(peerid.clone())),
    };

    let mut swarm = SwarmBuilder::new(transport, behaviour, peerid.clone())
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    dial_bootstrap(&mut swarm, config.bootstrap_nodes);

    swarm
}

fn dial_bootstrap(_swarm: &mut Swarm<ComposedBehaviour>, nodes: Vec<String>) {
    todo!()
}
