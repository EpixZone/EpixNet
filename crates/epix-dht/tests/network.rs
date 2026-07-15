//! An in-memory DHT network: nodes announce and look up peers through the
//! iterative Kademlia lookup, exercising id/routing/store/RPC end to end.

use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::{site_key, Contact, Node, NodeId, Request, Response, RpcClient};
use std::collections::HashMap;
use std::sync::Arc;

/// The whole simulated network: id -> node.
struct Net {
    nodes: HashMap<NodeId, Arc<Node>>,
}

/// One node's view of the network as an RpcClient (knows who "I" am, so the
/// receiver learns the caller).
struct Client {
    me: Contact,
    net: Arc<Net>,
}

#[async_trait]
impl RpcClient for Client {
    async fn send(&self, to: &Contact, req: Request) -> Result<Response, String> {
        let node = self
            .net
            .nodes
            .get(&to.id)
            .ok_or_else(|| "peer offline".to_string())?;
        Ok(node.handle(self.me.clone(), req))
    }
}

fn contact(i: usize) -> Contact {
    Contact::new(
        NodeId::hash(format!("node-{i}").as_bytes()),
        PeerAddr::parse(&format!("10.0.{}.{}:{}", i / 250, i % 250 + 1, 20000 + i)).unwrap(),
    )
}

#[tokio::test]
async fn announce_then_lookup_finds_the_host() {
    const N: usize = 30;
    let contacts: Vec<Contact> = (0..N).map(contact).collect();
    let mut nodes = HashMap::new();
    for c in &contacts {
        nodes.insert(c.id, Arc::new(Node::new(c.id)));
    }
    let net = Arc::new(Net { nodes });
    let client = |c: &Contact| Client { me: c.clone(), net: net.clone() };

    // Seed each node with the others (an established, connected network).
    for c in &contacts {
        let node = net.nodes.get(&c.id).unwrap();
        for other in &contacts {
            node.add_contact(other.clone());
        }
    }

    // Node 5 announces that a host serves a (rare) site.
    let key = site_key("epix1somerareblog777777777777777777777777");
    let host = PeerAddr::parse("203.0.113.9:26552").unwrap();
    net.nodes
        .get(&contacts[5].id)
        .unwrap()
        .announce(key, host.clone(), &client(&contacts[5]))
        .await;

    // A different node looks it up via the iterative lookup and finds the host.
    let found = net
        .nodes
        .get(&contacts[20].id)
        .unwrap()
        .get_peers(key, &client(&contacts[20]))
        .await;
    assert!(found.contains(&host), "lookup returned {found:?}");
}

/// Phase 4: a node with clearnet + onion + i2p + rns self-addresses announces
/// them all with one call; a different node's lookup returns every variant,
/// so an overlay-only publisher is discoverable through the DHT.
#[tokio::test]
async fn announce_all_makes_every_self_address_discoverable() {
    const N: usize = 30;
    let contacts: Vec<Contact> = (0..N).map(contact).collect();
    let mut nodes = HashMap::new();
    for c in &contacts {
        nodes.insert(c.id, Arc::new(Node::new(c.id)));
    }
    let net = Arc::new(Net { nodes });
    let client = |c: &Contact| Client { me: c.clone(), net: net.clone() };
    for c in &contacts {
        let node = net.nodes.get(&c.id).unwrap();
        for other in &contacts {
            node.add_contact(other.clone());
        }
    }

    let key = site_key("epix1toronlypublisher7777777777777777777");
    let claims = vec![
        PeerAddr::parse("203.0.113.9:48333").unwrap(),
        PeerAddr::parse("expyuzz4wqqyqhjn.onion:48333").unwrap(),
        PeerAddr::parse("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:48333").unwrap(),
        PeerAddr::parse("rns:00112233445566778899aabbccddeeff").unwrap(),
    ];
    net.nodes
        .get(&contacts[5].id)
        .unwrap()
        .announce_all(key, &claims, &client(&contacts[5]))
        .await;

    let found = net
        .nodes
        .get(&contacts[20].id)
        .unwrap()
        .get_peers(key, &client(&contacts[20]))
        .await;
    for claim in &claims {
        assert!(found.contains(claim), "missing {claim} in {found:?}");
    }
}

#[tokio::test]
async fn lookup_of_unknown_site_returns_nothing() {
    let a = Node::new(NodeId::hash(b"solo"));
    struct Empty;
    #[async_trait]
    impl RpcClient for Empty {
        async fn send(&self, _to: &Contact, _req: Request) -> Result<Response, String> {
            Err("no peers".into())
        }
    }
    let peers = a.get_peers(site_key("epix1nobody"), &Empty).await;
    assert!(peers.is_empty());
}
