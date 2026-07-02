//! Multiple DHT nodes over real TCP: each runs a PeerServer serving `kad` RPCs,
//! and looks up via a dial-on-demand WireRpcClient. Announce on one node, find
//! it from another - the whole DHT-over-connections path.

use epix_core::PeerAddr;
use epix_dht::{site_key, Contact, Node, NodeId};
use epix_dht_net::{DhtService, WireRpcClient};
use epix_protocol::PeerServer;
use epix_transport::{TcpTransport, Transport};
use std::sync::Arc;
use tokio::net::TcpListener;

struct TestNode {
    contact: Contact,
    node: Arc<Node>,
    client: WireRpcClient,
}

async fn spawn_node(i: usize, transport: Arc<dyn Transport>) -> TestNode {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let id = NodeId::hash(format!("node-{i}").as_bytes());
    let contact = Contact::new(id, PeerAddr::Ip(addr));
    let node = Arc::new(Node::new(id));

    let service = Arc::new(DhtService::new(node.clone()));
    tokio::spawn(PeerServer::new(service).serve(listener));

    let client = WireRpcClient::new(contact.clone(), transport);
    TestNode { contact, node, client }
}

#[tokio::test]
async fn dht_announce_and_lookup_over_real_tcp() {
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport);

    let mut nodes = Vec::new();
    for i in 0..6 {
        nodes.push(spawn_node(i, transport.clone()).await);
    }

    // Seed routing tables with each other's listen contacts (established net).
    let contacts: Vec<Contact> = nodes.iter().map(|n| n.contact.clone()).collect();
    for n in &nodes {
        for c in &contacts {
            n.node.add_contact(c.clone());
        }
    }

    // Node 4 announces (over the wire) that a host serves a rare xite.
    let key = site_key("epix1rarexite000000000000000000000000000");
    let host = PeerAddr::parse("203.0.113.9:26552").unwrap();
    nodes[4].node.announce(key, host.clone(), &nodes[4].client).await;

    // Node 0 looks it up over the wire and finds the host.
    let found = nodes[0].node.get_peers(key, &nodes[0].client).await;
    assert!(found.contains(&host), "lookup over TCP returned {found:?}");
}
