//! Multiple DHT nodes talking to each other over the EDX `Kad` payload: each
//! runs a `DhtService`, and looks up via a `WireRpcClient` whose `KadSender`
//! routes payloads to the addressed node. Announce on one node, find it from
//! another - the whole DHT-over-payloads path, encode and decode included.
//!
//! The real link underneath (dial, Noise, `Req::Kad`) is exercised end to end
//! by `epix-runtime`'s `edx_serves_the_control_plane`; here the sender is
//! in-process so the DHT logic can be tested without a transport stack.

use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_dht::{xite_key, Contact, Node, NodeId};
use epix_dht_net::{DhtService, KadSender, WireRpcClient};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The "network": every node's service, keyed by its address. `send` hands the
/// payload to the addressed service, tagging the caller's address the way an
/// accept loop would (so the source-IP rewrite is exercised).
#[derive(Default)]
struct Net {
    services: Mutex<HashMap<String, Arc<DhtService>>>,
}

impl Net {
    fn register(&self, addr: &PeerAddr, service: Arc<DhtService>) {
        self.services.lock().unwrap().insert(addr.to_string(), service);
    }
}

/// One node's view of the net: payloads it sends arrive tagged with its own
/// address, which is what a served connection sees.
struct NetSender {
    net: Arc<Net>,
    from: PeerAddr,
}

#[async_trait]
impl KadSender for NetSender {
    async fn send(&self, to: &PeerAddr, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        let svc = self
            .net
            .services
            .lock()
            .unwrap()
            .get(&to.to_string())
            .cloned()
            .ok_or_else(|| format!("no node at {to}"))?;
        svc.handle_edx(&self.from, &payload)
    }
}

struct TestNode {
    contact: Contact,
    node: Arc<Node>,
    client: WireRpcClient,
}

fn spawn_node(i: usize, net: &Arc<Net>) -> TestNode {
    let addr = PeerAddr::parse(&format!("127.0.0.1:{}", 30000 + i)).unwrap();
    let id = NodeId::hash(format!("node-{i}").as_bytes());
    let contact = Contact::new(id, addr.clone());
    let node = Arc::new(Node::new(id));
    net.register(&addr, Arc::new(DhtService::new(node.clone())));
    let sender = Arc::new(NetSender { net: net.clone(), from: addr });
    let client = WireRpcClient::new(contact.clone(), sender);
    TestNode { contact, node, client }
}

#[tokio::test]
async fn dht_announce_and_lookup_over_the_kad_payload() {
    let net = Arc::new(Net::default());
    let nodes: Vec<TestNode> = (0..6).map(|i| spawn_node(i, &net)).collect();

    // Seed routing tables with each other's listen contacts (established net).
    let contacts: Vec<Contact> = nodes.iter().map(|n| n.contact.clone()).collect();
    for n in &nodes {
        for c in &contacts {
            n.node.add_contact(c.clone());
        }
    }

    // Node 4 announces that a host serves a rare xite.
    let key = xite_key("epix1rarexite000000000000000000000000000");
    let host = PeerAddr::parse("203.0.113.9:26552").unwrap();
    nodes[4].node.announce(key, host.clone(), &nodes[4].client).await;

    // Node 0 looks it up and finds the host.
    let found = nodes[0].node.get_peers(key, &nodes[0].client).await;
    assert!(found.contains(&host), "lookup returned {found:?}");
}

/// Phase 4: overlay self-addresses (onion/i2p/rns) announced over a clearnet
/// link pass through the serving side's rewrite untouched and come back from a
/// lookup - the path that makes a Tor-only or I2P-only publisher discoverable
/// by everyone else. A clearnet `0.0.0.0` claim on the same announce is
/// rewritten to the connection's source IP, keeping the claimed port.
#[tokio::test]
async fn overlay_self_addresses_round_trip_over_the_wire() {
    let net = Arc::new(Net::default());
    let nodes: Vec<TestNode> = (200..206).map(|i| spawn_node(i, &net)).collect();
    let contacts: Vec<Contact> = nodes.iter().map(|n| n.contact.clone()).collect();
    for n in &nodes {
        for c in &contacts {
            n.node.add_contact(c.clone());
        }
    }

    let key = xite_key("epix1onionpublisher77777777777777777777");
    let claims = vec![
        PeerAddr::parse("0.0.0.0:48333").unwrap(),
        PeerAddr::parse("expyuzz4wqqyqhjn.onion:48333").unwrap(),
        PeerAddr::parse("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:48333").unwrap(),
        PeerAddr::parse("rns:00112233445566778899aabbccddeeff").unwrap(),
    ];
    nodes[4].node.announce_all(key, &claims, &nodes[4].client).await;

    let found = nodes[0].node.get_peers(key, &nodes[0].client).await;
    // Overlay claims arrive verbatim.
    for claim in &claims[1..] {
        assert!(found.contains(claim), "missing {claim} in {found:?}");
    }
    // The clearnet 0.0.0.0 claim was rewritten to the announcer's source IP
    // (loopback here) with the claimed listening port kept, when it reaches a
    // remote node's store via Announce.
    assert!(
        found.contains(&PeerAddr::parse("127.0.0.1:48333").unwrap()),
        "rewritten clearnet claim missing in {found:?}"
    );
    // Wire contract: the announcer ALSO stores its own raw 0.0.0.0 claim
    // locally (GetPeers returns store contents verbatim, only Announce claims
    // get the source-IP rewrite), and the lookup queries the announcer too, so
    // the raw claim leaks back. The runtime drops it via `dialable_dht_peer`
    // before dialing; this asserts the leak is real so that filter stays.
    assert!(
        found.contains(&PeerAddr::parse("0.0.0.0:48333").unwrap()),
        "raw 0.0.0.0 claim expected in lookup (downstream must filter it): {found:?}"
    );
}

#[tokio::test]
async fn cold_start_probe_bootstraps_and_finds_a_xite_with_no_tracker() {
    // The rare-xite scenario: A serves a xite, B knows A only by ADDRESS
    // (e.g. learned from another xite's swarm) - no node id, no tracker,
    // empty routing tables on both sides.
    let net = Arc::new(Net::default());
    let a = spawn_node(100, &net);
    let b = spawn_node(101, &net);

    // A announces the xite into its own store (its dht_loop does this).
    let key = xite_key("epix1rarexite000000000000000000000000000");
    let host = PeerAddr::parse("203.0.113.9:26552").unwrap();
    a.node.announce(key, host.clone(), &a.client).await;

    // B probes A's bare address: the reply is stamped with A's node id, so B
    // learns A's authentic contact without knowing it beforehand.
    let (a_contact, shared) = b.client.probe(&a.contact.addr, b.node.id).await.unwrap();
    assert_eq!(a_contact.id, a.contact.id);
    assert_eq!(a_contact.addr, a.contact.addr);
    for c in shared {
        b.node.add_contact(c);
    }
    b.node.add_contact(a_contact);

    // B's lookup now reaches A and finds the announced host - trackerless
    // discovery from a cold start.
    let found = b.node.get_peers(key, &b.client).await;
    assert!(found.contains(&host), "cold-start lookup returned {found:?}");
}
