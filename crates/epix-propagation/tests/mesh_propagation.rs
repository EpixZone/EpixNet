//! Propagation over the **real Reticulum mesh**, end to end: a propagation node
//! serves `PropagationService` on inbound RNS links (`ReticulumServer`), and a
//! peer dials it over a real link (`ReticulumTransport`), announces an update,
//! and pulls it back with the client. This proves the whole stack works over
//! mesh, not just TCP: `ReticulumStream` -> `Connection` -> the propagation
//! service and client, all over a UDP-loopback RNS link with no shared IP
//! routing.

use std::sync::Arc;
use std::time::Duration;

use epix_core::PeerAddr;
use epix_propagation::{announce_update, PropagationClient, PropagationService, PropagationStore};
use epix_protocol::Connection;
use epix_reticulum::{ReticulumServer, ReticulumTransport};
use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport as RnsTransport, TransportConfig};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn propagation_round_trip_over_rns_link() {
    timeout(Duration::from_secs(30), run())
        .await
        .expect("mesh propagation timed out");
}

async fn run() {
    let name = DestinationName::new("epix", "mesh");

    // Propagation node: register + announce a destination, serve the
    // propagation service on inbound links.
    let store = Arc::new(Mutex::new(PropagationStore::new()));
    let node_id = PrivateIdentity::new_from_rand(OsRng);
    let mut node_tp = RnsTransport::new(TransportConfig::new("prop-node", &node_id, true));
    let node_dest = node_tp.add_destination(node_id.clone(), name).await;
    let node_tp = Arc::new(node_tp);
    node_tp.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52051", Some("127.0.0.1:52052"), false),
        UdpInterface::spawn,
    );

    let mut hash = [0u8; 16];
    hash.copy_from_slice(node_dest.lock().await.desc.address_hash.as_slice());

    {
        let node_tp = node_tp.clone();
        let node_dest = node_dest.clone();
        tokio::spawn(async move {
            loop {
                node_tp.send_announce(&node_dest, None).await;
                sleep(Duration::from_millis(400)).await;
            }
        });
    }
    tokio::spawn(ReticulumServer::new(Arc::new(PropagationService::new(store.clone()))).serve(node_tp.clone()));

    // Peer: dial the propagation node over the mesh, announce an update, then
    // pull it back through the client.
    let peer_id = PrivateIdentity::new_from_rand(OsRng);
    let peer_rns = Arc::new(RnsTransport::new(TransportConfig::new("peer", &peer_id, true)));
    peer_rns.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:52052", Some("127.0.0.1:52051"), false),
        UdpInterface::spawn,
    );
    let peer = ReticulumTransport::new(peer_rns);

    let mut conn = Connection::connect(&peer, &PeerAddr::Rns(hash))
        .await
        .expect("dial propagation node over mesh");
    conn.handshake().await.expect("handshake over mesh");

    // Announce a xite update over the mesh — the node stores it.
    let seq = announce_update(&mut conn, "mesh.epix", 4242)
        .await
        .expect("announce over mesh");
    assert_eq!(seq, 1);

    // Pull it back over the mesh via the client.
    let mut client = PropagationClient::new();
    let updates = client.poll(&mut conn).await.expect("poll over mesh");
    assert_eq!(updates.len(), 1, "update delivered back over the mesh");
    assert_eq!(updates[0].xite, "mesh.epix");
    assert_eq!(updates[0].modified, 4242);
    assert_eq!(client.cursor(), 1);

    // Caught up: nothing new.
    let again = client.poll(&mut conn).await.expect("second poll over mesh");
    assert!(again.is_empty());
}
