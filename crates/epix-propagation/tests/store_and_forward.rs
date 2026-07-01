//! Store-and-forward over the real wire protocol: a propagation node holds an
//! update published while a peer was offline, and the peer pulls it on connect.
//! Runs over TCP here; because it rides `PeerServer`/`Connection`, the same
//! service works unchanged over the Reticulum mesh.

use std::sync::Arc;

use epix_core::PeerAddr;
use epix_propagation::{announce_update, fetch_updates, PropagationService, PropagationStore};
use epix_protocol::{Connection, PeerServer};
use epix_transport::TcpTransport;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[tokio::test]
async fn offline_peer_receives_stored_update() {
    // Propagation node A.
    let store = Arc::new(Mutex::new(PropagationStore::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(PeerServer::new(Arc::new(PropagationService::new(store.clone()))).serve(listener));

    // Publisher B announces an update — peer C is not connected at this point.
    let mut b = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    b.handshake().await.unwrap();
    let seq = announce_update(&mut b, "1abc.epix", 1000).await.unwrap();
    assert_eq!(seq, 1);

    // C connects later and pulls from the start — it receives B's stored update.
    let mut c = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    c.handshake().await.unwrap();
    let (updates, head) = fetch_updates(&mut c, 0).await.unwrap();
    assert_eq!(updates.len(), 1, "offline-published update was delivered on reconnect");
    assert_eq!(updates[0].xite, "1abc.epix");
    assert_eq!(updates[0].modified, 1000);
    assert_eq!(head, 1);

    // C is caught up: pulling from head yields nothing.
    let (updates, head2) = fetch_updates(&mut c, head).await.unwrap();
    assert!(updates.is_empty());
    assert_eq!(head2, 1);

    // A duplicate re-announce is idempotent; a new version is a new notification.
    announce_update(&mut b, "1abc.epix", 1000).await.unwrap();
    let seq2 = announce_update(&mut b, "1abc.epix", 2000).await.unwrap();
    assert_eq!(seq2, 2);

    let (updates, head3) = fetch_updates(&mut c, head).await.unwrap();
    assert_eq!(updates.len(), 1, "only the new version, not the duplicate");
    assert_eq!(updates[0].modified, 2000);
    assert_eq!(head3, 2);
}
