//! Store-and-forward over the real wire protocol: a propagation node holds an
//! update published while a peer was offline, and the peer pulls it on connect.
//! Runs over TCP here; because it rides `PeerServer`/`Connection`, the same
//! service works unchanged over the Reticulum mesh.

use std::collections::HashMap;
use std::sync::Arc;

use epix_core::PeerAddr;
use epix_propagation::{
    announce_update, fetch_updates, needs_sync, PropagationClient, PropagationService,
    PropagationStore,
};
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

    // Publisher B announces an update - peer C is not connected at this point.
    let mut b = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    b.handshake().await.unwrap();
    let seq = announce_update(&mut b, "1abc.epix", 1000).await.unwrap();
    assert_eq!(seq, 1);

    // C connects later and pulls from the start - it receives B's stored update.
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

/// The client-side flow a node runtime will drive: a cursor-tracking pull, then
/// deciding which locally-hosted xites are stale and need a verified resync.
#[tokio::test]
async fn client_polls_and_decides_what_to_sync() {
    let store = Arc::new(Mutex::new(PropagationStore::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(PeerServer::new(Arc::new(PropagationService::new(store.clone()))).serve(listener));

    // A publisher announces newer versions of two xites.
    let mut pubconn = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    pubconn.handshake().await.unwrap();
    announce_update(&mut pubconn, "hosted.epix", 200).await.unwrap();
    announce_update(&mut pubconn, "elsewhere.epix", 999).await.unwrap();

    // A node that hosts `hosted.epix` at an older version (and doesn't host the
    // other) polls, then decides what to resync.
    let mut node = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    node.handshake().await.unwrap();
    let mut client = PropagationClient::new();
    let updates = client.poll(&mut node).await.unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(client.cursor(), 2, "cursor advanced to head");

    let local = HashMap::from([("hosted.epix".to_string(), 100)]);
    let to_sync = needs_sync(&updates, &local);
    assert_eq!(to_sync.len(), 1, "only the hosted, newer xite");
    assert_eq!(to_sync[0].xite, "hosted.epix");
    assert_eq!(to_sync[0].modified, 200);

    // Polling again from the advanced cursor yields nothing new.
    let again = client.poll(&mut node).await.unwrap();
    assert!(again.is_empty());
    assert_eq!(client.cursor(), 2);
}
