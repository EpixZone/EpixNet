//! Inbound seeding: a client peer pulls a file from our node's file server over
//! real TCP, exercising the whole getFile serving path end to end.

use std::sync::Arc;

use epix_core::PeerAddr;
use epix_protocol::{Connection, PeerServer};
use epix_transport::TcpTransport;
use epix_ui::fileserve::FileService;
use epix_ui::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn peer_pulls_a_file_from_our_file_server() {
    // Server node with one xite and a file on disk.
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"served from the seed node").unwrap();
    storage.write("data/big.bin", &vec![7u8; 300_000]).unwrap();
    let state = AppState::new("seed");
    state
        .add_xite("1Seed", XiteEntry { storage, content: Some(json!({ "address": "1Seed" })) })
        .await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(FileService::new(state));
    tokio::spawn(PeerServer::new(handler).serve(listener));

    // Client peer connects and pulls both files.
    let mut conn = Connection::connect(&TcpTransport, &PeerAddr::Ip(addr)).await.unwrap();
    conn.handshake().await.unwrap();

    let small = conn.get_file("1Seed", "index.html").await.unwrap();
    assert_eq!(small, b"served from the seed node");

    // A file bigger than one FILE_BUFF chunk still comes back whole (multi-chunk).
    let big = conn.get_file("1Seed", "data/big.bin").await.unwrap();
    assert_eq!(big.len(), 300_000);
    assert!(big.iter().all(|&b| b == 7));

    // A ranged pull returns exactly the requested window.
    let range = conn.get_file_range("1Seed", "data/big.bin", 100, 50).await.unwrap();
    assert_eq!(range, vec![7u8; 50]);
}
