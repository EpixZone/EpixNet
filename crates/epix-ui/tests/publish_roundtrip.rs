//! The publish round-trip over a real TCP socket: node A signs a new
//! content.json version and publishes it; node B's inbound file server
//! verifies the pushed update and applies it. This is the receive half of the
//! Phase 3 publish checkpoint (two Rust nodes propagating an update by push,
//! no polling).

use epix_core::PeerAddr;
use epix_transport::Transport;
use epix_ui::fileserve::FileService;
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use std::sync::Arc;

fn signed_content(address: &str, privkey: &str, modified: i64) -> (serde_json::Value, Vec<u8>) {
    let mut content = json!({ "address": address, "modified": modified, "files": {} });
    epix_content::sign(&mut content, privkey).unwrap();
    let bytes = serde_json::to_vec(&content).unwrap();
    (content, bytes)
}

#[tokio::test]
async fn publish_pushes_an_update_a_second_node_accepts() {
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let (v1, v1_bytes) = signed_content(&address, &privkey, 1000);

    // Node B: serves v1, listens for inbound peer requests.
    let dir_b = tempfile::tempdir().unwrap();
    let storage_b = XiteStorage::new(dir_b.path());
    storage_b.write("content.json", &v1_bytes).unwrap();
    let state_b = AppState::new("node-b");
    state_b
        .add_xite(&address, XiteEntry { storage: storage_b, content: Some(v1.clone()) })
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = epix_protocol::PeerServer::new(Arc::new(FileService::new(state_b.clone())));
    tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    // Node A: has signed v2 on disk and knows B as a peer.
    let dir_a = tempfile::tempdir().unwrap();
    let storage_a = XiteStorage::new(dir_a.path());
    let (v2, v2_bytes) = signed_content(&address, &privkey, 2000);
    storage_a.write("content.json", &v2_bytes).unwrap();
    let state_a = AppState::new("node-a");
    state_a
        .add_xite(&address, XiteEntry { storage: storage_a, content: Some(v2) })
        .await;
    let transport: Arc<dyn Transport> = Arc::new(epix_transport::TcpTransport);
    state_a.set_transport(transport).await;
    state_a
        .add_peers(&address, [PeerAddr::parse(&format!("127.0.0.1:{port}")).unwrap()])
        .await;

    // A pushes; B verifies and applies without ever polling.
    let published = state_a.publish(&address, "content.json").await.unwrap();
    assert_eq!(published, 1);
    let applied = state_b.content(&address).await.unwrap();
    assert_eq!(applied.get("modified").and_then(|m| m.as_i64()), Some(2000));

    // B's copy on disk is the signed v2 bytes' content (re-read and verify).
    let republished = state_b.read_file(&address, "content.json").await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&republished).unwrap();
    assert!(epix_content::verify_signer(&parsed, &address));
}
