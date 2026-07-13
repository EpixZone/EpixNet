//! The Phase 5 checkpoint: two nodes with no peer-to-peer IP connectivity
//! sync a xite over a Reticulum link. Node A serves the xite over the mesh
//! only (its wire protocol mounted on a `ReticulumServer`); node B joins the
//! mesh, dials A's destination hash, clones + verifies content.json over the
//! link, and downloads the data files with the regular worker. The TCP
//! interface here is Reticulum's own link layer (the stand-in for a LoRa or
//! BLE radio), not a peer TCP connection - the wire protocol never touches a
//! direct socket between the two nodes.

use std::sync::Arc;
use std::time::Duration;

use epix_core::{Address, PeerAddr};
use epix_protocol::Connection;
use epix_reticulum::{MeshConfig, MeshNode};
use epix_transport::Transport;
use epix_ui::fileserve::FileService;
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::{Xite, XiteStorage};
use serde_json::json;
use tokio::time::timeout;

#[tokio::test]
async fn xite_syncs_over_a_mesh_link() {
    timeout(Duration::from_secs(60), run()).await.expect("mesh xite sync timed out");
}

async fn run() {
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let index = b"<html>over the mesh</html>";

    // Node A: the xite on disk (content.json + index.html), serving over the
    // mesh only.
    let dir_a = tempfile::tempdir().unwrap();
    let storage_a = XiteStorage::new(dir_a.path());
    storage_a.write("index.html", index).unwrap();
    let mut content = json!({
        "address": address, "modified": 1000,
        "files": { "index.html": {
            "size": index.len(),
            "sha512": XiteStorage::hash_bytes(index),
        } },
    });
    epix_content::sign(&mut content, &privkey).unwrap();
    let content_bytes = serde_json::to_vec(&content).unwrap();
    storage_a.write("content.json", &content_bytes).unwrap();

    let state_a = AppState::new("node-a");
    state_a
        .add_xite(&address, XiteEntry { storage: storage_a, content: Some(content) })
        .await;

    let mesh_a = MeshNode::spawn(MeshConfig {
        identity_path: None,
        tcp_peers: Vec::new(),
        tcp_listen: Some("127.0.0.1:48731".into()),
    })
    .await
    .unwrap();
    let a_addr = mesh_a.addr();
    let _announce = mesh_a.spawn_announce(Duration::from_millis(300));
    tokio::spawn(async move {
        mesh_a.serve(Arc::new(FileService::new(state_a))).await;
    });

    // Node B: joins the mesh through A's interface, knows only A's dest hash.
    let mesh_b = MeshNode::spawn(MeshConfig {
        identity_path: None,
        tcp_peers: vec!["127.0.0.1:48731".into()],
        tcp_listen: None,
    })
    .await
    .unwrap();
    let transport_b: Arc<dyn Transport> = Arc::new(mesh_b.transport());

    // Clone: fetch + verify content.json over the link (the dial itself waits
    // for A's announce to arrive).
    let mut conn = Connection::connect(transport_b.as_ref(), &a_addr).await.unwrap();
    conn.handshake().await.unwrap();
    let fetched = conn.get_file(&address, "content.json").await.unwrap();
    assert_eq!(fetched, content_bytes, "content.json fetched over mesh");

    let dir_b = tempfile::tempdir().unwrap();
    let mut xite_b =
        Xite::new(Address::parse(address.clone()).unwrap(), XiteStorage::new(dir_b.path()));
    xite_b.set_content(&fetched).expect("verifies");

    // Download the declared files with the regular worker, peers = the mesh
    // destination only.
    let report =
        epix_worker::sync_files(&xite_b, &[a_addr], transport_b, 2, None).await.expect("sync");
    assert!(report.failed.is_empty(), "failed: {:?}", report.failed);
    assert_eq!(xite_b.storage().read("index.html").unwrap(), index);
    assert!(xite_b.files_needed().is_empty(), "everything verified on disk");

    // The mesh peer is a real PeerAddr both sides can gossip.
    assert_eq!(PeerAddr::parse(&mesh_b.addr().to_string()).unwrap(), mesh_b.addr());
}
