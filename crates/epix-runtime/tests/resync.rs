//! The node runtime picks up a published update: a peer serves a newer
//! content.json + file, and the re-sync loop verifies and downloads it.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_protocol::{vget, vmap, PeerServer, RequestHandler};
use epix_runtime::{NodeRuntime, RuntimeConfig};
use epix_transport::TcpTransport;
use epix_ui::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use rmpv::Value as Rmp;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};

/// A peer that serves `getFile` from a storage.
struct FileServe {
    storage: XiteStorage,
}

#[async_trait]
impl RequestHandler for FileServe {
    async fn handle(&self, _peer: &PeerAddr, cmd: &str, params: &Rmp) -> Rmp {
        if cmd != "getFile" {
            return vmap(vec![("error", Rmp::from("unknown command"))]);
        }
        let inner = vget(params, "inner_path").and_then(|v| v.as_str()).unwrap_or("");
        let location = vget(params, "location").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let read = vget(params, "read_bytes").and_then(|v| v.as_u64()).unwrap_or(512 * 1024) as usize;
        let bytes = self.storage.read(inner).unwrap_or_default();
        let start = location.min(bytes.len());
        let end = (start + read).min(bytes.len());
        vmap(vec![
            ("body", Rmp::Binary(bytes[start..end].to_vec())),
            ("size", Rmp::from(bytes.len() as i64)),
            ("location", Rmp::from(end as i64)),
        ])
    }
}

/// A signed content.json for `address` at `modified`, listing `files`.
fn signed_content(priv_hex: &str, address: &str, modified: f64, files: Value) -> Vec<u8> {
    let mut content = json!({ "address": address, "modified": modified, "files": files });
    epix_content::sign(&mut content, priv_hex).unwrap();
    serde_json::to_vec(&content).unwrap()
}

#[tokio::test]
async fn runtime_resyncs_a_published_update() {
    let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
    let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

    // --- Source peer: newer content.json (modified 200) + a new file.
    let post = b"a freshly published post";
    let src_dir = tempfile::tempdir().unwrap();
    let src = XiteStorage::new(src_dir.path());
    src.write("post.txt", post).unwrap();
    let new_content = signed_content(
        priv_hex,
        &address,
        200.0,
        json!({ "post.txt": { "size": post.len(), "sha512": XiteStorage::hash_bytes(post) } }),
    );
    src.write("content.json", &new_content).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    tokio::spawn(PeerServer::new(Arc::new(FileServe { storage: src.clone() })).serve(listener));

    // --- Client: older content.json (modified 100), file not present.
    let cli_dir = tempfile::tempdir().unwrap();
    let old: Value = serde_json::from_slice(&signed_content(priv_hex, &address, 100.0, json!({}))).unwrap();
    let state = AppState::new("test");
    state
        .add_xite(&address, XiteEntry { storage: XiteStorage::new(cli_dir.path()), content: Some(old) })
        .await;
    state.set_transport(Arc::new(TcpTransport)).await;
    state.add_peers(&address, [PeerAddr::Ip(peer_addr)]).await;

    // Runtime with a fast re-sync tick, no trackers.
    let mut runtime = NodeRuntime::with_config(
        state.clone(),
        vec![],
        RuntimeConfig {
            announce_interval: Duration::from_secs(3600),
            resync_interval: Duration::from_millis(100),
            chart_interval: Duration::from_secs(3600),
            connection_interval: Duration::from_secs(3600),
        },
    );
    runtime.start();

    // The loop should fetch the newer content.json, verify it, and download the
    // file. Wait for both the applied content and the downloaded file (the file
    // lands a moment after content.json is applied).
    let post_path = cli_dir.path().join("post.txt");
    timeout(Duration::from_secs(10), async {
        loop {
            let applied = state.site_info(&address).await["content_updated"].as_f64() == Some(200.0);
            if applied && std::fs::read(&post_path).ok().as_deref() == Some(post.as_slice()) {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("runtime applied the update + downloaded the file in time");

    // The published file was downloaded + verified.
    assert_eq!(std::fs::read(&post_path).unwrap(), post);

    runtime.shutdown().await;
}
