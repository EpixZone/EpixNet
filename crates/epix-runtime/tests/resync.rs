//! The node runtime picks up a published update over EDX: a seeder serves a
//! newer content.json (GetSigned) plus a `b3` file, and the re-sync loop
//! verifies and fetches it over the verified-streaming path.

use std::sync::Arc;
use std::time::Duration;

use epix_blob::store::Store;
use epix_blob::ObjId;
use epix_core::PeerAddr;
use epix_protocol::PeerServer;
use epix_runtime::edx::edx_hook;
use epix_runtime::{NodeRuntime, RuntimeConfig};
use epix_transport::TcpTransport;
use epix_ui::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};

/// A signed content.json for `address` at `modified`, listing `files`.
fn signed_content(priv_hex: &str, address: &str, modified: f64, files: Value) -> Vec<u8> {
    let mut content = json!({ "address": address, "modified": modified, "files": files });
    epix_content::sign(&mut content, priv_hex).unwrap();
    serde_json::to_vec(&content).unwrap()
}

/// Stand up an EDX seeder serving `content.json` (+ the files it declares) for
/// `address`, from `src` storage. Returns its listening address.
async fn spawn_edx_seeder(address: &str, src: XiteStorage) -> std::net::SocketAddr {
    let state = AppState::new("source");
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_dir.path()).unwrap());
    state.set_edx_store(store.clone()).await;
    state.add_xite(address, XiteEntry { storage: src, content: None }).await;
    assert!(state.load_content_from_disk(address).await, "load registers files into the EDX store");
    std::mem::forget(store_dir);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = PeerServer::new(edx_hook(
        state,
        store,
        epix_crypt::new_seed(),
        None,
        epix_runtime::edx::ControlHandles::detached(),
        false,
        None,
    ));
    tokio::spawn(server.serve(listener));
    addr
}

#[tokio::test]
async fn runtime_resyncs_a_published_update() {
    let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
    let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

    // --- Source: newer content.json (modified 200) + a new `b3` file.
    let post = b"a freshly published post";
    let src_dir = tempfile::tempdir().unwrap();
    let src = XiteStorage::new(src_dir.path());
    src.write("post.txt", post).unwrap();
    let new_content = signed_content(
        priv_hex,
        &address,
        200.0,
        json!({ "post.txt": {
            "size": post.len(),
            "sha512": XiteStorage::hash_bytes(post),
            "b3": ObjId::of(post).to_string(),
        } }),
    );
    src.write("content.json", &new_content).unwrap();
    let peer_addr = spawn_edx_seeder(&address, src).await;
    std::mem::forget(src_dir);

    // --- Client: older content.json (modified 100), file not present. A real
    // data dir so the runtime stands up the full EDX stack (store + fetcher).
    let cli_dir = tempfile::tempdir().unwrap();
    let cli_data = tempfile::tempdir().unwrap();
    let old: Value =
        serde_json::from_slice(&signed_content(priv_hex, &address, 100.0, json!({}))).unwrap();
    let state = AppState::with_data_dir("test", cli_data.path());
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
            // An ephemeral fileserver port so the runtime stands up the EDX
            // stack (store + fetcher); resync then fetches over it.
            fileserver_port: Some(0),
            offline: false,
            ..Default::default()
        },
    );
    runtime.start();

    // The loop should fetch the newer content.json over EDX, verify it, and
    // download the file. Wait for both the applied content and the file.
    let post_path = cli_dir.path().join("post.txt");
    timeout(Duration::from_secs(15), async {
        loop {
            let applied =
                state.site_info(&address).await["content_updated"].as_f64() == Some(200.0);
            if applied && std::fs::read(&post_path).ok().as_deref() == Some(post.as_slice()) {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("runtime applied the update + fetched the file over EDX in time");

    assert_eq!(std::fs::read(&post_path).unwrap(), post);

    runtime.shutdown().await;
}
