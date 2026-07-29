//! The propagation poll makes a missed update appear without waiting for the
//! full resync tick: a peer holds a store-and-forward hint, the node polls it
//! over EDX (`Req::UpdatesSince`), learns its hosted xite advanced to a newer
//! version, and resyncs - fetching the newer content.json + `b3` file even
//! though `resync_interval` is effectively disabled here. This is the client
//! half of `epix-propagation` driven by the running node.

use std::sync::Arc;
use std::time::Duration;

use epix_blob::store::Store;
use epix_blob::ObjId;
use epix_core::PeerAddr;
use epix_propagation::PropagationStore;
use epix_protocol::PeerServer;
use epix_runtime::edx::edx_hook;
use epix_runtime::{NodeRuntime, RuntimeConfig};
use epix_transport::TcpTransport;
use epix_ui::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

/// A signed content.json for `address` at `modified`, listing `files`.
fn signed_content(priv_hex: &str, address: &str, modified: f64, files: Value) -> Vec<u8> {
    let mut content = json!({ "address": address, "modified": modified, "files": files });
    epix_content::sign(&mut content, priv_hex).unwrap();
    serde_json::to_vec(&content).unwrap()
}

#[tokio::test]
async fn propagation_poll_triggers_resync_of_a_hinted_xite() {
    let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
    let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

    // --- Source: newer content.json (modified 200) + a new `b3` file, plus a
    // propagation store already holding the "site advanced to 200" hint.
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

    let prop_store = Arc::new(Mutex::new(PropagationStore::new()));
    prop_store.lock().await.record(&address, 200);

    // Source node: EDX store with the site registered so EDX serves content.json
    // + the file, plus the propagation handler for the hint.
    let src_state = AppState::new("source");
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(store_dir.path()).unwrap());
    src_state.set_edx_store(store.clone()).await;
    src_state.add_xite(&address, XiteEntry { storage: src.clone(), content: None }).await;
    assert!(
        src_state.load_content_from_disk(&address).await,
        "load registers post.txt into the EDX store"
    );
    std::mem::forget(src_dir);
    std::mem::forget(store_dir);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    // The EDX control plane serves UpdatesSince from the very store the hint
    // was recorded into.
    let control = epix_runtime::edx::ControlHandles {
        prop: prop_store,
        ..epix_runtime::edx::ControlHandles::detached()
    };
    let server = PeerServer::new(edx_hook(
        src_state,
        store,
        epix_crypt::new_seed(),
        None,
        control,
        None,
    ));
    tokio::spawn(server.serve(listener));

    // --- Client: older content.json (modified 100), file not present. A real
    // data dir + ephemeral fileserver port so the runtime stands up the EDX
    // stack (store + fetcher) that resync fetches over.
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

    // Resync effectively disabled (1h): only the fast propagation poll can drive
    // the update within the test window.
    let mut runtime = NodeRuntime::with_config(
        state.clone(),
        vec![],
        RuntimeConfig {
            announce_interval: Duration::from_secs(3600),
            resync_interval: Duration::from_secs(3600),
            propagation_interval: Duration::from_millis(100),
            chart_interval: Duration::from_secs(3600),
            connection_interval: Duration::from_secs(3600),
            fileserver_port: Some(0),
            offline: false,
            ..Default::default()
        },
    );
    runtime.start();

    // The propagation poll should learn of the hint, resync the xite (fetch the
    // newer content.json over EDX), and download the file - all without a resync
    // tick.
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
    .expect("propagation poll resynced the hinted update over EDX in time");

    assert_eq!(std::fs::read(&post_path).unwrap(), post);

    runtime.shutdown().await;
}
