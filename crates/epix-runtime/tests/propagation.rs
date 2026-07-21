//! The propagation poll makes a missed update appear without waiting for the
//! full resync tick: a peer holds a store-and-forward hint (`meshGetUpdates`),
//! the node polls it, learns its hosted xite advanced to a newer version, and
//! resyncs - fetching the newer content.json + file even though `resync_interval`
//! is effectively disabled here. This is the client half of `epix-propagation`
//! that, before, was built and tested but never driven by the running node.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_propagation::{PropagationService, PropagationStore};
use epix_protocol::{vget, vmap, PeerServer, RequestHandler};
use epix_runtime::{NodeRuntime, RuntimeConfig};
use epix_transport::TcpTransport;
use epix_ui::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use rmpv::Value as Rmp;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};

/// One peer that answers both `getFile` (from a storage) and the propagation
/// commands (`meshGetUpdates` / `meshAnnounceUpdate`, from a shared store).
struct HintAndFiles {
    storage: XiteStorage,
    prop: PropagationService,
}

#[async_trait]
impl RequestHandler for HintAndFiles {
    async fn handle(&self, peer: &PeerAddr, cmd: &str, params: &Rmp) -> Rmp {
        match cmd {
            epix_propagation::CMD_GET | epix_propagation::CMD_ANNOUNCE => {
                self.prop.handle(peer, cmd, params).await
            }
            "getFile" => {
                let inner = vget(params, "inner_path").and_then(|v| v.as_str()).unwrap_or("");
                let location =
                    vget(params, "location").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let read = vget(params, "read_bytes").and_then(|v| v.as_u64()).unwrap_or(512 * 1024)
                    as usize;
                let bytes = self.storage.read(inner).unwrap_or_default();
                let start = location.min(bytes.len());
                let end = (start + read).min(bytes.len());
                vmap(vec![
                    ("body", Rmp::Binary(bytes[start..end].to_vec())),
                    ("size", Rmp::from(bytes.len() as i64)),
                    ("location", Rmp::from(end as i64)),
                ])
            }
            _ => vmap(vec![("error", Rmp::from("unknown command"))]),
        }
    }
}

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

    // --- Source peer: newer content.json (modified 200) + a new file, and a
    // propagation store already holding the "site advanced to 200" hint.
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

    let store = Arc::new(Mutex::new(PropagationStore::new()));
    store.lock().await.record(&address, 200);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();
    let handler =
        Arc::new(HintAndFiles { storage: src.clone(), prop: PropagationService::new(store) });
    tokio::spawn(PeerServer::new(handler).serve(listener));

    // --- Client: older content.json (modified 100), file not present.
    let cli_dir = tempfile::tempdir().unwrap();
    let old: Value =
        serde_json::from_slice(&signed_content(priv_hex, &address, 100.0, json!({}))).unwrap();
    let state = AppState::new("test");
    state
        .add_xite(
            &address,
            XiteEntry { storage: XiteStorage::new(cli_dir.path()), content: Some(old) },
        )
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
            fileserver_port: None,
            offline: false,
            ..Default::default()
        },
    );
    runtime.start();

    // The propagation poll should learn of the hint, resync the xite (fetch the
    // newer content.json), and download the file - all without a resync tick.
    let post_path = cli_dir.path().join("post.txt");
    timeout(Duration::from_secs(10), async {
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
    .expect("propagation poll resynced the hinted update in time");

    assert_eq!(std::fs::read(&post_path).unwrap(), post);

    runtime.shutdown().await;
}
