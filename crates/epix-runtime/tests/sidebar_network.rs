//! Sidebar commands against real EDX peers, signed manifests and temporary
//! storage. No command responses or download results are substituted.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use epix_blob::ObjId;
use epix_core::PeerAddr;
use epix_protocol::PeerServer;
use epix_runtime::edx::{edx_hook, enable_serving, ControlHandles};
use epix_transport::TcpTransport;
use epix_ui::{AppState, CommandRegistry, WsSession, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use tokio::{
    net::TcpListener,
    task::JoinHandle,
    time::{sleep, timeout},
};

const KEY: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";

struct Node {
    state: Arc<AppState>,
    storage: XiteStorage,
    address: String,
    endpoint: SocketAddr,
    server: JoinHandle<std::io::Result<()>>,
    _data: tempfile::TempDir,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Node {
    async fn start(content: &Value, files: &[(&str, &[u8])]) -> Self {
        let address = epix_crypt::privatekey_to_address(KEY).unwrap();
        let data = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(data.path().join("data").join(&address));
        storage
            .write("content.json", &serde_json::to_vec(content).unwrap())
            .unwrap();
        for (path, bytes) in files {
            storage.write(path, bytes).unwrap();
        }
        let state = AppState::with_data_dir("sidebar-network-test", data.path());
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(content.clone()),
                },
            )
            .await;
        assert!(state.load_content_from_disk(&address).await);
        assert!(state.xite_info(&address).await["settings"]["downloaded"].is_number());
        state.set_transport(Arc::new(TcpTransport)).await;
        let identity = epix_crypt::new_seed();
        let store = enable_serving(&state, data.path(), identity.clone(), None)
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let peer = PeerServer::new(edx_hook(
            state.clone(),
            store,
            identity,
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        let server = tokio::spawn(peer.serve(listener));
        Self {
            state,
            storage,
            address,
            endpoint,
            server,
            _data: data,
        }
    }

    async fn command(&self, name: &str, params: Value) -> Value {
        timeout(
            Duration::from_secs(30),
            CommandRegistry::with_defaults().dispatch(
                &WsSession::new_wrapper(self.state.clone(), Some(self.address.clone())),
                name,
                &params,
                1_000_001,
            ),
        )
        .await
        .expect("command completed")
        .unwrap_or_else(|error| panic!("{name}: {error}"))
    }

    async fn connect_to(&self, other: &Node) {
        self.state
            .add_peers(&self.address, [PeerAddr::Ip(other.endpoint)])
            .await;
    }
}

fn manifest(modified: u64, title: &str, optional: Value) -> Value {
    let mut value = json!({"address": epix_crypt::privatekey_to_address(KEY).unwrap(),
        "modified": modified, "title": title, "files": {}, "files_optional": optional});
    epix_content::sign(&mut value, KEY).unwrap();
    value
}

fn file_info(bytes: &[u8]) -> Value {
    json!({"size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes), "b3": ObjId::of(bytes).to_string()})
}

async fn wait_for_file(node: &Node, path: &str, expected: &[u8]) {
    timeout(Duration::from_secs(30), async {
        loop {
            if node.storage.read(path).ok().as_deref() == Some(expected) {
                return;
            }
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{path} did not arrive from the real peer"));
}

async fn wait_for_title(node: &Node, title: &str) -> Value {
    timeout(Duration::from_secs(15), async {
        loop {
            let content: Value =
                serde_json::from_slice(&node.storage.read("content.json").unwrap()).unwrap();
            if content["title"] == title {
                return content;
            }
            sleep(Duration::from_millis(40)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("published title {title:?} was not committed by the receiver"))
}

#[tokio::test]
async fn sidebar_publish_only_and_sign_publish_reach_a_real_peer() {
    let old = manifest(100, "Before", json!({}));
    let new = manifest(200, "Published", json!({}));
    let receiver = Node::start(&old, &[]).await;
    let sender = Node::start(&new, &[]).await;
    sender.connect_to(&receiver).await;

    assert_eq!(
        sender
            .command(
                "sitePublish",
                json!({"inner_path":"content.json","sign":false})
            )
            .await,
        "ok"
    );
    // Root push acknowledgement follows staging; wait for its actual commit.
    let received = wait_for_title(&receiver, "Published").await;
    assert_eq!(received["title"], "Published");
    assert!(epix_content::verify_signer(&received, &sender.address));

    let mut edited = new;
    edited["title"] = json!("Signed and delivered");
    sender
        .storage
        .write("content.json", &serde_json::to_vec(&edited).unwrap())
        .unwrap();
    assert!(!epix_content::verify_signer(&edited, &sender.address));
    assert_eq!(
        sender
            .command(
                "sitePublish",
                json!({"inner_path":"content.json", "sign":true,
        "privatekey":KEY, "update_changed_files":true})
            )
            .await,
        "ok"
    );
    let received = wait_for_title(&receiver, "Signed and delivered").await;
    assert_eq!(received["title"], "Signed and delivered");
    assert!(epix_content::verify_signer(&received, &sender.address));
}

#[tokio::test]
async fn sidebar_zero_peer_publish_reports_failure_without_success() {
    let node = Node::start(&manifest(100, "No peers", json!({})), &[]).await;
    let mut events = node.state.subscribe_events();
    // Legacy callers expect an acknowledgement; the notification carries the
    // actual peer outcome and must never advertise a successful publication.
    assert_eq!(
        node.command("sitePublish", json!({"sign":false})).await,
        "ok"
    );
    let mut failed = false;
    while let Ok(event) = events.try_recv() {
        let value: Value = serde_json::from_str(&event.payload).unwrap();
        if value["cmd"] == "notification" {
            assert_ne!(value["params"][0], "done");
            failed |= value["params"][1]
                .as_str()
                .is_some_and(|text| text.contains("no peers reachable"));
        }
    }
    assert!(
        failed,
        "zero acceptors produce the actual publish failure notification"
    );
}

#[tokio::test]
async fn sidebar_update_reports_completion_after_receiving_a_real_peer_manifest() {
    let old = manifest(100, "Before update", json!({}));
    let new = manifest(200, "Updated from a peer", json!({}));
    let seeder = Node::start(&new, &[]).await;
    let reader = Node::start(&old, &[]).await;
    reader.connect_to(&seeder).await;
    let mut events = reader.state.subscribe_events();
    assert_eq!(
        reader
            .command(
                "siteUpdate",
                json!({"update_request_id":"sidebar-network-update"})
            )
            .await,
        "Updated"
    );
    let outcome = timeout(Duration::from_secs(30), async {
        loop {
            let event = events.recv().await.unwrap();
            let value: Value = serde_json::from_str(&event.payload).unwrap();
            if value["cmd"] == "setSiteInfo"
                && value["params"]["event"][0] == "updated"
                && value["params"]["update_request_id"] == "sidebar-network-update"
            {
                return value["params"].clone();
            }
        }
    })
    .await
    .expect("actual update completion event");
    assert_ne!(outcome["content_updated"], false);
    assert_eq!(outcome["update_applied"], true);
    let received: Value =
        serde_json::from_slice(&reader.storage.read("content.json").unwrap()).unwrap();
    assert_eq!(received["title"], "Updated from a peer");
    assert!(epix_content::verify_signer(&received, &reader.address));
}

#[tokio::test]
async fn sidebar_optional_commands_fetch_real_bytes_and_enforce_the_per_xite_limit() {
    let small = b"optional file downloaded by the sidebar";
    let large = vec![b'L'; 2 * 1024 * 1024];
    let content = manifest(
        200,
        "Optional downloads",
        json!({
            "small.txt": file_info(small), "large.bin": file_info(&large)
        }),
    );
    let seeder = Node::start(&content, &[("small.txt", small), ("large.bin", &large)]).await;
    let reader = Node::start(&content, &[]).await;
    reader.connect_to(&seeder).await;
    assert_eq!(
        reader
            .command("siteSetDownloadoptional", json!([false]))
            .await,
        "ok"
    );
    assert_eq!(
        reader
            .command("siteSetAutodownloadBigfileLimit", json!({"limit":1}))
            .await,
        "ok"
    );
    let mut events = reader.state.subscribe_events();
    let started = reader
        .command("siteDownloadOptionalPrevious", json!({}))
        .await;
    assert_eq!(started["status"], "started");
    assert_eq!(
        started["files"], 1,
        "large file is excluded from the one-shot plan"
    );
    wait_for_file(&reader, "small.txt", small).await;
    timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.unwrap();
            let value: Value = serde_json::from_str(&event.payload).unwrap();
            if value["cmd"] == "notification"
                && value["params"][1]
                    .as_str()
                    .is_some_and(|text| text.contains("Optional download finished"))
            {
                break;
            }
        }
    })
    .await
    .expect("real completion notification, not an enqueue acknowledgement");
    assert!(reader.storage.read("large.bin").is_err());
    let settings = reader.state.xite_info(&reader.address).await["settings"].clone();
    assert_eq!(
        settings["download_optional"], false,
        "one-shot does not enable on-demand"
    );
    assert_eq!(
        settings["autodownloadoptional"], false,
        "one-shot does not enable bulk policy"
    );
    assert_eq!(
        reader
            .command("siteDownloadOptionalPrevious", json!({}))
            .await["status"],
        "complete"
    );

    assert_eq!(
        reader
            .command("siteSetAutodownloadBigfileLimit", json!({"limit":0}))
            .await,
        "ok"
    );
    assert_eq!(
        reader
            .command("siteSetAutodownloadoptional", json!([true]))
            .await,
        "ok"
    );
    wait_for_file(&reader, "large.bin", &large).await;
    let settings = reader.state.xite_info(&reader.address).await["settings"].clone();
    assert_eq!(settings["download_optional"], true);
    assert_eq!(settings["autodownloadoptional"], true);
    assert_eq!(
        reader
            .command("siteSetDownloadoptional", json!([false]))
            .await,
        "ok"
    );
    let settings = reader.state.xite_info(&reader.address).await["settings"].clone();
    assert_eq!(settings["download_optional"], false);
    assert_eq!(settings["autodownloadoptional"], false);
}
