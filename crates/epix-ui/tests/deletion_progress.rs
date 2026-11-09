//! Site deletion reports actual disk-file progress to its initiating socket.

use epix_ui::command::{CommandRegistry, WsSession};
use epix_ui::state::{AppState, UiEvent, XiteEntry};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

const WRAPPER_ID: i64 = 1_000_000;
type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Fixture {
    root: tempfile::TempDir,
    state: Arc<AppState>,
    address: String,
    storage: XiteStorage,
}

impl Fixture {
    async fn new(title: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("deletion-progress-test", root.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(root.path().join("data").join(&address));
        let payload = b"file to remove";
        for path in [
            "index.html",
            "media/optional.bin",
            "drafts/nested/note.txt",
            ".local",
        ] {
            storage.write(path, payload).unwrap();
        }
        std::fs::create_dir_all(storage.root().join("empty/directory")).unwrap();
        let record = json!({
            "size": payload.len(),
            "sha512": XiteStorage::hash_bytes(payload),
            "b3": epix_blob::ObjId::of(payload).to_string(),
        });
        let mut content = json!({
            "address": address,
            "title": title,
            "modified": 1,
            "files": { "index.html": record },
            "files_optional": {
                "media/optional.bin": record,
                "media/not-downloaded.bin": record,
            },
        });
        epix_content::sign(&mut content, &key).unwrap();
        storage
            .write("content.json", &serde_json::to_vec(&content).unwrap())
            .unwrap();
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(content),
                },
            )
            .await;
        assert!(state.has_any_alias(&address).await);
        Self {
            root,
            state,
            address,
            storage,
        }
    }

    fn session(&self) -> WsSession {
        WsSession::new_wrapper(self.state.clone(), Some(self.address.clone()))
    }
}

fn progress_events(
    events: &mut tokio::sync::broadcast::Receiver<UiEvent>,
) -> Vec<(UiEvent, Value)> {
    let mut progress = Vec::new();
    while let Ok(event) = events.try_recv() {
        let payload: Value = serde_json::from_str(&event.payload).unwrap();
        if payload["cmd"] == "progress" {
            progress.push((event, payload));
        }
    }
    progress
}

fn assert_routed_progress(events: &[(UiEvent, Value)], address: &str, session: u64) {
    assert!(!events.is_empty(), "deletion must report progress");
    for (event, payload) in events {
        assert_eq!(
            event.only,
            Some(session),
            "progress belongs to the initiating connection"
        );
        assert_eq!(payload["params"][0], format!("delete-{address}"));
        assert_eq!(
            payload["params"][3], true,
            "titles must use the plain-text rendering path"
        );
    }
}

#[tokio::test]
async fn deletion_counts_nested_optional_and_untracked_files_and_marks_the_title_as_plain_text() {
    let f = Fixture::new("Archive & <script>name</script>").await;
    let session = f.session();
    let mut events = f.state.subscribe_events();
    let result = CommandRegistry::with_defaults()
        .dispatch(
            &session,
            "siteDelete",
            &json!({ "address": f.address }),
            WRAPPER_ID,
        )
        .await
        .unwrap();
    assert_eq!(result, json!("ok"));
    let progress = progress_events(&mut events);
    assert_routed_progress(&progress, &f.address, session.id);
    assert_eq!(progress.first().unwrap().1["params"][2], 0);
    assert!(progress.iter().any(|(_, event)| {
        let message = event["params"][1].as_str().unwrap();
        message.contains("Deleting site Archive & <script>name</script>...\n")
            && message.contains("Deleting file 5/5")
    }), "the total includes downloaded, untracked and hidden files, but not directories or absent optional files: {:?}",
        progress.iter().map(|(_, event)| event).collect::<Vec<_>>());
    let terminal = &progress.last().unwrap().1["params"];
    assert_eq!(terminal[2], 100);
    assert!(terminal[1]
        .as_str()
        .unwrap()
        .contains("All files deleted successfully"));
    assert_eq!(
        progress
            .iter()
            .filter(|(_, event)| event["params"][2] == 100)
            .count(),
        1
    );
    assert!(!f.storage.root().exists());
    assert!(!f.state.has_any_alias(&f.address).await);
}

#[tokio::test]
async fn a_failed_removal_closes_progress_without_claiming_completion() {
    let f = Fixture::new("Preserved xite").await;
    let journal = f.root.path().join("private/xite-removals.json");
    std::fs::write(&journal, b"{ invalid journal").unwrap();
    let session = f.session();
    let mut events = f.state.subscribe_events();
    let error = CommandRegistry::with_defaults()
        .dispatch(
            &session,
            "siteDelete",
            &json!({ "address": f.address }),
            WRAPPER_ID,
        )
        .await
        .unwrap_err();
    assert!(error.contains("xite-removals.json"), "{error}");
    let progress = progress_events(&mut events);
    assert_routed_progress(&progress, &f.address, session.id);
    assert!(progress.iter().all(|(_, event)| event["params"][2] != 100));
    let terminal = &progress.last().unwrap().1["params"];
    assert_eq!(terminal[2], -1);
    assert!(terminal[1]
        .as_str()
        .unwrap()
        .contains("Site deletion failed:"));
    assert!(f.storage.root().join("index.html").exists());
    assert!(f.state.has_any_alias(&f.address).await);
}

#[tokio::test]
async fn deferred_store_cleanup_does_not_report_all_files_deleted() {
    let f = Fixture::new("Deferred cleanup").await;
    // An unopened persistent Store may own these files. Its presence keeps
    // the root and durable receipt for retry until Store activation.
    let store = f.root.path().join("edx-store");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join("index.redb"), b"dormant store fixture").unwrap();
    let session = f.session();
    let mut events = f.state.subscribe_events();
    let result = CommandRegistry::with_defaults()
        .dispatch(
            &session,
            "siteDelete",
            &json!({ "address": f.address }),
            WRAPPER_ID,
        )
        .await
        .unwrap();
    assert_eq!(result, json!("ok"), "the durable removal was accepted");
    let progress = progress_events(&mut events);
    assert_routed_progress(&progress, &f.address, session.id);
    assert!(progress.iter().all(|(_, event)| event["params"][2] != 100));
    let terminal = &progress.last().unwrap().1["params"];
    assert_eq!(terminal[2], -1);
    assert!(terminal[1]
        .as_str()
        .unwrap()
        .contains("Site deletion is pending and will retry."));
    assert!(f.storage.root().join("index.html").exists());
    assert!(!f.state.has_any_alias(&f.address).await);
    let journal: Value = serde_json::from_slice(
        &std::fs::read(f.root.path().join("private/xite-removals.json")).unwrap(),
    )
    .unwrap();
    assert!(journal.get(&f.address).is_some());
}

#[tokio::test]
async fn an_unknown_xite_closes_the_progress_notification_with_an_error() {
    let f = Fixture::new("Existing xite").await;
    let missing = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    let session = f.session();
    let mut events = f.state.subscribe_events();
    let error = CommandRegistry::with_defaults()
        .dispatch(
            &session,
            "siteDelete",
            &json!({ "address": missing }),
            WRAPPER_ID,
        )
        .await
        .unwrap_err();
    assert_eq!(error, format!("Unknown xite: {missing}"));
    let progress = progress_events(&mut events);
    assert_routed_progress(&progress, &missing, session.id);
    assert!(progress.iter().all(|(_, event)| event["params"][2] != 100));
    let terminal = &progress.last().unwrap().1["params"];
    assert_eq!(terminal[2], -1);
    assert!(terminal[1]
        .as_str()
        .unwrap()
        .contains(&format!("Unknown xite: {missing}")));
    assert!(f.state.has_any_alias(&f.address).await);
}

#[tokio::test]
async fn merger_deletion_reports_progress_to_the_merger_connection() {
    let f = Fixture::new("Merged files").await;
    let key = epix_crypt::new_seed();
    let merger = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(f.root.path().join("data").join(&merger));
    let mut content = json!({ "address": merger, "files": {} });
    epix_content::sign(&mut content, &key).unwrap();
    storage
        .write("content.json", &serde_json::to_vec(&content).unwrap())
        .unwrap();
    f.state
        .add_xite(
            &merger,
            XiteEntry {
                storage,
                content: Some(content),
            },
        )
        .await;
    f.state.add_permission(&merger, "Merger:ProgressTest").await;
    let session = WsSession::new(f.state.clone(), Some(merger.clone()));
    let mut events = f.state.subscribe_events();
    let result = CommandRegistry::with_defaults()
        .dispatch(&session, "mergerSiteDelete", &json!([f.address]), 1)
        .await
        .unwrap();
    assert_eq!(result, json!("ok"));
    let progress = progress_events(&mut events);
    assert_routed_progress(&progress, &f.address, session.id);
    assert_eq!(progress.last().unwrap().1["params"][2], 100);
    assert!(f.state.has_any_alias(&merger).await);
    assert!(!f.storage.root().exists());
}

async fn receive(ws: &mut Ws) -> Value {
    loop {
        if let Message::Text(text) = ws.next().await.expect("socket remains open").unwrap() {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn large_deletion_streams_live_counters_without_blocking_or_notifying_another_socket() {
    let f = Fixture::new("Large archive").await;
    const EXTRA_FILES: usize = 8192;
    for batch in 0..32 {
        let directory = f.storage.root().join(format!("archive/{batch}"));
        std::fs::create_dir_all(&directory).unwrap();
        for file in 0..(EXTRA_FILES / 32) {
            std::fs::write(directory.join(format!("{file}.txt")), b"archive entry").unwrap();
        }
    }
    let (key, _) = f.state.wrapper_keys(&f.address).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = UiServer::new(f.state.clone()).router();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let url = format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={key}");
    let (mut initiator, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut observer, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    initiator
        .send(Message::Text(
            json!({
                "cmd": "siteDelete", "params": { "address": f.address }, "id": WRAPPER_ID,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    let mut messages = Vec::new();
    let mut reply = None;
    let mut terminal = false;
    let mut live_counter = false;
    tokio::time::timeout(Duration::from_secs(30), async {
        while reply.is_none() || !terminal {
            let event = receive(&mut initiator).await;
            if event["cmd"] == "progress" {
                assert_eq!(event["params"][0], format!("delete-{}", f.address));
                let body = event["params"][1].as_str().unwrap();
                if body.contains("Deleting file ") && event["params"][2].as_i64().unwrap() < 85 {
                    live_counter |= f.storage.root().exists();
                }
                terminal |= event["params"][2] == 100;
                messages.push(event);
            } else if event["cmd"] == "response" && event["to"] == WRAPPER_ID {
                reply = Some(event["result"].clone());
            }
        }
    })
    .await
    .expect("the socket must receive progress while deletion is running");
    assert_eq!(reply, Some(json!("ok")));
    #[cfg(unix)]
    assert!(
        live_counter,
        "file counters must arrive before the root is removed on a single-thread runtime"
    );
    let total = EXTRA_FILES + 5;
    assert!(messages.iter().any(|event| event["params"][1]
        .as_str()
        .unwrap()
        .contains(&format!("Deleting file {total}/{total}"))));
    assert!(!f.storage.root().exists());

    // A second wrapper for the same xite must remain usable after membership
    // removal and must not receive the first connection's progress toast.
    observer
        .send(Message::Text(
            json!({ "cmd": "ping", "params": {}, "id": 7 })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(2), receive(&mut observer))
        .await
        .expect("unrelated socket remains responsive");
    assert_eq!(
        pong["cmd"], "response",
        "progress leaked to the other wrapper: {pong}"
    );
    assert_eq!(pong["to"], 7);
    server.abort();
}
