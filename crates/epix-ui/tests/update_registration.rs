//! A root update fetched for a removed registration cannot overwrite its replacement.
use epix_core::PeerAddr;
use epix_transport::TcpTransport;
use epix_ui::state::{
    AppState, ContentSyncer, EdxBatch, EdxBatchProgress, EdxFetcher, EdxPushError, EdxPushProgress,
    EdxWant, UpdatePayload, XiteEntry,
};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::timeout;

const ASSET: &[u8] = b"the replacement's complete declared asset";
const LIMIT: Duration = Duration::from_secs(5);

struct DelayedRootFetcher {
    peer: PeerAddr,
    address: String,
    manifest: Vec<u8>,
    entered: Notify,
    release: Notify,
    requests: AtomicUsize,
}
#[async_trait::async_trait]
impl EdxFetcher for DelayedRootFetcher {
    async fn fetch_file(&self, _: &str, _: &str) -> Result<bool, String> {
        unreachable!("the fixture already has every declared asset")
    }
    async fn fetch_signed(
        &self,
        peer: PeerAddr,
        address: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        assert_eq!(peer, self.peer);
        assert_eq!(address, self.address);
        assert_eq!(path, "content.json");
        assert_eq!(self.requests.fetch_add(1, Ordering::SeqCst), 0);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(Some(self.manifest.clone()))
    }
    async fn fetch_signed_many(
        &self,
        _: &str,
        _: Vec<String>,
        _: Vec<PeerAddr>,
        _: Option<epix_ui::state::EdxSignedProgress>,
    ) -> HashMap<String, Vec<u8>> {
        unreachable!()
    }
    async fn fetch_range(
        &self,
        _: &str,
        _: &str,
        _: u64,
        _: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        unreachable!()
    }
    async fn push_update(
        &self,
        _: PeerAddr,
        _: &str,
        _: &str,
        _: Arc<Vec<u8>>,
        _: f64,
        _: Arc<UpdatePayload>,
        _: Arc<Vec<String>>,
        _: Arc<EdxPushProgress>,
    ) -> Result<bool, EdxPushError> {
        unreachable!()
    }
    async fn fetch_files(
        &self,
        address: &str,
        want: Vec<EdxWant>,
        _: Vec<PeerAddr>,
        _: Option<serde_json::Value>,
        _: Option<EdxBatchProgress>,
    ) -> EdxBatch {
        assert_eq!(address, self.address);
        assert!(want.is_empty(), "the declared asset is already complete");
        EdxBatch {
            done: Vec::new(),
            missed: Vec::new(),
            bytes: 0,
        }
    }
    async fn list_signed(
        &self,
        _: PeerAddr,
        _: &str,
        _: u64,
    ) -> Result<Option<Vec<(String, u64, u64)>>, String> {
        unreachable!()
    }
    async fn pex(
        &self,
        _: PeerAddr,
        _: &str,
        _: u32,
        _: Vec<PeerAddr>,
    ) -> Result<Vec<PeerAddr>, String> {
        unreachable!()
    }
    async fn get_trackers(&self, _: PeerAddr) -> Result<Vec<String>, String> {
        unreachable!()
    }
    async fn kad(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        unreachable!()
    }
    async fn announce(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        unreachable!()
    }
    async fn updates_since(
        &self,
        _: PeerAddr,
        _: u64,
    ) -> Result<(Vec<(String, i64)>, u64), String> {
        unreachable!()
    }
}

fn signed_manifest(key: &str, address: &str, modified: u64) -> (Value, Vec<u8>) {
    let mut content = json!({
        "address": address,
        "modified": modified,
        "title": format!("signed version {modified}"),
        "files": {"index.html": {
            "size": ASSET.len(),
            "sha512": XiteStorage::hash_bytes(ASSET),
            "b3": epix_blob::ObjId::of(ASSET).to_string(),
        }},
    });
    epix_content::sign(&mut content, key).unwrap();
    let bytes = epix_content::dumps_content(&content).into_bytes();
    (content, bytes)
}

async fn delayed_root_response(replace_registration: bool) {
    let directory = tempfile::tempdir().unwrap();
    let state = AppState::new("update-registration-test");
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(directory.path().join(&address));
    let (old, old_bytes) = signed_manifest(&key, &address, 100);
    let (_, new_bytes) = signed_manifest(&key, &address, 200);
    storage.write("content.json", &old_bytes).unwrap();
    storage.write("index.html", ASSET).unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: storage.clone(),
                content: Some(old.clone()),
            },
        )
        .await;
    let original_generation = state.xite_membership_generation(&address).await.unwrap();
    let peer = PeerAddr::parse("127.0.0.1:26552").unwrap();
    // The signed-content fetcher is the entire network seam. TcpTransport is
    // only the resync eligibility marker; no socket or external peer is used.
    state.set_transport(Arc::new(TcpTransport)).await;
    state.add_peers(&address, [peer.clone()]).await;
    let fetcher = Arc::new(DelayedRootFetcher {
        peer,
        address: address.clone(),
        manifest: new_bytes.clone(),
        entered: Notify::new(),
        release: Notify::new(),
        requests: AtomicUsize::new(0),
    });
    state.set_edx_fetcher(fetcher.clone()).await;

    // JoinSet aborts the held fetch if any setup/assertion fails. No detached
    // resync survives a timeout or retains the disposable directory.
    let mut passes = JoinSet::new();
    passes.spawn({
        let state = state.clone();
        let address = address.clone();
        async move {
            state
                .resync_xite_for_registration(&address, original_generation)
                .await
        }
    });
    timeout(LIMIT, fetcher.entered.notified())
        .await
        .expect("root request reached the gate");

    if replace_registration {
        assert!(timeout(LIMIT, state.remove_xite(&address))
            .await
            .expect("removal completed"));
        assert!(state.xite_membership_generation(&address).await.is_none());
        assert!(
            !storage.root().exists(),
            "the original tree was really removed"
        );
        // Reuse the exact address AND filesystem path. A path or current
        // manifest comparison alone cannot distinguish this new registration.
        storage.write("content.json", &old_bytes).unwrap();
        storage.write("index.html", ASSET).unwrap();
        timeout(
            LIMIT,
            state.add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(old),
                },
            ),
        )
        .await
        .expect("replacement registration completed");
        assert_ne!(
            state.xite_membership_generation(&address).await,
            Some(original_generation)
        );
    }

    fetcher.release.notify_one();
    let applied = timeout(LIMIT, passes.join_next())
        .await
        .expect("released root update completed")
        .unwrap()
        .expect("update task did not panic");
    assert_eq!(applied, Ok(!replace_registration));
    let expected = if replace_registration {
        &old_bytes
    } else {
        &new_bytes
    };
    assert_eq!(
        storage.read("content.json").unwrap(),
        *expected,
        "the old response must not commit into the replacement registration"
    );
    assert_eq!(storage.read("index.html").unwrap(), ASSET);
    assert_eq!(
        state.xite_info(&address).await["content_updated"],
        json!(if replace_registration { 100.0 } else { 200.0 })
    );
    assert_eq!(fetcher.requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn delayed_root_response_applies_to_its_original_registration() {
    delayed_root_response(false).await;
}

#[tokio::test]
async fn delayed_root_response_cannot_mutate_replacement_at_the_same_path() {
    delayed_root_response(true).await;
}

struct DelayedContentSyncer {
    address: String,
    entered: Notify,
    release: Notify,
}

#[async_trait::async_trait]
impl ContentSyncer for DelayedContentSyncer {
    async fn sync_user_content(&self, address: &str) -> (u64, Vec<String>) {
        assert_eq!(address, self.address);
        self.entered.notify_one();
        self.release.notified().await;
        (17, vec!["data/member/data.json".to_string()])
    }
}

async fn delayed_content_completion(replace_registration: bool) {
    let directory = tempfile::tempdir().unwrap();
    let state = AppState::new("content-registration-test");
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(directory.path().join(&address));
    let (content, bytes) = signed_manifest(&key, &address, 100);
    storage.write("content.json", &bytes).unwrap();
    storage.write("index.html", ASSET).unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: storage.clone(),
                content: Some(content.clone()),
            },
        )
        .await;
    let generation = state.xite_membership_generation(&address).await.unwrap();
    let syncer = Arc::new(DelayedContentSyncer {
        address: address.clone(),
        entered: Notify::new(),
        release: Notify::new(),
    });
    state.set_content_syncer(syncer.clone()).await;
    let mut passes = JoinSet::new();
    passes.spawn({
        let state = state.clone();
        let address = address.clone();
        async move {
            state
                .sync_user_content_for_registration(&address, generation)
                .await
        }
    });
    timeout(LIMIT, syncer.entered.notified())
        .await
        .expect("user-content sync reached the gate");
    if replace_registration {
        assert!(timeout(LIMIT, state.remove_xite(&address))
            .await
            .expect("removal completed"));
        assert!(!storage.root().exists());
        storage.write("content.json", &bytes).unwrap();
        storage.write("index.html", ASSET).unwrap();
        timeout(
            LIMIT,
            state.add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(content),
                },
            ),
        )
        .await
        .expect("replacement registration completed");
        assert_ne!(
            state.xite_membership_generation(&address).await,
            Some(generation)
        );
    }
    // Subscribe after replacement so removal/addition events cannot be
    // mistaken for the old sync's completion refresh.
    let mut events = state.subscribe_events();
    syncer.release.notify_one();
    let downloaded = timeout(LIMIT, passes.join_next())
        .await
        .expect("released user-content sync completed")
        .unwrap()
        .expect("user-content task did not panic");
    assert_eq!(downloaded, if replace_registration { 0 } else { 17 });
    if replace_registration {
        assert!(
            matches!(
                events.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "a stale completion must not refresh the replacement's UI"
        );
    } else {
        let event = events
            .try_recv()
            .expect("current completion refreshes the UI");
        assert_eq!(event.target.as_deref(), Some(address.as_str()));
        let payload: Value = serde_json::from_str(&event.payload).unwrap();
        assert_eq!(payload["cmd"], "setSiteInfo");
    }
    assert_eq!(storage.read("content.json").unwrap(), bytes);
    assert_eq!(storage.read("index.html").unwrap(), ASSET);
}

#[tokio::test]
async fn delayed_user_content_completion_reports_its_original_registration() {
    delayed_content_completion(false).await;
}

#[tokio::test]
async fn delayed_user_content_completion_does_not_refresh_replacement() {
    delayed_content_completion(true).await;
}
