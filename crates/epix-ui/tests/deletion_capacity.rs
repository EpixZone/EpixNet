//! Deletion failures must preserve the xite and report the failed recovery write.

use epix_ui::command::{CommandRegistry, WsSession};
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

const WRAPPER_ID: i64 = 1_000_000;
const PAYLOAD: &[u8] = b"signed content that must survive a refused deletion";

struct Fixture {
    root: tempfile::TempDir,
    state: Arc<AppState>,
    address: String,
    storage: XiteStorage,
    manifest: Vec<u8>,
    registry: Vec<u8>,
}

impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("deletion-capacity-test", root.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(root.path().join("data").join(&address));
        storage.write("index.html", PAYLOAD).unwrap();
        let mut content = json!({
            "address": address,
            "modified": 1,
            "files": {
                "index.html": {
                    "size": PAYLOAD.len(),
                    "sha512": XiteStorage::hash_bytes(PAYLOAD),
                    "b3": epix_blob::ObjId::of(PAYLOAD).to_string(),
                },
            },
        });
        epix_content::sign(&mut content, &key).unwrap();
        let manifest = serde_json::to_vec(&content).unwrap();
        storage.write("content.json", &manifest).unwrap();
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
        let registry = std::fs::read(root.path().join("private/xites.json")).unwrap();
        Self {
            root,
            state,
            address,
            storage,
            manifest,
            registry,
        }
    }

    fn journal_path(&self) -> PathBuf {
        self.root.path().join("private/xite-removals.json")
    }

    async fn delete(&self, address: &str) -> Result<serde_json::Value, String> {
        let session = WsSession::new(self.state.clone(), Some(self.address.clone()));
        CommandRegistry::with_defaults()
            .dispatch(
                &session,
                "siteDelete",
                &json!({ "address": address }),
                WRAPPER_ID,
            )
            .await
    }

    async fn assert_unchanged(&self, journal: &[u8]) {
        assert!(self.state.has_any_alias(&self.address).await);
        assert_eq!(self.storage.read("index.html").unwrap(), PAYLOAD);
        assert_eq!(self.storage.read("content.json").unwrap(), self.manifest);
        assert_eq!(
            std::fs::read(self.root.path().join("private/xites.json")).unwrap(),
            self.registry,
        );
        assert_eq!(std::fs::read(self.journal_path()).unwrap(), journal);
    }
}

#[tokio::test]
async fn site_delete_reports_malformed_recovery_journal_without_removing_the_xite() {
    let fixture = Fixture::new().await;
    let journal = b"{ an interrupted recovery journal";
    std::fs::write(fixture.journal_path(), journal).unwrap();

    let error = fixture.delete(&fixture.address).await.unwrap_err();
    assert!(error.contains("xite-removals.json"), "{error}");
    assert!(error.contains("parse"), "{error}");
    assert!(!error.contains("Unknown xite"), "{error}");
    fixture.assert_unchanged(journal).await;

    // Repairing the journal permits a later command to delete the same membership.
    std::fs::write(fixture.journal_path(), b"{}").unwrap();
    assert_eq!(fixture.delete(&fixture.address).await.unwrap(), json!("ok"));
    assert!(!fixture.state.has_any_alias(&fixture.address).await);
    assert!(!fixture.storage.root().exists());
}

#[tokio::test]
async fn site_delete_reports_oversized_recovery_journal_without_removing_the_xite() {
    let fixture = Fixture::new().await;
    // Valid JSON with whitespace padding isolates the installed journal's size limit.
    let mut journal = vec![b' '; 8 * 1024 * 1024 + 1];
    journal[..2].copy_from_slice(b"{}");
    std::fs::write(fixture.journal_path(), &journal).unwrap();

    let error = fixture.delete(&fixture.address).await.unwrap_err();
    assert!(error.contains("xite-removals.json"), "{error}");
    assert!(error.contains("size limit"), "{error}");
    assert!(!error.contains("Unknown xite"), "{error}");
    fixture.assert_unchanged(&journal).await;
}

#[tokio::test]
async fn site_delete_keeps_unknown_xite_error_with_a_healthy_recovery_journal() {
    let fixture = Fixture::new().await;
    let journal = b"{}";
    std::fs::write(fixture.journal_path(), journal).unwrap();
    let missing = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    assert!(!fixture.state.has_any_alias(&missing).await);

    let error = fixture.delete(&missing).await.unwrap_err();
    assert_eq!(error, format!("Unknown xite: {missing}"));
    fixture.assert_unchanged(journal).await;
}

#[test]
fn startup_reserves_space_only_after_the_removal_journal_is_empty() {
    let root = tempfile::tempdir().unwrap();
    let private = root.path().join("private");
    std::fs::create_dir_all(&private).unwrap();
    let journal_path = private.join("xite-removals.json");
    let reserve_path = private.join("deletion-reserve");
    let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    let pending = serde_json::to_vec(&json!({ address: {} })).unwrap();
    std::fs::write(&journal_path, &pending).unwrap();

    let state = AppState::with_data_dir("pending-removal-test", root.path());
    assert!(
        !reserve_path.exists(),
        "pending removal must retain the available space for recovery",
    );
    assert_eq!(std::fs::read(&journal_path).unwrap(), pending);
    drop(state);

    std::fs::write(&journal_path, b"{}").unwrap();
    let _state = AppState::with_data_dir("completed-removal-test", root.path());
    let reserve = std::fs::metadata(&reserve_path).unwrap();
    assert_eq!(reserve.len(), 16 * 1024 * 1024);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert!(
            reserve.blocks() * 512 >= reserve.len(),
            "reserve must allocate disk blocks, not just a sparse file length",
        );
    }
    assert_eq!(std::fs::read(&journal_path).unwrap(), b"{}");
}
