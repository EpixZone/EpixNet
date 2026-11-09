//! Atomic edits keep rejected drafts out of accepted database inputs.

use super::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const SETTINGS: &str = "data/admin/admin-settings.json";
const MANIFEST: &str = "data/admin/content.json";
const OPTIONAL: &str = "data/admin/optional.bin";
const MERGED: &str = "data/admin/records.json";
const INITIAL: &[u8] = br#"{"pinned_topic_uris":[]}"#;
const DRAFT: &[u8] = br#"{"pinned_topic_uris":["42_alice.epix"]}"#;
const OTHER_DRAFT: &[u8] = br#"{"pinned_topic_uris":["43_bob.epix"]}"#;
const QUERY: &str = "SELECT title FROM topic";

struct Fixture {
    directory: tempfile::TempDir,
    state: Arc<AppState>,
    address: String,
    key: String,
    storage: XiteStorage,
}

struct Snapshot {
    settings: Vec<u8>,
    manifest: Vec<u8>,
    old_settings: Option<Vec<u8>>,
    accepted: HashMap<String, Value>,
    verified_epoch: u64,
    source_epoch: u64,
    rows: Vec<Value>,
}

impl Fixture {
    async fn new(max_size: u64, other_file_kinds: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("signed-write-test", directory.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(directory.path().join("data").join(&address));
        let schema = br#"{"db_name":"Talk signing regression","db_file":"talk.db","version":2,
            "maps":{"data/public.json":{"to_table":[{"node":"topic","table":"topic"}]}},
            "tables":{"topic":{"cols":[["title","TEXT"],["json_id","INTEGER"]]}}}"#;
        let topics = br#"{"topic":[{"title":"Already accepted topic"}]}"#;
        for (path, bytes) in [
            ("dbschema.json", schema.as_slice()),
            ("data/public.json", topics.as_slice()),
            (SETTINGS, INITIAL),
        ] {
            storage.write(path, bytes).unwrap();
        }
        let entry =
            |bytes: &[u8]| json!({"sha512": XiteStorage::hash_bytes(bytes), "size": bytes.len()});
        let mut child = json!({
            "address": address, "inner_path": MANIFEST, "modified": 1,
            "files": {"admin-settings.json": entry(INITIAL)},
        });
        let mut rules = json!({"signers_required":1,"max_size":max_size});
        if other_file_kinds {
            let optional = b"optional data";
            storage.write(OPTIONAL, optional).unwrap();
            child["files_optional"] = json!({"optional.bin":entry(optional)});
            child["files_merged"] = json!({"records.json":{"class":"epix-orset-1"}});
            rules["merge_files"] =
                json!({"records.json":{"class":"epix-orset-1","max_size":100_000}});
            storage
                .write(
                    MERGED,
                    &serde_json::to_vec(&epix_content::make_container(Vec::new())).unwrap(),
                )
                .unwrap();
        }
        epix_content::sign(&mut child, &key).unwrap();
        storage
            .write(MANIFEST, &serde_json::to_vec(&child).unwrap())
            .unwrap();
        let mut root = json!({
            "address": address, "modified": 1,
            "files": {"dbschema.json": entry(schema), "data/public.json": entry(topics)},
            "includes": {(MANIFEST):rules},
        });
        epix_content::sign(&mut root, &key).unwrap();
        storage
            .write("content.json", &serde_json::to_vec(&root).unwrap())
            .unwrap();
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root),
                },
            )
            .await;
        let fixture = Self {
            directory,
            state,
            address,
            key,
            storage,
        };
        let snapshot = fixture.snapshot().await;
        assert_eq!(snapshot.rows[0]["title"], "Already accepted topic");
        assert!(snapshot.accepted.contains_key(MANIFEST));
        fixture
    }

    async fn snapshot(&self) -> Snapshot {
        let rows = self
            .state
            .db_query(&self.address, QUERY, &Value::Null)
            .await
            .unwrap();
        Snapshot {
            settings: self.storage.read(SETTINGS).unwrap(),
            manifest: self.storage.read(MANIFEST).unwrap(),
            old_settings: self.storage.read(&format!("{SETTINGS}-old")).ok(),
            accepted: self
                .state
                .verified_manifest_snapshot(&self.address)
                .await
                .unwrap()
                .1,
            verified_epoch: self.state.verified_index_epoch(&self.address),
            source_epoch: self.state.db_source_epoch(&self.address),
            rows,
        }
    }

    async fn assert_unchanged(&self, before: &Snapshot) {
        assert_eq!(self.storage.read(SETTINGS).unwrap(), before.settings);
        assert_eq!(self.storage.read(MANIFEST).unwrap(), before.manifest);
        assert_eq!(
            self.storage.read(&format!("{SETTINGS}-old")).ok(),
            before.old_settings
        );
        assert_eq!(
            self.state.verified_index_epoch(&self.address),
            before.verified_epoch
        );
        assert_eq!(
            self.state.db_source_epoch(&self.address),
            before.source_epoch
        );
        assert_eq!(
            self.state
                .verified_manifest_snapshot(&self.address)
                .await
                .unwrap()
                .1,
            before.accepted
        );
        assert_eq!(
            self.state
                .db_query(&self.address, QUERY, &Value::Null)
                .await
                .unwrap(),
            before.rows,
            "an unrelated accepted topic must remain queryable"
        );
        assert_eq!(
            self.state.db_source_epoch(&self.address),
            before.source_epoch
        );
    }

    async fn write(&self, replacement: &[u8], expected: &[u8]) -> Result<(), String> {
        self.state
            .write_file_signed(
                &self.address,
                SETTINGS,
                replacement,
                expected,
                Some(self.key.clone()),
                None,
            )
            .await
    }

    async fn assert_committed(&self, expected: &[u8], oldest: &[u8], rows: &[Value]) {
        assert_eq!(self.storage.read(SETTINGS).unwrap(), expected);
        assert_eq!(
            self.storage.read(&format!("{SETTINGS}-old")).unwrap(),
            oldest
        );
        let manifest: Value =
            serde_json::from_slice(&self.storage.read(MANIFEST).unwrap()).unwrap();
        assert!(epix_content::verify_signer(&manifest, &self.address));
        assert_eq!(
            manifest["files"]["admin-settings.json"]["sha512"],
            XiteStorage::hash_bytes(expected)
        );
        assert_eq!(
            manifest["files"]["admin-settings.json"]["size"],
            expected.len() as u64
        );
        assert_eq!(
            self.state
                .verified_manifest_snapshot(&self.address)
                .await
                .unwrap()
                .1
                .get(MANIFEST),
            Some(&manifest)
        );
        assert_eq!(
            self.state
                .db_query(&self.address, QUERY, &Value::Null)
                .await
                .unwrap(),
            rows
        );
        self.assert_no_staged_artifacts().await;
    }

    async fn assert_no_staged_artifacts(&self) {
        let staging = self.directory.path().join("data/.epix-stage");
        tokio::time::timeout(Duration::from_secs(2), async {
            while contains_files(&staging) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a completed edit left staged bytes or a promotion journal behind");
    }
}

fn contains_files(path: &Path) -> bool {
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries.any(|entry| {
            let path = entry.unwrap().path();
            path.is_file() || contains_files(&path)
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("could not inspect staging artifacts: {error}"),
    }
}

#[tokio::test]
async fn rejected_signer_preserves_queries_and_authorized_retry_commits() {
    let fixture = Fixture::new(100_000, false).await;
    let before = fixture.snapshot().await;
    let error = fixture
        .state
        .write_file_signed(
            &fixture.address,
            SETTINGS,
            DRAFT,
            INITIAL,
            Some(epix_crypt::new_seed()),
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(error, "crypto: Valid signs: 0/1");
    fixture.assert_unchanged(&before).await;
    fixture.assert_no_staged_artifacts().await;

    fixture.write(DRAFT, INITIAL).await.unwrap();
    fixture.assert_committed(DRAFT, INITIAL, &before.rows).await;
    assert_ne!(fixture.storage.read(MANIFEST).unwrap(), before.manifest);
    assert!(fixture.state.db_source_epoch(&fixture.address) > before.source_epoch);
}

#[tokio::test]
async fn stale_expected_bytes_preserve_the_accepted_winner() {
    let fixture = Fixture::new(100_000, false).await;
    fixture.write(DRAFT, INITIAL).await.unwrap();
    let winner = fixture.snapshot().await;
    let error = fixture.write(OTHER_DRAFT, INITIAL).await.unwrap_err();
    assert!(error.contains("File changed since it was read"), "{error}");
    fixture.assert_unchanged(&winner).await;
    fixture.assert_no_staged_artifacts().await;
}

#[tokio::test]
async fn committed_edits_keep_the_first_snapshot_until_diffs_are_taken() {
    let fixture = Fixture::new(100_000, false).await;
    let before = fixture.snapshot().await;
    fixture.write(DRAFT, INITIAL).await.unwrap();
    fixture.assert_committed(DRAFT, INITIAL, &before.rows).await;
    fixture.write(OTHER_DRAFT, DRAFT).await.unwrap();
    fixture
        .assert_committed(OTHER_DRAFT, INITIAL, &before.rows)
        .await;

    let diffs = fixture.state.take_diffs(&fixture.address, MANIFEST).await;
    let actions = diffs
        .get("admin-settings.json")
        .expect("committed edits need an inline diff");
    assert_eq!(
        epix_content::diff::patch(INITIAL, actions).unwrap(),
        OTHER_DRAFT
    );
    assert!(!fixture.storage.exists(&format!("{SETTINGS}-old")));

    fixture.write(DRAFT, OTHER_DRAFT).await.unwrap();
    fixture
        .assert_committed(DRAFT, OTHER_DRAFT, &before.rows)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_same_base_writes_have_one_accepted_winner() {
    let fixture = Fixture::new(100_000, false).await;
    let before = fixture.snapshot().await;
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let mut writers = Vec::new();
    for replacement in [DRAFT, OTHER_DRAFT] {
        let state = fixture.state.clone();
        let address = fixture.address.clone();
        let key = fixture.key.clone();
        let barrier = barrier.clone();
        writers.push(tokio::spawn(async move {
            barrier.wait().await;
            (
                replacement,
                state
                    .write_file_signed(&address, SETTINGS, replacement, INITIAL, Some(key), None)
                    .await,
            )
        }));
    }
    barrier.wait().await;
    let results = tokio::time::timeout(Duration::from_secs(5), async {
        let mut results = Vec::new();
        for writer in writers {
            results.push(writer.await.unwrap());
        }
        results
    })
    .await
    .expect("concurrent signed edits did not complete");
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        1
    );
    let winner = results.iter().find(|(_, result)| result.is_ok()).unwrap().0;
    let error = results
        .iter()
        .find_map(|(_, result)| result.as_ref().err())
        .unwrap();
    assert!(error.contains("File changed since it was read"), "{error}");
    fixture
        .assert_committed(winner, INITIAL, &before.rows)
        .await;
}

#[tokio::test]
async fn staging_io_failure_preserves_live_files_and_queries() {
    let fixture = Fixture::new(100_000, false).await;
    let before = fixture.snapshot().await;
    let staging = fixture.directory.path().join("data/.epix-stage");
    std::fs::write(&staging, b"stage blocker").unwrap();
    assert!(fixture.write(DRAFT, INITIAL).await.is_err());
    fixture.assert_unchanged(&before).await;
    assert_eq!(std::fs::read(&staging).unwrap(), b"stage blocker");
    std::fs::remove_file(&staging).unwrap();
    fixture.assert_no_staged_artifacts().await;
    fixture.write(DRAFT, INITIAL).await.unwrap();
    fixture.assert_committed(DRAFT, INITIAL, &before.rows).await;
}

#[tokio::test]
async fn include_size_limit_checks_the_replacement_bytes() {
    let fixture = Fixture::new(2_048, false).await;
    let before = fixture.snapshot().await;
    let oversized = serde_json::to_vec(&json!({"pinned_topic_uris":["x".repeat(4_096)]})).unwrap();
    let error = fixture.write(&oversized, INITIAL).await.unwrap_err();
    assert!(error.contains("Include too large"), "{error}");
    fixture.assert_unchanged(&before).await;
    fixture.assert_no_staged_artifacts().await;
}

#[tokio::test]
async fn signed_write_rejects_paths_outside_required_child_files() {
    let fixture = Fixture::new(100_000, true).await;
    let before = fixture.snapshot().await;
    for (path, reason) in [
        ("content.json", "normal child data file"),
        (MANIFEST, "normal child data file"),
        ("data/public.json", "child content.json"),
        (
            "data/admin/undeclared.json",
            "existing required hashed file",
        ),
        (OPTIONAL, "existing required hashed file"),
        (MERGED, "existing required hashed file"),
    ] {
        let original = fixture.storage.read(path).ok();
        let error = fixture
            .state
            .write_file_signed(
                &fixture.address,
                path,
                b"{}",
                original.as_deref().unwrap_or(b"{}"),
                Some(fixture.key.clone()),
                None,
            )
            .await
            .expect_err(path);
        assert!(error.contains(reason), "{path}: {error}");
        assert_eq!(fixture.storage.read(path).ok(), original, "{path}");
        fixture.assert_unchanged(&before).await;
        fixture.assert_no_staged_artifacts().await;
    }
}
