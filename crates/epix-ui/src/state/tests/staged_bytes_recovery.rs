//! Digest-addressed local stages must obey the same crash journal contract as objects.

use super::*;
use tempfile::tempdir;

const SETTINGS: &str = "data/admin/admin-settings.json";
const SNAPSHOT: &str = "data/admin/admin-settings.json-old";
const MANIFEST: &str = "data/admin/content.json";
const BEFORE: &[u8] = br#"{"pinned_topic_uris":[]}"#;
const AFTER: &[u8] = br#"{"pinned_topic_uris":["42_writer.epix"]}"#;

struct Fixture {
    directory: tempfile::TempDir,
    storage: XiteStorage,
    state: Arc<AppState>,
    address: String,
    key: String,
    root: Value,
    old_child: Vec<u8>,
    new_child: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempdir().unwrap();
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(directory.path().join("data").join(&address));
        let schema = br#"{"db_name":"Recovery test","db_file":"talk.db","version":2,
            "maps":{"data/public.json":{"to_table":[{"node":"topic","table":"topic"}]}},
            "tables":{"topic":{"cols":[["title","TEXT"],["json_id","INTEGER"]]}}}"#;
        let topics = br#"{"topic":[{"title":"Accepted topic"}]}"#;
        let entry =
            |bytes: &[u8]| json!({"size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes)});
        let child = |bytes: &[u8], modified: u64| {
            let mut child = json!({
                "address": address, "inner_path": MANIFEST, "modified": modified,
                "files": {"admin-settings.json": entry(bytes)},
            });
            epix_content::sign(&mut child, &key).unwrap();
            serde_json::to_vec(&child).unwrap()
        };
        let old_child = child(BEFORE, 1);
        let new_child = child(AFTER, 2);
        let mut root = json!({
            "address": address, "modified": 1,
            "files": {"dbschema.json": entry(schema), "data/public.json": entry(topics)},
            "includes": {(MANIFEST): {"signers_required": 1}},
        });
        epix_content::sign(&mut root, &key).unwrap();
        for (inner, bytes) in [
            ("dbschema.json", schema.as_slice()),
            ("data/public.json", topics.as_slice()),
            (SETTINGS, BEFORE),
            (MANIFEST, old_child.as_slice()),
        ] {
            storage.write(inner, bytes).unwrap();
        }
        storage
            .write("content.json", &serde_json::to_vec(&root).unwrap())
            .unwrap();
        Self {
            directory,
            storage,
            state: AppState::new("test"),
            address,
            key,
            root,
            old_child,
            new_child,
        }
    }

    async fn transaction(&self, candidate: &[u8]) -> ManifestTransaction {
        let guard = self
            .state
            .acquire_manifest_guard(&self.address, MANIFEST)
            .await
            .unwrap();
        AppState::bind_manifest_transaction(
            &self.storage,
            &self.address,
            MANIFEST,
            candidate,
            guard,
        )
        .unwrap()
    }

    fn stage(&self, transaction: &ManifestTransaction, inner: &str, bytes: &[u8]) -> String {
        let staged = transaction
            .lease
            .register_staged_bytes(&self.storage, inner, bytes)
            .unwrap();
        assert_eq!(
            staged,
            format!("objects/{}/{inner}", epix_blob::ObjId::of(bytes))
        );
        XiteStorage::new(transaction.lease.stage_root.clone())
            .write_atomic_durable(&staged, bytes)
            .unwrap();
        staged
    }
}

async fn recover_edit(phase: &str) {
    let fixture = Fixture::new();
    let transaction = fixture.transaction(&fixture.new_child).await;
    fixture.stage(&transaction, SETTINGS, AFTER);
    fixture.stage(&transaction, SNAPSHOT, BEFORE);
    let mut promotion =
        AppState::begin_staged_promotion(&fixture.storage, &transaction, &[], &[], None).unwrap();
    if phase != "journal" {
        promotion.apply().unwrap();
    }
    if phase == "committed" {
        fixture
            .storage
            .write_atomic_durable(MANIFEST, &fixture.new_child)
            .unwrap();
        promotion
            .mark_manifest_committed(&fixture.storage.path(MANIFEST).unwrap())
            .unwrap();
    }
    let journal_path = promotion.journal_path.clone();
    transaction.lease.disarm_cleanup();
    drop(promotion);
    drop(transaction);

    // A new state instance uses the real restart path, before exposing the xite.
    let recovered = AppState::new("test");
    recovered
        .add_xite(
            &fixture.address,
            XiteEntry {
                storage: fixture.storage.clone(),
                content: Some(fixture.root.clone()),
            },
        )
        .await;
    let committed = phase == "committed";
    let expected = if committed { AFTER } else { BEFORE };
    let expected_child = if committed {
        &fixture.new_child
    } else {
        &fixture.old_child
    };
    assert_eq!(fixture.storage.read(SETTINGS).unwrap(), expected, "{phase}");
    assert_eq!(
        fixture.storage.read(MANIFEST).unwrap(),
        *expected_child,
        "{phase}"
    );
    assert_eq!(
        fixture.storage.read(SNAPSHOT).ok(),
        committed.then(|| BEFORE.to_vec()),
        "{phase}"
    );
    let child: Value = serde_json::from_slice(expected_child).unwrap();
    assert_eq!(
        recovered
            .verified_manifest_snapshot(&fixture.address)
            .await
            .unwrap()
            .1
            .get(MANIFEST),
        Some(&child)
    );
    let rows = recovered
        .db_query(&fixture.address, "SELECT title FROM topic", &Value::Null)
        .await
        .unwrap();
    assert_eq!(rows[0]["title"], "Accepted topic");
    assert!(
        journal_path.is_file(),
        "Store reconciliation must finish before journal cleanup"
    );

    let store = Arc::new(
        epix_blob::store::Store::open_with(
            fixture.directory.path().join("store"),
            epix_blob::store::StoreConfig {
                xite_root: Some(fixture.directory.path().join("data")),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    recovered.set_edx_store(store).await.unwrap();
    assert!(!journal_path.exists());
    assert_eq!(fixture.storage.read(SETTINGS).unwrap(), expected);
    assert_eq!(
        fixture.storage.read(SNAPSHOT).ok(),
        committed.then(|| BEFORE.to_vec())
    );
    if committed {
        let diffs = recovered.take_diffs(&fixture.address, MANIFEST).await;
        assert!(
            diffs.contains_key("admin-settings.json"),
            "the recovered first snapshot must still support publication"
        );
    }
}

#[tokio::test]
async fn staged_bytes_recovery_restores_settings_and_removes_snapshot_before_manifest_commit() {
    for phase in ["journal", "promoted"] {
        recover_edit(phase).await;
    }
}

#[tokio::test]
async fn staged_bytes_recovery_finishes_settings_and_snapshot_after_manifest_commit() {
    recover_edit("committed").await;
}

#[tokio::test]
async fn staged_bytes_registration_is_idempotent_and_preserves_conflicting_stages() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction(&fixture.new_child).await;
    let original = fixture.stage(&transaction, SETTINGS, AFTER);
    assert_eq!(
        transaction
            .lease
            .register_staged_bytes(&fixture.storage, SETTINGS, AFTER)
            .unwrap(),
        original
    );
    assert!(transaction
        .lease
        .register_staged_bytes(&fixture.storage, SETTINGS, BEFORE)
        .unwrap_err()
        .contains("conflicting"));
    let staged = transaction.lease.staged_file(SETTINGS).unwrap();
    assert_eq!(staged.staged_inner, original);
    assert_eq!(std::fs::read(staged.staged_path).unwrap(), AFTER);

    let pending = "data/admin/pending.json";
    let pending_path = transaction
        .lease
        .register_staged(&fixture.storage, pending, None)
        .unwrap();
    assert!(transaction
        .lease
        .register_staged_bytes(&fixture.storage, pending, BEFORE)
        .unwrap_err()
        .contains("conflicting"));
    assert_eq!(
        transaction.lease.staged_file(pending).unwrap().staged_inner,
        pending_path
    );
    let merged = "data/admin/records.json";
    transaction
        .lease
        .register_staged_merge(&fixture.storage, merged)
        .unwrap();
    assert!(transaction
        .lease
        .register_staged_bytes(&fixture.storage, merged, BEFORE)
        .unwrap_err()
        .contains("conflicting"));
}

#[tokio::test]
async fn staged_snapshot_rejects_a_portable_case_alias_of_a_candidate_file() {
    let fixture = Fixture::new();
    let alias = "data/admin/ADMIN-SETTINGS.JSON-OLD";
    fixture.storage.write(alias, BEFORE).unwrap();
    let mut child: Value = serde_json::from_slice(&fixture.new_child).unwrap();
    child["files"]["ADMIN-SETTINGS.JSON-OLD"] =
        json!({"size": BEFORE.len(), "sha512": XiteStorage::hash_bytes(BEFORE)});
    epix_content::sign(&mut child, &fixture.key).unwrap();
    let transaction = fixture
        .transaction(&serde_json::to_vec(&child).unwrap())
        .await;
    fixture.stage(&transaction, SETTINGS, AFTER);
    fixture.stage(&transaction, SNAPSHOT, BEFORE);
    let error =
        match AppState::begin_staged_promotion(&fixture.storage, &transaction, &[], &[], None) {
            Ok(_) => panic!("a reserved snapshot aliased a candidate file"),
            Err(error) => error,
        };
    assert!(error.contains("case-aliases candidate"), "{error}");
    assert_eq!(fixture.storage.read(SETTINGS).unwrap(), BEFORE);
    assert_eq!(fixture.storage.read(alias).unwrap(), BEFORE);
    // On a case-insensitive filesystem SNAPSHOT resolves to the existing
    // alias. Its bytes above must stay untouched when the promotion rejects.
}

#[tokio::test]
async fn staged_bytes_cannot_alias_the_governing_manifest() {
    let fixture = Fixture::new();
    let transaction = fixture.transaction(&fixture.new_child).await;
    fixture.stage(&transaction, "data/admin/CONTENT.JSON", BEFORE);
    let error =
        match AppState::begin_staged_promotion(&fixture.storage, &transaction, &[], &[], None) {
            Ok(_) => panic!("a staged auxiliary file aliased the governing manifest"),
            Err(error) => error,
        };
    assert!(error.contains("aliases governing manifest"), "{error}");
    assert_eq!(fixture.storage.read(MANIFEST).unwrap(), fixture.old_child);
}

async fn publication_waits_for_promotion(committed: bool) {
    let fixture = Fixture::new();
    fixture
        .state
        .add_xite(
            &fixture.address,
            XiteEntry {
                storage: fixture.storage.clone(),
                content: Some(fixture.root.clone()),
            },
        )
        .await;
    let transaction = fixture.transaction(&fixture.new_child).await;
    let tree = fixture
        .state
        .tree_mutation_lock(&fixture.address)
        .lock_owned()
        .await;
    fixture.stage(&transaction, SETTINGS, AFTER);
    fixture.stage(&transaction, SNAPSHOT, BEFORE);
    let mut promotion =
        AppState::begin_staged_promotion(&fixture.storage, &transaction, &[], &[], None).unwrap();
    promotion.apply().unwrap();

    // The publisher starts after the new bytes and snapshot reached their
    // final paths, while this transaction still owns their rollback authority.
    let (started, running) = tokio::sync::oneshot::channel();
    let publish_state = fixture.state.clone();
    let address = fixture.address.clone();
    let mut publisher = tokio::spawn(async move {
        started.send(()).unwrap();
        publish_state.take_diffs(&address, MANIFEST).await
    });
    running.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut publisher)
            .await
            .is_err(),
        "publication consumed a snapshot still owned by an unfinished promotion"
    );
    assert_eq!(fixture.storage.read(SNAPSHOT).unwrap(), BEFORE);

    if committed {
        fixture
            .storage
            .write_atomic_durable(MANIFEST, &fixture.new_child)
            .unwrap();
        promotion
            .mark_manifest_committed(&fixture.storage.path(MANIFEST).unwrap())
            .unwrap();
        let (_, warnings, _) = promotion.finish(&transaction);
        assert!(warnings.is_empty(), "{warnings:?}");
    } else {
        // An error after file promotion must still be able to restore every
        // original byte; publication cannot remove an input needed by rollback.
        promotion.rollback(&fixture.storage, MANIFEST).unwrap();
        assert_eq!(fixture.storage.read(SETTINGS).unwrap(), BEFORE);
        assert_eq!(fixture.storage.read(MANIFEST).unwrap(), fixture.old_child);
    }
    drop(tree);
    transaction.lease.release_manifest_mutex();
    transaction.lease.release_activation();
    let diffs = tokio::time::timeout(std::time::Duration::from_secs(5), publisher)
        .await
        .expect("publication did not resume after the transaction completed")
        .unwrap();
    assert_eq!(diffs.contains_key("admin-settings.json"), committed);
    assert!(!fixture.storage.exists(SNAPSHOT));
    assert_eq!(
        fixture.storage.read(SETTINGS).unwrap(),
        if committed { AFTER } else { BEFORE }
    );
}

#[tokio::test]
async fn staged_bytes_recovery_publication_waits_for_rollback() {
    publication_waits_for_promotion(false).await;
}

#[tokio::test]
async fn staged_bytes_recovery_publication_waits_for_commit() {
    publication_waits_for_promotion(true).await;
}
