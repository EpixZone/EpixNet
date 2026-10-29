use epix_db::{DbSchema, DerivedIndex, SourceVersion};
use serde_json::{json, Value};

fn schema() -> DbSchema {
    serde_json::from_value(json!({
        "version": 3, "db_file": "data.db",
        "maps": {
            ".*/data/users/[^/]+/content.json$": {"to_json_table": ["cert_user_id"], "file_name": "data.json"},
            ".*/data/users/[^/]+/data.json$": {"to_json_table": ["user_name"], "to_table": ["post"], "to_keyvalue": ["next_id"]},
            ".*/data/users/[^/]+/posts.json$": {"to_table": ["post"], "file_name": "data.json"}
        },
        "tables": {"post": {
            "cols": [["post_id", "INTEGER"], ["body", "TEXT NOT NULL"], ["json_id", "INTEGER"]],
            "indexes": ["CREATE UNIQUE INDEX post_key ON post(json_id,post_id)"]
        }}
    })).unwrap()
}

fn version(value: &Value, authority: &str) -> SourceVersion {
    SourceVersion {
        digest: value.to_string(),
        authority: authority.into(),
    }
}

fn put(index: &DerivedIndex, hub: &str, path: &str, value: Value) -> epix_db::DeltaMetrics {
    let expected = index.source(hub, path).unwrap();
    index
        .apply_source(
            hub,
            path,
            &version(&value, "verified-v1"),
            &value,
            expected.as_ref(),
        )
        .unwrap()
}

fn rows(index: &DerivedIndex) -> Vec<Value> {
    index.database().query_untrusted(
        "SELECT site,directory,cert_user_id,user_name,post_id,body FROM post JOIN json USING(json_id) ORDER BY site,directory,post_id", &Value::Null,
    ).unwrap()
}

#[test]
fn sibling_sources_replay_only_their_component_and_restore_shadowed_rows() {
    let dir = tempfile::tempdir().unwrap();
    let index = DerivedIndex::open(dir.path().join("cache.db"), &schema(), "context").unwrap();
    // Arrival order differs from canonical full population order.
    put(
        &index,
        "hub-a",
        "data/users/alice/posts.json",
        json!({"post":[{"post_id":1,"body":"signed"}]}),
    );
    put(
        &index,
        "hub-a",
        "data/users/alice/content.json",
        json!({"cert_user_id":"alice@xid"}),
    );
    put(
        &index,
        "hub-a",
        "data/users/alice/data.json",
        json!({"user_name":"Alice","next_id":2,"post":[{"post_id":1,"body":"legacy"}]}),
    );
    put(
        &index,
        "hub-a",
        "data/users/bob/data.json",
        json!({"user_name":"Bob","post":[{"post_id":2,"body":"unrelated"}]}),
    );
    let prior = rows(&index);
    assert_eq!(prior[0]["body"], "signed");
    assert_eq!(prior[0]["cert_user_id"], "alice@xid");
    let metrics = put(
        &index,
        "hub-a",
        "data/users/alice/data.json",
        json!({"user_name":"Alice updated","post":[{"post_id":1,"body":"legacy updated"}]}),
    );
    assert_eq!(metrics.replayed_sources, 3);
    assert_eq!(metrics.affected_targets, 3);
    assert_eq!(rows(&index)[0]["body"], "signed");
    assert_eq!(rows(&index)[0]["user_name"], "Alice updated");
    assert_eq!(rows(&index)[1], prior[1]);
    let expected = index
        .source("hub-a", "data/users/alice/content.json")
        .unwrap()
        .unwrap();
    index
        .remove_source("hub-a", "data/users/alice/content.json", &expected)
        .unwrap();
    assert_eq!(rows(&index)[0]["cert_user_id"], Value::Null);
    assert_eq!(rows(&index)[0]["user_name"], "Alice updated");
    let expected = index
        .source("hub-a", "data/users/alice/posts.json")
        .unwrap()
        .unwrap();
    index
        .remove_source("hub-a", "data/users/alice/posts.json", &expected)
        .unwrap();
    assert_eq!(rows(&index)[0]["body"], "legacy updated");
    assert_eq!(index.sources("hub-a").unwrap().len(), 2);
    assert_eq!(index.sources_all().unwrap().len(), 2);
}

#[test]
fn cache_restart_preserves_rows_and_rejects_context_or_same_version_schema_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let source = "data/users/alice/data.json";
    let data = json!({"user_name":"Alice","post":[{"post_id":1,"body":"persisted"}]});
    {
        let index = DerivedIndex::open(&path, &schema(), "trusted-context").unwrap();
        put(&index, "hub-a", source, data.clone());
    }
    let reopened = DerivedIndex::open(&path, &schema(), "trusted-context").unwrap();
    assert_eq!(rows(&reopened)[0]["body"], "persisted");
    let expected = reopened.source("hub-a", source).unwrap().unwrap();
    let metrics = reopened
        .apply_source("hub-a", source, &expected, &data, Some(&expected))
        .unwrap();
    assert_eq!(metrics.skipped_sources, 1);
    assert_eq!(metrics.sql_changes, 0);
    assert!(DerivedIndex::open(&path, &schema(), "other-context").is_err());
    let mut changed = schema();
    changed.maps.values_mut().next().unwrap().file_name = Some("profile.json".into());
    assert!(DerivedIndex::open(&path, &changed, "trusted-context").is_err());
    assert_eq!(rows(&reopened)[0]["body"], "persisted");
}

#[test]
fn cas_rejects_stale_updates_removals_and_reused_versions_without_changing_data() {
    let dir = tempfile::tempdir().unwrap();
    let index = DerivedIndex::open(dir.path().join("cache.db"), &schema(), "context").unwrap();
    let path = "data/users/alice/data.json";
    let first = json!({"post":[{"post_id":1,"body":"first"}]});
    let second = json!({"post":[{"post_id":1,"body":"second"}]});
    put(&index, "hub-a", path, first.clone());
    let old = index.source("hub-a", path).unwrap().unwrap();
    put(&index, "hub-a", path, second.clone());
    let current = index.source("hub-a", path).unwrap().unwrap();
    assert!(index
        .apply_source("hub-a", path, &current, &second, Some(&old))
        .is_err());
    assert!(index
        .apply_source("hub-a", path, &old, &first, None)
        .is_err());
    assert!(index.remove_source("hub-a", path, &old).is_err());
    assert!(index
        .apply_source("hub-a", path, &current, &first, Some(&current))
        .is_err());
    assert_eq!(rows(&index)[0]["body"], "second");
    assert_eq!(index.source("hub-a", path).unwrap(), Some(current));
}

#[test]
fn authority_only_update_skips_projection_but_changed_accepted_records_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let index = DerivedIndex::open(dir.path().join("cache.db"), &schema(), "context").unwrap();
    let path = "data/users/alice/data.json";
    let data = json!({"post":[{"post_id":1,"body":"verified"}]});
    put(&index, "hub-a", path, data.clone());
    let old = index.source("hub-a", path).unwrap().unwrap();
    let next = SourceVersion {
        digest: old.digest.clone(),
        authority: "authority-v2".into(),
    };
    let metrics = index
        .apply_source("hub-a", path, &next, &data, Some(&old))
        .unwrap();
    assert_eq!(metrics.changed_sources, 1);
    assert_eq!(metrics.replayed_sources, 0);
    assert_eq!(metrics.sql_changes, 1);
    let third = SourceVersion {
        digest: old.digest,
        authority: "authority-v3".into(),
    };
    let metrics = index
        .apply_source("hub-a", path, &third, &json!({"post":[]}), Some(&next))
        .unwrap();
    assert_eq!(metrics.replayed_sources, 1);
    assert!(rows(&index).is_empty());
}

#[test]
fn failed_row_constraint_rolls_back_the_ledger_and_all_sibling_projections() {
    let dir = tempfile::tempdir().unwrap();
    let index = DerivedIndex::open(dir.path().join("cache.db"), &schema(), "context").unwrap();
    let path = "data/users/alice/data.json";
    put(
        &index,
        "hub-a",
        path,
        json!({"user_name":"Alice","post":[{"post_id":1,"body":"old"}]}),
    );
    let old = index.source("hub-a", path).unwrap().unwrap();
    let bad = json!({"user_name":"Bad","post":[{"post_id":2,"body":"partial"},{"post_id":3}]});
    assert!(index
        .apply_source(
            "hub-a",
            path,
            &version(&bad, "verified-v1"),
            &bad,
            Some(&old)
        )
        .is_err());
    assert_eq!(index.source("hub-a", path).unwrap(), Some(old));
    assert_eq!(rows(&index)[0]["body"], "old");
    assert_eq!(rows(&index)[0]["user_name"], "Alice");
    // A rolled-back guard must not poison the next checked-out connection.
    put(
        &index,
        "hub-a",
        path,
        json!({"user_name":"Recovered","post":[{"post_id":1,"body":"new"}]}),
    );
    assert_eq!(rows(&index)[0]["body"], "new");
}

#[test]
fn global_unique_collisions_fail_closed_but_same_target_replacement_is_preserved() {
    for index_sql in [
        "CREATE UNIQUE INDEX post_key ON post(post_id)",
        "CREATE UNIQUE INDEX post_key ON post(lower(body)) WHERE post_id > 0",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut definition = schema();
        definition.tables.get_mut("post").unwrap().indexes = vec![index_sql.into()];
        let index =
            DerivedIndex::open(dir.path().join("cache.db"), &definition, "context").unwrap();
        let path = "data/users/alice/data.json";
        put(
            &index,
            "hub-a",
            path,
            json!({"post":[{"post_id":1,"body":"same"},{"post_id":1,"body":"SAME"}]}),
        );
        assert_eq!(rows(&index).len(), 1);
        assert_eq!(rows(&index)[0]["body"], "SAME");
        let collision = json!({"post":[{"post_id":1,"body":"same"}]});
        assert!(index
            .apply_source(
                "hub-b",
                path,
                &version(&collision, "verified"),
                &collision,
                None
            )
            .is_err());
        assert!(index.source("hub-b", path).unwrap().is_none());
        assert_eq!(rows(&index).len(), 1);
        assert_eq!(rows(&index)[0]["site"], "hub-a");
    }
}

#[test]
fn internal_metadata_is_not_accessible_through_untrusted_sql_or_schema() {
    let dir = tempfile::tempdir().unwrap();
    let index = DerivedIndex::open(dir.path().join("cache.db"), &schema(), "context").unwrap();
    for sql in [
        "SELECT * FROM __epix_sources",
        "SELECT * FROM \"__EPIX_DERIVED_META\"",
        "WITH ledger AS (SELECT value FROM __epix_sources) SELECT * FROM ledger",
        "DELETE FROM __epix_sources",
        "DROP TABLE __epix_sources",
    ] {
        assert!(
            index.database().query_untrusted(sql, &Value::Null).is_err(),
            "{sql}"
        );
    }
    let mut reserved = schema();
    reserved
        .tables
        .insert("__EPIX_sources".into(), reserved.tables["post"].clone());
    assert!(DerivedIndex::open(dir.path().join("reserved.db"), &reserved, "context").is_err());
    let mut reserved_index = schema();
    reserved_index.tables.get_mut("post").unwrap().indexes =
        vec!["CREATE INDEX __EPIX_custom ON post(body)".into()];
    assert!(DerivedIndex::open(
        dir.path().join("reserved-index.db"),
        &reserved_index,
        "context"
    )
    .is_err());
    let mut reserved_map = schema();
    reserved_map.maps.values_mut().next().unwrap().to_table =
        vec![epix_db::ToTable::Simple("__epix_sources".into())];
    assert!(
        DerivedIndex::open(dir.path().join("reserved-map.db"), &reserved_map, "context").is_err()
    );
}

#[test]
fn unmatched_json_is_not_retained_and_source_paths_are_normalized() {
    let dir = tempfile::tempdir().unwrap();
    let index = DerivedIndex::open(dir.path().join("cache.db"), &schema(), "context").unwrap();
    let data = json!({"large":"unrelated app payload"});
    assert!(!index.matches_source("hub-a", "other.json").unwrap());
    assert_eq!(
        index
            .apply_source(
                "hub-a",
                "other.json",
                &version(&data, "verified"),
                &data,
                None
            )
            .unwrap()
            .skipped_sources,
        1
    );
    assert!(index.sources_all().unwrap().is_empty());
    for path in [
        "/data.json",
        "../data.json",
        "data//data.json",
        "data/./data.json",
        "data\\data.json",
    ] {
        assert!(index.matches_source("hub-a", path).is_err());
    }
}

#[test]
fn concurrent_compare_and_swap_commits_exactly_one_version() {
    let dir = tempfile::tempdir().unwrap();
    let index = DerivedIndex::open(dir.path().join("cache.db"), &schema(), "context").unwrap();
    let path = "data/users/alice/data.json";
    put(
        &index,
        "hub-a",
        path,
        json!({"post":[{"post_id":1,"body":"old"}]}),
    );
    let old = index.source("hub-a", path).unwrap().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = ["left", "right"].map(|body| {
        let index = index.clone();
        let old = old.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let data = json!({"post":[{"post_id":1,"body":body}]});
            barrier.wait();
            index
                .apply_source(
                    "hub-a",
                    path,
                    &version(&data, "verified-v1"),
                    &data,
                    Some(&old),
                )
                .is_ok()
        })
    });
    assert_eq!(
        handles
            .into_iter()
            .map(|handle| u8::from(handle.join().unwrap()))
            .sum::<u8>(),
        1
    );
    assert_eq!(rows(&index).len(), 1);
}

#[test]
fn damaged_and_incomplete_caches_have_a_recoverable_open_error() {
    let dir = tempfile::tempdir().unwrap();
    let garbage = dir.path().join("garbage.db");
    std::fs::write(&garbage, b"this is not a database").unwrap();
    let error = DerivedIndex::open(&garbage, &schema(), "context")
        .err()
        .unwrap();
    assert!(DerivedIndex::is_recoverable_cache_error(&error), "{error}");
    for (name, damage) in [
        ("projection", "DROP TABLE post"),
        ("ledger", "DROP TABLE __epix_source_targets"),
        ("app-index", "DROP INDEX post_key"),
        ("source-index", "DROP INDEX __epix_source_rows_post"),
        ("checkpoint", "DELETE FROM __epix_derived_meta"),
    ] {
        let path = dir.path().join(format!("{name}.db"));
        {
            let index = DerivedIndex::open(&path, &schema(), "context").unwrap();
            put(
                &index,
                "hub-a",
                "data/users/alice/data.json",
                json!({"post":[{"post_id":1,"body":"safe"}]}),
            );
        }
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(damage)
            .unwrap();
        let error = DerivedIndex::open(&path, &schema(), "context")
            .err()
            .unwrap();
        assert!(
            DerivedIndex::is_recoverable_cache_error(&error),
            "{name}: {error}"
        );
    }
    let truncated = dir.path().join("truncated.db");
    drop(DerivedIndex::open(&truncated, &schema(), "context").unwrap());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&truncated)
        .unwrap()
        .set_len(128)
        .unwrap();
    let error = DerivedIndex::open(&truncated, &schema(), "context")
        .err()
        .unwrap();
    assert!(DerivedIndex::is_recoverable_cache_error(&error), "{error}");
}

#[test]
fn invalid_application_schema_is_not_a_disposable_cache_failure() {
    let dir = tempfile::tempdir().unwrap();
    let mut invalid_schema = schema();
    invalid_schema.tables.get_mut("post").unwrap().indexes =
        vec!["CREATE INDEX bad ON post(missing_column)".into()];
    let error = DerivedIndex::open(dir.path().join("invalid.db"), &invalid_schema, "context")
        .err()
        .unwrap();
    assert!(!DerivedIndex::is_recoverable_cache_error(&error));
    let valid = DerivedIndex::open(dir.path().join("valid.db"), &schema(), "context").unwrap();
    let data = json!({"post":[{"post_id":1}]});
    let error = valid
        .apply_source(
            "hub-a",
            "data/users/alice/data.json",
            &version(&data, "verified"),
            &data,
            None,
        )
        .unwrap_err();
    assert!(!DerivedIndex::is_recoverable_cache_error(&error));
}

#[test]
fn explicit_reset_clears_ledger_and_projections_for_verified_repopulation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reset.db");
    let index = DerivedIndex::open(&path, &schema(), "context").unwrap();
    let source = "data/users/alice/data.json";
    let data = json!({"user_name":"Alice","next_id":2,"post":[{"post_id":1,"body":"restored"}]});
    put(&index, "hub-a", source, data.clone());
    let prior = index.source("hub-a", source).unwrap().unwrap();
    // Model a well-formed but damaged projection; structural checks alone
    // cannot prove that every cached row still matches its verified sources.
    index.database().execute_batch("DELETE FROM post").unwrap();
    let metrics = index.reset().unwrap();
    assert_eq!(metrics.changed_sources, 1);
    assert!(index.sources_all().unwrap().is_empty());
    assert!(rows(&index).is_empty());
    assert!(index.remove_source("hub-a", source, &prior).is_err());
    put(&index, "hub-a", source, data);
    assert_eq!(rows(&index)[0]["body"], "restored");
    assert_eq!(
        index
            .database()
            .query_untrusted(
                "SELECT value FROM keyvalue WHERE key='db.version' AND json_id=0",
                &Value::Null
            )
            .unwrap(),
        vec![json!({"value":3})]
    );
    drop(index);
    assert!(DerivedIndex::open(&path, &schema(), "context").is_ok());
}

#[test]
fn reset_handles_projection_foreign_keys_without_deletion_order_dependence() {
    let dir = tempfile::tempdir().unwrap();
    let definition: DbSchema = serde_json::from_value(json!({
        "version":3,"db_file":"data.db",
        "maps":{
            ".*/parent.json$":{"to_table":["parent"]},
            ".*/child.json$":{"to_table":["z_child"]}
        },
        "tables":{
            "parent":{"cols":[["id","INTEGER PRIMARY KEY"],["json_id","INTEGER"]]},
            "z_child":{"cols":[["id","INTEGER PRIMARY KEY"],["parent_id","INTEGER REFERENCES parent(id) ON DELETE RESTRICT"],["json_id","INTEGER"]]}
        }
    })).unwrap();
    let index = DerivedIndex::open(dir.path().join("foreign.db"), &definition, "context").unwrap();
    put(&index, "hub-a", "parent.json", json!({"parent":[{"id":1}]}));
    put(
        &index,
        "hub-a",
        "child.json",
        json!({"z_child":[{"id":1,"parent_id":1}]}),
    );
    assert_eq!(index.reset().unwrap().changed_sources, 2);
    assert!(index.sources_all().unwrap().is_empty());
    assert_eq!(
        index
            .database()
            .query_untrusted("SELECT COUNT(*) AS n FROM parent", &Value::Null)
            .unwrap(),
        vec![json!({"n":0})]
    );
}

fn cache_sibling(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn wait_for_cleanup(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while ["", "-wal", "-shm", ".retired"]
        .iter()
        .any(|suffix| cache_sibling(path, suffix).exists())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "retired cache did not close: {}",
            path.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn retirement_waits_for_database_clones_and_checked_out_readers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("leased.db");
    let index = DerivedIndex::open(&path, &schema(), "context").unwrap();
    put(
        &index,
        "hub-a",
        "data/users/alice/data.json",
        json!({"post":[{"post_id":1,"body":"still readable"}]}),
    );
    let db = index.database();
    let conn = db.conn().unwrap();
    index.retire().unwrap();
    assert!(cache_sibling(&path, ".retired").exists());
    drop(index);
    assert!(!DerivedIndex::discard_cache(&path).unwrap());
    assert_eq!(
        db.query_untrusted("SELECT body FROM post", &Value::Null)
            .unwrap(),
        vec![json!({"body":"still readable"})]
    );
    drop(db);
    assert!(path.exists());
    assert!(!DerivedIndex::discard_cache(&path).unwrap());
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM post", [], |row| row.get::<_, u64>(0))
            .unwrap(),
        1
    );
    drop(conn);
    wait_for_cleanup(&path);
}

#[test]
fn valid_same_path_open_revives_a_retired_live_cache() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("revived.db");
    let old = DerivedIndex::open(&path, &schema(), "context").unwrap();
    put(
        &old,
        "hub-a",
        "data/users/alice/data.json",
        json!({"post":[{"post_id":1,"body":"persisted"}]}),
    );
    let reader = old.database().conn().unwrap();
    old.retire().unwrap();
    let current = DerivedIndex::open(&path, &schema(), "context").unwrap();
    assert!(!cache_sibling(&path, ".retired").exists());
    drop(old);
    drop(reader);
    assert_eq!(rows(&current)[0]["body"], "persisted");
    drop(current);
    // Normal closing after revival preserves the restart cache.
    assert!(path.exists());
    let restarted = DerivedIndex::open(&path, &schema(), "context").unwrap();
    assert_eq!(rows(&restarted)[0]["body"], "persisted");
    restarted.retire().unwrap();
    drop(restarted);
    wait_for_cleanup(&path);
}

#[test]
fn invalid_reopen_does_not_revive_and_independent_handles_share_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared.db");
    let first = DerivedIndex::open(&path, &schema(), "context").unwrap();
    let second = DerivedIndex::open(&path, &schema(), "context").unwrap();
    first.retire().unwrap();
    assert!(DerivedIndex::open(&path, &schema(), "different-context").is_err());
    assert!(cache_sibling(&path, ".retired").exists());
    drop(first);
    assert!(path.exists());
    assert!(!DerivedIndex::discard_cache(&path).unwrap());
    assert!(second.sources_all().unwrap().is_empty());
    drop(second);
    wait_for_cleanup(&path);
}

#[test]
fn final_retired_drop_and_reopen_never_unlink_a_new_live_cache() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("racing.db");
    for _ in 0..24 {
        let old = DerivedIndex::open(&path, &schema(), "context").unwrap();
        old.retire().unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(2));
        let drop_start = start.clone();
        let thread = std::thread::spawn(move || {
            drop_start.wait();
            drop(old);
        });
        start.wait();
        let current = DerivedIndex::open(&path, &schema(), "context").unwrap();
        thread.join().unwrap();
        assert!(path.exists());
        put(
            &current,
            "hub-a",
            "data/users/alice/data.json",
            json!({"post":[{"post_id":1,"body":"live"}]}),
        );
        assert_eq!(rows(&current)[0]["body"], "live");
        // Exercise cleanup and recreation as well as the shared-lease path.
        current.retire().unwrap();
        drop(current);
        wait_for_cleanup(&path);
    }
}

#[test]
fn unleased_private_cache_discard_cleans_files_and_retirement_marker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("discard.db");
    for suffix in ["", "-wal", "-shm", ".retired"] {
        std::fs::write(cache_sibling(&path, suffix), "disposable").unwrap();
    }
    assert!(DerivedIndex::discard_cache(&path).unwrap());
    wait_for_cleanup(&path);
    assert!(DerivedIndex::discard_cache(&path).unwrap());
}
