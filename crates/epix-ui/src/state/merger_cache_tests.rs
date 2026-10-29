// Persistent-cache regressions use the same signed fixtures as merger tests.
async fn persistent_merger_fixture() -> (
    tempfile::TempDir,
    Arc<AppState>,
    String,
    PathBuf,
    Vec<(String, XiteEntry)>,
) {
    let (dir, source_state, merger) = merger_with_one_post().await;
    let entries = source_state
        .xites
        .read()
        .await
        .iter()
        .map(|(key, xite)| {
            (
                key.clone(),
                XiteEntry {
                    storage: xite.storage.clone(),
                    content: xite.content.clone(),
                },
            )
        })
        .collect::<Vec<_>>();
    let root = dir.path().join("persistent-node");
    let state = restore_merger_fixture(&root, &merger, &entries).await;
    (dir, state, merger, root, entries)
}

async fn restore_merger_fixture(
    root: &Path,
    merger: &str,
    entries: &[(String, XiteEntry)],
) -> Arc<AppState> {
    let state = AppState::with_data_dir("persistent-index-test", root);
    state.set_boot_restore_pending(true);
    // Force the frontend to arrive first, before its sources. Partial restore
    // must not prune and then repopulate a persisted complete aggregate.
    let frontend = entries.iter().find(|(key, _)| key == merger).unwrap();
    state
        .add_xite(
            &frontend.0,
            XiteEntry {
                storage: frontend.1.storage.clone(),
                content: frontend.1.content.clone(),
            },
        )
        .await;
    state.add_permission(merger, "Merger:EpixPost").await;
    for (key, entry) in entries.iter().filter(|(key, _)| key != merger) {
        state
            .add_xite(
                key,
                XiteEntry {
                    storage: entry.storage.clone(),
                    content: entry.content.clone(),
                },
            )
            .await;
    }
    assert_eq!(state.merger_index_stats()["replayed_sources"], 0);
    assert!(state.current_receipt_for(merger).await.is_none());
    state.set_boot_restore_pending(false);
    state.rebuild_merger_dbs().await;
    assert_eq!(
        state
            .db_query(merger, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap(),
        vec![json!({"title":"hello"})]
    );
    state
}

#[tokio::test]
async fn merger_persistent_restart_reuses_rows_even_when_frontend_restores_first() {
    let (_dir, state, merger, root, entries) = persistent_merger_fixture().await;
    assert_eq!(state.merger_index_stats()["replayed_sources"], 1);
    drop(state);
    let restarted = restore_merger_fixture(&root, &merger, &entries).await;
    assert_eq!(restarted.merger_index_stats()["replayed_sources"], 0);
    assert_eq!(restarted.merger_index_stats()["changed_sources"], 0);
    assert!(
        restarted.merger_index_stats()["skipped_sources"]
            .as_u64()
            .unwrap()
            >= 1
    );
}

#[tokio::test]
async fn merger_frontend_restored_last_stays_unavailable_until_reconciliation() {
    let (_dir, state, merger, root, entries) = persistent_merger_fixture().await;
    drop(state);
    let restarted = AppState::with_data_dir("persistent-index-test", &root);
    restarted.set_boot_restore_pending(true);
    for (key, entry) in entries.iter().filter(|(key, _)| key != &merger) {
        restarted
            .add_xite(
                key,
                XiteEntry {
                    storage: entry.storage.clone(),
                    content: entry.content.clone(),
                },
            )
            .await;
    }
    let frontend = entries.iter().find(|(key, _)| key == &merger).unwrap();
    restarted
        .add_xite(
            &merger,
            XiteEntry {
                storage: frontend.1.storage.clone(),
                content: frontend.1.content.clone(),
            },
        )
        .await;
    // The persisted grant is restored during add_xite. No later permission or
    // source mutation should accidentally invalidate this frontend's receipt.
    assert!(restarted
        .xite_permissions(&merger)
        .await
        .contains(&"Merger:EpixPost".to_string()));
    assert_eq!(restarted.merger_index_stats()["reconciliations"], 0);
    restarted.set_boot_restore_pending(false);
    assert!(
        restarted.current_receipt_for(&merger).await.is_none(),
        "clearing the restore gate exposed an empty frontend before reconciliation"
    );

    restarted.rebuild_merger_dbs().await;
    assert_eq!(
        restarted
            .db_query(&merger, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap(),
        vec![json!({ "title": "hello" })]
    );
    assert_eq!(restarted.merger_index_stats()["replayed_sources"], 0);
}

#[tokio::test]
async fn merger_rebuild_repairs_missing_projection_rows() {
    let (_dir, state, merger, _root, _entries) = persistent_merger_fixture().await;
    state
        .current_receipt_for(&merger)
        .await
        .unwrap()
        .db
        .execute("DELETE FROM post", &[])
        .unwrap();
    assert!(state
        .db_query(&merger, "SELECT title FROM post", &Value::Null)
        .await
        .unwrap()
        .is_empty());
    assert!(state.rebuild_xite_db(&merger).await);
    assert_eq!(
        state
            .db_query(&merger, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap(),
        vec![json!({"title":"hello"})]
    );
    assert_eq!(state.merger_index_stats()["explicit_resets"], 1);
}

#[tokio::test]
async fn merger_restart_recovers_corrupt_and_incomplete_private_caches() {
    for damage in ["header", "projection", "checkpoint"] {
        let (_dir, state, merger, root, entries) = persistent_merger_fixture().await;
        drop(state);
        let cache = std::fs::read_dir(root.join("private/cache/merger-index-v1"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "sqlite")
            })
            .unwrap();
        match damage {
            "header" => std::fs::write(&cache, b"invalid private cache").unwrap(),
            "projection" => {
                rusqlite::Connection::open(&cache)
                    .unwrap()
                    .execute_batch("DROP TABLE post")
                    .unwrap();
            }
            "checkpoint" => {
                rusqlite::Connection::open(&cache)
                    .unwrap()
                    .execute_batch("DROP TABLE __epix_derived_meta")
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let restarted = restore_merger_fixture(&root, &merger, &entries).await;
        assert_eq!(
            restarted.merger_index_stats()["cache_recoveries"],
            1,
            "{damage}"
        );
        assert_eq!(
            restarted.merger_index_stats()["replayed_sources"],
            1,
            "{damage}"
        );
        for (_, entry) in &entries {
            assert!(
                entry.storage.exists("content.json"),
                "cache recovery changed signed sources"
            );
        }
    }
}

fn merger_private_cache_files(root: &Path) -> Vec<PathBuf> {
    let mut files = std::fs::read_dir(root.join("private/cache/merger-index-v1"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "sqlite")
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[tokio::test]
async fn merger_frontend_deletion_waits_for_its_last_cache_reader() {
    let (_dir, state, merger, root, entries) = persistent_merger_fixture().await;
    let cache = merger_private_cache_files(&root).pop().unwrap();
    let receipt = state.current_receipt_for(&merger).await.unwrap();
    let reader = receipt.db.conn().unwrap();
    drop(receipt);

    assert!(state.try_remove_xite(&merger).await.unwrap());
    assert!(state.current_receipt_for(&merger).await.is_none());
    assert!(
        cache.is_file(),
        "frontend removal unlinked a live reader's cache"
    );
    let title: String = reader
        .query_row("SELECT title FROM post", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        title, "hello",
        "the retained SQLite reader lost its backing files"
    );
    for (key, entry) in &entries {
        if key != &merger {
            assert!(entry.storage.exists("content.json"));
        }
    }

    drop(reader);
    db_test_step("retired cache deleted after its final reader", async {
        while ["", "-wal", "-shm", ".retired"].iter().any(|suffix| {
            let mut path = cache.as_os_str().to_os_string();
            path.push(suffix);
            PathBuf::from(path).exists()
        }) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn merger_failed_unpublished_generation_is_removed_without_retiring_published_cache() {
    let (dir, source_state, _) = merger_with_one_post().await;
    let (source, source_entry) = {
        let xites = source_state.xites.read().await;
        let (key, xite) = xites
            .iter()
            .find(|(_, xite)| {
                xite.content
                    .as_ref()
                    .and_then(|content| content.get("merged_type"))
                    .and_then(Value::as_str)
                    == Some("EpixPost")
            })
            .unwrap();
        (
            key.clone(),
            XiteEntry {
                storage: xite.storage.clone(),
                content: xite.content.clone(),
            },
        )
    };
    let root = dir.path().join("failed-generation-node");
    let state = AppState::with_data_dir("persistent-index-test", &root);
    state.add_xite(&source, source_entry).await;
    let key = epix_crypt::new_seed();
    let merger = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(root.join("data").join(&merger));
    // Valid schema, but the existing accepted source row violates its rule.
    // With no merger permission the initial empty generation can publish.
    let schema = serde_json::to_vec(&json!({
        "db_name": "Rejecting merger", "db_file": "db.db", "version": 3,
        "maps": { ".+/data/.*/data.json$": {
            "to_table": [{ "node": "posts", "table": "post" }]
        } },
        "tables": { "post": { "cols": [
            ["post_id", "INTEGER"],
            ["title", "TEXT NOT NULL CHECK (title = 'never')"],
            ["json_id", "INTEGER"]
        ] } }
    }))
    .unwrap();
    storage.write("dbschema.json", &schema).unwrap();
    let mut content = json!({
        "address": merger, "modified": 1,
        "files": { "dbschema.json": {
            "size": schema.len(), "sha512": XiteStorage::hash_bytes(&schema)
        } }
    });
    epix_content::sign(&mut content, &key).unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&content).as_bytes(),
        )
        .unwrap();
    state
        .add_xite(
            &merger,
            XiteEntry {
                storage,
                content: Some(content),
            },
        )
        .await;
    let published = merger_private_cache_files(&root);
    assert_eq!(published.len(), 1);
    assert!(state.current_receipt_for(&merger).await.is_some());

    // Changing permissions opens a different context generation. Its failed
    // projection must retire without deleting the previously published cache.
    state.add_permission(&merger, "Merger:EpixPost").await;
    assert!(state.current_receipt_for(&merger).await.is_none());
    db_test_step("unpublished cache generation retired", async {
        while merger_private_cache_files(&root) != published {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(published[0].is_file());
    drop(state);
    assert!(
        published[0].is_file(),
        "published cache was retired by a provisional guard"
    );
}
