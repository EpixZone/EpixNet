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
    let state = prepare_merger_restore(root, merger, entries).await;
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

async fn prepare_merger_restore(
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

#[tokio::test]
async fn merger_pending_refresh_reuses_completed_hubs_after_epoch_retry() {
    for restarting in [false, true] {
        let (dir, original, merger, persisted_root, entries) = persistent_merger_fixture().await;
        drop(original);
        let root = if restarting {
            persisted_root
        } else {
            dir.path().join("initial-refresh-retry")
        };
        let state = prepare_merger_restore(&root, &merger, &entries).await;
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        *state.merger_db_before_install_pause.lock().unwrap() =
            Some((started.clone(), release.clone()));
        let refresh = {
            let state = state.clone();
            tokio::spawn(async move { state.rebuild_merger_dbs().await })
        };
        db_test_step(
            "pending generation reached installation",
            started.notified(),
        )
        .await;
        let expected_replays = if restarting { 0 } else { 1 };
        assert_eq!(
            state.merger_index_stats()["replayed_sources"],
            expected_replays
        );
        let verified = state.merger_index_stats()["verified_input_files"].clone();
        assert!(state.current_receipt_for(&merger).await.is_none());

        // Only the target generation changes. The accepted source hub remains
        // identical and must survive the retry without another scan or replay.
        state.bump_db_source_epoch(&merger);
        state.merger_db_before_install_pause.lock().unwrap().take();
        release.add_permits(1);
        db_test_step("pending generation retried successfully", refresh)
            .await
            .unwrap();
        assert_eq!(
            state
                .db_query(&merger, "SELECT title FROM post", &Value::Null)
                .await
                .unwrap(),
            vec![json!({ "title": "hello" })]
        );
        assert_eq!(
            state.merger_index_stats()["replayed_sources"],
            expected_replays,
            "freshness retry discarded a completed projection (restart={restarting})"
        );
        assert_eq!(
            state.merger_index_stats()["verified_input_files"],
            verified,
            "freshness retry rescanned an unchanged hub (restart={restarting})"
        );
    }
}

#[tokio::test]
async fn merger_pending_refresh_survives_install_lock_contention() {
    let (dir, original, merger, _persisted_root, entries) = persistent_merger_fixture().await;
    drop(original);
    let state =
        prepare_merger_restore(&dir.path().join("contended-refresh"), &merger, &entries).await;
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    *state.merger_db_before_install_pause.lock().unwrap() =
        Some((started.clone(), release.clone()));
    let refresh = {
        let state = state.clone();
        tokio::spawn(async move { state.rebuild_merger_dbs().await })
    };
    db_test_step(
        "pending generation reached installation",
        started.notified(),
    )
    .await;
    let verified = state.merger_index_stats()["verified_input_files"].clone();
    let generation = state.xites.read().await.get(&merger).unwrap().db_generation;
    let tree = state.tree_mutation_lock(&merger).lock_owned().await;
    state.merger_db_before_install_pause.lock().unwrap().take();
    release.add_permits(1);
    // A retry withdraws handles before visiting registry entries. Waiting for
    // hub reuse while holding this tree would depend on HashMap order: the
    // refresh may visit the frontend and block on our lock before its source.
    db_test_step("contended install began another preparation", async {
        while state.xites.read().await.get(&merger).unwrap().db_generation == generation {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(state.current_receipt_for(&merger).await.is_none());
    drop(tree);
    db_test_step("contended pending generation installed", refresh)
        .await
        .unwrap();
    assert_eq!(state.merger_index_stats()["replayed_sources"], 1);
    assert_eq!(state.merger_index_stats()["verified_input_files"], verified);
    assert_eq!(
        state
            .db_query(&merger, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap(),
        vec![json!({ "title": "hello" })]
    );
}

#[tokio::test]
async fn merger_pending_refresh_revalidates_changed_sources_and_filters() {
    for change in ["source", "filter"] {
        let (dir, original, merger, _persisted_root, entries) = persistent_merger_fixture().await;
        drop(original);
        let source = entries
            .iter()
            .find(|(key, _)| key != &merger)
            .unwrap()
            .0
            .clone();
        let state =
            prepare_merger_restore(&dir.path().join("changed-refresh"), &merger, &entries).await;
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        *state.merger_db_before_install_pause.lock().unwrap() =
            Some((started.clone(), release.clone()));
        let refresh = {
            let state = state.clone();
            tokio::spawn(async move { state.rebuild_merger_dbs().await })
        };
        db_test_step(
            "pending generation reached installation",
            started.notified(),
        )
        .await;
        let verified = state.merger_index_stats()["verified_input_files"]
            .as_u64()
            .unwrap();
        let delete = if change == "source" {
            let epoch = state.db_source_epoch(&source);
            let task = {
                let state = state.clone();
                let source = source.clone();
                tokio::spawn(
                    async move { state.delete_file(&source, "data/u/data.json", None).await },
                )
            };
            db_test_step("source changed before pending installation", async {
                while state.db_source_epoch(&source) == epoch {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            Some(task)
        } else {
            // Apply the filter mutation without its separate rebuild/reset so
            // this test exercises pending receipt invalidation itself.
            state.filters.write().await["mutes"][source.as_str()] = json!({ "reason": "test" });
            state.bump_db_filter_epoch();
            None
        };
        state.merger_db_before_install_pause.lock().unwrap().take();
        release.add_permits(1);
        db_test_step("changed pending generation reconciled", refresh)
            .await
            .unwrap();
        if let Some(delete) = delete {
            db_test_step("source deletion completed", delete)
                .await
                .unwrap()
                .unwrap();
        }
        assert!(
            state
                .db_query(&merger, "SELECT title FROM post", &Value::Null)
                .await
                .unwrap()
                .is_empty(),
            "pending reuse bypassed a changed {change}"
        );
        assert!(
            state.merger_index_stats()["verified_input_files"]
                .as_u64()
                .unwrap()
                > verified,
            "pending reuse skipped verification after a changed {change}"
        );
    }
}
