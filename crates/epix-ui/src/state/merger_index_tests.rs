#[tokio::test]
async fn merger_incremental_input_cannot_restore_a_muted_source_hub() {
    let (_dir, state, merger) = merger_with_one_post().await;
    let source = {
        let xites = state.xites.read().await;
        xites
            .iter()
            .find(|(_, xite)| {
                xite.content
                    .as_ref()
                    .and_then(|root| root.get("merged_type"))
                    .and_then(Value::as_str)
                    == Some("EpixPost")
            })
            .map(|(key, _)| key.clone())
            .unwrap()
    };

    // The exclusion matches the hub prefix, not the input's relative path.
    // Its cached receipt remains useful, but must not authorize a later delta.
    state.mute_add(&source, "", "test hub exclusion").await;
    let rows = state
        .db_query(&merger, "SELECT title FROM post", &Value::Null)
        .await
        .unwrap();
    assert!(rows.is_empty());
    state.ingest_file(&source, "data/u/data.json").await;
    let rows = state
        .db_query(&merger, "SELECT title FROM post", &Value::Null)
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "incremental ingestion bypassed the hub-prefix mute"
    );

    state.mute_remove(&source).await;
    let rows = state
        .db_query(&merger, "SELECT title FROM post", &Value::Null)
        .await
        .unwrap();
    assert_eq!(rows, vec![json!({ "title": "hello" })]);
}

#[tokio::test]
async fn merger_epoch_advances_when_an_object_is_materialized() {
    let dir = tempdir().unwrap();
    let state = AppState::new("test");
    let key = epix_crypt::new_seed();
    let source = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(dir.path().join("source"));
    let path = "data/u/data.json";
    let bytes = br#"{"posts":[{"post_id":1,"title":"arrived"}]}"#;
    let id = epix_blob::ObjId::of(bytes);
    let mut root = json!({
        "address": source,
        "modified": 1,
        "merged_type": "EpixPost",
        "files": { (path): {
            "size": bytes.len(),
            "sha512": XiteStorage::hash_bytes(bytes),
            "b3": id.to_string()
        } }
    });
    epix_content::sign(&mut root, &key).unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&root).as_bytes(),
        )
        .unwrap();
    state
        .add_xite(
            &source,
            XiteEntry {
                storage: storage.clone(),
                content: Some(root),
            },
        )
        .await;
    let store = Arc::new(
        epix_blob::store::Store::open_with(
            dir.path().join("store"),
            epix_blob::store::StoreConfig {
                xite_root: Some(dir.path().to_path_buf()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    state.set_edx_store(store.clone()).await.unwrap();
    let outboard = epix_blob::verified::OutboardBytes::from_slice(bytes);
    let ranges = [0..bytes.len() as u64];
    let mut encoded = Vec::new();
    epix_blob::verified::encode_slice(&bytes[..], &outboard, &ranges, &mut encoded).unwrap();
    store
        .ensure_sparse(id, epix_blob::Ns::Plain, bytes.len() as u64, 1)
        .unwrap();
    store.write_slice(id, &ranges, &encoded[..], 1).unwrap();
    let source_epoch = state.db_source_epoch(&source);
    let merger_epoch = state.db_merger_epoch();

    state
        .edx_materialize_object(&source, path, id, None)
        .await
        .unwrap();

    assert_eq!(storage.read(path).unwrap(), bytes);
    assert_eq!(state.db_source_epoch(&source), source_epoch + 1);
    assert_eq!(
        state.db_merger_epoch(),
        merger_epoch + 1,
        "object materialization left complete merger receipts apparently current"
    );
}

#[tokio::test]
async fn merger_refresh_keeps_its_writer_after_caller_cancellation() {
    let (_dir, state, merger) = merger_with_one_post().await;
    let source = {
        let xites = state.xites.read().await;
        xites
            .iter()
            .find(|(_, xite)| {
                xite.content
                    .as_ref()
                    .and_then(|root| root.get("merged_type"))
                    .and_then(Value::as_str)
                    == Some("EpixPost")
            })
            .map(|(key, _)| key.clone())
            .unwrap()
    };
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    *state.merger_db_before_install_pause.lock().unwrap() =
        Some((started.clone(), release.clone()));
    let caller = {
        let state = state.clone();
        tokio::spawn(async move { state.rebuild_merger_dbs().await })
    };
    db_test_step("refresh reached its installation pause", started.notified()).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        state.merger_index_refresh.try_lock().is_err(),
        "cancelling the waiter released the unfinished refresh writer"
    );
    assert!(state.current_receipt_for(&merger).await.is_none());

    // A newer source generation lands while the detached refresh completes.
    // It must force a retry before any old projection becomes queryable.
    let previous_epoch = state.db_source_epoch(&source);
    let delete = {
        let state = state.clone();
        let source = source.clone();
        tokio::spawn(async move { state.delete_file(&source, "data/u/data.json", None).await })
    };
    db_test_step("source changed during the cancelled refresh", async {
        while state.db_source_epoch(&source) == previous_epoch {
            tokio::task::yield_now().await;
        }
    })
    .await;
    state.merger_db_before_install_pause.lock().unwrap().take();
    release.add_permits(1);
    db_test_step("new source generation reconciled", delete)
        .await
        .unwrap()
        .unwrap();
    let rows = state
        .db_query(&merger, "SELECT title FROM post", &Value::Null)
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "cancelled refresh installed its obsolete source rows"
    );
}

#[tokio::test]
async fn merger_hot_update_keeps_its_guards_after_caller_cancellation() {
    let (_dir, state, merger) = merger_with_one_post().await;
    let source = {
        let xites = state.xites.read().await;
        xites
            .iter()
            .find(|(_, xite)| {
                xite.content
                    .as_ref()
                    .and_then(|root| root.get("merged_type"))
                    .and_then(Value::as_str)
                    == Some("EpixPost")
            })
            .map(|(key, _)| key.clone())
            .unwrap()
    };
    let receipt = state.current_receipt_for(&merger).await.unwrap();
    let mut connection = receipt.db.conn().unwrap();
    // Block the real SQL worker at its transaction boundary. This leaves its
    // owned async completion task holding the writer and source tree guards.
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let reconciliations = state.merger_index_stats()["reconciliations"].clone();
    let caller = {
        let state = state.clone();
        let source = source.clone();
        tokio::spawn(async move { state.ingest_file(&source, "data/u/data.json").await })
    };
    db_test_step("incremental worker withdrew its query handle", async {
        loop {
            if state.xites.read().await.get(&merger).unwrap().db.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        state.merger_index_stats()["reconciliations"],
        reconciliations,
        "fixture must exercise the single-input path"
    );
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        state.merger_index_refresh.try_lock().is_err(),
        "cancelling the waiter released the SQL worker's writer"
    );
    assert!(
        state.tree_mutation_lock(&source).try_lock_owned().is_err(),
        "cancelling the waiter released the SQL worker's source authority"
    );
    let refresh = {
        let state = state.clone();
        tokio::spawn(async move { state.rebuild_merger_dbs().await })
    };
    tokio::task::yield_now().await;
    assert_eq!(
        state.merger_index_stats()["reconciliations"],
        reconciliations,
        "another refresh overlapped the blocked SQL worker"
    );

    transaction.rollback().unwrap();
    db_test_step("queued refresh completed after the SQL worker", refresh)
        .await
        .unwrap();
    let rows = state
        .db_query(&merger, "SELECT title FROM post", &Value::Null)
        .await
        .unwrap();
    assert_eq!(rows, vec![json!({ "title": "hello" })]);
}
