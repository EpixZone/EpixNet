use super::{build_xite_db, AppState, MB};
use crate::command::{CommandRegistry, WsSession, WRAPPER_ID_BASE};
use crate::state::{UpdateOutcome, XiteEntry};
use epix_xite::{XiteSettings, XiteStorage};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};

const ADDRESS: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";

#[test]
fn sidebar_optional_limit_preserves_legacy_settings_compatibility() {
    let legacy: XiteSettings = serde_json::from_value(json!({"serving": true})).unwrap();
    assert_eq!(legacy.autodownload_bigfile_size_limit, None);
    assert!(serde_json::to_value(&legacy)
        .unwrap()
        .get("autodownload_bigfile_size_limit")
        .is_none());
    let mut limited = legacy;
    limited.autodownload_bigfile_size_limit = Some(12);
    let restored: XiteSettings =
        serde_json::from_value(serde_json::to_value(limited).unwrap()).unwrap();
    assert_eq!(restored.autodownload_bigfile_size_limit, Some(12));
}

async fn fixture(root: &Path) -> Arc<AppState> {
    let state = AppState::with_data_dir("sidebar-mutations-test", root);
    state
        .add_xite(
            ADDRESS,
            XiteEntry {
                storage: XiteStorage::new(root.join("data").join(ADDRESS)),
                content: None,
            },
        )
        .await;
    state
}

async fn dispatch(state: &Arc<AppState>, command: &str, params: Value) -> Result<Value, String> {
    CommandRegistry::with_defaults()
        .dispatch(
            &WsSession::new_wrapper(state.clone(), Some(ADDRESS.into())),
            command,
            &params,
            WRAPPER_ID_BASE,
        )
        .await
}

#[tokio::test]
async fn sidebar_theme_change_broadcasts_durable_merged_settings() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path()).await;
    state
        .set_global_settings_checked(json!({
            "theme": "light", "use_system_theme": false, "sidebar_peer_map_open": false
        }))
        .await
        .unwrap();
    let mut events = state.subscribe_events();

    assert_eq!(
        dispatch(&state, "userSetGlobalSettings", json!([{"theme": "dark"}]))
            .await
            .unwrap(),
        "ok"
    );
    let event = events.try_recv().expect("confirmed settings are broadcast before acknowledgement");
    assert_eq!(event.channel.as_deref(), Some("serverChanged"));
    assert_eq!(event.target, None);
    assert_eq!(event.only, None);
    let payload: Value = serde_json::from_str(&event.payload).unwrap();
    assert_eq!(payload["cmd"], "setServerInfo");
    let expected = json!({
        "theme": "dark", "use_system_theme": false, "sidebar_peer_map_open": false
    });
    assert_eq!(payload["params"]["user_settings"], expected);
    let restored = AppState::with_data_dir("sidebar-theme-restart-test", dir.path());
    assert_eq!(restored.global_settings().await, expected);
}

#[tokio::test]
async fn sidebar_theme_write_failure_does_not_broadcast_a_change() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path()).await;
    let before = json!({"theme": "light", "use_system_theme": false});
    state.set_global_settings_checked(before.clone()).await.unwrap();
    let users = dir.path().join("private/users.json");
    std::fs::remove_file(&users).unwrap();
    std::fs::create_dir(&users).unwrap();
    let mut events = state.subscribe_events();

    assert!(dispatch(&state, "userSetGlobalSettings", json!({"theme": "dark"}))
        .await
        .is_err());
    assert_eq!(state.global_settings().await, before);
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn sidebar_update_token_only_marks_its_own_final_event() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path()).await;
    let mut events = state.subscribe_events();
    state
        .push_update_result(ADDRESS, UpdateOutcome::NoChange)
        .await;
    let other: Value = serde_json::from_str(&events.recv().await.unwrap().payload).unwrap();
    assert!(other["params"].get("update_request_id").is_none());
    assert_eq!(
        dispatch(
            &state,
            "siteUpdate",
            json!({
                "address": ADDRESS, "update_request_id": "sidebar-request-1"
            })
        )
        .await
        .unwrap(),
        "Updated"
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let event: Value = serde_json::from_str(&events.recv().await.unwrap().payload).unwrap();
            if event["params"]["event"][0] == "updated" {
                assert_eq!(event["params"]["update_request_id"], "sidebar-request-1");
                break;
            }
            assert!(event["params"].get("update_request_id").is_none());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sidebar_mutations_are_durable_without_trackers_or_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    {
        let state = fixture(dir.path()).await;
        for (command, params) in [
            ("sitePause", json!([])),
            ("siteFavourite", json!([])),
            ("siteSetOwned", json!([true])),
            ("siteSetAutodownloadoptional", json!([true])),
            ("siteSetAutodownloadBigfileLimit", json!({"limit": 12})),
            (
                "userSetGlobalSettings",
                json!([{"sidebar_peer_map_open": false}]),
            ),
            ("siteblockAdd", json!(["blocked", "test reason"])),
        ] {
            assert_eq!(
                dispatch(&state, command, params).await.unwrap(),
                "ok",
                "{command}"
            );
        }
        state.set_size_limit_checked(ADDRESS, 123).await.unwrap();
    }
    let restarted = fixture(dir.path()).await;
    let settings = restarted.xite_info(ADDRESS).await["settings"].clone();
    assert_eq!(settings["serving"], false);
    assert_eq!(settings["favorite"], true);
    assert_eq!(settings["own"], true);
    assert_eq!(settings["download_optional"], true);
    assert_eq!(settings["autodownloadoptional"], true);
    assert_eq!(settings["autodownload_bigfile_size_limit"], 12);
    assert_eq!(settings["size_limit"], 123);
    assert_eq!(
        restarted.global_settings().await["sidebar_peer_map_open"],
        false
    );
    assert_eq!(
        restarted.siteblock_get("blocked").await["reason"],
        "test reason"
    );
    dispatch(&restarted, "siteSetDownloadoptional", json!([false]))
        .await
        .unwrap();
    let settings = restarted.xite_info(ADDRESS).await["settings"].clone();
    assert_eq!(settings["download_optional"], false);
    assert_eq!(settings["autodownloadoptional"], false);
}

#[tokio::test]
async fn sidebar_xite_write_failures_are_errors_and_leave_settings_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path()).await;
    let path = dir.path().join("private/xites.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let before = state.xite_info(ADDRESS).await["settings"].clone();
    for (command, params) in [
        ("sitePause", json!([])),
        ("siteFavourite", json!([])),
        ("siteSetOwned", json!([true])),
        ("siteSetDownloadoptional", json!([false])),
        ("siteSetAutodownloadoptional", json!([true])),
        ("siteSetAutodownloadBigfileLimit", json!({"limit": 12})),
    ] {
        assert!(
            dispatch(&state, command, params).await.is_err(),
            "{command}"
        );
        assert_eq!(
            state.xite_info(ADDRESS).await["settings"],
            before,
            "{command}"
        );
    }
    assert!(state.set_size_limit_checked(ADDRESS, 123).await.is_err());
}

#[tokio::test]
async fn sidebar_user_and_blocklist_failures_are_not_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path()).await;
    let users = dir.path().join("private/users.json");
    std::fs::remove_file(&users).unwrap();
    std::fs::create_dir(&users).unwrap();
    assert!(dispatch(
        &state,
        "userSetGlobalSettings",
        json!({"sidebar_peer_map_open": false})
    )
    .await
    .is_err());
    assert!(state
        .global_settings()
        .await
        .get("sidebar_peer_map_open")
        .is_none());
    assert!(state.identity_select(ADDRESS, Some("")).await.is_err());

    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: XiteStorage::new(dir.path().join("data").join(&address)),
                content: None,
            },
        )
        .await;
    assert!(state.set_xite_privatekey(&address, &key).await.is_err());
    assert!(state.xite_privatekey(&address).await.is_none());

    let filters = dir.path().join("private/filters.json");
    std::fs::create_dir(&filters).unwrap();
    assert!(dispatch(&state, "siteblockAdd", json!(["blocked", "test"]))
        .await
        .is_err());
    assert_eq!(state.siteblock_get("blocked").await, false);
}

#[tokio::test]
async fn sidebar_limits_reject_invalid_values_and_enforce_only_automatic_fetches() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path()).await;
    for limit in [0, -1, i64::MAX] {
        assert!(state.set_size_limit_checked(ADDRESS, limit).await.is_err());
    }
    for limit in [-1, i64::MAX] {
        assert!(
            dispatch(&state, "siteSetAutodownloadBigfileLimit", json!([limit]))
                .await
                .is_err()
        );
    }
    assert!(dispatch(
        &state,
        "siteSetAutodownloadBigfileLimit",
        json!({"limit": 1.5})
    )
    .await
    .is_err());
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(dir.path().join("data").join(&address));
    let mut content = json!({"address": address, "files_optional": {
        "small.bin": {"size": 10, "sha512": XiteStorage::hash_bytes(b"0123456789")},
        "large.bin": {"size": 2 * MB, "sha512": XiteStorage::hash_bytes(&vec![1u8; (2 * MB) as usize])}
    }});
    epix_content::sign(&mut content, &key).unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&content).as_bytes(),
        )
        .unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage,
                content: Some(content),
            },
        )
        .await;
    state.set_optional_file_limit(&address, 1).await.unwrap();
    assert_eq!(
        state.missing_optional_files(&address, None).await,
        vec![("small.bin".into(), 10)]
    );
    assert!(state
        .file_need_background(&address, "large.bin")
        .await
        .unwrap_err()
        .contains("automatic file download limit"));
    assert!(!state
        .file_need(&address, "large.bin")
        .await
        .unwrap_err()
        .contains("automatic file download limit"));
    state.set_optional_file_limit(&address, 0).await.unwrap();
    assert_eq!(state.missing_optional_files(&address, None).await.len(), 2);
}

#[tokio::test]
async fn sidebar_auto_file_limit_keeps_already_held_bytes_in_the_storage_budget() {
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    let held = vec![1u8; (2 * MB) as usize];
    storage.write("large.bin", &held).unwrap();
    let state = AppState::new("sidebar-budget-test");
    state.add_xite(ADDRESS, XiteEntry { storage, content: Some(json!({
        "address": ADDRESS,
        "files": {"next.bin": {"size": MB, "sha512": "aa"}},
        "files_optional": {"large.bin": {"size": held.len(), "sha512": XiteStorage::hash_bytes(&held)}}
    }))}).await;
    state.set_size_limit_checked(ADDRESS, 2).await.unwrap();
    state.set_optional_file_limit(ADDRESS, 1).await.unwrap();
    let plan = state.retention_completion_plan(ADDRESS).await;
    assert_eq!(plan.paths, vec!["next.bin"]);
    assert!(
        plan.needs_consent,
        "held oversized files still consume the storage budget"
    );
}

#[tokio::test]
async fn sidebar_one_shot_runs_without_enabling_standing_optional_consent() {
    let dir = tempfile::tempdir().unwrap();
    let state = fixture(dir.path()).await;
    state.xites.write().await.get_mut(ADDRESS).unwrap().content = Some(json!({
        "address": ADDRESS, "files_optional": {"missing.bin": {"size": 10, "sha512": "aa"}}
    }));
    state
        .set_download_optional_checked(ADDRESS, false, false)
        .await
        .unwrap();
    assert!(dispatch(&state, "siteDownloadOptionalPrevious", json!({}))
        .await
        .unwrap_err()
        .contains("network"));
    state
        .set_transport(Arc::new(epix_transport::TcpTransport))
        .await;
    let response = dispatch(&state, "siteDownloadOptionalPrevious", json!({}))
        .await
        .unwrap();
    assert_eq!(response, json!({"status": "started", "files": 1}));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while state.optional_pass_in_flight(ADDRESS) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let settings = state.xite_info(ADDRESS).await["settings"].clone();
    assert_eq!(settings["download_optional"], false);
    assert_eq!(settings["autodownloadoptional"], false);
    assert!(state.optional_retry_flagged().await.is_empty());
    assert!(state.optional_one_shots.lock().unwrap().is_empty());
    assert!(state.xite_info(ADDRESS).await["optional_progress"].is_null());
    assert_eq!(state.xite_info(ADDRESS).await["optional_left"], 0);
}

async fn database_fixture() -> (tempfile::TempDir, Arc<AppState>, XiteStorage) {
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    let schema = json!({"db_name":"Test", "db_file":"db.db", "version":2,
        "maps":{"data.json":{"to_table":[{"node":"posts","table":"post"}]}},
        "tables":{"post":{"cols":[["title","TEXT"],["json_id","INTEGER"]]}}});
    storage
        .write("dbschema.json", &serde_json::to_vec(&schema).unwrap())
        .unwrap();
    storage
        .write("data.json", br#"{"posts":[{"title":"original"}]}"#)
        .unwrap();
    let state = AppState::new("sidebar-db-test");
    state
        .add_xite(
            ADDRESS,
            XiteEntry {
                storage: storage.clone(),
                content: Some(json!({
                    "address": ADDRESS, "files": {"dbschema.json": {}, "data.json": {}}
                })),
            },
        )
        .await;
    state.set_owned_checked(ADDRESS, true).await.unwrap();
    dispatch(&state, "dbRebuild", json!([])).await.unwrap();
    (dir, state, storage)
}

#[tokio::test]
async fn sidebar_database_reload_preserves_rows_and_rebuild_reindexes_files() {
    let (_dir, state, storage) = database_fixture().await;
    storage
        .write("data.json", br#"{"posts":[{"title":"changed"}]}"#)
        .unwrap();
    dispatch(&state, "dbReload", json!([])).await.unwrap();
    assert_eq!(
        state
            .db_query(ADDRESS, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap()[0]["title"],
        "original"
    );
    dispatch(&state, "dbRebuild", json!([])).await.unwrap();
    assert_eq!(
        state
            .db_query(ADDRESS, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap()[0]["title"],
        "changed"
    );
    storage.write("dbschema.json", b"not json").unwrap();
    assert!(dispatch(&state, "dbReload", json!([])).await.is_err());
    assert!(dispatch(&state, "dbRebuild", json!([])).await.is_err());
    assert_eq!(
        state
            .db_query(ADDRESS, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap()[0]["title"],
        "changed"
    );
}

#[tokio::test]
async fn sidebar_database_reload_preserves_a_connection_replaced_while_it_waits() {
    let (_dir, state, storage) = database_fixture().await;
    let tree = state.tree_mutation_lock(ADDRESS).lock_owned().await;
    let reload = dispatch(&state, "dbReload", json!([]));
    tokio::pin!(reload);
    assert!(futures_util::poll!(&mut reload).is_pending());

    // Commit a replacement while holding the tree lock, as a preceding
    // rebuild does. The queued reload must preserve this connection's rows.
    storage
        .write("data.json", br#"{"posts":[{"title":"replacement"}]}"#)
        .unwrap();
    let (replacement, _) = build_xite_db(
        &storage,
        &[],
        &["dbschema.json".into(), "data.json".into()],
        None,
    )
    .unwrap();
    state.xites.write().await.get_mut(ADDRESS).unwrap().db = Some(replacement);
    drop(tree);
    assert_eq!(reload.await.unwrap(), "ok");
    assert_eq!(
        state
            .db_query(ADDRESS, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap()[0]["title"],
        "replacement"
    );
}
