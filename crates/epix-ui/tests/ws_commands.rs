//! The WS commands from the parity re-audit: siteAdd, siteClone,
//! serverPortcheck, fileQuery, as, badCert, siteSetSettingsValue,
//! siteListModifiedFiles, and announcerInfo's ADMIN blanking.

use epix_ui::command::{CommandRegistry, WsSession};
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::sync::Arc;

const WRAPPER_ID: i64 = 1_000_000;

/// A data-dir-backed state with one owned, signed site holding a template
/// layout (data-default/ + live data/) for the clone test.
async fn state_with_site() -> (Arc<AppState>, tempfile::TempDir, String, String) {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("ws-test", root.path());
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let dir = root.path().join("data").join(&address);
    let storage = XiteStorage::new(&dir);
    storage.write("index.html", b"<h1>template</h1>").unwrap();
    storage.write("data-default/users/content.json", b"{}").unwrap();
    storage.write("data/users/alice/data.json", br#"{"topic":[{"topic_id":7,"title":"live"}]}"#).unwrap();
    storage.write("data/users/bob/data.json", br#"{"topic":[{"topic_id":9,"title":"other"}]}"#).unwrap();
    let content = json!({ "address": address, "title": "Template Blog", "files": {} });
    state
        .add_xite(&address, XiteEntry { storage, content: Some(content) })
        .await;
    state.set_site_privatekey(&address, &privkey).await.unwrap();
    state.sign_xite(&address, &privkey).await.unwrap();
    (state, root, address, privkey)
}

#[tokio::test]
async fn site_add_reports_existing_site() {
    let (state, _root, address, _key) = state_with_site().await;
    let registry = CommandRegistry::with_defaults();
    let session = WsSession::new(state, Some(address.clone()));
    let res = registry
        .dispatch(&session, "siteAdd", &json!({ "address": address }), WRAPPER_ID)
        .await
        .unwrap();
    assert_eq!(res, json!({ "error": "Site already added" }));
}

#[tokio::test]
async fn file_query_wildcard_and_filter() {
    let (state, _root, address, _key) = state_with_site().await;
    let registry = CommandRegistry::with_defaults();
    let session = WsSession::new(state, Some(address));

    // Wildcard + dotted list path: every user's topics, tagged inner_path.
    let res = registry
        .dispatch(
            &session,
            "fileQuery",
            &json!({ "dir_inner_path": "data/users/*/data.json", "query": "topic" }),
            1,
        )
        .await
        .unwrap();
    let rows = res.as_array().unwrap();
    assert_eq!(rows.len(), 2, "{res}");
    assert!(rows.iter().any(|r| r["inner_path"] == "alice" && r["topic_id"] == 7));
    assert!(rows.iter().any(|r| r["inner_path"] == "bob" && r["topic_id"] == 9));

    // Equality filter on the list.
    let res = registry
        .dispatch(
            &session,
            "fileQuery",
            &json!({ "dir_inner_path": "data/users/*/data.json", "query": "topic.topic_id=9" }),
            1,
        )
        .await
        .unwrap();
    let rows = res.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["title"], "other");
}

#[tokio::test]
async fn modified_files_and_settings_value() {
    let (state, _root, address, _key) = state_with_site().await;
    let registry = CommandRegistry::with_defaults();
    let session = WsSession::new(state.clone(), Some(address.clone()));

    // Freshly signed: nothing modified.
    let res = registry
        .dispatch(&session, "siteListModifiedFiles", &json!({}), 1)
        .await
        .unwrap();
    assert_eq!(res["modified_files"], json!([]));

    // Edit a signed file on disk: it shows up.
    let dir = state.xite_dir(&address).unwrap();
    std::fs::write(dir.join("index.html"), b"<h1>edited</h1>").unwrap();
    let res = registry
        .dispatch(&session, "siteListModifiedFiles", &json!({}), 1)
        .await
        .unwrap();
    assert_eq!(res["modified_files"], json!(["index.html"]));

    // siteSetSettingsValue: only the whitelisted key.
    let res = registry
        .dispatch(
            &session,
            "siteSetSettingsValue",
            &json!({ "key": "own", "value": true }),
            WRAPPER_ID,
        )
        .await
        .unwrap();
    assert_eq!(res, json!({ "error": "Can't change this key" }));
    let res = registry
        .dispatch(
            &session,
            "siteSetSettingsValue",
            &json!({ "key": "modified_files_notification", "value": false }),
            WRAPPER_ID,
        )
        .await
        .unwrap();
    assert_eq!(res, Value::from("ok"));
}

#[tokio::test]
async fn as_runs_commands_for_other_sites_with_admin_only() {
    let (state, _root, address, _key) = state_with_site().await;
    // A second site the caller will reach via `as`.
    let dir = tempfile::tempdir().unwrap();
    state
        .add_xite("1Other", XiteEntry {
            storage: XiteStorage::new(dir.path()),
            content: Some(json!({ "address": "1Other" })),
        })
        .await;
    let registry = CommandRegistry::with_defaults();
    let session = WsSession::new(state.clone(), Some(address.clone()));

    let as_params = json!({ "address": "1Other", "cmd": "siteInfo", "params": [] });
    // Without ADMIN on the caller's site: refused.
    let err = registry.dispatch(&session, "as", &as_params, 1).await.unwrap_err();
    assert!(err.contains("permission"), "{err}");

    // With ADMIN granted to the caller's site: the inner command runs bound
    // to the target.
    state.add_permission(&address, "ADMIN").await;
    let res = registry.dispatch(&session, "as", &as_params, 1).await.unwrap();
    assert_eq!(res["address"], "1Other", "{res}");
}

#[tokio::test]
async fn bad_cert_is_recorded() {
    let (state, _root, address, _key) = state_with_site().await;
    let registry = CommandRegistry::with_defaults();
    let session = WsSession::new(state.clone(), Some(address));
    registry
        .dispatch(&session, "badCert", &json!({ "sign": "SIGxyz" }), 1)
        .await
        .unwrap();
    assert!(state.is_bad_cert("SIGxyz"));
    assert!(!state.is_bad_cert("SIGother"));
}

#[tokio::test]
async fn server_portcheck_reports_cached_status() {
    let (state, _root, address, _key) = state_with_site().await;
    let registry = CommandRegistry::with_defaults();
    let session = WsSession::new(state.clone(), Some(address));
    let res =
        registry.dispatch(&session, "serverPortcheck", &json!({}), WRAPPER_ID).await.unwrap();
    assert_eq!(res, Value::from(false));
    state.set_port_status(true, Some("1.2.3.4".into())).await;
    let res =
        registry.dispatch(&session, "serverPortcheck", &json!({}), WRAPPER_ID).await.unwrap();
    assert_eq!(res, Value::from(true));
}

#[tokio::test]
async fn site_clone_copies_template_not_live_data() {
    let (state, root, address, _key) = state_with_site().await;
    let registry = CommandRegistry::with_defaults();
    let session = WsSession::new(state.clone(), Some(address.clone()));

    let res = registry
        .dispatch(&session, "siteClone", &json!({ "address": address }), WRAPPER_ID)
        .await
        .unwrap();
    let new_address = res["address"].as_str().expect("new address").to_string();
    assert_ne!(new_address, address);

    let dir = root.path().join("data").join(&new_address);
    // The -default tree replaced the live one: the clone starts clean.
    assert!(dir.join("data/users/content.json").exists(), "-default landed de-suffixed");
    assert!(!dir.join("data/users/alice").exists(), "live user data not copied");
    assert!(dir.join("index.html").exists());

    // The new content.json is signed by the new owner and titled "My ...".
    let content: Value =
        serde_json::from_slice(&std::fs::read(dir.join("content.json")).unwrap()).unwrap();
    assert_eq!(content["address"], new_address);
    assert_eq!(content["cloned_from"], address);
    assert_eq!(content["title"], "My Template Blog");
    assert!(content["signs"][&new_address].is_string(), "signed by the clone's key");
    assert!(epix_content::verify_signer(&content, &new_address), "signature verifies");

    // The clone is served and owned; its own privatekey is saved.
    assert!(state.has_xite(&new_address).await);
    assert!(state.site_privatekey(&new_address).await.is_some());
}
