//! sites.json persistence: the served-xite list survives a restart. A node
//! records the xites it serves; a fresh node started on the same data root
//! restores them (verifying each on-disk content.json) without re-cloning.

use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;

fn signed_content(address: &str, privkey: &str, modified: i64) -> (serde_json::Value, Vec<u8>) {
    let mut content = json!({ "address": address, "modified": modified, "files": {} });
    epix_content::sign(&mut content, privkey).unwrap();
    let bytes = serde_json::to_vec(&content).unwrap();
    (content, bytes)
}

#[tokio::test]
async fn served_xites_survive_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let (content, bytes) = signed_content(&address, &privkey, 1000);

    // The xite's files live under <root>/data/<address>/ (Python EpixNet's
    // layout). Write its verified content.json there.
    let xite_dir = root.path().join("data").join(&address);
    let storage = XiteStorage::new(&xite_dir);
    storage.write("content.json", &bytes).unwrap();

    // First run: a node serving the xite persists sites.json.
    {
        let state = AppState::with_data_dir("run-1", root.path());
        state
            .add_xite(&address, XiteEntry { storage: storage.clone(), content: Some(content) })
            .await;
        assert!(state.has_any_alias(&address).await);
        // sites.json written where Python's SiteManager keeps it.
        assert!(root.path().join("private/sites.json").exists());
    }

    // Second run: a fresh node on the same data dir restores the xite with no
    // add_xite call and no network.
    {
        let state = AppState::with_data_dir("run-2", root.path());
        assert!(!state.has_any_alias(&address).await, "starts empty");
        let restored = state.restore_sites().await;
        assert_eq!(restored, 1);
        assert!(state.has_any_alias(&address).await, "xite restored");
        // The restored content.json is the signed one.
        let c = state.content(&address).await.unwrap();
        assert_eq!(c.get("modified").and_then(|m| m.as_i64()), Some(1000));
    }
}

#[tokio::test]
async fn sites_json_uses_the_epixnet_schema_and_restores_settings() {
    let root = tempfile::tempdir().unwrap();
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let (content, bytes) = signed_content(&address, &privkey, 1000);

    let xite_dir = root.path().join("data").join(&address);
    let storage = XiteStorage::new(&xite_dir);
    storage.write("content.json", &bytes).unwrap();

    {
        let state = AppState::with_data_dir("run-1", root.path());
        state
            .add_xite(&address, XiteEntry { storage: storage.clone(), content: Some(content) })
            .await;
        state.set_owned(&address, true).await;
        state.set_size_limit(&address, 25).await;
        state.persist_sites().await;
    }

    // The written schema is EpixNet's SiteManager.save: settings flat at the
    // top level of each entry (a Python node can read this file directly).
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("private/sites.json")).unwrap())
            .unwrap();
    let entry = saved.get(&address).expect("entry keyed by address");
    assert!(entry.get("serving").is_some(), "settings are flat, not nested: {entry}");
    assert!(entry.get("settings").is_none(), "no nested settings key");
    assert_eq!(entry.get("own"), Some(&json!(true)));

    // A fresh node restores the persisted user-facing settings.
    let state = AppState::with_data_dir("run-2", root.path());
    assert_eq!(state.restore_sites().await, 1);
    let info = state.site_info(&address).await;
    assert_eq!(info.get("settings").and_then(|s| s.get("own")), Some(&json!(true)));
    assert_eq!(info.get("size_limit").and_then(|v| v.as_i64()), Some(25));
}

#[tokio::test]
async fn restores_a_python_written_sites_json_entry() {
    let root = tempfile::tempdir().unwrap();
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let (_content, bytes) = signed_content(&address, &privkey, 1000);

    let xite_dir = root.path().join("data").join(&address);
    XiteStorage::new(&xite_dir).write("content.json", &bytes).unwrap();

    // A sites.json as EpixNet's SiteManager writes it, in the place EpixNet
    // keeps it (private/sites.json): flat settings, no wrapper_key/ajax_key,
    // extra keys the Rust side doesn't model.
    let python_sites = json!({
        &address: {
            "own": true,
            "serving": true,
            "permissions": ["ADMIN"],
            "added": 1600000000,
            "downloaded": 1600000001,
            "modified": 1000,
            "size": 0,
            "size_optional": 0,
            "optional_downloaded": 0,
            "peers": 3,
            "cache": { "bad_files": {} },
            "size_files_optional": 0
        }
    });
    std::fs::create_dir_all(root.path().join("private")).unwrap();
    std::fs::write(
        root.path().join("private/sites.json"),
        serde_json::to_vec_pretty(&python_sites).unwrap(),
    )
    .unwrap();

    let state = AppState::with_data_dir("run-1", root.path());
    assert_eq!(state.restore_sites().await, 1, "python-written entry restores");
    let info = state.site_info(&address).await;
    assert_eq!(info.get("settings").and_then(|s| s.get("own")), Some(&json!(true)));
}

#[tokio::test]
async fn restore_falls_back_to_local_copy_for_unverified_content() {
    // A content.json that no longer verifies (authored here, edited, or not
    // re-signed yet) is still restored, served as a local working copy - it is
    // already-downloaded content in the operator's own data dir. Dropping it
    // used to make a registered xite vanish on restart.
    let root = tempfile::tempdir().unwrap();
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let (content, bytes) = signed_content(&address, &privkey, 1000);

    let xite_dir = root.path().join("data").join(&address);
    let storage = XiteStorage::new(&xite_dir);
    storage.write("content.json", &bytes).unwrap();
    {
        let state = AppState::with_data_dir("run-1", root.path());
        state.add_xite(&address, XiteEntry { storage, content: Some(content) }).await;
    }

    // Edit the on-disk content.json so its signature no longer verifies.
    let mut edited: serde_json::Value =
        serde_json::from_slice(&std::fs::read(xite_dir.join("content.json")).unwrap()).unwrap();
    edited["modified"] = json!(9999);
    std::fs::write(xite_dir.join("content.json"), serde_json::to_vec(&edited).unwrap()).unwrap();

    let state = AppState::with_data_dir("run-2", root.path());
    let restored = state.restore_sites().await;
    assert_eq!(restored, 1, "unverified content.json restores as a local copy");
    assert!(state.has_any_alias(&address).await);
    let info = state.site_info(&address).await;
    assert_eq!(info["content"]["modified"], json!(9999), "the local copy is what serves");
}

#[tokio::test]
async fn global_settings_survive_a_restart() {
    let root = tempfile::tempdir().unwrap();

    // A fresh node defaults to following the system theme.
    let fresh = AppState::with_data_dir("run-0", root.path());
    let info = fresh.server_info().await;
    assert_eq!(info["user_settings"]["use_system_theme"], json!(true));

    // Choose a theme; it is stored in the master user's settings (users.json).
    fresh
        .set_global_settings(json!({ "theme": "dark", "use_system_theme": false }))
        .await;
    assert!(root.path().join("private/users.json").exists());
    drop(fresh);

    // A new node on the same data dir reads the chosen theme back.
    let restarted = AppState::with_data_dir("run-1", root.path());
    let gs = restarted.global_settings().await;
    assert_eq!(gs["theme"], json!("dark"));
    assert_eq!(gs["use_system_theme"], json!(false));
}

#[tokio::test]
async fn language_survives_a_restart() {
    let root = tempfile::tempdir().unwrap();

    // Default language is English, and the wrapper renders it.
    let fresh = AppState::with_data_dir("run-0", root.path());
    assert_eq!(fresh.ui_language().await, "en");

    // Toggle the language; it's a node config value, saved to config.json.
    fresh.config_set("language", json!("de")).await;
    assert!(root.path().join("private/config.json").exists());
    drop(fresh);

    // A new node on the same data dir reads it back and renders it.
    let restarted = AppState::with_data_dir("run-1", root.path());
    assert_eq!(restarted.ui_language().await, "de");
    assert_eq!(restarted.server_info().await["language"], json!("de"));
}
