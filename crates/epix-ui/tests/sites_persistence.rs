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
async fn restore_skips_unverified_content() {
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

    // Corrupt the on-disk content.json so its signature no longer verifies.
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(xite_dir.join("content.json")).unwrap()).unwrap();
    tampered["modified"] = json!(9999);
    std::fs::write(xite_dir.join("content.json"), serde_json::to_vec(&tampered).unwrap()).unwrap();

    let state = AppState::with_data_dir("run-2", root.path());
    let restored = state.restore_sites().await;
    assert_eq!(restored, 0, "tampered content.json is not restored");
    assert!(!state.has_any_alias(&address).await);
}
