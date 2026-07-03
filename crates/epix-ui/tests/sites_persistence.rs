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

    // The xite's files live under <root>/<address>/ (the per-xite dir the node
    // uses). Write its verified content.json there.
    let xite_dir = root.path().join(&address);
    let storage = XiteStorage::new(&xite_dir);
    storage.write("content.json", &bytes).unwrap();

    // First run: a node serving the xite persists sites.json.
    {
        let state = AppState::with_data_dir("run-1", &xite_dir);
        state
            .add_xite(&address, XiteEntry { storage: storage.clone(), content: Some(content) })
            .await;
        assert!(state.has_any_alias(&address).await);
        // sites.json written in the shared root (parent of the per-xite dir).
        assert!(root.path().join("sites.json").exists());
    }

    // Second run: a fresh node on the same data dir restores the xite with no
    // add_xite call and no network.
    {
        let state = AppState::with_data_dir("run-2", &xite_dir);
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
async fn restore_skips_unverified_content() {
    let root = tempfile::tempdir().unwrap();
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let (content, bytes) = signed_content(&address, &privkey, 1000);

    let xite_dir = root.path().join(&address);
    let storage = XiteStorage::new(&xite_dir);
    storage.write("content.json", &bytes).unwrap();
    {
        let state = AppState::with_data_dir("run-1", &xite_dir);
        state.add_xite(&address, XiteEntry { storage, content: Some(content) }).await;
    }

    // Corrupt the on-disk content.json so its signature no longer verifies.
    let mut tampered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(xite_dir.join("content.json")).unwrap()).unwrap();
    tampered["modified"] = json!(9999);
    std::fs::write(xite_dir.join("content.json"), serde_json::to_vec(&tampered).unwrap()).unwrap();

    let state = AppState::with_data_dir("run-2", &xite_dir);
    let restored = state.restore_sites().await;
    assert_eq!(restored, 0, "tampered content.json is not restored");
    assert!(!state.has_any_alias(&address).await);
}
