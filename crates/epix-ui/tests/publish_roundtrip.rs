//! The publish round-trip over a real TCP socket: node A signs a new
//! content.json version and publishes it; node B's inbound file server
//! verifies the pushed update and applies it. This is the receive half of the
//! Phase 3 publish checkpoint (two Rust nodes propagating an update by push,
//! no polling).

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
async fn far_future_modified_is_rejected() {
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let (v1, v1_bytes) = signed_content(&address, &privkey, 1000);

    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("content.json", &v1_bytes).unwrap();
    let state = AppState::new("node");
    state.add_xite(&address, XiteEntry { storage, content: Some(v1) }).await;

    // Validly signed, but dated 100 days into the future (EpixNet allows at
    // most now + 1 day): rejected, so a peer can't pin a bogus newest version.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (_far, far_bytes) = signed_content(&address, &privkey, now + 100 * 24 * 60 * 60);
    let err = state
        .apply_inbound_update(&address, "content.json", Some(far_bytes), None, None, Default::default(), Vec::new())
        .await
        .unwrap_err();
    assert!(err.contains("far future"), "unexpected error: {err}");

    // The served version is unchanged.
    let content = state.content(&address).await.unwrap();
    assert_eq!(content.get("modified").and_then(|m| m.as_i64()), Some(1000));
}
