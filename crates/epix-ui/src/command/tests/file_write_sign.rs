use super::*;
use crate::state::XiteEntry;
use epix_xite::XiteStorage;

const INNER: &str = "data/admin/admin-settings.json";
const BEFORE: &[u8] = b"{\"pinned_topic_uris\":[]}";
const AFTER: &[u8] = b"{\"pinned_topic_uris\":[\"42_writer.epix\"]}";

async fn fixture() -> (tempfile::TempDir, Arc<AppState>, String, String, XiteStorage) {
    let directory = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("test", directory.path());
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(directory.path().join("data").join(&address));
    storage.write(INNER, BEFORE).unwrap();
    let mut child = json!({
        "address": address, "inner_path": "data/admin/content.json", "modified": 1,
        "files": {"admin-settings.json": {"size": BEFORE.len(), "sha512": XiteStorage::hash_bytes(BEFORE)}},
    });
    epix_content::sign(&mut child, &key).unwrap();
    storage.write("data/admin/content.json", &serde_json::to_vec(&child).unwrap()).unwrap();
    let mut root = json!({
        "address": address, "modified": 1, "merged_type": "Talk", "files": {},
        "includes": {"data/admin/content.json": {"signers_required": 1}},
    });
    epix_content::sign(&mut root, &key).unwrap();
    storage.write("content.json", &serde_json::to_vec(&root).unwrap()).unwrap();
    state.add_xite(&address, XiteEntry {storage: storage.clone(), content: Some(root)}).await;
    (directory, state, address, key, storage)
}

fn params(inner: &str) -> Value {
    json!({
        "inner_path": inner,
        "content_base64": base64::engine::general_purpose::STANDARD.encode(AFTER),
        "expected_base64": base64::engine::general_purpose::STANDARD.encode(BEFORE),
        "privatekey": "stored",
    })
}

#[tokio::test]
async fn file_write_sign_requires_object_fields_and_valid_base64() {
    let registry = CommandRegistry::with_defaults();
    assert!(registry.has("fileWriteSign"));
    let session = WsSession::new(AppState::new("test"), Some("1Fixture".into()));
    for (field, expected) in [
        ("inner_path", "inner_path required"),
        ("content_base64", "content_base64 required"),
        ("expected_base64", "expected_base64 required"),
    ] {
        let mut value = params(INNER);
        value.as_object_mut().unwrap().remove(field);
        let error = registry.dispatch(&session, "fileWriteSign", &value, 1).await.unwrap_err();
        assert!(error.contains(expected), "{error}");
    }
    for field in ["content_base64", "expected_base64"] {
        let mut value = params(INNER);
        value[field] = json!("%%%not-base64");
        let error = registry.dispatch(&session, "fileWriteSign", &value, 1).await.unwrap_err();
        assert!(error.contains(&format!("invalid {field}")), "{error}");
    }
}

#[tokio::test]
async fn file_write_sign_stored_key_commits_from_page_session() {
    let (_directory, state, address, key, storage) = fixture().await;
    state.set_xite_privatekey(&address, &key).await.unwrap();
    let session = WsSession::new(state, Some(address.clone()));
    let result = CommandRegistry::with_defaults().dispatch(&session, "fileWriteSign", &params(INNER), 1).await.unwrap();
    assert_eq!(result, "ok");
    assert_eq!(storage.read(INNER).unwrap(), AFTER);
    let child: Value = serde_json::from_slice(&storage.read("data/admin/content.json").unwrap()).unwrap();
    assert!(child["signs"][&address].is_string());
    assert_eq!(child["files"]["admin-settings.json"]["sha512"], XiteStorage::hash_bytes(AFTER));
}

#[tokio::test]
async fn file_write_sign_missing_stored_key_and_wrong_explicit_key_leave_files_unchanged() {
    let (_directory, state, address, _key, storage) = fixture().await;
    let manifest = storage.read("data/admin/content.json").unwrap();
    let session = WsSession::new(state, Some(address));
    let registry = CommandRegistry::with_defaults();
    let missing = registry.dispatch(&session, "fileWriteSign", &params(INNER), 1).await.unwrap_err();
    assert!(missing.contains("Private key not found"), "{missing}");
    let mut wrong = params(INNER);
    wrong["privatekey"] = json!(epix_crypt::new_seed());
    let rejected = registry.dispatch(&session, "fileWriteSign", &wrong, 2).await.unwrap_err();
    assert!(rejected.contains("Valid signs: 0/1"), "{rejected}");
    assert_eq!(storage.read(INNER).unwrap(), BEFORE);
    assert_eq!(storage.read("data/admin/content.json").unwrap(), manifest);
}

#[tokio::test]
async fn file_write_sign_respects_cors_and_merger_target_permissions() {
    let (_directory, state, address, key, storage) = fixture().await;
    state.set_xite_privatekey(&address, &key).await.unwrap();
    let caller = "1Caller";
    state.add_xite(caller, XiteEntry {
        storage: XiteStorage::new(storage.root().parent().unwrap().join(caller)),
        content: None,
    }).await;
    let session = WsSession::new(state.clone(), Some(caller.into()));
    let registry = CommandRegistry::with_defaults();
    for inner in [format!("cors-{address}/{INNER}"), format!("merged-Talk/{address}/{INNER}")] {
        let error = registry.dispatch(&session, "fileWriteSign", &params(&inner), 1).await.unwrap_err();
        assert!(error.contains("permission"), "{error}");
    }
    assert_eq!(storage.read(INNER).unwrap(), BEFORE);
    state.add_permission(caller, "Merger:Talk").await;
    let result = registry.dispatch(&session, "fileWriteSign", &params(&format!("merged-Talk/{address}/{INNER}")), 2).await.unwrap();
    assert_eq!(result, "ok", "stored key must resolve from the target, not the caller");
    assert_eq!(storage.read(INNER).unwrap(), AFTER);
}

#[tokio::test]
async fn file_write_sign_gateway_checks_bound_and_routed_target_even_with_admin_or_forged_id() {
    let (_directory, state, address, key, storage) = fixture().await;
    state.set_xite_privatekey(&address, &key).await.unwrap();
    state.set_owned(&address, false).await;
    state.add_permission(&address, "ADMIN").await;
    state.config_set("ui_restrict", json!(true)).await;
    let registry = CommandRegistry::with_defaults();
    let page = WsSession::new(state.clone(), Some(address.clone()));
    for id in [1, WRAPPER_ID_BASE] {
        let error = registry.dispatch(&page, "fileWriteSign", &params(INNER), id).await.unwrap_err();
        assert!(error.contains("read-only gateway"), "{error}");
    }
    let caller = "1OwnedCaller";
    state.add_xite(caller, XiteEntry {storage: XiteStorage::new(storage.root().parent().unwrap().join(caller)), content: None}).await;
    state.set_owned(caller, true).await;
    state.add_permission(caller, &format!("Cors:{address}")).await;
    let routed = WsSession::new(state.clone(), Some(caller.into()));
    let error = registry.dispatch(&routed, "fileWriteSign", &params(&format!("cors-{address}/{INNER}")), WRAPPER_ID_BASE).await.unwrap_err();
    assert!(error.contains("read-only gateway"), "{error}");
    assert_eq!(storage.read(INNER).unwrap(), BEFORE);
    // The operator socket remains the explicit trusted route on a gateway.
    let trusted = WsSession::new_trusted(state, Some(address));
    assert_eq!(registry.dispatch(&trusted, "fileWriteSign", &params(INNER), 1).await.unwrap(), "ok");
    assert_eq!(storage.read(INNER).unwrap(), AFTER);
}
