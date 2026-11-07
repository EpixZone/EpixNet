//! Recovery from an identity backup taken before a xite's owner key existed.

use super::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;

fn nodes_from_precreation_identity(
    owner_root: &Path,
    recovery_root: &Path,
) -> (Arc<AppState>, Arc<AppState>) {
    let owner = AppState::with_data_dir("key-recovery-test", owner_root);
    std::fs::create_dir_all(recovery_root.join("private")).unwrap();
    std::fs::copy(
        owner_root.join("private/users.json"),
        recovery_root.join("private/users.json"),
    )
    .unwrap();
    let recovery = AppState::with_data_dir("key-recovery-test", recovery_root);
    (owner, recovery)
}

fn signed_manifest(storage: &XiteStorage, address: &str) -> Value {
    let content: Value = serde_json::from_slice(&storage.read("content.json").unwrap()).unwrap();
    assert!(
        epix_content::verify_signer(&content, address),
        "the stored manifest must retain a valid owner signature"
    );
    content
}

async fn copy_published_xite(owner: &AppState, recovery: &Arc<AppState>, address: &str) {
    let source = XiteStorage::new(owner.xite_dir(address).unwrap());
    let content = signed_manifest(&source, address);
    let destination = XiteStorage::new(recovery.xite_dir(address).unwrap());
    // Copy public content only. No post-creation users.json or owner key is
    // transferred from the publishing node to the restored node.
    for path in content["files"].as_object().unwrap().keys() {
        destination
            .write(path, &source.read(path).unwrap())
            .unwrap();
    }
    destination
        .write("content.json", &source.read("content.json").unwrap())
        .unwrap();
    recovery
        .add_xite(
            address,
            XiteEntry {
                storage: destination,
                content: Some(content),
            },
        )
        .await;
    recovery.persist_xites().await;
}

async fn verify_restarted_key_can_sign(
    recovery_root: &Path,
    recovery: Arc<AppState>,
    address: &str,
    expected_key: &str,
) {
    drop(recovery);
    let restarted = AppState::with_data_dir("key-recovery-test", recovery_root);
    assert_eq!(restarted.restore_xites().await, 1);
    let key = restarted
        .xite_privatekey(address)
        .await
        .expect("owner key persisted across restart");
    // Do not put disposable private keys into assertion diagnostics.
    assert!(
        key == expected_key,
        "the persisted key must match the original owner"
    );
    assert_eq!(epix_crypt::privatekey_to_address(&key).unwrap(), address);
    let storage = XiteStorage::new(restarted.xite_dir(address).unwrap());
    let original = signed_manifest(&storage, address);
    storage
        .write("index.html", b"<h1>Updated after identity recovery</h1>")
        .unwrap();
    restarted.sign_xite(address, &key).await.unwrap();
    let updated = signed_manifest(&storage, address);
    assert_eq!(updated.get("address_index"), original.get("address_index"));
    assert_ne!(
        updated["files"]["index.html"]["sha512"],
        original["files"]["index.html"]["sha512"]
    );
    assert!(storage.verify(
        "index.html",
        updated["files"]["index.html"]["sha512"].as_str().unwrap()
    ));
}

async fn recover_then_restart(
    recovery_root: &Path,
    recovery: Arc<AppState>,
    address: &str,
    expected_key: &str,
) {
    assert!(
        recovery.xite_privatekey(address).await.is_none(),
        "backup predates the owner key"
    );
    assert_eq!(recovery.recover_privatekey(address).await, json!("ok"));
    assert!(
        recovery
            .xites
            .read()
            .await
            .get(address)
            .unwrap()
            .settings
            .own
    );
    verify_restarted_key_can_sign(recovery_root, recovery, address, expected_key).await;
}

#[tokio::test]
async fn newly_created_xite_recovers_from_a_precreation_identity_backup() {
    let owner_root = tempfile::tempdir().unwrap();
    let recovery_root = tempfile::tempdir().unwrap();
    let (owner, recovery) =
        nodes_from_precreation_identity(owner_root.path(), recovery_root.path());
    let (address, privatekey) = owner.create_xite().await.unwrap();
    copy_published_xite(&owner, &recovery, &address).await;
    recover_then_restart(recovery_root.path(), recovery, &address, &privatekey).await;
}

#[tokio::test]
async fn newly_cloned_xite_recovers_from_a_precreation_identity_backup() {
    let owner_root = tempfile::tempdir().unwrap();
    let recovery_root = tempfile::tempdir().unwrap();
    let (owner, recovery) =
        nodes_from_precreation_identity(owner_root.path(), recovery_root.path());
    let (source, _) = owner.create_xite().await.unwrap();
    let address = owner.clone_xite(&source, "", None).await.unwrap();
    assert_ne!(address, source);
    let privatekey = owner.xite_privatekey(&address).await.unwrap();
    copy_published_xite(&owner, &recovery, &address).await;
    recover_then_restart(recovery_root.path(), recovery, &address, &privatekey).await;
}

async fn owned_fixture(
    owner: &Arc<AppState>,
    derivation_index: Option<u64>,
    advertised_index: Option<u64>,
) -> (String, String) {
    let privatekey = match derivation_index {
        Some(index) => {
            let user = owner.user.read().await;
            epix_crypt::hd_privatekey(&user.master_seed, index).unwrap()
        }
        None => epix_crypt::new_seed(),
    };
    let address = epix_crypt::privatekey_to_address(&privatekey).unwrap();
    let storage = XiteStorage::new(owner.xite_dir(&address).unwrap());
    let mut content = json!({"address": address, "title": "Recovery fixture", "files": {}});
    if let Some(index) = advertised_index {
        content["address_index"] = json!(index);
    }
    storage
        .write("index.html", format!("<h1>{address}</h1>").as_bytes())
        .unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&content).as_bytes(),
        )
        .unwrap();
    owner
        .add_xite(
            &address,
            XiteEntry {
                storage,
                content: Some(content),
            },
        )
        .await;
    owner
        .set_xite_privatekey(&address, &privatekey)
        .await
        .unwrap();
    owner.sign_xite(&address, &privatekey).await.unwrap();
    (address, privatekey)
}

async fn recovery_stays_unowned_after_restart(
    root: &Path,
    state: Arc<AppState>,
    address: &str,
    expected_error: &str,
) {
    assert!(state.xite_privatekey(address).await.is_none());
    assert_eq!(
        state.recover_privatekey(address).await,
        json!({"error": expected_error})
    );
    assert!(state.xite_privatekey(address).await.is_none());
    assert!(!state.xites.read().await.get(address).unwrap().settings.own);
    drop(state);
    let restarted = AppState::with_data_dir("key-recovery-test", root);
    assert_eq!(restarted.restore_xites().await, 1);
    assert!(restarted.xite_privatekey(address).await.is_none());
    assert!(
        !restarted
            .xites
            .read()
            .await
            .get(address)
            .unwrap()
            .settings
            .own
    );
}

#[tokio::test]
async fn full_users_backup_retains_owner_key_without_manifest_recovery_index() {
    let owner_root = tempfile::tempdir().unwrap();
    let recovery_root = tempfile::tempdir().unwrap();
    let owner = AppState::with_data_dir("key-recovery-test", owner_root.path());
    let (address, privatekey) = owner.create_xite().await.unwrap();
    // Model a previously created xite: its saved owner key exists but its
    // valid published manifest has no recovery metadata.
    let storage = XiteStorage::new(owner.xite_dir(&address).unwrap());
    let mut legacy = signed_manifest(&storage, &address);
    legacy.as_object_mut().unwrap().remove("address_index");
    epix_content::sign(&mut legacy, &privatekey).unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&legacy).as_bytes(),
        )
        .unwrap();
    std::fs::create_dir_all(recovery_root.path().join("private")).unwrap();
    std::fs::copy(
        owner_root.path().join("private/users.json"),
        recovery_root.path().join("private/users.json"),
    )
    .unwrap();
    let recovery = AppState::with_data_dir("key-recovery-test", recovery_root.path());
    copy_published_xite(&owner, &recovery, &address).await;
    assert!(recovery.xite_privatekey(&address).await.as_deref() == Some(privatekey.as_str()));
    assert_eq!(
        recovery.recover_privatekey(&address).await,
        json!({"error": "This xite already has a saved private key"})
    );
    verify_restarted_key_can_sign(recovery_root.path(), recovery, &address, &privatekey).await;
}

#[tokio::test]
async fn another_users_seed_does_not_recover_or_persist_an_owner_key() {
    let owner_root = tempfile::tempdir().unwrap();
    let recovery_root = tempfile::tempdir().unwrap();
    let owner = AppState::with_data_dir("key-recovery-test", owner_root.path());
    let recovery = AppState::with_data_dir("key-recovery-test", recovery_root.path());
    let (address, _) = owned_fixture(&owner, Some(17), Some(17)).await;
    copy_published_xite(&owner, &recovery, &address).await;
    recovery_stays_unowned_after_restart(
        recovery_root.path(),
        recovery,
        &address,
        "Unable to deliver private key for this xite from current user's master_seed",
    )
    .await;
}

#[tokio::test]
async fn a_signed_but_incorrect_index_does_not_persist_an_owner_key() {
    let owner_root = tempfile::tempdir().unwrap();
    let recovery_root = tempfile::tempdir().unwrap();
    let (owner, recovery) =
        nodes_from_precreation_identity(owner_root.path(), recovery_root.path());
    let (address, _) = owned_fixture(&owner, Some(23), Some(24)).await;
    copy_published_xite(&owner, &recovery, &address).await;
    recovery_stays_unowned_after_restart(
        recovery_root.path(),
        recovery,
        &address,
        "Unable to deliver private key for this xite from current user's master_seed",
    )
    .await;
}

#[tokio::test]
async fn imported_owner_key_without_an_index_cannot_be_recreated_from_the_seed() {
    let owner_root = tempfile::tempdir().unwrap();
    let recovery_root = tempfile::tempdir().unwrap();
    let (owner, recovery) =
        nodes_from_precreation_identity(owner_root.path(), recovery_root.path());
    let (address, _) = owned_fixture(&owner, None, None).await;
    copy_published_xite(&owner, &recovery, &address).await;
    recovery_stays_unowned_after_restart(
        recovery_root.path(),
        recovery,
        &address,
        "No address_index in content.json",
    )
    .await;
}

#[tokio::test]
async fn clone_upgrade_preserves_target_index_zero_or_its_existing_absence() {
    for index in [Some(0), None] {
        let owner_root = tempfile::tempdir().unwrap();
        let recovery_root = tempfile::tempdir().unwrap();
        let (owner, recovery) =
            nodes_from_precreation_identity(owner_root.path(), recovery_root.path());
        let (source, _) = owned_fixture(&owner, Some(31), Some(31)).await;
        let (address, privatekey) = owned_fixture(&owner, index, index).await;
        assert_eq!(
            owner
                .clone_xite(&source, "", Some(address.clone()))
                .await
                .unwrap(),
            address
        );
        let storage = XiteStorage::new(owner.xite_dir(&address).unwrap());
        let content = signed_manifest(&storage, &address);
        assert_eq!(
            content.get("address_index"),
            index.map(|index| json!(index)).as_ref()
        );
        assert_eq!(
            storage.read("index.html").unwrap(),
            format!("<h1>{source}</h1>").as_bytes()
        );
        assert!(owner.xite_privatekey(&address).await.as_deref() == Some(privatekey.as_str()));
        copy_published_xite(&owner, &recovery, &address).await;
        if index.is_some() {
            recover_then_restart(recovery_root.path(), recovery, &address, &privatekey).await;
        } else {
            recovery_stays_unowned_after_restart(
                recovery_root.path(),
                recovery,
                &address,
                "No address_index in content.json",
            )
            .await;
        }
    }
}

#[tokio::test]
async fn changing_the_published_derivation_index_invalidates_the_owner_signature() {
    let root = tempfile::tempdir().unwrap();
    let owner = AppState::with_data_dir("key-recovery-test", root.path());
    let (address, _) = owned_fixture(&owner, Some(0), Some(0)).await;
    let storage = XiteStorage::new(owner.xite_dir(&address).unwrap());
    let mut changed = signed_manifest(&storage, &address);
    changed["address_index"] = json!(1);
    assert!(!epix_content::verify_signer(&changed, &address));
}
