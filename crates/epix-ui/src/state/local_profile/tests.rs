use super::{
    protocol::{self, Keys},
    storage::{Document, Documents},
    View,
};
use crate::{
    command::{CommandRegistry, WsSession},
    state::{AppState, XiteEntry},
};
use base64::Engine;
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

fn key(seed: u8, xite: &str) -> Keys {
    Keys::from_seed(&hex::encode([seed; 32]), xite).unwrap()
}
fn xite() -> String {
    epix_crypt::privatekey_to_address(&hex::encode([99; 32])).unwrap()
}

#[test]
fn keys_are_stable_domain_separated_and_xite_scoped() {
    let a = xite();
    let b = epix_crypt::privatekey_to_address(&hex::encode([98; 32])).unwrap();
    let first = key(1, &a);
    let restored = key(1, &a);
    let other = key(1, &b);
    assert_eq!(first.author, restored.author);
    assert_eq!(first.public, restored.public);
    assert_ne!(first.author, other.author);
    assert_ne!(first.public, other.public);
    assert_ne!(
        first.author,
        epix_crypt::pubkey_to_address(&hex::decode(&first.public).unwrap()).unwrap()
    );
    assert_ne!(first.author, key(2, &a).author);
}

#[test]
fn profiles_reject_tampering_cross_xite_and_malformed_encryption_keys() {
    let a = xite();
    let keys = key(1, &a);
    let profile = keys.profile("Alice", None).unwrap();
    protocol::verify_profile(&profile, &a).unwrap();
    let mut forged = profile.clone();
    forged["display_name"] = json!("Mallory");
    assert!(protocol::verify_profile(&forged, &a).is_err());
    assert!(protocol::verify_profile(&profile, &key(2, &a).author).is_err());
    let mut invalid = profile.clone();
    invalid["encryption_key"] = json!("02ff");
    assert!(protocol::verify_profile(&invalid, &a).is_err());
    assert!(keys.profile("\0private", None).is_err());
}

#[test]
fn groups_encrypt_to_authenticated_members_and_reject_outsiders() {
    let a = xite();
    let alice = key(1, &a);
    let bob = key(2, &a);
    let outsider = key(3, &a);
    let pa = alice.profile("Alice", None).unwrap();
    let pb = bob.profile("Bob", None).unwrap();
    let group = alice.group("Private title", &[pb], &pa).unwrap();
    let envelope = alice.seal(&group, "message", "private content").unwrap();
    let encoded = serde_json::to_string(&envelope).unwrap();
    assert!(!encoded.contains("Private title"));
    assert!(!encoded.contains("private content"));
    assert!(!encoded.contains(&bob.author));
    for member in [&alice, &bob] {
        let opened = member.open(&envelope, &mut 8).unwrap();
        assert_eq!(opened["text"], "private content");
        assert_eq!(opened["group_id"], protocol::group_id(&group));
    }
    assert_eq!(
        outsider.open(&envelope, &mut 8).unwrap_err(),
        "Not a recipient"
    );
    assert!(outsider.seal(&group, "message", "intrusion").is_err());
    assert!(key(1, &bob.author).open(&envelope, &mut 8).is_err());
}

#[test]
fn group_membership_is_immutable_and_duplicate_or_forged_profiles_fail() {
    let a = xite();
    let alice = key(1, &a);
    let bob = key(2, &a);
    let pa = alice.profile("Alice", None).unwrap();
    let pb = bob.profile("Bob", None).unwrap();
    let g1 = alice.group("One", &[pb.clone()], &pa).unwrap();
    let g2 = alice.group("One", &[], &pa).unwrap();
    assert_ne!(protocol::group_id(&g1), protocol::group_id(&g2));
    assert!(alice
        .group("Duplicates", &[pb.clone(), pb.clone()], &pa)
        .is_err());
    let mut fake = pb;
    fake["author"] = pa["author"].clone();
    assert!(alice.group("Fake", &[fake], &pa).is_err());
    let mut modified = g1;
    modified["members"] = json!([pa]);
    assert!(alice.seal(&modified, "message", "test").is_err());
}

#[test]
fn private_envelope_tamper_and_bounded_decryption_fail_closed() {
    let a = xite();
    let alice = key(1, &a);
    let pa = alice.profile("Alice", None).unwrap();
    let group = alice.group("Only me", &[], &pa).unwrap();
    let envelope = alice.seal(&group, "message", "content").unwrap();
    assert_eq!(
        alice.open(&envelope, &mut 0).unwrap_err(),
        "Private read budget exhausted"
    );
    for field in ["id", "author", "sent_at", "boxes"] {
        let mut bad = envelope.clone();
        bad[field] = Value::Null;
        assert!(alice.open(&bad, &mut 8).is_err(), "{field}");
    }
    assert!(alice
        .public_post(&pa, "lobby", &"x".repeat(protocol::MAX_TEXT + 1))
        .is_err());
}

#[test]
fn list_deduplicates_signed_messages_and_rejects_author_swapping() {
    let a = xite();
    let alice = key(1, &a);
    let bob = key(2, &a);
    let pa = alice.profile("Alice", None).unwrap();
    let record = alice.public_post(&pa, "lobby", "hello").unwrap();
    let mut doc = Document::default();
    doc.append(pa).unwrap();
    doc.append(record.clone()).unwrap();
    doc.append(record.clone()).unwrap();
    let view = View::build(
        &alice,
        Documents {
            docs: vec![(alice.author.clone(), doc.clone())],
            truncated: false,
            rejected: 0,
        },
    )
    .unwrap();
    assert_eq!(view.public_messages.len(), 1);
    let bad = View::build(
        &alice,
        Documents {
            docs: vec![(bob.author, doc)],
            truncated: false,
            rejected: 0,
        },
    )
    .unwrap();
    assert!(bad.profiles.is_empty());
    assert!(bad.public_messages.is_empty());
    assert_eq!(bad.rejected, 1);
}

#[test]
fn private_groups_recover_from_signed_history_after_seed_restore() {
    let a = xite();
    let alice = key(1, &a);
    let pa = alice.profile("Alice", None).unwrap();
    let group = alice.group("Saved group", &[], &pa).unwrap();
    let mut doc = Document::default();
    doc.append(pa).unwrap();
    doc.append(alice.seal(&group, "invitation", "").unwrap())
        .unwrap();
    let restored = key(1, &a);
    let view = View::build(
        &restored,
        Documents {
            docs: vec![(alice.author, doc)],
            truncated: false,
            rejected: 0,
        },
    )
    .unwrap();
    assert_eq!(view.groups.len(), 1);
    assert_eq!(view.groups[0]["title"], "Saved group");
    assert!(restored
        .seal(
            &view.signed_groups[&protocol::group_id(&group)],
            "message",
            "After restart"
        )
        .is_ok());
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: Arc<AppState>,
    storage: XiteStorage,
    address: String,
    owner: String,
    root: Value,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let owner = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&owner).unwrap();
        let storage = XiteStorage::new(dir.path().join("data").join(&address));
        let mut parent = json!({"address":address,"inner_path":"data/users/content.json","modified":1,"files":{},"user_contents":{
            "cert_signers":{},"permissions":{},"permission_rules":{".*":{"max_size":1048576,"files_allowed":"data\\.json"}}}});
        epix_content::sign(&mut parent, &owner).unwrap();
        storage
            .write(
                "data/users/content.json",
                epix_content::dumps_content(&parent).as_bytes(),
            )
            .unwrap();
        let mut root = json!({"address":address,"modified":1,"files":{},"includes":{"data/users/content.json":{"signers":[address],"signers_required":1}}});
        epix_content::sign(&mut root, &owner).unwrap();
        storage
            .write(
                "content.json",
                epix_content::dumps_content(&root).as_bytes(),
            )
            .unwrap();
        let state = AppState::new("local-profile-test");
        *state.user.write().await = epix_user::User::from_seed(&hex::encode([7; 32])).unwrap();
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root.clone()),
                },
            )
            .await;
        Self {
            _dir: dir,
            state,
            storage,
            address,
            owner,
            root,
        }
    }
    fn session(&self) -> WsSession {
        WsSession::new(self.state.clone(), Some(self.address.clone()))
    }
    async fn grant(&self) {
        self.state
            .add_permission(&self.address, "LOCAL_PROFILE")
            .await;
    }
    async fn write_root_draft(&self, root: &Value) {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(epix_content::dumps_content(root).as_bytes());
        self.call(
            &self.session(),
            "fileWrite",
            json!(["content.json", encoded]),
        )
        .await
        .unwrap();
    }
    async fn call(&self, session: &WsSession, cmd: &str, params: Value) -> Result<Value, String> {
        CommandRegistry::with_defaults()
            .dispatch(session, cmd, &params, 1)
            .await
    }
    async fn create(&self) -> Value {
        self.grant().await;
        self.call(
            &self.session(),
            "localProfileCreate",
            json!({"display_name":"Alice"}),
        )
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn opt_in_permission_gateway_and_as_boundaries_are_enforced() {
    let f = Fixture::new().await;
    let s = f.session();
    let info = f.call(&s, "localProfileInfo", json!({})).await.unwrap();
    assert_eq!(info["granted"], false);
    assert!(info["profile"].is_null());
    assert!(f
        .call(&s, "localProfileCreate", json!({"display_name":"Alice"}))
        .await
        .unwrap_err()
        .contains("permission"));
    f.grant().await;
    let trusted = WsSession::new_trusted(f.state.clone(), Some(f.address.clone()));
    assert!(f
        .call(
            &trusted,
            "as",
            json!({"address":f.address,"cmd":"localProfileInfo","params":{}})
        )
        .await
        .unwrap_err()
        .contains("through as"));
    f.state.config_set("ui_restrict", json!(true)).await;
    assert!(f
        .call(&trusted, "localProfileInfo", json!({}))
        .await
        .unwrap_err()
        .contains("gateways"));
}

#[tokio::test]
async fn native_create_post_and_group_use_signed_children_without_xid() {
    let f = Fixture::new().await;
    let s = f.session();
    let created = f.create().await;
    assert_eq!(created["publish"]["status"], "local_only");
    let author = created["record"]["author"].as_str().unwrap();
    let manifest = format!("data/users/{author}/content.json");
    let data = format!("data/users/{author}/data.json");
    let bytes = f.storage.read(&manifest).unwrap();
    let signed: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        signed["files"]["data.json"]["sha512"],
        XiteStorage::hash_bytes(&f.storage.read(&data).unwrap())
    );
    assert!(signed["signs"].get(author).is_some());
    assert!(signed.get("cert_user_id").is_none());
    f.call(
        &s,
        "localProfilePublicPost",
        json!({"room":"lobby","text":"hello offline"}),
    )
    .await
    .unwrap();
    let invitation = f
        .call(
            &s,
            "localProfileGroupCreate",
            json!({"title":"Local group","profiles":[]}),
        )
        .await
        .unwrap();
    let group = invitation["record"]["group_id"].as_str().unwrap();
    f.call(
        &s,
        "localProfileSeal",
        json!({"group_id":group,"text":"private text"}),
    )
    .await
    .unwrap();
    let list = f.call(&s, "localProfileList", json!({})).await.unwrap();
    assert_eq!(list["profiles"].as_array().unwrap().len(), 1);
    assert_eq!(list["public_messages"][0]["text"], "hello offline");
    assert_eq!(list["private_messages"].as_array().unwrap().len(), 2);
    assert_eq!(list["groups"][0]["title"], "Local group");
    let stored = String::from_utf8(f.storage.read(&data).unwrap()).unwrap();
    assert!(!stored.contains("private text"));
    assert!(!stored.contains("Local group"));
    let seed = f.state.user.read().await.master_seed.clone();
    assert!(!serde_json::to_string(&list).unwrap().contains(&seed));
}

#[tokio::test]
async fn list_rejects_disk_tampering_and_unsigned_peer_files() {
    let f = Fixture::new().await;
    let created = f.create().await;
    let author = created["record"]["author"].as_str().unwrap();
    let data = format!("data/users/{author}/data.json");
    f.storage.write(&data, b"{\"forged\":true}").unwrap();
    let fake = key(8, &f.address);
    let fake_profile = fake.profile("Unsigned", None).unwrap();
    let mut fake_doc = Document::default();
    fake_doc.append(fake_profile).unwrap();
    f.storage
        .write(
            &format!("data/users/{}/data.json", fake.author),
            &serde_json::to_vec(&fake_doc).unwrap(),
        )
        .unwrap();
    let list = f
        .call(&f.session(), "localProfileList", json!({}))
        .await
        .unwrap();
    assert!(list["profiles"].as_array().unwrap().is_empty());
    assert_eq!(list["rejected"], 1);
    assert!(f
        .call(
            &f.session(),
            "localProfilePublicPost",
            json!({"room":"lobby","text":"must fail"})
        )
        .await
        .is_err());
}

#[tokio::test]
async fn root_authority_changes_cannot_be_borrowed_from_old_receipts() {
    let f = Fixture::new().await;
    f.create().await;
    let mut root = f.root.clone();
    root["includes"] = json!({});
    root["modified"] = json!(2);
    epix_content::sign(&mut root, &f.owner).unwrap();
    f.storage
        .write(
            "content.json",
            epix_content::dumps_content(&root).as_bytes(),
        )
        .unwrap();
    assert!(f
        .call(&f.session(), "localProfileList", json!({}))
        .await
        .is_err());
}

#[tokio::test]
async fn concurrent_posts_append_without_loss_and_stale_revision_is_rejected() {
    let f = Fixture::new().await;
    f.create().await;
    let s1 = f.session();
    let s2 = f.session();
    let (a, b) = tokio::join!(
        f.call(
            &s1,
            "localProfilePublicPost",
            json!({"room":"lobby","text":"one"})
        ),
        f.call(
            &s2,
            "localProfilePublicPost",
            json!({"room":"lobby","text":"two"})
        )
    );
    a.unwrap();
    b.unwrap();
    let list = f.call(&s1, "localProfileList", json!({})).await.unwrap();
    assert_eq!(list["public_messages"].as_array().unwrap().len(), 2);
    let keys = key(7, &f.address);
    let profile = keys.profile("Alice", None).unwrap();
    let record = keys.public_post(&profile, "lobby", "stale").unwrap();
    assert!(f
        .state
        .local_commit(&f.address, &keys, 0, record, 1)
        .await
        .unwrap_err()
        .contains("changed"));
}

#[tokio::test]
async fn a_stale_websocket_cannot_adopt_another_local_user() {
    let f = Fixture::new().await;
    f.create().await;
    let s = f.session();
    f.call(&s, "localProfileInfo", json!({})).await.unwrap();
    *f.state.user.write().await = epix_user::User::from_seed(&hex::encode([8; 32])).unwrap();
    assert!(f
        .call(&s, "localProfileInfo", json!({}))
        .await
        .unwrap_err()
        .contains("reopen"));
    let new = f
        .call(&f.session(), "localProfileInfo", json!({}))
        .await
        .unwrap();
    assert!(new["profile"].is_null());
}

#[tokio::test]
async fn native_identity_and_group_survive_reopen_with_same_users_backup() {
    let f = Fixture::new().await;
    let created = f.create().await;
    let s = f.session();
    f.call(
        &s,
        "localProfileGroupCreate",
        json!({"title":"Restored","profiles":[]}),
    )
    .await
    .unwrap();
    let path = f._dir.path().join("users.json");
    f.state.user.read().await.save(&path).unwrap();
    let state = AppState::new("restored-profile-test");
    *state.user.write().await = epix_user::User::load_or_create(&path).unwrap();
    state
        .add_xite(
            &f.address,
            XiteEntry {
                storage: f.storage.clone(),
                content: Some(f.root.clone()),
            },
        )
        .await;
    state.add_permission(&f.address, "LOCAL_PROFILE").await;
    let session = WsSession::new(state, Some(f.address.clone()));
    let list = f
        .call(&session, "localProfileList", json!({}))
        .await
        .unwrap();
    assert_eq!(list["profiles"][0]["author"], created["record"]["author"]);
    assert_eq!(list["groups"][0]["title"], "Restored");
}

#[test]
fn maximum_group_can_read_a_full_length_message() {
    let address = xite();
    let alice = key(1, &address);
    let own = alice.profile(&"a".repeat(80), None).unwrap();
    let peers: Vec<_> = (2..=8).map(|n| key(n, &address)).collect();
    let profiles: Vec<_> = peers
        .iter()
        .map(|keys| keys.profile(&"b".repeat(80), None).unwrap())
        .collect();
    let group = alice.group(&"g".repeat(120), &profiles, &own).unwrap();
    let envelope = alice
        .seal(&group, "message", &"x".repeat(protocol::MAX_TEXT))
        .unwrap();
    for member in peers.iter().chain(std::iter::once(&alice)) {
        assert_eq!(
            member.open(&envelope, &mut 8).unwrap()["text"]
                .as_str()
                .unwrap()
                .len(),
            protocol::MAX_TEXT
        );
    }
}

#[test]
fn optional_xid_proof_cannot_be_transplanted_to_another_profile() {
    let address = xite();
    let alice = key(1, &address);
    let bob = key(2, &address);
    let auth_key = hex::encode([90; 32]);
    let identity = epix_user::Identity {
        auth_address: epix_crypt::privatekey_to_address(&auth_key).unwrap(),
        auth_privatekey: auth_key,
        name: "alice".into(),
        tld: "epix".into(),
        cert_sign: String::new(),
        linked_at: None,
        hd_index: None,
    };
    let profile = alice.profile("Alice", None).unwrap();
    let linked = alice.link(&profile, &identity).unwrap();
    protocol::verify_profile(&linked, &address).unwrap();
    assert_eq!(linked["author"], profile["author"]);
    assert_eq!(linked["encryption_key"], profile["encryption_key"]);
    let mut other = bob.profile("Bob", None).unwrap();
    other["xid"] = linked["xid"].clone();
    assert!(protocol::verify_profile(&other, &address).is_err());
    assert!(bob.profile("Bob", Some(&linked)).is_err());
}

#[test]
fn signed_off_curve_encryption_key_is_rejected() {
    let address = xite();
    let keys = key(1, &address);
    let mut profile = keys.profile("Alice", None).unwrap();
    profile["encryption_key"] = json!(format!("02{}", "ff".repeat(32)));
    let signing = epix_crypt::private_to_wif(&AppState::consumer_seed(
        &hex::encode([1; 32]),
        "epix/local-profile/sign/v1",
        &address,
    ));
    let payload = format!(
        "epix/local-profile/record/v1\0{}",
        epix_content::record_signed_data(&profile)
    );
    profile["sign"] = json!(epix_crypt::sign(&payload, &signing).unwrap());
    assert!(epix_crypt::verify(
        &payload,
        &keys.author,
        profile["sign"].as_str().unwrap()
    ));
    assert!(protocol::verify_profile(&profile, &address).is_err());
}

#[tokio::test]
async fn trusted_wrapper_grant_is_required_and_describes_the_scope() {
    let f = Fixture::new().await;
    let page = f.session();
    let registry = CommandRegistry::with_defaults();
    assert!(registry
        .dispatch(&page, "permissionAdd", &json!("LOCAL_PROFILE"), 1)
        .await
        .is_err());
    let wrapper = WsSession::new_wrapper(f.state.clone(), Some(f.address.clone()));
    let description = registry
        .dispatch(
            &wrapper,
            "permissionDetails",
            &json!("LOCAL_PROFILE"),
            1_000_001,
        )
        .await
        .unwrap();
    assert!(description.as_str().unwrap().contains("for this xite"));
    assert_eq!(
        registry
            .dispatch(
                &wrapper,
                "permissionAdd",
                &json!("LOCAL_PROFILE"),
                1_000_002
            )
            .await
            .unwrap(),
        "ok"
    );
    assert_eq!(
        f.call(&page, "localProfileInfo", json!({})).await.unwrap()["granted"],
        true
    );
}

#[tokio::test]
async fn disconnect_does_not_release_commit_guard_before_revocation() {
    let f = Fixture::new().await;
    f.grant().await;
    let keys = key(7, &f.address);
    let manifest = format!("data/users/{}/content.json", keys.author);
    let hold = f
        .state
        .acquire_manifest_mutex(&f.address, &manifest)
        .await
        .unwrap();
    let state = f.state.clone();
    let address = f.address.clone();
    let command = tokio::spawn(async move {
        let session = WsSession::new(state, Some(address));
        CommandRegistry::with_defaults()
            .dispatch(
                &session,
                "localProfileCreate",
                &json!({"display_name":"Atomic"}),
                1,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if f.state.local_profile_lock.try_lock().is_err()
                && f.state.xite_activation_gate.try_write().is_err()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    command.abort();
    let _ = command.await;
    let state = f.state.clone();
    let address = f.address.clone();
    let revoke = tokio::spawn(async move {
        state.remove_permission(&address, "LOCAL_PROFILE").await;
    });
    tokio::task::yield_now().await;
    assert!(
        !revoke.is_finished(),
        "revocation must wait for the accepted commit"
    );
    drop(hold);
    tokio::time::timeout(Duration::from_secs(5), revoke)
        .await
        .unwrap()
        .unwrap();
    assert!(f.storage.exists(&manifest));
    assert!(!f
        .state
        .xite_permissions(&f.address)
        .await
        .iter()
        .any(|p| p == "LOCAL_PROFILE"));
}

#[cfg(feature = "multiuser")]
#[tokio::test]
async fn user_switch_waits_for_native_profile_operation_guard() {
    let f = Fixture::new().await;
    let target = epix_user::User::from_seed(&hex::encode([8; 32])).unwrap();
    let next = target.master_address.clone();
    f.state
        .multi_users
        .write()
        .await
        .insert(next.clone(), target);
    let guard = f.state.local_profile_lock.clone().lock_owned().await;
    let state = f.state.clone();
    let switching = tokio::spawn(async move { state.multiuser_select(&next).await });
    tokio::task::yield_now().await;
    assert!(!switching.is_finished());
    assert_eq!(f.state.user.read().await.master_seed, hex::encode([7; 32]));
    drop(guard);
    switching.await.unwrap().unwrap();
    assert_eq!(f.state.user.read().await.master_seed, hex::encode([8; 32]));
}

#[tokio::test]
async fn signed_peer_documents_allow_members_and_exclude_an_outsider() {
    let alice = Fixture::new().await;
    let created = alice.create().await;
    let alice_profile = created["record"]["signed_profile"].clone();
    let bob_keys = key(8, &alice.address);
    let bob_profile = bob_keys.profile("Bob", None).unwrap();
    let invitation = alice
        .call(
            &alice.session(),
            "localProfileGroupCreate",
            json!({"title":"Two members","profiles":[bob_profile]}),
        )
        .await
        .unwrap();
    alice
        .call(
            &alice.session(),
            "localProfileSeal",
            json!({"group_id":invitation["record"]["group_id"],"text":"Only Alice and Bob"}),
        )
        .await
        .unwrap();
    let alice_ref = &alice;
    let make_reader = |seed| async move {
        let state = AppState::new("independent-reader");
        *state.user.write().await = epix_user::User::from_seed(&hex::encode([seed; 32])).unwrap();
        state
            .add_xite(
                &alice_ref.address,
                XiteEntry {
                    storage: alice_ref.storage.clone(),
                    content: Some(alice_ref.root.clone()),
                },
            )
            .await;
        state
            .add_permission(&alice_ref.address, "LOCAL_PROFILE")
            .await;
        WsSession::new(state, Some(alice_ref.address.clone()))
    };
    let bob = make_reader(8).await;
    let outsider = make_reader(9).await;
    let bob_view = alice
        .call(&bob, "localProfileList", json!({}))
        .await
        .unwrap();
    assert_eq!(bob_view["groups"][0]["title"], "Two members");
    assert!(bob_view["private_messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["text"] == "Only Alice and Bob"));
    let other_view = alice
        .call(&outsider, "localProfileList", json!({}))
        .await
        .unwrap();
    assert!(other_view["groups"].as_array().unwrap().is_empty());
    assert!(other_view["private_messages"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(other_view["profiles"][0]["author"], alice_profile["author"]);
}

#[tokio::test]
async fn draft_root_address_cannot_rebind_first_use_profile_decryption() {
    let f = Fixture::new().await;
    f.grant().await;
    let foreign = epix_crypt::privatekey_to_address(&hex::encode([29; 32])).unwrap();
    let victim = Keys::from_seed(&hex::encode([7; 32]), &foreign).unwrap();
    let profile = victim.profile("Foreign profile", None).unwrap();
    let group = victim.group("Foreign group", &[], &profile).unwrap();
    let envelope = victim
        .seal(&group, "message", "foreign scope fixture")
        .unwrap();

    let mut draft = f.root.clone();
    draft["address"] = json!(foreign);
    f.write_root_draft(&draft).await;
    assert_eq!(
        f.state.content(&f.address).await.unwrap()["address"],
        foreign
    );

    // This fresh socket has never initialized its local-profile scope guard.
    let fresh = f.session();
    let result = f
        .call(&fresh, "localProfileOpen", json!({"envelope":envelope}))
        .await;
    assert!(
        result.is_err(),
        "a mutable draft must not select another xite's decryption key"
    );
}

#[tokio::test]
async fn draft_root_cannot_redirect_persisted_profile_revocation() {
    let f = Fixture::new().await;
    f.grant().await;
    let foreign = epix_crypt::privatekey_to_address(&hex::encode([29; 32])).unwrap();
    let mut draft = f.root.clone();
    draft["address"] = json!(foreign);
    f.write_root_draft(&draft).await;
    f.state.remove_permission(&f.address, "LOCAL_PROFILE").await;
    assert!(f.state.xite_permissions(&f.address).await.is_empty());
    assert!(
        !f.state.grants.read().await[&f.address]
            .iter()
            .any(|p| p == "LOCAL_PROFILE"),
        "revocation must remove the original canonical grant from persisted state"
    );
}

#[tokio::test]
async fn verified_registration_alias_uses_the_same_local_profile() {
    let f = Fixture::new().await;
    let alias = "local-profile-fixture.epix";
    f.state
        .add_xite(
            alias,
            XiteEntry {
                storage: f.storage.clone(),
                content: Some(f.root.clone()),
            },
        )
        .await;
    f.grant().await;
    let alias_session = WsSession::new(f.state.clone(), Some(alias.into()));
    let created = f
        .call(
            &alias_session,
            "localProfileCreate",
            json!({"display_name":"Alias"}),
        )
        .await
        .unwrap();
    let canonical = f
        .call(&f.session(), "localProfileInfo", json!({}))
        .await
        .unwrap();
    assert_eq!(canonical["profile"]["author"], created["record"]["author"]);
    assert_eq!(canonical["profile"]["signed_profile"]["xite"], f.address);
}
