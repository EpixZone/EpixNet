//! Source upgrades refresh code without resetting a clone's authored data.

use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::sync::Arc;

const POSTS: &[u8] =
    br#"{ "title": "My blog", "post": [{"post_id": 42, "body": "Keep my post"}] }"#;
const EMPTY_POSTS: &[u8] = br#"{"post":[]}"#;

async fn owned_xite(
    state: &Arc<AppState>,
    root: &tempfile::TempDir,
    content: Value,
    files: &[(&str, &[u8])],
) -> (String, XiteStorage) {
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(root.path().join("data").join(&address));
    for (path, bytes) in files {
        storage.write(path, bytes).unwrap();
    }
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: storage.clone(),
                content: Some(content),
            },
        )
        .await;
    state.set_xite_privatekey(&address, &key).await.unwrap();
    state.sign_xite(&address, &key).await.unwrap();
    (address, storage)
}

async fn blog_source(state: &Arc<AppState>, root: &tempfile::TempDir) -> (String, XiteStorage) {
    owned_xite(
        state,
        root,
        json!({"title": "Template Blog", "files": {}}),
        &[
            ("index.html", b"new blog code"),
            ("data-default/data.json", EMPTY_POSTS),
            (
                "data-default/users/content-default.json",
                br#"{"files":{},"ignore":".*"}"#,
            ),
            (
                "data/data.json",
                br#"{"post":[{"body":"Source author's post"}]}"#,
            ),
            (
                "data/users/alice/data.json",
                br#"{"comment":["Source comment"]}"#,
            ),
            (
                "data/users/alice/settings-default.json",
                br#"{"theme":"Source author's theme"}"#,
            ),
        ],
    )
    .await
}

#[tokio::test]
async fn upgrade_preserves_posts_permissions_and_full_target_manifest() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("upgrade-test", root.path());
    let (source, source_storage) = blog_source(&state, &root).await;
    source_storage
        .write("data-default/avatar.jpg", b"starter avatar")
        .unwrap();
    let permissions =
        br#"{"files":{},"ignore":".*","user_contents":{"permissions":{"carol":false}}}"#;
    let (target, target_storage) = owned_xite(
        &state,
        &root,
        json!({"title": "My blog", "cloned_from": source, "clone_root": ".", "files": {}}),
        &[
            ("index.html", b"old code"),
            ("data/data.json", POSTS),
            ("data/users/content.json", permissions),
            (
                "data/users/carol/data.json",
                br#"{"comment":["My comment"]}"#,
            ),
            ("private/draft.txt", b"Do not publish this draft"),
            ("media/local.mp4", b"local video"),
        ],
    )
    .await;

    // Unsigned owner edits on disk must survive as well as the managed view.
    let mut before: Value =
        serde_json::from_slice(&target_storage.read("content.json").unwrap()).unwrap();
    let owner_fields = json!({
        "title": "My edited title",
        "description": "My description",
        "domain": "myblog.epix",
        "xid_name": "myblog",
        "background-color": "#123456",
        "favicon": "my-icon.png",
        "ignore": "private/.*",
        "optional": "media/.*",
        "includes": {"data/users/content.json": {"signers": [], "signers_required": 1}},
        "custom_settings": {"theme": "dark", "author": "Carol"},
        "clone_root": ".",
        "cloned_from": source,
    });
    for (key, value) in owner_fields.as_object().unwrap() {
        before[key] = value.clone();
    }
    before["modified"] = json!(4_000_000_000u64);
    let remote_media = json!({"size": 12, "sha512": "ab".repeat(32)});
    before["files_optional"] = json!({
        "media/remote.mp4": remote_media,
        "data/avatar.jpg": remote_media,
    });
    target_storage
        .write("content.json", &serde_json::to_vec(&before).unwrap())
        .unwrap();

    let mut previous_modified = before["modified"].as_f64().unwrap();
    for (code, starter) in [
        (b"new blog code".as_slice(), EMPTY_POSTS),
        (
            b"newer blog code".as_slice(),
            br#"{"post":[],"new_setting":true}"#.as_slice(),
        ),
    ] {
        source_storage.write("index.html", code).unwrap();
        source_storage
            .write("data-default/data.json", starter)
            .unwrap();
        assert_eq!(
            state
                .clone_xite(&source, ".", Some(target.clone()))
                .await
                .unwrap(),
            target
        );
        assert_eq!(target_storage.read("index.html").unwrap(), code);
        assert_eq!(target_storage.read("data/data.json").unwrap(), POSTS);
        assert_eq!(
            target_storage.read("data/users/content.json").unwrap(),
            permissions
        );
        assert!(target_storage.exists("data/users/carol/data.json"));
        assert!(!target_storage.exists("data/users/alice/data.json"));
        assert!(!target_storage.exists("data/users/alice/settings-default.json"));
        assert!(!target_storage.exists("data/users/alice/settings.json"));
        assert_eq!(
            target_storage.read("data-default/data.json").unwrap(),
            starter
        );

        let after: Value =
            serde_json::from_slice(&target_storage.read("content.json").unwrap()).unwrap();
        for (key, value) in owner_fields.as_object().unwrap() {
            assert_eq!(
                &after[key], value,
                "owner field {key} changed during upgrade"
            );
        }
        assert_eq!(after["files_optional"]["media/remote.mp4"], remote_media);
        assert_eq!(after["files_optional"]["data/avatar.jpg"], remote_media);
        assert!(!target_storage.exists("data/avatar.jpg"));
        assert!(after["files_optional"]["media/local.mp4"].is_object());
        assert!(after["files"].get("private/draft.txt").is_none());
        assert!(after["modified"].as_f64().unwrap() > previous_modified);
        previous_modified = after["modified"].as_f64().unwrap();
        assert!(epix_content::verify_signer(&after, &target));
    }
}

#[tokio::test]
async fn fresh_and_second_generation_clones_keep_empty_defaults() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("upgrade-test", root.path());
    let (source, _) = blog_source(&state, &root).await;
    let first = state.clone_xite(&source, "", None).await.unwrap();
    let first_storage = XiteStorage::new(root.path().join("data").join(&first));
    assert_eq!(first_storage.read("data/data.json").unwrap(), EMPTY_POSTS);
    assert_eq!(
        first_storage.read("data-default/data.json").unwrap(),
        EMPTY_POSTS
    );
    assert!(!first_storage.exists("data/users/alice/data.json"));
    assert!(!first_storage.exists("data/users/alice/settings-default.json"));
    assert!(!first_storage.exists("data/users/alice/settings.json"));
    first_storage.write("data/data.json", POSTS).unwrap();

    let second = state.clone_xite(&first, "", None).await.unwrap();
    let second_storage = XiteStorage::new(root.path().join("data").join(second));
    assert_eq!(second_storage.read("data/data.json").unwrap(), EMPTY_POSTS);
    assert_eq!(first_storage.read("data/data.json").unwrap(), POSTS);
}

#[tokio::test]
async fn upgrade_from_subdirectory_keeps_existing_defaults_and_seeds_missing_files() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("upgrade-test", root.path());
    let (source, _) = owned_xite(
        &state,
        &root,
        json!({"title": "Templates", "files": {}}),
        &[
            ("outside.txt", b"outside clone root"),
            ("templates/blog/index.html", b"new code"),
            (
                "templates/blog/settings.json-default",
                br#"{"theme":"default"}"#,
            ),
            ("templates/blog/settings.json", br#"{"theme":"source"}"#),
            ("templates/blog/new.json-default", br#"{"new":true}"#),
            ("templates/blog/data-default/data.json", EMPTY_POSTS),
            (
                "templates/blog/data-default/new.json",
                br#"{"new_nested":true}"#,
            ),
            ("templates/blog/data/data.json", br#"{"post":["source"]}"#),
            ("templates/blog/database.js", b"new database code"),
            ("templates/blog/settings.json.bak", b"new adjacent code"),
        ],
    )
    .await;
    let (target, storage) = owned_xite(
        &state,
        &root,
        json!({"title": "My blog", "clone_root": "templates/blog", "cloned_from": source, "files": {}}),
        &[
            ("index.html", b"old code"),
            ("settings.json", br#"{"theme":"mine"}"#),
            ("data/data.json", POSTS),
            ("database.js", b"old database code"),
            ("settings.json.bak", b"old adjacent code"),
        ],
    ).await;
    state
        .clone_xite(&source, "templates/blog", Some(target))
        .await
        .unwrap();
    assert_eq!(storage.read("index.html").unwrap(), b"new code");
    assert_eq!(
        storage.read("settings.json").unwrap(),
        br#"{"theme":"mine"}"#
    );
    assert_eq!(storage.read("data/data.json").unwrap(), POSTS);
    assert_eq!(storage.read("new.json").unwrap(), br#"{"new":true}"#);
    assert_eq!(
        storage.read("data/new.json").unwrap(),
        br#"{"new_nested":true}"#
    );
    assert_eq!(storage.read("database.js").unwrap(), b"new database code");
    assert_eq!(
        storage.read("settings.json.bak").unwrap(),
        b"new adjacent code"
    );
    assert!(storage.exists("settings.json-default"));
    assert!(storage.exists("data-default/data.json"));
    assert!(!storage.exists("outside.txt"));
    assert!(!storage.root().join("templates").exists());
}

#[tokio::test]
async fn upgrade_rejects_invalid_target_manifest_before_replacing_files() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("upgrade-test", root.path());
    let (source, _) = blog_source(&state, &root).await;
    let (target, storage) = owned_xite(
        &state,
        &root,
        json!({"title": "My blog", "files": {}}),
        &[("index.html", b"old code"), ("data/data.json", POSTS)],
    )
    .await;
    for invalid in [b"invalid JSON".as_slice(), b"[]".as_slice()] {
        storage.write("content.json", invalid).unwrap();
        assert!(state
            .clone_xite(&source, "", Some(target.clone()))
            .await
            .is_err());
        assert_eq!(storage.read("content.json").unwrap(), invalid);
        assert_eq!(storage.read("index.html").unwrap(), b"old code");
        assert_eq!(storage.read("data/data.json").unwrap(), POSTS);
    }

    storage.delete("content.json").unwrap();
    assert!(state
        .clone_xite(&source, "", Some(target.clone()))
        .await
        .is_err());
    assert!(!storage.exists("content.json"));
    assert_eq!(storage.read("index.html").unwrap(), b"old code");

    // A directory at the manifest path reliably fails reads, even as root.
    std::fs::create_dir(storage.root().join("content.json")).unwrap();
    assert!(state.clone_xite(&source, "", Some(target)).await.is_err());
    assert_eq!(storage.read("index.html").unwrap(), b"old code");
    assert_eq!(storage.read("data/data.json").unwrap(), POSTS);
}

const USER_GOVERNOR_DEFAULT: &[u8] = br#"{
    "files":{}, "signs":{}, "ignore":".*",
    "user_contents":{"cert_signers":{},"permissions":{},
        "permission_rules":{".*":{"files_allowed":"data.json","max_size":200000}}}
}"#;
const ADMIN_GOVERNOR_DEFAULT: &[u8] = br#"{"files":{},"signs":{}}"#;

async fn forum_source(state: &Arc<AppState>, root: &tempfile::TempDir) -> (String, XiteStorage) {
    owned_xite(
        state,
        root,
        json!({
            "title":"Forum template", "files":{},
            "includes":{
                "data/users/content.json":{"signers":[],"signers_required":1},
                "data/admin/content.json":{"signers":[],"signers_required":1}
            }
        }),
        &[
            ("index.html", b"forum code"),
            (
                "data-default/users/content-default.json",
                USER_GOVERNOR_DEFAULT,
            ),
            (
                "data-default/admin/content-default.json",
                ADMIN_GOVERNOR_DEFAULT,
            ),
            (
                "data-default/admin/admin-settings.json",
                br#"{"mods":[],"pinned_topic_uris":[]}"#,
            ),
        ],
    )
    .await
}

fn assert_owned_manifest(storage: &XiteStorage, path: &str, owner: &str) -> Value {
    let content: Value = serde_json::from_slice(&storage.read(path).unwrap()).unwrap();
    assert!(
        epix_content::verify_signer(&content, owner),
        "{path} must be signed by the clone owner"
    );
    assert_eq!(content["address"], owner);
    assert_eq!(content["inner_path"], path);
    content
}

#[tokio::test]
async fn fresh_clone_signs_default_governors_for_each_generation() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("clone-governors-test", root.path());
    let (source, _) = forum_source(&state, &root).await;
    let first = state.clone_xite(&source, "", None).await.unwrap();
    let second = state.clone_xite(&first, "", None).await.unwrap();
    for address in [&first, &second] {
        let storage = XiteStorage::new(root.path().join("data").join(address));
        assert_owned_manifest(&storage, "data/users/content.json", address);
        let admin = assert_owned_manifest(&storage, "data/admin/content.json", address);
        assert_eq!(
            admin["files"]["admin-settings.json"]["sha512"],
            XiteStorage::hash_bytes(&storage.read("data/admin/admin-settings.json").unwrap())
        );
        assert_eq!(
            storage
                .read("data-default/users/content-default.json")
                .unwrap(),
            USER_GOVERNOR_DEFAULT
        );
    }
}

#[tokio::test]
async fn fresh_clone_user_content_signing_has_a_verified_governor() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("clone-user-signing-test", root.path());
    let (source, _) = forum_source(&state, &root).await;
    let address = state.clone_xite(&source, "", None).await.unwrap();
    let storage = XiteStorage::new(root.path().join("data").join(&address));
    let author_key = epix_crypt::new_seed();
    let author = epix_crypt::privatekey_to_address(&author_key).unwrap();
    let child = format!("data/users/{author}/content.json");
    storage
        .write(
            &format!("data/users/{author}/data.json"),
            br#"{"topic":[]}"#,
        )
        .unwrap();
    state
        .sign_user_content(&address, &child, Some(author_key), None)
        .await
        .expect("a fresh clone must accept user writes through its instantiated governor");
    let content: Value = serde_json::from_slice(&storage.read(&child).unwrap()).unwrap();
    assert!(epix_content::verify_signer(&content, &author));
}

#[tokio::test]
async fn fresh_clone_initializes_declared_nested_governors_parent_first() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("nested-clone-test", root.path());
    let (source, _) = owned_xite(&state, &root, json!({
        "title":"Nested template", "files":{},
        "includes":{"data/config/content.json":{"signers":[],"signers_required":1}}
    }), &[
        ("index.html", b"nested template"),
        ("data-default/config/content-default.json", br#"{"files":{},"signs":{},"includes":{"nested/content.json":{"signers":[],"signers_required":1}}}"#),
        ("data-default/config/nested/content-default.json", ADMIN_GOVERNOR_DEFAULT),
        ("data-default/config/nested/settings.json", br#"{"theme":"default"}"#),
    ]).await;
    let address = state.clone_xite(&source, "", None).await.unwrap();
    let storage = XiteStorage::new(root.path().join("data").join(&address));
    assert_owned_manifest(&storage, "data/config/content.json", &address);
    assert_owned_manifest(&storage, "data/config/nested/content.json", &address);
    assert!(
        state
            .edx_read_verified_signed(&address, "data/config/nested/content.json", 100_000)
            .await
            .is_some(),
        "nested manifest must be in the accepted authority chain"
    );
}

#[tokio::test]
async fn upgrade_signs_new_default_governor_and_preserves_existing_governor_bytes() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("upgrade-governor-test", root.path());
    let (source, source_storage) = forum_source(&state, &root).await;
    let target = state.clone_xite(&source, "", None).await.unwrap();
    let storage = XiteStorage::new(root.path().join("data").join(&target));
    let owner_key = state.xite_privatekey(&target).await.unwrap();
    // Preserve customized target authority, including unpublished owner edits.
    let custom = br#"{"files":{},"ignore":".*","custom":"keep exact bytes","user_contents":{"permissions":{"carol":false}}}"#;
    storage.write("data/users/content.json", custom).unwrap();
    let mut target_root: Value =
        serde_json::from_slice(&storage.read("content.json").unwrap()).unwrap();
    target_root["includes"]["data/config/content.json"] =
        json!({"signers":[],"signers_required":1});
    source_storage
        .write(
            "data-default/config/content-default.json",
            ADMIN_GOVERNOR_DEFAULT,
        )
        .unwrap();
    source_storage
        .write("data-default/config/settings.json", br#"{"new":true}"#)
        .unwrap();
    // Existing target data must not be overwritten while code is upgraded.
    storage
        .write(
            "data/admin/admin-settings.json",
            br#"{"mods":["mine.epix"]}"#,
        )
        .unwrap();
    state
        .sign_user_content(&target, "data/admin/content.json", Some(owner_key), None)
        .await
        .unwrap();
    let existing_admin = storage.read("data/admin/content.json").unwrap();
    storage
        .write("content.json", &serde_json::to_vec(&target_root).unwrap())
        .unwrap();
    state
        .clone_xite(&source, "", Some(target.clone()))
        .await
        .unwrap();
    assert_eq!(storage.read("data/users/content.json").unwrap(), custom);
    assert_eq!(
        storage.read("data/admin/content.json").unwrap(),
        existing_admin
    );
    assert_eq!(
        storage.read("data/admin/admin-settings.json").unwrap(),
        br#"{"mods":["mine.epix"]}"#
    );
    assert_owned_manifest(&storage, "data/config/content.json", &target);
}

#[tokio::test]
async fn fresh_clone_rejects_a_malformed_instantiated_governor() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("malformed-clone-test", root.path());
    let (source, storage) = forum_source(&state, &root).await;
    storage
        .write("data-default/users/content-default.json", b"{broken")
        .unwrap();
    let error = state
        .clone_xite(&source, "", None)
        .await
        .expect_err("clone must report an unusable declared default governor");
    assert!(error.contains("data/users/content.json"), "{error}");
}

#[tokio::test]
async fn upgrade_rejects_a_noncanonical_include_in_a_preserved_manifest() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("preserved-include-test", root.path());
    let (source, _) = forum_source(&state, &root).await;
    let target = state.clone_xite(&source, "", None).await.unwrap();
    let storage = XiteStorage::new(root.path().join("data").join(&target));
    let preserved =
        br#"{"files":{},"includes":{"./content.json":{}},"custom":"keep this owner draft"}"#;
    storage.write("data/users/content.json", preserved).unwrap();
    let error = state
        .clone_xite(&source, "", Some(target.clone()))
        .await
        .expect_err("a preserved noncanonical include must be rejected before it aliases itself");
    assert!(error.contains("./content.json"), "{error}");
    assert_eq!(storage.read("data/users/content.json").unwrap(), preserved);
}
