//! Public xite export through the existing sidebar URL.
use axum::{
    body::{to_bytes, Body},
    http::{HeaderMap, Request, StatusCode},
};
use epix_blob::{
    store::{Store, StoreConfig},
    Ns, ObjId,
};
use epix_ui::{rewrite_proxy_host, AppState, OnDemandResolver, ResolvedHost, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tower::ServiceExt;

const NAME: &str = "export-fixture.epix";
const PRIVATE: &[u8] = b"private fixture key must never be exported";
const INDEX: &[u8] = b"<!doctype html><link href='assets/all.css'><p>{theme}</p>";
const CSS: &[u8] = b"body { color: #abc; }";
const CHILD: &[u8] = b"signed child public data";
const OPTIONAL: &[u8] = b"available optional data";
const UNICODE: &[u8] = b"unicode public path";

#[derive(Default)]
struct NoFetch(AtomicUsize);

#[async_trait::async_trait]
impl OnDemandResolver for NoFetch {
    async fn ensure(&self, _: &str) -> Result<(), String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("export must not start a clone".into())
    }
    async fn resolve(&self, _: &str) -> Option<ResolvedHost> {
        self.0.fetch_add(1, Ordering::SeqCst);
        None
    }
}

fn file_info(bytes: &[u8]) -> Value {
    json!({"size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes),
           "b3": ObjId::of(bytes).to_string()})
}

struct Fixture {
    directory: tempfile::TempDir,
    state: Arc<AppState>,
    router: axum::Router,
    storage: XiteStorage,
    address: String,
    expected: BTreeMap<String, Vec<u8>>,
    fetch: Arc<NoFetch>,
}

impl Fixture {
    async fn new() -> Self {
        Self::customize(|_, _, _| {}).await
    }

    async fn customize(change: impl FnOnce(&mut Value, &mut Value, &XiteStorage)) -> Self {
        Self::customize_with_key(|root, child, storage, _| change(root, child, storage)).await
    }

    async fn customize_with_key(
        change: impl FnOnce(&mut Value, &mut Value, &XiteStorage, &str),
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(directory.path().join("data").join(&address));
        let mut expected = BTreeMap::new();
        for (path, bytes) in [
            ("index.html", INDEX),
            ("assets/all.css", CSS),
            ("child/data.txt", CHILD),
            ("optional/present.txt", OPTIONAL),
            ("docs/café.txt", UNICODE),
        ] {
            storage.write(path, bytes).unwrap();
            expected.insert(path.to_string(), bytes.to_vec());
        }
        let mut root = json!({
            "address": address, "modified": 1, "files": {
                "index.html": file_info(INDEX), "assets/all.css": file_info(CSS),
                "docs/café.txt": file_info(UNICODE)
            },
            "files_optional": {
                "optional/present.txt": file_info(OPTIONAL),
                "optional/missing.txt": file_info(b"not downloaded")
            },
            "includes": {"child/content.json": {"signers": [address], "signers_required": 1}}
        });
        let mut child = json!({
            "address": address, "inner_path": "child/content.json", "modified": 1,
            "files": {"data.txt": file_info(CHILD)}
        });
        change(&mut root, &mut child, &storage, &key);
        epix_content::sign(&mut root, &key).unwrap();
        epix_content::sign(&mut child, &key).unwrap();
        for (path, content) in [("content.json", &root), ("child/content.json", &child)] {
            let bytes = epix_content::dumps_content(content).into_bytes();
            storage.write(path, &bytes).unwrap();
            expected.insert(path.to_string(), bytes);
        }
        for path in [
            "private/signing-key.json",
            "draft.txt",
            "data.db",
            ".git/config",
            ".staging/secret",
        ] {
            storage.write(path, PRIVATE).unwrap();
        }
        std::fs::create_dir_all(directory.path().join("private")).unwrap();
        for path in [
            "private/users.json",
            "private/config.json",
            "private/transport.key",
        ] {
            std::fs::write(directory.path().join(path), PRIVATE).unwrap();
        }
        let state = AppState::new("zip-test");
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root),
                },
            )
            .await;
        assert!(
            state.has_xite(&address).await,
            "fixture registration failed"
        );
        state.set_display(&address, NAME).await;
        state.config_set("ui_check_cors", json!(true)).await;
        let fetch = Arc::new(NoFetch::default());
        state.set_on_demand(fetch.clone()).await;
        Self {
            directory,
            router: UiServer::new(state.clone()).router(),
            state,
            storage,
            address,
            expected,
            fetch,
        }
    }

    async fn get(&self, host: &str, reference: &str, headers: &[(&str, &str)]) -> Reply {
        let mut request = Request::builder()
            .uri(format!("/EpixNet-Internal/Zip?address={reference}"))
            .header("host", host);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            self.router
                .clone()
                .oneshot(rewrite_proxy_host(request.body(Body::empty()).unwrap())),
        )
        .await
        .expect("a local archive must not wait for peers")
        .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = tokio::time::timeout(
            Duration::from_secs(3),
            to_bytes(response.into_body(), 4 << 20),
        )
        .await
        .expect("bounded fixture archive stalled")
        .unwrap()
        .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    async fn navigation(&self) -> Reply {
        self.get(
            "127.0.0.1:42222",
            &self.address,
            &[("sec-fetch-mode", "navigate")],
        )
        .await
    }

    async fn add_other_xite(&self) -> String {
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(self.directory.path().join("data").join(&address));
        let mut root =
            json!({"address": address, "modified": 1, "files": {"secret.txt": file_info(PRIVATE)}});
        epix_content::sign(&mut root, &key).unwrap();
        storage
            .write(
                "content.json",
                epix_content::dumps_content(&root).as_bytes(),
            )
            .unwrap();
        storage.write("secret.txt", PRIVATE).unwrap();
        self.state
            .add_xite(
                &address,
                XiteEntry {
                    storage,
                    content: Some(root),
                },
            )
            .await;
        address
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn user_merge_fixture() -> (Fixture, String, String, Vec<u8>) {
    let author_key = epix_crypt::new_seed();
    let author = epix_crypt::privatekey_to_address(&author_key).unwrap();
    let child_path = format!("data/users/{author}/content.json");
    let posts_path = format!("data/users/{author}/posts.json");
    let nonce = epix_crypt::new_seed();
    let mut record = json!({
        "post_id": epix_content::derive_post_id(&author, &nonce, 1),
        "nonce": nonce, "author": author, "clock": epix_core::now_ms(),
        "date_added": 1, "body": "public signed record"
    });
    record["sign"] =
        json!(epix_crypt::sign(&epix_content::record_signed_data(&record), &author_key).unwrap());
    let bytes = serde_json::to_vec(&epix_content::make_container(vec![record])).unwrap();
    let mut extra = BTreeMap::new();
    let mut fixture = Fixture::customize_with_key(|root, _, storage, owner_key| {
        root["includes"]["data/users/content.json"] = json!({});
        let mut parent = json!({
            "address": root["address"], "inner_path": "data/users/content.json", "modified": 1,
            "files": {}, "user_contents": {
                "cert_signers": {}, "permissions": {},
                "permission_rules": {".*": {"max_size": 100_000,
                    "merge_files": {"posts.json": {"class": "epix-orset-1", "max_size": 100_000}}}}
            }
        });
        epix_content::sign(&mut parent, owner_key).unwrap();
        let mut child = json!({
            "address": root["address"], "inner_path": child_path, "modified": 1,
            "files": {}, "files_merged": {"posts.json": {"class": "epix-orset-1"}}
        });
        epix_content::sign(&mut child, &author_key).unwrap();
        for (path, content) in [("data/users/content.json", parent), (&child_path, child)] {
            let raw = serde_json::to_vec(&content).unwrap();
            storage.write(path, &raw).unwrap();
            extra.insert(path.to_string(), raw);
        }
        storage.write(&posts_path, &bytes).unwrap();
        extra.insert(posts_path.clone(), bytes.clone());
        // A physically present child with an invalid signature cannot become
        // part of the archive just because its directory looks like a user.
        let bad_key = epix_crypt::new_seed();
        let bad_author = epix_crypt::privatekey_to_address(&bad_key).unwrap();
        let bad_path = format!("data/users/{bad_author}/content.json");
        storage
            .write(
                &bad_path,
                serde_json::to_vec(&json!({
                    "address": root["address"], "inner_path": bad_path, "modified": 1,
                    "files": {"secret.txt": file_info(PRIVATE)}, "signs": {}
                }))
                .unwrap()
                .as_slice(),
            )
            .unwrap();
        storage
            .write(&format!("data/users/{bad_author}/secret.txt"), PRIVATE)
            .unwrap();
    })
    .await;
    fixture.expected.extend(extra);
    (fixture, child_path, posts_path, bytes)
}

#[tokio::test]
async fn exports_only_authorized_user_content_and_verified_merge_records() {
    let (fixture, _, _, _) = user_merge_fixture().await;
    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
    assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejects_invalid_missing_or_oversized_declared_merge_containers() {
    let (fixture, _, posts, valid) = user_merge_fixture().await;
    let mut container: Value = serde_json::from_slice(&valid).unwrap();
    container["post"][0]["body"] = json!("unsigned replacement");
    fixture
        .storage
        .write(&posts, &serde_json::to_vec(&container).unwrap())
        .unwrap();
    fixture.navigation().await.incomplete();
    let mut container: Value = serde_json::from_slice(&valid).unwrap();
    container["unsigned_private"] = json!("must not be exported");
    fixture
        .storage
        .write(&posts, &serde_json::to_vec(&container).unwrap())
        .unwrap();
    fixture.navigation().await.incomplete();
    fixture.storage.write(&posts, &vec![b' '; 100_001]).unwrap();
    fixture.navigation().await.incomplete();
    std::fs::remove_file(fixture.storage.root().join(&posts)).unwrap();
    fixture.navigation().await.incomplete();
}

#[tokio::test]
async fn signed_public_database_and_config_files_are_exported() {
    let mut fixture = Fixture::customize(|root, _, storage| {
        for path in ["public.db", "config.json"] {
            root["files"][path] = file_info(b"declared public content");
            storage.write(path, b"declared public content").unwrap();
        }
    })
    .await;
    for path in ["public.db", "config.json"] {
        fixture
            .expected
            .insert(path.into(), b"declared public content".to_vec());
    }
    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
}

#[tokio::test]
async fn duplicate_json_keys_cannot_hide_unsigned_manifest_or_record_bytes() {
    let (fixture, _, posts, valid) = user_merge_fixture().await;
    let duplicate_record = String::from_utf8(valid).unwrap().replacen(
        "\"body\":",
        "\"\\u0062ody\":\"unsigned private field\",\"body\":",
        1,
    );
    fixture
        .storage
        .write(&posts, duplicate_record.as_bytes())
        .unwrap();
    fixture.navigation().await.incomplete();

    let fixture = Fixture::new().await;
    let raw = String::from_utf8(fixture.storage.read("content.json").unwrap()).unwrap();
    let duplicate = raw.replacen('{', "{\"address\":\"unsigned hidden value\",", 1);
    let parsed: Value = serde_json::from_str(&duplicate).unwrap();
    assert_eq!(parsed, serde_json::from_str::<Value>(&raw).unwrap());
    fixture
        .storage
        .write("content.json", duplicate.as_bytes())
        .unwrap();
    fixture.navigation().await.incomplete();
}

#[tokio::test]
async fn dropping_download_body_releases_export_admission() {
    let fixture = Fixture::new().await;
    let request = || {
        Request::builder()
            .uri(format!("/EpixNet-Internal/Zip?address={}", fixture.address))
            .header("host", "127.0.0.1:42222")
            .header("sec-fetch-mode", "navigate")
            .body(Body::empty())
            .unwrap()
    };
    let response = fixture.router.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let busy = fixture.router.clone().oneshot(request()).await.unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(response);
    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
}

impl Reply {
    fn archive(self) -> BTreeMap<String, Vec<u8>> {
        assert_eq!(
            self.status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&self.body)
        );
        assert_eq!(self.headers["content-type"], "application/zip");
        assert_eq!(self.headers["x-content-type-options"], "nosniff");
        assert!(self.headers["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store"));
        let disposition = self.headers["content-disposition"].to_str().unwrap();
        assert!(disposition.starts_with("attachment;") && disposition.contains(".zip"));
        let mut zip =
            zip::ZipArchive::new(Cursor::new(self.body)).expect("complete ZIP central directory");
        let mut entries = BTreeMap::new();
        for index in 0..zip.len() {
            let mut file = zip.by_index(index).unwrap();
            assert!(!file.is_dir(), "only declared files belong in this fixture");
            let name = file.name().unwrap().into_owned();
            assert!(
                epix_content::verify::is_valid_relative_path(&name),
                "unsafe archive path: {name}"
            );
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            assert!(
                entries.insert(name.clone(), bytes).is_none(),
                "duplicate archive path: {name}"
            );
        }
        entries
    }

    fn incomplete(self) {
        assert!(
            matches!(
                self.status,
                StatusCode::CONFLICT | StatusCode::SERVICE_UNAVAILABLE
            ),
            "missing required content must be explicit, not a partial successful ZIP: {} {}",
            self.status,
            String::from_utf8_lossy(&self.body)
        );
        assert!(!self
            .headers
            .get("content-type")
            .is_some_and(|v| v == "application/zip"));
        let message = String::from_utf8_lossy(&self.body).to_ascii_lowercase();
        assert!(
            message.contains("missing")
                || message.contains("incomplete")
                || message.contains("unavailable")
                || message.contains("changed"),
            "{message}"
        );
    }
}

#[tokio::test]
async fn sidebar_url_exports_only_the_signed_public_snapshot_on_every_origin() {
    let fixture = Fixture::new().await;
    fixture.add_other_xite().await;
    let alias = format!("{}.epix", fixture.address);
    for host in ["127.0.0.1:42222", NAME, alias.as_str()] {
        for reference in [fixture.address.as_str(), NAME, alias.as_str()] {
            let entries = fixture
                .get(host, reference, &[("sec-fetch-mode", "navigate")])
                .await
                .archive();
            assert_eq!(
                entries, fixture.expected,
                "host={host}, reference={reference}"
            );
        }
    }
    assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn query_target_enforces_same_xite_cors_and_foreign_origin_checks() {
    let fixture = Fixture::new().await;
    let source = fixture.add_other_xite().await;
    let local = "127.0.0.1:42222";
    let own_ref = format!("http://{local}/{}/index.html", fixture.address);
    let other_ref = format!("http://{local}/{source}/index.html");
    assert_eq!(
        fixture
            .get(local, &fixture.address, &[("referer", &own_ref)])
            .await
            .archive(),
        fixture.expected
    );
    assert_eq!(
        fixture
            .get(local, &fixture.address, &[("referer", &other_ref)])
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture.get(local, &fixture.address, &[]).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .get(
                local,
                &fixture.address,
                &[("origin", "https://evil.example"), ("referer", &own_ref)]
            )
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    fixture
        .state
        .add_permission(&source, &format!("Cors:{}", fixture.address))
        .await;
    assert_eq!(
        fixture
            .get(local, &fixture.address, &[("referer", &other_ref)])
            .await
            .archive(),
        fixture.expected
    );
    assert_eq!(
        fixture
            .get(
                NAME,
                &fixture.address,
                &[
                    ("origin", "http://export-fixture.epix"),
                    ("referer", "http://export-fixture.epix/index.html")
                ]
            )
            .await
            .archive(),
        fixture.expected
    );
}

#[tokio::test]
async fn missing_required_root_and_child_assets_return_an_explicit_error() {
    for path in ["index.html", "child/data.txt"] {
        let fixture = Fixture::new().await;
        assert_eq!(fixture.navigation().await.archive(), fixture.expected);
        fixture.storage.delete(path).unwrap();
        fixture.navigation().await.incomplete();
        assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn required_child_manifest_missing_at_registration_is_not_silently_omitted() {
    let fixture = Fixture::new().await;
    let root: Value =
        serde_json::from_slice(&fixture.storage.read("content.json").unwrap()).unwrap();
    fixture.storage.delete("child/content.json").unwrap();
    let state = AppState::new("incomplete-zip-test");
    state
        .add_xite(
            &fixture.address,
            XiteEntry {
                storage: fixture.storage.clone(),
                content: Some(root),
            },
        )
        .await;
    let fixture = Fixture {
        router: UiServer::new(state.clone()).router(),
        state,
        ..fixture
    };
    fixture.navigation().await.incomplete();
}

#[tokio::test]
async fn unpublished_replacement_bytes_cannot_be_exported_under_an_accepted_path() {
    let fixture = Fixture::new().await;
    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
    fixture.storage.write("index.html", PRIVATE).unwrap();
    fixture.navigation().await.incomplete();
}

#[tokio::test]
async fn available_public_store_objects_export_without_loose_files_or_other_objects() {
    let fixture = Fixture::new().await;
    let store = Arc::new(
        Store::open_with(
            fixture.directory.path().join("store"),
            StoreConfig {
                xite_root: Some(fixture.directory.path().join("data")),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    fixture.state.set_edx_store(store.clone()).await.unwrap();
    for (path, bytes) in [("index.html", INDEX), ("child/data.txt", CHILD)] {
        let id = ObjId::of(bytes);
        assert!(store.is_complete(id).unwrap());
        fixture.storage.delete(path).unwrap();
        assert_eq!(store.read_bytes(id, 1).unwrap(), bytes);
    }
    let unrelated = ObjId::of(PRIVATE);
    store
        .insert_bytes(unrelated, Ns::Plain, PRIVATE, 1)
        .unwrap();
    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
    assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
    assert!(
        !fixture.storage.exists("index.html"),
        "export should not materialize or fetch files"
    );
}

#[tokio::test]
async fn random_key_shards_never_export_cached_private_plaintext() {
    let fixture = Fixture::customize(|root, _, storage| {
        root["files_shard"] = json!({"private-message.txt": {
            "size": PRIVATE.len(), "mode": 1, "chunks": [{
                "ph": ObjId::of(PRIVATE).to_string(), "ca": "11".repeat(32),
                "len": PRIVATE.len(), "cs": PRIVATE.len() + 16
            }]
        }});
        storage.write("private-message.txt", PRIVATE).unwrap();
    })
    .await;
    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
}

#[tokio::test]
async fn unknown_and_traversal_address_queries_do_not_resolve_or_read_directories() {
    let fixture = Fixture::new().await;
    for reference in ["missing.epix", "..%2Fprivate", "%2Fetc", "%2e%2e%5cprivate"] {
        let reply = fixture
            .get(
                "127.0.0.1:42222",
                reference,
                &[("sec-fetch-mode", "navigate")],
            )
            .await;
        assert!(matches!(
            reply.status,
            StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND
        ));
        assert!(!reply
            .body
            .windows(PRIVATE.len())
            .any(|bytes| bytes == PRIVATE));
    }
    assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn unsafe_signed_archive_paths_are_rejected() {
    for path in [
        "../private/users.json",
        "/private/users.json",
        "a/../secret",
        "a\\secret",
        "C:secret",
        "CON.txt",
    ] {
        let fixture = Fixture::customize(|root, _, _| {
            root["files"][path] = file_info(PRIVATE);
        })
        .await;
        let reply = fixture.navigation().await;
        assert!(
            matches!(
                reply.status,
                StatusCode::BAD_REQUEST | StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "unsafe manifest path {path} returned {}",
            reply.status
        );
        assert!(!reply
            .body
            .windows(PRIVATE.len())
            .any(|bytes| bytes == PRIVATE));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn file_directory_and_registered_root_symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    for kind in ["file", "directory", "root"] {
        let fixture = Fixture::new().await;
        assert_eq!(fixture.navigation().await.archive(), fixture.expected);
        let outside = fixture.directory.path().join("outside");
        match kind {
            "file" => {
                // Matching bytes prove refusal is about NOFOLLOW, not just a hash mismatch.
                std::fs::write(&outside, CSS).unwrap();
                fixture.storage.delete("assets/all.css").unwrap();
                symlink(&outside, fixture.storage.root().join("assets/all.css")).unwrap();
            }
            "directory" => {
                std::fs::rename(fixture.storage.root().join("child"), &outside).unwrap();
                symlink(&outside, fixture.storage.root().join("child")).unwrap();
            }
            _ => {
                std::fs::rename(fixture.storage.root(), &outside).unwrap();
                symlink(&outside, fixture.storage.root()).unwrap();
            }
        }
        let reply = fixture.navigation().await;
        assert!(
            matches!(
                reply.status,
                StatusCode::BAD_REQUEST
                    | StatusCode::FORBIDDEN
                    | StatusCode::CONFLICT
                    | StatusCode::SERVICE_UNAVAILABLE
            ),
            "{kind} symlink returned {}",
            reply.status
        );
    }
}

// Supplemental storage-source regressions, appended after issue-579-tests.rs.

fn export_fixture_store(fixture: &Fixture) -> Arc<Store> {
    Arc::new(
        Store::open_with(
            fixture.directory.path().join("store"),
            StoreConfig {
                xite_root: Some(fixture.directory.path().join("data")),
                ..Default::default()
            },
        )
        .unwrap(),
    )
}

fn convergent_entry(
    plaintext: &[u8],
    encrypted: &epix_selfenc::Encrypted,
) -> epix_blob::manifest::ShardEntry {
    assert_eq!(encrypted.mode, epix_selfenc::Mode::SaltedConvergent);
    assert_eq!(encrypted.chunks.len(), encrypted.shards.len());
    epix_blob::manifest::ShardEntry {
        size: plaintext.len() as u64,
        mode: 0,
        chunks: encrypted
            .chunks
            .iter()
            .zip(&encrypted.shards)
            .map(|(chunk, (address, bytes))| {
                assert_eq!(chunk.cipher_addr, *address);
                epix_blob::manifest::ShardChunk {
                    plain_hash: chunk.plain_hash,
                    cipher_addr: ObjId(*address),
                    len: chunk.len,
                    csize: u32::try_from(bytes.len()).unwrap(),
                }
            })
            .collect(),
    }
}

fn store_ciphertext(store: &Store, encrypted: &epix_selfenc::Encrypted) {
    for (address, bytes) in &encrypted.shards {
        let id = ObjId(*address);
        store.insert_bytes(id, Ns::Shard, bytes, 1).unwrap();
        assert!(store.is_complete(id).unwrap());
        assert_eq!(store.read_bytes(id, 1).unwrap(), *bytes);
    }
}

#[tokio::test]
async fn bundle_only_members_export_exact_slices_without_a_bundle_container() {
    let members = BTreeMap::from([
        ("index.html".to_string(), INDEX.to_vec()),
        ("assets/all.css".to_string(), CSS.to_vec()),
    ]);
    let assignment = epix_blob::bundle::assign(&members, &[]);
    assert_eq!(assignment.bundles.len(), 1);
    assert!(assignment
        .members
        .values()
        .any(|(_, offset, _)| *offset != 0));
    let fixture = Fixture::customize(|root, _, _| {
        // Retain the existing signed sha512/size fields and assign real bundle offsets.
        let mut roots = BTreeMap::new();
        for section in ["files", "files_optional"] {
            for (path, info) in root[section].as_object().unwrap() {
                roots.insert(
                    path.clone(),
                    ObjId::from_hex(info["b3"].as_str().unwrap()).unwrap(),
                );
            }
        }
        epix_blob::manifest::apply_edx(root, &roots, &assignment).unwrap();
    })
    .await;

    // Delete before Store activation so no independent member object can be registered.
    for path in members.keys() {
        fixture.storage.delete(path).unwrap();
    }
    let store = export_fixture_store(&fixture);
    for bundle in &assignment.bundles {
        store
            .insert_bytes(bundle.id, Ns::Plain, &bundle.bytes, 1)
            .unwrap();
    }
    let tally = fixture.state.set_edx_store(store.clone()).await.unwrap();
    assert_eq!(
        (tally.xites, tally.quarantined),
        (1, 0),
        "fixture must retain its accepted manifest authority: {tally:?}"
    );
    for bundle in &assignment.bundles {
        assert!(store.is_complete(bundle.id).unwrap());
    }
    for bytes in members.values() {
        assert!(!store.contains(ObjId::of(bytes)).unwrap());
    }

    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
    assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
    for (path, bytes) in &members {
        assert!(!fixture.storage.exists(path));
        assert!(!store.contains(ObjId::of(bytes)).unwrap());
    }
}

#[tokio::test]
async fn root_and_child_public_shards_use_their_own_salt_without_cached_plaintext() {
    // Two chunks exercise chained key derivation, not just the first-chunk shortcut.
    let root_plaintext: Vec<u8> = (0..epix_selfenc::CHUNK_SIZE + 37)
        .map(|index| (index % 251) as u8)
        .collect();
    let mut child_plaintext = root_plaintext.clone();
    child_plaintext[0] ^= 0xff;
    child_plaintext[epix_selfenc::CHUNK_SIZE] ^= 0xff;
    let root_salt = [0x31; 32];
    let child_salt = [0x72; 32];
    let root_encrypted = epix_selfenc::encrypt_convergent(&root_plaintext, &root_salt);
    let child_encrypted = epix_selfenc::encrypt_convergent(&child_plaintext, &child_salt);
    assert_eq!(root_encrypted.chunks.len(), 2);
    assert_ne!(root_encrypted.shards[0].0, child_encrypted.shards[0].0);
    let mut fixture = Fixture::customize(|root, child, _| {
        root["edx_salt"] = json!(hex::encode(root_salt));
        child["edx_salt"] = json!(hex::encode(child_salt));
        epix_blob::manifest::set_shard_entry(
            root,
            "public.bin",
            &convergent_entry(&root_plaintext, &root_encrypted),
        );
        epix_blob::manifest::set_shard_entry(
            child,
            "public.bin",
            &convergent_entry(&child_plaintext, &child_encrypted),
        );
    })
    .await;
    fixture
        .expected
        .insert("public.bin".into(), root_plaintext.clone());
    fixture
        .expected
        .insert("child/public.bin".into(), child_plaintext.clone());
    let store = export_fixture_store(&fixture);
    store_ciphertext(&store, &root_encrypted);
    store_ciphertext(&store, &child_encrypted);
    let tally = fixture.state.set_edx_store(store.clone()).await.unwrap();
    assert_eq!(
        (tally.xites, tally.quarantined),
        (1, 0),
        "fixture must retain its accepted manifest authority: {tally:?}"
    );
    for path in ["public.bin", "child/public.bin"] {
        assert!(!fixture.storage.exists(path));
    }
    for plaintext in [&root_plaintext, &child_plaintext] {
        assert!(!store.contains(ObjId::of(plaintext)).unwrap());
    }

    assert_eq!(fixture.navigation().await.archive(), fixture.expected);
    assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
    for path in ["public.bin", "child/public.bin"] {
        assert!(!fixture.storage.exists(path));
    }
    for plaintext in [&root_plaintext, &child_plaintext] {
        assert!(!store.contains(ObjId::of(plaintext)).unwrap());
    }
}

#[tokio::test]
async fn malformed_shard_integers_cannot_narrow_to_valid_public_descriptors() {
    let salt = [0x43; 32];
    let plaintext = b"valid ciphertext must not legitimize an invalid signed descriptor";
    let encrypted = epix_selfenc::encrypt_convergent(plaintext, &salt);
    for malformed in ["mode", "len", "cs"] {
        let fixture = Fixture::customize(|root, _, _| {
            root["edx_salt"] = json!(hex::encode(salt));
            epix_blob::manifest::set_shard_entry(
                root,
                "public.bin",
                &convergent_entry(plaintext, &encrypted),
            );
            let entry = &mut root["files_shard"]["public.bin"];
            if malformed == "mode" {
                // A direct `as u8` turns an unsupported mode into public mode 0.
                entry["mode"] = json!(256u64);
            } else {
                // `as u32` would restore the original, otherwise valid length.
                let value = entry["chunks"][0][malformed].as_u64().unwrap();
                entry["chunks"][0][malformed] = json!(value + (1u64 << 32));
            }
        })
        .await;
        let store = export_fixture_store(&fixture);
        store_ciphertext(&store, &encrypted);
        let tally = fixture.state.set_edx_store(store.clone()).await.unwrap();
        assert_eq!(
            (tally.xites, tally.quarantined),
            (1, 0),
            "fixture must retain its accepted manifest authority: {tally:?}"
        );
        assert!(!fixture.storage.exists("public.bin"));
        assert!(!store.contains(ObjId::of(plaintext)).unwrap());

        let reply = fixture.navigation().await;
        assert!(
            matches!(
                reply.status,
                StatusCode::BAD_REQUEST
                    | StatusCode::CONFLICT
                    | StatusCode::UNPROCESSABLE_ENTITY
                    | StatusCode::SERVICE_UNAVAILABLE
            ),
            "invalid shard {malformed} must fail the export, got {}: {}",
            reply.status,
            String::from_utf8_lossy(&reply.body)
        );
        assert!(!reply
            .headers
            .get("content-type")
            .is_some_and(|value| value == "application/zip"));
        assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn complete_sparse_objects_are_rechecked_before_exporting_their_bytes() {
    use epix_blob::verified::{encode_slice, OutboardBytes};

    let fixture = Fixture::new().await;
    // No loose or slab copy may hide the sparse source being tested.
    fixture.storage.delete("index.html").unwrap();
    let store = export_fixture_store(&fixture);
    let outboard = OutboardBytes::from_slice(INDEX);
    let ranges = [0..outboard.size];
    let mut encoded = Vec::new();
    encode_slice(INDEX, &outboard, &ranges, &mut encoded).unwrap();
    store
        .ensure_sparse(outboard.root, Ns::Plain, outboard.size, 1)
        .unwrap();
    store
        .write_slice(outboard.root, &ranges, &encoded[..], 1)
        .unwrap();
    let tally = fixture.state.set_edx_store(store.clone()).await.unwrap();
    assert_eq!(
        (tally.xites, tally.quarantined),
        (1, 0),
        "fixture must retain its accepted manifest authority: {tally:?}"
    );
    assert_eq!(store.read_bytes(outboard.root, 1).unwrap(), INDEX);
    assert_eq!(fixture.navigation().await.archive(), fixture.expected);

    // Match the corruption fixture in epix-blob/tests/store.rs: alter bytes after
    // verified ingestion while the durable present bits still say complete.
    let path = store.root().join("sparse").join(outboard.root.to_string());
    let mut corrupt = std::fs::read(&path).unwrap();
    corrupt[0] ^= 1;
    std::fs::write(&path, &corrupt).unwrap();
    assert!(store.is_complete(outboard.root).unwrap());
    assert_eq!(
        store
            .read_range(outboard.root, 0, outboard.size, 1)
            .unwrap(),
        corrupt
    );
    assert!(store.read_bytes(outboard.root, 1).is_err());

    fixture.navigation().await.incomplete();
    assert_eq!(fixture.fetch.0.load(Ordering::SeqCst), 0);
    assert!(!fixture.storage.exists("index.html"));
}
