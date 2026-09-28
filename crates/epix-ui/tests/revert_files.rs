//! Restoring an owned file uses verified downloads without deleting its local copy first.
use epix_core::PeerAddr;
use epix_ui::state::{
    AppState, EdxBatch, EdxBatchProgress, EdxFetcher, EdxPushError, EdxPushProgress, EdxWant,
    UpdatePayload, XiteEntry,
};
use epix_ui::{rewrite_proxy_host, UiServer};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tower::ServiceExt;

const ORIGINAL: &[u8] = b"body { color: purple; }";
const EDITED: &[u8] = b"body { invalid: local edit; }";
const FILE: &str = "css/writer's #style.css";
const ENCODED_FILE: &str = "css/writer%27s%20%23style.css";

struct RecoveryFetcher {
    state: Weak<AppState>,
    bytes: Vec<u8>,
    failure: Option<String>,
}
#[async_trait::async_trait]
impl EdxFetcher for RecoveryFetcher {
    async fn fetch_file(&self, address: &str, path: &str) -> Result<bool, String> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        self.state
            .upgrade()
            .unwrap()
            .edx_materialize_file(
                address,
                path,
                epix_blob::ObjId::of(ORIGINAL),
                &self.bytes,
                None,
            )
            .await?;
        Ok(true)
    }
    async fn fetch_signed(&self, _: PeerAddr, _: &str, _: &str) -> Result<Option<Vec<u8>>, String> {
        unreachable!()
    }
    async fn fetch_signed_many(
        &self,
        _: &str,
        _: Vec<String>,
        _: Vec<PeerAddr>,
        _: Option<epix_ui::state::EdxSignedProgress>,
    ) -> HashMap<String, Vec<u8>> {
        unreachable!()
    }
    async fn fetch_range(
        &self,
        _: &str,
        _: &str,
        _: u64,
        _: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        unreachable!()
    }
    async fn push_update(
        &self,
        _: PeerAddr,
        _: &str,
        _: &str,
        _: Arc<Vec<u8>>,
        _: f64,
        _: Arc<UpdatePayload>,
        _: Arc<Vec<String>>,
        _: Arc<EdxPushProgress>,
    ) -> Result<bool, EdxPushError> {
        unreachable!()
    }
    async fn fetch_files(
        &self,
        _: &str,
        _: Vec<EdxWant>,
        _: Vec<PeerAddr>,
        _: Option<serde_json::Value>,
        _: Option<EdxBatchProgress>,
    ) -> EdxBatch {
        unreachable!()
    }
    async fn list_signed(
        &self,
        _: PeerAddr,
        _: &str,
        _: u64,
    ) -> Result<Option<Vec<(String, u64, u64)>>, String> {
        unreachable!()
    }
    async fn pex(
        &self,
        _: PeerAddr,
        _: &str,
        _: u32,
        _: Vec<PeerAddr>,
    ) -> Result<Vec<PeerAddr>, String> {
        unreachable!()
    }
    async fn get_trackers(&self, _: PeerAddr) -> Result<Vec<String>, String> {
        unreachable!()
    }
    async fn kad(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        unreachable!()
    }
    async fn announce(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
        unreachable!()
    }
    async fn updates_since(
        &self,
        _: PeerAddr,
        _: u64,
    ) -> Result<(Vec<(String, i64)>, u64), String> {
        unreachable!()
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    state: Arc<AppState>,
    address: String,
    storage: XiteStorage,
    manifest: Vec<u8>,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::new("revert-test");
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(dir.path().join("xite"));
    let mut content = json!({"address": address, "modified": 1, "files": {
        FILE: {"size": ORIGINAL.len(), "sha512": XiteStorage::hash_bytes(ORIGINAL),
            "b3": epix_blob::ObjId::of(ORIGINAL).to_string()}
    }});
    epix_content::sign(&mut content, &key).unwrap();
    let manifest = epix_content::dumps_content(&content).into_bytes();
    storage.write("content.json", &manifest).unwrap();
    storage.write(FILE, EDITED).unwrap();
    storage.write("draft.js", b"unsigned new file").unwrap();
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: storage.clone(),
                content: Some(content),
            },
        )
        .await;
    state.set_owned(&address, true).await;
    state
        .set_edx_fetcher(Arc::new(RecoveryFetcher {
            state: Arc::downgrade(&state),
            bytes: ORIGINAL.to_vec(),
            failure: None,
        }))
        .await;
    Fixture {
        _dir: dir,
        state,
        address,
        storage,
        manifest,
    }
}

async fn request(
    f: &Fixture,
    method: &str,
    host: &str,
    path: &str,
    body: String,
) -> (u16, String, axum::http::HeaderMap) {
    let req = axum::extract::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header("sec-fetch-mode", "navigate")
        .header("origin", format!("http://{host}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body))
        .unwrap();
    let response = UiServer::new(f.state.clone())
        .router()
        .oneshot(rewrite_proxy_host(req))
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap(), headers)
}

#[tokio::test]
async fn existing_download_path_can_restore_an_edited_file_without_deleting_it() {
    let f = fixture().await;
    assert!(f.state.file_need(&f.address, FILE).await.unwrap());
    assert_eq!(f.storage.read(FILE).unwrap(), ORIGINAL);
    assert_eq!(f.storage.read("draft.js").unwrap(), b"unsigned new file");
    assert_eq!(f.storage.read("content.json").unwrap(), f.manifest);
}

#[tokio::test]
async fn file_browser_offers_a_confirmed_revert_of_a_signed_file() {
    let f = fixture().await;
    let (status, html, _) = request(
        &f,
        "GET",
        "127.0.0.1",
        &format!("/list/{}/css", f.address),
        String::new(),
    )
    .await;
    assert_eq!(status, 200);
    let target = format!("/EpixNet-Internal/Revert/{}/{ENCODED_FILE}", f.address);
    assert!(
        html.contains(&format!("href='{target}'")),
        "file browser must offer Revert"
    );
    let (status, html, headers) = request(&f, "GET", "127.0.0.1", &target, String::new()).await;
    assert_eq!(status, 200);
    assert!(html.contains("Revert file"));
    assert!(html.contains("name='csrf'"));
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(
        f.storage.read(FILE).unwrap(),
        EDITED,
        "GET only asks for confirmation"
    );
    let (status, _, _) = request(
        &f,
        "POST",
        "127.0.0.1",
        &target,
        format!("csrf={}", f.state.ui_csrf_token()),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(f.storage.read(FILE).unwrap(), ORIGINAL);
    assert_eq!(f.storage.read("content.json").unwrap(), f.manifest);
}

#[tokio::test(start_paused = true)]
async fn unavailable_or_invalid_downloads_keep_the_local_edit() {
    for failure in [None, Some("No reachable peers <test>".to_string())] {
        let f = fixture().await;
        f.state
            .set_edx_fetcher(Arc::new(RecoveryFetcher {
                state: Arc::downgrade(&f.state),
                bytes: b"untrusted bytes".to_vec(),
                failure,
            }))
            .await;
        let target = format!("/EpixNet-Internal/Revert/{}/{ENCODED_FILE}", f.address);
        let (status, html, _) = request(
            &f,
            "POST",
            "127.0.0.1",
            &target,
            format!("csrf={}", f.state.ui_csrf_token()),
        )
        .await;
        assert_eq!(status, 502);
        assert!(html.contains("Could not restore this file"));
        assert!(!html.contains("<test>"), "errors are escaped");
        assert_eq!(f.storage.read(FILE).unwrap(), EDITED);
        assert_eq!(f.storage.read("content.json").unwrap(), f.manifest);
    }
}

#[tokio::test(start_paused = true)]
async fn an_edited_manifest_cannot_authorize_recovery() {
    let f = fixture().await;
    let mut manifest: Value = serde_json::from_slice(&f.manifest).unwrap();
    manifest["title"] = json!("Unsigned manifest change");
    let edited_manifest = epix_content::dumps_content(&manifest).into_bytes();
    f.storage.write("content.json", &edited_manifest).unwrap();
    let (status, _, _) = request(
        &f,
        "POST",
        "127.0.0.1",
        &format!("/EpixNet-Internal/Revert/{}/{ENCODED_FILE}", f.address),
        format!("csrf={}", f.state.ui_csrf_token()),
    )
    .await;
    assert_eq!(status, 502);
    assert_eq!(f.storage.read(FILE).unwrap(), EDITED);
    assert_eq!(f.storage.read("content.json").unwrap(), edited_manifest);
}

#[tokio::test]
async fn recovery_requires_csrf_ownership_and_a_signed_file() {
    let f = fixture().await;
    let target = format!("/EpixNet-Internal/Revert/{}/{ENCODED_FILE}", f.address);
    for body in ["", "csrf=invalid"] {
        assert_eq!(
            request(&f, "POST", "127.0.0.1", &target, body.into())
                .await
                .0,
            403
        );
        assert_eq!(f.storage.read(FILE).unwrap(), EDITED);
    }
    let body = format!("csrf={}", f.state.ui_csrf_token());
    for file in [
        "draft.js",
        "content.json",
        "%2e%2e/escape.css",
        "unknown.css",
    ] {
        assert_eq!(
            request(
                &f,
                "POST",
                "127.0.0.1",
                &format!("/EpixNet-Internal/Revert/{}/{file}", f.address),
                body.clone()
            )
            .await
            .0,
            404
        );
    }
    let (_, html, _) = request(
        &f,
        "GET",
        "127.0.0.1",
        &format!("/list/{}", f.address),
        String::new(),
    )
    .await;
    assert!(
        !html.contains("class='revert'"),
        "unsigned files, manifests and directories have no Revert action"
    );
    f.state.set_owned(&f.address, false).await;
    assert_eq!(request(&f, "POST", "127.0.0.1", &target, body).await.0, 404);
    let (_, html, _) = request(
        &f,
        "GET",
        "127.0.0.1",
        &format!("/list/{}/css", f.address),
        String::new(),
    )
    .await;
    assert!(!html.contains("class='revert'"));
    assert_eq!(f.storage.read(FILE).unwrap(), EDITED);
}

#[tokio::test]
async fn recovery_is_disabled_on_gateways_and_with_the_file_manager_disabled() {
    let f = fixture().await;
    let target = format!("/EpixNet-Internal/Revert/{}/{ENCODED_FILE}", f.address);
    f.state.config_set("ui_restrict", json!(true)).await;
    for method in ["GET", "POST"] {
        assert_eq!(
            request(
                &f,
                method,
                "127.0.0.1",
                &target,
                format!("csrf={}", f.state.ui_csrf_token())
            )
            .await
            .0,
            403
        );
    }
    let (_, html, _) = request(
        &f,
        "GET",
        "127.0.0.1",
        &format!("/list/{}/css", f.address),
        String::new(),
    )
    .await;
    assert!(!html.contains("class='revert'"));
    f.state.config_set("ui_restrict", json!(false)).await;
    f.state.set_plugin_enabled("UiFileManager", false).await;
    for method in ["GET", "POST"] {
        assert_eq!(
            request(
                &f,
                method,
                "127.0.0.1",
                &target,
                format!("csrf={}", f.state.ui_csrf_token())
            )
            .await
            .0,
            404
        );
    }
    assert_eq!(f.storage.read(FILE).unwrap(), EDITED);
}

#[tokio::test]
async fn xite_origins_cannot_read_tokens_or_submit_recovery_even_with_cors_disabled() {
    let f = fixture().await;
    f.state.config_set("ui_check_cors", json!(false)).await;
    let target = format!("/EpixNet-Internal/Revert/{}/{ENCODED_FILE}", f.address);
    let (status, html, headers) = request(&f, "GET", "test.epix", &target, String::new()).await;
    assert_eq!(status, 307);
    assert_eq!(
        headers["location"],
        format!("http://127.0.0.1:{}{target}", f.state.ui_port().await)
    );
    assert!(!html.contains(f.state.ui_csrf_token()));
    assert_eq!(
        request(
            &f,
            "POST",
            "test.epix",
            &target,
            format!("csrf={}", f.state.ui_csrf_token())
        )
        .await
        .0,
        403
    );

    // A script fetch from a loopback xite must not expose the node token.
    let req = axum::extract::Request::builder()
        .uri(&target)
        .header("host", "127.0.0.1")
        .header("sec-fetch-mode", "cors")
        .header("referer", format!("http://127.0.0.1/{}/", f.address))
        .body(axum::body::Body::empty())
        .unwrap();
    let response = UiServer::new(f.state.clone())
        .router()
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), 403);

    let req = axum::extract::Request::builder()
        .method("POST")
        .uri(&target)
        .header("host", "127.0.0.1")
        .header("origin", "https://evil.example")
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "navigate")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!(
            "csrf={}",
            f.state.ui_csrf_token()
        )))
        .unwrap();
    let response = UiServer::new(f.state.clone())
        .router()
        .oneshot(req)
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(f.storage.read(FILE).unwrap(), EDITED);
}
