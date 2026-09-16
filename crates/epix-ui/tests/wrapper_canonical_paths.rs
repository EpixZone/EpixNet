//! Canonical wrapper redirects preserve the browser's encoded document URL.
use axum::{body::Body, http::Request};
use epix_ui::{rewrite_proxy_host, AppState, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

async fn fixture() -> (tempfile::TempDir, axum::Router, String) {
    let directory = tempfile::tempdir().unwrap();
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(directory.path().join("data").join(&address));
    let index = b"<!doctype html><title>Verified xite</title>";
    let mut content = json!({
        "address": address, "domain": "talk.epix", "modified": 1,
        "files": { "index.html": {
            "size": index.len(), "sha512": XiteStorage::hash_bytes(index)
        } }
    });
    epix_content::sign(&mut content, &key).unwrap();
    storage.write("index.html", index).unwrap();
    storage.write("content.json", epix_content::dumps_content(&content).as_bytes()).unwrap();
    // This isolated integration-test process uses the default finality-off
    // policy; a current resolver cache entry is authoritative under that policy.
    assert!(!epix_chain::verify_finality_enabled());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    tokio::fs::write(directory.path().join("resolve-cache.json"),
        json!({ "talk.epix": { "address": address, "resolved_at": now } }).to_string())
        .await.unwrap();
    let state = AppState::with_data_dir("canonical-path-test", directory.path());
    state.add_xite(&address, XiteEntry { storage, content: Some(content) }).await;
    (directory, UiServer::new(state).router(), address)
}

async fn redirect(router: &axum::Router, host: &str, uri: &str) -> String {
    let request = Request::builder().uri(uri).header("host", host)
        .header("sec-fetch-mode", "navigate").header("sec-fetch-dest", "document")
        .body(Body::empty()).unwrap();
    let response = router.clone().oneshot(rewrite_proxy_host(request)).await.unwrap();
    assert_eq!(response.status(), 307, "{host}{uri}");
    response.headers()["location"].to_str().unwrap().to_string()
}

#[tokio::test]
async fn verified_host_redirect_preserves_encoded_path_and_query() {
    let (_directory, router, address) = fixture().await;
    let path = "/docs/a%23b%252Fc.html?view=a%2Fb";
    assert_eq!(redirect(&router, &format!("{address}.epix"), path).await,
        format!("//talk.epix{path}"));
}

#[tokio::test]
async fn verified_loopback_redirect_preserves_encoded_path_and_query() {
    let (_directory, router, address) = fixture().await;
    let path = "/docs/a%23b%252Fc.html?view=a%2Fb";
    assert_eq!(redirect(&router, "127.0.0.1:42222", &format!("/{address}{path}")).await,
        format!("/talk.epix{path}"));
}

#[tokio::test]
async fn explicit_index_filenames_are_not_rewritten_as_directories() {
    let (_directory, router, address) = fixture().await;
    for path in ["/index.html?keep=1", "/myindex.html?keep=1", "/docs/index.html?keep=1", "/docs/?keep=1"] {
        assert_eq!(redirect(&router, &format!("{address}.epix"), path).await,
            format!("//talk.epix{path}"));
    }
}

#[tokio::test]
async fn cross_xite_origin_normalization_preserves_the_encoded_document_path() {
    let (_directory, router, address) = fixture().await;
    for path in ["/docs/a%23b%252Fc.html?view=a%2Fb", "/myindex.html?keep=1"] {
        assert_eq!(redirect(&router, "dashboard.epix", &format!("/{address}{path}")).await,
            format!("//{address}.epix{path}"));
    }
}
