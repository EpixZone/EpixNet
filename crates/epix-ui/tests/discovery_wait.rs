//! Browser document requests must remain recoverable between discovery attempts.

use axum::{body::Body, http::{Request, StatusCode}};
use epix_ui::{AppState, OnDemandResolver, ResolvedHost, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

struct UnavailablePeer;

#[async_trait::async_trait]
impl OnDemandResolver for UnavailablePeer {
    async fn ensure(&self, _host: &str) -> Result<(), String> {
        Err("No reachable peer yet".into())
    }

    async fn resolve(&self, host: &str) -> Option<ResolvedHost> {
        Some(ResolvedHost { address: host.into(), verified: true })
    }
}

async fn fixture(partial: bool) -> (axum::Router, String, XiteStorage, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let index = b"<!doctype html><html><head><link rel='stylesheet' href='style.css'></head><body>Ready xite</body></html>";
    let css = b"body { color: purple; }";
    let optional = b"<h1>Later</h1>";
    let mut root = json!({
        "address": address, "title": "Rare xite", "modified": 1,
        "files": {
            "index.html": { "size": index.len(), "sha512": XiteStorage::hash_bytes(index) },
            "style.css": { "size": css.len(), "sha512": XiteStorage::hash_bytes(css) }
        },
        "files_optional": {
            "extras.html": { "size": optional.len(), "sha512": XiteStorage::hash_bytes(optional) }
        }
    });
    epix_content::sign(&mut root, &key).unwrap();
    let state = AppState::new("discovery-wait-test");
    state.set_on_demand(Arc::new(UnavailablePeer)).await;
    if partial {
        storage.write("content.json", epix_content::dumps_content(&root).as_bytes()).unwrap();
        storage.write("index.html", index).unwrap();
        state.add_xite(&address, XiteEntry { storage: storage.clone(), content: Some(root) }).await;
        assert!(state.html_doc_gated(&address).await);
    }
    (UiServer::new(state).router(), address, storage, dir)
}

fn document(address: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/{address}/index.html?wrapper_nonce=waiting"))
        .header("sec-fetch-dest", "iframe")
        .body(Body::empty()).unwrap()
}

#[tokio::test]
async fn interrupted_core_download_keeps_document_waiting_then_serves_complete_xite() {
    let (router, address, storage, _dir) = fixture(true).await;
    let response = tokio::time::timeout(std::time::Duration::from_secs(2),
        router.clone().oneshot(document(&address))).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE,
        "a failed attempt must not serve index.html before its stylesheet is available");
    assert_eq!(response.headers()["retry-after"], "30");
    let html = String::from_utf8(axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("data-epix-load-state=\"waiting\""));
    assert!(!html.contains("Ready xite"));

    storage.write("style.css", b"body { color: purple; }").unwrap();
    let response = router.oneshot(document(&address)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = String::from_utf8(axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("Ready xite"));
    assert!(!html.contains("data-epix-load-state"));
}

#[tokio::test]
async fn unavailable_new_xite_returns_retryable_document_instead_of_stranding_request() {
    let (router, address, _storage, _dir) = fixture(false).await;
    let response = tokio::time::timeout(std::time::Duration::from_secs(2),
        router.oneshot(document(&address))).await
        .expect("a finished discovery attempt should return a recoverable waiting document promptly")
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["retry-after"], "30");
    let html = String::from_utf8(axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("data-epix-load-state=\"waiting\""));
}

#[tokio::test]
async fn a_declared_optional_document_remains_retryable_after_the_core_is_complete() {
    let (router, address, storage, _dir) = fixture(true).await;
    storage.write("style.css", b"body { color: purple; }").unwrap();
    let request = Request::builder().uri(format!("/{address}/extras.html"))
        .body(Body::empty()).unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2),
        router.oneshot(request)).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE,
        "a declared optional file can still arrive; it is not an unlisted path");
}

#[tokio::test]
async fn an_unlisted_document_in_a_complete_registered_xite_is_not_retryable() {
    let (router, address, storage, _dir) = fixture(true).await;
    storage.write("style.css", b"body { color: purple; }").unwrap();
    let request = Request::builder()
        .uri(format!("/{address}/missing.html?wrapper_nonce=waiting"))
        .header("sec-fetch-dest", "iframe")
        .body(Body::empty()).unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(2),
        router.oneshot(request)).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND,
        "a manifest-known missing path must not ask the browser to retry forever");
    assert!(response.headers().get("retry-after").is_none());
}
