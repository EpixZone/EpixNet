//! Document requests must not turn a finishing download into a permanent 404.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use epix_ui::{rewrite_proxy_host, AppState, OnDemandResolver, ResolvedHost, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt;

struct Downloading;

#[async_trait::async_trait]
impl OnDemandResolver for Downloading {
    async fn ensure(&self, _: &str) -> Result<(), String> {
        Ok(()) // The fixture drives the already-running clone.
    }

    async fn resolve(&self, host: &str) -> Option<ResolvedHost> {
        Some(ResolvedHost {
            address: host.into(),
            verified: true,
        })
    }
}

const INDEX: &[u8] = b"<!doctype html><h1>First load works</h1>";
const DOMAIN: &str = "first-load.epix";

async fn fixture() -> (
    tempfile::TempDir,
    Arc<AppState>,
    String,
    String,
    XiteStorage,
    Value,
) {
    let dir = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("first-load-test", dir.path());
    state.set_on_demand(Arc::new(Downloading)).await;
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(state.xite_dir(&address).unwrap());
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: storage.clone(),
                content: None,
            },
        )
        .await;
    state.set_display(&address, DOMAIN).await;
    state.begin_clone(&address);
    let mut root = json!({"address": address, "modified": 1, "files": {
        "index.html": {"size": INDEX.len(), "sha512": XiteStorage::hash_bytes(INDEX)}
    }});
    epix_content::sign(&mut root, &key).unwrap();
    (dir, state, key, address, storage, root)
}

fn document(state: &AppState, address: &str, by_name: bool) -> Request<Body> {
    let nonce = state.issue_wrapper_nonce();
    let uri = if by_name {
        format!("/index.html?wrapper_nonce={nonce}")
    } else {
        format!("/{address}/index.html?wrapper_nonce={nonce}")
    };
    rewrite_proxy_host(
        Request::builder()
            .uri(uri)
            .header("host", if by_name { DOMAIN } else { "127.0.0.1" })
            .header("sec-fetch-dest", "iframe")
            .header("sec-fetch-mode", "navigate")
            .body(Body::empty())
            .unwrap(),
    )
}

async fn fetch(router: axum::Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finishing_download_serves_first_request_without_a_reload() {
    // A resumed clone can have its signed root on disk before update_content
    // installs the accepted declaration index. Overlap document probes with
    // the last verified file arriving, as the downloader does in that case.
    for iteration in 0..30 {
        let (_dir, state, _key, address, storage, root) = fixture().await;
        storage
            .write(
                "content.json",
                epix_content::dumps_content(&root).as_bytes(),
            )
            .unwrap();
        let router = UiServer::new(state.clone()).router();
        let mut requests = Vec::new();
        for request in 0..64 {
            requests.push(tokio::spawn(fetch(
                router.clone(),
                document(&state, &address, request % 2 == 0),
            )));
        }
        tokio::time::sleep(Duration::from_millis(iteration % 5)).await;
        storage.write("index.html", INDEX).unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        state.update_content(&address, Some(root)).await;
        state.end_clone(&address);
        let mut failures = Vec::new();
        for request in requests {
            let (status, bytes) = tokio::time::timeout(Duration::from_secs(2), request)
                .await
                .unwrap()
                .unwrap();
            if status != StatusCode::OK {
                failures.push((status, String::from_utf8_lossy(&bytes).into_owned()));
            } else {
                assert_eq!(bytes, INDEX);
            }
        }
        // Reproduce the report's second half too: a reload already works.
        assert_eq!(
            fetch(router, document(&state, &address, true)).await,
            (StatusCode::OK, INDEX.to_vec())
        );
        assert!(
            failures.is_empty(),
            "iteration {iteration}: first requests {failures:?}, reload 200"
        );
    }
}

#[tokio::test]
async fn unindexed_manifest_does_not_make_a_declared_document_not_found() {
    let (_dir, state, key, address, storage, mut root) = fixture().await;
    // The root core is ready while an optional document is still arriving.
    // Keep finalization locked so this exercises the missing in-memory
    // declaration index deterministically, independent of task scheduling.
    root["files_optional"] = root["files"].take();
    root["files"] = json!({});
    epix_content::sign(&mut root, &key).unwrap();
    let mut next = root.clone();
    next["modified"] = json!(2);
    epix_content::sign(&mut next, &key).unwrap();
    let transaction = state
        .begin_staged_root_transaction(&address, epix_content::dumps_content(&next).as_bytes())
        .await
        .unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&root).as_bytes(),
        )
        .unwrap();
    assert!(state.xite_core_complete(&address).await);
    assert!(state.content(&address).await.is_none());
    let router = UiServer::new(state.clone()).router();
    let mut request = tokio::spawn(fetch(router.clone(), document(&state, &address, true)));
    let early = tokio::time::timeout(Duration::from_millis(50), &mut request).await;
    storage.write("index.html", INDEX).unwrap();
    drop(transaction);
    let reload = fetch(router, document(&state, &address, true)).await;
    assert_eq!(reload, (StatusCode::OK, INDEX.to_vec()));
    assert!(
        early.is_err(),
        "first request returned {early:?} before its declared document arrived; reload 200"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), request)
            .await
            .unwrap()
            .unwrap(),
        (StatusCode::OK, INDEX.to_vec())
    );
    state.end_clone(&address);
}
