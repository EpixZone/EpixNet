//! Tier 1 UI security, ported from EpixNet's `UiRequest.route` entry checks:
//! the Host allowlist (DNS-rebinding protection), the OPTIONS preflight
//! answer, and the cross-origin request gate with its `Cors:<target>`
//! permission escape hatch.

use epix_ui::state::{AppState, XiteEntry};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

async fn test_server() -> (Arc<AppState>, axum::Router) {
    let state = AppState::new("sec-test");
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("data.json", b"{}").unwrap();
    for addr in ["1Source", "1Target"] {
        let storage = storage.clone();
        state
            .add_xite(addr, XiteEntry { storage, content: Some(json!({ "address": addr })) })
            .await;
    }
    std::mem::forget(dir); // keep files for the router's lifetime
    let router = UiServer::new(state.clone()).router();
    (state, router)
}

fn get(uri: &str, headers: &[(&str, &str)]) -> axum::extract::Request {
    let mut req = axum::extract::Request::builder().uri(uri).method("GET");
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.body(axum::body::Body::empty()).unwrap()
}

#[tokio::test]
async fn host_allowlist_blocks_dns_rebinding() {
    let (_state, router) = test_server().await;

    // A rebinding attacker's DNS name is refused outright.
    let resp = router
        .clone()
        .oneshot(get("/", &[("host", "evil.example.com")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // IPs, localhost, and `.epix` proxy hosts pass.
    for host in ["127.0.0.1:42222", "localhost", "[::1]:8080", "talk.epix"] {
        let resp = router.clone().oneshot(get("/", &[("host", host)])).await.unwrap();
        assert_ne!(resp.status(), 403, "host {host} must be allowed");
    }
}

#[tokio::test]
async fn options_preflight_is_answered_directly() {
    let (_state, router) = test_server().await;
    let req = axum::extract::Request::builder()
        .uri("/1Target/data.json")
        .method("OPTIONS")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    let h = resp.headers();
    assert_eq!(h.get("access-control-allow-origin").unwrap(), "null");
    assert!(h
        .get("access-control-allow-headers")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("X-Requested-With"));
    assert_eq!(h.get("access-control-allow-credentials").unwrap(), "true");
}

#[tokio::test]
async fn cross_origin_gate_and_cors_permission() {
    let (state, router) = test_server().await;
    // The gate defaults on for loopback binds; force it on for the test.
    state.config_set("ui_check_cors", json!(true)).await;
    let host = ("host", "127.0.0.1:42222");

    // Navigation is always allowed.
    let resp = router
        .clone()
        .oneshot(get("/1Target/data.json", &[host, ("sec-fetch-mode", "navigate")]))
        .await
        .unwrap();
    assert_ne!(resp.status(), 403, "navigation passes");

    // An untraceable request (no origin, no referer) for a xite is blocked.
    let resp = router.clone().oneshot(get("/1Target/data.json", &[host])).await.unwrap();
    assert_eq!(resp.status(), 403);

    // A foreign origin is blocked.
    let resp = router
        .clone()
        .oneshot(get("/1Target/data.json", &[host, ("origin", "https://evil.example")]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Same-xite subresource fetches pass.
    let resp = router
        .clone()
        .oneshot(get(
            "/1Target/data.json",
            &[host, ("referer", "http://127.0.0.1:42222/1Target/")],
        ))
        .await
        .unwrap();
    assert_ne!(resp.status(), 403, "same-xite read passes");

    // A cross-xite read is blocked without the Cors permission...
    let cross = || {
        get("/1Target/data.json", &[host, ("referer", "http://127.0.0.1:42222/1Source/")])
    };
    let resp = router.clone().oneshot(cross()).await.unwrap();
    assert_eq!(resp.status(), 403, "cross-xite read blocked");

    // ...and allowed once the source xite holds Cors:<target>.
    state.add_permission("1Source", "Cors:1Target").await;
    let resp = router.clone().oneshot(cross()).await.unwrap();
    assert_ne!(resp.status(), 403, "Cors permission unlocks the read");

    // Global routes carry nothing to probe and stay reachable.
    let resp = router
        .clone()
        .oneshot(get("/EpixNet-Internal/Status", &[host]))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
