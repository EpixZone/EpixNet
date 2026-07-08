//! Route/wrapper polish parity: `/raw/*` (no wrapper, noscript CSP), the
//! root favicon, `/add/*` redirect, content-type table entries, and the
//! wrapper's content.json page hints (background-color, viewport, favicon).

use epix_ui::state::{AppState, XiteEntry};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use serde_json::json;
use tower::ServiceExt;

async fn router_with_site() -> axum::Router {
    let state = AppState::new("polish-test");
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"<h1>hi</h1>").unwrap();
    storage.write("style.webp", b"not really an image").unwrap();
    state
        .add_xite("1Polish", XiteEntry {
            storage,
            content: Some(json!({
                "address": "1Polish",
                "background-color": "#101418",
                "viewport": "width=device-width, initial-scale=1",
                "favicon": "img/icon.png",
            })),
        })
        .await;
    std::mem::forget(dir);
    UiServer::new(state).router()
}

fn get(uri: &str) -> axum::extract::Request {
    axum::extract::Request::builder()
        .uri(uri)
        .header("sec-fetch-mode", "navigate")
        .body(axum::body::Body::empty())
        .unwrap()
}

#[tokio::test]
async fn raw_serves_without_wrapper_under_noscript_csp() {
    let router = router_with_site().await;
    let resp = router.oneshot(get("/raw/1Polish/index.html")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let csp = resp.headers().get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.starts_with("default-src 'none'; sandbox"), "noscript CSP: {csp}");
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&body[..], b"<h1>hi</h1>", "raw bytes, no wrapper");
}

#[tokio::test]
async fn root_favicon_and_add_redirect() {
    let router = router_with_site().await;
    let resp = router.clone().oneshot(get("/favicon.ico")).await.unwrap();
    assert_eq!(resp.status(), 308);
    assert_eq!(resp.headers().get("location").unwrap(), "/uimedia/img/favicon.ico");

    let resp = router.oneshot(get("/add/1Polish")).await.unwrap();
    assert_eq!(resp.status(), 307);
    assert_eq!(resp.headers().get("location").unwrap(), "/1Polish/");
}

#[tokio::test]
async fn content_type_table_covers_epixnet_entries() {
    let router = router_with_site().await;
    let resp = router.oneshot(get("/raw/1Polish/style.webp")).await.unwrap();
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/webp");
}

#[tokio::test]
async fn wrapper_carries_content_json_page_hints() {
    let router = router_with_site().await;
    let resp = router.oneshot(get("/1Polish/")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let html =
        String::from_utf8(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec())
            .unwrap();
    assert!(html.contains("background-color: #101418;"), "body_style: {html}");
    assert!(
        html.contains(r#"<meta name="viewport" id="viewport" content="width=device-width, initial-scale=1">"#),
        "viewport meta"
    );
    assert!(html.contains(r#"<link rel="icon" href="/1Polish/img/icon.png">"#), "favicon link");
}
