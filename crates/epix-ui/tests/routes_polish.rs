//! Route/wrapper polish parity: `/raw/*` (no wrapper, noscript CSP), the
//! root favicon, `/add/*` redirect, content-type table entries, and the
//! wrapper's content.json page hints (background-color, viewport, favicon).

use epix_ui::state::{AppState, XiteEntry};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use serde_json::json;
use tower::ServiceExt;

async fn router_with_xite() -> axum::Router {
    router_with_hints(json!({
        "background-color": "#101418",
        "viewport": "width=device-width, initial-scale=1",
        "favicon": "img/icon.png",
    })).await
}

async fn router_with_hints(mut hints: serde_json::Value) -> axum::Router {
    hints["address"] = json!("1Polish");
    let state = AppState::new("polish-test");
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"<h1>hi</h1>").unwrap();
    storage.write("style.webp", b"not really an image").unwrap();
    state
        .add_xite("1Polish", XiteEntry {
            storage,
            content: Some(hints),
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
    let router = router_with_xite().await;
    let resp = router.oneshot(get("/raw/1Polish/index.html")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let csp = resp.headers().get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.starts_with("default-src 'none'; sandbox"), "noscript CSP: {csp}");
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&body[..], b"<h1>hi</h1>", "raw bytes, no wrapper");
}

#[tokio::test]
async fn root_favicon_and_add_redirect() {
    let router = router_with_xite().await;
    let resp = router.clone().oneshot(get("/favicon.ico")).await.unwrap();
    assert_eq!(resp.status(), 308);
    assert_eq!(resp.headers().get("location").unwrap(), "/uimedia/img/favicon.ico");

    let resp = router.oneshot(get("/add/1Polish")).await.unwrap();
    assert_eq!(resp.status(), 307);
    assert_eq!(resp.headers().get("location").unwrap(), "/1Polish/");
}

#[tokio::test]
async fn content_type_table_covers_epixnet_entries() {
    let router = router_with_xite().await;
    let resp = router.oneshot(get("/raw/1Polish/style.webp")).await.unwrap();
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/webp");
}

#[tokio::test]
async fn wrapper_carries_content_json_page_hints() {
    let router = router_with_xite().await;
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

#[tokio::test]
async fn empty_page_hints_keep_default_wrapper_behavior() {
    for blank in ["", "  "] {
        let router = router_with_hints(json!({
            "title": blank, "favicon": blank, "viewport": blank,
            "background-color": blank, "background-color-light": blank, "background-color-dark": blank,
        })).await;
        let response = router.oneshot(get("/1Polish/")).await.unwrap();
        assert_eq!(response.status(), 200);
        let html = String::from_utf8(axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("<title>1Polish - EpixNet</title>"));
        assert!(!html.contains("<link rel=\"icon\""), "an empty favicon must not request the wrapper as an image");
        assert!(!html.contains("id=\"viewport\""), "keep the default viewport");
        assert!(!html.contains(&format!("background-color: {blank};")));
    }
}

#[tokio::test]
async fn empty_theme_background_falls_back_to_the_shared_background() {
    let router = router_with_hints(json!({
        "background-color": "#123456", "background-color-light": "", "background-color-dark": "",
    })).await;
    let response = router.oneshot(get("/1Polish/")).await.unwrap();
    assert_eq!(response.status(), 200);
    let html = String::from_utf8(axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("background-color: #123456;"));
}

#[tokio::test]
async fn theme_background_overrides_the_shared_background() {
    let router = router_with_hints(json!({
        "background-color": "#123456", "background-color-light": "#abcdef", "background-color-dark": "#abcdef",
    })).await;
    let response = router.oneshot(get("/1Polish/")).await.unwrap();
    assert_eq!(response.status(), 200);
    let html = String::from_utf8(axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("background-color: #abcdef;"));
    assert!(!html.contains("background-color: #123456;"));
}
