//! Browser icon requests follow the metadata emitted by the trusted wrapper.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use epix_ui::state::{AppState, XiteEntry};
use epix_ui::{rewrite_proxy_host, UiServer};
use epix_xite::XiteStorage;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

async fn wrapper_touch_icon(host: &str, wrapper_path: &str) {
    let directory = tempfile::tempdir().unwrap();
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(directory.path().join("data").join(&address));
    let index = b"<h1>Talk</h1>";
    let mut content = json!({
        "address": address, "domain": "talk.epix", "title": "Talk", "modified": 1,
        "files": {"index.html": {
            "size": index.len(), "sha512": XiteStorage::hash_bytes(index)
        }}
    });
    epix_content::sign(&mut content, &key).unwrap();
    storage.write("index.html", index).unwrap();
    storage
        .write(
            "content.json",
            epix_content::dumps_content(&content).as_bytes(),
        )
        .unwrap();
    // Match the node's name resolution without contacting the network.
    assert!(!epix_chain::verify_finality_enabled());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(
        directory.path().join("resolve-cache.json"),
        json!({"talk.epix":{"address":address,"resolved_at":now}}).to_string(),
    )
    .unwrap();
    let state = AppState::with_data_dir("wrapper-icon-test", directory.path());
    state
        .add_xite(
            &address,
            XiteEntry {
                storage,
                content: Some(content),
            },
        )
        .await;
    state.config_set("ui_check_cors", json!(true)).await;
    let router = UiServer::new(state).router();

    let wrapper = router
        .clone()
        .oneshot(rewrite_proxy_host(
            Request::builder()
                .uri(wrapper_path)
                .header("host", host)
                .header("sec-fetch-mode", "navigate")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(wrapper.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(wrapper.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        html.contains("<title>Talk - EpixNet</title>"),
        "the xite name resolved"
    );
    let icon_tag = html
        .lines()
        .find(|line| line.contains("rel=\"apple-touch-icon\""))
        .expect("wrapper declares its touch icon");
    let icon_path = icon_tag
        .split_once("href=\"")
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap();

    let icon = router
        .oneshot(rewrite_proxy_host(
            Request::builder()
                .uri(icon_path)
                .header("host", host)
                .header("referer", format!("http://{host}{wrapper_path}"))
                .header("sec-fetch-mode", "no-cors")
                .header("sec-fetch-dest", "image")
                .body(Body::empty())
                .unwrap(),
        ))
        .await
        .unwrap();
    let status = icon.status();
    let content_type = icon.headers().get("content-type").cloned();
    let body = to_bytes(icon.into_body(), 1 << 20).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "declared icon {icon_path} from {host}{wrapper_path}: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(content_type.unwrap(), "image/png");
    assert!(
        body.starts_with(b"\x89PNG\r\n\x1a\n"),
        "the icon is a PNG image"
    );
}

#[tokio::test]
async fn path_wrapper_declares_a_loadable_touch_icon() {
    wrapper_touch_icon("127.0.0.1:42222", "/talk.epix/").await;
}

#[tokio::test]
async fn proxy_wrapper_declares_a_loadable_touch_icon() {
    wrapper_touch_icon("talk.epix", "/").await;
}
