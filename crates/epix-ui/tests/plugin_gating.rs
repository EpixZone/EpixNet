//! Plugin toggles gate their features, not just their command groups:
//! ContentFilter's mutes/blocks stop applying while the plugin is off, and
//! the UiFileManager route disappears.

use epix_ui::state::{AppState, XiteEntry};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn content_filter_toggle_gates_mutes_and_blocks() {
    let state = AppState::new("gate-test");
    state.mute_add("epix1baduser", "bad@epixid.epix", "spam").await;
    state.siteblock_add("epix1badsite", "scam").await;

    assert_eq!(state.muted_authors().await, vec!["epix1baduser".to_string()]);
    assert!(state.siteblock_reason("epix1badsite").await.is_some());

    // Toggled off: stored but no longer applied.
    state.set_plugin_enabled("ContentFilter", false).await;
    assert!(state.muted_authors().await.is_empty());
    assert!(state.siteblock_reason("epix1badsite").await.is_none());

    // Back on: enforcement resumes from the stored filters.
    state.set_plugin_enabled("ContentFilter", true).await;
    assert_eq!(state.muted_authors().await.len(), 1);
    assert!(state.siteblock_reason("epix1badsite").await.is_some());
}

#[tokio::test]
async fn file_manager_route_gated_by_toggle() {
    let state = AppState::new("gate-test");
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"x").unwrap();
    state
        .add_xite("1Gate", XiteEntry { storage, content: Some(json!({ "address": "1Gate" })) })
        .await;
    let router = UiServer::new(state.clone()).router();
    let get = |uri: &str| {
        axum::extract::Request::builder()
            .uri(uri)
            .header("sec-fetch-mode", "navigate")
            .body(axum::body::Body::empty())
            .unwrap()
    };

    let resp = router.clone().oneshot(get("/list/1Gate/")).await.unwrap();
    assert_ne!(resp.status(), 404, "file manager serves while enabled");

    state.set_plugin_enabled("UiFileManager", false).await;
    let resp = router.oneshot(get("/list/1Gate/")).await.unwrap();
    assert_eq!(resp.status(), 404, "route gone while disabled");
}
