//! MergerSite HTTP parity: a merger site's `merged-<type>/<address>/<path>`
//! URL serves the merged site's file - permission-gated like EpixNet's
//! `checkMergerPath` - on both the wrapper route and `/raw/*`.

use epix_ui::state::{AppState, XiteEntry};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use serde_json::json;
use tower::ServiceExt;

/// A merger site + a merged site (`merged_type: "Test"`) holding `f.txt`.
/// `merger_perm` is the Merger permission granted to the merger, if any.
async fn router_with_merged_site(merger_perm: Option<&str>) -> axum::Router {
    let state = AppState::new("merged-test");
    let dir = tempfile::tempdir().unwrap();
    state
        .add_xite("1Merger", XiteEntry {
            storage: XiteStorage::new(dir.path().join("merger")),
            content: Some(json!({ "address": "1Merger", "files": {} })),
        })
        .await;
    if let Some(perm) = merger_perm {
        state.add_permission("1Merger", perm).await;
    }
    let storage = XiteStorage::new(dir.path().join("merged"));
    storage.write("f.txt", b"merged bytes").unwrap();
    state
        .add_xite("1Merged", XiteEntry {
            storage,
            content: Some(json!({
                "address": "1Merged",
                "merged_type": "Test",
                "files": {},
            })),
        })
        .await;
    std::mem::forget(dir);
    UiServer::new(state).router()
}

/// An iframe resource load from the merger's own page (the Referer traces the
/// source xite for the cross-origin gate).
fn get(uri: &str) -> axum::extract::Request {
    axum::extract::Request::builder()
        .uri(uri)
        .header("referer", "http://localhost/1Merger/")
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn body_of(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()
}

#[tokio::test]
async fn merged_path_serves_the_merged_sites_file() {
    let router = router_with_merged_site(Some("Merger:Test")).await;
    let resp = router.oneshot(get("/1Merger/merged-Test/1Merged/f.txt")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(&body_of(resp).await[..], b"merged bytes");
}

#[tokio::test]
async fn merged_path_without_the_merger_permission_is_refused() {
    let router = router_with_merged_site(None).await;
    let resp = router.oneshot(get("/1Merger/merged-Test/1Merged/f.txt")).await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = String::from_utf8(body_of(resp).await).unwrap();
    assert!(body.contains("No merger permission"), "unexpected body: {body}");
}

#[tokio::test]
async fn merged_path_with_a_mismatched_type_is_refused() {
    // The merger may load Test2 sites, but the target declares "Test".
    let router = router_with_merged_site(Some("Merger:Test2")).await;
    let resp = router.oneshot(get("/1Merger/merged-Test2/1Merged/f.txt")).await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = String::from_utf8(body_of(resp).await).unwrap();
    assert!(body.contains("does not have permission"), "unexpected body: {body}");
}

#[tokio::test]
async fn raw_route_resolves_merged_paths_too() {
    let router = router_with_merged_site(Some("Merger:Test")).await;
    let resp = router.oneshot(get("/raw/1Merger/merged-Test/1Merged/f.txt")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(&body_of(resp).await[..], b"merged bytes");
}
