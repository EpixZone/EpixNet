//! A Range request for a declared EDX file we do not hold yet must serve
//! through the EDX seek path (only the bytes the range covers) instead of the
//! whole-file `file_need` download, and one response never carries more than a
//! single window.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use epix_core::PeerAddr;
use epix_ui::state::{
    AppState, EdxBatch, EdxBatchProgress, EdxFetcher, EdxPushError, EdxPushProgress, EdxWant,
    UpdatePayload, XiteEntry,
};
use epix_ui::UiServer;
use epix_xite::XiteStorage;
use serde_json::json;
use tower::ServiceExt;

/// Serves ranges out of an in-memory body and counts whole-file fetches, so a
/// test can tell the seek path from the whole-file download. With `cap` set it
/// returns at most that many bytes per range - a fetch that could only land a
/// contiguous prefix of the window.
struct RangeFetcher {
    body: Vec<u8>,
    cap: Option<usize>,
    whole_file_calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl EdxFetcher for RangeFetcher {
    async fn fetch_file(&self, _: &str, _: &str) -> Result<bool, String> {
        self.whole_file_calls.fetch_add(1, Ordering::SeqCst);
        Ok(false)
    }
    async fn fetch_signed(
        &self,
        _: PeerAddr,
        _: &str,
        _: &str,
    ) -> Result<Option<Vec<u8>>, String> {
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
        start: u64,
        len: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        let len = self.cap.map_or(len as usize, |c| (len as usize).min(c));
        let end = (start as usize).saturating_add(len).min(self.body.len());
        let start = (start as usize).min(end);
        Ok(Some(self.body[start..end].to_vec()))
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

/// A registered xite declaring `media/movie.mp4` with `b3` + `size` (an EDX
/// entry, no piecemap) that is NOT on disk, plus a fetcher that can serve its
/// ranges. The declaration must come from a SIGNED on-disk manifest: range
/// serving resolves it through the verified manifest index, so an unsigned
/// in-memory root would 404. Returns the router, the xite address, and the
/// whole-file fetch counter.
async fn router_with_declared_edx_file(
    body: &[u8],
) -> (axum::Router, String, Arc<AtomicUsize>) {
    router_with_edx_fetcher(body, None).await
}

/// [`router_with_declared_edx_file`], but the fetcher lands at most `cap`
/// bytes per range (a partial fetch over a slow overlay).
async fn router_with_partial_edx_file(
    body: &[u8],
    cap: usize,
) -> (axum::Router, String, Arc<AtomicUsize>) {
    router_with_edx_fetcher(body, Some(cap)).await
}

async fn router_with_edx_fetcher(
    body: &[u8],
    cap: Option<usize>,
) -> (axum::Router, String, Arc<AtomicUsize>) {
    let state = AppState::new("range-test");
    let dir = tempfile::tempdir().unwrap();
    let id = epix_blob::ObjId::of(body);
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(dir.path().join("site"));
    let mut root = json!({
        "address": address,
        "modified": 1.0,
        "files": {
            "media/movie.mp4": {
                "size": body.len(),
                "sha512": XiteStorage::hash_bytes(body),
                "b3": id.to_string(),
            }
        },
    });
    epix_content::sign(&mut root, &key).unwrap();
    storage.write("content.json", &serde_json::to_vec(&root).unwrap()).unwrap();
    state
        .add_xite(&address, XiteEntry { storage, content: Some(root) })
        .await;
    let whole_file_calls = Arc::new(AtomicUsize::new(0));
    state
        .set_edx_fetcher(Arc::new(RangeFetcher {
            body: body.to_vec(),
            cap,
            whole_file_calls: whole_file_calls.clone(),
        }))
        .await;
    std::mem::forget(dir);
    (UiServer::new(state).router(), address, whole_file_calls)
}

fn get_range(address: &str, range: &str) -> axum::extract::Request {
    axum::extract::Request::builder()
        .uri(format!("/{address}/media/movie.mp4"))
        .header("referer", format!("http://localhost/{address}/"))
        .header("range", range)
        .body(axum::body::Body::empty())
        .unwrap()
}

/// `(status, content-range, body)` of a response.
async fn parts(resp: axum::response::Response) -> (u16, String, Vec<u8>) {
    let status = resp.status().as_u16();
    let range = resp
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 24).await.unwrap().to_vec();
    (status, range, body)
}

#[tokio::test]
async fn range_of_a_missing_edx_file_seeks_instead_of_downloading_the_whole_file() {
    let body: Vec<u8> = (0..2048).map(|i| i as u8).collect();
    let (router, address, whole_file_calls) = router_with_declared_edx_file(&body).await;
    let resp = router.oneshot(get_range(&address, "bytes=0-1023")).await.unwrap();
    let (status, content_range, served) = parts(resp).await;
    assert_eq!(status, 206);
    assert_eq!(content_range, "bytes 0-1023/2048");
    assert_eq!(served.as_slice(), &body[..1024]);
    assert_eq!(
        whole_file_calls.load(Ordering::SeqCst),
        0,
        "the range must not trigger a whole-file fetch"
    );
}

#[tokio::test]
async fn a_partial_fetch_serves_the_prefix_as_a_shorter_206() {
    // The fetch could only land the first 1024 bytes of the requested
    // window (overlay peers mid-transfer): the response must be a SHORTER
    // 206 whose Content-Range matches what is actually served - the
    // browser re-requests the remainder - never a 404 for bytes we hold.
    let body: Vec<u8> = (0..4096).map(|i| i as u8).collect();
    let (router, address, whole_file_calls) = router_with_partial_edx_file(&body, 1024).await;
    let resp = router.oneshot(get_range(&address, "bytes=0-4095")).await.unwrap();
    let (status, content_range, served) = parts(resp).await;
    assert_eq!(status, 206);
    assert_eq!(content_range, "bytes 0-1023/4096");
    assert_eq!(served.as_slice(), &body[..1024]);
    assert_eq!(whole_file_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_open_ended_range_serves_one_window_not_the_whole_file() {
    let body: Vec<u8> = (0..5 * 1024 * 1024).map(|i| i as u8).collect();
    let (router, address, whole_file_calls) = router_with_declared_edx_file(&body).await;
    let resp = router.oneshot(get_range(&address, "bytes=0-")).await.unwrap();
    let (status, content_range, served) = parts(resp).await;
    assert_eq!(status, 206);
    assert_eq!(served.len(), 4 * 1024 * 1024, "one window, not the whole 5 MiB file");
    assert_eq!(content_range, format!("bytes 0-{}/{}", 4 * 1024 * 1024 - 1, body.len()));
    assert_eq!(whole_file_calls.load(Ordering::SeqCst), 0);
}
