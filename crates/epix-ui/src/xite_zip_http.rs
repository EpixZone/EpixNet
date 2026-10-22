//! The sidebar's public xite archive download.
use crate::{is_cross_origin_request, xite_zip, Ctx};
use axum::{
    body::Body,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde::Deserialize;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Deserialize)]
pub(super) struct ZipQuery {
    address: String,
}

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn unavailable(message: impl Into<String>) -> Response {
    let message = message.into();
    let message = if message.starts_with("Public export unavailable:") {
        message
    } else {
        format!("Public export unavailable: {message}")
    };
    (
        StatusCode::CONFLICT,
        [(header::CACHE_CONTROL, "no-store")],
        message,
    )
        .into_response()
}

pub(super) async fn download(
    State(ctx): State<Ctx>,
    Query(query): Query<ZipQuery>,
    headers: HeaderMap,
) -> Response {
    let address = ctx.state.canonical_key(&query.address).await;
    if epix_core::Address::parse(address.clone()).is_err() || !ctx.state.has_xite(&address).await {
        return (StatusCode::NOT_FOUND, "Xite is not available on this node").into_response();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    // Internal routes normally have no target. This one must authorize the
    // query's xite, not the global /EpixNet-Internal path or proxy host.
    if ctx.state.ui_check_cors().await
        && is_cross_origin_request(&ctx, &headers, &format!("/{address}/"), host).await
    {
        return (StatusCode::FORBIDDEN, "Cross-origin export blocked").into_response();
    }
    let permit = match ctx.zip_exports.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Another xite export is in progress",
            )
                .into_response()
        }
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_on_drop = CancelOnDrop(cancelled.clone());
    let prepared = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        let (input, stamp) = ctx.state.xite_export_snapshot(&address).await?;
        // The worker owns admission until it stops, even if its caller leaves.
        let (file, permit) = tokio::task::spawn_blocking(move || {
            xite_zip::build(input, cancelled).map(|file| (file, permit))
        })
        .await
        .map_err(|_| "Xite export worker stopped".to_string())??;
        if !ctx.state.xite_export_is_current(&stamp).await {
            return Err("Xite changed during export; retry the download".to_string());
        }
        Ok::<_, String>((file, permit))
    })
    .await;
    let (file, permit) = match prepared {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => return unavailable(error),
        Err(_) => return unavailable("Xite export timed out; required content is unavailable"),
    };
    let length = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(_) => return unavailable("Xite export is no longer available"),
    };
    let reader =
        tokio_util::io::ReaderStream::with_capacity(tokio::fs::File::from_std(file), 64 * 1024);
    let stream = reader.map(move |chunk| {
        // Slow or abandoned downloads cannot accumulate unlimited temp files.
        let _keep_alive = (&permit, &cancel_on_drop);
        chunk
    });
    (
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{address}.zip\""),
            ),
            (header::CONTENT_LENGTH, length.to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}
