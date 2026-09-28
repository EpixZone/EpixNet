//! Explicit recovery of an owned file from its current signed declaration.
use super::{attr_escape, page_shell, url_encode, AppState, Ctx};
use axum::{
    extract::{Form, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::{collections::HashMap, time::Duration};

pub(super) const PREFIX: &str = "/EpixNet-Internal/Revert/";

pub(super) fn url(address: &str, inner: &str) -> String {
    let inner = inner
        .split('/')
        .map(url_encode)
        .collect::<Vec<_>>()
        .join("/");
    format!("{PREFIX}{}/{inner}", url_encode(address))
}

pub(super) async fn can_revert(state: &AppState, address: &str, inner: &str) -> bool {
    // Manifests and unsigned new files have no recoverable file declaration.
    inner.rsplit('/').next() != Some("content.json")
        && state.xite_owned(address).await
        && state.file_info_any(address, inner).await.is_some()
        && state.file_has_b3(address, inner).await
}

async fn target(ctx: &Ctx, path: &str) -> Result<(String, String), Response> {
    if !ctx.state.plugin_enabled("UiFileManager").await {
        return Err((StatusCode::NOT_FOUND, "UiFileManager plugin is disabled").into_response());
    }
    let (address, inner) = path
        .split_once('/')
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Choose a file to revert").into_response())?;
    let address = ctx.state.canonical_key(address).await;
    if !can_revert(&ctx.state, &address, inner).await {
        return Err((
            StatusCode::NOT_FOUND,
            "No recoverable signed file on an owned xite",
        )
            .into_response());
    }
    Ok((address, inner.to_string()))
}

fn list_url(address: &str, inner: &str) -> String {
    let parent = inner
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("");
    let parent = parent
        .split('/')
        .map(url_encode)
        .collect::<Vec<_>>()
        .join("/");
    format!("/list/{}/{parent}", url_encode(address))
}

async fn page(
    ctx: &Ctx,
    address: &str,
    inner: &str,
    message: &str,
    status: StatusCode,
) -> Response {
    let body = format!(
        "<p><strong>{}</strong></p>{message}\
         <p><a href='{}'>Back to files</a></p>",
        attr_escape(inner),
        attr_escape(&list_url(address, inner)),
    );
    let theme = ctx.state.theme_class().await;
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        page_shell("Revert file", "Revert file", "", &body, address, &theme),
    )
        .into_response()
}

pub(super) async fn confirm(State(ctx): State<Ctx>, Path(path): Path<String>) -> Response {
    let (address, inner) = match target(&ctx, &path).await {
        Ok(target) => target,
        Err(response) => return response,
    };
    let message = format!(
        "<p>Restore the version recorded in the signed content.json? \
         This replaces unsigned edits to this file.</p>\
         <p>This cannot undo changes that have already been signed. \
         Recovery needs a local verified copy or a peer that still has the file.</p>\
         <form method='post' action='{}'>\
         <input type='hidden' name='csrf' value='{}'>\
         <button class='button' type='submit'>Revert file</button></form>",
        attr_escape(&url(&address, &inner)),
        attr_escape(ctx.state.ui_csrf_token()),
    );
    page(&ctx, &address, &inner, &message, StatusCode::OK).await
}

pub(super) async fn restore(
    State(ctx): State<Ctx>,
    Path(path): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !form
        .get("csrf")
        .is_some_and(|token| ctx.state.ui_csrf_valid(token))
    {
        return (StatusCode::FORBIDDEN, "Invalid or missing CSRF token").into_response();
    }
    let (address, inner) = match target(&ctx, &path).await {
        Ok(target) => target,
        Err(response) => return response,
    };
    // Keep the local file in place while fetching. The existing downloader
    // verifies bytes and rechecks the signed authority before atomic replacement.
    let restored = tokio::time::timeout(
        Duration::from_secs(180),
        ctx.state.file_need(&address, &inner),
    )
    .await;
    let error = match restored {
        Ok(Ok(true)) => {
            ctx.state.ingest_file(&address, &inner).await;
            return page(
                &ctx,
                &address,
                &inner,
                "<p>File restored. Reload the xite to use the restored version.</p>",
                StatusCode::OK,
            )
            .await;
        }
        Ok(Ok(false)) => "No verified copy was available".to_string(),
        Ok(Err(error)) => error,
        Err(_) => "Timed out waiting for a verified copy".to_string(),
    };
    page(
        &ctx,
        &address,
        &inner,
        &format!(
            "<p>Could not restore this file: {}</p>",
            attr_escape(&error)
        ),
        StatusCode::BAD_GATEWAY,
    )
    .await
}
