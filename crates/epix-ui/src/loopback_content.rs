//! Address-bound content origins for a node reached through its loopback UI.
//!
//! The wrapper remains on the node origin. Content hosts serve xite files and
//! scoped transfer endpoints, without the node's UI or WebSocket authority.

use super::{Ctx, FileQuery};
use axum::http::request::Parts;
use axum::{
    extract::{FromRequest, Path, Query, RawQuery, Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

fn authority(host: &str) -> Option<axum::http::uri::Authority> {
    let authority = host.parse::<axum::http::uri::Authority>().ok()?;
    (!authority.as_str().contains('@')).then_some(authority)
}

fn reserved(host: &str) -> bool {
    // Reserve malformed aliases for denial as well. In particular a trailing
    // DNS dot must not fall through to the node's password/Login middleware.
    host.to_ascii_lowercase().contains(".localhost")
}

pub(super) fn address(host: &str) -> Option<String> {
    let authority = authority(host)?;
    let host = authority.host().to_ascii_lowercase();
    let address = host.strip_prefix("epix-")?.strip_suffix(".localhost")?;
    (epix_core::classify_label(address) == epix_core::LabelClass::Address)
        .then(|| address.to_string())
}

fn content_server(address: &str, port: u16) -> String {
    format!("epix-{address}.localhost:{port}")
}

fn origin_identity(origin: &str, port: u16) -> Option<String> {
    let url = reqwest::Url::parse(origin).ok()?;
    if url.scheme() != "http"
        || url.port_or_known_default() != Some(port)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization() != origin
    {
        return None;
    }
    address(url.host_str()?)
}

fn referrer_identity(value: &str, port: u16) -> Option<String> {
    let url = reqwest::Url::parse(value).ok()?;
    if url.scheme() != "http"
        || url.port_or_known_default() != Some(port)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    address(url.host_str()?)
}

fn passive_resource(headers: &HeaderMap) -> bool {
    matches!(
        headers
            .get("sec-fetch-dest")
            .and_then(|value| value.to_str().ok()),
        Some("image" | "audio" | "video" | "track" | "font")
    )
}

fn navigation(headers: &HeaderMap) -> bool {
    headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        == Some("navigate")
}

fn same_content_request(headers: &HeaderMap, xite: &str, port: u16) -> bool {
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    let referrer = headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok());
    (!headers.contains_key(header::ORIGIN) || origin.is_some())
        && (!headers.contains_key(header::REFERER) || referrer.is_some())
        && (origin.is_some() || referrer.is_some())
        && origin.is_none_or(|value| origin_identity(value, port).as_deref() == Some(xite))
        && referrer.is_none_or(|value| referrer_identity(value, port).as_deref() == Some(xite))
}

fn stream_request(headers: &HeaderMap, method: &Method, path: &str, xite: &str, port: u16) -> bool {
    cfg!(feature = "bittorrent")
        && path == "/bt/stream"
        && matches!(*method, Method::GET | Method::HEAD)
        && matches!(
            headers
                .get("sec-fetch-dest")
                .and_then(|value| value.to_str().ok()),
            Some("audio" | "video")
        )
        && same_content_request(headers, xite, port)
}

fn sandbox_resource(response: &mut Response) {
    response.headers_mut().append(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static("sandbox"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
}

fn document_request(headers: &HeaderMap) -> bool {
    navigation(headers)
        || matches!(
            headers
                .get("sec-fetch-dest")
                .and_then(|value| value.to_str().ok()),
            Some("document" | "iframe" | "frame" | "object" | "embed")
        )
}

fn resource_url(server: &str, path: &str, query: Option<&str>) -> String {
    let mut url = reqwest::Url::parse(&format!("http://{server}/")).unwrap();
    // Encode each decoded segment, including literal '%' and '#', once.
    url.path_segments_mut()
        .unwrap()
        .clear()
        .extend(path.split('/'));
    url.set_query(query);
    url.to_string()
}

pub(super) fn is_content_origin(origin: &str) -> bool {
    reqwest::Url::parse(origin)
        .ok()
        .and_then(|url| url.host_str().map(reserved))
        .unwrap_or(false)
}

/// Only the real local listener may advertise a loopback content origin.
/// LAN clients and gateway visitors must not be sent to their own localhost.
async fn node_port(ctx: &Ctx, host: &str) -> Option<u16> {
    if !ctx.state.ui_is_loopback().await || ctx.state.ui_restrict().await {
        return None;
    }
    let authority = authority(host)?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if !host.eq_ignore_ascii_case("localhost") && !matches!(host, "127.0.0.1" | "::1") {
        return None;
    }
    let port = authority.port_u16().unwrap_or(80);
    (port == ctx.state.ui_port().await).then_some(port)
}

pub(super) async fn iframe_server(ctx: &Ctx, host: &str, xite: &str) -> Option<String> {
    let port = node_port(ctx, host).await?;
    (epix_core::classify_label(xite) == epix_core::LabelClass::Address)
        .then(|| format!("//{}", content_server(xite, port)))
}

/// Raw xite bytes cannot acquire the trusted node origin, even in an iframe
/// or when a caller supplies a stale/forged wrapper nonce. Normal wrapper
/// rendering runs before this guard. The normal node password gate also ran.
pub(super) async fn redirect_node_file(
    ctx: &Ctx,
    address: &str,
    path: &str,
    uri: &Uri,
    headers: &HeaderMap,
) -> Option<Response> {
    let port = node_port(ctx, header_text(headers, "host").unwrap_or("")).await?;
    let mut canonical = ctx.state.canonical_key(address).await;
    if epix_core::classify_label(&canonical) != epix_core::LabelClass::Address {
        // An actually registered legacy serving key may carry a signed
        // canonical address. An arbitrary unknown path grants no identity.
        canonical = ctx
            .state
            .content(address)
            .await
            .and_then(|content| {
                content
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
    }
    if epix_core::classify_label(&canonical) != epix_core::LabelClass::Address {
        return Some(denied());
    }
    let query = redirect_query(ctx, uri).await;
    Some(content_redirect(
        &content_server(&canonical, port),
        path,
        query.as_deref(),
    ))
}

fn denied() -> Response {
    (
        StatusCode::FORBIDDEN,
        "This content origin cannot access that resource",
    )
        .into_response()
}

/// Decode once, preserving '+' in filenames. Encoded separators and dot
/// components cannot change the identity or filesystem boundary.
fn decoded_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.starts_with("//") {
        return None;
    }
    let mut output = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        let value = if byte == b'%' {
            let high = (bytes.next()? as char).to_digit(16)?;
            let low = (bytes.next()? as char).to_digit(16)?;
            let value = (high * 16 + low) as u8;
            if matches!(value, b'/' | b'\\') {
                return None;
            }
            value
        } else {
            byte
        };
        if value == b'\\' || value.is_ascii_control() {
            return None;
        }
        output.push(value);
    }
    let path = String::from_utf8(output).ok()?;
    if path.split('/').any(|part| matches!(part, "." | "..")) {
        return None;
    }
    Some(path)
}

fn node_route(path: &str) -> bool {
    matches!(
        path.trim_start_matches('/').split('/').next().unwrap_or(""),
        "Config"
            | "Plugins"
            | "Stats"
            | "StatsJson"
            | "Backup"
            | "EpixWallet"
            | "EpixNet-Internal"
            | "Login"
            | "Logout"
            | "Benchmark"
            | "list"
            | "raw"
            | "add"
            | "bt"
            | "uimedia"
    )
}

fn top_navigation(headers: &HeaderMap) -> bool {
    headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok()) == Some("navigate")
        && headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) == Some("document")
}

fn navigation_query(uri: &Uri) -> Option<String> {
    // A nonce marks an inner file request on the node. It must never follow
    // a top-level redirect and suppress the destination's wrapper render.
    uri.query()
        .map(super::strip_wrapper_nonce)
        .filter(|query| !query.is_empty())
}

#[derive(Clone, Copy)]
enum ContentRoute {
    File,
    Upload,
    Stream,
    NodeNavigation,
}

struct ContentRequest {
    xite: String,
    port: u16,
    path: String,
    node_server: String,
    route: ContentRoute,
}

fn header_text<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|value| value.to_str().ok())
}

fn upload_request(request: &Parts, path: &str, xite: &str, port: u16) -> bool {
    path == super::BIGFILE_UPLOAD_PATH
        && request.method == Method::POST
        && header_text(&request.headers, "origin")
            .and_then(|value| origin_identity(value, port))
            .as_deref()
            == Some(xite)
        && same_content_request(&request.headers, xite, port)
}

fn node_navigation(request: &Parts, path: &str) -> bool {
    request.method == Method::GET
        && top_navigation(&request.headers)
        && matches!(
            path,
            "/Config" | "/Config/" | "/Plugins" | "/Plugins/" | "/Stats" | "/Stats/" | "/Backup"
        )
}

fn node_server(request: &Parts, port: u16) -> String {
    // ConnectInfo is attached by the server, never supplied by the page. A
    // loopback IPv6 connection needs a return address reachable on ::1 too.
    let ipv6 = request
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .is_some_and(|peer| peer.0.ip().is_loopback() && peer.0.is_ipv6());
    if ipv6 {
        format!("[::1]:{port}")
    } else {
        format!("127.0.0.1:{port}")
    }
}

async fn admit(ctx: &Ctx, request: &Parts, host: &str) -> Result<ContentRequest, Response> {
    let xite = address(host).ok_or_else(denied)?;
    let port = ctx.state.ui_port().await;
    if authority(host).and_then(|a| a.port_u16()).unwrap_or(80) != port
        || !ctx.state.ui_is_loopback().await
        || ctx.state.ui_restrict().await
    {
        return Err(denied());
    }
    let path = decoded_path(request.uri.path()).ok_or_else(denied)?;
    let route = if upload_request(request, &path, &xite, port) {
        ContentRoute::Upload
    } else if stream_request(&request.headers, &request.method, &path, &xite, port) {
        ContentRoute::Stream
    } else if node_navigation(request, &path) {
        ContentRoute::NodeNavigation
    } else {
        if node_route(&path)
            || !matches!(request.method, Method::GET | Method::HEAD | Method::OPTIONS)
        {
            return Err(denied());
        }
        ContentRoute::File
    };
    Ok(ContentRequest {
        xite,
        port,
        path,
        node_server: node_server(request, port),
        route,
    })
}

#[cfg(feature = "ui-password")]
async fn password_session(ctx: &Ctx, request: &Parts) -> Result<bool, Response> {
    if ctx.state.ui_password().await.is_none() {
        return Ok(false);
    }
    let cookie = header_text(&request.headers, "cookie");
    if super::uipassword::session_valid(&super::uipassword::cookie_session_id(cookie)) {
        return Ok(false);
    }
    let nonce = Query::<FileQuery>::try_from_uri(&request.uri)
        .ok()
        .and_then(|query| query.0.wrapper_nonce);
    if nonce
        .as_deref()
        .is_some_and(|value| ctx.state.wrapper_nonce_outstanding(value))
    {
        Ok(true)
    } else {
        Err(denied())
    }
}

#[cfg(feature = "ui-password")]
fn set_session(response: &mut Response, new_session: bool) {
    // The first file request consumes its nonce even when discovery returns
    // a retryable waiting page. Keep that admitted page authenticated for the
    // next attempt; an admission denial never reaches this helper.
    let admitted =
        response.status().is_success() || response.status() == StatusCode::SERVICE_UNAVAILABLE;
    if !new_session || !admitted {
        return;
    }
    let id = super::uipassword::session_create();
    if let Ok(cookie) =
        format!("session_id={id}; path=/; max-age=2592000; SameSite=None; Secure; HttpOnly").parse()
    {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
}

async fn upload(ctx: &Ctx, request: Request, xite: &str) -> Response {
    let query = match Query::<super::UploadQuery>::try_from_uri(request.uri()) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    if !query
        .upload_nonce
        .as_deref()
        .is_some_and(|token| ctx.state.bigfile_upload_belongs_to(token, xite))
    {
        return denied();
    }
    let headers = request.headers().clone();
    // Use the existing endpoint's Bytes extractor and body-size limit. The
    // handler checks the xite again while atomically consuming the nonce.
    let body = match axum::body::Bytes::from_request(request, ctx).await {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    let mut response = super::bigfile_upload(State(ctx.clone()), query, headers, body).await;
    sandbox_resource(&mut response);
    response
}

#[cfg(feature = "bittorrent")]
async fn stream(ctx: &Ctx, headers: HeaderMap, uri: &Uri) -> Response {
    let query = match Query::<super::BtStreamQuery>::try_from_uri(uri) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let mut response = super::serve_bt_stream(State(ctx.clone()), query, headers).await;
    sandbox_resource(&mut response);
    response
}

#[cfg(not(feature = "bittorrent"))]
async fn stream(_ctx: &Ctx, _headers: HeaderMap, _uri: &Uri) -> Response {
    denied()
}

fn node_navigation_redirect(content: &ContentRequest, uri: &Uri) -> Response {
    Redirect::temporary(&resource_url(
        &content.node_server,
        content.path.trim_start_matches('/'),
        navigation_query(uri).as_deref(),
    ))
    .into_response()
}

#[cfg(feature = "ui-password")]
async fn raw_navigation_needs_node(ctx: &Ctx, request: &Parts) -> bool {
    password_session(ctx, request).await.is_err()
}

#[cfg(not(feature = "ui-password"))]
async fn raw_navigation_needs_node(_ctx: &Ctx, _request: &Parts) -> bool {
    false
}

fn needs_wrapper(target: &ResourceTarget) -> bool {
    super::wrapper_inner_path(&target.path, true).is_some()
}

async fn navigation_redirect(
    ctx: &Ctx,
    request: &Parts,
    content: &ContentRequest,
) -> Option<Response> {
    if request.method != Method::GET || !top_navigation(&request.headers) {
        return None;
    }
    // Partitioned iframe cookies may not follow top-level navigation. HTML
    // returns to its wrapper; raw resources without a content session first
    // use the node's normal authentication and one-use bootstrap redirect.
    match content.route {
        ContentRoute::NodeNavigation => Some(node_navigation_redirect(content, &request.uri)),
        ContentRoute::File => {
            let target = match resolve_target(ctx, content).await {
                Ok(target) => target,
                Err(response) => return Some(response),
            };
            if needs_wrapper(&target) || raw_navigation_needs_node(ctx, request).await {
                Some(top_redirect(content, &target, &request.uri))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// This layer runs before password and generic routing. Content hosts never
/// render node controls, including Login for unauthenticated requests.
pub(super) async fn gate(State(ctx): State<Ctx>, request: Request, next: Next) -> Response {
    let host = header_text(request.headers(), "host").unwrap_or("");
    if !reserved(host) {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let host = header_text(&parts.headers, "host").unwrap_or("");
    let content = match admit(&ctx, &parts, host).await {
        Ok(content) => content,
        Err(response) => return response,
    };
    if let Some(response) = navigation_redirect(&ctx, &parts, &content).await {
        return response;
    }
    #[cfg(feature = "ui-password")]
    let new_session = match password_session(&ctx, &parts).await {
        Ok(new_session) => new_session,
        Err(response) => return response,
    };
    let method = parts.method.clone();
    let request = Request::from_parts(parts, body);
    let mut response = match content.route {
        ContentRoute::Upload => upload(&ctx, request, &content.xite).await,
        ContentRoute::Stream => stream(&ctx, request.headers().clone(), request.uri()).await,
        ContentRoute::NodeNavigation => node_navigation_redirect(&content, request.uri()),
        ContentRoute::File => {
            serve(&ctx, request.headers(), request.uri(), &method, &content).await
        }
    };
    #[cfg(feature = "ui-password")]
    set_session(&mut response, new_session);
    if method == Method::HEAD {
        *response.body_mut() = axum::body::Body::empty();
    }
    response
}

struct ResourceTarget {
    source: String,
    xite: String,
    path: String,
    explicit: bool,
    merged: bool,
}

async fn resolve_target(ctx: &Ctx, content: &ContentRequest) -> Result<ResourceTarget, Response> {
    let relative = content.path.trim_start_matches('/');
    let (first, remaining) = relative.split_once('/').unwrap_or((relative, ""));
    let explicit = super::cross_xite_origin(first);
    let source = match explicit.as_deref() {
        Some(reference) => {
            ctx.state
                .canonical_key(super::address_alias(reference).unwrap_or(reference))
                .await
        }
        None => content.xite.clone(),
    };
    let inner = if explicit.is_some() {
        remaining
    } else {
        relative
    };
    let resolved = ctx
        .state
        .resolve_merged(&source, inner)
        .await
        .map_err(|_| denied())?;
    let merged = resolved.is_some();
    let (xite, path) = resolved.unwrap_or_else(|| (source.clone(), inner.to_string()));
    Ok(ResourceTarget {
        source,
        xite,
        path,
        explicit: explicit.is_some(),
        merged,
    })
}

fn top_redirect(content: &ContentRequest, target: &ResourceTarget, uri: &Uri) -> Response {
    let query = navigation_query(uri);
    let url = if target.merged {
        resource_url(
            &content.node_server,
            &format!("{}/{}", target.xite, target.path),
            query.as_deref(),
        )
    } else {
        let suffix = query
            .as_ref()
            .map(|value| format!("?{value}"))
            .unwrap_or_default();
        if target.explicit {
            format!("http://{}{}{suffix}", content.node_server, uri.path())
        } else {
            format!(
                "http://{}/{}{}{suffix}",
                content.node_server,
                content.xite,
                uri.path()
            )
        }
    };
    Redirect::temporary(&url).into_response()
}

struct RequestIdentity<'a> {
    origin: Option<&'a str>,
    origin_xite: Option<String>,
    referrer: Option<&'a str>,
    referrer_xite: Option<String>,
}

impl<'a> RequestIdentity<'a> {
    fn new(headers: &'a HeaderMap, port: u16) -> Self {
        let origin = header_text(headers, "origin");
        let referrer = header_text(headers, "referer");
        Self {
            origin,
            origin_xite: origin.and_then(|value| origin_identity(value, port)),
            referrer,
            referrer_xite: referrer.and_then(|value| referrer_identity(value, port)),
        }
    }

    fn absent(&self) -> bool {
        self.origin.is_none() && self.referrer.is_none()
    }

    fn matches(&self, xite: &str) -> bool {
        if self.origin.is_some() {
            self.origin_xite.as_deref() == Some(xite)
        } else {
            self.referrer_xite.as_deref() == Some(xite)
        }
    }
}

struct ResourceRequest<'a> {
    content: &'a ContentRequest,
    headers: &'a HeaderMap,
    uri: &'a Uri,
    identity: RequestIdentity<'a>,
}

fn unproven_foreign_request(request: &ResourceRequest<'_>) -> bool {
    matches!(
        header_text(request.headers, "sec-fetch-site"),
        Some("cross-site" | "same-site")
    ) && !document_request(request.headers)
        && !passive_resource(request.headers)
        && !request.identity.matches(&request.content.xite)
}

#[cfg(feature = "ui-password")]
async fn redirect_query(ctx: &Ctx, uri: &Uri) -> Option<String> {
    if ctx.state.ui_password().await.is_none() {
        return uri.query().map(str::to_string);
    }
    // The source request passed password admission and the selected redirect
    // passed resource authorization. Reuse the existing one-use bootstrap for
    // the target's host-only session; its file handler consumes this nonce.
    let query = super::strip_wrapper_nonce(uri.query().unwrap_or(""));
    let nonce = ctx.state.issue_wrapper_nonce();
    Some(if query.is_empty() {
        format!("wrapper_nonce={nonce}")
    } else {
        format!("{query}&wrapper_nonce={nonce}")
    })
}

#[cfg(not(feature = "ui-password"))]
async fn redirect_query(_ctx: &Ctx, uri: &Uri) -> Option<String> {
    uri.query().map(str::to_string)
}

async fn target_redirect(
    ctx: &Ctx,
    request: &ResourceRequest<'_>,
    target: &ResourceTarget,
) -> Response {
    let query = redirect_query(ctx, request.uri).await;
    content_redirect(
        &content_server(&target.xite, request.content.port),
        &target.path,
        query.as_deref(),
    )
}

fn content_redirect(server: &str, path: &str, query: Option<&str>) -> Response {
    let mut response = Redirect::temporary(&resource_url(server, path, query)).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn foreign_resource_response(
    ctx: &Ctx,
    request: &ResourceRequest<'_>,
    target: &ResourceTarget,
) -> Option<Response> {
    let host = &request.content.xite;
    // A path cannot borrow a different source xite's merger permission.
    if target.merged && target.source != *host {
        return Some(denied());
    }
    if target.xite == *host {
        return None;
    }
    if epix_core::classify_label(&target.xite) != epix_core::LabelClass::Address {
        return Some(denied());
    }
    if document_request(request.headers) {
        return Some(target_redirect(ctx, request, target).await);
    }
    let granted = target.merged || ctx.state.has_cors_permission(host, &target.xite).await;
    if !granted {
        // Ungranted images stay cross-origin, preserving canvas tainting.
        return Some(if passive_resource(request.headers) {
            target_redirect(ctx, request, target).await
        } else {
            denied()
        });
    }
    if !request.identity.absent() && !request.identity.matches(host) {
        return Some(denied());
    }
    None
}

async fn foreign_referrer_denied(
    ctx: &Ctx,
    request: &ResourceRequest<'_>,
    foreign_resource: bool,
) -> bool {
    let identity = &request.identity;
    if foreign_resource
        || identity.origin.is_some()
        || identity.referrer.is_none()
        || navigation(request.headers)
        || passive_resource(request.headers)
        || identity.referrer_xite.as_deref() == Some(request.content.xite.as_str())
    {
        return false;
    }
    !ctx.state
        .has_cors_permission(
            identity.referrer_xite.as_deref().unwrap_or(""),
            &request.content.xite,
        )
        .await
}

async fn read_access(
    ctx: &Ctx,
    request: &ResourceRequest<'_>,
    foreign_resource: bool,
) -> Result<bool, Response> {
    let identity = &request.identity;
    if identity.origin.is_some() && identity.origin_xite.is_none() {
        return Err(denied());
    }
    let cross_origin = identity
        .origin_xite
        .as_deref()
        .is_some_and(|source| source != request.content.xite);
    let cors_grant = cross_origin
        && (ctx
            .state
            .has_cors_permission(
                identity.origin_xite.as_deref().unwrap(),
                &request.content.xite,
            )
            .await
            || header_text(request.headers, "sec-fetch-dest") == Some("font"));
    let opaque_resource = passive_resource(request.headers)
        && header_text(request.headers, "sec-fetch-mode") == Some("no-cors");
    if cross_origin && !cors_grant && !opaque_resource {
        return Err(denied());
    }
    if foreign_referrer_denied(ctx, request, foreign_resource).await {
        return Err(denied());
    }
    Ok(cors_grant)
}

async fn file_response(
    ctx: &Ctx,
    request: &ResourceRequest<'_>,
    target: ResourceTarget,
) -> Response {
    let mut inner = target.path;
    if inner.is_empty() || inner.ends_with('/') {
        inner.push_str("index.html");
    }
    let query = match Query::<FileQuery>::try_from_uri(request.uri) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    super::serve_file(
        State(ctx.clone()),
        Path((target.xite, inner)),
        query,
        RawQuery(request.uri.query().map(str::to_string)),
        request.uri.clone(),
        request.headers.clone(),
    )
    .await
}

fn resource_headers(
    response: &mut Response,
    request: &ResourceRequest<'_>,
    cors_grant: bool,
    foreign_resource: bool,
) {
    response
        .headers_mut()
        .remove(header::ACCESS_CONTROL_ALLOW_ORIGIN);
    response
        .headers_mut()
        .remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
    if cors_grant {
        if let Some(value) = request
            .identity
            .origin
            .and_then(|origin| origin.parse().ok())
        {
            response
                .headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
            response
                .headers_mut()
                .append(header::VARY, axum::http::HeaderValue::from_static("Origin"));
        }
    }
    if foreign_resource {
        // CSP prevents headerless documents acquiring A's origin. CORP also
        // blocks no-cors script embeds, where document CSP does not apply.
        sandbox_resource(response);
    }
    if foreign_resource || (request.identity.absent() && !passive_resource(request.headers)) {
        response.headers_mut().insert(
            "cross-origin-resource-policy",
            axum::http::HeaderValue::from_static("same-origin"),
        );
    }
    response.headers_mut().append(
        header::VARY,
        axum::http::HeaderValue::from_static("Sec-Fetch-Dest, Sec-Fetch-Mode"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
}

async fn serve(
    ctx: &Ctx,
    headers: &HeaderMap,
    uri: &Uri,
    method: &Method,
    content: &ContentRequest,
) -> Response {
    let target = match resolve_target(ctx, content).await {
        Ok(target) => target,
        Err(response) => return response,
    };
    if method == Method::OPTIONS {
        return denied();
    }
    if top_navigation(headers) && needs_wrapper(&target) {
        return top_redirect(content, &target, uri);
    }
    let request = ResourceRequest {
        content,
        headers,
        uri,
        identity: RequestIdentity::new(headers, content.port),
    };
    if unproven_foreign_request(&request) {
        return denied();
    }
    if let Some(response) = foreign_resource_response(ctx, &request, &target).await {
        return response;
    }
    let foreign_resource = target.xite != content.xite;
    let cors_grant = match read_access(ctx, &request, foreign_resource).await {
        Ok(granted) => granted,
        Err(response) => return response,
    };
    let mut response = file_response(ctx, &request, target).await;
    resource_headers(&mut response, &request, cors_grant, foreign_resource);
    response
}
