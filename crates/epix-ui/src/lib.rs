//! `epix-ui` - the local UI server.
//!
//! Serves the wrapper (`GET /{address}/`), the wrapper runtime assets
//! (`/uimedia/*`, embedded at build time), a xite's own files
//! (`GET /{address}/{inner_path}`), and the EpixFrame WebSocket command API at
//! `/EpixNet-Internal/Websocket?wrapper_key=…`. Commands are dispatched through
//! the [`CommandRegistry`], which the plugin system extends.

#[cfg(feature = "benchmark")]
pub mod benchmark;
pub mod chart;
pub mod command;
pub mod conn_pool;
pub mod fileserve;
pub mod geoip;
pub mod paths;
pub mod state;
pub mod tracker;
#[cfg(feature = "ui-password")]
pub mod uipassword;

pub use command::{CommandRegistry, WsCommand, WsSession};
pub use state::{AppState, ContentSyncer, OnDemandResolver, PeerFinder, XiteEntry};

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use include_dir::{include_dir, Dir};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

/// The wrapper runtime (all.js / all.css / img / lib), embedded at build time.
static UIMEDIA: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../ui/media");
const WRAPPER_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../ui/wrapper.html"));

/// One plugin's `/uimedia/*` contributions.
#[derive(Default, Clone)]
pub struct PluginMedia {
    /// Plugin name; empty for base (always-on) contributions.
    pub name: String,
    pub append_js: Vec<u8>,
    pub append_css: Vec<u8>,
    pub files: std::collections::HashMap<String, Vec<u8>>,
}

/// Plugins' contributions to `/uimedia/*`, kept per-plugin so a disabled plugin
/// can be excluded at request time (append_js/css concatenated onto the base
/// bundle, plus extra static files keyed by path under `/uimedia/`).
#[derive(Default, Clone)]
pub struct MediaBundle {
    pub plugins: Vec<PluginMedia>,
}

#[derive(Clone)]
struct Ctx {
    state: Arc<AppState>,
    registry: Arc<CommandRegistry>,
    media: Arc<MediaBundle>,
}

/// The UI server.
pub struct UiServer {
    ctx: Ctx,
}

impl UiServer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self::with_registry(state, CommandRegistry::with_defaults())
    }

    pub fn with_registry(state: Arc<AppState>, registry: CommandRegistry) -> Self {
        Self::with_registry_and_media(state, registry, MediaBundle::default())
    }

    /// Build the server with plugin-contributed `/uimedia` content.
    pub fn with_registry_and_media(
        state: Arc<AppState>,
        registry: CommandRegistry,
        media: MediaBundle,
    ) -> Self {
        Self {
            ctx: Ctx { state, registry: Arc::new(registry), media: Arc::new(media) },
        }
    }

    pub fn router(&self) -> Router {
        let router = Router::new()
            .route("/", get(health))
            .route("/EpixNet-Internal/Status", get(serve_status))
            .route("/EpixNet-Internal/Websocket", get(ws_upgrade))
            .route("/EpixNet-Internal/BigfileUpload", axum::routing::post(bigfile_upload))
            .route("/uimedia/*path", get(serve_uimedia))
            .route("/Plugins", get(serve_plugins_page))
            .route("/Config", get(serve_config_page))
            .route("/Stats", get(serve_stats_page))
            .route("/StatsJson", get(serve_stats_json))
            // Trailing-slash variants would otherwise fall through to the
            // xite route ("/Stats/" -> serve_wrapper("Stats") -> 404).
            .route("/Plugins/", get(|| async { Redirect::permanent("/Plugins") }))
            .route("/Config/", get(|| async { Redirect::permanent("/Config") }))
            .route("/Stats/", get(|| async { Redirect::permanent("/Stats") }))
            // The Epix Wallet web app for the mobile shells (see
            // AppState::wallet_ui_dir); 404s when nothing is staged.
            .route("/EpixWallet", get(|| async { Redirect::permanent("/EpixWallet/mobile.html") }))
            .route("/EpixWallet/", get(|| async { Redirect::permanent("/EpixWallet/mobile.html") }))
            .route("/EpixWallet/*path", get(serve_wallet))
            .route("/list/*path", get(serve_file_manager))
            // Browsers ask for /favicon.ico at the origin root.
            .route(
                "/favicon.ico",
                get(|| async { Redirect::permanent("/uimedia/img/favicon.ico") }),
            )
            // EpixNet's /raw/<site>/<path>: the file without the wrapper,
            // under the restrictive noscript CSP.
            .route("/raw/:address/*path", get(serve_raw))
            // EpixNet's /add/<site> confirmation flow maps onto this node's
            // on-demand design: navigating to a xite already resolves +
            // clones it (gated by NoNewSites), so /add is a redirect.
            .route("/add/:address", get(redirect_add))
            .route("/add/:address/", get(redirect_add))
            .route("/:address", get(redirect_to_slash))
            .route("/:address/", get(serve_wrapper))
            .route("/:address/*path", get(serve_file));
        // Benchmark: a diagnostics page timing the node's hot paths.
        #[cfg(feature = "benchmark")]
        let router = router.route("/Benchmark", get(serve_benchmark));
        // Tier 1 UI security (EpixNet's UiRequest.route entry checks): the
        // Host allowlist (DNS-rebinding protection), the OPTIONS preflight
        // answer, and the cross-origin request gate.
        let router = router.layer(axum::middleware::from_fn_with_state(
            self.ctx.clone(),
            security_gate,
        ));
        // UiPassword: mount the login/logout routes and the session gate.
        #[cfg(feature = "ui-password")]
        let router = router
            .route("/Login", get(serve_login).post(serve_login_post))
            .route("/Logout", get(serve_logout))
            .layer(axum::middleware::from_fn_with_state(
                self.ctx.clone(),
                ui_password_gate,
            ));
        router.with_state(self.ctx.clone())
    }

    pub async fn serve(self, addr: SocketAddr) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        // EpixNet enables the cross-origin gate by default only on a loopback
        // bind (a LAN/public bind is a deliberate multi-client deployment);
        // the `ui_check_cors` config key overrides either way.
        self.ctx.state.set_ui_loopback(addr.ip().is_loopback()).await;
        // Wrap the router so a transparent-proxy request (Firefox routing a
        // `*.epix` host to us) is rewritten from host form to the path form the
        // routes already understand, BEFORE routing. `Router::layer` runs after
        // route matching, so the rewrite is a `map_request` around the whole
        // router served per-connection via `Shared`.
        let app = tower::ServiceExt::<axum::extract::Request>::map_request(
            self.router(),
            rewrite_proxy_host,
        );
        axum::serve(listener, tower::make::Shared::new(app)).await
    }
}

/// The route-entry security checks, ported from EpixNet's `UiRequest.route`:
///
/// 1. **Host allowlist** (DNS-rebinding protection, `isHostAllowed`): a
///    request must carry a Host we recognize - an IP literal, `localhost`, a
///    `.epix` name (the transparent-proxy wildcard), or an operator-listed
///    `ui_host` config entry. A rebinding attacker's DNS name matches none.
/// 2. **OPTIONS preflight**: answered directly with the same headers EpixNet
///    sends (`Access-Control-Allow-Origin: null` + the allow-list), never
///    routed.
/// 3. **Cross-origin gate** (`isCrossOriginRequest`): blocks non-navigation
///    requests that are untraceable or from another origin, so a clearnet
///    page cannot probe which xites this node serves. Cross-xite reads are
///    allowed when the source xite holds the `Cors:<target>` permission.
async fn security_gate(
    State(ctx): State<Ctx>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let host_raw = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !host_allowed(&ctx, &host_raw).await {
        return (
            StatusCode::FORBIDDEN,
            format!(
                "Invalid host: {host_raw}
Add it to the ui_host config key, or access the UI                  by IP."
            ),
        )
            .into_response();
    }

    if req.method() == axum::http::Method::OPTIONS {
        return (
            [
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "null".to_string()),
                (
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "Origin, X-Requested-With, Content-Type, Accept, Cookie, Range, Referer"
                        .to_string(),
                ),
                (header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".to_string()),
            ],
            "",
        )
            .into_response();
    }

    if ctx.state.ui_check_cors().await
        && is_cross_origin_request(&ctx, req.headers(), req.uri().path(), &host_raw).await
    {
        return (StatusCode::FORBIDDEN, "Cross-origin request blocked").into_response();
    }

    next.run(req).await
}

/// EpixNet's `isHostAllowed`. The `.epix` wildcard covers transparent-proxy
/// requests (the desktop browser routes every `*.epix` host to the node).
async fn host_allowed(ctx: &Ctx, host: &str) -> bool {
    if host.is_empty() {
        return true; // HTTP/1.0-style, nothing to rebind
    }
    let bare = strip_port(host);
    if bare == "localhost" || bare.parse::<std::net::IpAddr>().is_ok() {
        return true; // IPs are not affected by DNS rebinding
    }
    if bare.ends_with(".epix") {
        return true;
    }
    // Operator-listed extra hosts (reverse proxies etc.), one per line.
    ctx.state
        .config_get("ui_host")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
        .lines()
        .any(|l| l.trim().eq_ignore_ascii_case(bare))
}

/// `host:port` -> `host`, handling `[v6]:port` and bare `[v6]`.
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
}

/// EpixNet's `isCrossOriginRequest`, same decision order.
async fn is_cross_origin_request(
    ctx: &Ctx,
    headers: &header::HeaderMap,
    path: &str,
    host: &str,
) -> bool {
    // User navigation is always allowed.
    if headers.get("sec-fetch-mode").and_then(|v| v.to_str().ok()) == Some("navigate") {
        return false;
    }
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    let referer = headers.get(header::REFERER).and_then(|v| v.to_str().ok());
    // Untraceable requests are blocked for site paths (checked below for /).
    if origin.is_none() && referer.is_none() && !is_public_ui_path(path) {
        return true;
    }
    // A foreign origin never reads site content.
    if let Some(origin) = origin {
        if !url_is_same_host(origin, host) {
            return true;
        }
    }
    // Non-site-specific routes carry nothing to probe.
    if is_public_ui_path(path) {
        return false;
    }
    let Some(target) = path.trim_start_matches('/').split('/').next().filter(|s| !s.is_empty())
    else {
        return false;
    };
    // Same-xite requests pass; cross-xite needs the Cors:<target> permission
    // on the source xite.
    let source = referer.and_then(|r| referer_site(ctx, r, host));
    match source {
        Some(source) if source == target => false,
        Some(source) => !ctx.state.has_cors_permission(&source, target).await,
        None => true,
    }
}

/// Routes that identify no xite (safe to answer regardless of referer).
fn is_public_ui_path(path: &str) -> bool {
    path == "/" || is_global_path(path)
}

/// Whether `url`'s host equals the request `host` (both with ports ignored).
fn url_is_same_host(url: &str, host: &str) -> bool {
    let url_host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    strip_port(url_host) == strip_port(host)
}

/// The xite a referer URL points at: the nested path segment if it is itself a
/// xite (`/epix1…/` or `/name.epix/`), else - in transparent-proxy mode - the
/// `.epix` host itself, else the first path segment.
fn referer_site(_ctx: &Ctx, referer: &str, _host: &str) -> Option<String> {
    let after_scheme = referer
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let (ref_host, ref_path) = after_scheme.split_once('/').unwrap_or((after_scheme, ""));
    let ref_host = strip_port(ref_host);
    // A xite can be served nested under another xite's proxy host: clicking a
    // site in the dashboard lands the iframe on `dashboard.epix/epix1talk…/`,
    // so that page's OWN resources carry a referer like
    // `dashboard.epix/epix1talk…/index.html`. The nested path segment is the
    // real source xite (a page loading its own files is same-origin), so it
    // wins over the host - mirroring the target routing in `rewrite_proxy_host`.
    // Without this the cross-origin gate reads the source as the host and
    // 403s the nested xite's stylesheet, scripts, and images.
    let first_seg = ref_path.split('/').next().unwrap_or("");
    if plausible_xite_ref(first_seg) {
        return Some(first_seg.to_string());
    }
    if ref_host.ends_with(".epix") {
        return Some(ref_host.to_string());
    }
    ref_path.split('/').next().filter(|s| !s.is_empty()).map(str::to_string)
}

/// Global routes that are served the same regardless of Host (the UI chrome and
/// the wrapper runtime), so a `*.epix` proxy request to one of these is NOT
/// rewritten into a per-xite path.
fn is_global_path(path: &str) -> bool {
    path.starts_with("/uimedia/")
        || path.starts_with("/EpixNet-Internal/")
        || path == "/Config"
        || path == "/Plugins"
        || path == "/Stats"
        || path == "/StatsJson"
        || path == "/Config/"
        || path == "/Plugins/"
        || path == "/Stats/"
        || path.starts_with("/list/")
        || path == "/Benchmark"
        || path == "/Login"
        || path == "/Logout"
        || path == "/favicon.ico"
}

/// True if `host` (no port) is a transparent-proxy xite host - a `.epix` name
/// Firefox routed to us - rather than the loopback UI bind.
fn is_proxy_host(host: &str) -> bool {
    host.ends_with(".epix") && !host.is_empty()
}

/// True if a path segment plausibly references a xite we could fetch on
/// demand: a `.epix` name (xID) or a bech32 `epix1…` address.
fn plausible_xite_ref(s: &str) -> bool {
    s.ends_with(".epix") || (s.starts_with("epix1") && s.len() > 20)
}

/// Rewrite a transparent-proxy request into the path form the router uses.
/// `Host: dashboard.epix` + `GET /index.html` (or absolute-form
/// `GET http://dashboard.epix/index.html`) becomes `GET /dashboard.epix/index.html`,
/// so the existing `/:address/*path` handlers serve it. The Host header is left
/// intact so [`serve_wrapper`] can tell it is host mode and emit host-relative
/// URLs. Non-`.epix` hosts and the global routes pass through unchanged.
///
/// Public so the desktop browser proxy (which serves the same router over TLS)
/// can apply the identical rewrite.
pub fn rewrite_proxy_host(mut req: axum::extract::Request) -> axum::extract::Request {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    if !is_proxy_host(&host) {
        return req;
    }
    let path = req.uri().path();
    if is_global_path(path) {
        return req;
    }
    // A path that already targets a xite (`/epix1…/` or `/name.epix/`, as the
    // dashboard's site links do) routes as-is instead of being nested under
    // this host's path.
    let first_seg = path.trim_start_matches('/').split('/').next().unwrap_or("");
    if (first_seg.starts_with("epix1") && first_seg.len() > 20) || first_seg.ends_with(".epix") {
        return req;
    }
    let query = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let new_paq = format!("/{host}{path}{query}");
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    if let Ok(paq) = new_paq.parse() {
        parts.path_and_query = Some(paq);
        if let Ok(uri) = axum::http::Uri::from_parts(parts) {
            *req.uri_mut() = uri;
        }
    }
    req
}

/// The built-in plugins/features this node ships, for the Plugins page and
/// `serverInfo.plugins`. The always-on ones are listed unconditionally; the
/// feature-gated ones appear only when compiled in.
pub fn builtin_plugins() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut plugins = vec![
        "Cors",
        "PeerDb",
        "Notification",
        "FilePack",
        "UiFileManager",
        "AnnounceLocal",
        "AnnounceShare",
        "AnnounceBitTorrent",
        "NoNewSites",
        "ContentFilter",
        "MergerSite",
        "OptionalManager",
        "Newsfeed",
        "CryptMessage",
        "Chart",
        "Bigfile",
        "Stats",
        "UiConfig",
        "UiPluginManager",
    ];
    #[cfg(feature = "ui-password")]
    plugins.push("UiPassword");
    #[cfg(feature = "multiuser")]
    plugins.push("Multiuser");
    #[cfg(feature = "benchmark")]
    plugins.push("Benchmark");
    plugins
}

async fn health() -> &'static str {
    "Epix UI server"
}

/// `GET /EpixNet-Internal/Status` - a small JSON status the browser's native
/// host polls to drive the wallet's Epix panel: whether the node is serving,
/// the Tor state (`tor_enabled`/`tor_status`) + our onion address, and the I2P
/// state (`i2p_enabled`/`i2p_status`) + our `.b32.i2p` address if published.
async fn serve_status(State(ctx): State<Ctx>) -> Response {
    let (tor_enabled, tor_status) = ctx.state.tor_status().await;
    let onion = ctx.state.onion_address().await;
    // I2P: the runtime keeps a status object (mode, phase, b32, tunnels, ...);
    // surface a concise view. `i2p_status` is the phase label ("Off",
    // "Starting…", "Ready", "Failed: …"), `i2p_mode` is
    // disable/embedded/external, and `i2p_enabled` is true once the router has
    // published our address (fully ready).
    let i2p = ctx.state.i2p_status().await;
    let i2p_phase = i2p.get("phase").and_then(|v| v.as_str()).unwrap_or("Off").to_string();
    let i2p_mode = i2p.get("mode").and_then(|v| v.as_str()).unwrap_or("disable").to_string();
    let i2p_address = ctx.state.i2p_address().await;
    let mesh_address = ctx.state.rns_address().await;
    let body = json!({
        "serving": true,
        "tor_enabled": tor_enabled,
        "tor_status": tor_status,
        "onion_address": onion,
        "i2p_enabled": i2p_address.is_some(),
        "i2p_status": i2p_phase,
        "i2p_mode": i2p_mode,
        "i2p_address": i2p_address,
        "mesh_enabled": mesh_address.is_some(),
        "mesh_address": mesh_address,
    });
    (
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "null".to_string()),
        ],
        body.to_string(),
    )
        .into_response()
}

/// `/{address}` → `/{address}/` (so a xite URL works without the trailing slash).
async fn redirect_to_slash(
    Path(address): Path<String>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Redirect {
    match query.as_deref().filter(|q| !q.is_empty()) {
        Some(q) => Redirect::permanent(&format!("/{address}/?{q}")),
        None => Redirect::permanent(&format!("/{address}/")),
    }
}

/// Serve `/uimedia/*` from the embedded wrapper runtime, with plugin
/// contributions: `all.js`/`all.css` get each plugin's client code appended,
/// and plugins can add extra files (e.g. the sidebar's `globe/*`).
async fn serve_uimedia(State(ctx): State<Ctx>, Path(path): Path<String>) -> Response {
    let ct = content_type(&path);
    // Base bundle + each *enabled* plugin's appended JS/CSS (assembled per
    // request, so enabling/disabling a plugin takes effect on the next reload).
    if path == "all.js" || path == "all.css" {
        if let Some(file) = UIMEDIA.get_file(&path) {
            let mut body = file.contents().to_vec();
            for pm in &ctx.media.plugins {
                if !pm.name.is_empty() && !ctx.state.plugin_enabled(&pm.name).await {
                    continue;
                }
                let append = if path == "all.js" { &pm.append_js } else { &pm.append_css };
                if !append.is_empty() {
                    body.push(b'\n');
                    body.extend_from_slice(append);
                }
            }
            return ([(header::CONTENT_TYPE, ct)], body).into_response();
        }
    }
    // Plugin-provided static files (e.g. globe assets) - only for enabled plugins.
    for pm in &ctx.media.plugins {
        if let Some(bytes) = pm.files.get(&path) {
            if pm.name.is_empty() || ctx.state.plugin_enabled(&pm.name).await {
                return ([(header::CONTENT_TYPE, ct)], bytes.clone()).into_response();
            }
        }
    }
    match UIMEDIA.get_file(&path) {
        Some(file) => ([(header::CONTENT_TYPE, ct)], file.contents().to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Serve the Epix Wallet web app from `<data_root>/wallet-ui`, where the
/// mobile shells stage their bundled wallet build (their WebViews cannot run
/// the WebExtension the desktop browser embeds, so the wallet runs as a
/// plain web app served from this loopback origin - see the wallet repo's
/// mobile.html). 404s when nothing is staged.
async fn serve_wallet(State(ctx): State<Ctx>, Path(path): Path<String>) -> Response {
    let Some(root) = ctx.state.wallet_ui_dir() else {
        return (StatusCode::NOT_FOUND, "no wallet staged").into_response();
    };
    // Plain relative components only - no traversal out of the staging dir.
    if path.split('/').any(|c| c.is_empty() || c == "." || c == "..") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    match tokio::fs::read(root.join(&path)).await {
        Ok(body) => ([(header::CONTENT_TYPE, content_type(&path))], body).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Serve the wrapper page for a xite (`GET /{address}/`).
/// The page shown in place of a blocked site (ContentFilter).
fn blocklisted_html(address: &str, reason: &str) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let reason_html = if reason.is_empty() {
        String::new()
    } else {
        format!("<p>Reason: {}</p>", esc(reason))
    };
    format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>Site blocked</title>\
         <meta name='viewport' content='width=device-width, initial-scale=1'></head>\
         <body style='font-family:Inter,-apple-system,Segoe UI,Roboto,sans-serif;background:#09090A;color:#F6F6F9;text-align:center;margin:0;padding:15vh 24px 0'>\
         <h1 style='font-size:24px;font-weight:600'>This site is blocked</h1>\
         <p style='color:#ABABB5;overflow-wrap:anywhere'>{}</p>{}</body></html>",
        esc(address),
        reason_html,
    )
}

async fn serve_wrapper(
    State(ctx): State<Ctx>,
    Path(requested): Path<String>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    headers: axum::http::HeaderMap,
) -> Response {
    render_wrapper(ctx, requested, "index.html".to_string(), raw_query, headers).await
}

/// The inner file a wrapper request points its iframe at, for a `/:address/path`
/// URL. A top-level navigation to a directory renders the wrapper with the
/// iframe pointed at that directory's `index.html` (this is how multi-page
/// xites like Git Epix navigate: `index/`, `myrepos/`). A request for a
/// specific file (js, css, image, or even a bare `.html`) is a raw resource
/// load and returns `None` - the iframe fetches those directly (with the
/// wrapper nonce), and a direct address of a file is served raw as before.
fn wrapper_inner_path(path: &str) -> Option<String> {
    if path.is_empty() {
        Some("index.html".to_string())
    } else if path.ends_with('/') {
        Some(format!("{path}index.html"))
    } else {
        None
    }
}

async fn render_wrapper(
    ctx: Ctx,
    requested: String,
    inner_path: String,
    raw_query: Option<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    // The Host without port; in transparent-proxy mode it equals the xite name.
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();
    let proxy_mode = host == requested;

    // The path segment may be a `.epix` name (xID) or the bech32 address; the
    // node's identity for a xite is ALWAYS the bech32 address, so translate
    // once here and key everything below (state lookups, wrapper identity,
    // the WS session) by the address.
    let mut address = ctx.state.canonical_key(&requested).await;
    let mut loading = false;
    let ready = |state: &Arc<AppState>, addr: String| {
        let state = state.clone();
        async move {
            state.has_xite(&addr).await
                && state.content(&addr).await.is_some()
                && state.xite_file_exists(&addr, "index.html").await
                // index.html alone isn't ready: it downloads first, and the
                // core set (styles, scripts, chunks) may still be coming. Show
                // the loading screen; the iframe's document request waits on
                // the same condition, so the two dismiss together.
                && !state.html_doc_gated(&addr).await
        }
    };
    if !ready(&ctx.state, address.clone()).await {
        // On-demand: resolve + clone in the background and serve the wrapper
        // with the loading screen immediately (EpixNet's flow: the wrapper's
        // inner file request blocks per file until it lands). The entry
        // registers (empty) as soon as the clone starts, so "loading" means
        // not-ready, not not-registered. Works for `.epix` names and raw
        // addresses, in path and proxy mode alike.
        if !plausible_xite_ref(&requested) || !ctx.state.has_on_demand().await {
            return (StatusCode::NOT_FOUND, "unknown xite").into_response();
        }
        // NoNewSites: a locked node serves what it has; browsing to a xite it
        // doesn't serve won't clone it.
        if !ctx.state.has_xite(&address).await && ctx.state.no_new_sites().await {
            return (StatusCode::FORBIDDEN, "Adding new sites is disabled on this node")
                .into_response();
        }
        let ensure = {
            let state = ctx.state.clone();
            let target = requested.clone();
            tokio::spawn(async move {
                state.ensure_xite(&target).await;
            })
        };
        // A name resolves quickly (cache or one chain query) while the clone
        // continues in the background; wait briefly so the wrapper can embed
        // the bech32 identity (the WS session + events key off it). If the
        // background ensure already finished without a resolution, the name
        // doesn't exist - fail fast instead of waiting out the window.
        if !requested.starts_with("epix1") {
            for _ in 0..60 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let key = ctx.state.canonical_key(&requested).await;
                if key != requested {
                    address = key;
                    break;
                }
                if ensure.is_finished() {
                    break;
                }
            }
            if address == requested {
                return (StatusCode::NOT_FOUND, format!("could not resolve {requested}"))
                    .into_response();
            }
        }
        loading = !ready(&ctx.state, address.clone()).await;
    }
    // Trust this Host as a WebSocket origin (the wrapper's own page will open
    // the WS from it).
    if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        ctx.state.allow_ws_origin(host);
    }
    // ContentFilter: a blocked site is not served - show the block page instead.
    if let Some(reason) = ctx.state.siteblock_reason(&address).await {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            blocklisted_html(&address, &reason),
        )
            .into_response();
    }
    let content = ctx.state.content(&address).await;
    let title = content
        .as_ref()
        .and_then(|c| c.get("title"))
        .and_then(|t| t.as_str())
        .unwrap_or(&requested)
        .to_string();
    // A xite's content.json can opt into strict postMessage nonce checks
    // (EpixNet honors this flag; the wrapper then requires the wrapper_nonce
    // on every inner message instead of running the opener test).
    let nonce_security = content
        .as_ref()
        .and_then(|c| c.get("postmessage_nonce_security"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // A one-time wrapper nonce (released on the inner file request) and a random
    // CSP script nonce for the wrapper's own inline scripts.
    let nonce = ctx.state.issue_wrapper_nonce();
    let script_nonce = ctx.state.issue_wrapper_nonce();
    // Forward the request's query string into the iframe src so client-routed
    // xites keep working: EpixTalk links use `<base target="_top">`, the top
    // window lands on `/{address}/?Topic:...`, and the inner page reads the
    // query on boot to route. Without this the inner page always reloads at
    // its default view.
    let query_string = match raw_query.as_deref().filter(|q| !q.is_empty()) {
        Some(q) => format!("?{}&wrapper_nonce={nonce}", escape_query(q)),
        None => format!("?wrapper_nonce={nonce}"),
    };
    // The xite's real permissions (empty until the user grants one). This is
    // only the wrapper's initial value; the authoritative list arrives over the
    // WebSocket via siteInfo.
    let permissions = ctx.state.site_permissions(&address).await;

    // The corner home button returns to the node's homepage (the launch xite,
    // e.g. dashboard.epix), not the xite being viewed. In transparent-proxy
    // (host) mode a named homepage links as a host (`//dashboard.epix`) so the
    // browser lands on its clean origin; an address links by path, which the
    // proxy rewrite routes as-is. File URLs stay relative to the current xite.
    let node_home = ctx.state.homepage().await.unwrap_or_else(|| requested.clone());
    let (homepage, file_url) = if proxy_mode {
        let home = if node_home.contains('.') {
            format!("//{node_home}")
        } else {
            format!("/{node_home}")
        };
        (home, format!("/{inner_path}"))
    } else {
        (format!("/{node_home}"), format!("/{requested}/{inner_path}"))
    };

    // wrapper_key == the bech32 address for this single-user local node, so
    // the WS session and every command bind to the address, never the name.
    let themeclass = ctx.state.theme_class().await;
    let lang = ctx.state.ui_language().await;
    // Wrapper page hints from the root content.json (UiRequest parity):
    // `background-color` (with a per-theme variant) styles the page behind
    // the iframe, `viewport` and `favicon` become head tags.
    let (meta_tags, body_style) = {
        let mut meta = String::new();
        let mut style = String::new();
        if let Some(content) = ctx.state.content(&address).await {
            let theme = themeclass.trim_start_matches("theme-");
            let themed_key = format!("background-color-{theme}");
            let background = content
                .get(&themed_key)
                .or_else(|| content.get("background-color"))
                .and_then(|v| v.as_str());
            if let Some(color) = background {
                style.push_str(&format!("background-color: {};", html_escape(color)));
            }
            if let Some(viewport) = content.get("viewport").and_then(|v| v.as_str()) {
                meta.push_str(&format!(
                    "<meta name=\"viewport\" id=\"viewport\" content=\"{}\">",
                    html_escape(viewport)
                ));
            }
            if let Some(favicon) = content.get("favicon").and_then(|v| v.as_str()) {
                let root = if proxy_mode { "/".to_string() } else { format!("/{requested}/") };
                meta.push_str(&format!(
                    "<link rel=\"icon\" href=\"{root}{}\">",
                    html_escape(favicon)
                ));
            }
        }
        (meta, style)
    };
    let vars: Vec<(&str, String)> = vec![
        ("title", title),
        ("rev", "1".into()),
        ("meta_tags", meta_tags),
        ("body_style", body_style),
        ("themeclass", themeclass),
        ("script_nonce", script_nonce.clone()),
        ("homepage", homepage),
        ("site_file_server", String::new()),
        ("file_url", file_url),
        ("file_inner_path", inner_path.clone()),
        ("query_string", query_string),
        ("address", address.clone()),
        ("wrapper_nonce", nonce),
        ("wrapper_key", address.clone()),
        ("ajax_key", address.clone()),
        ("postmessage_nonce_security", nonce_security.to_string()),
        ("permissions", json!(permissions).to_string()),
        ("show_loadingscreen", if loading { "true" } else { "false" }.into()),
        ("sandbox_permissions", String::new()),
        ("server_url", String::new()),
        ("lang", lang),
    ];
    let mut html = render(WRAPPER_HTML, &vars);
    // NoNewSites gateway: every page carries the read-only banner.
    if ctx.state.no_new_sites().await {
        html = inject_gateway_banner(html);
    }
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_SECURITY_POLICY, wrapper_csp(&script_nonce)),
            (header::REFERRER_POLICY, "same-origin".to_string()),
            (header::CACHE_CONTROL, "no-cache, no-store, private, must-revalidate, max-age=0".to_string()),
        ],
        html,
    )
        .into_response()
}

#[derive(Deserialize)]
struct PluginsQuery {
    toggle: Option<String>,
}

/// `GET /Plugins` - the plugin manager page. `?toggle=<name>` flips a plugin's
/// enabled state (persisted) and redirects back; the change takes effect on the
/// next page load, no restart.
async fn serve_plugins_page(State(ctx): State<Ctx>, Query(q): Query<PluginsQuery>) -> Response {
    if let Some(name) = q.toggle {
        let enabled = ctx.state.plugin_enabled(&name).await;
        ctx.state.set_plugin_enabled(&name, !enabled).await;
        return Redirect::to("/Plugins").into_response();
    }
    let states = ctx.state.plugin_states().await;
    let homepage = ctx.state.homepage().await.unwrap_or_default();
    let theme = ctx.state.theme_class().await;
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_plugins_page(&states, &homepage, &theme))
        .into_response()
}

/// A short description for a known built-in plugin/feature.
fn plugin_description(name: &str) -> &'static str {
    match name {
        "Sidebar" => "Slide-out site info panel with peers, transfer stats, and the world globe.",
        "Stats" => "Network stats charts and the peer world map on the dashboard.",
        "UiPluginManager" => "This plugin manager page.",
        "UiConfig" => "The node configuration page.",
        "Cors" => "Cross-site file access via a Cors:<address> permission grant.",
        "PeerDb" => "Remembers known peers across restarts.",
        "Notification" => "Per-site notification subscriptions, muting, and counts.",
        "FilePack" => "Serves files from inside .tar.gz / .zip archives.",
        "UiFileManager" => "Browse a xite's files from the dashboard.",
        "AnnounceLocal" => "Finds peers on the local network over UDP broadcast.",
        "AnnounceShare" => "Remembers working trackers and reuses them across restarts.",
        "Beacon" => "Announcer discovery: learns working announcers from peers, shares yours back, and keeps the set healthy. Can also follow a list published on a xite (trackers_xite).",
        "AnnounceBitTorrent" => "Announces to HTTP(S) and UDP BitTorrent trackers.",
        "NoNewSites" => "Locks the node's site set: blocks adding and deleting sites.",
        "ContentFilter" => "Mute authors and block sites (enforced on serve + db).",
        "MergerSite" => "Aggregates merged sites into one database.",
        "OptionalManager" => "Manages optional (on-demand) files and the size limit.",
        "Newsfeed" => "Cross-site news feed from followed sites.",
        "CryptMessage" => "ECIES encrypt/decrypt, AES, and ECDSA sign/verify for zites.",
        "Chart" => "Collects the time-series data behind the Stats charts.",
        "Bigfile" => "Piecewise download of large files with piecefield exchange.",
        "UiPassword" => "Password-protects the whole UI with a login gate.",
        "Multiuser" => "Multiple master-seed identities with login/switch.",
        "Benchmark" => "A /Benchmark page timing the node's crypto/hash/pack hot paths.",
        _ => "Built-in plugin.",
    }
}

/// Render the plugin manager page (sliding toggle switches, one row per
/// plugin). The toggle is a link (`/Plugins?toggle=…`) so it works without
/// JS/WebSocket.
fn render_plugins_page(states: &[(String, bool, bool)], homepage: &str, theme: &str) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut rows = String::new();
    for (name, enabled, default_enabled) in states {
        let checked = if *enabled { "checked" } else { "" };
        let default_txt = if *default_enabled { "enabled" } else { "disabled" };
        rows.push_str(&format!(
            "<div class='plugin'>\
               <div class='title'><h3>{name}</h3>\
                 <div class='description'>{descr} <span class='default'>(default: {default_txt})</span></div></div>\
               <a class='value value-right checkbox {checked}' href='/Plugins?toggle={name}' \
                  title='{action} {name}'><div class='checkbox-skin'></div></a>\
             </div>",
            name = esc(name),
            descr = esc(plugin_description(name)),
            action = if *enabled { "Disable" } else { "Enable" },
        ));
    }
    if rows.is_empty() {
        rows.push_str("<div class='description'>No plugins loaded.</div>");
    }
    page_shell("Plugins", "Plugins", "", &format!("<div class='plugins'>{rows}</div>"), homepage, theme)
}

/// `GET /Config` - the node settings page. `?save=1&<key>=<value>` persists the
/// changed keys (via configSet) and redirects back.
async fn serve_config_page(
    State(ctx): State<Ctx>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    // Action buttons (e.g. Clear xID Cache) come back as `?action=<name>`.
    if let Some(action) = params.get("action") {
        if action == "xidClearCache" {
            // The resolver cache is per-request at the chain layer, so there's
            // nothing persistent to drop; the call succeeds like EpixNet's.
            return Redirect::to("/Config?cleared=1").into_response();
        }
        return Redirect::to("/Config").into_response();
    }
    if params.contains_key("save") {
        // data_dir is special: it persists to epixnet.conf and copies the data
        // to the new location, so its outcome is reported back on the page.
        let mut flash: Option<(bool, String)> = None;
        if let Some(dir) = params.get("data_dir") {
            if dir.trim() != ctx.state.data_dir_value() {
                flash = Some(match ctx.state.set_data_dir(dir).await {
                    Ok(msg) => (true, msg),
                    Err(e) => (false, e),
                });
            }
        }
        for (_section, key, _label, _default, kind) in crate::state::CONFIG_SCHEMA {
            // Disabled ("coming soon") controls and action buttons aren't saved.
            if *key == "data_dir" || kind.starts_with("soon:") || crate::state::is_config_action(kind) {
                continue;
            }
            if *kind == "bool" {
                // An unchecked checkbox isn't submitted, so absence means false.
                let on = params.get(*key).map(|v| v == "on" || v == "true").unwrap_or(false);
                ctx.state.config_set(key, Value::from(if on { "true" } else { "false" })).await;
            } else if let Some(val) = params.get(*key) {
                ctx.state.config_set(key, Value::from(val.as_str())).await;
            }
        }
        let to = match &flash {
            Some((ok, msg)) => {
                format!("/Config?{}={}", if *ok { "done" } else { "error" }, url_encode(msg))
            }
            None => "/Config".to_string(),
        };
        return Redirect::to(&to).into_response();
    }
    let mut values = Vec::new();
    for (section, key, label, default, kind) in crate::state::CONFIG_SCHEMA {
        // data_dir isn't in config.json: its value is the live data root and
        // its default the per-OS conventional location.
        let (val, default) = if *key == "data_dir" {
            (ctx.state.data_dir_value(), ctx.state.data_dir_default())
        } else {
            let val = ctx
                .state
                .config_get(key)
                .await
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| default.to_string());
            (val, default.to_string())
        };
        values.push((*section, *key, *label, val, default, *kind));
    }
    let flash = if params.contains_key("cleared") {
        Some((true, "xID cache cleared.".to_string()))
    } else if let Some(msg) = params.get("done") {
        Some((true, msg.clone()))
    } else {
        params.get("error").map(|msg| (false, msg.clone()))
    };
    let homepage = ctx.state.homepage().await.unwrap_or_default();
    let theme = ctx.state.theme_class().await;
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_config_page(&values, flash, &homepage, &theme))
        .into_response()
}

/// Percent-encode a string for use as a query-parameter value.
fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `GET /StatsJson` - the lightweight public stats endpoint the NoNewSites
/// gateway exposes for a marketing page (CORS left to the reverse proxy, as
/// in the original, so headers are not doubled).
async fn serve_stats_json(State(ctx): State<Ctx>) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], ctx.state.stats_json().await.to_string())
        .into_response()
}

/// The public-gateway banner the NoNewSites plugin injects into every wrapper
/// page (ported from the original): a fixed top bar telling visitors this is
/// a read-only gateway, with the iframe shifted down to make room.
const GATEWAY_BANNER_HTML: &str = "<style>#epix-gateway-banner {    position: fixed; top: 0; left: 0; right: 0; z-index: 1;    height: 38px;    background: #151517; color: #DCDCE3;    font: 13px/1.45 Inter, -apple-system, 'Segoe UI', Roboto, sans-serif;    display: flex; align-items: center; justify-content: center;    text-align: center; padding: 0 16px;    box-sizing: border-box; white-space: nowrap; overflow: hidden;}#epix-gateway-banner .banner-inner { display: inline-block; max-width: 1200px; }#epix-gateway-banner strong { color: #FEFEFE; font-weight: 600; }#epix-gateway-banner a {    color: #09090A; background: #2DCE89; text-decoration: none;    padding: 5px 12px; border-radius: 4px; margin-left: 10px;    font-weight: 600; display: inline-block;}#epix-gateway-banner a:hover { text-decoration: underline; }#inner-iframe { top: 38px !important; height: calc(100% - 38px) !important; }@media (max-width: 900px) {#epix-gateway-banner { height: 76px; padding: 8px 12px; white-space: normal; }#inner-iframe { top: 76px !important; height: calc(100% - 76px) !important; }}@media (max-width: 640px) {#epix-gateway-banner { height: 112px; font-size: 12px; }#epix-gateway-banner a { padding: 0 16px; display: inline-flex; align-items: center; justify-content: center; min-height: 44px; }#inner-iframe { top: 112px !important; height: calc(100% - 112px) !important; }}</style><div id='epix-gateway-banner'><span class='banner-inner'>    <strong>Public gateway - read-only.</strong>    Install EpixNet to use your own identity, browse the full network, and host sites.    <a href='https://epixnet.io/#download' target='_blank' rel='noopener'>Get EpixNet</a></span></div>";

/// Inject the gateway banner just before the wrapper's closing body tag.
fn inject_gateway_banner(html: String) -> String {
    match html.rfind("</body>") {
        Some(i) => {
            let mut out = html;
            out.insert_str(i, GATEWAY_BANNER_HTML);
            out
        }
        None => html,
    }
}

/// `GET /Stats` - the diagnostics page (EpixNet's `/Stats`): node identity,
/// live connections, tracker stats, Tor state, and a per-site table.
async fn serve_stats_page(State(ctx): State<Ctx>) -> Response {
    // Each table gets an overflow-x scroll container so wide rows (peer
    // addresses) scroll inside the content card instead of the page.
    let body = ctx
        .state
        .stats_html()
        .await
        .replace("<table>", "<div class='overflow'><table>")
        .replace("</table>", "</table></div>");
    let homepage = ctx.state.homepage().await.unwrap_or_default();
    let theme = ctx.state.theme_class().await;
    let styled = format!(
        "<style>\
         .stats-wrap{{font-family:var(--epix-font-mono);font-size:12.5px}}\
         .stats-wrap h2{{margin:24px 0 8px;font-size:14px;font-family:var(--epix-font-sans)}}\
         .stats-wrap table{{border-collapse:collapse;width:100%;max-width:100%;margin-bottom:6px}}\
         .stats-wrap th,.stats-wrap td{{text-align:left;padding:4px 12px 4px 0;border-bottom:1px solid var(--epix-border);white-space:nowrap}}\
         .stats-wrap th{{color:var(--epix-text-mid);font-weight:600}}\
         .stats-wrap tr.muted td,.stats-wrap .muted{{color:var(--epix-text-low)}}\
         .stats-wrap .stat-head{{padding:8px 0;color:var(--epix-text-mid);border-bottom:1px solid var(--epix-border);overflow-wrap:anywhere}}\
         .stats-wrap .stat-row{{padding:2px 0;overflow-wrap:anywhere}}\
         .stats-wrap .overflow{{overflow-x:auto;max-width:100%}}\
         </style>\
         <div class='stats-wrap'>{body}</div>"
    );
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], page_shell("Stats", "Stats", "Node diagnostics", &styled, &homepage, &theme))
        .into_response()
}

/// Render the settings page, styled like EpixNet's Config page: settings are
/// grouped into sections (Web Interface / Network / Performance / Epix Chain
/// Config) with a widget per config kind. Keys whose backend isn't built yet
/// (Tor, tracker proxy) render disabled with a "coming soon" note.
fn render_config_page(
    values: &[(&str, &str, &str, String, String, &str)],
    flash: Option<(bool, String)>,
    homepage: &str,
    theme: &str,
) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    };
    // Render a `select` from a `Label=value|...` option spec; `disabled` greys it out.
    let render_select = |key: &str, spec: &str, val: &str, disabled: bool| -> String {
        let options: String = spec
            .split('|')
            .map(|o| {
                let (label, value) = o.split_once('=').unwrap_or((o, o));
                let sel = if value == val { "selected" } else { "" };
                format!("<option value='{v}' {sel}>{l}</option>", v = esc(value), l = esc(label))
            })
            .collect();
        let dis = if disabled { "disabled" } else { "" };
        format!("<select class='input-text' name='{key}' {dis}>{options}</select>", key = esc(key))
    };

    let mut sections = String::new();
    let mut current_section = "";
    for (section, key, label, val, default, kind) in values {
        if *section != current_section {
            if !current_section.is_empty() {
                sections.push_str("</div>");
            }
            sections.push_str(&format!(
                "<h2 class='section-title'>{}</h2><div class='config'>",
                esc(section)
            ));
            current_section = section;
        }

        // A "soon:" prefix means the control is shown but disabled.
        let (kind, coming_soon) = match kind.strip_prefix("soon:") {
            Some(inner) => (inner, true),
            None => (*kind, false),
        };

        let widget = if kind == "bool" {
            let checked = if matches!(val.as_str(), "true" | "on" | "1") { "checked" } else { "" };
            let dis = if coming_soon { "disabled" } else { "" };
            format!(
                "<label class='checkbox'><input type='checkbox' name='{key}' {checked} {dis}/>\
                 <div class='checkbox-skin'></div></label>",
                key = esc(key),
            )
        } else if let Some(opts) = kind.strip_prefix("select:") {
            render_select(key, opts, val, coming_soon)
        } else if let Some(action) = kind.strip_prefix("button:") {
            // A standalone action link, not a stored value.
            format!(
                "<a class='button' href='/Config?action={action}'>{label}</a>",
                action = esc(action),
                label = esc(label),
            )
        } else if kind == "textarea" {
            format!(
                "<textarea class='input-text' name='{key}' rows='2' spellcheck='false'>{val}</textarea>",
                key = esc(key),
                val = esc(val),
            )
        } else {
            format!(
                "<input class='input-text' name='{key}' value='{val}' spellcheck='false'>",
                key = esc(key),
                val = esc(val),
            )
        };

        // Buttons carry their label inside the widget; other rows show it up top
        // with the default value, plus a "coming soon" note when disabled.
        if kind.starts_with("button:") {
            sections.push_str(&format!(
                "<div class='config-item'>\
                   <div class='title'><h3>{label}</h3></div>\
                   <div class='value value-right'>{widget}</div>\
                 </div>",
                label = esc(label),
            ));
        } else {
            let note = if coming_soon {
                "<span class='default'> - coming soon (not yet supported)</span>"
            } else {
                ""
            };
            sections.push_str(&format!(
                "<div class='config-item'>\
                   <div class='title'><h3>{label}</h3>\
                     <div class='description'><span class='default'>(default: {default})</span>{note}</div></div>\
                   <div class='value value-right'>{widget}</div>\
                 </div>",
                label = esc(label),
                default = esc(default),
            ));
        }
    }
    if !current_section.is_empty() {
        sections.push_str("</div>");
    }

    let flash = match &flash {
        Some((ok, msg)) => format!(
            "<div class='notification notification-{kind}'>{msg}</div>",
            kind = if *ok { "done" } else { "error" },
            msg = esc(msg),
        ),
        None => String::new(),
    };
    let body = format!(
        "{flash}<form method='get' action='/Config'>\
           {sections}\
           <input type='hidden' name='save' value='1'>\
           <button class='button button-submit' type='submit'>Save</button>\
         </form>"
    );
    page_shell("Configuration", "Configuration", "", &body, homepage, theme)
}

/// `GET /list/<address>/<inner_path>` - the UiFileManager file browser. Lists a
/// directory inside a xite with links to navigate and open files.
async fn serve_file_manager(State(ctx): State<Ctx>, Path(path): Path<String>) -> Response {
    if !ctx.state.plugin_enabled("UiFileManager").await {
        return (StatusCode::NOT_FOUND, "UiFileManager plugin is disabled").into_response();
    }
    let (address, inner) = match path.split_once('/') {
        Some((a, i)) => (a.to_string(), i.trim_end_matches('/').to_string()),
        None => (path.clone(), String::new()),
    };
    // A `.epix` name in the URL resolves to the bech32 serving key.
    let address = ctx.state.canonical_key(&address).await;
    let Some(entries) = ctx.state.list_dir(&address, &inner).await else {
        return (StatusCode::NOT_FOUND, "unknown xite or path").into_response();
    };
    let theme = ctx.state.theme_class().await;
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_file_manager(&address, &inner, &entries, &theme))
        .into_response()
}

/// Render the file browser for a xite directory.
fn render_file_manager(address: &str, inner: &str, entries: &[Value], theme: &str) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    };
    let human = |n: u64| {
        if n >= 1 << 20 {
            format!("{:.1} MB", n as f64 / (1 << 20) as f64)
        } else if n >= 1 << 10 {
            format!("{:.1} kB", n as f64 / (1 << 10) as f64)
        } else {
            format!("{n} B")
        }
    };
    let mut rows = String::new();
    // Parent link.
    if !inner.is_empty() {
        let parent = inner.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        rows.push_str(&format!(
            "<div class='row'><a class='name dir' href='/list/{address}/{parent}'>../</a></div>",
            address = esc(address),
            parent = esc(parent),
        ));
    }
    for e in entries {
        let name = e["name"].as_str().unwrap_or("");
        let is_dir = e["is_dir"].as_bool().unwrap_or(false);
        let child = if inner.is_empty() { name.to_string() } else { format!("{inner}/{name}") };
        if is_dir {
            rows.push_str(&format!(
                "<div class='row'><a class='name dir' href='/list/{address}/{child}'>{name}/</a></div>",
                address = esc(address),
                child = esc(&child),
                name = esc(name),
            ));
        } else {
            let size = human(e["size"].as_u64().unwrap_or(0));
            rows.push_str(&format!(
                "<div class='row'><a class='name' href='/{address}/{child}'>{name}</a>\
                 <span class='size'>{size}</span></div>",
                address = esc(address),
                child = esc(&child),
                name = esc(name),
            ));
        }
    }
    // Breadcrumb heading: the address and every parent directory link back to
    // their own /list page; the current (last) segment stays plain text.
    let heading = if inner.is_empty() {
        format!("Files: {}", esc(address))
    } else {
        let mut heading =
            format!("Files: <a href='/list/{a}'>{a}</a>", a = esc(address));
        let segs: Vec<&str> = inner.split('/').filter(|s| !s.is_empty()).collect();
        let mut prefix = String::new();
        for (i, seg) in segs.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(seg);
            if i + 1 == segs.len() {
                heading.push_str(&format!("/{}", esc(seg)));
            } else {
                heading.push_str(&format!(
                    "/<a href='/list/{}/{}'>{}</a>",
                    esc(address),
                    esc(&prefix),
                    esc(seg),
                ));
            }
        }
        heading
    };
    let body = format!(
        "<style>.row{{padding:10px 0;border-bottom:1px solid var(--epix-border);overflow:hidden}}\
          .name{{font-size:15px;overflow-wrap:anywhere}} .name.dir{{font-weight:600}}\
          .size{{float:right;color:var(--epix-text-low);font-size:13px;margin-left:12px}}</style>\
         <div class='files'>{rows}</div>"
    );
    // From the file browser, the fixbutton returns to the xite being browsed.
    page_shell("Files", &heading, "", &body, address, theme)
}

/// Design tokens + shared styles for the server-rendered admin pages, adapted
/// from the Epix UI kit (assets/ui-kit/epix-tokens.css, trimmed to what these
/// pages use). Light values live on :root/.theme-light; dark values apply
/// through prefers-color-scheme (guarded so body.theme-light still wins) and
/// through the explicit .theme-dark class the server renders on <body> from
/// the user's stored theme (see AppState::theme_class).
const PAGE_CSS: &str = "\
:root,.theme-light{color-scheme:light;\
--epix-purple:#8A4BDB;--epix-cyan:#69E9F5;\
--epix-neutral-0:#FEFEFE;--epix-neutral-1:#F6F6F9;--epix-neutral-2:#F2F2F6;--epix-neutral-3:#DCDCE3;--epix-neutral-4:#ABABB5;--epix-neutral-5:#72747B;--epix-neutral-6:#404045;--epix-neutral-7:#2E2E32;--epix-neutral-8:#242428;--epix-neutral-9:#1D1D1F;--epix-neutral-11:#09090A;\
--epix-success-soft:#E8F8F0;--epix-danger-soft:#FDEDEC;--epix-ink-soft:#1D1D1F;\
--epix-bg:var(--epix-neutral-1);--epix-surface:var(--epix-neutral-0);--epix-surface-2:var(--epix-neutral-2);--epix-border:var(--epix-neutral-3);--epix-border-strong:var(--epix-neutral-4);\
--epix-text:var(--epix-neutral-9);--epix-text-mid:var(--epix-neutral-6);--epix-text-low:var(--epix-neutral-5);\
--epix-accent:var(--epix-purple);--epix-on-accent:#FEFEFE;--epix-focus:var(--epix-purple);--epix-link:var(--epix-purple);\
--epix-font-sans:Inter,-apple-system,'Segoe UI',Roboto,sans-serif;--epix-font-mono:'IBM Plex Mono',ui-monospace,Menlo,Consolas,monospace;\
--epix-shadow:0 1px 3px rgba(2,2,2,.12)}\
@media (prefers-color-scheme:dark){:root:not(.theme-light){color-scheme:dark;\
--epix-bg:var(--epix-neutral-11);--epix-surface:var(--epix-neutral-9);--epix-surface-2:var(--epix-neutral-8);--epix-border:var(--epix-neutral-7);--epix-border-strong:var(--epix-neutral-6);\
--epix-text:var(--epix-neutral-1);--epix-text-mid:var(--epix-neutral-3);--epix-text-low:var(--epix-neutral-4);\
--epix-focus:var(--epix-cyan);--epix-link:var(--epix-cyan)}}\
.theme-dark{color-scheme:dark;\
--epix-bg:var(--epix-neutral-11);--epix-surface:var(--epix-neutral-9);--epix-surface-2:var(--epix-neutral-8);--epix-border:var(--epix-neutral-7);--epix-border-strong:var(--epix-neutral-6);\
--epix-text:var(--epix-neutral-1);--epix-text-mid:var(--epix-neutral-3);--epix-text-low:var(--epix-neutral-4);\
--epix-focus:var(--epix-cyan);--epix-link:var(--epix-cyan)}\
*{box-sizing:border-box}\
body{margin:0;padding:0;background:var(--epix-bg);color:var(--epix-text);font-family:var(--epix-font-sans);font-size:14px;line-height:1.5}\
h1{background:var(--epix-purple);color:#FEFEFE;margin:0;padding:20px max(16px,calc((100% - 800px)/2 + 32px));font-size:24px;font-weight:700;line-height:1.25;overflow-wrap:anywhere}\
h1 a{color:#FEFEFE;text-decoration:none}\
h1 a:hover{text-decoration:underline}\
.content{max-width:min(800px,calc(100% - 32px));margin:24px auto 80px;background:var(--epix-surface);border:1px solid var(--epix-border);border-radius:12px;padding:28px 32px 48px}\
.sub{color:var(--epix-text-mid);font-size:14px;margin:0 0 24px}\
a{color:var(--epix-link);text-decoration:none}\
.plugin,.config-item{position:relative;padding:16px 0;border-bottom:1px solid var(--epix-border)}\
.plugin{padding-right:66px}\
.plugin .title h3,.config-item .title h3{font-size:15px;font-weight:600;margin:0;line-height:1.4}\
.plugin .description,.config-item .description{font-size:13px;color:var(--epix-text-mid);line-height:1.5;margin-top:2px}\
.default{color:var(--epix-text-low);font-size:12px}\
.plugin .value-right{position:absolute;right:0;top:50%;transform:translateY(-50%)}\
.config-item .value{margin-top:10px}\
.config-item:has(.checkbox){padding-right:66px}\
.config-item:has(.value .button){padding-right:180px}\
.config-item:has(.checkbox) .value,.config-item:has(.value .button) .value{position:absolute;right:0;top:50%;transform:translateY(-50%);margin-top:0}\
.checkbox{display:inline-block;cursor:pointer}\
.checkbox-skin{background:var(--epix-border-strong);width:50px;height:24px;border-radius:12px;transition:background .2s ease;display:inline-block;vertical-align:middle}\
.checkbox-skin:before{content:'';position:relative;width:20px;height:20px;background:#FEFEFE;display:block;border-radius:50%;margin:2px 0 0 2px;transition:margin .25s ease}\
.checkbox.checked .checkbox-skin{background:var(--epix-accent)}\
.checkbox.checked .checkbox-skin:before{margin-left:27px}\
.checkbox input{position:absolute;opacity:0;width:0;height:0}\
.checkbox input:checked + .checkbox-skin{background:var(--epix-accent)}\
.checkbox input:checked + .checkbox-skin:before{margin-left:27px}\
.checkbox input:disabled + .checkbox-skin{opacity:.45;cursor:not-allowed}\
a.checkbox:focus-visible,.button:focus-visible{outline:2px solid var(--epix-focus);outline-offset:2px}\
.input-text{width:100%;padding:9px 12px;border:1px solid var(--epix-border-strong);border-radius:8px;font-size:14px;font-family:var(--epix-font-sans);background:var(--epix-surface);color:var(--epix-text)}\
.input-text:focus{border-color:var(--epix-focus);outline:1px solid var(--epix-focus)}\
textarea.input-text{resize:vertical;line-height:1.5}\
.input-text:disabled{background:var(--epix-surface-2);color:var(--epix-text-low);border-color:var(--epix-border);cursor:not-allowed}\
.section-title{font-size:12px;font-weight:600;color:var(--epix-text-mid);text-transform:uppercase;letter-spacing:.08em;margin:32px 0 4px;padding-bottom:8px;border-bottom:1px solid var(--epix-border)}\
.config{margin-bottom:8px}\
.notification{padding:12px 16px;border-radius:8px;margin:0 0 20px;font-size:14px;color:var(--epix-ink-soft)}\
.notification-done{background:var(--epix-success-soft)}\
.notification-error{background:var(--epix-danger-soft)}\
.button{margin-top:24px;background:var(--epix-accent);color:var(--epix-on-accent);border:none;border-radius:8px;height:44px;padding:0 24px;font-size:15px;font-weight:600;font-family:var(--epix-font-sans);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;text-decoration:none}\
.button:hover{box-shadow:var(--epix-shadow)}\
.button:active{transform:translateY(1px)}\
.config-item .value .button{margin-top:0;height:36px;padding:0 16px;font-size:14px;color:var(--epix-on-accent)}\
.fixbutton{position:fixed;right:23px;top:9px;width:48px;height:48px;z-index:999;border-radius:50%;background:#020202 url('/uimedia/img/logo.png') center/48px no-repeat;display:block;transition:box-shadow .3s,transform .15s}\
.fixbutton{-webkit-user-select:none;user-select:none;-webkit-user-drag:none}\
.fixbutton:hover{box-shadow:var(--epix-shadow)}\
@media (max-width:640px){\
.content{max-width:100%;margin:0;border:none;border-radius:0;padding:20px 16px 64px}\
h1{padding:18px 84px 18px 16px;font-size:20px}\
.config-item:has(.value .button){padding-right:0}\
.config-item:has(.value .button) .value{position:static;transform:none;margin-top:10px}\
.button,.config-item .value .button{height:44px;min-height:44px}\
.checkbox{padding:10px 0 10px 10px}\
}";

/// Shared page shell for the server-rendered admin pages, on the flat Epix
/// design tokens (purple header bar, centered content card, themed light/dark
/// from the user's setting with a prefers-color-scheme fallback).
fn page_shell(
    title: &str,
    heading: &str,
    subtitle: &str,
    body: &str,
    homepage: &str,
    theme: &str,
) -> String {
    let sub = if subtitle.is_empty() {
        String::new()
    } else {
        format!("<p class='sub'>{subtitle}</p>")
    };
    // The corner fixbutton (like the wrapper's): click to return to the
    // dashboard. Hidden when there is no homepage xite to go back to.
    let fixbutton = if homepage.is_empty() {
        String::new()
    } else {
        format!("<a class='fixbutton' draggable='false' href='/{homepage}/' title='Back to the dashboard'></a>")
    };
    // Rubber-band drag: on these standalone pages the fixbutton is not a sidebar
    // handle, so a drag attempt gives way a little then springs back.
    let script = if homepage.is_empty() { "" } else { FIXBUTTON_DRAG_JS };
    format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>\
         <meta name='viewport' content='width=device-width, initial-scale=1'>\
         <link rel='icon' type='image/x-icon' href='/uimedia/img/favicon.ico'>\
         <link rel='apple-touch-icon' href='/uimedia/img/apple-touch-icon.png'>\
         <style>{PAGE_CSS}</style></head><body class='{theme}'>\
         {fixbutton}<h1>{heading}</h1><div class='content'>{sub}{body}</div>{script}</body></html>"
    )
}

/// A drag on the standalone-page fixbutton follows the pointer a little (damped
/// and capped) then springs back with a slight overshoot, so it's clear the
/// button is click-to-dashboard, not a draggable sidebar handle. A real drag
/// suppresses the click so it doesn't navigate.
const FIXBUTTON_DRAG_JS: &str = "<script>(function(){\
var b=document.querySelector('.fixbutton');if(!b)return;\
var sx=0,sy=0,drag=false,moved=0;\
function pt(e){return e.touches&&e.touches[0]?e.touches[0]:e;}\
function down(e){var p=pt(e);sx=p.clientX;sy=p.clientY;drag=true;moved=0;b.style.transition='none';}\
function move(e){if(!drag)return;var p=pt(e),dx=p.clientX-sx,dy=p.clientY-sy;\
moved=Math.max(moved,Math.abs(dx)+Math.abs(dy));var c=16;\
var rx=Math.max(-c,Math.min(c,dx*0.4)),ry=Math.max(-c,Math.min(c,dy*0.4));\
b.style.transform='translate('+rx+'px,'+ry+'px)';}\
function up(){if(!drag)return;drag=false;\
b.style.transition='transform .55s cubic-bezier(.18,.89,.32,1.28)';\
b.style.transform='translate(0,0)';if(moved>5){b._dragged=true;}}\
b.addEventListener('mousedown',down);\
window.addEventListener('mousemove',move);window.addEventListener('mouseup',up);\
b.addEventListener('touchstart',down,{passive:true});\
window.addEventListener('touchmove',move,{passive:true});window.addEventListener('touchend',up);\
b.addEventListener('click',function(e){if(b._dragged){e.preventDefault();b._dragged=false;}});\
})();</script>";

/// Replace known `{name}` tokens; JS braces (not a known name) are left intact.
/// Escape a raw query string for embedding in the wrapper template (it lands
/// inside a script string that sets the iframe src). Mirrors EpixNet's
/// xescape: html chars become entities so the value cannot break out of the
/// string or the script tag; backslashes are doubled.
fn escape_query(q: &str) -> String {
    q.replace('\\', "\\\\")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Drop a `wrapper_nonce=…` pair from a raw query string, keeping the rest.
fn strip_wrapper_nonce(q: &str) -> String {
    q.split('&')
        .filter(|kv| !kv.starts_with("wrapper_nonce="))
        .collect::<Vec<_>>()
        .join("&")
}

fn render(template: &str, vars: &[(&str, String)]) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

/// Serve a xite's own file (the inner iframe content + its assets).
/// `/raw/<site>/<path>`: the file bytes with no wrapper and EpixNet's
/// noscript Content-Security-Policy, so active content cannot run - the
/// share-a-file view (`actionSiteMedia(raw=True)`).
async fn serve_raw(
    State(ctx): State<Ctx>,
    Path((address, path)): Path<(String, String)>,
) -> Response {
    let address = ctx.state.canonical_key(&address).await;
    let Some(bytes) = ctx.state.read_file(&address, &path).await else {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    };
    let mut headers = file_headers(content_type(&path), StatusCode::OK);
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; sandbox allow-top-navigation allow-forms; img-src *;          font-src * data:; media-src *; style-src * 'unsafe-inline';"
            .parse()
            .unwrap(),
    );
    (headers, bytes).into_response()
}

/// `/add/<site>` -> `/<site>/`: the wrapper route resolves + clones unknown
/// xites on demand (and NoNewSites gates it), so the EpixNet add-confirmation
/// page reduces to a redirect here.
async fn redirect_add(Path(address): Path<String>) -> Redirect {
    Redirect::temporary(&format!("/{address}/"))
}

async fn serve_file(
    State(ctx): State<Ctx>,
    Path((address, path)): Path<(String, String)>,
    Query(q): Query<FileQuery>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    headers: axum::http::HeaderMap,
) -> Response {
    // A top-level navigation to a directory or HTML page (no wrapper_nonce)
    // renders the wrapper with the iframe pointed at that inner file, matching
    // EpixNet's isWrapperNecessary. Multi-page xites (Git Epix's `index/`,
    // `myrepos/`) navigate this way. Iframe resource loads carry the nonce and
    // fall through to the raw file below.
    if q.wrapper_nonce.is_none() {
        if let Some(inner) = wrapper_inner_path(&path) {
            // Strip the wrapper_nonce we would append back; the caller had none.
            let outer_query = raw_query
                .as_deref()
                .map(strip_wrapper_nonce)
                .filter(|s| !s.is_empty())
                .map(String::from);
            return render_wrapper(ctx, address, inner, outer_query, headers).await;
        }
    }
    // Release a one-time wrapper nonce if the inner frame passed one (tracks
    // that the request came through the wrapper; EpixNet warns otherwise).
    if let Some(nonce) = &q.wrapper_nonce {
        if !ctx.state.consume_wrapper_nonce(nonce) {
            ctx.state.log("WARNING", format!("Invalid wrapper nonce for /{address}/{path}")).await;
        }
    }
    // A `.epix` name in the URL resolves to the bech32 serving key.
    let requested = address;
    let mut address = ctx.state.canonical_key(&requested).await;
    // Progressive serve during an on-demand clone (EpixNet's `needFile`, per
    // file): kick the clone off (coalesced with any already running) and serve
    // each file the moment its verified bytes hit disk - the page renders
    // seconds into a big clone because index.html/css/js download first. The
    // entry registers (empty) at clone start, so a registered entry whose
    // requested file is missing gets the same wait-for-disk treatment.
    let registered = ctx.state.has_xite(&address).await;
    if !registered && ctx.state.no_new_sites().await {
        // NoNewSites: don't start a clone for a file request either.
        return (StatusCode::FORBIDDEN, "Adding new sites is disabled on this node")
            .into_response();
    }
    // An html document is the page itself: while its xite's core set (every
    // file the root content.json declares) is still downloading, hold it back
    // instead of serving it the moment it lands. index.html downloads first,
    // so serving it right away boots the page with its styles, scripts and
    // lazy chunks missing - and the wrapper drops its loading screen once the
    // iframe loads, stranding the user in a half-downloaded site. Non-html
    // assets still serve as they land: only an already-running page asks for
    // them, and each request waits for its own file (EpixNet's needFile).
    let is_html = content_type(&path).starts_with("text/html");
    let still_loading = !registered
        || !ctx.state.xite_file_exists(&address, &path).await
        || (is_html && ctx.state.html_doc_gated(&address).await);
    if still_loading && plausible_xite_ref(&requested) && ctx.state.has_on_demand().await {
        // Kick the clone off; also resumes an interrupted clone (a registered
        // xite with core files missing). Keep the handle: the html gate must
        // lift when no clone can run (failed, NoNewSites, nothing to resume),
        // or an incomplete-but-servable site would stall until the deadline.
        let ensure = {
            let state = ctx.state.clone();
            let target = requested.clone();
            tokio::spawn(async move {
                state.ensure_xite(&target).await;
            })
        };
        let ct = content_type(&path).to_string();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
        loop {
            let key = ctx.state.canonical_key(&requested).await;
            // Hold an html document while its core set is still incomplete AND
            // someone is working on completing it (a running clone, or our
            // ensure call still deciding whether to start one).
            let gated = is_html
                && ctx.state.html_doc_gated(&key).await
                && (ctx.state.is_cloning(&key) || !ensure.is_finished())
                && std::time::Instant::now() < deadline;
            if !gated
                && ctx.state.has_xite(&key).await
                && ctx.state.xite_file_exists(&key, &path).await
            {
                address = key; // the file is on disk - serve the normal path
                break;
            }
            // Once the name resolved (or was an address all along), the clone
            // dir is known - check the disk.
            let disk_key = if key != requested || requested.starts_with("epix1") {
                Some(key)
            } else {
                None
            };
            if let Some(k) = disk_key {
                match ctx.state.loading_file(&k, &path) {
                    crate::state::LoadingFile::Ready(_) if gated => {} // wait for the core set
                    crate::state::LoadingFile::Ready(bytes) => {
                        let bytes = substitute_html_vars(&ctx.state, &k, &ct, bytes).await;
                        return (file_headers(&ct, StatusCode::OK), bytes).into_response();
                    }
                    crate::state::LoadingFile::NotInSite => {
                        return (StatusCode::NOT_FOUND, "not found").into_response();
                    }
                    crate::state::LoadingFile::Pending => {}
                }
            }
            if std::time::Instant::now() >= deadline {
                return (StatusCode::NOT_FOUND, "not found").into_response();
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }
    let ct = content_type(&path).to_string();
    // Range request → 206 Partial Content, streamed from disk (big files seek
    // in the browser without loading the whole file).
    if let Some(range) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        if let (Some(total), Some((start, end))) =
            (ctx.state.file_size(&address, &path).await, parse_range(range))
        {
            if start < total {
                let end = end.unwrap_or(total - 1).min(total - 1);
                let len = (end - start + 1) as usize;
                // Big file: pull only the pieces this range needs (no-op otherwise).
                let _ = ctx.state.bigfile_fetch_range(&address, &path, start, len as u64).await;
                if let Some(bytes) = ctx.state.read_file_range(&address, &path, start, len).await {
                    let mut h = file_headers(&ct, StatusCode::PARTIAL_CONTENT);
                    if let Ok(v) = header::HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")) {
                        h.insert(header::CONTENT_RANGE, v);
                    }
                    return (StatusCode::PARTIAL_CONTENT, h, bytes).into_response();
                }
            }
        }
    }
    match ctx.state.read_file(&address, &path).await {
        Some(bytes) => {
            let bytes = substitute_html_vars(&ctx.state, &address, &ct, bytes).await;
            (file_headers(&ct, StatusCode::OK), bytes).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// EpixNet substitutes wrapper variables in served .html files
/// (`replaceHtmlVariables` + Translate): `{themeclass}` (the user's theme),
/// `{site_modified}` (content.json's modified time) and the `lang={lang}`
/// cache-buster. Xites key their styling off `body.theme-…`, so serving the
/// raw placeholder leaves them unstyled.
async fn substitute_html_vars(
    state: &Arc<AppState>,
    address: &str,
    content_type: &str,
    bytes: Vec<u8>,
) -> Vec<u8> {
    if !content_type.starts_with("text/html") {
        return bytes;
    }
    let mut text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => return e.into_bytes(),
    };
    text = text.replace("{themeclass}", &state.theme_class().await);
    text = text.replace("lang={lang}", &format!("lang={}", state.ui_language().await));
    if text.contains("{site_modified}") {
        let modified = state
            .content(address)
            .await
            .and_then(|c| c.get("modified").and_then(|m| m.as_f64()))
            .unwrap_or(0.0) as i64;
        text = text.replace("{site_modified}", &modified.to_string());
    }
    text.into_bytes()
}

#[derive(Deserialize)]
struct FileQuery {
    wrapper_nonce: Option<String>,
}

#[derive(Deserialize)]
struct UploadQuery {
    upload_nonce: Option<String>,
}

/// `POST /EpixNet-Internal/BigfileUpload?upload_nonce=<nonce>` - receive a big
/// file's bytes (from `bigfileUploadInit`), hash + store them, and return the
/// merkle root + piece info. Accepts a raw body or a single multipart part.
async fn bigfile_upload(
    State(ctx): State<Ctx>,
    Query(q): Query<UploadQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !ctx.state.bigfile_enabled().await {
        return (StatusCode::FORBIDDEN, "Bigfile plugin is disabled").into_response();
    }
    let Some(nonce) = q.upload_nonce else {
        return (StatusCode::BAD_REQUEST, "missing upload_nonce").into_response();
    };
    // If multipart/form-data, extract the single file part's bytes.
    let content_type = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let data: &[u8] = if content_type.starts_with("multipart/form-data") {
        match extract_multipart_file(&body) {
            Some(slice) => slice,
            None => return (StatusCode::BAD_REQUEST, "malformed multipart body").into_response(),
        }
    } else {
        &body
    };
    match ctx.state.bigfile_upload_finish(&nonce, data).await {
        Ok(r) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            json!({
                "merkle_root": r.merkle_root,
                "piece_num": r.piece_num,
                "piece_size": r.piece_size,
                "inner_path": r.inner_path,
            })
            .to_string(),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            json!({ "error": e }).to_string(),
        )
            .into_response(),
    }
}

/// Extract the single file part's bytes from a `multipart/form-data` body: the
/// content between the first blank line (`\r\n\r\n`) after the part headers and
/// the trailing boundary. Good enough for the wrapper's single-file XHR upload.
fn extract_multipart_file(body: &[u8]) -> Option<&[u8]> {
    let header_end = find_subslice(body, b"\r\n\r\n")? + 4;
    let rest = &body[header_end..];
    // The part ends at the last CRLF before the closing boundary line (`--…`).
    let boundary_start = rfind_subslice(rest, b"\r\n--")?;
    Some(&rest[..boundary_start])
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Parse an HTTP `Range: bytes=start-end` (single range). `end` is optional.
fn parse_range(header: &str) -> Option<(u64, Option<u64>)> {
    let spec = header.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end = end.trim();
    let end = if end.is_empty() { None } else { Some(end.parse().ok()?) };
    Some((start, end))
}

/// Security + caching headers for an inner site file, matching EpixNet's
/// `sendHeader`: Referrer-Policy, Cache-Control by type, and
/// Content-Disposition:attachment for file types dangerous to render inline
/// (svg/xml/pdf/flash).
///
/// Normal site files carry **no** Content-Security-Policy - matching EpixNet,
/// which only sends the restrictive `sandbox` CSP for `raw`/noscript requests.
/// The inner content is sandboxed by the wrapper's iframe `sandbox` attribute
/// (`allow-scripts allow-same-origin …`); putting `default-src 'none'; sandbox
/// (no allow-scripts)` on the file itself would block the site's own scripts and
/// - now that we serve over https (a secure context) - its service worker.
fn file_headers(content_type: &str, status: StatusCode) -> axum::http::HeaderMap {
    let mut pairs = vec![
        (header::CONTENT_TYPE, content_type.to_string()),
        (header::ACCEPT_RANGES, "bytes".to_string()),
        (header::REFERRER_POLICY, "same-origin".to_string()),
    ];
    // Download (don't render) types that can carry active content.
    if ["/svg", "/xml", "/x-shockwave-flash", "/pdf"].iter().any(|t| content_type.contains(t)) {
        pairs.push((header::CONTENT_DISPOSITION, "attachment".to_string()));
    }
    let base = content_type.split('/').next().unwrap_or("");
    let cacheable = matches!(base, "image" | "video" | "font")
        || content_type.starts_with("application/javascript")
        || content_type.starts_with("text/css");
    let cache = if matches!(status, StatusCode::OK | StatusCode::PARTIAL_CONTENT) && cacheable {
        "public, max-age=600"
    } else {
        "no-cache, no-store, private, must-revalidate, max-age=0"
    };
    pairs.push((header::CACHE_CONTROL, cache.to_string()));
    header_map(pairs)
}

/// Build a `HeaderMap` from name/value pairs (bad values are skipped).
fn header_map(pairs: Vec<(header::HeaderName, String)>) -> axum::http::HeaderMap {
    let mut map = axum::http::HeaderMap::new();
    for (name, value) in pairs {
        if let Ok(v) = header::HeaderValue::from_str(&value) {
            map.insert(name, v);
        }
    }
    map
}

/// The wrapper's script-nonce CSP header value (EpixNet's `script_nonce` path).
fn wrapper_csp(script_nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{script_nonce}'; img-src 'self' blob: data:; \
         style-src 'self' blob: 'unsafe-inline'; connect-src *; frame-src *"
    )
}

/// Minimal HTML attribute escaping for wrapper-injected values.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "gif" => "image/gif",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "webmanifest" => "application/manifest+json",
        "xml" => "text/xml; charset=utf-8",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "application/ogg",
        "oga" => "audio/ogg",
        "ogv" => "video/ogg",
        "otf" => "font/otf",
        "eot" => "font/eot",
        "asc" => "application/pgp-keys",
        "gpg" => "application/pgp-encrypted",
        "sig" => "application/pgp-signature",
        _ => "application/octet-stream",
    }
}

#[derive(Deserialize)]
struct WsQuery {
    wrapper_key: Option<String>,
    xite: Option<String>,
}

async fn ws_upgrade(
    State(ctx): State<Ctx>,
    Query(q): Query<WsQuery>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // Reject a WebSocket whose Origin isn't the request host, loopback, or a
    // previously-served wrapper host - so a cross-origin page can't drive the
    // local command API (EpixNet's allowed_ws_origins check).
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()).unwrap_or("");
    let origin_host = origin.rsplit("://").next().unwrap_or("");
    if !ctx.state.is_ws_origin_allowed(origin_host, host) {
        return (StatusCode::FORBIDDEN, "Invalid origin").into_response();
    }
    // wrapper_key == xite address for this node. The wrapper embeds the bech32
    // address, but resolve a `.epix` name too (older wrappers, manual clients)
    // so the session always binds to the address.
    let xite = match q.wrapper_key.or(q.xite) {
        Some(key) => Some(ctx.state.canonical_key(&key).await),
        None => None,
    };
    ws.on_upgrade(move |socket| handle_ws(socket, ctx, xite))
}

/// One item pumped from the shared event broadcast to a connection's queue.
enum Pumped {
    Event(state::UiEvent),
    /// The broadcast wrapped past this connection's cursor and events were
    /// lost. The forwarder repairs the damage it can: a lost `updated` event
    /// would strand a site row's "Updating..." pill forever.
    Lagged,
}

async fn handle_ws(socket: WebSocket, ctx: Ctx, xite: Option<String>) {
    use futures_util::{SinkExt, StreamExt};
    let session = std::sync::Arc::new(WsSession::new(ctx.state.clone(), xite));
    // Don't read the broadcast directly in the select loop below: while
    // `sink.send` waits on a slow socket (a backgrounded tab that stops
    // reading), a sync burst - one setSiteInfo per arriving file - wraps the
    // broadcast's ring buffer and events are dropped, updating/updated pairs
    // included. A pump task that does nothing but move events into this
    // connection's own unbounded queue can't fall behind, so nothing is
    // dropped (EpixNet writes to each websocket's own queue the same way).
    let mut broadcast_rx = ctx.state.subscribe_events();
    let (event_tx, mut events) = tokio::sync::mpsc::unbounded_channel::<Pumped>();
    let pump = tokio::spawn(async move {
        loop {
            let item = match broadcast_rx.recv().await {
                Ok(ev) => Pumped::Event(ev),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => Pumped::Lagged,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            if event_tx.send(item).is_err() {
                break; // connection gone
            }
        }
    });
    let (mut sink, mut stream) = socket.split();
    // Replies from concurrently-running command handlers (the sink has one
    // writer: this loop).
    let (reply_tx, mut replies) = tokio::sync::mpsc::unbounded_channel::<String>();
    loop {
        tokio::select! {
            // Xite -> server requests. Each command runs on its OWN task
            // (EpixNet runs every ws action in its own greenlet): the wrapper
            // and the inner page share this single connection, so a command
            // that waits on the user (certXid's account dialog, a confirm) or
            // on the network (fileGet's download wait) must not stall it -
            // the dialog events AND the user's answer ride this same socket,
            // and every later command (the page's boot queries) would queue
            // behind the wait forever.
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let ctx = ctx.clone();
                        let session = session.clone();
                        let reply_tx = reply_tx.clone();
                        tokio::spawn(async move {
                            let reply = handle_text(&ctx, &session, &text).await;
                            // An empty reply (e.g. a response to a pushed
                            // callback) isn't sent back.
                            if !reply.is_empty() {
                                let _ = reply_tx.send(reply);
                            }
                        });
                    }
                    Some(Ok(_)) => {} // ignore non-text frames (ping/pong/binary)
                    _ => break, // stream closed or errored
                }
            }
            // A finished command's response.
            Some(reply) = replies.recv() => {
                if sink.send(Message::Text(reply)).await.is_err() {
                    break;
                }
            }
            // Server -> xite pushed events (setSiteInfo, setAnnouncerInfo, …).
            event = events.recv() => {
                match event {
                    Some(Pumped::Event(ev)) => {
                        // Per-connection routing first: an event caused by this
                        // connection's own command is never echoed back to it
                        // (EpixNet's `ws != self` - the page already knows what
                        // it did, and the echo re-renders it mid-interaction),
                        // and a single-recipient event reaches only its
                        // addressee (EpixNet's `self.cmd`).
                        if ev.exclude == Some(session.id) {
                            continue;
                        }
                        if let Some(only) = ev.only {
                            if only == session.id
                                && sink.send(Message::Text(ev.payload)).await.is_err()
                            {
                                break;
                            }
                            continue;
                        }
                        // Deliver only if the connection joined the event's
                        // channel (ungated events always pass) and it is for this
                        // connection's xite (untargeted events always pass).
                        let channel_ok = match &ev.channel {
                            None => true,
                            Some(ch) => session.in_channel(ch),
                        };
                        let target_ok = match (&ev.target, &ev.channel) {
                            (None, _) => true,
                            // Bound xite matches, or the connection joined this
                            // channel for all sites (channelJoinAllsite), or the
                            // event is for a site merged into this connection's
                            // merger site (EpixNet forwards merged sites' events
                            // to their merger's sockets - Git Epix's repo pages
                            // track their repo site's download this way).
                            (Some(addr), channel) => {
                                session.xite.as_deref() == Some(addr.as_str())
                                    || channel.as_deref().is_some_and(|ch| session.in_allsite(ch))
                                    || merger_receives(&ctx.state, session.xite.as_deref(), addr).await
                            }
                        };
                        if channel_ok && target_ok && sink.send(Message::Text(ev.payload)).await.is_err() {
                            break;
                        }
                    }
                    // Events were dropped before reaching this connection's
                    // queue. Re-send the closing `updated` event for every
                    // finished site: if the drop swallowed one, its row's
                    // "Updating..." pill would never clear (a harmless extra
                    // "Updated!" flash otherwise).
                    Some(Pumped::Lagged) => {
                        ctx.state.push_missed_update_results(session.id).await;
                    }
                    None => break, // pump ended (state shutting down)
                }
            }
        }
    }
    pump.abort();
}

/// Whether a session bound to `session_xite` should also receive events
/// targeted at `target` because `target` is merged into it: the session's
/// site holds a `Merger:<type>` permission matching the target's
/// `merged_type`. Mirrors EpixNet's MergerSite plugin, which notifies a
/// merger site's websockets about its merged sites' changes.
async fn merger_receives(
    state: &Arc<AppState>,
    session_xite: Option<&str>,
    target: &str,
) -> bool {
    let Some(merger) = session_xite else { return false };
    if merger == target {
        return false;
    }
    let Some(merged_type) = state.site_merged_type(target).await else { return false };
    state.merger_types(merger).await.contains(&merged_type)
}

/// Parse one `{cmd, id, params}` request and format the EpixFrame response.
async fn handle_text(ctx: &Ctx, session: &WsSession, text: &str) -> String {
    let req: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return json!({"cmd": "response", "to": 0, "error": "invalid JSON"}).to_string(),
    };
    let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    let id = req.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    // A reply to a server-pushed confirm/prompt: resolve the waiting callback
    // rather than dispatching it as a command. `to` is the pushed event's id.
    if cmd == "response" {
        if let Some(to) = req.get("to").and_then(|v| v.as_i64()) {
            let result = req.get("result").cloned().unwrap_or(Value::Null);
            ctx.state.resolve_callback(to, result);
        }
        return String::new(); // no reply to a response
    }

    match ctx.registry.dispatch(session, cmd, &params, id).await {
        Ok(result) => json!({"cmd": "response", "to": id, "result": result}).to_string(),
        // EpixNet convention: a command error is the result being
        // `{"error": ...}`, which is what site scripts and epixframe.js read
        // (a top-level `error` field is dropped by callback-mode ws.cmd).
        Err(error) => {
            json!({"cmd": "response", "to": id, "result": { "error": error }}).to_string()
        }
    }
}

// ---- UiPassword: session gate + login/logout routes ------------------------

/// Middleware: when a UI password is configured, require a valid `session_id`
/// cookie on every request except the login page and favicon. Unauthenticated
/// requests get the login page.
#[cfg(feature = "ui-password")]
async fn ui_password_gate(
    State(ctx): State<Ctx>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if ctx.state.ui_password().await.is_none() {
        return next.run(request).await;
    }
    let path = request.uri().path();
    if path == "/Login" || path.ends_with("favicon.ico") {
        return next.run(request).await;
    }
    let cookie = request
        .headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok());
    if uipassword::session_valid(&uipassword::cookie_session_id(cookie)) {
        return next.run(request).await;
    }
    login_page(false)
}

/// Render the login page as an HTML response.
#[cfg(feature = "ui-password")]
fn login_page(bad_password: bool) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        uipassword::login_html(bad_password),
    )
        .into_response()
}

/// `GET /Login` - show the login form.
#[cfg(feature = "ui-password")]
async fn serve_login() -> Response {
    login_page(false)
}

/// `POST /Login` - check the password; on success set the session cookie and
/// redirect home, otherwise re-show the form with the error state.
#[cfg(feature = "ui-password")]
async fn serve_login_post(State(ctx): State<Ctx>, body: String) -> Response {
    let password = form_field(&body, "password");
    match ctx.state.ui_password().await {
        Some(expected) if password == expected => {
            let sid = uipassword::session_create();
            let cookie = format!("session_id={sid}; path=/; max-age=2592000");
            (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, "/".to_string()), (header::SET_COOKIE, cookie)],
            )
                .into_response()
        }
        _ => login_page(true),
    }
}

/// `GET /Logout` - drop the current session and clear the cookie.
#[cfg(feature = "ui-password")]
async fn serve_logout(headers: header::HeaderMap) -> Response {
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok());
    uipassword::session_delete(&uipassword::cookie_session_id(cookie));
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/".to_string()),
            (
                header::SET_COOKIE,
                "session_id=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
            ),
        ],
    )
        .into_response()
}

/// Pull a single field out of an `application/x-www-form-urlencoded` body.
#[cfg(feature = "ui-password")]
fn form_field(body: &str, key: &str) -> String {
    for pair in body.split('&') {
        if let Some(val) = pair.strip_prefix(&format!("{key}=")) {
            return percent_decode(val);
        }
    }
    String::new()
}

/// Minimal form-value decode: `+` to space and `%XX` escapes.
#[cfg(feature = "ui-password")]
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---- Benchmark: /Benchmark diagnostics page --------------------------------

#[cfg(feature = "benchmark")]
#[derive(Deserialize)]
struct BenchmarkQuery {
    #[serde(default)]
    filter: String,
}

/// `GET /Benchmark?filter=` - run the micro-benchmark suite and return its
/// plain-text report. Runs on a blocking thread since it is CPU-bound.
#[cfg(feature = "benchmark")]
async fn serve_benchmark(Query(q): Query<BenchmarkQuery>) -> Response {
    let report = tokio::task::spawn_blocking(move || benchmark::run(&q.filter))
        .await
        .unwrap_or_else(|_| "benchmark task failed".to_string());
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], report).into_response()
}


#[cfg(test)]
mod gateway_tests {
    use super::inject_gateway_banner;

    #[test]
    fn banner_lands_before_the_closing_body_tag() {
        let html = "<html><body><h1>site</h1></body></html>".to_string();
        let out = inject_gateway_banner(html);
        assert!(out.contains("epix-gateway-banner"));
        assert!(out.ends_with("</body></html>"));
        let banner_at = out.find("epix-gateway-banner").unwrap();
        assert!(banner_at < out.rfind("</body>").unwrap());
        assert!(banner_at > out.find("<h1>site</h1>").unwrap());
    }
}
