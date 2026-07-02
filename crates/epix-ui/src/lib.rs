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
pub mod geoip;
pub mod state;
#[cfg(feature = "ui-password")]
pub mod uipassword;

pub use command::{CommandRegistry, WsCommand, WsSession};
pub use state::{AppState, XiteEntry};

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
            .route("/EpixNet-Internal/Websocket", get(ws_upgrade))
            .route("/uimedia/*path", get(serve_uimedia))
            .route("/Plugins", get(serve_plugins_page))
            .route("/Config", get(serve_config_page))
            .route("/list/*path", get(serve_file_manager))
            .route("/:address", get(redirect_to_slash))
            .route("/:address/", get(serve_wrapper))
            .route("/:address/*path", get(serve_file));
        // Benchmark: a diagnostics page timing the node's hot paths.
        #[cfg(feature = "benchmark")]
        let router = router.route("/Benchmark", get(serve_benchmark));
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
        axum::serve(listener, self.router()).await
    }
}

async fn health() -> &'static str {
    "Epix UI server"
}

/// `/{address}` → `/{address}/` (so a xite URL works without the trailing slash).
async fn redirect_to_slash(Path(address): Path<String>) -> Redirect {
    Redirect::permanent(&format!("/{address}/"))
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
        "<!doctype html><html><head><meta charset='utf-8'><title>Site blocked</title></head>\
         <body style='font-family:Segoe UI,Helvetica,Arial;background:#323C4D;color:#fff;text-align:center;padding-top:15%'>\
         <h1>This site is blocked</h1><p style='opacity:.7'>{}</p>{}</body></html>",
        esc(address),
        reason_html,
    )
}

async fn serve_wrapper(State(ctx): State<Ctx>, Path(address): Path<String>) -> Response {
    if !ctx.state.has_xite(&address).await {
        return (StatusCode::NOT_FOUND, "unknown xite").into_response();
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
        .unwrap_or(&address)
        .to_string();
    let nonce = ctx.state.wrapper_nonce();
    // The xite's real permissions (empty until the user grants one). This is
    // only the wrapper's initial value; the authoritative list arrives over the
    // WebSocket via siteInfo.
    let permissions = ctx.state.site_permissions(&address).await;

    // wrapper_key == address for this single-user local node.
    let vars: Vec<(&str, String)> = vec![
        ("title", title),
        ("rev", "1".into()),
        ("meta_tags", String::new()),
        ("body_style", String::new()),
        ("themeclass", "theme-light".into()),
        ("script_nonce", String::new()),
        ("homepage", format!("/{address}")),
        ("site_file_server", String::new()),
        ("file_url", format!("/{address}/index.html")),
        ("file_inner_path", "index.html".into()),
        ("query_string", format!("?wrapper_nonce={nonce}")),
        ("address", address.clone()),
        ("wrapper_nonce", nonce),
        ("wrapper_key", address.clone()),
        ("ajax_key", address.clone()),
        ("postmessage_nonce_security", "false".into()),
        ("permissions", json!(permissions).to_string()),
        ("show_loadingscreen", "false".into()),
        ("sandbox_permissions", String::new()),
        ("server_url", String::new()),
        ("lang", "en".into()),
    ];
    let html = render(WRAPPER_HTML, &vars);
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
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
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_plugins_page(&states))
        .into_response()
}

/// A short description for a known built-in plugin/feature.
fn plugin_description(name: &str) -> &'static str {
    match name {
        "Sidebar" => "Slide-out site info panel with peers, transfer stats, and the world globe.",
        "Stats" => "Network stats charts and the peer world map on the dashboard.",
        "UiPluginManager" => "This plugin manager page.",
        "UiConfig" => "The node configuration page.",
        _ => "Built-in plugin.",
    }
}

/// Render the plugin manager page, styled like EpixNet's (light theme, gradient
/// header, sliding toggle switches). The toggle is a link (`/Plugins?toggle=…`)
/// so it works without JS/WebSocket.
fn render_plugins_page(states: &[(String, bool)]) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut rows = String::new();
    for (name, enabled) in states {
        let checked = if *enabled { "checked" } else { "" };
        rows.push_str(&format!(
            "<div class='plugin'>\
               <div class='title'><h3>{name}</h3>\
                 <div class='description'>{descr}</div></div>\
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
    page_shell("Plugins", "Plugins", "", &format!("<div class='plugins'>{rows}</div>"))
}

/// `GET /Config` - the node settings page. `?save=1&<key>=<value>` persists the
/// changed keys (via configSet) and redirects back.
async fn serve_config_page(
    State(ctx): State<Ctx>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if params.contains_key("save") {
        for (key, _label, _default) in crate::state::CONFIG_SCHEMA {
            if let Some(val) = params.get(*key) {
                ctx.state.config_set(key, Value::from(val.as_str())).await;
            }
        }
        return Redirect::to("/Config").into_response();
    }
    let mut values = Vec::new();
    for (key, label, default) in crate::state::CONFIG_SCHEMA {
        let val = ctx
            .state
            .config_get(key)
            .await
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| default.to_string());
        values.push((*key, *label, val));
    }
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_config_page(&values)).into_response()
}

/// Render the settings page, styled like EpixNet's Config page.
fn render_config_page(values: &[(&str, &str, String)]) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    };
    let mut fields = String::new();
    for (key, label, val) in values {
        fields.push_str(&format!(
            "<div class='config-item'>\
               <div class='title'><h3>{label}</h3></div>\
               <div class='value value-right'>\
                 <input class='input-text' name='{key}' value='{val}' spellcheck='false'></div>\
             </div>",
            label = esc(label),
            key = esc(key),
            val = esc(val),
        ));
    }
    let body = format!(
        "<form method='get' action='/Config'>\
           <div class='config'>{fields}</div>\
           <input type='hidden' name='save' value='1'>\
           <button class='button' type='submit'>Save</button>\
         </form>"
    );
    page_shell("Configuration", "Configuration", "", &body)
}

/// `GET /list/<address>/<inner_path>` - the UiFileManager file browser. Lists a
/// directory inside a xite with links to navigate and open files.
async fn serve_file_manager(State(ctx): State<Ctx>, Path(path): Path<String>) -> Response {
    let (address, inner) = match path.split_once('/') {
        Some((a, i)) => (a.to_string(), i.trim_end_matches('/').to_string()),
        None => (path.clone(), String::new()),
    };
    let Some(entries) = ctx.state.list_dir(&address, &inner).await else {
        return (StatusCode::NOT_FOUND, "unknown xite or path").into_response();
    };
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_file_manager(&address, &inner, &entries))
        .into_response()
}

/// Render the file browser for a xite directory.
fn render_file_manager(address: &str, inner: &str, entries: &[Value]) -> String {
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
    let heading = if inner.is_empty() {
        format!("Files: {}", esc(address))
    } else {
        format!("Files: {}/{}", esc(address), esc(inner))
    };
    let body = format!(
        "<style>.row{{padding:8px 0;border-bottom:1px solid #f0f2f5}}\
          .name{{font-size:16px}} .name.dir{{font-weight:600}}\
          .size{{float:right;color:#999;font-size:13px}}</style>\
         <div class='files'>{rows}</div>"
    );
    page_shell("Files", &heading, "", &body)
}

/// Shared page shell for the server-rendered admin pages, styled to match
/// EpixNet (light theme, gradient header, sliding toggles, config inputs).
fn page_shell(title: &str, heading: &str, subtitle: &str, body: &str) -> String {
    let sub = if subtitle.is_empty() {
        String::new()
    } else {
        format!("<p class='sub'>{subtitle}</p>")
    };
    format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>{title}</title>\
         <meta name='viewport' content='width=device-width, initial-scale=1'>\
         <style>\
          body{{background:#EDF2F5;font-family:Roboto,'Segoe UI',Arial,'Helvetica Neue',sans-serif;margin:0;padding:0;color:#333}}\
          h1{{background:linear-gradient(33deg,#af3bff,#0d99c9);color:#fff;padding:16px 30px;margin:0;font-weight:200;font-size:30px}}\
          .content{{max-width:800px;margin:auto;background:#fff;padding:40px 30px 120px;box-sizing:border-box;min-height:100vh}}\
          .sub{{color:#666;font-size:15px;margin:0 0 26px}}\
          .plugin,.config-item{{position:relative;padding:16px 0;border-bottom:1px solid #f0f2f5}}\
          .plugin .title,.config-item .title{{display:inline-block}}\
          .plugin .title h3,.config-item .title h3{{font-size:20px;font-weight:lighter;margin:0;line-height:32px}}\
          .plugin .description{{font-size:14px;color:#777;line-height:22px;margin-top:2px}}\
          .value-right{{right:0;position:absolute;top:16px}}\
          .checkbox{{display:inline-block;cursor:pointer}}\
          .checkbox-skin{{background:#CCC;width:50px;height:24px;border-radius:15px;transition:all .3s ease-in-out;display:inline-block}}\
          .checkbox-skin:before{{content:'';position:relative;width:20px;height:20px;background:#fff;display:block;border-radius:100%;margin:2px 0 0 2px;transition:all .5s cubic-bezier(.785,.135,.15,.86)}}\
          .checkbox.checked .checkbox-skin{{background:#2ECC71}}\
          .checkbox.checked .checkbox-skin:before{{margin-left:27px}}\
          .input-text{{padding:8px 18px;border:1px solid #CCC;border-radius:3px;font-size:15px;box-sizing:border-box;min-width:280px;font-family:'Segoe UI',Arial,sans-serif}}\
          .input-text:focus{{border-color:#3396ff;outline:none}}\
          .button{{margin-top:26px;background:linear-gradient(33deg,#af3bff,#0d99c9);color:#fff;border:none;border-radius:4px;padding:12px 30px;font-size:16px;cursor:pointer}}\
          a{{color:#9760F9;text-decoration:none}}\
         </style></head><body>\
         <h1>{heading}</h1><div class='content'>{sub}{body}</div></body></html>"
    )
}

/// Replace known `{name}` tokens; JS braces (not a known name) are left intact.
fn render(template: &str, vars: &[(&str, String)]) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

/// Serve a xite's own file (the inner iframe content + its assets).
async fn serve_file(
    State(ctx): State<Ctx>,
    Path((address, path)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Response {
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
                    return (
                        StatusCode::PARTIAL_CONTENT,
                        [
                            (header::CONTENT_TYPE, ct),
                            (header::CONTENT_RANGE, format!("bytes {start}-{end}/{total}")),
                            (header::ACCEPT_RANGES, "bytes".to_string()),
                        ],
                        bytes,
                    )
                        .into_response();
                }
            }
        }
    }
    match ctx.state.read_file(&address, &path).await {
        Some(bytes) => (
            [(header::CONTENT_TYPE, ct), (header::ACCEPT_RANGES, "bytes".to_string())],
            bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
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
        _ => "application/octet-stream",
    }
}

#[derive(Deserialize)]
struct WsQuery {
    wrapper_key: Option<String>,
    xite: Option<String>,
}

async fn ws_upgrade(State(ctx): State<Ctx>, Query(q): Query<WsQuery>, ws: WebSocketUpgrade) -> Response {
    // wrapper_key == xite address for this node.
    let xite = q.wrapper_key.or(q.xite);
    ws.on_upgrade(move |socket| handle_ws(socket, ctx, xite))
}

async fn handle_ws(socket: WebSocket, ctx: Ctx, xite: Option<String>) {
    use futures_util::{SinkExt, StreamExt};
    let session = WsSession::new(ctx.state.clone(), xite);
    let mut events = ctx.state.subscribe_events();
    let (mut sink, mut stream) = socket.split();
    loop {
        tokio::select! {
            // Xite -> server requests.
            incoming = stream.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let reply = handle_text(&ctx, &session, &text).await;
                        if sink.send(Message::Text(reply)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {} // ignore non-text frames (ping/pong/binary)
                    _ => break, // stream closed or errored
                }
            }
            // Server -> xite pushed events (setSiteInfo, setAnnouncerInfo, …).
            event = events.recv() => {
                match event {
                    Ok(ev) => {
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
                            // channel for all sites (channelJoinAllsite).
                            (Some(addr), channel) => {
                                session.xite.as_deref() == Some(addr.as_str())
                                    || channel.as_deref().is_some_and(|ch| session.in_allsite(ch))
                            }
                        };
                        if channel_ok && target_ok && sink.send(Message::Text(ev.payload)).await.is_err() {
                            break;
                        }
                    }
                    // Lagged: dropped some events under load - keep going.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
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

    match ctx.registry.dispatch(session, cmd, &params, id).await {
        Ok(result) => json!({"cmd": "response", "to": id, "result": result}).to_string(),
        Err(error) => json!({"cmd": "response", "to": id, "error": error}).to_string(),
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
