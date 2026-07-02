//! `epix-ui` — the local UI server.
//!
//! Serves the wrapper (`GET /{address}/`), the wrapper runtime assets
//! (`/uimedia/*`, embedded at build time), a xite's own files
//! (`GET /{address}/{inner_path}`), and the EpixFrame WebSocket command API at
//! `/EpixNet-Internal/Websocket?wrapper_key=…`. Commands are dispatched through
//! the [`CommandRegistry`], which the plugin system extends.

pub mod chart;
pub mod command;
pub mod state;

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

/// Plugins' contributions to `/uimedia/*`: bytes appended to the base
/// `all.js`/`all.css`, plus extra static files (keyed by path under `/uimedia/`).
#[derive(Default, Clone)]
pub struct MediaBundle {
    pub append_js: Vec<u8>,
    pub append_css: Vec<u8>,
    pub files: std::collections::HashMap<String, Vec<u8>>,
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
        Router::new()
            .route("/", get(health))
            .route("/EpixNet-Internal/Websocket", get(ws_upgrade))
            .route("/uimedia/*path", get(serve_uimedia))
            .route("/:address", get(redirect_to_slash))
            .route("/:address/", get(serve_wrapper))
            .route("/:address/*path", get(serve_file))
            .with_state(self.ctx.clone())
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
    // Base bundle + appended plugin JS/CSS.
    if path == "all.js" || path == "all.css" {
        if let Some(file) = UIMEDIA.get_file(&path) {
            let mut body = file.contents().to_vec();
            let append = if path == "all.js" { &ctx.media.append_js } else { &ctx.media.append_css };
            body.extend_from_slice(append);
            return ([(header::CONTENT_TYPE, ct)], body).into_response();
        }
    }
    // Plugin-provided static files (e.g. globe assets).
    if let Some(bytes) = ctx.media.files.get(&path) {
        return ([(header::CONTENT_TYPE, ct)], bytes.clone()).into_response();
    }
    match UIMEDIA.get_file(&path) {
        Some(file) => ([(header::CONTENT_TYPE, ct)], file.contents().to_vec()).into_response(),
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

/// Serve the wrapper page for a xite (`GET /{address}/`).
async fn serve_wrapper(State(ctx): State<Ctx>, Path(address): Path<String>) -> Response {
    if !ctx.state.has_xite(&address).await {
        return (StatusCode::NOT_FOUND, "unknown xite").into_response();
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

async fn handle_ws(mut socket: WebSocket, ctx: Ctx, xite: Option<String>) {
    let session = WsSession { state: ctx.state.clone(), xite };
    while let Some(Ok(msg)) = socket.recv().await {
        if let Message::Text(text) = msg {
            let reply = handle_text(&ctx, &session, &text).await;
            if socket.send(Message::Text(reply)).await.is_err() {
                break;
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
