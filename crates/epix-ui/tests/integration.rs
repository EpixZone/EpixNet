//! Exercise the UI server: serve a xite file over HTTP and run EpixFrame
//! WebSocket commands (ping / serverInfo / siteInfo).

use epix_ui::{AppState, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn call(ws: &mut Ws, cmd: &str, id: i64) -> Value {
    call_params(ws, cmd, json!({}), id).await
}

async fn call_params(ws: &mut Ws, cmd: &str, params: Value, id: i64) -> Value {
    ws.send(Message::Text(
        json!({ "cmd": cmd, "id": id, "params": params }).to_string(),
    ))
    .await
    .unwrap();
    loop {
        if let Some(Ok(Message::Text(t))) = ws.next().await {
            return serde_json::from_str(&t).unwrap();
        }
    }
}

async fn start_server() -> (std::net::SocketAddr, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"<html>hi from xite</html>").unwrap();

    let state = AppState::new("0.1.0");
    state
        .add_xite(
            "epix1xite",
            XiteEntry {
                storage,
                content: Some(json!({ "title": "Test Xite", "files": { "index.html": {} } })),
            },
        )
        .await;
    // Seed the chart db so the Stats page has data to query.
    state.collect_chart().await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = UiServer::new(state).router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (addr, dir)
}

#[tokio::test]
async fn serves_xite_files_over_http() {
    let (addr, _dir) = start_server().await;
    let body = reqwest::get(format!("http://{addr}/epix1xite/index.html"))
        .await
        .unwrap();
    assert_eq!(body.status(), 200);
    assert_eq!(
        body.headers()["content-type"],
        "text/html; charset=utf-8"
    );
    // Security headers: sandbox CSP + Referrer-Policy on inner site files.
    let csp = body.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("sandbox"), "inner file gets the sandbox CSP: {csp}");
    assert_eq!(body.headers()["referrer-policy"], "same-origin");
    assert_eq!(body.text().await.unwrap(), "<html>hi from xite</html>");

    // The wrapper page carries a script-nonce CSP (not the sandbox one).
    let wrapper = reqwest::get(format!("http://{addr}/epix1xite/")).await.unwrap();
    let wcsp = wrapper.headers()["content-security-policy"].to_str().unwrap();
    assert!(wcsp.contains("script-src 'nonce-"), "wrapper CSP has a script nonce: {wcsp}");
    assert!(!wcsp.contains("sandbox"));

    let missing = reqwest::get(format!("http://{addr}/epix1xite/nope.txt"))
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn transparent_proxy_serves_epix_host() {
    // A xite served under a `.epix` name, reachable via the transparent-proxy
    // host rewrite (what Firefox's PAC sends: Host: talk.epix, path /).
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"<h1>inner</h1>").unwrap();
    let state = AppState::new("0.1.0");
    state
        .add_xite(
            "talk.epix",
            XiteEntry {
                storage,
                content: Some(json!({ "title": "Talk", "files": { "index.html": {} } })),
            },
        )
        .await;

    // The full serve() path (includes the proxy rewrite wrap), not router().
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // serve() binds itself
    let server = UiServer::new(state);
    tokio::spawn(async move {
        let _ = server.serve(addr).await;
    });
    // Wait for bind.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let client = reqwest::Client::new();

    // Proxy request for the wrapper: Host is the xite name, path is "/".
    let wrapper = client
        .get(format!("http://{addr}/"))
        .header("host", "talk.epix")
        .send()
        .await
        .unwrap();
    assert_eq!(wrapper.status(), 200);
    let html = wrapper.text().await.unwrap();
    // Host mode emits host-relative URLs (NOT /talk.epix/index.html).
    assert!(html.contains(r#"iframe_src = "/index.html?"#), "host-relative iframe: {html}");
    assert!(!html.contains("/talk.epix/index.html"), "no path-prefix in host mode");

    // Proxy request for an inner file: Host + host-relative path.
    let inner = client
        .get(format!("http://{addr}/index.html"))
        .header("host", "talk.epix")
        .send()
        .await
        .unwrap();
    assert_eq!(inner.status(), 200);
    assert_eq!(inner.text().await.unwrap(), "<h1>inner</h1>");

    // Normal localhost path mode is unchanged: path-prefixed URLs.
    let path_mode = client.get(format!("http://{addr}/talk.epix/")).send().await.unwrap();
    let path_html = path_mode.text().await.unwrap();
    assert!(path_html.contains("/talk.epix/index.html"), "path mode keeps the prefix");
}

#[tokio::test]
async fn rejects_cross_origin_websocket() {
    let (addr, _dir) = start_server().await;
    // A WebSocket from a foreign Origin is refused (can't drive the local API).
    use tokio_tungstenite::tungstenite::http;
    let req = http::Request::builder()
        .uri(format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key=epix1xite"))
        .header("Host", addr.to_string())
        .header("Origin", "http://evil.example.com")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    let result = tokio_tungstenite::connect_async(req).await;
    assert!(result.is_err(), "cross-origin WS should be rejected");
}

#[tokio::test]
async fn handles_epixframe_websocket_commands() {
    let (addr, _dir) = start_server().await;
    let url = format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key=epix1xite");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

    let pong = call(&mut ws, "ping", 1).await;
    assert_eq!(pong["to"], 1);
    assert_eq!(pong["result"], "Pong!");

    let info = call(&mut ws, "serverInfo", 2).await;
    assert_eq!(info["result"]["version"], "0.1.0");

    let site = call(&mut ws, "siteInfo", 3).await;
    assert_eq!(site["result"]["address"], "epix1xite");
    assert_eq!(site["result"]["content"]["title"], "Test Xite");
    // A xite holds no permissions until the user grants one.
    assert!(site["result"]["settings"]["permissions"].as_array().unwrap().is_empty());

    // An admin command from the inner page (small id) is refused...
    let denied = call(&mut ws, "siteList", 4).await;
    assert_eq!(denied["to"], 4);
    assert!(denied["error"].as_str().unwrap().contains("permission"));

    // ...but the trusted wrapper chrome (id >= 1_000_000) may run it.
    let allowed = call(&mut ws, "siteList", 1_000_001).await;
    assert!(allowed["result"].is_array());

    // The Stats page reads the chart db via chartDbQuery (also admin-gated).
    let types = call_params(&mut ws, "chartDbQuery", json!("SELECT * FROM type"), 1_000_002).await;
    let names: Vec<&str> =
        types["result"].as_array().unwrap().iter().filter_map(|r| r["name"].as_str()).collect();
    assert!(names.contains(&"size") && names.contains(&"peer"));

    // Unimplemented commands return null (logged), not a hard error.
    let unknown = call(&mut ws, "bogusCommand", 5).await;
    assert_eq!(unknown["to"], 5);
    assert!(unknown["result"].is_null());
}
