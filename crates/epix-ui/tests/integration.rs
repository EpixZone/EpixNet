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
        json!({ "cmd": cmd, "id": id, "params": params }).to_string().into(),
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
    // Inner site files carry NO CSP (like EpixNet) - the wrapper's iframe
    // sandbox attribute does the sandboxing; a `default-src 'none'` CSP here
    // would block the site's own scripts + service worker. Referrer-Policy stays.
    assert!(
        body.headers().get("content-security-policy").is_none(),
        "inner file has no CSP",
    );
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
async fn site_scripts_revalidate_with_etag() {
    // Site js/css is cached with `public, no-cache` + an ETag: stored, but
    // revalidated on every use. The wrapper navigates its iframe from script,
    // so a hard reload never bypass-caches the inner assets - with the old
    // max-age=600 a freshly published script stayed stale for 10 minutes with
    // no recourse. Unchanged files answer 304; a change serves new bytes.
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("app.js", b"var v = 1;").unwrap();
    let state = AppState::new("0.1.0");
    state
        .add_xite(
            "epix1cache",
            XiteEntry {
                storage: storage.clone(),
                content: Some(json!({ "title": "C", "files": { "app.js": {} } })),
            },
        )
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = UiServer::new(state).router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/epix1cache/app.js?wrapper_nonce=x");
    let referer = ("referer", format!("http://{addr}/epix1cache/"));
    let r = client.get(&url).header(referer.0, &referer.1).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["cache-control"], "public, no-cache");
    let etag = r.headers()["etag"].to_str().unwrap().to_string();
    assert!(etag.starts_with('"'), "quoted etag: {etag}");

    // Unchanged: revalidation answers 304 with no body.
    let r = client
        .get(&url)
        .header(referer.0, &referer.1)
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 304);
    assert!(r.bytes().await.unwrap().is_empty());

    // Changed on disk (a publish / local edit): same request serves the new
    // bytes under a new tag.
    storage.write("app.js", b"var v = 2;").unwrap();
    let r = client
        .get(&url)
        .header(referer.0, &referer.1)
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_ne!(r.headers()["etag"].to_str().unwrap(), etag);
    assert_eq!(r.text().await.unwrap(), "var v = 2;");
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
        .header("sec-fetch-mode", "navigate")
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
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert_eq!(inner.status(), 200);
    assert_eq!(inner.text().await.unwrap(), "<h1>inner</h1>");

    // Normal localhost path mode is unchanged: path-prefixed URLs.
    let path_mode = client
        .get(format!("http://{addr}/talk.epix/"))
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    let path_html = path_mode.text().await.unwrap();
    assert!(path_html.contains("/talk.epix/index.html"), "path mode keeps the prefix");
}

#[tokio::test]
async fn transparent_proxy_redirects_cross_xite_paths_to_own_origin() {
    // In host (transparent-proxy) mode a document that targets a DIFFERENT
    // xite by path must land on that xite's own origin, not serve nested.
    // Clicking a site on the dashboard links `/epix1talk…/`; without the
    // redirect that page rendered under `https://dashboard.epix/epix1talk…/`
    // with path-mode links, so its home button then went to
    // `dashboard.epix/dashboard.epix/`.
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"<h1>dash</h1>").unwrap();
    let state = AppState::new("0.1.0");
    state
        .add_xite(
            "dashboard.epix",
            XiteEntry {
                storage,
                content: Some(json!({ "title": "Dash", "files": { "index.html": {} } })),
            },
        )
        .await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let server = UiServer::new(state);
    tokio::spawn(async move {
        let _ = server.serve(addr).await;
    });
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();

    // A dashboard-style site link: another xite's address as the path.
    let talk = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
    let r = client
        .get(format!("http://{addr}/{talk}/"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_redirection(), "cross-xite path redirects: {}", r.status());
    assert_eq!(r.headers()["location"].to_str().unwrap(), format!("//{talk}/"));

    // Directory and query survive the redirect.
    let r = client
        .get(format!("http://{addr}/{talk}/docs/?Topic:9"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_redirection());
    assert_eq!(r.headers()["location"].to_str().unwrap(), format!("//{talk}/docs/?Topic:9"));

    // A named cross-xite path redirects to the name's origin.
    let r = client
        .get(format!("http://{addr}/talk.epix/"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_redirection());
    assert_eq!(r.headers()["location"].to_str().unwrap(), "//talk.epix/");

    // A literal SELF path (the Config page's path-form home link lands on
    // `dashboard.epix/dashboard.epix/`) collapses to the clean origin...
    let r = client
        .get(format!("http://{addr}/dashboard.epix/"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_redirection(), "literal self path redirects: {}", r.status());
    assert_eq!(r.headers()["location"].to_str().unwrap(), "//dashboard.epix/");

    // ...while the host-mode root (what that redirect lands on) serves, and a
    // client cannot suppress-or-forge its way into the nested serve by sending
    // the internal rewrite marker itself.
    let r = client
        .get(format!("http://{addr}/"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .header("x-epix-host-rewrite", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "host-mode root serves (no redirect loop)");

    // A bech32-address HOST is a proxy origin too (the redirect target): it
    // serves in host mode, not nested and not redirected again.
    let dir2 = tempfile::tempdir().unwrap();
    let storage2 = XiteStorage::new(dir2.path());
    storage2.write("index.html", b"<h1>talk</h1>").unwrap();
    // (A second server keeps the test simple: fresh state with the address key.)
    let state2 = AppState::new("0.1.0");
    state2
        .add_xite(
            talk,
            XiteEntry {
                storage: storage2,
                content: Some(json!({ "title": "Talk", "files": { "index.html": {} } })),
            },
        )
        .await;
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    drop(listener2);
    let server2 = UiServer::new(state2);
    tokio::spawn(async move {
        let _ = server2.serve(addr2).await;
    });
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr2).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let r = client
        .get(format!("http://{addr2}/"))
        .header("host", talk)
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "address host serves at its own origin");
    let html = r.text().await.unwrap();
    assert!(html.contains(r#"iframe_src = "/index.html?"#), "host-relative iframe: {html}");

    // Loopback path mode is untouched: no redirect for 127.0.0.1 hosts.
    let r = client
        .get(format!("http://{addr2}/{talk}/"))
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "loopback path serving unchanged");
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
async fn own_write_is_not_echoed_back() {
    // EpixNet notifies `ws != self`: the connection whose fileWrite produced a
    // file_done must not receive the event (an echo re-renders the page
    // mid-interaction), while every other connection on the site does.
    use base64::Engine;
    let (addr, _dir) = start_server().await;
    let url = format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key=epix1xite");
    let (mut writer, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut watcher, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    call_params(&mut writer, "channelJoin", json!({ "channels": ["siteChanged"] }), 1).await;
    call_params(&mut watcher, "channelJoin", json!({ "channels": ["siteChanged"] }), 1).await;

    let b64 = base64::engine::general_purpose::STANDARD.encode(br#"{"topic":[]}"#);
    let res = call_params(&mut writer, "fileWrite", json!(["data/test.json", b64]), 2).await;
    assert_eq!(res["result"], json!("ok"));

    // The other connection gets the file_done push.
    let evt = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Message::Text(t))) = watcher.next().await {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["cmd"] == "setSiteInfo" && v["params"]["event"][0] == "file_done" {
                    return v;
                }
            }
        }
    })
    .await
    .expect("watcher receives the file_done event");
    assert_eq!(evt["params"]["event"][1], "data/test.json");

    // The writer must not: nothing arrives beyond its own command reply.
    let echo =
        tokio::time::timeout(std::time::Duration::from_millis(800), writer.next()).await;
    assert!(echo.is_err(), "no event echoed to the writing connection: {echo:?}");
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
    // Errors nest under `result` (EpixNet convention).
    assert!(denied["result"]["error"].as_str().unwrap().contains("permission"));

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
