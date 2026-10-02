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

/// Start a UI server with one owned, SIGNED test xite (real key + address,
/// verified-authority root on disk). Ingest and db authority flow from an
/// accepted manifest authority, so the root must declare every managed file -
/// including `data/test.json`, the exact bytes `own_write_is_not_echoed_back`
/// later writes. Returns the bound address, the xite's bech32 address, the
/// xite's secret wrapper_key (what the served wrapper page embeds), and the
/// tempdir keeping the storage alive.
async fn start_server() -> (std::net::SocketAddr, String, String, tempfile::TempDir) {
    let (addr, address, key, _state, dir) = start_server_with_state().await;
    (addr, address, key, dir)
}

/// [`start_server`] that also hands back the node state, for tests that
/// change it (grant a permission, flip a config) between requests.
async fn start_server_with_state(
) -> (std::net::SocketAddr, String, String, std::sync::Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    let index = b"<html>hi from xite</html>";
    storage.write("index.html", index).unwrap();
    let test_json = br#"{"topic":[]}"#;

    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let mut root = json!({
        "address": address,
        "title": "Test Xite",
        "modified": 1.0,
        "files": {
            "index.html": {
                "size": index.len(), "sha512": XiteStorage::hash_bytes(index)
            },
            "data/test.json": {
                "size": test_json.len(), "sha512": XiteStorage::hash_bytes(test_json)
            },
        },
    });
    epix_content::sign(&mut root, &key).unwrap();
    storage
        .write("content.json", epix_content::dumps_content(&root).as_bytes())
        .unwrap();

    let state = AppState::new("0.1.0");
    state
        .add_xite(&address, XiteEntry { storage, content: Some(root) })
        .await;
    // The operator's own xite: local writes (fileWrite) stay served as-is.
    state.set_owned(&address, true).await;
    // Seed the chart db so the Stats page has data to query.
    state.collect_chart().await;
    let (wrapper_key, _ajax_key) = state.wrapper_keys(&address).await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = UiServer::new(state.clone()).router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (addr, address, wrapper_key, state, dir)
}

#[tokio::test]
async fn the_wrapper_runs_the_xite_in_an_opaque_origin() {
    let (addr, xite, key, state, _dir) = start_server_with_state().await;
    let wrapper = || async {
        reqwest::Client::new()
            .get(format!("http://{addr}/{xite}/"))
            .header("sec-fetch-mode", "navigate")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    };
    let html = wrapper().await;
    let sandbox = html
        .split("id='inner-iframe' sandbox=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the inner iframe carries a sandbox attribute");
    // The xite page is an opaque origin: it can run scripts and navigate, but
    // it is not this origin, so it cannot script the wrapper or open the
    // node's WebSocket as the wrapper's origin.
    assert!(sandbox.contains("allow-scripts"), "{sandbox}");
    assert!(!sandbox.contains("allow-same-origin"), "default sandbox is opaque: {sandbox}");
    // The wrapper's own script receives the xite's secret keys and the
    // gateway flag; the keys are what its WebSocket authenticates with.
    assert!(html.contains(&format!("wrapper_key = \"{key}\"")), "wrapper embeds its key");
    assert!(!html.contains(&format!("wrapper_key = \"{xite}\"")), "the key is not the address");
    assert!(html.contains("ui_restrict = false"), "{html}");
    let (_, ajax_key) = state.wrapper_keys(&xite).await;
    assert!(html.contains(&format!("ajax_key = \"{ajax_key}\"")), "wrapper embeds the ajax key");

    // NOSANDBOX is the user's explicit full-trust grant: only then does the
    // frame share the wrapper's origin.
    state.add_permission(&xite, "NOSANDBOX").await;
    let html = wrapper().await;
    assert!(html.contains("allow-popups-to-escape-sandbox allow-same-origin\""), "{html}");
}

#[tokio::test]
async fn serves_xite_files_over_http() {
    let (addr, xite, _key, _dir) = start_server().await;
    let body = reqwest::get(format!("http://{addr}/{xite}/index.html"))
        .await
        .unwrap();
    assert_eq!(body.status(), 200);
    assert_eq!(
        body.headers()["content-type"],
        "text/html; charset=utf-8"
    );
    // Inner xite files carry NO CSP (like EpixNet) - the wrapper's iframe
    // sandbox attribute does the sandboxing; a `default-src 'none'` CSP here
    // would block the xite's own scripts + service worker. Referrer-Policy stays.
    assert!(
        body.headers().get("content-security-policy").is_none(),
        "inner file has no CSP",
    );
    assert_eq!(body.headers()["referrer-policy"], "same-origin");
    assert_eq!(body.text().await.unwrap(), "<html>hi from xite</html>");

    // The wrapper page carries a script-nonce CSP (not the sandbox one).
    let wrapper = reqwest::get(format!("http://{addr}/{xite}/")).await.unwrap();
    let wcsp = wrapper.headers()["content-security-policy"].to_str().unwrap();
    assert!(wcsp.contains("script-src 'nonce-"), "wrapper CSP has a script nonce: {wcsp}");
    // WebAssembly compilation is allowed (the wallet's injected provider is
    // wasm crypto); scripts themselves still need the nonce.
    assert!(wcsp.contains("'wasm-unsafe-eval'"), "wasm compilation allowed: {wcsp}");
    assert!(!wcsp.contains("unsafe-eval'") || wcsp.contains("wasm-unsafe-eval'"), "no plain unsafe-eval");
    assert!(!wcsp.contains(" 'unsafe-eval'"), "JS eval stays blocked: {wcsp}");
    assert!(!wcsp.contains("sandbox"));

    let missing = reqwest::get(format!("http://{addr}/{xite}/nope.txt"))
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn xite_scripts_revalidate_with_etag() {
    // Xite js/css is cached with `public, no-cache` + an ETag: stored, but
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
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let sandbox_of = |html: &str| -> String {
        html.split("id='inner-iframe' sandbox=\"").nth(1).and_then(|r| r.split('"').next()).unwrap().to_string()
    };

    // Proxy request for the wrapper: Host is the xite name, path is "/". The
    // wrapper is the chrome origin; the xite page gets its own origin, the
    // content host, and because that is a real origin of its own it keeps
    // allow-same-origin (storage, service workers) without being the wrapper.
    let wrapper = client
        .get(format!("http://{addr}/"))
        .header("host", "talk.epix")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert_eq!(wrapper.status(), 200);
    let html = wrapper.text().await.unwrap();
    assert!(
        html.contains(r#"iframe_src = "//talk.content.epix/index.html?"#),
        "the frame loads from the content host: {html}"
    );
    assert!(!html.contains("/talk.epix/index.html"), "no path-prefix in host mode");
    assert!(sandbox_of(&html).contains("allow-same-origin"), "host mode: own origin: {html}");

    // The chrome host serves no xite file: every file request moves to the
    // content host (an HTML file served raw here would run as the wrapper).
    let moved = client
        .get(format!("http://{addr}/index.html?wrapper_nonce=abc"))
        .header("host", "talk.epix")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "iframe")
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), 307);
    assert_eq!(moved.headers()["location"], "//talk.content.epix/index.html?wrapper_nonce=abc");

    // The content host serves the files...
    let inner = client
        .get(format!("http://{addr}/index.html"))
        .header("host", "talk.content.epix")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "iframe")
        .send()
        .await
        .unwrap();
    assert_eq!(inner.status(), 200);
    assert_eq!(inner.text().await.unwrap(), "<h1>inner</h1>");
    // ...but never the wrapper: a document navigation there (a `_top` link
    // from inside the page, a typed URL) lands back on the chrome host.
    for path in ["/", "/index.html"] {
        let back = client
            .get(format!("http://{addr}{path}?Topic:1"))
            .header("host", "talk.content.epix")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document")
            .send()
            .await
            .unwrap();
        assert_eq!(back.status(), 307, "{path}");
        assert_eq!(back.headers()["location"], format!("//talk.epix{}?Topic:1", if path == "/" { "/" } else { path }), "{path}");
    }

    // The content host is never a wrapper: no WebSocket is accepted there,
    // and a page on it cannot open one to the chrome host either.
    use tokio_tungstenite::tungstenite::http;
    for (host, origin) in [("talk.content.epix", "http://talk.content.epix"), ("talk.epix", "http://talk.content.epix")] {
        let req = http::Request::builder()
            .uri(format!("ws://{addr}/EpixNet-Internal/Websocket?xite=talk.epix"))
            .header("Host", host)
            .header("Origin", origin)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();
        assert!(tokio_tungstenite::connect_async(req).await.is_err(), "ws refused for {host} from {origin}");
    }

    // Normal localhost path mode is unchanged: path-prefixed URLs, and the
    // page stays an opaque origin because it would share the node's.
    let path_mode = client
        .get(format!("http://{addr}/talk.epix/"))
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    let path_html = path_mode.text().await.unwrap();
    assert!(path_html.contains("/talk.epix/index.html"), "path mode keeps the prefix");
    assert!(!sandbox_of(&path_html).contains("allow-same-origin"), "path mode stays opaque: {path_html}");
    let raw = client
        .get(format!("http://{addr}/talk.epix/index.html"))
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "iframe")
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 200, "path mode serves files on the node origin");
}

#[tokio::test]
async fn transparent_proxy_redirects_cross_xite_paths_to_own_origin() {
    // In host (transparent-proxy) mode a document that targets a DIFFERENT
    // xite by path must land on that xite's own origin, not serve nested.
    // Clicking a xite on the dashboard links `/epix1talk…/`; without the
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

    // A dashboard-style xite link: another xite's address as the path.
    let talk = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";
    let r = client
        .get(format!("http://{addr}/{talk}/"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_redirection(), "cross-xite path redirects: {}", r.status());
    // Bare addresses redirect to their dotted `.epix` alias (dotless hosts
    // trip browser search fixup / proxy bypass heuristics).
    assert_eq!(r.headers()["location"].to_str().unwrap(), format!("//{talk}.epix/"));

    // Directory and query survive the redirect.
    let r = client
        .get(format!("http://{addr}/{talk}/docs/?Topic:9"))
        .header("host", "dashboard.epix")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_redirection());
    assert_eq!(r.headers()["location"].to_str().unwrap(), format!("//{talk}.epix/docs/?Topic:9"));

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
    assert!(
        html.contains(&format!(r#"iframe_src = "//{talk}.content.epix/index.html?"#)),
        "the frame loads from the address's content host: {html}"
    );

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
    let (addr, xite, _key, _dir) = start_server().await;
    // A WebSocket from a foreign Origin is refused (can't drive the local API).
    use tokio_tungstenite::tungstenite::http;
    let req = http::Request::builder()
        .uri(format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={xite}"))
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
async fn a_socket_without_the_wrapper_key_never_gains_wrapper_authority() {
    use tokio_tungstenite::tungstenite::http;
    let (addr, xite, key, _dir) = start_server().await;

    // Binding by address (a manual client, an older wrapper, or a page that
    // opened its own socket) gives a page-level session: an elevated id is
    // just a number it chose, so admin commands and grants stay refused and
    // nothing is persisted.
    let url = format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={xite}");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let denied = call(&mut ws, "siteList", 1_000_001).await;
    assert!(denied["result"]["error"].as_str().unwrap().contains("permission"), "{denied}");
    let denied = call_params(&mut ws, "permissionAdd", json!("ADMIN"), 1_000_002).await;
    assert!(denied["result"]["error"].as_str().unwrap().contains("prompt"), "{denied}");
    let info = call(&mut ws, "siteInfo", 1_000_003).await;
    assert!(info["result"]["settings"]["permissions"].as_array().unwrap().is_empty());
    // Pushed-dialog answers from such a socket are ignored (no reply at all).
    ws.send(Message::Text(
        json!({ "cmd": "response", "id": 1_000_004, "to": 1, "result": true }).to_string().into(),
    ))
    .await
    .unwrap();
    let pong = call(&mut ws, "ping", 9).await;
    assert_eq!(pong["to"], 9, "the ignored answer produced no frame of its own");

    // The real key from some other local origin (a page on another local
    // server that learned it) binds, but is not the wrapper: the wrapper's
    // socket comes from the wrapper's own origin.
    let req = http::Request::builder()
        .uri(format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={key}"))
        .header("Host", addr.to_string())
        .header("Origin", "http://localhost:3000")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.expect("loopback origins may open page sockets");
    let denied = call(&mut ws, "siteList", 1_000_001).await;
    assert!(denied["result"]["error"].as_str().unwrap().contains("permission"), "{denied}");
    let info = call(&mut ws, "siteInfo", 2).await;
    assert_eq!(info["result"]["address"].as_str(), Some(xite.as_str()), "still bound to the xite");
    // From the wrapper's origin the same key is the wrapper.
    let req = http::Request::builder()
        .uri(format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={key}"))
        .header("Host", addr.to_string())
        .header("Origin", format!("http://{addr}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    let allowed = call(&mut ws, "siteList", 1_000_001).await;
    assert!(allowed["result"].is_array(), "{allowed}");

    // A random key that matches no xite binds the same way (and to nothing).
    let url = format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={}", "f".repeat(64));
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let denied = call(&mut ws, "siteList", 1_000_001).await;
    assert!(denied["result"]["error"].is_string(), "{denied}");

    // The sandboxed inner frame is an opaque origin: a socket it opens says
    // `Origin: null` and is refused at the upgrade, whatever key it carries.
    let req = http::Request::builder()
        .uri(format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={xite}"))
        .header("Host", addr.to_string())
        .header("Origin", "null")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(())
        .unwrap();
    assert!(tokio_tungstenite::connect_async(req).await.is_err(), "null-origin WS refused");
}

#[tokio::test]
async fn own_write_is_not_echoed_back() {
    // EpixNet notifies `ws != self`: the connection whose fileWrite produced a
    // file_done must not receive the event (an echo re-renders the page
    // mid-interaction), while every other connection on the xite does.
    use base64::Engine;
    let (addr, xite, _key, _dir) = start_server().await;
    let url = format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={xite}");
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
    let (addr, xite, key, _dir) = start_server().await;
    // The wrapper page connects with the xite's secret wrapper_key: that is
    // what makes this socket the trusted chrome for the xite.
    let url = format!("ws://{addr}/EpixNet-Internal/Websocket?wrapper_key={key}");
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();

    let pong = call(&mut ws, "ping", 1).await;
    assert_eq!(pong["to"], 1);
    assert_eq!(pong["result"], "Pong!");

    let info = call(&mut ws, "serverInfo", 2).await;
    assert_eq!(info["result"]["version"], "0.1.0");

    let info = call(&mut ws, "siteInfo", 3).await;
    assert_eq!(info["result"]["address"].as_str(), Some(xite.as_str()));
    assert_eq!(info["result"]["content"]["title"], "Test Xite");
    // A xite holds no permissions until the user grants one.
    assert!(info["result"]["settings"]["permissions"].as_array().unwrap().is_empty());
    // The wrapper/AJAX secrets never travel to a page in siteInfo.
    assert!(info["result"]["settings"].get("wrapper_key").is_none(), "{info}");
    assert!(info["result"]["settings"].get("ajax_key").is_none(), "{info}");

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

/// With a UI password set, the chrome host's session cookie is host-only and
/// never reaches the content host; the wrapper's iframe document request
/// proves the session with its wrapper nonce and gets the content host a
/// session of its own. Nothing else on the content host passes without one.
#[cfg(feature = "ui-password")]
#[tokio::test]
async fn host_mode_hands_the_password_session_to_the_content_host() {
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"<h1>inner</h1>").unwrap();
    storage.write("app.js", b"1").unwrap();
    let state = AppState::new("0.1.0");
    state
        .add_xite(
            "talk.epix",
            XiteEntry {
                storage,
                content: Some(json!({ "title": "Talk", "files": { "index.html": {}, "app.js": {} } })),
            },
        )
        .await;
    state.config_set("ui_password", json!("pw")).await;
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

    // Log in on the chrome host.
    let login = client
        .post(format!("http://{addr}/Login"))
        .header("host", "talk.epix")
        .header("sec-fetch-site", "same-origin")
        .form(&[("password", "pw")])
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 303, "login accepted");
    let cookie = login.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let wrapper = client
        .get(format!("http://{addr}/"))
        .header("host", "talk.epix")
        .header("cookie", &cookie)
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .unwrap();
    let html = wrapper.text().await.unwrap();
    let nonce = html
        .split("//talk.content.epix/index.html?wrapper_nonce=")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("the frame loads from the content host with a nonce")
        .to_string();

    // The iframe document request: content host, the nonce, no cookie.
    let inner = client
        .get(format!("http://{addr}/index.html?wrapper_nonce={nonce}"))
        .header("host", "talk.content.epix")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "iframe")
        .send()
        .await
        .unwrap();
    assert_eq!(inner.status(), 200);
    let content_cookie = inner.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    assert!(content_cookie.starts_with("session_id="), "content host gets a session");
    assert_ne!(content_cookie, cookie, "a session of its own");
    assert_eq!(inner.text().await.unwrap(), "<h1>inner</h1>");

    // The page's later requests carry that cookie...
    let js = client
        .get(format!("http://{addr}/app.js"))
        .header("host", "talk.content.epix")
        .header("cookie", &content_cookie)
        .header("sec-fetch-mode", "no-cors")
        .header("sec-fetch-dest", "script")
        .send()
        .await
        .unwrap();
    assert_eq!(js.status(), 200);
    assert_eq!(js.text().await.unwrap(), "1");
    // ...and without one, or with a spent or made-up nonce, nothing passes.
    for uri in ["/app.js", &format!("/index.html?wrapper_nonce={nonce}"), "/index.html?wrapper_nonce=bogus"] {
        let locked = client
            .get(format!("http://{addr}{uri}"))
            .header("host", "talk.content.epix")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "iframe")
            .send()
            .await
            .unwrap();
        let body = locked.text().await.unwrap();
        assert!(body.contains("/Login"), "{uri} served the login page, not the file: {body}");
    }
}
