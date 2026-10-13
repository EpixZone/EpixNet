//! Serve one signed fixture xite through the real UI server for a browser
//! check of the wrapper sandbox (`docs/wrapper-sandbox.md`).
//!
//! The fixture page exercises everything an opaque-origin xite page does:
//! a classic script, a stylesheet, an ES module, an XHR keyed with the
//! `ajax_key` it asks the wrapper for, a WebSocket it opens itself (which the
//! node must refuse), and an attempt to reach the wrapper window. It records
//! each outcome on `window.results` for the driver to read.
//!
//! Run: `cargo run -p epix-ui --example wrapper_fixture [port]`; it prints the
//! wrapper URL and serves until killed. With `--host`, it instead serves host
//! mode the way the Epix browser does: through the browsers' TLS proxy
//! (`epix-browser-net`), so `https://<xite>.epix/` is the wrapper and
//! `https://<xite>.content.epix/` the page's own origin. It then prints the
//! proxy address and the CA certificate path; point a browser at that proxy.

use epix_evx::EvxPlugin;
use epix_plugin::PluginRegistry;
use epix_ui::{AppState, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;

/// The fixture's declared program: adds two numbers, no capabilities.
const CALC: &str = r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#;

const INDEX: &str = r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Sandbox fixture</title>
<link rel="stylesheet" href="style.css">
<script src="classic.js"></script>
<script type="module" src="module.js"></script>
</head><body><p id="p">fixture</p>
<script>
window.results = window.results || {};
var results = window.results;
try { results.parentAccess = typeof parent.document; } catch (e) { results.parentAccess = e.name; }
try { localStorage.setItem("a", "b"); results.localStorage = "ok"; } catch (e) { results.localStorage = e.name; }
results.origin = window.origin;
try {
  var sw = navigator.serviceWorker;
  results.serviceWorker = typeof sw;
  if (sw) { sw.register("sw.js").then(function () { results.serviceWorkerRegistered = true; }, function (e) { results.serviceWorkerRegistered = e.name; }); }
} catch (e) { results.serviceWorker = e.name; }
// The wrapper's page must stay unreadable from here (cross-origin).
fetch(location.protocol + "//" + location.host.replace(".content.epix", ".epix") + "/", { mode: "cors" })
  .then(function (r) { return r.text(); })
  .then(function (t) { results.wrapperPageReadable = t.length > 0; }, function () { results.wrapperPageReadable = false; });
// The frame library's flow: ask the wrapper for the ajax key, then fetch.
var pending = {};
var next = 1;
function cmd(name, params) {
  return new Promise(function (resolve) {
    var id = next++;
    pending[id] = resolve;
    parent.postMessage({ cmd: name, params: params || {}, id: id }, "*");
  });
}
window.addEventListener("message", function (e) {
  var m = e.data;
  if (m && m.cmd === "response" && pending[m.to]) { pending[m.to](m.result); delete pending[m.to]; }
  if (m && m.cmd === "wrapperOpenedWebsocket") { results.wrapperSocket = "open"; }
});
cmd("wrapperGetAjaxKey").then(function (key) {
  results.ajaxKeyLength = (key || "").length;
  var x = new XMLHttpRequest();
  x.open("GET", "data.json?ajax_key=" + key);
  x.onloadend = function () { results.keyedXhr = x.status; results.keyedXhrBody = x.responseText; };
  x.send();
  var y = new XMLHttpRequest();
  y.open("GET", "data.json");
  y.onloadend = function () { results.keylessXhr = y.status; results.keylessXhrBody = y.responseText; };
  y.send();
  return cmd("siteInfo");
}).then(function (info) {
  results.siteInfoAddress = info && info.address;
  results.siteInfoHasSecrets = !!(info && info.settings && (info.settings.wrapper_key || info.settings.ajax_key));
});
try {
  var ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/EpixNet-Internal/Websocket?xite=" + location.host.split(".")[0]);
  ws.onerror = function () { results.ownSocket = "refused"; };
  ws.onopen = function () { results.ownSocket = "open"; };
} catch (e) { results.ownSocket = e.name; }
// EVX: the driver calls these from outside; the page only ever asks.
window.evxRequest = function (program) { return cmd("evxRequest", { program: program }).then(function (r) { results.evx = r; return r; }); };
window.evxStatus = function () { return cmd("evxStatus", {}).then(function (r) { results.evxStatus = r; return r; }); };
window.evxGrantDirect = function () { return cmd("evxGrant", { xite: "x", declaration_digest: "0", mode: "enable" }).then(function (r) { results.evxDirect = r; return r; }); };
window.addEventListener("load", function () {
  results.classic = window.classic_loaded === true;
  results.styled = getComputedStyle(document.getElementById("p")).color;
  setTimeout(function () { results.module = window.module_loaded === true; }, 200);
});
</script></body></html>
"#;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host_mode = args.iter().any(|a| a == "--host");
    let port: u16 = args.iter().find_map(|a| a.parse().ok()).unwrap_or(0);
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    let module = evx_runtime::text_to_binary(CALC).expect("fixture program");
    let files: Vec<(&str, &[u8])> = vec![
        ("evx/calc.wasm", &module),
        ("index.html", INDEX.as_bytes()),
        ("style.css", b"#p { color: rgb(0, 128, 0); }"),
        ("classic.js", b"window.classic_loaded = true;"),
        ("module.js", b"window.module_loaded = true; export const ok = true;"),
        ("data.json", br#"{"fixture":true}"#),
        ("sw.js", b"self.addEventListener('fetch', function () {});"),
    ];
    let mut manifest_files = serde_json::Map::new();
    for (name, bytes) in &files {
        storage.write(name, bytes).unwrap();
        manifest_files.insert(
            (*name).to_string(),
            json!({ "size": bytes.len(), "sha512": XiteStorage::hash_bytes(bytes) }),
        );
    }
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let mut root = json!({
        "address": address,
        "title": "Sandbox fixture",
        "modified": 1.0,
        "files": manifest_files,
        "evx": {
            "version": 1,
            "programs": {
                "calc": {
                    "runtime_profile": "wasm-core-v1",
                    "entry": "evx/calc.wasm",
                    "allow_run_once": true,
                    "capabilities": []
                }
            }
        }
    });
    epix_content::sign(&mut root, &key).unwrap();
    storage
        .write("content.json", epix_content::dumps_content(&root).as_bytes())
        .unwrap();

    // A data root, so the EVX grant store and workspaces have a home.
    let data = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("fixture", data.path());
    state
        .add_xite(&address, XiteEntry { storage, content: Some(root) })
        .await;
    state.set_owned(&address, true).await;
    // The node's plugin set as far as EVX is concerned: the worker comes from
    // EVX_WORKER (or beside this executable).
    let mut plugins = PluginRegistry::new();
    plugins.register(std::sync::Arc::new(EvxPlugin::default()));
    plugins.start_all(&state);
    let registry = plugins.command_registry();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    if host_mode {
        // What epix-browser does: the router behind the host rewrite, served
        // by the TLS-terminating proxy with a per-install CA.
        let ca_dir = tempfile::tempdir().unwrap();
        let ca = std::sync::Arc::new(
            epix_browser_net::ca::LocalCa::load_or_create(ca_dir.path()).expect("local CA"),
        );
        let ca_pem = ca_dir.path().join("ca.pem");
        std::fs::write(&ca_pem, ca.cert_pem()).unwrap();
        let app = tower::ServiceExt::<axum::extract::Request>::map_request(
            UiServer::with_registry(state, registry).router(),
            epix_ui::rewrite_proxy_host,
        );
        let secure = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        println!("fixture https://{address}.epix/ proxy {addr} ca {}", ca_pem.display());
        epix_browser_net::proxy::serve(listener, app, ca, secure).await.unwrap();
        drop(ca_dir);
    } else {
        println!("fixture http://{addr}/{address}/");
        let router = UiServer::with_registry(state, registry).router();
        axum::serve(listener, router).await.unwrap();
    }
    drop(data);
    drop(dir);
}
