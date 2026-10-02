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
//! wrapper URL and serves until killed.

use epix_ui::{AppState, UiServer, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::json;

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
  var ws = new WebSocket("ws://" + location.host + "/EpixNet-Internal/Websocket?wrapper_key=" + location.pathname.split("/")[1]);
  ws.onerror = function () { results.ownSocket = "refused"; };
  ws.onopen = function () { results.ownSocket = "open"; };
} catch (e) { results.ownSocket = e.name; }
window.addEventListener("load", function () {
  results.classic = window.classic_loaded === true;
  results.styled = getComputedStyle(document.getElementById("p")).color;
  setTimeout(function () { results.module = window.module_loaded === true; }, 200);
});
</script></body></html>
"#;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    let files: Vec<(&str, &[u8])> = vec![
        ("index.html", INDEX.as_bytes()),
        ("style.css", b"#p { color: rgb(0, 128, 0); }"),
        ("classic.js", b"window.classic_loaded = true;"),
        ("module.js", b"window.module_loaded = true; export const ok = true;"),
        ("data.json", br#"{"fixture":true}"#),
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
    });
    epix_content::sign(&mut root, &key).unwrap();
    storage
        .write("content.json", epix_content::dumps_content(&root).as_bytes())
        .unwrap();

    let state = AppState::new("fixture");
    state
        .add_xite(&address, XiteEntry { storage, content: Some(root) })
        .await;
    state.set_owned(&address, true).await;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    println!("fixture http://{addr}/{address}/");
    let router = UiServer::new(state).router();
    axum::serve(listener, router).await.unwrap();
    drop(dir);
}
