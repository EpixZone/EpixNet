//! Native-messaging host logic for the Epix browser extension.
//!
//! Firefox speaks native messaging as: a 32-bit little-endian length followed
//! by that many bytes of JSON, both directions over stdio. The extension sends
//! a request; we answer. This module has the pure request handling (so it is
//! unit-testable); `main` does the stdio framing.
//!
//! Requests the extension makes:
//! - `{"cmd":"status"}` -> `{ serving, ui_port }`
//! - `{"cmd":"resolve","name":"talk.epix"}` -> `{ address }` or `{ error }`
//! - `{"cmd":"getClearnetAllow","xite":"talk.epix"}` -> `{ allow: bool }`
//! - `{"cmd":"setClearnetAllow","xite":"talk.epix","allow":true}` -> `{ ok }`
//! - `{"cmd":"listClearnetAllow"}` -> `{ xites: [..] }`
//! - `{"cmd":"ledgerList"}` -> `{ devices: [..] }` (Ledger over HID)
//! - `{"cmd":"ledgerExchange","apdu":"<hex>"}` -> `{ response: "<hex>" }`

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub mod ledger;

/// Per-browser settings persisted next to the node data (which xites may reach
/// clearnet). The extension enforces the block; this is the source of truth.
pub struct Settings {
    path: PathBuf,
}

impl Settings {
    pub fn new(data_root: &Path) -> Self {
        Self { path: data_root.join("browser-settings.json") }
    }

    fn read(&self) -> Value {
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| json!({ "clearnet_allow": {} }))
    }

    fn write(&self, v: &Value) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(v) {
            let _ = std::fs::write(&self.path, bytes);
        }
    }

    pub fn clearnet_allowed(&self, xite: &str) -> bool {
        self.read()
            .get("clearnet_allow")
            .and_then(|m| m.get(xite))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    pub fn set_clearnet_allowed(&self, xite: &str, allow: bool) {
        let mut v = self.read();
        let map = v
            .get_mut("clearnet_allow")
            .and_then(|m| m.as_object_mut());
        if let Some(map) = map {
            if allow {
                map.insert(xite.to_string(), json!(true));
            } else {
                map.remove(xite);
            }
        } else {
            v["clearnet_allow"] = json!({ xite: allow });
        }
        self.write(&v);
    }

    pub fn allowed_xites(&self) -> Vec<String> {
        self.read()
            .get("clearnet_allow")
            .and_then(|m| m.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The node data root these settings live in (parent of the settings file).
    pub fn data_root(&self) -> Option<&Path> {
        self.path.parent()
    }

    /// Whether the user routes clearnet (non-`.epix`) browsing through Tor.
    pub fn tor_clearnet(&self) -> bool {
        // Default on (opt-out): clearnet routes through Tor unless turned off.
        self.read().get("tor_clearnet").and_then(|v| v.as_bool()).unwrap_or(true)
    }

    pub fn set_tor_clearnet(&self, on: bool) {
        let mut v = self.read();
        v["tor_clearnet"] = json!(on);
        self.write(&v);
    }
}

/// Handle one request, returning the response value. `resolve` is async, so
/// this returns a future.
/// Query a loopback node endpoint with a hard timeout. Without one, a wrong or
/// half-open listener on the UI port - e.g. a stray standalone node holding the
/// default port - makes the request hang forever. The host would then never
/// return to read stdin, never see Firefox close the pipe, and never exit; so
/// Firefox spawns a fresh host on every poll and they pile up (we have seen
/// 100+). The timeout makes the query fail fast so the host answers best-effort
/// and exits cleanly.
async fn node_get(url: &str) -> reqwest::Result<reqwest::Response> {
    reqwest::Client::new()
        .get(url)
        .timeout(std::time::Duration::from_secs(4))
        .send()
        .await
}

async fn node_resolve(ui_port: u16, token: &str, name: &str) -> Result<String, String> {
    let url = format!("http://127.0.0.1:{ui_port}{}", epix_node::NMH_RESOLVE_PATH);
    let nonce = epix_node::new_nmh_nonce()?;
    let request_mac = epix_node::nmh_request_mac(token, &nonce, name)?;
    let mut response = reqwest::Client::new()
        .post(url)
        .json(&json!({
            "name": name,
            "nonce": nonce,
            "mac": request_mac,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("node resolve endpoint unavailable: {e}"))?;
    let status = response.status();
    // Enforce the size cap DURING the read, not after: a stale or hostile
    // process squatting the loopback UI port could otherwise stream an
    // unbounded body that `bytes()` buffers entirely into memory before any
    // check. Reject an oversized Content-Length up front, then accumulate
    // chunk-by-chunk and bail the instant the running total exceeds the cap.
    const MAX_BODY: usize = 16 * 1024;
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BODY as u64)
    {
        return Err("invalid node resolve response: body is too large".to_string());
    }
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("invalid node resolve response: {e}"))?
    {
        if bytes.len() + chunk.len() > MAX_BODY {
            return Err("invalid node resolve response: body is too large".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid node resolve response: {e}"))?;
    let response_nonce = body
        .get("nonce")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if response_nonce != nonce {
        return Err("node resolve response authentication failed".to_string());
    }
    let address = body.get("address").and_then(Value::as_str);
    let error = body.get("error").and_then(Value::as_str);
    let response_mac = body.get("mac").and_then(Value::as_str).unwrap_or_default();
    if !epix_node::nmh_response_mac_valid(
        token,
        &nonce,
        name,
        status.as_u16(),
        address,
        error,
        response_mac,
    ) {
        return Err("node resolve response authentication failed".to_string());
    }
    if !status.is_success() {
        return Err(error
            .unwrap_or("node rejected the resolve request")
            .to_string());
    }
    address
        .filter(|address| !address.is_empty())
        .map(str::to_string)
        .ok_or_else(|| "node resolve response has no address".to_string())
}

pub async fn handle(req: &Value, settings: &Settings, ui_port: u16) -> Value {
    let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    match cmd {
        "status" => {
            // Fetch the node's status (Tor state + onion) over loopback; fall
            // back to a plain connect check if it isn't answering yet.
            let url = format!("http://127.0.0.1:{ui_port}/EpixNet-Internal/Status");
            match node_get(&url).await.and_then(|r| r.error_for_status()) {
                Ok(resp) => match resp.json::<Value>().await {
                    Ok(mut v) => {
                        v["ui_port"] = json!(ui_port);
                        v["tor_clearnet"] = json!(settings.tor_clearnet());
                        v
                    }
                    Err(_) => json!({ "serving": true, "ui_port": ui_port }),
                },
                Err(_) => {
                    let serving = std::net::TcpStream::connect(("127.0.0.1", ui_port)).is_ok();
                    json!({ "serving": serving, "ui_port": ui_port })
                }
            }
        }
        "getTorClearnet" => json!({ "on": settings.tor_clearnet() }),
        "setTorClearnet" => {
            let on = req.get("on").and_then(|v| v.as_bool()).unwrap_or(false);
            settings.set_tor_clearnet(on);
            json!({ "ok": true, "on": on })
        }
        "resolve" => {
            let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let target = epix_node::parse_target(name);
            let (label, tld) = target.rsplit_once('.').unwrap_or((target.as_str(), "epix"));
            match epix_core::classify_label(label) {
                epix_core::LabelClass::Address => return json!({ "address": label }),
                epix_core::LabelClass::AddressShaped => {
                    return json!({
                        "error": format!(
                            "{label} looks like a mistyped epix1 address (bad checksum)"
                        )
                    });
                }
                epix_core::LabelClass::Name => {}
            }
            let full = format!("{label}.{tld}");
            let Some(data_root) = settings.data_root() else {
                return json!({ "error": "native-messaging data root is unavailable" });
            };
            let token = match epix_node::read_nmh_auth_token(data_root) {
                Ok(token) => token,
                Err(error) => return json!({ "error": error }),
            };
            match node_resolve(ui_port, &token, &full).await {
                Ok(address) => json!({ "address": address }),
                Err(error) => json!({ "error": format!("resolve {full}: {error}") }),
            }
        }
        "getClearnetAllow" => {
            let xite = req.get("site").and_then(|v| v.as_str()).unwrap_or("");
            json!({ "allow": settings.clearnet_allowed(xite) })
        }
        "setClearnetAllow" => {
            let xite = req.get("site").and_then(|v| v.as_str()).unwrap_or("");
            let allow = req.get("allow").and_then(|v| v.as_bool()).unwrap_or(false);
            if !xite.is_empty() {
                settings.set_clearnet_allowed(xite, allow);
            }
            json!({ "ok": true, "site": xite, "allow": allow })
        }
        "listClearnetAllow" => json!({ "sites": settings.allowed_xites() }),
        // Ledger hardware wallet over HID (see src/ledger.rs). Blocking HID
        // I/O, so run it off the async runtime's worker.
        "ledgerList" => ledger::list(),
        "ledgerExchange" => {
            let req = req.clone();
            tokio::task::spawn_blocking(move || ledger::exchange(&req))
                .await
                .unwrap_or_else(|e| json!({ "error": format!("ledger task: {e}") }))
        }
        other => json!({ "error": format!("unknown command: {other}") }),
    }
}

/// Read one native-messaging frame (4-byte LE length + JSON) from `r`. Returns
/// `Ok(None)` on clean EOF.
pub fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    // Firefox caps outgoing messages at 1 MB; guard against a bad length.
    if len > 8 * 1024 * 1024 {
        return Err(std::io::Error::other("native message too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    let v = serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::other(format!("bad json: {e}")))?;
    Ok(Some(v))
}

/// Write one native-messaging frame (4-byte LE length + JSON) to `w`.
pub fn write_frame<W: Write>(w: &mut W, v: &Value) -> std::io::Result<()> {
    let body = serde_json::to_vec(v)?;
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrips() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &json!({ "cmd": "status" })).unwrap();
        // 4-byte length prefix then the JSON.
        assert_eq!(u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize, buf.len() - 4);
        let mut cur = std::io::Cursor::new(buf);
        let v = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(v["cmd"], "status");
        // Clean EOF -> None.
        assert!(read_frame(&mut cur).unwrap().is_none());
    }

    #[tokio::test]
    async fn clearnet_allow_get_set_persist() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::new(dir.path());

        // Default: not allowed.
        let r = handle(&json!({ "cmd": "getClearnetAllow", "site": "talk.epix" }), &settings, 1).await;
        assert_eq!(r["allow"], false);

        // Allow it, then read back (persists to disk).
        handle(&json!({ "cmd": "setClearnetAllow", "site": "talk.epix", "allow": true }), &settings, 1).await;
        let settings2 = Settings::new(dir.path());
        assert!(settings2.clearnet_allowed("talk.epix"));

        let list = handle(&json!({ "cmd": "listClearnetAllow" }), &settings2, 1).await;
        assert_eq!(list["sites"], json!(["talk.epix"]));

        // Revoking removes it.
        handle(&json!({ "cmd": "setClearnetAllow", "site": "talk.epix", "allow": false }), &settings2, 1).await;
        assert!(!Settings::new(dir.path()).clearnet_allowed("talk.epix"));
    }

    #[tokio::test]
    async fn unknown_command_errors() {
        let dir = tempfile::tempdir().unwrap();
        let s = Settings::new(dir.path());
        let r = handle(&json!({ "cmd": "bogus" }), &s, 1).await;
        assert!(r["error"].as_str().unwrap().contains("unknown command"));
    }

    #[tokio::test]
    async fn resolve_never_uses_an_unbound_cache_without_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::new(dir.path());
        std::fs::write(
            dir.path().join("resolve-cache.json"),
            serde_json::to_vec(&json!({
                "talk.epix": {
                    "address": "epix1forged",
                    "resolved_at": u64::MAX,
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let response = handle(
            &json!({ "cmd": "resolve", "name": "talk.epix" }),
            &settings,
            1,
        )
        .await;
        assert!(response.get("address").is_none());
        assert!(response["error"]
            .as_str()
            .unwrap()
            .contains("native-messaging token"));
    }

    #[tokio::test]
    async fn dotted_epix1_brand_name_is_delegated_not_treated_as_an_address() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::new(dir.path());
        let response = handle(
            &json!({ "cmd": "resolve", "name": "epix1shop.epix" }),
            &settings,
            1,
        )
        .await;
        assert!(response.get("address").is_none());
        assert!(response.get("error").is_some());
    }

    #[tokio::test]
    async fn checksum_valid_address_resolves_without_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::new(dir.path());
        let address = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let response = handle(
            &json!({ "cmd": "resolve", "name": format!("{address}.epix") }),
            &settings,
            1,
        )
        .await;
        assert_eq!(response["address"], address);
    }

    #[tokio::test]
    async fn address_shaped_bad_checksum_is_rejected_locally() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::new(dir.path());
        let response = handle(
            &json!({
                "cmd": "resolve",
                "name": "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6q.epix"
            }),
            &settings,
            1,
        )
        .await;
        assert!(response.get("address").is_none());
        assert!(response["error"].as_str().unwrap().contains("bad checksum"));
    }

    #[tokio::test]
    async fn stale_port_cannot_forge_a_response_or_receive_the_secret() {
        let token = "66".repeat(32);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request_tx, request_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            use std::io::{Read as _, Write as _};

            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut end = None;
            let mut content_len = None;
            loop {
                let mut chunk = [0u8; 4096];
                let read = stream.read(&mut chunk).unwrap();
                assert!(read != 0, "request ended before its body arrived");
                request.extend_from_slice(&chunk[..read]);
                if end.is_none() {
                    end = request.windows(4).position(|window| window == b"\r\n\r\n");
                    if let Some(header_end) = end {
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        content_len = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        });
                    }
                }
                if let (Some(header_end), Some(content_len)) = (end, content_len) {
                    if request.len() >= header_end + 4 + content_len {
                        break;
                    }
                }
            }
            let header_end = end.unwrap();
            let request_body = &request[header_end + 4..];
            let parsed: Value = serde_json::from_slice(request_body).unwrap();
            let nonce = parsed["nonce"].as_str().unwrap();
            let forged = json!({
                "nonce": nonce,
                "address": "epix1forged",
                "mac": "00".repeat(32),
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                forged.len(),
                forged,
            )
            .unwrap();
            stream.flush().unwrap();
            request_tx.send(request).unwrap();
        });

        let error = node_resolve(port, &token, "talk.epix").await.unwrap_err();
        assert!(error.contains("response authentication failed"));
        let request = request_rx.recv().unwrap();
        assert!(
            !request
                .windows(token.len())
                .any(|window| window == token.as_bytes()),
            "the raw native-messaging secret was sent to the stale listener"
        );
        server.join().unwrap();
    }
}
