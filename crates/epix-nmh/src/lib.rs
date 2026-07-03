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
//! - `{"cmd":"getClearnetAllow","site":"talk.epix"}` -> `{ allow: bool }`
//! - `{"cmd":"setClearnetAllow","site":"talk.epix","allow":true}` -> `{ ok }`
//! - `{"cmd":"listClearnetAllow"}` -> `{ sites: [..] }`

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Per-browser settings persisted next to the node data (which sites may reach
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

    pub fn clearnet_allowed(&self, site: &str) -> bool {
        self.read()
            .get("clearnet_allow")
            .and_then(|m| m.get(site))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    pub fn set_clearnet_allowed(&self, site: &str, allow: bool) {
        let mut v = self.read();
        let map = v
            .get_mut("clearnet_allow")
            .and_then(|m| m.as_object_mut());
        if let Some(map) = map {
            if allow {
                map.insert(site.to_string(), json!(true));
            } else {
                map.remove(site);
            }
        } else {
            v["clearnet_allow"] = json!({ site: allow });
        }
        self.write(&v);
    }

    pub fn allowed_sites(&self) -> Vec<String> {
        self.read()
            .get("clearnet_allow")
            .and_then(|m| m.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Handle one request, returning the response value. `resolve` is async (chain
/// lookup), so this returns a future.
pub async fn handle(req: &Value, settings: &Settings, ui_port: u16) -> Value {
    let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    match cmd {
        "status" => {
            let serving =
                std::net::TcpStream::connect(("127.0.0.1", ui_port)).is_ok();
            json!({ "serving": serving, "ui_port": ui_port })
        }
        "resolve" => {
            let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let target = epix_node::parse_target(name);
            let (label, tld) = target.rsplit_once('.').unwrap_or((target.as_str(), "epix"));
            if label.starts_with("epix1") {
                return json!({ "address": label });
            }
            let resolver = epix_chain::XidResolver::new(epix_chain::DEFAULT_RPC_URL);
            match resolver.resolve(label, tld).await {
                Ok(d) => match d.xite_address() {
                    Some(a) => json!({ "address": a.to_string() }),
                    None => json!({ "error": format!("{label}.{tld} has no xite address") }),
                },
                Err(e) => json!({ "error": format!("resolve {label}.{tld}: {e}") }),
            }
        }
        "getClearnetAllow" => {
            let site = req.get("site").and_then(|v| v.as_str()).unwrap_or("");
            json!({ "allow": settings.clearnet_allowed(site) })
        }
        "setClearnetAllow" => {
            let site = req.get("site").and_then(|v| v.as_str()).unwrap_or("");
            let allow = req.get("allow").and_then(|v| v.as_bool()).unwrap_or(false);
            if !site.is_empty() {
                settings.set_clearnet_allowed(site, allow);
            }
            json!({ "ok": true, "site": site, "allow": allow })
        }
        "listClearnetAllow" => json!({ "sites": settings.allowed_sites() }),
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
}
