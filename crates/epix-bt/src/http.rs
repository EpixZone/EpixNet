//! The HTTP client every web-seed / `.torrent` fetch uses.
//!
//! Mirrors `epix-chain`'s pattern: a process-global SOCKS setting so fetches
//! route through the node's Tor listener (`socks5h://127.0.0.1:<port>`), and a
//! Tor-required gate so that in Tor-always mode a fetch is REFUSED until Tor is
//! up rather than leaking the node's real IP over clearnet. `socks5h` keeps DNS
//! resolution inside Tor too, so the web-seed hostname is never resolved
//! locally.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::time::Duration;

static BT_SOCKS: RwLock<Option<String>> = RwLock::new(None);
static REQUIRE_TOR: AtomicBool = AtomicBool::new(false);

/// Route all BitTorrent HTTP fetches through `socks` (e.g.
/// `socks5h://127.0.0.1:43111`), or clearnet when `None`. Set by the node as
/// its Tor state changes.
pub fn set_socks(socks: Option<String>) {
    if let Ok(mut w) = BT_SOCKS.write() {
        *w = socks.filter(|s| !s.is_empty());
    }
}

/// In Tor-always mode a fetch before the SOCKS proxy is wired would egress over
/// clearnet and leak the IP + the web-seed host, so it is refused until Tor is
/// ready (the caller retries). A no-op otherwise.
pub fn set_require_tor(required: bool) {
    REQUIRE_TOR.store(required, Ordering::Relaxed);
}

fn socks() -> Option<String> {
    BT_SOCKS.read().ok().and_then(|s| s.clone())
}

/// Whether a fetch may egress right now.
pub fn egress_ok() -> Result<(), HttpError> {
    if REQUIRE_TOR.load(Ordering::Relaxed) && socks().is_none() {
        return Err(HttpError::TorNotReady);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("Tor-always mode: fetch blocked until Tor is ready")]
    TorNotReady,
    #[error("http client: {0}")]
    Client(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("unexpected status {0}")]
    Status(u16),
}

/// Build a client honoring the current SOCKS setting. Cheap to call per fetch;
/// reqwest clients share a connection pool internally when cloned, but the
/// engine holds one and reuses it, so this is mainly for one-shot fetches
/// (a `.torrent`).
pub fn client(timeout: Duration) -> Result<reqwest::Client, HttpError> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(s) = socks() {
        let proxy = reqwest::Proxy::all(&s).map_err(|e| HttpError::Client(e.to_string()))?;
        builder = builder.proxy(proxy);
    }
    builder.build().map_err(|e| HttpError::Client(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_gate_blocks_until_socks_is_set() {
        set_require_tor(true);
        set_socks(None);
        assert!(matches!(egress_ok(), Err(HttpError::TorNotReady)));
        set_socks(Some("socks5h://127.0.0.1:43111".into()));
        assert!(egress_ok().is_ok());
        // A built client with the proxy set is Ok.
        assert!(client(Duration::from_secs(5)).is_ok());
        // Reset globals so other tests aren't affected.
        set_require_tor(false);
        set_socks(None);
    }
}
