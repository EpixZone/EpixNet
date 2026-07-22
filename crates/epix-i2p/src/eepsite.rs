//! Outbound eepsite access for the browser's `.i2p` HTTP proxy: resolve a
//! hostname or `.b32.i2p` via the router's naming service and open SAM streams
//! to the destination. Reuses one transient outbound session across requests
//! (the same tunnels), with the wedged-session rebuild [`crate::I2pTransport`]
//! uses - the SAM plumbing stays in this crate so the browser only speaks HTTP.

use crate::{dial_once, Error, Result};
use epix_transport::PeerStream;
use std::sync::Arc;
use tokio::sync::Mutex;
use yosemite::{style::Stream, RouterApi, Session};

/// A shared handle for dialing eepsites: cheap to clone, one SAM session
/// behind it. `sam_port` is passed per call because the router (and its port)
/// can come up after the proxy starts listening.
#[derive(Clone, Default)]
pub struct EepsiteDialer {
    session: Arc<Mutex<Option<Session<Stream>>>>,
}

impl EepsiteDialer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a stream to `destination` (I2P base64) through the router at
    /// `sam_port`. A wedged session is dropped and rebuilt once, like the peer
    /// transport; a clean per-site failure (unreachable destination) is
    /// surfaced as-is.
    pub async fn connect(&self, sam_port: u16, destination: &str) -> Result<PeerStream> {
        let mut guard = self.session.lock().await;
        match dial_once(&mut guard, sam_port, destination).await {
            Ok(stream) => Ok(stream),
            Err((e, retry)) if !retry => Err(e),
            Err(_) => dial_once(&mut guard, sam_port, destination).await.map_err(|(e, _)| e),
        }
    }

    /// Resolve `name` (an addressbook hostname like `web.telegram.i2p`, or a
    /// `.b32.i2p` address) to its base64 destination via the router's naming
    /// service (SAM `NAMING LOOKUP`).
    pub async fn lookup(sam_port: u16, name: &str) -> Result<String> {
        RouterApi::new(sam_port)
            .lookup_name(name)
            .await
            .map_err(|e| Error::Protocol(format!("i2p name lookup {name}: {e}")))
    }
}
