//! I2P transport for Epix.
//!
//! I2P peers are `.b32.i2p` destinations. Reaching them needs an I2P **router**
//! (which does the garlic routing) that the app talks to over the **SAMv3**
//! bridge. This crate provides:
//!
//! - [`I2p::start`] - bring up I2P: either an **embedded** pure-Rust router
//!   ([emissary], no separate process, the default) or an **external** router a
//!   power user already runs (i2pd / Java I2P), reached at its SAM port.
//! - [`I2pTransport`] - dial a `.b32.i2p` peer, yielding an
//!   [`epix_transport::PeerStream`] the wire protocol runs over, exactly like
//!   TCP or Tor.
//! - an inbound accept loop, so the node is reachable over I2P (its own
//!   destination), the way [`epix_tor`]'s onion service gives inbound Tor.
//!
//! The SAM client is [`yosemite`]; the router backend is swappable behind it.
//!
//! [emissary]: https://github.com/eepnet/emissary

use async_trait::async_trait;
use epix_core::{Error, PeerAddr, Result};
use epix_transport::{PeerStream, Transport};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use yosemite::{style::Stream, Session, SessionOptions};

mod router;

/// How I2P is provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I2pMode {
    /// I2P off.
    Disable,
    /// Embedded emissary router, in-process (no separate daemon). Default.
    Embedded,
    /// An external router (i2pd / Java I2P) the user already runs, at
    /// `sam_tcp_port`.
    External,
}

impl I2pMode {
    /// Parse the config value (`disable`/`embedded`/`external`); unknown falls
    /// back to `Disable`.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "embedded" | "enable" | "on" => I2pMode::Embedded,
            "external" => I2pMode::External,
            _ => I2pMode::Disable,
        }
    }
}

/// I2P startup configuration.
pub struct I2pConfig {
    pub mode: I2pMode,
    /// External router's SAM TCP port (I2P's default is 7656). Ignored for
    /// the embedded router, which binds its own and reports it back.
    pub sam_tcp_port: u16,
    /// Where the embedded router keeps its state (netdb, keys). A subdir of
    /// the node's data root.
    pub data_dir: std::path::PathBuf,
}

impl Default for I2pConfig {
    fn default() -> Self {
        Self {
            mode: I2pMode::Disable,
            sam_tcp_port: 7656,
            data_dir: std::path::PathBuf::from("i2p"),
        }
    }
}

/// A running I2P integration: the SAM endpoint to use, our own inbound
/// destination, and (for embedded) the router task kept alive.
pub struct I2p {
    /// SAM TCP port yosemite connects to (embedded router's or external).
    sam_port: u16,
    /// Our inbound `.b32.i2p` destination - the address peers dial us at.
    destination: String,
    /// Keeps the embedded router future running for the process lifetime.
    _router: Option<router::EmbeddedRouter>,
}

impl I2p {
    /// Bring up I2P per `config`. Returns the handle and a receiver of inbound
    /// peer streams (empty stream forever if disabled). For the embedded
    /// router this reseeds and builds tunnels on first run, which takes a few
    /// minutes - the returned future resolves once SAM is reachable and our
    /// inbound session is created.
    pub async fn start(config: I2pConfig) -> Result<(Self, mpsc::Receiver<PeerStream>)> {
        let (tx, rx) = mpsc::channel::<PeerStream>(16);

        let (sam_port, router) = match config.mode {
            I2pMode::Disable => return Ok((disabled(), rx)),
            I2pMode::External => (config.sam_tcp_port, None),
            I2pMode::Embedded => {
                let started = router::EmbeddedRouter::start(&config.data_dir).await?;
                (started.sam_port(), Some(started))
            }
        };

        // Inbound: a server session whose destination is our advertised I2P
        // address; accept streams forever and hand them to the node's server.
        let mut inbound = new_session(sam_port).await?;
        let destination = inbound.destination().to_string();
        tokio::spawn(async move {
            loop {
                match inbound.accept().await {
                    Ok(stream) => {
                        if tx.send(Box::pin(stream) as PeerStream).await.is_err() {
                            break; // node shut down
                        }
                    }
                    Err(e) => {
                        tracing::debug!(target: "epix::i2p", "i2p accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            }
        });

        Ok((Self { sam_port, destination, _router: router }, rx))
    }

    /// The peer transport that dials `.b32.i2p` peers over this router.
    pub fn transport(&self) -> I2pTransport {
        I2pTransport { sam_port: self.sam_port, outbound: Arc::new(Mutex::new(None)) }
    }

    /// Our inbound `.b32.i2p` destination - advertise this so peers can dial us.
    pub fn destination(&self) -> &str {
        &self.destination
    }
}

/// A disabled I2P handle: no router, no destination.
fn disabled() -> I2p {
    I2p { sam_port: 0, destination: String::new(), _router: None }
}

/// Create a SAM stream session against the router at `sam_port`.
async fn new_session(sam_port: u16) -> Result<Session<Stream>> {
    let options = SessionOptions { samv3_tcp_port: sam_port, ..Default::default() };
    Session::<Stream>::new(options).await.map_err(|e| Error::Protocol(format!("i2p session: {e}")))
}

/// Dials `.b32.i2p` peers through a router's SAM bridge. Holds one persistent
/// outbound session (built lazily on first dial) so every dial reuses the same
/// tunnels instead of rebuilding them.
pub struct I2pTransport {
    sam_port: u16,
    outbound: Arc<Mutex<Option<Session<Stream>>>>,
}

#[async_trait]
impl Transport for I2pTransport {
    fn scheme(&self) -> &'static str {
        "i2p"
    }

    async fn dial(&self, addr: &PeerAddr) -> Result<PeerStream> {
        let dest = addr
            .i2p_dest()
            .ok_or_else(|| Error::Protocol(format!("I2pTransport cannot dial `{}`", addr.scheme())))?;
        let mut guard = self.outbound.lock().await;
        if guard.is_none() {
            *guard = Some(new_session(self.sam_port).await?);
        }
        let session = guard.as_mut().expect("session just set");
        let stream = session
            .connect(&dest)
            .await
            .map_err(|e| Error::Protocol(format!("i2p connect {dest}: {e}")))?;
        Ok(Box::pin(stream) as PeerStream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parses_config_values() {
        assert_eq!(I2pMode::parse("embedded"), I2pMode::Embedded);
        assert_eq!(I2pMode::parse("External"), I2pMode::External);
        assert_eq!(I2pMode::parse("disable"), I2pMode::Disable);
        assert_eq!(I2pMode::parse(""), I2pMode::Disable);
        assert_eq!(I2pMode::parse("on"), I2pMode::Embedded);
    }

    #[tokio::test]
    async fn disabled_mode_starts_with_no_router() {
        let (i2p, _rx) =
            I2p::start(I2pConfig { mode: I2pMode::Disable, ..Default::default() }).await.unwrap();
        assert!(i2p.destination().is_empty());
    }

    #[tokio::test]
    async fn transport_rejects_non_i2p_addresses() {
        let t = I2pTransport { sam_port: 0, outbound: Arc::new(Mutex::new(None)) };
        let err = match t.dial(&PeerAddr::parse("1.2.3.4:15441").unwrap()).await {
            Ok(_) => panic!("expected an error dialing a non-i2p address"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("cannot dial"));
    }
}
