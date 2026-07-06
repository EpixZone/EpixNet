//! I2P transport for Epix.
//!
//! I2P peers are `.b32.i2p` destinations. Reaching them needs an I2P **router**
//! (which does the garlic routing) that the app talks to over the **SAMv3**
//! bridge. This crate provides:
//!
//! - [`I2p::spawn`] - bring up I2P **without blocking**: either an **embedded**
//!   pure-Rust router ([emissary], no separate process, the default) or an
//!   **external** router a power user already runs (i2pd / Java I2P). The
//!   embedded router reseeds and builds tunnels on its own background task
//!   (minutes on a cold start) while the node keeps working over clearnet/Tor;
//!   I2P dials succeed once it's [`I2pPhase::Ready`].
//! - [`I2pTransport`] - dial a `.b32.i2p` peer, yielding an
//!   [`epix_transport::PeerStream`] the wire protocol runs over, like TCP/Tor.
//! - an inbound accept loop, so the node is reachable over I2P (its own
//!   destination), the way [`epix_tor`]'s onion service gives inbound Tor.
//! - [`I2pStatus`] - live phase + router/tunnel/peer counts for the UI.
//!
//! The SAM client is [`yosemite`]; the router backend is swappable behind it.
//!
//! [emissary]: https://github.com/eepnet/emissary

use async_trait::async_trait;
use epix_core::{Error, PeerAddr, Result};
use epix_transport::{PeerStream, Transport};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use yosemite::{style::Stream, Session, SessionOptions};

mod router;

/// How I2P is provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I2pMode {
    /// I2P off.
    Disable,
    /// Embedded emissary router, in-process (no separate daemon). Default.
    Embedded,
    /// An external router (i2pd / Java I2P) the user already runs.
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

    pub fn as_str(&self) -> &'static str {
        match self {
            I2pMode::Disable => "disable",
            I2pMode::Embedded => "embedded",
            I2pMode::External => "external",
        }
    }
}

/// Where the I2P bringup is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum I2pPhase {
    /// I2P disabled.
    Off,
    /// Router starting (embedded: reseeding + building tunnels; external:
    /// connecting to its SAM bridge).
    Starting,
    /// SAM reachable and our inbound session created - I2P dials work.
    Ready,
    /// Bringup failed; the message says why. Clearnet/Tor are unaffected.
    Failed(String),
}

impl I2pPhase {
    pub fn label(&self) -> String {
        match self {
            I2pPhase::Off => "Off".into(),
            I2pPhase::Starting => "Starting…".into(),
            I2pPhase::Ready => "Ready".into(),
            I2pPhase::Failed(e) => format!("Failed: {e}"),
        }
    }
}

/// A snapshot of the I2P integration for the UI (Stats page).
#[derive(Debug, Clone)]
pub struct I2pStatus {
    pub mode: I2pMode,
    pub phase: I2pPhase,
    /// Our inbound `.b32.i2p`/base64 destination once ready (empty otherwise).
    pub destination: String,
    /// SAM TCP port in use (embedded router's discovered port, or external).
    pub sam_port: u16,
    /// Routers reseeded into the netdb at startup (embedded only).
    pub reseed_routers: usize,
    /// Connected I2P routers - the live peer count (embedded only).
    pub connected_routers: usize,
    /// Client/exploratory tunnels built so far (embedded only).
    pub tunnels_built: usize,
    /// Tunnel build failures (embedded only).
    pub tunnel_failures: usize,
}

impl I2pStatus {
    fn new(mode: I2pMode) -> Self {
        let phase = if mode == I2pMode::Disable { I2pPhase::Off } else { I2pPhase::Starting };
        Self {
            mode,
            phase,
            destination: String::new(),
            sam_port: 0,
            reseed_routers: 0,
            connected_routers: 0,
            tunnels_built: 0,
            tunnel_failures: 0,
        }
    }
}

/// I2P startup configuration.
pub struct I2pConfig {
    pub mode: I2pMode,
    /// External router's SAM TCP port (I2P's default is 7656). Ignored for the
    /// embedded router, which binds its own and reports it back.
    pub sam_tcp_port: u16,
    /// Where the embedded router keeps its state (netdb, keys).
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

pub(crate) type SharedStatus = Arc<RwLock<I2pStatus>>;

/// A running (or starting) I2P integration.
pub struct I2p {
    status: SharedStatus,
    transport: I2pTransport,
}

impl I2p {
    /// Bring up I2P per `config` **without blocking**: returns immediately with
    /// the handle and a receiver of inbound peer streams. The router bootstrap
    /// runs on its own task; watch [`I2p::status`] for progress. Disabled mode
    /// returns an idle handle and an empty receiver.
    pub fn spawn(config: I2pConfig) -> (Self, mpsc::Receiver<PeerStream>) {
        let (tx, rx) = mpsc::channel::<PeerStream>(16);
        let status: SharedStatus = Arc::new(RwLock::new(I2pStatus::new(config.mode.clone())));
        let transport = I2pTransport { status: status.clone(), outbound: Arc::new(Mutex::new(None)) };

        if config.mode != I2pMode::Disable {
            let status = status.clone();
            tokio::spawn(async move {
                if let Err(e) = bringup(config, status.clone(), tx).await {
                    status.write().await.phase = I2pPhase::Failed(e.to_string());
                }
            });
        }
        (Self { status, transport }, rx)
    }

    /// A snapshot of the I2P status for the UI.
    pub async fn status(&self) -> I2pStatus {
        self.status.read().await.clone()
    }

    /// The peer transport that dials `.b32.i2p` peers once I2P is ready.
    pub fn transport(&self) -> I2pTransport {
        self.transport.clone()
    }
}

/// Bootstrap the router (embedded or external), create our inbound session,
/// then keep the status' live stats fresh. Runs on its own task.
async fn bringup(config: I2pConfig, status: SharedStatus, tx: mpsc::Sender<PeerStream>) -> Result<()> {
    // Bring up the router backend and learn the SAM port to talk to. The
    // embedded router also spawns its own stats poller against `status`, so the
    // live peer/tunnel counts refresh for the UI.
    let sam_port = match config.mode {
        I2pMode::External => config.sam_tcp_port,
        I2pMode::Embedded => {
            router::EmbeddedRouter::start(&config.data_dir, status.clone()).await?.sam_port()
        }
        I2pMode::Disable => return Ok(()),
    };
    status.write().await.sam_port = sam_port;

    // Inbound: a server session whose destination is our advertised I2P
    // address; accept forever and hand streams to the node's server.
    let mut inbound = new_session(sam_port).await?;
    let destination = inbound.destination().to_string();
    {
        let mut s = status.write().await;
        s.destination = destination;
        s.phase = I2pPhase::Ready;
    }
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

    Ok(())
}

/// Create a SAM stream session against the router at `sam_port`.
async fn new_session(sam_port: u16) -> Result<Session<Stream>> {
    let options = SessionOptions { samv3_tcp_port: sam_port, ..Default::default() };
    Session::<Stream>::new(options).await.map_err(|e| Error::Protocol(format!("i2p session: {e}")))
}

/// Dials `.b32.i2p` peers through the router's SAM bridge. Shares the status so
/// dials are refused (cleanly) until I2P is ready and clearnet keeps working.
/// Holds one persistent outbound session so dials reuse the same tunnels.
#[derive(Clone)]
pub struct I2pTransport {
    status: SharedStatus,
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
        let sam_port = {
            let s = self.status.read().await;
            if s.phase != I2pPhase::Ready {
                return Err(Error::Protocol(format!("i2p not ready ({})", s.phase.label())));
            }
            s.sam_port
        };
        let mut guard = self.outbound.lock().await;
        if guard.is_none() {
            *guard = Some(new_session(sam_port).await?);
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
    async fn disabled_mode_is_idle() {
        let (i2p, _rx) = I2p::spawn(I2pConfig { mode: I2pMode::Disable, ..Default::default() });
        let s = i2p.status().await;
        assert_eq!(s.phase, I2pPhase::Off);
        assert!(s.destination.is_empty());
    }

    #[tokio::test]
    async fn transport_rejects_non_i2p_and_not_ready() {
        let (i2p, _rx) = I2p::spawn(I2pConfig { mode: I2pMode::Disable, ..Default::default() });
        let t = i2p.transport();
        // Wrong address type.
        let err = match t.dial(&PeerAddr::parse("1.2.3.4:15441").unwrap()).await {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("cannot dial"));
        // Right type but I2P is off -> not ready, not a panic.
        let err = match t.dial(&PeerAddr::parse("abcd.i2p:0").unwrap()).await {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not ready"));
    }
}
