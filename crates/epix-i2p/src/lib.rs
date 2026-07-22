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
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use yosemite::{style::Stream, DestinationKind, RouterApi, Session, SessionOptions};

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
    /// Our inbound base64 destination once ready (empty otherwise).
    pub destination: String,
    /// Our short `.b32.i2p` address (from the destination), what peers dial and
    /// what we advertise in PEX/trackers. Empty until ready.
    pub b32: String,
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
            b32: String::new(),
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

    // Our stable server identity - persisted so the advertised address survives
    // restarts and session rebuilds.
    let identity = load_or_create_identity(&config.data_dir, sam_port).await?;

    // Inbound: a server session on our persistent destination - our advertised
    // I2P address; accept forever and hand streams to the node's server.
    let mut inbound = Some(
        new_persistent_session(sam_port, &identity.private_key)
            .await
            .map_err(|e| Error::Protocol(format!("i2p inbound session: {e}")))?,
    );
    let b32 = b32_address(&identity.destination).unwrap_or_default();
    {
        let mut s = status.write().await;
        s.destination = identity.destination.clone();
        s.b32 = b32;
        s.phase = I2pPhase::Ready;
    }
    let private_key = identity.private_key;
    tokio::spawn(async move {
        loop {
            // Rebuild the listening session if it was torn down (a wedged
            // session was dropped below). Reusing the persistent key gives the
            // same destination, so our advertised address never changes.
            let session = match inbound {
                Some(ref mut s) => s,
                None => match new_persistent_session(sam_port, &private_key).await {
                    Ok(s) => inbound.insert(s),
                    Err(e) => {
                        tracing::debug!(
                            target: "epix::i2p",
                            "i2p inbound rebuild failed, will retry: {e}",
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                },
            };
            match session.accept().await {
                Ok(stream) => {
                    if tx.send(Box::pin(stream) as PeerStream).await.is_err() {
                        break; // node shut down
                    }
                }
                Err(e) => {
                    tracing::debug!(target: "epix::i2p", "i2p accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    // A wedged listening session never accepts again. Drop it so
                    // the next iteration recreates it on the same destination -
                    // the drop frees that destination at the router first, or the
                    // recreate would be rejected as a duplicate.
                    if session_fatal(&e) {
                        tracing::info!(
                            target: "epix::i2p",
                            "rebuilding wedged i2p inbound session",
                        );
                        inbound = None;
                    }
                }
            }
        }
    });

    Ok(())
}

/// Create a **transient** SAM stream session against the router at `sam_port` -
/// a throwaway destination for outbound dials. Keeps the raw `yosemite` error so
/// callers can tell a wedged session apart from an ordinary failure.
async fn new_session_raw(sam_port: u16) -> yosemite::Result<Session<Stream>> {
    let options = SessionOptions { samv3_tcp_port: sam_port, ..Default::default() };
    Session::<Stream>::new(options).await
}

/// Create a **persistent** SAM stream session against the router at `sam_port`,
/// bound to `private_key`. This is our inbound (server) destination: reusing the
/// same key keeps our advertised `.b32.i2p` address stable across restarts and
/// session rebuilds. The caller must have dropped any previous session on this
/// key first, or the router rejects the create as a duplicate destination.
async fn new_persistent_session(sam_port: u16, private_key: &str) -> yosemite::Result<Session<Stream>> {
    let options = SessionOptions {
        samv3_tcp_port: sam_port,
        destination: DestinationKind::Persistent { private_key: private_key.to_string() },
        ..Default::default()
    };
    Session::<Stream>::new(options).await
}

/// Our stable I2P server identity: the public `destination` (what the `.b32.i2p`
/// address is derived from and what peers connect to) and its `private_key` (the
/// blob that recreates it via [`DestinationKind::Persistent`]).
struct I2pIdentity {
    destination: String,
    private_key: String,
}

impl I2pIdentity {
    /// Serialize as two lines (`destination`\n`private_key`) - both are
    /// single-line I2P base64, so a line each round-trips losslessly.
    fn serialize(&self) -> String {
        format!("{}\n{}\n", self.destination, self.private_key)
    }

    /// Parse the two-line form written by [`Self::serialize`]; `None` if either
    /// line is missing or empty (treated as "regenerate").
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
        let destination = lines.next()?.to_string();
        let private_key = lines.next()?.to_string();
        Some(Self { destination, private_key })
    }
}

/// Load our persisted I2P identity from `<data_dir>/destination.key`, or - on
/// first run, or if the file is missing/corrupt - generate a fresh one via the
/// router and persist it (owner-only). The key blob is I2P private-key material;
/// it sits alongside the embedded router's own identity in the same data dir,
/// under the same local-disk trust assumption.
async fn load_or_create_identity(data_dir: &Path, sam_port: u16) -> Result<I2pIdentity> {
    let path = data_dir.join("destination.key");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Some(identity) = I2pIdentity::parse(&text) {
            return Ok(identity);
        }
        tracing::warn!(target: "epix::i2p", "i2p destination.key unreadable, regenerating");
    }
    let (destination, private_key) = RouterApi::new(sam_port)
        .generate_destination()
        .await
        .map_err(|e| Error::Protocol(format!("i2p generate destination: {e}")))?;
    let identity = I2pIdentity { destination, private_key };
    if let Err(e) = write_key_file(&path, &identity.serialize()) {
        // Non-fatal: we still have a working destination this run, we just
        // won't keep it next time. Better to run than to refuse to start.
        tracing::warn!(target: "epix::i2p", "could not persist i2p destination.key: {e}");
    }
    Ok(identity)
}

/// Write `contents` to `path` owner-only (0600 on unix), creating the parent dir
/// and replacing any existing file atomically via a temp file + rename.
fn write_key_file(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("key.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Whether a `yosemite` error means the SAM **session itself** is no longer
/// usable - the control connection to the router dropped, or the session's
/// state machine desynced (yosemite marks it `Poisoned`, after which every
/// later call on that session fails with `invalid state`). Such a session must
/// be discarded and rebuilt. A clean per-peer failure (the router reporting a
/// specific `.b32.i2p` destination unreachable) leaves the session healthy, so
/// it is *not* fatal and the session is kept for the next dial.
fn session_fatal(e: &yosemite::Error) -> bool {
    match e {
        // Control-connection I/O died, or the router sent a reply we can't
        // parse mid-handshake: the session is wedged.
        yosemite::Error::IoError(_) | yosemite::Error::Malformed => true,
        // A router error about the *peer* (e.g. CantReachPeer) is reported as
        // `Protocol(Router(_))`; the session survives it. Any other protocol
        // error is a state-machine desync and is fatal.
        yosemite::Error::Protocol(p) => !matches!(p, yosemite::ProtocolError::Router(_)),
        // Router-reported I2P errors are about the request, not the session.
        yosemite::Error::I2p(_) => false,
    }
}

/// Compute the short `.b32.i2p` address from a full base64 I2P destination:
/// `base32(sha256(destination_bytes)).lower() + ".b32.i2p"`. This is what other
/// nodes dial and what we advertise in PEX/trackers. Returns `None` if the
/// destination isn't valid I2P base64.
pub fn b32_address(destination: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let raw = i2p_base64_decode(destination)?;
    let hash = Sha256::digest(&raw);
    let b32 = data_encoding::BASE32_NOPAD.encode(&hash).to_lowercase();
    Some(format!("{b32}.b32.i2p"))
}

/// Decode an I2P-base64 string. I2P uses the standard base64 alphabet with
/// `+`/`/` swapped for `-`/`~` and `=` padding. Tolerates missing padding.
fn i2p_base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut spec = data_encoding::Specification::new();
    spec.symbols
        .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");
    spec.padding = Some('=');
    let encoding = spec.encoding().ok()?;
    let mut input = s.trim().to_string();
    while input.len() % 4 != 0 {
        input.push('=');
    }
    encoding.decode(input.as_bytes()).ok()
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
        // Reuse the one persistent outbound session; if a dial wedges it (the
        // router's SAM control connection dropped, leaving the session
        // `Poisoned` so every later dial fails), drop it and rebuild once so
        // I2P recovers without restarting the node. A clean per-peer failure
        // leaves the session healthy and is surfaced as-is.
        let mut last_err = None;
        for attempt in 0..2u8 {
            if guard.is_none() {
                match new_session_raw(sam_port).await {
                    Ok(s) => *guard = Some(s),
                    Err(e) => {
                        let fatal = session_fatal(&e);
                        last_err = Some(Error::Protocol(format!("i2p session: {e}")));
                        if attempt == 0 && fatal {
                            continue;
                        }
                        break;
                    }
                }
            }
            let session = guard.as_mut().expect("session set above");
            match session.connect(&dest).await {
                Ok(stream) => return Ok(Box::pin(stream) as PeerStream),
                Err(e) => {
                    let fatal = session_fatal(&e);
                    last_err = Some(Error::Protocol(format!("i2p connect {dest}: {e}")));
                    if attempt == 0 && fatal {
                        // Wedged session: discard it so the retry rebuilds.
                        tracing::debug!(target: "epix::i2p", "i2p session wedged, rebuilding: {e}");
                        *guard = None;
                        continue;
                    }
                    break;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Protocol("i2p dial failed".into())))
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

    #[test]
    fn session_fatal_classifies_errors() {
        use yosemite::{Error as YErr, I2pError, ProtocolError};
        // Control-connection loss / unparseable reply -> rebuild the session.
        assert!(session_fatal(&YErr::IoError(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
        assert!(session_fatal(&YErr::Malformed));
        // State-machine desync (the `Poisoned`/invalid-state path) -> rebuild.
        assert!(session_fatal(&YErr::Protocol(ProtocolError::InvalidState)));
        assert!(session_fatal(&YErr::Protocol(ProtocolError::InvalidMessage)));
        // A per-peer failure leaves the session healthy -> keep it.
        assert!(!session_fatal(&YErr::Protocol(ProtocolError::Router(
            I2pError::CantReachPeer
        ))));
        assert!(!session_fatal(&YErr::I2p(I2pError::CantReachPeer)));
    }

    #[test]
    fn identity_round_trips() {
        let id = I2pIdentity {
            destination: "PUBLIC~dest-base64".to_string(),
            private_key: "PRIVATE~key-base64".to_string(),
        };
        let parsed = I2pIdentity::parse(&id.serialize()).expect("parses");
        assert_eq!(parsed.destination, id.destination);
        assert_eq!(parsed.private_key, id.private_key);
        // Tolerates trailing whitespace / blank lines, rejects a truncated file.
        assert!(I2pIdentity::parse("dest\n\nkey\n").is_some());
        assert!(I2pIdentity::parse("only-one-line\n").is_none());
        assert!(I2pIdentity::parse("").is_none());
    }

    #[test]
    fn write_key_file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("destination.key");
        write_key_file(&path, "dest\nkey\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "dest\nkey\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
        }
        // No temp file left behind.
        assert!(!path.with_extension("key.tmp").exists());
    }

    #[test]
    fn b32_matches_i2p_reference() {
        // A real 679-byte destination (with certificate) captured from the
        // embedded router; b32 cross-checked against I2P's own algorithm.
        let dest = "sgHFio~SvU1ncIhFyE4mFB7zRaSdvce0WjH58tBBQbRmvC3gFdp15wAHxXjdc7bAejcH75B5YjdjxEVQ3Z1cX-8-qQeAIp7ZstwGVaTHomhZTnFxzuzMJmQsYNbvQ~Q~eLBPej8YqEN1lf~KGfnA8QXon24hMhY9gDAMEsYUjsjZCI2JugvPfjKIQotFcoWaepAulv~4sxsASpV1F1lWfpwdJlI2CSKInS09uYbtP4PVoeyya7txoRRJHX5I07tU7tYn2A8YhMIHD4W4o7u0b5dUtqsFV8jznbbS1r0wRt8GVBMobwe18AdQ~-tMrMeMrR7YpgcBzZHJFft0dzVowJGsbiBThX78VTmCElJmzkfy8RdpM5btYWPUdBfvlkKL4kJcOe3dNXsnRT9-bGe05~0EB5FX4KwiUFuNrS3YID8alL~3fTj3iKmDGqqMFXzwwg7W-wFxO8gwWSY56U452NnOTZIdV3i7Yqiy3Cm5bysdIZl6FKdtjOmg~gbBygO3BQAEAAcAAM-dVR9APaUHHhJLbkLhkgpk8IS~StoM8SLicrE9NcCv305LV53IbmMAnk~RFWWVbCpeGw9T0LdhzDDUYxkpFFTkoGqSXLy3ocp0THFIvSiJobxkIquRNfdOg~JpfOx7Ucgn7EUOw5EMOrB7~JkyNqydCvs1GYpOhWIP1eN1HlSdD0m8YCuiy8ATb7POGIkgCxEda3IizJBAYjzeAWKuBAj7VRmSIYMDpUVKLNJ3mn0LfPuMozuH9-20MxAKfA1KiOpYqboYu1gn-TX2DFLrdRNTaztfq0M93HezFSnQgLzzLVRNJdz98C~hjCyskiKvaDvOX37K7cMWZS67Ek7tvm6gDsk0uQcW4YTLg~gKneXX-G~37zEr7l46aH9kArb6JQ";
        assert_eq!(
            b32_address(dest).unwrap(),
            "narvewf7cmhowltv4vybkf4y4zgt63xxf2kbiantnzrb3slglw2q.b32.i2p"
        );
    }

    #[test]
    fn b32_rejects_garbage() {
        assert!(b32_address("not valid base64 !!!").is_none());
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
