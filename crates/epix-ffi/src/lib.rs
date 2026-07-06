//! `epix-ffi` - the UniFFI surface the mobile shells embed in-process.
//!
//! Kotlin (Android) and Swift (iOS) construct one [`EpixNode`], `start()` it
//! with a [`NodeConfig`], point their WebView/GeckoView at `ui_url()`, and use
//! `resolve()` for the address bar. The node owns its own multi-thread tokio
//! runtime, so the shell calls are ordinary blocking method calls - no async
//! FFI, no event loop on the shell side.
//!
//! The bindings are generated at mobile-build time by `uniffi-bindgen` from
//! this crate's exported types (proc-macro mode - no UDL).

use epix_node::{boot, AppState, NodeOptions, RunningNode};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

/// How the shell wants the node to boot. Mirrors [`epix_node::NodeOptions`],
/// minus the desktop-only concerns (GeoIP asset, browser open, log file).
#[derive(uniffi::Record, Clone)]
pub struct NodeConfig {
    /// The app's data directory (from the platform: `filesDir` on Android,
    /// the app group container on iOS).
    pub data_dir: String,
    /// The xite to open: a raw `epix1…` address, a `.epix` name, or an
    /// `epix://…` deep link.
    pub target: String,
    /// UI bind. Loopback on desktop; the shells usually keep `127.0.0.1:43110`
    /// and point their web view at it.
    pub ui_addr: String,
    /// Tor mode: `disable` / `enable` / `always`.
    pub tor_mode: String,
    /// App version string reported in `serverInfo`.
    pub version: String,
}

/// The node's lifecycle state, polled by the shell to drive its UI.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Idle,
    Starting,
    Serving,
    Failed,
}

/// A failure crossing the FFI boundary.
#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum EpixError {
    #[error("{msg}")]
    Message { msg: String },
}

impl EpixError {
    fn msg(m: impl Into<String>) -> Self {
        EpixError::Message { msg: m.into() }
    }
}

/// Shared, mutable node state behind the FFI object.
struct Inner {
    state: NodeState,
    /// Set once the node boots; drives status/resolve queries.
    node: Option<Arc<AppState>>,
    error: Option<String>,
    /// The UI bind that actually succeeded (from the running node, so it is
    /// right even when the requested port was 0 or taken).
    ui_addr: Option<std::net::SocketAddr>,
    /// The display name (`dashboard.epix` or the raw address) the node opened.
    display: Option<String>,
}

/// The embedded Epix node. One per app; `start()` boots it on its own runtime.
#[derive(uniffi::Object)]
pub struct EpixNode {
    rt: Runtime,
    inner: Mutex<Inner>,
}

#[uniffi::export]
impl EpixNode {
    /// Create an idle node. Call [`EpixNode::start`] to boot it.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("build tokio runtime");
        Arc::new(Self {
            rt,
            inner: Mutex::new(Inner {
                state: NodeState::Idle,
                node: None,
                error: None,
                ui_addr: None,
                display: None,
            }),
        })
    }

    /// Boot the node: resolve + clone the target xite (from disk if cached,
    /// else the network), then serve the UI + peer network in the background.
    /// Blocks until serving has started (or fails). Safe to call once.
    pub fn start(self: Arc<Self>, config: NodeConfig) -> Result<(), EpixError> {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.state == NodeState::Serving || inner.state == NodeState::Starting {
                return Ok(());
            }
            inner.state = NodeState::Starting;
            inner.error = None;
        }
        let opts = NodeOptions {
            data_root: config.data_dir.into(),
            target: config.target,
            ui_addr: config.ui_addr,
            tor_mode: config.tor_mode,
            open_browser: false,
            geoip_gz: None,
            log_file: None,
            version: config.version,
            rev: env!("EPIX_GIT_REV").to_string(),
        };
        // Boot synchronously so the shell knows serving is ready (and can point
        // its web view at ui_url) before returning; then drive the server on a
        // background task for the process lifetime.
        let booted: Result<RunningNode, String> = self.rt.block_on(async {
            let (server, running) = boot(opts).await?;
            let addr = running.ui_addr;
            tokio::spawn(async move {
                let _ = server.serve(addr).await;
            });
            Ok(running)
        });
        let mut inner = self.inner.lock().unwrap();
        match booted {
            Ok(running) => {
                inner.ui_addr = Some(running.ui_addr);
                inner.display = Some(running.display.clone());
                inner.node = Some(running.state);
                inner.state = NodeState::Serving;
                Ok(())
            }
            Err(e) => {
                inner.state = NodeState::Failed;
                inner.error = Some(e.clone());
                Err(EpixError::msg(e))
            }
        }
    }

    /// The node's current lifecycle state.
    pub fn state(&self) -> NodeState {
        self.inner.lock().unwrap().state
    }

    /// The last error, if the node failed to start.
    pub fn last_error(&self) -> Option<String> {
        self.inner.lock().unwrap().error.clone()
    }

    /// The local UI URL the shell should load once [`NodeState::Serving`], e.g.
    /// `http://127.0.0.1:43110/dashboard.epix/`. `None` until serving.
    pub fn ui_url(&self) -> Option<String> {
        let inner = self.inner.lock().unwrap();
        if inner.state != NodeState::Serving {
            return None;
        }
        // The bind and display recorded from the RUNNING node - correct even
        // when the shell asked for port 0 or a non-default bind. (This used to
        // return the compile-time default port regardless of config, sending
        // shells to a port nothing listened on.)
        let addr = inner.ui_addr?;
        let display = inner.display.as_deref()?;
        Some(format!("http://{addr}/{display}/"))
    }

    /// Our onion address (no `.onion` suffix), once the onion service has
    /// published. `None` if Tor is off or not yet ready.
    pub fn onion_address(&self) -> Option<String> {
        let node = self.inner.lock().unwrap().node.clone()?;
        self.rt.block_on(async move { node.onion_address().await })
    }

    /// `(tor_enabled, tor_status)` for the shell's status UI.
    pub fn tor_status(&self) -> TorStatus {
        match self.inner.lock().unwrap().node.clone() {
            Some(node) => {
                let (enabled, status) = self.rt.block_on(async move { node.tor_status().await });
                TorStatus { enabled, status }
            }
            None => TorStatus { enabled: false, status: "Disabled".into() },
        }
    }

    /// Resolve a `.epix` name (or `epix://…` link) to its xite address on the
    /// chain, for the address bar. Blocks on the network.
    pub fn resolve(&self, name: String) -> Result<String, EpixError> {
        let target = epix_node::parse_target(&name);
        let (label, tld) = target.rsplit_once('.').unwrap_or((target.as_str(), "epix"));
        if label.starts_with("epix1") {
            return Ok(label.to_string());
        }
        let resolver = epix_chain::XidResolver::new(epix_chain::DEFAULT_RPC_URL);
        let label = label.to_string();
        let tld = tld.to_string();
        self.rt.block_on(async move {
            let domain = resolver
                .resolve(&label, &tld)
                .await
                .map_err(|e| EpixError::msg(format!("resolve {label}.{tld}: {e}")))?;
            domain
                .xite_address()
                .map(|a| a.to_string())
                .ok_or_else(|| EpixError::msg(format!("{label}.{tld} has no xite address")))
        })
    }
}

/// `(tor_enabled, tor_status)` for the shell.
#[derive(uniffi::Record, Clone)]
pub struct TorStatus {
    pub enabled: bool,
    pub status: String,
}

