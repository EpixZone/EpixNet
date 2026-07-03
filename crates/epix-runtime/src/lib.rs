//! `epix-runtime` - the persistent node runtime.
//!
//! Turns a served [`AppState`] into a live node by running supervised background
//! loops, replacing EpixNet's gevent greenlets with `tokio::spawn` tasks whose
//! handles the runtime owns:
//!
//! - **announce** - periodically re-announce to trackers and fold the results
//!   into each xite's peer registry, so peer lists stay fresh.
//! - **re-sync** - periodically check each xite for a newer content.json among
//!   its peers and, if found, verify + download the changed files (updating the
//!   live worker stats the sidebar shows).
//!
//! [`NodeRuntime::shutdown`] signals every loop and awaits them, so the node
//! stops cleanly.

use epix_core::PeerAddr;
use epix_ui::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

pub mod handler;
#[cfg(feature = "local-discovery")]
pub mod local;

/// Re-export of the Tor routing mode so callers configure it without a direct
/// `epix-tor` dependency. Only present with the `tor` feature.
#[cfg(feature = "tor")]
pub use epix_tor::TorMode;

/// How often the loops run.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub announce_interval: Duration,
    pub resync_interval: Duration,
    pub chart_interval: Duration,
    pub connection_interval: Duration,
    /// TCP port for the inbound file server (seeding). `None` disables it (the
    /// node stays download-only). Ignored without the `inbound-seeding` feature.
    pub fileserver_port: Option<u16>,
    /// Offline mode: skip every peer-networking loop (announce, connections,
    /// re-sync, seeding). Only the local chart collector keeps running.
    pub offline: bool,
    /// Tor routing mode. Ignored without the `tor` feature.
    #[cfg(feature = "tor")]
    pub tor_mode: epix_tor::TorMode,
    /// Local SOCKS5 port the browser shells route page traffic through (dialed
    /// via Tor). `None` disables the listener. Ignored without `tor`.
    #[cfg(feature = "tor")]
    pub tor_socks_port: Option<u16>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(20 * 60),
            resync_interval: Duration::from_secs(5 * 60),
            chart_interval: Duration::from_secs(5 * 60),
            connection_interval: Duration::from_secs(60),
            fileserver_port: None,
            offline: false,
            #[cfg(feature = "tor")]
            tor_mode: epix_tor::TorMode::default(),
            #[cfg(feature = "tor")]
            tor_socks_port: None,
        }
    }
}

/// Owns the node's background loops. The announce/re-sync work uses the
/// transport already set on the [`AppState`].
pub struct NodeRuntime {
    state: Arc<AppState>,
    trackers: Vec<PeerAddr>,
    config: RuntimeConfig,
    shutdown: Arc<Notify>,
    handles: Vec<JoinHandle<()>>,
    /// The node's DHT participant (serves `kad` RPCs + drives lookups). Shared
    /// with the inbound handler so peers can query us as a DHT node.
    dht: Arc<epix_dht::Node>,
    /// Store-and-forward propagation store peers announce updates into (served
    /// by the propagation handler so offline peers can catch up later).
    prop_store: Arc<tokio::sync::Mutex<epix_propagation::PropagationStore>>,
    /// Data root for Tor state/cache (`<root>/tor/...`). Set via
    /// [`NodeRuntime::with_data_dir`] before `start()` to enable Tor.
    #[cfg(feature = "tor")]
    data_dir: Option<std::path::PathBuf>,
}

impl NodeRuntime {
    pub fn new(state: Arc<AppState>, trackers: Vec<PeerAddr>) -> Self {
        Self::with_config(state, trackers, RuntimeConfig::default())
    }

    pub fn with_config(state: Arc<AppState>, trackers: Vec<PeerAddr>, config: RuntimeConfig) -> Self {
        // A per-process DHT node id (ties to this run; a stable identity-derived
        // id is a later Sybil-resistance refinement).
        let seed = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let dht = Arc::new(epix_dht::Node::new(epix_dht::NodeId::hash(seed.as_bytes())));
        let prop_store =
            Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new()));
        Self {
            state,
            trackers,
            config,
            shutdown: Arc::new(Notify::new()),
            handles: Vec::new(),
            dht,
            prop_store,
            #[cfg(feature = "tor")]
            data_dir: None,
        }
    }

    /// Set the data root Tor keeps its state + directory cache under. Required
    /// for the `tor` feature to actually bootstrap a client.
    #[cfg(feature = "tor")]
    pub fn with_data_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }

    /// The composite inbound handler (files + DHT + propagation), shared by the
    /// TCP seed loop and the Tor onion-service accept loop.
    fn node_handler(&self) -> Arc<handler::NodeHandler> {
        Arc::new(handler::NodeHandler::new(
            Arc::new(epix_ui::fileserve::FileService::new(self.state.clone())),
            Arc::new(epix_dht_net::DhtService::new(self.dht.clone())),
            Arc::new(epix_propagation::PropagationService::new(self.prop_store.clone())),
        ))
    }

    /// Spawn the background loops. Idempotent per instance (call once). The local
    /// chart collector always runs; the peer-networking loops are skipped in
    /// offline mode.
    pub fn start(&mut self) {
        self.handles.push(tokio::spawn(chart_loop(
            self.state.clone(),
            self.shutdown.clone(),
            self.config.chart_interval,
        )));
        if self.config.offline {
            return;
        }
        self.handles.push(tokio::spawn(announce_loop(
            self.state.clone(),
            self.trackers.clone(),
            self.shutdown.clone(),
            self.config.announce_interval,
        )));
        self.handles.push(tokio::spawn(resync_loop(
            self.state.clone(),
            self.shutdown.clone(),
            self.config.resync_interval,
        )));
        self.handles.push(tokio::spawn(connection_loop(
            self.state.clone(),
            self.shutdown.clone(),
            self.config.connection_interval,
        )));
        // Inbound file server: let peers pull our files (seeding), and try to
        // open that port through the home router with UPnP so it's reachable.
        #[cfg(feature = "inbound-seeding")]
        if let Some(port) = self.config.fileserver_port {
            self.handles.push(tokio::spawn(seed_loop(
                self.state.clone(),
                self.node_handler(),
                port,
                self.shutdown.clone(),
            )));
            self.handles.push(tokio::spawn(upnp_loop(
                self.state.clone(),
                port,
                self.shutdown.clone(),
            )));
        }
        // In-process Tor: bootstrap Arti, set the peer transport (onion dials,
        // or all traffic in Always mode), host an onion service that feeds the
        // same inbound handler, and run the SOCKS listener for the browser
        // shells. All best-effort and off the startup path.
        #[cfg(feature = "tor")]
        if self.config.tor_mode != epix_tor::TorMode::Disable {
            if let Some(dir) = self.data_dir.clone() {
                self.handles.push(tokio::spawn(tor_loop(
                    self.state.clone(),
                    self.node_handler(),
                    dir,
                    self.config.tor_mode,
                    self.config.fileserver_port,
                    self.config.tor_socks_port,
                    self.shutdown.clone(),
                )));
            } else {
                tokio::spawn({
                    let state = self.state.clone();
                    async move {
                        state
                            .log("WARNING", "Tor enabled but no data dir set; skipping".to_string())
                            .await;
                    }
                });
            }
        }
        // AnnounceLocal: discover peers on the LAN over UDP broadcast. When the
        // file server is up, advertise its port so discovered peers can reach us.
        #[cfg(feature = "local-discovery")]
        self.handles.push(tokio::spawn(local::local_discovery_loop(
            self.state.clone(),
            self.config.fileserver_port.unwrap_or(0),
            self.shutdown.clone(),
            Duration::from_secs(5 * 60),
        )));
    }

    /// Signal the loops to stop and wait for them.
    pub async fn shutdown(self) {
        self.shutdown.notify_waiters();
        for handle in self.handles {
            let _ = handle.await;
        }
    }
}

/// Re-announce every xite to the trackers (recording per-tracker stats).
/// Announces once immediately (so peers populate right after startup without
/// blocking the server bind), then every `period`.
async fn announce_loop(
    state: Arc<AppState>,
    trackers: Vec<PeerAddr>,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    let announce = || async {
        // AnnounceShare: announce to the configured trackers plus any remembered
        // from previous runs.
        let mut all = trackers.clone();
        for t in state.shared_trackers().await {
            if !all.contains(&t) {
                all.push(t);
            }
        }
        if all.is_empty() {
            return;
        }
        for address in state.xite_addresses().await {
            state.announce_to_trackers(&address, &all).await;
        }
        // AnnounceBitTorrent: also announce to any configured HTTP(S) BT
        // trackers and fold their peers in.
        if let Some(bt) = state.config_get("bt_trackers").await.and_then(|v| v.as_array().cloned()) {
            for url in bt.iter().filter_map(|v| v.as_str()) {
                for address in state.xite_addresses().await {
                    let peers = epix_discovery::announce_bittorrent(url, &address, 0).await;
                    if !peers.is_empty() {
                        state.add_peers(&address, peers).await;
                    }
                }
            }
        }
        // Persist the freshly discovered peers so they survive a restart.
        state.persist_peers().await;
        // Persist the served-xite list (settings/size may have changed).
        state.persist_sites().await;
    };
    announce().await;
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => announce().await,
        }
    }
}

/// Keep a small pool of warm peer connections open + pinged, so the dashboard's
/// connection stats reflect real live links. Warms up quickly (peers arrive from
/// the announce loop shortly after startup), then settles into `period`.
async fn connection_loop(state: Arc<AppState>, shutdown: Arc<Notify>, period: Duration) {
    // Retry every few seconds until the pool has a connection, so the count
    // shows soon after the background announce populates peers - rather than
    // waiting a full period after the empty first attempt.
    for _ in 0..10 {
        state.manage_connections().await;
        if state.connection_stats().await.total > 0 {
            break;
        }
        tokio::select! {
            _ = shutdown.notified() => return,
            _ = tokio::time::sleep(Duration::from_secs(3)) => {}
        }
    }
    // Re-snapshot the chart so connection stats reflect the warmed pool instead
    // of the empty startup snapshot.
    state.collect_chart().await;
    let mut last = state.connection_stats().await.total;
    if last > 0 {
        state.log("INFO", format!("Connected to {last} peers")).await;
    }
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                state.manage_connections().await;
                // Log only when the connection count changes (avoid spam).
                let now = state.connection_stats().await.total;
                if now != last {
                    state.log("INFO", format!("Peer connections: {now}")).await;
                    last = now;
                }
            }
        }
    }
}

/// Snapshot node metrics into the chart db so the dashboard's Stats page has
/// data. Collects once immediately, then every `period`.
async fn chart_loop(state: Arc<AppState>, shutdown: Arc<Notify>, period: Duration) {
    state.collect_chart().await;
    // Enforce retention once at startup, then roughly once a day (the collector
    // runs far more often, so archive only every Nth tick).
    state.archive_chart().await;
    let archive_every = (Duration::from_secs(24 * 60 * 60).as_secs() / period.as_secs().max(1)).max(1);
    let mut ticks: u64 = 0;
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                state.collect_chart().await;
                ticks += 1;
                if ticks % archive_every == 0 {
                    state.archive_chart().await;
                }
            }
        }
    }
}

/// Re-sync every xite (fetch a newer content.json + changed files).
async fn resync_loop(state: Arc<AppState>, shutdown: Arc<Notify>, period: Duration) {
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                for address in state.xite_addresses().await {
                    let _ = state.resync_xite(&address).await;
                }
                // OptionalManager: keep optional files under the size cap.
                let freed = state.enforce_optional_limit().await;
                if freed > 0 {
                    state.log("INFO", format!("Optional-file cleanup freed {freed} bytes")).await;
                }
            }
        }
    }
}

/// Serve inbound file requests (seeding) on `port` until shutdown. Peers connect
/// with the ordinary wire protocol and pull files via `getFile`.
#[cfg(feature = "inbound-seeding")]
async fn seed_loop(
    state: Arc<AppState>,
    handler: Arc<handler::NodeHandler>,
    port: u16,
    shutdown: Arc<Notify>,
) {
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            state.log("ERROR", format!("File server bind on port {port} failed: {e}")).await;
            return;
        }
    };
    let server = epix_protocol::PeerServer::new(handler);
    state.log("INFO", format!("Seeding files (+ DHT + propagation) on port {port}")).await;
    tokio::select! {
        _ = shutdown.notified() => {}
        _ = server.serve(listener) => {}
    }
}

/// Bootstrap in-process Tor and run its three surfaces until shutdown: the peer
/// transport (set on the app state so onion peers are dialable, or all traffic
/// is Tor-routed in Always mode), an onion service whose inbound streams feed
/// the same node handler as the TCP seed loop, and a local SOCKS listener for
/// the browser shells.
#[cfg(feature = "tor")]
async fn tor_loop(
    state: Arc<AppState>,
    handler: Arc<handler::NodeHandler>,
    data_dir: std::path::PathBuf,
    mode: epix_tor::TorMode,
    fileserver_port: Option<u16>,
    socks_port: Option<u16>,
    shutdown: Arc<Notify>,
) {
    use epix_protocol::RequestHandler;
    state.log("INFO", "Tor: bootstrapping in-process Arti client …".to_string()).await;
    // Surface a bootstrapping state so the browser's Tor icon can show progress.
    state.set_tor_status(false, "Bootstrapping").await;
    let tor = match epix_tor::Tor::bootstrap(&data_dir).await {
        Ok(t) => t,
        Err(e) => {
            state.log("ERROR", format!("Tor bootstrap failed: {e}")).await;
            state.set_tor_status(false, "Failed").await;
            return;
        }
    };
    state.log("INFO", "Tor: bootstrapped".to_string()).await;

    // Route peer dials through Tor: onion peers always, everything in Always
    // mode. Wrap the existing transport type so the worker/connection code is
    // unchanged.
    let route_all = mode == epix_tor::TorMode::Always;
    let transport: Arc<dyn epix_transport::Transport> =
        Arc::new(epix_tor::MixedTransport::new(Some(tor.transport(route_all)), mode));
    state.set_transport(transport).await;
    state.set_tor_status(true, if route_all { "Always" } else { "OK" }).await;

    // Host an onion service for inbound peers (so Tor-only peers reach us) and
    // feed its streams to the same handler the TCP listener uses.
    if let Some(port) = fileserver_port {
        match tor.launch_onion_service("epix", port) {
            Ok((_svc, onion_host, mut inbound)) => {
                state
                    .log("INFO", format!("Tor: onion service up at {onion_host}.onion:{port}"))
                    .await;
                state.set_onion_address(&onion_host).await;
                let handler = handler.clone();
                let (version, rev) = epix_protocol::PeerServer::new(handler.clone()).banner();
                tokio::spawn(async move {
                    while let Some(stream) = inbound.recv().await {
                        let handler = handler.clone() as Arc<dyn RequestHandler>;
                        let version = version.clone();
                        // Inbound onion peers have no dial-back IP; the handshake
                        // rebind is a no-op for them (they PEX their onion host).
                        let peer = epix_core::PeerAddr::Onion {
                            host: String::new(),
                            port: 0,
                        };
                        tokio::spawn(async move {
                            epix_protocol::serve_stream(handler, peer, stream, &version, rev).await;
                        });
                    }
                });
            }
            Err(e) => state.log("WARNING", format!("Tor: onion service failed: {e}")).await,
        }
    }

    // Local SOCKS5 for the browser shells to route page traffic through Tor.
    if let Some(sport) = socks_port {
        match tokio::net::TcpListener::bind(("127.0.0.1", sport)).await {
            Ok(listener) => {
                state.log("INFO", format!("Tor: SOCKS5 listener on 127.0.0.1:{sport}")).await;
                let tor = tor.clone();
                tokio::spawn(async move {
                    let _ = tor.serve_socks(listener).await;
                });
            }
            Err(e) => state.log("WARNING", format!("Tor: SOCKS bind on {sport} failed: {e}")).await,
        }
    }

    shutdown.notified().await;
    state.set_tor_status(false, "Disabled").await;
}

/// Keep the fileserver `port` mapped through the home router with UPnP so peers
/// on the internet can reach us, refreshing the lease before it expires and
/// removing the mapping on shutdown. Best effort - many networks have no UPnP
/// gateway, in which case the node still serves on the LAN and to manually
/// forwarded ports.
#[cfg(feature = "inbound-seeding")]
async fn upnp_loop(state: Arc<AppState>, port: u16, shutdown: Arc<Notify>) {
    use igd_next::aio::tokio::search_gateway;
    use igd_next::{PortMappingProtocol, SearchOptions};
    use std::net::SocketAddr;

    let Some(local_ip) = local_ipv4() else {
        state.log("INFO", "UPnP: no local IPv4 address; skipping port mapping").await;
        return;
    };
    let local = SocketAddr::new(local_ip, port);

    let gateway = match search_gateway(SearchOptions::default()).await {
        Ok(g) => g,
        Err(e) => {
            state
                .log("INFO", format!("UPnP: no gateway found ({e}); port {port} not auto-forwarded"))
                .await;
            return;
        }
    };
    let ext_ip = gateway.get_external_ip().await.ok().map(|ip| ip.to_string());
    const LEASE: u32 = 3600; // 1 hour; refreshed before it expires
    let mut announced = false;

    loop {
        match gateway
            .add_port(PortMappingProtocol::TCP, port, local, LEASE, "EpixNet fileserver")
            .await
        {
            Ok(()) => {
                state.set_port_status(true, ext_ip.clone()).await;
                if !announced {
                    let ip = ext_ip.clone().unwrap_or_else(|| "?".into());
                    state.log("INFO", format!("UPnP: opened port {port} (external {ip}:{port})")).await;
                    announced = true;
                }
            }
            Err(e) => {
                state.set_port_status(false, ext_ip.clone()).await;
                state.log("INFO", format!("UPnP: could not map port {port} ({e})")).await;
            }
        }
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tokio::time::sleep(Duration::from_secs((LEASE * 4 / 5) as u64)) => {}
        }
    }
    // Remove the mapping on shutdown (best effort).
    let _ = gateway.remove_port(PortMappingProtocol::TCP, port).await;
    state.set_port_status(false, None).await;
}

/// The node's primary local IPv4 address (the source IP for outbound traffic),
/// used as the internal target of the UPnP port mapping. Connecting the UDP
/// socket only sets the default route - no packets are sent.
#[cfg(feature = "inbound-seeding")]
fn local_ipv4() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    ip.is_ipv4().then_some(ip)
}
