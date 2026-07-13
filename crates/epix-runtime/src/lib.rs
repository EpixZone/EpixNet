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
    /// I2P mode (`disable`/`embedded`/`external`). Ignored without `i2p`.
    #[cfg(feature = "i2p")]
    pub i2p_mode: String,
    /// External I2P router's SAM TCP port (only used in `external` mode).
    #[cfg(feature = "i2p")]
    pub i2p_sam_port: u16,
    /// Reticulum mesh enable. Ignored without the `mesh` feature.
    #[cfg(feature = "mesh")]
    pub mesh_enabled: bool,
    /// Mesh TCP interfaces to dial (`host:port` hubs/peers).
    #[cfg(feature = "mesh")]
    pub mesh_peers: Vec<String>,
    /// Mesh TCP interface to listen on (`ip:port`), if any.
    #[cfg(feature = "mesh")]
    pub mesh_listen: Option<String>,
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
            #[cfg(feature = "i2p")]
            i2p_mode: "disable".to_string(),
            #[cfg(feature = "i2p")]
            i2p_sam_port: 7656,
            #[cfg(feature = "mesh")]
            mesh_enabled: false,
            #[cfg(feature = "mesh")]
            mesh_peers: Vec::new(),
            #[cfg(feature = "mesh")]
            mesh_listen: None,
        }
    }
}

/// Owns the node's background loops. The announce/re-sync work uses the
/// transport already set on the [`AppState`].
pub struct NodeRuntime {
    state: Arc<AppState>,
    trackers: Vec<epix_xite::Tracker>,
    config: RuntimeConfig,
    shutdown: Arc<Notify>,
    handles: Vec<JoinHandle<()>>,
    /// The node's DHT participant (serves `kad` RPCs + drives lookups). Shared
    /// with the inbound handler so peers can query us as a DHT node.
    dht: Arc<epix_dht::Node>,
    /// Store-and-forward propagation store peers announce updates into (served
    /// by the propagation handler so offline peers can catch up later).
    prop_store: Arc<tokio::sync::Mutex<epix_propagation::PropagationStore>>,
    /// Data root for Tor/I2P state (`<root>/tor`, `<root>/i2p`). Set via
    /// [`NodeRuntime::with_data_dir`] before `start()`.
    #[cfg(any(feature = "tor", feature = "i2p", feature = "mesh"))]
    data_dir: Option<std::path::PathBuf>,
}

impl NodeRuntime {
    pub fn new(state: Arc<AppState>, trackers: Vec<epix_xite::Tracker>) -> Self {
        Self::with_config(state, trackers, RuntimeConfig::default())
    }

    pub fn with_config(
        state: Arc<AppState>,
        trackers: Vec<epix_xite::Tracker>,
        config: RuntimeConfig,
    ) -> Self {
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
            #[cfg(any(feature = "tor", feature = "i2p", feature = "mesh"))]
            data_dir: None,
        }
    }

    /// Set the data root Tor/I2P keep their state under.
    #[cfg(any(feature = "tor", feature = "i2p", feature = "mesh"))]
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
        // DHT: probe known peers into the routing table, announce every served
        // site, and look up extra peers - a tracker-independent discovery path
        // (works for rare sites and if the trackers go down). Also installs the
        // PeerFinder hook so on-demand clones can query the DHT.
        self.handles.push(tokio::spawn(dht_loop(
            self.state.clone(),
            self.dht.clone(),
            self.config.fileserver_port,
            self.shutdown.clone(),
            self.config.announce_interval,
        )));
        // Inbound file server: let peers pull our files (seeding), and try to
        // open that port through the home router with UPnP so it's reachable.
        #[cfg(feature = "inbound-seeding")]
        if let Some(port) = self.config.fileserver_port {
            // Tor-always binds the fileserver to loopback, so clearnet is
            // deliberately closed - don't report a public port in that mode,
            // whether from a public interface IP or an inbound peer.
            #[cfg(feature = "tor")]
            let clearnet_seeding = self.config.tor_mode != epix_tor::TorMode::Always;
            #[cfg(not(feature = "tor"))]
            let clearnet_seeding = true;
            self.handles.push(tokio::spawn(seed_loop(
                self.state.clone(),
                self.node_handler(),
                port,
                clearnet_seeding,
                self.shutdown.clone(),
            )));
            self.handles.push(tokio::spawn(upnp_loop(
                self.state.clone(),
                port,
                clearnet_seeding,
                self.shutdown.clone(),
            )));
        }
        // In-process I2P: bring up the router (embedded or external) on its own
        // task so clearnet keeps working while it reseeds/builds tunnels, layer
        // .b32.i2p dialing onto the transport, feed inbound I2P streams to the
        // node handler, and poll live status for the Stats page.
        #[cfg(feature = "i2p")]
        if epix_i2p::I2pMode::parse(&self.config.i2p_mode) != epix_i2p::I2pMode::Disable {
            if let Some(dir) = self.data_dir.clone() {
                self.handles.push(tokio::spawn(i2p_loop(
                    self.state.clone(),
                    self.node_handler(),
                    dir.join("i2p"),
                    self.config.i2p_mode.clone(),
                    self.config.i2p_sam_port,
                    self.config.fileserver_port,
                    self.shutdown.clone(),
                )));
            }
        }
        // Reticulum mesh: join the configured mesh interfaces, layer `rns:`
        // dialing onto the transport, serve the wire protocol to peers that
        // link to us, and announce our destination so they can.
        #[cfg(feature = "mesh")]
        if self.config.mesh_enabled {
            let identity_path =
                self.data_dir.clone().map(|d| d.join("mesh").join("identity"));
            self.handles.push(tokio::spawn(mesh_loop(
                self.state.clone(),
                self.node_handler(),
                identity_path,
                self.config.mesh_peers.clone(),
                self.config.mesh_listen.clone(),
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
        // Wakeup watcher: detect a wall-clock jump (the machine slept) and
        // force a fresh announce + connection sweep on resume, like EpixNet's
        // FileServer.wakeupWatcher. Cheap: a 30s self-check.
        self.handles.push(tokio::spawn(wakeup_loop(
            self.state.clone(),
            self.shutdown.clone(),
        )));
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
    trackers: Vec<epix_xite::Tracker>,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    let announce = || async {
        // AnnounceShare: announce to the configured trackers plus any remembered
        // from previous runs, plus the runtime-contributed list (Syncronite's
        // live bootstrap) - re-read every pass, like EpixNet's loadTrackersFile
        // in its announce loop.
        let mut all = trackers.clone();
        for t in state.shared_trackers().await.into_iter().chain(state.extra_trackers().await) {
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
        // Drop tracker peers other nodes announced that have gone stale.
        state.tracker_expire().await;
    };
    announce().await;
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // consume the immediate first tick
    // Re-announce early when the tracker set changes (Beacon loading its book
    // or a xite list right after boot) - otherwise fresh announcers would sit
    // unused until the next 20-minute pass.
    let trackers_changed = state.trackers_changed();
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => announce().await,
            _ = trackers_changed.notified() => announce().await,
        }
    }
}

/// A [`epix_ui::PeerFinder`] backed by the runtime's DHT node, so the
/// on-demand clone path can look up peers for sites the trackers don't know.
struct DhtPeerFinder {
    dht: Arc<epix_dht::Node>,
    rpc: Arc<epix_dht_net::WireRpcClient>,
}

#[async_trait::async_trait]
impl epix_ui::PeerFinder for DhtPeerFinder {
    async fn find(&self, address: &str) -> Vec<PeerAddr> {
        let mut peers = self.dht.get_peers(epix_dht::site_key(address), self.rpc.as_ref()).await;
        peers.retain(|p| !matches!(p, PeerAddr::Ip(s) if s.ip().is_unspecified()));
        peers
    }
}

/// Drive the DHT: seed the routing table by probing peers we already know
/// (learning real node contacts from their responses), announce every served
/// site under its key, and fold looked-up peers into each site's registry.
/// Tracker-independent discovery: a rare site findable from any peer that
/// serves it, even with every tracker down. Runs on the announce cadence.
async fn dht_loop(
    state: Arc<AppState>,
    dht: Arc<epix_dht::Node>,
    fileserver_port: Option<u16>,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    // Wait for the transport (set by the node just before the runtime starts).
    let transport = loop {
        if let Some(t) = state.transport().await {
            break t;
        }
        tokio::select! {
            _ = shutdown.notified() => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    };
    // Our claimed contact. A NAT'd node doesn't know its public IP; it claims
    // 0.0.0.0 and the serving side substitutes the connection's source IP
    // (see DhtService). The port is our real listening port.
    let port = fileserver_port.unwrap_or(0);
    let me_addr = PeerAddr::parse(&format!("0.0.0.0:{port}")).expect("addr");
    let me = epix_dht::Contact::new(dht.id, me_addr.clone());
    let rpc = Arc::new(epix_dht_net::WireRpcClient::new(me, transport));

    // Expose DHT lookups to the on-demand clone path.
    state
        .set_peer_finder(Arc::new(DhtPeerFinder { dht: dht.clone(), rpc: rpc.clone() }))
        .await;

    let round = || async {
        // 1. Probe a handful of known peers: send FindNode(self) so they learn
        //    our real contact and we learn real contacts from their tables.
        //    The probed peer itself is NOT inserted (we don't know its node id;
        //    only contacts carried in responses have authentic ids).
        let addresses = state.xite_addresses().await;
        let mut probed = std::collections::HashSet::new();
        for address in &addresses {
            for peer in state.connectable_peers(address, 3).await {
                if !probed.insert(peer.clone()) || probed.len() > 8 {
                    continue;
                }
                let probe = tokio::time::timeout(
                    Duration::from_secs(10),
                    rpc.probe(&peer, dht.id),
                );
                if let Ok(Ok((responder, contacts))) = probe.await {
                    // The responder's authentic contact (id stamped into the
                    // reply, address we dialed) plus whatever it shared.
                    for contact in responder.into_iter().chain(contacts) {
                        if contact.id != dht.id {
                            dht.add_contact(contact);
                        }
                    }
                }
            }
        }
        // 2. Announce every served site and fold in any peers the DHT knows.
        let mut found_total = 0;
        for address in &addresses {
            let key = epix_dht::site_key(address);
            if port != 0 {
                dht.announce(key, me_addr.clone(), rpc.as_ref()).await;
            }
            let mut peers = dht.get_peers(key, rpc.as_ref()).await;
            // Drop unusable claims (a NAT'd announcer's own 0.0.0.0 entry).
            peers.retain(|p| !matches!(p, PeerAddr::Ip(s) if s.ip().is_unspecified()));
            if !peers.is_empty() {
                found_total += peers.len();
                state.add_peers(address, peers).await;
            }
        }
        let routing = dht.routing_len();
        if !probed.is_empty() || routing > 0 || found_total > 0 {
            state
                .log(
                    "INFO",
                    format!(
                        "DHT: probed {} peer(s), {routing} node(s) in the routing table, {found_total} peer(s) found for {} site(s)",
                        probed.len(),
                        addresses.len()
                    ),
                )
                .await;
        }
    };

    // First round shortly after start (peers arrive from the first announce),
    // then on the announce cadence.
    tokio::select! {
        _ = shutdown.notified() => return,
        _ = tokio::time::sleep(Duration::from_secs(30)) => {}
    }
    let _ = tokio::time::timeout(Duration::from_secs(120), round()).await;
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => { let _ = tokio::time::timeout(Duration::from_secs(120), round()).await; },
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
                // The Chart plugin toggle pauses collection (data kept).
                if !state.plugin_enabled("Chart").await {
                    continue;
                }
                state.collect_chart().await;
                ticks += 1;
                if ticks % archive_every == 0 {
                    state.archive_chart().await;
                }
            }
        }
    }
}

/// Detect a large wall-clock jump between ticks - the signature of the
/// machine sleeping and resuming (tokio's interval is monotonic, so after a
/// suspend the loops just resume with stale peers and a stale announce). On a
/// jump, kick a fresh announce (via the trackers-changed notify the announce
/// loop already waits on) and a connection sweep, so a laptop that closes and
/// reopens rejoins the network at once instead of on the next 20-minute pass.
async fn wakeup_loop(state: Arc<AppState>, shutdown: Arc<Notify>) {
    let check = Duration::from_secs(30);
    // A jump longer than a few checks means real suspended time, not scheduler
    // jitter (EpixNet uses 3 minutes).
    let jump_threshold = Duration::from_secs(3 * 60);
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tokio::time::sleep(check) => {}
        }
        let elapsed = last.elapsed();
        last = tokio::time::Instant::now();
        if elapsed > jump_threshold {
            state
                .log(
                    "INFO",
                    format!(
                        "Wakeup: {}s wall-clock jump detected, re-announcing",
                        elapsed.as_secs()
                    ),
                )
                .await;
            // Kick the announce loop (it selects on this) and refresh peers.
            state.trackers_changed().notify_waiters();
            state.manage_connections().await;
        }
    }
}

/// Re-sync every xite (fetch a newer content.json + changed files).
async fn resync_loop(state: Arc<AppState>, shutdown: Arc<Notify>, period: Duration) {
    // Initial user-content pass shortly after start (own task, so the resync
    // ticker isn't delayed): sites cloned before the recursive-content
    // feature (or while this node was offline) backfill their included and
    // per-user data without waiting a full period.
    {
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.notified() => return,
                _ = tokio::time::sleep(Duration::from_secs(20)) => {}
            }
            for address in state.xite_addresses().await {
                state.sync_user_content(&address).await;
            }
        });
    }
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                for address in state.xite_addresses().await {
                    // Show the check on the dashboard like EpixNet: the
                    // "Updating..." pill while checking, then an `updated`
                    // outcome event - "Updated!" (self-clearing) on success,
                    // the error pill on failure. The pill only clears on a
                    // matching outcome event, never on a plain refresh.
                    state.push_site_info_event(&address, "updating").await;
                    state.begin_site_update(&address);
                    // The pass runs on its own task so a panic in one xite's
                    // sync can't kill this loop (which would strand the pill
                    // and end all future resyncs) - it surfaces as a JoinError
                    // and counts as a failed update.
                    let joined = tokio::spawn({
                        let state = state.clone();
                        let address = address.clone();
                        async move {
                            let ok = state.resync_xite(&address).await.is_ok();
                            // New and updated user content (posts, comments)
                            // rides the same cycle.
                            state.sync_user_content(&address).await;
                            ok
                        }
                    })
                    .await;
                    state.end_site_update(&address);
                    let ok = match joined {
                        Ok(ok) => ok,
                        Err(e) => {
                            state
                                .log("ERROR", format!("Resync pass for {address} died: {e}"))
                                .await;
                            false
                        }
                    };
                    state.push_update_result(&address, ok).await;
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
    clearnet: bool,
    shutdown: Arc<Notify>,
) {
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            state.log("ERROR", format!("File server bind on port {port} failed: {e}")).await;
            return;
        }
    };
    let mut server = epix_protocol::PeerServer::new(handler);
    // A real peer reaching us over clearnet TCP proves the fileserver port is
    // open from the internet - the privacy-preserving alternative to the Python
    // client's third-party port-scan services (no phone-home). The first public
    // inbound peer flips the status if nothing already has (a public interface
    // IP or UPnP may have set it first). Onion/I2P inbound never runs this
    // server, so it stays strictly clearnet.
    if clearnet {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::net::SocketAddr>();
        let listener_state = state.clone();
        tokio::spawn(async move {
            while let Some(addr) = rx.recv().await {
                if is_public_ipv4(&addr.ip()) {
                    let (already, _) = listener_state.port_status().await;
                    if !already {
                        listener_state.set_port_status(true, Some(addr.ip().to_string())).await;
                        listener_state
                            .log(
                                "INFO",
                                format!("Fileserver port confirmed open by inbound peer {}", addr.ip()),
                            )
                            .await;
                    }
                    break; // one public confirmation is enough
                }
            }
        });
        let hook: epix_protocol::InboundHook = Arc::new(move |peer: &epix_core::PeerAddr| {
            if let epix_core::PeerAddr::Ip(addr) = peer {
                let _ = tx.send(*addr);
            }
        });
        server = server.on_inbound(hook);
    }
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
            Ok((svc, onion_host, mut inbound)) => {
                state
                    .log("INFO", format!("Tor: onion service up at {onion_host}.onion:{port}"))
                    .await;
                state.set_onion_address(&onion_host).await;
                let handler = handler.clone();
                let (version, rev) = epix_protocol::PeerServer::new(handler.clone()).banner();
                tokio::spawn(async move {
                    // The RunningOnionService handle keeps the service alive:
                    // dropping it decommissions the service, so its descriptor
                    // is never published and no peer can ever reach us. Hold it
                    // for as long as we accept inbound streams (the process
                    // lifetime) - previously it was dropped right here at the
                    // end of the match arm, silently killing the service
                    // milliseconds after the "onion service up" log line.
                    let _svc = svc;
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
                            epix_protocol::serve_stream(handler, peer, stream, &version, rev, port)
                                .await;
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

/// Bring up I2P and run its surfaces until shutdown, none of it on the startup
/// path: the embedded (or external) router boots on its own task, `.b32.i2p`
/// dialing is layered onto the peer transport, inbound I2P streams feed the
/// same node handler as the TCP/onion loops, and the live status is polled into
/// the app state for the Stats page. The node keeps working over clearnet/Tor
/// throughout the (minutes-long) embedded bootstrap.
/// Join the Reticulum mesh and run its surfaces until shutdown: bring up the
/// mesh node (identity + destination + TCP interfaces), layer `rns:` dialing
/// onto the peer transport, feed inbound mesh links to the same node handler
/// as the TCP/onion/I2P loops, and announce our destination on an interval so
/// peers can find a path to us. LoRa/BLE radios become further interface
/// types on the same mesh node later; this loop does not change.
#[cfg(feature = "mesh")]
async fn mesh_loop(
    state: Arc<AppState>,
    handler: Arc<handler::NodeHandler>,
    identity_path: Option<std::path::PathBuf>,
    tcp_peers: Vec<String>,
    tcp_listen: Option<String>,
    shutdown: Arc<Notify>,
) {
    use epix_protocol::RequestHandler;
    let config = epix_reticulum::MeshConfig {
        identity_path,
        tcp_peers: tcp_peers.clone(),
        tcp_listen: tcp_listen.clone(),
    };
    let node = match epix_reticulum::MeshNode::spawn(config).await {
        Ok(node) => node,
        Err(e) => {
            state.log("WARNING", format!("Mesh: bring-up failed: {e}")).await;
            return;
        }
    };
    let listen_note = tcp_listen.map(|l| format!(", listening on {l}")).unwrap_or_default();
    state
        .log(
            "INFO",
            format!(
                "Mesh: up, our address rns:{} ({} interface peer(s){listen_note})",
                node.dest_hash_hex(),
                tcp_peers.len(),
            ),
        )
        .await;

    // Layer `rns:` dialing onto the transport (composed with TCP/Tor/I2P).
    state.set_rns_transport(Arc::new(node.transport())).await;
    state.set_rns_address(&node.dest_hash_hex()).await;

    // Announce our destination and serve inbound links until shutdown.
    let announce = node.spawn_announce(Duration::from_secs(60));
    let handler: Arc<dyn RequestHandler> = handler;
    let serve = tokio::spawn(async move { node.serve(handler).await });

    shutdown.notified().await;
    announce.abort();
    serve.abort();
}

#[cfg(feature = "i2p")]
async fn i2p_loop(
    state: Arc<AppState>,
    handler: Arc<handler::NodeHandler>,
    data_dir: std::path::PathBuf,
    mode: String,
    sam_port: u16,
    fileserver_port: Option<u16>,
    shutdown: Arc<Notify>,
) {
    use epix_protocol::RequestHandler;
    let config = epix_i2p::I2pConfig {
        mode: epix_i2p::I2pMode::parse(&mode),
        sam_tcp_port: sam_port,
        data_dir,
    };
    state.log("INFO", format!("I2P: starting ({mode} router) in the background")).await;
    let (i2p, mut inbound) = epix_i2p::I2p::spawn(config);

    // Layer .b32.i2p dialing onto the transport (composed with TCP/Tor).
    state.set_i2p_transport(Arc::new(i2p.transport())).await;

    // Feed inbound I2P peer streams to the same handler the TCP listener uses.
    if fileserver_port.is_some() {
        let handler = handler.clone();
        let (version, rev) = epix_protocol::PeerServer::new(handler.clone()).banner();
        tokio::spawn(async move {
            while let Some(stream) = inbound.recv().await {
                let handler = handler.clone() as Arc<dyn RequestHandler>;
                let version = version.clone();
                // Inbound I2P peers have no dial-back IP (they're reached by
                // destination); use an empty i2p addr like the onion path does.
                let peer = epix_core::PeerAddr::I2p { dest: String::new(), port: 0 };
                let port = fileserver_port.unwrap_or(0);
                tokio::spawn(async move {
                    epix_protocol::serve_stream(handler, peer, stream, &version, rev, port).await;
                });
            }
        });
    }

    // Poll live status (phase, peers, tunnels, destination) into the app state
    // for the Stats page until shutdown.
    let mut announced_b32 = false;
    loop {
        let s = i2p.status().await;
        // Once ready, publish our `.b32.i2p` (minus the `.i2p` suffix) so PEX
        // advertises us and peers can reach + gossip us over I2P.
        if !announced_b32 {
            if let Some(host) = s.b32.strip_suffix(".i2p") {
                state.set_i2p_address(host).await;
                state.log("INFO", format!("I2P: inbound address {}", s.b32)).await;
                announced_b32 = true;
            }
        }
        state
            .set_i2p_status(serde_json::json!({
                "mode": s.mode.as_str(),
                "phase": s.phase.label(),
                "destination": s.destination,
                "b32": s.b32,
                "sam_port": s.sam_port,
                "reseed_routers": s.reseed_routers,
                "connected_routers": s.connected_routers,
                "tunnels_built": s.tunnels_built,
                "tunnel_failures": s.tunnel_failures,
            }))
            .await;
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

/// Keep the fileserver `port` mapped through the home router with UPnP so peers
/// on the internet can reach us, refreshing the lease before it expires and
/// removing the mapping on shutdown. Best effort - many networks have no UPnP
/// gateway, in which case the node still serves on the LAN and to manually
/// forwarded ports.
#[cfg(feature = "inbound-seeding")]
async fn upnp_loop(state: Arc<AppState>, port: u16, clearnet: bool, shutdown: Arc<Notify>) {
    use igd_next::aio::tokio::search_gateway;
    use igd_next::{PortMappingProtocol, SearchOptions};
    use std::net::SocketAddr;

    // A publicly-routable address peers can already reach directly, with no
    // router to traverse: either the operator set `ip_external`, or this host
    // has a public IP bound to its interface (a VPS/seedbox, no NAT). Either
    // way the fileserver port is reachable without UPnP, so mark it opened and
    // skip the gateway search entirely. This mirrors the Python client, which
    // treated "we have an external IP" as port-opened (FileServer.portCheck);
    // the Rust client previously only ever set port_opened via a successful
    // UPnP mapping, so a VPS with no UPnP gateway always showed "port closed".
    if clearnet {
        let external = state
            .config_get("ip_external")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.trim().is_empty())
            .or_else(|| public_ipv4().map(|ip| ip.to_string()));
        if let Some(ip) = external {
            state.set_port_status(true, Some(ip.clone())).await;
            state
                .log("INFO", format!("Fileserver reachable at {ip}:{port} (public IP, no UPnP needed)"))
                .await;
            // Nothing to refresh; hold the task until shutdown, then clear.
            shutdown.notified().await;
            state.set_port_status(false, None).await;
            return;
        }
    }

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

/// This host's own IPv4 if it is a publicly-routable address (a VPS/seedbox
/// where the public IP sits directly on the interface, not behind NAT). The
/// outbound-source-IP probe returns that public IP directly in that case; a
/// NAT'd home machine returns a private `192.168.x`/`10.x` address instead and
/// this yields `None`, leaving UPnP to open the port.
#[cfg(feature = "inbound-seeding")]
fn public_ipv4() -> Option<std::net::IpAddr> {
    let ip = local_ipv4()?;
    is_public_ipv4(&ip).then_some(ip)
}

/// Whether an IPv4 is reachable from the public internet: excludes private,
/// loopback, link-local, unspecified, broadcast, and the 100.64.0.0/10 CGNAT
/// range (carrier NAT, not directly reachable).
#[cfg(feature = "inbound-seeding")]
fn is_public_ipv4(ip: &std::net::IpAddr) -> bool {
    let std::net::IpAddr::V4(v4) = ip else { return false };
    let o = v4.octets();
    !v4.is_private()
        && !v4.is_loopback()
        && !v4.is_link_local()
        && !v4.is_unspecified()
        && !v4.is_broadcast()
        && !(o[0] == 100 && (0x40..0x80).contains(&o[1])) // 100.64.0.0/10 CGNAT
}

#[cfg(all(test, feature = "inbound-seeding"))]
mod tests {
    use super::is_public_ipv4;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn public_addresses_are_reachable() {
        // A VPS public IP (this server) and other routable addresses.
        assert!(is_public_ipv4(&ip("74.208.249.9")));
        assert!(is_public_ipv4(&ip("8.8.8.8")));
        assert!(is_public_ipv4(&ip("1.1.1.1")));
    }

    #[test]
    fn nat_and_reserved_addresses_are_not() {
        // Private ranges (home NAT) - UPnP should handle these, not us.
        assert!(!is_public_ipv4(&ip("192.168.1.10")));
        assert!(!is_public_ipv4(&ip("10.0.0.5")));
        assert!(!is_public_ipv4(&ip("172.16.4.4")));
        // Loopback, link-local, unspecified, CGNAT.
        assert!(!is_public_ipv4(&ip("127.0.0.1")));
        assert!(!is_public_ipv4(&ip("169.254.1.1")));
        assert!(!is_public_ipv4(&ip("0.0.0.0")));
        assert!(!is_public_ipv4(&ip("100.64.0.1")));
        assert!(!is_public_ipv4(&ip("100.127.255.255")));
        // 100.0.0.0/8 outside the CGNAT sub-range is still public.
        assert!(is_public_ipv4(&ip("100.0.0.1")));
        // IPv6 is out of scope for this clearnet check.
        assert!(!is_public_ipv4(&ip("2001:4860:4860::8888")));
    }
}
