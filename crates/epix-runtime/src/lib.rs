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
//! - **propagation** - poll peers for store-and-forward update hints on a short
//!   interval and resync the hinted xites at once, so a freshly published post
//!   appears in seconds instead of waiting for the next re-sync tick.
//!
//! [`NodeRuntime::shutdown`] signals every loop and awaits them, so the node
//! stops cleanly.

use epix_core::PeerAddr;
use epix_ui::conn_pool::LinkOpener;
use epix_ui::{AppState, UpdateOutcome, UPDATE_PHASE_CHECKING};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

pub mod edx;
#[cfg(feature = "local-discovery")]
pub mod local;
pub mod xfer;
#[cfg(feature = "inbound-seeding")]
mod portcheck;

/// Re-export of the Tor routing mode so callers configure it without a direct
/// `epix-tor` dependency. Only present with the `tor` feature.
#[cfg(feature = "tor")]
pub use epix_tor::TorMode;

/// How often the loops run.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub announce_interval: Duration,
    pub resync_interval: Duration,
    /// How often to poll propagation peers for update hints and resync the
    /// hinted xites. Much shorter than `resync_interval`: this is the fast path
    /// that makes a freshly published post/upvote appear in seconds instead of
    /// waiting for the next full resync tick.
    pub propagation_interval: Duration,
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
    /// Route Tor's guard channel through an in-process Snowflake bridge (for
    /// censored networks). Always present so the field never has to be
    /// cfg-forked at call sites; only acted on under the `bridges` feature.
    pub tor_use_bridges: bool,
    /// I2P mode (`disable`/`embedded`/`external`). Ignored without `i2p`.
    #[cfg(feature = "i2p")]
    pub i2p_mode: String,
    /// External I2P router's SAM TCP port (only used in `external` mode).
    #[cfg(feature = "i2p")]
    pub i2p_sam_port: u16,
    /// LAN peer discovery over UDP broadcast (AnnounceLocal). Off by default:
    /// the node answers discovery requests with the hashes of every xite it
    /// serves, so participating is a presence disclosure to everyone on the
    /// network - an opt-in, not a background default. Ignored without the
    /// `local-discovery` feature.
    #[cfg(feature = "local-discovery")]
    pub local_discovery: bool,
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
            propagation_interval: Duration::from_secs(30),
            chart_interval: Duration::from_secs(5 * 60),
            connection_interval: Duration::from_secs(60),
            fileserver_port: None,
            offline: false,
            #[cfg(feature = "tor")]
            tor_mode: epix_tor::TorMode::default(),
            #[cfg(feature = "tor")]
            tor_socks_port: None,
            tor_use_bridges: false,
            #[cfg(feature = "i2p")]
            i2p_mode: "disable".to_string(),
            #[cfg(feature = "i2p")]
            i2p_sam_port: 7656,
            #[cfg(feature = "local-discovery")]
            local_discovery: false,
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

    /// Spawn the background loops. Idempotent per instance (call once). The local
    /// chart collector always runs; the peer-networking loops are skipped in
    /// offline mode.
    pub fn start(&mut self) {
        // Share the propagation hint store with the app state, so a received
        // EDX update records a gossip hint into the same book the EDX control
        // plane serves and `propagation_loop` polls.
        self.state.set_prop_store(self.prop_store.clone());
        self.handles.push(tokio::spawn(chart_loop(
            self.state.clone(),
            self.shutdown.clone(),
            self.config.chart_interval,
        )));
        if self.config.offline {
            return;
        }
        // Tor-Always mode closes clearnet: every outbound dial must go through
        // Tor. But the node installs a plain TCP transport at startup and
        // tor_loop only swaps in the Tor-routed transport once Arti finishes
        // bootstrapping (~10-40s). Each peer-dialing loop below waits for that
        // (await_tor_routed) in Always mode, so none of them dials over clearnet
        // during the bootstrap window and leaks the real IP. A no-op otherwise.
        #[cfg(feature = "tor")]
        let tor_always = self.config.tor_mode == epix_tor::TorMode::Always;
        #[cfg(not(feature = "tor"))]
        let tor_always = false;
        // Seed the self-advertisement (Phase 6): an outbound EDX Hello offers
        // our dial-back address so an inbound overlay peer becomes
        // dialable at first contact instead of waiting on PEX/trackers. The
        // overlay loops fill in each address below as it comes up; port_opened
        // flips when an inbound public peer confirms the port (seed_loop).
        epix_protocol::set_self_advert(epix_protocol::SelfAdvert {
            version: self.state.version.clone(),
            fileserver_port: self.config.fileserver_port.unwrap_or(0),
            port_opened: false,
            tor_always,
            onion: None,
            i2p: None,
            rns: None,
        });
        self.handles.push(tokio::spawn(announce_loop(
            self.state.clone(),
            self.trackers.clone(),
            tor_always,
            self.shutdown.clone(),
            self.config.announce_interval,
        )));
        self.handles.push(tokio::spawn(resync_loop(
            self.state.clone(),
            tor_always,
            self.shutdown.clone(),
            self.config.resync_interval,
        )));
        // Client half of store-and-forward propagation: poll peers for update
        // hints and resync the hinted xites right away, so a published post
        // appears in seconds instead of waiting for the full resync tick.
        self.handles.push(tokio::spawn(propagation_loop(
            self.state.clone(),
            tor_always,
            self.shutdown.clone(),
            self.config.propagation_interval,
        )));
        self.handles.push(tokio::spawn(connection_loop(
            self.state.clone(),
            tor_always,
            self.shutdown.clone(),
            self.config.connection_interval,
        )));
        // Health prober: re-check benched (backed-off) peers off the streaming
        // path, so a temporarily-down peer is reinstated the moment it answers
        // instead of waiting out a full dial backoff. See peer_probe_loop.
        self.handles.push(tokio::spawn(peer_probe_loop(
            self.state.clone(),
            tor_always,
            self.shutdown.clone(),
        )));
        // DHT: probe known peers into the routing table, announce every served
        // xite, and look up extra peers - a tracker-independent discovery path
        // (works for rare xites and if the trackers go down). Also installs the
        // PeerFinder hook so on-demand clones can query the DHT.
        //
        // In Tor-Always mode the DHT runs OVER Tor: it waits for the onion
        // service, dials every contact through the Tor transport, and claims
        // only its onion address - so it never leaves from (or claims) the real
        // IP. Outside Always mode the DHT runs over clearnet as before. See
        // dht_loop. (`tor_always` is computed above, shared with the peer loops.)
        self.handles.push(tokio::spawn(dht_loop(
            self.state.clone(),
            self.dht.clone(),
            self.config.fileserver_port,
            tor_always,
            self.shutdown.clone(),
            self.config.announce_interval,
        )));
        // One shared EDX serve context (store + identity key + reciprocity
        // governor), initialized on demand by whichever transport's accept
        // loop comes up first and reused by all of them (clearnet + overlays),
        // so credit and storage are unified across transports. It also carries
        // the control-plane handles every accept loop serves `Kad` and
        // `UpdatesSince` from - one DHT node and one hint log for the whole
        // node, whichever transport a peer arrives on.
        let edx_cell = edx::new_serve_cell(edx::ControlHandles {
            dht: Arc::new(epix_dht_net::DhtService::new(self.dht.clone())),
            prop: self.prop_store.clone(),
        });
        // Bring the serve context up right away rather than waiting for an
        // accept loop. The same call installs the outbound EDX fetcher, and
        // every peer path goes through it: announce, fetch, publish and the DHT
        // client. A download-only node (fileserver_port = None) runs no accept
        // loop, so leaving the install to one would leave it with no peer I/O
        // at all. Inbound serving stays gated on the port below; the cell keeps
        // this idempotent for the seed/tor/i2p/mesh callers.
        self.handles.push(tokio::spawn({
            let cell = edx_cell.clone();
            let state = self.state.clone();
            async move {
                if edx::ensure_edx_serve(&cell, &state).await.is_none() {
                    state
                        .log("INFO", "No EDX object store: peer transfers disabled".to_string())
                        .await;
                }
            }
        }));
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
                port,
                clearnet_seeding,
                edx_cell.clone(),
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
                    dir.join("i2p"),
                    self.config.i2p_mode.clone(),
                    self.config.i2p_sam_port,
                    self.config.fileserver_port,
                    edx_cell.clone(),
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
                identity_path,
                self.config.mesh_peers.clone(),
                self.config.mesh_listen.clone(),
                edx_cell.clone(),
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
                    dir,
                    self.config.tor_mode,
                    self.config.fileserver_port,
                    self.config.tor_socks_port,
                    self.config.tor_use_bridges,
                    edx_cell.clone(),
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
            tor_always,
            self.shutdown.clone(),
        )));
        // AnnounceLocal: discover peers on the LAN over UDP broadcast. When the
        // file server is up, advertise its port so discovered peers can reach us.
        // Opt-in (`local_discovery`): with it off nothing is spawned and no
        // socket is bound, so the node is silent on the LAN rather than merely
        // quiet - answering a stranger's discovery request would disclose which
        // xites we serve.
        #[cfg(feature = "local-discovery")]
        if self.config.local_discovery {
            self.handles.push(tokio::spawn(local::local_discovery_loop(
                self.state.clone(),
                self.config.fileserver_port.unwrap_or(0),
                self.shutdown.clone(),
                Duration::from_secs(5 * 60),
            )));
        }
    }

    /// Signal the loops to stop and wait for them.
    pub async fn shutdown(self) {
        self.shutdown.notify_waiters();
        for handle in self.handles {
            // `notify_waiters` wakes only the loops parked on `notified()` at the
            // instant it fires. A loop busy inside its tick body (e.g. the resync
            // loop mid-fetch when its interval is short and the machine is loaded)
            // misses that one-shot wakeup and, if its next tick is already due,
            // hot-spins without ever re-parking to see it - so a plain
            // `handle.await` here can block teardown forever. Give each loop a
            // short grace window to wind down cleanly, then abort so shutdown
            // always completes.
            let abort = handle.abort_handle();
            if tokio::time::timeout(Duration::from_secs(2), handle).await.is_err() {
                abort.abort();
            }
        }
    }
}

/// Re-announce every xite to the trackers (recording per-tracker stats).
/// Announces once immediately (so peers populate right after startup without
/// blocking the server bind), then every `period`.
/// In Tor-Always mode, park until the Tor-routed transport is live before a
/// peer-dialing loop does any outbound dial. `tor_status().0` flips true only
/// AFTER tor_loop swaps in the Tor transport (set_transport precedes
/// set_tor_status), so it is an exact "Tor routing is live" signal - waiting on
/// it keeps a loop off the plain clearnet transport installed at startup, which
/// would otherwise leak the real IP during the ~10-40s Tor bootstrap window.
/// A no-op in every other mode. Returns false if shutdown fired while waiting
/// (the caller should stop). It never falls through to clearnet: if Tor never
/// comes up the caller simply never dials - the correct consequence of Always
/// mode closing clearnet.
async fn await_tor_routed(state: &AppState, tor_always: bool, shutdown: &Notify) -> bool {
    if !tor_always {
        return true;
    }
    loop {
        if state.tor_status().await.0 {
            return true;
        }
        tokio::select! {
            _ = shutdown.notified() => return false,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn announce_loop(
    state: Arc<AppState>,
    trackers: Vec<epix_xite::Tracker>,
    tor_always: bool,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    let announce = || async {
        // AnnounceShare: announce to the configured trackers plus any remembered
        // from previous runs, plus the runtime-contributed list (Syncronite's
        // live bootstrap) - re-read every pass, like EpixNet's loadTrackersFile
        // in its announce loop.
        let all = std::sync::Arc::new(state.all_trackers(&trackers).await);
        if all.is_empty() {
            return;
        }
        // Bounded-concurrent per-xite announces. Strictly serial passes made
        // a cold start unusable: each xite's announce waits out its slowest
        // tracker (75s ceiling), so a boot pass over dozens of xites with the
        // usual dead trackers ground on for tens of minutes - during which
        // the loop could not react to Tor coming up either. Four at a time
        // keeps the dial pressure modest while cutting the pass to a quarter.
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
        let mut passes = tokio::task::JoinSet::new();
        for address in state.xite_addresses().await {
            let state = state.clone();
            let all = all.clone();
            let gate = gate.clone();
            passes.spawn(async move {
                let Ok(_permit) = gate.acquire_owned().await else { return };
                state.announce_to_trackers(&address, &all).await;
            });
        }
        while passes.join_next().await.is_some() {}
        // AnnounceBitTorrent: also announce to any configured HTTP(S) BT
        // trackers and fold their peers in.
        if let Some(bt) = state.config_get("bt_trackers").await.and_then(|v| v.as_array().cloned()) {
            for url in bt.iter().filter_map(|v| v.as_str()) {
                for address in state.xite_addresses().await {
                    if let Ok(peers) = epix_discovery::announce_bittorrent(url, &address, 0).await {
                        if !peers.is_empty() {
                            state.add_peers(&address, peers).await;
                        }
                    }
                }
            }
        }
        // Persist the freshly discovered peers so they survive a restart.
        state.persist_peers().await;
        // Persist the served-xite list (settings/size may have changed).
        state.persist_xites().await;
        // Drop tracker peers other nodes announced that have gone stale.
        state.tracker_expire().await;
    };
    // In Always mode, don't announce (which dials trackers) until Tor routes
    // our traffic - otherwise the immediate boot announce leaks our real IP.
    if !await_tor_routed(&state, tor_always, &shutdown).await {
        return;
    }
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
/// on-demand clone path can look up peers for xites the trackers don't know.
struct DhtPeerFinder {
    dht: Arc<epix_dht::Node>,
    rpc: Arc<epix_dht_net::WireRpcClient>,
}

#[async_trait::async_trait]
impl epix_ui::PeerFinder for DhtPeerFinder {
    async fn find(&self, address: &str) -> Vec<PeerAddr> {
        let mut peers = self.dht.get_peers(epix_dht::xite_key(address), self.rpc.as_ref()).await;
        peers.retain(dialable_dht_peer);
        peers
    }
}

/// Whether a DHT lookup result is a usable dial target. A NAT'd announcer
/// stores its own `0.0.0.0:port` claim locally, and `GetPeers` returns store
/// contents verbatim (only `Announce` claims get the source-IP rewrite), so an
/// unspecified-IP claim leaks back through lookups and must be dropped before
/// anyone tries to dial it. The wire test `overlay_..._round_trip` pins that
/// this raw claim really is present in responses, so this filter stays load
/// bearing.
fn dialable_dht_peer(p: &PeerAddr) -> bool {
    !matches!(p, PeerAddr::Ip(s) if s.ip().is_unspecified())
}

/// The addresses this node claims to host xites at when announcing to the
/// DHT. Clearnet is claimed as `0.0.0.0:port` (a NAT'd node doesn't know its
/// public IP; the serving side substitutes the connection's source IP - see
/// `DhtService`). Overlay self-addresses pass through `rewrite_claimed_addr`
/// verbatim, which is what makes a Tor-only or I2P-only publisher
/// discoverable through the DHT at all. `onion` comes without its `.onion`
/// suffix, `i2p` without `.i2p` (as AppState stores them), `rns` as the hex
/// destination hash. Everything is gated on a real fileserver port: the port
/// doubles as the onion/i2p virtual port, so a portless node has no inbound
/// service to claim on any network.
///
/// `include_clearnet` is false in Tor-Always mode: our announce reaches peers
/// from a Tor exit, so a `0.0.0.0` claim would be rewritten to the exit IP
/// (useless, and it re-introduces a correlation). There we claim overlays only.
fn dht_self_claims(
    port: u16,
    include_clearnet: bool,
    onion: Option<String>,
    i2p: Option<String>,
    rns: Option<String>,
) -> Vec<PeerAddr> {
    let mut claims = Vec::new();
    if port == 0 {
        return claims;
    }
    if include_clearnet {
        claims.push(PeerAddr::parse(&format!("0.0.0.0:{port}")).expect("addr"));
    }
    if let Some(host) = onion.filter(|h| !h.is_empty()) {
        claims.extend(PeerAddr::parse(&format!("{host}.onion:{port}")));
    }
    if let Some(dest) = i2p.filter(|d| !d.is_empty()) {
        claims.extend(PeerAddr::parse(&format!("{dest}.i2p:{port}")));
    }
    if let Some(hash) = rns.filter(|h| !h.is_empty()) {
        claims.extend(PeerAddr::parse(&format!("rns:{hash}")));
    }
    claims
}

/// Dial deadline for a DHT contact. In Tor-Always mode every dial rides Tor -
/// even a clearnet peer - so it gets the overlay bound, since a cold Tor
/// circuit build can exceed the 15s clearnet timeout and cut off a reachable
/// peer mid-handshake. Otherwise the peer's own per-network bound applies.
fn dht_dial_timeout(peer: &PeerAddr, tor_always: bool) -> Duration {
    if tor_always {
        Duration::from_secs(45)
    } else {
        peer.connect_timeout()
    }
}

/// Announce our self-claims for one xite to the DHT and fold any peers the DHT
/// returns into the xite's registry. Returns how many usable peers it found.
/// dht_loop spawns this per xite (bounded concurrency) so a pass stays roughly
/// one lookup deep instead of summing every xite's round trips serially.
async fn dht_announce_xite(
    state: Arc<AppState>,
    dht: Arc<epix_dht::Node>,
    rpc: Arc<epix_dht_net::WireRpcClient>,
    claims: Arc<Vec<PeerAddr>>,
    address: String,
) -> usize {
    let key = epix_dht::xite_key(&address);
    if !claims.is_empty() {
        dht.announce_all(key, claims.as_slice(), rpc.as_ref()).await;
    }
    let mut peers = dht.get_peers(key, rpc.as_ref()).await;
    // Drop unusable claims (a NAT'd announcer's own 0.0.0.0 entry).
    peers.retain(dialable_dht_peer);
    let found = peers.len();
    if found > 0 {
        state.add_peers(&address, peers).await;
    }
    found
}

/// Tracker-independent discovery: a rare xite findable from any peer that
/// serves it, even with every tracker down. Runs on the announce cadence.
async fn dht_loop(
    state: Arc<AppState>,
    dht: Arc<epix_dht::Node>,
    fileserver_port: Option<u16>,
    tor_always: bool,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    let port = fileserver_port.unwrap_or(0);

    // Wait for the transport the DHT's EDX links ride, and resolve the address
    // we claim as our own contact.
    let me_addr = if tor_always {
        // Tor-Always: the DHT must ride Tor, and we claim only our onion. Wait
        // for the onion service - its address appears strictly AFTER tor_loop
        // installs the MixedTransport (set_transport precedes set_onion_address),
        // so its presence is both the readiness gate and the self-claim source.
        // With no fileserver port there is no onion virtual port to claim, so
        // there is nothing to announce.
        if port == 0 {
            state.log("INFO", "DHT: idle in Tor-Always mode (no fileserver port)").await;
            return;
        }
        let onion = loop {
            if let Some(o) = state.onion_address().await {
                break o;
            }
            tokio::select! {
                _ = shutdown.notified() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        };
        if state.transport().await.is_none() {
            return;
        }
        let Ok(me_addr) = PeerAddr::parse(&format!("{onion}.onion:{port}")) else { return };
        state.log("INFO", "DHT: running over Tor (Always mode)").await;
        me_addr
    } else {
        // Wait for the transport (set by the node just before the runtime
        // starts). A NAT'd node doesn't know its public IP; it claims 0.0.0.0
        // and the serving side substitutes the connection's source IP (see
        // DhtService). The port is our real listening port.
        loop {
            if state.transport().await.is_some() {
                break;
            }
            tokio::select! {
                _ = shutdown.notified() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
        PeerAddr::parse(&format!("0.0.0.0:{port}")).expect("addr")
    };

    let me = epix_dht::Contact::new(dht.id, me_addr);
    // Kad RPCs ride EDX links the state's fetcher opens.
    let rpc = Arc::new(epix_dht_net::WireRpcClient::new(
        me,
        Arc::new(edx::EdxKadSender::new(state.clone())),
    ));

    // Expose DHT lookups to the on-demand clone path.
    state
        .set_peer_finder(Arc::new(DhtPeerFinder { dht: dht.clone(), rpc: rpc.clone() }))
        .await;

    let round = || async {
        // 1. Probe a handful of known peers: send FindNode(self) so they learn
        //    our contact and we learn real contacts from their tables. The
        //    probed peer itself is NOT inserted (we don't know its node id; only
        //    contacts carried in responses have authentic ids). Probes run
        //    CONCURRENTLY: over Tor a dial takes tens of seconds and dead peers
        //    hit the full 45s bound, so a serial probe phase (up to 8 x 45s)
        //    would blow the 120s per-pass budget and starve the announce phase
        //    below - the actual point of the pass.
        let addresses = state.xite_addresses().await;
        let mut targets = Vec::new();
        let mut seen = std::collections::HashSet::new();
        'gather: for address in &addresses {
            for peer in state.connectable_peers(address, 3).await {
                if seen.insert(peer.clone()) {
                    targets.push(peer);
                    if targets.len() >= 8 {
                        break 'gather;
                    }
                }
            }
        }
        let probed = targets.len();
        let mut probe_set = tokio::task::JoinSet::new();
        for peer in targets {
            let rpc = rpc.clone();
            let dht = dht.clone();
            // Overlay-aware bound: an onion/i2p contact (or any contact over Tor
            // in Always mode) needs the longer dial deadline to join the table.
            let timeout = dht_dial_timeout(&peer, tor_always);
            probe_set.spawn(async move {
                if let Ok(Ok((responder, contacts))) =
                    tokio::time::timeout(timeout, rpc.probe(&peer, dht.id)).await
                {
                    for contact in std::iter::once(responder).chain(contacts) {
                        if contact.id != dht.id {
                            dht.add_contact(contact);
                        }
                    }
                }
            });
        }
        while probe_set.join_next().await.is_some() {}
        // 2. Announce every served xite and fold in any peers the DHT knows.
        // Self-claims are rebuilt every round: the onion service, I2P session,
        // and mesh come up minutes after start, and this is where they become
        // discoverable (Phase 4 - a Tor/I2P-only publisher is invisible to
        // clearnet-NAT'd nodes otherwise). Clearnet is excluded in Tor-Always
        // mode, where we claim overlays only (see dht_self_claims).
        let claims = Arc::new(dht_self_claims(
            port,
            !tor_always,
            state.onion_address().await,
            state.i2p_address().await,
            state.rns_address().await,
        ));
        // Announce + look up each xite concurrently, bounded. A lookup is
        // several sequential round trips; over Tor each is far slower than
        // clearnet, so a serial pass across ~dozens of xites would not fit the
        // per-pass budget. A small cap keeps the pass roughly one lookup deep
        // without opening too many Tor streams at once.
        const XITE_CONCURRENCY: usize = 4;
        let mut found_total = 0usize;
        let mut set = tokio::task::JoinSet::new();
        let mut pending = addresses.iter().cloned();
        for address in pending.by_ref().take(XITE_CONCURRENCY) {
            set.spawn(dht_announce_xite(
                state.clone(),
                dht.clone(),
                rpc.clone(),
                claims.clone(),
                address,
            ));
        }
        while let Some(res) = set.join_next().await {
            found_total += res.unwrap_or(0);
            if let Some(address) = pending.next() {
                set.spawn(dht_announce_xite(
                    state.clone(),
                    dht.clone(),
                    rpc.clone(),
                    claims.clone(),
                    address,
                ));
            }
        }
        let routing = dht.routing_len();
        if probed > 0 || routing > 0 || found_total > 0 {
            state
                .log(
                    "INFO",
                    format!(
                        "DHT: probed {probed} peer(s), {routing} node(s) in the routing table, {found_total} peer(s) found for {} xite(s)",
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
async fn connection_loop(
    state: Arc<AppState>,
    tor_always: bool,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    // In Always mode, don't warm peer connections until Tor routes our traffic;
    // manage_connections dials candidate peers, which over clearnet leaks our IP.
    if !await_tor_routed(&state, tor_always, &shutdown).await {
        return;
    }
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

/// How often the health prober wakes to look for benched peers due a re-check.
const PROBE_TICK: Duration = Duration::from_secs(30);
/// Most probes in flight at once, and the per-tick candidate cap. An overlay
/// probe builds a whole circuit, so this stays tiny; with the tick period it
/// also bounds total probe work per tick.
const PROBE_CONCURRENCY: usize = 2;

/// Background peer health prober. A peer that stops answering gets benched by
/// the registry's dial backoff, and the streaming path should not burn a
/// session slot rediscovering it. This loop re-checks benched peers whose
/// probe cooldown expired - a fresh dial + control Ping, off the streaming
/// path - and feeds the result back: an answer lifts the dial backoff so
/// connectable_peers returns the peer immediately (session revalidation picks
/// it up on its next window), while the error streak waits for a real fetch -
/// a ping is weaker evidence than the fetch-level failures that bench a peer,
/// and clearing the streak on it kept resurrecting zombies that handshake but
/// never serve. Silence advances the exponential cooldown (~30s doubling to a
/// ~10min cap + jitter, see epix_peer::probe_cooldown_secs).
async fn peer_probe_loop(state: Arc<AppState>, tor_always: bool, shutdown: Arc<Notify>) {
    // Probes are outbound dials: in Always mode, none before Tor routes us.
    if !await_tor_routed(&state, tor_always, &shutdown).await {
        return;
    }
    let mut tick = interval(PROBE_TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // nothing is benched at startup; skip the immediate tick
    loop {
        tokio::select! {
            _ = shutdown.notified() => return,
            _ = tick.tick() => {}
        }
        let Some(opener) = state.link_opener().await else { continue };
        probe_pass(&state, opener).await;
    }
}

/// One prober pass: probe up to [`PROBE_CONCURRENCY`] due candidates in
/// parallel and fold the outcomes back into the registries. Split from the
/// loop so a test can drive a pass directly. No state lock spans a probe
/// await: candidates are snapshotted first, outcomes recorded after.
async fn probe_pass(state: &Arc<AppState>, opener: Arc<dyn LinkOpener>) {
    let candidates = state.probe_candidates(PROBE_CONCURRENCY).await;
    if candidates.is_empty() {
        return;
    }
    let mut set = tokio::task::JoinSet::new();
    for c in candidates {
        let opener = opener.clone();
        set.spawn(async move {
            let ok = probe_peer(opener.as_ref(), &c.addr).await;
            (c, ok)
        });
    }
    while let Some(res) = set.join_next().await {
        let Ok((c, ok)) = res else { continue };
        state.note_probe_outcome(&c.addr, ok).await;
        if ok {
            state
                .log(
                    "INFO",
                    format!("Peer {} answered a health probe after {} failure(s), reinstated", c.addr, c.failures),
                )
                .await;
        }
    }
}

/// One health probe: a fresh dial + frame-level Ping, bounded end to end
/// (10s clearnet, 30s overlay - an onion dial builds a circuit). The link
/// drops on return, so a probe never holds a connection or a session slot.
async fn probe_peer(opener: &dyn LinkOpener, addr: &PeerAddr) -> bool {
    let budget = if addr.is_overlay() || epix_core::route_all_via_overlay() {
        Duration::from_secs(30)
    } else {
        Duration::from_secs(10)
    };
    matches!(
        tokio::time::timeout(budget, async { opener.open_link(addr.clone()).await?.ping().await })
            .await,
        Ok(Ok(_))
    )
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
async fn wakeup_loop(state: Arc<AppState>, tor_always: bool, shutdown: Arc<Notify>) {
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
            // manage_connections dials peers; in Always mode wait for Tor first
            // so a resume during the Tor bootstrap window can't dial clearnet
            // and leak our IP.
            if !await_tor_routed(&state, tor_always, &shutdown).await {
                break;
            }
            state.manage_connections().await;
        }
    }
}

/// Re-sync every xite (fetch a newer content.json + changed files).
async fn resync_loop(
    state: Arc<AppState>,
    tor_always: bool,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    // Initial user-content pass shortly after start (own task, so the resync
    // ticker isn't delayed): xites cloned before the recursive-content
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
            // sync_user_content dials peers; in Always mode wait for Tor first
            // so the 20s pass can't race the Tor bootstrap and leak our IP.
            if !await_tor_routed(&state, tor_always, &shutdown).await {
                return;
            }
            for address in state.xite_addresses().await {
                state.sync_user_content(&address).await;
            }
        });
    }
    // The resync tick itself dials peers to fetch updates; hold it until Tor
    // routes our traffic in Always mode.
    if !await_tor_routed(&state, tor_always, &shutdown).await {
        return;
    }
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    // Per shard-file backoff for the volunteer sweep below, so files that
    // held nothing are not re-dialed every tick. Loop-local: it dies with
    // the loop, and the sweep is called from nowhere else.
    let mut volunteer_backoff = std::collections::HashMap::new();
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                for address in state.xite_addresses().await {
                    // Show the pass on the dashboard: the quiet "Checking..."
                    // pill while we ask peers whether anything is newer, which
                    // becomes "Updating..." only if one of them says yes (see
                    // `resync_apply_newer`), then an `updated` outcome event.
                    // The phase is registered BEFORE the event so the pushed
                    // siteInfo carries it. The pill only clears on a matching
                    // outcome event, never on a plain refresh.
                    state.begin_xite_update(&address);
                    state.push_xite_info_event(&address, UPDATE_PHASE_CHECKING).await;
                    // The pass runs on its own task so a panic in one xite's
                    // sync can't kill this loop (which would strand the pill
                    // and end all future resyncs) - it surfaces as a JoinError
                    // and counts as a failed update.
                    let joined = tokio::spawn({
                        let state = state.clone();
                        let address = address.clone();
                        async move {
                            let applied = state.resync_xite(&address).await;
                            // New and updated user content (posts, comments)
                            // rides the same cycle, and counts as an update in
                            // its own right: a pass that pulled a new post did
                            // bring something, even when the root content.json
                            // was already current.
                            let user_bytes = state.sync_user_content(&address).await;
                            match applied {
                                Ok(true) => UpdateOutcome::Applied,
                                Ok(false) if user_bytes > 0 => UpdateOutcome::Applied,
                                Ok(false) => UpdateOutcome::NoChange,
                                Err(_) => UpdateOutcome::Failed,
                            }
                        }
                    })
                    .await;
                    state.end_xite_update(&address);
                    let outcome = match joined {
                        Ok(outcome) => outcome,
                        Err(e) => {
                            state
                                .log("ERROR", format!("Resync pass for {address} died: {e}"))
                                .await;
                            UpdateOutcome::Failed
                        }
                    };
                    state.push_update_result(&address, outcome).await;
                }
                // Verified updates whose files couldn't all be fetched are
                // held uncommitted (the previous version keeps serving);
                // re-fetch their missing files and commit the completed ones.
                state.retry_pending_updates().await;
                // Anti-entropy for merge files (posts.json): re-pull + merge
                // from peers so a node that missed a live push still converges.
                state.resync_merge_files().await;
                // OptionalManager: keep optional files under the size cap.
                let freed = state.enforce_optional_limit().await;
                if freed > 0 {
                    state.log("INFO", format!("Optional-file cleanup freed {freed} bytes")).await;
                }
                // Volunteer role: hold our slice of the encrypted shards of
                // whatever private content we have manifests for.
                crate::edx::volunteer_sweep(&state, &mut volunteer_backoff).await;
            }
        }
    }
}

/// Client half of the store-and-forward propagation layer: poll peers for
/// update hints and resync the hinted xites immediately, instead of waiting for
/// the next full `resync_loop` tick.
///
/// A peer records a small `(xite, modified)` notification after an EDX update
/// is verified and its required files have landed, so the hint spreads with
/// the publish flood without advertising content the relay cannot serve. This
/// loop pulls those notifications
/// from a spread of connectable peers, keeps a per-peer cursor so each is seen
/// once, and - for any hint naming a xite we host at an older version
/// (`needs_sync`) - triggers a targeted resync of that one xite. The relay is
/// untrusted: it only hints that an update exists; the resync re-verifies
/// content.json signatures, so a bad hint can at worst cost a wasted resync.
///
/// The 5-minute `resync_loop` stays as the safety net for hints we never hear
/// (every peer holding them was unreachable at poll time).
async fn propagation_loop(
    state: Arc<AppState>,
    tor_always: bool,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    // Polling dials peers; in Tor-Always mode hold until Tor routes our traffic
    // so we never dial over clearnet during the bootstrap window.
    if !await_tor_routed(&state, tor_always, &shutdown).await {
        return;
    }
    // One cursor per propagation peer (keyed by its address), so each peer's
    // notifications are pulled exactly once. Reset on restart, which is the
    // correct "catch up on what I missed while offline" behavior - a re-pull
    // from cursor 0 is filtered by `needs_sync` and stays cheap.
    let mut cursors: HashMap<String, u64> = HashMap::new();
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                let local = state.local_xite_versions().await;
                if local.is_empty() {
                    continue;
                }
                let peers = state.propagation_peers(8).await;
                if peers.is_empty() {
                    continue;
                }
                let polled_keys: HashSet<String> = peers.iter().map(|p| p.to_string()).collect();
                let mut stale: HashSet<String> = HashSet::new();
                for peer in peers {
                    let key = peer.to_string();
                    let after = cursors.get(&key).copied().unwrap_or(0);
                    // The EDX control request carries its own dial + request
                    // bounds. Only a completed reply advances the cursor, so a
                    // dead peer re-asks from the same point next pass.
                    let Some(Ok((updates, head))) =
                        state.edx_updates_since(peer, after).await
                    else {
                        continue;
                    };
                    cursors.insert(key, head);
                    let notifs: Vec<epix_propagation::Notification> = updates
                        .into_iter()
                        .map(|(xite, modified)| epix_propagation::Notification { xite, modified })
                        .collect();
                    for n in epix_propagation::needs_sync(&notifs, &local) {
                        stale.insert(n.xite);
                    }
                }
                // Drop cursors for peers we no longer poll, so the map can't grow
                // without bound as peer sets churn.
                cursors.retain(|k, _| polled_keys.contains(k));
                for address in stale {
                    if !state.is_serving(&address).await {
                        continue;
                    }
                    state.log("INFO", format!("Propagation hint: resyncing {address}")).await;
                    // Mirror the resync tick's per-xite work for this one xite:
                    // root content.json + changed files, then user content
                    // (posts/comments), then an unconditional merge-record pull
                    // (upvotes/comments live in CRDT merge files that bypass hash
                    // sync, so a "content already current" resync never fetches
                    // them). Each fires its own file_done/updated events, so open
                    // pages re-query as the data lands.
                    //
                    // Bracketed like the tick above so the row shows what is
                    // happening: a hint means a peer told us this xite moved,
                    // so the pill usually goes checking -> updating -> the file
                    // countdown rather than quietly retiring.
                    state.begin_xite_update(&address);
                    state.push_xite_info_event(&address, UPDATE_PHASE_CHECKING).await;
                    let applied = state.resync_xite(&address).await;
                    let user_bytes = state.sync_user_content(&address).await;
                    state.resync_merge_files_for(&address).await;
                    state.end_xite_update(&address);
                    let outcome = match applied {
                        Ok(true) => UpdateOutcome::Applied,
                        Ok(false) if user_bytes > 0 => UpdateOutcome::Applied,
                        Ok(false) => UpdateOutcome::NoChange,
                        Err(_) => UpdateOutcome::Failed,
                    };
                    state.push_update_result(&address, outcome).await;
                }
            }
        }
    }
}

/// Serve inbound peers (seeding) on `port` until shutdown. Peers bring up an
/// EDX link and pull verified ranges over it.
#[cfg(feature = "inbound-seeding")]
async fn seed_loop(
    state: Arc<AppState>,
    port: u16,
    clearnet: bool,
    edx_cell: edx::EdxServeCell,
    shutdown: Arc<Notify>,
) {
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            state.log("ERROR", format!("File server bind on port {port} failed: {e}")).await;
            return;
        }
    };
    // Open the content-addressed object store + the verified-streaming fetcher
    // (shared across every transport via edx_cell) and register the loaded
    // xites. Without a data dir there is nowhere to put the store, so such a
    // node cannot seed at all.
    let Some(es) = edx::ensure_edx_serve(&edx_cell, &state).await else {
        state.log("INFO", "No EDX object store: not seeding".to_string()).await;
        return;
    };
    // A real peer reaching us over clearnet TCP proves the fileserver port is
    // open from the internet - the privacy-preserving alternative to the Python
    // client's third-party port-scan services (no phone-home). The first public
    // inbound peer flips the status if nothing already has (a public interface
    // IP or UPnP may have set it first). Onion/I2P inbound never runs this
    // server, so it stays strictly clearnet.
    let mut on_inbound = None;
    if clearnet {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::net::SocketAddr>();
        let listener_state = state.clone();
        tokio::spawn(async move {
            while let Some(addr) = rx.recv().await {
                if is_public_ipv4(&addr.ip()) {
                    let (already, known_ip) = listener_state.port_status().await;
                    if !already {
                        // Keep OUR external address (detected/configured by
                        // the UPnP loop) - the inbound peer's address is
                        // theirs, not ours.
                        listener_state.set_port_status(true, known_ip).await;
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
        on_inbound = Some(Arc::new(move |peer: &epix_core::PeerAddr| {
            if let epix_core::PeerAddr::Ip(addr) = peer {
                let _ = tx.send(*addr);
            }
        }) as epix_protocol::InboundHook);
    }
    let server = epix_protocol::PeerServer::new(es.clearnet_hook(on_inbound));
    state.log("INFO", format!("Seeding files (+ DHT + propagation) on port {port}")).await;
    tokio::select! {
        _ = shutdown.notified() => {}
        _ = server.serve(listener) => {}
    }
}

/// Bridges the Arti-persisted onion identity key to the announcer's
/// challenge-signing hook (`epix-tor` doesn't depend on `epix-discovery`).
#[cfg(feature = "tor")]
struct TorOnionSigner(epix_tor::OnionKey);

#[cfg(feature = "tor")]
impl epix_xite::OnionSigner for TorOnionSigner {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }

    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg)
    }
}

/// The result of one arti bootstrap attempt under the watchdog.
#[cfg(feature = "tor")]
enum BootstrapAttempt {
    /// Tor is up and usable.
    Ready(epix_tor::Tor),
    /// The attempt failed or timed out; the string is a ready-to-log reason.
    Failed(String),
    /// Shutdown fired mid-attempt; the caller should stop.
    Shutdown,
}

/// Bootstrap arti, returning the client once it is up, or `None` if shutdown
/// fired before that.
///
/// A fresh install on a slow or filtered network (the VirtualBox Windows 10 in
/// EpixNet#239) can take minutes or stall outright. With no timeout the task
/// parks forever inside arti, the status stays "Bootstrapping" - which the UI
/// renders as "off" - and nothing ever explains why. Cap each attempt (see
/// [`bootstrap_tor_attempt`]) and keep retrying with a backoff so a transient
/// failure self-heals once the network settles. arti's own reason now reaches
/// the log via the node's tracing subscriber; these lines add the coarse story
/// to the in-UI log.
///
/// Returns the bootstrapped client together with a session guard the caller
/// holds for as long as Tor should run: under `bridges` it owns the running
/// Snowflake (dropping it stops the transport), so the bridge stays up for the
/// whole session, not just the bootstrap.
#[cfg(all(feature = "tor", feature = "bridges"))]
type SnowflakeGuard = Option<epix_tor::bridges::Snowflake>;
#[cfg(all(feature = "tor", not(feature = "bridges")))]
type SnowflakeGuard = ();

#[cfg(feature = "tor")]
async fn bootstrap_tor_with_watchdog(
    state: &AppState,
    data_dir: &std::path::Path,
    shutdown: &Notify,
    force_bridges: bool,
) -> Option<(epix_tor::Tor, SnowflakeGuard)> {
    const RETRY_BACKOFF_SECS: u64 = 30;
    // Consecutive direct-bootstrap failures to tolerate before auto-falling back
    // to a Snowflake bridge (the signature of a network that blocks Tor, like
    // EpixNet#239). `tor_use_bridges` forces the bridge up front instead.
    #[cfg(feature = "bridges")]
    const DIRECT_FAILURES_BEFORE_BRIDGE: u32 = 2;

    // Surface a bootstrapping state so the browser's Tor icon can show progress.
    state.set_tor_status(false, "Bootstrapping").await;

    #[allow(unused_mut)] // both are only reassigned under the `bridges` feature
    let mut opts = epix_tor::BootstrapOpts::default();
    #[allow(unused_mut)]
    let mut attempt_timeout_secs = 150u64;
    // Snowflake guard, held for the rest of the call once started (eagerly when
    // forced, else lazily after repeated direct failures).
    #[cfg(feature = "bridges")]
    let mut snowflake: Option<epix_tor::bridges::Snowflake> = None;
    #[cfg(feature = "bridges")]
    let mut failures = 0u32;

    #[cfg(feature = "bridges")]
    if force_bridges {
        if let Some((guard, o, t)) = start_snowflake_bridge(state, data_dir).await {
            snowflake = Some(guard);
            opts = o;
            attempt_timeout_secs = t;
        }
    }
    #[cfg(not(feature = "bridges"))]
    let _ = force_bridges;

    loop {
        state.log("INFO", "Tor: bootstrapping in-process Arti client …".to_string()).await;
        match bootstrap_tor_attempt(state, data_dir, shutdown, &opts, attempt_timeout_secs).await {
            BootstrapAttempt::Ready(tor) => {
                #[cfg(feature = "bridges")]
                return Some((tor, snowflake));
                #[cfg(not(feature = "bridges"))]
                return Some((tor, ()));
            }
            BootstrapAttempt::Shutdown => {
                state.set_tor_status(false, "Disabled").await;
                return None;
            }
            BootstrapAttempt::Failed(reason) => state.log("ERROR", reason).await,
        }

        // Auto-fallback: after repeated direct failures, bring Snowflake up and
        // route later attempts through it. Once up it stays up for this call.
        #[cfg(feature = "bridges")]
        {
            failures += 1;
            if snowflake.is_none() && failures >= DIRECT_FAILURES_BEFORE_BRIDGE {
                state
                    .log(
                        "INFO",
                        "Tor: direct bootstrap keeps failing; trying a Snowflake bridge".to_string(),
                    )
                    .await;
                if let Some((guard, o, t)) = start_snowflake_bridge(state, data_dir).await {
                    snowflake = Some(guard);
                    opts = o;
                    attempt_timeout_secs = t;
                }
            }
        }

        // Make the failure visible instead of a silent perpetual "Bootstrapping",
        // then wait before the next attempt (waking early on shutdown).
        state.set_tor_status(false, "Failed").await;
        state.log("INFO", format!("Tor: retrying bootstrap in {RETRY_BACKOFF_SECS}s …")).await;
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(RETRY_BACKOFF_SECS)) => {}
            _ = shutdown.notified() => {
                state.set_tor_status(false, "Disabled").await;
                return None;
            }
        }
        state.set_tor_status(false, "Bootstrapping").await;
    }
}

/// Fetch the current Snowflake rendezvous params from Tor's Moat API - through
/// the node's Tor SOCKS listener when it is up, so it also works on a censored
/// link - and persist them into `snowflake.json`'s fetched section. Best-effort:
/// any failure just leaves the existing params in place.
#[cfg(all(feature = "tor", feature = "bridges"))]
async fn refresh_snowflake_params(
    state: &AppState,
    data_dir: &std::path::Path,
    socks_port: Option<u16>,
) {
    // The SOCKS listener is bound a little later in `tor_loop`; give it a moment
    // so the fetch routes through Tor rather than hitting an unbound port.
    tokio::time::sleep(Duration::from_secs(10)).await;
    state
        .log("INFO", "Snowflake: refreshing rendezvous params from Tor's Moat API".to_string())
        .await;
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(60));
    if let Some(port) = socks_port {
        if let Ok(proxy) = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")) {
            builder = builder.proxy(proxy);
        }
    }
    let Ok(client) = builder.build() else { return };
    let resp = client
        .get(epix_tor::bridges::MOAT_BUILTIN_URL)
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
        .and_then(|r| r.error_for_status());
    let json = match resp {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(_) => return,
        },
        Err(e) => {
            state.log("INFO", format!("Snowflake: rendezvous refresh skipped ({e})")).await;
            return;
        }
    };
    match epix_tor::bridges::persist_fetched(data_dir, &json) {
        Ok(true) => {
            state
                .log("INFO", "Snowflake: refreshed rendezvous params from Tor's Moat API".to_string())
                .await
        }
        Ok(false) => {}
        Err(e) => state.log("INFO", format!("Snowflake: rendezvous refresh failed ({e})")).await,
    }
}

/// Start the in-process Snowflake bridge and build the bootstrap options that
/// route arti through it: `(guard, opts, attempt_timeout_secs)`. `None` if
/// Snowflake is unavailable (the caller then keeps trying direct).
#[cfg(all(feature = "tor", feature = "bridges"))]
async fn start_snowflake_bridge(
    state: &AppState,
    data_dir: &std::path::Path,
) -> Option<(epix_tor::bridges::Snowflake, epix_tor::BootstrapOpts, u64)> {
    // The bridge line and rendezvous params come from the built-in defaults,
    // overridable per node via `<data_dir>/private/snowflake.json` (edited by
    // hand when the public defaults rotate).
    let bridge_line = epix_tor::bridges::bridge_line(data_dir);
    match epix_tor::bridges::start_snowflake(data_dir).await {
        Ok((guard, port)) => {
            state.log("INFO", format!("Tor: Snowflake up, SOCKS on 127.0.0.1:{port}")).await;
            let opts = epix_tor::BootstrapOpts { bridge: Some((bridge_line, port)) };
            // WebRTC rendezvous is legitimately slow on a censored link.
            Some((guard, opts, 300))
        }
        Err(e) => {
            state.log("ERROR", format!("Tor: Snowflake unavailable ({e})")).await;
            None
        }
    }
}

/// One bootstrap attempt: race the bootstrap against a heartbeat that logs
/// progress every `HEARTBEAT_SECS` and gives up after `ATTEMPT_TIMEOUT_SECS`,
/// and against shutdown. Dropping the bootstrap future on timeout cancels it.
#[cfg(feature = "tor")]
async fn bootstrap_tor_attempt(
    state: &AppState,
    data_dir: &std::path::Path,
    shutdown: &Notify,
    opts: &epix_tor::BootstrapOpts,
    attempt_timeout_secs: u64,
) -> BootstrapAttempt {
    const HEARTBEAT_SECS: u64 = 15;
    let boot = epix_tor::Tor::bootstrap(data_dir, opts);
    tokio::pin!(boot);
    let mut elapsed = 0u64;
    let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
    ticker.tick().await; // an interval fires immediately; drop the zero tick
    loop {
        tokio::select! {
            res = &mut boot => {
                return match res {
                    Ok(tor) => BootstrapAttempt::Ready(tor),
                    Err(e) => BootstrapAttempt::Failed(format!("Tor bootstrap failed: {e}")),
                };
            }
            _ = ticker.tick() => {
                elapsed += HEARTBEAT_SECS;
                if elapsed >= attempt_timeout_secs {
                    return BootstrapAttempt::Failed(format!(
                        "Tor bootstrap did not complete within {attempt_timeout_secs}s"
                    ));
                }
                state.log("INFO", format!("Tor: still bootstrapping ({elapsed}s elapsed) …")).await;
            }
            _ = shutdown.notified() => return BootstrapAttempt::Shutdown,
        }
    }
}

/// Why one Tor generation stopped serving.
#[cfg(feature = "tor")]
enum TorGenerationEnd {
    /// The node is shutting down; leave Tor down.
    Shutdown,
    /// Onion transport stopped working. Clear the guard sample and re-bootstrap.
    Unhealthy,
}

/// How often to probe that onion traffic still works.
#[cfg(feature = "tor")]
const ONION_HEALTH_INTERVAL: Duration = Duration::from_secs(180);
/// Budget for one probe. A live onion dial needs a descriptor fetch plus a
/// rendezvous circuit (single-digit seconds when healthy), so this is generous
/// enough that only a real outage trips it.
#[cfg(feature = "tor")]
const ONION_PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// Consecutive failed probes before rebuilding the client. Onion circuits fail
/// individually all the time; only a sustained run means the guard sample has
/// gone bad, and the rebuild is disruptive enough to be worth confirming.
#[cfg(feature = "tor")]
const ONION_FAILURES_BEFORE_RESET: u32 = 3;
/// Shortest gap between two client rebuilds, doubled per repeat up to
/// [`ONION_REBUILD_MAX_BACKOFF_SECS`].
///
/// A rebuild that is followed within minutes by the same failure did not help:
/// the cause is outside the guard sample (a hostile or throttled link), and
/// rebuilding again just adds another bootstrap plus descriptor republish, with
/// the client fully down in between. Rate-limiting the *rebuild* while leaving
/// the current client running keeps whatever partial service it still provides.
#[cfg(feature = "tor")]
const ONION_REBUILD_BACKOFF_SECS: i64 = 15 * 60;
#[cfg(feature = "tor")]
const ONION_REBUILD_MAX_BACKOFF_SECS: i64 = 2 * 60 * 60;
/// A generation that served this long before failing means the previous rebuild
/// worked, so the next failure starts the escalation over rather than inheriting
/// a backoff earned hours earlier.
#[cfg(feature = "tor")]
const ONION_REBUILD_ESCALATION_RESET_SECS: i64 = 60 * 60;

/// Seconds since the Unix epoch.
#[cfg(feature = "tor")]
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Resolve once onion transport has been unreachable for
/// `ONION_FAILURES_BEFORE_RESET` consecutive probes - the signal that arti's
/// guard sample has rotted and the client needs rebuilding.
///
/// Arti can keep reporting "bootstrapped", keep its directory fresh and keep
/// building ordinary exit circuits while every onion circuit dies, so the node
/// looks healthy from the inside and is invisible to the network: peers cannot
/// fetch from us and we cannot reach them. Probing is the only way to see it.
/// Pends forever when there is no onion service to probe (nothing to check, and
/// nothing that a rebuild would fix).
///
/// `earliest_rebuild` (unix seconds) rate-limits the rebuild, not the probing:
/// while the threshold is met but the gap has not elapsed, the current client
/// keeps running and is re-probed each interval, so a client that recovers on
/// its own is never torn down and one that stays broken is rebuilt as soon as
/// the gap passes.
#[cfg(feature = "tor")]
async fn await_onion_failure(
    state: &AppState,
    tor: &epix_tor::Tor,
    onion: Option<(String, u16)>,
    earliest_rebuild: i64,
) {
    let Some((host, port)) = onion else {
        std::future::pending::<()>().await;
        return;
    };
    let mut failures = 0u32;
    let mut held_off = false;
    loop {
        tokio::time::sleep(ONION_HEALTH_INTERVAL).await;
        if tor.onion_reachable(&host, port, ONION_PROBE_TIMEOUT).await {
            failures = 0;
            held_off = false;
            continue;
        }
        failures += 1;
        state
            .log(
                "WARNING",
                format!(
                    "Tor: onion self-check failed ({failures}/{ONION_FAILURES_BEFORE_RESET}); \
                     peers cannot reach this node over Tor"
                ),
            )
            .await;
        if failures < ONION_FAILURES_BEFORE_RESET {
            continue;
        }
        let now = unix_now();
        if now >= earliest_rebuild {
            return;
        }
        // Stay armed at the threshold so the rebuild happens on the first probe
        // after the gap, without re-running the whole confirmation streak.
        failures = ONION_FAILURES_BEFORE_RESET;
        if !held_off {
            held_off = true;
            state
                .log(
                    "WARNING",
                    format!(
                        "Tor: onion still unreachable, but the last rebuild did not help; \
                         keeping this client and retrying the rebuild in {}m",
                        (earliest_rebuild - now).max(0) / 60
                    ),
                )
                .await;
        }
    }
}

/// Bootstrap in-process Tor and run its three surfaces until shutdown: the peer
/// transport (set on the app state so onion peers are dialable, or all traffic
/// is Tor-routed in Always mode), an onion service whose inbound streams feed
/// the same node handler as the TCP seed loop, and a local SOCKS listener for
/// the browser shells.
///
/// Runs as a supervision loop: each pass owns one bootstrapped client and the
/// surfaces built on it, and a failed onion health check ends the pass so the
/// poisoned guard state can be cleared and the client rebuilt.
#[cfg(feature = "tor")]
async fn tor_loop(
    state: Arc<AppState>,
    data_dir: std::path::PathBuf,
    mode: epix_tor::TorMode,
    fileserver_port: Option<u16>,
    socks_port: Option<u16>,
    tor_use_bridges: bool,
    edx_cell: edx::EdxServeCell,
    shutdown: Arc<Notify>,
) {
    // Repeated rebuilds that do not help are throttled (see
    // ONION_REBUILD_BACKOFF_SECS); a generation that serves well before failing
    // clears the escalation.
    let mut consecutive_rebuilds = 0u32;
    let mut earliest_rebuild = 0i64;
    loop {
        let started = unix_now();
        let end = run_tor_generation(
            state.clone(),
            data_dir.clone(),
            mode,
            fileserver_port,
            socks_port,
            tor_use_bridges,
            edx_cell.clone(),
            shutdown.clone(),
            earliest_rebuild,
        )
        .await;
        match end {
            TorGenerationEnd::Shutdown => break,
            TorGenerationEnd::Unhealthy => {
                if unix_now().saturating_sub(started) >= ONION_REBUILD_ESCALATION_RESET_SECS {
                    consecutive_rebuilds = 0;
                }
                consecutive_rebuilds += 1;
                let backoff = ONION_REBUILD_BACKOFF_SECS
                    .saturating_mul(1 << (consecutive_rebuilds - 1).min(3))
                    .min(ONION_REBUILD_MAX_BACKOFF_SECS);
                earliest_rebuild = unix_now().saturating_add(backoff);
                // Fail closed while no client is routed: in Always mode a
                // transport without Tor must never fall through to clearnet.
                state.set_transport(Arc::new(epix_tor::MixedTransport::new(None, mode))).await;
                state.set_tor_status(false, "Recovering").await;
                let cleared = epix_tor::reset_guard_state(&data_dir);
                state
                    .log(
                        "WARNING",
                        format!(
                            "Tor: onion transport was dead; {}re-bootstrapping \
                             (the .onion address is unchanged; rebuild {consecutive_rebuilds}, \
                             next one no sooner than {}m from now)",
                            if cleared { "cleared the guard sample and " } else { "" },
                            backoff / 60
                        ),
                    )
                    .await;
                // Give the decommissioned onion service and the SOCKS listener a
                // moment to release the port the next generation rebinds.
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
    state.set_tor_status(false, "Disabled").await;
}

/// One Tor generation: bootstrap a client, run the transport, onion service and
/// SOCKS listener on it, and serve until shutdown or an onion health failure.
/// Every task spawned here is tied to `generation` so the whole set is torn down
/// together when the generation ends.
#[cfg(feature = "tor")]
async fn run_tor_generation(
    state: Arc<AppState>,
    data_dir: std::path::PathBuf,
    mode: epix_tor::TorMode,
    fileserver_port: Option<u16>,
    socks_port: Option<u16>,
    tor_use_bridges: bool,
    edx_cell: edx::EdxServeCell,
    shutdown: Arc<Notify>,
    earliest_rebuild: i64,
) -> TorGenerationEnd {
    // Cancels this generation's spawned tasks (onion accept loop, SOCKS).
    let (generation, _) = tokio::sync::watch::channel(false);
    // Bootstrap under a watchdog (heartbeat + timeout + retry). It starts a
    // Snowflake bridge when `tor_use_bridges` forces it, or automatically after
    // repeated direct failures (a censored network). `None` means shutdown fired
    // before Tor came up, so the loop stops. The guard keeps Snowflake up for
    // the whole session (not just the bootstrap); it is dropped on shutdown or
    // when the bridge is turned off live.
    let Some((tor, snowflake_guard)) =
        bootstrap_tor_with_watchdog(&state, &data_dir, &shutdown, tor_use_bridges).await
    else {
        return TorGenerationEnd::Shutdown;
    };
    state.log("INFO", "Tor: bootstrapped".to_string()).await;
    // Set once the onion service is up; what the health watchdog probes.
    let mut onion_probe: Option<(String, u16)> = None;

    // Self-heal the Snowflake rendezvous params: now that Tor is up (possibly
    // via the current params on a censored link), refresh them from Tor's Moat
    // API through this Tor circuit and persist, so the next start uses a current
    // set even if the built-in defaults have since rotated. Best-effort, in the
    // background.
    #[cfg(feature = "bridges")]
    {
        let state = state.clone();
        let data_dir = data_dir.clone();
        tokio::spawn(async move {
            refresh_snowflake_params(&state, &data_dir, socks_port).await;
        });
    }

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
                onion_probe = Some((onion_host.clone(), port));
                // Handshakes on Tor-bound connections now offer this onion as
                // our dial-back address (Phase 6).
                let advert_host = onion_host.clone();
                epix_protocol::update_self_advert(move |a| a.onion = Some(advert_host));
                // Load the identity key so announces can answer the tracker's
                // onion-ownership challenge; without it the onion is never
                // registered and Tor-only peers can't discover us.
                match epix_tor::OnionKey::load(&data_dir, "epix") {
                    Ok(key) => {
                        state.set_onion_signer(std::sync::Arc::new(TorOnionSigner(key))).await
                    }
                    Err(e) => {
                        state
                            .log(
                                "WARNING",
                                format!("Tor: onion identity key unavailable ({e}); tracker onion announces will not register"),
                            )
                            .await
                    }
                }
                let hook_state = state.clone();
                let hook_cell = edx_cell.clone();
                let mut gen_rx = generation.subscribe();
                tokio::spawn(async move {
                    // The RunningOnionService handle keeps the service alive:
                    // dropping it decommissions the service, so its descriptor
                    // is never published and no peer can ever reach us. Hold it
                    // for as long as we accept inbound streams (the process
                    // lifetime).
                    let _svc = svc;
                    // Onion streams are already encrypted, so EDX skips Noise
                    // here (the overlay hook).
                    let Some(es) = edx::ensure_edx_serve(&hook_cell, &hook_state).await else {
                        return;
                    };
                    let edx_hook = es.overlay_hook();
                    loop {
                        // Ending the generation drops `_svc`, decommissioning the
                        // service so the rebuilt client can relaunch it on the
                        // same key (and so the same address).
                        let stream = tokio::select! {
                            _ = gen_rx.changed() => break,
                            recv = inbound.recv() => match recv {
                                Some(s) => s,
                                None => break,
                            },
                        };
                        let edx_hook = edx_hook.clone();
                        // Inbound onion peers arrive with no dial-back address;
                        // the Hello carries the peer's advertised `onion`
                        // self-address. Until then it is an empty placeholder
                        // that never enters a peer table.
                        let peer = epix_core::PeerAddr::Onion {
                            host: String::new(),
                            port: 0,
                        };
                        tokio::spawn(async move { edx_hook(peer, stream).await });
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
                let mut gen_rx = generation.subscribe();
                tokio::spawn(async move {
                    // Cancelling drops the listener, freeing the port for the
                    // next generation to rebind.
                    tokio::select! {
                        _ = gen_rx.changed() => {}
                        _ = tor.serve_socks(listener) => {}
                    }
                });
            }
            Err(e) => state.log("WARNING", format!("Tor: SOCKS bind on {sport} failed: {e}")).await,
        }
    }

    // Serve until shutdown. The bridges setting (`tor_use_bridges`) applies live:
    // when it changes, reconfigure the running client to add or drop the
    // Snowflake bridge (Arti retires the affected circuits and rebuilds them over
    // the new path) instead of restarting the node - the onion service and SOCKS
    // listener above keep running on the same client throughout.
    // A third exit joins shutdown and the bridges setting: the onion health
    // watchdog, which ends the generation so the caller can clear the guard
    // sample and rebuild the client.
    #[cfg(feature = "bridges")]
    let end = {
        let tor_config_changed = state.tor_config_changed();
        let mut snowflake_guard = snowflake_guard;
        let health = await_onion_failure(&state, &tor, onion_probe, earliest_rebuild);
        tokio::pin!(health);
        loop {
            tokio::select! {
                _ = shutdown.notified() => break TorGenerationEnd::Shutdown,
                _ = tor_config_changed.notified() => {
                    apply_bridge_change(&state, &data_dir, &tor, &mut snowflake_guard).await;
                }
                _ = &mut health => break TorGenerationEnd::Unhealthy,
            }
        }
    };
    #[cfg(not(feature = "bridges"))]
    let end = {
        let _ = snowflake_guard;
        tokio::select! {
            _ = shutdown.notified() => TorGenerationEnd::Shutdown,
            _ = await_onion_failure(&state, &tor, onion_probe, earliest_rebuild) => TorGenerationEnd::Unhealthy,
        }
    };

    // Tear down this generation's surfaces before the client is dropped.
    let _ = generation.send(true);
    end
}

/// Apply a live change to the Tor bridges setting on the running client: start
/// Snowflake and reconfigure to route through it when the setting is turned on,
/// or reconfigure back to direct guards and stop Snowflake when turned off. A
/// no-op when the current guard state already matches the setting.
#[cfg(all(feature = "tor", feature = "bridges"))]
async fn apply_bridge_change(
    state: &AppState,
    data_dir: &std::path::Path,
    tor: &epix_tor::Tor,
    guard: &mut Option<epix_tor::bridges::Snowflake>,
) {
    let want = state.config_bool("tor_use_bridges", false).await;
    if want == guard.is_some() {
        return;
    }
    if want {
        // Start Snowflake, then point the live client at its bridge.
        let Some((snowflake, opts, _)) = start_snowflake_bridge(state, data_dir).await else {
            return; // unavailable; start_snowflake_bridge already logged why
        };
        match tor.reconfigure_bridge(data_dir, opts.bridge) {
            Ok(()) => {
                *guard = Some(snowflake);
                state
                    .log("INFO", "Tor: now routing through the Snowflake bridge (applied live)".to_string())
                    .await;
            }
            // Dropping `snowflake` here stops the transport we could not use.
            Err(e) => state.log("ERROR", format!("Tor: enabling the bridge failed ({e})")).await,
        }
    } else {
        match tor.reconfigure_bridge(data_dir, None) {
            Ok(()) => {
                *guard = None; // drops the guard, stopping Snowflake
                state
                    .log("INFO", "Tor: routing directly again (bridge turned off, applied live)".to_string())
                    .await;
            }
            Err(e) => state.log("ERROR", format!("Tor: disabling the bridge failed ({e})")).await,
        }
    }
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
    identity_path: Option<std::path::PathBuf>,
    tcp_peers: Vec<String>,
    tcp_listen: Option<String>,
    edx_cell: edx::EdxServeCell,
    shutdown: Arc<Notify>,
) {
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
    // A Hello over a mesh link now offers this destination hash as our
    // dial-back address (Phase 6) - the inbound link id a peer sees is not it.
    let advert_hash = node.dest_hash_hex();
    epix_protocol::update_self_advert(move |a| a.rns = Some(advert_hash));

    // Announce our destination and serve inbound links until shutdown. Mesh
    // links are already encrypted, so EDX skips Noise (the overlay hook).
    let announce = node.spawn_announce(Duration::from_secs(60));
    let serve = edx::ensure_edx_serve(&edx_cell, &state)
        .await
        .map(|es| {
            let hook = es.overlay_hook();
            tokio::spawn(async move { node.serve(hook).await })
        });

    shutdown.notified().await;
    announce.abort();
    if let Some(serve) = serve {
        serve.abort();
    }
}

#[cfg(feature = "i2p")]
async fn i2p_loop(
    state: Arc<AppState>,
    data_dir: std::path::PathBuf,
    mode: String,
    sam_port: u16,
    fileserver_port: Option<u16>,
    edx_cell: edx::EdxServeCell,
    shutdown: Arc<Notify>,
) {
    let config = epix_i2p::I2pConfig {
        mode: epix_i2p::I2pMode::parse(&mode),
        sam_tcp_port: sam_port,
        data_dir,
    };
    state.log("INFO", format!("I2P: starting ({mode} router) in the background")).await;
    let (i2p, mut inbound) = epix_i2p::I2p::spawn(config);

    // Layer .b32.i2p dialing onto the transport (composed with TCP/Tor).
    state.set_i2p_transport(Arc::new(i2p.transport())).await;

    // Feed inbound I2P peer streams to the same EDX serve context the TCP
    // listener uses.
    if fileserver_port.is_some() {
        let hook_state = state.clone();
        tokio::spawn(async move {
            // I2P streams are already encrypted, so EDX skips Noise here.
            let Some(es) = edx::ensure_edx_serve(&edx_cell, &hook_state).await else { return };
            let edx_hook = es.overlay_hook();
            while let Some(stream) = inbound.recv().await {
                let edx_hook = edx_hook.clone();
                // Inbound I2P peers arrive with no dial-back address; the Hello
                // carries the peer's advertised `i2p` destination. Until then it
                // is an empty placeholder that never enters a peer table.
                let peer = epix_core::PeerAddr::I2p { dest: String::new(), port: 0 };
                tokio::spawn(async move { edx_hook(peer, stream).await });
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
                // A Hello on an i2p connection now offers this destination as
                // our dial-back address (Phase 6).
                let advert_dest = host.to_string();
                epix_protocol::update_self_advert(move |a| a.i2p = Some(advert_dest));
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

    // A clearnet node with a directly-routable path (configured IP, or a
    // dial-back-confirmed public IP) needs no UPnP: the status is settled and
    // the task just holds until shutdown. Only a NAT'd host falls through.
    if clearnet && resolve_direct_port_status(&state, port).await {
        shutdown.notified().await;
        state.set_port_status(false, None).await;
        return;
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
    // The verdict + external IP adopted after the first successful mapping,
    // reused on lease renewals so a verified-closed port doesn't flap open.
    let mut verified: Option<(bool, Option<String>)> = None;

    loop {
        match gateway
            .add_port(PortMappingProtocol::TCP, port, local, LEASE, "EpixNet fileserver")
            .await
        {
            Ok(()) => {
                if verified.is_none() {
                    verified = Some(verify_mapped_port(&state, port, clearnet, &ext_ip).await);
                }
                let (opened, ip) = verified.clone().unwrap_or((true, ext_ip.clone()));
                state.set_port_status(opened, ip).await;
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

/// Try to settle the fileserver port status for a clearnet node WITHOUT UPnP:
/// an operator-configured `ip_external`, or the Python client's dial-back
/// check (an external service connects to our port and reports both the
/// verdict and our external IP). Returns true if the status is settled (the
/// caller holds until shutdown); false means a NAT'd host that should try
/// UPnP mapping instead.
///
/// A public interface IP is NOT proof of reachability: provider panel
/// firewalls (VPS hosts allow 22/80/443 by default) silently drop other
/// ports, and assuming "public IP = open" hid exactly that on the gateway.
#[cfg(feature = "inbound-seeding")]
async fn resolve_direct_port_status(state: &Arc<AppState>, port: u16) -> bool {
    // Operator-configured external IP: trusted as-is (Python parity:
    // "Server port opened based on configuration").
    let configured = state
        .config_get("ip_external")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|s| !s.trim().is_empty());
    if let Some(ip) = configured {
        state.set_port_status(true, Some(ip.clone())).await;
        state
            .log("INFO", format!("Fileserver port {port} open (ip_external configured: {ip})"))
            .await;
        return true;
    }

    let Some(check) = crate::portcheck::port_check(port).await else {
        // No check service reachable: reachability is UNKNOWN. A public-IP
        // host records the address and lets the first inbound handshake
        // confirm; a NAT'd host falls through to UPnP.
        let Some(ip) = public_ipv4() else { return false };
        let (already_open, _) = state.port_status().await;
        state.set_port_status(already_open, Some(ip.to_string())).await;
        state
            .log(
                "INFO",
                format!(
                    "Port check services unreachable; {ip}:{port} reported open once an inbound connection confirms it"
                ),
            )
            .await;
        return true;
    };

    // Never regress a confirmation that raced in from the seed listener (an
    // inbound handshake is proof too).
    let (already_open, _) = state.port_status().await;
    state.set_port_status(check.opened || already_open, Some(check.ip.clone())).await;
    if check.opened {
        state
            .log("INFO", format!("Port check: {}:{port} is reachable from the internet", check.ip))
            .await;
        return true;
    }
    state
        .log(
            "WARNING",
            format!("Port check: {}:{port} is NOT reachable from the internet", check.ip),
        )
        .await;
    // Public IP and still unreachable: there is no NAT router to map, so
    // something upstream drops the port. An inbound handshake still flips the
    // status if the path opens later (see seed_loop). A NAT'd host (no public
    // IP) returns false to try UPnP.
    if public_ipv4().is_some() {
        state
            .log(
                "WARNING",
                format!(
                    "The OS is listening on port {port} but probes never arrive; check the provider/network firewall for TCP {port}"
                ),
            )
            .await;
        return true;
    }
    false
}

/// After a UPnP mapping succeeds, confirm it actually opened the port with a
/// dial-back check (a mapping can "succeed" behind double-NAT or upstream
/// filtering, like Python's portOpen -> portCheck). Returns the `(opened, ip)`
/// to record; with no check service reachable, stays optimistic (the old
/// behavior) and reports the router's external IP.
#[cfg(feature = "inbound-seeding")]
async fn verify_mapped_port(
    state: &Arc<AppState>,
    port: u16,
    clearnet: bool,
    ext_ip: &Option<String>,
) -> (bool, Option<String>) {
    let check = if clearnet { crate::portcheck::port_check(port).await } else { None };
    match check {
        Some(check) => {
            state
                .log(
                    "INFO",
                    format!(
                        "UPnP: mapped port {port}; dial-back check: {} (external {})",
                        if check.opened { "reachable" } else { "still not reachable" },
                        check.ip
                    ),
                )
                .await;
            (check.opened, Some(check.ip))
        }
        None => {
            let ip = ext_ip.clone().unwrap_or_else(|| "?".into());
            state.log("INFO", format!("UPnP: opened port {port} (external {ip}:{port})")).await;
            (true, ext_ip.clone())
        }
    }
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
    use super::{dht_dial_timeout, dht_self_claims, is_public_ipv4};
    use epix_core::PeerAddr;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn dht_self_claims_cover_every_configured_network() {
        // Clearnet only: the 0.0.0.0 claim the serving side rewrites.
        let claims = dht_self_claims(48333, true, None, None, None);
        assert_eq!(claims, vec![PeerAddr::parse("0.0.0.0:48333").unwrap()]);

        // All networks up: one claim per network, fileserver port throughout
        // (it doubles as the onion/i2p virtual port).
        let claims = dht_self_claims(
            48333,
            true,
            Some("expyuzz4wqqyqhjn".into()),
            Some("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32".into()),
            Some("00112233445566778899aabbccddeeff".into()),
        );
        let strings: Vec<String> = claims.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            strings,
            vec![
                "0.0.0.0:48333",
                "expyuzz4wqqyqhjn.onion:48333",
                "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:48333",
                "rns:00112233445566778899aabbccddeeff",
            ]
        );

        // Tor-Always mode (include_clearnet=false): overlays only, no 0.0.0.0
        // (which would be rewritten to a useless, correlating Tor exit IP).
        let claims = dht_self_claims(
            48333,
            false,
            Some("expyuzz4wqqyqhjn".into()),
            Some("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32".into()),
            None,
        );
        let strings: Vec<String> = claims.iter().map(|c| c.to_string()).collect();
        assert_eq!(
            strings,
            vec![
                "expyuzz4wqqyqhjn.onion:48333",
                "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:48333",
            ],
            "no 0.0.0.0 claim in Always mode"
        );
        // An Always-mode node with no overlay address yet claims nothing.
        assert!(dht_self_claims(48333, false, None, None, None).is_empty());

        // No fileserver port = no inbound service on any network: claim
        // nothing (an onion claim with port 0 is not connectable either).
        assert!(dht_self_claims(0, true, Some("expyuzz4wqqyqhjn".into()), None, None).is_empty());

        // Empty overlay hosts (address not yet learned) are skipped, not
        // announced as junk like ".onion:48333".
        let claims = dht_self_claims(48333, true, Some(String::new()), Some(String::new()), None);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn dht_dial_timeout_uses_overlay_bound_over_tor() {
        let clearnet = PeerAddr::parse("8.8.8.8:26552").unwrap();
        let onion = PeerAddr::parse("expyuzz4wqqyqhjn.onion:26552").unwrap();
        // Normal mode: a clearnet peer gets the 15s direct-socket bound, an
        // onion peer the 45s overlay bound.
        assert_eq!(dht_dial_timeout(&clearnet, false), std::time::Duration::from_secs(15));
        assert_eq!(dht_dial_timeout(&onion, false), std::time::Duration::from_secs(45));
        // Tor-Always: every dial rides Tor, so a clearnet peer also gets 45s.
        assert_eq!(dht_dial_timeout(&clearnet, true), std::time::Duration::from_secs(45));
        assert_eq!(dht_dial_timeout(&onion, true), std::time::Duration::from_secs(45));
    }

    #[tokio::test]
    async fn await_tor_routed_is_noop_outside_always_mode() {
        let state = crate::AppState::new("test");
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        // Not Always mode: proceed immediately even though Tor is not up (an
        // Enable/Disable node may dial clearnet).
        assert!(super::await_tor_routed(&state, false, &shutdown).await);
    }

    #[tokio::test]
    async fn await_tor_routed_proceeds_once_tor_is_up() {
        let state = crate::AppState::new("test");
        state.set_tor_status(true, "Always").await;
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        // Always mode with Tor up: the Tor-routed transport is live, so proceed.
        assert!(super::await_tor_routed(&state, true, &shutdown).await);
    }

    #[tokio::test]
    async fn await_tor_routed_returns_false_on_shutdown_in_always_mode() {
        let state = crate::AppState::new("test");
        // Tor never comes up. The gate blocks (never dials clearnet); a shutdown
        // releases it with false so the loop stops instead of leaking.
        let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
        let sd = shutdown.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            sd.notify_waiters();
        });
        assert!(!super::await_tor_routed(&state, true, &shutdown).await);
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
