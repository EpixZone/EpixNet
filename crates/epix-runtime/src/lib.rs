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

#[cfg(feature = "local-discovery")]
pub mod local;

/// How often the loops run.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub announce_interval: Duration,
    pub resync_interval: Duration,
    pub chart_interval: Duration,
    pub connection_interval: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(20 * 60),
            resync_interval: Duration::from_secs(5 * 60),
            chart_interval: Duration::from_secs(5 * 60),
            connection_interval: Duration::from_secs(60),
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
}

impl NodeRuntime {
    pub fn new(state: Arc<AppState>, trackers: Vec<PeerAddr>) -> Self {
        Self::with_config(state, trackers, RuntimeConfig::default())
    }

    pub fn with_config(state: Arc<AppState>, trackers: Vec<PeerAddr>, config: RuntimeConfig) -> Self {
        Self { state, trackers, config, shutdown: Arc::new(Notify::new()), handles: Vec::new() }
    }

    /// Spawn the background loops. Idempotent per instance (call once).
    pub fn start(&mut self) {
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
        self.handles.push(tokio::spawn(chart_loop(
            self.state.clone(),
            self.shutdown.clone(),
            self.config.chart_interval,
        )));
        self.handles.push(tokio::spawn(connection_loop(
            self.state.clone(),
            self.shutdown.clone(),
            self.config.connection_interval,
        )));
        // AnnounceLocal: discover peers on the LAN over UDP broadcast.
        #[cfg(feature = "local-discovery")]
        self.handles.push(tokio::spawn(local::local_discovery_loop(
            self.state.clone(),
            0, // this node does not accept incoming P2P connections
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
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => state.collect_chart().await,
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
            }
        }
    }
}
