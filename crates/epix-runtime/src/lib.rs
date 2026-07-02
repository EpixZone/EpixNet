//! `epix-runtime` — the persistent node runtime.
//!
//! Turns a served [`AppState`] into a live node by running supervised background
//! loops, replacing EpixNet's gevent greenlets with `tokio::spawn` tasks whose
//! handles the runtime owns:
//!
//! - **announce** — periodically re-announce to trackers and fold the results
//!   into each xite's peer registry, so peer lists stay fresh.
//! - **re-sync** — periodically check each xite for a newer content.json among
//!   its peers and, if found, verify + download the changed files (updating the
//!   live worker stats the sidebar shows).
//!
//! [`NodeRuntime::shutdown`] signals every loop and awaits them, so the node
//! stops cleanly.

use epix_core::PeerAddr;
use epix_transport::Transport;
use epix_ui::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

/// How often the loops run.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub announce_interval: Duration,
    pub resync_interval: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            announce_interval: Duration::from_secs(20 * 60),
            resync_interval: Duration::from_secs(5 * 60),
        }
    }
}

/// Owns the node's background loops.
pub struct NodeRuntime {
    state: Arc<AppState>,
    transport: Arc<dyn Transport>,
    trackers: Vec<PeerAddr>,
    config: RuntimeConfig,
    shutdown: Arc<Notify>,
    handles: Vec<JoinHandle<()>>,
}

impl NodeRuntime {
    pub fn new(state: Arc<AppState>, transport: Arc<dyn Transport>, trackers: Vec<PeerAddr>) -> Self {
        Self::with_config(state, transport, trackers, RuntimeConfig::default())
    }

    pub fn with_config(
        state: Arc<AppState>,
        transport: Arc<dyn Transport>,
        trackers: Vec<PeerAddr>,
        config: RuntimeConfig,
    ) -> Self {
        Self { state, transport, trackers, config, shutdown: Arc::new(Notify::new()), handles: Vec::new() }
    }

    /// Spawn the background loops. Idempotent per instance (call once).
    pub fn start(&mut self) {
        self.handles.push(tokio::spawn(announce_loop(
            self.state.clone(),
            self.transport.clone(),
            self.trackers.clone(),
            self.shutdown.clone(),
            self.config.announce_interval,
        )));
        self.handles.push(tokio::spawn(resync_loop(
            self.state.clone(),
            self.shutdown.clone(),
            self.config.resync_interval,
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

/// Re-announce every xite to the trackers and fold in the peers found.
async fn announce_loop(
    state: Arc<AppState>,
    transport: Arc<dyn Transport>,
    trackers: Vec<PeerAddr>,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                if trackers.is_empty() { continue; }
                for address in state.xite_addresses().await {
                    let peers = epix_xite::announce(transport.as_ref(), &address, &trackers, 0).await;
                    state.add_peers(&address, peers).await;
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
            }
        }
    }
}
