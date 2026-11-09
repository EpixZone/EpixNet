//! Native radio policy and opaque runtime bridge, independent of platform APIs.
use super::AppState;
use async_trait::async_trait;
use epix_core::PeerAddr;
use serde_json::json;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeRadioState {
    FeatureUnavailable,
    Offline,
    MeshDisabled,
    Starting,
    Ready,
}

#[derive(Clone, Copy, Debug)]
pub enum NativeRadioKind {
    Ble,
    WifiAware,
}

pub struct NativeRadioRead {
    pub data: Vec<u8>,
    pub closed: bool,
}

#[async_trait]
pub trait NativeRadioStream: Send + Sync {
    async fn write(&self, bytes: Vec<u8>, timeout: Duration) -> Result<(), String>;
    async fn read(&self, max_bytes: usize, timeout: Duration) -> Result<NativeRadioRead, String>;
    fn close(&self);
}

#[async_trait]
pub trait NativeRadioBridge: Send + Sync {
    async fn open(&self, kind: NativeRadioKind) -> Result<Arc<dyn NativeRadioStream>, String>;
    async fn candidates(&self) -> Vec<PeerAddr>;
    fn close(&self);
}

pub(super) struct NativeRadioControl {
    available: AtomicBool,
    boot_offline: AtomicBool,
    initial_enabled: AtomicBool,
    pub(super) config_write: Mutex<()>,
    bridge: RwLock<Option<Arc<dyn NativeRadioBridge>>>,
    changes: watch::Sender<()>,
}

impl Default for NativeRadioControl {
    fn default() -> Self {
        Self {
            available: AtomicBool::new(false),
            boot_offline: AtomicBool::new(false),
            initial_enabled: AtomicBool::new(false),
            config_write: Mutex::new(()),
            bridge: RwLock::new(None),
            changes: watch::channel(()).0,
        }
    }
}

impl AppState {
    pub fn configure_native_mesh(&self, available: bool, offline: bool, enabled: bool) {
        self.native_radio
            .available
            .store(available, Ordering::Release);
        self.native_radio
            .boot_offline
            .store(offline, Ordering::Release);
        self.native_radio
            .initial_enabled
            .store(enabled, Ordering::Release);
    }

    pub fn native_mesh_changes(&self) -> watch::Receiver<()> {
        self.native_radio.changes.subscribe()
    }

    pub async fn native_radio_state(&self) -> NativeRadioState {
        if !self.native_radio.available.load(Ordering::Acquire) {
            return NativeRadioState::FeatureUnavailable;
        }
        if self.native_radio.boot_offline.load(Ordering::Acquire)
            || self.config_bool("offline", false).await
        {
            return NativeRadioState::Offline;
        }
        if !self.native_mesh_enabled().await {
            return NativeRadioState::MeshDisabled;
        }
        if self.native_radio.bridge.read().await.is_some() {
            NativeRadioState::Ready
        } else {
            NativeRadioState::Starting
        }
    }

    pub async fn native_mesh_enabled(&self) -> bool {
        self.config_get("mesh").await.map_or_else(
            || self.native_radio.initial_enabled.load(Ordering::Acquire),
            |value| value.as_str() == Some("enable"),
        )
    }

    /// Persist the schema's exact select value before changing live policy.
    /// Persistence errors leave both the active generation and config unchanged.
    pub async fn set_native_mesh_enabled(&self, enabled: bool) -> Result<(), String> {
        if !self.native_radio.available.load(Ordering::Acquire) {
            return Err("mesh is not compiled into this node".into());
        }
        let _serial = self.native_radio.config_write.lock().await;
        let mut config = self.config.write().await;
        let mut replacement = config.clone();
        replacement.insert(
            "mesh".into(),
            json!(if enabled { "enable" } else { "disable" }),
        );
        if let Some(path) = self.config_path.clone() {
            let bytes =
                serde_json::to_vec_pretty(&replacement).map_err(|error| error.to_string())?;
            tokio::task::spawn_blocking(move || {
                let parent = path
                    .parent()
                    .ok_or_else(|| "config has no directory".to_string())?;
                let mut staged =
                    tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
                staged
                    .write_all(&bytes)
                    .and_then(|_| staged.as_file().sync_all())
                    .map_err(|error| error.to_string())?;
                staged.persist(path).map_err(|error| error.to_string())?;
                Ok::<(), String>(())
            })
            .await
            .map_err(|error| error.to_string())??;
        }
        *config = replacement;
        drop(config);
        self.native_mesh_policy_changed().await;
        Ok(())
    }

    pub(super) async fn native_mesh_policy_changed(&self) {
        // Saving an unchanged enabled preference must not replace live links.
        // Starting still wakes the supervisor, allowing an explicit retry.
        if self.native_radio_state().await == NativeRadioState::Ready {
            return;
        }
        if !matches!(
            self.native_radio_state().await,
            NativeRadioState::Ready | NativeRadioState::Starting
        ) {
            self.clear_native_radio().await;
        }
        self.native_radio.changes.send_replace(());
    }

    pub async fn install_native_radio(
        &self,
        bridge: Arc<dyn NativeRadioBridge>,
        transport: Arc<dyn epix_transport::Transport>,
        legacy: &str,
        reliable: &str,
    ) -> bool {
        let _serial = self.native_radio.config_write.lock().await;
        if self.native_radio_state().await != NativeRadioState::Starting {
            bridge.close();
            return false;
        }
        self.set_rns_address(legacy).await;
        self.set_rns_reliable_address(reliable).await;
        self.set_rns_transport(transport).await;
        let hash = legacy.to_string();
        epix_protocol::update_self_advert(move |advert| advert.rns = Some(hash));
        *self.native_radio.bridge.write().await = Some(bridge);
        true
    }

    pub async fn clear_native_radio(&self) {
        if let Some(bridge) = self.native_radio.bridge.write().await.take() {
            bridge.close();
        }
        *self.rns_transport.write().await = None;
        *self.rns_address.write().await = None;
        *self.rns_reliable_address.write().await = None;
        epix_protocol::update_self_advert(|advert| advert.rns = None);
        self.recompose_transport().await;
    }

    pub async fn open_native_radio(
        &self,
        kind: NativeRadioKind,
    ) -> Result<Arc<dyn NativeRadioStream>, String> {
        let _serial = self.native_radio.config_write.lock().await;
        if self.native_radio_state().await != NativeRadioState::Ready {
            return Err("native radio mesh is not ready".into());
        }
        let bridge = self
            .native_radio
            .bridge
            .read()
            .await
            .clone()
            .ok_or("mesh generation stopped")?;
        bridge.open(kind).await
    }

    /// Announcements describe a node, not its xites. They are fallback candidates
    /// only for an existing requested registration, never a reason to join a xite.
    pub async fn native_mesh_candidates(&self, address: &str) -> Vec<PeerAddr> {
        if self.native_radio_state().await != NativeRadioState::Ready {
            return Vec::new();
        }
        let Some(generation) = self.xite_membership_generation(address).await else {
            return Vec::new();
        };
        if !self.xite_update_is_current(address, generation).await {
            return Vec::new();
        }
        let bridge = self.native_radio.bridge.read().await.clone();
        let Some(bridge) = bridge else {
            return Vec::new();
        };
        let nets = self.dialable_networks().await;
        let mut candidates = Vec::new();
        for peer in bridge.candidates().await.into_iter().take(32) {
            if matches!(peer, PeerAddr::Rns(_))
                && nets.can_dial(&peer)
                && !self.is_own_peer(&peer).await
            {
                candidates.push(peer);
            }
        }
        let same_bridge = self
            .native_radio
            .bridge
            .read()
            .await
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &bridge));
        if same_bridge
            && self.native_radio_state().await == NativeRadioState::Ready
            && self.xite_update_is_current(address, generation).await
        {
            candidates
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
#[path = "native_radio_tests.rs"]
mod tests;
