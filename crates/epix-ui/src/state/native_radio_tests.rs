use super::{
    NativeRadioBridge, NativeRadioKind, NativeRadioRead, NativeRadioState, NativeRadioStream,
};
use crate::state::{AppState, XiteEntry};
use async_trait::async_trait;
use epix_core::PeerAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Fixture {
    closed: Arc<AtomicBool>,
    candidates: Vec<PeerAddr>,
}

#[async_trait]
impl NativeRadioBridge for Fixture {
    async fn open(&self, _: NativeRadioKind) -> Result<Arc<dyn NativeRadioStream>, String> {
        if self.closed.load(Ordering::Acquire) {
            return Err("closed".into());
        }
        Ok(Arc::new(Handle(self.closed.clone())))
    }
    async fn candidates(&self) -> Vec<PeerAddr> {
        self.candidates.clone()
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

struct Handle(Arc<AtomicBool>);

#[async_trait]
impl NativeRadioStream for Handle {
    async fn write(&self, _: Vec<u8>, _: Duration) -> Result<(), String> {
        if self.0.load(Ordering::Acquire) {
            Err("closed".into())
        } else {
            Ok(())
        }
    }
    async fn read(&self, _: usize, _: Duration) -> Result<NativeRadioRead, String> {
        Ok(NativeRadioRead {
            data: Vec::new(),
            closed: self.0.load(Ordering::Acquire),
        })
    }
    fn close(&self) {
        self.0.store(true, Ordering::Release);
    }
}

async fn install(state: &AppState, candidates: Vec<PeerAddr>) -> Arc<Fixture> {
    let bridge = Arc::new(Fixture {
        closed: Arc::new(AtomicBool::new(false)),
        candidates,
    });
    assert!(
        state
            .install_native_radio(
                bridge.clone(),
                Arc::new(epix_transport::TcpTransport),
                "01010101010101010101010101010101",
                "02020202020202020202020202020202"
            )
            .await
    );
    bridge
}

#[tokio::test]
async fn native_policy_distinguishes_unavailable_disabled_starting_and_ready() {
    let state = AppState::new("radio-test");
    assert_eq!(
        state.native_radio_state().await,
        NativeRadioState::FeatureUnavailable
    );
    assert!(state.set_native_mesh_enabled(true).await.is_err());
    state.configure_native_mesh(true, false, false);
    assert_eq!(
        state.native_radio_state().await,
        NativeRadioState::MeshDisabled
    );
    assert!(state.open_native_radio(NativeRadioKind::Ble).await.is_err());
    state.set_native_mesh_enabled(true).await.unwrap();
    assert_eq!(state.native_radio_state().await, NativeRadioState::Starting);
    let bridge = install(&state, Vec::new()).await;
    let old = state.open_native_radio(NativeRadioKind::Ble).await.unwrap();
    assert_eq!(state.native_radio_state().await, NativeRadioState::Ready);
    state.set_native_mesh_enabled(false).await.unwrap();
    assert!(bridge.closed.load(Ordering::Acquire));
    assert!(old.write(vec![1], Duration::ZERO).await.is_err());
    assert!(state.rns_address().await.is_none());
    assert!(state.rns_reliable_address().await.is_none());
    assert!(!state.dialable_networks().await.rns);
    state.set_native_mesh_enabled(true).await.unwrap();
    let replacement = install(&state, Vec::new()).await;
    assert!(!replacement.closed.load(Ordering::Acquire));
    assert!(old.read(1, Duration::ZERO).await.unwrap().closed);
}

#[tokio::test]
async fn offline_policy_cannot_be_overridden_by_native_mesh_enable() {
    let state = AppState::new("radio-test");
    state.configure_native_mesh(true, true, false);
    state.set_native_mesh_enabled(true).await.unwrap();
    assert_eq!(state.native_radio_state().await, NativeRadioState::Offline);
    assert!(state
        .open_native_radio(NativeRadioKind::WifiAware)
        .await
        .is_err());
    state.configure_native_mesh(true, false, true);
    let bridge = install(&state, Vec::new()).await;
    state.config_set("offline", serde_json::json!(true)).await;
    assert!(bridge.closed.load(Ordering::Acquire));
    assert_eq!(state.native_radio_state().await, NativeRadioState::Offline);
}

#[tokio::test]
async fn native_mesh_setting_persists_and_failure_keeps_previous_policy() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("radio-test", root.path());
    state.configure_native_mesh(true, false, false);
    state.set_native_mesh_enabled(true).await.unwrap();
    let restarted = AppState::with_data_dir("radio-test", root.path());
    restarted.configure_native_mesh(true, false, false);
    assert_eq!(
        restarted.native_radio_state().await,
        NativeRadioState::Starting
    );
    let path = state.config_path.as_ref().unwrap();
    tokio::fs::remove_file(path).await.unwrap();
    tokio::fs::create_dir(path).await.unwrap();
    assert!(state.set_native_mesh_enabled(false).await.is_err());
    assert_eq!(state.native_radio_state().await, NativeRadioState::Starting);
}

#[tokio::test]
async fn announcement_candidates_require_requested_xite_and_exclude_self_and_non_mesh() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::new("radio-test");
    state.configure_native_mesh(true, false, true);
    let remote = PeerAddr::Rns([3; 16]);
    install(
        &state,
        vec![
            PeerAddr::Rns([1; 16]),
            PeerAddr::Rns([2; 16]),
            remote.clone(),
            PeerAddr::parse("127.0.0.1:3000").unwrap(),
        ],
    )
    .await;
    assert!(state
        .native_mesh_candidates("not-requested")
        .await
        .is_empty());
    let address = crate::state::DASHBOARD_XITE_ADDRESS;
    state
        .add_xite(
            address,
            XiteEntry {
                storage: epix_xite::XiteStorage::new(root.path().join(address)),
                content: None,
            },
        )
        .await;
    assert_eq!(state.native_mesh_candidates(address).await, vec![remote]);
    assert!(
        state.xites.read().await[address].peers.is_empty(),
        "discovery candidates are not persisted peer claims"
    );
    state
        .xites
        .write()
        .await
        .get_mut(address)
        .unwrap()
        .settings
        .serving = false;
    assert!(state.native_mesh_candidates(address).await.is_empty());
}

struct DelayedCandidates {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl NativeRadioBridge for DelayedCandidates {
    async fn open(&self, _: NativeRadioKind) -> Result<Arc<dyn NativeRadioStream>, String> {
        Err("unused".into())
    }
    async fn candidates(&self) -> Vec<PeerAddr> {
        self.entered.notify_one();
        self.release.notified().await;
        vec![PeerAddr::Rns([3; 16])]
    }
    fn close(&self) {}
}

#[tokio::test]
async fn late_candidates_do_not_cross_replaced_xite_or_mesh_generations() {
    for replace_mesh in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let state = AppState::new("radio-stale-test");
        let address = crate::state::DASHBOARD_XITE_ADDRESS;
        let entry = || XiteEntry {
            storage: epix_xite::XiteStorage::new(root.path().join(address)),
            content: None,
        };
        state.add_xite(address, entry()).await;
        state.configure_native_mesh(true, false, true);
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let bridge = Arc::new(DelayedCandidates {
            entered: entered.clone(),
            release: release.clone(),
        });
        assert!(
            state
                .install_native_radio(
                    bridge,
                    Arc::new(epix_transport::TcpTransport),
                    "01010101010101010101010101010101",
                    "02020202020202020202020202020202"
                )
                .await
        );
        let pending = tokio::spawn({
            let state = state.clone();
            async move { state.native_mesh_candidates(address).await }
        });
        entered.notified().await;
        if replace_mesh {
            state.clear_native_radio().await;
            install(&state, Vec::new()).await;
        } else {
            state.xites.write().await.remove(address);
            state.add_xite(address, entry()).await;
        }
        release.notify_one();
        assert!(pending.await.unwrap().is_empty());
    }
}
