use super::supervise;
use crate::edx::{new_serve_cell, ControlHandles};
use epix_ui::state::native_radio::{NativeRadioKind, NativeRadioState};
use epix_ui::state::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::Notify;

async fn ready(state: &AppState) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.native_radio_state().await != NativeRadioState::Ready {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dormant_mesh_activates_live_and_revokes_old_handles_on_disable_restart_and_shutdown() {
    let state = AppState::new("native-mesh-test");
    state.configure_native_mesh(true, false, false);
    let shutdown = Arc::new(Notify::new());
    let running = tokio::spawn(supervise(
        state.clone(),
        None,
        Vec::new(),
        None,
        new_serve_cell(ControlHandles::detached()),
        shutdown.clone(),
    ));
    assert_eq!(
        state.native_radio_state().await,
        NativeRadioState::MeshDisabled
    );
    assert!(state.open_native_radio(NativeRadioKind::Ble).await.is_err());
    state.set_native_mesh_enabled(true).await.unwrap();
    ready(&state).await;
    let old = state.open_native_radio(NativeRadioKind::Ble).await.unwrap();
    state.set_native_mesh_enabled(false).await.unwrap();
    assert!(old.read(1, Duration::from_secs(1)).await.unwrap().closed);
    assert!(state.rns_address().await.is_none());
    state.set_native_mesh_enabled(true).await.unwrap();
    ready(&state).await;
    assert!(old.write(vec![1], Duration::ZERO).await.is_err());
    let replacement = state
        .open_native_radio(NativeRadioKind::WifiAware)
        .await
        .unwrap();
    shutdown.notify_waiters();
    tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap();
    assert!(replacement.read(1, Duration::ZERO).await.unwrap().closed);
    assert!(state.rns_address().await.is_none());
    assert!(!state.dialable_networks().await.rns);
}

#[tokio::test]
async fn config_disable_revokes_tcp_generation_without_waiting_for_supervisor() {
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let state = AppState::new("mesh-disable-test");
    state.configure_native_mesh(true, false, true);
    let cell = new_serve_cell(ControlHandles::detached());
    let _generation = super::start_generation(
        &state,
        epix_reticulum::MeshConfig {
            tcp_listen: Some(address.to_string()),
            ..epix_reticulum::MeshConfig::default()
        },
        &cell,
    )
    .await
    .unwrap();
    let mut socket = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(socket) = tokio::net::TcpStream::connect(address).await {
                break socket;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Retain the generation and never run its supervisor. The config hook
    // itself must revoke all interfaces, not only native radio handles.
    state.set_native_mesh_enabled(false).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match socket.read(&mut [0; 4096]).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("disabled generation must close the accepted TCP socket");
    assert!(state.rns_address().await.is_none());
}

#[tokio::test]
async fn enabling_an_already_ready_mesh_preserves_generation_and_open_stream() {
    let state = AppState::new("mesh-idempotent-test");
    state.configure_native_mesh(true, false, true);
    let shutdown = Arc::new(Notify::new());
    let running = tokio::spawn(supervise(
        state.clone(),
        None,
        Vec::new(),
        None,
        new_serve_cell(ControlHandles::detached()),
        shutdown.clone(),
    ));
    ready(&state).await;
    let stream = state.open_native_radio(NativeRadioKind::Ble).await.unwrap();
    let changes = state.native_mesh_changes();
    assert!(
        state.config_get("mesh").await.is_none(),
        "initial runtime flag is not yet an explicit saved preference"
    );
    state.set_native_mesh_enabled(true).await.unwrap();
    assert_eq!(
        state.config_get("mesh").await,
        Some(serde_json::json!("enable"))
    );
    assert!(
        !changes.has_changed().unwrap(),
        "saving the already-enabled preference must not restart the generation"
    );
    state.config_set("mesh", serde_json::json!("enable")).await;
    assert!(
        !changes.has_changed().unwrap(),
        "saving unchanged Config must preserve the generation too"
    );
    assert!(!stream.read(4096, Duration::ZERO).await.unwrap().closed);
    shutdown.notify_waiters();
    tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap();
}
