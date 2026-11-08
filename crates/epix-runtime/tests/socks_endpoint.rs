//! The local proxy must remain owned even while Tor cannot route traffic.

use epix_runtime::{NodeRuntime, RuntimeConfig};
use epix_ui::AppState;
use std::net::TcpListener;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

fn reserve_test_start() -> TcpListener {
    for _ in 0..32 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if port < u16::MAX - 4 && !(43110..=43113).contains(&port) {
            return listener;
        }
    }
    panic!("could not reserve a non-legacy test port");
}

#[tokio::test]
async fn offline_start_reserves_its_socks_endpoint_before_returning() {
    let probe = reserve_test_start();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let state = AppState::new("socks-port-regression");
    let mut runtime = NodeRuntime::with_config(
        state.clone(),
        vec![],
        RuntimeConfig {
            offline: true,
            tor_socks_port: Some(port),
            ..RuntimeConfig::default()
        },
    );
    runtime.start().await.unwrap();
    let actual = state.tor_socks_port().await.unwrap();
    assert_eq!(actual, port);
    assert!(!state.tor_status().await.0);
    let foreign_claim = TcpListener::bind(("127.0.0.1", port));
    let mut stream = TcpStream::connect(("127.0.0.1", actual)).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), stream.read_u8())
        .await
        .unwrap();
    assert!(closed.is_err(), "unavailable Tor must reject, not forward");
    runtime.shutdown().await;
    assert_eq!(state.tor_socks_port().await, None);
    assert!(
        foreign_claim.is_err(),
        "offline startup left the configured SOCKS endpoint available to another process"
    );
}

#[tokio::test]
async fn simultaneous_runtimes_retain_distinct_owned_endpoints() {
    let foreign = reserve_test_start();
    foreign.set_nonblocking(true).unwrap();
    let start = foreign.local_addr().unwrap().port();
    let mut runtimes = Vec::new();
    let mut ports = std::collections::HashSet::new();
    for _ in 0..3 {
        let state = AppState::new("independent-socks");
        let mut runtime = NodeRuntime::with_config(
            state.clone(),
            vec![],
            RuntimeConfig {
                offline: true,
                tor_socks_port: Some(start),
                ..RuntimeConfig::default()
            },
        );
        runtime.start().await.unwrap();
        let port = state.tor_socks_port().await.unwrap();
        assert_ne!(port, start);
        assert!(ports.insert(port));
        assert!(TcpListener::bind(("127.0.0.1", port)).is_err());
        runtimes.push(runtime);
    }
    assert_eq!(
        foreign.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    for runtime in runtimes {
        runtime.shutdown().await;
    }
}

#[tokio::test]
async fn failed_reservation_does_not_publish_a_guessed_endpoint() {
    // If another test/process already owns the final port, that collision is
    // equally valid. Do not probe it or connect to it.
    let _held = TcpListener::bind(("127.0.0.1", u16::MAX)).ok();
    let state = AppState::new("failed-socks");
    let mut runtime = NodeRuntime::with_config(
        state.clone(),
        vec![],
        RuntimeConfig {
            offline: true,
            tor_socks_port: Some(u16::MAX),
            ..RuntimeConfig::default()
        },
    );
    assert!(runtime.start().await.is_err());
    assert_eq!(state.tor_socks_port().await, None);
    assert!(!state.tor_status().await.0);
    runtime.shutdown().await;
}
