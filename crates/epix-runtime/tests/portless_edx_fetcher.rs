//! A download-only node (no inbound fileserver port) must still install the
//! EDX store and fetcher. Every peer path - announce, fetch, publish, the DHT
//! client - goes through the fetcher, so a node that only installed it from an
//! accept loop had no peer I/O at all when the port was disabled.

use std::sync::Arc;
use std::time::Duration;

use epix_core::PeerAddr;
use epix_runtime::{NodeRuntime, RuntimeConfig};
use epix_ui::AppState;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn portless_node_installs_the_edx_fetcher() {
    let data = tempfile::tempdir().unwrap();
    let state: Arc<AppState> = AppState::with_data_dir("test", data.path());

    let mut runtime = NodeRuntime::with_config(
        state.clone(),
        vec![],
        RuntimeConfig {
            announce_interval: Duration::from_secs(3600),
            resync_interval: Duration::from_secs(3600),
            chart_interval: Duration::from_secs(3600),
            connection_interval: Duration::from_secs(3600),
            // Download-only: the Config page maps a configured port 0 to None.
            fileserver_port: None,
            offline: false,
            ..Default::default()
        },
    );
    runtime.start();

    // The store install is the visible half of the same call that installs the
    // fetcher, and it runs on its own task, so wait for it.
    timeout(Duration::from_secs(10), async {
        while state.edx_store().await.is_none() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("EDX store installed without a fileserver port");

    // The fetcher itself: with no transport set the call still reaches it and
    // reports that error, where a missing fetcher returns None.
    let probe = state.edx_kad(PeerAddr::Ip("127.0.0.1:1".parse().unwrap()), Vec::new()).await;
    assert!(probe.is_some(), "EDX fetcher installed on a download-only node");

    runtime.shutdown().await;
}
