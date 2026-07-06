//! Live bootstrap of the embedded emissary router. Ignored by default: it
//! reseeds over HTTPS and builds I2P tunnels, which needs network and takes a
//! few minutes. Run explicitly:
//!
//!   cargo test -p epix-i2p --test embedded_bootstrap -- --ignored --nocapture

use epix_i2p::{I2p, I2pConfig, I2pMode};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn embedded_router_reseeds_and_gives_us_a_destination() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = I2pConfig {
        mode: I2pMode::Embedded,
        sam_tcp_port: 0,
        data_dir: dir.path().to_path_buf(),
    };

    // start() reseeds, builds the router, and creates our inbound session -
    // which only succeeds once the router has tunnels. Bound it generously.
    let started = tokio::time::timeout(std::time::Duration::from_secs(300), I2p::start(cfg)).await;

    let (i2p, _rx) = started.expect("embedded router bootstrap timed out (5 min)").expect("start");
    let dest = i2p.destination();
    println!("embedded i2p destination ({} chars): {dest}", dest.len());
    // SAM returns the full base64 destination (~516+ chars) once the router has
    // reseeded and built tunnels - a non-empty one proves the embedded router
    // bootstrapped and gave us a live session.
    assert!(dest.len() > 500, "got a real inbound destination (len {})", dest.len());
}
