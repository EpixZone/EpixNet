//! Live bootstrap of the embedded emissary router. Ignored by default: it
//! reseeds over HTTPS and builds I2P tunnels, which needs network and takes a
//! few minutes. Run explicitly:
//!
//!   cargo test -p epix-i2p --test embedded_bootstrap -- --ignored --nocapture

use epix_i2p::{I2p, I2pConfig, I2pMode, I2pPhase};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn embedded_router_reseeds_and_gives_us_a_destination() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = I2pConfig {
        mode: I2pMode::Embedded,
        sam_tcp_port: 0,
        data_dir: dir.path().to_path_buf(),
    };

    // spawn() returns immediately; the router reseeds + builds tunnels on its
    // own task and reaches Ready once our inbound session exists. Poll for it.
    let (i2p, _rx) = I2p::spawn(cfg);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
        let s = i2p.status().await;
        if s.phase == I2pPhase::Ready {
            println!(
                "i2p ready: {} chars, {} peers, {} tunnels",
                s.destination.len(),
                s.connected_routers,
                s.tunnels_built
            );
            // SAM returns the full base64 destination (~516+ chars) - a real
            // one proves the embedded router bootstrapped and gave us a session.
            assert!(s.destination.len() > 500, "got a real inbound destination");
            return;
        }
        if let I2pPhase::Failed(e) = &s.phase {
            panic!("i2p bringup failed: {e}");
        }
        assert!(std::time::Instant::now() < deadline, "embedded router bootstrap timed out (5 min)");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
