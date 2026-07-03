//! Runnable Epix node: discover peers, clone a xite from the live EpixNet
//! network, and serve it in a browser through the UI server. The node logic
//! lives in `epix-node` (shared with the FFI layer and the shells); this binary
//! adds the desktop concerns: platform data dir, single-instance lock, file
//! logging, the bundled GeoIP asset, and `epix://` argument handling.

mod platform;

use epix_node::{NodeOptions, DEFAULT_UI_ADDR};

/// Bundled peer-geolocation database for the dashboard's world map: DB-IP City
/// Lite (CC-BY-4.0), shipped gzipped and expanded into the data dir at runtime.
const GEOIP_CITY_GZ: &[u8] = include_bytes!("../assets/dbip-city-lite.mmdb.gz");

/// The UI bind address: `EPIX_UI_ADDR` if set, else the default loopback bind.
fn ui_bind() -> String {
    std::env::var("EPIX_UI_ADDR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_UI_ADDR.to_string())
}

#[tokio::main]
async fn main() {
    // Accept a raw `epix1…` address, a `.epix` name, or an `epix://…` deep link
    // (from the OS handing off a clicked link). Default to the dashboard.
    let raw = std::env::args().nth(1).unwrap_or_else(|| "dashboard.epix".to_string());
    let target = epix_node::parse_target(&raw);

    // Persistent per-OS data directory with a single-instance lock. If already
    // running, hand off to the existing instance's browser tab and exit.
    let root = platform::data_root();
    std::fs::create_dir_all(&root).expect("create data root");
    let _lock = match platform::acquire_lock(&root) {
        Ok(lock) => lock,
        Err(()) => {
            eprintln!(
                "Epix is already running (lock held in {}). Opening the existing instance.",
                root.display()
            );
            epix_node::open_in_browser(&format!("http://{}/{target}/", ui_bind()));
            return;
        }
    };

    let tor_mode = std::env::var("EPIX_TOR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "enable".to_string());

    let opts = NodeOptions {
        data_root: root.clone(),
        target,
        ui_addr: ui_bind(),
        tor_mode,
        open_browser: true,
        geoip_gz: Some(GEOIP_CITY_GZ.to_vec()),
        log_file: Some(platform::log_path(&root, 8 * 1024 * 1024)),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    println!("· Epix node starting (data: {})", root.display());
    if let Err(e) = epix_node::run(opts).await {
        eprintln!("Epix node failed: {e}");
        std::process::exit(1);
    }
}
