//! Runnable Epix node: discover peers, clone a xite from the live EpixNet
//! network, and serve it in a browser through the UI server. The node logic
//! lives in `epix-node` (shared with the FFI layer and the shells); this binary
//! adds the desktop concerns: platform data dir, single-instance lock, file
//! logging, the bundled GeoIP asset, and `epix://` argument handling.

mod actions;
mod platform;

use epix_node::{NodeOptions, DEFAULT_UI_ADDR};

/// Bundled peer-geolocation database for the dashboard's world map: DB-IP City
/// Lite (CC-BY-4.0), shipped gzipped and expanded into the data dir at runtime.
const GEOIP_CITY_GZ: &[u8] = include_bytes!("../assets/dbip-city-lite.mmdb.gz");

/// The xite opened when no target is given on the command line: the dashboard.
/// A bech32 address (not the `dashboard.epix` name) so boot never depends on
/// chain name resolution being reachable.
const DEFAULT_DASHBOARD: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";

/// The UI bind address: `EPIX_UI_ADDR` if set, else the default loopback bind.
fn ui_bind() -> String {
    std::env::var("EPIX_UI_ADDR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_UI_ADDR.to_string())
}

#[tokio::main]
async fn main() {
    // CLI actions (siteCreate, siteSign, peerPing, ...) run and exit; the
    // action name is the first argument, Python-CLI style. Anything else is
    // a xite target and starts the node.
    let cli: Vec<String> = std::env::args().skip(1).collect();
    // Guard the conventional flags: without this, `--help` would be taken for
    // a xite target and boot a full node against the real data dir.
    match cli.first().map(String::as_str) {
        Some("-h") | Some("--help") | Some("help") => {
            println!("epix-server {}", env!("EPIX_VERSION"));
            println!("Usage: epix-server [xite address | name.epix | epix://link]");
            println!("       epix-server <action> [args...]");
            println!();
            println!("Actions: siteCreate, siteSign, siteVerify, siteList, siteDelete,");
            println!("         siteDownload, dbRebuild, dbQuery, importBundle, cryptSign,");
            println!("         cryptVerify, cryptGetPrivatekey, cryptPrivatekeyToAddress,");
            println!("         peerPing, peerGetFile, peerCmd");
            println!();
            println!("Env: EPIX_DATA_DIR, EPIX_UI_ADDR, EPIX_HEADLESS, EPIX_TOR");
            return;
        }
        Some("-V") | Some("--version") => {
            println!("epix-server {}", env!("EPIX_VERSION"));
            return;
        }
        _ => {}
    }
    if let Some(action) = cli.first().map(String::as_str).filter(|a| actions::is_action(a)) {
        let root = platform::data_root();
        std::fs::create_dir_all(&root).expect("create data root");
        let code = actions::run(action, &cli[1..], &root, env!("EPIX_VERSION")).await;
        std::process::exit(code);
    }

    // Accept a raw `epix1…` address, a `.epix` name, or an `epix://…` deep link
    // (from the OS handing off a clicked link). Default to the dashboard xite.
    let raw = cli.first().cloned().unwrap_or_else(|| DEFAULT_DASHBOARD.to_string());
    let target = epix_node::parse_target(&raw);

    // Headless mode (`EPIX_HEADLESS=1`): serve the node but don't open a browser
    // window - for servers/seedboxes. The dashboard is still reachable at the UI
    // address; open it yourself.
    let headless = std::env::var("EPIX_HEADLESS")
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);

    // Persistent per-OS data directory with a single-instance lock. If already
    // running, hand off to the existing instance's browser tab and exit.
    let root = platform::data_root();
    std::fs::create_dir_all(&root).expect("create data root");
    let _lock = match platform::acquire_lock(&root) {
        Ok(lock) => lock,
        Err(()) => {
            eprintln!("Epix is already running (lock held in {}).", root.display());
            if !headless {
                epix_node::open_in_browser(&format!("http://{}/{target}/", ui_bind()));
            }
            return;
        }
    };

    // EPIX_TOR is an explicit override; empty defers to the Config page's
    // persisted choice (the node resolves it at boot, default enable).
    let tor_mode = std::env::var("EPIX_TOR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    let opts = NodeOptions {
        data_root: root.clone(),
        target,
        ui_addr: ui_bind(),
        tor_mode,
        open_browser: !headless,
        geoip_gz: Some(GEOIP_CITY_GZ.to_vec()),
        log_file: Some(platform::log_path(&root, 8 * 1024 * 1024)),
        version: env!("EPIX_VERSION").to_string(),
        rev: env!("EPIX_GIT_REV").to_string(),
    };

    println!("· Epix node starting (data: {})", root.display());
    if let Err(e) = epix_node::run(opts).await {
        eprintln!("Epix node failed: {e}");
        std::process::exit(1);
    }
}
