//! Runnable Epix node: discover peers, clone a xite from the live EpixNet
//! network, and serve it in a browser through the UI server. The node logic
//! lives in `epix-node` (shared with the FFI layer and the shells); this binary
//! adds the desktop concerns: platform data dir, single-instance lock, file
//! logging, the bundled GeoIP asset, and `epix://` argument handling.

mod actions;
mod launch;
mod platform;

use epix_node::NodeOptions;

/// Bundled peer-geolocation database for the dashboard's world map: DB-IP City
/// Lite (CC-BY-4.0), shipped gzipped and expanded into the data dir at runtime.
const GEOIP_CITY_GZ: &[u8] = include_bytes!("../assets/dbip-city-lite.mmdb.gz");

/// The xite opened when no target is given on the command line: the dashboard.
/// A bech32 address (not the `dashboard.epix` name) so boot never depends on
/// chain name resolution being reachable.
const DEFAULT_DASHBOARD: &str = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";

#[tokio::main]
async fn main() {
    // CLI actions (siteCreate, siteSign, peerPing, ...) run and exit; the
    // action name is the first argument, Python-CLI style. Anything else is
    // a xite target and starts the node. argv[0] is skipped, never trusted.
    // args_os, not args: args() PANICS on a non-Unicode argument, and this
    // CLI takes file paths (importBundle) that need not be valid UTF-8 -
    // fail those with a clean usage error instead.
    let cli: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(bad) => {
            eprintln!("Argument is not valid Unicode: {bad:?}");
            std::process::exit(2);
        }
    };
    // Guard the conventional flags: without this, `--help` would be taken for
    // a xite target and boot a full node against the real data dir.
    match cli.first().map(String::as_str) {
        Some("-h") | Some("--help") | Some("help") => {
            println!("epix-server {}", env!("EPIX_VERSION"));
            println!("Usage: epix-server [--browser epix|system] [xite address | name.epix | epix://link]");
            println!("       epix-server <action> [args...]");
            println!();
            println!("Actions: siteCreate, siteSign, sitePublish, siteVerify, siteList,");
            println!("         siteDelete, siteDownload, siteSignMessage, dbRebuild, dbQuery,");
            println!("         importBundle,");
            println!("         cryptSign, cryptVerify, cryptGetPrivatekey,");
            println!("         cryptPrivatekeyToAddress, peerPing, siteCmd");
            println!();
            println!("Env: EPIX_DATA_DIR, EPIX_UI_ADDR, EPIX_HEADLESS, EPIX_TOR, EPIX_BROWSER");
            println!("Browser: --browser > EPIX_BROWSER > saved browser setting > epix");
            println!("EPIX_HEADLESS or saved open_browser=false disables automatic opening.");
            return;
        }
        Some("-V") | Some("--version") => {
            println!("epix-server {}", env!("EPIX_VERSION"));
            return;
        }
        _ => {}
    }
    if let Some(action) = cli
        .first()
        .map(String::as_str)
        .filter(|a| actions::is_action(a))
    {
        let root = platform::data_root();
        std::fs::create_dir_all(&root).expect("create data root");
        let code = actions::run(action, &cli[1..], &root, env!("EPIX_VERSION")).await;
        std::process::exit(code);
    }

    // Accept a raw `epix1…` address, a `.epix` name, or an `epix://…` deep link
    // (from the OS handing off a clicked link). Default to the dashboard xite.
    let arguments = launch::Arguments::parse(&cli, DEFAULT_DASHBOARD).unwrap_or_else(|error| {
        eprintln!("{error}. Use epix-server --help for usage.");
        std::process::exit(2);
    });

    // Headless mode (`EPIX_HEADLESS=1`): serve the node but don't open a browser
    // window - for servers/seedboxes. The dashboard is still reachable at the UI
    // address; open it yourself.
    let headless = std::env::var("EPIX_HEADLESS")
        .map(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(false);

    let browser_environment = match std::env::var("EPIX_BROWSER") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => {
            eprintln!("EPIX_BROWSER must be epix or system");
            std::process::exit(2);
        }
    };
    // Match prepare_data_root's OS-string handling of explicit paths, including
    // valid filesystem paths that cannot be represented as Unicode.
    let settings_root = std::env::var_os("EPIX_DATA_DIR")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(platform::data_root);
    let browser = launch::select(
        &settings_root,
        arguments.browser,
        browser_environment.as_deref(),
        headless,
    )
    .unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(1);
    });
    if browser == Some(launch::Browser::Epix) {
        // epix-browser owns its own node and handles existing managed instances.
        // Hand over before preparing data, because that pins a process-long lease.
        let code = launch::handoff(&arguments.target).unwrap_or_else(|error| {
            eprintln!("{error}");
            1
        });
        std::process::exit(code);
    }
    let target = epix_node::parse_target(&arguments.target);

    // Apply a queued move before opening the log or any persistent node data.
    let data_lease = match epix_node::prepare_data_root() {
        Ok(lease) => lease,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let root = data_lease.root().to_path_buf();

    // EPIX_TOR is an explicit override; empty defers to the Config page's
    // persisted choice (the node resolves it at boot, default enable).
    let tor_mode = std::env::var("EPIX_TOR")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    let opts = NodeOptions {
        data_root: root.clone(),
        target,
        ui_addr: epix_node::ui_bind(&root).unwrap_or_else(|error| {
            eprintln!("Epix node failed: {error}");
            std::process::exit(1);
        }),
        tor_mode,
        open_browser: browser == Some(launch::Browser::System),
        geoip_gz: Some(GEOIP_CITY_GZ.to_vec()),
        log_file: Some(platform::log_path(&root, 8 * 1024 * 1024)),
        version: env!("EPIX_VERSION").to_string(),
        rev: env!("EPIX_GIT_REV").to_string(),
    };

    println!("· Epix node starting (data: {})", root.display());
    if let Err(e) = epix_node::run_with_data_lease(opts, data_lease).await {
        eprintln!("Epix node failed: {e}");
        std::process::exit(1);
    }
}
