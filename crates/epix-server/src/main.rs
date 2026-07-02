//! Runnable Epix node: discover peers, clone a xite from the live EpixNet
//! network, and serve it in a browser through the UI server.

use epix_core::{Address, PeerAddr};
use epix_protocol::Connection;
use epix_transport::{TcpTransport, Transport};
use epix_ui::{AppState, UiServer, XiteEntry};
use epix_xite::{Xite, XiteStorage};
use std::sync::Arc;

const TRACKER: &str = "145.223.69.23:26959";
const BIND: &str = "127.0.0.1:43110";

/// Bundled peer-geolocation database for the dashboard's world map: DB-IP City
/// Lite (CC-BY-4.0), shipped gzipped and expanded into the data dir at runtime.
const GEOIP_CITY_GZ: &[u8] = include_bytes!("../assets/dbip-city-lite.mmdb.gz");

#[tokio::main]
async fn main() {
    // Accept a raw `epix1…` xite address, or a `.epix` name to resolve on-chain.
    let arg = std::env::args().nth(1).unwrap_or_else(|| "dashboard.epix".to_string());
    let (address, display, from_cache) = resolve_target(&arg).await;
    // A cached resolution serves instantly; re-verify it on the chain in the
    // background so a changed record is noticed without blocking startup.
    if from_cache {
        let (full, served) = (display.clone(), address.clone());
        tokio::spawn(async move { reverify_resolution(&full, &served).await });
    }
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport);

    let data_dir = std::env::temp_dir().join("epix-data").join(&address);
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let mut xite = Xite::new(
        Address::parse(address.clone()).expect("valid address"),
        XiteStorage::new(&data_dir),
    );

    // 0. If already cloned + verified, skip the network fetch (fast restarts).
    if xite.load_content().unwrap_or(false) && xite.files_needed().is_empty() {
        println!("· {address} already cloned + verified — serving from cache");
        serve(address, display, data_dir, xite.content.clone(), 0).await;
        return;
    }

    // 1. Discover peers via the Epix tracker.
    println!("· discovering peers for {address} …");
    let peers = epix_xite::announce(
        transport.as_ref(),
        &address,
        &[PeerAddr::parse(TRACKER).unwrap()],
        0,
    )
    .await;
    println!("  found {} peers", peers.len());
    if peers.is_empty() {
        eprintln!("no peers found — is the network reachable?");
        std::process::exit(1);
    }

    // 2. Fetch + verify content.json.
    let mut ok = false;
    for peer in &peers {
        if let Ok(mut conn) = Connection::connect(transport.as_ref(), peer).await {
            if conn.handshake().await.is_ok() {
                if let Ok(bytes) = conn.get_file(&address, "content.json").await {
                    if xite.set_content(&bytes).is_ok() {
                        ok = true;
                        break;
                    }
                }
            }
        }
    }
    if !ok {
        eprintln!("could not fetch + verify content.json from any peer");
        std::process::exit(1);
    }

    // 3. Sync every file, verifying each hash.
    let needed = xite.files_needed().len();
    println!("· content.json verified — downloading {needed} files …");
    let report = epix_worker::sync_files(&xite, &peers, transport.clone(), 8)
        .await
        .expect("sync");
    println!(
        "  downloaded {} files ({} bytes); {} failed",
        report.downloaded,
        report.bytes,
        report.failed.len()
    );

    // 4. Serve it.
    serve(address, display, data_dir, xite.content.clone(), report.bytes).await;
}

/// Turn a CLI argument into `(xite_address, display_name, from_cache)`: pass
/// `epix1…` through; resolve a `.epix` name (or bare label, defaulting to
/// `epix`) — from the on-disk resolve cache if we have it (instant, re-verified
/// later), otherwise on the chain. The display name is the `.epix` name so URLs
/// read as `dashboard.epix`.
async fn resolve_target(arg: &str) -> (String, String, bool) {
    if arg.starts_with("epix1") && !arg.contains('.') {
        return (arg.to_string(), arg.to_string(), false);
    }
    let (name, tld) = arg.rsplit_once('.').unwrap_or((arg, "epix"));
    let full = format!("{name}.{tld}");
    if let Some(address) = read_resolve_cache().get(&full).and_then(|v| v.as_str()) {
        println!("· {full} → {address} (cached; re-verifying on chain in background)");
        return (address.to_string(), full, true);
    }
    println!("· resolving {full} on the Epix chain …");
    let address = resolve_on_chain(name, tld).await;
    println!("  {full} → {address} (chain-verified)");
    write_resolve_cache(&full, &address);
    (address, full, false)
}

/// Resolve a `.epix` name to its xite address on the chain (panics on failure).
async fn resolve_on_chain(name: &str, tld: &str) -> String {
    let resolver = epix_chain::XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let domain = resolver
        .resolve(name, tld)
        .await
        .unwrap_or_else(|e| panic!("could not resolve {name}.{tld}: {e}"));
    domain
        .xite_address()
        .unwrap_or_else(|| panic!("{name}.{tld} has no EpixNet xite address record"))
        .to_string()
}

/// Re-resolve a cached name on the chain and warn if the record changed. Runs in
/// the background after we have already started serving the cached address.
async fn reverify_resolution(full: &str, served_address: &str) {
    let (name, tld) = full.rsplit_once('.').unwrap_or((full, "epix"));
    let resolver = epix_chain::XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let resolved =
        resolver.resolve(name, tld).await.ok().and_then(|d| d.xite_address().map(|a| a.to_string()));
    match resolved {
        Some(address) if address == served_address => {
            println!("· {full} re-verified on chain (unchanged)");
        }
        Some(address) => {
            eprintln!(
                "⚠ {full} now resolves to {address} (serving cached {served_address}); \
                 restart to switch to the new address"
            );
            write_resolve_cache(full, &address);
        }
        None => eprintln!("⚠ could not re-verify {full} on chain; keeping the cached address"),
    }
}

/// The name→address resolve cache (shared across xites, keyed by `.epix` name).
fn resolve_cache_path() -> std::path::PathBuf {
    std::env::temp_dir().join("epix-data").join("resolve-cache.json")
}

fn read_resolve_cache() -> serde_json::Map<String, serde_json::Value> {
    std::fs::read(resolve_cache_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_resolve_cache(full: &str, address: &str) {
    let path = resolve_cache_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut cache = read_resolve_cache();
    cache.insert(full.to_string(), serde_json::Value::from(address));
    if let Ok(bytes) = serde_json::to_vec_pretty(&cache) {
        let _ = std::fs::write(path, bytes);
    }
}

async fn serve(
    address: String,
    display: String,
    data_dir: std::path::PathBuf,
    content: Option<serde_json::Value>,
    bytes_recv: u64,
) {
    let state = AppState::with_data_dir(env!("CARGO_PKG_VERSION"), &data_dir);
    // Load the bundled IP geolocation db (DB-IP City Lite, CC-BY-4.0) off the
    // startup path: first run expands the ~62MB gzip to disk, so do it in the
    // background. The node serves and connects to peers immediately; the world
    // map returns empty until the db is ready, then fills in.
    {
        let state = state.clone();
        let mmdb = data_dir.join("geoip-city.mmdb");
        tokio::spawn(async move {
            let geoip = tokio::task::spawn_blocking(move || {
                epix_ui::geoip::GeoIp::ensure(GEOIP_CITY_GZ, &mmdb)
            })
            .await
            .ok()
            .flatten();
            if let Some(geoip) = geoip {
                state.set_geoip(geoip).await;
                state.push_notification("done", "World map ready", 4000);
                println!("· geolocation database ready — world map enabled");
            }
        });
    }
    // Serve under the raw address and (if resolved from a name) the .epix name,
    // so both http://…/dashboard.epix/ and http://…/epix1…/ work.
    state
        .add_xite(
            &address,
            XiteEntry {
                storage: XiteStorage::new(&data_dir),
                content: content.clone(),
            },
        )
        .await;
    if display != address {
        state
            .add_xite(
                &display,
                XiteEntry {
                    storage: XiteStorage::new(&data_dir),
                    content,
                },
            )
            .await;
    }

    // Record the clone's transfer so siteInfo/the sidebar show real bytes. The
    // tracker announce is left to the runtime's announce loop (which runs
    // immediately on start), so it does not block the server bind.
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
    state.set_transport(transport.clone()).await;
    let trackers = vec![PeerAddr::parse(TRACKER).unwrap()];
    state.add_transfer(&address, bytes_recv, 0).await;
    if display != address {
        state.add_transfer(&display, bytes_recv, 0).await;
    }
    // Fill any merger site's aggregate db from the merged sites we serve.
    state.rebuild_merger_dbs().await;

    // Bring the node to life: supervised loops re-announce to trackers and
    // re-sync each xite (picking up published updates) in the background.
    let mut runtime = epix_runtime::NodeRuntime::new(state.clone(), trackers);
    runtime.start();

    // Assemble the UI command set + media through the plugin system.
    let mut plugins = epix_plugin::PluginRegistry::new();
    plugins.register(std::sync::Arc::new(epix_plugins::SidebarPlugin));

    let bind: std::net::SocketAddr = BIND.parse().unwrap();
    println!("\n┌──────────────────────────────────────────────");
    println!("│ Epix node — live (announce + re-sync loops running)");
    println!("│ plugins: {:?}", plugins.names());
    println!("│ Open in your browser:");
    println!("│   http://{BIND}/{display}/");
    println!("└──────────────────────────────────────────────\n");
    UiServer::with_registry_and_media(state, plugins.command_registry(), plugins.media_bundle())
        .serve(bind)
        .await
        .expect("server");
}
