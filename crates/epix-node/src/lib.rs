//! `epix-node` - the embeddable node: resolve a `.epix` name, clone + verify
//! the xite, and serve the UI + peer network. One code path for the server
//! binary, the FFI layer (mobile), and the desktop shell.
//!
//! The caller supplies platform paths and policy through [`NodeOptions`]; the
//! node owns everything else (peer discovery, cloning, the UI server, the
//! background runtime loops, and - when enabled - in-process Tor).

use epix_core::{Address, PeerAddr};
use epix_protocol::Connection;
use epix_transport::{TcpTransport, Transport};
use epix_ui::{UiServer, XiteEntry};
use epix_xite::{Xite, XiteStorage};
use std::path::PathBuf;
use std::sync::Arc;

/// Re-export so embedders (FFI, shells) can name the served state without a
/// direct `epix-ui` dependency.
pub use epix_ui::AppState;

/// The default Epix bootstrap tracker.
pub const DEFAULT_TRACKER: &str = "145.223.69.23:26959";
/// The default UI bind (loopback, EpixNet's port).
pub const DEFAULT_UI_ADDR: &str = "127.0.0.1:43110";

/// How the embedded node should boot and serve.
pub struct NodeOptions {
    /// The shared data root (holds `sites.json`, `resolve-cache.json`, and a
    /// per-xite subdirectory). Tor keeps its state under `<root>/tor`.
    pub data_root: PathBuf,
    /// A raw `epix1…` xite address or a `.epix` name (or bare label) to open.
    pub target: String,
    /// The UI HTTP/WebSocket bind, e.g. `127.0.0.1:43110`.
    pub ui_addr: String,
    /// Tor routing mode: `disable` / `enable` / `always`.
    pub tor_mode: String,
    /// Open the served xite in the OS browser once serving (desktop only;
    /// shells that own their own webview pass `false`).
    pub open_browser: bool,
    /// Optional gzipped GeoIP City db for the dashboard world map; expanded to
    /// `<data>/geoip-city.mmdb` in the background. `None` disables the map.
    pub geoip_gz: Option<Vec<u8>>,
    /// Optional file the node appends its log to (rotated by the caller).
    pub log_file: Option<PathBuf>,
    /// Node version string reported in `serverInfo`.
    pub version: String,
}

impl NodeOptions {
    /// Minimal options: a target and a data root, everything else defaulted.
    pub fn new(data_root: impl Into<PathBuf>, target: impl Into<String>) -> Self {
        Self {
            data_root: data_root.into(),
            target: target.into(),
            ui_addr: DEFAULT_UI_ADDR.to_string(),
            tor_mode: "enable".to_string(),
            open_browser: false,
            geoip_gz: None,
            log_file: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// A booted, serving node. The UI server future is returned so the caller
/// decides whether to await it (block) or drive it on its own task.
pub struct RunningNode {
    pub state: Arc<AppState>,
    /// The `.epix` display name (or raw address) the node serves under.
    pub display: String,
    /// The served xite address.
    pub address: String,
    /// The UI bind that succeeded.
    pub ui_addr: std::net::SocketAddr,
}

/// Normalize a launch argument into a resolver target: strip an `epix://`
/// scheme and any path/query so `epix://talk.epix/topic/1` becomes `talk.epix`
/// (the host is the xite; the path is opened inside the wrapper afterwards).
/// A raw address or bare name passes through unchanged.
pub fn parse_target(arg: &str) -> String {
    let s = arg.strip_prefix("epix://").unwrap_or(arg);
    // Host is everything up to the first `/`, `?`, or `#`.
    let host_end = s.find(['/', '?', '#']).unwrap_or(s.len());
    let host = &s[..host_end];
    if host.is_empty() {
        arg.to_string()
    } else {
        host.to_string()
    }
}

/// The in-wrapper path from an `epix://host/path?query` link (everything after
/// the host), or `""` if none. The shell navigates the wrapper here after the
/// xite loads.
pub fn parse_inner_path(arg: &str) -> String {
    let s = arg.strip_prefix("epix://").unwrap_or(arg);
    match s.find(['/', '?', '#']) {
        Some(i) => s[i..].to_string(),
        None => String::new(),
    }
}

/// Resolve `target` into `(xite_address, display_name, from_cache)`: pass an
/// `epix1…` address through; resolve a `.epix` name (or bare label, defaulting
/// to the `epix` TLD) from the on-disk cache, hitting the chain only when the
/// name has no cache entry or the entry expired ([`RESOLVE_CACHE_TTL_SECS`]).
/// If an expired entry can't be re-resolved (chain unreachable), the stale
/// mapping keeps serving rather than failing the boot.
pub async fn resolve_target(data_root: &std::path::Path, target: &str) -> (String, String, bool) {
    if target.starts_with("epix1") && !target.contains('.') {
        return (target.to_string(), target.to_string(), false);
    }
    let (name, tld) = target.rsplit_once('.').unwrap_or((target, "epix"));
    let full = format!("{name}.{tld}");
    match cached_resolution(data_root, &full) {
        Some((address, true)) => return (address, full, true),
        Some((stale, false)) => {
            // Expired: refresh from the chain; keep the stale mapping if that fails.
            return match try_resolve_on_chain(name, tld).await {
                Ok(address) => {
                    write_resolve_cache(data_root, &full, &address);
                    (address, full, false)
                }
                Err(_) => (stale, full, true),
            };
        }
        None => {}
    }
    let address = resolve_on_chain(name, tld).await;
    write_resolve_cache(data_root, &full, &address);
    (address, full, false)
}

/// Resolve a `.epix` name to its xite address on the chain, or an error string
/// (never panics - safe to call from a request handler).
pub async fn try_resolve_on_chain(name: &str, tld: &str) -> Result<String, String> {
    let resolver = epix_chain::XidResolver::new(epix_chain::DEFAULT_RPC_URL);
    let domain = resolver
        .resolve(name, tld)
        .await
        .map_err(|e| format!("could not resolve {name}.{tld}: {e}"))?;
    domain
        .xite_address()
        .map(|a| a.to_string())
        .ok_or_else(|| format!("{name}.{tld} has no EpixNet xite address record"))
}

/// Resolve a `.epix` name to its xite address on the chain (panics on failure -
/// the initial-boot CLI path).
pub async fn resolve_on_chain(name: &str, tld: &str) -> String {
    try_resolve_on_chain(name, tld)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
}

/// Boot the node: resolve, clone + verify (unless already on disk), set up the
/// UI server and the background runtime, and return the [`UiServer`] future to
/// await plus the [`RunningNode`] handle. Cloning uses the network only when
/// the xite is not already complete on disk.
pub async fn boot(
    opts: NodeOptions,
) -> Result<(UiServer, RunningNode), String> {
    let (address, display, _from_cache) = resolve_target(&opts.data_root, &opts.target).await;
    let transport: Arc<dyn Transport> = Arc::new(TcpTransport);

    std::fs::create_dir_all(&opts.data_root).map_err(|e| format!("create data root: {e}"))?;
    let data_dir = opts.data_root.join(&address);
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("create data dir: {e}"))?;

    let trackers = vec![PeerAddr::parse(DEFAULT_TRACKER).unwrap()];
    let (content, bytes_recv) =
        clone_xite(&address, &data_dir, transport.clone(), &trackers).await?;

    let running = serve(opts, address, display, data_dir, content, bytes_recv).await?;
    Ok(running)
}

/// Boot and then serve forever (blocks). The convenience entry point for the
/// server binary and the FFI background thread.
pub async fn run(opts: NodeOptions) -> Result<(), String> {
    let (server, running) = boot(opts).await?;
    server.serve(running.ui_addr).await.map_err(|e| format!("server: {e}"))
}

/// Clone a xite into `data_dir` from the network (skipping the fetch if it is
/// already complete on disk): discover peers, fetch + verify content.json, and
/// sync every file. Returns the verified content and the bytes downloaded.
/// Shared by initial boot and the on-demand resolver.
async fn clone_xite(
    address: &str,
    data_dir: &std::path::Path,
    transport: Arc<dyn Transport>,
    trackers: &[PeerAddr],
) -> Result<(Option<serde_json::Value>, u64), String> {
    clone_xite_with_progress(address, data_dir, transport, trackers, None).await
}

/// [`clone_xite`], pushing wrapper loading-screen events (`peers_added`,
/// `file_done` for content.json with the pending-file counts) to `progress`
/// as the clone advances - the on-demand path, where a browser is watching
/// the loading screen.
async fn clone_xite_with_progress(
    address: &str,
    data_dir: &std::path::Path,
    transport: Arc<dyn Transport>,
    trackers: &[PeerAddr],
    progress: Option<&Arc<AppState>>,
) -> Result<(Option<serde_json::Value>, u64), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("create xite dir: {e}"))?;
    let mut xite = Xite::new(
        Address::parse(address.to_string()).map_err(|e| format!("bad address: {e}"))?,
        XiteStorage::new(data_dir),
    );

    let complete = xite.load_content().unwrap_or(false) && xite.files_needed().is_empty();
    if complete {
        return Ok((xite.content.clone(), 0));
    }

    // With a loading screen watching, announce through the state so the
    // per-tracker stats record + push live (the screen's tracker status line)
    // and the screen shows the search stage; the boot path stays direct.
    let mut peers = match progress {
        Some(state) => {
            state.push_clone_event(address, serde_json::Value::Null, serde_json::json!({}));
            state.announce_to_trackers(address, trackers).await
        }
        None => epix_xite::announce(transport.as_ref(), address, trackers, 0).await,
    };
    // Trackers came up short: ask the DHT (tracker-independent - any peer that
    // serves the site can answer). Only wired on the on-demand path; at boot
    // the runtime (which owns the DHT) isn't running yet.
    if peers.is_empty() {
        if let Some(state) = progress {
            peers = state.find_peers_dht(address).await;
        }
    }
    if peers.is_empty() {
        return Err("no peers found - is the network reachable?".into());
    }
    if let Some(state) = progress {
        state.push_clone_event(
            address,
            serde_json::json!(["peers_added", peers.len()]),
            serde_json::json!({ "peers": peers.len() }),
        );
    }
    if xite.content.is_none() {
        let mut ok = false;
        for peer in &peers {
            if let Ok(mut conn) = Connection::connect(transport.as_ref(), peer).await {
                if conn.handshake().await.is_ok() {
                    if let Ok(b) = conn.get_file(address, "content.json").await {
                        if xite.set_content(&b).is_ok() {
                            ok = true;
                            break;
                        }
                    }
                }
            }
        }
        if !ok {
            return Err("could not fetch + verify content.json from any peer".into());
        }
        if let Some(state) = progress {
            let total = xite.files_needed().len();
            let counts = serde_json::json!({
                "peers": peers.len(),
                "bad_files": total,
                "tasks": total,
                "started_task_num": total,
            });
            state.push_clone_event(
                address,
                serde_json::json!(["file_done", "content.json"]),
                counts.clone(),
            );
            // "N files needs to be downloaded"
            state.push_clone_event(address, serde_json::json!(["file_added", total]), counts);
        }
    }
    // Per-file progress: each finished file prints its line on the loading
    // screen and advances the progress bar (tasks/started_task_num).
    let on_file = progress.map(|state| {
        let state = state.clone();
        let addr = address.to_string();
        let peers_n = peers.len();
        Arc::new(move |inner: &str, done: usize, total: usize| {
            // The wrapper closes the loading screen on index.html's file_done,
            // but the page itself only serves once the whole clone lands - so
            // that one is pushed at the end (do_ensure), not from here.
            if inner == "index.html" {
                return;
            }
            let left = total.saturating_sub(done);
            state.push_clone_event(
                &addr,
                serde_json::json!(["file_done", inner]),
                serde_json::json!({
                    "peers": peers_n,
                    "bad_files": left,
                    "tasks": left,
                    "started_task_num": total,
                }),
            );
        }) as epix_worker::FileProgress
    });
    let mut bytes_recv = 0;
    if let Ok(report) =
        epix_worker::sync_files_with_progress(&xite, &peers, transport.clone(), 8, on_file).await
    {
        bytes_recv = report.bytes;
    }
    Ok((xite.content.clone(), bytes_recv))
}

/// The on-demand resolver the browser proxy path uses: given a `.epix` host not
/// yet served, resolve it on-chain, clone it, and add it as a served xite keyed
/// by its bech32 address (the name is display metadata), so typing any
/// `talk.epix` opens it live.
struct OnDemand {
    state: Arc<AppState>,
    data_root: PathBuf,
    transport: Arc<dyn Transport>,
    trackers: Vec<PeerAddr>,
    /// Names currently being cloned, so concurrent requests coalesce.
    in_flight: tokio::sync::Mutex<std::collections::HashSet<String>>,
}

#[async_trait::async_trait]
impl epix_ui::OnDemandResolver for OnDemand {
    async fn ensure(&self, host: &str) -> Result<(), String> {
        // Served already? (name -> address via display metadata / resolve cache)
        let key = self.state.canonical_key(host).await;
        if self.state.has_xite(&key).await {
            return Ok(());
        }
        // Coalesce concurrent clones of the same name: the first does the work,
        // the rest wait briefly for it to land.
        {
            let mut inflight = self.in_flight.lock().await;
            if inflight.contains(host) {
                drop(inflight);
                // The wrapper's inner file request blocks on this while the
                // loading screen shows, so wait as long as a clone can take.
                for _ in 0..600 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    let key = self.state.canonical_key(host).await;
                    if self.state.has_xite(&key).await {
                        return Ok(());
                    }
                    if !self.in_flight.lock().await.contains(host) {
                        break; // the working clone finished (or failed)
                    }
                }
                let key = self.state.canonical_key(host).await;
                if self.state.has_xite(&key).await {
                    return Ok(());
                }
                return Err("timed out waiting for a concurrent clone".into());
            }
            inflight.insert(host.to_string());
        }
        let result = self.do_ensure(host).await;
        self.in_flight.lock().await.remove(host);
        result
    }
}

impl OnDemand {
    async fn do_ensure(&self, host: &str) -> Result<(), String> {
        // Resolve the name to a xite address (unless it's already one): the
        // on-disk cache first; the chain only on a miss or an expired entry.
        // An expired entry still serves if the chain is unreachable.
        let (name, tld) = host.rsplit_once('.').unwrap_or((host, "epix"));
        let address = if name.starts_with("epix1") {
            name.to_string()
        } else {
            match cached_resolution(&self.data_root, host) {
                Some((address, true)) => address,
                stale => match try_resolve_on_chain(name, tld).await {
                    Ok(address) => {
                        // Persist so a restart serves it without re-resolving.
                        write_resolve_cache(&self.data_root, host, &address);
                        address
                    }
                    Err(e) => stale.map(|(address, _)| address).ok_or(e)?,
                },
            }
        };

        let data_dir = self.data_root.join(&address);
        // If we already serve the raw address, just alias the name to it.
        if !self.state.has_xite(&address).await {
            let cloned = clone_xite_with_progress(
                &address,
                &data_dir,
                self.transport.clone(),
                &self.trackers,
                Some(&self.state),
            )
            .await;
            let (content, bytes) = match cloned {
                Ok(r) => r,
                Err(e) => {
                    // Tell the loading screen: "index.html download failed",
                    // and "No peers found" when peers stayed at 0.
                    self.state.push_clone_event(
                        &address,
                        serde_json::json!(["file_failed", "index.html"]),
                        serde_json::json!({}),
                    );
                    return Err(e);
                }
            };
            self.state
                .add_xite(
                    &address,
                    XiteEntry { storage: XiteStorage::new(&data_dir), content: content.clone() },
                )
                .await;
            self.state.add_transfer(&address, bytes, 0).await;
            // Hide the loading screen: the wrapper closes on the file_done of
            // its own index.html.
            self.state.push_clone_event(
                &address,
                serde_json::json!(["file_done", "index.html"]),
                serde_json::json!({ "content": content }),
            );
        }
        // The `.epix` name is display metadata on the address-keyed entry.
        if host != address {
            self.state.set_display(&address, host).await;
        }
        self.state.log("INFO", format!("On-demand cloned {host} -> {address}")).await;
        Ok(())
    }
}

/// Wire up the [`AppState`], plugins, background runtime, and UI server for an
/// already-resolved (and cloned) xite. Returns the server future + handle.
async fn serve(
    opts: NodeOptions,
    address: String,
    display: String,
    data_dir: PathBuf,
    content: Option<serde_json::Value>,
    bytes_recv: u64,
) -> Result<(UiServer, RunningNode), String> {
    let state = AppState::with_data_dir(&opts.version, &data_dir);
    if let Some(log_file) = &opts.log_file {
        state.set_log_file(log_file);
    }

    // Expand the GeoIP db off the startup path (first run unzips ~62MB).
    if let Some(gz) = opts.geoip_gz.clone() {
        let state = state.clone();
        let mmdb = data_dir.join("geoip-city.mmdb");
        tokio::spawn(async move {
            let geoip = tokio::task::spawn_blocking(move || {
                epix_ui::geoip::GeoIp::ensure(&gz, &mmdb)
            })
            .await
            .ok()
            .flatten();
            if let Some(geoip) = geoip {
                state.set_geoip(geoip).await;
            }
        });
    }

    // Restore xites served in a previous run (from sites.json).
    let restored = state.restore_sites().await;
    if restored > 0 {
        state.log("INFO", format!("Restored {restored} xite(s) from sites.json")).await;
    }

    // Serve keyed by the bech32 address; the resolved `.epix` name is display
    // metadata (names translate to addresses at the HTTP/WS edges).
    state
        .add_xite(&address, XiteEntry { storage: XiteStorage::new(&data_dir), content })
        .await;
    if display != address {
        state.set_display(&address, &display).await;
    }
    // The launch xite is the homepage: the wrapper's corner home button and
    // the admin pages' back link return here from any other xite.
    state.set_homepage(&display);

    let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
    state.set_transport(transport.clone()).await;

    // Trackers: configured list, else the default.
    let trackers: Vec<PeerAddr> = match state
        .config_get("trackers")
        .await
        .and_then(|v| v.as_str().map(str::to_string))
    {
        Some(list) if !list.trim().is_empty() => {
            list.split([',', '\n']).filter_map(|t| PeerAddr::parse(t.trim()).ok()).collect()
        }
        _ => vec![PeerAddr::parse(DEFAULT_TRACKER).unwrap()],
    };

    // On-demand resolve + clone: typing any `talk.epix` in the browser clones
    // and serves it live.
    state
        .set_on_demand(Arc::new(OnDemand {
            state: state.clone(),
            data_root: opts.data_root.clone(),
            transport: transport.clone(),
            trackers: trackers.clone(),
            in_flight: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        }))
        .await;

    state.add_transfer(&address, bytes_recv, 0).await;
    state.rebuild_merger_dbs().await;

    // Seeding + offline policy.
    const DEFAULT_FILESERVER_PORT: u16 = 26552;
    let fileserver_port = match state.config_get("fileserver_port").await.and_then(|v| v.as_u64()) {
        Some(0) => None,
        Some(p) => Some(p as u16),
        None => Some(DEFAULT_FILESERVER_PORT),
    };
    let offline = state
        .config_get("offline")
        .await
        .map(|v| v.as_bool().unwrap_or_else(|| v.as_str() == Some("true")))
        .unwrap_or(false);
    if let Some(port) = fileserver_port {
        state.set_fileserver_port(port).await;
    }

    #[cfg(feature = "tor")]
    let tor_mode = if offline {
        epix_runtime::TorMode::Disable
    } else {
        epix_runtime::TorMode::parse(&opts.tor_mode)
    };

    let runtime_config = epix_runtime::RuntimeConfig {
        fileserver_port: if offline { None } else { fileserver_port },
        offline,
        #[cfg(feature = "tor")]
        tor_mode,
        #[cfg(feature = "tor")]
        tor_socks_port: Some(43111),
        ..Default::default()
    };
    let mut runtime =
        epix_runtime::NodeRuntime::with_config(state.clone(), trackers, runtime_config);
    #[cfg(feature = "tor")]
    {
        runtime = runtime.with_data_dir(opts.data_root.clone());
    }
    runtime.start();

    // Tor-always: once the Arti SOCKS listener is up (tor_status == "Always"),
    // route all chain RPC through it, so name resolution never exposes the
    // node's IP or which `.epix` names it looks up. Peer/tracker traffic already
    // rides Tor via the always-mode transport.
    //
    // Cold-start gap: Tor takes ~10-40s to bootstrap. Any chain RPC that runs
    // before this fires (e.g. resolving the site named on the command line at
    // startup) goes direct. Steady-state resolves - on-demand navigation, the
    // native host, re-verification - all wait until the proxy is set and route
    // through Tor.
    #[cfg(feature = "tor")]
    if tor_mode == epix_runtime::TorMode::Always {
        let state = state.clone();
        tokio::spawn(async move {
            loop {
                if state.tor_status().await.1 == "Always" {
                    epix_chain::set_chain_socks(Some("socks5h://127.0.0.1:43111".into()));
                    state.log("INFO", "Chain RPC now routed through Tor".to_string()).await;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        });
    }
    // The runtime's loops are owned by their spawned tasks; leak the handle so
    // they run for the process lifetime (the caller serves forever).
    std::mem::forget(runtime);

    // Plugins + media.
    let mut plugins = epix_plugin::PluginRegistry::new();
    plugins.register(Arc::new(epix_plugins::SidebarPlugin));
    let mut plugin_names: Vec<String> = plugins.names().iter().map(|s| s.to_string()).collect();
    plugin_names.extend(epix_ui::builtin_plugins().into_iter().map(String::from));
    plugin_names.sort();
    plugin_names.dedup();
    state.set_plugins(plugin_names).await;

    let bind: std::net::SocketAddr = opts
        .ui_addr
        .parse()
        .map_err(|_| format!("invalid ui_addr '{}'", opts.ui_addr))?;
    state.log("INFO", format!("Serving {display} ({bytes_recv} bytes received)")).await;

    if opts.open_browser {
        open_in_browser(&format!("http://{bind}/{display}/"));
    }

    let server =
        UiServer::with_registry_and_media(state.clone(), plugins.command_registry(), plugins.media_bundle());
    Ok((server, RunningNode { state, display, address, ui_addr: bind }))
}

fn resolve_cache_path(data_root: &std::path::Path) -> PathBuf {
    data_root.join("resolve-cache.json")
}

/// How long a cached xID resolution stays fresh. Within this window the chain
/// is never consulted for that name; after it, the next lookup re-resolves
/// (falling back to the stale entry if the chain is unreachable).
pub const RESOLVE_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Look up a name in the resolve cache: `Some((address, fresh))` where `fresh`
/// says the entry is within [`RESOLVE_CACHE_TTL_SECS`]. Reads both the current
/// format (`{"address": "epix1…", "resolved_at": secs}`) and the legacy plain
/// string form (address known, age unknown - treated as expired so it upgrades
/// on the next successful resolve).
pub fn cached_resolution(data_root: &std::path::Path, full: &str) -> Option<(String, bool)> {
    match read_resolve_cache(data_root).get(full)? {
        serde_json::Value::String(address) => Some((address.clone(), false)),
        serde_json::Value::Object(entry) => {
            let address = entry.get("address")?.as_str()?.to_string();
            let resolved_at = entry.get("resolved_at").and_then(|v| v.as_u64()).unwrap_or(0);
            let fresh = now_secs().saturating_sub(resolved_at) < RESOLVE_CACHE_TTL_SECS;
            Some((address, fresh))
        }
        _ => None,
    }
}

fn read_resolve_cache(
    data_root: &std::path::Path,
) -> serde_json::Map<String, serde_json::Value> {
    std::fs::read(resolve_cache_path(data_root))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Record a fresh chain resolution: `{"address": …, "resolved_at": now}`.
/// Public so the native-messaging host shares the node's cache.
pub fn write_resolve_cache(data_root: &std::path::Path, full: &str, address: &str) {
    let path = resolve_cache_path(data_root);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut cache = read_resolve_cache(data_root);
    cache.insert(
        full.to_string(),
        serde_json::json!({ "address": address, "resolved_at": now_secs() }),
    );
    if let Ok(bytes) = serde_json::to_vec_pretty(&cache) {
        let _ = std::fs::write(path, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_strips_scheme_and_path() {
        assert_eq!(parse_target("epix://talk.epix/topic/1"), "talk.epix");
        assert_eq!(parse_target("epix://talk.epix"), "talk.epix");
        assert_eq!(parse_target("talk.epix"), "talk.epix");
        assert_eq!(parse_target("epix1abcdef"), "epix1abcdef");
        assert_eq!(parse_target("epix://dashboard.epix/?x=1#frag"), "dashboard.epix");
        // A bare scheme with no host falls back to the raw arg.
        assert_eq!(parse_target("epix://"), "epix://");
    }

    #[test]
    fn parse_inner_path_keeps_path_and_query() {
        assert_eq!(parse_inner_path("epix://talk.epix/topic/1"), "/topic/1");
        assert_eq!(parse_inner_path("epix://talk.epix/?q=2"), "/?q=2");
        assert_eq!(parse_inner_path("epix://talk.epix"), "");
        assert_eq!(parse_inner_path("talk.epix/a"), "/a");
    }

    #[test]
    fn resolve_cache_ttl_fresh_expired_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Miss.
        assert_eq!(cached_resolution(root, "talk.epix"), None);

        // A fresh write is fresh.
        write_resolve_cache(root, "talk.epix", "epix1talk");
        assert_eq!(cached_resolution(root, "talk.epix"), Some(("epix1talk".into(), true)));

        // An entry past the TTL reports expired (address still returned, so
        // callers can fall back to it when the chain is unreachable).
        let old = now_secs() - RESOLVE_CACHE_TTL_SECS - 1;
        let cache = serde_json::json!({
            "old.epix": { "address": "epix1old", "resolved_at": old },
            "legacy.epix": "epix1legacy",
        });
        std::fs::write(resolve_cache_path(root), serde_json::to_vec(&cache).unwrap()).unwrap();
        assert_eq!(cached_resolution(root, "old.epix"), Some(("epix1old".into(), false)));

        // Legacy plain-string entries: address known, treated as expired.
        assert_eq!(cached_resolution(root, "legacy.epix"), Some(("epix1legacy".into(), false)));

        // Re-writing upgrades a legacy entry to the timestamped form.
        write_resolve_cache(root, "legacy.epix", "epix1legacy");
        assert_eq!(cached_resolution(root, "legacy.epix"), Some(("epix1legacy".into(), true)));
    }
}

/// The shared data root: `EPIX_DATA_DIR` if set, else the conventional per-OS
/// application-data location (`~/Library/Application Support/EpixNet` on macOS,
/// `%APPDATA%\EpixNet` on Windows, `$XDG_DATA_HOME/EpixNet` or
/// `~/.local/share/EpixNet` on Linux). Shared by the server binary and the
/// desktop browser so they use one identity, site set, and Tor state.
pub fn data_root() -> PathBuf {
    if let Ok(dir) = std::env::var("EPIX_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let base = if cfg!(target_os = "macos") {
        home_dir().join("Library/Application Support")
    } else if cfg!(target_os = "windows") {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir().join("AppData/Roaming"))
    } else {
        std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir().join(".local/share"))
    };
    base.join("EpixNet")
}

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
}

/// Open `url` in the default browser (best effort, platform-specific).
pub fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let (cmd, args): (&str, &[&str]) = ("open", &[]);
    #[cfg(target_os = "windows")]
    let (cmd, args): (&str, &[&str]) = ("cmd", &["/C", "start", ""]);
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let (cmd, args): (&str, &[&str]) = ("xdg-open", &[]);
    let _ = std::process::Command::new(cmd).args(args).arg(url).spawn();
}
