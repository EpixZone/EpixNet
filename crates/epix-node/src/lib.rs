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
/// Epix's default UI port.
pub const DEFAULT_UI_PORT: u16 = 42222;
/// Legacy EpixNet UI port, used as a fallback when the default is taken (so a
/// fresh Epix and an old EpixNet can coexist, and old 43110 links still resolve).
pub const LEGACY_UI_PORT: u16 = 43110;
/// The default UI bind (loopback, Epix's port).
pub const DEFAULT_UI_ADDR: &str = "127.0.0.1:42222";

/// How the embedded node should boot and serve.
pub struct NodeOptions {
    /// The shared data root, laid out like Python EpixNet: node files
    /// (users.json, sites.json) under `<root>/private/`, each xite under
    /// `<root>/data/<address>/`. Tor keeps its state under `<root>/tor`.
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
    /// `<root>/geoip-city.mmdb` in the background. `None` disables the map.
    pub geoip_gz: Option<Vec<u8>>,
    /// Optional file the node appends its log to (rotated by the caller).
    pub log_file: Option<PathBuf>,
    /// Node version string reported in `serverInfo`.
    pub version: String,
    /// Short git commit of this build, reported in `serverInfo.rev`.
    pub rev: String,
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
            rev: "0".to_string(),
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
    let data_dir = opts.data_root.join("data").join(&address);
    std::fs::create_dir_all(&data_dir).map_err(|e| format!("create data dir: {e}"))?;

    let trackers = vec![PeerAddr::parse(DEFAULT_TRACKER).unwrap()];
    let (content, bytes_recv) =
        clone_xite(&address, &data_dir, transport.clone(), &trackers).await?;

    let running = serve(opts, address, display, data_dir, content, bytes_recv).await?;
    Ok(running)
}

/// Pick the UI bind address: the requested one if its port is free, otherwise -
/// only when the requested port is Epix's default - fall back to the legacy
/// EpixNet port so a fresh Epix and an old EpixNet can run side by side and old
/// `127.0.0.1:43110` links still resolve. An explicitly chosen port is honored
/// as-is (serve reports the bind error if it's taken).
fn resolve_ui_bind(requested: std::net::SocketAddr) -> std::net::SocketAddr {
    resolve_ui_bind_with(requested, |addr| std::net::TcpListener::bind(addr).is_ok())
}

/// The bind decision, with the port-availability check injected so it can be
/// tested without touching real sockets.
fn resolve_ui_bind_with(
    requested: std::net::SocketAddr,
    free: impl Fn(std::net::SocketAddr) -> bool,
) -> std::net::SocketAddr {
    if free(requested) || requested.port() != DEFAULT_UI_PORT {
        return requested;
    }
    let fallback = std::net::SocketAddr::new(requested.ip(), LEGACY_UI_PORT);
    if free(fallback) {
        fallback
    } else {
        requested
    }
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
    clone_xite_with_progress(address, data_dir, transport, trackers, None)
        .await
        .map(|(content, bytes, _)| (content, bytes))
}

/// [`clone_xite`], pushing wrapper loading-screen events (`peers_added`,
/// `file_done` for content.json with the pending-file counts) to `progress`
/// as the clone advances - the on-demand path, where a browser is watching
/// the loading screen.
///
/// Discovery and download run concurrently: every tracker announce and the
/// DHT lookup stream discovered peers into a channel, content.json is raced
/// against the first peers to respond, and the file download starts the
/// moment content.json verifies - while discovery keeps feeding fresh peers
/// (and replacement workers) into the running download.
async fn clone_xite_with_progress(
    address: &str,
    data_dir: &std::path::Path,
    transport: Arc<dyn Transport>,
    trackers: &[PeerAddr],
    progress: Option<&Arc<AppState>>,
) -> Result<(Option<serde_json::Value>, u64, Vec<String>), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("create xite dir: {e}"))?;
    let mut xite = Xite::new(
        Address::parse(address.to_string()).map_err(|e| format!("bad address: {e}"))?,
        XiteStorage::new(data_dir),
    );

    let complete = xite.load_content().unwrap_or(false) && xite.files_needed().is_empty();
    if complete {
        return Ok((xite.content.clone(), 0, Vec::new()));
    }
    if let Some(state) = progress {
        // "Searching for peers..." on the loading screen.
        state.push_clone_event(address, serde_json::Value::Null, serde_json::json!({}));
    }

    // Discovery: one task per tracker plus a DHT lookup, all feeding a shared
    // channel as peers turn up (deduplicated at the source). The channel
    // closes when every discovery task is done.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PeerAddr>();
    let found = Arc::new(std::sync::Mutex::new(std::collections::HashSet::<String>::new()));
    for tracker in trackers.iter().cloned() {
        let tx = tx.clone();
        let found = found.clone();
        let address = address.to_string();
        let transport = transport.clone();
        let state = progress.cloned();
        tokio::spawn(async move {
            let peers = match &state {
                // Through the state so per-tracker stats record + push live
                // (the loading screen's tracker line).
                Some(s) => s.announce_to_trackers(&address, std::slice::from_ref(&tracker)).await,
                None => {
                    // Bootstrap clone with no state yet: passive query (no
                    // self-advertise), just fetch peers for the address.
                    epix_xite::announce(
                        transport.as_ref(),
                        &address,
                        std::slice::from_ref(&tracker),
                        &epix_xite::SelfAdvert::default(),
                    )
                    .await
                }
            };
            for p in peers {
                if found.lock().unwrap().insert(p.to_string()) {
                    let _ = tx.send(p);
                }
            }
        });
    }
    if let Some(state) = progress {
        // The DHT joins the search from the start (tracker-independent).
        let tx = tx.clone();
        let found = found.clone();
        let address = address.to_string();
        let state = state.clone();
        tokio::spawn(async move {
            for p in state.find_peers_dht(&address).await {
                if found.lock().unwrap().insert(p.to_string()) {
                    let _ = tx.send(p);
                }
            }
        });
    }
    // PEX: the first few discovered peers are asked for their peers too,
    // feeding the same channel - EpixNet ran peer exchange during the
    // download, and it reaches peers the trackers/DHT don't know.
    let pex_budget = Arc::new(std::sync::atomic::AtomicUsize::new(3));
    let spawn_pex = {
        let found = found.clone();
        let address = address.to_string();
        let transport = transport.clone();
        let budget = pex_budget.clone();
        move |peer: PeerAddr, tx: tokio::sync::mpsc::UnboundedSender<PeerAddr>| {
            use std::sync::atomic::Ordering;
            if budget
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |b| b.checked_sub(1))
                .is_err()
            {
                return;
            }
            let found = found.clone();
            let address = address.clone();
            let transport = transport.clone();
            tokio::spawn(async move {
                let reply = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    let mut conn = Connection::connect(transport.as_ref(), &peer).await.ok()?;
                    conn.handshake().await.ok()?;
                    conn.pex(&address, Vec::new(), Vec::new(), Vec::new(), Vec::new(), 10).await.ok()
                })
                .await
                .ok()
                .flatten();
                let Some(reply) = reply else { return };
                let unpacked = reply
                    .ipv4
                    .iter()
                    .chain(reply.ipv6.iter())
                    .filter_map(|b| PeerAddr::unpack_ip(b))
                    .chain(reply.onion.iter().filter_map(|b| PeerAddr::unpack_onion(b)))
                    .chain(reply.i2p.iter().filter_map(|b| PeerAddr::unpack_i2p(b)));
                for p in unpacked {
                    if found.lock().unwrap().insert(p.to_string()) {
                        let _ = tx.send(p);
                    }
                }
            });
        }
    };
    let pex_tx = tx.clone();
    drop(tx);

    // Phase 1: race the first peers for a verified content.json (unless it is
    // already on disk). Every discovered peer is also forwarded to the
    // download channel, so the file sync starts with them buffered.
    let (sync_tx, sync_rx) = tokio::sync::mpsc::unbounded_channel::<PeerAddr>();
    let mut peer_count = 0usize;
    if xite.content.is_none() {
        let mut fetchers: tokio::task::JoinSet<Option<Vec<u8>>> = tokio::task::JoinSet::new();
        let mut untried: std::collections::VecDeque<PeerAddr> = std::collections::VecDeque::new();
        let mut channel_open = true;
        let mut got_content = false;
        while !got_content {
            if !channel_open && fetchers.is_empty() && untried.is_empty() {
                break;
            }
            tokio::select! {
                maybe = tokio::time::timeout(
                    std::time::Duration::from_secs(60),
                    rx.recv(),
                ), if channel_open => {
                    match maybe {
                        // 60s with no newly discovered peer and still no
                        // content.json: stop waiting on discovery. A hung
                        // tracker/DHT task would otherwise keep this loop -
                        // and the registered-but-empty xite entry - alive
                        // forever. In-flight fetchers still drain (bounded).
                        Err(_) => channel_open = false,
                        Ok(None) => channel_open = false,
                        Ok(Some(peer)) => {
                            peer_count += 1;
                            if let Some(state) = progress {
                                state.push_clone_event(
                                    address,
                                    serde_json::json!(["peers_added", peer_count]),
                                    serde_json::json!({ "peers": peer_count }),
                                );
                            }
                            let _ = sync_tx.send(peer.clone());
                            if let Some(state) = progress {
                                state.add_peers(address, [peer.clone()]).await;
                            }
                            spawn_pex(peer.clone(), pex_tx.clone());
                            if fetchers.len() < 4 {
                                fetchers.spawn(fetch_content(
                                    transport.clone(),
                                    peer,
                                    address.to_string(),
                                ));
                            } else {
                                untried.push_back(peer);
                            }
                        }
                    }
                }
                Some(result) = fetchers.join_next(), if !fetchers.is_empty() => {
                    if let Ok(Some(bytes)) = result {
                        if xite.set_content(&bytes).is_ok() {
                            got_content = true;
                        }
                    }
                    if !got_content {
                        if let Some(peer) = untried.pop_front() {
                            fetchers.spawn(fetch_content(
                                transport.clone(),
                                peer,
                                address.to_string(),
                            ));
                        }
                    }
                }
                else => break,
            }
        }
        fetchers.abort_all();
        if !got_content {
            if peer_count == 0 {
                return Err("no peers found - is the network reachable?".into());
            }
            return Err("could not fetch + verify content.json from any peer".into());
        }
        if let Some(state) = progress {
            // The entry is registered (empty) during the clone: give it the
            // verified content right away so siteInfo/files are real.
            state.update_content(address, xite.content.clone()).await;
        }
        if let Some(state) = progress {
            let total = xite.files_needed().len();
            let counts = serde_json::json!({
                "peers": peer_count,
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
    // Keep forwarding late-discovered peers into the running download; the
    // sync channel closes when discovery finishes.
    {
        let sync_tx = sync_tx.clone();
        let state = progress.cloned();
        let address = address.to_string();
        let mut count = peer_count;
        let spawn_pex = spawn_pex.clone();
        let pex_tx = pex_tx.clone();
        tokio::spawn(async move {
            while let Some(peer) = rx.recv().await {
                count += 1;
                if let Some(state) = &state {
                    state.add_peers(&address, [peer.clone()]).await;
                    state.push_clone_event(
                        &address,
                        serde_json::json!(["peers_added", count]),
                        serde_json::json!({ "peers": count }),
                    );
                }
                spawn_pex(peer.clone(), pex_tx.clone());
                let _ = sync_tx.send(peer);
            }
            drop(pex_tx);
        });
    }
    drop(pex_tx);
    drop(sync_tx);

    // Per-file progress: each finished file prints its line on the loading
    // screen and advances the progress bar (tasks/started_task_num).
    let on_file = progress.map(|state| {
        let state = state.clone();
        let addr = address.to_string();
        let peers_n = peer_count.max(1);
        Arc::new(move |inner: &str, done: usize, total: usize| {
            let left = total.saturating_sub(done);
            // The wrapper hides the loading screen on index.html's file_done
            // - and index.html downloads FIRST (priority queue). Firing it
            // mid-sync dropped the user into a half-downloaded site (styles
            // and scripts still missing, forum data not even started), which
            // reads as broken. Hold it back unless it is the last core file;
            // the pass below pushes it when the core set is complete.
            if inner == "index.html" && left > 0 {
                return;
            }
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
        epix_worker::sync_files_streaming(&xite, sync_rx, transport.clone(), 8, on_file).await
    {
        bytes_recv = report.bytes;
    }
    // Core set done: NOW dismiss the loading screen. The site opens fully
    // styled, and the user-content pass below streams topics/posts into the
    // already-rendered page (db ingest + file_done per file).
    if let Some(state) = progress {
        state.push_clone_event(
            address,
            serde_json::json!(["file_done", "index.html"]),
            serde_json::json!({ "peers": peer_count.max(1), "bad_files": 0, "tasks": 0 }),
        );
    }

    // Recursive content: user_contents sites (EpixTalk, EpixPost, ...) keep their
    // real data (topics, comments) in INCLUDED and per-user content.json files
    // that the root's `files` map never lists. Fetch those content.json files
    // and their data files so the site's db can populate.
    let peers = state_peers(progress, &xite, address).await;
    let mut user_files = Vec::new();
    if !peers.is_empty() {
        let (bytes, files) =
            sync_included_content(&xite, &peers, transport.clone(), progress, address).await;
        bytes_recv += bytes;
        user_files = files;
    }
    Ok((xite.content.clone(), bytes_recv, user_files))
}

/// The peer set to use for the included-content pass: the live registry when a
/// state is present (accumulated during discovery), else empty.
async fn state_peers(progress: Option<&Arc<AppState>>, _xite: &Xite, address: &str) -> Vec<PeerAddr> {
    match progress {
        Some(state) => state.connectable_peers(address, 20).await,
        None => Vec::new(),
    }
}

/// Download every included / per-user content.json (and the data files they
/// declare) for a user_contents site, parent-first so each verifies against
/// its parent's rules. Returns the bytes downloaded and the inner paths of
/// the files that arrived from peers (for `file_done` events after the db
/// rebuild).
async fn sync_included_content(
    xite: &Xite,
    peers: &[PeerAddr],
    transport: Arc<dyn Transport>,
    progress: Option<&Arc<AppState>>,
    address: &str,
) -> (u64, Vec<String>) {
    use std::collections::HashSet;
    // Enumerate content.json paths: the root's includes, plus everything a peer
    // advertises via listModified (this is how per-user content.json files -
    // never listed statically - are discovered).
    // Paths to consider, with the peer-advertised modified time when known
    // (0.0 = statically included, always checked).
    let mut paths: std::collections::HashMap<String, f64> =
        xite.includes().into_iter().map(|p| (p, 0.0)).collect();
    // Also every content.json already on disk (per-user ones from earlier
    // passes): their declared data files may still be missing, and when the
    // listModified race below comes up empty they would otherwise never be
    // visited - a hub with all its user content.json but none of the
    // data.json (the actual posts) stays that way forever.
    for p in walk_disk_content_json(xite.storage().root()) {
        paths.entry(p).or_insert(0.0);
    }
    // Race listModified across the first several peers concurrently and take
    // the first non-empty answer, so one slow/dead peer can't stall the pass.
    let mut probes = tokio::task::JoinSet::new();
    for peer in peers.iter().take(8).cloned() {
        let transport = transport.clone();
        let address = address.to_string();
        probes.spawn(async move {
            let list = fetch_list_modified(transport.as_ref(), &peer, &address).await;
            (peer, list)
        });
    }
    let mut live_peer: Option<PeerAddr> = None;
    while let Some(res) = probes.join_next().await {
        if let Ok((peer, Some(list))) = res {
            if live_peer.is_none() {
                live_peer = Some(peer.clone());
            }
            if !list.is_empty() {
                live_peer = Some(peer);
                for (p, modified) in list {
                    if p.ends_with("content.json") && p != "content.json" {
                        let entry = paths.entry(p).or_insert(0.0);
                        if modified > *entry {
                            *entry = modified;
                        }
                    }
                }
                break;
            }
        }
    }
    probes.abort_all();
    // The peer that answered goes FIRST: every fetch below races peers in
    // groups from the front of this list, so a front full of dead peers costs
    // a full timeout per group per file. One known-live peer up front means
    // each file lands on the first try.
    let mut peers: Vec<PeerAddr> = peers.to_vec();
    if let Some(lp) = &live_peer {
        if let Some(pos) = peers.iter().position(|p| p.to_string() == lp.to_string()) {
            let p = peers.remove(pos);
            peers.insert(0, p);
        }
    }
    let peers = &peers[..];
    if paths.is_empty() {
        return (0, Vec::new());
    }
    // Parent-first: shallower paths (data/users/content.json) before deeper
    // ones (data/users/mud.epix/content.json), so each verifies against its parent.
    let mut ordered: Vec<(String, f64)> = paths.into_iter().collect();
    ordered.sort_by_key(|(p, _)| p.matches('/').count());

    // Pre-warm the xID resolver cache: resolve every user's linked signers
    // concurrently up front. The verification loop below then hits the warm
    // cache instead of making one blocking chain call per user in sequence -
    // over a phone's slow TLS that serialized 15+ resolves into minutes,
    // which is why EpixTalk/EpixPost content took so long to appear on iOS.
    let mut warm = tokio::task::JoinSet::new();
    for (path, _) in &ordered {
        if let Some(name) = user_dir_name(path) {
            if name.contains('.') {
                let name = name.to_string();
                warm.spawn(async move {
                    let (label, tld) = name.rsplit_once('.').unwrap_or((&name, "epix"));
                    epix_chain::xid_signers::resolve(label, tld).await;
                });
            }
        }
    }
    while warm.join_next().await.is_some() {}

    let mut child_files: Vec<epix_xite::FileEntry> = Vec::new();
    let mut arrived: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    // Process content.json one depth level at a time: a level's files are
    // fetched together (the slow network I/O), then verified sequentially
    // (add_content is CPU-only and needs the parent level's rules registered
    // first). Shallower paths - data/users/content.json, whose user_contents
    // rules the per-user files verify against - are their own earlier level,
    // so they always land before the children that need them.
    //
    // The fetch itself is a worker pass over PERSISTENT connections
    // (fetch_files_raw): one connect per peer for the whole level, files
    // pulled from a shared queue. Opening a fresh connection per file per
    // peer burned a full timeout on every dead peer - and on seeders that
    // limit concurrent handshakes - which serialized a fresh clone's posts
    // into minutes of nothing.
    let mut pending: std::collections::BTreeMap<usize, Vec<(String, f64)>> =
        std::collections::BTreeMap::new();
    for (p, m) in ordered {
        pending.entry(p.matches('/').count()).or_default().push((p, m));
    }
    while let Some((_, level)) = pending.pop_first() {
        let mut fetched: Vec<(String, Vec<u8>, bool)> = Vec::new();
        let mut to_fetch: Vec<(String, Option<Vec<u8>>)> = Vec::new();
        for (path, peer_modified) in level {
            if !seen.insert(path.clone()) {
                continue;
            }
            let disk = xite.storage().read(&path).ok();
            let disk_modified = disk
                .as_deref()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                .and_then(|j| j.get("modified").and_then(|v| v.as_f64()))
                .unwrap_or(-1.0);
            match disk {
                // The on-disk copy serves unless a peer advertises a newer
                // version (new posts); add_content re-verifies either way.
                Some(d) if peer_modified <= disk_modified => fetched.push((path, d, false)),
                disk => to_fetch.push((path, disk)),
            }
        }
        if !to_fetch.is_empty() {
            let mut results = epix_worker::fetch_files_raw(
                to_fetch.iter().map(|(p, _)| p.clone()).collect(),
                address,
                peers,
                transport.clone(),
                8,
            )
            .await;
            for (path, disk) in to_fetch {
                match results.remove(&path) {
                    Some(bytes) => fetched.push((path, bytes, true)),
                    // Unfetchable: fall back to the (stale) disk copy if any.
                    None => {
                        if let Some(d) = disk {
                            fetched.push((path, d, false));
                        }
                    }
                }
            }
        }
        for (path, bytes, was_fetched) in fetched {
            let xid_map = resolve_user_signers(&xite, &path).await; // warm cache: cheap
            match xite.add_content(&path, &bytes, &xid_map) {
                Ok(files) => {
                    if was_fetched {
                        arrived.push(path.clone());
                        // Ingest + file_done NOW (EpixNet fires these as each
                        // file is written): a user's content.json carries db
                        // columns (cert_user_id), and the event makes open
                        // pages re-query instead of waiting out the pass.
                        if let Some(state) = progress {
                            state.ingest_file(address, &path).await;
                        }
                    }
                    child_files.extend(files);
                    // A nested include lands in its own (deeper) level.
                    for inc in xite.child_includes(&path) {
                        if !seen.contains(&inc) {
                            pending.entry(inc.matches('/').count()).or_default().push((inc, 0.0));
                        }
                    }
                }
                Err(e) => {
                    if let Some(state) = progress {
                        state.log("WARNING", format!("Skipped {path}: {e}")).await;
                    }
                }
            }
        }
    }
    // Download the declared data files that aren't already present.
    let needed: Vec<_> = child_files
        .into_iter()
        .filter(|f| !xite.storage().verify(&f.inner_path, &f.sha512))
        .collect();
    if needed.is_empty() {
        return (0, arrived);
    }
    if let Some(state) = progress {
        state
            .log("INFO", format!("Fetching {} user-content file(s) for {address}", needed.len()))
            .await;
    }
    let needed_paths: Vec<String> = needed.iter().map(|f| f.inner_path.clone()).collect();
    // Each data file is ingested into the site's db (and its mergers') the
    // moment it verifies, with its file_done pushed right after - this is
    // what makes topics/posts appear one by one while the sync is running.
    let on_file = progress.map(|state| {
        let state = state.clone();
        let addr = address.to_string();
        Arc::new(move |inner: &str, _done: usize, _total: usize| {
            let state = state.clone();
            let addr = addr.clone();
            let inner = inner.to_string();
            tokio::spawn(async move {
                state.ingest_file(&addr, &inner).await;
            });
        }) as epix_worker::FileProgress
    });
    match epix_worker::sync_files_list(needed, xite, peers, transport, 8, on_file).await {
        Ok(report) => {
            // Report only the files that actually landed - a partial sync
            // (dead peers) must not fire file_done for missing files.
            arrived.extend(
                needed_paths.into_iter().filter(|p| xite.storage().exists(p)),
            );
            (report.bytes, arrived)
        }
        Err(_) => (0, arrived),
    }
}

/// Every non-root `content.json` under `root` (per-user / included content
/// already on disk), as inner paths.
fn walk_disk_content_json(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|n| n.to_str()) == Some("content.json") {
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    if rel != "content.json" {
                        out.push(rel);
                    }
                }
            }
        }
    }
    out
}

/// The user-directory name in `data/users/<name>/content.json`, if the path has
/// that shape (else `None`).
fn user_dir_name(inner_path: &str) -> Option<&str> {
    let parts: Vec<&str> = inner_path.split('/').collect();
    if parts.len() >= 3 && parts[0] == "data" && parts[1] == "users" {
        Some(parts[2])
    } else {
        None
    }
}

/// Resolve every xID name that verifying `inner_path` may need to the chain
/// addresses allowed to sign it: the user directory's own name (EpixTalk
/// stores each user's posts under their xID and signs with the identity that
/// xID belongs to) plus any name-form signers the parent's `user_contents`
/// rules grant (site admins, for moderation). Resolution is chain-verified
/// (Merkle proof) and cached.
async fn resolve_user_signers(
    xite: &Xite,
    inner_path: &str,
) -> std::collections::HashMap<String, Vec<String>> {
    let mut map = std::collections::HashMap::new();
    let parent_path = epix_content::verify::parent_content_path(inner_path);
    let parent = xite
        .storage()
        .read(&parent_path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .unwrap_or_else(|| serde_json::json!({ "inner_path": parent_path }));
    for name in epix_content::verify::user_content_xid_names(&parent, inner_path) {
        let (label, tld) = name.rsplit_once('.').unwrap_or((name.as_str(), "epix"));
        let signers = epix_chain::xid_signers::resolve(label, tld).await;
        if !signers.is_empty() {
            map.insert(name, signers);
        }
    }
    map
}

/// Ask a peer for its list of modified files (`listModified` since 0): the
/// inner_paths of every content.json it serves, including per-user ones.
async fn fetch_list_modified(
    transport: &dyn Transport,
    peer: &PeerAddr,
    address: &str,
) -> Option<Vec<(String, f64)>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut conn = Connection::connect(transport, peer).await.ok()?;
        conn.handshake().await.ok()?;
        let reply = conn.list_modified(address, 0.0).await.ok()?;
        let map = epix_protocol::vget(&reply, "modified_files")?.as_map()?;
        Some(
            map.iter()
                .filter_map(|(k, v)| {
                    let path = k.as_str()?.to_string();
                    let modified = v.as_f64().or_else(|| v.as_i64().map(|n| n as f64))?;
                    Some((path, modified))
                })
                .collect::<Vec<_>>(),
        )
    })
    .await
    .ok()
    .flatten()
}

/// One bounded attempt to pull content.json from a peer (phase 1 of a clone).
async fn fetch_content(
    transport: Arc<dyn Transport>,
    peer: PeerAddr,
    address: String,
) -> Option<Vec<u8>> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut conn = Connection::connect(transport.as_ref(), &peer).await.ok()?;
        conn.handshake().await.ok()?;
        conn.get_file(&address, "content.json").await.ok()
    })
    .await
    .ok()
    .flatten()
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

#[async_trait::async_trait]
impl epix_ui::ContentSyncer for OnDemand {
    async fn sync_user_content(&self, address: &str) -> (u64, Vec<String>) {
        let dir = self.data_root.join("data").join(address);
        let Ok(addr) = Address::parse(address.to_string()) else { return (0, Vec::new()) };
        let mut xite = Xite::new(addr, XiteStorage::new(dir));
        // Only user_contents sites (with includes) have out-of-tree content.
        if !xite.load_content().unwrap_or(false) || xite.includes().is_empty() {
            return (0, Vec::new());
        }
        let mut peers = self.state.connectable_peers(address, 20).await;
        if peers.is_empty() {
            // A rarely-visited site may have no warm peers yet: announce for
            // some, then fall back to the DHT.
            peers = self.state.announce_to_trackers(address, &self.trackers).await;
            if peers.is_empty() {
                peers = self.state.find_peers_dht(address).await;
            }
        }
        if peers.is_empty() {
            return (0, Vec::new());
        }
        sync_included_content(
            &xite,
            &peers,
            self.transport.clone(),
            Some(&self.state),
            address,
        )
        .await
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

        let data_dir = self.data_root.join("data").join(&address);
        // If we already serve the raw address, just alias the name to it.
        if !self.state.has_xite(&address).await {
            // Register the xite empty BEFORE the download (EpixNet's
            // SiteManager.need): siteInfo/dbQuery/permissions are real for the
            // page the moment it renders progressively, peers accumulate on
            // the live entry, and the dashboard shows the row mid-clone.
            self.state
                .add_xite(
                    &address,
                    XiteEntry { storage: XiteStorage::new(&data_dir), content: None },
                )
                .await;
            if host != address {
                self.state.set_display(&address, host).await;
            }
            let cloned = clone_xite_with_progress(
                &address,
                &data_dir,
                self.transport.clone(),
                &self.trackers,
                Some(&self.state),
            )
            .await;
            let (content, bytes, user_files) = match cloned {
                Ok(r) => r,
                Err(e) => {
                    // Tell the loading screen ("index.html download failed",
                    // "No peers found" when none), and unregister the failed
                    // clone so a revisit starts fresh.
                    self.state.push_clone_event(
                        &address,
                        serde_json::json!(["file_failed", "index.html"]),
                        serde_json::json!({}),
                    );
                    self.state.remove_xite(&address).await;
                    return Err(e);
                }
            };
            self.state.update_content(&address, content.clone()).await;
            self.state.add_transfer(&address, bytes, 0).await;
            // Rebuild the db now that the included / per-user data files are on
            // disk, so a user_contents site's topics/comments are queryable.
            self.state.rebuild_xite_db(&address).await;
            // A merged site (e.g. a Git Epix repo) also feeds its merger's db.
            if content.as_ref().and_then(|c| c.get("merged_type")).is_some() {
                self.state.rebuild_merger_dbs().await;
            }
            self.state.push_site_info(&address).await;
            // file_done per user-content file already fired as each file
            // landed (ingest_file), with the db updated first - the page,
            // served progressively, re-queried and showed each one live.
            //
            // A complete-on-disk core short-circuits the clone WITHOUT the
            // user-content pass - but "core complete" says nothing about the
            // per-user files. An interrupted earlier clone (crash, restart)
            // leaves exactly that state, and waiting for the next resync tick
            // (minutes) shows a working page with an empty forum. Backfill in
            // the background right away; it is one listModified when nothing
            // is missing.
            if bytes == 0 && user_files.is_empty() {
                let state = self.state.clone();
                let address = address.clone();
                tokio::spawn(async move {
                    state.sync_user_content(&address).await;
                });
            }
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
    let state = AppState::with_data_dir(&opts.version, &opts.data_root);
    state.set_rev(&opts.rev).await;
    if let Some(log_file) = &opts.log_file {
        state.set_log_file(log_file);
    }
    // The Config page's "Data directory" works only when the root is the
    // user-relocatable desktop one (not pinned by EPIX_DATA_DIR or set
    // programmatically by an embedding shell). The choice persists as
    // `data_dir` in the default location's epixnet.conf, Python-style.
    let env_pinned = std::env::var("EPIX_DATA_DIR").map(|v| !v.is_empty()).unwrap_or(false);
    if !env_pinned && opts.data_root == epix_ui::paths::data_root() {
        state.set_data_dir_conf(epix_ui::paths::default_data_root().join("epixnet.conf"));
    }

    // Expand the GeoIP db off the startup path (first run unzips ~62MB).
    if let Some(gz) = opts.geoip_gz.clone() {
        let state = state.clone();
        let mmdb = opts.data_root.join("geoip-city.mmdb");
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

    // Xite dbs are in-memory, so merger databases (Git Epix, Epix Post) are
    // empty on every boot until filled from their merged sites - do it now
    // that all restored xites are registered, or merger pages show nothing
    // until some merger action happens to trigger a rebuild.
    state.rebuild_merger_dbs().await;

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
    let on_demand = Arc::new(OnDemand {
        state: state.clone(),
        data_root: opts.data_root.clone(),
        transport: transport.clone(),
        trackers: trackers.clone(),
        in_flight: tokio::sync::Mutex::new(std::collections::HashSet::new()),
    });
    state.set_on_demand(on_demand.clone()).await;
    // The same component syncs included/user content for existing sites
    // (called by the resync loop, so EpixTalk-style posts stay fresh).
    state.set_content_syncer(on_demand).await;

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

    // Privacy by default: turn the embedded I2P router on the first time a node
    // runs with no explicit `i2p` choice (persisted so the Config page shows it
    // selected, and an explicit Disable is never overridden). On both desktop
    // and mobile - the router is a no-transit leaf, so its cost is Tor-like.
    // Gated on `i2p-autostart`; offline mode stays off.
    #[cfg(feature = "i2p-autostart")]
    if !offline && state.config_get("i2p").await.is_none() {
        state.config_set("i2p", serde_json::json!("embedded")).await;
    }

    // I2P config from the node config (Config page): mode + external SAM port.
    #[cfg(feature = "i2p")]
    let (i2p_mode, i2p_sam_port) = {
        let mode = if offline {
            "disable".to_string()
        } else {
            state
                .config_get("i2p")
                .await
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "disable".to_string())
        };
        let port = state
            .config_get("i2p_sam_port")
            .await
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(7656) as u16;
        (mode, port)
    };

    let runtime_config = epix_runtime::RuntimeConfig {
        fileserver_port: if offline { None } else { fileserver_port },
        offline,
        #[cfg(feature = "tor")]
        tor_mode,
        #[cfg(feature = "tor")]
        tor_socks_port: Some(43111),
        #[cfg(feature = "i2p")]
        i2p_mode,
        #[cfg(feature = "i2p")]
        i2p_sam_port,
        ..Default::default()
    };
    let mut runtime =
        epix_runtime::NodeRuntime::with_config(state.clone(), trackers, runtime_config);
    #[cfg(any(feature = "tor", feature = "i2p"))]
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
    plugins.register(Arc::new(epix_plugins::BeaconPlugin));
    let mut plugin_names: Vec<String> = plugins.names().iter().map(|s| s.to_string()).collect();
    plugin_names.extend(epix_ui::builtin_plugins().into_iter().map(String::from));
    plugin_names.sort();
    plugin_names.dedup();
    state.set_plugins(plugin_names).await;
    plugins.start_all(&state);

    let requested: std::net::SocketAddr = opts
        .ui_addr
        .parse()
        .map_err(|_| format!("invalid ui_addr '{}'", opts.ui_addr))?;
    let bind = resolve_ui_bind(requested);
    if bind.port() != requested.port() {
        state
            .log("INFO", format!("UI port {} in use; using {}", requested.port(), bind.port()))
            .await;
    }
    state.set_ui_port(bind.port()).await;
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
    fn ui_bind_prefers_default_and_falls_back_to_legacy() {
        let addr = |p: u16| std::net::SocketAddr::from(([127, 0, 0, 1], p));

        // Default port free -> use it.
        assert_eq!(resolve_ui_bind_with(addr(DEFAULT_UI_PORT), |_| true), addr(DEFAULT_UI_PORT));

        // Default port taken -> fall back to the legacy EpixNet port.
        let taken_default = |a: std::net::SocketAddr| a.port() != DEFAULT_UI_PORT;
        assert_eq!(resolve_ui_bind_with(addr(DEFAULT_UI_PORT), taken_default), addr(LEGACY_UI_PORT));

        // Default and legacy both taken -> keep the default (serve reports it).
        assert_eq!(resolve_ui_bind_with(addr(DEFAULT_UI_PORT), |_| false), addr(DEFAULT_UI_PORT));

        // An explicitly chosen (non-default) port is honored even if taken -
        // no surprise jump to 43110.
        assert_eq!(resolve_ui_bind_with(addr(9999), |_| false), addr(9999));
    }

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

/// The shared data root: `EPIX_DATA_DIR` if set, else the `data_dir`
/// configured in the default location's `epixnet.conf`, else the conventional
/// per-OS application-data location (`~/Library/Application Support/EpixNet`
/// on macOS, `%APPDATA%\EpixNet` on Windows, `$XDG_DATA_HOME/EpixNet` or
/// `~/.local/share/EpixNet` on Linux). Shared by the server binary and the
/// desktop browser so they use one identity, site set, and Tor state.
pub fn data_root() -> PathBuf {
    epix_ui::paths::data_root()
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
