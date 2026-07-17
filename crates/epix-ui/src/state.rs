//! Shared server state: the xites this node serves (with their runtime
//! settings + stats), the local user identity, and node metadata.

use epix_core::{Address, PeerAddr};
use epix_db::{Database, DbSchema};
use epix_peer::{DialableNets, Peer, PeerCounts, Peers};
use epix_protocol::Connection;
use epix_transport::Transport;
use epix_user::User;
use epix_xite::{content_stats, FileEntry, Xite, XiteSettings, XiteStorage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Default per-xite size limit, in MB. The Epix python client raised its
/// `--size-limit` default from EpixNet's 10 to 1000; a growing xite stops
/// syncing at this cap until the user raises it, so the old 10 broke any
/// site past 10 MB out of the box.
pub const DEFAULT_SIZE_LIMIT_MB: i64 = 1000;

/// Resolves + clones a `.epix` host that isn't served yet, so the browser can
/// open any name by typing it. Implemented by the node (which has the chain
/// resolver + download worker); the UI server calls it via
/// [`AppState::ensure_xite`]. Kept as a trait so `epix-ui` has no dependency on
/// the chain/worker crates.
#[async_trait::async_trait]
pub trait OnDemandResolver: Send + Sync {
    /// Resolve + clone `host` and add it as a served xite. `Ok(())` once served.
    async fn ensure(&self, host: &str) -> Result<(), String>;

    /// Resolve `host` (a `.epix` name or an address) to a xite address WITHOUT
    /// cloning: the on-disk cache first, the chain on a miss. Used so a
    /// locked-down node can still follow an xID to a xite it already serves.
    async fn resolve(&self, host: &str) -> Option<String>;
}

/// Extra peer discovery beyond the trackers - the runtime installs a DHT
/// lookup here so announces and on-demand clones can find peers for rare
/// sites when the trackers come up short. Kept as a trait so `epix-ui` has
/// no dependency on the DHT crates.
#[async_trait::async_trait]
pub trait PeerFinder: Send + Sync {
    /// Find peers hosting the xite at `address` (bech32).
    async fn find(&self, address: &str) -> Vec<PeerAddr>;
}

/// Fetch a xite's included / per-user content (user_contents sites keep their
/// data - topics, posts - outside the root's file list). Implemented by the
/// node (it has the chain resolver for user xIDs); the resync loop calls it so
/// existing sites pick up new and backfilled user content.
#[async_trait::async_trait]
pub trait ContentSyncer: Send + Sync {
    /// Sync `address`'s included/user content; returns bytes downloaded and
    /// the inner paths of the files that arrived (for `file_done` events).
    async fn sync_user_content(&self, address: &str) -> (u64, Vec<String>);
}

/// One file's state during an on-demand clone (progressive serve).
pub enum LoadingFile {
    /// Verified bytes are on disk - serve them now.
    Ready(Vec<u8>),
    /// Expected but not downloaded yet - keep waiting.
    Pending,
    /// content.json is here and doesn't list this file - 404.
    NotInSite,
}

/// Plugins that ship disabled by default, matching the plugins EpixNet keeps
/// `disabled-` (that we have): they are off until the operator turns them on.
const DEFAULT_DISABLED_PLUGINS: &[&str] = &["NoNewSites", "UiPassword", "Multiuser"];

/// Whether a plugin is off unless explicitly enabled.
fn is_default_disabled(name: &str) -> bool {
    DEFAULT_DISABLED_PLUGINS.contains(&name)
}

/// Severity rank of a log level, for the `log_level` minimum-level filter.
/// Unknown levels rank as INFO so they aren't silently dropped.
fn log_rank(level: &str) -> u8 {
    match level.to_ascii_uppercase().as_str() {
        "DEBUG" => 0,
        "INFO" => 1,
        "WARN" | "WARNING" => 2,
        "ERROR" => 3,
        _ => 1,
    }
}

/// A plugin's effective enabled state: an explicit override wins, else the
/// default (on, except for the default-disabled set).
fn effective_enabled(name: &str, disabled: &[String], enabled: &[String]) -> bool {
    if disabled.iter().any(|n| n == name) {
        return false;
    }
    if enabled.iter().any(|n| n == name) {
        return true;
    }
    !is_default_disabled(name)
}

/// How many warm peer connections the node keeps for live connection stats.
const CONNECTION_POOL_MAX: usize = 8;

/// Editable node config keys shown on the Config page:
/// `(section, key, label, default, kind)`, grouped into the same sections
/// EpixNet's Config page uses (Web Interface / Network / Performance / Epix
/// Chain Config). `kind` drives the input widget:
///   - `"text"` / `"textarea"` - free text
///   - `"bool"` - checkbox
///   - `"select:Label=value|Label2=value2"` - dropdown (label defaults to value
///     when there's no `=`)
///   - `"button:actionName"` - an action button (not a stored config key)
///   - `"soon:<inner>"` - render `<inner>` disabled with a "coming soon" note,
///     for keys whose backend (Tor transport, SOCKS proxy) isn't built yet.
pub const CONFIG_SCHEMA: &[(&str, &str, &str, &str, &str)] = &[
    // --- Web Interface
    ("Web Interface", "open_browser", "Open web browser on EpixNet startup", "true", "bool"),
    ("Web Interface", "language", "Interface language", "en", "text"),
    // --- Network
    ("Network", "offline", "Offline mode", "false", "bool"),
    (
        "Network",
        "fileserver_ip_type",
        "File server network",
        "ipv4",
        "select:IPv4=ipv4|IPv6=ipv6|Dual (IPv4 & IPv6)=dual",
    ),
    ("Network", "fileserver_port", "File server port (0 to disable seeding)", "26552", "text"),
    ("Network", "ip_external", "File server external ip (blank = auto-detect via UPnP)", "", "textarea"),
    (
        "Network",
        "tor",
        "Tor (Always routes all peer traffic through Tor; restart EpixNet to apply)",
        "enable",
        "select:Disable=disable|Enable=enable|Always=always",
    ),
    ("Network", "tor_use_bridges", "Use Tor bridges", "false", "soon:bool"),
    (
        "Network",
        "i2p",
        "I2P (reach and host peers over I2P; the embedded router boots in the background)",
        "disable",
        "select:Disable=disable|Embedded router=embedded|External router=external",
    ),
    (
        "Network",
        "i2p_sam_port",
        "I2P external router SAM port (only used with External)",
        "7656",
        "text",
    ),
    (
        "Network",
        "mesh",
        "Reticulum mesh (reach and host peers over mesh links)",
        "disable",
        "select:Disable=disable|Enable=enable",
    ),
    (
        "Network",
        "mesh_peers",
        "Mesh TCP interfaces to join (host:port, one per line)",
        "",
        "textarea",
    ),
    (
        "Network",
        "mesh_listen",
        "Mesh TCP listen address (blank = do not accept mesh links over IP)",
        "",
        "text",
    ),
    ("Network", "trackers", "Trackers", "145.223.69.23:26959", "textarea"),
    ("Network", "trackers_file", "Trackers files (one path per line)", "", "textarea"),
    (
        "Network",
        "trackers_xite",
        "Announcer list xite (optional: <address>/<inner path> of a published tracker list)",
        "",
        "text",
    ),
    (
        "Network",
        "trackers_proxy",
        "Proxy for tracker connections",
        "disable",
        "soon:select:Custom=custom|Tor=tor|Disable=disable",
    ),
    (
        "Network",
        "tracker",
        "Act as a tracker (answer other nodes' announces, incl. onion/i2p peers)",
        "enable",
        "select:Enable=enable|Disable=disable",
    ),
    // --- Storage. `data_dir` is special: the value is the live data root and
    // the setting persists to `epixnet.conf` (see `AppState::set_data_dir`),
    // not config.json - config.json lives inside the directory it would name.
    (
        "Storage",
        "data_dir",
        "Data directory (existing data is copied there; restart EpixNet to apply)",
        "",
        "text",
    ),
    // --- Performance
    (
        "Performance",
        "log_level",
        "Level of logging to file",
        "INFO",
        "select:Everything=DEBUG|Only important messages=INFO|Only errors=ERROR",
    ),
    // --- Epix Chain Config
    ("Epix Chain Config", "chain_rpc_url", "Chain RPC URL", "https://api.epix.zone", "text"),
    ("Epix Chain Config", "chain_evm_rpc_url", "Chain EVM RPC URL", "https://evmrpc.epix.zone", "text"),
    ("Epix Chain Config", "chain_block_explorer_url", "Block Explorer URL", "https://scan.epix.zone", "text"),
    ("Epix Chain Config", "xid_clear_cache", "Clear xID Cache", "", "button:xidClearCache"),
];

/// True for schema entries that aren't stored config keys (action buttons), so
/// `configList` / save loops can skip them.
pub fn is_config_action(kind: &str) -> bool {
    kind.starts_with("button:")
}

/// Config keys the node only reads while booting - changing one takes effect
/// on the next start. The Config page offers a restart when one of these has
/// changed since boot (`data_dir` is tracked separately off epixnet.conf).
pub const CONFIG_RESTART_KEYS: &[&str] = &[
    "offline",
    "fileserver_ip_type",
    "fileserver_port",
    "tor",
    "i2p",
    "i2p_sam_port",
    "mesh",
    "mesh_peers",
    "mesh_listen",
    "trackers",
];

/// A config value normalized for change comparison: strings trimmed, bools and
/// numbers in their canonical text form (config.json written by the Python
/// client holds real numbers/bools where the Config page saves strings).
fn config_value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.trim().to_string(),
        other => other.to_string(),
    }
}

/// The input to [`AppState::add_xite`]: a xite's storage and (if loaded) its
/// verified content.json. Settings/stats are derived from these.
pub struct XiteEntry {
    pub storage: XiteStorage,
    pub content: Option<Value>,
}

/// A served xite with its derived runtime state.
struct ManagedXite {
    storage: XiteStorage,
    content: Option<Value>,
    settings: XiteSettings,
    /// The human-readable `.epix` name (xID) this xite was resolved from, if
    /// any. Display metadata only - the map is keyed by the bech32 address and
    /// every command references the address; names are translated at the
    /// HTTP/WS edges.
    display: Option<String>,
    /// Per-xite database (built from dbschema.json), if the xite has one.
    db: Option<Database>,
    /// The parsed dbschema (kept for merger-db rebuilds).
    db_schema: Option<DbSchema>,
    /// Known peers (from discovery/PEX/DHT/announces).
    peers: Peers,
    /// Total bytes transferred for this xite this run.
    bytes_recv: u64,
    bytes_sent: u64,
    /// Live worker accounting.
    tasks_active: usize,
    started_task_num: usize,
    workers: usize,
    /// Optional files the user pinned (kept even when clearing space).
    pinned: std::collections::HashSet<String>,
    /// Which optional-file hash ids we hold (`getHashfield`), maintained as
    /// optional files are downloaded/pushed/deleted.
    hashfield: epix_xite::Hashfield,
    /// Optional-file hash ids each known peer advertises (`setHashfield`), so
    /// `findHashIds` can point a downloader at peers holding a rare file.
    /// Keyed by peer address string.
    peer_hashfields: HashMap<String, epix_xite::Hashfield>,
}

/// A verified root content.json waiting for its files: the signature checked
/// out but some declared files could not be fetched yet, so it was NOT
/// committed to disk and the node keeps serving the previous version. Only the
/// small signed JSON value + its exact bytes are held - file data is always
/// verified per-file and written to disk as it arrives.
struct PendingUpdate {
    /// Every served key the commit applies to (raw address + `.epix` aliases).
    keys: Vec<String>,
    /// The verified content.json.
    content: Value,
    /// The exact signed bytes to commit (atomically) once the files land.
    bytes: Vec<u8>,
    /// Retry passes attempted so far, driving the decaying retry probability.
    tries: i64,
}

/// EpixNet's bad-file backoff (`random.randint(0, min(40, tries)) < 4`): the
/// first few passes always retry, then the chance decays to ~10% per tick so a
/// file nobody serves doesn't burn bandwidth forever.
fn retry_pending_allowed(tries: i64) -> bool {
    let bound = tries.clamp(0, 40) as u8;
    let mut b = [0u8; 1];
    if getrandom::fill(&mut b).is_err() {
        return true;
    }
    (b[0] % (bound + 1)) < 4
}

/// Server-wide state shared across all HTTP/WebSocket handlers.
pub struct AppState {
    pub version: String,
    /// Short git commit of this build, reported in `serverInfo.rev` (the
    /// dashboard shows it next to the version). Set by the binary after boot.
    rev: RwLock<String>,
    /// The UI port actually bound (default 42222, or 43110 fallback), reported
    /// in `serverInfo.ui_port` so the dashboard builds correct links.
    ui_port: RwLock<u16>,
    xites: RwLock<HashMap<String, ManagedXite>>,
    user: RwLock<User>,
    user_path: Option<PathBuf>,
    nonce_counter: AtomicU64,
    /// ContentFilter store: `{ "mutes": {auth_address: {...}}, "siteblocks": {site: {...}} }`.
    filters: RwLock<Value>,
    filters_path: Option<PathBuf>,
    /// Transport used to publish updates to peers (set by the node). This is
    /// the composed transport actually dialed with: the base (TCP, or Tor's
    /// MixedTransport) with I2P dispatch layered on when I2P is up.
    transport: RwLock<Option<Arc<dyn Transport>>>,
    /// The raw base transport (TCP / Tor mixed), kept so I2P can be composed in
    /// or out without the base overwriting it and vice versa.
    base_transport: RwLock<Option<Arc<dyn Transport>>>,
    /// The I2P transport (dials `.b32.i2p` peers), once I2P is up.
    i2p_transport: RwLock<Option<Arc<dyn Transport>>>,
    /// The Reticulum mesh transport (dials `rns:` dest hashes), once up.
    rns_transport: RwLock<Option<Arc<dyn Transport>>>,
    /// Latest I2P status snapshot for the Stats page (JSON; `{}` when off).
    i2p_status: RwLock<Value>,
    /// On-demand resolver: resolve + clone a `.epix` host not yet served (set by
    /// the node, which has the chain + worker). Lets the browser open any
    /// `talk.epix` by typing it, cloning it live.
    on_demand: RwLock<Option<Arc<dyn OnDemandResolver>>>,
    /// DHT-backed peer lookup, installed by the runtime.
    peer_finder: RwLock<Option<Arc<dyn PeerFinder>>>,
    /// Included/user-content syncer, installed by the node.
    content_syncer: RwLock<Option<Arc<dyn ContentSyncer>>>,
    /// Per-tracker announce stats (`tracker -> {status, num_*, …}`) for the
    /// dashboard's Trackers panel.
    tracker_stats: RwLock<HashMap<String, Value>>,
    /// Permissions the user has explicitly granted per xite (`address -> [perm]`),
    /// e.g. ADMIN or `Merger:<type>`. A xite gets no permission until it requests
    /// one and the user approves the grant prompt; persisted so a grant survives
    /// restarts.
    grants: RwLock<HashMap<String, Vec<String>>>,
    grants_path: Option<PathBuf>,
    /// Network-stats chart database (feeds the dashboard's Stats page). A
    /// background collector snapshots node metrics into it.
    chart: Arc<crate::chart::ChartDb>,
    /// The optional-files size cap (`optionalLimitStats`/`optionalLimitSet`).
    /// Either a percentage of free disk (e.g. `"10%"`) or a GB number
    /// (e.g. `"5"`). Persisted so it survives restarts.
    optional_limit: RwLock<String>,
    optional_limit_path: Option<PathBuf>,
    /// IP geolocation database for the world map (`chartGetPeerLocations`), set
    /// once the node has extracted its bundled `.mmdb`.
    geoip: RwLock<Option<Arc<crate::geoip::GeoIp>>>,
    /// A small pool of warm peer connections, so the dashboard's connection
    /// stats reflect real live links.
    conn_pool: crate::conn_pool::ConnectionPool,
    /// Broadcast channel for server-pushed UI events (`setSiteInfo`,
    /// `setServerInfo`, `setAnnouncerInfo`, `notification`). Each WebSocket
    /// connection subscribes and forwards matching messages to its socket, so
    /// the dashboard updates live instead of waiting for its next poll.
    events: tokio::sync::broadcast::Sender<UiEvent>,
    /// Node config set via `configSet` (e.g. `language`). Persisted so it
    /// survives restarts.
    config: RwLock<serde_json::Map<String, Value>>,
    config_path: Option<PathBuf>,
    /// Effective values of [`CONFIG_RESTART_KEYS`] captured when boot finished
    /// applying them ([`Self::snapshot_boot_config`]). The Config page marks a
    /// key "pending restart" when its saved value has drifted from this. None
    /// until snapshotted (test/in-memory nodes never are, so nothing pends).
    boot_config: std::sync::Mutex<Option<HashMap<String, String>>>,
    /// The argv a requested restart relaunches with. Set by the embedding
    /// shell - the desktop browser relaunches itself with `--background` so no
    /// second window pops. None relaunches the current exe with its own args.
    restart_argv: std::sync::Mutex<Option<Vec<String>>>,
    /// Names of loaded plugins/features, reported in `serverInfo` (the dashboard
    /// menu shows plugin-gated items like Stats from this).
    plugins: RwLock<Vec<String>>,
    /// Recent log lines for the dashboard console (`serverErrors`): each is
    /// `[date_added, level, message]`, newest last, capped.
    logs: RwLock<std::collections::VecDeque<Value>>,
    /// Open sidebar-console log streams (`consoleLogStream`) as `(stream_id,
    /// level_filter)`; new log lines are pushed to each as `logLineAdd` events,
    /// but only when the line passes that stream's filter.
    log_streams: RwLock<Vec<(i64, String)>>,
    /// Path to the persisted peer database (`peers.json`), so known peers survive
    /// restarts (the PeerDb plugin). None for in-memory nodes.
    peers_path: Option<PathBuf>,
    /// Path to the persisted optional-file pins (`pins.json`), so a pinned file
    /// stays pinned across restarts (OptionalManager). None for in-memory nodes.
    pins_path: Option<PathBuf>,
    /// The fileserver (seeding) TCP port, 0 if seeding is disabled. Reported by
    /// `serverInfo`.
    fileserver_port: RwLock<u16>,
    /// UPnP: whether the fileserver port is currently open to the internet, and
    /// the node's external IP if known. Set by the runtime's UPnP loop; read by
    /// `serverInfo`. Default closed / unknown.
    port_opened: RwLock<bool>,
    ip_external: RwLock<Option<String>>,
    /// Tor: whether the in-process Arti client is up, its status string
    /// (`OK`/`Always`/`Disabled`), and our onion address once the service
    /// publishes. Set by the runtime's Tor loop; read by `serverInfo`.
    tor_enabled: RwLock<bool>,
    tor_status: RwLock<String>,
    onion_address: RwLock<Option<String>>,
    /// Signer for tracker onion-ownership challenges (`onion_sign_this`),
    /// set once the onion service is up. Included in every self-advert.
    onion_signer: RwLock<Option<std::sync::Arc<dyn epix_xite::OnionSigner>>>,
    /// Our own `.b32.i2p` short address (host without the `.i2p` suffix) once
    /// the I2P inbound session is ready. Advertised in PEX so peers can reach
    /// and gossip us over I2P. Set by the runtime's I2P loop.
    i2p_address: RwLock<Option<String>>,
    /// Whether the UI listener is bound to loopback - drives the
    /// cross-origin gate's default (EpixNet enables it only there).
    ui_loopback: RwLock<bool>,
    /// Cert signatures the user marked bad (`badCert`); inbound user content
    /// carrying one is rejected. Session-scoped.
    bad_certs: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Our Reticulum mesh address (destination hash, hex), once the mesh is up.
    rns_address: RwLock<Option<String>>,
    /// In-memory announce tracker: peers other nodes announced to us, keyed by
    /// xite hash, so this node answers `announce` like a Bootstrapper.
    tracker: crate::tracker::TrackerDb,
    /// Inbound updates currently being verified/downloaded (`site/inner:modified`
    /// URIs), so the same pushed version isn't processed twice concurrently
    /// (EpixNet's `files_parsing`).
    updates_in_flight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Verified root content.json updates whose declared files have not all
    /// landed yet, keyed by canonical address. The on-disk content.json (the
    /// completeness marker) stays at the previous consistent version until the
    /// file set completes; [`Self::retry_pending_updates`] re-fetches the
    /// missing files each resync tick and commits when they land. Holds only
    /// the small signed JSON + bytes, never file data.
    pending_updates: std::sync::Mutex<HashMap<String, PendingUpdate>>,
    /// Xite addresses with an update pass (periodic resync or `siteUpdate`)
    /// currently running, bracketed by [`Self::begin_site_update`] /
    /// [`Self::end_site_update`]. A websocket whose event stream lagged
    /// (dropped events under load) uses this to re-send the closing `updated`
    /// event for finished sites only - an in-flight site's real outcome event
    /// is still coming, and a premature one would clear its pill early.
    site_updates_in_flight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Xite addresses with an on-demand clone currently downloading files,
    /// bracketed by [`Self::begin_clone`] / [`Self::end_clone`]. The html
    /// serving gate reads this: while a clone runs, the page document waits
    /// for the whole core set instead of booting half-downloaded.
    clones_in_flight: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Per-file locks keyed by `(address, inner_path)` so concurrent
    /// `file_need`s for the same file download it once: later callers wait on
    /// the first, then hit the verified-on-disk early return. Entries are
    /// removed when the fetch finishes.
    file_need_locks: std::sync::Mutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>,
    /// Pending wrapper callbacks (`confirm`/`prompt`): a pushed event's `to` id
    /// maps to the oneshot awaiting the wrapper's `{cmd:"response", to}` reply.
    callbacks: std::sync::Mutex<HashMap<i64, tokio::sync::oneshot::Sender<Value>>>,
    /// Optional file that `log()` also appends each line to (`debug.log`), so
    /// the node's activity survives restarts for support/debugging. Set by the
    /// host; None keeps logging in-memory + stdout only.
    log_file: std::sync::Mutex<Option<std::fs::File>>,
    /// Pending Bigfile uploads keyed by nonce (`bigfileUploadInit` → the
    /// `/EpixNet-Internal/BigfileUpload` POST consumes it).
    bigfile_uploads: std::sync::Mutex<HashMap<String, BigfileUpload>>,
    /// Outstanding one-time wrapper nonces (EpixNet's `server.wrapper_nonces`):
    /// issued when a wrapper is served, consumed on the inner file request.
    wrapper_nonces: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Hosts allowed as WebSocket `Origin`s (a wrapper's Host is added when
    /// served), so a cross-origin page can't drive the local WS API.
    allowed_ws_origins: std::sync::Mutex<std::collections::HashSet<String>>,
    /// The launch xite (name or address) the node was started with - where the
    /// wrapper's corner home button and the admin pages' back link return to.
    launch_homepage: std::sync::Mutex<Option<String>>,
    /// The shared data root, laid out like Python EpixNet: node files under
    /// `private/`, per-xite dirs under `data/`. None for in-memory nodes.
    data_root: Option<PathBuf>,
    /// Path to `private/sites.json` (the persistent served-xite registry,
    /// EpixNet's SiteManager). None for in-memory nodes.
    sites_path: Option<PathBuf>,
    /// Path to the `epixnet.conf` at the default per-OS location, when this
    /// node's data root is user-relocatable (a desktop node not pinned by
    /// `EPIX_DATA_DIR`). `set_data_dir` persists the choice there.
    data_dir_conf: std::sync::Mutex<Option<PathBuf>>,
    /// Trackers contributed at runtime (the Beacon plugin's live list),
    /// folded into every announce alongside the configured ones. Replaced
    /// wholesale on each refresh - not persisted, the plugin's book is.
    extra_trackers: RwLock<Vec<epix_xite::Tracker>>,
    /// Fired when the runtime-contributed tracker set changes, so the announce
    /// loop can run early instead of waiting out its period.
    trackers_changed: Arc<tokio::sync::Notify>,
    /// Multiuser: extra identities keyed by master_address, persisted alongside
    /// the active `user`. Lets the operator log in with another master seed and
    /// switch between identities. Feature-gated (desktop only).
    #[cfg(feature = "multiuser")]
    multi_users: RwLock<HashMap<String, User>>,
    #[cfg(feature = "multiuser")]
    multi_users_path: Option<PathBuf>,
}

/// A server-pushed UI event.
///
/// - `channel` gates by subscription: `Some("siteChanged")` reaches only
///   connections that joined that channel; `None` is ungated (notifications).
/// - `target` routes by xite: `Some(addr)` only to connections bound to that
///   xite (so `setSiteInfo` for one alias does not overwrite another's), `None`
///   is any xite.
#[derive(Clone)]
pub struct UiEvent {
    pub channel: Option<String>,
    pub target: Option<String>,
    pub payload: String,
    /// Connection id that must NOT receive this event: the one whose own
    /// command produced it. EpixNet's actionFileWrite notifies `ws != self` -
    /// echoing a file_done back to the page that wrote the file makes it
    /// re-render mid-interaction.
    pub exclude: Option<u64>,
    /// Deliver ONLY to this connection id (EpixNet's `self.cmd(...)` - e.g.
    /// publish progress goes to the page that asked, not every open tab).
    pub only: Option<u64>,
}

/// Outcome of an accepted inbound `update` push (errors are `Err` strings that
/// go back on the wire, matching EpixNet's responses).
#[derive(Debug, PartialEq, Eq)]
pub enum InboundUpdate {
    /// Newer version, signature valid: stored, files syncing in the background.
    Applied,
    /// We already have this version (or newer) - sender recorded as a peer.
    NotChanged,
}

/// A pending Bigfile upload (created by `bigfileUploadInit`, consumed by the
/// `/EpixNet-Internal/BigfileUpload` POST).
#[derive(Clone)]
pub struct BigfileUpload {
    pub address: String,
    pub inner_path: String,
    pub size: u64,
    pub piece_size: usize,
    pub piecemap_inner_path: String,
}

/// The result of a completed Bigfile upload (returned to the uploader).
pub struct BigfileUploadResult {
    pub merkle_root: String,
    pub piece_num: usize,
    pub piece_size: usize,
    pub inner_path: String,
}

fn empty_filters() -> Value {
    json!({ "mutes": {}, "siteblocks": {} })
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Counters for one publish call, shared across its batches so progress
/// events describe the whole run: `attempted` counts candidates whose dial
/// actually started (the progress denominator), `done` counts completed
/// dials, `published` counts acceptors. `origin` is the progress routing
/// (None = silent re-broadcast).
struct PublishRun {
    origin: Option<Option<u64>>,
    published: usize,
    done: usize,
    attempted: usize,
}

/// One publish candidate's fate, fed back into the peer registry: an
/// unreachable peer is backed off, a refuser is deprioritized, an acceptor
/// is rewarded.
enum PushOutcome {
    /// The peer took the update.
    Accepted(PeerAddr),
    /// Dial or handshake failed/timed out: dead or unreachable.
    Unreachable(PeerAddr),
    /// Reachable (handshake completed) but the update didn't land: refused,
    /// errored, or stalled mid-transfer - the reason string says which (the
    /// remote's error reply passes through verbatim, so a publisher can see
    /// WHY its own seed rejected an update instead of a bare "refused").
    /// Scored as a file failure ONLY - reputation dock, no backoff, no
    /// connected/response stamp. Rewarding it with ConnectOk would reset its
    /// error count and freshen its response time, which the selection
    /// tiebreak prefers - promoting a useless peer above never-tried
    /// candidates and (via the connected flag) shielding it from eviction.
    Refused(PeerAddr, String),
}

impl PushOutcome {
    fn accepted(&self) -> bool {
        matches!(self, PushOutcome::Accepted(_))
    }

    /// The registry feedback for this outcome, plus the label it carries in
    /// the DEBUG failed-candidates line (None = success).
    fn feedback(self) -> (PeerAddr, epix_worker::PeerOutcome, Option<String>) {
        match self {
            PushOutcome::Accepted(peer) => (peer, epix_worker::PeerOutcome::ConnectOk, None),
            PushOutcome::Unreachable(peer) => {
                (peer, epix_worker::PeerOutcome::ConnectFail, Some("unreachable".into()))
            }
            PushOutcome::Refused(peer, why) => {
                (peer, epix_worker::PeerOutcome::FileFail, Some(format!("refused: {why}")))
            }
        }
    }
}

/// Fold one publish dial's outcome into the run counters and the batch's
/// registry-feedback / failed-candidates buffers.
fn record_push_outcome(
    outcome: PushOutcome,
    run: &mut PublishRun,
    outcomes: &mut Vec<(PeerAddr, epix_worker::PeerOutcome)>,
    accepted: &mut Vec<String>,
    failed: &mut Vec<String>,
) {
    run.published += outcome.accepted() as usize;
    let (peer, score, fail_label) = outcome.feedback();
    match fail_label {
        Some(label) => failed.push(format!("{peer} ({label})")),
        None => accepted.push(peer.to_string()),
    }
    outcomes.push((peer, score));
}

/// Dial one publish candidate and push the update, bounded by the peer's
/// connect timeout: reachable clearnet peers answer in ~1-3s, so the deadline
/// only ever pays for dead candidates, and overlay peers get the longer dial
/// bound - a fresh onion circuit takes 20-40s, and cutting it off is what
/// made publishing to Tor-only peers silently fail. A deadline that expires
/// after the handshake succeeded is scored Refused (the peer is alive), not
/// Unreachable - repeatedly backing off a slow-but-live overlay peer would
/// eventually get a reachable peer evicted.
async fn push_update_to_peer(
    transport: Arc<dyn Transport>,
    peer: PeerAddr,
    address: String,
    inner_path: String,
    body: Arc<Vec<u8>>,
    modified: f64,
    diffs: Option<rmpv::Value>,
    sender_peers: Arc<Vec<String>>,
) -> PushOutcome {
    let deadline = peer.connect_timeout();
    let timeout_peer = peer.clone();
    // Set once the handshake succeeds (see the doc comment).
    let progressed = AtomicBool::new(false);
    let push = async {
        let mut conn = match Connection::connect(transport.as_ref(), &peer).await {
            Ok(conn) => conn,
            Err(_) => return PushOutcome::Unreachable(peer),
        };
        if conn.handshake().await.is_err() {
            return PushOutcome::Unreachable(peer);
        }
        progressed.store(true, Ordering::Relaxed);
        if let Err(e) =
            conn.update(&address, &inner_path, &body, modified, diffs, &sender_peers).await
        {
            return PushOutcome::Refused(peer, e.to_string());
        }
        // Live-hook: tell the peer (acting as a propagation node) about the
        // new version so peers that are offline now can pull it later.
        let _ = epix_propagation::announce_update(&mut conn, &address, modified as i64).await;
        PushOutcome::Accepted(peer)
    };
    match tokio::time::timeout(deadline, push).await {
        Ok(outcome) => outcome,
        Err(_) if progressed.load(Ordering::Relaxed) => {
            PushOutcome::Refused(timeout_peer, "timed out mid-transfer".into())
        }
        Err(_) => PushOutcome::Unreachable(timeout_peer),
    }
}

/// The per-announcer stats key: the tracker's canonical form - Epix
/// announcers by their real transport (`tcp://…`, `onion://…`, `i2p://…` -
/// the dashboard pill shows the actual protocol), BitTorrent trackers by
/// their announce URL. Identical to `Tracker`'s Display on purpose: the
/// Beacon book uses the same form, so stats lookups can never drift from it.
fn tracker_stat_key(tracker: &epix_xite::Tracker) -> String {
    tracker.to_string()
}

/// Whether the Tor state makes `tracker` unusable this pass. Tor Always
/// routes every peer dial through Tor - but BitTorrent announces do their own
/// networking (UDP cannot ride Tor at all, and a direct HTTP announce would
/// leak the real IP), so they are skipped outright in that mode; Epix
/// announcers keep working over the (Tor-routed) transport. Symmetrically,
/// onion announcers are unreachable without Tor, so they are skipped while it
/// is off rather than piling up failures.
fn tracker_tor_gated(tracker: &epix_xite::Tracker, tor_on: bool, tor_status: &str) -> bool {
    match tracker {
        epix_xite::Tracker::Bt(_) => tor_on && tor_status == "Always",
        epix_xite::Tracker::Epix(PeerAddr::Onion { .. }) => !tor_on,
        epix_xite::Tracker::Epix(_) => false,
    }
}

/// Escape a string for safe interpolation into dialog HTML (cert names,
/// addresses shown in the certXid picker).
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// A random lowercase-hex string of `bytes` random bytes (2 hex chars each).
/// Used for wrapper/CSP nonces.
/// Dispatches by transport: `.b32.i2p` peers to the I2P transport, `rns:`
/// dest hashes to the Reticulum mesh, everything else (clearnet, onion) to
/// the base. Lets the overlays be layered onto TCP or Tor's MixedTransport
/// without any of them clobbering another.
struct OverlayTransport {
    base: Arc<dyn Transport>,
    i2p: Option<Arc<dyn Transport>>,
    rns: Option<Arc<dyn Transport>>,
}

#[async_trait::async_trait]
impl Transport for OverlayTransport {
    fn scheme(&self) -> &'static str {
        "overlay"
    }
    async fn dial(&self, addr: &PeerAddr) -> Result<epix_transport::PeerStream, epix_core::Error> {
        match addr {
            PeerAddr::I2p { .. } => match &self.i2p {
                Some(i2p) => i2p.dial(addr).await,
                None => self.base.dial(addr).await,
            },
            PeerAddr::Rns(_) => match &self.rns {
                Some(rns) => rns.dial(addr).await,
                None => self.base.dial(addr).await,
            },
            _ => self.base.dial(addr).await,
        }
    }
}

/// SQL-literal-quote a JSON scalar (EpixNet's `helper.sqlquote`), for inlining
/// `:params` into subscribed notification queries.
fn sql_quote(v: &Value) -> String {
    match v {
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => (*b as i64).to_string(),
        Value::String(s) => format!("'{}'", s.replace('\'', "''")),
        _ => "null".into(),
    }
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let _ = getrandom::fill(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// The running executable's canonical path, for building a self-relaunch
/// argv. This is exec plumbing, not an authorization decision: the value
/// comes from the kernel (/proc/self/exe, _NSGetExecutablePath,
/// GetModuleFileNameW - not argv[0]), is resolved to a real path right away,
/// and must name an existing file. Anyone who could swap it already runs
/// code as this user.
pub fn self_exe() -> Option<String> {
    let exe = std::env::current_exe().ok()?; // nosemgrep: rust.lang.security.current-exe.current-exe
    let exe = exe.canonicalize().ok()?;
    exe.is_file().then(|| exe.display().to_string())
}

/// Launch a detached helper that waits for this process to die, then starts
/// the node again with `argv`. The wait matters: the single-instance guard
/// and the bound ports are only free once the old process is gone. Only ever
/// called with an argv the embedding shell registered explicitly
/// ([`AppState::set_restart_argv`]) - there is no environment-derived
/// fallback, so a node whose shell cannot relaunch (the mobile apps) plainly
/// shuts down instead.
fn spawn_relauncher(argv: &[String]) {
    if argv.first().map(|s| s.is_empty()).unwrap_or(true) {
        return;
    }
    let pid = std::process::id();
    #[cfg(unix)]
    {
        let sq = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
        let cmd = format!(
            "while kill -0 {pid} 2>/dev/null; do sleep 0.2; done; exec {}",
            argv.iter().map(|a| sq(a)).collect::<Vec<_>>().join(" ")
        );
        let _ = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(cmd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    #[cfg(windows)]
    {
        let pq = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let mut cmd = format!(
            "Wait-Process -Id {pid} -ErrorAction SilentlyContinue; Start-Process -FilePath {}",
            pq(&argv[0])
        );
        let args = argv[1..].iter().map(|a| pq(a)).collect::<Vec<_>>().join(",");
        if !args.is_empty() {
            cmd.push_str(&format!(" -ArgumentList {args}"));
        }
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd])
            .spawn();
    }
}

impl AppState {
    /// In-memory node with a freshly generated user identity.
    pub fn new(version: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            version: version.into(),
            rev: RwLock::new("0".to_string()),
            ui_port: RwLock::new(42222),
            xites: RwLock::new(HashMap::new()),
            user: RwLock::new(User::generate()),
            user_path: None,
            nonce_counter: AtomicU64::new(1),
            filters: RwLock::new(empty_filters()),
            filters_path: None,
            transport: RwLock::new(None),
            base_transport: RwLock::new(None),
            i2p_transport: RwLock::new(None),
            rns_transport: RwLock::new(None),
            i2p_status: RwLock::new(json!({})),
            on_demand: RwLock::new(None),
            peer_finder: RwLock::new(None),
            content_syncer: RwLock::new(None),
            tracker_stats: RwLock::new(HashMap::new()),
            grants: RwLock::new(HashMap::new()),
            grants_path: None,
            chart: Arc::new(crate::chart::ChartDb::memory().expect("in-memory chart db")),
            optional_limit: RwLock::new("10%".to_string()),
            optional_limit_path: None,
            geoip: RwLock::new(None),
            conn_pool: crate::conn_pool::ConnectionPool::new(CONNECTION_POOL_MAX),
            events: tokio::sync::broadcast::channel(4096).0,
            config: RwLock::new(serde_json::Map::new()),
            config_path: None,
            boot_config: std::sync::Mutex::new(None),
            restart_argv: std::sync::Mutex::new(None),
            plugins: RwLock::new(Vec::new()),
            logs: RwLock::new(std::collections::VecDeque::new()),
            log_streams: RwLock::new(Vec::new()),
            peers_path: None,
            fileserver_port: RwLock::new(0),
            port_opened: RwLock::new(false),
            ip_external: RwLock::new(None),
            tor_enabled: RwLock::new(false),
            tor_status: RwLock::new("Disabled".to_string()),
            onion_address: RwLock::new(None),
            onion_signer: RwLock::new(None),
            i2p_address: RwLock::new(None),
            ui_loopback: RwLock::new(false),
            bad_certs: std::sync::Mutex::new(std::collections::HashSet::new()),
            rns_address: RwLock::new(None),
            tracker: crate::tracker::TrackerDb::new(),
            pins_path: None,
            updates_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            pending_updates: std::sync::Mutex::new(HashMap::new()),
            site_updates_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            clones_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            file_need_locks: std::sync::Mutex::new(HashMap::new()),
            callbacks: std::sync::Mutex::new(HashMap::new()),
            log_file: std::sync::Mutex::new(None),
            bigfile_uploads: std::sync::Mutex::new(HashMap::new()),
            wrapper_nonces: std::sync::Mutex::new(std::collections::HashSet::new()),
            allowed_ws_origins: std::sync::Mutex::new(std::collections::HashSet::new()),
            launch_homepage: std::sync::Mutex::new(None),
            data_root: None,
            sites_path: None,
            data_dir_conf: std::sync::Mutex::new(None),
            extra_trackers: RwLock::new(Vec::new()),
            trackers_changed: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "multiuser")]
            multi_users: RwLock::new(HashMap::new()),
            #[cfg(feature = "multiuser")]
            multi_users_path: None,
        })
    }

    /// Node backed by a persistent data root, laid out exactly like Python
    /// EpixNet: node-level files (users.json, sites.json, config, permissions)
    /// live in `<root>/private/` and each xite's files in `<root>/data/<addr>/`.
    /// Upgrading from the Python client to this node therefore needs no
    /// migration - the identity, certs, and downloaded xites are read in place.
    pub fn with_data_dir(version: impl Into<String>, data_root: impl Into<PathBuf>) -> Arc<Self> {
        let data_root = data_root.into();
        let dir = data_root.join("private");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::create_dir_all(data_root.join("data"));
        let user_path = dir.join("users.json");
        let user = User::load_or_create(&user_path).unwrap_or_else(|_| User::generate());
        let filters_path = dir.join("filters.json");
        let filters = std::fs::read(&filters_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(empty_filters);
        let grants_path = dir.join("permissions.json");
        let grants = std::fs::read(&grants_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let chart = crate::chart::ChartDb::file(dir.join("chart.db"))
            .or_else(crate::chart::ChartDb::memory)
            .expect("chart db");
        let optional_limit_path = dir.join("optional_limit");
        let optional_limit = std::fs::read_to_string(&optional_limit_path)
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "10%".to_string());
        let config_path = dir.join("config.json");
        let config = std::fs::read(&config_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        // Multiuser: load the extra-identities store, seeding it with the active
        // user so it is always listed.
        #[cfg(feature = "multiuser")]
        let multi_users: HashMap<String, User> = {
            let mut m: HashMap<String, User> = std::fs::read(dir.join("users_multi.json"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            m.insert(user.master_address.clone(), user.clone());
            m
        };
        Arc::new(Self {
            version: version.into(),
            rev: RwLock::new("0".to_string()),
            ui_port: RwLock::new(42222),
            xites: RwLock::new(HashMap::new()),
            user: RwLock::new(user),
            user_path: Some(user_path),
            nonce_counter: AtomicU64::new(1),
            filters: RwLock::new(filters),
            filters_path: Some(filters_path),
            transport: RwLock::new(None),
            base_transport: RwLock::new(None),
            i2p_transport: RwLock::new(None),
            rns_transport: RwLock::new(None),
            i2p_status: RwLock::new(json!({})),
            on_demand: RwLock::new(None),
            peer_finder: RwLock::new(None),
            content_syncer: RwLock::new(None),
            tracker_stats: RwLock::new(HashMap::new()),
            grants: RwLock::new(grants),
            grants_path: Some(grants_path),
            chart: Arc::new(chart),
            optional_limit: RwLock::new(optional_limit),
            optional_limit_path: Some(optional_limit_path),
            geoip: RwLock::new(None),
            conn_pool: crate::conn_pool::ConnectionPool::new(CONNECTION_POOL_MAX),
            events: tokio::sync::broadcast::channel(4096).0,
            config: RwLock::new(config),
            config_path: Some(config_path),
            boot_config: std::sync::Mutex::new(None),
            restart_argv: std::sync::Mutex::new(None),
            plugins: RwLock::new(Vec::new()),
            logs: RwLock::new(std::collections::VecDeque::new()),
            log_streams: RwLock::new(Vec::new()),
            peers_path: Some(dir.join("peers.json")),
            pins_path: Some(dir.join("pins.json")),
            fileserver_port: RwLock::new(0),
            port_opened: RwLock::new(false),
            ip_external: RwLock::new(None),
            tor_enabled: RwLock::new(false),
            tor_status: RwLock::new("Disabled".to_string()),
            onion_address: RwLock::new(None),
            onion_signer: RwLock::new(None),
            i2p_address: RwLock::new(None),
            ui_loopback: RwLock::new(false),
            bad_certs: std::sync::Mutex::new(std::collections::HashSet::new()),
            rns_address: RwLock::new(None),
            tracker: crate::tracker::TrackerDb::new(),
            updates_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            pending_updates: std::sync::Mutex::new(HashMap::new()),
            site_updates_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            clones_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            file_need_locks: std::sync::Mutex::new(HashMap::new()),
            callbacks: std::sync::Mutex::new(HashMap::new()),
            log_file: std::sync::Mutex::new(None),
            bigfile_uploads: std::sync::Mutex::new(HashMap::new()),
            wrapper_nonces: std::sync::Mutex::new(std::collections::HashSet::new()),
            allowed_ws_origins: std::sync::Mutex::new(std::collections::HashSet::new()),
            launch_homepage: std::sync::Mutex::new(None),
            // The served-xite registry lives where Python's SiteManager keeps
            // it, so an EpixNet install's site list carries over as-is.
            sites_path: Some(dir.join("sites.json")),
            data_root: Some(data_root),
            data_dir_conf: std::sync::Mutex::new(None),
            extra_trackers: RwLock::new(Vec::new()),
            trackers_changed: Arc::new(tokio::sync::Notify::new()),
            #[cfg(feature = "multiuser")]
            multi_users: RwLock::new(multi_users),
            #[cfg(feature = "multiuser")]
            multi_users_path: Some(dir.join("users_multi.json")),
        })
    }

    /// Set the loaded plugin/feature names.
    pub async fn set_plugins(&self, names: Vec<String>) {
        *self.plugins.write().await = names;
    }

    /// The loaded plugin/feature names that are currently enabled
    /// (`serverInfo.plugins`). A disabled plugin is hidden from feature checks.
    pub async fn plugins(&self) -> Vec<String> {
        let (disabled, enabled) = self.plugin_overrides().await;
        self.plugins
            .read()
            .await
            .iter()
            .filter(|n| effective_enabled(n, &disabled, &enabled))
            .cloned()
            .collect()
    }

    /// All loaded plugins with their current + default enabled state
    /// (`[(name, enabled, default_enabled)]`), for the plugin manager.
    pub async fn plugin_states(&self) -> Vec<(String, bool, bool)> {
        let (disabled, enabled) = self.plugin_overrides().await;
        self.plugins
            .read()
            .await
            .iter()
            .map(|n| (n.clone(), effective_enabled(n, &disabled, &enabled), !is_default_disabled(n)))
            .collect()
    }

    /// Whether a plugin is currently enabled. Most default enabled; the plugins
    /// EpixNet ships `disabled-` (NoNewSites, UiPassword, Multiuser) default off
    /// until explicitly turned on.
    pub async fn plugin_enabled(&self, name: &str) -> bool {
        let (disabled, enabled) = self.plugin_overrides().await;
        effective_enabled(name, &disabled, &enabled)
    }

    /// Enable/disable a plugin at runtime (persisted). Only stores an override
    /// when the choice differs from the plugin's default, so config stays minimal.
    /// Takes effect on the next page load / command - no restart.
    pub async fn set_plugin_enabled(&self, name: &str, enabled: bool) {
        let (mut disabled, mut enabled_list) = self.plugin_overrides().await;
        disabled.retain(|n| n != name);
        enabled_list.retain(|n| n != name);
        let default_on = !is_default_disabled(name);
        if enabled != default_on {
            if enabled {
                enabled_list.push(name.to_string());
            } else {
                disabled.push(name.to_string());
            }
        }
        self.config_set("plugins_disabled", json!(disabled)).await;
        self.config_set("plugins_enabled", json!(enabled_list)).await;
    }

    /// The persisted `(plugins_disabled, plugins_enabled)` override lists.
    async fn plugin_overrides(&self) -> (Vec<String>, Vec<String>) {
        (self.config_str_list("plugins_disabled").await, self.config_str_list("plugins_enabled").await)
    }

    /// Read a config value as a list of strings.
    async fn config_str_list(&self, key: &str) -> Vec<String> {
        self.config_get(key)
            .await
            .and_then(|v| {
                v.as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            })
            .unwrap_or_default()
    }

    /// A node config value set via `configSet` (e.g. `language`).
    pub async fn config_get(&self, key: &str) -> Option<Value> {
        self.config.read().await.get(key).cloned()
    }

    // --- NoNewSites: refuse to clone/add new sites when set -----------------

    /// Whether the operator has disabled adding new sites to this node.
    pub async fn no_new_sites(&self) -> bool {
        // The NoNewSites plugin toggle is the normal switch; the config key
        // remains as an operator override (headless/proxy deployments).
        self.plugin_enabled("NoNewSites").await
            || self.config_get("no_new_sites").await.and_then(|v| v.as_bool()).unwrap_or(false)
    }

    /// Whether this node runs as a restricted, internet-facing gateway.
    ///
    /// A normal node binds the UI to loopback, so the only client that can
    /// reach the command API is the local wrapper - and the wrapper proves
    /// itself with an elevated request id that grants ADMIN. Behind a reverse
    /// proxy (the public gateway) that assumption breaks: any internet client
    /// can send the same elevated id. When this is set, the node never trusts
    /// the client-supplied id for ADMIN, and content-mutating commands require
    /// genuine ownership of the bound xite - so a public visitor gets a
    /// read-only view and settings can only change server-side.
    pub async fn ui_restrict(&self) -> bool {
        self.config_get("ui_restrict")
            .await
            .map(|v| v.as_bool().unwrap_or_else(|| v.as_str() == Some("true")))
            .unwrap_or(false)
    }

    /// The configured UI password, if any (UiPassword). Empty/unset means the
    /// login gate is off.
    pub async fn ui_password(&self) -> Option<String> {
        self.config_get("ui_password")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty())
    }

    // --- AnnounceShare: persisted working trackers --------------------------

    /// The trackers remembered from previous announces (`epix://…` addresses
    /// and BitTorrent tracker URLs).
    pub async fn shared_trackers(&self) -> Vec<epix_xite::Tracker> {
        self.config_get("shared_trackers")
            .await
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(epix_xite::Tracker::parse)
            .collect()
    }

    /// Replace the runtime-contributed tracker list (the Beacon plugin's
    /// refresh). Every announce pass folds these in; a change wakes the
    /// announce loop so new announcers are used right away.
    pub async fn set_extra_trackers(&self, trackers: Vec<epix_xite::Tracker>) {
        let changed = {
            let mut current = self.extra_trackers.write().await;
            let changed = *current != trackers;
            *current = trackers;
            changed
        };
        if changed {
            // notify_one stores a permit: the announce loop is usually still
            // inside its boot pass when Beacon's first refresh lands, and a
            // waiterless notify_waiters would be lost.
            self.trackers_changed.notify_one();
        }
    }

    /// The runtime-contributed trackers (beyond the configured/static list).
    pub async fn extra_trackers(&self) -> Vec<epix_xite::Tracker> {
        self.extra_trackers.read().await.clone()
    }

    /// The full tracker set for an announce: the `bootstrap` list plus the
    /// operator's `shared_trackers` and the Beacon-discovered `extra_trackers`,
    /// deduped. The periodic announce loop and the on-demand resolver must use
    /// the same set - a site whose only peers are registered on a
    /// Beacon-discovered tracker is otherwise invisible to on-demand clones,
    /// which is how an onion-only xite ends up "No peers found" even though a
    /// shared tracker knows its peer.
    pub async fn all_trackers(
        &self,
        bootstrap: &[epix_xite::Tracker],
    ) -> Vec<epix_xite::Tracker> {
        let mut all = bootstrap.to_vec();
        for t in self.shared_trackers().await.into_iter().chain(self.extra_trackers().await) {
            if !all.contains(&t) {
                all.push(t);
            }
        }
        all
    }

    /// The signal fired when the runtime-contributed tracker set changes.
    pub fn trackers_changed(&self) -> Arc<tokio::sync::Notify> {
        self.trackers_changed.clone()
    }

    /// Remember a tracker that answered, so it is reused (and shared) later.
    async fn add_shared_tracker(&self, tracker: &str) {
        let mut list: Vec<String> = self
            .config_get("shared_trackers")
            .await
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !list.iter().any(|t| t == tracker) {
            list.push(tracker.to_string());
            self.config_set("shared_trackers", json!(list)).await;
        }
    }

    /// The user's directory name under data/users/ (EpixNet's
    /// `getUserDirectory`): the xID cert's `<name>.epix` when one is selected,
    /// else the auth address. EpixTalk-style pages build their write paths
    /// from this, and notification queries reference it as `{xid_directory}`.
    pub async fn user_directory(&self, address: &str, auth_address: &str) -> String {
        match self.user.read().await.get_cert(address) {
            Some(cert) if cert.auth_type == "xid" && !cert.auth_user_name.is_empty() => {
                format!("{}.epix", cert.auth_user_name)
            }
            _ => auth_address.to_string(),
        }
    }

    /// A xite's stored per-user settings (`userGetSettings`).
    pub async fn user_site_settings(&self, address: &str) -> Value {
        self.user.read().await.site_settings(address)
    }

    /// Store a xite's per-user settings (`userSetSettings`), persisted to
    /// users.json like EpixNet's `setSiteSettings`.
    pub async fn set_user_site_settings(&self, address: &str, settings: Value) -> Result<(), String> {
        self.user.write().await.set_site_settings(address, settings)?;
        self.save_user().await;
        Ok(())
    }

    // --- Notification plugin -------------------------------------------------

    /// `notificationSubscribe` - save a site's notification queries
    /// (`{name: [query, params]}`), persisted per site.
    pub async fn notification_subscribe(&self, site: &str, subscriptions: Value) {
        let mut all = self.config_get("notifications").await.unwrap_or_else(|| json!({}));
        if let Value::Object(m) = &mut all {
            m.insert(site.to_string(), subscriptions);
        }
        self.config_set("notifications", all).await;
    }

    /// `notificationList` - a site's saved notification subscriptions.
    pub async fn notification_list(&self, site: &str) -> Value {
        self.config_get("notifications")
            .await
            .and_then(|v| v.get(site).cloned())
            .unwrap_or_else(|| json!({}))
    }

    /// `notificationMute` - global (site = None) or per-site mute.
    pub async fn notification_mute(&self, muted: bool, site: Option<&str>) {
        match site {
            None => self.config_set("notification_muted", json!(muted)).await,
            Some(addr) => {
                let mut mutes = self.config_get("notification_site_muted").await.unwrap_or_else(|| json!({}));
                if let Value::Object(m) = &mut mutes {
                    m.insert(addr.to_string(), json!(muted));
                }
                self.config_set("notification_site_muted", mutes).await;
            }
        }
    }

    /// `notificationMuteStatus` - `{global_muted, site_mutes}`.
    pub async fn notification_mute_status(&self) -> Value {
        let global = self.config_get("notification_muted").await.and_then(|v| v.as_bool()).unwrap_or(false);
        let site_mutes = self.config_get("notification_site_muted").await.unwrap_or_else(|| json!({}));
        json!({ "global_muted": global, "site_mutes": site_mutes })
    }

    /// `notificationQuery` - run every subscribed site's notification queries
    /// and return the counts, mirroring EpixNet's `actionNotificationQuery`:
    /// global/per-site mutes, `:params` inlining, the `{xid_directory}` and
    /// `{last_seen}` placeholders, the `notification_seen` baseline from the
    /// site's per-user settings, and per-entry `site`/`title`/`icon` metadata
    /// (icons from the site's `notification_icons` in content.json).
    pub async fn notification_query(&self) -> Value {
        if self.config_get("notification_muted").await.and_then(|v| v.as_bool()).unwrap_or(false) {
            return json!({ "results": [], "num": 0, "sites": 0, "muted": true });
        }
        let subs = self.config_get("notifications").await.unwrap_or_else(|| json!({}));
        let site_muted = self.config_get("notification_site_muted").await.unwrap_or_else(|| json!({}));
        let dismissed_all =
            self.config_get("notification_dismissed").await.unwrap_or_else(|| json!({}));
        let mut results = Vec::new();
        let mut sites = 0i64;
        let Value::Object(by_site) = &subs else {
            return json!({ "results": [], "num": 0, "sites": 0, "muted": false });
        };
        for (address, site_subs) in by_site {
            if site_muted.get(address).and_then(|v| v.as_bool()).unwrap_or(false) {
                continue;
            }
            let Value::Object(queries) = site_subs else { continue };
            // Like EpixNet, only sites that have (or can have) a database run.
            let (has_db, title, icons) = {
                let xites = self.xites.read().await;
                match xites.get(address) {
                    Some(x) => (
                        x.db.is_some() || x.storage.exists("dbschema.json"),
                        x.content
                            .as_ref()
                            .and_then(|c| c.get("title"))
                            .and_then(|t| t.as_str())
                            .unwrap_or(address)
                            .to_string(),
                        x.content
                            .as_ref()
                            .and_then(|c| c.get("notification_icons"))
                            .and_then(|v| v.as_object().cloned())
                            .unwrap_or_default(),
                    ),
                    None => (false, address.clone(), Default::default()),
                }
            };
            if !has_db {
                continue;
            }
            sites += 1;
            let seen = self
                .user_site_settings(address)
                .await
                .get("notification_seen")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let dismissed = dismissed_all.get(address).cloned().unwrap_or_else(|| json!({}));
            for (name, spec) in queries {
                let (query_raw, params) = match spec {
                    Value::Array(a) => (
                        a.first().and_then(|v| v.as_str()).unwrap_or(""),
                        a.get(1).cloned().unwrap_or(Value::Null),
                    ),
                    Value::String(q) => (q.as_str(), Value::Null),
                    _ => continue,
                };
                if !query_raw.trim_start().to_uppercase().starts_with("SELECT") {
                    continue;
                }
                let mut query = query_raw.to_string();
                if query.contains(":params") {
                    let inlined = params
                        .as_array()
                        .map(|a| a.iter().map(sql_quote).collect::<Vec<_>>().join(","))
                        .unwrap_or_default();
                    query = query.replace(":params", &inlined);
                }
                if query.contains("{xid_directory}") {
                    let auth = self.user.write().await.auth_address(address).unwrap_or_default();
                    if auth.is_empty() {
                        continue;
                    }
                    let dir = self.user_directory(address, &auth).await;
                    query = query.replace("{xid_directory}", &dir);
                }
                let last_seen = dismissed.get(name).and_then(|v| v.as_i64()).unwrap_or(0);
                if query.contains("{last_seen}") {
                    query = query.replace("{last_seen}", &last_seen.to_string());
                }
                let mut entry = json!({
                    "site": address,
                    "title": title,
                    "name": name,
                    "count": 0,
                    "last_seen": last_seen,
                });
                match self.db_query(address, &query, &Value::Null).await {
                    Ok(rows) => {
                        // A notification query is `SELECT COUNT(*) AS count`
                        // shaped: the total is a column on the first row.
                        let mut count = rows
                            .first()
                            .and_then(|r| r.get("count").or_else(|| r.get("COUNT(*)")))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        // Subtract the "seen" baseline the site stored via
                        // userSetSettings when the user last visited.
                        let baseline =
                            seen.get(name).and_then(|v| v.as_i64()).unwrap_or(0);
                        if baseline > 0 && count > 0 {
                            count = (count - baseline).max(0);
                        }
                        entry["count"] = json!(count);
                    }
                    Err(e) => {
                        entry["error"] = json!(e);
                    }
                }
                if let Some(icon) = icons.get(name.as_str()).and_then(|v| v.as_str()) {
                    entry["icon"] = json!(icon);
                }
                results.push(entry);
            }
        }
        json!({ "results": results, "num": results.len(), "sites": sites, "muted": false })
    }

    /// `notificationDismiss` - record when the user cleared a site's
    /// notification, so `{last_seen}` queries can filter to newer items.
    /// Stored as milliseconds, like EpixNet.
    pub async fn notification_mark_dismissed(&self, site: &str, name: &str) {
        let mut all =
            self.config_get("notification_dismissed").await.unwrap_or_else(|| json!({}));
        if !all.is_object() {
            all = json!({});
        }
        let entry = all
            .as_object_mut()
            .unwrap()
            .entry(site.to_string())
            .or_insert_with(|| json!({}));
        if let Value::Object(m) = entry {
            m.insert(name.to_string(), json!(now_secs() * 1000));
        }
        self.config_set("notification_dismissed", all).await;
    }

    /// `configList` - the editable config keys with current value + default.
    /// `pending` marks a restart-only key whose saved value this run did not
    /// boot with, so the change waits for the next start.
    pub async fn config_list(&self) -> Value {
        let pending = self.restart_pending_keys().await;
        let mut back = serde_json::Map::new();
        for (_section, key, _label, default, kind) in CONFIG_SCHEMA {
            if is_config_action(kind) {
                continue;
            }
            let (value, default) = if *key == "data_dir" {
                (json!(self.data_dir_value()), json!(self.data_dir_default()))
            } else {
                (self.config_get(key).await.unwrap_or_else(|| json!(default)), json!(default))
            };
            back.insert(
                key.to_string(),
                json!({ "value": value, "default": default, "pending": pending.iter().any(|p| p == key) }),
            );
        }
        Value::Object(back)
    }

    /// A key's effective value for change comparison: the saved config value,
    /// else the schema default, normalized to canonical text.
    async fn config_effective(&self, key: &str, default: &str) -> String {
        match self.config_get(key).await {
            Some(v) => config_value_str(&v),
            None => default.trim().to_string(),
        }
    }

    /// Capture the restart-only keys' effective values once boot has applied
    /// them (epix-node calls this at the end of boot, after boot's own
    /// config writes like the I2P autostart). [`Self::restart_pending_keys`]
    /// diffs against this snapshot.
    pub async fn snapshot_boot_config(&self) {
        let mut snap = HashMap::new();
        for (_section, key, _label, default, _kind) in CONFIG_SCHEMA {
            if CONFIG_RESTART_KEYS.contains(key) {
                snap.insert(key.to_string(), self.config_effective(key, default).await);
            }
        }
        *self.boot_config.lock().unwrap() = Some(snap);
    }

    /// Config keys whose saved value differs from what this run booted with -
    /// the changes only a restart applies. Includes `data_dir` when a move is
    /// staged in epixnet.conf.
    pub async fn restart_pending_keys(&self) -> Vec<String> {
        let snap = self.boot_config.lock().unwrap().clone();
        let mut pending = Vec::new();
        if let Some(snap) = snap {
            for (_section, key, _label, default, _kind) in CONFIG_SCHEMA {
                if let Some(boot) = snap.get(*key) {
                    if *boot != self.config_effective(key, default).await {
                        pending.push(key.to_string());
                    }
                }
            }
        }
        // data_dir applies from epixnet.conf on the next start: pending when
        // the staged root (or the default, when the entry was removed) is not
        // the one this run opened.
        let conf = self.data_dir_conf.lock().unwrap().clone();
        if let (Some(conf), Some(root)) = (conf, &self.data_root) {
            let staged = crate::paths::read_conf_data_dir(&conf)
                .unwrap_or_else(crate::paths::default_data_root);
            if &staged != root {
                pending.push("data_dir".to_string());
            }
        }
        pending
    }

    /// Register the argv a requested restart relaunches with. Only shells that
    /// really can respawn the process set one (the desktop browser passes
    /// `--background`); without it a restart request is a plain shutdown and
    /// the Config page words its restart bar accordingly.
    pub fn set_restart_argv(&self, argv: Vec<String>) {
        *self.restart_argv.lock().unwrap() = Some(argv);
    }

    /// Whether a restart can actually relaunch the node (a shell registered
    /// a relaunch argv).
    pub fn can_restart(&self) -> bool {
        self.restart_argv.lock().unwrap().is_some()
    }

    /// Stop the node process; with `restart` a detached helper waits for this
    /// process to die and starts it again (the Config page's restart button
    /// and `serverShutdown {restart: true}`). State is persisted first, then
    /// exit is delayed a moment so the caller's response can flush.
    pub async fn shutdown(&self, restart: bool) {
        self.log(
            "INFO",
            format!("Shutdown requested ({})", if restart { "restart" } else { "quit" }),
        )
        .await;
        self.persist_peers().await;
        self.persist_sites().await;
        let argv = if restart { self.restart_argv.lock().unwrap().clone() } else { None };
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            if let Some(argv) = argv {
                spawn_relauncher(&argv);
            }
            std::process::exit(0);
        });
    }

    // --- Data directory (the `data_dir` config key) --------------------------

    /// Where `set_data_dir` persists the choice: the `epixnet.conf` at the
    /// default per-OS location. Set only for desktop nodes whose root is
    /// user-relocatable (not pinned by `EPIX_DATA_DIR` or an embedding shell).
    pub fn set_data_dir_conf(&self, conf: impl Into<PathBuf>) {
        *self.data_dir_conf.lock().unwrap() = Some(conf.into());
    }

    /// The current data root as shown on the Config page.
    pub fn data_dir_value(&self) -> String {
        self.data_root.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
    }

    /// The staged Epix Wallet web app (`<data_root>/wallet-ui`), if present.
    /// The mobile shells copy their bundled wallet build here so the UI
    /// server can serve it as a plain web app - their WebViews cannot run
    /// the WebExtension the desktop browser embeds. None (404s) when nothing
    /// is staged.
    pub fn wallet_ui_dir(&self) -> Option<PathBuf> {
        let dir = self.data_root.as_ref()?.join("wallet-ui");
        dir.is_dir().then_some(dir)
    }

    /// The per-OS default root as shown on the Config page.
    pub fn data_dir_default(&self) -> String {
        crate::paths::default_data_root().display().to_string()
    }

    /// Change where EpixNet stores its data. Copies `private/` and `data/`
    /// to the new location (unless it already holds an identity), then records
    /// the choice as `data_dir` in `epixnet.conf` - the same key the Python
    /// client uses. The old directory is left in place as a backup; the node
    /// switches to the new one on the next start. An empty path resets to the
    /// per-OS default. Returns the message to show the user.
    pub async fn set_data_dir(&self, new_dir: &str) -> Result<String, String> {
        let conf = self
            .data_dir_conf
            .lock()
            .unwrap()
            .clone()
            .ok_or("The data directory is fixed for this node (set via EPIX_DATA_DIR or the embedding app)")?;
        let current = self.data_root.clone().ok_or("This node keeps no data on disk")?;

        // Resolve the input: empty resets to the default; "~" expands.
        let mut input = new_dir.trim().to_string();
        if let Some(rest) = input.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
                input = format!("{}/{}", home.trim_end_matches('/'), rest);
            }
        }
        let default = crate::paths::default_data_root();
        let target = if input.is_empty() { default.clone() } else { PathBuf::from(&input) };
        if !target.is_absolute() {
            return Err(format!("The data directory must be an absolute path (got: {input})"));
        }
        if target == current {
            // Nothing to copy, but the conf must still match (e.g. resetting a
            // stale data_dir line while already running on the default root).
            crate::paths::write_conf_data_dir(&conf, (target != default).then_some(target.as_path()))
                .map_err(|e| format!("Could not save {}: {e}", conf.display()))?;
            return Ok(format!("Data directory is already {}", target.display()));
        }
        if target.starts_with(&current) || current.starts_with(&target) {
            return Err("The new data directory can't be inside the current one (or contain it)".to_string());
        }

        // Copy the node's data over unless the target already holds an
        // identity of its own (then switching must not overwrite it).
        if !target.join("private/users.json").exists() && current.join("private").exists() {
            let (from, to) = (current.clone(), target.clone());
            tokio::task::spawn_blocking(move || {
                for sub in ["private", "data"] {
                    let src = from.join(sub);
                    if src.exists() {
                        copy_dir_all(&src, &to.join(sub))?;
                    }
                }
                Ok::<(), std::io::Error>(())
            })
            .await
            .map_err(|e| format!("copy task failed: {e}"))?
            .map_err(|e| format!("Could not copy the data to {}: {e}", target.display()))?;
        }

        crate::paths::write_conf_data_dir(&conf, (target != default).then_some(target.as_path()))
            .map_err(|e| format!("Could not save {}: {e}", conf.display()))?;
        self.log("INFO", format!("Data directory set to {} (was {})", target.display(), current.display())).await;
        Ok(format!(
            "Data directory set to {}. Restart EpixNet to start using it; the old directory is kept as a backup.",
            target.display()
        ))
    }

    /// Set a node config value (`configSet`), persisted to `data_dir/config.json`.
    pub async fn config_set(&self, key: &str, value: Value) {
        {
            let mut cfg = self.config.write().await;
            if value.is_null() {
                cfg.remove(key);
            } else {
                cfg.insert(key.to_string(), value);
            }
        }
        if let Some(path) = &self.config_path {
            if let Ok(bytes) = serde_json::to_vec_pretty(&*self.config.read().await) {
                let _ = std::fs::write(path, bytes);
            }
        }
    }

    /// Global (per-user) settings - theme etc. Backed by the master user's
    /// `settings` in users.json (like EpixNet's `user.settings`), so a chosen
    /// theme survives restarts instead of resetting to the default.
    pub async fn global_settings(&self) -> Value {
        Value::Object(self.user.read().await.settings.clone())
    }

    /// The interface language the wrapper renders (config `language`, default
    /// `en`), sanitized to a bare language code so it's safe to inject into the
    /// wrapper HTML/URLs. Xites load their translations off this.
    pub async fn ui_language(&self) -> String {
        let lang = self
            .config_get("language")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let clean: String =
            lang.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(16).collect();
        if clean.is_empty() {
            "en".to_string()
        } else {
            clean
        }
    }

    /// The initial `theme-<name>` body class the wrapper renders, from the
    /// user's stored theme (default light; only light/dark are emitted). For
    /// system theme this is the last resolved value; the client corrects it via
    /// prefers-color-scheme, so pages don't flash the wrong theme on every load.
    pub async fn theme_class(&self) -> String {
        let settings = self.global_settings().await;
        match settings.get("theme").and_then(|v| v.as_str()) {
            Some("dark") => "theme-dark".to_string(),
            _ => "theme-light".to_string(),
        }
    }

    /// Merge `value` into the user's settings and persist users.json. Merging
    /// (rather than replacing) keeps node-managed keys like
    /// `next_identity_index` even if the dashboard sends only theme fields.
    pub async fn set_global_settings(&self, value: Value) {
        if let Value::Object(incoming) = value {
            let mut user = self.user.write().await;
            for (k, v) in incoming {
                user.settings.insert(k, v);
            }
        }
        self.save_user().await;
    }

    /// Register a served xite, deriving its settings + stats from content.json.
    /// Register `address` as an empty served xite and persist it, so the node
    /// downloads it on demand later. Used by the offline `siteDownload` CLI,
    /// which has no network stack to clone right now.
    pub async fn register_for_download(&self, address: &str) -> Result<(), String> {
        if !address.starts_with("epix1") {
            return Err(format!("Not a xite address: {address}"));
        }
        if self.has_xite(address).await {
            return Ok(());
        }
        let root = self.data_root.as_ref().ok_or("no data dir")?;
        let dir = root.join("data").join(address);
        self.add_xite(address, XiteEntry { storage: XiteStorage::new(&dir), content: None }).await;
        self.persist_sites().await;
        Ok(())
    }

    pub async fn add_xite(&self, address: impl Into<String>, entry: XiteEntry) {
        let address = address.into();
        let mut settings = XiteSettings::new(now_secs());
        // A xite starts with no permissions. ADMIN (and other permissions) are
        // granted only when the xite requests one and the user approves the
        // wrapper's grant prompt; those grants are restored here from disk.
        // Grants are keyed by the signed content address so a site served under
        // both its raw address and a `.epix` alias shares one grant.
        let canonical = canonical_address(entry.content.as_ref(), &address);
        if let Some(granted) = self.grants.read().await.get(&canonical) {
            settings.permissions = granted.clone();
        }
        if let Some(content) = &entry.content {
            settings.apply_content_stats(&content_stats(content));
            // The node adds a xite after cloning+verifying it, so having content
            // means it was downloaded. Guards inbound `update`: arbitrary peers
            // can't push content for sites we never voluntarily fetched.
            settings.downloaded = Some(now_secs());
        }
        let muted = self.muted_authors().await;
        let (db, db_schema) = match build_xite_db(&entry.storage, &muted) {
            Some((db, schema)) => (Some(db), Some(schema)),
            None => (None, None),
        };
        // Restore any peers persisted by the PeerDb plugin, keyed by the signed
        // content address - including their learned reputation/error state, so
        // a restart doesn't flatten selection back to a blind lottery.
        let mut peers = Peers::new();
        for saved in self.load_persisted_peers(&canonical) {
            peers.restore(saved);
        }
        // Restore optional-file pins persisted by OptionalManager.
        let pinned = self.load_persisted_pins(&canonical);
        // Seed the optional-file hashfield from what's already on disk, so we
        // advertise held optional files immediately (getHashfield/findHashIds).
        let hashfield = compute_hashfield(&entry.storage, entry.content.as_ref());
        self.xites.write().await.insert(
            address,
            ManagedXite {
                storage: entry.storage,
                content: entry.content,
                settings,
                display: None,
                db,
                db_schema,
                peers,
                bytes_recv: 0,
                bytes_sent: 0,
                tasks_active: 0,
                started_task_num: 0,
                workers: 0,
                pinned,
                hashfield,
                peer_hashfields: HashMap::new(),
            },
        );
        // Record the served-xite list so it is restored on the next start.
        self.persist_sites().await;
    }

    /// Record the `.epix` name (xID) a served xite was resolved from. Display
    /// metadata only; the serving key stays the bech32 address.
    pub async fn set_display(&self, address: &str, name: &str) {
        {
            let mut xites = self.xites.write().await;
            let Some(x) = xites.get_mut(address) else { return };
            if x.display.as_deref() == Some(name) {
                return;
            }
            x.display = Some(name.to_string());
        }
        self.persist_sites().await;
    }

    /// The `.epix` name a served xite was resolved from, if any.
    pub async fn display_of(&self, address: &str) -> Option<String> {
        self.xites.read().await.get(address).and_then(|x| x.display.clone())
    }

    /// Resolve a `.epix` name (xID) to its bech32 address: first the served
    /// xites' display metadata, then the on-disk resolve cache (written by the
    /// node on every chain resolution - so a name maps as soon as it resolves,
    /// even while its clone is still downloading). `None` for unknown names.
    pub async fn resolve_name(&self, name: &str) -> Option<String> {
        {
            let xites = self.xites.read().await;
            if let Some((k, _)) = xites.iter().find(|(_, x)| x.display.as_deref() == Some(name)) {
                return Some(k.clone());
            }
        }
        // Entries are `{"address": …, "resolved_at": …}` or a legacy string.
        let root = self.data_root.as_ref()?;
        let cache: serde_json::Map<String, Value> =
            std::fs::read(root.join("resolve-cache.json"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())?;
        let entry = cache.get(name)?;
        entry
            .as_str()
            .or_else(|| entry.get("address").and_then(Value::as_str))
            .map(str::to_string)
    }

    /// Clear every xID resolution cache, so the next visit to any `.epix` name
    /// does a fresh chain lookup instead of reusing a remembered address:
    ///   - the on-disk resolve cache (`resolve-cache.json`),
    ///   - the served xites' display-name bindings ([`Self::resolve_name`]
    ///     checks those FIRST, so a still-registered xite that was resolved
    ///     from a name would otherwise keep claiming it even after the name
    ///     moves to a new address on chain),
    ///   - the chain layer's in-memory caches (resolver snapshots, signers,
    ///     identities).
    /// The xites themselves stay registered and serving under their bech32
    /// addresses; a name rebinds to whatever address the next resolve returns.
    pub async fn xid_clear_cache(&self) {
        if let Some(root) = &self.data_root {
            let _ = std::fs::remove_file(root.join("resolve-cache.json"));
        }
        {
            let mut xites = self.xites.write().await;
            for x in xites.values_mut() {
                x.display = None;
            }
        }
        self.persist_sites().await;
        epix_chain::clear_xid_caches().await;
    }

    /// Normalize a serving reference to the bech32 address: an address passes
    /// through; a `.epix` name resolves via [`Self::resolve_name`]. Returns the
    /// input unchanged if the name is unknown (lookups then miss cleanly).
    pub async fn canonical_key(&self, address_or_name: &str) -> String {
        if !address_or_name.contains('.') {
            return address_or_name.to_string();
        }
        self.resolve_name(address_or_name).await.unwrap_or_else(|| address_or_name.to_string())
    }

    /// A xite's on-disk directory: `<root>/data/<address>` (Python EpixNet's
    /// layout, so an existing install's downloads are found in place). None
    /// for in-memory nodes.
    pub fn xite_dir(&self, address: &str) -> Option<PathBuf> {
        Some(self.data_root.as_ref()?.join("data").join(address))
    }

    /// The shared data root itself (None for in-memory nodes) - where
    /// node-level files like `trackers.json` live.
    pub fn data_root_path(&self) -> Option<PathBuf> {
        self.data_root.clone()
    }

    // --- SiteManager: persist the served-xite list across restarts ----------

    /// Persist the served xites to `sites.json` (keyed by signed content
    /// address; aliases collapse to one entry). The file is EpixNet's
    /// `SiteManager.save` schema - `{address: {…settings…}}` with the settings
    /// flat at the top level - so a Python node can read it and vice versa.
    /// The display alias (e.g. `dashboard.epix`) rides along as an extra
    /// `display` key inside the settings dict (Python preserves unknown keys).
    pub async fn persist_sites(&self) {
        let Some(path) = &self.sites_path else { return };
        let xites = self.xites.read().await;
        let mut map: serde_json::Map<String, Value> = serde_json::Map::new();
        for (key, x) in xites.iter() {
            let canonical = canonical_address(x.content.as_ref(), key);
            // The human-readable name (e.g. `dashboard.epix`) rides along as
            // display metadata; legacy alias-keyed entries still collapse.
            let display =
                x.display.clone().or_else(|| (key != &canonical).then(|| key.clone()));
            let entry = map.entry(canonical).or_insert_with(|| json!(x.settings));
            if let (Some(d), Value::Object(obj)) = (display, entry) {
                obj.insert("display".to_string(), json!(d));
            }
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(&Value::Object(map)) {
            let _ = std::fs::write(path, bytes);
        }
    }

    /// Restore xites recorded in `sites.json`: for each, point storage at
    /// `<root>/data/<canonical>`, load + verify the on-disk content.json, and add it
    /// (plus its display alias). Skips entries already served and any whose
    /// content.json is missing or fails verification. Returns how many were
    /// restored. Call once at startup before serving.
    pub async fn restore_sites(self: &Arc<Self>) -> usize {
        let (Some(path), Some(root)) = (&self.sites_path, &self.data_root) else { return 0 };
        let root = root.join("data");
        let map: serde_json::Map<String, Value> = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => return 0,
        };
        let mut restored = 0;
        for (canonical, entry) in map {
            if self.has_any_alias(&canonical).await {
                continue;
            }
            let dir = root.join(&canonical);
            let storage = XiteStorage::new(&dir);
            // Load the on-disk content.json under the canonical address. Prefer
            // the verified copy; if it doesn't verify but parses, serve it as a
            // local copy anyway (the same fallback boot() uses for the launch
            // xite) - it's already-downloaded content in the operator's own data
            // dir. Dropping it here used to make a registered xite vanish on
            // restart, and under NoNewSites the wrapper then 403s before the
            // on-demand heal can run. Only skip when there's no content.json at
            // all (a bare registration whose clone never landed).
            let Ok(addr) = Address::parse(canonical.clone()) else { continue };
            let mut xite = Xite::new(addr, storage.clone());
            let loaded = xite.load_content().unwrap_or(false) || xite.load_content_local();
            if !loaded {
                continue; // no content.json on disk yet
            }
            // Legacy persisted-ahead state: older builds wrote content.json to
            // disk before its files, so a crash or failed sync could leave a
            // stored content.json whose files are missing. New code commits
            // content.json only after its files (staged adopt), so this only
            // flags dirs written by older builds; the resync loop heals them.
            let missing = xite.files_needed().len();
            if missing > 0 {
                self.log(
                    "INFO",
                    format!(
                        "{canonical}: stored content.json declares {missing} file(s) not on disk; resync will fetch them"
                    ),
                )
                .await;
            }
            let content = xite.content.clone();
            // Settings live flat in the entry (EpixNet schema); accept the old
            // nested `{"settings": {…}}` form too.
            let settings_src = entry.get("settings").cloned().unwrap_or_else(|| entry.clone());
            let saved: Option<XiteSettings> = serde_json::from_value(settings_src).ok();
            self.add_xite(&canonical, XiteEntry { storage: storage.clone(), content: content.clone() })
                .await;
            // Reapply the persisted user-facing settings (ownership, serving,
            // size limit, favourite, added time) that add_xite can't derive
            // from content.json.
            if let Some(saved) = saved {
                let mut xites = self.xites.write().await;
                if let Some(x) = xites.get_mut(&canonical) {
                    x.settings.own = saved.own;
                    x.settings.serving = saved.serving;
                    x.settings.size_limit = saved.size_limit;
                    x.settings.autodownloadoptional = saved.autodownloadoptional;
                    x.settings.optional_help = saved.optional_help;
                    x.settings.favorite = saved.favorite;
                    if saved.added > 0 {
                        x.settings.added = saved.added;
                    }
                    // add_xite derived modified from the ROOT content.json;
                    // the saved value also folds in per-user content seen
                    // last run (user posts), so keep whichever is newest.
                    x.settings.modified = x.settings.modified.max(saved.modified);
                }
            }
            // Per-user content already on disk counts too (sites synced before
            // settings.modified folded it in would show the root's old date
            // until the next post arrives): take the newest content.json
            // anywhere in the tree, once, at restore. New arrivals keep it
            // fresh incrementally from here.
            let newest = walk_content_json(&dir)
                .into_iter()
                .filter_map(|p| std::fs::read(dir.join(&p)).ok())
                .filter_map(|b| serde_json::from_slice::<Value>(&b).ok())
                .filter_map(|c| c.get("modified").and_then(|v| v.as_f64()))
                .fold(0.0_f64, f64::max);
            self.bump_modified(&canonical, newest).await;
            // The `.epix` name is display metadata, not a second serving key.
            if let Some(display) = entry.get("display").and_then(|v| v.as_str()) {
                if display != canonical {
                    self.set_display(&canonical, display).await;
                    // Older builds keyed the per-site user identity (certs,
                    // site keys) by the name; move it to the address so the
                    // identity survives the switch to address-only keys.
                    self.migrate_user_site_key(display, &canonical).await;
                }
            }
            restored += 1;
        }
        restored
    }

    /// Whether `addr` is one of this node's OWN addresses (external ip:port,
    /// onion service, i2p destination, or mesh hash). Trackers, PEX, and the
    /// DHT all echo our own announces back at us; registering them makes the
    /// node dial itself - the dial "succeeds" and it serves itself its own
    /// stale files, wasting a selection slot on every sync pass.
    async fn is_own_peer(&self, addr: &PeerAddr) -> bool {
        match addr {
            PeerAddr::Ip(sa) => {
                let port = self.fileserver_port().await;
                if port == 0 || sa.port() != port {
                    return false;
                }
                let (_, detected) = self.port_status().await;
                let configured = self
                    .config_get("ip_external")
                    .await
                    .and_then(|v| v.as_str().map(str::to_string))
                    .filter(|s| !s.is_empty());
                [configured, detected]
                    .iter()
                    .flatten()
                    .any(|ip| ip.parse().ok() == Some(sa.ip()))
            }
            // Overlay ports are historic/vestigial: any entry with our host
            // is us.
            PeerAddr::Onion { host, .. } => {
                self.onion_address().await.as_deref() == Some(host.as_str())
            }
            PeerAddr::I2p { dest, .. } => {
                self.i2p_address().await.as_deref() == Some(dest.as_str())
            }
            PeerAddr::Rns(_) => match self.rns_address().await {
                Some(r) => addr.to_string() == format!("rns:{}", r.to_lowercase()),
                None => false,
            },
        }
    }

    /// Add discovered peers to a xite, syncing `settings.peers` to the count.
    /// Silently drops this node's own addresses (see [`Self::is_own_peer`]) and
    /// placeholder shapes (an inbound overlay sender whose handshake never
    /// advertised a dial-back address arrives as an empty onion/i2p addr -
    /// recording it wastes a selection slot on an undialable entry).
    pub async fn add_peers(&self, address: &str, addrs: impl IntoIterator<Item = PeerAddr>) {
        let mut filtered = Vec::new();
        for a in addrs {
            if a.is_wellformed() && !self.is_own_peer(&a).await {
                filtered.push(a);
            }
        }
        let grew = {
            let mut xites = self.xites.write().await;
            match xites.get_mut(address) {
                Some(x) => {
                    let before = x.peers.len();
                    x.peers.add_many(filtered, now_secs());
                    x.settings.peers = x.peers.len() as i64;
                    x.peers.len() > before
                }
                None => false,
            }
        };
        // New peers discovered (announce/PEX/DHT/local): update the site's
        // dashboard row live, like EpixNet's peers_added.
        if grew {
            self.push_site_info(address).await;
        }
    }

    /// Connectable public peers for a PEX reply: up to `need`, excluding any in
    /// `exclude` (peers the requester already sent us) and private/loopback
    /// addresses. Resolves aliases so any key sharing the canonical address
    /// draws from the same peer set.
    pub async fn pex_peers(
        &self,
        address: &str,
        need: usize,
        exclude: &std::collections::HashSet<String>,
    ) -> Vec<PeerAddr> {
        let xites = self.xites.read().await;
        let Some(x) = self.resolve_xite(&xites, address) else { return Vec::new() };
        x.peers
            .peers()
            .filter(|p| p.is_connectable() && !p.addr.is_private())
            .filter(|p| !exclude.contains(&p.addr.to_string()))
            .map(|p| p.addr.clone())
            .take(need)
            .collect()
    }

    /// content.json files modified after `since` (ms), as `{inner_path:
    /// modified}` - the `listModified` reply, covering the root plus every
    /// include / per-user content.json on disk.
    pub async fn list_modified(&self, address: &str, since: f64) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        let xites = self.xites.read().await;
        let Some(x) = self.resolve_xite(&xites, address) else { return out };
        let root = x.storage.root().to_path_buf();
        drop(xites);
        // Every content.json on disk (root + includes + per-user), keyed by its
        // `modified` time - so a peer cloning a user_contents site learns about
        // the included and per-user content.json files, not just the root.
        for path in walk_content_json(&root) {
            if let Ok(bytes) = std::fs::read(root.join(&path)) {
                if let Ok(json) = serde_json::from_slice::<Value>(&bytes) {
                    let modified = json.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    if modified > since {
                        out.insert(path, json!(modified));
                    }
                }
            }
        }
        out
    }

    /// Our optional-file hashfield bytes for a xite (`getHashfield` reply).
    pub async fn hashfield_bytes(&self, address: &str) -> Option<Vec<u8>> {
        let xites = self.xites.read().await;
        self.resolve_xite(&xites, address).map(|x| x.hashfield.to_bytes())
    }

    /// Record a peer's advertised hashfield (`setHashfield`). Also registers the
    /// peer if new - but never a placeholder shape (an inbound overlay sender
    /// that advertised no dial-back address) nor this node's OWN address (an
    /// inbound peer can now advertise an adopted overlay self-address, so the
    /// same `is_own_peer` guard every other recording path applies is required
    /// here too - otherwise a peer could plant our own onion/i2p/rns as a
    /// dialable peer and make us sync from ourselves). The hashfield is only
    /// stored for an addressable, non-self peer, so `findHashIds` never
    /// attributes an attacker-supplied hashfield to our own address or to an
    /// undialable placeholder.
    pub async fn set_peer_hashfield(&self, address: &str, peer: &PeerAddr, raw: &[u8]) -> bool {
        // is_own_peer reads only onion/i2p/rns/port state, never self.xites, so
        // computing it before the write lock cannot deadlock.
        let registerable = peer.is_wellformed() && !self.is_own_peer(peer).await;
        let mut xites = self.xites.write().await;
        let key = xites
            .iter()
            .find(|(k, x)| {
                k.as_str() == address || canonical_address(x.content.as_ref(), k) == address
            })
            .map(|(k, _)| k.clone());
        let Some(key) = key else { return false };
        let x = xites.get_mut(&key).unwrap();
        if registerable {
            x.peers.add(peer.clone(), now_secs());
            x.settings.peers = x.peers.len() as i64;
            x.peer_hashfields
                .insert(peer.to_string(), epix_xite::Hashfield::from_bytes(raw));
        }
        true
    }

    /// Mark that we now hold an optional file (add its hash id to our hashfield).
    pub async fn hashfield_add(&self, address: &str, sha512: &str) {
        let mut xites = self.xites.write().await;
        if let Some(x) = xites.get_mut(address) {
            x.hashfield.add_hash(sha512);
        }
    }

    /// For `findHashIds`: which known peers advertise each requested hash id,
    /// packed and bucketed by ip type (`{hash_id: [packed_addr]}` per bucket),
    /// plus the hash ids we ourselves hold (`my`). Up to 20 peers per hash id.
    pub async fn find_hash_ids(
        &self,
        address: &str,
        hash_ids: &[u16],
    ) -> (
        HashMap<u16, Vec<Vec<u8>>>, // ipv4
        HashMap<u16, Vec<Vec<u8>>>, // ipv6
        HashMap<u16, Vec<Vec<u8>>>, // onion
        Vec<u16>,                   // my
    ) {
        let (mut v4, mut v6, mut onion) = (HashMap::new(), HashMap::new(), HashMap::new());
        let mut mine = Vec::new();
        let xites = self.xites.read().await;
        let Some(x) = self.resolve_xite(&xites, address) else {
            return (v4, v6, onion, mine);
        };
        for &id in hash_ids {
            if x.hashfield.has_id(id) {
                mine.push(id);
            }
            for peer in x.peers.peers() {
                let has = x.peer_hashfields.get(&peer.addr.to_string()).is_some_and(|hf| hf.has_id(id));
                if !has || !peer.is_connectable() {
                    continue;
                }
                let (Some(bucket), Some(packed)) = (
                    match peer.addr.ip_type() {
                        epix_core::IpType::Ipv4 => Some(&mut v4),
                        epix_core::IpType::Ipv6 => Some(&mut v6),
                        epix_core::IpType::Onion => Some(&mut onion),
                        epix_core::IpType::I2p | epix_core::IpType::Rns => None,
                    },
                    peer.addr.pack(),
                ) else {
                    continue;
                };
                let list: &mut Vec<Vec<u8>> = bucket.entry(id).or_default();
                if list.len() < 20 {
                    list.push(packed);
                }
            }
        }
        (v4, v6, onion, mine)
    }

    /// Receive a pushed optional file (`pushFile`): verify its declared size and
    /// sha512 from content.json, write it, and record it in our hashfield.
    /// Mirrors EpixNet's `actionPushFile`. Returns an Ok/error message string.
    pub async fn apply_push_file(
        &self,
        site: &str,
        inner_path: &str,
        body: &[u8],
    ) -> Result<String, String> {
        let (key, info) = {
            let xites = self.xites.read().await;
            let x = self.resolve_xite(&xites, site).ok_or("Unknown site")?;
            if x.settings.downloaded.is_none() {
                return Err("Site not yet downloaded".into());
            }
            // File must be declared (required or optional) in content.json.
            let info = x
                .content
                .as_ref()
                .and_then(|c| {
                    c.get("files")
                        .and_then(|f| f.get(inner_path))
                        .or_else(|| c.get("files_optional").and_then(|f| f.get(inner_path)))
                })
                .ok_or("File not in content.json")?;
            let size = info.get("size").and_then(|v| v.as_i64()).unwrap_or(-1);
            let sha512 = info.get("sha512").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // Find the real serving key so we write to the right storage.
            let key = xites
                .iter()
                .find(|(k, x)| {
                    k.as_str() == site || canonical_address(x.content.as_ref(), k) == site
                })
                .map(|(k, _)| k.clone())
                .ok_or("Unknown site")?;
            (key, (size, sha512))
        };
        let (expected_size, expected_hash) = info;
        if body.len() as i64 != expected_size {
            return Err("File size mismatch".into());
        }
        let actual = XiteStorage::hash_bytes(body);
        if actual != expected_hash {
            return Err("File verify failed".into());
        }
        {
            let xites = self.xites.read().await;
            let x = xites.get(&key).ok_or("Unknown site")?;
            x.storage.write(inner_path, body).map_err(|e| e.to_string())?;
        }
        self.hashfield_add(&key, &expected_hash).await;
        Ok("File pushed".into())
    }

    /// Find a managed xite by a key that may be its serving key or its signed
    /// content address (alias-aware).
    fn resolve_xite<'a>(
        &self,
        xites: &'a HashMap<String, ManagedXite>,
        address: &str,
    ) -> Option<&'a ManagedXite> {
        xites.get(address).or_else(|| {
            xites
                .values()
                .find(|x| canonical_address(x.content.as_ref(), address) == address)
        })
    }

    /// True if we serve a xite under `address` (its serving key or signed
    /// content address).
    pub async fn has_any_alias(&self, address: &str) -> bool {
        let xites = self.xites.read().await;
        self.resolve_xite(&xites, address).is_some()
    }

    // --- PeerDb: persist known peers across restarts ------------------------

    /// Load the peers persisted for a site (by signed content address), with
    /// their persisted learning state. Entries are either bare address strings
    /// (the legacy format) or `{addr, rep, errors, seen}` objects; both parse,
    /// so an old peers.json upgrades in place. Malformed/placeholder shapes
    /// (e.g. the legacy port-1 tracker placeholder) are dropped here - the
    /// boot restore bypasses [`Self::add_peers`]' ingest filter, so junk that
    /// predates the filter would otherwise survive on disk forever.
    fn load_persisted_peers(&self, canonical: &str) -> Vec<Peer> {
        let Some(path) = &self.peers_path else { return Vec::new() };
        let map: serde_json::Map<String, Value> = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let now = now_secs();
        map.get(canonical)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|entry| {
                        let (addr_str, saved) = match entry {
                            Value::String(s) => (s.as_str(), None),
                            Value::Object(o) => (o.get("addr")?.as_str()?, Some(o)),
                            _ => return None,
                        };
                        let addr = PeerAddr::parse(addr_str).ok()?;
                        if !addr.is_wellformed() {
                            return None;
                        }
                        let mut peer = Peer::new(addr, now);
                        if let Some(o) = saved {
                            // Saturate out-of-range values (a hand-edited or
                            // foreign peers.json) instead of `as`-wrapping
                            // them into nonsense reputations/counters.
                            peer.reputation = o
                                .get("rep")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0)
                                .clamp(i32::MIN as i64, i32::MAX as i64)
                                as i32;
                            peer.connection_errors =
                                o.get("errors").and_then(|v| v.as_u64()).unwrap_or(0).min(u32::MAX as u64)
                                    as u32;
                            peer.time_response =
                                o.get("seen").and_then(|v| v.as_i64()).unwrap_or(0);
                        }
                        Some(peer)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Persist every served xite's peers to `peers.json` (keyed by signed content
    /// address, so aliases share one list). Called periodically by the runtime.
    /// Sweeps first: evicts dead peers, and drops entries that never belonged -
    /// malformed/placeholder shapes and this node's own addresses (junk that
    /// predates the ingest filters, or an external IP detected only after the
    /// entries were restored at boot) - so they age out of the table instead of
    /// being persisted and PEX-shared forever. Each peer is stored with its
    /// learned reputation/error state so a restart doesn't reset selection.
    pub async fn persist_peers(&self) {
        // is_own_peer is async (it reads port/onion/i2p/rns state, never
        // self.xites), so classify addresses before taking the write lock.
        let unique: std::collections::HashSet<PeerAddr> = self
            .xites
            .read()
            .await
            .values()
            .flat_map(|x| x.peers.peers().map(|p| p.addr.clone()))
            .collect();
        let mut junk: std::collections::HashSet<PeerAddr> = std::collections::HashSet::new();
        for addr in unique {
            if !addr.is_wellformed() || self.is_own_peer(&addr).await {
                junk.insert(addr);
            }
        }
        let dropped: usize = {
            let mut xites = self.xites.write().await;
            let now = now_secs();
            xites
                .values_mut()
                .map(|x| {
                    let evicted =
                        x.peers.evict_dead(now) + x.peers.retain(|p| !junk.contains(&p.addr));
                    x.settings.peers = x.peers.len() as i64;
                    evicted
                })
                .sum()
        };
        if dropped > 0 {
            self.log("INFO", format!("Evicted {dropped} dead/junk peer(s)")).await;
        }
        if !self.plugin_enabled("PeerDb").await {
            return;
        }
        let Some(path) = &self.peers_path else { return };
        let mut map: serde_json::Map<String, Value> = serde_json::Map::new();
        for (key, x) in self.xites.read().await.iter() {
            let canonical = canonical_address(x.content.as_ref(), key);
            if x.peers.len() == 0 {
                continue;
            }
            let list: Vec<Value> = x
                .peers
                .peers()
                .map(|p| {
                    json!({
                        "addr": p.addr.to_string(),
                        "rep": p.reputation,
                        "errors": p.connection_errors,
                        "seen": p.time_response,
                    })
                })
                .collect();
            map.insert(canonical, Value::Array(list));
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(&map) {
            let _ = std::fs::write(path, bytes);
        }
    }

    // --- OptionalManager: persist optional-file pins across restarts ---------

    /// Load the pinned optional-file paths for a site (by signed content address).
    fn load_persisted_pins(&self, canonical: &str) -> std::collections::HashSet<String> {
        let Some(path) = &self.pins_path else { return Default::default() };
        let map: serde_json::Map<String, Value> = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        map.get(canonical)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    }

    /// Persist every served xite's pins to `pins.json` (keyed by signed content
    /// address, so aliases share one list).
    pub async fn persist_pins(&self) {
        let Some(path) = &self.pins_path else { return };
        let mut map: serde_json::Map<String, Value> = serde_json::Map::new();
        for (key, x) in self.xites.read().await.iter() {
            if x.pinned.is_empty() {
                continue;
            }
            let canonical = canonical_address(x.content.as_ref(), key);
            let mut list: Vec<String> = x.pinned.iter().cloned().collect();
            list.sort();
            map.insert(canonical, json!(list));
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(&map) {
            let _ = std::fs::write(path, bytes);
        }
    }

    /// How we advertise ourselves to trackers so they hand our address out:
    /// our fileserver port plus any onion/i2p addresses we host (overlay
    /// addresses are the only route by which onion/i2p-only nodes get found).
    /// The `want_*` flags ask the tracker for peers of that type, so they key
    /// on whether we can DIAL the network - not on whether we publish an
    /// inbound address there. A dial-only i2p node (transport Ready, no
    /// inbound b32) wants i2p peers; a node with a stale published b32 whose
    /// session died does not.
    pub async fn self_advert(&self) -> epix_xite::SelfAdvert {
        let nets = self.dialable_networks().await;
        epix_xite::SelfAdvert {
            port: self.fileserver_port().await,
            onion: self.onion_address().await,
            i2p: self.i2p_address().await,
            want_onion: self.tor_status().await.0,
            want_i2p: nets.i2p,
            onion_signer: self.onion_signer.read().await.clone(),
        }
    }

    /// Announce a xite to each tracker in turn, recording per-tracker stats and
    /// folding the peers found into the xite's registry. Returns all peers.
    pub async fn announce_to_trackers(
        &self,
        address: &str,
        trackers: &[epix_xite::Tracker],
    ) -> Vec<PeerAddr> {
        let Some(transport) = self.transport.read().await.clone() else { return Vec::new() };
        let (tor_on, tor_st) = self.tor_status().await;
        // Trackers key peers by the signed content address, so a `.epix` alias
        // must announce under that (not the display name) to find the same
        // peers as the raw address.
        let key = {
            let xites = self.xites.read().await;
            xites
                .get(address)
                .map(|x| canonical_address(x.content.as_ref(), address))
                .unwrap_or_else(|| address.to_string())
        };
        let advert = std::sync::Arc::new(self.self_advert().await);
        // Announce to every tracker concurrently: with a Beacon-sized list
        // (dozens, some dead), serial announces would stretch one pass across
        // many timeouts and the dashboard's per-tracker stats would trickle in.
        let mut set = tokio::task::JoinSet::new();
        let mut skipped = 0;
        for tracker in trackers.iter().cloned() {
            if tracker_tor_gated(&tracker, tor_on, &tor_st) {
                continue;
            }
            if self.tracker_backed_off(&tracker).await {
                skipped += 1;
                continue;
            }
            let transport = transport.clone();
            let key = key.clone();
            let advert = advert.clone();
            set.spawn(async move {
                let peers = tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    epix_xite::announce(transport.as_ref(), &key, std::slice::from_ref(&tracker), &advert),
                )
                .await
                .unwrap_or_default();
                (tracker, peers)
            });
        }
        let all = self.absorb_announce_results(set).await;
        self.add_peers(address, all.clone()).await;
        let skip_note = if skipped > 0 { format!(" ({skipped} backed off)") } else { String::new() };
        self.log("INFO", format!("Announced {address}: {} peers{skip_note}", all.len())).await;
        // Push the fresh peer count + tracker status to any connected UI.
        self.push_site_info(address).await;
        self.push_announcer_info(&key).await;
        all
    }

    /// Drain the concurrent per-tracker announces: record each tracker's
    /// stats, remember answering trackers for AnnounceShare, and return the
    /// de-duplicated union of discovered peers.
    async fn absorb_announce_results(
        &self,
        mut set: tokio::task::JoinSet<(epix_xite::Tracker, Vec<PeerAddr>)>,
    ) -> Vec<PeerAddr> {
        let mut all: Vec<PeerAddr> = Vec::new();
        while let Some(res) = set.join_next().await {
            let Ok((tracker, peers)) = res else { continue };
            self.record_tracker(&tracker, peers.len()).await;
            // AnnounceShare: remember a tracker that answered, so it is
            // reused (and shared) across restarts - while the plugin is on.
            if !peers.is_empty() && self.plugin_enabled("AnnounceShare").await {
                self.add_shared_tracker(&tracker.to_string()).await;
            }
            for p in peers {
                if !all.contains(&p) {
                    all.push(p);
                }
            }
        }
        all
    }

    /// Record a completed announce to `tracker` (found `num_added` peers). An
    /// announce that returned no peers counts as an error, not a success, so
    /// the dashboard's working-tracker count and Beacon's health check reflect
    /// which announcers actually answer (a dead onion/IPv6 entry shouldn't read
    /// as working just because it was tried).
    async fn record_tracker(&self, tracker: &epix_xite::Tracker, num_added: usize) {
        // Key (and show) Epix announcers by their real transport, not a
        // blanket `epix://` - `tcp://1.2.3.4:15441`, `onion://…`, `i2p://…` -
        // so the dashboard's tracker pill reflects the actual protocol.
        // BitTorrent trackers are keyed by their announce URL.
        let key = tracker_stat_key(tracker);
        let mut stats = self.tracker_stats.write().await;
        let entry = stats.entry(key).or_insert_with(|| {
            json!({ "status": "announcing", "num_request": 0, "num_success": 0, "num_error": 0, "num_added": 0, "time_request": 0 })
        });
        let obj = entry.as_object_mut().expect("tracker stat object");
        let bump = |o: &mut serde_json::Map<String, Value>, k: &str, by: i64| {
            let v = o.get(k).and_then(|v| v.as_i64()).unwrap_or(0) + by;
            o.insert(k.to_string(), json!(v));
        };
        obj.insert("time_request".into(), json!(now_secs()));
        bump(obj, "num_request", 1);
        bump(obj, "num_added", num_added as i64);
        if num_added > 0 {
            obj.insert("status".into(), json!("announced"));
            bump(obj, "num_success", 1);
        } else {
            obj.insert("status".into(), json!("error"));
            bump(obj, "num_error", 1);
        }
    }

    /// EpixNet's tracker back-off (`SiteAnnouncer.announce`): skip a tracker
    /// that has failed more than 5 times and was tried within the last
    /// `60 * min(30, num_error)` seconds, so a reliably-dead tracker is not
    /// hammered every pass. `force` (a manual `siteAnnounce`) bypasses it.
    async fn tracker_backed_off(&self, tracker: &epix_xite::Tracker) -> bool {
        let key = tracker_stat_key(tracker);
        let stats = self.tracker_stats.read().await;
        let Some(entry) = stats.get(&key) else { return false };
        let num_error = entry.get("num_error").and_then(|v| v.as_i64()).unwrap_or(0);
        let time_request = entry.get("time_request").and_then(|v| v.as_i64()).unwrap_or(0);
        if num_error <= 5 {
            return false;
        }
        let wait = 60 * num_error.min(30);
        now_secs() as i64 - time_request < wait
    }

    /// Per-tracker announce stats for the dashboard. `announcerStats`.
    pub async fn announcer_stats(&self) -> Value {
        Value::Object(self.tracker_stats.read().await.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    /// Mark a peer connected/disconnected for a xite.
    pub async fn set_peer_connected(&self, address: &str, addr: &PeerAddr, connected: bool) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.peers.set_connected(addr, connected, now_secs());
        }
    }

    /// Record transferred bytes for a xite (and against the peer if known).
    pub async fn record_transfer(&self, address: &str, addr: &PeerAddr, recv: u64, sent: u64) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.bytes_recv += recv;
            x.bytes_sent += sent;
            x.peers.record_transfer(addr, recv, sent);
        }
    }

    /// Add to a xite's transfer totals (no per-peer attribution).
    pub async fn add_transfer(&self, address: &str, recv: u64, sent: u64) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.bytes_recv += recv;
            x.bytes_sent += sent;
        }
    }

    /// Update live worker accounting for a xite.
    pub async fn set_worker_stats(&self, address: &str, active: usize, workers: usize, started_delta: usize) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.tasks_active = active;
            x.workers = workers;
            x.started_task_num += started_delta;
        }
    }

    /// The addresses of all served xites.
    pub async fn xite_addresses(&self) -> Vec<String> {
        self.xites.read().await.keys().cloned().collect()
    }

    /// Record the fileserver's reachability (UPnP): whether the port is open to
    /// the internet and the node's external IP, if known.
    pub async fn set_port_status(&self, opened: bool, ip_external: Option<String>) {
        let changed = {
            let mut cur = self.port_opened.write().await;
            let was = *cur;
            *cur = opened;
            was != opened
        };
        *self.ip_external.write().await = ip_external;
        // Outbound handshakes advertise clearnet reachability (Phase 6); keep
        // the advert in sync with every confirmation path (inbound peer,
        // port check, UPnP, ip_external config) - and with regressions.
        epix_protocol::update_self_advert(|a| a.port_opened = opened);
        // The dashboard shows port reachability live (serverChanged).
        if changed {
            self.push_server_info().await;
        }
    }

    /// The fileserver's reachability for `serverInfo`: `(port_opened, ip_external)`.
    pub async fn port_status(&self) -> (bool, Option<String>) {
        (*self.port_opened.read().await, self.ip_external.read().await.clone())
    }

    /// Record the in-process Tor client's state, for `serverInfo`. `status` is
    /// the human string EpixNet shows (`OK`/`Always`/`Disabled`).
    pub async fn set_tor_status(&self, enabled: bool, status: &str) {
        let changed = {
            let mut cur = self.tor_status.write().await;
            let was = cur.clone();
            *self.tor_enabled.write().await = enabled;
            *cur = status.to_string();
            was != status
        };
        // The dashboard shows the Tor state live (serverChanged).
        if changed {
            self.push_server_info().await;
        }
    }

    /// Record our onion address (no `.onion` suffix) once the service publishes.
    pub async fn set_onion_address(&self, host: &str) {
        *self.onion_address.write().await = Some(host.to_string());
        self.push_server_info().await;
    }

    /// Record the onion identity signer used to answer tracker
    /// `onion_sign_this` challenges - without it, Bootstrapper trackers never
    /// register our onion and other nodes cannot discover us over Tor.
    pub async fn set_onion_signer(&self, signer: std::sync::Arc<dyn epix_xite::OnionSigner>) {
        *self.onion_signer.write().await = Some(signer);
    }

    /// Tor state for `serverInfo`: `(enabled, status)`.
    pub async fn tor_status(&self) -> (bool, String) {
        (*self.tor_enabled.read().await, self.tor_status.read().await.clone())
    }

    /// Our onion address (no suffix), if the onion service has published one.
    pub async fn onion_address(&self) -> Option<String> {
        self.onion_address.read().await.clone()
    }

    /// Record our `.b32.i2p` address (host without the `.i2p` suffix, e.g.
    /// `<b32>.b32`) once the I2P inbound session is ready.
    pub async fn set_i2p_address(&self, host: &str) {
        *self.i2p_address.write().await = Some(host.to_string());
    }

    /// Our `.b32.i2p` address (host without `.i2p`), if I2P inbound is ready.
    pub async fn i2p_address(&self) -> Option<String> {
        self.i2p_address.read().await.clone()
    }

    /// The addresses other nodes can dial US at right now: onion and i2p
    /// service addresses plus the clearnet ip:port when the port check found
    /// it open. Stamped onto update pushes (`sender_peers`) so receivers can
    /// fetch a pushed version's files straight from us - the socket address
    /// they see is not dialable when we are behind NAT.
    pub async fn own_dialable_addresses(&self) -> Vec<String> {
        let port = self.fileserver_port().await;
        if port == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(onion) = self.onion_address().await {
            out.push(format!("{onion}.onion:{port}"));
        }
        if let Some(b32) = self.i2p_address().await {
            out.push(format!("{b32}.i2p:{port}"));
        }
        let (open, ip) = self.port_status().await;
        if open {
            if let Some(ip) = ip {
                out.push(format!("{ip}:{port}"));
            }
        }
        out
    }

    /// Record whether the UI listener bound to loopback (set at serve time).
    pub async fn set_ui_loopback(&self, loopback: bool) {
        *self.ui_loopback.write().await = loopback;
    }

    /// Whether the cross-origin request gate is on: the `ui_check_cors`
    /// config key when set, else on for loopback binds only (a LAN/public
    /// bind is a deliberate multi-client deployment), like EpixNet.
    pub async fn ui_check_cors(&self) -> bool {
        match self.config_get("ui_check_cors").await {
            Some(v) => v.as_bool().unwrap_or_else(|| v.as_str() == Some("true")),
            None => *self.ui_loopback.read().await,
        }
    }

    /// EpixNet's `Site.clone`: copy the source xite's template files into a
    /// brand-new site (or a given target we own), rewrite content.json for
    /// the new owner, sign it with the new key, and serve it. Template
    /// convention: paths containing `-default` are the clean starting state -
    /// they are copied with the suffix stripped, and the source's live
    /// counterparts (e.g. `data/` next to `data-default/`) are NOT copied, so
    /// a cloned blog starts empty instead of with the author's posts.
    /// Returns the new site's address.
    pub async fn clone_xite(
        self: &Arc<Self>,
        source: &str,
        root_inner_path: &str,
        target_address: Option<String>,
    ) -> Result<String, String> {
        let src_storage = {
            let xites = self.xites.read().await;
            self.resolve_xite(&xites, source).map(|x| x.storage.clone()).ok_or("Unknown site")?
        };
        // Refuse mid-sync sources (EpixNet: "Site still in sync").
        let bad = self.bad_files(source).await;
        if bad.iter().any(|f| !f.ends_with("content.json") && !f.contains("data/users/")) {
            return Err("Site still in sync".into());
        }
        let root = root_inner_path.trim_matches('/');
        let prefix = if root.is_empty() { String::new() } else { format!("{root}/") };

        // The new owner's key: a fresh derivation, or the target's saved key.
        let (address, privatekey) = match target_address {
            Some(target) => {
                let key = self
                    .site_privatekey(&target)
                    .await
                    .ok_or("Target site private key not known")?;
                (target, key)
            }
            None => {
                let pair = self.user.write().await.new_site_data()?;
                self.save_user().await;
                pair
            }
        };

        // The template content.json: `<root>/content.json-default` wins (template
        // sites ship their clean copy there); otherwise fall back to the ROOT
        // content.json, NOT `<root>/content.json`. EpixNet's `Site.clone` does the
        // same - a clone root like `template-new/` holds only page files
        // (index.html), never its own content.json, so keying off the sub-path
        // there fails with "Source has no content.json".
        let template = src_storage
            .read(&format!("{prefix}content.json-default"))
            .or_else(|_| src_storage.read("content.json"))
            .map_err(|_| "Source has no content.json".to_string())?;
        let mut content: Value =
            serde_json::from_slice(&template).map_err(|_| "Invalid template content.json")?;
        let map = content.as_object_mut().ok_or("Invalid template content.json")?;
        for key in ["domain", "xid_name", "signs", "signers_sign", "address_index", "inner_path"] {
            map.remove(key);
        }
        // A `template-*` clone root is a blank starter, so it gets a generic
        // title rather than "My <source title>" (EpixNet's `Site.clone`).
        let new_title = if root.starts_with("template-") {
            "My New Epix Site".to_string()
        } else {
            let title = map.get("title").and_then(|v| v.as_str()).unwrap_or("New Epix Site");
            format!("My {title}")
        };
        map.insert("title".into(), json!(new_title));
        map.insert("cloned_from".into(), json!(source));
        if !root.is_empty() {
            map.insert("clone_root".into(), json!(root));
        }
        map.insert("address".into(), json!(address));
        map.insert("files".into(), json!({}));

        // Copy the files. Normal files are skipped when a `-default` variant
        // owns their target path; `-default` paths land de-suffixed.
        let dst_dir = self.xite_dir(&address).ok_or("No data root")?;
        std::fs::create_dir_all(&dst_dir).map_err(|e| e.to_string())?;
        let dst_storage = XiteStorage::new(&dst_dir);
        let files = src_storage.list_files();
        // Target prefixes owned by -default sources (e.g. `data-default/…`
        // owns `data/…`).
        let default_roots: Vec<String> = files
            .iter()
            .filter_map(|f| f.strip_prefix(&prefix))
            .filter(|rel| rel.contains("-default"))
            .filter_map(|rel| {
                rel.split("-default").next().map(|head| format!("{head}"))
            })
            .collect();
        for inner in &files {
            let Some(rel) = inner.strip_prefix(&prefix) else { continue };
            if rel == "content.json"
                || rel == "content.json-default"
                || rel.ends_with("-old")
                || rel.ends_with("-new")
            {
                continue;
            }
            let target_rel = if rel.contains("-default") {
                rel.replace("-default", "")
            } else if default_roots.iter().any(|d| !d.is_empty() && rel.starts_with(d.as_str())) {
                continue; // the -default variant supplies this tree
            } else {
                rel.to_string()
            };
            if let Ok(bytes) = src_storage.read(inner) {
                let _ = dst_storage.write(&target_rel, &bytes);
            }
        }
        if !dst_storage.exists("index.html") {
            let _ = dst_storage.write("index.html", b"<h1>My new site</h1>");
        }
        dst_storage
            .write("content.json", epix_content::dumps_content(&content).as_bytes())
            .map_err(|e| e.to_string())?;

        // Serve it, sign it as the new owner, and mark it ours.
        self.add_xite(&address, XiteEntry { storage: dst_storage, content: Some(content) }).await;
        self.sign_xite(&address, &privatekey).await?;
        self.set_owned(&address, true).await;
        self.log("INFO", format!("Cloned {source} -> {address} (root: {root:?})")).await;
        Ok(address)
    }

    /// Author a brand-new empty xite (`siteCreate`): a fresh key derived from
    /// the master seed, a starter index.html, a signed content.json, served
    /// and owned. Returns (address, privatekey WIF) - the caller shows the
    /// key to the author once.
    pub async fn create_xite(self: &Arc<Self>) -> Result<(String, String), String> {
        let (address, privatekey) = self.user.write().await.new_site_data()?;
        self.save_user().await;
        let dir = self.xite_dir(&address).ok_or("No data root")?;
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let storage = XiteStorage::new(&dir);
        storage
            .write(
                "index.html",
                format!(
                    "<!DOCTYPE html><html><body><h1>New Epix xite</h1>\
                     <p>{address}</p><p>Replace this page and run siteSign.</p></body></html>"
                )
                .as_bytes(),
            )
            .map_err(|e| e.to_string())?;
        let content = json!({ "address": address, "title": "My new xite", "files": {} });
        storage
            .write("content.json", epix_content::dumps_content(&content).as_bytes())
            .map_err(|e| e.to_string())?;
        self.add_xite(&address, XiteEntry { storage, content: Some(content) }).await;
        self.sign_xite(&address, &privatekey).await?;
        self.set_owned(&address, true).await;
        self.log("INFO", format!("Created new xite {address}")).await;
        Ok((address, privatekey))
    }

    /// Import a bundle (`importBundle`): a zip whose top-level directories are
    /// xite addresses (optionally under one wrapper directory). Each is
    /// extracted into the data dir, verified, and served. Returns the
    /// addresses that imported cleanly.
    pub async fn import_bundle(self: &Arc<Self>, bundle: &std::path::Path) -> Result<Vec<String>, String> {
        let file = std::fs::File::open(bundle).map_err(|e| e.to_string())?;
        let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        let root = self.data_root_path().ok_or("No data root")?.join("data");

        // A single non-address top-level dir wraps the real content.
        let tops: std::collections::HashSet<String> = (0..zip.len())
            .filter_map(|i| {
                let name = zip.by_index(i).ok()?.name().to_string();
                Some(name.split('/').next()?.to_string())
            })
            .filter(|t| !t.is_empty())
            .collect();
        let prefix = match tops.len() {
            1 => {
                let top = tops.iter().next().unwrap();
                if Address::parse(top.clone()).is_ok() { String::new() } else { format!("{top}/") }
            }
            _ => String::new(),
        };

        let mut addresses: std::collections::HashSet<String> = std::collections::HashSet::new();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
            if entry.is_dir() {
                continue;
            }
            let name = entry.name().to_string();
            let Some(rel) = name.strip_prefix(&prefix) else { continue };
            let Some((address, inner)) = rel.split_once('/') else { continue };
            if Address::parse(address.to_string()).is_err() || inner.is_empty() {
                continue;
            }
            // Extract via XiteStorage so path traversal is rejected.
            let storage = XiteStorage::new(root.join(address));
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).map_err(|e| e.to_string())?;
            storage.write(inner, &bytes).map_err(|e| e.to_string())?;
            addresses.insert(address.to_string());
        }

        // Verify + serve each imported xite; drop ones whose root fails.
        let mut imported = Vec::new();
        for address in addresses {
            if self.has_any_alias(&address).await {
                imported.push(address);
                continue;
            }
            let storage = XiteStorage::new(root.join(&address));
            let Ok(addr) = Address::parse(address.clone()) else { continue };
            let mut xite = Xite::new(addr, storage.clone());
            match xite.load_content() {
                Ok(true) => {
                    let content = xite.content.clone();
                    self.add_xite(&address, XiteEntry { storage, content }).await;
                    imported.push(address);
                }
                _ => {
                    self.log(
                        "WARNING",
                        format!("importBundle: {address} has no valid content.json, skipped"),
                    )
                    .await;
                }
            }
        }
        imported.sort();
        Ok(imported)
    }

    /// EpixNet's `QueryJson`: list rows from JSON files under a xite
    /// directory. `dir_inner_path` may hold one `*` segment
    /// (`data/users/*/data.json`); `query` is empty (whole file / the array
    /// at a dotted path) or `dotted.path=intval` filtering a list of objects.
    /// Each row carries `inner_path` (the wildcard match). `fileQuery`.
    pub async fn query_json_files(
        &self,
        address: &str,
        dir_inner_path: &str,
        query: &str,
    ) -> Vec<Value> {
        let storage = {
            let xites = self.xites.read().await;
            match self.resolve_xite(&xites, address) {
                Some(x) => x.storage.clone(),
                None => return Vec::new(),
            }
        };
        // Expand the single `*` wildcard against the file list.
        let matches: Vec<(String, String)> = if let Some((head, tail)) =
            dir_inner_path.split_once("*")
        {
            let head = head.to_string();
            let tail = tail.trim_start_matches('/').to_string();
            storage
                .list_files()
                .into_iter()
                .filter_map(|f| {
                    let rest = f.strip_prefix(&head)?;
                    let (dir, file) = rest.split_once('/')?;
                    (file == tail).then(|| (f.clone(), dir.to_string()))
                })
                .collect()
        } else {
            vec![(dir_inner_path.to_string(), String::new())]
        };

        let (filter_path, filter_val) = match query.split_once('=') {
            Some((p, v)) => (p.trim(), v.trim().parse::<i64>().ok()),
            None => (query.trim(), None),
        };
        let mut rows = Vec::new();
        for (inner, wildcard) in matches {
            let Ok(bytes) = storage.read(&inner) else { continue };
            let Ok(mut data) = serde_json::from_slice::<Value>(&bytes) else { continue };
            // Walk the dotted path.
            if !filter_path.is_empty() {
                for key in filter_path.split('.') {
                    data = match data.get(key) {
                        Some(v) => v.clone(),
                        None => Value::Null,
                    };
                }
            }
            match (&data, filter_val) {
                // A list filtered by `key=val` on the LAST path segment is
                // handled below; a plain list expands to rows.
                (Value::Array(items), None) => {
                    for item in items {
                        let mut row = item.clone();
                        if let Some(obj) = row.as_object_mut() {
                            obj.insert("inner_path".into(), json!(wildcard));
                        }
                        rows.push(row);
                    }
                }
                _ => {
                    if filter_val.is_some() {
                        // `list.key=val`: the path minus its last segment is
                        // the list, the last segment the field to match.
                        let mut parts: Vec<&str> = filter_path.split('.').collect();
                        let field = parts.pop().unwrap_or("");
                        let mut node = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
                        for key in &parts {
                            node = node.get(*key).cloned().unwrap_or(Value::Null);
                        }
                        if let Some(items) = node.as_array() {
                            for item in items {
                                if item.get(field).and_then(|v| v.as_i64()) == filter_val {
                                    let mut row = item.clone();
                                    if let Some(obj) = row.as_object_mut() {
                                        obj.insert("inner_path".into(), json!(wildcard));
                                    }
                                    rows.push(row);
                                }
                            }
                        }
                    } else if !data.is_null() {
                        let mut row = data.clone();
                        if let Some(obj) = row.as_object_mut() {
                            obj.insert("inner_path".into(), json!(wildcard));
                        }
                        rows.push(row);
                    }
                }
            }
        }
        rows
    }

    /// Files whose on-disk bytes differ from what the signed content.json
    /// declares - possibly-unsigned local changes (`siteListModifiedFiles`).
    /// Paths under an `includes` entry are separately-signed units and are
    /// skipped, like EpixNet.
    pub async fn list_modified_files(&self, address: &str) -> Vec<String> {
        let (storage, content) = {
            let xites = self.xites.read().await;
            match self.resolve_xite(&xites, address) {
                Some(x) => (x.storage.clone(), x.content.clone()),
                None => return Vec::new(),
            }
        };
        let Some(content) = content else { return Vec::new() };
        let include_dirs: Vec<String> = content
            .get("includes")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.keys()
                    .filter_map(|k| k.rsplit_once('/').map(|(d, _)| format!("{d}/")))
                    .collect()
            })
            .unwrap_or_default();
        let mut out = Vec::new();
        if let Some(files) = content.get("files").and_then(|v| v.as_object()) {
            for (rel, info) in files {
                if include_dirs.iter().any(|d| rel.starts_with(d.as_str())) {
                    continue;
                }
                let declared_size = info.get("size").and_then(|v| v.as_i64()).unwrap_or(-1);
                let declared_hash = info.get("sha512").and_then(|v| v.as_str()).unwrap_or("");
                match storage.read(rel) {
                    Err(_) => out.push(rel.clone()), // missing = modified
                    Ok(bytes) => {
                        if bytes.len() as i64 != declared_size
                            || XiteStorage::hash_bytes(&bytes) != declared_hash
                        {
                            out.push(rel.clone());
                        }
                    }
                }
            }
        }
        out
    }

    /// Set the one per-site settings key EpixNet lets a page change
    /// (`siteSetSettingsValue`): `modified_files_notification`.
    pub async fn set_modified_files_notification(&self, address: &str, value: bool) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.modified_files_notification = Some(value);
        }
        self.persist_sites().await;
    }

    /// Record a cert signature as bad (`badCert`): inbound user content
    /// carrying it is rejected from now on. In-memory, like a session-scoped
    /// revocation; the authoritative revocation is the parent's archive rules.
    pub fn add_bad_cert(&self, sign: &str) {
        self.bad_certs.lock().unwrap().insert(sign.to_string());
    }

    /// Whether a cert signature was marked bad this session.
    pub fn is_bad_cert(&self, sign: &str) -> bool {
        self.bad_certs.lock().unwrap().contains(sign)
    }

    /// Whether `source` (a served xite, by address or alias) holds the
    /// `Cors:<target>` permission - the grant that lets one xite read
    /// another's files cross-origin (EpixNet's `hasCorsPermission`).
    pub async fn has_cors_permission(&self, source: &str, target: &str) -> bool {
        let xites = self.xites.read().await;
        let Some(src) = self.resolve_xite(&xites, source) else { return false };
        // An ADMIN site can already read any site's files over the WS API
        // (fileGet et al.), so blocking its subresource loads adds no
        // security; allowing them lets the dashboard show other xites'
        // favicons without per-site Cors grants.
        if src.settings.permissions.iter().any(|p| p == "ADMIN") {
            return true;
        }
        let target_canonical = self
            .resolve_xite(&xites, target)
            .map(|x| canonical_address(x.content.as_ref(), target));
        src.settings.permissions.iter().any(|p| {
            p.strip_prefix("Cors:").is_some_and(|granted| {
                granted == target || Some(granted.to_string()) == target_canonical
            })
        })
    }

    /// Record our Reticulum mesh address (destination hash, hex).
    pub async fn set_rns_address(&self, hex: &str) {
        *self.rns_address.write().await = Some(hex.to_string());
    }

    /// Our mesh destination hash (hex), once the mesh is up.
    pub async fn rns_address(&self) -> Option<String> {
        self.rns_address.read().await.clone()
    }

    /// Record this build's short git commit (reported in `serverInfo.rev`).
    pub async fn set_rev(&self, rev: &str) {
        if !rev.is_empty() {
            *self.rev.write().await = rev.to_string();
        }
    }

    /// This build's short git commit (`serverInfo.rev`).
    pub async fn rev(&self) -> String {
        self.rev.read().await.clone()
    }

    /// Record the UI port actually bound (`serverInfo.ui_port`).
    pub async fn set_ui_port(&self, port: u16) {
        *self.ui_port.write().await = port;
    }

    /// The UI port actually bound.
    pub async fn ui_port(&self) -> u16 {
        *self.ui_port.read().await
    }

    /// Whether we answer `announce` as a tracker (config `tracker`, default on).
    /// Off disables recording/serving peers for other nodes.
    pub async fn tracker_enabled(&self) -> bool {
        match self.config_get("tracker").await {
            Some(v) => !matches!(v.as_str(), Some("disable") | Some("false") | Some("0")),
            None => true,
        }
    }

    /// Record `addr` in the tracker for each `hash` (announce server).
    pub async fn tracker_announce(&self, hashes: &[[u8; 32]], addr: &PeerAddr) {
        self.tracker.announce(hashes, addr, now_secs()).await;
    }

    /// Known tracker peers for `hash`, filtered as the announce request asked.
    pub async fn tracker_peer_list(
        &self,
        hash: &[u8; 32],
        exclude: &std::collections::HashSet<String>,
        limit: usize,
        need: crate::tracker::NeedTypes,
    ) -> Vec<PeerAddr> {
        self.tracker.peer_list(hash, exclude, limit, now_secs(), need).await
    }

    /// Drop stale tracker peers (called from the announce loop).
    pub async fn tracker_expire(&self) {
        self.tracker.expire(now_secs()).await;
    }

    /// `(hashes, peers)` the tracker currently holds, for the Stats page.
    pub async fn tracker_stats(&self) -> (usize, usize) {
        self.tracker.stats().await
    }

    /// Set the fileserver (seeding) port the node bound, for `serverInfo`.
    pub async fn set_fileserver_port(&self, port: u16) {
        *self.fileserver_port.write().await = port;
    }

    /// The fileserver (seeding) port, 0 if seeding is disabled.
    pub async fn fileserver_port(&self) -> u16 {
        *self.fileserver_port.read().await
    }

    /// The configured minimum log level (config `log_level`), default `INFO`.
    pub async fn log_level(&self) -> String {
        self.config_get("log_level")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "INFO".to_string())
    }

    /// Record the launch xite (name or address) as the node's homepage - where
    /// the wrapper's corner home button and the admin pages' back link go.
    pub fn set_homepage(&self, target: &str) {
        *self.launch_homepage.lock().unwrap() = Some(target.to_string());
    }

    /// The node's homepage xite: the launch target if recorded, else a served
    /// xite's human-readable name (display metadata or a legacy alias key),
    /// else the first served xite's address.
    pub async fn homepage(&self) -> Option<String> {
        if let Some(home) = self.launch_homepage.lock().unwrap().clone() {
            return Some(home);
        }
        let xites = self.xites.read().await;
        xites
            .values()
            .find_map(|x| x.display.clone())
            .or_else(|| xites.keys().find(|k| k.contains('.')).cloned())
            .or_else(|| xites.keys().next().cloned())
    }

    /// Replace a xite's content.json, refreshing its stats and rebuilding its db.
    pub async fn update_content(&self, address: &str, content: Option<Value>) {
        let muted = self.muted_authors().await;
        if let Some(x) = self.xites.write().await.get_mut(address) {
            if let Some(c) = &content {
                x.settings.apply_content_stats(&content_stats(c));
            }
            x.content = content;
            let (db, schema) = match build_xite_db(&x.storage, &muted) {
                Some((db, schema)) => (Some(db), Some(schema)),
                None => (None, None),
            };
            x.db = db;
            x.db_schema = schema;
        }
    }

    /// Every served key for the xite signed as `canonical` (the raw address
    /// plus any `.epix` alias). Falls back to `fallback` alone if the registry
    /// has no match.
    async fn alias_keys(&self, canonical: &str, fallback: &str) -> Vec<String> {
        let keys: Vec<String> = {
            let xites = self.xites.read().await;
            xites
                .iter()
                .filter(|(k, x)| {
                    k.as_str() == canonical
                        || canonical_address(x.content.as_ref(), k) == canonical
                })
                .map(|(k, _)| k.clone())
                .collect()
        };
        if keys.is_empty() {
            vec![fallback.to_string()]
        } else {
            keys
        }
    }

    /// Land a verified root content.json: when every file it declares is
    /// present (`failed` empty), commit it - atomic-rename the exact signed
    /// bytes over the stored content.json and adopt it under every alias key.
    /// Otherwise DEFER: keep the previous on-disk version authoritative (the
    /// node keeps serving a consistent site instead of a loading screen),
    /// record the missing paths in `settings.cache.bad_files`, and hold the
    /// update as a [`PendingUpdate`] for [`Self::retry_pending_updates`].
    /// Returns whether the update committed.
    async fn finalize_root_update(
        &self,
        keys: &[String],
        canonical: &str,
        storage: &XiteStorage,
        content: Value,
        bytes: &[u8],
        failed: &[String],
    ) -> bool {
        if failed.is_empty() {
            self.commit_root_update(keys, canonical, storage, content, bytes).await
        } else {
            self.defer_root_update(keys, canonical, content, bytes, failed).await;
            false
        }
    }

    /// The commit half of [`Self::finalize_root_update`]: atomic-rename the
    /// exact signed bytes over the stored content.json, drop any pending
    /// record, clear the bad-file counters, and adopt the new content under
    /// every alias key.
    async fn commit_root_update(
        &self,
        keys: &[String],
        canonical: &str,
        storage: &XiteStorage,
        content: Value,
        bytes: &[u8],
    ) -> bool {
        if let Err(e) = storage.write_atomic("content.json", bytes) {
            self.log("ERROR", format!("Committing content.json for {canonical} failed: {e}"))
                .await;
            return false;
        }
        self.pending_updates.lock().unwrap().remove(canonical);
        {
            let mut xites = self.xites.write().await;
            for k in keys {
                if let Some(x) = xites.get_mut(k) {
                    x.settings.cache.bad_files.clear();
                }
            }
        }
        for k in keys {
            self.update_content(k, Some(content.clone())).await;
        }
        true
    }

    /// The defer half of [`Self::finalize_root_update`]: record the missing
    /// paths in `settings.cache.bad_files` (the dashboard's bad-file warning)
    /// and hold the update as a [`PendingUpdate`] for
    /// [`Self::retry_pending_updates`].
    async fn defer_root_update(
        &self,
        keys: &[String],
        canonical: &str,
        content: Value,
        bytes: &[u8],
        failed: &[String],
    ) {
        self.log(
            "INFO",
            format!(
                "Update for {canonical} incomplete: {} file(s) not yet available; keeping the previous version and retrying",
                failed.len()
            ),
        )
        .await;
        {
            let mut xites = self.xites.write().await;
            for k in keys {
                if let Some(x) = xites.get_mut(k) {
                    for f in failed {
                        *x.settings.cache.bad_files.entry(f.clone()).or_insert(0) += 1;
                    }
                }
            }
        }
        let new_modified = content.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let mut pending = self.pending_updates.lock().unwrap();
        // Keep only the newest pending version per xite; a re-attempt of the
        // same version keeps its retry counter (the backoff keeps decaying).
        let (replace, tries) = match pending.get(canonical) {
            Some(p) => {
                let pm = p.content.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
                (pm <= new_modified, if pm == new_modified { p.tries } else { 0 })
            }
            None => (true, 0),
        };
        if replace {
            pending.insert(
                canonical.to_string(),
                PendingUpdate { keys: keys.to_vec(), content, bytes: bytes.to_vec(), tries },
            );
        }
    }

    /// Retry the pending (verified but uncommitted) root updates: re-fetch each
    /// one's still-missing files from connectable peers and commit the ones
    /// whose file set completed. Called from the periodic resync tick, with a
    /// decaying per-update retry probability so files nobody serves don't cost
    /// bandwidth every pass.
    pub async fn retry_pending_updates(&self) {
        let due: Vec<(Vec<String>, String, Value, Vec<u8>)> = {
            let mut pending = self.pending_updates.lock().unwrap();
            pending
                .iter_mut()
                .filter_map(|(canonical, p)| {
                    p.tries += 1;
                    retry_pending_allowed(p.tries).then(|| {
                        (p.keys.clone(), canonical.clone(), p.content.clone(), p.bytes.clone())
                    })
                })
                .collect()
        };
        for (keys, canonical, content, bytes) in due {
            if self.retry_pending_update(&keys, &canonical, content, &bytes).await {
                self.log("INFO", format!("Pending update for {} completed and committed", keys[0]))
                    .await;
                for k in &keys {
                    self.push_site_info_event(k, "updated").await;
                }
            }
        }
    }

    /// One retry pass for a single pending update: re-fetch its still-missing
    /// files and try to commit. Returns whether the update committed.
    async fn retry_pending_update(
        &self,
        keys: &[String],
        canonical: &str,
        content: Value,
        bytes: &[u8],
    ) -> bool {
        let key = &keys[0];
        if !self.has_xite(key).await {
            // The xite was deleted; drop its pending update.
            self.pending_updates.lock().unwrap().remove(canonical);
            return false;
        }
        if !self.is_serving(key).await {
            return false;
        }
        let Ok(view) = self.xite_view(key).await else { return false };
        let Ok(addr) = Address::parse(canonical.to_string()) else { return false };
        // A view staged at the pending content, so files_needed() reflects
        // the version we are trying to complete, not the served one.
        let mut xite = Xite::new(addr, view.storage.clone());
        xite.content = Some(content.clone());
        let needed = xite.files_needed();
        if !needed.is_empty() {
            self.fetch_pending_files(key, &xite, needed).await;
        }
        let failed: Vec<String> =
            xite.files_needed().iter().map(|f| f.inner_path.clone()).collect();
        self.finalize_root_update(keys, canonical, &view.storage, content, bytes, &failed).await
    }

    /// Fetch a pending update's missing files from connectable peers, updating
    /// the live worker stats. A no-op without a transport or peers - files
    /// that arrive some other way still let the caller's commit land.
    async fn fetch_pending_files(&self, key: &str, xite: &Xite, needed: Vec<epix_xite::FileEntry>) {
        let Some(transport) = self.transport.read().await.clone() else { return };
        let peers = self.connectable_peers(key, 10).await;
        if peers.is_empty() {
            return;
        }
        self.set_worker_stats(key, needed.len(), peers.len().min(8), needed.len()).await;
        let feedback = epix_worker::CollectFeedback::new();
        let report = epix_worker::sync_files_list(
            needed,
            xite,
            &peers,
            transport,
            8,
            None,
            Some(feedback.clone() as Arc<dyn epix_worker::PeerFeedback>),
        )
        .await;
        self.set_worker_stats(key, 0, 0, 0).await;
        let failed_files = report.as_ref().map(|r| r.failed.len()).unwrap_or(0);
        self.absorb_sync_outcomes(key, feedback.drain(), failed_files).await;
        if let Ok(report) = report {
            self.add_transfer(key, report.bytes, 0).await;
        }
    }

    /// Check a xite for a newer content.json among its peers and, if found,
    /// verify it and download the changed files (updating live worker stats).
    /// Returns true if an update was applied. This is the node's re-sync step.
    pub async fn resync_xite(&self, address: &str) -> Result<bool, String> {
        // A paused xite (sitePause) is not re-synced until resumed.
        if !self.is_serving(address).await {
            return Ok(false);
        }
        let transport = self.transport.read().await.clone().ok_or("no transport")?;
        let peers = self.connectable_peers(address, 10).await;
        if peers.is_empty() {
            return Ok(false);
        }
        let view = self.xite_view(address).await?;
        // Never resync a local working copy: a stored content.json that does
        // not verify for the address it is served under (authored here,
        // edited, or signed for a different address and not re-signed yet) is
        // authoritative locally. Its `address` field would point the fetch
        // below at a foreign xite, and we'd overwrite the local files with
        // that (older) content - exactly the "loads the old dashboard after a
        // minute" symptom. No stored content.json at all is fine: that's a
        // registered xite whose sync never committed, and resync is exactly
        // what heals it.
        if view.storage.exists("content.json") {
            let mut probe = Xite::new(
                Address::parse(address.to_string()).map_err(|e| e.to_string())?,
                view.storage.clone(),
            );
            if !probe.load_content().unwrap_or(false) {
                return Ok(false);
            }
        }
        let local_modified = view
            .content
            .as_ref()
            .and_then(|c| c.get("modified"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        // Peers key files by the signed content address, so fetch/verify under
        // that even when serving under a `.epix` alias.
        let canonical = canonical_address(view.content.as_ref(), address);

        for peer in &peers {
            // Bound each peer attempt so a slow/unresponsive peer doesn't
            // stall the whole update; overlay peers get the longer dial
            // deadline (a flat clearnet bound meant resync could never fetch
            // content.json from an onion/i2p peer). The nested Option
            // separates "dial/handshake failed" (outer None) from "connected
            // but the fetch failed" (inner None), and `progressed` marks a
            // handshake that succeeded before the deadline expired - so each
            // case feeds the registry its own outcome. Without this, probe
            // failures taught selection nothing and dead candidates were
            // redialed every pass. A reachable-but-unserving peer gets a
            // FileFail ONLY (reputation dock): ConnectOk would reset its
            // error count and freshen its response time, promoting a useless
            // peer above never-tried candidates in the selection tiebreak.
            let progressed = AtomicBool::new(false);
            let fetched = tokio::time::timeout(peer.connect_timeout(), async {
                let mut conn = Connection::connect(transport.as_ref(), peer).await.ok()?;
                conn.handshake().await.ok()?;
                progressed.store(true, Ordering::Relaxed);
                Some(conn.get_file(&canonical, "content.json").await.ok())
            })
            .await;
            let bytes = match fetched {
                Ok(Some(Some(bytes))) => bytes,
                // Alive but couldn't serve the file (or stalled mid-fetch):
                // dialable, deprioritized.
                Ok(Some(None)) => {
                    self.log("DEBUG", format!("resync {address}: {peer} had no content.json"))
                        .await;
                    self.apply_peer_outcomes(
                        address,
                        vec![(peer.clone(), epix_worker::PeerOutcome::FileFail)],
                    )
                    .await;
                    continue;
                }
                Err(_) if progressed.load(Ordering::Relaxed) => {
                    self.apply_peer_outcomes(
                        address,
                        vec![(peer.clone(), epix_worker::PeerOutcome::FileFail)],
                    )
                    .await;
                    continue;
                }
                Ok(None) | Err(_) => {
                    self.log("DEBUG", format!("resync {address}: {peer} unreachable")).await;
                    self.apply_peer_outcomes(
                        address,
                        vec![(peer.clone(), epix_worker::PeerOutcome::ConnectFail)],
                    )
                    .await;
                    continue;
                }
            };
            let Ok(new): std::result::Result<Value, _> = serde_json::from_slice(&bytes) else {
                // Answered with junk: deprioritize like a failed fetch.
                self.apply_peer_outcomes(
                    address,
                    vec![(peer.clone(), epix_worker::PeerOutcome::FileFail)],
                )
                .await;
                continue;
            };
            let new_modified = new.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
            // Served a valid content.json: the genuine positive signal.
            self.apply_peer_outcomes(
                address,
                vec![(peer.clone(), epix_worker::PeerOutcome::ConnectOk)],
            )
            .await;
            if new_modified <= local_modified {
                return Ok(false); // already current
            }

            // Verify the newer content.json (full signer/rules check,
            // size-limited) and STAGE it in memory only, then sync its changed
            // files against the staged version. The stored content.json - the
            // completeness marker the html gate keys on - is untouched until
            // every declared file lands, so an incomplete sync leaves the node
            // serving the previous consistent version instead of a loading
            // screen (the "content.json updated but files stale" hang).
            let mut xite = Xite::new(
                Address::parse(canonical.clone()).map_err(|e| e.to_string())?,
                view.storage.clone(),
            );
            let limit = self.size_limit_bytes(address).await;
            xite.stage_content_limited(&bytes, limit).map_err(|e| e.to_string())?;

            let needed = xite.files_needed().len();
            let workers = peers.len().min(8);
            self.set_worker_stats(address, needed, workers, needed).await;
            let feedback = epix_worker::CollectFeedback::new();
            let report = epix_worker::sync_files(
                &xite,
                &peers,
                transport.clone(),
                8,
                Some(feedback.clone() as Arc<dyn epix_worker::PeerFeedback>),
            )
            .await;
            // Always clear the live task counters - a leftover tasks>0 keeps
            // the dashboard row's "Updating" spinner stuck.
            self.set_worker_stats(address, 0, 0, 0).await;
            self.apply_peer_outcomes(address, feedback.drain()).await;
            let report = report.map_err(|e| e.to_string())?;
            self.add_transfer(address, report.bytes, 0).await;

            // Commit when complete, else defer (kept pending + retried by the
            // resync tick); either way the node serves a consistent version.
            let keys = self.alias_keys(&canonical, address).await;
            let failed: Vec<String> =
                xite.files_needed().iter().map(|f| f.inner_path.clone()).collect();
            let Some(content) = xite.content else { return Ok(false) };
            let committed = self
                .finalize_root_update(&keys, &canonical, &view.storage, content, &bytes, &failed)
                .await;
            return Ok(committed);
        }
        Ok(false)
    }

    /// Peer counts (connected/connectable/onion/local/total) for the sidebar.
    pub async fn peer_counts(&self, address: &str) -> PeerCounts {
        self.xites.read().await.get(address).map(|x| x.peers.counts()).unwrap_or_default()
    }

    /// Connectable peer addresses for a xite that this node can actually dial
    /// right now: filtered to the dialable networks, skipping peers in
    /// failure backoff, best first. Every sync/publish/PEX caller inherits
    /// the filter, so a clearnet-only node stops handing workers onion/i2p
    /// peers it can never reach.
    pub async fn connectable_peers(&self, address: &str, limit: usize) -> Vec<PeerAddr> {
        let nets = self.dialable_networks().await;
        self.xites
            .read()
            .await
            .get(address)
            .map(|x| x.peers.connectable_dialable(limit, nets, now_secs()))
            .unwrap_or_default()
    }

    /// Which peer networks this node can DIAL right now. Clearnet always (the
    /// base transport is TCP); onion when the Tor client is up - dialing
    /// needs no published onion service of our own; i2p when the I2P
    /// transport is composed in and the session reports Ready; rns when the
    /// mesh transport is up.
    pub async fn dialable_networks(&self) -> DialableNets {
        let (tor_enabled, tor_status) = self.tor_status().await;
        let onion = tor_enabled && matches!(tor_status.as_str(), "OK" | "Always");
        let i2p_ready = self
            .i2p_status()
            .await
            .get("phase")
            .and_then(|v| v.as_str())
            .map(|p| p == "Ready")
            .unwrap_or(false);
        let i2p = i2p_ready && self.i2p_transport.read().await.is_some();
        let rns = self.rns_transport.read().await.is_some();
        DialableNets { clearnet: true, onion, i2p, rns }
    }

    /// Apply a sync pass's outcomes and, when files are still missing, log
    /// one line saying what was tried. Without it a failing fetch is
    /// invisible: the worker skips bad peers silently and the operator only
    /// ever saw "N file(s) not yet available" with nothing to go on.
    async fn absorb_sync_outcomes(
        &self,
        key: &str,
        outcomes: Vec<(PeerAddr, epix_worker::PeerOutcome)>,
        failed_files: usize,
    ) {
        if failed_files > 0 {
            use epix_worker::PeerOutcome as O;
            let peers_tried: std::collections::HashSet<String> =
                outcomes.iter().map(|(p, _)| p.to_string()).collect();
            let count = |o: O| outcomes.iter().filter(|(_, x)| *x == o).count();
            self.log(
                "INFO",
                format!(
                    "Fetch pass for {key}: {failed_files} file(s) still missing after {} peer(s) tried ({} connect failures, {} file failures, {} files ok)",
                    peers_tried.len(),
                    count(O::ConnectFail),
                    count(O::FileFail),
                    count(O::FileOk),
                ),
            )
            .await;
        }
        self.apply_peer_outcomes(key, outcomes).await;
    }

    /// Apply a sync pass's per-peer outcomes (drained from an
    /// [`epix_worker::CollectFeedback`]) to a xite's peer registry: a
    /// success clears the backoff and rewards the peer, a failure docks its
    /// reputation and backs it off exponentially. This is what feeds
    /// [`Self::connectable_peers`]' ordering - without it reputation never
    /// moved and selection was effectively random.
    pub async fn apply_peer_outcomes(
        &self,
        address: &str,
        outcomes: Vec<(PeerAddr, epix_worker::PeerOutcome)>,
    ) {
        if outcomes.is_empty() {
            return;
        }
        let now = now_secs();
        if let Some(x) = self.xites.write().await.get_mut(address) {
            for (addr, outcome) in outcomes {
                let Some(p) = x.peers.get_mut(&addr) else { continue };
                match outcome {
                    epix_worker::PeerOutcome::ConnectOk => p.note_connect_ok(now),
                    epix_worker::PeerOutcome::ConnectFail => p.note_connect_fail(now),
                    epix_worker::PeerOutcome::FileOk => p.note_file_ok(now),
                    epix_worker::PeerOutcome::FileFail => p.note_file_fail(),
                }
            }
        }
    }

    /// Bytes transferred for a xite this run (recv, sent).
    pub async fn transfer(&self, address: &str) -> (u64, u64) {
        self.xites.read().await.get(address).map(|x| (x.bytes_recv, x.bytes_sent)).unwrap_or((0, 0))
    }

    /// Run a `dbQuery` against a xite's database. `params` is the JSON value the
    /// WS command carries (object = named binds, array = positional). Errors if
    /// the xite has no `dbschema.json`.
    pub async fn db_query(&self, address: &str, query: &str, params: &Value) -> Result<Vec<Value>, String> {
        // Clone the pooled DB handle out of the lock so the query doesn't hold it.
        let mut db = self.xites.read().await.get(address).and_then(|x| x.db.clone());
        if db.is_none() {
            // Lazy build, matching EpixNet's openDb: a dbQuery that arrives
            // before the db exists (a page served progressively mid-clone)
            // creates the schema and returns real (if still empty) rows.
            // Sites crash on an error here - their query callbacks iterate
            // the result - and their boot never recovers
            // EpixNet's needFile, WAIT for the schema (bounded) instead of
            // erroring - unless the root content.json is already known and
            // declares no dbschema.json, in which case a db will never exist.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                let (exists, declared) = {
                    let xites = self.xites.read().await;
                    match xites.get(address) {
                        Some(x) => (
                            x.storage.exists("dbschema.json"),
                            x.content.as_ref().map(|c| {
                                c.get("files").and_then(|f| f.get("dbschema.json")).is_some()
                            }),
                        ),
                        None => (false, Some(false)),
                    }
                };
                if exists {
                    self.rebuild_xite_db(address).await;
                    db = self.xites.read().await.get(address).and_then(|x| x.db.clone());
                    break;
                }
                if declared == Some(false) || std::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
        }
        let db = db.ok_or_else(|| "xite has no database".to_string())?;
        db.query_value(query, params).map_err(|e| e.to_string())
    }

    /// Every served xite's dbschema-declared feeds, with the xite's title:
    /// `(address, title, {feed_name: query})`. What `feedSearch` sweeps.
    pub async fn feed_sources(&self) -> Vec<(String, String, Vec<(String, String)>)> {
        let xites = self.xites.read().await;
        xites
            .iter()
            .filter_map(|(addr, x)| {
                let schema: Value =
                    serde_json::from_slice(&x.storage.read("dbschema.json").ok()?).ok()?;
                let feeds: Vec<(String, String)> = schema
                    .get("feeds")?
                    .as_object()?
                    .iter()
                    .filter_map(|(n, q)| Some((n.clone(), q.as_str()?.to_string())))
                    .collect();
                if feeds.is_empty() {
                    return None;
                }
                let title = x
                    .content
                    .as_ref()
                    .and_then(|c| c.get("title"))
                    .and_then(|t| t.as_str())
                    .unwrap_or(addr)
                    .to_string();
                Some((addr.clone(), title, feeds))
            })
            .collect()
    }

    /// Set (and persist) a site's Newsfeed follows.
    pub async fn set_feed_follow(&self, address: &str, feeds: Value) {
        self.user.write().await.set_feed_follow(address, feeds);
        self.save_user().await;
    }

    /// A site's Newsfeed follows.
    pub async fn feed_follow(&self, address: &str) -> Value {
        self.user.read().await.feed_follow(address)
    }

    /// All follows across sites (`site_address -> feeds`), for feed aggregation.
    pub async fn all_follows(&self) -> std::collections::HashMap<String, Value> {
        self.user.read().await.follows.clone()
    }

    /// All identity addresses this node's user controls: the master address
    /// plus every per-site auth address. xidResolve's fallback tries them all
    /// when the queried address is the user's own (EpixNet does the same, so
    /// an identity linked under any of the user's addresses is found).
    pub async fn user_all_addresses(&self) -> Vec<String> {
        let user = self.user.read().await;
        let mut out = vec![user.master_address.clone()];
        out.extend(user.sites.values().map(|s| s.auth_address.clone()));
        out
    }

    /// The user's CryptMessage encryption private key (WIF) for a xite.
    pub async fn user_encrypt_privatekey(&self, address: &str, index: u64) -> Result<String, String> {
        let mut user = self.user.write().await;
        // Ensure the site entry exists with the active cert attached (Python's
        // getSiteData does this implicitly) - the cert shifts the derivation.
        user.site_data(address)?;
        user.encrypt_privatekey(address, index)
    }

    /// The user's auth (identity) private key (WIF) for a xite - used by
    /// `ecdsaSign` when no explicit key is given.
    pub async fn user_auth_privatekey(&self, address: &str) -> Result<String, String> {
        self.user.write().await.site_data(address).map(|d| d.auth_privatekey.clone())
    }

    /// The user's auth (identity) address for a xite.
    pub async fn user_auth_address(&self, address: &str) -> Result<String, String> {
        self.user.write().await.auth_address(address)
    }

    // --- Certs (certAdd / certSelect / certSet / certList) ------------------

    /// Add a cert obtained from an ID provider, bound to the xite's current auth
    /// address, and (if newly added) select it globally. Returns:
    /// `Ok(Some(true))` added + selected, `Ok(None)` unchanged (identical),
    /// `Ok(Some(false))` a different cert exists for the domain (needs the user
    /// to confirm replacement). Persists on change.
    pub async fn cert_add(
        &self,
        address: &str,
        domain: &str,
        auth_type: &str,
        auth_user_name: &str,
        cert_sign: &str,
    ) -> Result<Option<bool>, String> {
        let mut user = self.user.write().await;
        let auth_address = user.auth_address(address)?;
        let res = user.add_cert(&auth_address, domain, auth_type, auth_user_name, cert_sign)?;
        if res == Some(true) {
            user.set_cert_global(Some(domain));
        }
        drop(user);
        if res == Some(true) {
            self.save_user().await;
        }
        Ok(res)
    }

    /// Replace an existing cert for `domain` (used after the user confirms the
    /// change prompt), then select it globally.
    pub async fn cert_replace(
        &self,
        address: &str,
        domain: &str,
        auth_type: &str,
        auth_user_name: &str,
        cert_sign: &str,
    ) -> Result<(), String> {
        let mut user = self.user.write().await;
        let auth_address = user.auth_address(address)?;
        user.delete_cert(domain);
        user.add_cert(&auth_address, domain, auth_type, auth_user_name, cert_sign)?;
        user.set_cert_global(Some(domain));
        drop(user);
        self.save_user().await;
        Ok(())
    }

    /// Select a cert domain on all sites (portable cert), or clear with an empty
    /// domain. `certSet`. Persists.
    pub async fn cert_set(&self, domain: &str) {
        let d = if domain.is_empty() { None } else { Some(domain) };
        self.user.write().await.set_cert_global(d);
        self.save_user().await;
    }

    /// The user's certs for `certList` (`[{auth_address, auth_type,
    /// auth_user_name, domain, selected}]`).
    pub async fn cert_list(&self, address: &str) -> Vec<Value> {
        self.user.write().await.cert_list(address)
    }

    /// Whether the user already holds a cert for `domain` (used by certAdd to
    /// decide whether to prompt for replacement).
    pub async fn has_cert(&self, domain: &str) -> bool {
        self.user.read().await.certs.contains_key(domain)
    }

    // --- xID cert (certXid) --------------------------------------------------

    /// The Epix chain's xID auth/linking site - where "New" and the
    /// not-yet-linked redirect send the user to link an identity address to
    /// their xID name. EpixNet's `xid_site`.
    const XID_SITE: &'static str = "epix1xauthduuyn63k6kj54jzgp4l8nnjlhrsyaku8c";

    /// Show the xID cert-selection dialog and act on the choice (EpixNet's
    /// `actionCertXid`). Discovers which of the user's addresses already map
    /// to a registered xID name on chain, offers them plus a "New" option
    /// that links a fresh identity, and on selection acquires (self-signs) the
    /// cert or redirects to the xID site to link. Returns the WS result the
    /// site's callback expects (`"ok"`, `"Not changed"`, or an error object).
    ///
    /// With `xid_name` set, skips the dialog and goes straight to acquisition
    /// (EpixNet's direct-name path).
    pub async fn cert_xid(&self, site_address: &str, xid_name: Option<&str>) -> Result<Value, String> {
        if let Some(name) = xid_name {
            return self.cert_xid_acquire(site_address, name, None).await;
        }

        let auth_address = self.user.write().await.auth_address(site_address)?;
        let (existing_cert, is_xid_active, identity_addresses) = {
            let user = self.user.read().await;
            let existing = user.certs.get("xid.epix").cloned();
            let active = user.get_cert(site_address).map(|c| c.auth_type == "xid").unwrap_or(false);
            (existing, active, user.identity_addresses())
        };
        let existing_name = existing_cert.as_ref().map(|c| c.auth_user_name.clone());

        // Discover linked xID names across the user's addresses. The site's
        // own auth address first, then each standalone identity - stopping at
        // the first UNLINKED identity, which becomes the "New" candidate.
        let mut discovered: Vec<(String, String)> = Vec::new(); // (name, address)
        let mut new_addr: Option<String> = None;
        self.push_inject_script(site_address, "$('#button-identity').text('Checking...')");
        if let Some(info) = epix_chain::xid_identity::resolve_identity(&auth_address).await {
            if existing_name.as_deref() != Some(info.name.as_str()) {
                discovered.push((info.name.clone(), auth_address.clone()));
            }
        }
        for addr in &identity_addresses {
            if *addr == auth_address {
                continue;
            }
            match epix_chain::xid_identity::resolve_identity(addr).await {
                Some(info) if existing_name.as_deref() != Some(info.name.as_str()) => {
                    discovered.push((info.name.clone(), addr.clone()));
                }
                Some(_) => {}
                None => {
                    new_addr = Some(addr.clone());
                    break;
                }
            }
        }
        self.push_inject_script(site_address, "$('#button-identity').text('Change')");

        // No spare unlinked identity: mint one so "New" always has an address.
        let new_addr = match new_addr {
            Some(a) => a,
            None => {
                let (addr, _pk) = self.user.write().await.generate_new_identity_address()?;
                self.save_user().await;
                addr
            }
        };

        // Build the picker (EpixNet's dialog markup + classes/titles).
        let mut body = String::from(
            "<span style='padding-bottom: 5px; display: inline-block'>\
             Select the xID account you want to use on this site:</span>",
        );
        let none_current = if is_xid_active { "" } else { " <small>(currently selected)</small>" };
        let none_active = if is_xid_active { "" } else { " active" };
        body.push_str(&format!(
            "<a href='#Select+account' class='select select-close cert{none_active}' title=''>\
             <b>None</b>{none_current}</a>"
        ));
        if let Some(name) = &existing_name {
            if !name.is_empty() {
                let cur = if is_xid_active { " <small>(currently selected)</small>" } else { "" };
                let act = if is_xid_active { " active" } else { "" };
                body.push_str(&format!(
                    "<a href='#Select+account' class='select select-close cert{act}' title='xid.epix'>\
                     <b>{}@xid.epix</b>{cur}</a>",
                    html_escape(name)
                ));
            }
        }
        for (name, addr) in &discovered {
            body.push_str(&format!(
                "<a href='#Select+account' class='select select-close cert' title='acquire:{}:{}'>\
                 <b>{}.epix</b> <small>(acquire certificate)</small></a>",
                html_escape(name), html_escape(addr), html_escape(name)
            ));
        }
        let short = if new_addr.len() > 14 {
            format!("{}...{}", &new_addr[..10], &new_addr[new_addr.len() - 4..])
        } else {
            new_addr.clone()
        };
        let new_link = format!(
            "/{}/?linkIdentity={}&returnTo=/{}",
            Self::XID_SITE, new_addr, site_address
        );
        body.push_str(&format!(
            "<a href='{new_link}' target='_top' class='select'>\
             <b>New</b> {short} <small>Register &raquo;</small></a>"
        ));

        // Ask, then act on the clicked option's title.
        let choice = self.notification_ask(site_address, &body).await;
        match choice.as_deref() {
            // "New" is a plain navigation link (no `.cert` class), so it never
            // resolves the callback - the wrapper just follows the href.
            None => Ok(Value::from("Not changed")),
            Some("") => {
                // None: drop the global xID cert.
                self.user.write().await.set_cert_global(None);
                self.save_user().await;
                self.push_cert_changed(site_address).await;
                Ok(Value::from("ok"))
            }
            Some("xid.epix") => {
                self.user.write().await.set_cert_global(Some("xid.epix"));
                self.save_user().await;
                self.push_cert_changed(site_address).await;
                Ok(Value::from("ok"))
            }
            Some(choice) if choice.starts_with("acquire:") => {
                let parts: Vec<&str> = choice.splitn(3, ':').collect();
                if parts.len() == 3 {
                    self.cert_xid_acquire(site_address, parts[1], Some(parts[2])).await
                } else {
                    Err("Invalid acquire choice".to_string())
                }
            }
            Some(_) => Ok(Value::from("Not changed")),
        }
    }

    /// Acquire (self-sign) an xID cert for `xid_name`, verifying on chain that
    /// the auth address is an active linked identity of that name. If it isn't
    /// linked, offers to open the xID site to link it. EpixNet's
    /// `_processCertXid`. `linked_auth_address` overrides the site's own auth
    /// address (when the identity was discovered under a different one).
    async fn cert_xid_acquire(
        &self,
        site_address: &str,
        xid_name: &str,
        linked_auth_address: Option<&str>,
    ) -> Result<Value, String> {
        let name = xid_name.trim().to_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .enumerate()
                .all(|(i, c)| c.is_ascii_lowercase() || c.is_ascii_digit() || (i > 0 && c == b'-'))
        {
            return Err("Invalid xID name".to_string());
        }

        // Resolve the auth address + its private key to sign the cert.
        let (auth_address, privatekey) = match linked_auth_address {
            Some(addr) => {
                let pk = self
                    .user
                    .read()
                    .await
                    .privatekey_for(addr)
                    .ok_or("No private key for the linked identity")?;
                (addr.to_string(), pk)
            }
            None => {
                let mut user = self.user.write().await;
                let sd = user.site_data(site_address)?.clone();
                (sd.auth_address, sd.auth_privatekey)
            }
        };

        // Verify on chain: the name resolves and this address is an ACTIVE
        // linked identity of it. Uses the full snapshot (identities + active).
        let (label, tld) = name.rsplit_once('.').unwrap_or((name.as_str(), "epix"));
        let domain = match epix_chain::shared_resolver().resolve(label, tld).await {
            Ok(d) => d,
            Err(_) => {
                return Ok(json!({ "error": format!("xID name '{name}' not found on chain") }))
            }
        };
        let linked = domain
            .identities
            .iter()
            .any(|i| i.address == auth_address && i.active);
        if !linked {
            // Offer to open the xID site to link this address.
            let url = format!(
                "/{}/?linkIdentity={}&returnTo=/{}",
                Self::XID_SITE, auth_address, site_address
            );
            let body = format!(
                "Your address is not linked as an identity for <b>{}.{}</b>.<br><br>\
                 Open the xID site to link it?",
                html_escape(label), html_escape(tld)
            );
            if self.confirm(site_address, &body, "Open xID").await {
                self.push_redirect(site_address, &url);
            }
            return Ok(json!({ "error": "identity_not_linked", "auth_address": auth_address }));
        }

        // Self-signed cert: sign "<auth_address>#xid/<name>" with the auth key.
        let cert_subject = format!("{auth_address}#xid/{label}");
        let cert_sign = epix_crypt::sign_keccak(&cert_subject, &privatekey)
            .map_err(|e| format!("Failed to sign certificate: {e}"))?;

        let mut user = self.user.write().await;
        match user.add_cert(&auth_address, "xid.epix", "xid", label, &cert_sign)? {
            Some(true) => {
                user.set_cert_global(Some("xid.epix"));
                drop(user);
                self.save_user().await;
                self.push_notification(
                    "done",
                    &format!("xID certificate acquired: {label}@xid.epix"),
                    5000,
                );
                self.push_cert_changed(site_address).await;
                Ok(Value::from("ok"))
            }
            Some(false) => {
                // A different xID cert exists: confirm replacement.
                drop(user);
                let body = "You already have an xID cert. Replace it?".to_string();
                if !self.confirm(site_address, &body, "Replace").await {
                    return Ok(Value::from("Not changed"));
                }
                let mut user = self.user.write().await;
                user.delete_cert("xid.epix");
                user.add_cert(&auth_address, "xid.epix", "xid", label, &cert_sign)?;
                user.set_cert_global(Some("xid.epix"));
                drop(user);
                self.save_user().await;
                self.push_notification(
                    "done",
                    &format!("xID certificate updated: {label}@xid.epix"),
                    5000,
                );
                self.push_cert_changed(site_address).await;
                Ok(Value::from("ok"))
            }
            None => {
                // Identical cert already present: just select it.
                user.set_cert_global(Some("xid.epix"));
                drop(user);
                self.save_user().await;
                self.push_cert_changed(site_address).await;
                Ok(Value::from("ok"))
            }
        }
    }

    /// Push a `notification ["ask", body]` dialog and wire its option links to
    /// resolve with the clicked link's `title`, awaiting the user's choice
    /// (EpixNet's cert dialog: a `notification` plus an `injectScript` that
    /// binds `.select.cert` clicks to `epixframe.response`). `None` on
    /// timeout, dismissal, or a non-`.cert` link (e.g. "New" navigates away).
    async fn notification_ask(&self, address: &str, body: &str) -> Option<String> {
        let id = self.nonce_counter.fetch_add(1, Ordering::Relaxed) as i64;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.callbacks.lock().unwrap().insert(id, tx);
        let payload =
            json!({ "cmd": "notification", "params": ["ask", body], "id": id }).to_string();
        let _ = self.events.send(UiEvent {
            channel: None,
            target: Some(address.to_string()),
            payload,
            exclude: None,
            only: None,
        });
        // Bind the dialog's `.select.cert` options to answer with their title.
        // The wrapper renders a `notification` under `.notification-ws-<id>`.
        let script = format!(
            "$('.notification .select.cert').off('click.certxid').on('click.certxid', function() {{ \
               $('.notification .select').removeClass('active'); \
               epixframe.response({id}, $(this).attr('title') || ''); \
               return false; }})"
        );
        self.push_inject_script(address, &script);
        match tokio::time::timeout(std::time::Duration::from_secs(180), rx).await {
            Ok(Ok(Value::String(s))) => Some(s),
            Ok(Ok(v)) if !v.is_null() => Some(v.to_string()),
            _ => None,
        }
    }

    /// Notify the site (and its wrapper) that the selected cert changed, so the
    /// page re-renders its identity - EpixNet's `updateWebsocket(cert_changed)`.
    async fn push_cert_changed(&self, address: &str) {
        let mut info = self.site_info(address).await;
        if let Value::Object(m) = &mut info {
            m.insert("event".to_string(), json!(["cert_changed", "xid.epix"]));
            self.push_event("setSiteInfo", info, Some("siteChanged"), Some(address.to_string()));
        }
    }

    /// The configured Epix chain RPC URL (Vrf / XidResolver), or the default.
    pub async fn chain_rpc_url(&self) -> String {
        self.config_get("chain_rpc_url")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| epix_chain::DEFAULT_RPC_URL.to_string())
    }

    /// The user's CryptMessage encryption public key (compressed SEC1) for a xite.
    pub async fn user_encrypt_publickey(&self, address: &str, index: u64) -> Result<Vec<u8>, String> {
        let pk = self.user_encrypt_privatekey(address, index).await?;
        epix_crypt::private_to_compressed_pubkey(&pk)
    }

    // --- ContentFilter: mutes + siteblocks -----------------------------------

    async fn save_filters(&self) {
        if let Some(path) = &self.filters_path {
            if let Ok(bytes) = serde_json::to_vec_pretty(&*self.filters.read().await) {
                let _ = std::fs::write(path, bytes);
            }
        }
    }

    /// Mute an author. `auth_address -> {cert_user_id, reason, date_added}`.
    pub async fn mute_add(&self, auth_address: &str, cert_user_id: &str, reason: &str) {
        {
            let mut f = self.filters.write().await;
            f["mutes"][auth_address] =
                json!({ "cert_user_id": cert_user_id, "reason": reason, "date_added": now_secs() });
        }
        self.save_filters().await;
        // Rebuild dbs so the muted author's content drops out (ContentFilter).
        self.rebuild_all_dbs().await;
    }

    pub async fn mute_remove(&self, auth_address: &str) {
        if let Some(m) = self.filters.write().await["mutes"].as_object_mut() {
            m.remove(auth_address);
        }
        self.save_filters().await;
        // Rebuild dbs so the un-muted author's content comes back.
        self.rebuild_all_dbs().await;
    }

    /// Rebuild every served xite's database (e.g. after a mute change), so the
    /// mute filter is re-applied across all sites.
    async fn rebuild_all_dbs(&self) {
        for address in self.xite_addresses().await {
            self.rebuild_xite_db(&address).await;
        }
    }

    /// The mute map (`auth_address -> info`).
    pub async fn mute_list(&self) -> Value {
        self.filters.read().await["mutes"].clone()
    }

    /// Block a site. `site_address -> {reason, date_added}`.
    pub async fn siteblock_add(&self, site_address: &str, reason: &str) {
        {
            let mut f = self.filters.write().await;
            f["siteblocks"][site_address] = json!({ "reason": reason, "date_added": now_secs() });
        }
        self.save_filters().await;
    }

    pub async fn siteblock_remove(&self, site_address: &str) {
        if let Some(m) = self.filters.write().await["siteblocks"].as_object_mut() {
            m.remove(site_address);
        }
        self.save_filters().await;
    }

    /// The siteblock map (`site_address -> info`).
    pub async fn siteblock_list(&self) -> Value {
        self.filters.read().await["siteblocks"].clone()
    }

    /// Whether a site is blocked.
    pub async fn siteblock_get(&self, site_address: &str) -> Value {
        self.filters.read().await["siteblocks"].get(site_address).cloned().unwrap_or(Value::Bool(false))
    }

    /// The block reason for a site, if it is blocked (`ContentFilter` enforcement
    /// point). Checks both the plain address and its `sha256` hash, matching
    /// EpixNet's hashed-address blocklists.
    pub async fn siteblock_reason(&self, site_address: &str) -> Option<String> {
        if !self.plugin_enabled("ContentFilter").await {
            return None;
        }
        let hashed = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(site_address.as_bytes()))
        };
        let f = self.filters.read().await;
        let blocks = &f["siteblocks"];
        for key in [site_address, hashed.as_str()] {
            if let Some(info) = blocks.get(key) {
                return Some(
                    info.get("reason").and_then(|r| r.as_str()).unwrap_or("").to_string(),
                );
            }
        }
        None
    }

    /// The muted authors' auth-addresses (`ContentFilter` enforcement point).
    /// Content signed by these is excluded when (re)building a xite's database.
    /// Empty while the ContentFilter plugin is toggled off - mutes stay stored
    /// but stop applying, like disabling the plugin in EpixNet.
    pub async fn muted_authors(&self) -> Vec<String> {
        if !self.plugin_enabled("ContentFilter").await {
            return Vec::new();
        }
        self.filters.read().await["mutes"]
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    // --- OptionalManager -----------------------------------------------------

    /// Reconstruct a `Xite` view (address + storage + content) for file ops.
    async fn xite_view(&self, address: &str) -> Result<Xite, String> {
        let (storage, content) = {
            let x = self.xites.read().await;
            let e = x.get(address).ok_or("unknown xite")?;
            (e.storage.clone(), e.content.clone())
        };
        // Parse the signed content address, so a `.epix` alias (not a valid
        // address itself) still yields a usable Xite.
        let canonical = canonical_address(content.as_ref(), address);
        let mut xite = Xite::new(Address::parse(canonical).map_err(|e| e.to_string())?, storage);
        xite.content = content;
        Ok(xite)
    }

    /// The raw content.json entry declaring `inner_path`: the root content.json
    /// first, then the child content.json governing the path (user content
    /// declares its files in `data/users/<auth>/content.json`, which a
    /// root-only lookup misses). Returns `(entry, dir, optional)` where `dir`
    /// is the declaring content.json's directory (`""` for the root) - paths
    /// inside the entry (e.g. a bigfile's `piecemap`) are relative to it.
    async fn declared_entry(&self, address: &str, inner_path: &str) -> Option<(Value, String, bool)> {
        let content = self.content(address).await;
        for (section, optional) in [("files", false), ("files_optional", true)] {
            let entry =
                content.as_ref().and_then(|c| c.get(section)).and_then(|f| f.get(inner_path));
            if let Some(entry) = entry {
                return Some((entry.clone(), String::new(), optional));
            }
        }
        let governing = self.content_inner_path(address, inner_path).await;
        let (dir, _) = governing.rsplit_once('/')?; // the root was searched above
        let storage = self.xites.read().await.get(address).map(|x| x.storage.clone())?;
        let child: Value = serde_json::from_slice(&storage.read(governing.as_str()).ok()?).ok()?;
        let rel = inner_path.strip_prefix(&format!("{dir}/"))?;
        for (section, optional) in [("files", false), ("files_optional", true)] {
            if let Some(entry) = child.get(section).and_then(|f| f.get(rel)) {
                return Some((entry.clone(), dir.to_string(), optional));
            }
        }
        None
    }

    /// Info for one declared file - required or optional, found through the
    /// root or its governing child content.json - as a site-relative
    /// [`FileEntry`], plus whether it is optional.
    pub async fn file_info_any(&self, address: &str, inner_path: &str) -> Option<(FileEntry, bool)> {
        let (entry, _, optional) = self.declared_entry(address, inner_path).await?;
        Some((
            FileEntry {
                inner_path: inner_path.to_string(),
                size: entry.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
                sha512: entry.get("sha512").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            },
            optional,
        ))
    }

    /// Download a file (required or optional) on demand from peers, verifying
    /// its hash before writing. `fileNeed`. Returns true if present after.
    pub async fn file_need(&self, address: &str, inner_path: &str) -> Result<bool, String> {
        let (entry, _, optional) = self
            .declared_entry(address, inner_path)
            .await
            .ok_or("file not declared in content.json")?;
        let info = FileEntry {
            inner_path: inner_path.to_string(),
            size: entry.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
            sha512: entry.get("sha512").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        };
        // A multi-piece big file's declared sha512 is a merkle root over its
        // pieces - a whole-file flat hash never matches it, neither for the
        // on-disk check nor for a fetched blob.
        let is_bigfile = entry.get("piecemap").is_some();
        let storage = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.clone())
            .ok_or("unknown xite")?;
        if !is_bigfile && storage.verify(inner_path, &info.sha512) {
            return Ok(true); // already have it
        }
        // Coalesce concurrent requests for the same file (a page asks for the
        // same avatar once per post): later callers wait on the first fetch,
        // then the verify re-check below makes them a no-op.
        let key = (address.to_string(), inner_path.to_string());
        let lock = {
            let mut locks = self.file_need_locks.lock().unwrap();
            locks.entry(key.clone()).or_default().clone()
        };
        // Remove the map entry from a Drop guard, not a statement after the
        // fetch: serve_file wraps this future in a timeout, and a cancelled
        // fetch would otherwise leak its entry.
        struct Cleanup<'a> {
            locks: &'a std::sync::Mutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>,
            key: (String, String),
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                self.locks.lock().unwrap().remove(&self.key);
            }
        }
        let _cleanup = Cleanup { locks: &self.file_need_locks, key };
        let _guard = lock.lock().await;
        async {
            if is_bigfile {
                // Fetch the missing pieces, each verified against the
                // piecemap (EpixNet needFile's Bigfile path). Boxed: the
                // piecemap itself downloads through file_need.
                Box::pin(self.bigfile_fetch_range(address, inner_path, 0, info.size.max(0) as u64))
                    .await?;
                return Ok(true);
            }
            if storage.verify(inner_path, &info.sha512) {
                return Ok(true); // fetched by the caller we waited on
            }
            self.fetch_file_from_peers(address, &info, optional, &storage).await
        }
        .await
    }

    /// Ask each connectable peer for the file until one hands over a blob
    /// matching the declared hash, then write it and do the optional-file
    /// bookkeeping. The fetch half of [`file_need`](Self::file_need).
    async fn fetch_file_from_peers(
        &self,
        address: &str,
        info: &FileEntry,
        optional: bool,
        storage: &XiteStorage,
    ) -> Result<bool, String> {
        let transport = self.transport.read().await.clone().ok_or("no transport")?;
        let peers = self.connectable_peers(address, 20).await;
        for peer in peers {
            let Ok(mut conn) = Connection::connect(transport.as_ref(), &peer).await else {
                continue;
            };
            if conn.handshake().await.is_err() {
                continue;
            }
            let Ok(bytes) = conn.get_file(address, &info.inner_path).await else { continue };
            if XiteStorage::hash_bytes(&bytes) != info.sha512 {
                continue;
            }
            storage.write(&info.inner_path, &bytes).map_err(|e| e.to_string())?;
            self.set_peer_connected(address, &peer, true).await;
            // Count optional bytes downloaded and advertise it in our
            // hashfield so peers can discover we now hold it.
            if optional {
                if let Some(x) = self.xites.write().await.get_mut(address) {
                    x.settings.optional_downloaded += info.size;
                    x.hashfield.add_hash(&info.sha512);
                }
            }
            return Ok(true);
        }
        Err("could not fetch the file from any peer".into())
    }

    /// List optional files with their state. `filter` = "downloaded" (default)
    /// or anything else for all. `optionalFileList`.
    pub async fn optional_file_list(&self, address: &str, filter: &str) -> Result<Vec<Value>, String> {
        let xite = self.xite_view(address).await?;
        let pinned = self.xites.read().await.get(address).map(|x| x.pinned.clone()).unwrap_or_default();
        let only_downloaded = filter == "downloaded";
        Ok(xite
            .optional_files()
            .into_iter()
            .filter_map(|f| {
                let is_downloaded = xite.storage.verify(&f.inner_path, &f.sha512);
                if only_downloaded && !is_downloaded {
                    return None;
                }
                Some(json!({
                    "inner_path": f.inner_path,
                    "size": f.size,
                    "sha512": f.sha512,
                    "is_downloaded": is_downloaded,
                    "is_pinned": pinned.contains(&f.inner_path),
                }))
            })
            .collect())
    }

    /// Info for one optional file, or null. `optionalFileInfo`. For a big file
    /// (>1MB with a `piecemap`) it also carries the piece layout (Bigfile).
    pub async fn optional_file_info(&self, address: &str, inner_path: &str) -> Result<Value, String> {
        let mut info = self
            .optional_file_list(address, "all")
            .await?
            .into_iter()
            .find(|f| f["inner_path"] == inner_path)
            .unwrap_or(Value::Null);
        if info.is_null() {
            info = self.child_optional_info(address, inner_path).await?;
        }
        if let Value::Object(map) = &mut info {
            // Cosmetic parity with EpixNet's file_optional db row: count
            // ourselves as the one known peer once the file is downloaded.
            let downloaded = map.get("is_downloaded").and_then(|v| v.as_bool()).unwrap_or(false);
            map.insert("peer".into(), json!(u8::from(downloaded)));
            self.add_bigfile_fields(address, inner_path, map).await;
        }
        Ok(info)
    }

    /// Optional-file info from the governing child content.json, for the files
    /// the root scan misses: user content declares its optional files in
    /// `data/users/<auth>/content.json`. Null when undeclared or not optional.
    async fn child_optional_info(&self, address: &str, inner_path: &str) -> Result<Value, String> {
        let Some((f, true)) = self.file_info_any(address, inner_path).await else {
            return Ok(Value::Null);
        };
        let (storage, is_pinned) = {
            let xites = self.xites.read().await;
            let x = xites.get(address).ok_or("unknown xite")?;
            (x.storage.clone(), x.pinned.contains(inner_path))
        };
        Ok(json!({
            "inner_path": f.inner_path,
            "size": f.size,
            "sha512": f.sha512,
            "is_downloaded": storage.verify(inner_path, &f.sha512),
            "is_pinned": is_pinned,
        }))
    }

    /// Add the Bigfile piece layout to an optional-file info object when the
    /// entry is >1MB and declared with a `piecemap`.
    async fn add_bigfile_fields(
        &self,
        address: &str,
        inner_path: &str,
        map: &mut serde_json::Map<String, Value>,
    ) {
        let size = map["size"].as_i64().unwrap_or(0);
        if size <= 1024 * 1024 {
            return;
        }
        let Some((entry, dir, _)) = self.declared_entry(address, inner_path).await else {
            return;
        };
        let piece_size = entry.get("piece_size").and_then(|v| v.as_i64()).unwrap_or(1024 * 1024);
        let piece_num = (size + piece_size - 1) / piece_size.max(1);
        map.insert("is_bigfile".into(), json!(true));
        map.insert("piece_size".into(), json!(piece_size));
        map.insert("piece_num".into(), json!(piece_num));
        // A child content.json's piecemap path is relative to its own dir -
        // return it site-relative like everything else.
        if let Some(pm) = entry.get("piecemap").and_then(|v| v.as_str()) {
            let pm = if dir.is_empty() { pm.to_string() } else { format!("{dir}/{pm}") };
            map.insert("piecemap".into(), json!(pm));
        }
    }

    /// On-disk size of a xite file (for HTTP Range / Content-Range).
    pub async fn file_size(&self, address: &str, inner_path: &str) -> Option<u64> {
        let storage = self.xites.read().await.get(address)?.storage.clone();
        let path = storage.path(inner_path).ok()?;
        std::fs::metadata(path).ok().map(|m| m.len())
    }

    /// The declared size of a big file (an entry carrying a `piecemap`), or
    /// `None` when `inner_path` isn't one. Lets the HTTP Range path serve a
    /// big file that has no sparse file on disk yet.
    pub async fn bigfile_total(&self, address: &str, inner_path: &str) -> Option<u64> {
        let (entry, _, _) = self.declared_entry(address, inner_path).await?;
        entry.get("piecemap")?;
        Some(entry.get("size").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u64)
    }

    /// Ensure the pieces covering `[offset, offset+size)` of a big file are
    /// present, downloading only the missing ones from peers and verifying each
    /// against the piecemap before writing it into the sparse file. A no-op for
    /// files that aren't big files. This is true piecewise Bigfile download.
    pub async fn bigfile_fetch_range(
        &self,
        address: &str,
        inner_path: &str,
        offset: u64,
        size: u64,
    ) -> Result<(), String> {
        let Some((entry, dir, optional)) = self.declared_entry(address, inner_path).await else {
            return Ok(()); // not declared -> nothing to do
        };
        let Some(piecemap_path) = entry.get("piecemap").and_then(|v| v.as_str()) else {
            return Ok(()); // not a big file
        };
        // A child content.json's piecemap path is relative to its own dir.
        let piecemap_path =
            if dir.is_empty() { piecemap_path.to_string() } else { format!("{dir}/{piecemap_path}") };
        let piece_size = entry.get("piece_size").and_then(|v| v.as_i64()).unwrap_or(1024 * 1024) as u64;
        let total = entry.get("size").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
        if piece_size == 0 || total == 0 || size == 0 {
            return Ok(());
        }

        let storage = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.clone())
            .ok_or("unknown xite")?;

        // The piecemap is itself a (small) optional file - fetch it if missing.
        if !storage.exists(&piecemap_path) {
            self.file_need(address, &piecemap_path).await?;
        }
        let pm_bytes = storage.read(&piecemap_path).map_err(|e| e.to_string())?;
        let file_name = inner_path.rsplit('/').next().unwrap_or(inner_path);
        let hashes = epix_xite::parse_piecemap(&pm_bytes, file_name).ok_or("malformed piecemap")?;

        ensure_sparse_file(&storage, inner_path, total)?;

        let last_byte = (offset + size - 1).min(total - 1);
        let (first, last) = (offset / piece_size, last_byte / piece_size);
        let transport = self.transport.read().await.clone();
        let peers = self.connectable_peers(address, 20).await;

        // Piece-aware peer selection (Bigfile piecefields): for a multi-piece
        // fetch, ask each peer up front which pieces of this file it holds, so we
        // skip peers that don't have a given piece. `sha512` keys the piecefield.
        let sha512 = entry.get("sha512").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mut peer_pf: std::collections::HashMap<String, epix_xite::Piecefield> =
            std::collections::HashMap::new();
        if last > first {
            if let Some(t) = &transport {
                for peer in &peers {
                    if let Ok(mut conn) = Connection::connect(t.as_ref(), peer).await {
                        if conn.handshake().await.is_ok() {
                            if let Ok(map) = conn.get_piecefields(address).await {
                                if let Some(bytes) = map.get(&sha512) {
                                    peer_pf.insert(peer.to_string(), epix_xite::Piecefield::unpack(bytes));
                                }
                            }
                        }
                    }
                }
            }
        }

        for i in first..=last {
            let poff = i * piece_size;
            let plen = piece_size.min(total - poff);
            let expected = hashes.get(i as usize).ok_or("piece index past piecemap")?;
            if piece_present(&storage, inner_path, poff, plen, expected) {
                continue;
            }
            let transport = transport.clone().ok_or("no transport")?;
            let mut got = false;
            for peer in &peers {
                // Skip peers we know (from their piecefield) don't have this piece.
                if let Some(pf) = peer_pf.get(&peer.to_string()) {
                    if !pf.get(i as usize) {
                        continue;
                    }
                }
                let Ok(mut conn) = Connection::connect(transport.as_ref(), peer).await else { continue };
                if conn.handshake().await.is_err() {
                    continue;
                }
                let Ok(data) = conn.get_file_range(address, inner_path, poff, plen).await else {
                    continue;
                };
                if data.len() as u64 == plen && XiteStorage::hash_bytes(&data) == *expected {
                    write_at(&storage, inner_path, poff, &data)?;
                    self.set_peer_connected(address, peer, true).await;
                    if optional {
                        if let Some(x) = self.xites.write().await.get_mut(address) {
                            x.settings.optional_downloaded += plen as i64;
                        }
                    }
                    got = true;
                    break;
                }
            }
            if !got {
                return Err(format!("could not fetch piece {i} of {inner_path}"));
            }
        }
        Ok(())
    }

    /// Which pieces of each big file we hold, keyed by the file's `sha512`
    /// (`getPiecefields`). A big file is one with a `piecemap` + `piece_size` in
    /// content.json; a piece counts as held when the on-disk bytes verify against
    /// the piecemap. Files without their piecemap on disk are skipped.
    /// Begin a Bigfile upload (`bigfileUploadInit`): check the user may write to
    /// this site (owner, or their auth address is a valid signer), stash the
    /// upload under a fresh nonce, and return `(nonce, piece_size,
    /// file_relative_path)`. The caller POSTs the bytes to
    /// `/EpixNet-Internal/BigfileUpload?upload_nonce=<nonce>`.
    /// Whether Bigfile uploads are accepted (the plugin toggle).
    pub async fn bigfile_enabled(&self) -> bool {
        self.plugin_enabled("Bigfile").await
    }

    pub async fn bigfile_upload_init(
        &self,
        address: &str,
        inner_path: &str,
        size: u64,
    ) -> Result<(String, usize, String), String> {
        // Permission: own the site, or the user's auth address is a valid signer.
        let owned = self.xites.read().await.get(address).map(|x| x.settings.own).unwrap_or(false);
        if !owned {
            let auth = self.user.write().await.auth_address(address).unwrap_or_default();
            let content = self.content(address).await;
            let is_signer = content
                .as_ref()
                .and_then(|c| c.get("signers"))
                .and_then(|v| v.as_array())
                .is_some_and(|a| a.iter().any(|s| s.as_str() == Some(&auth)))
                || content.as_ref().and_then(|c| c.get("address")).and_then(|v| v.as_str())
                    == Some(&auth);
            if !is_signer {
                return Err("Forbidden, you can only modify your own files".into());
            }
        }
        const PIECE_SIZE: usize = 1024 * 1024;
        let inner_path = inner_path.trim_start_matches('/').to_string();
        let piecemap_inner_path = format!("{inner_path}.piecemap.msgpack");
        let file_relative_path =
            inner_path.rsplit('/').next().unwrap_or(&inner_path).to_string();
        let nonce = random_hex(16);
        self.bigfile_uploads.lock().unwrap().insert(
            nonce.clone(),
            BigfileUpload {
                address: address.to_string(),
                inner_path,
                size,
                piece_size: PIECE_SIZE,
                piecemap_inner_path,
            },
        );
        Ok((nonce, PIECE_SIZE, file_relative_path))
    }

    /// Complete a Bigfile upload (`/EpixNet-Internal/BigfileUpload` POST): hash
    /// the body into pieces + a merkle root, write the file and (for a multi-
    /// piece file) its `.piecemap.msgpack`, add a `files_optional` entry to the
    /// on-disk root content.json (unsigned - the owner signs later via
    /// `siteSign`), and advertise the file in our hashfield. Consumes the nonce.
    pub async fn bigfile_upload_finish(
        &self,
        nonce: &str,
        body: &[u8],
    ) -> Result<BigfileUploadResult, String> {
        let upload = self
            .bigfile_uploads
            .lock()
            .unwrap()
            .remove(nonce)
            .ok_or("Unknown or expired upload nonce")?;
        let storage = self
            .xites
            .read()
            .await
            .get(&upload.address)
            .map(|x| x.storage.clone())
            .ok_or("Unknown site")?;

        let hash = epix_xite::hash_bigfile(body, upload.piece_size);
        storage.write(&upload.inner_path, body).map_err(|e| e.to_string())?;

        let piece_num = hash.piece_hashes.len();
        let mut entry = json!({
            "sha512": hash.merkle_root,
            "size": body.len(),
        });
        if piece_num > 1 {
            // Multi-piece: write the piecemap and record it in the entry.
            let file_name =
                upload.inner_path.rsplit('/').next().unwrap_or(&upload.inner_path);
            let blob = epix_xite::build_piecemap(file_name, &hash);
            storage.write(&upload.piecemap_inner_path, &blob).map_err(|e| e.to_string())?;
            let piecemap_rel =
                upload.piecemap_inner_path.rsplit('/').next().unwrap_or(&upload.piecemap_inner_path);
            if let Value::Object(m) = &mut entry {
                m.insert("piecemap".into(), json!(piecemap_rel));
                m.insert("piece_size".into(), json!(hash.piece_size));
            }
        }

        // Add to the on-disk root content.json's files_optional (unsigned).
        let mut content: Value = storage
            .read("content.json")
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(|| json!({}));
        if let Value::Object(root) = &mut content {
            let files_opt = root
                .entry("files_optional")
                .or_insert_with(|| Value::Object(Default::default()));
            if let Value::Object(fo) = files_opt {
                fo.insert(upload.inner_path.clone(), entry);
            }
        }
        let bytes = epix_content::dumps_content(&content).into_bytes();
        storage.write("content.json", &bytes).map_err(|e| e.to_string())?;
        // Refresh our in-memory view + advertise the file.
        self.update_content(&upload.address, Some(content)).await;
        self.hashfield_add(&upload.address, &hash.merkle_root).await;

        Ok(BigfileUploadResult {
            merkle_root: hash.merkle_root,
            piece_num,
            piece_size: hash.piece_size,
            inner_path: upload.inner_path,
        })
    }

    pub async fn our_piecefields(&self, address: &str) -> std::collections::HashMap<String, Vec<u8>> {
        let mut out = std::collections::HashMap::new();
        let content = self.content(address).await;
        let Some(files_opt) = content
            .as_ref()
            .and_then(|c| c.get("files_optional"))
            .and_then(|o| o.as_object())
        else {
            return out;
        };
        let Some(storage) = self.xites.read().await.get(address).map(|x| x.storage.clone()) else {
            return out;
        };
        for (inner_path, entry) in files_opt {
            let (Some(sha512), Some(piecemap_path)) = (
                entry.get("sha512").and_then(|v| v.as_str()),
                entry.get("piecemap").and_then(|v| v.as_str()),
            ) else {
                continue; // not a big file
            };
            let piece_size =
                entry.get("piece_size").and_then(|v| v.as_i64()).unwrap_or(1024 * 1024) as u64;
            let total = entry.get("size").and_then(|v| v.as_i64()).unwrap_or(0) as u64;
            if piece_size == 0 || total == 0 || !storage.exists(piecemap_path) {
                continue;
            }
            let Ok(pm_bytes) = storage.read(piecemap_path) else { continue };
            let file_name = inner_path.rsplit('/').next().unwrap_or(inner_path);
            let Some(hashes) = epix_xite::parse_piecemap(&pm_bytes, file_name) else { continue };
            let piece_num = total.div_ceil(piece_size);
            let mut pf = epix_xite::Piecefield::new();
            for i in 0..piece_num {
                let poff = i * piece_size;
                let plen = piece_size.min(total - poff);
                let present = hashes
                    .get(i as usize)
                    .is_some_and(|h| piece_present(&storage, inner_path, poff, plen, h));
                pf.set(i as usize, present);
            }
            out.insert(sha512.to_string(), pf.pack());
        }
        out
    }

    /// Read a byte range from a xite file (for streaming big files / HTTP Range).
    /// Returns up to `length` bytes starting at `offset`.
    pub async fn read_file_range(
        &self,
        address: &str,
        inner_path: &str,
        offset: u64,
        length: usize,
    ) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let storage = self.xites.read().await.get(address)?.storage.clone();
        let path = storage.path(inner_path).ok()?;
        let mut f = std::fs::File::open(path).ok()?;
        f.seek(SeekFrom::Start(offset)).ok()?;
        let mut buf = vec![0u8; length];
        let n = f.read(&mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    /// Delete a downloaded optional file. `optionalFileDelete`.
    pub async fn optional_file_delete(&self, address: &str, inner_path: &str) -> Result<Value, String> {
        let (info, optional) =
            self.file_info_any(address, inner_path).await.ok_or("file not declared")?;
        let storage = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.clone())
            .ok_or("unknown xite")?;
        if let Ok(path) = storage.path(inner_path) {
            let _ = std::fs::remove_file(path);
        }
        let mut changed_pin = false;
        if let Some(x) = self.xites.write().await.get_mut(address) {
            if optional {
                x.settings.optional_downloaded = (x.settings.optional_downloaded - info.size).max(0);
            }
            changed_pin = x.pinned.remove(inner_path);
        }
        if changed_pin {
            self.persist_pins().await;
        }
        Ok(Value::from("ok"))
    }

    /// Pin/unpin an optional file. `optionalFilePin` / `optionalFileUnpin`.
    pub async fn set_pin(&self, address: &str, inner_path: &str, pinned: bool) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            if pinned {
                x.pinned.insert(inner_path.to_string());
            } else {
                x.pinned.remove(inner_path);
            }
        }
        // Persist so the pin survives a restart (OptionalManager).
        self.persist_pins().await;
    }

    /// Optional-file storage stats. `optionalLimitStats`. `used` is the total
    /// optional bytes downloaded across every served xite; `free` is real free
    /// disk space (what the `%` limit is measured against).
    pub async fn optional_limit_stats(&self) -> Value {
        let used: i64 =
            self.xites.read().await.values().map(|x| x.settings.optional_downloaded).sum();
        json!({
            "limit": self.optional_limit.read().await.clone(),
            "used": used,
            "free": free_space(self.optional_limit_path.as_deref()),
        })
    }

    /// Set the optional-files cap (`optionalLimitSet`), persisted.
    pub async fn set_optional_limit(&self, limit: &str) {
        let limit = limit.trim().to_string();
        if let Some(path) = &self.optional_limit_path {
            let _ = std::fs::write(path, &limit);
        }
        *self.optional_limit.write().await = limit;
    }

    /// The optional-files cap in bytes: a `%` value is that fraction of free
    /// disk, otherwise the number is read as gigabytes (matching EpixNet's
    /// `getOptionalLimitBytes`).
    pub async fn optional_limit_bytes(&self) -> i64 {
        let limit = self.optional_limit.read().await.clone();
        let digits: String = limit.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
        let n: f64 = digits.parse().unwrap_or(0.0);
        if limit.trim_end().ends_with('%') {
            (free_space(self.optional_limit_path.as_deref()) as f64 * (n / 100.0)) as i64
        } else {
            (n * 1024.0 * 1024.0 * 1024.0) as i64
        }
    }

    /// Enforce the optional-files cap (`OptionalManager`): if downloaded optional
    /// files exceed the limit, delete the oldest un-pinned ones until back under.
    /// Returns the bytes freed. Called periodically by the runtime.
    pub async fn enforce_optional_limit(&self) -> i64 {
        let limit = self.optional_limit_bytes().await;
        if limit <= 0 {
            return 0;
        }
        // One scan of all downloaded optional files. "Downloaded" is judged by
        // the on-disk file matching the declared size (cheaper than re-hashing).
        // `used` counts every downloaded optional file; `candidates` are the
        // un-pinned ones we may delete, oldest first.
        let mut used: i64 = 0;
        let mut candidates: Vec<(String, String, i64, u64)> = Vec::new();
        {
            let xites = self.xites.read().await;
            for (addr, x) in xites.iter() {
                let Some(files_opt) =
                    x.content.as_ref().and_then(|c| c.get("files_optional")).and_then(|f| f.as_object())
                else {
                    continue;
                };
                for (inner, meta) in files_opt {
                    let size = meta.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
                    let Ok(path) = x.storage.path(inner) else { continue };
                    let Ok(md) = std::fs::metadata(&path) else { continue };
                    if md.len() as i64 != size {
                        continue; // not fully downloaded
                    }
                    used += size;
                    if x.pinned.contains(inner) {
                        continue; // pinned files are never evicted
                    }
                    let mtime = md
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    candidates.push((addr.clone(), inner.clone(), size, mtime));
                }
            }
        }
        if used <= limit {
            return 0;
        }
        // Oldest first.
        candidates.sort_by_key(|c| c.3);
        let mut freed = 0i64;
        for (addr, inner, size, _) in candidates {
            if used <= limit {
                break;
            }
            if self.optional_file_delete(&addr, &inner).await.is_ok() {
                used -= size;
                freed += size;
            }
        }
        freed
    }

    // --- MergerSite ----------------------------------------------------------

    /// Grant a permission to a xite (e.g. `ADMIN`, `Merger:ZeroMe`). Idempotent.
    /// The grant is keyed by the signed content address (so every alias of the
    /// same site shares it) and persisted so it survives restarts.
    pub async fn add_permission(&self, address: &str, permission: &str) {
        let mut xites = self.xites.write().await;
        let canonical = xites
            .get(address)
            .map(|x| canonical_address(x.content.as_ref(), address))
            .unwrap_or_else(|| address.to_string());
        // Apply to every served alias that shares this canonical address.
        for (key, x) in xites.iter_mut() {
            if canonical_address(x.content.as_ref(), key) == canonical
                && !x.settings.permissions.iter().any(|p| p == permission)
            {
                x.settings.permissions.push(permission.to_string());
            }
        }
        drop(xites);
        {
            let mut grants = self.grants.write().await;
            let entry = grants.entry(canonical).or_default();
            if !entry.iter().any(|p| p == permission) {
                entry.push(permission.to_string());
            }
        }
        self.save_grants().await;
    }

    /// Revoke a permission from a xite (and every alias of the same site).
    /// Persisted.
    pub async fn remove_permission(&self, address: &str, permission: &str) {
        let mut xites = self.xites.write().await;
        let canonical = xites
            .get(address)
            .map(|x| canonical_address(x.content.as_ref(), address))
            .unwrap_or_else(|| address.to_string());
        for (key, x) in xites.iter_mut() {
            if canonical_address(x.content.as_ref(), key) == canonical {
                x.settings.permissions.retain(|p| p != permission);
            }
        }
        drop(xites);
        if let Some(entry) = self.grants.write().await.get_mut(&canonical) {
            entry.retain(|p| p != permission);
        }
        self.save_grants().await;
    }

    /// The permissions currently held by a xite (empty if it is not served).
    pub async fn site_permissions(&self, address: &str) -> Vec<String> {
        self.xites
            .read()
            .await
            .get(address)
            .map(|x| x.settings.permissions.clone())
            .unwrap_or_default()
    }

    /// Whether a xite holds ADMIN.
    pub async fn site_has_admin(&self, address: &str) -> bool {
        self.xites
            .read()
            .await
            .get(address)
            .map(|x| x.settings.permissions.iter().any(|p| p == "ADMIN"))
            .unwrap_or(false)
    }

    /// Persist the per-xite permission grants to `data_dir/permissions.json`.
    async fn save_grants(&self) {
        if let Some(path) = &self.grants_path {
            if let Ok(bytes) = serde_json::to_vec_pretty(&*self.grants.read().await) {
                let _ = std::fs::write(path, bytes);
            }
        }
    }

    // --- Network-stats chart -------------------------------------------------

    /// Run a `chartDbQuery` (SELECT-only) against the chart database, binding
    /// `params` by name.
    pub async fn chart_query(&self, sql: &str, params: &Value) -> Result<Vec<Value>, String> {
        self.chart.query(sql, params)
    }

    /// Install the geolocation database (used by the world map).
    pub async fn set_geoip(&self, geoip: crate::geoip::GeoIp) {
        *self.geoip.write().await = Some(Arc::new(geoip));
    }

    /// `chartGetPeerLocations` - geolocate every distinct clearnet peer IP we
    /// know across all served xites, for the dashboard's world map. Returns
    /// `[{lat, lon, city, country, ping}]`. Empty if no geolocation db is loaded.
    /// Every geolocated peer the node knows, across all xites - the dashboard's
    /// world map (`chartGetPeerLocations`).
    pub async fn peer_locations(&self) -> Vec<Value> {
        self.peer_locations_impl(None).await
    }

    /// The geolocated peers of a single xite - the sidebar's per-site globe.
    /// EpixNet's `getPeerLocations(self.site.peers)`: a xite with no peers gets
    /// an empty globe rather than the whole node's peer set.
    pub async fn site_peer_locations(&self, address: &str) -> Vec<Value> {
        self.peer_locations_impl(Some(address)).await
    }

    /// The clearnet peer IPs of the selected xite(s), unpinged (`None`):
    /// `only_site = None` pools every served xite, `Some(address)` just that
    /// one. The first stage of the peer-location queries below.
    async fn known_peer_ips(&self, only_site: Option<&str>) -> HashMap<std::net::IpAddr, Option<i64>> {
        let xites = self.xites.read().await;
        let selected: Vec<&ManagedXite> = match only_site {
            Some(addr) => self.resolve_xite(&xites, addr).into_iter().collect(),
            None => xites.values().collect(),
        };
        let mut pings = HashMap::new();
        for x in selected {
            for p in x.peers.peers() {
                if let PeerAddr::Ip(sa) = &p.addr {
                    pings.entry(sa.ip()).or_insert(None);
                }
            }
        }
        pings
    }

    /// Shared body: `only_site = None` pools every xite's peers (the global
    /// world map); `Some(address)` restricts to that one xite (the sidebar
    /// globe), so an unconnected site doesn't borrow other sites' dots.
    async fn peer_locations_impl(&self, only_site: Option<&str>) -> Vec<Value> {
        let Some(geoip) = self.geoip.read().await.clone() else { return Vec::new() };
        // Best ping seen per IP (ms), across the selected xite(s).
        let mut pings = self.known_peer_ips(only_site).await;
        // Ping (ms) per connected clearnet peer, from the warm pool. For a single
        // site, only annotate IPs that are actually this site's peers - the warm
        // pool is node-wide, so folding all of it in would re-introduce other
        // sites' dots.
        for addr in self.conn_pool.connected_addrs().await {
            let PeerAddr::Ip(sa) = &addr else { continue };
            let ip = sa.ip();
            if only_site.is_some() && !pings.contains_key(&ip) {
                continue;
            }
            if let Some(ms) = self.conn_pool.ping_for(&addr).await {
                pings.insert(ip, Some(ms));
            }
        }
        let mut out = Vec::new();
        for (ip, ping) in pings {
            let Some(loc) = geoip.locate(ip) else { continue };
            out.push(json!({
                "lat": loc.lat,
                "lon": loc.lon,
                "city": loc.city,
                "country": loc.country,
                "ping": ping,
            }));
        }
        out
    }

    /// `sidebarGetPeers` - peer positions for the sidebar's WebGL globe, as a
    /// flat `[lat, lon, height, …]` array (the globe's `magnitude` format).
    /// Height is derived from ping (log-scaled around the average), matching
    /// EpixNet: connected peers rise with latency, unpinged peers sit slightly
    /// below the surface.
    pub async fn peer_globe_data(&self, address: &str) -> Vec<f64> {
        let locs = self.site_peer_locations(address).await;
        let pings: Vec<f64> =
            locs.iter().filter_map(|l| l["ping"].as_f64()).filter(|p| *p > 0.0).collect();
        let ping_avg =
            if pings.is_empty() { 0.0 } else { pings.iter().sum::<f64>() / pings.len() as f64 };
        let mut out = Vec::new();
        for l in &locs {
            let lat = l["lat"].as_f64().unwrap_or(0.0);
            let lon = l["lon"].as_f64().unwrap_or(0.0);
            let height = match l["ping"].as_f64() {
                Some(p) if p == 0.0 => -0.135, // self
                Some(p) if p > 0.0 && ping_avg > 0.0 => (1.0 + p / ping_avg).log(300.0).min(0.20),
                _ => -0.03, // known peer, no live ping
            };
            out.extend_from_slice(&[lat, lon, height]);
        }
        out
    }

    /// Keep the warm connection pool topped up and pinged, and reflect its
    /// membership onto each xite's peer `connected` flags. Called periodically
    /// by the runtime so connection stats stay live.
    pub async fn manage_connections(&self) {
        let Some(transport) = self.transport.read().await.clone() else { return };
        // Candidate peers across all served xites.
        let mut candidates: Vec<PeerAddr> = Vec::new();
        {
            let xites = self.xites.read().await;
            for x in xites.values() {
                for p in x.peers.peers() {
                    if !candidates.contains(&p.addr) {
                        candidates.push(p.addr.clone());
                    }
                }
            }
        }
        self.conn_pool.ensure(transport, &candidates).await;
        self.conn_pool.ping_all().await;

        // Mark peers we hold a live connection to as connected.
        let connected = self.conn_pool.connected_addrs().await;
        let addresses: Vec<String> = {
            let mut xites = self.xites.write().await;
            for x in xites.values_mut() {
                for addr in &connected {
                    x.peers.set_connected(addr, true, now_secs());
                }
            }
            xites.keys().cloned().collect()
        };
        // Push the updated connection/peer counts to any connected UI.
        for address in &addresses {
            self.push_site_info(address).await;
        }

        // PEX: keep the peer set self-healing between announces. Cheap - a few
        // peers per xite - so run it each connection cycle.
        for address in &addresses {
            self.run_pex(address, 3, 5).await;
        }
    }

    /// Peer-exchange one xite: ask a few connectable peers for their peers and
    /// fold in any new ones. Trackers/DHT bootstrap discovery; PEX keeps it
    /// self-healing between announces (EpixNet runs this in its cleanup loop).
    /// Returns how many new peers were learned.
    pub async fn run_pex(&self, address: &str, max_peers: usize, need: i64) -> usize {
        let Some(transport) = self.transport.read().await.clone() else { return 0 };
        let canonical = {
            let xites = self.xites.read().await;
            let Some(x) = self.resolve_xite(&xites, address) else { return 0 };
            canonical_address(x.content.as_ref(), address)
        };
        // The peers we offer them (packed by type), and the set we already know.
        let ours = self.connectable_peers(address, 10).await;
        let mut known: std::collections::HashSet<String> =
            ours.iter().map(|p| p.to_string()).collect();
        let (mut ipv4, mut ipv6, mut onion, mut i2p) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut rns: Vec<Vec<u8>> = Vec::new();
        for p in &ours {
            if p.is_private() {
                continue;
            }
            match (p.ip_type(), p.pack()) {
                (epix_core::IpType::Ipv4, Some(b)) => ipv4.push(b),
                (epix_core::IpType::Ipv6, Some(b)) => ipv6.push(b),
                (epix_core::IpType::Onion, Some(b)) => onion.push(b),
                (epix_core::IpType::I2p, Some(b)) => i2p.push(b),
                (epix_core::IpType::Rns, Some(b)) => rns.push(b),
                _ => {}
            }
        }
        // Advertise our own reachable overlay addresses so the peers we reach
        // add and gossip us (mirrors the server-side pex reply).
        let fs_port = self.fileserver_port().await;
        if let Some(host) = self.onion_address().await {
            if let Some(b) = (PeerAddr::Onion { host, port: fs_port }).pack() {
                onion.push(b);
            }
        }
        if let Some(dest) = self.i2p_address().await {
            if let Some(b) = (PeerAddr::I2p { dest, port: fs_port }).pack() {
                i2p.push(b);
            }
        }
        if let Some(hex) = self.rns_address().await {
            if let Ok(p) = PeerAddr::parse(&format!("rns:{hex}")) {
                if let Some(b) = p.pack() {
                    rns.push(b);
                }
            }
        }

        let mut learned: Vec<PeerAddr> = Vec::new();
        for peer in ours.iter().take(max_peers) {
            // Overlay-aware bound: an onion/i2p peer can't finish a dial +
            // PEX inside a clearnet-sized timeout.
            let got = tokio::time::timeout(peer.connect_timeout(), async {
                let mut conn = Connection::connect(transport.as_ref(), peer).await.ok()?;
                conn.handshake().await.ok()?;
                conn.pex(
                    &canonical,
                    ipv4.clone(),
                    ipv6.clone(),
                    onion.clone(),
                    i2p.clone(),
                    rns.clone(),
                    need,
                )
                .await
                .ok()
            })
            .await;
            let Ok(Some(reply)) = got else { continue };
            self.set_peer_connected(address, peer, true).await;
            let unpacked = reply
                .ipv4
                .iter()
                .chain(reply.ipv6.iter())
                .filter_map(|b| PeerAddr::unpack_ip(b))
                .chain(reply.onion.iter().filter_map(|b| PeerAddr::unpack_onion(b)))
                .chain(reply.i2p.iter().filter_map(|b| PeerAddr::unpack_i2p(b)))
                .chain(reply.rns.iter().filter_map(|b| PeerAddr::unpack_rns(b)));
            for p in unpacked {
                if known.insert(p.to_string()) {
                    learned.push(p);
                }
            }
        }
        let count = learned.len();
        if count > 0 {
            self.add_peers(address, learned).await;
        }
        count
    }

    /// Live connection stats (`connection`, `connection_in`, `connection_onion`,
    /// ping avg/min) for the chart collector.
    pub async fn connection_stats(&self) -> crate::conn_pool::ConnectionStats {
        self.conn_pool.stats().await
    }

    /// The lightweight public stats payload (`/StatsJson`, the NoNewSites
    /// gateway endpoint): totals a marketing page can poll without hitting
    /// the full diagnostics page.
    pub async fn stats_json(&self) -> Value {
        let xites = self.xites.read().await;
        let mut peers_total = 0usize;
        let mut peers_connected = 0usize;
        let mut bytes_recv = 0u64;
        let mut bytes_sent = 0u64;
        for x in xites.values() {
            let counts = x.peers.counts();
            peers_total += counts.total;
            peers_connected += counts.connected;
            bytes_recv += x.bytes_recv;
            bytes_sent += x.bytes_sent;
        }
        let sites = xites.len();
        drop(xites);
        let (port_opened, _) = self.port_status().await;
        // Wire totals cover ALL protocol traffic (handshakes, announces,
        // content checks), not just file payloads - so they move even when an
        // update finds nothing new to download. The tray shows these.
        let (wire_recv, wire_sent) = epix_protocol::wire_totals();
        // Per-connection handshake identities (Phase 6): which node versions
        // the network runs, per live pooled connection.
        let connections_detail: Vec<Value> = self
            .conn_pool
            .connection_details()
            .await
            .into_iter()
            .map(|d| {
                json!({
                    "peer": d.addr.to_string(),
                    "ping_ms": d.ping_ms,
                    "version": d.peer.as_ref().map(|p| p.version.clone()),
                    "rev": d.peer.as_ref().map(|p| p.rev),
                    "protocol": d.peer.as_ref().map(|p| p.protocol.clone()),
                    "crypt_supported": d.peer.as_ref().map(|p| p.crypt_supported.clone()),
                })
            })
            .collect();
        json!({
            "version": self.version,
            "sites": sites,
            "peers_total": peers_total,
            "peers_connected": peers_connected,
            "connections": self.connection_stats().await.total,
            "connections_detail": connections_detail,
            "bytes_recv": bytes_recv,
            "bytes_sent": bytes_sent,
            "wire_recv": wire_recv,
            "wire_sent": wire_sent,
            "port_opened": port_opened,
        })
    }

    /// Render the diagnostics Stats page (EpixNet's `/Stats`): node identity,
    /// connection pool, trackers, Tor, and a per-site table. Returns the inner
    /// HTML body; the route wraps it in the shared page shell.
    pub async fn stats_html(&self) -> String {
        use std::fmt::Write;
        let esc = |s: &str| {
            s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        };
        let (tor_enabled, tor_status) = self.tor_status().await;
        let (port_opened, ip_ext) = self.port_status().await;
        let stats = self.connection_stats().await;
        let mut h = String::new();

        // Head line.
        let _ = write!(
            h,
            "<div class='stat-head'>v{ver} | Port: {port} | Opened: {opened} |              External IP: {ip} | Tor: {tor} | Connections: {conns}</div>",
            ver = esc(&self.version),
            port = self.fileserver_port().await,
            opened = port_opened,
            ip = esc(&ip_ext.unwrap_or_else(|| "-".into())),
            tor = if tor_enabled { esc(&tor_status) } else { "off".into() },
            conns = stats.total,
        );

        // Connections, split by network so the mix is visible at a glance.
        let _ = write!(
            h,
            "<h2>Connections ({} live - clearnet: {}, tor: {}, i2p: {})</h2>             <table><tr><th>peer</th><th>type</th><th>version</th><th>protocol</th><th>ping</th></tr>",
            stats.total, stats.clearnet, stats.onion, stats.i2p
        );
        // What the handshake told us about each peer (Phase 6): the node
        // version + rev show which releases the network runs, protocol and
        // crypt show wire capabilities.
        for detail in self.conn_pool.connection_details().await {
            let ping = detail.ping_ms.map(|ms| format!("{ms} ms")).unwrap_or_else(|| "-".into());
            let kind = match &detail.addr {
                PeerAddr::Onion { .. } => "onion",
                PeerAddr::I2p { .. } => "i2p",
                PeerAddr::Rns(_) => "mesh",
                PeerAddr::Ip(_) => "ip",
            };
            let (version, protocol) = match &detail.peer {
                Some(p) => (
                    if p.version.is_empty() { "-".to_string() } else { p.version.clone() },
                    if p.protocol.is_empty() { "-".to_string() } else { p.protocol.clone() },
                ),
                None => ("-".into(), "-".into()),
            };
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&detail.addr.to_string()),
                kind,
                esc(&version),
                esc(&protocol),
                ping
            );
        }
        if stats.total == 0 {
            h.push_str("<tr><td colspan=5 class='muted'>no live connections</td></tr>");
        }
        h.push_str("</table>");

        // Trackers.
        h.push_str("<h2>Trackers</h2><table><tr><th>address</th><th>requests</th><th>errors</th><th>peers found</th><th>status</th></tr>");
        let trackers = self.announcer_stats().await;
        if let Value::Object(map) = &trackers {
            for (addr, st) in map {
                let get = |k: &str| st.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
                let status =
                    st.get("status").and_then(|v| v.as_str()).unwrap_or("-").to_string();
                let _ = write!(
                    h,
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(addr),
                    get("num_request"),
                    get("num_error"),
                    get("num_added"),
                    esc(&status),
                );
            }
        }
        if !matches!(&trackers, Value::Object(m) if !m.is_empty()) {
            h.push_str("<tr><td colspan=5 class='muted'>no announces yet</td></tr>");
        }
        h.push_str("</table>");

        // Our own tracker (we answer other nodes' announces).
        if self.tracker_enabled().await {
            let (hashes, peers) = self.tracker_stats().await;
            let _ = write!(
                h,
                "<div class='stat-row'>as tracker: serving <b>{peers}</b> peer(s) across <b>{hashes}</b> xite(s)</div>"
            );
        }

        // Tor.
        h.push_str("<h2>Tor</h2>");
        let _ = write!(
            h,
            "<div class='stat-row'>status: <b>{}</b></div>",
            if tor_enabled { esc(&tor_status) } else { "disabled".into() }
        );
        if let Some(onion) = self.onion_address().await {
            let _ = write!(h, "<div class='stat-row'>onion: {}.onion</div>", esc(&onion));
        }

        // I2P.
        h.push_str("<h2>I2P</h2>");
        let i2p = self.i2p_status().await;
        let i2p_str = |k: &str| i2p.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let i2p_num = |k: &str| i2p.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        let mode = i2p_str("mode");
        if mode.is_empty() || mode == "disable" {
            h.push_str("<div class='stat-row'>status: <b>disabled</b></div>");
        } else {
            let _ = write!(
                h,
                "<div class='stat-row'>mode: <b>{}</b> &nbsp; status: <b>{}</b></div>",
                esc(&mode),
                esc(&i2p_str("phase"))
            );
            let _ = write!(
                h,
                "<div class='stat-row'>peers (routers): {} &nbsp; tunnels built: {} &nbsp; \
                 tunnel failures: {} &nbsp; reseed routers: {}</div>",
                i2p_num("connected_routers"),
                i2p_num("tunnels_built"),
                i2p_num("tunnel_failures"),
                i2p_num("reseed_routers"),
            );
            let b32 = i2p_str("b32");
            if !b32.is_empty() {
                // Our reachable I2P address, advertised to peers via PEX.
                let _ = write!(h, "<div class='stat-row'>address: <b>{}</b></div>", esc(&b32));
            }
        }

        // Sites.
        h.push_str("<h2>Sites</h2><table><tr><th>address</th><th>peers (conn/able/total)</th><th>onion</th><th>local</th><th>out</th><th>in</th><th>serving</th></tr>");
        for address in self.xite_addresses().await {
            // One row per site (skip the display-name alias key, if any).
            if address.contains('.') {
                continue;
            }
            let pc = self.peer_counts(&address).await;
            let (recv, sent) = self.transfer(&address).await;
            let serving = self.is_serving(&address).await;
            let display = self.display_of(&address).await;
            let label = match &display {
                Some(d) => format!("{} <span class='muted'>({})</span>", esc(d), esc(&address)),
                None => esc(&address),
            };
            let _ = write!(
                h,
                "<tr class='{cls}'><td>{label}</td><td>{c}/{able}/{total}</td><td>{onion}</td>                 <td>{local}</td><td>{out:.0}k</td><td>{in_:.0}k</td><td>{serving}</td></tr>",
                cls = if serving { "" } else { "muted" },
                c = pc.connected,
                able = pc.connectable,
                total = pc.total,
                onion = pc.onion,
                local = pc.local,
                out = sent as f64 / 1024.0,
                in_ = recv as f64 / 1024.0,
                serving = serving,
            );
        }
        h.push_str("</table>");
        h
    }

    // --- Server-pushed UI events --------------------------------------------

    // --- Console log buffer -------------------------------------------------

    /// Maximum log lines kept for the console.
    const LOG_CAPACITY: usize = 300;

    /// Record a log line for the dashboard console and echo it to stdout.
    /// `level` is `INFO`/`WARNING`/`ERROR`. Feeds both `serverErrors` (tuples)
    /// and any open sidebar-console stream (`logLineAdd`, formatted strings).
    pub async fn log(&self, level: &str, message: impl Into<String>) {
        // Honour the configured minimum log level (config `log_level`).
        if log_rank(level) < log_rank(&self.log_level().await) {
            return;
        }
        let message = message.into();
        println!("[{level}] {message}");
        // Append to the on-disk log file, if one is configured.
        if let Some(file) = self.log_file.lock().unwrap().as_mut() {
            use std::io::Write;
            let _ = writeln!(file, "[{}] [{level}] {message}", now_secs());
        }
        let line = json!([now_secs() as f64, level, message]);
        {
            let mut logs = self.logs.write().await;
            logs.push_back(line.clone());
            while logs.len() > Self::LOG_CAPACITY {
                logs.pop_front();
            }
        }
        // Stream to any open sidebar console(s) whose filter matches this line.
        let streams = self.log_streams.read().await;
        if !streams.is_empty() {
            let formatted = format_log_line(&line);
            for (id, filter) in streams.iter() {
                if !log_line_matches(&line, filter) {
                    continue;
                }
                self.push_event(
                    "logLineAdd",
                    json!({ "stream_id": id, "lines": [formatted] }),
                    None,
                    None,
                );
            }
        }
    }

    /// `serverErrors` - only the ERROR-level log lines, `[[date_added, level,
    /// message], …]`. Matches EpixNet's error logger (level ERROR), so the
    /// dashboard's warning badge lights up for real errors, not routine INFO
    /// activity. The full activity log is in the sidebar console
    /// (`consoleLogRead`/`consoleLogStream`), which keeps every level.
    pub async fn server_errors(&self) -> Vec<Value> {
        self.logs
            .read()
            .await
            .iter()
            .filter(|l| matches!(l.get(1).and_then(Value::as_str), Some("ERROR") | Some("CRITICAL")))
            .cloned()
            .collect()
    }

    /// `consoleLogRead` - recent lines for the sidebar console as formatted
    /// strings, plus the byte-position metadata the panel displays. `filter`
    /// is the active tab's level (`INFO`/`WARNING`/`ERROR`, or empty for All).
    pub async fn console_log_read(&self, filter: &str) -> Value {
        let lines: Vec<Value> = self
            .logs
            .read()
            .await
            .iter()
            .filter(|l| log_line_matches(l, filter))
            .map(|l| json!(format_log_line(l)))
            .collect();
        let n = lines.len();
        json!({ "lines": lines, "pos_start": 0, "pos_end": n * 80, "num_found": n })
    }

    /// `consoleLogStream` - open a live log stream; returns its id. New lines
    /// arrive as `logLineAdd` events tagged with this id, filtered to `filter`
    /// (the active tab's level, or empty for All).
    pub async fn console_log_stream_open(&self, filter: &str) -> i64 {
        let id = self.nonce_counter.fetch_add(1, Ordering::Relaxed) as i64;
        self.log_streams.write().await.push((id, filter.to_string()));
        id
    }

    /// `consoleLogStreamRemove` - stop a live log stream.
    pub async fn console_log_stream_remove(&self, id: i64) {
        self.log_streams.write().await.retain(|s| s.0 != id);
    }

    /// Subscribe to server-pushed UI events (one receiver per WS connection).
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<UiEvent> {
        self.events.subscribe()
    }

    /// Push an unsolicited `{cmd, params}` event. `channel` gates by
    /// subscription (`None` = ungated); `target` gates by xite (`None` = any).
    /// No-op if nothing is listening.
    fn push_event(&self, cmd: &str, params: Value, channel: Option<&str>, target: Option<String>) {
        self.push_event_routed(cmd, params, channel, target, None, None);
    }

    /// [`Self::push_event`] with per-connection routing: `exclude` skips the
    /// originating connection, `only` delivers to a single one.
    fn push_event_routed(
        &self,
        cmd: &str,
        params: Value,
        channel: Option<&str>,
        target: Option<String>,
        exclude: Option<u64>,
        only: Option<u64>,
    ) {
        // Every pushed command carries a unique id, like EpixNet's
        // UiWebsocket.cmd - the wrapper keys notification toasts on it
        // (`notification-ws-<id>`), so without one every toast shares a key
        // and replaces the previous.
        let id = self.nonce_counter.fetch_add(1, Ordering::Relaxed) as i64;
        let payload = json!({ "cmd": cmd, "params": params, "id": id }).to_string();
        let _ = self.events.send(UiEvent {
            channel: channel.map(str::to_string),
            target,
            payload,
            exclude,
            only,
        });
    }

    /// Push the latest `siteInfo` for a xite (`setSiteInfo`) on the `siteChanged`
    /// channel, only to that xite's connections, so the dashboard's
    /// peer/connection/content readouts update the moment they change.
    pub async fn push_site_info(&self, address: &str) {
        let info = self.site_info(address).await;
        if !info.is_null() {
            self.push_event("setSiteInfo", info, Some("siteChanged"), Some(address.to_string()));
        }
    }

    /// Push `setSiteInfo` tagged with an `event` (`["updating"|"updated", true]`),
    /// so the dashboard's site row shows the spinner + "Updating…"/"Updated!"
    /// inline (matching EpixNet's `updateWebsocket(updating/updated)`).
    pub async fn push_site_info_event(&self, address: &str, event: &str) {
        self.push_site_info_event_excluding(address, event, None).await;
    }

    /// [`Self::push_site_info_event`] skipping the originating connection.
    pub async fn push_site_info_event_excluding(
        &self,
        address: &str,
        event: &str,
        exclude: Option<u64>,
    ) {
        let mut info = self.site_info(address).await;
        if let Value::Object(m) = &mut info {
            m.insert("event".to_string(), json!([event, true]));
            self.push_event_routed(
                "setSiteInfo",
                info,
                Some("siteChanged"),
                Some(address.to_string()),
                exclude,
                None,
            );
        }
    }

    /// Push `setSiteInfo` tagged `["file_done", inner_path]`, EpixNet's
    /// per-file signal. Sites re-query their db when a `.json` file lands
    /// (EpixSites' site list, EpixTalk's topics), so push this only after the
    /// db is rebuilt or the page re-queries into the old data.
    ///
    /// `exclude` is the connection whose own write produced the file (EpixNet
    /// notifies `ws != self`): the page already knows what it wrote, and an
    /// echoed event re-renders it mid-interaction (detaching inline editors).
    pub async fn push_site_info_file_done(
        &self,
        address: &str,
        inner_path: &str,
        exclude: Option<u64>,
    ) {
        let mut info = self.site_info(address).await;
        if let Value::Object(m) = &mut info {
            m.insert("event".to_string(), json!(["file_done", inner_path]));
            self.push_event_routed(
                "setSiteInfo",
                info,
                Some("siteChanged"),
                Some(address.to_string()),
                exclude,
                None,
            );
        }
    }

    /// A notification for a single connection (EpixNet's `self.cmd`), not
    /// every open page.
    pub fn push_notification_to(&self, only: u64, kind: &str, message: &str, timeout_ms: i64) {
        self.push_event_routed(
            "notification",
            json!([kind, message, timeout_ms]),
            None,
            None,
            None,
            Some(only),
        );
    }

    /// Push the outcome of an update check as the dashboard expects it
    /// (EpixNet's contract): an `updated` event ends the "Updating..." pill -
    /// rendered as a self-clearing "Updated!" flash on success, or (with
    /// `content_updated: false`) as the "Update failed"/"No peers" error pill.
    /// A plain eventless push would leave the old pill text on screen.
    pub async fn push_update_result(&self, address: &str, ok: bool) {
        let mut info = self.site_info(address).await;
        if let Value::Object(m) = &mut info {
            m.insert("event".to_string(), json!(["updated", true]));
            if !ok {
                m.insert("content_updated".to_string(), json!(false));
            }
            self.push_event("setSiteInfo", info, Some("siteChanged"), Some(address.to_string()));
        }
    }

    /// Mark an update pass (periodic resync or `siteUpdate`) as running for a
    /// xite. Pair with [`Self::end_site_update`] before pushing the outcome.
    pub fn begin_site_update(&self, address: &str) {
        self.site_updates_in_flight.lock().unwrap().insert(address.to_string());
    }

    /// The update pass for a xite finished (its outcome event is about to be
    /// pushed).
    pub fn end_site_update(&self, address: &str) {
        self.site_updates_in_flight.lock().unwrap().remove(address);
    }

    /// Mark an on-demand clone as downloading a xite's files. Pair with
    /// [`Self::end_clone`] (on failure too).
    pub fn begin_clone(&self, address: &str) {
        self.clones_in_flight.lock().unwrap().insert(address.to_string());
    }

    /// The clone for a xite finished (or failed).
    pub fn end_clone(&self, address: &str) {
        self.clones_in_flight.lock().unwrap().remove(address);
    }

    /// Whether an on-demand clone is currently downloading this xite's files.
    pub fn is_cloning(&self, address: &str) -> bool {
        self.clones_in_flight.lock().unwrap().contains(address)
    }

    /// Advance a xite's `settings.modified` (the dashboard's "last updated")
    /// to `modified` if newer. Far-future timestamps are capped at now + 10
    /// minutes like EpixNet, so one bogus clock can't pin the display.
    pub async fn bump_modified(&self, address: &str, modified: f64) {
        let capped = modified.min(now_secs() as f64 + 600.0);
        if capped <= 0.0 {
            return;
        }
        if let Some(x) = self.xites.write().await.get_mut(address) {
            if capped > x.settings.modified {
                x.settings.modified = capped;
            }
        }
    }

    /// Whether this xite is marked owned (its files are edited locally and
    /// must never be overwritten with the signed versions from peers).
    pub async fn xite_owned(&self, address: &str) -> bool {
        let xites = self.xites.read().await;
        self.resolve_xite(&xites, address).map(|x| x.settings.own).unwrap_or(false)
    }

    /// Whether serving an html document for this xite should keep waiting: its
    /// core set (every file the root content.json declares) is not fully on
    /// disk yet, and it isn't ours. The document is the page itself - serving
    /// it as soon as it lands boots the page with its styles, scripts and lazy
    /// chunks still downloading, which reads as broken (the wrapper also drops
    /// its loading screen once the iframe loads). Non-html assets are only
    /// requested by an already-running page, so they serve as they land.
    pub async fn html_doc_gated(&self, address: &str) -> bool {
        // Without an on-demand resolver nothing can complete the download -
        // serve what is on disk (also keeps bare embedded servers, which add
        // xites programmatically, out of the gate).
        self.has_on_demand().await
            && !self.xite_owned(address).await
            && !self.xite_core_complete(address).await
    }

    /// Re-send the closing `updated` event, to one connection, for every xite
    /// with no update pass in flight. Called when that connection's event
    /// stream reports it dropped events (broadcast lag): the dashboard's
    /// "Updating..." pill only ever clears on an outcome event, so if the
    /// dropped window held one the pill would stay up forever. Sites still
    /// mid-update are skipped - their real outcome event is coming.
    pub async fn push_missed_update_results(&self, only: u64) {
        for address in self.xite_addresses().await {
            if self.site_updates_in_flight.lock().unwrap().contains(&address) {
                continue;
            }
            let mut info = self.site_info(&address).await;
            if let Value::Object(m) = &mut info {
                m.insert("event".to_string(), json!(["updated", true]));
                self.push_event_routed(
                    "setSiteInfo",
                    info,
                    Some("siteChanged"),
                    Some(address.clone()),
                    None,
                    Some(only),
                );
            }
        }
    }

    /// Push the latest tracker stats (`setAnnouncerInfo`) on `announcerChanged`.
    /// Tagged with the announcing xite's address so its wrapper (the loading
    /// screen's tracker line) picks it up.
    pub async fn push_announcer_info(&self, address: &str) {
        let params = json!({ "address": address, "stats": self.announcer_stats().await });
        self.push_event(
            "setAnnouncerInfo",
            params,
            Some("announcerChanged"),
            Some(address.to_string()),
        );
    }

    /// Push a synthetic `setSiteInfo` event for a xite that is still being
    /// cloned (not yet registered), driving the wrapper's loading screen:
    /// `peers_added` ("Peers found: N"), `file_added` ("N files needs to be
    /// downloaded"), `file_done` (hides the screen when index.html lands), and
    /// `file_failed` ("download failed" / "No peers found"). `fields` merges
    /// extra keys (e.g. `peers`, `bad_files`) over the minimal shape the
    /// wrapper JS reads.
    pub fn push_clone_event(&self, address: &str, event: Value, fields: Value) {
        // Once content.json has been verified mid-clone, the title is known:
        // carry it so the dashboard's "Connecting sites" row shows the xite's
        // name instead of its bech32 address (and the wrapper's tab title
        // doesn't read "undefined"). try_read because this is called from
        // sync per-file progress callbacks: under momentary write contention
        // the title just rides the next event instead.
        let title = self
            .xites
            .try_read()
            .ok()
            .and_then(|xites| xites.get(address)?.content.as_ref()?.get("title").cloned());
        let content = match title {
            Some(t) => json!({ "title": t }),
            None => json!({}),
        };
        let mut params = json!({
            "address": address,
            "peers": 0,
            "tasks": 0,
            "started_task_num": 0,
            "bad_files": 0,
            "size_limit": DEFAULT_SIZE_LIMIT_MB,
            "settings": { "size": 0 },
            // Always an object - dashboard rows read `content.title` unchecked.
            "content": content,
            "event": event,
        });
        if let (Value::Object(p), Value::Object(f)) = (&mut params, fields) {
            for (k, v) in f {
                p.insert(k, v);
            }
        }
        self.push_event("setSiteInfo", params, Some("siteChanged"), Some(address.to_string()));
    }

    /// Whether an on-demand resolver is installed (the browser/node wires one;
    /// bare test servers don't).
    pub async fn has_on_demand(&self) -> bool {
        self.on_demand.read().await.is_some()
    }

    /// Whether a served xite's file exists on disk (ready to serve) - false
    /// while it is still downloading.
    pub async fn xite_file_exists(&self, address: &str, inner_path: &str) -> bool {
        self.xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.exists(inner_path))
            .unwrap_or(false)
    }

    /// Whether every file the ROOT content.json declares is present on disk
    /// with its declared size (the core set: html/css/js - not per-user
    /// content). The loading screen dismisses on this, not on index.html
    /// alone: index.html downloads first, and entering a half-downloaded
    /// site with its styles and scripts still missing reads as broken.
    ///
    /// Size check only, EpixNet's quick_check: the files were hash-verified
    /// when the workers wrote them, and this runs on EVERY wrapper connect
    /// (the file_status probe) - reading and SHA512ing a whole site per page
    /// load would make big sites expensive to open.
    pub async fn xite_core_complete(&self, address: &str) -> bool {
        let storage = {
            let xites = self.xites.read().await;
            let Some(x) = self.resolve_xite(&xites, address) else { return false };
            x.storage.clone()
        };
        // Verify the on-disk content.json against the address the xite is SERVED
        // under - not the address the content claims. A content.json that does
        // not verify for this address (authored here, edited, or signed for a
        // different address and not re-signed yet) is a LOCAL working copy.
        let Ok(addr) = Address::parse(address.to_string()) else { return false };
        let mut xite = Xite::new(addr, storage.clone());
        match xite.load_content() {
            // Authoritative content (a valid signature for this address): the
            // core is complete when every declared file is PRESENT on disk.
            // Presence is enough: workers only write verified bytes, so a file
            // that exists but differs from its signed size can only be a local
            // edit made after the last sign - and local changes serve as-is
            // (the signature only gates content downloaded from peers).
            // Requiring the signed size here turned an edited-but-servable
            // xite into a page that hangs behind the html gate, waiting on a
            // "download" no peer can ever satisfy.
            Ok(true) => xite.files().iter().all(|f| {
                storage
                    .path(&f.inner_path)
                    .ok()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .is_some()
            }),
            // A content.json is on disk but does not verify for this address, or
            // none is stored yet. `load_content_local` is true only in the first
            // case: a local copy, served as-is and never gated or auto-downloaded
            // over (its files may differ from the stale content.json until it is
            // re-signed - a signature is only required for content from peers).
            // No content.json at all -> not complete -> download on demand.
            _ => xite.load_content_local(),
        }
    }

    /// Load a registered xite's on-disk content.json into its in-memory entry
    /// when it isn't there yet. A clone that wrote every file but errored before
    /// finalizing (a transient "could not fetch + verify content.json from any
    /// peer" that later healed once more peers appeared), or an incomplete
    /// resync, can leave the files complete on disk while `entry.content` stays
    /// `None`. The wrapper then shows a perpetual download page and siteInfo has
    /// no title. Returns true if content is present afterward (already loaded or
    /// just loaded here).
    pub async fn load_content_from_disk(&self, address: &str) -> bool {
        let storage = {
            let xites = self.xites.read().await;
            let Some(x) = self.resolve_xite(&xites, address) else { return false };
            // Already loaded: nothing to heal.
            if x.content.is_some() {
                return true;
            }
            x.storage.clone()
        };
        let Ok(addr) = Address::parse(address.to_string()) else { return false };
        let mut xite = Xite::new(addr, storage);
        // Verified load (a valid signature for this address); fall back to a
        // local unsigned copy so an authored/edited site still populates.
        let loaded = xite.load_content().unwrap_or(false) || xite.load_content_local();
        if !loaded {
            return false;
        }
        // update_content also finalizes settings (size/modified via
        // apply_content_stats) and rebuilds the db from the on-disk files.
        self.update_content(address, xite.content.clone()).await;
        self.persist_sites().await;
        self.push_site_info(address).await;
        true
    }

    /// Progressive serve during an on-demand clone: the state of one file of a
    /// xite that is downloading but not yet registered.
    pub fn loading_file(&self, address: &str, inner_path: &str) -> LoadingFile {
        let Some(dir) = self.xite_dir(address) else { return LoadingFile::Pending };
        let storage = epix_xite::XiteStorage::new(dir);
        // Workers verify every file's hash (against the signature-verified
        // content.json) before writing, so anything on disk is safe to serve.
        if let Ok(bytes) = storage.read(inner_path) {
            return LoadingFile::Ready(bytes);
        }
        // content.json on disk tells us which files will ever exist: a request
        // for something unlisted 404s instead of waiting out the clone.
        if let Ok(bytes) = storage.read("content.json") {
            if let Ok(content) = serde_json::from_slice::<Value>(&bytes) {
                let listed = content
                    .get("files")
                    .and_then(|f| f.get(inner_path))
                    .is_some()
                    || content
                        .get("files_optional")
                        .and_then(|f| f.get(inner_path))
                        .is_some();
                if !listed {
                    return LoadingFile::NotInSite;
                }
            }
        }
        LoadingFile::Pending
    }

    /// Push a wrapper notification (`["info"|"done"|"error", message,
    /// timeout_ms]`). Ungated - notifications reach every connection.
    pub fn push_notification(&self, kind: &str, message: &str, timeout_ms: i64) {
        self.push_event("notification", json!([kind, message, timeout_ms]), None, None);
    }

    /// Build the `serverInfo` payload (shared by the `serverInfo` command and
    /// the `setServerInfo` push).
    pub async fn server_info(&self) -> Value {
        let mut user_settings = self.global_settings().await;
        if let Value::Object(m) = &mut user_settings {
            // Default to following the OS theme when the user hasn't chosen one.
            m.entry("theme").or_insert(json!("light"));
            m.entry("use_system_theme").or_insert(json!(true));
        }
        let connections = self.connection_stats().await.total;
        let plugins = self.plugins().await;
        // The multiuser feature compiles the code in; the PLUGIN toggle (off
        // by default) decides at runtime whether the dashboard sees it.
        #[cfg(feature = "multiuser")]
        let (multiuser, multiuser_admin, master_address) = if self.plugin_enabled("Multiuser").await
        {
            (true, true, self.multiuser_list().await.first().cloned().unwrap_or_default())
        } else {
            (false, false, String::new())
        };
        #[cfg(not(feature = "multiuser"))]
        let (multiuser, multiuser_admin, master_address): (bool, bool, String) =
            (false, false, String::new());
        let language = self
            .config_get("language")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "en".to_string());
        let (port_opened, detected_ip) = self.port_status().await;
        let configured_ip = self
            .config_get("ip_external")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|x| !x.is_empty());
        let ip_external = if let Some(ip) = configured_ip {
            json!(ip)
        } else if let (true, Some(ip)) = (port_opened, detected_ip) {
            json!(ip)
        } else {
            json!(false)
        };
        let fileserver_port = self.fileserver_port().await;
        let (tor_enabled, tor_status) = self.tor_status().await;
        // The dashboard reads `fileserver_ip == "127.0.0.1"` as "route all via
        // Tor" (the fileserver is loopback-only). Only report that in Tor-always
        // mode; otherwise "*" (all interfaces), matching EpixNet's default - so
        // the dashboard doesn't wrongly warn "your browser is not safe".
        let fileserver_ip = if tor_status == "Always" { "127.0.0.1" } else { "*" };
        let rev = self.rev().await;
        let ui_port = self.ui_port().await;
        let (epix_browser, browser_tor_clearnet) = self.browser_settings().await;
        let ui_restrict = self.ui_restrict().await;
        json!({
            "version": self.version,
            "rev": rev,
            "platform": std::env::consts::OS,
            "dist_type": "standalone",
            "ip_external": ip_external,
            "port_opened": port_opened,
            "fileserver_ip": fileserver_ip,
            "fileserver_port": fileserver_port,
            "tor_enabled": tor_enabled,
            "tor_status": tor_status,
            "tor_has_meek_bridges": false,
            "tor_use_bridges": false,
            "network_status": self.network_status().await,
            "epix_browser": epix_browser,
            "browser_tor_clearnet": browser_tor_clearnet,
            // Read-only gateway mode: the dashboard hides node-lifecycle
            // controls (shut down, restart) since the backend refuses them here.
            "ui_restrict": ui_restrict,
            "ui_ip": "127.0.0.1",
            "ui_port": ui_port,
            "debug": false,
            "offline": false,
            "multiuser": multiuser,
            "multiuser_admin": multiuser_admin,
            "master_address": master_address,
            "connections": connections,
            "timecorrection": 0.0,
            "lib_verify_best": "sslcrypto",
            "plugins": plugins,
            "plugins_rev": {},
            "user_settings": user_settings,
            "language": language,
        })
    }

    /// Per-network inbound reachability for the dashboard's Network pill. Each
    /// entry says whether peers can reach this node over that network; the
    /// top-level `reachable` is true when ANY of them works (a Tor-only or
    /// I2P-only node still counts as reachable). Additive to `serverInfo` -
    /// the older `port_opened`/`ip_external`/`tor_*` fields stay as they were.
    pub async fn network_status(&self) -> Value {
        let (port_opened, detected_ip) = self.port_status().await;
        let fileserver_port = self.fileserver_port().await;
        let configured_ip = self
            .config_get("ip_external")
            .await
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|x| !x.is_empty());
        // Seeding disabled (port 0) means no clearnet inbound at all.
        let clearnet_enabled = fileserver_port != 0;
        let clearnet_reachable = clearnet_enabled && port_opened;
        let clearnet_ip = configured_ip.or(detected_ip);

        let (tor_enabled, tor_status) = self.tor_status().await;
        let onion = self.onion_address().await;
        let tor_ok = matches!(tor_status.as_str(), "OK" | "Always");
        let tor_reachable = tor_enabled && tor_ok && onion.is_some();

        let i2p = self.i2p_status().await;
        let i2p_str = |k: &str| i2p.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let i2p_mode = i2p_str("mode").unwrap_or_default();
        let i2p_enabled = !i2p_mode.is_empty() && i2p_mode != "disable";
        // Peers can only dial us over I2P once our inbound destination is
        // published, i.e. we have a non-empty b32. While the session is still
        // "Starting…" the status carries an empty b32, which is not reachable.
        let i2p_b32 = i2p_str("b32").filter(|s| !s.is_empty());
        let i2p_reachable = i2p_enabled && i2p_b32.is_some();

        let reachable = clearnet_reachable || tor_reachable || i2p_reachable;

        json!({
            "reachable": reachable,
            "clearnet": {
                "enabled": clearnet_enabled,
                "reachable": clearnet_reachable,
                "port": fileserver_port,
                "ip": clearnet_ip,
            },
            "tor": {
                "enabled": tor_enabled,
                "reachable": tor_reachable,
                "status": tor_status,
                "always": tor_ok && tor_status == "Always",
                "address": onion.map(|o| format!("{o}.onion")),
            },
            "i2p": {
                "enabled": i2p_enabled,
                "reachable": i2p_reachable,
                "phase": i2p_str("phase"),
                // The runtime's status carries the session's full
                // `<hash>.b32.i2p` (epix-runtime feeds `s.b32` verbatim);
                // normalize instead of appending blindly so neither feed
                // shape renders a doubled `.i2p.i2p`.
                "address": i2p_b32.map(|b| if b.ends_with(".i2p") { b } else { format!("{b}.i2p") }),
            },
        })
    }

    /// Whether the node runs under the Epix Browser (its native host writes
    /// `browser-settings.json` next to the node data) and whether that browser
    /// routes clearnet (non-`.epix`) traffic through Tor. Returns
    /// `(epix_browser, tor_clearnet)`. `tor_clearnet` defaults on (opt-out),
    /// matching epix-nmh's `Settings::tor_clearnet`. The dashboard uses this to
    /// drop the "your browser is not safe" warning in Tor-always mode when the
    /// browser already tunnels clearnet through Tor.
    pub async fn browser_settings(&self) -> (bool, bool) {
        let Some(root) = &self.data_root else { return (false, true) };
        match std::fs::read(root.join("browser-settings.json")) {
            Ok(bytes) => {
                let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                let tor_clearnet =
                    v.get("tor_clearnet").and_then(|b| b.as_bool()).unwrap_or(true);
                (true, tor_clearnet)
            }
            Err(_) => (false, true),
        }
    }

    /// Push the latest `serverInfo` (`setServerInfo`) on the `serverChanged`
    /// channel, so the dashboard's server readouts update live (plugins,
    /// connection counts, tor status, …).
    pub async fn push_server_info(&self) {
        let info = self.server_info().await;
        self.push_event("setServerInfo", info, Some("serverChanged"), None);
    }

    /// Push a file/site progress event (`progress [inner_path, done, total]`),
    /// so the wrapper's loading bar advances during a download.
    pub fn push_progress(&self, address: &str, inner_path: &str, done: i64, total: i64) {
        self.push_event(
            "progress",
            json!([inner_path, done, total]),
            None,
            Some(address.to_string()),
        );
    }

    /// Ask the wrapper to navigate (`redirect <url>`).
    pub fn push_redirect(&self, address: &str, url: &str) {
        self.push_event("redirect", json!(url), None, Some(address.to_string()));
    }

    /// Inject a script into the wrapper (`injectScript <script>`).
    pub fn push_inject_script(&self, address: &str, script: &str) {
        self.push_event("injectScript", json!(script), None, Some(address.to_string()));
    }

    /// Push a `{cmd, params, to}` event that expects a reply, and return a
    /// receiver for the wrapper's answer (delivered as `{cmd:"response", to}`).
    /// Used by `confirm`/`prompt`.
    fn push_cmd_await(
        &self,
        cmd: &str,
        params: Value,
        target: Option<String>,
    ) -> tokio::sync::oneshot::Receiver<Value> {
        let id = self.nonce_counter.fetch_add(1, Ordering::Relaxed) as i64;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.callbacks.lock().unwrap().insert(id, tx);
        // The wrapper answers a pushed confirm/prompt with
        // `{cmd:"response", to: message.id}` - so the callback key must go out
        // as `id` (EpixNet's UiWebsocket.cmd does the same). Sent as `to`, the
        // reply comes back without an id and the waiting future times out
        // silently: an "Add N new site?" dialog whose Add button does nothing.
        let payload = json!({ "cmd": cmd, "params": params, "id": id }).to_string();
        let _ =
            self.events.send(UiEvent { channel: None, target, payload, exclude: None, only: None });
        rx
    }

    /// Resolve a pending wrapper callback (`{cmd:"response", to}`). Returns true
    /// if a callback was waiting on `to`.
    pub fn resolve_callback(&self, to: i64, result: Value) -> bool {
        if let Some(tx) = self.callbacks.lock().unwrap().remove(&to) {
            let _ = tx.send(result);
            true
        } else {
            false
        }
    }

    /// Ask the wrapper to confirm (`confirm [body, button_title]`); resolves to
    /// the user's choice. Times out to `false` if no wrapper answers.
    pub async fn confirm(&self, address: &str, body: &str, button_title: &str) -> bool {
        let rx = self.push_cmd_await(
            "confirm",
            json!([body, button_title]),
            Some(address.to_string()),
        );
        match tokio::time::timeout(std::time::Duration::from_secs(120), rx).await {
            Ok(Ok(v)) => v.as_bool().unwrap_or(!v.is_null()),
            _ => false,
        }
    }

    /// Ask the wrapper to prompt for input (`prompt [body, type]`); resolves to
    /// the entered string, or None on timeout/cancel.
    pub async fn prompt(&self, address: &str, body: &str, input_type: &str) -> Option<String> {
        let rx =
            self.push_cmd_await("prompt", json!([body, input_type]), Some(address.to_string()));
        match tokio::time::timeout(std::time::Duration::from_secs(120), rx).await {
            Ok(Ok(Value::String(s))) => Some(s),
            _ => None,
        }
    }

    /// Enforce chart-db retention (drop old datapoints, reclaim space). Called
    /// periodically by the runtime so `chart.db` does not grow without bound.
    pub async fn archive_chart(&self) {
        self.chart.archive(now_secs());
    }

    /// Snapshot current node metrics into the chart db: one global datapoint
    /// set plus a per-xite set. Called at startup and periodically by the
    /// runtime so the dashboard's Stats page has data to draw.
    pub async fn collect_chart(&self) {
        use crate::chart::Metric;
        let now = now_secs();
        let optional_limit = self.optional_limit_bytes().await;
        let conns = self.connection_stats().await;
        let xites = self.xites.read().await;

        let mut size = 0i64;
        let mut size_optional = 0i64;
        let mut optional_used = 0i64;
        let mut bytes_recv = 0f64;
        let mut bytes_sent = 0f64;
        let mut unique_peers = std::collections::HashSet::new();
        let mut onion_peers = std::collections::HashSet::new();
        let mut content = std::collections::HashSet::new();
        for (addr, x) in xites.iter() {
            size += x.settings.size;
            size_optional += x.settings.size_optional;
            optional_used += x.settings.optional_downloaded;
            bytes_recv += x.bytes_recv as f64;
            bytes_sent += x.bytes_sent as f64;
            for p in x.peers.peers() {
                let key = p.addr.to_string();
                if p.is_onion() {
                    onion_peers.insert(key.clone());
                }
                unique_peers.insert(key);
            }
            // Count distinct sites by signed content address (alias + raw key
            // point at the same content), matching site_list.
            match x.content.as_ref().and_then(|c| c.get("address")).and_then(Value::as_str) {
                Some(a) => { content.insert(a.to_string()); }
                None => { content.insert(addr.clone()); }
            }
        }

        let global = [
            Metric::now("peer", unique_peers.len() as f64),
            Metric::now("peer_onion", onion_peers.len() as f64),
            Metric::now("connection", conns.total as f64),
            Metric::now("connection_onion", conns.onion as f64),
            Metric::now("connection_in", conns.incoming as f64),
            Metric::now("connection_ping_avg", conns.ping_avg as f64),
            Metric::now("connection_ping_min", conns.ping_min as f64),
            Metric::now("size", size as f64),
            Metric::now("size_optional", size_optional as f64),
            Metric::now("optional_used", optional_used as f64),
            Metric::now("optional_limit", optional_limit as f64),
            Metric::now("content", content.len() as f64),
            Metric::change("file_bytes_recv", bytes_recv),
            Metric::change("file_bytes_sent", bytes_sent),
        ];
        self.chart.record(now, None, &global);

        for (addr, x) in xites.iter() {
            let Some(site_id) = self.chart.site_id(addr) else { continue };
            let site = [
                Metric::now("site_size", x.settings.size as f64),
                Metric::now("site_size_optional", x.settings.size_optional as f64),
                Metric::now("site_optional_downloaded", x.settings.optional_downloaded as f64),
                Metric::now("site_peer", x.peers.len() as f64),
                Metric::change("site_bytes_recv", x.bytes_recv as f64),
                Metric::change("site_bytes_sent", x.bytes_sent as f64),
            ];
            self.chart.record(now, Some(site_id), &site);
        }
    }

    /// The `merged_type` a xite's content.json declares, if any (the mark of a
    /// site that belongs to a merger, e.g. a Git Epix repo).
    pub async fn site_merged_type(&self, address: &str) -> Option<String> {
        self.xites
            .read()
            .await
            .get(address)
            .and_then(|x| x.content.as_ref())
            .and_then(|c| c.get("merged_type"))
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// The merger types a site declares (`Merger:<type>` permissions).
    pub async fn merger_types(&self, address: &str) -> Vec<String> {
        self.xites
            .read()
            .await
            .get(address)
            .map(|x| {
                x.settings
                    .permissions
                    .iter()
                    .filter_map(|p| p.strip_prefix("Merger:").map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `mergerSiteList`: the served sites whose content.json `merged_type` is one
    /// this merger accepts. `address -> merged_type`, or `-> siteInfo` when
    /// `query_site_info`.
    pub async fn merger_list(&self, address: &str, query_site_info: bool) -> Result<Value, String> {
        let merger_types = self.merger_types(address).await;
        if merger_types.is_empty() {
            return Err("Not a merger site".into());
        }
        // Collect matches under the read lock, then build the response (siteInfo
        // re-locks, so don't hold the lock across it).
        let matches: Vec<(String, String)> = {
            let xites = self.xites.read().await;
            xites
                .iter()
                .filter_map(|(addr, x)| {
                    let mt = x.content.as_ref()?.get("merged_type")?.as_str()?.to_string();
                    merger_types.contains(&mt).then(|| (addr.clone(), mt))
                })
                .collect()
        };

        let mut ret = serde_json::Map::new();
        for (addr, merged_type) in matches {
            let value = if query_site_info { self.site_info(&addr).await } else { json!(merged_type) };
            ret.insert(addr, value);
        }
        Ok(Value::Object(ret))
    }

    /// Fill every merger site's version-3 database from its merged sites: for
    /// each merger, populate its db from each served site whose `merged_type`
    /// the merger accepts, tagging rows with the merged site's address. Call
    /// after the merged sites are served (or when they change).
    pub async fn rebuild_merger_dbs(&self) {
        // Snapshot the merged sites (address, content dir, merged_type)…
        let merged: Vec<(String, std::path::PathBuf, String)> = {
            let xites = self.xites.read().await;
            xites
                .iter()
                .filter_map(|(addr, x)| {
                    let mt = x.content.as_ref()?.get("merged_type")?.as_str()?.to_string();
                    Some((addr.clone(), x.storage.root().to_path_buf(), mt))
                })
                .collect()
        };
        // …and the merger sites with a version-3 db (handle + schema + accepted types).
        let mergers: Vec<(Database, DbSchema, Vec<String>)> = {
            let xites = self.xites.read().await;
            xites
                .values()
                .filter_map(|x| {
                    let schema = x.db_schema.clone()?;
                    if schema.version != 3 {
                        return None;
                    }
                    let db = x.db.clone()?;
                    let types: Vec<String> = x
                        .settings
                        .permissions
                        .iter()
                        .filter_map(|p| p.strip_prefix("Merger:").map(String::from))
                        .collect();
                    if types.is_empty() {
                        return None;
                    }
                    Some((db, schema, types))
                })
                .collect()
        };
        for (db, schema, types) in mergers {
            for (merged_addr, merged_dir, merged_type) in &merged {
                if types.contains(merged_type) {
                    // Scan the merged site's root and key every file under the
                    // merged site's address. EpixNet nests merged sites
                    // physically at `merged-<type>/<address>/`, so its relative
                    // paths (and json.directory) begin with the address; we
                    // reproduce that with the prefix instead of nesting on disk.
                    // The `db_file` subdir is where the MERGER keeps its own db,
                    // not a subdir of each merged site, so it is not joined here.
                    let _ = db.populate_site(&schema, merged_dir, merged_addr);
                }
            }
        }
    }

    /// The merged site + inner path for a `merged-<type>/<address>/<path>` path,
    /// if it is one (else `None`).
    pub fn split_merged_path(inner_path: &str) -> Option<(String, String)> {
        Self::split_merged_path_typed(inner_path).map(|(_, address, inner)| (address, inner))
    }

    /// [`Self::split_merged_path`], keeping the type:
    /// `(merged_type, address, inner_path)`.
    pub fn split_merged_path_typed(inner_path: &str) -> Option<(String, String, String)> {
        let rest = inner_path.strip_prefix("merged-")?;
        // merged-<type>/<address>/<inner_path>
        let mut parts = rest.splitn(3, '/');
        let merged_type = parts.next()?.to_string();
        let address = parts.next()?.to_string();
        let inner = parts.next().unwrap_or("").to_string();
        Some((merged_type, address, inner))
    }

    /// Resolve a merger site's `merged-<type>/<address>/<path>` reference to
    /// the real `(address, inner_path)`, enforcing MergerSite's access rules
    /// (EpixNet's `checkMergerPath`): the merger must hold the
    /// `Merger:<type>` permission and the target must be a served site whose
    /// content.json declares that `merged_type`. `Ok(None)` when the path is
    /// not a merged path at all.
    pub async fn resolve_merged(
        &self,
        merger: &str,
        inner_path: &str,
    ) -> Result<Option<(String, String)>, String> {
        let Some((merged_type, address, inner)) = Self::split_merged_path_typed(inner_path) else {
            return Ok(None);
        };
        if !self.merger_types(merger).await.contains(&merged_type) {
            return Err(format!(
                "No merger permission to load: {merger} holds no Merger:{merged_type}"
            ));
        }
        let key = self.canonical_key(&address).await;
        if !self.has_xite(&key).await {
            return Err(format!("Merged site not found: {address}"));
        }
        if self.site_merged_type(&key).await.as_deref() != Some(merged_type.as_str()) {
            // A site mid-clone has no verified content.json yet, so it cannot
            // declare its merged_type. Let it through so its files serve
            // progressively during the initial hub clone (the html wait loop
            // gates on this same signal) instead of erroring until it lands.
            let still_cloning = self.is_cloning(&key) && self.content(&key).await.is_none();
            if !still_cloning {
                return Err(format!(
                    "Merger site ({merged_type}) does not have permission for merged site: {address}"
                ));
            }
        }
        Ok(Some((key, inner)))
    }

    // --- publish / sign ------------------------------------------------------

    /// Set the base peer transport (TCP, or Tor's MixedTransport). Recomposes
    /// with I2P dispatch if I2P is up, so neither overwrites the other.
    pub async fn set_transport(&self, transport: Arc<dyn Transport>) {
        *self.base_transport.write().await = Some(transport);
        self.recompose_transport().await;
    }

    /// Set the I2P transport (dials `.b32.i2p` peers). Layered onto the base.
    pub async fn set_i2p_transport(&self, transport: Arc<dyn Transport>) {
        *self.i2p_transport.write().await = Some(transport);
        self.recompose_transport().await;
    }

    /// Set the Reticulum mesh transport (dials `rns:` dest hashes). Layered
    /// onto the base like I2P.
    pub async fn set_rns_transport(&self, transport: Arc<dyn Transport>) {
        *self.rns_transport.write().await = Some(transport);
        self.recompose_transport().await;
    }

    /// Rebuild the composed transport from the base + the overlay layers.
    async fn recompose_transport(&self) {
        let base = self.base_transport.read().await.clone();
        let i2p = self.i2p_transport.read().await.clone();
        let rns = self.rns_transport.read().await.clone();
        let composed: Option<Arc<dyn Transport>> = match (base, i2p, rns) {
            (Some(base), None, None) => Some(base),
            (Some(base), i2p, rns) => Some(Arc::new(OverlayTransport { base, i2p, rns })),
            _ => None,
        };
        *self.transport.write().await = composed;
    }

    /// The (composed) transport set by the node, once available.
    pub async fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.transport.read().await.clone()
    }

    /// Store the latest I2P status snapshot (JSON) for the Stats page.
    pub async fn set_i2p_status(&self, status: Value) {
        *self.i2p_status.write().await = status;
    }

    /// The latest I2P status snapshot (`{}` when I2P is off).
    pub async fn i2p_status(&self) -> Value {
        self.i2p_status.read().await.clone()
    }

    /// Install the on-demand resolver (set by the node).
    pub async fn set_on_demand(&self, resolver: Arc<dyn OnDemandResolver>) {
        *self.on_demand.write().await = Some(resolver);
    }

    /// Install the DHT-backed peer lookup (set by the runtime).
    pub async fn set_peer_finder(&self, finder: Arc<dyn PeerFinder>) {
        *self.peer_finder.write().await = Some(finder);
    }

    /// Look up peers for `address` via the installed [`PeerFinder`] (the DHT),
    /// or an empty list when none is installed. Drops this node's own addresses:
    /// we announce our onion/i2p/rns self-claims to the DHT, and a lookup for a
    /// site we serve echoes them straight back. The clone/user-content dial
    /// paths call this directly (bypassing [`Self::add_peers`]' own-peer
    /// filter), so without this a sole seeder would dial its own onion service
    /// and "sync" from itself, masking the no-peers condition.
    pub async fn find_peers_dht(&self, address: &str) -> Vec<PeerAddr> {
        let hook = self.peer_finder.read().await.clone();
        let Some(hook) = hook else { return Vec::new() };
        let mut peers = hook.find(address).await;
        let mut kept = Vec::with_capacity(peers.len());
        for peer in peers.drain(..) {
            if !self.is_own_peer(&peer).await {
                kept.push(peer);
            }
        }
        kept
    }

    /// Install the included/user-content syncer (set by the node).
    pub async fn set_content_syncer(&self, syncer: Arc<dyn ContentSyncer>) {
        *self.content_syncer.write().await = Some(syncer);
    }

    /// Sync a xite's included / per-user content via the installed
    /// [`ContentSyncer`]; rebuilds the db when anything new arrived.
    pub async fn sync_user_content(&self, address: &str) -> u64 {
        let hook = self.content_syncer.read().await.clone();
        let Some(hook) = hook else { return 0 };
        let (bytes, files) = hook.sync_user_content(address).await;
        if bytes > 0 {
            self.rebuild_xite_db(address).await;
            // A merged site's fresh rows must reach its merger's db too (its
            // repos/issues live there; the merger page queries only its own db).
            if self.site_merged_type(address).await.is_some() {
                self.rebuild_merger_dbs().await;
            }
            self.log("INFO", format!("Synced user content for {address} ({bytes} bytes)")).await;
            // Per-file file_done events already fired as each file landed
            // (ingest_file); one site_info refreshes the aggregate counts.
            let _ = files;
            self.push_site_info(address).await;
        }
        bytes
    }

    /// Ingest ONE just-arrived file into the xite's database (and, when the
    /// xite is a merged site, into every merger database aggregating it),
    /// then push its `file_done` event so open pages re-query. EpixNet does
    /// this per file as it is written (`SiteStorage.onUpdated` ->
    /// `Db.updateJson` -> websocket `file_done`), which is what makes
    /// topics/posts pop in one by one while a site is still syncing; batching
    /// it into one rebuild at the end of the pass left pages empty until the
    /// whole sync (minutes when peers are slow) finished.
    pub async fn ingest_file(&self, address: &str, inner_path: &str) {
        self.ingest_file_from(address, inner_path, None).await;
    }

    /// [`Self::ingest_file`] for a locally-written file: `origin` is the
    /// connection whose command wrote it, excluded from the `file_done` echo
    /// (EpixNet notifies `ws != self`).
    pub async fn ingest_file_from(&self, address: &str, inner_path: &str, origin: Option<u64>) {
        // ContentFilter: a muted author's file stays out of the db, and gets
        // no event - nothing changed for the page.
        if self.muted_authors().await.iter().any(|m| inner_path.contains(m.as_str())) {
            return;
        }
        // A content.json (a synced per-user file, or one we just signed)
        // carries a `modified` clock: fold it into settings.modified so the
        // dashboard's "last updated" reflects user posts, not just the root
        // (EpixNet advances settings.modified on every content.json load).
        if inner_path.ends_with("content.json") {
            let modified = {
                let xites = self.xites.read().await;
                xites.get(address).and_then(|x| x.storage.read(inner_path).ok())
            }
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|c| c.get("modified").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);
            self.bump_modified(address, modified).await;
        }
        // Snapshot the db handle out of the lock; file + SQL work runs unlocked.
        let mut build_first = false;
        let own: Option<(Database, DbSchema)> = {
            let xites = self.xites.read().await;
            match xites.get(address) {
                None => None,
                Some(x) => match (&x.db, &x.db_schema) {
                    // A version-3 merger db fills from its merged sites, not
                    // its own tree - only the merger loop below applies.
                    (Some(db), Some(schema)) if schema.version != 3 => {
                        Some((db.clone(), schema.clone()))
                    }
                    (Some(_), _) => None,
                    // No db yet but the schema has arrived (a clone in
                    // progress): the first data file triggers the build, which
                    // ingests everything on disk so far, this file included.
                    (None, _) => {
                        build_first = x.storage.exists("dbschema.json");
                        None
                    }
                },
            }
        };
        if build_first {
            self.rebuild_xite_db(address).await;
        } else if let Some((db, schema)) = own {
            let db_dir = {
                let xites = self.xites.read().await;
                xites.get(address).map(|x| db_file_dir(x.storage.root(), &schema.db_file))
            };
            if let Some(db_dir) = db_dir {
                // Paths are matched relative to the db file's directory
                // (EpixNet's db_dir); a file outside it can't match any map.
                let db_sub = schema.db_file.replace('\\', "/");
                let db_sub = db_sub.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                let rel = if db_sub.is_empty() {
                    Some(inner_path)
                } else {
                    inner_path.strip_prefix(db_sub).and_then(|p| p.strip_prefix('/'))
                };
                if let Some(rel) = rel {
                    let _ = db.update_file(&schema, &db_dir, rel, "", "");
                }
            }
        }
        // A merged site's file must also reach the mergers aggregating it:
        // their pages (Git Epix's repo list, Epix Post's feed) query only
        // their own version-3 db.
        let merged_type = self.site_merged_type(address).await;
        if let Some(mt) = merged_type {
            let root = {
                let xites = self.xites.read().await;
                xites.get(address).map(|x| x.storage.root().to_path_buf())
            };
            let mergers: Vec<(Database, DbSchema)> = {
                let xites = self.xites.read().await;
                xites
                    .values()
                    .filter_map(|x| {
                        let schema = x.db_schema.clone()?;
                        if schema.version != 3 {
                            return None;
                        }
                        let accepts = x
                            .settings
                            .permissions
                            .iter()
                            .any(|p| p.strip_prefix("Merger:") == Some(mt.as_str()));
                        accepts.then_some((x.db.clone()?, schema))
                    })
                    .collect()
            };
            if let Some(root) = root {
                for (db, schema) in mergers {
                    // db_dir is the merged site's root; the regex match sees
                    // the path keyed under the merged site's address, and the
                    // rows are tagged with it (populate_site's convention).
                    let _ = db.update_file(&schema, &root, inner_path, address, address);
                }
            }
        }
        self.push_site_info_file_done(address, inner_path, origin).await;
    }

    /// Ensure `host` (a `.epix` name) is served, resolving + cloning it on demand
    /// if a resolver is installed and it isn't served yet. Returns whether it is
    /// now served. Used by the browser proxy path so typing any `talk.epix`
    /// clones and opens it live.
    pub async fn ensure_xite(&self, host: &str) -> bool {
        self.ensure_xite_inner(host, false).await
    }

    /// Operator variant (the trusted admin socket): clone `host` even when
    /// NoNewSites locks the site set, so `siteDownload` works server-side.
    pub async fn ensure_xite_admin(&self, host: &str) -> bool {
        self.ensure_xite_inner(host, true).await
    }

    async fn ensure_xite_inner(&self, host: &str, force: bool) -> bool {
        // Served AND complete (or ours): done. A registered xite whose core
        // files are missing (an interrupted clone) still goes to the resolver
        // so its download resumes - the periodic resync only fetches files
        // when a newer content.json shows up, so it never heals one. Owned
        // sites never re-download: local edits stay.
        let key0 = self.canonical_key(host).await;
        if self.has_xite(&key0).await
            && (self.xite_owned(&key0).await || self.xite_core_complete(&key0).await)
        {
            // Files are complete on disk. Heal an interrupted finalize where the
            // in-memory content.json was never loaded (clone errored after
            // writing files; an incomplete resync) - otherwise the wrapper shows
            // a perpetual download page and siteInfo has no title.
            self.load_content_from_disk(&key0).await;
            return true;
        }
        // NoNewSites (unless an operator forces it): the site set is locked, but
        // an xID must still RESOLVE and a xite already on this node must still
        // serve and resume/update. Only a brand-new xite (one we do not already
        // have) is refused - the caller shows the "new xites disabled" page.
        if !force && self.no_new_sites().await {
            let key = self.resolve_for_serving(host).await;
            if !self.has_xite(&key).await {
                return false;
            }
            // Registered but maybe incomplete: fall through so the resolver
            // resumes its download. This adds no new site, it heals an existing
            // one.
        }
        let hook = self.on_demand.read().await.clone();
        match hook {
            Some(hook) => {
                if let Err(e) = hook.ensure(host).await {
                    self.log("INFO", format!("On-demand resolve of {host} failed: {e}")).await;
                }
                self.has_xite(&self.canonical_key(host).await).await
            }
            None => false,
        }
    }

    /// Resolve `host` to a xite address for SERVING (no cloning): the in-memory
    /// display metadata and on-disk cache first (via `canonical_key`), then the
    /// chain through the on-demand resolver. Returns the address if resolved, or
    /// `host` unchanged if it cannot be. Lets a locked-down node follow an xID
    /// to a xite it already serves without adding anything new.
    pub async fn resolve_for_serving(&self, host: &str) -> String {
        let key = self.canonical_key(host).await;
        // Resolved via cache/display, or `host` is already a bech32 address.
        if key != host || !host.contains('.') {
            return key;
        }
        if let Some(hook) = self.on_demand.read().await.clone() {
            if let Some(address) = hook.resolve(host).await {
                return address;
            }
        }
        key
    }

    /// Mark a xite owned/not (`siteSetOwned`). Signing still requires the key.
    pub async fn set_owned(&self, address: &str, owned: bool) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.own = owned;
        }
        self.persist_sites().await;
    }

    /// Try to recover a xite's private key from the user's master seed via its
    /// `address_index` (only works for sites this user created). `"ok"` on
    /// success (key saved + marked owned), else `{error}`. `siteRecoverPrivatekey`.
    pub async fn recover_privatekey(&self, address: &str) -> Value {
        if self.user.read().await.site_privatekey(address).is_some() {
            return json!({ "error": "This site already has a saved private key" });
        }
        let content = self.content(address).await;
        let Some(index) = content.as_ref().and_then(|c| c.get("address_index")).and_then(|v| v.as_u64())
        else {
            return json!({ "error": "No address_index in content.json" });
        };
        let seed = self.user.read().await.master_seed.clone();
        let privatekey = match epix_crypt::hd_privatekey(&seed, index) {
            Ok(p) => p,
            Err(e) => return json!({ "error": e }),
        };
        match epix_crypt::privatekey_to_address(&privatekey) {
            Ok(derived) if derived == address => {
                let _ = self.user.write().await.set_site_privatekey(address, &privatekey);
                self.save_user().await;
                self.set_owned(address, true).await;
                json!("ok")
            }
            _ => json!({ "error": "Unable to deliver private key for this site from current user's master_seed" }),
        }
    }

    /// Save a xite's private key directly (`userSetSitePrivatekey`), marking it
    /// owned.
    pub async fn set_site_privatekey(&self, address: &str, privatekey: &str) -> Result<(), String> {
        self.user.write().await.set_site_privatekey(address, privatekey)?;
        self.set_owned(address, true).await;
        Ok(())
    }

    /// The saved private key for a xite (used to auto-sign on publish).
    pub async fn site_privatekey(&self, address: &str) -> Option<String> {
        self.user.read().await.site_privatekey(address)
    }

    /// The content rules for `inner_path` - chiefly the `signers` allowed to
    /// sign it (the sidebar checks these before prompting for a key). For the
    /// root content.json that's the xite's own address (or its declared
    /// `signers`); for a user content, the user's auth address. `fileRules`.
    pub async fn file_rules(&self, address: &str, inner_path: &str) -> Value {
        if inner_path.starts_with("data/users/") && inner_path.ends_with("content.json") {
            if let Some(rules) = self.user_content_rules(address, inner_path).await {
                return rules;
            }
        }
        let content = self.content(address).await;
        let signers = if inner_path.starts_with("data/users/") {
            let auth = self.user.write().await.auth_address(address).unwrap_or_default();
            vec![Value::from(auth)]
        } else {
            content
                .as_ref()
                .and_then(|c| c.get("signers"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_else(|| vec![Value::from(address)])
        };
        let signers_required = content
            .as_ref()
            .and_then(|c| c.get("signers_required"))
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        json!({
            "signers": signers,
            "signers_required": signers_required,
            "user_contents": content.as_ref().and_then(|c| c.get("user_contents")).cloned().unwrap_or(Value::Null),
            "cert_signers": {},
            "max_size": 10 * 1024 * 1024,
            "files_allowed": ".*",
        })
    }

    /// Resolve the governing rules for a user content.json and stamp on its
    /// `current_size`. Returns `None` if no parent `user_contents` governs it
    /// (the caller falls back to the generic rules).
    async fn user_content_rules(&self, address: &str, inner_path: &str) -> Option<Value> {
        let storage = self.xites.read().await.get(address)?.storage.clone();
        // The content being rule-checked: the user's stored content.json, or -
        // when they haven't posted yet - a synthetic one carrying the current
        // cert so the per-user permission_rules still match.
        let stored = storage.read(inner_path).ok();
        let content: Value = match &stored {
            Some(bytes) => serde_json::from_slice(bytes).ok()?,
            None => {
                let mut c = serde_json::Map::new();
                let user = self.user.read().await;
                if let (Some(id), Some(cert)) = (user.cert_user_id(address), user.get_cert(address))
                {
                    c.insert("cert_user_id".into(), json!(id));
                    c.insert("cert_auth_type".into(), json!(cert.auth_type));
                    c.insert("cert_sign".into(), json!(cert.cert_sign));
                }
                Value::Object(c)
            }
        };
        let xid_map = Self::resolve_xid_map(&storage, inner_path).await;
        let addr = Address::parse(address.to_string()).ok()?;
        let xite = Xite::new(addr, storage);
        let mut rules = xite.content_rules(inner_path, &content, &xid_map)?;
        // current_size = the raw content.json bytes + its declared files, the
        // same measure verification limits with `max_size` (EpixNet uses
        // len(dumps(content)) + sum(file sizes); an empty synthetic is 0).
        let current_size = match &stored {
            Some(bytes) => {
                let files: i64 = content
                    .get("files")
                    .and_then(|f| f.as_object())
                    .map(|m| {
                        m.values()
                            .filter_map(|f| f.get("size").and_then(|s| s.as_i64()))
                            .sum()
                    })
                    .unwrap_or(0);
                bytes.len() as i64 + files
            }
            None => 0,
        };
        if let Some(obj) = rules.as_object_mut() {
            obj.insert("current_size".into(), json!(current_size));
        }
        Some(rules)
    }

    /// Write a file into a xite's storage (`fileWrite`).
    pub async fn write_file(&self, address: &str, inner_path: &str, bytes: &[u8]) -> Result<(), String> {
        let storage = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.clone())
            .ok_or("unknown xite")?;
        // Keep the previous version as `<file>-old` (EpixNet's actionFileWrite):
        // the next publish diffs old vs new so peers patch their copies instead
        // of fetching the file back - which they often can't, when the
        // publisher is unreachable from outside (NAT, port taken).
        if inner_path.ends_with(".json")
            && !inner_path.ends_with("content.json")
            && storage.exists(inner_path)
            && !storage.exists(&format!("{inner_path}-old"))
        {
            if let Ok(old) = storage.read(inner_path) {
                let _ = storage.write(&format!("{inner_path}-old"), &old);
            }
        }
        storage.write(inner_path, bytes).map_err(|e| e.to_string())?;
        if inner_path == "content.json" {
            if let Ok(content) = serde_json::from_slice::<Value>(bytes) {
                self.update_content(address, Some(content)).await;
            }
        }
        Ok(())
    }

    /// Delete a file from a xite's storage (`fileDelete`). If the file is an
    /// optional file, its `files_optional` entry is removed from the stored
    /// content.json as well (matching EpixNet's `actionFileDelete`; the
    /// content.json becomes changed-needs-signing). `origin` is the deleting
    /// connection, excluded from the event echo.
    pub async fn delete_file(
        &self,
        address: &str,
        inner_path: &str,
        origin: Option<u64>,
    ) -> Result<(), String> {
        let (storage, content) = {
            let x = self.xites.read().await;
            let e = x.get(address).ok_or("unknown xite")?;
            (e.storage.clone(), e.content.clone())
        };
        let is_optional = content
            .as_ref()
            .and_then(|c| c.get("files_optional"))
            .and_then(|f| f.get(inner_path))
            .is_some();
        if is_optional {
            if let Ok(bytes) = storage.read("content.json") {
                if let Ok(mut json) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(map) =
                        json.get_mut("files_optional").and_then(|f| f.as_object_mut())
                    {
                        if map.remove(inner_path).is_some() {
                            let out = epix_content::dumps_content(&json);
                            let _ = storage.write("content.json", out.as_bytes());
                        }
                    }
                }
            }
        }
        if storage.exists(inner_path) {
            storage
                .delete(inner_path)
                .map_err(|e| format!("Delete error: {e}"))?;
        } else if !is_optional {
            return Err("Delete error: file does not exist".into());
        }
        self.push_site_info_event_excluding(address, "file_deleted", origin).await;
        Ok(())
    }

    /// Sign a xite's content.json with `privatekey` (rebuilds the files map,
    /// bumps `modified` past the previous value), updating the managed content
    /// + settings. Returns the signed content.json bytes. The key must own the
    /// xite. This is `siteSign`.
    pub async fn sign_xite(&self, address: &str, privatekey: &str) -> Result<Vec<u8>, String> {
        let (storage, content) = {
            let x = self.xites.read().await;
            let e = x.get(address).ok_or("unknown xite")?;
            (e.storage.clone(), e.content.clone())
        };
        let addr = Address::parse(address.to_string()).map_err(|e| e.to_string())?;
        let mut xite = Xite::new(addr, storage);
        xite.content = xite
            .storage
            .read("content.json")
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .or(content);

        // Stamp the running node version onto the root content.json before
        // signing (EpixNet's ContentManager.sign sets `epixnet_version =
        // config.version`), so a re-signed xite advertises the version that
        // signed it instead of carrying whatever stale value it shipped with.
        if let Some(map) = xite.content.as_mut().and_then(|c| c.as_object_mut()) {
            map.insert("epixnet_version".into(), json!(self.version));
        }

        let prev = xite
            .content
            .as_ref()
            .and_then(|c| c.get("modified"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let modified = (now_secs() as f64).max(prev + 1.0);

        xite.sign(privatekey, modified).map_err(|e| e.to_string())?;
        let signed = xite.content.clone();
        let bytes = xite.storage.read("content.json").map_err(|e| e.to_string())?;

        if let Some(x) = self.xites.write().await.get_mut(address) {
            if let Some(content) = &signed {
                x.settings.apply_content_stats(&content_stats(content));
                x.settings.own = true;
            }
            x.content = signed;
        }
        Ok(bytes)
    }

    /// The content.json that governs `inner_path`: itself when it already is
    /// one, else the nearest content.json up the directory tree that exists on
    /// disk, falling back to the root (EpixNet's
    /// `getFileInfo()["content_inner_path"]`). EpixTalk publishes with the
    /// data file's path (`data/users/<xid>/data.json`), so this picks the
    /// user's own content.json to sign.
    pub async fn content_inner_path(&self, address: &str, inner_path: &str) -> String {
        if inner_path == "content.json" || inner_path.ends_with("/content.json") {
            return inner_path.to_string();
        }
        let Some(storage) = self.xites.read().await.get(address).map(|x| x.storage.clone()) else {
            return "content.json".to_string();
        };
        let mut dir = inner_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        loop {
            if dir.is_empty() {
                return "content.json".to_string();
            }
            let candidate = format!("{dir}/content.json");
            if let Ok(bytes) = storage.read(&candidate) {
                // A user_contents parent governs per-user dirs below it: the
                // file's content.json is <user dir>/content.json even when it
                // doesn't exist yet (a user's first post creates it).
                let has_user_contents = serde_json::from_slice::<Value>(&bytes)
                    .ok()
                    .is_some_and(|c| c.get("user_contents").is_some());
                if has_user_contents {
                    let rel = inner_path.strip_prefix(&format!("{dir}/")).unwrap_or("");
                    if let Some((user_seg, _)) = rel.split_once('/') {
                        return format!("{dir}/{user_seg}/content.json");
                    }
                }
                return candidate;
            }
            dir = dir.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        }
    }

    /// Sign a non-root content.json as the current user (EpixNet's
    /// `actionSiteSign` for user content): attach the selected cert's fields,
    /// sign with the cert identity's key (or the xite's derived auth key, or
    /// an explicit `privatekey`), verify against the parent's rules, store,
    /// and ingest into the xite's database so the change shows immediately.
    pub async fn sign_user_content(
        &self,
        address: &str,
        content_inner_path: &str,
        privatekey: Option<String>,
        origin: Option<u64>,
    ) -> Result<(), String> {
        let storage = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.clone())
            .ok_or("unknown xite")?;

        // The cert fields to extend the content.json with, and the signing key.
        let (extend, key) = {
            let mut user = self.user.write().await;
            let mut extend = serde_json::Map::new();
            if privatekey.is_none() {
                if let Some(id) = user.cert_user_id(address) {
                    if let Some(cert) = user.get_cert(address) {
                        extend.insert("cert_auth_type".into(), json!(cert.auth_type));
                        extend.insert("cert_sign".into(), json!(cert.cert_sign));
                    }
                    extend.insert("cert_user_id".into(), json!(id));
                }
            }
            let key = match privatekey {
                Some(k) => k,
                None => user.auth_privatekey(address)?,
            };
            (extend, key)
        };
        self.save_user().await; // auth_privatekey may have derived the site entry

        // Resolve every xID name verification will need (the user dir's own
        // name + any name-form signers the parent rules grant).
        let xid_map = Self::resolve_xid_map(&storage, content_inner_path).await;

        let prev = storage
            .read(content_inner_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|c| c.get("modified").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);
        let modified = (now_secs() as f64).max(prev + 1.0);

        let addr = Address::parse(address.to_string()).map_err(|e| e.to_string())?;
        let xite = Xite::new(addr, storage);
        xite.sign_child(content_inner_path, &key, modified, &extend, &xid_map)
            .map_err(|e| e.to_string())?;
        self.log("INFO", format!("Signed {content_inner_path} on {address}")).await;
        self.ingest_file_from(address, content_inner_path, origin).await;
        Ok(())
    }

    /// The per-file diffs for a publish (EpixNet's `getDiffs`): for each file
    /// of `content_inner_path` with a `<file>-old` snapshot (kept by
    /// [`Self::write_file`]), diff old vs current and drop the snapshot. Keys
    /// are relative to the content.json's directory, as Python peers expect.
    pub async fn take_diffs(
        &self,
        address: &str,
        content_inner_path: &str,
    ) -> HashMap<String, Vec<epix_content::DiffAction>> {
        let mut out = HashMap::new();
        let Some(storage) = self.xites.read().await.get(address).map(|x| x.storage.clone())
        else {
            return out;
        };
        let Some(files) = storage
            .read(content_inner_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|c| c.get("files").and_then(|f| f.as_object()).cloned())
        else {
            return out;
        };
        let dir =
            content_inner_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
        for rel in files.keys() {
            let full = format!("{dir}{rel}");
            let old_path = format!("{full}-old");
            if !storage.exists(&old_path) {
                continue;
            }
            if let (Ok(old), Ok(new)) = (storage.read(&old_path), storage.read(&full)) {
                // An over-limit (or degenerate) diff is just omitted: the
                // receiver falls back to downloading the file.
                if let Some(actions) = epix_content::diff::diff(&old, &new, Some(30 * 1024)) {
                    out.insert(rel.clone(), actions);
                }
            }
            let _ = storage.delete(&old_path);
        }
        out
    }

    /// Publish `inner_path` to the xite's connectable peers via the `update`
    /// command, with per-file diffs so receivers can patch their data files in
    /// place, and progress pushed to the xite's pages (EpixNet's publish
    /// progress bar). Returns how many peers accepted it. `sitePublish`.
    pub async fn publish(
        self: &Arc<Self>,
        address: &str,
        inner_path: &str,
        origin: Option<u64>,
        exhaustive: bool,
    ) -> Result<usize, String> {
        let diffs = self.take_diffs(address, inner_path).await;
        self.publish_to(address, inner_path, 20, exhaustive, diffs, Some(origin)).await
    }

    /// Publish to at most `limit` connectable peers per batch. The
    /// re-broadcast of an accepted inbound update uses a small limit (EpixNet
    /// uses 3) so a push floods the network without every node hammering
    /// every peer. `exhaustive`: a user publish keeps walking the
    /// reputation-sorted candidate pool in `limit`-sized batches until one
    /// batch lands somewhere (or [`Self::MAX_PUBLISH_DIALS`] candidates were
    /// tried) - without it a junk-heavy registry starved the publish on the
    /// first 20 dead entries while a reachable peer sat at rank 21;
    /// re-broadcasts pass `false` (one batch, best effort, the flood
    /// redundancy covers the misses). Every dial outcome feeds the peer
    /// registry via [`Self::apply_peer_outcomes`], so failed candidates sink
    /// (backoff + reputation) and later batches/passes select better.
    /// `progress`: `None` = silent (re-broadcasts); `Some(origin)` = push
    /// progress events, to the originating connection only when known
    /// (EpixNet's `self.cmd("progress", …)`), else to the xite's pages.
    pub async fn publish_to(
        self: &Arc<Self>,
        address: &str,
        inner_path: &str,
        limit: usize,
        exhaustive: bool,
        diffs: HashMap<String, Vec<epix_content::DiffAction>>,
        progress: Option<Option<u64>>,
    ) -> Result<usize, String> {
        /// Upper bound on dial attempts for an exhaustive publish: batches of
        /// `limit` are bounded by one connect_timeout each, so this caps the
        /// worst case (a fully dead registry) at a few minutes while still
        /// walking deep enough to reach the first live peer of a junk-heavy
        /// pool. Sync keeps spreading the content afterwards regardless.
        const MAX_PUBLISH_DIALS: usize = 100;
        let body = self
            .xites
            .read()
            .await
            .get(address)
            .and_then(|x| x.storage.read(inner_path).ok())
            .ok_or("nothing to publish")?;
        // The version we're publishing: sent with the update so receivers can
        // short-circuit, and used for the offline-peer propagation hint.
        let modified = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|c| c.get("modified").and_then(|v| v.as_f64()))
            .unwrap_or(0.0);
        let transport = self.transport.read().await.clone().ok_or("no transport for publishing")?;
        let pool =
            self.connectable_peers(address, if exhaustive { MAX_PUBLISH_DIALS } else { limit }).await;
        let total = pool.len();
        if exhaustive {
            let overlay = pool.iter().filter(|p| p.is_overlay()).count();
            self.log(
                "DEBUG",
                format!(
                    "publish {address}: {total} candidate(s) ({} clearnet, {overlay} overlay), batch size {limit}",
                    total - overlay
                ),
            )
            .await;
        }
        let wire_diffs = (!diffs.is_empty()).then(|| crate::fileserve::encode_diffs(&diffs));
        // The pushed body is cloned into every spawned task; Arc it so 100
        // candidates share one buffer instead of cloning a possibly-MB
        // content.json per dial.
        let body = Arc::new(body);
        // Stamp every push with the addresses we can be dialed back at, so
        // receivers behind the usual "publisher is the only seed" wall can
        // fetch the new files from us over onion/i2p even when our clearnet
        // port is closed.
        let sender_peers = Arc::new(self.own_dialable_addresses().await);
        let mut run = PublishRun { origin: progress, published: 0, done: 0, attempted: 0 };
        self.publish_progress(address, &run, total.min(limit.max(1)));

        for (batch_no, batch) in pool.chunks(limit.max(1)).enumerate() {
            // The pool was selected once up front; a concurrent sync pass may
            // have backed off (or evicted) peers in later batches since. Skip
            // candidates the registry now says to leave alone rather than
            // burning a bounded timeout on each.
            let batch = if batch_no == 0 {
                batch.to_vec()
            } else {
                self.still_dialable(address, batch).await
            };
            if batch.is_empty() {
                continue;
            }
            run.attempted += batch.len();
            self.push_batch(address, inner_path, batch, &body, modified, &wire_diffs, &sender_peers, &transport, &mut run)
                .await;
            // One batch with any acceptor is enough: the accepted push
            // re-broadcasts peer-to-peer, and the remaining candidates get
            // the version on their next sync. Only an all-failed batch walks
            // deeper into the pool.
            if run.published > 0 || !exhaustive {
                break;
            }
        }
        // Close the bar against what was actually attempted (idempotent when
        // the loop already emitted this exact event on its last candidate).
        self.publish_progress(address, &run, run.done);
        Ok(run.published)
    }

    /// The subset of `batch` the registry still allows dialing - not backed
    /// off (or evicted) since the publish pool was selected.
    async fn still_dialable(&self, address: &str, batch: &[PeerAddr]) -> Vec<PeerAddr> {
        let now = now_secs();
        let xites = self.xites.read().await;
        let Some(x) = xites.get(address) else { return Vec::new() };
        batch
            .iter()
            .filter(|p| x.peers.get(p).is_some_and(|peer| peer.retry_after <= now))
            .cloned()
            .collect()
    }

    /// Emit a publish progress event ("Content published to X/Y peers.").
    /// `target` is what has actually been dialed (the batches entered so
    /// far), NOT the whole candidate pool - a successful publish must read
    /// "5/20 peers", not "5/100" against candidates that were never dialed.
    fn publish_progress(&self, address: &str, run: &PublishRun, target: usize) {
        let Some(origin) = run.origin else { return };
        if target == 0 {
            return;
        }
        // No dial counters: how many of the first batch answered is plumbing,
        // not progress the author cares about. One acceptance means the
        // network has the update (acceptors that commit re-gossip it), so
        // the message flips to done at the first success.
        let message = if run.published > 0 {
            "Changes published to the network."
        } else {
            "Publishing changes to the network..."
        };
        self.push_event_routed(
            "progress",
            json!(["publish", message, (100 * run.done / target) as i64]),
            None,
            Some(address.to_string()),
            None,
            origin,
        );
    }

    /// Push the update to one batch of candidates concurrently (EpixNet
    /// publishes with parallel workers): a page waits on the sitePublish
    /// reply, so dead peers must cost one bounded timeout, not a serial sum
    /// of them (an exhaustive walk still pays one bounded timeout per
    /// all-failed batch). Every outcome is fed into the peer registry, and
    /// progress streams per completion.
    #[allow(clippy::too_many_arguments)]
    async fn push_batch(
        self: &Arc<Self>,
        address: &str,
        inner_path: &str,
        batch: Vec<PeerAddr>,
        body: &Arc<Vec<u8>>,
        modified: f64,
        wire_diffs: &Option<rmpv::Value>,
        sender_peers: &Arc<Vec<String>>,
        transport: &Arc<dyn Transport>,
        run: &mut PublishRun,
    ) {
        let mut set = tokio::task::JoinSet::new();
        for peer in batch {
            set.spawn(push_update_to_peer(
                transport.clone(),
                peer,
                address.to_string(),
                inner_path.to_string(),
                body.clone(),
                modified,
                wire_diffs.clone(),
                sender_peers.clone(),
            ));
        }
        let mut outcomes = Vec::new();
        let mut accepted: Vec<String> = Vec::new();
        let mut failed: Vec<String> = Vec::new();
        while let Some(res) = set.join_next().await {
            run.done += 1;
            if let Ok(outcome) = res {
                record_push_outcome(outcome, run, &mut outcomes, &mut accepted, &mut failed);
            }
            self.publish_progress(address, run, run.attempted);
            // One acceptance is enough for the author: the acceptor gossips
            // the update onward (it re-publishes on commit) and the periodic
            // sync covers stragglers. Stop holding the page's sitePublish
            // reply and let the remaining in-flight dials finish - and feed
            // the peer registry - in the background.
            if run.published > 0 && !set.is_empty() {
                self.drain_pushes_in_background(address, set);
                break;
            }
        }
        self.apply_peer_outcomes(address, outcomes).await;
        if !accepted.is_empty() {
            self.log("DEBUG", format!("publish {address}: accepted by: {}", accepted.join(", ")))
                .await;
        }
        if !failed.is_empty() {
            self.log("DEBUG", format!("publish {address}: failed candidates: {}", failed.join(", ")))
                .await;
        }
    }

    /// Await a publish batch's remaining in-flight dials off the page's
    /// critical path, still feeding each outcome into the peer registry.
    fn drain_pushes_in_background(
        self: &Arc<Self>,
        address: &str,
        mut set: tokio::task::JoinSet<PushOutcome>,
    ) {
        let state = self.clone();
        let addr = address.to_string();
        tokio::spawn(async move {
            let mut outcomes = Vec::new();
            while let Some(res) = set.join_next().await {
                if let Ok(outcome) = res {
                    let (peer, score, _) = outcome.feedback();
                    outcomes.push((peer, score));
                }
            }
            state.apply_peer_outcomes(&addr, outcomes).await;
        });
    }

    /// Handle a peer pushing us a new `content.json` (the inbound `update` wire
    /// command - the receive half of the publish round-trip). Mirrors EpixNet's
    /// `FileRequest.actionUpdate`: reject unknown/not-downloaded sites, skip
    /// versions we already have, verify the signature before accepting, then
    /// download the changed files in the background and re-publish to a few
    /// peers so the update floods.
    ///
    /// `body` is the pushed content.json (None/empty when the sender omitted it
    /// - EpixNet drops bodies over 1 MB - in which case it is fetched back from
    /// `sender`). `modified_hint` is the pushed version, letting us short-
    /// circuit without parsing. Returns whether the update was applied.
    pub async fn apply_inbound_update(
        self: &Arc<Self>,
        site: &str,
        inner_path: &str,
        body: Option<Vec<u8>>,
        modified_hint: Option<f64>,
        sender: Option<PeerAddr>,
        diffs: HashMap<String, Vec<epix_content::DiffAction>>,
        sender_peers: Vec<PeerAddr>,
    ) -> Result<InboundUpdate, String> {
        // A xite may be served under aliases (raw address + `.epix` name); an
        // update applies to every key sharing the pushed canonical address.
        let keys: Vec<String> = {
            let xites = self.xites.read().await;
            xites
                .iter()
                .filter(|(k, x)| {
                    k.as_str() == site || canonical_address(x.content.as_ref(), k) == site
                })
                .map(|(k, _)| k.clone())
                .collect()
        };
        let Some(key) = keys.first().cloned() else {
            return Err("Unknown site".into());
        };
        if !self.is_serving(&key).await {
            return Err("Unknown site".into());
        }
        if !inner_path.ends_with("content.json") {
            return Err("Only content.json update allowed".into());
        }
        let is_root = inner_path == "content.json";
        // Only accept pushes for sites we voluntarily downloaded. The version
        // to beat is the root's in-memory clock, or - for an include / user
        // content.json - the on-disk child's own `modified`.
        let (downloaded, current_modified) = {
            let xites = self.xites.read().await;
            let x = xites.get(&key).ok_or("Unknown site")?;
            let current = if is_root {
                x.content
                    .as_ref()
                    .and_then(|c| c.get("modified"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
            } else {
                x.storage
                    .read(inner_path)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .and_then(|c| c.get("modified").and_then(|v| v.as_f64()))
                    .unwrap_or(0.0)
            };
            (x.settings.downloaded.is_some(), current)
        };
        if !downloaded {
            return Err("Site not yet downloaded".into());
        }

        // Same or older version than ours: record the sender as a peer and stop.
        if let Some(hint) = modified_hint {
            if hint <= current_modified {
                if let Some(s) = &sender {
                    self.add_peers(&key, [s.clone()]).await;
                }
                return Ok(InboundUpdate::NotChanged);
            }
        }

        // Body-less update (large content.json): fetch it back from the sender.
        let bytes = match body.filter(|b| !b.is_empty()) {
            Some(b) => b,
            None => {
                let fetched = match (&sender, self.transport.read().await.clone()) {
                    (Some(s), Some(transport)) => {
                        // The sender may be an onion/i2p peer: use its dial
                        // deadline, not a flat clearnet one.
                        tokio::time::timeout(s.connect_timeout(), async {
                            let mut conn =
                                Connection::connect(transport.as_ref(), s).await.ok()?;
                            conn.handshake().await.ok()?;
                            conn.get_file(site, inner_path).await.ok()
                        })
                        .await
                        .ok()
                        .flatten()
                    }
                    _ => None,
                };
                fetched.ok_or("File invalid update: Can't download updated file")?
            }
        };

        let new: Value =
            serde_json::from_slice(&bytes).map_err(|_| "File invalid JSON".to_string())?;
        let new_modified = new.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
        // Reject far-future timestamps (EpixNet allows at most now + 1 day) so
        // a peer can't pin a bogus "newest" version that blocks real updates.
        if new_modified > (now_secs() as f64) + 60.0 * 60.0 * 24.0 {
            return Err(format!(
                "File {inner_path} invalid: Modify timestamp is in the far future!"
            ));
        }
        if new_modified <= current_modified {
            if let Some(s) = &sender {
                self.add_peers(&key, [s.clone()]).await;
            }
            return Ok(InboundUpdate::NotChanged);
        }

        // Don't process the same pushed version twice concurrently.
        let uri = format!("{site}/{inner_path}:{new_modified}");
        if !self.updates_in_flight.lock().unwrap().insert(uri.clone()) {
            return Ok(InboundUpdate::NotChanged);
        }

        // Full verification (signers/rules/size limit); only writes if valid.
        let mut xite = match self.xite_view(&key).await {
            Ok(x) => x,
            Err(e) => {
                self.updates_in_flight.lock().unwrap().remove(&uri);
                return Err(e);
            }
        };
        let mut child_files: Option<Vec<epix_xite::FileEntry>> = None;
        let mut committed_inline = false;
        if is_root {
            // Verify + STAGE the pushed root in memory only. It is committed
            // (written to disk + adopted for serving) by finish_inbound_update
            // once every file it declares is present, so a push whose files
            // can't all be fetched never regresses a working site.
            let limit = self.size_limit_bytes(&key).await;
            if let Err(e) = xite.stage_content_limited(&bytes, limit) {
                self.updates_in_flight.lock().unwrap().remove(&uri);
                return Err(format!("File {inner_path} invalid: {e}"));
            }
            // Fast path: every declared file is already present (a
            // metadata-only re-sign, or files that landed earlier), so there
            // is nothing to wait for - commit before answering the sender.
            if xite.files_needed().is_empty() {
                let canonical = canonical_address(xite.content.as_ref(), &key);
                let content = xite.content.clone().unwrap_or(Value::Null);
                committed_inline = self
                    .finalize_root_update(&keys, &canonical, &xite.storage, content, &bytes, &[])
                    .await;
            }
        } else {
            // An include / user content.json: verified against its on-disk
            // parent's rules (signers, cert, max_size, files_allowed), with
            // any xID-name signers resolved on-chain first.
            if let Some(sign) = new.get("cert_sign").and_then(|v| v.as_str()) {
                if self.is_bad_cert(sign) {
                    self.updates_in_flight.lock().unwrap().remove(&uri);
                    return Err(format!("File {inner_path} invalid: Invalid cert!"));
                }
            }
            let xid_map = Self::resolve_xid_map(&xite.storage, inner_path).await;
            match xite.add_content(inner_path, &bytes, &xid_map) {
                Ok(files) => {
                    child_files = Some(files);
                    // Fold the child's modified clock into settings and its
                    // db columns (cert_user_id) into the site db.
                    self.ingest_file_from(&key, inner_path, None).await;
                }
                Err(e) => {
                    self.updates_in_flight.lock().unwrap().remove(&uri);
                    return Err(format!("File {inner_path} invalid: {e}"));
                }
            }
        }
        if let Some(s) = &sender {
            self.add_peers(&key, [s.clone()]).await;
        }
        // Register the publisher's self-declared dialable addresses too, so
        // even a later retry pass (after this fetch, or after a restart) can
        // reach the one node that has the new files.
        if !sender_peers.is_empty() {
            self.add_peers(&key, sender_peers.iter().cloned()).await;
        }

        // Download the changed files and re-publish in the background, like
        // EpixNet - the sender gets its "ok" response right away.
        let state = self.clone();
        let inner = inner_path.to_string();
        // Already-committed roots (and child pushes) have nothing left to
        // commit; finish only syncs/publishes for them.
        let root_bytes = if is_root && !committed_inline { Some(bytes) } else { None };
        tokio::spawn(async move {
            state
                .finish_inbound_update(
                    keys,
                    xite,
                    sender,
                    sender_peers,
                    inner,
                    uri,
                    diffs,
                    child_files,
                    root_bytes,
                )
                .await;
        });
        Ok(InboundUpdate::Applied)
    }

    /// Resolve every xID name that verifying `content_inner_path` may need -
    /// the user directory's own name (`data/users/user.epix/…` is signed by
    /// the identity that xID belongs to) plus any name-form signers the
    /// parent's rules grant (a site's admins may sign every user's content
    /// for moderation) - to their on-chain signer addresses.
    async fn resolve_xid_map(
        storage: &XiteStorage,
        content_inner_path: &str,
    ) -> HashMap<String, Vec<String>> {
        let parent_path = epix_content::verify::parent_content_path(content_inner_path);
        let parent = storage
            .read(&parent_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or_else(|| json!({ "inner_path": parent_path }));
        let mut xid_map = HashMap::new();
        for name in epix_content::verify::user_content_xid_names(&parent, content_inner_path) {
            let (label, tld) = name.rsplit_once('.').unwrap_or((name.as_str(), "epix"));
            let signers = epix_chain::xid_signers::resolve(label, tld).await;
            if !signers.is_empty() {
                xid_map.insert(name, signers);
            }
        }
        xid_map
    }

    /// The deferred half of [`Self::apply_inbound_update`]: apply any diffs the
    /// publisher sent (patching our old file copies to skip downloads), sync the
    /// files still needed (preferring the sender), then - for a root push -
    /// commit the staged content.json only if every declared file is present
    /// (else defer it for retry and keep serving the previous version), and
    /// re-publish to a few peers so the update spreads.
    async fn finish_inbound_update(
        self: &Arc<Self>,
        keys: Vec<String>,
        xite: Xite,
        sender: Option<PeerAddr>,
        sender_peers: Vec<PeerAddr>,
        inner_path: String,
        uri: String,
        diffs: HashMap<String, Vec<epix_content::DiffAction>>,
        child_files: Option<Vec<epix_xite::FileEntry>>,
        root_bytes: Option<Vec<u8>>,
    ) {
        let key = keys[0].clone();
        // Diff keys are relative to the pushed content.json's directory (the
        // root for a root push, the user/include dir for a child push).
        let diff_dir =
            inner_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
        // Apply diffs first: patch our old copy of each changed file and keep it
        // only if the result matches the new content.json's declared hash. A
        // bad/mismatched diff is ignored - the file just gets downloaded below.
        if !diffs.is_empty() {
            let mut patched = 0;
            for (file_path, actions) in &diffs {
                let full = format!("{diff_dir}{file_path}");
                let info = match &child_files {
                    Some(list) => list.iter().find(|f| f.inner_path == full).cloned(),
                    None => xite.file_info(&full),
                };
                let Some(info) = info else { continue };
                if xite.storage.verify(&full, &info.sha512) {
                    continue; // already current
                }
                let Ok(old) = xite.storage.read(&full) else { continue };
                let Ok(new) = epix_content::patch(&old, actions) else { continue };
                if XiteStorage::hash_bytes(&new) == info.sha512
                    && xite.storage.write(&full, &new).is_ok()
                {
                    patched += 1;
                }
            }
            if patched > 0 {
                self.log("INFO", format!("Applied {patched} diff(s) for {key}")).await;
            }
        }
        if let Some(transport) = self.transport.read().await.clone() {
            let mut peers = self.connectable_peers(&key, 10).await;
            // Prefer fetching from the sender - it definitely has the files
            // it just announced - but only if its address is dialable (an
            // inbound-only peer, e.g. `ip:0`, would just waste a worker).
            if let Some(s) = sender {
                if epix_peer::Peer::new(s.clone(), 0).is_connectable() && !peers.contains(&s) {
                    peers.insert(0, s);
                }
            }
            // Even before the sender's wire address: the addresses the
            // publisher SAYS it is dialable at (onion/i2p/open clearnet).
            // For a NAT'd publisher these are the only routes to the new
            // files. Own addresses are dropped (a lone seeder must not dial
            // itself) and so are networks we cannot dial right now.
            let nets = self.dialable_networks().await;
            for sp in sender_peers.into_iter().rev() {
                if nets.can_dial(&sp)
                    && epix_peer::Peer::new(sp.clone(), 0).is_connectable()
                    && !self.is_own_peer(&sp).await
                    && !peers.contains(&sp)
                {
                    peers.insert(0, sp);
                }
            }
            // The files to fetch: for a root push, whatever the new root
            // declares and we lack; for a child push, the child's declared
            // files that are missing or stale.
            let needed: Vec<epix_xite::FileEntry> = match &child_files {
                Some(list) => list
                    .iter()
                    .filter(|f| !xite.storage.verify(&f.inner_path, &f.sha512))
                    .cloned()
                    .collect(),
                None => xite.files_needed(),
            };
            if !needed.is_empty() && !peers.is_empty() {
                let needed_paths: Vec<String> =
                    needed.iter().map(|f| f.inner_path.clone()).collect();
                self.set_worker_stats(&key, needed.len(), peers.len().min(8), needed.len())
                    .await;
                let feedback = epix_worker::CollectFeedback::new();
                let report = epix_worker::sync_files_list(
                    needed,
                    &xite,
                    &peers,
                    transport.clone(),
                    8,
                    None,
                    Some(feedback.clone() as Arc<dyn epix_worker::PeerFeedback>),
                )
                .await;
                let failed_files = report.as_ref().map(|r| r.failed.len()).unwrap_or(0);
                if let Ok(report) = &report {
                    self.add_transfer(&key, report.bytes, 0).await;
                }
                self.set_worker_stats(&key, 0, 0, 0).await;
                self.absorb_sync_outcomes(&key, feedback.drain(), failed_files).await;
                if child_files.is_some() {
                    // Child data files (user posts) feed the db per file, so
                    // open pages see them without a full rebuild.
                    for path in needed_paths {
                        if xite.storage.exists(&path) {
                            self.ingest_file_from(&key, &path, None).await;
                        }
                    }
                }
            }
        }

        // Root push: commit the staged content.json (write to disk + adopt for
        // serving + rebuild db views) only when every file it declares is now
        // present. Otherwise the update is deferred - the previous version
        // keeps serving and the resync tick retries the missing files. This is
        // what apply_inbound_update staged instead of writing.
        let committed = match (&child_files, &root_bytes) {
            (None, Some(bytes)) => {
                let canonical = canonical_address(xite.content.as_ref(), &key);
                let failed: Vec<String> =
                    xite.files_needed().iter().map(|f| f.inner_path.clone()).collect();
                let content = xite.content.clone().unwrap_or(Value::Null);
                self.finalize_root_update(&keys, &canonical, &xite.storage, content, bytes, &failed)
                    .await
            }
            // Child pushes were verified + stored by add_content already.
            _ => true,
        };

        // EpixNet re-publishes an accepted update to up to 3 more peers,
        // forwarding the diffs it received so they spread with the push - but
        // never a version we couldn't complete ourselves.
        if committed && self.transport.read().await.is_some() {
            let _ = self.publish_to(&key, &inner_path, 3, false, diffs, None).await;
        }
        self.updates_in_flight.lock().unwrap().remove(&uri);
        // Flash the dashboard row: a peer pushed a new version and it landed.
        if committed {
            for k in &keys {
                self.push_site_info_event(k, "updated").await;
            }
        }
    }

    pub async fn has_xite(&self, address: &str) -> bool {
        self.xites.read().await.contains_key(address)
    }

    /// Read a file from a served xite's storage.
    /// Serve one chunk of a local file to a peer (`getFile`): the bytes from
    /// `offset` up to `length`, plus the file's total size. `None` if the xite or
    /// file is not present here. Used by the inbound file server (seeding).
    pub async fn serve_file_chunk(
        &self,
        address: &str,
        inner_path: &str,
        offset: u64,
        length: usize,
    ) -> Option<(Vec<u8>, u64)> {
        let path = {
            let xites = self.xites.read().await;
            xites.get(address)?.storage.path(inner_path).ok()?
        };
        let total = std::fs::metadata(&path).ok()?.len();
        let chunk = self.read_file_range(address, inner_path, offset, length).await?;
        Some((chunk, total))
    }

    pub async fn read_file(&self, address: &str, inner_path: &str) -> Option<Vec<u8>> {
        // FilePack: `<pack>.zip/<inner>` or `<pack>.tar.gz/<inner>` serves a file
        // from inside the archive.
        if let Some((archive, within)) = split_archive_path(inner_path) {
            if !self.plugin_enabled("FilePack").await {
                return None;
            }
            let bytes = self.xites.read().await.get(address)?.storage.read(&archive).ok()?;
            return read_from_archive(&archive, &bytes, &within);
        }
        let xites = self.xites.read().await;
        xites.get(address)?.storage.read(inner_path).ok()
    }

    /// A clone of a xite's content.json, if loaded.
    pub async fn content(&self, address: &str) -> Option<Value> {
        self.xites.read().await.get(address)?.content.clone()
    }

    /// `UiFileManager` - list a directory inside a xite as
    /// `[{name, is_dir, size}]`, sorted (directories first). `None` if the xite
    /// or path is unknown.
    pub async fn list_dir(&self, address: &str, inner_path: &str) -> Option<Vec<Value>> {
        let root = self.xites.read().await.get(address)?.storage.root().to_path_buf();
        let dir = if inner_path.is_empty() { root.clone() } else { root.join(inner_path) };
        // Stay within the xite root.
        if !dir.starts_with(&root) {
            return None;
        }
        let mut entries: Vec<Value> = Vec::new();
        for entry in std::fs::read_dir(&dir).ok()? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            entries.push(json!({ "name": name, "is_dir": is_dir, "size": size }));
        }
        entries.sort_by(|a, b| {
            let ad = a["is_dir"].as_bool().unwrap_or(false);
            let bd = b["is_dir"].as_bool().unwrap_or(false);
            bd.cmp(&ad).then_with(|| {
                a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or(""))
            })
        });
        Some(entries)
    }

    /// Recursively list every file under `inner_path` as inner paths relative to
    /// the xite root (`fileList`). Stays within the root; `None` if unknown.
    pub async fn walk_files(&self, address: &str, inner_path: &str) -> Option<Vec<String>> {
        let root = self.xites.read().await.get(address)?.storage.root().to_path_buf();
        let start = if inner_path.is_empty() { root.clone() } else { root.join(inner_path) };
        if !start.starts_with(&root) {
            return None;
        }
        let mut out = Vec::new();
        let mut stack = vec![start.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&start) {
                    // Relative to the REQUESTED dir, not the site root:
                    // EpixNet's storage.walk(inner_path) yields the same, and
                    // sites join the names back onto the dir they asked for
                    // (git.js builds "objects/pack/" + name to load pack
                    // indexes - root-relative paths broke that).
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        out.sort();
        Some(out)
    }

    /// A xite's known bad (missing/failed) files (`siteBadFiles`): inner paths
    /// still needed. Empty if the xite is unknown or fully downloaded.
    pub async fn bad_files(&self, address: &str) -> Vec<String> {
        let xites = self.xites.read().await;
        let Some(x) = self.resolve_xite(&xites, address) else { return Vec::new() };
        x.settings.cache.bad_files.keys().cloned().collect()
    }

    /// Set the known peer count for a xite (from discovery), persisting nothing
    /// here - it's derived runtime state.
    pub async fn set_peer_count(&self, address: &str, peers: i64) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.peers = peers;
        }
    }

    /// Override the per-xite size limit (MB).
    pub async fn set_size_limit(&self, address: &str, size_limit_mb: i64) {
        let changed = {
            let mut xites = self.xites.write().await;
            match xites.get_mut(address) {
                Some(x) => {
                    x.settings.size_limit = Some(size_limit_mb);
                    true
                }
                None => false,
            }
        };
        if changed {
            self.persist_sites().await;
        }
    }

    /// A xite's effective size limit in bytes (its per-xite override or the
    /// default), for content.json verification. Unknown xite -> default.
    pub async fn size_limit_bytes(&self, address: &str) -> i64 {
        let mb = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.settings.size_limit(DEFAULT_SIZE_LIMIT_MB))
            .unwrap_or(DEFAULT_SIZE_LIMIT_MB);
        mb.saturating_mul(1024 * 1024)
    }

    /// Pause/resume a xite (`sitePause`/`siteResume`). A paused xite is skipped
    /// by the re-sync loop. Returns false if the xite isn't served here.
    pub async fn set_serving(&self, address: &str, serving: bool) -> bool {
        let ok = if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.serving = serving;
            true
        } else {
            false
        };
        if ok {
            self.push_site_info(address).await;
        }
        ok
    }

    /// Whether a xite is currently serving (not paused).
    pub async fn is_serving(&self, address: &str) -> bool {
        self.xites.read().await.get(address).map(|x| x.settings.serving).unwrap_or(false)
    }

    /// Toggle a xite's favourite flag (`siteFavourite`/`siteUnfavourite`).
    pub async fn set_favorite(&self, address: &str, favorite: bool) -> bool {
        let ok = if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.favorite = favorite;
            true
        } else {
            false
        };
        if ok {
            self.push_site_info(address).await;
        }
        ok
    }

    /// Mark a directory of optional files for distribution help
    /// (`optionalHelp`): record `{directory: title}` and report the file
    /// count + total size under it. Returns (num, size).
    pub async fn optional_help_add(&self, address: &str, directory: &str, title: &str) -> Option<(i64, i64)> {
        let (storage, content) = {
            let mut xites = self.xites.write().await;
            let x = xites.get_mut(address)?;
            x.settings.optional_help.insert(directory.to_string(), json!(title));
            (x.storage.clone(), x.content.clone())
        };
        // Tally the optional files under this directory prefix - the root
        // content.json's plus those declared by stored child content.jsons
        // (per-user optional files), which EpixNet counts through its
        // file_optional table.
        let (mut num, mut size) = (0i64, 0i64);
        let mut tally = |files: Option<&Value>, dir: &str| {
            let Some(files) = files.and_then(|f| f.as_object()) else { return };
            for (rel, info) in files {
                let path = if dir.is_empty() { rel.clone() } else { format!("{dir}/{rel}") };
                if path.starts_with(directory) {
                    num += 1;
                    size += info.get("size").and_then(|v| v.as_i64()).unwrap_or(0);
                }
            }
        };
        tally(content.as_ref().and_then(|c| c.get("files_optional")), "");
        for child in storage.list_files() {
            if !child.ends_with("/content.json") {
                continue; // the root's was tallied from memory above
            }
            let Ok(bytes) = storage.read(&child) else { continue };
            let Ok(child_json) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            let dir = child.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
            tally(child_json.get("files_optional"), dir);
        }
        self.persist_sites().await;
        Some((num, size))
    }

    /// The `{directory: title}` map recorded by optionalHelp
    /// (`optionalHelpList`). `None` if the xite isn't served.
    pub async fn optional_help_list(
        &self,
        address: &str,
    ) -> Option<serde_json::Map<String, Value>> {
        self.xites.read().await.get(address).map(|x| x.settings.optional_help.clone())
    }

    /// Stop helping distribute a directory (`optionalHelpRemove`). Returns
    /// whether it was set.
    pub async fn optional_help_remove(&self, address: &str, directory: &str) -> bool {
        let removed = {
            let mut xites = self.xites.write().await;
            match xites.get_mut(address) {
                Some(x) => x.settings.optional_help.remove(directory).is_some(),
                None => false,
            }
        };
        if removed {
            self.persist_sites().await;
        }
        removed
    }

    /// Set a xite's auto-download-optional flag (`siteSetAutodownloadoptional`).
    pub async fn set_autodownloadoptional(&self, address: &str, on: bool) -> bool {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.autodownloadoptional = on;
            true
        } else {
            false
        }
    }

    /// Rebuild a xite's database from its files on disk (`dbReload`/`dbRebuild`).
    /// Returns false if the xite isn't served here.
    pub async fn rebuild_xite_db(&self, address: &str) -> bool {
        let muted = self.muted_authors().await;
        let mut xites = self.xites.write().await;
        let Some(x) = xites.get_mut(address) else { return false };
        let (db, schema) = match build_xite_db(&x.storage, &muted) {
            Some((db, schema)) => (Some(db), Some(schema)),
            None => (None, None),
        };
        x.db = db;
        x.db_schema = schema;
        true
    }

    /// Remove a xite from the node and delete its files on disk (`siteDelete`).
    /// A site may be served under several keys (raw `epix1…` address plus a
    /// `.epix` alias) sharing one storage; all of them are removed, otherwise a
    /// surviving alias keeps syncing and the periodic `persist_sites` writes
    /// the site straight back into `sites.json`. Returns false if the xite
    /// isn't served here.
    pub async fn remove_xite(&self, address: &str) -> bool {
        let mut roots = Vec::new();
        let mut removed_keys = Vec::new();
        {
            let mut xites = self.xites.write().await;
            // Canonical (signed content) address of the target, alias-aware.
            let Some(x) = self.resolve_xite(&xites, address) else { return false };
            let canonical = canonical_address(x.content.as_ref(), address);
            // Remove every serving key that shares this canonical address.
            let keys: Vec<String> = xites
                .iter()
                .filter(|(k, x)| canonical_address(x.content.as_ref(), k) == canonical)
                .map(|(k, _)| k.clone())
                .collect();
            for key in keys {
                if let Some(x) = xites.remove(&key) {
                    let root = x.storage.root().to_path_buf();
                    if !roots.contains(&root) {
                        roots.push(root);
                    }
                    // The site's user data may be keyed by the display name in
                    // stores written by older builds; purge both.
                    if let Some(display) = x.display {
                        removed_keys.push(display);
                    }
                    removed_keys.push(key);
                }
            }
        }
        // Best-effort delete of the xite's storage directory (shared by all
        // aliases), then drop the site from the persisted registries so it
        // stays deleted across restarts.
        for root in roots {
            let _ = std::fs::remove_dir_all(&root);
        }
        // EpixNet parity (`user.deleteSiteData`): forget the site's derived
        // auth identity, cert selection, and feed follows. Harmless to the
        // user - the keys re-derive from the master seed if the site returns.
        self.delete_user_site_data(&removed_keys).await;
        self.persist_peers().await;
        self.persist_sites().await;
        true
    }

    /// Drop the per-site user data (derived auth keys, cert binding, feed
    /// follows) for the given serving keys and persist users.json if anything
    /// was removed. EpixNet's `User.deleteSiteData`.
    async fn delete_user_site_data(&self, keys: &[String]) {
        let mut changed = false;
        {
            let mut user = self.user.write().await;
            for key in keys {
                changed |= user.sites.remove(key).is_some();
                changed |= user.follows.remove(key).is_some();
            }
        }
        if changed {
            self.save_user().await;
        }
    }

    /// Add a peer (ip + port) to a xite's known-peer set (`peerAdd`).
    pub async fn add_peer_ipport(&self, address: &str, ip: &str, port: u16) -> Result<(), String> {
        let peer = PeerAddr::parse(&format!("{ip}:{port}")).map_err(|e| e.to_string())?;
        self.add_peers(address, [peer]).await;
        Ok(())
    }

    /// A xite's storage directory on disk (`serverShowdirectory` "site").
    pub async fn xite_root(&self, address: &str) -> Option<PathBuf> {
        self.xites.read().await.get(address).map(|x| x.storage.root().to_path_buf())
    }

    /// The node's data directory (parent of `users.json`), if this is a
    /// persistent node (`serverShowdirectory` "backup").
    pub fn data_dir(&self) -> Option<PathBuf> {
        self.user_path.as_ref().and_then(|p| p.parent().map(Path::to_path_buf))
    }

    /// Build the `siteInfo` response for a xite - EpixNet's `formatSiteInfo`.
    /// Returns `Null` if the xite isn't served here.
    pub async fn site_info(&self, address: &str) -> Value {
        let xites = self.xites.read().await;
        let Some(entry) = xites.get(address) else {
            return Value::Null;
        };
        let settings = &entry.settings;

        let auth_address = self
            .user
            .write()
            .await
            .auth_address(address)
            .unwrap_or_default();
        let cert_user_id = self.user.read().await.cert_user_id(address);
        let xid_directory = self.user_directory(address, &auth_address).await;
        // Whether users.json holds this site's own private key (a bool, never
        // the key itself) - EpixNet's formatSiteInfo parity. The wrapper
        // infopanel and the sidebar sign/publish buttons key off this: true ->
        // sign with `privatekey: "stored"`, false -> prompt for the key.
        let has_privatekey = self.user.read().await.site_privatekey(address).is_some();

        let address_hash = hex::encode(Sha256::digest(address.as_bytes()));
        let short = if address.len() > 6 { &address[..6] } else { address };
        let size_limit = settings.size_limit(DEFAULT_SIZE_LIMIT_MB);
        let next_size_limit = next_size_limit(settings.size);
        // No verified content.json yet (registered mid-clone): an EMPTY object,
        // not null - EpixNet's formatSiteInfo sends {} too, and dashboard site
        // rows read `content.title` without a null check, so null kills the
        // whole site list render.
        let content = entry.content.as_ref().map(summarize_content).unwrap_or_else(|| json!({}));

        // peers = max(settings, known) + self (we serve it), matching formatSiteInfo.
        let known_peers = entry.peers.len() as i64;
        let mut peers = settings.peers.max(known_peers);
        if settings.serving {
            peers += 1;
        }

        // Newsfeed: `null` = the user never followed this site, else the
        // follow count. Xites key their one-time auto-follow off the null
        // (EpixNet's Newsfeed plugin injected this): without the key present
        // they never register their feed queries and the dashboard feed
        // stays empty for them.
        let feed_follow_num = {
            let user = self.user.read().await;
            user.follows
                .get(address)
                .map(|f| json!(f.as_object().map(|o| o.len()).unwrap_or(0)))
                .unwrap_or(Value::Null)
        };

        json!({
            "auth_address": auth_address,
            "cert_user_id": cert_user_id,
            "privatekey": has_privatekey,
            "feed_follow_num": feed_follow_num,
            "xid_directory": xid_directory,
            "address": address,
            "display": entry.display,
            "address_short": short,
            "address_hash": address_hash,
            "settings": serde_json::to_value(settings).unwrap_or(Value::Null),
            "content_updated": settings.modified,
            "bad_files": settings.cache.bad_files.len(),
            "size_limit": size_limit,
            "next_size_limit": next_size_limit,
            "peers": peers.max(1),
            "started_task_num": entry.started_task_num,
            "tasks": entry.tasks_active,
            "workers": entry.workers,
            "content": content,
        })
    }

    /// `siteList` - one siteInfo per served xite, for the dashboard's Sites
    /// panel. A xite served under both its raw address and a `.epix` alias is a
    /// single site, so we collapse entries that share the same signed content
    /// address (the alias points at the same storage + content).
    pub async fn site_list(&self) -> Vec<Value> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for address in self.xite_addresses().await {
            let info = self.site_info(&address).await;
            if info.is_null() {
                continue;
            }
            // Prefer the signed address to dedupe alias/raw pairs; fall back to
            // the serving key when there is no verified content yet.
            let dedupe_key = info
                .get("content")
                .and_then(|c| c.get("address"))
                .and_then(Value::as_str)
                .unwrap_or(&address)
                .to_string();
            if seen.insert(dedupe_key) {
                out.push(info);
            }
        }
        out
    }

    /// A fresh wrapper nonce (monotonic; sufficient for a local single-user node).
    pub fn wrapper_nonce(&self) -> String {
        let n = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        format!("{n:016x}")
    }

    /// Append the node's log lines to `path` as well as stdout / the in-memory
    /// buffer, so activity survives restarts. Opens in append mode.
    pub fn set_log_file(&self, path: &std::path::Path) {
        if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            *self.log_file.lock().unwrap() = Some(file);
        }
    }

    /// Issue a one-time wrapper nonce (tracked so an inner file request can be
    /// recognized as coming through the wrapper), EpixNet's
    /// `server.wrapper_nonces`.
    pub fn issue_wrapper_nonce(&self) -> String {
        let nonce = random_hex(16);
        let mut set = self.wrapper_nonces.lock().unwrap();
        set.insert(nonce.clone());
        // Bound the set so it can't grow without limit on a long-running node.
        if set.len() > 2000 {
            if let Some(oldest) = set.iter().next().cloned() {
                set.remove(&oldest);
            }
        }
        nonce
    }

    /// Consume a wrapper nonce; true if it was outstanding (valid). Matches
    /// EpixNet's remove-on-use.
    pub fn consume_wrapper_nonce(&self, nonce: &str) -> bool {
        self.wrapper_nonces.lock().unwrap().remove(nonce)
    }

    /// Record a wrapper's Host as an allowed WebSocket origin (EpixNet adds
    /// `HTTP_HOST` to `allowed_ws_origins` when it serves the wrapper).
    pub fn allow_ws_origin(&self, host: &str) {
        if !host.is_empty() {
            self.allowed_ws_origins.lock().unwrap().insert(host.to_string());
        }
    }

    /// Whether a WebSocket `Origin` host is allowed: same as the request host,
    /// loopback, or a previously-served wrapper host.
    pub fn is_ws_origin_allowed(&self, origin_host: &str, request_host: &str) -> bool {
        if origin_host.is_empty() || origin_host == request_host {
            return true;
        }
        let host_only = origin_host.split(':').next().unwrap_or(origin_host);
        if host_only == "127.0.0.1" || host_only == "localhost" || host_only == "[::1]" {
            return true;
        }
        self.allowed_ws_origins.lock().unwrap().contains(origin_host)
    }

    /// Move a per-site user identity (derived site keys, cert binding, feed
    /// follows) stored under an old serving key (a `.epix` name, from builds
    /// that keyed sites by name as well as address) to the bech32 address.
    /// Never overwrites an existing address-keyed entry.
    async fn migrate_user_site_key(&self, from: &str, to: &str) {
        let mut changed = false;
        {
            let mut user = self.user.write().await;
            if let Some(auth) = user.sites.remove(from) {
                user.sites.entry(to.to_string()).or_insert(auth);
                changed = true;
            }
            if let Some(follows) = user.follows.remove(from) {
                user.follows.entry(to.to_string()).or_insert(follows);
                changed = true;
            }
        }
        if changed {
            self.save_user().await;
        }
    }

    /// Persist the user identity if this node has a data dir.
    pub async fn save_user(&self) {
        if let Some(path) = &self.user_path {
            let _ = self.user.read().await.save(path);
        }
        // Multiuser: keep the active identity's full state mirrored in the store,
        // so its certs/follows are not lost when the operator switches identity.
        #[cfg(feature = "multiuser")]
        self.multiuser_sync_active().await;
    }

    // --- Multiuser: multiple master-seed identities ------------------------

    /// Master addresses of every known identity (the active one first).
    #[cfg(feature = "multiuser")]
    pub async fn multiuser_list(&self) -> Vec<String> {
        let active = self.user.read().await.master_address.clone();
        let mut out = vec![active.clone()];
        for addr in self.multi_users.read().await.keys() {
            if *addr != active {
                out.push(addr.clone());
            }
        }
        out
    }

    /// The active identity's master seed (`userShowMasterSeed`).
    #[cfg(feature = "multiuser")]
    pub async fn multiuser_current_seed(&self) -> String {
        self.user.read().await.master_seed.clone()
    }

    /// Add (or look up) an identity from a master seed and make it active.
    /// Returns its master_address (`responseUserLogin`).
    #[cfg(feature = "multiuser")]
    pub async fn multiuser_login(&self, master_seed: &str) -> Result<String, String> {
        let incoming = User::from_seed(master_seed.trim())?;
        let addr = incoming.master_address.clone();
        // Keep an existing richer copy (with certs/follows) if we already know it.
        {
            let mut store = self.multi_users.write().await;
            store.entry(addr.clone()).or_insert(incoming);
        }
        self.multiuser_select(&addr).await?;
        Ok(addr)
    }

    /// Switch the active identity to a known master_address (`userSet`).
    #[cfg(feature = "multiuser")]
    pub async fn multiuser_select(&self, master_address: &str) -> Result<(), String> {
        // Persist the currently-active identity into the store first.
        self.multiuser_sync_active().await;
        let target = self
            .multi_users
            .read()
            .await
            .get(master_address)
            .cloned()
            .ok_or_else(|| format!("unknown user: {master_address}"))?;
        *self.user.write().await = target;
        self.save_user().await;
        self.persist_multi_users().await;
        Ok(())
    }

    /// Log out of an added identity: revert to the primary (first-listed) one.
    #[cfg(feature = "multiuser")]
    pub async fn multiuser_logout(&self) -> Result<(), String> {
        let primary = {
            let store = self.multi_users.read().await;
            let active = self.user.read().await.master_address.clone();
            store.keys().find(|a| **a != active).cloned()
        };
        match primary {
            Some(addr) => self.multiuser_select(&addr).await,
            None => Ok(()),
        }
    }

    /// Copy the active identity's full state into the store (so switching keeps
    /// its certs/follows).
    #[cfg(feature = "multiuser")]
    async fn multiuser_sync_active(&self) {
        let active = self.user.read().await.clone();
        self.multi_users.write().await.insert(active.master_address.clone(), active);
        self.persist_multi_users().await;
    }

    /// Write the extra-identities store to disk.
    #[cfg(feature = "multiuser")]
    async fn persist_multi_users(&self) {
        if let Some(path) = &self.multi_users_path {
            let store = self.multi_users.read().await;
            if let Ok(bytes) = serde_json::to_vec_pretty(&*store) {
                let _ = std::fs::write(path, bytes);
            }
        }
    }
}

/// Build a xite's database from its `dbschema.json` (if present): open an
/// in-memory db, create the tables, and populate from the xite's JSON data
/// files. `None` if the xite has no schema or building fails.
/// Every `content.json` under `root`, as site-relative inner_paths.
fn walk_content_json(root: &std::path::Path) -> Vec<String> {
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
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
    }
    out
}

/// The directory the db indexes files under: the site root joined with the
/// directory part of `db_file` (EpixNet's `db_dir = dirname(db_path)`), so
/// json paths are relative to the db file, not the site root.
fn db_file_dir(root: &std::path::Path, db_file: &str) -> std::path::PathBuf {
    match db_file.replace('\\', "/").rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => root.join(dir),
        _ => root.to_path_buf(),
    }
}

fn build_xite_db(storage: &XiteStorage, muted: &[String]) -> Option<(Database, DbSchema)> {
    let bytes = storage.read("dbschema.json").ok()?;
    let schema = DbSchema::from_json(&String::from_utf8_lossy(&bytes)).ok()?;
    let db = Database::open_in_memory().ok()?;
    db.apply_schema(&schema).ok()?;
    // A version-3 merger db is filled from its merged sites (rebuild_merger_dbs),
    // not from its own files; everything else populates from its own tree -
    // skipping muted authors' data files (ContentFilter enforcement).
    if schema.version != 3 {
        // EpixNet indexes files relative to the db FILE's directory (from
        // `db_file`, e.g. data/users/epix_talk.db -> data/users/), so the
        // json.directory of data/users/dice.epix/data.json is `dice.epix`,
        // not `data/users/dice.epix`. Root the scan there.
        let db_dir = db_file_dir(storage.root(), &schema.db_file);
        let _ = db.populate_filtered(&schema, &db_dir, muted);
    }
    Some((db, schema))
}

/// Create (or right-size) a file at `size` bytes so pieces can be written into
/// it sparsely at their offsets.
fn ensure_sparse_file(storage: &XiteStorage, inner_path: &str, size: u64) -> Result<(), String> {
    let path = storage.path(inner_path).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let wrong_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(u64::MAX) != size;
    if wrong_size {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        f.set_len(size).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Write `data` at `offset` in an existing file.
fn write_at(storage: &XiteStorage, inner_path: &str, offset: u64, data: &[u8]) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let path = storage.path(inner_path).map_err(|e| e.to_string())?;
    let mut f = std::fs::OpenOptions::new().write(true).open(&path).map_err(|e| e.to_string())?;
    f.seek(SeekFrom::Start(offset)).map_err(|e| e.to_string())?;
    f.write_all(data).map_err(|e| e.to_string())
}

/// Whether the piece at `offset` (length `len`) is present and matches `hash`.
fn piece_present(storage: &XiteStorage, inner_path: &str, offset: u64, len: u64, hash: &str) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(path) = storage.path(inner_path) else { return false };
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    if f.seek(SeekFrom::Start(offset)).is_err() {
        return false;
    }
    let mut buf = vec![0u8; len as usize];
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    XiteStorage::hash_bytes(&buf) == hash
}

/// content.json trimmed for `siteInfo`: `files`/`files_optional`/`includes`
/// become counts, and the signatures are stripped (matches `formatSiteInfo`).
/// Split a FilePack path into `(archive_inner_path, path_within_archive)` if it
/// points inside a `.zip` or `.tar.gz` archive, e.g.
/// `data.zip/img/a.jpg` -> `("data.zip", "img/a.jpg")`.
fn split_archive_path(inner_path: &str) -> Option<(String, String)> {
    for marker in [".tar.gz/", ".zip/"] {
        if let Some(pos) = inner_path.find(marker) {
            let split = pos + marker.len() - 1; // keep the extension, drop the slash
            return Some((inner_path[..split].to_string(), inner_path[split + 1..].to_string()));
        }
    }
    None
}

/// Read `within` out of an in-memory `.zip` or `.tar.gz` archive.
fn read_from_archive(archive_path: &str, bytes: &[u8], within: &str) -> Option<Vec<u8>> {
    use std::io::Read;
    if archive_path.ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).ok()?;
        let mut file = zip.by_name(within).ok()?;
        let mut out = Vec::new();
        file.read_to_end(&mut out).ok()?;
        Some(out)
    } else {
        // .tar.gz
        let gz = flate2::read::GzDecoder::new(bytes);
        let mut tar = tar::Archive::new(gz);
        for entry in tar.entries().ok()? {
            let mut entry = entry.ok()?;
            let path = entry.path().ok()?;
            if path.to_string_lossy() == within {
                let mut out = Vec::new();
                entry.read_to_end(&mut out).ok()?;
                return Some(out);
            }
        }
        None
    }
}

/// Free disk space (bytes) on the filesystem holding `path`'s directory (or the
/// current directory). Uses `statvfs` on unix.
/// Recursively copy a directory (for `set_data_dir`'s move to a new root).
/// Follows the file tree only - no symlink chasing surprises are expected in
/// a data dir the node wrote itself.
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

fn free_space(path: Option<&std::path::Path>) -> i64 {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let dir = path.and_then(|p| p.parent()).unwrap_or_else(|| std::path::Path::new("."));
        let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return 0 };
        // SAFETY: statvfs writes into the zeroed struct; we read it only on success.
        unsafe {
            let mut stat: libc::statvfs = std::mem::zeroed();
            if libc::statvfs(c.as_ptr(), &mut stat) == 0 {
                return stat.f_bavail.saturating_mul(stat.f_frsize as _) as i64;
            }
        }
        0
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0
    }
}

/// Format a `[date_added, level, message]` log tuple as the sidebar console's
/// `[HH:MM:SS] LEVEL Module text` string (UTC time-of-day; module = `Node`).
fn format_log_line(line: &Value) -> String {
    let secs = line.get(0).and_then(Value::as_f64).unwrap_or(0.0) as i64;
    let level = line.get(1).and_then(Value::as_str).unwrap_or("INFO");
    let msg = line.get(2).and_then(Value::as_str).unwrap_or("");
    let tod = secs.rem_euclid(86400);
    format!("[{:02}:{:02}:{:02}] {} Node {}", tod / 3600, (tod % 3600) / 60, tod % 60, level, msg)
}

/// Whether a stored console log line (`[ts, level, message]`) passes a console
/// tab filter. An empty filter (the "All" tab) shows everything; otherwise the
/// line's level must match. The Error tab also covers CRITICAL, mirroring
/// `server_errors`.
fn log_line_matches(line: &Value, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    let level = line.get(1).and_then(Value::as_str).unwrap_or("");
    level.eq_ignore_ascii_case(filter)
        || (filter.eq_ignore_ascii_case("ERROR") && level.eq_ignore_ascii_case("CRITICAL"))
}

/// The address a permission grant is keyed by: the xite's signed content
/// address when known (so a site served under both its raw address and a
/// `.epix` alias shares one grant), otherwise the serving key.
/// Build the optional-file hashfield from what's present on disk: for each
/// `files_optional` entry we actually hold (hash-verified), record its hash id.
fn compute_hashfield(storage: &XiteStorage, content: Option<&Value>) -> epix_xite::Hashfield {
    let mut hf = epix_xite::Hashfield::new();
    let Some(files) = content.and_then(|c| c.get("files_optional")).and_then(|f| f.as_object())
    else {
        return hf;
    };
    for (path, info) in files {
        let Some(sha512) = info.get("sha512").and_then(|v| v.as_str()) else { continue };
        if storage.verify(path, sha512) {
            hf.add_hash(sha512);
        }
    }
    hf
}

fn canonical_address(content: Option<&Value>, serving_key: &str) -> String {
    content
        .and_then(|c| c.get("address"))
        .and_then(Value::as_str)
        .unwrap_or(serving_key)
        .to_string()
}

fn summarize_content(content: &Value) -> Value {
    let mut c = content.clone();
    if let Value::Object(map) = &mut c {
        // If the xite doesn't declare a top-level `favicon`, fall back to a
        // conventional favicon file it ships (EpixTalk carries
        // `img/favicon.ico` with no `favicon` key). The dashboard site rail
        // reads `content.favicon` to show the marker icon, so without this it
        // shows the plain brand dot even though a favicon exists. Do this
        // before `files` is replaced by a count below.
        let has_favicon = map.get("favicon").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
        if !has_favicon {
            let from_files = map
                .get("files")
                .and_then(Value::as_object)
                .and_then(pick_favicon_file);
            if let Some(path) = from_files {
                map.insert("favicon".into(), json!(path));
            }
        }
        for key in ["files", "files_optional", "includes"] {
            let count = map.get(key).and_then(|v| v.as_object()).map(|o| o.len()).unwrap_or(0);
            map.insert(key.to_string(), json!(count));
        }
        map.remove("sign");
        map.remove("signs");
        map.remove("signers_sign");
    }
    c
}

/// Pick a favicon out of a content.json `files` map for xites that ship one but
/// don't declare a top-level `favicon`. Prefers well-known locations, then any
/// file basename that starts with `favicon.`.
fn pick_favicon_file(files: &serde_json::Map<String, Value>) -> Option<String> {
    const KNOWN: [&str; 4] =
        ["favicon.ico", "favicon.png", "img/favicon.ico", "img/favicon.png"];
    for cand in KNOWN {
        if files.contains_key(cand) {
            return Some(cand.to_string());
        }
    }
    files
        .keys()
        .find(|k| {
            let base = k.rsplit('/').next().unwrap_or(k);
            base.starts_with("favicon.")
        })
        .cloned()
}

/// `getNextSizeLimit`: the smallest tier (MB) that fits `size * 1.2`.
fn next_size_limit(size_bytes: i64) -> i64 {
    const TIERS: [i64; 13] =
        [10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000];
    let need = size_bytes as f64 * 1.2;
    for tier in TIERS {
        if need < tier as f64 * 1024.0 * 1024.0 {
            return tier;
        }
    }
    999999
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn summarize_content_falls_back_to_favicon_file() {
        // Declares a `favicon` key: kept as-is.
        let declared = summarize_content(&json!({
            "favicon": "custom.png",
            "files": { "custom.png": {}, "index.html": {} },
        }));
        assert_eq!(declared["favicon"], "custom.png");

        // No key but ships img/favicon.ico (EpixTalk's case): backfilled.
        let from_file = summarize_content(&json!({
            "files": { "img/favicon.ico": {}, "index.html": {} },
        }));
        assert_eq!(from_file["favicon"], "img/favicon.ico");
        // files is still collapsed to a count.
        assert_eq!(from_file["files"], 2);

        // Root favicon.ico wins over an img/ one.
        let root = summarize_content(&json!({
            "files": { "img/favicon.png": {}, "favicon.ico": {} },
        }));
        assert_eq!(root["favicon"], "favicon.ico");

        // No favicon anywhere: key stays absent.
        let none = summarize_content(&json!({ "files": { "index.html": {} } }));
        assert!(none.get("favicon").is_none());
    }

    #[tokio::test]
    async fn all_trackers_merges_bootstrap_shared_and_extra_deduped() {
        let state = AppState::new("test");
        let mk = |s: &str| epix_xite::Tracker::Epix(PeerAddr::parse(s).unwrap());
        let bootstrap = vec![mk("1.1.1.1:26959")];

        // No shared/extra yet: just the bootstrap list.
        assert_eq!(state.all_trackers(&bootstrap).await, bootstrap);

        // A shared tracker (config) and a Beacon-discovered one both fold in.
        state.config_set("shared_trackers", json!(["2.2.2.2:26959"])).await;
        state.set_extra_trackers(vec![mk("3.3.3.3:26959")]).await;
        let all = state.all_trackers(&bootstrap).await;
        assert!(all.contains(&mk("1.1.1.1:26959")));
        assert!(all.contains(&mk("2.2.2.2:26959")));
        assert!(all.contains(&mk("3.3.3.3:26959")));

        // A tracker present in more than one source appears once.
        state.config_set("shared_trackers", json!(["1.1.1.1:26959", "2.2.2.2:26959"])).await;
        let all = state.all_trackers(&bootstrap).await;
        assert_eq!(all.iter().filter(|t| **t == mk("1.1.1.1:26959")).count(), 1);
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn tracker_back_off_after_repeated_errors() {
        let state = AppState::new("test");
        let tracker = epix_xite::Tracker::Epix(PeerAddr::parse("1.2.3.4:26959").unwrap());
        // Fresh tracker: never backed off.
        assert!(!state.tracker_backed_off(&tracker).await);
        // Six failed announces (num_added == 0 records an error).
        for _ in 0..6 {
            state.record_tracker(&tracker, 0).await;
        }
        // >5 errors and just tried -> backed off this round.
        assert!(state.tracker_backed_off(&tracker).await);
        // A success resets the error count, so it is tried again.
        state.record_tracker(&tracker, 3).await;
        // num_error is still 6 in the running total, but a fresh look uses the
        // recorded time; force the stat's time_request into the past to prove
        // the window, not the count alone, gates it.
        {
            let mut stats = state.tracker_stats.write().await;
            let key = tracker_stat_key(&tracker);
            let e = stats.get_mut(&key).unwrap().as_object_mut().unwrap();
            e.insert("time_request".into(), json!(0));
        }
        assert!(!state.tracker_backed_off(&tracker).await, "old enough to retry");
    }

    #[tokio::test]
    async fn chart_collect_then_query_returns_datapoints() {
        let dir = tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite(
                "1SizeXite",
                XiteEntry {
                    storage: XiteStorage::new(dir.path()),
                    content: Some(json!({ "address": "1SizeXite", "files": { "a": { "size": 500 } } })),
                },
            )
            .await;

        state.collect_chart().await;

        // The type table is populated with the metric names the Stats page reads.
        let types = state.chart_query("SELECT * FROM type", &Value::Null).await.unwrap();
        let names: Vec<&str> = types.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"size"));
        assert!(names.contains(&"connection"));
        assert!(names.contains(&"peer"));

        // The site table has our xite.
        let sites = state.chart_query("SELECT * FROM site", &Value::Null).await.unwrap();
        assert!(sites.iter().any(|s| s["address"] == "1SizeXite"));

        // The global `size` datapoint reflects the xite's content size (500).
        let rows = state
            .chart_query(
                "SELECT value FROM data WHERE type_id = (SELECT type_id FROM type WHERE name='size') AND site_id IS NULL",
                &Value::Null,
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["value"], 500);

        // The Stats page's chart query binds a list param: `type_id IN
        // :type_ids` expands to a placeholder list and returns the latest value
        // per requested type. Look up the ids for `size` and `peer`.
        let type_ids: Vec<i64> = types
            .iter()
            .filter(|t| matches!(t["name"].as_str(), Some("size") | Some("peer")))
            .filter_map(|t| t["type_id"].as_i64())
            .collect();
        assert_eq!(type_ids.len(), 2);
        let latest = state
            .chart_query(
                "SELECT type_id, value FROM data WHERE type_id IN :type_ids AND site_id IS NULL",
                &json!({ "type_ids": type_ids }),
            )
            .await
            .unwrap();
        assert_eq!(latest.len(), 2, "list param expands and both types match");

        // Non-SELECT statements are rejected.
        assert!(state.chart_query("DELETE FROM data", &Value::Null).await.is_err());
    }

    fn sample_content() -> Value {
        json!({
            "address": "1abc",
            "modified": 1777992697.0,
            "title": "Test Xite",
            "files": {
                "index.html": {"size": 100, "sha512": "a"},
                "js/app.js": {"size": 250, "sha512": "b"},
            },
            "files_optional": {"big.mp4": {"size": 9000, "sha512": "c"}},
            "includes": {"data/content.json": {}},
            "sign": "should-be-stripped",
            "signs": {"1abc": "x"},
        })
    }

    #[tokio::test]
    async fn browser_settings_reads_epix_browser_and_tor_clearnet() {
        let dir = tempdir().unwrap();
        let state = AppState::with_data_dir("test", dir.path());
        let path = dir.path().join("browser-settings.json");

        // No file: not running under Epix Browser; tor_clearnet defaults on.
        assert_eq!(state.browser_settings().await, (false, true));

        // File present with the checkbox off: Epix Browser, clearnet NOT via Tor.
        std::fs::write(&path, br#"{"tor_clearnet": false}"#).unwrap();
        assert_eq!(state.browser_settings().await, (true, false));

        // File present without the key: default on (opt-out).
        std::fs::write(&path, br#"{"clearnet_allow": {}}"#).unwrap();
        assert_eq!(state.browser_settings().await, (true, true));
    }

    #[tokio::test]
    async fn dialable_networks_follows_transport_state() {
        let state = AppState::new("test");

        // Fresh node: only clearnet is dialable.
        let nets = state.dialable_networks().await;
        assert!(nets.clearnet && !nets.onion && !nets.i2p && !nets.rns);

        // Tor client up: onion dialable, regardless of our own onion service.
        state.set_tor_status(true, "OK").await;
        assert!(state.dialable_networks().await.onion);
        state.set_tor_status(true, "Always").await;
        assert!(state.dialable_networks().await.onion);
        state.set_tor_status(false, "Disabled").await;
        assert!(!state.dialable_networks().await.onion);

        // I2P needs BOTH the transport composed in and the session Ready.
        state.set_i2p_transport(Arc::new(epix_transport::TcpTransport)).await;
        state.set_i2p_status(json!({ "phase": "Starting…" })).await;
        assert!(!state.dialable_networks().await.i2p, "starting is not dialable");
        state.set_i2p_status(json!({ "phase": "Ready" })).await;
        assert!(state.dialable_networks().await.i2p);

        // Mesh transport up: rns dialable.
        state.set_rns_transport(Arc::new(epix_transport::TcpTransport)).await;
        assert!(state.dialable_networks().await.rns);
    }

    /// Phase 4: `want_i2p` asks trackers for i2p peers, so it must key on
    /// whether we can DIAL i2p - not on whether we publish an inbound b32.
    #[tokio::test]
    async fn want_i2p_follows_dialability_not_inbound_address() {
        let state = AppState::new("test");

        // A published inbound b32 alone must NOT request i2p peers: with no
        // dialable i2p transport we could never reach any peer we're handed.
        state.set_i2p_address("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32").await;
        assert!(!state.self_advert().await.want_i2p, "inbound b32 alone is not dialability");

        // Transport composed in but session not Ready yet: still no.
        state.set_i2p_transport(Arc::new(epix_transport::TcpTransport)).await;
        state.set_i2p_status(json!({ "phase": "Starting…" })).await;
        assert!(!state.self_advert().await.want_i2p);

        // Dialable (transport + Ready): want i2p peers - even a dial-only
        // node with no inbound b32 of its own benefits.
        state.set_i2p_status(json!({ "phase": "Ready" })).await;
        assert!(state.self_advert().await.want_i2p);

        // The advert still carries our inbound b32 independently of want_i2p.
        let advert = state.self_advert().await;
        assert_eq!(
            advert.i2p.as_deref(),
            Some("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32")
        );
    }

    #[tokio::test]
    async fn connectable_peers_filters_networks_the_node_cannot_dial() {
        let dir = tempdir().unwrap();
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let state = AppState::new("test"); // no Tor: clearnet-only node
        state
            .add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;

        let clearnet = PeerAddr::parse("8.8.8.8:15441").unwrap();
        let onion = PeerAddr::parse("expyuzz4wqqyqhjn.onion:15441").unwrap();
        state.add_peers(addr, [clearnet.clone(), onion.clone()]).await;

        // A clearnet peer exists: the undialable onion peer is excluded, so
        // it can't crowd reachable peers out of the worker's list.
        assert_eq!(state.connectable_peers(addr, 10).await, vec![clearnet.clone()]);

        // Tor comes up: both are candidates, clearnet preferred.
        state.set_tor_status(true, "OK").await;
        let got = state.connectable_peers(addr, 10).await;
        assert_eq!(got, vec![clearnet, onion.clone()]);
        state.set_tor_status(false, "Disabled").await;

        // An onion-only xite on the same clearnet-only node still gets its
        // peer (fallback) - selection never starves an overlay-only xite.
        let dir2 = tempdir().unwrap();
        let addr2 = "epix1readmehqfdxy4pzx7u72wwaerc4psx0gt6fety";
        state
            .add_xite(addr2, XiteEntry { storage: XiteStorage::new(dir2.path()), content: None })
            .await;
        state.add_peers(addr2, [onion.clone()]).await;
        assert_eq!(state.connectable_peers(addr2, 10).await, vec![onion]);
    }

    #[tokio::test]
    async fn add_peers_drops_the_nodes_own_addresses() {
        let dir = tempdir().unwrap();
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let state = AppState::new("test");
        state
            .add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;
        state.set_fileserver_port(26552).await;
        state.set_port_status(true, Some("74.208.249.9".into())).await;
        state.set_onion_address("jszogollvhtyttpbcdhghuewsbojgdioixvoqphtyq5bqyvfkjx3k5qd").await;

        let own_ip = PeerAddr::parse("74.208.249.9:26552").unwrap();
        let own_onion = PeerAddr::parse(
            "jszogollvhtyttpbcdhghuewsbojgdioixvoqphtyq5bqyvfkjx3k5qd.onion:26552",
        )
        .unwrap();
        // Same onion under an old port is still us.
        let own_onion_old_port = PeerAddr::parse(
            "jszogollvhtyttpbcdhghuewsbojgdioixvoqphtyq5bqyvfkjx3k5qd.onion:48333",
        )
        .unwrap();
        let other = PeerAddr::parse("8.8.8.8:26552").unwrap();
        // Same IP but a different port is NOT filtered (a NAT neighbor).
        let same_ip_other_port = PeerAddr::parse("74.208.249.9:11111").unwrap();

        state
            .add_peers(addr, [own_ip, own_onion, own_onion_old_port, other, same_ip_other_port])
            .await;
        let mut got = state.connectable_peers(addr, 10).await;
        got.sort_by_key(|p| p.to_string());
        assert_eq!(
            got,
            vec![
                PeerAddr::parse("74.208.249.9:11111").unwrap(),
                PeerAddr::parse("8.8.8.8:26552").unwrap(),
            ],
            "own addresses dropped, real peers kept"
        );
    }

    /// The i2p and rns arms of `is_own_peer` are exercised directly (not via
    /// connectable_peers, which would also drop them for dialability and mask a
    /// broken arm). Phase 4 announces i2p/rns self-claims to the DHT that echo
    /// straight back, so these arms are the only guard against self-dialing.
    #[tokio::test]
    async fn is_own_peer_matches_i2p_and_rns_self_addresses() {
        let state = AppState::new("test");
        state.set_fileserver_port(26552).await;
        state
            .set_i2p_address("shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32")
            .await;
        // rns_address is stored as given; is_own_peer lowercases for the compare,
        // so an uppercase stored hash must still match its `rns:<lower>` form.
        state.set_rns_address("00112233445566778899AABBCCDDEEFF").await;

        // Our own i2p destination (any virtual port) is us.
        assert!(
            state
                .is_own_peer(
                    &PeerAddr::parse(
                        "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p:26552"
                    )
                    .unwrap()
                )
                .await
        );
        // Our own rns destination is us, case-insensitively.
        assert!(
            state
                .is_own_peer(&PeerAddr::parse("rns:00112233445566778899aabbccddeeff").unwrap())
                .await
        );
        // A different i2p dest / rns hash is NOT us.
        assert!(
            !state
                .is_own_peer(
                    &PeerAddr::parse(
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p:26552"
                    )
                    .unwrap()
                )
                .await
        );
        assert!(
            !state
                .is_own_peer(&PeerAddr::parse("rns:ffffffffffffffffffffffffffffffff").unwrap())
                .await
        );
    }

    /// find_peers_dht must drop the node's own echoed claims before the clone /
    /// user-content paths dial them (they bypass add_peers' own-peer filter).
    #[tokio::test]
    async fn find_peers_dht_drops_own_echoed_claims() {
        struct StubFinder(Vec<PeerAddr>);
        #[async_trait::async_trait]
        impl PeerFinder for StubFinder {
            async fn find(&self, _address: &str) -> Vec<PeerAddr> {
                self.0.clone()
            }
        }

        let state = AppState::new("test");
        state.set_fileserver_port(26552).await;
        state.set_onion_address("jszogollvhtyttpbcdhghuewsbojgdioixvoqphtyq5bqyvfkjx3k5qd").await;

        let own_onion = PeerAddr::parse(
            "jszogollvhtyttpbcdhghuewsbojgdioixvoqphtyq5bqyvfkjx3k5qd.onion:26552",
        )
        .unwrap();
        let real_peer = PeerAddr::parse("expyuzz4wqqyqhjn.onion:26552").unwrap();
        state
            .set_peer_finder(Arc::new(StubFinder(vec![own_onion, real_peer.clone()])))
            .await;

        let got = state.find_peers_dht("epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g").await;
        assert_eq!(got, vec![real_peer], "own onion echo dropped, real peer kept");
    }

    #[tokio::test]
    async fn peer_outcomes_move_reputation_and_backoff() {
        let dir = tempdir().unwrap();
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let state = AppState::new("test");
        state
            .add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;
        let good = PeerAddr::parse("1.1.1.1:15441").unwrap();
        let dead = PeerAddr::parse("2.2.2.2:15441").unwrap();
        state.add_peers(addr, [good.clone(), dead.clone()]).await;

        // A sync pass's outcomes: `good` served a file, `dead` failed a dial.
        state
            .apply_peer_outcomes(
                addr,
                vec![
                    (good.clone(), epix_worker::PeerOutcome::ConnectOk),
                    (good.clone(), epix_worker::PeerOutcome::FileOk),
                    (dead.clone(), epix_worker::PeerOutcome::ConnectFail),
                ],
            )
            .await;

        // The dead peer is now in backoff: selection returns only `good`,
        // and the worker marked it connected (it never did before).
        assert_eq!(state.connectable_peers(addr, 10).await, vec![good]);
        assert_eq!(state.peer_counts(addr).await.connected, 1);
    }

    #[tokio::test]
    async fn load_content_from_disk_heals_registered_but_empty_entry() {
        let dir = tempdir().unwrap();
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        // A clone that wrote content.json to disk but errored before finalizing:
        // registered with content = None while the file sits on disk.
        std::fs::write(
            dir.path().join("content.json"),
            serde_json::to_vec(&json!({
                "address": addr,
                "modified": 1777992697.0,
                "title": "Epix Test",
                "files": { "index.html": { "size": 100, "sha512": "a" } },
            }))
            .unwrap(),
        )
        .unwrap();
        let state = AppState::new("test");
        state
            .add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;

        // Before: siteInfo has no title (the wrapper's perpetual download page).
        assert!(state.site_info(addr).await["content"].get("title").is_none());

        // Heal it from disk.
        assert!(state.load_content_from_disk(addr).await);

        // After: content is loaded and siteInfo carries the real title + stats.
        let info = state.site_info(addr).await;
        assert_eq!(info["content"]["title"], "Epix Test");
        assert_eq!(info["settings"]["size"], 100);

        // Idempotent: a second call is a no-op that still reports present.
        assert!(state.load_content_from_disk(addr).await);
    }

    #[tokio::test]
    async fn incomplete_update_keeps_previous_version_serving() {
        // The gateway regression: an update whose files can't all be fetched
        // must leave the previous version serving - on disk AND in the live
        // state - instead of a content.json that is ahead of its files.
        let dir = tempdir().unwrap();
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let storage = XiteStorage::new(dir.path());

        let v1 = serde_json::to_vec(&json!({
            "address": addr, "modified": 100.0, "title": "V1", "files": {}
        }))
        .unwrap();
        storage.write("content.json", &v1).unwrap();
        let state = AppState::new("test");
        state
            .add_xite(
                addr,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(serde_json::from_slice(&v1).unwrap()),
                },
            )
            .await;

        // Served under a `.epix` alias too: a commit must swap every key.
        state
            .add_xite(
                "dash.epix",
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(serde_json::from_slice(&v1).unwrap()),
                },
            )
            .await;

        // A newer v2 arrives but one of its files couldn't be fetched: the
        // update is deferred, nothing on disk or in the live state changes.
        let v2_content = json!({
            "address": addr, "modified": 200.0, "title": "V2",
            "files": { "js/app.js": { "size": 5, "sha512": "aa" } },
        });
        let v2 = serde_json::to_vec(&v2_content).unwrap();
        let keys = vec![addr.to_string(), "dash.epix".to_string()];
        let committed = state
            .finalize_root_update(
                &keys,
                addr,
                &storage,
                v2_content.clone(),
                &v2,
                &["js/app.js".to_string()],
            )
            .await;
        assert!(!committed);
        assert_eq!(storage.read("content.json").unwrap(), v1, "old version stays on disk");
        assert_eq!(state.site_info(addr).await["content"]["title"], "V1", "old version serves");
        assert_eq!(state.bad_files(addr).await, vec!["js/app.js"], "missing file recorded");

        // The files land later (any path): the same finalize now commits the
        // exact signed bytes and swaps the live state.
        let committed =
            state.finalize_root_update(&keys, addr, &storage, v2_content, &v2, &[]).await;
        assert!(committed);
        assert_eq!(storage.read("content.json").unwrap(), v2, "exact bytes committed");
        assert_eq!(state.site_info(addr).await["content"]["title"], "V2");
        assert_eq!(state.site_info("dash.epix").await["content"]["title"], "V2", "alias swapped");
        assert!(state.bad_files(addr).await.is_empty(), "bad_files cleared on commit");
    }

    #[tokio::test]
    async fn retry_pending_updates_commits_once_files_land() {
        // A deferred update converges: once its missing file appears on disk,
        // the retry tick commits it without needing peers or a transport.
        let dir = tempdir().unwrap();
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let storage = XiteStorage::new(dir.path());

        let v1 = serde_json::to_vec(&json!({
            "address": addr, "modified": 100.0, "title": "V1", "files": {}
        }))
        .unwrap();
        storage.write("content.json", &v1).unwrap();
        let state = AppState::new("test");
        state
            .add_xite(
                addr,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(serde_json::from_slice(&v1).unwrap()),
                },
            )
            .await;

        let body = b"hello";
        let v2_content = json!({
            "address": addr, "modified": 200.0, "title": "V2",
            "files": { "a.txt": {
                "size": body.len(),
                "sha512": XiteStorage::hash_bytes(body),
            } },
        });
        let v2 = serde_json::to_vec(&v2_content).unwrap();
        let keys = vec![addr.to_string()];
        assert!(
            !state
                .finalize_root_update(&keys, addr, &storage, v2_content, &v2, &["a.txt".into()])
                .await
        );
        assert_eq!(storage.read("content.json").unwrap(), v1);

        // Nothing on disk yet: the retry can't fetch (no transport) and the
        // update stays pending, still serving v1.
        state.retry_pending_updates().await;
        assert_eq!(storage.read("content.json").unwrap(), v1);
        assert_eq!(state.site_info(addr).await["content"]["title"], "V1");

        // The file lands (a later push, another peer, any path): the next
        // retry pass verifies the set is complete and commits.
        storage.write("a.txt", body).unwrap();
        state.retry_pending_updates().await;
        assert_eq!(storage.read("content.json").unwrap(), v2);
        assert_eq!(state.site_info(addr).await["content"]["title"], "V2");

        // Committed pending entries are gone: another pass is a no-op.
        state.retry_pending_updates().await;
        assert_eq!(storage.read("content.json").unwrap(), v2);
    }

    #[tokio::test]
    async fn site_info_is_real_not_stubbed() {
        let dir = tempdir().unwrap();
        let addr = "1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D";
        let state = AppState::new("test");
        state
            .add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(sample_content()) })
            .await;

        let info = state.site_info(addr).await;

        // Real address hash = sha256(address).
        assert_eq!(
            info["address_hash"].as_str().unwrap(),
            hex::encode(Sha256::digest(addr.as_bytes()))
        );
        // Real derived identity.
        assert!(info["auth_address"].as_str().unwrap().starts_with("epix1"));
        // No cert selected: the user directory is the bare auth address
        // (EpixNet's getUserDirectory; an xid cert would make it <name>.epix).
        assert_eq!(info["xid_directory"], info["auth_address"]);

        // Real stats from content.json.
        assert_eq!(info["settings"]["size"], 350);
        assert_eq!(info["settings"]["size_optional"], 9000);
        assert_eq!(info["content_updated"], 1777992697.0);
        // A freshly served xite holds no permissions until the user grants one.
        assert!(info["settings"]["permissions"].as_array().unwrap().is_empty());

        // content.json summarized: counts, signs stripped, title kept.
        assert_eq!(info["content"]["files"], 2);
        assert_eq!(info["content"]["files_optional"], 1);
        assert_eq!(info["content"]["includes"], 1);
        assert_eq!(info["content"]["title"], "Test Xite");
        assert!(info["content"].get("sign").is_none());
        assert!(info["content"].get("signs").is_none());

        // The default limit matches the python client's --size-limit (1000 MB,
        // not EpixNet's old 10) - a growing xite must not stall at 10 MB.
        assert_eq!(info["size_limit"], DEFAULT_SIZE_LIMIT_MB);
        assert_eq!(info["next_size_limit"], 10);
    }

    #[tokio::test]
    async fn site_list_returns_one_entry_per_site_collapsing_aliases() {
        let dir = tempdir().unwrap();
        let state = AppState::new("test");
        // Same signed content served under a raw address and a `.epix` alias.
        let content = json!({ "address": "1HeLLo", "modified": 1.0, "files": {}, "signs": {"1HeLLo": "x"} });
        state
            .add_xite("1HeLLo", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content.clone()) })
            .await;
        state
            .add_xite("hello.epix", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content) })
            .await;
        // A second, distinct site.
        let other = json!({ "address": "1Other", "modified": 1.0, "files": {}, "signs": {"1Other": "x"} });
        state
            .add_xite("1Other", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(other) })
            .await;

        let list = state.site_list().await;
        assert_eq!(list.len(), 2, "alias collapses; two distinct sites remain");
        let addrs: std::collections::HashSet<_> =
            list.iter().map(|s| s["content"]["address"].as_str().unwrap()).collect();
        assert!(addrs.contains("1HeLLo"));
        assert!(addrs.contains("1Other"));
    }

    #[tokio::test]
    async fn db_directory_is_relative_to_the_db_file_dir() {
        // A user_contents-style layout: db under data/users/, per-user data at
        // data/users/<name>/data.json. json.directory must be `<name>`, not
        // `data/users/<name>` (EpixNet computes it relative to the db file).
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Talk","db_file":"data/users/talk.db","version":2,
                     "maps": { ".+/data.json": { "to_table": [{"node":"topic","table":"topic"}] } },
                     "tables": { "topic": { "cols": [["topic_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] } } }"#,
            )
            .unwrap();
        storage
            .write(
                "data/users/dice.epix/data.json",
                br#"{ "topic": [ {"topic_id":1,"title":"Hi"} ] }"#,
            )
            .unwrap();
        let addr = "1TalkAddr";
        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: None }).await;

        let rows = state
            .db_query(addr, "SELECT directory FROM json", &Value::Null)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["directory"], "dice.epix", "directory relative to db file dir");

        // The topic still populated (path matched relative to the db dir).
        let topics = state
            .db_query(addr, "SELECT title FROM topic", &Value::Null)
            .await
            .unwrap();
        assert_eq!(topics[0]["title"], "Hi");
    }

    #[tokio::test]
    async fn db_query_returns_real_rows_from_the_xite_db() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Blog","db_file":"db.db","version":2,
                     "maps": { "data/.*/data.json": { "to_table": [{"node":"posts","table":"post"}] } },
                     "tables": { "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] } } }"#,
            )
            .unwrap();
        storage
            .write(
                "data/alice/data.json",
                br#"{ "posts": [ {"post_id":1,"title":"Hello"}, {"post_id":2,"title":"World"} ] }"#,
            )
            .unwrap();

        let addr = "1BlogAddress";
        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: None }).await;

        let rows = state
            .db_query(addr, "SELECT post_id, title FROM post ORDER BY post_id", &Value::Null)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["title"], "Hello");
        assert_eq!(rows[1]["post_id"], 2);

        // Named params bind.
        let one = state
            .db_query(addr, "SELECT title FROM post WHERE post_id = :id", &json!({"id": 2}))
            .await
            .unwrap();
        assert_eq!(one[0]["title"], "World");
    }

    /// A data file arriving mid-sync is queryable the moment `ingest_file`
    /// runs - no full rebuild needed (this is what makes topics pop in one by
    /// one during a clone).
    #[tokio::test]
    async fn ingest_file_makes_a_new_data_file_queryable_incrementally() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Blog","db_file":"data/users/db.db","version":2,
                     "maps": { ".*/data.json": { "to_table": [{"node":"posts","table":"post"}] } },
                     "tables": { "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] } } }"#,
            )
            .unwrap();
        let addr = "1BlogAddress";
        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: None }).await;

        // The page queried while the db was still empty.
        let rows = state
            .db_query(addr, "SELECT COUNT(*) AS n FROM post", &Value::Null)
            .await
            .unwrap();
        assert_eq!(rows[0]["n"], 0);

        // A user's data.json lands; ingest it without a rebuild.
        XiteStorage::new(dir.path())
            .write(
                "data/users/alice.epix/data.json",
                br#"{ "posts": [ {"post_id":1,"title":"First"} ] }"#,
            )
            .unwrap();
        state.ingest_file(addr, "data/users/alice.epix/data.json").await;

        let rows = state
            .db_query(addr, "SELECT title FROM post", &Value::Null)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["title"], "First");

        // A file outside the db dir is ignored without error.
        state.ingest_file(addr, "index.html").await;
    }

    #[tokio::test]
    async fn optional_limit_evicts_oldest_unpinned_and_keeps_pinned() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        // Three 1000-byte optional files.
        for name in ["a.bin", "b.bin", "c.bin"] {
            storage.write(name, &vec![0u8; 1000]).unwrap();
        }
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let content = json!({
            "address": addr,
            "files": {},
            "files_optional": {
                "a.bin": { "size": 1000, "sha512": "a" },
                "b.bin": { "size": 1000, "sha512": "b" },
                "c.bin": { "size": 1000, "sha512": "c" },
            }
        });
        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: Some(content) }).await;
        state.set_pin(addr, "a.bin", true).await;

        // ~2791-byte cap: 3000 downloaded > cap, so eviction runs.
        state.set_optional_limit("0.0000026").await;
        let limit = state.optional_limit_bytes().await;
        assert!(limit > 1000 && limit < 3000, "limit was {limit}");

        let freed = state.enforce_optional_limit().await;
        assert!(freed > 0, "expected some bytes freed");
        // The pinned file is never evicted.
        assert!(dir.path().join("a.bin").exists());
        // Usage is back under the cap.
        let remaining: i64 = ["a.bin", "b.bin", "c.bin"]
            .iter()
            .filter(|n| dir.path().join(n).exists())
            .count() as i64
            * 1000;
        assert!(remaining <= limit, "remaining {remaining} > limit {limit}");
    }

    #[tokio::test]
    async fn muting_an_author_drops_their_rows_from_the_db() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Blog","db_file":"db.db","version":2,
                     "maps": { "data/.*/data.json": { "to_table": [{"node":"posts","table":"post"}] } },
                     "tables": { "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] } } }"#,
            )
            .unwrap();
        storage.write("data/alice/data.json", br#"{ "posts": [ {"post_id":1,"title":"a"} ] }"#).unwrap();
        storage.write("data/mallory/data.json", br#"{ "posts": [ {"post_id":2,"title":"spam"} ] }"#).unwrap();

        let addr = "1MuteBlog";
        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: None }).await;
        // Both authors' posts present initially.
        assert_eq!(state.db_query(addr, "SELECT COUNT(*) AS n FROM post", &Value::Null).await.unwrap()[0]["n"], 2);

        // Muting mallory rebuilds the db without their data file.
        state.mute_add("mallory", "mallory@cert", "spam").await;
        let rows = state.db_query(addr, "SELECT title FROM post", &Value::Null).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["title"], "a");

        // Un-muting brings it back.
        state.mute_remove("mallory").await;
        assert_eq!(state.db_query(addr, "SELECT COUNT(*) AS n FROM post", &Value::Null).await.unwrap()[0]["n"], 2);
    }

    #[tokio::test]
    async fn siteblock_reason_matches_plain_and_hashed_address() {
        let state = AppState::new("test");
        assert!(state.siteblock_reason("1BadSite").await.is_none());
        state.siteblock_add("1BadSite", "malware").await;
        assert_eq!(state.siteblock_reason("1BadSite").await.as_deref(), Some("malware"));

        // A hashed-address block also matches.
        let hashed = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest("1HashBlocked".as_bytes()))
        };
        state.siteblock_add(&hashed, "hashed").await;
        assert_eq!(state.siteblock_reason("1HashBlocked").await.as_deref(), Some("hashed"));
    }

    #[tokio::test]
    async fn log_level_filters_below_the_configured_minimum() {
        let state = AppState::new("test");
        state.config_set("log_level", json!("ERROR")).await;
        state.log("INFO", "an info line").await; // below ERROR -> dropped
        state.log("DEBUG", "a debug line").await; // dropped
        state.log("ERROR", "a real error").await; // kept
        assert_eq!(state.console_log_read("").await["num_found"], 1);

        // Lowering the threshold lets INFO through again.
        state.config_set("log_level", json!("INFO")).await;
        state.log("INFO", "now visible").await;
        assert_eq!(state.console_log_read("").await["num_found"], 2);
    }

    #[tokio::test]
    async fn console_log_read_filters_by_tab_level() {
        let state = AppState::new("test");
        state.log("INFO", "started").await;
        state.log("INFO", "still going").await;
        state.log("WARNING", "slow peer").await;
        state.log("ERROR", "sync failed").await;

        // Empty filter (the "All" tab) returns every level.
        assert_eq!(state.console_log_read("").await["num_found"], 4);
        // Each tab returns only its own level, not everything.
        assert_eq!(state.console_log_read("INFO").await["num_found"], 2);
        assert_eq!(state.console_log_read("WARNING").await["num_found"], 1);
        assert_eq!(state.console_log_read("ERROR").await["num_found"], 1);

        // The Error tab also surfaces CRITICAL lines.
        state.log("CRITICAL", "disk full").await;
        assert_eq!(state.console_log_read("ERROR").await["num_found"], 2);
    }

    #[tokio::test]
    async fn console_stream_only_pushes_matching_levels() {
        let state = AppState::new("test");
        // Open a WARNING-filtered stream.
        let sid = state.console_log_stream_open("WARNING").await;
        let mut events = state.subscribe_events();

        // An INFO line must not be streamed to a WARNING tab.
        state.log("INFO", "routine").await;
        assert!(events.try_recv().is_err());

        // A WARNING line is streamed with the matching id.
        state.log("WARNING", "slow peer").await;
        let ev = events.try_recv().unwrap();
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "logLineAdd");
        assert_eq!(payload["params"]["stream_id"], sid);
        assert!(payload["params"]["lines"][0].as_str().unwrap().contains("slow peer"));
    }

    #[tokio::test]
    async fn notification_count_reads_the_count_column_not_row_count() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Blog","db_file":"db.db","version":2,
                     "maps": { "data/.*/data.json": { "to_table": [{"node":"posts","table":"post"}] } },
                     "tables": { "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] } } }"#,
            )
            .unwrap();
        storage
            .write(
                "data/alice/data.json",
                br#"{ "posts": [ {"post_id":1,"title":"a"}, {"post_id":2,"title":"b"}, {"post_id":3,"title":"c"} ] }"#,
            )
            .unwrap();
        let addr = "1BlogAddr";
        let state = AppState::new("test");
        state
            .add_xite(addr, XiteEntry {
                storage,
                content: Some(json!({
                    "address": addr, "title": "Blog", "files": {},
                    "notification_icons": { "unread": "img/bell.png" },
                })),
            })
            .await;
        // A COUNT(*) subscription must report the column value (3), not 1 row,
        // with the EpixNet result shape (site/title/icon, num = entry count).
        state
            .notification_subscribe(addr, json!({ "unread": ["SELECT COUNT(*) AS count FROM post", null] }))
            .await;
        let q = state.notification_query().await;
        assert_eq!(q["num"], 1, "num counts entries, not totals: {q}");
        let entry = &q["results"][0];
        assert_eq!(entry["count"], 3);
        assert_eq!(entry["site"], addr);
        assert_eq!(entry["title"], "Blog");
        assert_eq!(entry["icon"], "img/bell.png");

        // A `{last_seen}` query filters by the dismiss timestamp.
        state
            .notification_subscribe(
                addr,
                json!({ "unread": ["SELECT COUNT(*) AS count FROM post WHERE post_id > {last_seen}", null] }),
            )
            .await;
        state.notification_mark_dismissed(addr, "unread").await;
        let q = state.notification_query().await;
        // last_seen is a fresh ms timestamp, far above every post_id.
        assert_eq!(q["results"][0]["count"], 0);
        assert!(q["results"][0]["last_seen"].as_i64().unwrap() > 0);

        // The notification_seen baseline (stored via userSetSettings) subtracts.
        state
            .notification_subscribe(addr, json!({ "unread": ["SELECT COUNT(*) AS count FROM post", null] }))
            .await;
        state
            .set_user_site_settings(addr, json!({ "notification_seen": { "unread": 2 } }))
            .await
            .unwrap();
        let q = state.notification_query().await;
        assert_eq!(q["results"][0]["count"], 1, "3 total minus 2 seen: {q}");
    }

    #[tokio::test]
    async fn pause_stops_resync_and_reflects_in_site_info() {
        let content = json!({ "address": "1PauseMe", "files": {} });
        let state = AppState::new("test");
        let dir = tempdir().unwrap();
        state
            .add_xite("1PauseMe", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content) })
            .await;
        assert!(state.is_serving("1PauseMe").await);

        assert!(state.set_serving("1PauseMe", false).await);
        assert!(!state.is_serving("1PauseMe").await);
        // A paused xite is not re-synced (returns Ok(false), even with no transport).
        assert_eq!(state.resync_xite("1PauseMe").await, Ok(false));
        assert_eq!(state.site_info("1PauseMe").await["settings"]["serving"], false);

        assert!(state.set_serving("1PauseMe", true).await);
        assert_eq!(state.site_info("1PauseMe").await["settings"]["serving"], true);
    }

    #[tokio::test]
    async fn no_new_sites_plugin_toggle_locks_the_site_set() {
        struct AlwaysClone;
        #[async_trait::async_trait]
        impl OnDemandResolver for AlwaysClone {
            async fn ensure(&self, _host: &str) -> Result<(), String> {
                Ok(())
            }
            async fn resolve(&self, host: &str) -> Option<String> {
                host.starts_with("epix1").then(|| host.to_string())
            }
        }
        let state = AppState::new("test");
        state.set_on_demand(Arc::new(AlwaysClone)).await;

        // Plugin off (default): resolver runs (returns false only because the
        // stub doesn't register anything).
        assert!(!state.no_new_sites().await);

        // Plugin on: the site set is locked and the resolver is never asked.
        state.set_plugin_enabled("NoNewSites", true).await;
        assert!(state.no_new_sites().await);
        assert!(!state.ensure_xite("locked.epix").await);

        // The config key still works as an operator override.
        state.set_plugin_enabled("NoNewSites", false).await;
        assert!(!state.no_new_sites().await);
        state.config_set("no_new_sites", serde_json::json!(true)).await;
        assert!(state.no_new_sites().await);
    }

    #[tokio::test]
    async fn favourite_and_delete_take_effect() {
        let content = json!({ "address": "1FavMe", "files": {} });
        let state = AppState::new("test");
        let dir = tempdir().unwrap();
        state
            .add_xite("1FavMe", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content) })
            .await;
        assert!(state.set_favorite("1FavMe", true).await);
        assert_eq!(state.site_info("1FavMe").await["settings"]["favorite"], true);

        // Delete removes the xite; a second delete reports not-found.
        assert!(state.remove_xite("1FavMe").await);
        assert!(!state.has_xite("1FavMe").await);
        assert!(!state.remove_xite("1FavMe").await);
    }

    #[tokio::test]
    async fn delete_removes_all_aliases_files_and_sites_json_entry() {
        // A site served under both its signed address and a `.epix` alias,
        // like the browser sets up. Deleting by the signed address (what the
        // dashboard sends) must remove both entries, the files, and the
        // sites.json record - a surviving alias used to re-sync the site and
        // write it back, so it came back after a restart.
        let root = tempdir().unwrap();
        let addr = "1DeleteMe";
        let state = AppState::with_data_dir("test", root.path());
        let site_dir = root.path().join("data").join(addr);
        std::fs::create_dir_all(&site_dir).unwrap();
        std::fs::write(site_dir.join("index.html"), b"hi").unwrap();
        let content = json!({ "address": addr, "files": {} });
        let entry = || XiteEntry {
            storage: XiteStorage::new(&site_dir),
            content: Some(content.clone()),
        };
        state.add_xite(addr, entry()).await;
        state.add_xite("deleteme.epix", entry()).await;
        assert_eq!(state.site_list().await.len(), 1, "alias collapses to one site");

        assert!(state.remove_xite(addr).await);
        // Both serving keys gone, so nothing re-syncs it.
        assert!(!state.has_xite(addr).await);
        assert!(!state.has_xite("deleteme.epix").await);
        assert!(state.site_list().await.is_empty());
        // Files gone.
        assert!(!site_dir.exists());
        // sites.json no longer records it, so a restart won't restore it.
        let sites: serde_json::Map<String, Value> =
            std::fs::read(root.path().join("private/sites.json"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
        assert!(!sites.contains_key(addr));

        // Deleting by the alias works the same way.
        state.add_xite(addr, entry()).await;
        state.add_xite("deleteme.epix", entry()).await;
        assert!(state.remove_xite("deleteme.epix").await);
        assert!(!state.has_xite(addr).await);
        assert!(!state.has_xite("deleteme.epix").await);
    }

    #[tokio::test]
    async fn xid_clear_cache_forces_fresh_resolution() {
        // "Clear xID cache" must drop everything that can answer a name with a
        // remembered address: the display binding on a served xite (checked
        // first by resolve_name) and the on-disk resolve cache. Otherwise a
        // name moved to a new address on chain keeps loading the old xite.
        let root = tempdir().unwrap();
        let old_addr = "epix1oldaddress";
        let state = AppState::with_data_dir("test", root.path());
        let site_dir = root.path().join("data").join(old_addr);
        std::fs::create_dir_all(&site_dir).unwrap();
        state
            .add_xite(old_addr, XiteEntry {
                storage: XiteStorage::new(&site_dir),
                content: Some(json!({ "address": old_addr, "files": {} })),
            })
            .await;
        state.set_display(old_addr, "dashboard.epix").await;
        std::fs::write(
            root.path().join("resolve-cache.json"),
            serde_json::to_vec(&json!({
                "dashboard.epix": { "address": old_addr, "resolved_at": 4102444800u64 }
            }))
            .unwrap(),
        )
        .unwrap();
        // Both stale sources answer before the clear.
        assert_eq!(state.resolve_name("dashboard.epix").await.as_deref(), Some(old_addr));
        assert_eq!(state.canonical_key("dashboard.epix").await, old_addr);

        state.xid_clear_cache().await;

        // The name no longer maps anywhere: the next visit must resolve on
        // chain. The xite itself stays registered under its address.
        assert_eq!(state.resolve_name("dashboard.epix").await, None);
        assert_eq!(state.canonical_key("dashboard.epix").await, "dashboard.epix");
        assert!(state.has_xite(old_addr).await);
        assert!(!root.path().join("resolve-cache.json").exists());
        // The cleared binding is persisted, so it stays gone after a restart.
        let sites: serde_json::Map<String, Value> =
            std::fs::read(root.path().join("private/sites.json"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
        let entry = sites.get(old_addr).expect("xite still recorded");
        assert!(entry.get("display").is_none(), "display binding must not persist");
    }

    #[tokio::test]
    async fn delete_drops_user_site_data() {
        // EpixNet parity: siteDelete also forgets the site's per-user data
        // (derived auth identity, feed follows), like `user.deleteSiteData`.
        let root = tempdir().unwrap();
        let addr = "1ForgetMe";
        let state = AppState::with_data_dir("test", root.path());
        let site_dir = root.path().join("data").join(addr);
        std::fs::create_dir_all(&site_dir).unwrap();
        state
            .add_xite(addr, XiteEntry {
                storage: XiteStorage::new(&site_dir),
                content: Some(json!({ "address": addr, "files": {} })),
            })
            .await;

        // Touch the site (siteInfo derives the auth identity) and follow a feed.
        state.site_info(addr).await;
        state.set_feed_follow(addr, json!({ "posts": ["q", []] })).await;
        assert!(state.user.read().await.sites.contains_key(addr));
        assert!(state.user.read().await.follows.contains_key(addr));

        assert!(state.remove_xite(addr).await);
        assert!(!state.user.read().await.sites.contains_key(addr));
        assert!(!state.user.read().await.follows.contains_key(addr));
    }

    #[tokio::test]
    async fn file_write_then_site_sign_produces_owned_signed_content() {
        // A key that owns the xite (address == the xite address).
        let owner = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let owner_addr = epix_crypt::privatekey_to_address(owner).unwrap();

        let dir = tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite(&owner_addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;

        // Write a file, then sign.
        state.write_file(&owner_addr, "index.html", b"<h1>hi</h1>").await.unwrap();
        let bytes = state.sign_xite(&owner_addr, owner).await.unwrap();

        // The written content.json is signed by the owner and lists the file.
        let content: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(content["signs"].get(&owner_addr).is_some(), "signed by owner");
        assert_eq!(content["files"]["index.html"]["size"], 11);
        assert!(content["modified"].as_f64().unwrap() > 0.0);

        // siteInfo now reflects ownership + the real file count.
        let info = state.site_info(&owner_addr).await;
        assert_eq!(info["settings"]["own"], true);
        assert_eq!(info["content"]["files"], 1);

        // A non-owner key is refused.
        let other = "22c824485fe256587c3809b5f7c99864d7339e9fba061a016834cecc454e01f8";
        assert!(state.sign_xite(&owner_addr, other).await.is_err());
    }

    #[tokio::test]
    async fn editing_title_via_content_json_survives_signing() {
        // The sidebar "Save site settings" flow: fileWrite content.json with a
        // new title, then siteSign. The title must survive - signing used to
        // re-sign the stale in-memory content and revert the edit on disk.
        let owner = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let owner_addr = epix_crypt::privatekey_to_address(owner).unwrap();
        let dir = tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite(
                &owner_addr,
                XiteEntry {
                    storage: XiteStorage::new(dir.path()),
                    content: Some(json!({ "title": "Old title", "files": {} })),
                },
            )
            .await;

        // Edit the title + description via a content.json write (unsigned).
        let edited = json!({
            "title": "New title", "description": "New description", "files": {}
        });
        state
            .write_file(&owner_addr, "content.json", serde_json::to_vec(&edited).unwrap().as_slice())
            .await
            .unwrap();

        // The edit is visible immediately (siteInfo renders from memory, which
        // the write now refreshes) - not just on disk.
        let info = state.site_info(&owner_addr).await;
        assert_eq!(info["content"]["title"], "New title", "edit visible before signing");
        assert_eq!(info["content"]["description"], "New description");

        // Signing preserves the edit rather than reverting to the old title.
        let bytes = state.sign_xite(&owner_addr, owner).await.unwrap();
        let signed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(signed["title"], "New title", "title survives signing");
        assert_eq!(signed["description"], "New description");
        assert!(signed["signs"].get(&owner_addr).is_some(), "signed by owner");

        // And it's what serves + persists on disk.
        assert_eq!(state.site_info(&owner_addr).await["content"]["title"], "New title");
        let on_disk: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("content.json")).unwrap())
                .unwrap();
        assert_eq!(on_disk["title"], "New title");
    }

    #[tokio::test]
    async fn file_rules_reports_user_max_size_and_current_size() {
        // The forum's used/total gauge: fileRules on a user content.json must
        // return the per-user max_size (from user_contents.permission_rules)
        // and the current_size (content.json bytes + declared files), or the
        // bar stays empty (setCurrentSize(undefined)).
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let addr = "epix1talk58lw26c0cyrtuu8axptne2p6zf33s7xxwu";

        // Root delegates data/users/content.json.
        storage
            .write(
                "content.json",
                serde_json::to_vec(&json!({
                    "address": addr, "modified": 1, "files": {},
                    "includes": { "data/users/content.json": {} },
                }))
                .unwrap()
                .as_slice(),
            )
            .unwrap();
        // The user_contents parent with EpixTalk's per-user rule.
        storage
            .write(
                "data/users/content.json",
                serde_json::to_vec(&json!({
                    "address": addr, "inner_path": "data/users/content.json", "modified": 1,
                    "files": {},
                    "user_contents": {
                        "cert_signers": {}, "permissions": {},
                        "permission_rules": { ".*": { "files_allowed": "data.json", "max_size": 200000 } },
                    },
                }))
                .unwrap()
                .as_slice(),
            )
            .unwrap();
        // A user with a data.json of 500 bytes declared in their content.json.
        let user_content = json!({
            "address": addr, "inner_path": "data/users/1USER/content.json", "modified": 1,
            "files": { "data.json": { "size": 500, "sha512": "aa" } },
        });
        let user_bytes = serde_json::to_vec(&user_content).unwrap();
        storage.write("data/users/1USER/content.json", &user_bytes).unwrap();

        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: None }).await;

        let rules = state.file_rules(addr, "data/users/1USER/content.json").await;
        assert_eq!(rules["max_size"], 200000, "real per-user max_size, not the 10MB stub");
        assert_eq!(
            rules["current_size"],
            user_bytes.len() as i64 + 500,
            "content.json bytes + declared file sizes"
        );
        // The gauge would now render used/total instead of staying empty.
        assert!(rules["current_size"].as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn optional_file_lifecycle() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let data = b"an optional file's contents";
        let content = json!({
            "files": {},
            "files_optional": { "big.mp4": { "size": data.len(), "sha512": XiteStorage::hash_bytes(data) } },
        });
        let addr =
            &epix_crypt::privatekey_to_address("11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7").unwrap();
        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: Some(content) }).await;

        // Declared but not downloaded.
        let all = state.optional_file_list(addr, "all").await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0]["is_downloaded"], false);
        assert!(state.optional_file_list(addr, "downloaded").await.unwrap().is_empty());

        // "Download" it (write matching bytes); now it counts as downloaded, and
        // fileNeed returns true without touching the network.
        state.write_file(addr, "big.mp4", data).await.unwrap();
        assert!(state.file_need(addr, "big.mp4").await.unwrap());
        let info = state.optional_file_info(addr, "big.mp4").await.unwrap();
        assert_eq!(info["is_downloaded"], true);
        assert_eq!(info["size"], data.len());

        // Pin, then delete.
        state.set_pin(addr, "big.mp4", true).await;
        assert_eq!(state.optional_file_info(addr, "big.mp4").await.unwrap()["is_pinned"], true);
        state.optional_file_delete(addr, "big.mp4").await.unwrap();
        assert_eq!(state.optional_file_info(addr, "big.mp4").await.unwrap()["is_downloaded"], false);

        let stats = state.optional_limit_stats().await;
        assert!(stats["used"].is_number() && stats["free"].is_number());
        assert_eq!(stats["limit"], "10%");
    }

    #[tokio::test]
    async fn server_errors_returns_only_error_level() {
        let state = AppState::new("test");
        state.log("INFO", "started").await;
        state.log("WARNING", "slow peer").await;
        state.log("ERROR", "sync failed").await;
        // serverErrors is ERROR-only, so the warning badge ignores routine logs.
        let errors = state.server_errors().await;
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0][1], "ERROR");
        assert_eq!(errors[0][2], "sync failed");
        assert!(errors[0][0].as_f64().unwrap() > 0.0);
        // The sidebar console still sees all three levels.
        assert_eq!(state.console_log_read("").await["num_found"], 3);
    }

    #[tokio::test]
    async fn console_stream_returns_id_and_pushes_loglineadd() {
        let state = AppState::new("test");
        // Opening a stream returns a real id (was null before -> UI crash).
        let sid = state.console_log_stream_open("").await;
        let mut events = state.subscribe_events();

        // A new log line streams as logLineAdd with the matching stream_id.
        state.log("INFO", "hello world").await;
        let ev = events.try_recv().unwrap();
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "logLineAdd");
        assert_eq!(payload["params"]["stream_id"], sid);
        let line = payload["params"]["lines"][0].as_str().unwrap();
        assert!(line.contains("INFO Node hello world"));
        assert!(line.starts_with('['));

        // consoleLogRead returns the formatted line too.
        let read = state.console_log_read("").await;
        assert_eq!(read["num_found"], 1);
        assert!(read["lines"][0].as_str().unwrap().contains("hello world"));

        // After removing the stream, no more logLineAdd is pushed.
        state.console_log_stream_remove(sid).await;
        while events.try_recv().is_ok() {}
        state.log("INFO", "after removal").await;
        assert!(events.try_recv().is_err());
    }

    #[tokio::test]
    async fn notification_subscribe_list_and_mute() {
        let state = AppState::new("test");
        state.notification_subscribe("1Chat", json!({ "unread": ["SELECT * FROM message WHERE seen=0", null] })).await;
        assert_eq!(state.notification_list("1Chat").await["unread"][0], "SELECT * FROM message WHERE seen=0");
        assert_eq!(state.notification_list("1Other").await, json!({}));

        // Global mute reflected in status + query.
        state.notification_mute(true, None).await;
        assert_eq!(state.notification_mute_status().await["global_muted"], true);
        assert_eq!(state.notification_query().await["muted"], true);

        // Per-site mute.
        state.notification_mute(false, None).await;
        state.notification_mute(true, Some("1Chat")).await;
        assert_eq!(state.notification_mute_status().await["site_mutes"]["1Chat"], true);
    }

    #[tokio::test]
    async fn filepack_reads_from_tar_gz() {
        // Build a small .tar.gz containing dir/hello.txt.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        {
            let mut tar = tar::Builder::new(&mut gz);
            let data = b"hi from the pack";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, "dir/hello.txt", &data[..]).unwrap();
            tar.finish().unwrap();
        }
        let archive = gz.finish().unwrap();

        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage.write("pack.tar.gz", &archive).unwrap();
        let state = AppState::new("test");
        state.add_xite("1Pack", XiteEntry { storage, content: None }).await;

        let out = state.read_file("1Pack", "pack.tar.gz/dir/hello.txt").await;
        assert_eq!(out.as_deref(), Some(&b"hi from the pack"[..]));
        // A missing entry is None, not an error.
        assert!(state.read_file("1Pack", "pack.tar.gz/nope.txt").await.is_none());
    }

    #[tokio::test]
    async fn data_dir_uses_the_python_epixnet_layout() {
        // Upgrading from the Python client needs no migration: the identity
        // is read from private/users.json and xites from data/<address>,
        // exactly where EpixNet keeps them.
        let dir = tempdir().unwrap();
        let master = {
            let s = AppState::with_data_dir("test", dir.path());
            let master = s.user.read().await.master_address.clone();
            master
        };
        assert!(dir.path().join("private/users.json").exists());
        assert!(!dir.path().join("users.json").exists(), "no node files at the root");
        // A fresh node over the same root loads the same identity.
        let s = AppState::with_data_dir("test", dir.path());
        assert_eq!(s.user.read().await.master_address, master);
        assert_eq!(s.xite_dir("epix1xite").unwrap(), dir.path().join("data/epix1xite"));
    }

    #[tokio::test]
    async fn user_content_signs_with_the_users_auth_key() {
        // The EpixTalk topic flow: fileWrite the data file, then siteSign /
        // sitePublish with its inner_path - the node maps it to the user's own
        // content.json, hashes the dir, and signs as the user. A classic
        // auth-address-named user dir needs no chain resolution.
        let root = tempdir().unwrap();
        let site = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let state = AppState::with_data_dir("test", root.path());
        let storage = XiteStorage::new(root.path().join("data").join(&site));
        let users_content = json!({
            "address": site,
            "inner_path": "data/users/content.json",
            "user_contents": { "permissions": {}, "cert_signers": {} }
        });
        storage
            .write("data/users/content.json", &serde_json::to_vec(&users_content).unwrap())
            .unwrap();
        state
            .add_xite(&site, XiteEntry {
                storage: storage.clone(),
                content: Some(json!({ "address": site, "files": {} })),
            })
            .await;

        let auth = state.user.write().await.auth_address(&site).unwrap();
        let dir = format!("data/users/{auth}");
        let data_path = format!("{dir}/data.json");
        state.write_file(&site, &data_path, br#"{"topic":[{"topic_id":1}]}"#).await.unwrap();

        // The data file maps to the governing (user's own) content.json.
        let content_path = state.content_inner_path(&site, &data_path).await;
        assert_eq!(content_path, format!("{dir}/content.json"));

        state.sign_user_content(&site, &content_path, None, None).await.unwrap();
        let signed: Value =
            serde_json::from_slice(&storage.read(&content_path).unwrap()).unwrap();
        assert!(signed["signs"][&auth].is_string(), "signed by the user's auth key: {signed}");
        assert!(signed["files"]["data.json"]["sha512"].is_string(), "data.json hashed");
        assert_eq!(signed["inner_path"], json!(content_path));
        assert_eq!(signed["address"], json!(site));

        // Re-signing after an edit bumps modified and re-verifies.
        let first = signed["modified"].as_f64().unwrap();
        state.write_file(&site, &data_path, br#"{"topic":[{"topic_id":1},{"topic_id":2}]}"#).await.unwrap();
        state.sign_user_content(&site, &content_path, None, None).await.unwrap();
        let resigned: Value =
            serde_json::from_slice(&storage.read(&content_path).unwrap()).unwrap();
        assert!(resigned["modified"].as_f64().unwrap() > first);
    }

    #[tokio::test]
    async fn merged_site_signing_uses_the_globally_selected_cert() {
        // Python MergerSite copied the merger site's cert onto the merged site
        // on every write because python certs were per-site. Rust certs are
        // global: a site entry derived after certSelect auto-attaches the
        // active cert, so a merged site first touched through a merger path
        // signs as the cert identity with no copy step. This pins that down
        // against a hub whose user_contents actually demands the cert.
        let root = tempdir().unwrap();
        let state = AppState::with_data_dir("test", root.path());

        // A provider issues a cert for the identity the user derived on the
        // provider's own site, and the user selects it globally.
        let issuer_key = epix_crypt::new_seed();
        let issuer = epix_crypt::privatekey_to_address(&issuer_key).unwrap();
        let cert_auth = {
            let mut user = state.user.write().await;
            let cert_auth = user.site_data("epix1certprovider").unwrap().auth_address.clone();
            let cert_sign =
                epix_crypt::sign(&format!("{cert_auth}#web/tester"), &issuer_key).unwrap();
            user.add_cert(&cert_auth, "certs.epix", "web", "tester", &cert_sign).unwrap();
            user.set_cert_global(Some("certs.epix"));
            // A brand-new entry derived after the selection carries the cert.
            assert_eq!(user.site_data("epix1fresh").unwrap().cert.as_deref(), Some("certs.epix"));
            cert_auth
        };

        // A merger site and a hub whose user dirs require a certs.epix cert.
        let hub = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let storage = XiteStorage::new(root.path().join("data").join(&hub));
        storage
            .write(
                "data/users/content.json",
                &serde_json::to_vec(&json!({
                    "address": hub,
                    "inner_path": "data/users/content.json",
                    "user_contents": {
                        "permissions": {},
                        "cert_signers": { "certs.epix": [issuer] },
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        state
            .add_xite(&hub, XiteEntry {
                storage: storage.clone(),
                content: Some(json!({ "address": hub, "merged_type": "PostHub", "files": {} })),
            })
            .await;
        state
            .add_xite("epix1merger", XiteEntry {
                storage: XiteStorage::new(root.path().join("data/epix1merger")),
                content: Some(json!({ "address": "epix1merger", "files": {} })),
            })
            .await;
        state.add_permission("epix1merger", "Merger:PostHub").await;

        // First touch of the merged site: it reports the cert's auth address,
        // so the user dir the merger's xite writes into is the cert identity's.
        let auth = state.user.write().await.auth_address(&hub).unwrap();
        assert_eq!(auth, cert_auth, "the global cert reached the merged site");

        let merged_path = format!("merged-PostHub/{hub}/data/users/{auth}/data.json");
        let (target, inner) =
            state.resolve_merged("epix1merger", &merged_path).await.unwrap().unwrap();
        assert_eq!(target, hub);
        state.write_file(&target, &inner, br#"{"post":[{"post_id":1}]}"#).await.unwrap();
        let content_path = state.content_inner_path(&target, &inner).await;
        assert_eq!(content_path, format!("data/users/{auth}/content.json"));

        // The rule really bites: signing with the bare key (no cert fields
        // attached) is refused by the hub's cert_signers.
        let bare_key = state.user.read().await.get_cert(&hub).unwrap().auth_privatekey.clone();
        let err = state
            .sign_user_content(&target, &content_path, Some(bare_key), None)
            .await
            .unwrap_err();
        assert!(err.contains("cert"), "refused for the missing cert: {err}");

        // Signing as the user attaches and verifies the cert.
        state.sign_user_content(&target, &content_path, None, None).await.unwrap();
        let signed: Value =
            serde_json::from_slice(&storage.read(&content_path).unwrap()).unwrap();
        assert_eq!(signed["cert_user_id"], json!("tester@certs.epix"));
        assert_eq!(signed["cert_auth_type"], json!("web"));
        assert!(signed["signs"][&cert_auth].is_string(), "signed as the cert identity: {signed}");
        assert!(signed["files"]["data.json"]["sha512"].is_string(), "data.json hashed");
    }

    #[tokio::test]
    async fn publish_diffs_come_from_old_snapshots() {
        // fileWrite keeps a `-old` snapshot of a data file; take_diffs turns it
        // into the patch an update push carries (so peers that can't connect
        // back still get the change) and drops the snapshot; signing never
        // hashes snapshots into content.json.
        let root = tempdir().unwrap();
        let site = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let state = AppState::with_data_dir("test", root.path());
        let storage = XiteStorage::new(root.path().join("data").join(&site));
        storage
            .write(
                "data/users/content.json",
                &serde_json::to_vec(&json!({
                    "address": site,
                    "inner_path": "data/users/content.json",
                    "user_contents": { "permissions": {}, "cert_signers": {} }
                }))
                .unwrap(),
            )
            .unwrap();
        state
            .add_xite(&site, XiteEntry {
                storage: storage.clone(),
                content: Some(json!({ "address": site, "files": {} })),
            })
            .await;

        let auth = state.user.write().await.auth_address(&site).unwrap();
        let dir = format!("data/users/{auth}");
        let data_path = format!("{dir}/data.json");
        let content_path = format!("{dir}/content.json");
        let v1 = br#"{"topic":[]}"#.to_vec();
        let v2 = br#"{"topic":[{"topic_id":1,"title":"hello"}]}"#.to_vec();

        state.write_file(&site, &data_path, &v1).await.unwrap();
        state.sign_user_content(&site, &content_path, None, None).await.unwrap();
        // No previous file, so nothing to diff on the first publish.
        assert!(state.take_diffs(&site, &content_path).await.is_empty());

        state.write_file(&site, &data_path, &v2).await.unwrap();
        assert!(storage.exists(&format!("{data_path}-old")), "snapshot kept");
        state.sign_user_content(&site, &content_path, None, None).await.unwrap();
        let signed: Value =
            serde_json::from_slice(&storage.read(&content_path).unwrap()).unwrap();
        assert!(signed["files"]["data.json-old"].is_null(), "snapshot never hashed: {signed}");

        let diffs = state.take_diffs(&site, &content_path).await;
        let actions = diffs.get("data.json").expect("diff for the changed file");
        // The diff reconstructs the new file from what peers hold (v1).
        assert_eq!(epix_content::patch(&v1, actions).unwrap(), v2);
        // The snapshot is consumed with the publish.
        assert!(!storage.exists(&format!("{data_path}-old")));
        assert!(state.take_diffs(&site, &content_path).await.is_empty());
    }

    #[tokio::test]
    async fn set_data_dir_copies_data_and_persists_to_conf() {
        let old = tempdir().unwrap();
        let new = tempdir().unwrap();
        let conf_dir = tempdir().unwrap();
        let conf = conf_dir.path().join("epixnet.conf");
        let s = AppState::with_data_dir("test", old.path());
        // Not relocatable until the server marks the root as such.
        assert!(s.set_data_dir("/anywhere").await.is_err());
        s.set_data_dir_conf(&conf);

        // Relative and nested targets are refused.
        assert!(s.set_data_dir("relative/path").await.is_err());
        assert!(s.set_data_dir(old.path().join("inside").to_str().unwrap()).await.is_err());

        let target = new.path().join("EpixData");
        s.set_data_dir(target.to_str().unwrap()).await.unwrap();
        // The identity was copied and the choice recorded Python-style.
        assert!(target.join("private/users.json").exists());
        assert_eq!(crate::paths::read_conf_data_dir(&conf), Some(target.clone()));
        // The old root stays in place as a backup.
        assert!(old.path().join("private/users.json").exists());
    }

    #[tokio::test]
    async fn restart_pending_tracks_boot_snapshot() {
        let dir = tempdir().unwrap();
        let s = AppState::with_data_dir("test", dir.path());
        // No snapshot yet (test nodes don't boot): nothing pends.
        s.config_set("fileserver_port", json!("26000")).await;
        assert!(s.restart_pending_keys().await.is_empty());

        s.snapshot_boot_config().await;
        assert!(s.restart_pending_keys().await.is_empty());

        // A restart-only key drifting from the boot value pends...
        s.config_set("fileserver_port", json!("26001")).await;
        assert_eq!(s.restart_pending_keys().await, vec!["fileserver_port".to_string()]);
        // ...a live key does not...
        s.config_set("language", json!("de")).await;
        assert_eq!(s.restart_pending_keys().await, vec!["fileserver_port".to_string()]);
        // ...and changing it back clears the pending state.
        s.config_set("fileserver_port", json!("26000")).await;
        assert!(s.restart_pending_keys().await.is_empty());

        // Bool/number forms normalize: the Python client wrote real JSON
        // types where the Config page saves strings.
        s.config_set("offline", json!(false)).await;
        s.snapshot_boot_config().await;
        s.config_set("offline", json!("false")).await;
        assert!(s.restart_pending_keys().await.is_empty());
        s.config_set("offline", json!("true")).await;
        assert_eq!(s.restart_pending_keys().await, vec!["offline".to_string()]);

        // configList reports the same key as pending.
        let list = s.config_list().await;
        assert_eq!(list["offline"]["pending"], true);
        assert_eq!(list["language"]["pending"], false);
    }

    #[tokio::test]
    async fn restart_pending_includes_staged_data_dir() {
        let dir = tempdir().unwrap();
        let target = tempdir().unwrap();
        let conf = dir.path().join("epixnet.conf");
        // The conf names the root this node runs on (as after a normal boot).
        crate::paths::write_conf_data_dir(&conf, Some(dir.path())).unwrap();
        let s = AppState::with_data_dir("test", dir.path());
        s.set_data_dir_conf(&conf);
        s.snapshot_boot_config().await;
        assert!(s.restart_pending_keys().await.is_empty());

        // Staging a move in epixnet.conf pends data_dir until the next start.
        let target = target.path().join("new-root");
        s.set_data_dir(target.to_str().unwrap()).await.unwrap();
        assert_eq!(s.restart_pending_keys().await, vec!["data_dir".to_string()]);
    }

    #[tokio::test]
    async fn peers_persist_across_restart() {
        let dir = tempdir().unwrap();
        let content = json!({ "address": "1Site", "files": {} });
        {
            let s = AppState::with_data_dir("test", dir.path());
            s.add_xite("1Site", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content.clone()) }).await;
            s.add_peers("1Site", vec![
                PeerAddr::parse("1.2.3.4:15441").unwrap(),
                PeerAddr::parse("5.6.7.8:15441").unwrap(),
            ]).await;
            s.persist_peers().await;
        }
        // A fresh node over the same data dir restores the peers on add_xite.
        let s = AppState::with_data_dir("test", dir.path());
        s.add_xite("1Site", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content) }).await;
        assert_eq!(s.peer_counts("1Site").await.total, 2);
    }

    #[tokio::test]
    async fn optional_pins_persist_across_restart() {
        let dir = tempdir().unwrap();
        let addr = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        let content = json!({
            "address": addr,
            "files_optional": { "big.bin": { "size": 10, "sha512": "ab" } },
        });
        {
            let s = AppState::with_data_dir("test", dir.path());
            s.add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content.clone()) }).await;
            s.set_pin(addr, "big.bin", true).await;
        }
        // A fresh node over the same dir restores the pin.
        let s = AppState::with_data_dir("test", dir.path());
        s.add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content) }).await;
        let list = s.optional_file_list(addr, "all").await.unwrap();
        let entry = list.iter().find(|e| e["inner_path"] == "big.bin").expect("optional file listed");
        assert_eq!(entry["is_pinned"], true, "pin survived the restart");
    }

    #[cfg(feature = "multiuser")]
    #[tokio::test]
    async fn multiuser_login_switch_and_persist() {
        let dir = tempdir().unwrap();
        // A second identity from a known seed.
        let seed = "5f5e100000000000000000000000000000000000000000000000000000000001";
        let (primary, alt) = {
            let s = AppState::with_data_dir("test", dir.path());
            let primary = s.multiuser_current_seed().await;
            let alt = s.multiuser_login(seed).await.unwrap();
            // Active identity is now the alt one; both are listed.
            assert_eq!(s.multiuser_current_seed().await, seed);
            assert!(s.multiuser_list().await.contains(&alt));
            assert_eq!(s.multiuser_list().await.len(), 2);
            (primary, alt)
        };
        // A fresh node over the same dir remembers both; switching works.
        let s = AppState::with_data_dir("test", dir.path());
        assert!(s.multiuser_list().await.contains(&alt));
        s.multiuser_select(&alt).await.unwrap();
        assert_eq!(s.multiuser_current_seed().await, seed);
        // Logout reverts to the primary identity.
        s.multiuser_logout().await.unwrap();
        assert_eq!(s.multiuser_current_seed().await, primary);
        // Selecting an unknown user errors.
        assert!(s.multiuser_select("epix1nope").await.is_err());
    }

    #[tokio::test]
    async fn default_disabled_plugins_start_off_and_toggle() {
        let state = AppState::new("test");
        state
            .set_plugins(vec![
                "Sidebar".into(),
                "NoNewSites".into(),
                "UiPassword".into(),
                "Multiuser".into(),
            ])
            .await;
        // Default-on plugin is on; the EpixNet-disabled set starts off.
        assert!(state.plugin_enabled("Sidebar").await);
        assert!(!state.plugin_enabled("NoNewSites").await);
        assert!(!state.plugin_enabled("UiPassword").await);
        assert!(!state.plugin_enabled("Multiuser").await);

        // Turning a default-disabled plugin on, and a default-on plugin off.
        state.set_plugin_enabled("NoNewSites", true).await;
        state.set_plugin_enabled("Sidebar", false).await;
        assert!(state.plugin_enabled("NoNewSites").await);
        assert!(!state.plugin_enabled("Sidebar").await);

        let states: std::collections::HashMap<_, _> =
            state.plugin_states().await.into_iter().map(|(n, en, _def)| (n, en)).collect();
        assert_eq!(states["NoNewSites"], true);
        assert_eq!(states["Multiuser"], false);
        assert_eq!(states["Sidebar"], false);
        // The reported default is on for Sidebar, off for the disabled-by-default set.
        let defaults: std::collections::HashMap<_, _> =
            state.plugin_states().await.into_iter().map(|(n, _en, def)| (n, def)).collect();
        assert_eq!(defaults["Sidebar"], true);
        assert_eq!(defaults["NoNewSites"], false);
        assert_eq!(defaults["UiPassword"], false);
        // serverInfo.plugins excludes the disabled ones.
        let live = state.plugins().await;
        assert!(live.contains(&"NoNewSites".to_string()));
        assert!(!live.contains(&"Sidebar".to_string()));
        assert!(!live.contains(&"Multiuser".to_string()));
    }

    #[tokio::test]
    async fn plugins_enable_disable_persists_and_hides() {
        let dir = tempdir().unwrap();
        {
            let s = AppState::with_data_dir("test", dir.path());
            s.set_plugins(vec!["Sidebar".into(), "Stats".into()]).await;
            // All enabled by default.
            assert!(s.plugin_enabled("Sidebar").await);
            assert_eq!(s.plugins().await, vec!["Sidebar", "Stats"]);

            // Disabling hides it from serverInfo.plugins immediately (no restart).
            s.set_plugin_enabled("Sidebar", false).await;
            assert!(!s.plugin_enabled("Sidebar").await);
            assert_eq!(s.plugins().await, vec!["Stats".to_string()]);
            assert_eq!(
                s.plugin_states().await,
                vec![
                    ("Sidebar".to_string(), false, true),
                    ("Stats".to_string(), true, true)
                ]
            );
        }
        // The disabled state persists across a restart (config.json).
        let s = AppState::with_data_dir("test", dir.path());
        s.set_plugins(vec!["Sidebar".into(), "Stats".into()]).await;
        assert!(!s.plugin_enabled("Sidebar").await);
        // Re-enable.
        s.set_plugin_enabled("Sidebar", true).await;
        assert!(s.plugin_enabled("Sidebar").await);
    }

    #[tokio::test]
    async fn pushed_events_route_by_target() {
        let dir = tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1site", XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(json!({ "address": "1site", "files": {} })) })
            .await;
        let mut rx = state.subscribe_events();

        // A site event is on the siteChanged channel, targeted at that address.
        state.push_site_info("1site").await;
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.channel.as_deref(), Some("siteChanged"));
        assert_eq!(ev.target.as_deref(), Some("1site"));
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "setSiteInfo");
        assert_eq!(payload["params"]["address"], "1site");

        // A notification is ungated + global (no channel, no target).
        state.push_notification("done", "hi", 1000);
        let ev = rx.try_recv().unwrap();
        assert!(ev.channel.is_none() && ev.target.is_none());
        assert_eq!(serde_json::from_str::<Value>(&ev.payload).unwrap()["cmd"], "notification");
    }

    #[tokio::test]
    async fn peer_locations_empty_without_geoip_db() {
        // No geolocation db loaded → the world map query returns [] rather than
        // erroring, so the Stats page renders an empty map.
        let dir = tempdir().unwrap();
        let state = AppState::new("test");
        state.add_xite("1x", XiteEntry { storage: XiteStorage::new(dir.path()), content: None }).await;
        assert!(state.peer_locations().await.is_empty());
    }

    #[tokio::test]
    async fn optional_limit_persists_and_computes_bytes() {
        let dir = tempdir().unwrap();
        {
            let s = AppState::with_data_dir("test", dir.path());
            assert_eq!(s.optional_limit_stats().await["limit"], "10%");
            // A percentage cap is a fraction of real free disk space (non-zero).
            assert!(s.optional_limit_bytes().await > 0);
            s.set_optional_limit("5").await; // 5 GB
            assert_eq!(s.optional_limit_bytes().await, 5 * 1024 * 1024 * 1024);
        }
        // The new cap is restored on restart.
        let s = AppState::with_data_dir("test", dir.path());
        assert_eq!(s.optional_limit_stats().await["limit"], "5");
    }

    #[tokio::test]
    async fn bigfile_info_and_range_read() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let big = vec![7u8; 2 * 1024 * 1024 + 5]; // just over 2 MB
        let content = json!({
            "files": {},
            "files_optional": { "movie.mp4": {
                "size": big.len(), "sha512": XiteStorage::hash_bytes(&big),
                "piecemap": "movie.mp4.piecemap.msgpack", "piece_size": 1024 * 1024,
            } },
        });
        let addr =
            &epix_crypt::privatekey_to_address("11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7").unwrap();
        let state = AppState::new("test");
        state.add_xite(addr, XiteEntry { storage, content: Some(content) }).await;
        state.write_file(addr, "movie.mp4", &big).await.unwrap();

        // optionalFileInfo carries the Bigfile piece layout.
        let info = state.optional_file_info(addr, "movie.mp4").await.unwrap();
        assert_eq!(info["is_bigfile"], true);
        assert_eq!(info["piece_size"], 1024 * 1024);
        assert_eq!(info["piece_num"], 3); // ceil((2MB+5)/1MB)
        assert_eq!(info["piecemap"], "movie.mp4.piecemap.msgpack");

        // Range read returns exactly the requested window from the right offset.
        let chunk = state.read_file_range(addr, "movie.mp4", 1024 * 1024, 128).await.unwrap();
        assert_eq!(chunk.len(), 128);
        assert!(chunk.iter().all(|&b| b == 7));

        // A small optional file is not a bigfile.
        let small = json!({ "files_optional": { "a.txt": { "size": 10, "sha512": "x" } } });
        state.add_xite("small", XiteEntry { storage: XiteStorage::new(dir.path().join("s")), content: Some(small) }).await;
    }

    #[tokio::test]
    async fn v3_merger_db_aggregates_merged_sites() {
        let dir = tempdir().unwrap();
        let state = AppState::new("test");

        // A merger site: version-3 schema + Merger:ZeroMe permission, no own data.
        let merger = "1Merger";
        let mstore = XiteStorage::new(dir.path().join("merger"));
        mstore
            .write(
                "dbschema.json",
                // A real merger schema keys merged files under the merged
                // site's address (EpixNet nests them at merged-<type>/<addr>/),
                // so the map's leading `.+/` matches that address segment.
                br#"{ "db_name":"Merger","db_file":"db.db","version":3,
                     "maps": { ".+/data/.*/data.json": { "to_table": [{"node":"posts","table":"post"}] } },
                     "tables": { "post": { "cols": [["post_id","INTEGER"],["title","TEXT"],["json_id","INTEGER"]] } } }"#,
            )
            .unwrap();
        state.add_xite(merger, XiteEntry { storage: mstore, content: None }).await;
        state.add_permission(merger, "Merger:ZeroMe").await;

        // Two merged sites of that type, each with a post.
        for (addr, title) in [("1SiteA", "from A"), ("1SiteB", "from B")] {
            let s = XiteStorage::new(dir.path().join(addr));
            s.write(
                "data/u/data.json",
                format!(r#"{{ "posts": [ {{"post_id":1,"title":"{title}"}} ] }}"#).as_bytes(),
            )
            .unwrap();
            state
                .add_xite(addr, XiteEntry { storage: s, content: Some(json!({ "merged_type": "ZeroMe" })) })
                .await;
        }

        state.rebuild_merger_dbs().await;

        // One query over the merger db returns rows from BOTH sites, tagged with
        // their site via the json table (the point of a version-3 merger db).
        let rows = state
            .db_query(
                merger,
                "SELECT json.site AS site, post.title AS title FROM post LEFT JOIN json USING (json_id) ORDER BY json.site",
                &Value::Null,
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["site"], "1SiteA");
        assert_eq!(rows[0]["title"], "from A");
        assert_eq!(rows[1]["site"], "1SiteB");
    }

    #[tokio::test]
    async fn identity_persists_across_restart() {
        let dir = tempdir().unwrap();
        let addr = "talk.epix";
        let a1 = {
            let s = AppState::with_data_dir("test", dir.path());
            s.add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None }).await;
            s.site_info(addr).await["auth_address"].as_str().unwrap().to_string()
        };
        // A fresh node over the same data dir derives the same identity.
        let a2 = {
            let s = AppState::with_data_dir("test", dir.path());
            s.add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None }).await;
            s.site_info(addr).await["auth_address"].as_str().unwrap().to_string()
        };
        assert_eq!(a1, a2, "auth address is stable across restarts");
    }

    #[tokio::test]
    async fn granted_permission_persists_across_restart() {
        let dir = tempdir().unwrap();
        let addr = "dashboard.epix";
        {
            let s = AppState::with_data_dir("test", dir.path());
            s.add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None }).await;
            assert!(!s.site_has_admin(addr).await, "no permission before a grant");
            s.add_permission(addr, "ADMIN").await;
            assert!(s.site_has_admin(addr).await);
        }
        // A fresh node over the same data dir restores the grant.
        let s = AppState::with_data_dir("test", dir.path());
        s.add_xite(addr, XiteEntry { storage: XiteStorage::new(dir.path()), content: None }).await;
        assert!(s.site_has_admin(addr).await, "ADMIN grant survives restart");
        // A xite that was never granted anything stays unprivileged.
        s.add_xite("other.epix", XiteEntry { storage: XiteStorage::new(dir.path()), content: None }).await;
        assert!(!s.site_has_admin("other.epix").await);
    }

    #[tokio::test]
    async fn grant_is_shared_across_a_sites_aliases() {
        let dir = tempdir().unwrap();
        let content = json!({ "address": "epix1dash", "files": {}, "signs": {"epix1dash": "x"} });
        let store = || XiteStorage::new(dir.path());

        // First run: same site served under a raw address and a .epix alias.
        {
            let s = AppState::with_data_dir("test", dir.path());
            s.add_xite("epix1dash", XiteEntry { storage: store(), content: Some(content.clone()) }).await;
            s.add_xite("dashboard.epix", XiteEntry { storage: store(), content: Some(content.clone()) }).await;
            // Granting via the alias grants the raw address too.
            s.add_permission("dashboard.epix", "ADMIN").await;
            assert!(s.site_has_admin("dashboard.epix").await);
            assert!(s.site_has_admin("epix1dash").await, "grant applies to the raw alias");
        }
        // Second run: the grant is restored for both aliases from the single
        // canonical entry in permissions.json.
        let s = AppState::with_data_dir("test", dir.path());
        s.add_xite("epix1dash", XiteEntry { storage: store(), content: Some(content.clone()) }).await;
        s.add_xite("dashboard.epix", XiteEntry { storage: store(), content: Some(content) }).await;
        assert!(s.site_has_admin("epix1dash").await);
        assert!(s.site_has_admin("dashboard.epix").await);
    }

    #[tokio::test]
    async fn confirm_resolves_via_wrapper_callback() {
        let s = AppState::new("test");
        let mut events = s.subscribe_events();

        // Server asks the wrapper to confirm; the future is pending.
        let s2 = s.clone();
        let handle = tokio::spawn(async move { s2.confirm("talk.epix", "Sure?", "Yes").await });

        // The pushed confirm event carries an `id` the wrapper replies to
        // (`{cmd:"response", to: message.id}`, EpixNet's shape).
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "confirm");
        let to = payload["id"].as_i64().unwrap();
        assert!(s.resolve_callback(to, json!(true)));

        // confirm() now resolves to the wrapper's answer.
        let answer = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
        assert!(answer, "confirm resolves true when the wrapper accepts");

        // An unknown callback id resolves nothing.
        assert!(!s.resolve_callback(999999, json!(true)));
    }

    #[tokio::test]
    async fn user_content_advances_the_dashboard_modified_clock() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let s = AppState::new("test");
        s.add_xite(
            "epix1x",
            XiteEntry {
                storage: storage.clone(),
                content: Some(json!({ "modified": 1000.0, "files": {} })),
            },
        )
        .await;
        // The root content.json sets the baseline.
        assert_eq!(s.site_info("epix1x").await["settings"]["modified"], 1000.0);

        // A per-user content.json lands (someone posted): the clock advances,
        // so the dashboard row reads "hours ago" instead of the root's date.
        storage.write("data/users/1A/content.json", br#"{"modified": 2000}"#).unwrap();
        s.ingest_file("epix1x", "data/users/1A/content.json").await;
        assert_eq!(s.site_info("epix1x").await["settings"]["modified"], 2000.0);

        // Reloading the (older) root does not walk it back.
        s.update_content("epix1x", Some(json!({ "modified": 1000.0, "files": {} }))).await;
        assert_eq!(s.site_info("epix1x").await["settings"]["modified"], 2000.0);

        // A far-future timestamp is capped at now + 10 minutes.
        let future = now_secs() as f64 + 100_000.0;
        storage
            .write(
                "data/users/1B/content.json",
                format!("{{\"modified\": {future}}}").as_bytes(),
            )
            .unwrap();
        s.ingest_file("epix1x", "data/users/1B/content.json").await;
        let capped =
            s.site_info("epix1x").await["settings"]["modified"].as_f64().unwrap();
        assert!(capped <= now_secs() as f64 + 601.0, "capped: {capped}");
        assert!(capped >= 2000.0);
    }

    #[tokio::test]
    async fn clone_events_carry_the_title_once_content_is_known() {
        let dir = tempfile::tempdir().unwrap();
        let s = AppState::new("test");
        s.add_xite(
            "epix1x",
            XiteEntry { storage: XiteStorage::new(dir.path()), content: None },
        )
        .await;
        let mut events = s.subscribe_events();

        // Before content.json is verified there is no title to show.
        s.push_clone_event("epix1x", json!(["peers_added", 1]), json!({}));
        let p: Value = serde_json::from_str(&events.try_recv().unwrap().payload).unwrap();
        assert_eq!(p["params"]["content"], json!({}));

        // Once it is, every clone event names the row (the dashboard's
        // "Connecting sites" list shows the name, not the bech32 address).
        s.update_content("epix1x", Some(json!({ "title": "xID" }))).await;
        s.push_clone_event("epix1x", json!(["file_done", "content.json"]), json!({}));
        let p: Value = serde_json::from_str(&events.try_recv().unwrap().payload).unwrap();
        assert_eq!(p["params"]["content"]["title"], "xID");
    }

    #[tokio::test]
    async fn owned_xites_are_never_html_gated() {
        struct AlwaysClone;
        #[async_trait::async_trait]
        impl OnDemandResolver for AlwaysClone {
            async fn ensure(&self, _host: &str) -> Result<(), String> {
                Ok(())
            }
            async fn resolve(&self, host: &str) -> Option<String> {
                host.starts_with("epix1").then(|| host.to_string())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let s = AppState::new("test");
        s.add_xite(
            "epix1x",
            XiteEntry { storage: XiteStorage::new(dir.path()), content: None },
        )
        .await;
        // No resolver: nothing can complete a download, so nothing is gated.
        assert!(!s.html_doc_gated("epix1x").await);
        s.set_on_demand(Arc::new(AlwaysClone)).await;
        // Incomplete on disk (no verified core set): the document waits.
        assert!(s.html_doc_gated("epix1x").await);
        // But never for an owned site - local edits must keep serving.
        s.set_owned("epix1x", true).await;
        assert!(!s.html_doc_gated("epix1x").await);
    }

    #[tokio::test]
    async fn lag_recovery_resends_closing_updates_for_finished_sites_only() {
        let dir = tempfile::tempdir().unwrap();
        let s = AppState::new("test");
        s.add_xite(
            "epix1done",
            XiteEntry { storage: XiteStorage::new(dir.path().join("a")), content: None },
        )
        .await;
        s.add_xite(
            "epix1busy",
            XiteEntry { storage: XiteStorage::new(dir.path().join("b")), content: None },
        )
        .await;
        s.begin_site_update("epix1busy");
        let mut events = s.subscribe_events();

        // Only the finished site gets its closing event re-sent, and only to
        // the asking connection - the busy one's real outcome is still coming.
        s.push_missed_update_results(7).await;
        let ev = events.try_recv().unwrap();
        assert_eq!(ev.only, Some(7));
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "setSiteInfo");
        assert_eq!(payload["params"]["address"], "epix1done");
        assert_eq!(payload["params"]["event"][0], "updated");
        assert!(events.try_recv().is_err(), "no event for the in-flight site");

        // Once its pass ends, a later recovery covers it too.
        s.end_site_update("epix1busy");
        s.push_missed_update_results(7).await;
        let mut addrs = Vec::new();
        while let Ok(ev) = events.try_recv() {
            let p: Value = serde_json::from_str(&ev.payload).unwrap();
            addrs.push(p["params"]["address"].as_str().unwrap().to_string());
        }
        addrs.sort();
        assert_eq!(addrs, ["epix1busy", "epix1done"]);
    }

    #[tokio::test]
    async fn server_info_push_targets_server_changed() {
        let s = AppState::new("test");
        let mut events = s.subscribe_events();
        s.push_server_info().await;
        let ev = events.try_recv().unwrap();
        assert_eq!(ev.channel.as_deref(), Some("serverChanged"));
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "setServerInfo");
        assert!(payload["params"]["version"].is_string());
    }

    #[tokio::test]
    async fn file_info_any_finds_user_content_optional_files() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "data/users/u1/content.json",
                &serde_json::to_vec(&json!({
                    "files": { "data.json": { "size": 2, "sha512": "dd" } },
                    "files_optional": { "1.jpg": { "size": 7, "sha512": "aa" } },
                }))
                .unwrap(),
            )
            .unwrap();
        let state = AppState::new("test");
        state
            .add_xite(
                "epix1hub",
                XiteEntry {
                    storage,
                    content: Some(json!({
                        "address": "epix1hub",
                        "files": { "index.html": { "size": 1, "sha512": "ff" } },
                    })),
                },
            )
            .await;

        // The root content.json does not declare the user's image, so the
        // root-only lookup misses...
        let root = state.content("epix1hub").await.unwrap();
        assert!(root["files"].get("data/users/u1/1.jpg").is_none());
        assert!(root.get("files_optional").is_none());
        // ...but its governing child content.json does, as optional, with the
        // site-relative inner path kept.
        let (info, optional) =
            state.file_info_any("epix1hub", "data/users/u1/1.jpg").await.unwrap();
        assert!(optional);
        assert_eq!(info.inner_path, "data/users/u1/1.jpg");
        assert_eq!(info.size, 7);
        assert_eq!(info.sha512, "aa");
        // Required child files come back optional=false; root files still hit.
        let (_, optional) =
            state.file_info_any("epix1hub", "data/users/u1/data.json").await.unwrap();
        assert!(!optional);
        let (info, optional) = state.file_info_any("epix1hub", "index.html").await.unwrap();
        assert!(!optional);
        assert_eq!(info.size, 1);
        // Undeclared paths miss.
        assert!(state.file_info_any("epix1hub", "data/users/u1/2.jpg").await.is_none());
    }

    #[tokio::test]
    async fn resolve_merged_enforces_the_permission_matrix() {
        let dir = tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite(
                "epix1merger",
                XiteEntry {
                    storage: XiteStorage::new(dir.path().join("merger")),
                    content: Some(json!({ "address": "epix1merger", "files": {} })),
                },
            )
            .await;
        state
            .add_xite(
                "epix1hub",
                XiteEntry {
                    storage: XiteStorage::new(dir.path().join("hub")),
                    content: Some(json!({
                        "address": "epix1hub",
                        "merged_type": "EpixTalk",
                        "files": {},
                    })),
                },
            )
            .await;

        // Not a merged path at all.
        assert_eq!(state.resolve_merged("epix1merger", "index.html").await, Ok(None));

        // The merger holds no Merger:EpixTalk permission yet.
        assert!(state
            .resolve_merged("epix1merger", "merged-EpixTalk/epix1hub/avatar.jpg")
            .await
            .is_err());

        state.add_permission("epix1merger", "Merger:EpixTalk").await;

        // Happy path.
        assert_eq!(
            state.resolve_merged("epix1merger", "merged-EpixTalk/epix1hub/avatar.jpg").await,
            Ok(Some(("epix1hub".to_string(), "avatar.jpg".to_string())))
        );

        // The target must be a registered site.
        assert!(state
            .resolve_merged("epix1merger", "merged-EpixTalk/epix1nowhere/avatar.jpg")
            .await
            .is_err());

        // The target must declare the requested merged_type.
        state.add_permission("epix1merger", "Merger:GitCenter").await;
        assert!(state
            .resolve_merged("epix1merger", "merged-GitCenter/epix1hub/x")
            .await
            .is_err());

        // Exception: a target still cloning has no content.json to declare its
        // merged_type yet - it resolves so its files serve during the clone.
        state
            .add_xite(
                "epix1cloning",
                XiteEntry { storage: XiteStorage::new(dir.path().join("cloning")), content: None },
            )
            .await;
        state.begin_clone("epix1cloning");
        assert_eq!(
            state.resolve_merged("epix1merger", "merged-EpixTalk/epix1cloning/avatar.jpg").await,
            Ok(Some(("epix1cloning".to_string(), "avatar.jpg".to_string())))
        );
        // Once the clone ends without declaring the type, it is refused again.
        state.end_clone("epix1cloning");
        assert!(state
            .resolve_merged("epix1merger", "merged-EpixTalk/epix1cloning/avatar.jpg")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn file_need_fetches_bigfile_pieces_not_the_whole_blob() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        // A 3-piece big file, declared by a child content.json (a per-user
        // dir) whose piecemap path is relative to that child's own dir.
        let data = vec![7u8; 2500];
        let hash = epix_xite::hash_bigfile(&data, 1024);
        storage.write("data/users/A/big.bin", &data).unwrap();
        storage
            .write(
                "data/users/A/big.bin.piecemap.msgpack",
                &epix_xite::build_piecemap("big.bin", &hash),
            )
            .unwrap();
        storage
            .write(
                "data/users/A/content.json",
                &serde_json::to_vec(&json!({
                    "files_optional": {
                        "big.bin": {
                            "sha512": hash.merkle_root,
                            "size": 2500,
                            "piecemap": "big.bin.piecemap.msgpack",
                            "piece_size": 1024,
                        }
                    }
                }))
                .unwrap(),
            )
            .unwrap();
        let state = AppState::new("test");
        state
            .add_xite("epix1big", XiteEntry {
                storage,
                content: Some(json!({ "address": "epix1big", "files": {} })),
            })
            .await;
        std::mem::forget(dir);

        // The declared sha512 is a merkle root: a whole-file flat hash never
        // matches it, so the old blob fetch path could only fail. The
        // piecewise path verifies the on-disk pieces and succeeds without any
        // transport.
        assert_eq!(state.file_need("epix1big", "data/users/A/big.bin").await, Ok(true));
        assert_eq!(state.bigfile_total("epix1big", "data/users/A/big.bin").await, Some(2500));
    }

    #[tokio::test]
    async fn a_cancelled_file_need_removes_its_lock_map_entry() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let state = AppState::new("test");
        state
            .add_xite("epix1need", XiteEntry {
                storage,
                content: Some(json!({
                    "address": "epix1need",
                    "files_optional": { "a.bin": { "size": 3, "sha512": "aa" } },
                })),
            })
            .await;
        std::mem::forget(dir);

        // Hold the per-file lock so the fetch blocks at an await point, then
        // cancel it - serve_file's 45s timeout does exactly this - and the
        // dropped future's map entry must still be removed.
        let key = ("epix1need".to_string(), "a.bin".to_string());
        let lock = state.file_need_locks.lock().unwrap().entry(key.clone()).or_default().clone();
        let _guard = lock.lock().await;
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            state.file_need("epix1need", "a.bin"),
        )
        .await;
        assert!(cancelled.is_err(), "the fetch must still be blocked when the timeout fires");
        assert!(!state.file_need_locks.lock().unwrap().contains_key(&key));
    }

    #[tokio::test]
    async fn optional_help_counts_child_declared_optional_files() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "data/users/A/content.json",
                &serde_json::to_vec(&json!({
                    "files_optional": { "img.jpg": { "size": 700, "sha512": "aa" } }
                }))
                .unwrap(),
            )
            .unwrap();
        let state = AppState::new("test");
        state
            .add_xite("epix1help", XiteEntry {
                storage,
                content: Some(json!({
                    "address": "epix1help",
                    "files_optional": { "data/users/A/root.bin": { "size": 40, "sha512": "bb" } },
                })),
            })
            .await;
        std::mem::forget(dir);

        // One optional file from the root content.json, one from the child's
        // (python tallies both via its file_optional table).
        let (num, size) = state.optional_help_add("epix1help", "data/users/A", "T").await.unwrap();
        assert_eq!((num, size), (2, 740));
    }
}
