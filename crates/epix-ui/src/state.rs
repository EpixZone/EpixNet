//! Shared server state: the xites this node serves (with their runtime
//! settings + stats), the local user identity, and node metadata.

use epix_core::{Address, PeerAddr};
use epix_db::{Database, DbSchema};
use epix_peer::{PeerCounts, Peers};
use epix_protocol::Connection;
use epix_transport::Transport;
use epix_user::User;
use epix_xite::{content_stats, Xite, XiteSettings, XiteStorage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Default per-xite size limit, in MB (matches EpixNet's `config.size_limit`).
const DEFAULT_SIZE_LIMIT_MB: i64 = 10;

/// Resolves + clones a `.epix` host that isn't served yet, so the browser can
/// open any name by typing it. Implemented by the node (which has the chain
/// resolver + download worker); the UI server calls it via
/// [`AppState::ensure_xite`]. Kept as a trait so `epix-ui` has no dependency on
/// the chain/worker crates.
#[async_trait::async_trait]
pub trait OnDemandResolver: Send + Sync {
    /// Resolve + clone `host` and add it as a served xite. `Ok(())` once served.
    async fn ensure(&self, host: &str) -> Result<(), String>;
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
    ("Network", "tor", "Tor", "enable", "select:Disable=disable|Enable=enable|Always=always"),
    ("Network", "tor_use_bridges", "Use Tor bridges", "false", "soon:bool"),
    ("Network", "trackers", "Trackers", "145.223.69.23:26959", "textarea"),
    ("Network", "trackers_file", "Trackers files (one path per line)", "", "textarea"),
    (
        "Network",
        "trackers_proxy",
        "Proxy for tracker connections",
        "disable",
        "soon:select:Custom=custom|Tor=tor|Disable=disable",
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

/// Server-wide state shared across all HTTP/WebSocket handlers.
pub struct AppState {
    pub version: String,
    xites: RwLock<HashMap<String, ManagedXite>>,
    user: RwLock<User>,
    user_path: Option<PathBuf>,
    nonce_counter: AtomicU64,
    /// Persisted per-user global settings (theme, etc.). Must persist across a
    /// connection or xites that reload on a settings change loop forever.
    global_settings: RwLock<Value>,
    /// ContentFilter store: `{ "mutes": {auth_address: {...}}, "siteblocks": {site: {...}} }`.
    filters: RwLock<Value>,
    filters_path: Option<PathBuf>,
    /// Transport used to publish updates to peers (set by the node).
    transport: RwLock<Option<Arc<dyn Transport>>>,
    /// On-demand resolver: resolve + clone a `.epix` host not yet served (set by
    /// the node, which has the chain + worker). Lets the browser open any
    /// `talk.epix` by typing it, cloning it live.
    on_demand: RwLock<Option<Arc<dyn OnDemandResolver>>>,
    /// DHT-backed peer lookup, installed by the runtime.
    peer_finder: RwLock<Option<Arc<dyn PeerFinder>>>,
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
    /// Names of loaded plugins/features, reported in `serverInfo` (the dashboard
    /// menu shows plugin-gated items like Stats from this).
    plugins: RwLock<Vec<String>>,
    /// Recent log lines for the dashboard console (`serverErrors`): each is
    /// `[date_added, level, message]`, newest last, capped.
    logs: RwLock<std::collections::VecDeque<Value>>,
    /// Open sidebar-console log streams (`consoleLogStream`); new log lines are
    /// pushed to each as `logLineAdd` events.
    log_streams: RwLock<Vec<i64>>,
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
    /// Inbound updates currently being verified/downloaded (`site/inner:modified`
    /// URIs), so the same pushed version isn't processed twice concurrently
    /// (EpixNet's `files_parsing`).
    updates_in_flight: std::sync::Mutex<std::collections::HashSet<String>>,
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
    /// The shared data root (holds `sites.json` + per-xite subdirectories), so
    /// the served-xite list can be restored on the next start. None for
    /// in-memory nodes.
    data_root: Option<PathBuf>,
    /// Path to `sites.json` (the persistent served-xite registry, EpixNet's
    /// SiteManager). None for in-memory nodes.
    sites_path: Option<PathBuf>,
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

/// A random lowercase-hex string of `bytes` random bytes (2 hex chars each).
/// Used for wrapper/CSP nonces.
fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    let _ = getrandom::getrandom(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

impl AppState {
    /// In-memory node with a freshly generated user identity.
    pub fn new(version: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            version: version.into(),
            xites: RwLock::new(HashMap::new()),
            user: RwLock::new(User::generate()),
            user_path: None,
            nonce_counter: AtomicU64::new(1),
            global_settings: RwLock::new(json!({ "theme": "light" })),
            filters: RwLock::new(empty_filters()),
            filters_path: None,
            transport: RwLock::new(None),
            on_demand: RwLock::new(None),
            peer_finder: RwLock::new(None),
            tracker_stats: RwLock::new(HashMap::new()),
            grants: RwLock::new(HashMap::new()),
            grants_path: None,
            chart: Arc::new(crate::chart::ChartDb::memory().expect("in-memory chart db")),
            optional_limit: RwLock::new("10%".to_string()),
            optional_limit_path: None,
            geoip: RwLock::new(None),
            conn_pool: crate::conn_pool::ConnectionPool::new(CONNECTION_POOL_MAX),
            events: tokio::sync::broadcast::channel(256).0,
            config: RwLock::new(serde_json::Map::new()),
            config_path: None,
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
            pins_path: None,
            updates_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            callbacks: std::sync::Mutex::new(HashMap::new()),
            log_file: std::sync::Mutex::new(None),
            bigfile_uploads: std::sync::Mutex::new(HashMap::new()),
            wrapper_nonces: std::sync::Mutex::new(std::collections::HashSet::new()),
            allowed_ws_origins: std::sync::Mutex::new(std::collections::HashSet::new()),
            launch_homepage: std::sync::Mutex::new(None),
            data_root: None,
            sites_path: None,
            #[cfg(feature = "multiuser")]
            multi_users: RwLock::new(HashMap::new()),
            #[cfg(feature = "multiuser")]
            multi_users_path: None,
        })
    }

    /// Node whose user identity persists in `data_dir/users.json`, so the same
    /// per-xite auth addresses are used across restarts.
    pub fn with_data_dir(version: impl Into<String>, data_dir: impl Into<PathBuf>) -> Arc<Self> {
        let dir = data_dir.into();
        let _ = std::fs::create_dir_all(&dir);
        // The shared root holds the cross-xite registry (sites.json) and the
        // per-xite subdirectories; a per-xite `dir` sits directly under it.
        let data_root = dir.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| dir.clone());
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
            xites: RwLock::new(HashMap::new()),
            user: RwLock::new(user),
            user_path: Some(user_path),
            nonce_counter: AtomicU64::new(1),
            global_settings: RwLock::new(json!({ "theme": "light" })),
            filters: RwLock::new(filters),
            filters_path: Some(filters_path),
            transport: RwLock::new(None),
            on_demand: RwLock::new(None),
            peer_finder: RwLock::new(None),
            tracker_stats: RwLock::new(HashMap::new()),
            grants: RwLock::new(grants),
            grants_path: Some(grants_path),
            chart: Arc::new(chart),
            optional_limit: RwLock::new(optional_limit),
            optional_limit_path: Some(optional_limit_path),
            geoip: RwLock::new(None),
            conn_pool: crate::conn_pool::ConnectionPool::new(CONNECTION_POOL_MAX),
            events: tokio::sync::broadcast::channel(256).0,
            config: RwLock::new(config),
            config_path: Some(config_path),
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
            updates_in_flight: std::sync::Mutex::new(std::collections::HashSet::new()),
            callbacks: std::sync::Mutex::new(HashMap::new()),
            log_file: std::sync::Mutex::new(None),
            bigfile_uploads: std::sync::Mutex::new(HashMap::new()),
            wrapper_nonces: std::sync::Mutex::new(std::collections::HashSet::new()),
            allowed_ws_origins: std::sync::Mutex::new(std::collections::HashSet::new()),
            launch_homepage: std::sync::Mutex::new(None),
            // The served-xite registry lives in the shared root (the parent of a
            // per-xite dir), so it spans every xite that shares this root.
            data_root: Some(data_root.clone()),
            sites_path: Some(data_root.join("sites.json")),
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

    /// The persisted list of disabled plugin names.
    async fn disabled_plugins(&self) -> Vec<String> {
        self.config_str_list("plugins_disabled").await
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
        self.config_get("no_new_sites").await.and_then(|v| v.as_bool()).unwrap_or(false)
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

    /// The trackers remembered from previous announces (`epix://…` addresses).
    pub async fn shared_trackers(&self) -> Vec<PeerAddr> {
        self.config_get("shared_trackers")
            .await
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|s| PeerAddr::parse(s).ok())
            .collect()
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

    /// `notificationQuery` - run every subscribed site's notification queries and
    /// return the row counts (`{results, num, sites, muted}`).
    pub async fn notification_query(&self) -> Value {
        if self.config_get("notification_muted").await.and_then(|v| v.as_bool()).unwrap_or(false) {
            return json!({ "results": [], "num": 0, "sites": 0, "muted": true });
        }
        let subs = self.config_get("notifications").await.unwrap_or_else(|| json!({}));
        let site_muted = self.config_get("notification_site_muted").await.unwrap_or_else(|| json!({}));
        let mut results = Vec::new();
        let mut num = 0i64;
        let mut sites = 0i64;
        if let Value::Object(by_site) = &subs {
            for (address, site_subs) in by_site {
                if site_muted.get(address).and_then(|v| v.as_bool()).unwrap_or(false) {
                    continue;
                }
                let Value::Object(queries) = site_subs else { continue };
                let mut any = false;
                for (name, spec) in queries {
                    let (query, params) = match spec {
                        Value::Array(a) => (
                            a.first().and_then(|v| v.as_str()).unwrap_or(""),
                            a.get(1).cloned().unwrap_or(Value::Null),
                        ),
                        Value::String(q) => (q.as_str(), Value::Null),
                        _ => continue,
                    };
                    if let Ok(rows) = self.db_query(address, query, &params).await {
                        // A notification query is usually `SELECT COUNT(*) AS count`,
                        // so the real total is a column on the first row - not the
                        // number of rows returned. Fall back to the row count only
                        // when neither `count` nor `COUNT(*)` is present.
                        let count = rows
                            .first()
                            .and_then(|r| r.get("count").or_else(|| r.get("COUNT(*)")))
                            .and_then(|v| v.as_i64())
                            .unwrap_or(rows.len() as i64);
                        if count > 0 {
                            num += count;
                            any = true;
                            results.push(json!({ "address": address, "name": name, "count": count }));
                        }
                    }
                }
                if any {
                    sites += 1;
                }
            }
        }
        json!({ "results": results, "num": num, "sites": sites, "muted": false })
    }

    /// `configList` - the editable config keys with current value + default.
    pub async fn config_list(&self) -> Value {
        let mut back = serde_json::Map::new();
        for (_section, key, _label, default, kind) in CONFIG_SCHEMA {
            if is_config_action(kind) {
                continue;
            }
            let value = self.config_get(key).await.unwrap_or_else(|| json!(default));
            back.insert(
                key.to_string(),
                json!({ "value": value, "default": default, "pending": false }),
            );
        }
        Value::Object(back)
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

    pub async fn global_settings(&self) -> Value {
        self.global_settings.read().await.clone()
    }

    pub async fn set_global_settings(&self, value: Value) {
        *self.global_settings.write().await = value;
    }

    /// Register a served xite, deriving its settings + stats from content.json.
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
        // content address.
        let mut peers = Peers::new();
        let saved = self.load_persisted_peers(&canonical);
        if !saved.is_empty() {
            peers.add_many(saved, now_secs());
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

    /// Normalize a serving reference to the bech32 address: an address passes
    /// through; a `.epix` name resolves via [`Self::resolve_name`]. Returns the
    /// input unchanged if the name is unknown (lookups then miss cleanly).
    pub async fn canonical_key(&self, address_or_name: &str) -> String {
        if !address_or_name.contains('.') {
            return address_or_name.to_string();
        }
        self.resolve_name(address_or_name).await.unwrap_or_else(|| address_or_name.to_string())
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
    /// `<root>/<canonical>`, load + verify the on-disk content.json, and add it
    /// (plus its display alias). Skips entries already served and any whose
    /// content.json is missing or fails verification. Returns how many were
    /// restored. Call once at startup before serving.
    pub async fn restore_sites(self: &Arc<Self>) -> usize {
        let (Some(path), Some(root)) = (&self.sites_path, &self.data_root) else { return 0 };
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
            // Load + verify the on-disk content.json under the canonical address.
            let Ok(addr) = Address::parse(canonical.clone()) else { continue };
            let mut xite = Xite::new(addr, storage.clone());
            match xite.load_content() {
                Ok(true) => {}
                _ => continue, // no content.json, or it failed signature verification
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
                    x.settings.favorite = saved.favorite;
                    if saved.added > 0 {
                        x.settings.added = saved.added;
                    }
                }
            }
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

    /// Add discovered peers to a xite, syncing `settings.peers` to the count.
    pub async fn add_peers(&self, address: &str, addrs: impl IntoIterator<Item = PeerAddr>) {
        let grew = {
            let mut xites = self.xites.write().await;
            match xites.get_mut(address) {
                Some(x) => {
                    let before = x.peers.len();
                    x.peers.add_many(addrs, now_secs());
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
    /// modified}` - the `listModified` reply. Only the root content.json is
    /// tracked until includes land, so this returns it when newer than `since`.
    pub async fn list_modified(&self, address: &str, since: f64) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        let xites = self.xites.read().await;
        if let Some(x) = self.resolve_xite(&xites, address) {
            if let Some(modified) =
                x.content.as_ref().and_then(|c| c.get("modified")).and_then(|v| v.as_f64())
            {
                if modified > since {
                    out.insert("content.json".to_string(), json!(modified));
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
    /// peer if new.
    pub async fn set_peer_hashfield(&self, address: &str, peer: &PeerAddr, raw: &[u8]) -> bool {
        let mut xites = self.xites.write().await;
        let key = xites
            .iter()
            .find(|(k, x)| {
                k.as_str() == address || canonical_address(x.content.as_ref(), k) == address
            })
            .map(|(k, _)| k.clone());
        let Some(key) = key else { return false };
        let x = xites.get_mut(&key).unwrap();
        x.peers.add(peer.clone(), now_secs());
        x.settings.peers = x.peers.len() as i64;
        x.peer_hashfields
            .insert(peer.to_string(), epix_xite::Hashfield::from_bytes(raw));
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
                        epix_core::IpType::Rns => None,
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

    /// Load the peers persisted for a site (by signed content address).
    fn load_persisted_peers(&self, canonical: &str) -> Vec<PeerAddr> {
        let Some(path) = &self.peers_path else { return Vec::new() };
        let map: serde_json::Map<String, Value> = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        map.get(canonical)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).filter_map(|s| PeerAddr::parse(s).ok()).collect())
            .unwrap_or_default()
    }

    /// Persist every served xite's peers to `peers.json` (keyed by signed content
    /// address, so aliases share one list). Called periodically by the runtime.
    pub async fn persist_peers(&self) {
        let Some(path) = &self.peers_path else { return };
        let mut map: serde_json::Map<String, Value> = serde_json::Map::new();
        for (key, x) in self.xites.read().await.iter() {
            let canonical = canonical_address(x.content.as_ref(), key);
            if x.peers.len() == 0 {
                continue;
            }
            let list: Vec<Value> = x.peers.peers().map(|p| json!(p.addr.to_string())).collect();
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

    /// Announce a xite to each tracker in turn, recording per-tracker stats and
    /// folding the peers found into the xite's registry. Returns all peers.
    pub async fn announce_to_trackers(&self, address: &str, trackers: &[PeerAddr]) -> Vec<PeerAddr> {
        let Some(transport) = self.transport.read().await.clone() else { return Vec::new() };
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
        let mut all = Vec::new();
        for tracker in trackers {
            let peers = epix_xite::announce(transport.as_ref(), &key, std::slice::from_ref(tracker), 0).await;
            self.record_tracker(&tracker.to_string(), peers.len()).await;
            // AnnounceShare: remember a tracker that answered, so it is reused
            // (and shared) across restarts.
            if !peers.is_empty() {
                self.add_shared_tracker(&tracker.to_string()).await;
            }
            all.extend(peers);
        }
        self.add_peers(address, all.clone()).await;
        self.log("INFO", format!("Announced {address}: {} peers", all.len())).await;
        // Push the fresh peer count + tracker status to any connected UI.
        self.push_site_info(address).await;
        self.push_announcer_info(&key).await;
        all
    }

    /// Record a completed announce to `tracker` (found `num_added` peers).
    async fn record_tracker(&self, tracker: &str, num_added: usize) {
        let key = format!("epix://{tracker}");
        let mut stats = self.tracker_stats.write().await;
        let entry = stats.entry(key).or_insert_with(|| {
            json!({ "status": "announcing", "num_request": 0, "num_success": 0, "num_error": 0, "num_added": 0, "time_request": 0 })
        });
        let obj = entry.as_object_mut().expect("tracker stat object");
        let bump = |o: &mut serde_json::Map<String, Value>, k: &str, by: i64| {
            let v = o.get(k).and_then(|v| v.as_i64()).unwrap_or(0) + by;
            o.insert(k.to_string(), json!(v));
        };
        obj.insert("status".into(), json!("announced"));
        obj.insert("time_request".into(), json!(now_secs()));
        bump(obj, "num_request", 1);
        bump(obj, "num_success", 1);
        bump(obj, "num_added", num_added as i64);
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

    /// Tor state for `serverInfo`: `(enabled, status)`.
    pub async fn tor_status(&self) -> (bool, String) {
        (*self.tor_enabled.read().await, self.tor_status.read().await.clone())
    }

    /// Our onion address (no suffix), if the onion service has published one.
    pub async fn onion_address(&self) -> Option<String> {
        self.onion_address.read().await.clone()
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
            // Bound each peer attempt so a slow/unresponsive peer doesn't stall
            // the whole update.
            let fetched = tokio::time::timeout(std::time::Duration::from_secs(6), async {
                let mut conn = Connection::connect(transport.as_ref(), peer).await.ok()?;
                conn.handshake().await.ok()?;
                conn.get_file(&canonical, "content.json").await.ok()
            })
            .await;
            let Ok(Some(bytes)) = fetched else { continue };
            let Ok(new): std::result::Result<Value, _> = serde_json::from_slice(&bytes) else {
                continue;
            };
            let new_modified = new.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
            self.set_peer_connected(address, peer, true).await;
            if new_modified <= local_modified {
                return Ok(false); // already current
            }

            // Verify + apply the newer content.json (full signer/rules check,
            // size-limited), then sync its changed files.
            let mut xite = Xite::new(
                Address::parse(canonical.clone()).map_err(|e| e.to_string())?,
                view.storage.clone(),
            );
            let limit = self.size_limit_bytes(address).await;
            xite.set_content_limited(&bytes, limit).map_err(|e| e.to_string())?;
            self.update_content(address, xite.content.clone()).await;

            let needed = xite.files_needed().len();
            let workers = peers.len().min(8);
            self.set_worker_stats(address, needed, workers, needed).await;
            let report = epix_worker::sync_files(&xite, &peers, transport.clone(), 8).await;
            // Always clear the live task counters - a leftover tasks>0 keeps
            // the dashboard row's "Updating" spinner stuck.
            self.set_worker_stats(address, 0, 0, 0).await;
            let report = report.map_err(|e| e.to_string())?;
            self.add_transfer(address, report.bytes, 0).await;
            // Data files may have changed - rebuild the db view.
            self.update_content(address, xite.content).await;
            return Ok(true);
        }
        Ok(false)
    }

    /// Peer counts (connected/connectable/onion/local/total) for the sidebar.
    pub async fn peer_counts(&self, address: &str) -> PeerCounts {
        self.xites.read().await.get(address).map(|x| x.peers.counts()).unwrap_or_default()
    }

    /// Connectable peer addresses for a xite (best reputation first).
    pub async fn connectable_peers(&self, address: &str, limit: usize) -> Vec<PeerAddr> {
        self.xites
            .read()
            .await
            .get(address)
            .map(|x| x.peers.connectable(limit))
            .unwrap_or_default()
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
        let db = self.xites.read().await.get(address).and_then(|x| x.db.clone());
        let db = db.ok_or_else(|| "xite has no database".to_string())?;
        db.query_value(query, params).map_err(|e| e.to_string())
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

    /// The user's CryptMessage encryption private key (WIF) for a xite.
    pub async fn user_encrypt_privatekey(&self, address: &str, index: u64) -> Result<String, String> {
        self.user.read().await.encrypt_privatekey(address, index)
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
        let pk = self.user.read().await.encrypt_privatekey(address, index)?;
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
    pub async fn muted_authors(&self) -> Vec<String> {
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

    /// Download a file (required or optional) on demand from peers, verifying
    /// its hash before writing. `fileNeed`. Returns true if present after.
    pub async fn file_need(&self, address: &str, inner_path: &str) -> Result<bool, String> {
        let xite = self.xite_view(address).await?;
        let info = xite.file_info(inner_path).ok_or("file not declared in content.json")?;
        if xite.storage.verify(inner_path, &info.sha512) {
            return Ok(true); // already have it
        }
        let transport = self.transport.read().await.clone().ok_or("no transport")?;
        let peers = self.connectable_peers(address, 20).await;
        for peer in peers {
            let Ok(mut conn) = Connection::connect(transport.as_ref(), &peer).await else { continue };
            if conn.handshake().await.is_err() {
                continue;
            }
            let Ok(bytes) = conn.get_file(address, inner_path).await else { continue };
            if XiteStorage::hash_bytes(&bytes) == info.sha512 {
                xite.storage.write(inner_path, &bytes).map_err(|e| e.to_string())?;
                self.set_peer_connected(address, &peer, true).await;
                // Count optional bytes downloaded and advertise it in our
                // hashfield so peers can discover we now hold it.
                if xite.optional_files().iter().any(|f| f.inner_path == inner_path) {
                    if let Some(x) = self.xites.write().await.get_mut(address) {
                        x.settings.optional_downloaded += info.size;
                        x.hashfield.add_hash(&info.sha512);
                    }
                }
                return Ok(true);
            }
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

        if let Value::Object(map) = &mut info {
            let size = map["size"].as_i64().unwrap_or(0);
            if size > 1024 * 1024 {
                let content = self.content(address).await;
                let entry =
                    content.as_ref().and_then(|c| c.get("files_optional")).and_then(|o| o.get(inner_path));
                if let Some(entry) = entry {
                    let piece_size = entry.get("piece_size").and_then(|v| v.as_i64()).unwrap_or(1024 * 1024);
                    let piece_num = (size + piece_size - 1) / piece_size.max(1);
                    map.insert("is_bigfile".into(), json!(true));
                    map.insert("piece_size".into(), json!(piece_size));
                    map.insert("piece_num".into(), json!(piece_num));
                    if let Some(pm) = entry.get("piecemap").and_then(|v| v.as_str()) {
                        map.insert("piecemap".into(), json!(pm));
                    }
                }
            }
        }
        Ok(info)
    }

    /// On-disk size of a xite file (for HTTP Range / Content-Range).
    pub async fn file_size(&self, address: &str, inner_path: &str) -> Option<u64> {
        let storage = self.xites.read().await.get(address)?.storage.clone();
        let path = storage.path(inner_path).ok()?;
        std::fs::metadata(path).ok().map(|m| m.len())
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
        let content = self.content(address).await;
        let entry = content
            .as_ref()
            .and_then(|c| c.get("files_optional"))
            .and_then(|o| o.get(inner_path));
        let Some(entry) = entry else { return Ok(()) }; // not optional -> nothing to do
        let Some(piecemap_path) = entry.get("piecemap").and_then(|v| v.as_str()).map(String::from)
        else {
            return Ok(()); // not a big file
        };
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
                    if let Some(x) = self.xites.write().await.get_mut(address) {
                        x.settings.optional_downloaded += plen as i64;
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
        let bytes = serde_json::to_vec_pretty(&content).map_err(|e| e.to_string())?;
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
        let xite = self.xite_view(address).await?;
        let info = xite.file_info(inner_path).ok_or("file not declared")?;
        if let Ok(path) = xite.storage.path(inner_path) {
            let _ = std::fs::remove_file(path);
        }
        let mut changed_pin = false;
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.optional_downloaded = (x.settings.optional_downloaded - info.size).max(0);
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
    pub async fn peer_locations(&self) -> Vec<Value> {
        let Some(geoip) = self.geoip.read().await.clone() else { return Vec::new() };
        // Best ping seen per IP (ms), across xites.
        let mut pings: HashMap<std::net::IpAddr, Option<i64>> = HashMap::new();
        for x in self.xites.read().await.values() {
            for p in x.peers.peers() {
                if let PeerAddr::Ip(sa) = &p.addr {
                    pings.entry(sa.ip()).or_insert(None);
                }
            }
        }
        // Ping (ms) per connected clearnet peer, from the warm pool.
        for addr in self.conn_pool.connected_addrs().await {
            if let PeerAddr::Ip(sa) = &addr {
                if let Some(ms) = self.conn_pool.ping_for(&addr).await {
                    pings.insert(sa.ip(), Some(ms));
                }
            }
        }
        let mut out = Vec::new();
        for (ip, ping) in pings {
            if let Some(loc) = geoip.locate(ip) {
                out.push(json!({
                    "lat": loc.lat,
                    "lon": loc.lon,
                    "city": loc.city,
                    "country": loc.country,
                    "ping": ping,
                }));
            }
        }
        out
    }

    /// `sidebarGetPeers` - peer positions for the sidebar's WebGL globe, as a
    /// flat `[lat, lon, height, …]` array (the globe's `magnitude` format).
    /// Height is derived from ping (log-scaled around the average), matching
    /// EpixNet: connected peers rise with latency, unpinged peers sit slightly
    /// below the surface.
    pub async fn peer_globe_data(&self) -> Vec<f64> {
        let locs = self.peer_locations().await;
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
        let (mut ipv4, mut ipv6, mut onion) = (Vec::new(), Vec::new(), Vec::new());
        for p in &ours {
            if p.is_private() {
                continue;
            }
            match (p.ip_type(), p.pack()) {
                (epix_core::IpType::Ipv4, Some(b)) => ipv4.push(b),
                (epix_core::IpType::Ipv6, Some(b)) => ipv6.push(b),
                (epix_core::IpType::Onion, Some(b)) => onion.push(b),
                _ => {}
            }
        }

        let mut learned: Vec<PeerAddr> = Vec::new();
        for peer in ours.iter().take(max_peers) {
            let got = tokio::time::timeout(std::time::Duration::from_secs(6), async {
                let mut conn = Connection::connect(transport.as_ref(), peer).await.ok()?;
                conn.handshake().await.ok()?;
                conn.pex(&canonical, ipv4.clone(), ipv6.clone(), onion.clone(), need).await.ok()
            })
            .await;
            let Ok(Some(reply)) = got else { continue };
            self.set_peer_connected(address, peer, true).await;
            let unpacked = reply
                .ipv4
                .iter()
                .chain(reply.ipv6.iter())
                .filter_map(|b| PeerAddr::unpack_ip(b))
                .chain(reply.onion.iter().filter_map(|b| PeerAddr::unpack_onion(b)));
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

        // Connections.
        let _ = write!(
            h,
            "<h2>Connections ({} live, onion: {})</h2>             <table><tr><th>peer</th><th>type</th><th>ping</th></tr>",
            stats.total, stats.onion
        );
        for addr in self.conn_pool.connected_addrs().await {
            let ping = self
                .conn_pool
                .ping_for(&addr)
                .await
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "-".into());
            let kind = match &addr {
                PeerAddr::Onion { .. } => "onion",
                PeerAddr::Rns(_) => "mesh",
                PeerAddr::Ip(_) => "ip",
            };
            let _ = write!(
                h,
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&addr.to_string()),
                kind,
                ping
            );
        }
        if stats.total == 0 {
            h.push_str("<tr><td colspan=3 class='muted'>no live connections</td></tr>");
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
        // Stream to any open sidebar console(s).
        let streams = self.log_streams.read().await;
        if !streams.is_empty() {
            let formatted = format_log_line(&line);
            for id in streams.iter() {
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
    /// strings, plus the byte-position metadata the panel displays.
    pub async fn console_log_read(&self) -> Value {
        let lines: Vec<Value> =
            self.logs.read().await.iter().map(|l| json!(format_log_line(l))).collect();
        let n = lines.len();
        json!({ "lines": lines, "pos_start": 0, "pos_end": n * 80, "num_found": n })
    }

    /// `consoleLogStream` - open a live log stream; returns its id. New lines
    /// arrive as `logLineAdd` events tagged with this id.
    pub async fn console_log_stream_open(&self) -> i64 {
        let id = self.nonce_counter.fetch_add(1, Ordering::Relaxed) as i64;
        self.log_streams.write().await.push(id);
        id
    }

    /// `consoleLogStreamRemove` - stop a live log stream.
    pub async fn console_log_stream_remove(&self, id: i64) {
        self.log_streams.write().await.retain(|s| *s != id);
    }

    /// Subscribe to server-pushed UI events (one receiver per WS connection).
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<UiEvent> {
        self.events.subscribe()
    }

    /// Push an unsolicited `{cmd, params}` event. `channel` gates by
    /// subscription (`None` = ungated); `target` gates by xite (`None` = any).
    /// No-op if nothing is listening.
    fn push_event(&self, cmd: &str, params: Value, channel: Option<&str>, target: Option<String>) {
        let payload = json!({ "cmd": cmd, "params": params, "to": Value::Null }).to_string();
        let _ = self.events.send(UiEvent { channel: channel.map(str::to_string), target, payload });
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
        let mut info = self.site_info(address).await;
        if let Value::Object(m) = &mut info {
            m.insert("event".to_string(), json!([event, true]));
            self.push_event("setSiteInfo", info, Some("siteChanged"), Some(address.to_string()));
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
        let mut params = json!({
            "address": address,
            "peers": 0,
            "tasks": 0,
            "started_task_num": 0,
            "bad_files": 0,
            "size_limit": 10,
            "settings": { "size": 0 },
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
            m.entry("theme").or_insert(json!("light"));
            m.entry("use_system_theme").or_insert(json!(false));
        }
        let connections = self.connection_stats().await.total;
        let plugins = self.plugins().await;
        #[cfg(feature = "multiuser")]
        let (multiuser, multiuser_admin, master_address) =
            (true, true, self.multiuser_list().await.first().cloned().unwrap_or_default());
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
        json!({
            "version": self.version,
            "rev": 8192,
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
            "ui_ip": "127.0.0.1",
            "ui_port": 43110,
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
        let payload = json!({ "cmd": cmd, "params": params, "to": id }).to_string();
        let _ = self.events.send(UiEvent { channel: None, target, payload });
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
                    let _ = db.populate_site(&schema, merged_dir, merged_addr);
                }
            }
        }
    }

    /// The merged site + inner path for a `merged-<type>/<address>/<path>` path,
    /// if it is one (else `None`).
    pub fn split_merged_path(inner_path: &str) -> Option<(String, String)> {
        let rest = inner_path.strip_prefix("merged-")?;
        // merged-<type>/<address>/<inner_path>
        let mut parts = rest.splitn(3, '/');
        let _type = parts.next()?;
        let address = parts.next()?.to_string();
        let inner = parts.next().unwrap_or("").to_string();
        Some((address, inner))
    }

    // --- publish / sign ------------------------------------------------------

    /// The transport used to publish updates to peers.
    pub async fn set_transport(&self, transport: Arc<dyn Transport>) {
        *self.transport.write().await = Some(transport);
    }

    /// The transport set by the node, once available.
    pub async fn transport(&self) -> Option<Arc<dyn Transport>> {
        self.transport.read().await.clone()
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
    /// or an empty list when none is installed.
    pub async fn find_peers_dht(&self, address: &str) -> Vec<PeerAddr> {
        let hook = self.peer_finder.read().await.clone();
        match hook {
            Some(hook) => hook.find(address).await,
            None => Vec::new(),
        }
    }

    /// Ensure `host` (a `.epix` name) is served, resolving + cloning it on demand
    /// if a resolver is installed and it isn't served yet. Returns whether it is
    /// now served. Used by the browser proxy path so typing any `talk.epix`
    /// clones and opens it live.
    pub async fn ensure_xite(&self, host: &str) -> bool {
        if self.has_xite(host).await {
            return true;
        }
        let hook = self.on_demand.read().await.clone();
        match hook {
            Some(hook) => {
                if let Err(e) = hook.ensure(host).await {
                    self.log("INFO", format!("On-demand resolve of {host} failed: {e}")).await;
                }
                self.has_xite(host).await
            }
            None => false,
        }
    }

    /// Mark a xite owned/not (`siteSetOwned`). Signing still requires the key.
    pub async fn set_owned(&self, address: &str, owned: bool) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.own = owned;
        }
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
        let content = self.content(address).await;
        let signers = if inner_path.starts_with("data/users/") {
            // User content: signed by the user's own auth key for this xite.
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

    /// Write a file into a xite's storage (`fileWrite`).
    pub async fn write_file(&self, address: &str, inner_path: &str, bytes: &[u8]) -> Result<(), String> {
        let storage = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| x.storage.clone())
            .ok_or("unknown xite")?;
        storage.write(inner_path, bytes).map_err(|e| e.to_string())
    }

    /// Delete a file from a xite's storage (`fileDelete`). If the file is an
    /// optional file, its `files_optional` entry is removed from the stored
    /// content.json as well (matching EpixNet's `actionFileDelete`; the
    /// content.json becomes changed-needs-signing).
    pub async fn delete_file(&self, address: &str, inner_path: &str) -> Result<(), String> {
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
                            if let Ok(out) = serde_json::to_vec(&json) {
                                let _ = storage.write("content.json", &out);
                            }
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
        self.push_site_info_event(address, "file_deleted").await;
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
        xite.content = content;

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

    /// Publish `inner_path` to the xite's connectable peers via the `update`
    /// command. Returns how many peers accepted it. `sitePublish`.
    pub async fn publish(&self, address: &str, inner_path: &str) -> Result<usize, String> {
        self.publish_to(address, inner_path, 20).await
    }

    /// Publish to at most `limit` connectable peers. The re-broadcast of an
    /// accepted inbound update uses a small limit (EpixNet uses 3) so a push
    /// floods the network without every node hammering every peer.
    pub async fn publish_to(
        &self,
        address: &str,
        inner_path: &str,
        limit: usize,
    ) -> Result<usize, String> {
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
        let peers = self.connectable_peers(address, limit).await;

        let mut published = 0;
        for peer in peers {
            let Ok(mut conn) = Connection::connect(transport.as_ref(), &peer).await else { continue };
            if conn.handshake().await.is_err() {
                continue;
            }
            if conn.update(address, inner_path, &body, modified).await.is_ok() {
                self.set_peer_connected(address, &peer, true).await;
                published += 1;
                // Live-hook: tell the peer (acting as a propagation node) about
                // the new version so peers that are offline now can pull it later.
                let _ = epix_propagation::announce_update(&mut conn, address, modified as i64).await;
            }
        }
        Ok(published)
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
        // Only accept pushes for sites we voluntarily downloaded.
        let (downloaded, current_modified) = {
            let xites = self.xites.read().await;
            let x = xites.get(&key).ok_or("Unknown site")?;
            let current = x
                .content
                .as_ref()
                .and_then(|c| c.get("modified"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            (x.settings.downloaded.is_some(), current)
        };
        if !downloaded {
            return Err("Site not yet downloaded".into());
        }
        if !inner_path.ends_with("content.json") {
            return Err("Only content.json update allowed".into());
        }
        // The engine verifies the root signature only so far; nested/user
        // content.json verification is the content-rules parity work (Tier 0).
        if inner_path != "content.json" {
            return Err(format!(
                "File {inner_path} invalid: non-root content.json updates not supported yet"
            ));
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
                        tokio::time::timeout(std::time::Duration::from_secs(10), async {
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
        let limit = self.size_limit_bytes(&key).await;
        if let Err(e) = xite.set_content_limited(&bytes, limit) {
            self.updates_in_flight.lock().unwrap().remove(&uri);
            return Err(format!("File {inner_path} invalid: {e}"));
        }
        for k in &keys {
            self.update_content(k, xite.content.clone()).await;
        }
        if let Some(s) = &sender {
            self.add_peers(&key, [s.clone()]).await;
        }

        // Download the changed files and re-publish in the background, like
        // EpixNet - the sender gets its "ok" response right away.
        let state = self.clone();
        let inner = inner_path.to_string();
        tokio::spawn(async move {
            state.finish_inbound_update(keys, xite, sender, inner, uri, diffs).await;
        });
        Ok(InboundUpdate::Applied)
    }

    /// The deferred half of [`Self::apply_inbound_update`]: apply any diffs the
    /// publisher sent (patching our old file copies to skip downloads), sync the
    /// files still needed (preferring the sender), rebuild db views, then
    /// re-publish to a few peers so the update spreads.
    async fn finish_inbound_update(
        &self,
        keys: Vec<String>,
        xite: Xite,
        sender: Option<PeerAddr>,
        inner_path: String,
        uri: String,
        diffs: HashMap<String, Vec<epix_content::DiffAction>>,
    ) {
        let key = keys[0].clone();
        // Apply diffs first: patch our old copy of each changed file and keep it
        // only if the result matches the new content.json's declared hash. A
        // bad/mismatched diff is ignored - the file just gets downloaded below.
        if !diffs.is_empty() {
            let mut patched = 0;
            for (file_path, actions) in &diffs {
                let Some(info) = xite.file_info(file_path) else { continue };
                if xite.storage.verify(file_path, &info.sha512) {
                    continue; // already current
                }
                let Ok(old) = xite.storage.read(file_path) else { continue };
                let Ok(new) = epix_content::patch(&old, actions) else { continue };
                if XiteStorage::hash_bytes(&new) == info.sha512
                    && xite.storage.write(file_path, &new).is_ok()
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
            if let Some(s) = sender {
                if !peers.contains(&s) {
                    peers.insert(0, s);
                }
            }
            let needed = xite.files_needed().len();
            if needed > 0 && !peers.is_empty() {
                self.set_worker_stats(&key, needed, peers.len().min(8), needed).await;
                if let Ok(report) =
                    epix_worker::sync_files(&xite, &peers, transport.clone(), 8).await
                {
                    self.add_transfer(&key, report.bytes, 0).await;
                }
                self.set_worker_stats(&key, 0, 0, 0).await;
                // Data files changed - rebuild the db views under every alias.
                for k in &keys {
                    self.update_content(k, xite.content.clone()).await;
                }
            }
            // EpixNet re-publishes an accepted update to up to 3 more peers.
            let _ = self.publish_to(&key, &inner_path, 3).await;
        }
        self.updates_in_flight.lock().unwrap().remove(&uri);
        // Flash the dashboard row: a peer pushed a new version and it landed.
        for k in &keys {
            self.push_site_info_event(k, "updated").await;
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
        let mut stack = vec![start];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&root) {
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
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.size_limit = Some(size_limit_mb);
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

    /// Remember a dismissed notification center id (`notificationDismiss`), so a
    /// dismissed banner stays dismissed across reloads.
    pub async fn notification_dismiss(&self, center: &str) {
        let mut list = self
            .config_get("notification_dismissed")
            .await
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        if !list.iter().any(|v| v.as_str() == Some(center)) {
            list.push(json!(center));
            self.config_set("notification_dismissed", json!(list)).await;
        }
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
        let xid_directory = format!("users/{auth_address}");

        let address_hash = hex::encode(Sha256::digest(address.as_bytes()));
        let short = if address.len() > 6 { &address[..6] } else { address };
        let size_limit = settings.size_limit(DEFAULT_SIZE_LIMIT_MB);
        let next_size_limit = next_size_limit(settings.size);
        let content = entry.content.as_ref().map(summarize_content).unwrap_or(Value::Null);

        // peers = max(settings, known) + self (we serve it), matching formatSiteInfo.
        let known_peers = entry.peers.len() as i64;
        let mut peers = settings.peers.max(known_peers);
        if settings.serving {
            peers += 1;
        }

        json!({
            "auth_address": auth_address,
            "cert_user_id": cert_user_id,
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
fn build_xite_db(storage: &XiteStorage, muted: &[String]) -> Option<(Database, DbSchema)> {
    let bytes = storage.read("dbschema.json").ok()?;
    let schema = DbSchema::from_json(&String::from_utf8_lossy(&bytes)).ok()?;
    let db = Database::open_in_memory().ok()?;
    db.apply_schema(&schema).ok()?;
    // A version-3 merger db is filled from its merged sites (rebuild_merger_dbs),
    // not from its own files; everything else populates from its own tree -
    // skipping muted authors' data files (ContentFilter enforcement).
    if schema.version != 3 {
        let _ = db.populate_filtered(&schema, storage.root(), muted);
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
        assert_eq!(info["xid_directory"].as_str().unwrap(), format!("users/{}", info["auth_address"].as_str().unwrap()));

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

        assert_eq!(info["size_limit"], 10);
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
    async fn db_query_returns_real_rows_from_the_xite_db() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Blog","db_file":"db/db.db","version":2,
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

    #[tokio::test]
    async fn optional_limit_evicts_oldest_unpinned_and_keeps_pinned() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        // Three 1000-byte optional files.
        for name in ["a.bin", "b.bin", "c.bin"] {
            storage.write(name, &vec![0u8; 1000]).unwrap();
        }
        let addr = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t";
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
                br#"{ "db_name":"Blog","db_file":"db/db.db","version":2,
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
        assert_eq!(state.console_log_read().await["num_found"], 1);

        // Lowering the threshold lets INFO through again.
        state.config_set("log_level", json!("INFO")).await;
        state.log("INFO", "now visible").await;
        assert_eq!(state.console_log_read().await["num_found"], 2);
    }

    #[tokio::test]
    async fn notification_count_reads_the_count_column_not_row_count() {
        let dir = tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "dbschema.json",
                br#"{ "db_name":"Blog","db_file":"db/db.db","version":2,
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
        state.add_xite(addr, XiteEntry { storage, content: None }).await;
        // A COUNT(*) subscription must report the column value (3), not 1 row.
        state
            .notification_subscribe(addr, json!({ "unread": ["SELECT COUNT(*) AS count FROM post", null] }))
            .await;
        let q = state.notification_query().await;
        assert_eq!(q["num"], 3);
        assert_eq!(q["results"][0]["count"], 3);
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
        let state = AppState::with_data_dir("test", root.path().join(addr));
        let site_dir = root.path().join(addr);
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
            std::fs::read(root.path().join("sites.json"))
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
    async fn delete_drops_user_site_data() {
        // EpixNet parity: siteDelete also forgets the site's per-user data
        // (derived auth identity, feed follows), like `user.deleteSiteData`.
        let root = tempdir().unwrap();
        let addr = "1ForgetMe";
        // Keep the node's users.json outside the site dir (as in production,
        // where it lives in the launch xite's dir) so deleting the site does
        // not delete the store itself.
        let state = AppState::with_data_dir("test", root.path().join("node"));
        let site_dir = root.path().join(addr);
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
        assert_eq!(state.console_log_read().await["num_found"], 3);
    }

    #[tokio::test]
    async fn console_stream_returns_id_and_pushes_loglineadd() {
        let state = AppState::new("test");
        // Opening a stream returns a real id (was null before -> UI crash).
        let sid = state.console_log_stream_open().await;
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
        let read = state.console_log_read().await;
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
        use std::io::Write;
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
        let addr = "epix1dashuu6pvsut7aw9dx44f543mv7xt9zlydsj9t";
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
                br#"{ "db_name":"Merger","db_file":"db.db","version":3,
                     "maps": { "data/.*/data.json": { "to_table": [{"node":"posts","table":"post"}] } },
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

        // The pushed confirm event carries a `to` id we reply to.
        let ev = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
            .await
            .unwrap()
            .unwrap();
        let payload: Value = serde_json::from_str(&ev.payload).unwrap();
        assert_eq!(payload["cmd"], "confirm");
        let to = payload["to"].as_i64().unwrap();
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
}
