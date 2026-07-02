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

/// How many warm peer connections the node keeps for live connection stats.
const CONNECTION_POOL_MAX: usize = 8;

/// Editable node config keys shown on the Config page: `(key, label, default)`.
pub const CONFIG_SCHEMA: &[(&str, &str, &str)] = &[
    ("language", "Interface language", "en"),
    ("chain_rpc_url", "Chain RPC URL", "https://api.epix.zone"),
    ("chain_evm_rpc_url", "Chain EVM RPC URL", "https://evmrpc.epix.zone"),
    ("chain_block_explorer_url", "Block explorer URL", "https://scan.epix.zone"),
];

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

fn empty_filters() -> Value {
    json!({ "mutes": {}, "siteblocks": {} })
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
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
            pins_path: None,
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
        let disabled = self.disabled_plugins().await;
        self.plugins.read().await.iter().filter(|n| !disabled.contains(*n)).cloned().collect()
    }

    /// All loaded plugins with their enabled state (`[(name, enabled)]`), for the
    /// plugin manager.
    pub async fn plugin_states(&self) -> Vec<(String, bool)> {
        let disabled = self.disabled_plugins().await;
        self.plugins.read().await.iter().map(|n| (n.clone(), !disabled.contains(n))).collect()
    }

    /// Whether a plugin is currently enabled (unknown plugins default enabled).
    pub async fn plugin_enabled(&self, name: &str) -> bool {
        !self.disabled_plugins().await.iter().any(|n| n == name)
    }

    /// Enable/disable a plugin at runtime (persisted). Takes effect on the next
    /// page load / command - no restart.
    pub async fn set_plugin_enabled(&self, name: &str, enabled: bool) {
        let mut disabled = self.disabled_plugins().await;
        disabled.retain(|n| n != name);
        if !enabled {
            disabled.push(name.to_string());
        }
        self.config_set("plugins_disabled", json!(disabled)).await;
    }

    /// The persisted list of disabled plugin names.
    async fn disabled_plugins(&self) -> Vec<String> {
        self.config_get("plugins_disabled")
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
        for (key, _label, default) in CONFIG_SCHEMA {
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
        self.xites.write().await.insert(
            address,
            ManagedXite {
                storage: entry.storage,
                content: entry.content,
                settings,
                db,
                db_schema,
                peers,
                bytes_recv: 0,
                bytes_sent: 0,
                tasks_active: 0,
                started_task_num: 0,
                workers: 0,
                pinned,
            },
        );
    }

    /// Add discovered peers to a xite, syncing `settings.peers` to the count.
    pub async fn add_peers(&self, address: &str, addrs: impl IntoIterator<Item = PeerAddr>) {
        let mut xites = self.xites.write().await;
        if let Some(x) = xites.get_mut(address) {
            x.peers.add_many(addrs, now_secs());
            x.settings.peers = x.peers.len() as i64;
        }
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
        self.push_announcer_info().await;
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
        *self.port_opened.write().await = opened;
        *self.ip_external.write().await = ip_external;
    }

    /// The fileserver's reachability for `serverInfo`: `(port_opened, ip_external)`.
    pub async fn port_status(&self) -> (bool, Option<String>) {
        (*self.port_opened.read().await, self.ip_external.read().await.clone())
    }

    /// Set the fileserver (seeding) port the node bound, for `serverInfo`.
    pub async fn set_fileserver_port(&self, port: u16) {
        *self.fileserver_port.write().await = port;
    }

    /// The fileserver (seeding) port, 0 if seeding is disabled.
    pub async fn fileserver_port(&self) -> u16 {
        *self.fileserver_port.read().await
    }

    /// The node's homepage xite - where the standalone admin pages' "back"
    /// button returns to. Prefers a human-readable alias (e.g. `dashboard.epix`)
    /// over the canonical address, else the first served xite.
    pub async fn homepage(&self) -> Option<String> {
        let xites = self.xites.read().await;
        xites.keys().find(|k| k.contains('.')).or_else(|| xites.keys().next()).cloned()
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

            // Verify + apply the newer content.json, then sync its changed files.
            let mut xite = Xite::new(
                Address::parse(canonical.clone()).map_err(|e| e.to_string())?,
                view.storage.clone(),
            );
            xite.set_content(&bytes).map_err(|e| e.to_string())?; // checks signature + writes
            self.update_content(address, xite.content.clone()).await;

            let needed = xite.files_needed().len();
            let workers = peers.len().min(8);
            self.set_worker_stats(address, needed, workers, needed).await;
            let report = epix_worker::sync_files(&xite, &peers, transport.clone(), 8)
                .await
                .map_err(|e| e.to_string())?;
            self.set_worker_stats(address, 0, 0, 0).await;
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
                // Count optional bytes downloaded.
                if xite.optional_files().iter().any(|f| f.inner_path == inner_path) {
                    if let Some(x) = self.xites.write().await.get_mut(address) {
                        x.settings.optional_downloaded += info.size;
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
        for address in addresses {
            self.push_site_info(&address).await;
        }
    }

    /// Live connection stats (`connection`, `connection_in`, `connection_onion`,
    /// ping avg/min) for the chart collector.
    pub async fn connection_stats(&self) -> crate::conn_pool::ConnectionStats {
        self.conn_pool.stats().await
    }

    // --- Server-pushed UI events --------------------------------------------

    // --- Console log buffer -------------------------------------------------

    /// Maximum log lines kept for the console.
    const LOG_CAPACITY: usize = 300;

    /// Record a log line for the dashboard console and echo it to stdout.
    /// `level` is `INFO`/`WARNING`/`ERROR`. Feeds both `serverErrors` (tuples)
    /// and any open sidebar-console stream (`logLineAdd`, formatted strings).
    pub async fn log(&self, level: &str, message: impl Into<String>) {
        let message = message.into();
        println!("[{level}] {message}");
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
    pub async fn push_announcer_info(&self) {
        let params = json!({ "stats": self.announcer_stats().await });
        self.push_event("setAnnouncerInfo", params, Some("announcerChanged"), None);
    }

    /// Push a wrapper notification (`["info"|"done"|"error", message,
    /// timeout_ms]`). Ungated - notifications reach every connection.
    pub fn push_notification(&self, kind: &str, message: &str, timeout_ms: i64) {
        self.push_event("notification", json!([kind, message, timeout_ms]), None, None);
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
        let body = self
            .xites
            .read()
            .await
            .get(address)
            .and_then(|x| x.storage.read(inner_path).ok())
            .ok_or("nothing to publish")?;
        // The version we're publishing, for the offline-peer propagation hint.
        let modified = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|c| c.get("modified").and_then(|v| v.as_i64()))
            .unwrap_or(0);
        let transport = self.transport.read().await.clone().ok_or("no transport for publishing")?;
        let peers = self.connectable_peers(address, 20).await;

        let mut published = 0;
        for peer in peers {
            let Ok(mut conn) = Connection::connect(transport.as_ref(), &peer).await else { continue };
            if conn.handshake().await.is_err() {
                continue;
            }
            if conn.update(address, inner_path, &body).await.is_ok() {
                self.set_peer_connected(address, &peer, true).await;
                published += 1;
                // Live-hook: tell the peer (acting as a propagation node) about
                // the new version so peers that are offline now can pull it later.
                let _ = epix_propagation::announce_update(&mut conn, address, modified).await;
            }
        }
        Ok(published)
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
    /// Returns false if the xite isn't served here.
    pub async fn remove_xite(&self, address: &str) -> bool {
        let removed = self.xites.write().await.remove(address);
        match removed {
            Some(x) => {
                // Best-effort delete of the xite's storage directory.
                let root = x.storage.root().to_path_buf();
                let _ = std::fs::remove_dir_all(&root);
                self.persist_peers().await;
                true
            }
            None => false,
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
                vec![("Sidebar".to_string(), false), ("Stats".to_string(), true)]
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
}
