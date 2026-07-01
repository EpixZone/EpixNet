//! Shared server state: the xites this node serves (with their runtime
//! settings + stats), the local user identity, and node metadata.

use epix_core::PeerAddr;
use epix_peer::{PeerCounts, Peers};
use epix_user::User;
use epix_xite::{content_stats, XiteSettings, XiteStorage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Default per-xite size limit, in MB (matches EpixNet's `config.size_limit`).
const DEFAULT_SIZE_LIMIT_MB: i64 = 10;

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
    /// Known peers (from discovery/PEX/DHT/announces).
    peers: Peers,
    /// Total bytes transferred for this xite this run.
    bytes_recv: u64,
    bytes_sent: u64,
    /// Live worker accounting.
    tasks_active: usize,
    started_task_num: usize,
    workers: usize,
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
        })
    }

    /// Node whose user identity persists in `data_dir/users.json`, so the same
    /// per-xite auth addresses are used across restarts.
    pub fn with_data_dir(version: impl Into<String>, data_dir: impl Into<PathBuf>) -> Arc<Self> {
        let dir = data_dir.into();
        let _ = std::fs::create_dir_all(&dir);
        let user_path = dir.join("users.json");
        let user = User::load_or_create(&user_path).unwrap_or_else(|_| User::generate());
        Arc::new(Self {
            version: version.into(),
            xites: RwLock::new(HashMap::new()),
            user: RwLock::new(user),
            user_path: Some(user_path),
            nonce_counter: AtomicU64::new(1),
            global_settings: RwLock::new(json!({ "theme": "light" })),
        })
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
        // The local node administers what it serves.
        settings.permissions.push("ADMIN".to_string());
        if let Some(content) = &entry.content {
            settings.apply_content_stats(&content_stats(content));
        }
        self.xites.write().await.insert(
            address,
            ManagedXite {
                storage: entry.storage,
                content: entry.content,
                settings,
                peers: Peers::new(),
                bytes_recv: 0,
                bytes_sent: 0,
                tasks_active: 0,
                started_task_num: 0,
                workers: 0,
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

    pub async fn has_xite(&self, address: &str) -> bool {
        self.xites.read().await.contains_key(address)
    }

    /// Read a file from a served xite's storage.
    pub async fn read_file(&self, address: &str, inner_path: &str) -> Option<Vec<u8>> {
        let xites = self.xites.read().await;
        xites.get(address)?.storage.read(inner_path).ok()
    }

    /// A clone of a xite's content.json, if loaded.
    pub async fn content(&self, address: &str) -> Option<Value> {
        self.xites.read().await.get(address)?.content.clone()
    }

    /// Set the known peer count for a xite (from discovery), persisting nothing
    /// here — it's derived runtime state.
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

    /// Build the `siteInfo` response for a xite — EpixNet's `formatSiteInfo`.
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
    }
}

/// content.json trimmed for `siteInfo`: `files`/`files_optional`/`includes`
/// become counts, and the signatures are stripped (matches `formatSiteInfo`).
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
        assert!(info["settings"]["permissions"].as_array().unwrap().iter().any(|p| p == "ADMIN"));

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
}
