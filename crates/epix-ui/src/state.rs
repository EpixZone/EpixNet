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
        let (db, db_schema) = match build_xite_db(&entry.storage) {
            Some((db, schema)) => (Some(db), Some(schema)),
            None => (None, None),
        };
        self.xites.write().await.insert(
            address,
            ManagedXite {
                storage: entry.storage,
                content: entry.content,
                settings,
                db,
                db_schema,
                peers: Peers::new(),
                bytes_recv: 0,
                bytes_sent: 0,
                tasks_active: 0,
                started_task_num: 0,
                workers: 0,
                pinned: std::collections::HashSet::new(),
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
    }

    pub async fn mute_remove(&self, auth_address: &str) {
        if let Some(m) = self.filters.write().await["mutes"].as_object_mut() {
            m.remove(auth_address);
        }
        self.save_filters().await;
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

    // --- OptionalManager -----------------------------------------------------

    /// Reconstruct a `Xite` view (address + storage + content) for file ops.
    async fn xite_view(&self, address: &str) -> Result<Xite, String> {
        let (storage, content) = {
            let x = self.xites.read().await;
            let e = x.get(address).ok_or("unknown xite")?;
            (e.storage.clone(), e.content.clone())
        };
        let mut xite = Xite::new(Address::parse(address.to_string()).map_err(|e| e.to_string())?, storage);
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

        // The piecemap is itself a (small) optional file — fetch it if missing.
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
        if let Some(x) = self.xites.write().await.get_mut(address) {
            x.settings.optional_downloaded = (x.settings.optional_downloaded - info.size).max(0);
            x.pinned.remove(inner_path);
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
    }

    /// Optional-file storage stats. `optionalLimitStats`.
    pub async fn optional_limit_stats(&self, address: &str) -> Value {
        let (used, limit) = self
            .xites
            .read()
            .await
            .get(address)
            .map(|x| (x.settings.optional_downloaded, x.settings.size_optional))
            .unwrap_or((0, 0));
        json!({ "limit": "10%", "used": used, "free": (limit - used).max(0) })
    }

    // --- MergerSite ----------------------------------------------------------

    /// Grant a permission to a xite (e.g. `Merger:ZeroMe`). Idempotent.
    pub async fn add_permission(&self, address: &str, permission: &str) {
        if let Some(x) = self.xites.write().await.get_mut(address) {
            if !x.settings.permissions.iter().any(|p| p == permission) {
                x.settings.permissions.push(permission.to_string());
            }
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

/// Build a xite's database from its `dbschema.json` (if present): open an
/// in-memory db, create the tables, and populate from the xite's JSON data
/// files. `None` if the xite has no schema or building fails.
fn build_xite_db(storage: &XiteStorage) -> Option<(Database, DbSchema)> {
    let bytes = storage.read("dbschema.json").ok()?;
    let schema = DbSchema::from_json(&String::from_utf8_lossy(&bytes)).ok()?;
    let db = Database::open_in_memory().ok()?;
    db.apply_schema(&schema).ok()?;
    // A version-3 merger db is filled from its merged sites (rebuild_merger_dbs),
    // not from its own files; everything else populates from its own tree.
    if schema.version != 3 {
        let _ = db.populate(&schema, storage.root());
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

        let stats = state.optional_limit_stats(addr).await;
        assert!(stats["used"].is_number() && stats["free"].is_number());
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
}
