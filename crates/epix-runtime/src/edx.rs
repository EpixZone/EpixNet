//! EDX serving glue: an `AppState`-backed [`SignedProvider`] and the
//! accept-hook that plugs the EDX protocol server into the node's TCP
//! accept loop via [`epix_protocol::PeerServer::with_edx`]. Installed only
//! when an EDX object store is present on the node (see [`enable_serving`]);
//! otherwise the node serves msgpack only, unchanged.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use epix_blob::store::Store;
use epix_blob::{Ns, ObjId};
use epix_core::PeerAddr;
use epix_edx::choke::Choker;
use epix_edx::conn::Conn;
use epix_edx::sched::{needed_groups, Deadline, PeerHandle, Swarm};
use epix_edx::server::{client_hello, serve, PeerIdentity, ServeCtx, SignedProvider};
use epix_edx::sim::Class;
use epix_protocol::server::EdxHook;
use epix_transport::Transport;
use epix_ui::state::{EdxFetcher, InboundUpdate};
use epix_ui::AppState;

/// A shared upload governor for reciprocity choking (seed -> faster
/// service): the serve side consults it, the fetch side credits peers that
/// serve us. Opt-in via EPIX_EDX_RECIPROCITY.
pub type SharedChoker = Arc<Mutex<Choker>>;

/// Global upload cap (bytes/sec) for reciprocity-governed serving. Generous
/// by default; reciprocity is opt-in and this only bites when it is on.
const EDX_UPLOAD_CAP_BPS: u64 = 8_000_000;

/// Default object-store byte quota. Own (pinned) content is exempt; cached
/// content fetched from others is evicted LRU past this. Override with
/// EPIX_EDX_STORE_QUOTA_BYTES.
const EDX_STORE_QUOTA_BYTES: u64 = 8 << 30; // 8 GiB

fn store_quota() -> u64 {
    std::env::var("EPIX_EDX_STORE_QUOTA_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(EDX_STORE_QUOTA_BYTES)
}

/// True unless `var` is explicitly set to a falsey value (`0`/`false`);
/// unset means the default. Used for the default-on EDX kill switches.
pub fn env_on(var: &str) -> bool {
    std::env::var(var)
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

/// The shared upload governor. On by default (reciprocity: seed -> faster
/// service); `EPIX_EDX_RECIPROCITY=0` disables it and serves everything
/// ungoverned. One instance is shared between serving and fetching.
pub fn make_choker() -> Option<SharedChoker> {
    if env_on("EPIX_EDX_RECIPROCITY") {
        Some(Arc::new(Mutex::new(Choker::new(EDX_UPLOAD_CAP_BPS))))
    } else {
        None
    }
}

/// Unix seconds, for object last-access stamps.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Backs epix-edx's signed-content requests with the node's live xite
/// registry (raw content.json bytes, listModified, inbound update apply).
struct AppStateProvider {
    state: Arc<AppState>,
}

#[async_trait::async_trait]
impl SignedProvider for AppStateProvider {
    async fn get_signed(&self, xite: &str, inner_path: &str) -> Option<Vec<u8>> {
        self.state.read_file(xite, inner_path).await
    }

    async fn list_signed(&self, xite: &str, since: u64) -> Vec<(String, u64, u64)> {
        // list_modified keys each changed content.json by its `modified`
        // time; per-file byte size is not tracked here, so report 0.
        self.state
            .list_modified(xite, since as f64)
            .await
            .into_iter()
            .filter_map(|(path, v)| v.as_f64().map(|m| (path, m as u64, 0u64)))
            .collect()
    }

    async fn xite_summary(&self, xite: &str) -> Option<(u64, u64, u64)> {
        let m = self.state.list_modified(xite, 0.0).await;
        if m.is_empty() {
            return None;
        }
        let newest = m.values().filter_map(|v| v.as_f64()).fold(0.0_f64, f64::max) as u64;
        Some((m.len() as u64, newest, 0))
    }

    async fn apply_update(
        &self,
        xite: &str,
        inner_path: &str,
        signed: &[u8],
        _inline: &[(ObjId, Vec<u8>)],
    ) -> Result<bool, String> {
        // Bridge to the existing inbound-update path: the signed bytes are
        // the content.json body. Inline objects and per-record diffs ride
        // the propagation stage; a whole signed body is enough here.
        match self
            .state
            .apply_inbound_update(
                xite,
                inner_path,
                Some(signed.to_vec()),
                None,
                None,
                HashMap::new(),
                Vec::new(),
            )
            .await
        {
            Ok(InboundUpdate::Applied) => Ok(true),
            Ok(InboundUpdate::NotChanged) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Build the CLEARNET accept-hook: an EDX-sniffed TCP stream gets Noise-XX
/// then the EDX serve loop, backed by `store` and the node's xite registry.
/// `privatekey` is this node's EDX identity key, used for the Hello channel
/// binding.
pub fn edx_hook(
    state: Arc<AppState>,
    store: Arc<Store>,
    privatekey: String,
    choker: Option<SharedChoker>,
) -> EdxHook {
    let provider: Arc<dyn SignedProvider> = Arc::new(AppStateProvider { state });
    Arc::new(move |_peer: PeerAddr, stream| {
        let store = store.clone();
        let provider = provider.clone();
        let privatekey = privatekey.clone();
        let choker = choker.clone();
        Box::pin(async move {
            let l = match epix_edx::link::accept(stream).await {
                Ok(l) => l,
                Err(_) => return,
            };
            let mut ctx = ServeCtx::new(store, provider, privatekey);
            if let Some(c) = choker {
                ctx = ctx.with_choker(c);
            }
            serve(l.conn, l.incoming, Arc::new(ctx), Some(l.handshake_hash)).await;
        })
    })
}

/// Build the OVERLAY accept-hook (Tor/I2P/Reticulum): the transport already
/// encrypts, so this skips Noise and serves with no channel binding.
pub fn edx_hook_overlay(
    state: Arc<AppState>,
    store: Arc<Store>,
    privatekey: String,
    choker: Option<SharedChoker>,
) -> EdxHook {
    let provider: Arc<dyn SignedProvider> = Arc::new(AppStateProvider { state });
    Arc::new(move |_peer: PeerAddr, stream| {
        let store = store.clone();
        let provider = provider.clone();
        let privatekey = privatekey.clone();
        let choker = choker.clone();
        Box::pin(async move {
            let (conn, incoming) = match epix_edx::link::accept_overlay(stream).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut ctx = ServeCtx::new(store, provider, privatekey);
            if let Some(c) = choker {
                ctx = ctx.with_choker(c);
            }
            serve(conn, incoming, Arc::new(ctx), None).await;
        })
    })
}

/// The shared EDX serve context: one object store, identity key, and
/// reciprocity governor, built once and reused by every transport's accept
/// loop (clearnet + overlays) so credit and storage are unified.
#[derive(Clone)]
pub struct EdxServe {
    state: Arc<AppState>,
    store: Arc<Store>,
    privatekey: String,
    choker: Option<SharedChoker>,
}

impl EdxServe {
    /// The clearnet (Noise) accept hook for [`epix_protocol::PeerServer`].
    pub fn clearnet_hook(&self) -> EdxHook {
        edx_hook(self.state.clone(), self.store.clone(), self.privatekey.clone(), self.choker.clone())
    }
    /// The overlay (no-Noise) accept hook for Tor/I2P/Reticulum.
    pub fn overlay_hook(&self) -> EdxHook {
        edx_hook_overlay(self.state.clone(), self.store.clone(), self.privatekey.clone(), self.choker.clone())
    }
}

/// Lazily-shared EDX serve context so every accept loop initializes the same
/// store/key/choker exactly once regardless of which transport comes up first.
pub type EdxServeCell = Arc<tokio::sync::Mutex<Option<EdxServe>>>;

/// A fresh, uninitialized shared EDX serve cell (built in `start`, cloned
/// into each transport's accept loop).
pub fn new_serve_cell() -> EdxServeCell {
    Arc::new(tokio::sync::Mutex::new(None))
}

/// This node's EDX identity key (hex), for the Hello channel binding.
/// Persisted under the data dir as `edx-node.key` so a node keeps its
/// identity (and reciprocity standing) across restarts; falls back to a fresh
/// per-boot key when there is no data dir or the file is unusable.
pub async fn node_key(state: &Arc<AppState>) -> String {
    let Some(dir) = state.data_root_path() else {
        return epix_crypt::new_seed();
    };
    let path = dir.join("edx-node.key");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let key = existing.trim().to_string();
        if key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return key;
        }
    }
    let key = epix_crypt::new_seed();
    match std::fs::write(&path, &key) {
        Ok(()) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Err(e) => state.log("WARN", format!("could not persist EDX node key: {e}")).await,
    }
    key
}

/// Get (initializing on first call) the shared EDX serve context. Returns
/// None when EDX is disabled (EPIX_EDX=0) or the node keeps no data on disk.
pub async fn ensure_edx_serve(cell: &EdxServeCell, state: &Arc<AppState>) -> Option<EdxServe> {
    if !env_on("EPIX_EDX") {
        return None;
    }
    let mut guard = cell.lock().await;
    if let Some(es) = guard.as_ref() {
        return Some(es.clone());
    }
    let dir = state.data_root_path()?;
    let key = node_key(state).await;
    let choker = make_choker();
    let store = enable_serving(state, &dir, key.clone(), choker.clone()).await?;
    let es = EdxServe { state: state.clone(), store, privatekey: key, choker };
    *guard = Some(es.clone());
    Some(es)
}

/// Fetches a file's bytes over the EDX verified-streaming path: dial the
/// xite's connectable peers as EDX links, learn what each holds, run the
/// swarm scheduler into the object store, then materialize the completed
/// object into the xite's storage. Backs [`AppState`]'s injected fetcher.
struct RuntimeEdxFetcher {
    state: Arc<AppState>,
    privatekey: String,
    /// Shared upload governor; when present, peers that serve us are credited
    /// after each fetch so they earn faster service from us in return.
    choker: Option<SharedChoker>,
}

impl RuntimeEdxFetcher {
    /// Dial `peer`, bring up an EDX link past the Hello gate, and return the
    /// connection plus the peer's authenticated identity.
    async fn dial(
        &self,
        transport: &Arc<dyn Transport>,
        peer: &PeerAddr,
    ) -> Result<(Conn, PeerIdentity), String> {
        let stream = transport.dial(peer).await.map_err(|e| e.to_string())?;
        // A client context: client_hello only reads the key and caps; reuse
        // the AppState provider (harmless) and the object store.
        let store = self.state.edx_store().await.ok_or("no EDX store")?;
        let provider: Arc<dyn SignedProvider> =
            Arc::new(AppStateProvider { state: self.state.clone() });
        let ctx = ServeCtx::new(store, provider, self.privatekey.clone());
        // Clearnet TCP needs Noise; overlays (Tor/I2P/Reticulum) already
        // encrypt, so they skip it and bind with no handshake hash.
        let (conn, hh) = if matches!(peer, PeerAddr::Ip(_)) {
            let l = epix_edx::link::dial(stream).await.map_err(|e| e.to_string())?;
            (l.conn, Some(l.handshake_hash))
        } else {
            let (conn, _in) = epix_edx::link::dial_overlay(stream).await.map_err(|e| e.to_string())?;
            (conn, None)
        };
        let identity =
            client_hello(&conn, &ctx, vec![], hh).await.map_err(|e| e.to_string())?;
        Ok((conn, identity))
    }

    /// Fetch an encrypted-shard file: pull each content-addressed ciphertext
    /// shard (Ns::Shard) from peers, then decrypt with the xite salt from the
    /// signed content.json and materialize the plaintext. A node without the
    /// content.json (a volunteer holding only shards by hash) cannot do this.
    async fn fetch_shard_file(
        &self,
        address: &str,
        inner_path: &str,
        content: &serde_json::Value,
        shard: epix_blob::manifest::ShardEntry,
        store: &Arc<Store>,
    ) -> Result<bool, String> {
        let salt = epix_blob::manifest::edx_salt(content)
            .ok_or("no edx_salt (missing viewing material)")?;
        let now = now_secs();
        let transport = self.state.transport().await.ok_or("no transport")?;
        let peers = self.state.connectable_peers(address, 8).await;

        // Fetch each ciphertext shard object into the store, verified by its
        // BLAKE3 address (== the shard's bao root).
        for c in &shard.chunks {
            let id = c.cipher_addr;
            let csize = c.csize as u64;
            if store.is_complete(id).unwrap_or(false) {
                continue;
            }
            store.ensure_sparse(id, Ns::Shard, csize, now).map_err(|e| e.to_string())?;
            let mut handles: Vec<PeerHandle> = Vec::new();
            let mut node_pks: HashMap<String, Vec<u8>> = HashMap::new();
            for peer in &peers {
                let Ok((conn, identity)) = self.dial(&transport, peer).await else { continue };
                if let Ok((_sz, bits)) = epix_edx::fetch::fetch_bitfield(&conn, id).await {
                    let label = peer.to_string();
                    node_pks.insert(label.clone(), identity.node_pk);
                    handles.push(PeerHandle { conn, class: Class::of_addr(peer), bits, label });
                }
            }
            if handles.is_empty() {
                return Err(format!("no EDX peer holds shard {id}"));
            }
            let needed = needed_groups(store, id, csize).map_err(|e| e.to_string())?;
            let mut swarm = Swarm::new(store.clone(), id, csize);
            let report = swarm
                .fetch(&needed, &handles, Deadline::background(), now)
                .await
                .map_err(|e| e.to_string())?;
            self.credit(&report, &node_pks, now);
            if !store.is_complete(id).map_err(|e| e.to_string())? {
                return Err(format!("shard {id} did not complete"));
            }
        }

        // Decrypt: the store is the shard fetcher, keyed by ciphertext address.
        let chunks: Vec<epix_selfenc::ChunkRef> = shard
            .chunks
            .iter()
            .map(|c| epix_selfenc::ChunkRef {
                plain_hash: c.plain_hash,
                cipher_addr: c.cipher_addr.0,
                len: c.len,
            })
            .collect();
        let mode = if shard.mode == 1 {
            epix_selfenc::Mode::RandomKey
        } else {
            epix_selfenc::Mode::SaltedConvergent
        };
        let plaintext = epix_selfenc::decrypt(mode, &chunks, &salt, |addr| {
            store.read_bytes(epix_blob::ObjId(*addr), now).ok()
        })
        .map_err(|e| e.to_string())?;
        self.state.edx_materialize_file(address, inner_path, &plaintext).await?;
        let _ = store.enforce_quota(store_quota());
        Ok(true)
    }

    /// Credit each peer that delivered groups in `report` for the bytes it
    /// served us (reciprocity), when a shared choker is installed.
    fn credit(&self, report: &epix_edx::sched::FetchReport, node_pks: &HashMap<String, Vec<u8>>, now: u64) {
        let Some(choker) = &self.choker else { return };
        let mut c = choker.lock().expect("choker");
        for (label, groups) in &report.by_peer {
            if let Some(pk) = node_pks.get(label) {
                c.credit_peer(pk, groups * epix_blob::bitfield::GROUP_BYTES, now);
            }
        }
    }

    /// Resolve `inner_path`'s object id + size from the signed content.json.
    async fn resolve(&self, address: &str, inner_path: &str) -> Result<Option<(ObjId, u64)>, String> {
        let content_bytes =
            self.state.read_file(address, "content.json").await.ok_or("no content.json")?;
        let content: serde_json::Value =
            serde_json::from_slice(&content_bytes).map_err(|e| e.to_string())?;
        Ok(epix_blob::manifest::edx_entry(&content, inner_path).map(|e| (e.b3, e.size)))
    }

    /// Dial the xite's connectable peers as EDX links and learn what each
    /// holds of `id`. One link per peer, reused for the whole fetch. Also
    /// returns each peer label's authenticated node key, for crediting.
    async fn build_peers(
        &self,
        address: &str,
        id: ObjId,
    ) -> Result<(Vec<PeerHandle>, HashMap<String, Vec<u8>>), String> {
        let transport = self.state.transport().await.ok_or("no transport")?;
        let peers = self.state.connectable_peers(address, 8).await;
        if peers.is_empty() {
            return Err("no peers".into());
        }
        let mut handles: Vec<PeerHandle> = Vec::new();
        let mut node_pks: HashMap<String, Vec<u8>> = HashMap::new();
        for peer in peers {
            let Ok((conn, identity)) = self.dial(&transport, &peer).await else { continue };
            if let Ok((_sz, bits)) = epix_edx::fetch::fetch_bitfield(&conn, id).await {
                let label = peer.to_string();
                node_pks.insert(label.clone(), identity.node_pk);
                handles.push(PeerHandle { conn, class: Class::of_addr(&peer), bits, label });
            }
        }
        if handles.is_empty() {
            return Err("no EDX peer holds this object".into());
        }
        Ok((handles, node_pks))
    }
}

#[async_trait::async_trait]
impl EdxFetcher for RuntimeEdxFetcher {
    async fn fetch_file(&self, address: &str, inner_path: &str) -> Result<bool, String> {
        let store = self.state.edx_store().await.ok_or("no EDX store")?;
        // Encrypted-shard file: fetch the ciphertext shards and decrypt.
        let content_bytes =
            self.state.read_file(address, "content.json").await.ok_or("no content.json")?;
        let content: serde_json::Value =
            serde_json::from_slice(&content_bytes).map_err(|e| e.to_string())?;
        if let Some(shard) = epix_blob::manifest::edx_shard_entry(&content, inner_path) {
            return self.fetch_shard_file(address, inner_path, &content, shard, &store).await;
        }
        let Some((id, size)) = self.resolve(address, inner_path).await? else {
            return Err("no edx entry for file".into());
        };
        let now = now_secs();

        // Already complete in the store: just materialize it.
        if store.is_complete(id).unwrap_or(false) {
            let bytes = store.read_bytes(id, now).map_err(|e| e.to_string())?;
            self.state.edx_materialize_file(address, inner_path, &bytes).await?;
            return Ok(true);
        }

        let (handles, node_pks) = self.build_peers(address, id).await?;
        store.ensure_sparse(id, Ns::Plain, size, now).map_err(|e| e.to_string())?;
        let needed = needed_groups(&store, id, size).map_err(|e| e.to_string())?;
        let mut swarm = Swarm::new(store.clone(), id, size);
        let report = swarm
            .fetch(&needed, &handles, Deadline::background(), now)
            .await
            .map_err(|e| e.to_string())?;
        self.credit(&report, &node_pks, now);
        if !store.is_complete(id).map_err(|e| e.to_string())? {
            return Err("fetch did not complete".into());
        }

        let bytes = store.read_bytes(id, now).map_err(|e| e.to_string())?;
        self.state.edx_materialize_file(address, inner_path, &bytes).await?;
        // Cached content grows the store; keep it under quota (own content is
        // pinned, so only cached-from-others objects are evicted).
        let _ = store.enforce_quota(store_quota());
        Ok(true)
    }

    async fn fetch_range(
        &self,
        address: &str,
        inner_path: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<Vec<u8>>, String> {
        let store = self.state.edx_store().await.ok_or("no EDX store")?;
        let Some((id, size)) = self.resolve(address, inner_path).await? else {
            return Ok(None);
        };
        let now = now_secs();
        store.ensure_sparse(id, Ns::Plain, size, now).map_err(|e| e.to_string())?;
        let end = start.saturating_add(len).min(size);
        if end <= start {
            return Ok(Some(Vec::new()));
        }

        // Serve straight from the store if the covering range is already
        // present; otherwise fetch just the covering chunk groups (a seek,
        // never the whole file).
        if let Ok(bytes) = store.read_range(id, start, end - start, now) {
            return Ok(Some(bytes));
        }
        let (handles, node_pks) = self.build_peers(address, id).await?;
        let groups = epix_blob::bitfield::groups_for_bytes(&(start..end));
        let mut needed = epix_blob::bitfield::GroupBits::new();
        needed.add(groups.start..groups.end);
        let mut swarm = Swarm::new(store.clone(), id, size);
        let report = swarm
            .fetch(&needed, &handles, Deadline::tight(), now)
            .await
            .map_err(|e| e.to_string())?;
        self.credit(&report, &node_pks, now);
        let bytes = store.read_range(id, start, end - start, now).map_err(|e| e.to_string())?;
        let _ = store.enforce_quota(store_quota());
        Ok(Some(bytes))
    }
}

/// Open the EDX object store under `data_dir/edx-store` and install it plus
/// the verified-streaming fetcher on the node, using `privatekey` as the
/// node's EDX identity. Registers the already-loaded xites so serving does
/// not depend on load order. Returns the store, or None if it could not be
/// opened.
pub async fn enable_serving(
    state: &Arc<AppState>,
    data_dir: &std::path::Path,
    privatekey: String,
    choker: Option<SharedChoker>,
) -> Option<Arc<Store>> {
    let path = data_dir.join("edx-store");
    if let Err(e) = std::fs::create_dir_all(&path) {
        state.log("WARN", format!("EDX store dir {}: {e}", path.display())).await;
        return None;
    }
    let store = match Store::open(&path) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            state.log("WARN", format!("EDX store open {}: {e}", path.display())).await;
            return None;
        }
    };
    state.set_edx_store(store.clone()).await;
    state
        .set_edx_fetcher(Arc::new(RuntimeEdxFetcher {
            state: state.clone(),
            privatekey,
            choker,
        }))
        .await;
    // Register any xites already loaded before the store was installed, so
    // serving does not depend on load order.
    let n = state.edx_register_all_loaded().await;
    state.log("INFO", format!("EDX object store enabled ({n} xite(s) registered)")).await;
    Some(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_blob::{Ns, ObjId};
    use epix_edx::msg::{caps, Req, Resp};
    use epix_edx::server::client_hello;
    use epix_transport::{TcpTransport, Transport};
    use epix_ui::state::XiteEntry;
    use epix_xite::{Xite, XiteStorage};

    /// EDX and reciprocity are on unless explicitly disabled: env_on returns
    /// true when unset, false only for a 0/false value. This is the clean-cut
    /// default (EDX is the transfer protocol; EPIX_EDX=0 is the kill switch).
    #[test]
    fn edx_is_on_by_default() {
        assert!(env_on("EPIX_EDX_A_VAR_THAT_IS_NEVER_SET"), "unset means on");
        std::env::set_var("EPIX_EDX_KILLSWITCH_TEST", "0");
        assert!(!env_on("EPIX_EDX_KILLSWITCH_TEST"), "0 disables");
        std::env::set_var("EPIX_EDX_KILLSWITCH_TEST", "false");
        assert!(!env_on("EPIX_EDX_KILLSWITCH_TEST"), "false disables");
        std::env::set_var("EPIX_EDX_KILLSWITCH_TEST", "1");
        assert!(env_on("EPIX_EDX_KILLSWITCH_TEST"), "1 stays on");
        std::env::remove_var("EPIX_EDX_KILLSWITCH_TEST");
    }

    /// Client-side no-op provider: `client_hello` only needs our key.
    struct NoProvider;
    #[async_trait::async_trait]
    impl SignedProvider for NoProvider {
        async fn get_signed(&self, _: &str, _: &str) -> Option<Vec<u8>> {
            None
        }
        async fn list_signed(&self, _: &str, _: u64) -> Vec<(String, u64, u64)> {
            Vec::new()
        }
        async fn xite_summary(&self, _: &str) -> Option<(u64, u64, u64)> {
            None
        }
        async fn apply_update(
            &self,
            _: &str,
            _: &str,
            _: &[u8],
            _: &[(ObjId, Vec<u8>)],
        ) -> Result<bool, String> {
            Ok(true)
        }
    }

    /// Bring up a seeder node serving an EDX xite (index.html + a 400 KB
    /// movie.bin) on a real TCP port. Returns its address, the signed
    /// content.json bytes + value, the movie bytes, and the socket address.
    async fn spawn_seeder(
    ) -> (String, Vec<u8>, serde_json::Value, Vec<u8>, std::net::SocketAddr, Vec<u8>) {
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let site_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(site_dir.path());
        storage.write("index.html", &vec![b'h'; 5_000]).unwrap();
        let movie: Vec<u8> = (0..400_000usize).map(|i| (i % 251) as u8).collect();
        storage.write("movie.bin", &movie).unwrap();
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        xite.sign(&privkey, 1000.0).unwrap();
        let content_bytes = xite.storage.read("content.json").unwrap();
        let content: serde_json::Value = serde_json::from_slice(&content_bytes).unwrap();

        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(Store::open(store_dir.path()).unwrap());
        state_b.set_edx_store(store_b.clone()).await;
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(site_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await, "load registers files into the store");
        std::mem::forget(site_dir); // keep the on-disk files for the test's life
        std::mem::forget(store_dir);

        let server_key = epix_crypt::new_seed();
        let server_pk = epix_crypt::private_to_compressed_pubkey(&server_key).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(epix_ui::fileserve::FileService::new(state_b.clone()));
        let server = epix_protocol::PeerServer::new(handler)
            .with_edx(edx_hook(state_b.clone(), store_b.clone(), server_key, None));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
        (address, content_bytes, content, movie, addr, server_pk)
    }

    /// End-to-end serve fork: a node with EDX enabled answers an EDX peer's
    /// GetSigned (the signed content.json) and GetRange (bao-verified file
    /// bytes from its object store) over a real TCP socket, on the same port
    /// the msgpack file server uses.
    #[tokio::test]
    async fn edx_peer_gets_signed_content_and_a_verified_file() {
        let (address, content_bytes, content, movie, addr, _server_pk) = spawn_seeder().await;

        // Node A: dial the EDX link (magic sniffed on the shared port).
        let stream = TcpTransport.dial(&epix_core::PeerAddr::Ip(addr)).await.unwrap();
        let l = epix_edx::link::dial(stream).await.unwrap();

        let cdir = tempfile::tempdir().unwrap();
        let client_store = Arc::new(Store::open(cdir.path()).unwrap());
        let cctx = ServeCtx {
            caps: caps::MESH,
            now: || 0,
            ..ServeCtx::new(client_store.clone(), Arc::new(NoProvider), epix_crypt::new_seed())
        };
        client_hello(&l.conn, &cctx, vec![], Some(l.handshake_hash)).await.unwrap();

        // GetSigned returns the exact signed content.json bytes.
        match l.conn.request(Req::GetSigned { xite: address.clone(), inner_path: "content.json".into() }).await.unwrap() {
            Resp::Signed { bytes } => assert_eq!(bytes, content_bytes, "signed content.json round-trips"),
            other => panic!("expected Signed, got {other:?}"),
        }

        // GetRange streams the file, bao-verified into the client store.
        let e = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap();
        let size = movie.len() as u64;
        client_store.ensure_sparse(e.b3, Ns::Plain, size, 1).unwrap();
        let got = epix_edx::fetch::fetch_ranges(&l.conn, &client_store, e.b3, size, &[0..size], 100, 2)
            .await
            .unwrap();
        assert!(got > 0);
        assert!(client_store.is_complete(e.b3).unwrap(), "the whole file transferred");
        assert_eq!(client_store.read_bytes(e.b3, 3).unwrap(), movie, "bytes verify and reassemble");
    }

    /// End-to-end fetch driver: a node with only the signed content.json
    /// pulls a declared file from an EDX peer through the injected fetcher
    /// (dial -> swarm -> materialize), and the bytes land in its storage.
    #[tokio::test]
    async fn a_node_fetches_a_file_from_an_edx_peer() {
        let (address, content_bytes, content, movie, addr, _server_pk) = spawn_seeder().await;

        // Node A: knows B as a peer, has the manifest but not the file.
        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        let a_storage = XiteStorage::new(a_dir.path());
        a_storage.write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: Some(content) })
            .await;
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
        state_a.set_transport(transport).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        let a_store = Arc::new(Store::open(a_store_dir.path()).unwrap());
        state_a.set_edx_store(a_store).await;
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher {
                state: state_a.clone(),
                privatekey: epix_crypt::new_seed(),
                choker: None,
            }))
            .await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;

        // The file is not on disk yet.
        assert!(XiteStorage::new(a_dir.path()).read("movie.bin").is_err());

        // Fetch it over EDX through the injected fetcher.
        let result = state_a.edx_fetch_file(&address, "movie.bin").await;
        assert!(matches!(result, Some(Ok(true))), "edx fetch result: {result:?}");

        // It is now materialized on node A's disk, byte-for-byte.
        let got = XiteStorage::new(a_dir.path()).read("movie.bin").unwrap();
        assert_eq!(got, movie, "fetched file matches the seeder's bytes");
    }

    /// Media seek: a range fetch pulls only the covering bytes (verified),
    /// not the whole file, and the returned bytes match the seeker's slice.
    #[tokio::test]
    async fn a_range_fetch_seeks_without_the_whole_file() {
        let (address, content_bytes, content, movie, addr, _server_pk) = spawn_seeder().await;

        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        XiteStorage::new(a_dir.path()).write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: Some(content.clone()) })
            .await;
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        let a_store = Arc::new(Store::open(a_store_dir.path()).unwrap());
        state_a.set_edx_store(a_store.clone()).await;
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher {
                state: state_a.clone(),
                privatekey: epix_crypt::new_seed(),
                choker: None,
            }))
            .await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;

        // Seek to a mid-file range.
        let (start, len) = (200_000u64, 50_000u64);
        let result = state_a.edx_fetch_range(&address, "movie.bin", start, len).await;
        let bytes = match result {
            Some(Ok(Some(b))) => b,
            other => panic!("range fetch: {other:?}"),
        };
        assert_eq!(bytes, movie[start as usize..(start + len) as usize], "range bytes match");

        // Only the covering groups were fetched: the object is NOT complete.
        let id = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap().b3;
        assert!(!a_store.is_complete(id).unwrap(), "a seek must not pull the whole file");
    }

    /// Encrypted shards end to end: a private file signs into content-
    /// addressed ciphertext shards (its plaintext never enters the plain
    /// `files` map), a seeder holds only ciphertext, and a client that has
    /// the signed content.json (the salt + data-map) fetches the shards over
    /// EDX and decrypts them back to the exact plaintext.
    #[tokio::test]
    async fn a_private_file_transfers_as_encrypted_shards() {
        // Node B: sign a xite with a `shard` pattern; the private file is
        // self-encrypted, so it leaves `files` for `files_shard`.
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let secret = b"the private note nobody but a viewer should read".to_vec();
        let site_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(site_dir.path());
        storage.write("index.html", b"<h1>public</h1>").unwrap();
        storage.write("private/secret.txt", &secret).unwrap();
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        xite.content = Some(serde_json::json!({ "shard": "private/.*" }));
        xite.sign(&privkey, 1000.0).unwrap();
        let content = xite.content.clone().unwrap();
        // The plaintext is NOT in the plain files map; it is a shard entry.
        assert!(content.get("files").and_then(|f| f.get("private/secret.txt")).is_none());
        assert!(epix_blob::manifest::edx_shard_entry(&content, "private/secret.txt").is_some());
        assert!(epix_blob::manifest::edx_salt(&content).is_some());
        let content_bytes = xite.storage.read("content.json").unwrap();

        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(Store::open(store_dir.path()).unwrap());
        state_b.set_edx_store(store_b.clone()).await;
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(site_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await, "load stores shard ciphertext");
        std::mem::forget(site_dir);
        std::mem::forget(store_dir);
        let server_key = epix_crypt::new_seed();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(epix_ui::fileserve::FileService::new(state_b.clone()));
        let server = epix_protocol::PeerServer::new(handler)
            .with_edx(edx_hook(state_b.clone(), store_b.clone(), server_key, None));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // Node A: has the signed content.json (salt + data-map) but not the file.
        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        XiteStorage::new(a_dir.path()).write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: Some(content) })
            .await;
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        state_a.set_edx_store(Arc::new(Store::open(a_store_dir.path()).unwrap())).await;
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher {
                state: state_a.clone(),
                privatekey: epix_crypt::new_seed(),
                choker: None,
            }))
            .await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;

        // Fetch the shard file: fetch ciphertext shards over EDX, decrypt.
        let result = state_a.edx_fetch_file(&address, "private/secret.txt").await;
        assert!(matches!(result, Some(Ok(true))), "shard fetch: {result:?}");
        let got = XiteStorage::new(a_dir.path()).read("private/secret.txt").unwrap();
        assert_eq!(got, secret, "decrypted plaintext matches");
    }

    /// Reciprocity: with a shared choker installed, fetching from a peer
    /// credits that peer (by its authenticated node key) for the bytes it
    /// served us, so it earns faster service in return.
    #[tokio::test]
    async fn fetching_credits_the_serving_peer() {
        let (address, content_bytes, content, _movie, addr, server_pk) = spawn_seeder().await;

        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        XiteStorage::new(a_dir.path()).write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: Some(content) })
            .await;
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        state_a.set_edx_store(Arc::new(Store::open(a_store_dir.path()).unwrap())).await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;

        // Reciprocity on: the fetcher holds the shared choker.
        let choker: SharedChoker = Arc::new(Mutex::new(Choker::new(EDX_UPLOAD_CAP_BPS)));
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher {
                state: state_a.clone(),
                privatekey: epix_crypt::new_seed(),
                choker: Some(choker.clone()),
            }))
            .await;

        assert!(state_a.edx_fetch_file(&address, "movie.bin").await.unwrap().is_ok());

        // The seeder earned reciprocity credit for the bytes it served us.
        let credit = choker.lock().unwrap().credit_of(&server_pk);
        assert!(credit > 0, "the serving peer should be credited, got {credit}");
    }

    /// Latency floor over loopback TCP (real internet adds RTT on top): time
    /// first paint (dial + handshake + a small file), a cold media seek, and
    /// a full 400 KB fetch. Prints the numbers with `--nocapture`.
    #[tokio::test]
    async fn latency_floor_report() {
        use std::time::Instant;
        let (address, content_bytes, content, movie, addr, _pk) = spawn_seeder().await;

        let mk_client = || async {
            let state = AppState::new("client");
            let dir = tempfile::tempdir().unwrap();
            XiteStorage::new(dir.path()).write("content.json", &content_bytes).unwrap();
            state
                .add_xite(&address, XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content.clone()) })
                .await;
            state.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
            let sd = tempfile::tempdir().unwrap();
            state.set_edx_store(Arc::new(Store::open(sd.path()).unwrap())).await;
            state
                .set_edx_fetcher(Arc::new(RuntimeEdxFetcher {
                    state: state.clone(),
                    privatekey: epix_crypt::new_seed(),
                    choker: None,
                }))
                .await;
            state.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;
            std::mem::forget(dir);
            std::mem::forget(sd);
            state
        };

        // First paint: a fresh client dials, handshakes, and fetches the
        // small index.html (5 KB).
        let c1 = mk_client().await;
        let t = Instant::now();
        assert!(c1.edx_fetch_file(&address, "index.html").await.unwrap().is_ok());
        let first_paint = t.elapsed();

        // Cold media seek: a fresh client fetches a 50 KB mid-file range.
        let c2 = mk_client().await;
        let t = Instant::now();
        let seek = c2.edx_fetch_range(&address, "movie.bin", 200_000, 50_000).await.unwrap();
        assert!(matches!(seek, Ok(Some(_))));
        let seek_ms = t.elapsed();

        // Full 400 KB fetch.
        let c3 = mk_client().await;
        let t = Instant::now();
        assert!(c3.edx_fetch_file(&address, "movie.bin").await.unwrap().is_ok());
        let full = t.elapsed();

        eprintln!(
            "EDX latency floor (loopback): first_paint(5KB)={:?}  cold_seek(50KB)={:?}  full_fetch({}KB)={:?}",
            first_paint,
            seek_ms,
            movie.len() / 1000,
            full
        );
        // Sanity: the loopback floor is comfortably under the clearnet target.
        assert!(first_paint.as_millis() < 2500, "first paint floor {first_paint:?}");
    }
}
