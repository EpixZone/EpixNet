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
use epix_ui::state::{EdxBatch, EdxBatchProgress, EdxFetcher, EdxPushError, EdxWant, InboundUpdate};
use epix_ui::AppState;

/// Byte-exact wire encoding of one file's diff actions. The EDX push must
/// preserve arbitrary insert bytes: the retired msgpack encoder carried them
/// as binary blobs, but routing through JSON/UTF-8 (`actions_to_value`) would
/// mangle any non-UTF8 byte to U+FFFD and defeat the diff for such files.
/// Layout: u64-LE action count, then per action a tag byte and u64-LE fields
/// (Equal/Remove: one length; Insert: line count, then per line length+bytes).
fn encode_actions(actions: &[epix_content::DiffAction]) -> Vec<u8> {
    use epix_content::DiffAction;
    let mut out = Vec::new();
    out.extend_from_slice(&(actions.len() as u64).to_le_bytes());
    for a in actions {
        match a {
            DiffAction::Equal(n) => {
                out.push(0);
                out.extend_from_slice(&(*n as u64).to_le_bytes());
            }
            DiffAction::Remove(n) => {
                out.push(1);
                out.extend_from_slice(&(*n as u64).to_le_bytes());
            }
            DiffAction::Insert(lines) => {
                out.push(2);
                out.extend_from_slice(&(lines.len() as u64).to_le_bytes());
                for l in lines {
                    out.extend_from_slice(&(l.len() as u64).to_le_bytes());
                    out.extend_from_slice(l);
                }
            }
        }
    }
    out
}

/// Inverse of [`encode_actions`]. Returns None on any truncation or bad tag
/// (the caller drops that file's diff and refetches it whole). Reads only what
/// the buffer holds - a bogus length just runs off the end into None - and
/// never pre-allocates from an untrusted count, so a crafted blob can't OOM.
fn decode_actions(b: &[u8]) -> Option<Vec<epix_content::DiffAction>> {
    use epix_content::DiffAction;
    fn read_u64(b: &[u8], i: &mut usize) -> Option<u64> {
        let end = i.checked_add(8)?;
        let n = u64::from_le_bytes(b.get(*i..end)?.try_into().ok()?);
        *i = end;
        Some(n)
    }
    let mut i = 0usize;
    let count = read_u64(b, &mut i)?;
    let mut actions = Vec::new();
    for _ in 0..count {
        let tag = *b.get(i)?;
        i += 1;
        match tag {
            0 => actions.push(DiffAction::Equal(read_u64(b, &mut i)? as usize)),
            1 => actions.push(DiffAction::Remove(read_u64(b, &mut i)? as usize)),
            2 => {
                let lines_n = read_u64(b, &mut i)?;
                let mut lines = Vec::new();
                for _ in 0..lines_n {
                    let len = read_u64(b, &mut i)? as usize;
                    let end = i.checked_add(len)?;
                    lines.push(b.get(i..end)?.to_vec());
                    i = end;
                }
                actions.push(DiffAction::Insert(lines));
            }
            _ => return None,
        }
    }
    Some(actions)
}

/// Encode the neutral diff map to the EDX wire form (byte-exact per file).
fn encode_edx_diffs(
    diffs: &HashMap<String, Vec<epix_content::DiffAction>>,
) -> Vec<(String, Vec<u8>)> {
    diffs.iter().map(|(path, actions)| (path.clone(), encode_actions(actions))).collect()
}

/// Decode the EDX wire diffs back into the neutral map. A malformed entry is
/// dropped (the receiver just refetches that file whole - diffs are a
/// bandwidth optimization, never a correctness dependency).
fn decode_edx_diffs(
    diffs: &[(String, Vec<u8>)],
) -> HashMap<String, Vec<epix_content::DiffAction>> {
    let mut out = HashMap::new();
    for (path, bytes) in diffs {
        if let Some(actions) = decode_actions(bytes) {
            out.insert(path.clone(), actions);
        }
    }
    out
}

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
        modified: f64,
        diffs: &[(String, Vec<u8>)],
        sender_peers: &[String],
    ) -> Result<bool, String> {
        // Gossip the hint: record (xite, modified) so peers polling us learn a
        // new version exists and catch up fast. Done before (and regardless of)
        // apply, so a node that only relays this site still hints it for
        // others - the store-and-forward reach the retired msgpack announce had.
        self.state.record_update_hint(xite, modified as i64).await;

        // `inline` is not consumed: nothing sends it yet, and inserting pushed
        // objects into the store before apply_inbound_update authorizes the
        // update would let any peer fill our disk. Files land through the
        // verified fetch that the inbound update kicks off instead.
        //
        // Lower the EDX message into what the inbound-update path expects:
        // decode the per-file diffs (so data files patch in place) and parse
        // the publisher's dial-back addresses (unparseable ones dropped).
        let diffs = decode_edx_diffs(diffs);
        let sender_peers: Vec<PeerAddr> =
            sender_peers.iter().filter_map(|s| PeerAddr::parse(s).ok()).take(5).collect();
        match self
            .state
            .apply_inbound_update(
                xite,
                inner_path,
                Some(signed.to_vec()),
                Some(modified),
                None,
                diffs,
                sender_peers,
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

/// Get (initializing on first call) the shared EDX serve context. Returns None
/// only when the node keeps no data on disk (nowhere to put the object store).
/// EDX is the transfer + propagation protocol now, so there is no on/off knob:
/// a node that can serve, does. (Reciprocity and the store quota stay tunable.)
pub async fn ensure_edx_serve(cell: &EdxServeCell, state: &Arc<AppState>) -> Option<EdxServe> {
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

    /// Resolve `inner_path`'s object id + size from the root OR the governing
    /// child/per-user content.json (so forum and per-user files resolve too).
    async fn resolve(&self, address: &str, inner_path: &str) -> Result<Option<(ObjId, u64)>, String> {
        Ok(self.state.edx_resolve(address, inner_path).await)
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

    /// Dial `peers` (up to `cap`) ONCE and keep the links, so a batch fetches
    /// every file over the same connections instead of redialing per file (the
    /// redial-per-file cost of calling `fetch_file` in a loop). Object-
    /// independent: the per-object bitfield is fetched later over these links.
    async fn open_session(&self, peers: &[PeerAddr], cap: usize) -> Vec<SessionPeer> {
        let Some(transport) = self.state.transport().await else { return Vec::new() };
        let mut out = Vec::new();
        for peer in peers.iter().take(cap) {
            if let Ok((conn, identity)) = self.dial(&transport, peer).await {
                out.push(SessionPeer {
                    conn,
                    class: Class::of_addr(peer),
                    label: peer.to_string(),
                    node_pk: identity.node_pk,
                });
            }
        }
        out
    }

    /// Fetch one object over an already-open session (reused links): learn
    /// which links hold it (one bitfield request each), then stripe it with the
    /// swarm. Returns whether the object is complete in the store afterward.
    async fn fetch_one_over_session(
        &self,
        store: &Arc<Store>,
        id: ObjId,
        size: u64,
        session: &[SessionPeer],
        now: u64,
    ) -> bool {
        if store.is_complete(id).unwrap_or(false) {
            return true;
        }
        if store.ensure_sparse(id, Ns::Plain, size, now).is_err() {
            return false;
        }
        let mut handles: Vec<PeerHandle> = Vec::new();
        let mut node_pks: HashMap<String, Vec<u8>> = HashMap::new();
        for p in session {
            if let Ok((_sz, bits)) = epix_edx::fetch::fetch_bitfield(&p.conn, id).await {
                node_pks.insert(p.label.clone(), p.node_pk.clone());
                handles.push(PeerHandle {
                    conn: p.conn.clone(),
                    class: p.class,
                    bits,
                    label: p.label.clone(),
                });
            }
        }
        if handles.is_empty() {
            return false;
        }
        let Ok(needed) = needed_groups(store, id, size) else { return false };
        let mut swarm = Swarm::new(store.clone(), id, size);
        if let Ok(report) = swarm.fetch(&needed, &handles, Deadline::background(), now).await {
            self.credit(&report, &node_pks, now);
        }
        store.is_complete(id).unwrap_or(false)
    }
}

/// One peer's reused EDX link for a batch session (dialed once, borrowed by
/// every file's swarm via a cheap `Conn` clone).
struct SessionPeer {
    conn: Conn,
    class: Class,
    label: String,
    node_pk: Vec<u8>,
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

    async fn fetch_signed(
        &self,
        peer: PeerAddr,
        address: &str,
        inner_path: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let transport = self.state.transport().await.ok_or("no transport")?;
        // Dial an EDX link and ask for the signed bytes. A dial/handshake
        // failure is Err (peer unreachable - score ConnectFail); a live peer
        // that simply does not serve this content answers with an error we
        // map to Ok(None) (score FileFail), so the caller tries another peer.
        let (conn, _identity) = self.dial(&transport, &peer).await?;
        match epix_edx::fetch::fetch_signed(&conn, address, inner_path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => Ok(None),
        }
    }

    async fn fetch_signed_many(
        &self,
        address: &str,
        paths: Vec<String>,
        peers: Vec<PeerAddr>,
    ) -> HashMap<String, Vec<u8>> {
        let mut out = HashMap::new();
        // Dial the peers ONCE and GetSigned every path over the reused links,
        // so a forum's N user content.json files cost N requests on live
        // connections, not N dials per peer.
        let session = self.open_session(&peers, 8).await;
        if session.is_empty() {
            return out;
        }
        for path in paths {
            for p in &session {
                if let Ok(bytes) = epix_edx::fetch::fetch_signed(&p.conn, address, &path).await {
                    out.insert(path, bytes);
                    break;
                }
            }
        }
        out
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

    async fn push_update(
        &self,
        peer: PeerAddr,
        address: &str,
        inner_path: &str,
        signed: Arc<Vec<u8>>,
        modified: f64,
        diffs: Arc<HashMap<String, Vec<epix_content::DiffAction>>>,
        sender_peers: Arc<Vec<String>>,
        progressed: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), EdxPushError> {
        // Dial the peer as an EDX link and push the update. A dial/handshake
        // failure means the peer looks unreachable (back it off); a failure
        // after the link is up means it answered but refused (alive).
        let transport =
            self.state.transport().await.ok_or_else(|| EdxPushError::Unreachable("no transport".into()))?;
        let (conn, _identity) =
            self.dial(&transport, &peer).await.map_err(EdxPushError::Unreachable)?;
        // The link is up: from here a timeout is a slow-but-live peer, not an
        // unreachable one (the caller scores it Refused, not a backoff).
        progressed.store(true, std::sync::atomic::Ordering::Relaxed);

        // Keep the whole Req::Update under the frame cap. The signed
        // content.json is the big, refetchable part - if it would overflow,
        // send it body-less and let the receiver pull it via GetSigned (we
        // are in its sender_peers); only if the diffs alone still overflow do
        // we drop those too and let it refetch the changed files whole.
        const FRAME_BUDGET: usize = 56 * 1024;
        let wire_diffs = encode_edx_diffs(&diffs);
        let diffs_len: usize = wire_diffs.iter().map(|(p, b)| p.len() + b.len() + 16).sum();
        let (body, wire_diffs): (&[u8], Vec<(String, Vec<u8>)>) =
            if signed.len() + diffs_len < FRAME_BUDGET {
                (signed.as_slice(), wire_diffs)
            } else if diffs_len < FRAME_BUDGET {
                (&[], wire_diffs)
            } else {
                (&[], Vec::new())
            };
        epix_edx::fetch::push_update(
            &conn,
            address,
            inner_path,
            body,
            modified,
            wire_diffs,
            sender_peers.as_ref().clone(),
            Vec::new(),
        )
        .await
        .map_err(|e| EdxPushError::Refused(e.to_string()))
    }

    async fn fetch_files(
        &self,
        address: &str,
        want: Vec<EdxWant>,
        peers: Vec<PeerAddr>,
        on_file: Option<EdxBatchProgress>,
    ) -> EdxBatch {
        let mut batch = EdxBatch { done: Vec::new(), missed: Vec::new(), bytes: 0 };
        let Some(store) = self.state.edx_store().await else {
            // No store: every file falls back to the msgpack worker.
            batch.missed = want.into_iter().map(|w| w.inner_path).collect();
            return batch;
        };
        let now = now_secs();
        // Read the content.json once, for shard/salt detection.
        let content = self
            .state
            .read_file(address, "content.json")
            .await
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());

        // Resolve each want to an object id + size; split off shard files, and
        // send anything with no EDX entry straight to the fallback.
        struct Res {
            path: String,
            id: ObjId,
            size: u64,
        }
        let mut plain: Vec<Res> = Vec::new();
        let mut shard_paths: Vec<String> = Vec::new();
        for w in want {
            if content
                .as_ref()
                .is_some_and(|c| epix_blob::manifest::edx_shard_entry(c, &w.inner_path).is_some())
            {
                shard_paths.push(w.inner_path);
                continue;
            }
            let resolved = match (w.id, w.size) {
                (Some(id), Some(size)) => Some((id, size)),
                _ => self.resolve(address, &w.inner_path).await.ok().flatten(),
            };
            match resolved {
                Some((id, size)) => plain.push(Res { path: w.inner_path, id, size }),
                None => batch.missed.push(w.inner_path),
            }
        }

        // Materialize anything already complete in the store (no network).
        let mut pending: Vec<Res> = Vec::new();
        for r in plain {
            if store.is_complete(r.id).unwrap_or(false) {
                if let Ok(bytes) = store.read_bytes(r.id, now) {
                    if self.state.edx_materialize_file(address, &r.path, &bytes).await.is_ok() {
                        batch.bytes += bytes.len() as u64;
                        if let Some(cb) = &on_file {
                            cb(&r.path, bytes.len() as u64);
                        }
                        batch.done.push(r.path);
                        continue;
                    }
                }
            }
            pending.push(r);
        }

        // Encrypted-shard files: no msgpack fallback exists (they are not in
        // the plain files map), so fetch each over EDX or drop it.
        for path in shard_paths {
            let got = match content
                .as_ref()
                .and_then(|c| epix_blob::manifest::edx_shard_entry(c, &path).map(|s| (c, s)))
            {
                Some((c, shard)) => {
                    matches!(self.fetch_shard_file(address, &path, c, shard, &store).await, Ok(true))
                }
                None => false,
            };
            if got {
                if let Some(cb) = &on_file {
                    cb(&path, 0);
                }
                batch.done.push(path);
            } else {
                batch.missed.push(path);
            }
        }

        if pending.is_empty() {
            return batch;
        }

        // Dial the peers ONCE, then fetch every remaining file over the reused
        // links. A file no session peer holds (or that the swarm can't
        // complete) goes to `missed` for the worker.
        let session = self.open_session(&peers, 8).await;
        if session.is_empty() {
            for r in pending {
                epix_ui::state::note_edx_fallback_path(address, &r.path);
                batch.missed.push(r.path);
            }
            return batch;
        }

        // GetMany fast path: small whole objects (<= MAX_MANY_ITEM_BYTES) ride
        // one round trip per <= MAX_MANY_ITEMS-id batch over a session peer,
        // avoiding a bitfield + swarm per file - the win for a forum's many
        // tiny post/data files. Larger files, and any small file a peer did not
        // return, drop to the swarm pass below.
        let cap = epix_edx::server::MAX_MANY_ITEM_BYTES;
        let (small, mut remaining): (Vec<Res>, Vec<Res>) =
            pending.into_iter().partition(|r| r.size > 0 && r.size <= cap);
        if !small.is_empty() {
            // Unique ids only (two paths can share identical bytes -> one id).
            let mut ids: Vec<ObjId> = small.iter().map(|r| r.id).collect();
            ids.sort();
            ids.dedup();
            for peer in &session {
                let want: Vec<ObjId> = ids
                    .iter()
                    .copied()
                    .filter(|id| !store.is_complete(*id).unwrap_or(false))
                    .collect();
                if want.is_empty() {
                    break;
                }
                for chunk in want.chunks(epix_edx::server::MAX_MANY_ITEMS) {
                    let _ = epix_edx::fetch::fetch_many(&peer.conn, &store, chunk, now).await;
                }
            }
            // Materialize every small file the store now holds; the rest join
            // the swarm pass (a peer that lacked it may still hold its chunks).
            for r in small {
                if store.is_complete(r.id).unwrap_or(false) {
                    if let Ok(bytes) = store.read_bytes(r.id, now) {
                        if self.state.edx_materialize_file(address, &r.path, &bytes).await.is_ok() {
                            batch.bytes += bytes.len() as u64;
                            if let Some(cb) = &on_file {
                                cb(&r.path, bytes.len() as u64);
                            }
                            batch.done.push(r.path);
                            continue;
                        }
                    }
                }
                remaining.push(r);
            }
        }

        // Swarm pass: large files, plus any small file GetMany could not land.
        for r in remaining {
            let complete = self.fetch_one_over_session(&store, r.id, r.size, &session, now).await;
            let done = complete
                && match store.read_bytes(r.id, now) {
                    Ok(bytes) => {
                        let ok =
                            self.state.edx_materialize_file(address, &r.path, &bytes).await.is_ok();
                        if ok {
                            batch.bytes += bytes.len() as u64;
                            if let Some(cb) = &on_file {
                                cb(&r.path, bytes.len() as u64);
                            }
                        }
                        ok
                    }
                    Err(_) => false,
                };
            if done {
                batch.done.push(r.path);
            } else {
                // This EDX-eligible file went to the msgpack worker (the 1b
                // gate); counted once per distinct file across all retries.
                epix_ui::state::note_edx_fallback_path(address, &r.path);
                batch.missed.push(r.path);
            }
        }
        let _ = store.enforce_quota(store_quota());
        batch
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

    /// env_on is on unless explicitly disabled: true when unset, false only for
    /// a 0/false value. EDX itself has no on/off knob anymore (it is the
    /// protocol); this backs the remaining tunables like EPIX_EDX_RECIPROCITY.
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
            _: f64,
            _: &[(String, Vec<u8>)],
            _: &[String],
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

    /// Batch fetch: one dial-once session pulls every requested file over the
    /// reused links (the EDX analog of the worker pool), and an undeclared file
    /// (no b3) comes back in `missed` for the msgpack fallback - it is never
    /// silently dropped.
    #[tokio::test]
    async fn a_batch_fetch_gets_every_declared_file_and_reports_the_rest() {
        let (address, content_bytes, content, movie, addr, _pk) = spawn_seeder().await;

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

        let want = vec![
            EdxWant::path("index.html"),
            EdxWant::path("movie.bin"),
            EdxWant::path("not-declared.bin"), // no b3 -> must land in `missed`
        ];
        let peers = vec![epix_core::PeerAddr::Ip(addr)];
        let batch = state_a.edx_fetch_files(&address, want, peers, None).await.unwrap();

        assert!(batch.done.contains(&"index.html".to_string()));
        assert!(batch.done.contains(&"movie.bin".to_string()));
        assert_eq!(batch.missed, vec!["not-declared.bin".to_string()], "undeclared file falls back");
        assert!(batch.bytes >= movie.len() as u64);

        // Both declared files verified onto disk over the one session.
        assert_eq!(XiteStorage::new(a_dir.path()).read("movie.bin").unwrap(), movie);
        assert_eq!(XiteStorage::new(a_dir.path()).read("index.html").unwrap().len(), 5_000);
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

    /// Social/forum content over EDX: a per-user file declared in a child
    /// content.json (as forums store each user's posts) is registered by the
    /// seeder and fetched + resolved by a client through the governing child
    /// content.json, not just the root.
    #[tokio::test]
    async fn a_per_user_child_file_transfers_over_edx() {
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let site_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(site_dir.path());
        storage.write("index.html", b"<h1>forum</h1>").unwrap();
        let post = b"a forum post by alice, delivered over EDX not msgpack".to_vec();
        storage.write("data/users/alice/data.json", &post).unwrap();
        // A child content.json declaring the per-user file with its b3 (what
        // sign_child stamps in production; constructed here to skip the cert
        // flow). The transfer path reads the files map, not the signature.
        let b3 = epix_blob::ObjId::of(&post);
        let child = serde_json::json!({
            "files": { "data.json": { "size": post.len(), "b3": b3.to_string() } },
            "modified": 1000, "address": address,
            "inner_path": "data/users/alice/content.json",
        });
        storage
            .write("data/users/alice/content.json", &serde_json::to_vec(&child).unwrap())
            .unwrap();
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        xite.sign(&privkey, 1000.0).unwrap();
        let content_bytes = xite.storage.read("content.json").unwrap();

        // Node B: load (registers the root AND the child file) and serve.
        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(Store::open(store_dir.path()).unwrap());
        state_b.set_edx_store(store_b.clone()).await;
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(site_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await);
        // The per-user file's object is now in the store (child recursion).
        assert!(store_b.contains(b3).unwrap(), "child file registered for serving");
        std::mem::forget(site_dir);
        std::mem::forget(store_dir);
        let server_key = epix_crypt::new_seed();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(epix_ui::fileserve::FileService::new(state_b.clone()));
        let server = epix_protocol::PeerServer::new(handler)
            .with_edx(edx_hook(state_b.clone(), store_b, server_key, None));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // Node A: has root + child content.json on disk, fetches the per-user
        // file over EDX (resolved via the child content.json).
        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        let a_storage = XiteStorage::new(a_dir.path());
        a_storage.write("content.json", &content_bytes).unwrap();
        a_storage
            .write("data/users/alice/content.json", &serde_json::to_vec(&child).unwrap())
            .unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: None })
            .await;
        assert!(state_a.load_content_from_disk(&address).await);
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

        let result = state_a.edx_fetch_file(&address, "data/users/alice/data.json").await;
        assert!(matches!(result, Some(Ok(true))), "child-file fetch: {result:?}");
        let got = XiteStorage::new(a_dir.path()).read("data/users/alice/data.json").unwrap();
        assert_eq!(got, post, "per-user file transferred over EDX");
    }

    /// The EDX diff wire codec is byte-exact, including non-UTF8 insert bytes
    /// (routing diffs through JSON would mangle them to U+FFFD and defeat the
    /// diff), and a truncated/garbage blob decodes to None so the receiver
    /// safely refetches that file whole.
    #[test]
    fn diff_actions_wire_is_byte_exact_and_bounds_checked() {
        use epix_content::DiffAction;
        let actions = vec![
            DiffAction::Equal(42),
            DiffAction::Remove(7),
            DiffAction::Insert(vec![vec![0xFF, 0xFE, b'a', 0x00, 0x80], b"plain\n".to_vec()]),
        ];
        let bytes = encode_actions(&actions);
        assert_eq!(decode_actions(&bytes).as_ref(), Some(&actions), "byte-exact round trip");

        // Through the map form the wire actually uses.
        let mut map = HashMap::new();
        map.insert("data.json".to_string(), actions.clone());
        let back = decode_edx_diffs(&encode_edx_diffs(&map));
        assert_eq!(back.get("data.json"), Some(&actions));

        // Truncation and a too-short header both fail cleanly (no panic, None).
        assert!(decode_actions(&bytes[..bytes.len() - 1]).is_none());
        assert!(decode_actions(&[0xFF; 4]).is_none());
        // A wildly large embedded count can't pre-allocate/OOM: it just runs
        // off the end of the short buffer and returns None.
        assert!(decode_actions(&u64::MAX.to_le_bytes()).is_none());
    }

    /// Gossip: an EDX update push records a `(xite, modified)` hint even on a
    /// node that does NOT host the xite (a pure relay), so peers polling it
    /// still learn a new version exists. The apply itself fails (unknown site),
    /// but the hint must be recorded first.
    #[tokio::test]
    async fn an_edx_update_records_a_gossip_hint_even_when_not_hosting() {
        let state = AppState::new("relay");
        let store = Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new()));
        state.set_prop_store(store.clone());
        let provider = AppStateProvider { state: state.clone() };

        let res = provider
            .apply_update("1SomeXite", "content.json", b"{}", &[], 4242.0, &[], &[])
            .await;
        assert!(res.is_err(), "a xite we don't host is rejected: {res:?}");

        let (hints, head) = store.lock().await.since(0);
        assert_eq!(head, 1, "the hint was recorded despite the failed apply");
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].xite, "1SomeXite");
        assert_eq!(hints[0].modified, 4242);
    }

    /// Update propagation over EDX: a publisher pushes a new signed child
    /// content.json plus a data.json DIFF (a forum reply) to a receiver over a
    /// real EDX link (`Req::Update`), and the receiver applies it. The
    /// receiver has NO transport, so the patched data.json can only arrive by
    /// applying the diff that rode the push - proving the diff (and version)
    /// crossed EDX, not just the whole content.json.
    #[tokio::test]
    async fn edx_push_applies_a_forum_diff() {
        use epix_ui::state::XiteEntry;

        // --- Node B (receiver): a forum site holding v1 of alice's posts ---
        let site_pk = epix_crypt::new_seed();
        let site_addr = epix_crypt::privatekey_to_address(&site_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user_addr = epix_crypt::privatekey_to_address(&user_pk).unwrap();
        let user_dir = format!("data/users/{user_addr}");

        let b_dir = tempfile::tempdir().unwrap();
        let b_path = b_dir.path().to_path_buf();
        let storage = XiteStorage::new(b_dir.path());
        // Parent user_contents rules the pushed child verifies against.
        let parent = serde_json::json!({
            "address": site_addr,
            "inner_path": "data/users/content.json",
            "user_contents": {
                "cert_signers": {},
                "permissions": {},
                "permission_rules": { ".*": { "max_size": 100000 } },
            },
        });
        storage
            .write("data/users/content.json", &serde_json::to_vec(&parent).unwrap())
            .unwrap();
        let data_v1: &[u8] = br#"{ "posts": [ {"post_id":1,"title":"First"} ] }"#;
        storage.write(&format!("{user_dir}/data.json"), data_v1).unwrap();
        let mut c1 = serde_json::json!({
            "address": site_addr,
            "inner_path": format!("{user_dir}/content.json"),
            "modified": 1000,
            "files": { "data.json": { "size": data_v1.len(), "sha512": XiteStorage::hash_bytes(data_v1) } },
        });
        epix_content::sign(&mut c1, &user_pk).unwrap();
        storage
            .write(&format!("{user_dir}/content.json"), &serde_json::to_vec(&c1).unwrap())
            .unwrap();

        let root = serde_json::json!({ "address": site_addr, "modified": 1.0, "files": {} });
        let state_b = AppState::new("node-b");
        state_b
            .add_xite(&site_addr, XiteEntry { storage: XiteStorage::new(&b_path), content: Some(root) })
            .await;
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(Store::open(store_dir.path()).unwrap());
        state_b.set_edx_store(store_b.clone()).await;
        let prop_b = Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new()));
        state_b.set_prop_store(prop_b.clone());
        std::mem::forget(b_dir);
        std::mem::forget(store_dir);

        let server_key = epix_crypt::new_seed();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(epix_ui::fileserve::FileService::new(state_b.clone()));
        let server = epix_protocol::PeerServer::new(handler)
            .with_edx(edx_hook(state_b.clone(), store_b, server_key, None));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // --- Node A (publisher): v2 adds a reply; push the signed child + diff ---
        let data_v2: &[u8] =
            br#"{ "posts": [ {"post_id":1,"title":"First"}, {"post_id":2,"title":"Reply"} ] }"#;
        let mut c2 = serde_json::json!({
            "address": site_addr,
            "inner_path": format!("{user_dir}/content.json"),
            "modified": 2000,
            "files": { "data.json": { "size": data_v2.len(), "sha512": XiteStorage::hash_bytes(data_v2) } },
        });
        epix_content::sign(&mut c2, &user_pk).unwrap();
        let mut diffs = HashMap::new();
        diffs.insert(
            "data.json".to_string(),
            epix_content::diff::diff(data_v1, data_v2, Some(30 * 1024)).unwrap(),
        );

        let state_a = AppState::new("node-a");
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        state_a.set_edx_store(Arc::new(Store::open(a_store_dir.path()).unwrap())).await;
        std::mem::forget(a_store_dir);
        let fetcher = RuntimeEdxFetcher {
            state: state_a.clone(),
            privatekey: epix_crypt::new_seed(),
            choker: None,
        };

        let progressed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pushed = fetcher
            .push_update(
                epix_core::PeerAddr::Ip(addr),
                &site_addr,
                &format!("{user_dir}/content.json"),
                Arc::new(serde_json::to_vec(&c2).unwrap()),
                2000.0,
                Arc::new(diffs),
                Arc::new(Vec::new()),
                progressed.clone(),
            )
            .await;
        assert!(pushed.is_ok(), "the peer accepted the EDX update push");
        assert!(progressed.load(std::sync::atomic::Ordering::Relaxed), "the link came up");

        // B has no transport: the only way data.json can reach v2 is the diff
        // patch that rode the push. Poll B's disk until it lands.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(bytes) = XiteStorage::new(&b_path).read(&format!("{user_dir}/data.json")) {
                if bytes == data_v2 {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the diff-patched data.json never landed on the receiver over EDX"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // The same push gossiped a hint: the receiver recorded (xite, modified)
        // so peers polling it learn the new version exists.
        let (hints, _head) = prop_b.lock().await.since(0);
        assert!(
            hints.iter().any(|h| h.xite == site_addr && h.modified == 2000),
            "the EDX update recorded a propagation hint, got {hints:?}"
        );
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
