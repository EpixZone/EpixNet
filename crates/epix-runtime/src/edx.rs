//! EDX serving glue: an `AppState`-backed [`SignedProvider`] and the
//! accept-hooks that plug the EDX protocol server into every transport's
//! accept loop. Installed only when an EDX object store is present on the
//! node (see [`enable_serving`]); without one there is nowhere to hold
//! content, so such a node fetches but does not seed.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use epix_blob::store::Store;
use epix_blob::{Ns, ObjId};
use epix_core::PeerAddr;
use epix_edx::choke::Choker;
use epix_edx::conn::{Conn, Incoming};
use epix_edx::msg::{Hello, Req};
use epix_edx::sched::{needed_groups, Deadline, PeerHandle, Swarm};
use epix_edx::server::{
    client_hello, serve, ControlProvider, PeerIdentity, ServeCtx, SignedProvider,
};
use epix_edx::sim::Class;
use epix_protocol::registry::{ConnHandle, Direction};
use epix_protocol::server::{EdxHook, InboundHook};
use epix_protocol::HandshakeInfo;
use epix_transport::Transport;
use epix_ui::conn_pool::{LinkOpener, PeerLink};
use epix_ui::state::{EdxBatch, EdxBatchProgress, EdxFetcher, EdxPushError, EdxWant, InboundUpdate};
use epix_ui::AppState;

/// The peer's EDX Hello, in the shape the diagnostics Stats page renders. Only
/// `version` and the node key are real over EDX; `rev`, `fileserver_port` and
/// the crypt list were msgpack handshake fields with no EDX equivalent, and
/// `protocol` names the wire.
fn handshake_info(version: &str, node_pk: &[u8]) -> HandshakeInfo {
    HandshakeInfo {
        version: version.to_string(),
        rev: 0,
        protocol: "edx".into(),
        peer_id: hex::encode(node_pk),
        fileserver_port: 0,
        crypt_supported: Vec::new(),
    }
}

/// How long an accepted peer gets to finish the EDX handshake (magic, then
/// Noise on clearnet). The accept loop's reaper only covers the FIRST byte, so
/// without this a connection that opens with `E` and then stalls holds a socket
/// and a task forever - the same fd leak, one byte later.
const ACCEPT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Queue depth for the inbound-request tap. Matches the depth `Conn` gives its
/// own incoming channel, so the tap adds no extra buffering.
const INBOUND_TAP_DEPTH: usize = 16;

/// The request name shown in the Stats page's `last recv` column.
fn req_kind(req: &Req) -> &'static str {
    match req {
        Req::Hello(_) => "Hello",
        Req::GetSigned { .. } => "GetSigned",
        Req::ListSigned { .. } => "ListSigned",
        Req::GetRange { .. } => "GetRange",
        Req::GetMany { .. } => "GetMany",
        Req::GetBitfield { .. } => "GetBitfield",
        Req::HasXite { .. } => "HasXite",
        Req::HaveRanges { .. } => "HaveRanges",
        Req::Update { .. } => "Update",
        Req::UpdatesSince { .. } => "UpdatesSince",
        Req::Pex { .. } => "Pex",
        Req::GetTrackers => "GetTrackers",
        Req::Kad { .. } => "Kad",
        Req::Announce { .. } => "Announce",
    }
}

/// The xite a request names, for the Stats page's per-connection xite list.
/// Object requests carry a hash, not a xite, so they name none.
fn req_xite(req: &Req) -> Option<&str> {
    match req {
        Req::GetSigned { xite, .. }
        | Req::ListSigned { xite, .. }
        | Req::HasXite { xite }
        | Req::Update { xite, .. }
        | Req::Pex { xite, .. } => Some(xite),
        _ => None,
    }
}

/// Tap the inbound request stream of an accepted link so the diagnostics Stats
/// page shows it, then forward every request untouched to the serve loop.
///
/// The row is created inactive and only listed once the peer's Hello arrives:
/// a scanner that opens with the EDX magic and then says nothing never appears.
/// `on_inbound` fires on the same event - a peer that completed the Noise
/// handshake and spoke EDX is real proof our clearnet port is reachable.
fn tap_inbound(
    reg: Arc<ConnHandle>,
    mut incoming: tokio::sync::mpsc::Receiver<Incoming>,
    source: PeerAddr,
    on_inbound: Option<InboundHook>,
) -> tokio::sync::mpsc::Receiver<Incoming> {
    let (tx, rx) = tokio::sync::mpsc::channel(INBOUND_TAP_DEPTH);
    tokio::spawn(async move {
        while let Some(inc) = incoming.recv().await {
            if let Req::Hello(hello) = &inc.req {
                reg.activate();
                reg.set_peer(handshake_info(&hello.version, &hello.node_pk));
                adopt_dialback(&reg, hello);
                if let Some(hook) = &on_inbound {
                    hook(&source);
                }
            }
            reg.note_cmd_recv(req_kind(&inc.req), req_xite(&inc.req));
            if tx.send(inc).await.is_err() {
                break;
            }
        }
    });
    rx
}

/// Show an inbound peer under the address it says we can dial it back on: the
/// socket it reached us from is an ephemeral port (clearnet) or a blank
/// placeholder (onion/i2p/mesh), neither of which is an identity. The claim is
/// trusted the way PEX gossip is, but only when it is complete and
/// wire-packable - `pack()` base32/length-validates onion and i2p hosts, so
/// junk that could never round-trip peer exchange is never displayed.
fn adopt_dialback(reg: &ConnHandle, hello: &Hello) {
    if let Some(addr) =
        hello.listen.iter().find(|a| a.is_wellformed() && a.pack().is_some())
    {
        reg.set_addr(addr.clone());
    }
}

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

/// Bound each post-dial EDX request (bitfield / GetMany / GetSigned over a
/// session) so a peer that handshakes then stalls the response cannot hang the
/// fetch. The dial itself is bounded by `peer.connect_timeout()` in `dial()`.
const EDX_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn store_quota() -> u64 {
    std::env::var("EPIX_EDX_STORE_QUOTA_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(EDX_STORE_QUOTA_BYTES)
}

/// How far ahead of the play position a served range prefetches. A few
/// seconds of typical media over the next window so sequential playback finds
/// the bytes already in the store, small enough that a seek away wastes little.
const READAHEAD_BYTES: u64 = 6 * 1024 * 1024;

/// Files at least this large get a one-time head+tail warm-up on first touch.
/// Browsers read an mp4 moov atom (often at EOF) for metadata before playback;
/// warming the tail keeps that fetch from stalling the start. Gated by SIZE,
/// not extension - the content type is not always known here, and size is the
/// safe signal for "media-ish, worth warming".
const MOOV_MIN_SIZE: u64 = 4 * 1024 * 1024;

/// The tail span warmed for the moov metadata a browser reads before playback.
const MOOV_TAIL_BYTES: u64 = 1_536 * 1024;

/// The head span ensured on first touch (container/init metadata).
const MOOV_HEAD_BYTES: u64 = 1024 * 1024;

/// How long a serve's dialed peers stay reusable by its read-ahead. A fetch
/// path that redials is correct, just slower, so a stale entry only costs a
/// wasted attempt (read-ahead is silent on failure).
const PEER_CACHE_TTL: u64 = 15;

/// Cap on the per-file streaming hints (`anchor`/`warmed`) kept in memory.
/// These are only optimizations - a coalescing hint and a one-time moov-warm
/// gate - and a partially watched or tail-probed file leaves an entry that no
/// EOF-completion ever clears, so on a long-lived seeder streaming many
/// distinct files the maps would grow without bound. At the cap the map is
/// cleared: at worst a few files re-anchor or re-warm once, which is idempotent
/// (read-ahead and moov warm both skip already-present groups).
const MAX_STREAMING_FILES: usize = 4096;

/// Decide the read-ahead window after serving `served` bytes of a file of
/// `size`, given `anchor` = the from-offset of the last window we scheduled
/// for this (address, inner_path), or `None` if none yet. Returns the byte
/// window to prefetch and the new anchor to store, or `None` when there is
/// nothing to do: at/past EOF, or the play head has not advanced since the
/// last window (coalesce - a paused video re-requesting the same range must
/// not re-arm a prefetch).
///
/// Pure so the window/seek logic is unit-tested without any network. The
/// window always begins at the byte right after what the user just got, so
/// sequential playback slides it forward and a seek RE-ANCHORS it at the new
/// position automatically - a stale far-ahead region is never prefetched.
fn plan_readahead(served: &Range<u64>, size: u64, anchor: Option<u64>) -> Option<(Range<u64>, u64)> {
    let from = served.end.min(size);
    let to = from.saturating_add(READAHEAD_BYTES).min(size);
    if from >= to {
        return None; // at or past EOF - nothing ahead to warm
    }
    if anchor == Some(from) {
        return None; // play head unmoved since the last window - coalesce
    }
    Some((from..to, from))
}

/// The head and tail spans to warm on first touch of a large file (the mp4
/// moov metadata a browser reads, often at EOF, before playback). `None`
/// below the size threshold. Both ranges are clamped to the file. Pure, so
/// the threshold and clamping are unit-tested without any network.
fn moov_spans(size: u64) -> Option<(Range<u64>, Range<u64>)> {
    if size < MOOV_MIN_SIZE {
        return None;
    }
    let head = 0..MOOV_HEAD_BYTES.min(size);
    let tail = size.saturating_sub(MOOV_TAIL_BYTES)..size;
    Some((head, tail))
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
        // others - the store-and-forward reach a publish flood needs.
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

/// The node-wide handles the control plane needs beyond the [`AppState`]:
/// the DHT participant (`Kad`) and the store-and-forward propagation log
/// (`UpdatesSince`). Built once in the runtime and shared by every
/// transport's accept loop, so all of them serve the same DHT node and the
/// same hint log.
#[derive(Clone)]
pub struct ControlHandles {
    pub dht: Arc<epix_dht_net::DhtService>,
    pub prop: Arc<tokio::sync::Mutex<epix_propagation::PropagationStore>>,
}

impl ControlHandles {
    /// Handles shared with nothing else: a private DHT node and an empty
    /// hint log. For serving EDX without a [`crate::NodeRuntime`] (which
    /// passes its own, so both the DHT loop and the accept loops work off
    /// one routing table and one hint log).
    pub fn detached() -> Self {
        let id = epix_dht::NodeId::hash(epix_crypt::new_seed().as_bytes());
        Self {
            dht: Arc::new(epix_dht_net::DhtService::new(Arc::new(epix_dht::Node::new(id)))),
            prop: Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new())),
        }
    }
}

/// Serves the EDX control plane (`UpdatesSince`, `Pex`, `GetTrackers`, `Kad`,
/// `Announce`) for ONE connection.
///
/// It is per connection because every one of those handlers needs the
/// requester's address, and the EDX `PeerIdentity` carries none: the DHT
/// rewrites a NATed caller's claimed IP to the address the request actually
/// came from, and the tracker registers announcers the same way. Taking that
/// from the accept hook's `PeerAddr` (which is the socket/overlay address,
/// not something the peer asserts) keeps that anti-spoofing property; the
/// Hello's self-reported `listen` addresses could not.
struct RuntimeControlProvider {
    state: Arc<AppState>,
    handles: ControlHandles,
    /// Where this connection came from, as the accept loop saw it.
    peer: PeerAddr,
}

#[async_trait::async_trait]
impl ControlProvider for RuntimeControlProvider {
    async fn updates_since(&self, after: u64) -> (Vec<(String, i64)>, u64) {
        let (hints, head) = self.handles.prop.lock().await.since(after);
        (hints.into_iter().map(|h| (h.xite, h.modified)).collect(), head)
    }

    async fn pex(
        &self,
        xite: &str,
        need: u32,
        have: &[PeerAddr],
        _from: &PeerIdentity,
    ) -> Vec<PeerAddr> {
        self.state.pex_exchange(xite, need as usize, have.to_vec(), &self.peer).await
    }

    async fn trackers(&self) -> Vec<String> {
        self.state.tracker_list().await
    }

    async fn kad(&self, payload: &[u8], _from: &PeerIdentity) -> Result<Vec<u8>, String> {
        self.handles.dht.handle_edx(&self.peer, payload)
    }

    async fn announce(&self, payload: &[u8], _from: &PeerIdentity) -> Result<Vec<u8>, String> {
        let req = epix_discovery::tracker_pc::decode_request(payload).map_err(|e| e.to_string())?;
        let resp = self.state.announce_serve(&req, &self.peer).await;
        epix_discovery::tracker_pc::encode_reply(&resp).map_err(|e| e.to_string())
    }
}

/// Build the CLEARNET accept-hook: an accepted TCP stream gets Noise-XX then
/// the EDX serve loop, backed by `store` and the node's xite registry.
/// `privatekey` is this node's EDX identity key, used for the Hello channel
/// binding. `on_inbound` fires once per peer that completes the handshake.
pub fn edx_hook(
    state: Arc<AppState>,
    store: Arc<Store>,
    privatekey: String,
    choker: Option<SharedChoker>,
    control: ControlHandles,
    on_inbound: Option<InboundHook>,
) -> EdxHook {
    let provider: Arc<dyn SignedProvider> = Arc::new(AppStateProvider { state: state.clone() });
    Arc::new(move |peer: PeerAddr, stream| {
        let store = store.clone();
        let provider = provider.clone();
        let privatekey = privatekey.clone();
        let choker = choker.clone();
        let on_inbound = on_inbound.clone();
        let control = control_provider(&state, &control, peer.clone());
        Box::pin(async move {
            let (reg, stream) = ConnHandle::new(Direction::In, peer.clone()).attach(stream);
            let handshake = tokio::time::timeout(
                ACCEPT_HANDSHAKE_TIMEOUT,
                epix_edx::link::accept(stream),
            );
            let Ok(Ok(l)) = handshake.await else { return };
            let mut ctx = serve_ctx(store, provider, privatekey, control);
            if let Some(c) = choker {
                ctx = ctx.with_choker(c);
            }
            let incoming = tap_inbound(reg, l.incoming, peer, on_inbound);
            serve(l.conn, incoming, Arc::new(ctx), Some(l.handshake_hash)).await;
        })
    })
}

/// The per-connection control provider (see [`RuntimeControlProvider`]).
fn control_provider(
    state: &Arc<AppState>,
    handles: &ControlHandles,
    peer: PeerAddr,
) -> Arc<dyn ControlProvider> {
    Arc::new(RuntimeControlProvider { state: state.clone(), handles: handles.clone(), peer })
}

/// A serve context that answers the control plane too (so it advertises
/// `caps::CONTROL`) and reports this node's release version in its Hello -
/// which is what the Stats page's `client` column shows.
fn serve_ctx(
    store: Arc<Store>,
    provider: Arc<dyn SignedProvider>,
    privatekey: String,
    control: Arc<dyn ControlProvider>,
) -> ServeCtx {
    ServeCtx::new(store, provider, privatekey)
        .with_version(epix_protocol::self_advert_version())
        .with_control(control)
}

/// Build the OVERLAY accept-hook (Tor/I2P/Reticulum): the transport already
/// encrypts, so this skips Noise and serves with no channel binding.
pub fn edx_hook_overlay(
    state: Arc<AppState>,
    store: Arc<Store>,
    privatekey: String,
    choker: Option<SharedChoker>,
    control: ControlHandles,
) -> EdxHook {
    let provider: Arc<dyn SignedProvider> = Arc::new(AppStateProvider { state: state.clone() });
    Arc::new(move |peer: PeerAddr, stream| {
        let store = store.clone();
        let provider = provider.clone();
        let privatekey = privatekey.clone();
        let choker = choker.clone();
        let control = control_provider(&state, &control, peer.clone());
        Box::pin(async move {
            let (reg, stream) = ConnHandle::new(Direction::In, peer.clone()).attach(stream);
            let handshake = tokio::time::timeout(
                ACCEPT_HANDSHAKE_TIMEOUT,
                epix_edx::link::accept_overlay(stream),
            );
            let Ok(Ok((conn, incoming))) = handshake.await else { return };
            let mut ctx = serve_ctx(store, provider, privatekey, control);
            if let Some(c) = choker {
                ctx = ctx.with_choker(c);
            }
            // No inbound hook on overlays: reaching us over Tor/I2P/mesh says
            // nothing about whether our clearnet port is open.
            let incoming = tap_inbound(reg, incoming, peer, None);
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
    control: ControlHandles,
}

impl EdxServe {
    /// The clearnet (Noise) accept hook for [`epix_protocol::PeerServer`].
    /// `on_inbound` fires per peer that completes the handshake, which is how
    /// the node learns its fileserver port is open from the internet.
    pub fn clearnet_hook(&self, on_inbound: Option<InboundHook>) -> EdxHook {
        edx_hook(
            self.state.clone(),
            self.store.clone(),
            self.privatekey.clone(),
            self.choker.clone(),
            self.control.clone(),
            on_inbound,
        )
    }
    /// The overlay (no-Noise) accept hook for Tor/I2P/Reticulum.
    pub fn overlay_hook(&self) -> EdxHook {
        edx_hook_overlay(
            self.state.clone(),
            self.store.clone(),
            self.privatekey.clone(),
            self.choker.clone(),
            self.control.clone(),
        )
    }
}

/// Lazily-shared EDX serve context so every accept loop initializes the same
/// store/key/choker exactly once regardless of which transport comes up
/// first, plus the control-plane handles they all serve from.
#[derive(Clone)]
pub struct EdxServeCell {
    cell: Arc<tokio::sync::Mutex<Option<EdxServe>>>,
    control: ControlHandles,
}

/// A fresh, uninitialized shared EDX serve cell (built in `start`, cloned
/// into each transport's accept loop).
pub fn new_serve_cell(control: ControlHandles) -> EdxServeCell {
    EdxServeCell { cell: Arc::new(tokio::sync::Mutex::new(None)), control }
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
    let mut guard = cell.cell.lock().await;
    if let Some(es) = guard.as_ref() {
        return Some(es.clone());
    }
    let dir = state.data_root_path()?;
    let key = node_key(state).await;
    let choker = make_choker();
    let store = enable_serving(state, &dir, key.clone(), choker.clone()).await?;
    let es = EdxServe {
        state: state.clone(),
        store,
        privatekey: key,
        choker,
        control: cell.control.clone(),
    };
    *guard = Some(es.clone());
    Some(es)
}

/// Per-peer cache of live EDX links for the short control RPCs (PEX, Kad,
/// Announce, UpdatesSince, GetTrackers). A single DHT lookup or announce fans
/// the same handful of contacts out many times; without reuse each redials a
/// full Noise-XX handshake and holds an overlay stream for a whole request
/// timeout. A pooled `Conn` is multiplexed, so concurrent control ops sharing
/// one link are correct. The `Arc<ConnHandle>` is kept beside the `Conn` so
/// the link's diagnostics row lives while it is pooled and so `note_cmd_sent`
/// can annotate it; only the bulk fetch paths (which open and drain a session)
/// still dial fresh - those are never pooled.
#[derive(Default)]
struct ControlPool {
    conns: Mutex<HashMap<PeerAddr, (Conn, Arc<ConnHandle>)>>,
}

impl ControlPool {
    /// A live pooled link for `peer`, or None. A closed one is dropped so the
    /// caller redials (reuse-if-not-closed-else-redial, like `epix_edx::Pool`).
    fn live(&self, peer: &PeerAddr) -> Option<(Conn, Arc<ConnHandle>)> {
        let mut map = self.conns.lock().expect("control pool");
        match map.get(peer) {
            Some((c, reg)) if !c.is_closed() => Some((c.clone(), reg.clone())),
            Some(_) => {
                map.remove(peer);
                None
            }
            None => None,
        }
    }

    fn store(&self, peer: PeerAddr, conn: Conn, reg: Arc<ConnHandle>) {
        self.conns.lock().expect("control pool").insert(peer, (conn, reg));
    }

    /// Drop a peer's cached link (a control op errored on it, so a possibly
    /// dead link is not handed to the next caller).
    fn evict(&self, peer: &PeerAddr) {
        self.conns.lock().expect("control pool").remove(peer);
    }
}

/// Fetches a file's bytes over the EDX verified-streaming path: dial the
/// xite's connectable peers as EDX links, learn what each holds, run the
/// swarm scheduler into the object store, then materialize the completed
/// object into the xite's storage. Backs [`AppState`]'s injected fetcher.
/// Cheap to clone (Arc + String) - clones let a session dial its peers
/// concurrently.
#[derive(Clone)]
struct RuntimeEdxFetcher {
    state: Arc<AppState>,
    privatekey: String,
    /// Shared upload governor; when present, peers that serve us are credited
    /// after each fetch so they earn faster service from us in return.
    choker: Option<SharedChoker>,
    /// Reused links for the short control RPCs. Arc-shared because the fetcher
    /// is Arc-shared and cloned per session, so every clone must pool into the
    /// same cache. Built once via [`RuntimeEdxFetcher::new`] so no construction
    /// site (there are many, including tests) can forget to initialize it.
    control_pool: Arc<ControlPool>,
    /// Streaming read-ahead bookkeeping, Arc-shared like the fetcher so every
    /// clone sees the same in-flight/anchor/warmed state.
    streaming: Arc<Mutex<Streaming>>,
    /// A serve's dialed peers, briefly cached per object so its read-ahead
    /// reuses the same links instead of redialing. The serve itself always
    /// builds fresh peers (correctness); this only warms the background path.
    peer_cache: Arc<Mutex<HashMap<ObjId, CachedPeers>>>,
}

/// Per-file streaming state guarding read-ahead against firing an unbounded
/// task per browser Range request.
#[derive(Default)]
struct Streaming {
    /// Per (address, inner_path): the from-offset of the last read-ahead
    /// window scheduled. Equal offset means the play head has not moved, so we
    /// coalesce; a different offset advances or re-anchors the window.
    anchor: HashMap<(String, String), u64>,
    /// Files with a read-ahead task in flight - at most one per file, so a
    /// burst of Range requests cannot fan out into a burst of prefetches.
    inflight: HashSet<(String, String)>,
    /// Files whose one-time moov head/tail warm-up has been kicked off.
    warmed: HashSet<(String, String)>,
}

/// A serve's dialed peers, kept for a short TTL so its read-ahead reuses them.
struct CachedPeers {
    handles: Vec<PeerHandle>,
    node_pks: HashMap<String, Vec<u8>>,
    /// `now_secs` when built, for the TTL check.
    at: u64,
}

/// Clone a peer handle (its `Conn` is a cheap multiplexed clone). `PeerHandle`
/// is not `Clone`, so the peer cache clones field-by-field to hand a serve's
/// links to its background read-ahead.
fn clone_handle(h: &PeerHandle) -> PeerHandle {
    PeerHandle { conn: h.conn.clone(), class: h.class, bits: h.bits.clone(), label: h.label.clone() }
}

impl RuntimeEdxFetcher {
    /// Build a fetcher with an empty control-link cache.
    fn new(state: Arc<AppState>, privatekey: String, choker: Option<SharedChoker>) -> Self {
        Self {
            state,
            privatekey,
            choker,
            control_pool: Arc::default(),
            streaming: Arc::default(),
            peer_cache: Arc::default(),
        }
    }

    /// Dial `peer`, bring up an EDX link past the Hello gate, and return the
    /// connection, the peer's authenticated identity, and the link's entry in
    /// the diagnostics connection registry.
    ///
    /// The registry entry is owned by the wrapped stream (`ConnHandle::attach`),
    /// so it lists while the link's reader/writer tasks live and deregisters
    /// when they end - a `Conn` clone is too cheap to hang a lifetime off. The
    /// returned handle is for annotating the row afterwards (ping); dropping it
    /// changes nothing.
    async fn dial(
        &self,
        transport: &Arc<dyn Transport>,
        peer: &PeerAddr,
    ) -> Result<(Conn, PeerIdentity, Arc<ConnHandle>), String> {
        // A client context: client_hello only reads the key, caps and version;
        // reuse the AppState provider (harmless) and the object store.
        let store = self.state.edx_store().await.ok_or("no EDX store")?;
        // Offer our dial-back addresses in the Hello. The socket the peer sees
        // is our ephemeral source port, so without this an overlay-only or
        // NATed node that only ever dials OUT can never be dialed back.
        let listen: Vec<PeerAddr> = self
            .state
            .own_dialable_addresses()
            .await
            .iter()
            .filter_map(|s| PeerAddr::parse(s).ok())
            .collect();
        let provider: Arc<dyn SignedProvider> =
            Arc::new(AppStateProvider { state: self.state.clone() });
        let ctx = ServeCtx::new(store, provider, self.privatekey.clone())
            .with_version(epix_protocol::self_advert_version());
        // Bound the whole handshake: a peer that TCP-accepts then stalls the
        // Noise / client_hello exchange must not hang the fetch forever.
        tokio::time::timeout(peer.connect_timeout(), async {
            let stream = transport.dial(peer).await.map_err(|e| e.to_string())?;
            let (reg, stream) =
                ConnHandle::new(Direction::Out, peer.clone()).attach(stream);
            // Clearnet TCP needs Noise; overlays (Tor/I2P/Reticulum) already
            // encrypt, so they skip it and bind with no handshake hash.
            let (conn, hh) = if matches!(peer, PeerAddr::Ip(_)) {
                let l = epix_edx::link::dial(stream).await.map_err(|e| e.to_string())?;
                (l.conn, Some(l.handshake_hash))
            } else {
                let (conn, _in) =
                    epix_edx::link::dial_overlay(stream).await.map_err(|e| e.to_string())?;
                (conn, None)
            };
            let identity =
                client_hello(&conn, &ctx, listen, hh).await.map_err(|e| e.to_string())?;
            // List it only once the peer proved it speaks EDX, so a port scan
            // or a half-open TCP connect never shows up on the Stats page.
            reg.activate();
            reg.set_peer(handshake_info(&identity.version, &identity.node_pk));
            Ok::<_, String>((conn, identity, reg))
        })
        .await
        .map_err(|_| "EDX dial timed out".to_string())?
    }

    /// A live EDX link to `peer` for a control RPC, reused from the cache when
    /// one is still open or dialed and cached otherwise. Returns the multiplexed
    /// `Conn` plus its registry row so the caller can annotate `last cmd sent`.
    async fn control_link(&self, peer: &PeerAddr) -> Result<(Conn, Arc<ConnHandle>), String> {
        if let Some(hit) = self.control_pool.live(peer) {
            return Ok(hit);
        }
        let transport = self.state.transport().await.ok_or("no transport")?;
        let (conn, _identity, reg) = self.dial(&transport, peer).await?;
        self.control_pool.store(peer.clone(), conn.clone(), reg.clone());
        Ok((conn, reg))
    }

    /// Run ONE control-plane request over a cached (or freshly dialed) link to
    /// `peer`, bounded like every other post-dial request. `label` names the op
    /// for the Stats page's `last cmd sent` column. Reusing the link across a
    /// DHT lookup's many self-claims avoids a fresh Noise handshake per RPC; a
    /// pooled `Conn` is multiplexed so concurrent ops on it are fine. Both an
    /// unreachable peer and a stalled request are `Err`, and a dead-on-arrival
    /// link is evicted so it is not reused: the caller scores the peer and asks
    /// another.
    async fn control<T, F, Fut>(&self, peer: &PeerAddr, label: &str, f: F) -> Result<T, String>
    where
        F: FnOnce(Conn) -> Fut,
        Fut: std::future::Future<Output = std::io::Result<T>>,
    {
        let (conn, reg) = self.control_link(peer).await?;
        reg.note_cmd_sent(label, None);
        match tokio::time::timeout(EDX_FETCH_TIMEOUT, f(conn)).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                self.control_pool.evict(peer);
                Err(e.to_string())
            }
            Err(_) => {
                self.control_pool.evict(peer);
                Err("EDX control request timed out".into())
            }
        }
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
                let Ok((conn, identity, reg)) = self.dial(&transport, peer).await else { continue };
                reg.note_cmd_sent("GetBitfield", Some(address));
                if let Ok(Ok((_sz, bits))) =
                tokio::time::timeout(EDX_FETCH_TIMEOUT, epix_edx::fetch::fetch_bitfield(&conn, id))
                    .await
            {
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
            let Ok((conn, identity, reg)) = self.dial(&transport, &peer).await else { continue };
            reg.note_cmd_sent("GetBitfield", Some(address));
            if let Ok(Ok((_sz, bits))) =
                tokio::time::timeout(EDX_FETCH_TIMEOUT, epix_edx::fetch::fetch_bitfield(&conn, id))
                    .await
            {
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

    /// Cache a serve's freshly dialed peers so its read-ahead reuses the links.
    fn cache_peers(&self, id: ObjId, handles: &[PeerHandle], node_pks: &HashMap<String, Vec<u8>>) {
        let now = now_secs();
        let mut cache = self.peer_cache.lock().expect("peer_cache");
        // Drop entries past their TTL before inserting. The TTL is otherwise
        // only consulted to decide reuse, never retention, so without this a
        // served object whose id is never fetched again keeps its entry - and
        // its cloned peer `Conn`s - alive for the process lifetime. Pruning
        // here (the only growth path, hit on every store-miss serve) bounds the
        // map to the objects served within one TTL window.
        cache.retain(|_, c| now.saturating_sub(c.at) < PEER_CACHE_TTL);
        cache.insert(
            id,
            CachedPeers {
                handles: handles.iter().map(clone_handle).collect(),
                node_pks: node_pks.clone(),
                at: now,
            },
        );
    }

    /// Peers for `id`, reused from the short-lived cache when a serve dialed
    /// them recently, else dialed fresh and cached. Used only by the background
    /// read-ahead / moov warm-up so a seek and its prefetch share links; the
    /// user-facing serve always builds fresh peers itself.
    async fn peers_for(
        &self,
        address: &str,
        id: ObjId,
    ) -> Result<(Vec<PeerHandle>, HashMap<String, Vec<u8>>), String> {
        let now = now_secs();
        {
            let cache = self.peer_cache.lock().expect("peer_cache");
            if let Some(hit) = cache.get(&id) {
                if !hit.handles.is_empty() && now.saturating_sub(hit.at) < PEER_CACHE_TTL {
                    return Ok((hit.handles.iter().map(clone_handle).collect(), hit.node_pks.clone()));
                }
            }
        }
        let (handles, node_pks) = self.build_peers(address, id).await?;
        self.cache_peers(id, &handles, &node_pks);
        Ok((handles, node_pks))
    }

    /// On the FIRST touch of a large file, kick off a one-time background warm
    /// of the moov head+tail so the browser's metadata tail-fetch (often at
    /// EOF) does not stall playback. No-op below the size threshold or after
    /// the first touch. Never blocks or errors into the serve.
    fn maybe_warm_moov(&self, address: &str, inner_path: &str, id: ObjId, size: u64) {
        let Some((head, tail)) = moov_spans(size) else { return };
        let key = (address.to_string(), inner_path.to_string());
        {
            let mut s = self.streaming.lock().expect("streaming");
            if s.warmed.len() >= MAX_STREAMING_FILES {
                s.warmed.clear(); // bound memory; a cleared file re-warms once
            }
            if !s.warmed.insert(key.clone()) {
                return; // already warmed this file
            }
        }
        let this = self.clone();
        tokio::spawn(async move {
            // Tail first (the moov metadata that gates playback), then the head.
            this.run_readahead(&key.0, id, size, tail).await;
            this.run_readahead(&key.0, id, size, head).await;
        });
    }

    /// After serving a range, arm the background read-ahead of the NEXT window.
    /// Plans + reserves under the lock: coalesces an unmoved play head and caps
    /// to one in-flight task per file, so a browser's burst of Range requests
    /// cannot fan out into a burst of prefetches. Backpressure is inherent -
    /// a paused video issues no Range requests, so this stops being called and
    /// prefetch quiesces after the current window with no separate mechanism.
    fn maybe_spawn_readahead(
        &self,
        address: &str,
        inner_path: &str,
        id: ObjId,
        size: u64,
        served: Range<u64>,
    ) {
        let key = (address.to_string(), inner_path.to_string());
        let window = {
            let mut s = self.streaming.lock().expect("streaming");
            let anchor = s.anchor.get(&key).copied();
            let Some((window, new_anchor)) = plan_readahead(&served, size, anchor) else {
                return;
            };
            if s.inflight.contains(&key) {
                return; // a read-ahead is already running for this file
            }
            if s.anchor.len() >= MAX_STREAMING_FILES {
                s.anchor.clear(); // bound memory; a cleared file re-anchors once
            }
            s.anchor.insert(key.clone(), new_anchor);
            s.inflight.insert(key.clone());
            window
        };
        let this = self.clone();
        tokio::spawn(async move {
            this.run_readahead(&key.0, id, size, window).await;
            this.streaming.lock().expect("streaming").inflight.remove(&key);
        });
    }

    /// Warm the store with `window` of `id` at the BACKGROUND deadline (never
    /// competing with the tight-deadline range the user is watching), skipping
    /// groups already present. Silent on any failure: read-ahead only warms the
    /// cache and must never surface an error to the range response.
    async fn run_readahead(&self, address: &str, id: ObjId, size: u64, window: Range<u64>) {
        let Some(store) = self.state.edx_store().await else { return };
        let now = now_secs();
        // Only the groups of the window the store is still missing, so a
        // re-watch or an overlap with the served range does no work.
        let want = epix_blob::bitfield::groups_for_bytes(&window);
        let present = store.present_bits(id).unwrap_or_default();
        let mut needed = epix_blob::bitfield::GroupBits::new();
        for gap in present.gaps(&want) {
            needed.add(gap);
        }
        if needed.is_empty() {
            return; // already warm
        }
        if store.ensure_sparse(id, Ns::Plain, size, now).is_err() {
            return;
        }
        let Ok((handles, node_pks)) = self.peers_for(address, id).await else { return };
        let mut swarm = Swarm::new(store.clone(), id, size);
        if let Ok(report) = swarm.fetch(&needed, &handles, Deadline::background(), now).await {
            self.credit(&report, &node_pks, now);
        }
        let _ = store.enforce_quota(store_quota());
    }

    /// Dial `peers` (up to `cap`) ONCE and keep the links, so a batch fetches
    /// every file over the same connections instead of redialing per file (the
    /// redial-per-file cost of calling `fetch_file` in a loop). Object-
    /// independent: the per-object bitfield is fetched later over these links.
    ///
    /// Dials run CONCURRENTLY: a dead peer must not serialize its full
    /// connect_timeout ahead of a live one (the whole session would take
    /// cap * timeout instead of one timeout). Each dial's outcome is fed back
    /// into `address`'s peer registry (via note_edx_dials), so a dead peer
    /// sinks and a live one rises - without this the clone kept redialing the
    /// same unranked top-N and gave up while a reachable seeder sat lower.
    async fn open_session(&self, address: &str, peers: &[PeerAddr], cap: usize) -> Vec<SessionPeer> {
        let Some(transport) = self.state.transport().await else { return Vec::new() };
        let mut join = tokio::task::JoinSet::new();
        for peer in peers.iter().take(cap).cloned() {
            let this = self.clone();
            let transport = transport.clone();
            join.spawn(async move {
                let r = this.dial(&transport, &peer).await;
                (peer, r)
            });
        }
        let mut out = Vec::new();
        let mut outcomes: Vec<(PeerAddr, bool)> = Vec::new();
        while let Some(res) = join.join_next().await {
            let Ok((peer, r)) = res else { continue };
            match r {
                Ok((conn, identity, reg)) => {
                    outcomes.push((peer.clone(), true));
                    out.push(SessionPeer {
                        conn,
                        class: Class::of_addr(&peer),
                        label: peer.to_string(),
                        node_pk: identity.node_pk,
                        reg,
                    });
                }
                Err(_) => outcomes.push((peer, false)),
            }
        }
        self.state.note_edx_dials(address, outcomes).await;
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
            p.reg.note_cmd_sent("GetBitfield", None);
            if let Ok(Ok((_sz, bits))) =
                tokio::time::timeout(EDX_FETCH_TIMEOUT, epix_edx::fetch::fetch_bitfield(&p.conn, id))
                    .await
            {
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
    /// The link's diagnostics row, kept so requests issued over this reused
    /// link can stamp `last cmd sent` on it.
    reg: Arc<ConnHandle>,
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
        let (conn, _identity, reg) = self.dial(&transport, &peer).await?;
        reg.note_cmd_sent("GetSigned", Some(address));
        match tokio::time::timeout(
            EDX_FETCH_TIMEOUT,
            epix_edx::fetch::fetch_signed(&conn, address, inner_path),
        )
        .await
        {
            Ok(Ok(bytes)) => Ok(Some(bytes)),
            // Alive but no content, or the request stalled: try another peer.
            Ok(Err(_)) | Err(_) => Ok(None),
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
        let session = self.open_session(address, &peers, 8).await;
        if session.is_empty() {
            return out;
        }
        for path in paths {
            for p in &session {
                p.reg.note_cmd_sent("GetSigned", Some(address));
                if let Ok(Ok(bytes)) = tokio::time::timeout(
                    EDX_FETCH_TIMEOUT,
                    epix_edx::fetch::fetch_signed(&p.conn, address, &path),
                )
                .await
                {
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
        let served = start..end;

        // Warm the moov head/tail once on the first touch of a large file, so
        // the browser's metadata tail-fetch does not stall the start. Pure
        // background; failures never reach this response.
        self.maybe_warm_moov(address, inner_path, id, size);

        // Serve straight from the store if the covering range is already
        // present; otherwise fetch just the covering chunk groups (a seek,
        // never the whole file). This served range must stay byte-exact at the
        // tight deadline - read-ahead below is a pure background addition.
        let bytes = if let Ok(bytes) = store.read_range(id, start, end - start, now) {
            bytes
        } else {
            let (handles, node_pks) = self.build_peers(address, id).await?;
            // Warm the peer cache so the read-ahead reuses these dialed links.
            self.cache_peers(id, &handles, &node_pks);
            let groups = epix_blob::bitfield::groups_for_bytes(&served);
            let mut needed = epix_blob::bitfield::GroupBits::new();
            needed.add(groups.start..groups.end);
            let mut swarm = Swarm::new(store.clone(), id, size);
            let report = swarm
                .fetch(&needed, &handles, Deadline::tight(), now)
                .await
                .map_err(|e| e.to_string())?;
            self.credit(&report, &node_pks, now);
            let bytes =
                store.read_range(id, start, end - start, now).map_err(|e| e.to_string())?;
            let _ = store.enforce_quota(store_quota());
            bytes
        };

        // Arm the background read-ahead of the next window. Does not block this
        // response and can never error into it.
        self.maybe_spawn_readahead(address, inner_path, id, size, served);
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
        let (conn, _identity, reg) =
            self.dial(&transport, &peer).await.map_err(EdxPushError::Unreachable)?;
        reg.note_cmd_sent("Update", Some(address));
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
            // No store: nothing can be fetched, so every file is missed.
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

        // Encrypted-shard files: no other fetch path exists (they are not in
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
        let session = self.open_session(address, &peers, 8).await;
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
                peer.reg.note_cmd_sent("GetMany", Some(address));
                for chunk in want.chunks(epix_edx::server::MAX_MANY_ITEMS) {
                    let _ = tokio::time::timeout(
                        EDX_FETCH_TIMEOUT,
                        epix_edx::fetch::fetch_many(&peer.conn, &store, chunk, now),
                    )
                    .await;
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

    async fn list_signed(
        &self,
        peer: PeerAddr,
        address: &str,
        since: u64,
    ) -> Result<Option<Vec<(String, u64, u64)>>, String> {
        // Same split as fetch_signed: Err = unreachable (score ConnectFail),
        // Ok(None) = alive but served no list, so try another peer.
        let transport = self.state.transport().await.ok_or("no transport")?;
        let (conn, _identity, reg) = self.dial(&transport, &peer).await?;
        reg.note_cmd_sent("ListSigned", Some(address));
        match tokio::time::timeout(
            EDX_FETCH_TIMEOUT,
            epix_edx::fetch::list_signed(&conn, address, since),
        )
        .await
        {
            Ok(Ok(entries)) => Ok(Some(entries)),
            Ok(Err(_)) | Err(_) => Ok(None),
        }
    }

    async fn pex(
        &self,
        peer: PeerAddr,
        address: &str,
        need: u32,
        have: Vec<PeerAddr>,
    ) -> Result<Vec<PeerAddr>, String> {
        let address = address.to_string();
        self.control(&peer, "Pex", move |conn| async move {
            epix_edx::fetch::pex(&conn, &address, need, have).await
        })
        .await
    }

    async fn get_trackers(&self, peer: PeerAddr) -> Result<Vec<String>, String> {
        self.control(&peer, "GetTrackers", |conn| async move {
            epix_edx::fetch::get_trackers(&conn).await
        })
        .await
    }

    async fn kad(&self, peer: PeerAddr, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        self.control(&peer, "Kad", move |conn| async move {
            epix_edx::fetch::kad(&conn, payload).await
        })
        .await
    }

    async fn announce(&self, peer: PeerAddr, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        self.control(&peer, "Announce", move |conn| async move {
            epix_edx::fetch::announce(&conn, payload).await
        })
        .await
    }

    async fn updates_since(
        &self,
        peer: PeerAddr,
        after: u64,
    ) -> Result<(Vec<(String, i64)>, u64), String> {
        self.control(&peer, "UpdatesSince", move |conn| async move {
            epix_edx::fetch::updates_since(&conn, after).await
        })
        .await
    }
}

/// One warm pooled link: the EDX connection, the version its Hello carried,
/// and its row in the diagnostics registry (held so the row lives as long as
/// the pool keeps the link, and so pings land on it).
struct WarmLink {
    conn: Conn,
    version: String,
    reg: Arc<ConnHandle>,
}

#[async_trait::async_trait]
impl PeerLink for WarmLink {
    fn version(&self) -> &str {
        &self.version
    }

    async fn ping(&self) -> Result<i64, String> {
        let rtt = self.conn.ping().await.map_err(|e| e.to_string())?;
        let ms = rtt.as_millis() as i64;
        self.reg.set_ping_ms(ms);
        Ok(ms)
    }
}

#[async_trait::async_trait]
impl LinkOpener for RuntimeEdxFetcher {
    async fn open_link(&self, peer: PeerAddr) -> Result<Arc<dyn PeerLink>, String> {
        let transport = self.state.transport().await.ok_or("no transport")?;
        let (conn, identity, reg) = self.dial(&transport, &peer).await?;
        Ok(Arc::new(WarmLink { conn, version: identity.version, reg }))
    }
}

/// Carries Kademlia RPCs over EDX for `epix-dht-net`, which owns the payload
/// codec but no link. Installed on the DHT client at startup.
pub struct EdxKadSender {
    state: Arc<AppState>,
}

impl EdxKadSender {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl epix_dht_net::KadSender for EdxKadSender {
    async fn send(&self, to: &PeerAddr, payload: Vec<u8>) -> Result<Vec<u8>, String> {
        self.state.edx_kad(to.clone(), payload).await.unwrap_or_else(|| Err("no EDX fetcher".into()))
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
    let fetcher = Arc::new(RuntimeEdxFetcher::new(state.clone(), privatekey, choker));
    state.set_edx_fetcher(fetcher.clone()).await;
    // Same object behind both seams: the warm pool needs only a ping, so it
    // takes the narrow one.
    state.set_link_opener(fetcher).await;
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
        let server = epix_protocol::PeerServer::new(edx_hook(
                state_b.clone(),
                store_b.clone(),
                server_key,
                None,
                ControlHandles::detached(),
            None,
        ));
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
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
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
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
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
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
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

    /// Read-ahead window/anchor logic, tested as a pure function (no network):
    /// sequential playback advances the window, a seek re-anchors it, a paused
    /// reader (same range re-requested) arms no new prefetch, and it caps at EOF.
    #[test]
    fn readahead_window_advances_and_reanchors() {
        let size = 100 * 1024 * 1024;

        // First touch: window starts right after the served range, anchored there.
        let (w0, a0) = plan_readahead(&(0..1_000_000), size, None).unwrap();
        assert_eq!(w0.start, 1_000_000);
        assert_eq!(w0.end, 1_000_000 + READAHEAD_BYTES);
        assert_eq!(a0, 1_000_000);

        // Sequential playback: a later range slides the window forward.
        let (w1, a1) = plan_readahead(&(1_000_000..2_000_000), size, Some(a0)).unwrap();
        assert_eq!(w1.start, 2_000_000);
        assert!(w1.start > w0.start, "window advanced with the play head");
        assert_eq!(a1, 2_000_000);

        // Paused: the SAME range is re-requested (browser re-issues). The play
        // head has not moved, so no new prefetch is armed - this is the
        // inherent backpressure, not a separate mechanism.
        assert!(
            plan_readahead(&(1_000_000..2_000_000), size, Some(a1)).is_none(),
            "an unmoved play head coalesces to no new read-ahead"
        );

        // Seek far away: the window re-anchors at the new position, not the
        // stale one just ahead of the old play head.
        let (w2, a2) = plan_readahead(&(50_000_000..50_500_000), size, Some(a1)).unwrap();
        assert_eq!(w2.start, 50_500_000, "seek re-anchored the window");
        assert_eq!(a2, 50_500_000);

        // Near EOF: the window is capped to the file, never past it.
        let (w3, _) = plan_readahead(&(size - 100..size - 50), size, Some(0)).unwrap();
        assert_eq!(w3.end, size, "window capped at EOF");
        // Serving the exact tail leaves nothing ahead to warm.
        assert!(plan_readahead(&(size - 10..size), size, None).is_none());
    }

    /// moov head/tail span selection: gated by size, and both spans clamp to
    /// the file. Pure - no network.
    #[test]
    fn moov_spans_gate_on_size_and_clamp() {
        // Below the threshold: no warm-up.
        assert!(moov_spans(1024).is_none());
        assert!(moov_spans(MOOV_MIN_SIZE - 1).is_none());

        // At/above the threshold: a head from 0 and a tail ending at EOF.
        let big = 20 * 1024 * 1024;
        let (head, tail) = moov_spans(big).unwrap();
        assert_eq!(head, 0..MOOV_HEAD_BYTES);
        assert_eq!(tail, big - MOOV_TAIL_BYTES..big);
        assert_eq!(tail.end, big, "tail reaches EOF where the moov atom lives");
    }

    /// End to end: a range fetch near the start of a file spawns a background
    /// read-ahead that warms the rest of the store WITHOUT the caller waiting,
    /// the served bytes are byte-exact regardless, and a re-fetch of an
    /// already-warm range does no work (skips present groups). The seeder's
    /// movie is 400 KB, below the read-ahead window, so the whole tail warms.
    #[tokio::test]
    async fn read_ahead_warms_the_store_after_a_range_serve() {
        let (address, content_bytes, content, movie, addr, _pk) = spawn_seeder().await;

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
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;
        std::mem::forget(a_dir);
        std::mem::forget(a_store_dir);

        // Serve a small range at the start. The bytes must be exactly right.
        let (start, len) = (0u64, 20_000u64);
        let served = match state_a.edx_fetch_range(&address, "movie.bin", start, len).await {
            Some(Ok(Some(b))) => b,
            other => panic!("range fetch: {other:?}"),
        };
        assert_eq!(served, movie[..len as usize], "served range is byte-exact");

        // The background read-ahead warms the rest of the file (window covers
        // it since the movie is smaller than READAHEAD_BYTES). Poll for it -
        // the serve did NOT wait on it.
        let id = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap().b3;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !a_store.is_complete(id).unwrap() {
            assert!(std::time::Instant::now() < deadline, "read-ahead never warmed the store");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Whole file present: a re-fetch of any range is served from the store
        // and is still byte-exact (read-ahead skipped the already-present groups).
        let seek = match state_a.edx_fetch_range(&address, "movie.bin", 300_000, 40_000).await {
            Some(Ok(Some(b))) => b,
            other => panic!("re-fetch: {other:?}"),
        };
        assert_eq!(seek, movie[300_000..340_000], "re-fetched range is byte-exact");
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
        let server = epix_protocol::PeerServer::new(edx_hook(
                state_b.clone(),
                store_b,
                server_key,
                None,
                ControlHandles::detached(),
            None,
        ));
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
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
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
        let server = epix_protocol::PeerServer::new(edx_hook(
                state_b.clone(),
                store_b,
                server_key,
                None,
                ControlHandles::detached(),
            None,
        ));
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
        let fetcher =
            RuntimeEdxFetcher::new(state_a.clone(), epix_crypt::new_seed(), None);

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
        let server = epix_protocol::PeerServer::new(edx_hook(
                state_b.clone(),
                store_b.clone(),
                server_key,
                None,
                ControlHandles::detached(),
            None,
        ));
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
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
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
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                Some(choker.clone()),
            )))
            .await;

        assert!(state_a.edx_fetch_file(&address, "movie.bin").await.unwrap().is_ok());

        // The seeder earned reciprocity credit for the bytes it served us.
        let credit = choker.lock().unwrap().credit_of(&server_pk);
        assert!(credit > 0, "the serving peer should be credited, got {credit}");
    }

    /// `listModified` over EDX: a client asks one peer which signed files
    /// changed since a cutoff, and a cutoff past the newest version reports
    /// nothing (how a resync skips a peer with no news).
    #[tokio::test]
    async fn list_signed_reports_changed_content_json() {
        let (address, _bytes, _content, _movie, addr, _pk) = spawn_seeder().await;
        let state_a = AppState::new("node-a");
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let dir = tempfile::tempdir().unwrap();
        state_a.set_edx_store(Arc::new(Store::open(dir.path()).unwrap())).await;
        std::mem::forget(dir);
        let fetcher =
            RuntimeEdxFetcher::new(state_a.clone(), epix_crypt::new_seed(), None);
        let peer = PeerAddr::Ip(addr);

        let entries = fetcher.list_signed(peer.clone(), &address, 0).await.unwrap().unwrap();
        assert!(
            entries.iter().any(|(path, modified, _)| path == "content.json" && *modified == 1000),
            "list_signed entries {entries:?}"
        );
        let none = fetcher.list_signed(peer, &address, 2000).await.unwrap().unwrap();
        assert!(none.is_empty(), "nothing changed after the newest version, got {none:?}");
    }

    /// The control plane end to end: a seeder that serves it answers a
    /// client's PEX, tracker-set, DHT, tracker-announce and propagation-hint
    /// requests - the five commands the msgpack wire used to carry - and its
    /// Hello reports the node's release version (the Stats `client` column).
    #[tokio::test]
    async fn edx_serves_the_control_plane() {
        use epix_discovery::tracker_pc;

        // The version a peer must see, from the same advert the retired
        // msgpack handshake read.
        epix_protocol::set_self_advert(epix_protocol::SelfAdvert {
            version: "9.9.9".into(),
            ..Default::default()
        });

        // Seeder: a xite with a known peer, a tracker entry, a recorded
        // propagation hint, and its own DHT node.
        let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let site_dir = tempfile::tempdir().unwrap();
        let state_b = AppState::new("node-b");
        state_b
            .add_xite(
                &address,
                XiteEntry { storage: XiteStorage::new(site_dir.path()), content: None },
            )
            .await;
        let known = PeerAddr::parse("9.9.9.9:26552").unwrap();
        state_b.add_peers(&address, [known.clone()]).await;
        let hash = [42u8; 32];
        let tracked = PeerAddr::parse("7.7.7.7:26552").unwrap();
        state_b.tracker_announce(&[hash], &tracked).await;

        let prop = Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new()));
        prop.lock().await.record("1HintedXite", 4242);
        let dht_node = Arc::new(epix_dht::Node::new(epix_dht::NodeId::hash(b"seeder")));
        let control = ControlHandles {
            dht: Arc::new(epix_dht_net::DhtService::new(dht_node.clone())),
            prop: prop.clone(),
        };

        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(Store::open(store_dir.path()).unwrap());
        state_b.set_edx_store(store_b.clone()).await;
        std::mem::forget(site_dir);
        std::mem::forget(store_dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state_b.clone(),
            store_b,
            epix_crypt::new_seed(),
            None,
            control,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // Client: no xites, just the EDX stack.
        let state_a = AppState::new("node-a");
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        state_a.set_edx_store(Arc::new(Store::open(a_store_dir.path()).unwrap())).await;
        std::mem::forget(a_store_dir);
        let fetcher =
            RuntimeEdxFetcher::new(state_a.clone(), epix_crypt::new_seed(), None);
        let peer = PeerAddr::Ip(addr);

        // The handshake advertises the control plane and the release version.
        let transport = state_a.transport().await.unwrap();
        let (_conn, identity, _reg) = fetcher.dial(&transport, &peer).await.unwrap();
        assert_eq!(identity.version, "9.9.9", "the HelloAck carries the node version");
        assert!(identity.caps & caps::CONTROL != 0, "the seeder advertises CONTROL");

        // PEX: we get the peer it knows of that xite.
        let got = fetcher.pex(peer.clone(), &address, 5, Vec::new()).await.unwrap();
        assert!(got.contains(&known), "pex reply {got:?}");

        // Tracker gossip: a working set is served (empty on a bare node).
        assert!(fetcher.get_trackers(peer.clone()).await.unwrap().is_empty());

        // Kad: the seeder's DHT node answers the ping, stamped with its id.
        let me = epix_dht::Contact::new(
            epix_dht::NodeId::hash(b"client"),
            PeerAddr::parse("1.2.3.4:26552").unwrap(),
        );
        let payload = epix_dht_net::pc::encode_request(&me, &epix_dht::Request::Ping);
        let reply = fetcher.kad(peer.clone(), payload).await.unwrap();
        let (id, resp) = epix_dht_net::pc::decode_response(&reply).unwrap();
        assert_eq!(id, dht_node.id, "answered by the seeder's DHT node");
        assert!(matches!(resp, epix_dht::Response::Pong));

        // Announce: the tracker serves the peer it holds for that hash.
        let req = tracker_pc::AnnounceReq {
            hashes: vec![hash],
            need_types: vec!["ipv4".into()],
            need_num: 10,
            ..Default::default()
        };
        let reply = fetcher
            .announce(peer.clone(), tracker_pc::encode_request(&req).unwrap())
            .await
            .unwrap();
        let resp = tracker_pc::decode_reply(&reply).unwrap();
        assert_eq!(resp.error, "");
        assert_eq!(resp.peers.len(), 1, "one bucket set per requested hash");
        assert!(resp.peers[0].unpack().contains(&tracked), "announce reply {:?}", resp.peers[0]);

        // UpdatesSince: the recorded hint comes back with the new cursor.
        let (updates, head) = fetcher.updates_since(peer.clone(), 0).await.unwrap();
        assert_eq!(head, 1);
        assert_eq!(updates, vec![("1HintedXite".to_string(), 4242)]);
    }

    /// The warm pool's link: an EDX connection that answers a frame-level Ping
    /// and reports the peer's version, and shows up on the diagnostics Stats
    /// page (version/ping/bytes) the way the retired msgpack pool did.
    #[tokio::test]
    async fn warm_link_pings_and_lands_on_the_stats_page() {
        epix_protocol::set_self_advert(epix_protocol::SelfAdvert {
            version: "3.2.1".into(),
            ..Default::default()
        });
        let (_address, _content_bytes, _content, _movie, addr, _pk) = spawn_seeder().await;

        let state = AppState::new("client");
        state.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let dir = tempfile::tempdir().unwrap();
        state.set_edx_store(Arc::new(Store::open(dir.path()).unwrap())).await;
        std::mem::forget(dir);
        let fetcher = RuntimeEdxFetcher::new(state.clone(), epix_crypt::new_seed(), None);
        let peer = PeerAddr::Ip(addr);

        let link = fetcher.open_link(peer.clone()).await.expect("warm link");
        assert_eq!(link.version(), "3.2.1", "the peer's Hello version reaches the pool");
        let ms = link.ping().await.expect("the peer answered the ping");
        assert!(ms >= 0);

        let row = epix_protocol::registry::snapshot()
            .into_iter()
            .find(|s| s.addr == peer && s.peer.as_ref().is_some_and(|p| p.protocol == "edx"))
            .expect("the EDX link is listed on the Stats page");
        assert_eq!(row.peer.as_ref().unwrap().version, "3.2.1");
        assert_eq!(row.ping_ms, Some(ms), "the ping is stamped on the row");
        assert!(row.bytes_sent > 0 && row.bytes_recv > 0, "raw link bytes counted");

        // Dropping the link ends its IO tasks, which delists the row.
        drop(link);
        let delisted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !epix_protocol::registry::snapshot().iter().any(|s| s.addr == peer) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert_eq!(delisted, Ok(true), "a dropped link leaves the Stats page");
    }

    /// The INBOUND half of the accept path: a peer that dials us and speaks
    /// EDX lands on the Stats page with its Hello identity, its dial-back
    /// address and the request it made - and fires the inbound hook, which is
    /// how the node learns its fileserver port is open from the internet.
    #[tokio::test]
    async fn an_inbound_edx_peer_is_listed_and_confirms_the_port() {
        epix_protocol::set_self_advert(epix_protocol::SelfAdvert {
            version: "4.5.6".into(),
            ..Default::default()
        });

        // Server: a bare EDX node with an inbound hook recording who reached it.
        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(Store::open(store_dir.path()).unwrap());
        state_b.set_edx_store(store_b.clone()).await;
        std::mem::forget(store_dir);
        let seen: Arc<Mutex<Vec<PeerAddr>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_hook = seen.clone();
        let hook: InboundHook = Arc::new(move |peer: &PeerAddr| {
            seen_hook.lock().expect("seen").push(peer.clone());
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state_b.clone(),
            store_b,
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            Some(hook),
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // Client: dial, Hello with a dial-back address, then one real request.
        let dialback = PeerAddr::parse("203.0.113.9:26552").unwrap();
        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        let a_store = Arc::new(Store::open(a_dir.path()).unwrap());
        std::mem::forget(a_dir);
        let ctx = ServeCtx::new(
            a_store,
            Arc::new(AppStateProvider { state: state_a.clone() }),
            epix_crypt::new_seed(),
        )
        .with_version("4.5.6".into());
        let stream = TcpTransport.dial(&PeerAddr::Ip(addr)).await.unwrap();
        let link = epix_edx::link::dial(stream).await.unwrap();
        client_hello(&link.conn, &ctx, vec![dialback.clone()], Some(link.handshake_hash))
            .await
            .unwrap();
        let _ = epix_edx::fetch::fetch_signed(&link.conn, "1NoSuchXite", "content.json").await;

        // The row appears under the ADDRESS THE PEER SAID we can dial it back
        // on, not the ephemeral socket it reached us from.
        let row = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let found = epix_protocol::registry::snapshot().into_iter().find(|s| {
                    s.direction == Direction::In
                        && s.addr == dialback
                        && !s.last_cmd_recv.is_empty()
                });
                if let Some(row) = found {
                    return row;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the inbound EDX peer is listed on the Stats page");
        assert_eq!(row.peer.as_ref().expect("Hello identity").version, "4.5.6");
        assert_eq!(row.last_cmd_recv, "GetSigned");
        assert_eq!(row.xites, vec!["1NoSuchXite".to_string()]);
        assert!(row.bytes_recv > 0 && row.bytes_sent > 0, "raw link bytes counted");

        let seen = seen.lock().expect("seen").clone();
        assert!(
            seen.iter().any(|p| matches!(p, PeerAddr::Ip(a) if a.ip().is_loopback())),
            "the hook saw the SOURCE address that proved the port reachable, got {seen:?}"
        );
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
                .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                    state.clone(),
                    epix_crypt::new_seed(),
                    None,
                )))
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
