//! EDX serving glue: an `AppState`-backed [`SignedProvider`] and the
//! accept-hooks that plug the EDX protocol server into every transport's
//! accept loop. Installed only when an EDX object store is present on the
//! node (see [`enable_serving`]); without one there is nowhere to hold
//! content, so such a node fetches but does not seed.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::{Arc, Mutex};

use epix_blob::policy::{FetchTier, OrderPolicy};
use epix_blob::store::Store;
use epix_blob::{Ns, ObjId};
use epix_core::PeerAddr;
use epix_edx::choke::{Choker, Reach};
use epix_edx::conn::{Conn, Incoming};
use epix_edx::msg::{caps, Hello, Req};
use epix_edx::sched::{needed_groups, Deadline, PeerHandle, Swarm};
use epix_edx::server::{
    client_hello, serve, serve_authenticated_observed, ControlProvider, PeerIdentity, ServeCtx,
    SignedProvider, UpdateSource,
};
use epix_edx::sim::Class;
use epix_protocol::registry::{ConnHandle, Direction};
use epix_protocol::server::{EdxHook, InboundHook};
use epix_protocol::HandshakeInfo;
use epix_transport::Transport;
use epix_ui::conn_pool::{LinkOpener, PeerLink};
use epix_ui::state::{
    EdxBatch, EdxBatchProgress, EdxFetcher, EdxMaterializeAuthority, EdxObjectRef,
    EdxPushError, EdxWant, InboundEdxSource, InboundUpdate, UpdatePayload,
    MAX_MERGE_DELTA_OBJECT_BYTES,
};
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

/// The dial-back address an inbound OVERLAY link advertised in its Hello,
/// written by the request tap and read by that connection's control provider.
/// An overlay link is accepted under a blank placeholder address, so this is
/// the only thing PEX can record the requester under.
type DialbackSlot = Arc<Mutex<Option<PeerAddr>>>;

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
        Req::HasShards { .. } => "HasShards",
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
    dialback: DialbackSlot,
) -> tokio::sync::mpsc::Receiver<Incoming> {
    let (tx, rx) = tokio::sync::mpsc::channel(INBOUND_TAP_DEPTH);
    tokio::spawn(async move {
        while let Some(inc) = incoming.recv().await {
            if let Req::Hello(hello) = &inc.req {
                reg.activate();
                reg.set_peer(handshake_info(&hello.version, &hello.node_pk));
                adopt_dialback(&reg, hello, &source, &dialback);
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
///
/// The same claim also fills the connection's [`DialbackSlot`], but ONLY for an
/// inbound overlay link accepted under a placeholder and only from a listen
/// address of the SAME transport class. Without it a Tor/I2P-only seeder whose
/// first contact is a `Req::Pex` can never be recorded as a peer: the
/// placeholder it is served under is not an address. Clearnet keeps its
/// socket-sourced address, which the peer asserts nothing about.
fn adopt_dialback(
    reg: &ConnHandle,
    hello: &Hello,
    source: &PeerAddr,
    dialback: &DialbackSlot,
) {
    if let Some(addr) =
        hello.listen.iter().find(|a| a.is_wellformed() && a.pack().is_some())
    {
        reg.set_addr(addr.clone());
    }
    if !source.is_overlay() || source.is_wellformed() {
        return;
    }
    if let Some(addr) = hello.listen.iter().find(|a| {
        a.scheme() == source.scheme() && a.is_wellformed() && a.pack().is_some()
    }) {
        *dialback.lock().expect("dialback") = Some(addr.clone());
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

/// Versioned envelope stored in `Req::Update.inline`. `epix-edx` deliberately
/// treats inline objects as opaque bytes; the runtime maps one content-addressed
/// object back to the merge path and signed OR-set delta it carries.
#[derive(serde::Serialize, serde::Deserialize)]
struct InlineMergeDelta {
    path: String,
    body: InlineMergeBody,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum InlineMergeBody {
    /// A small complete signed OR-set delta carried in the Update frame.
    Records(Vec<u8>),
    /// A verified immutable delta pulled over the same authenticated link.
    Object { id: ObjId, size: u64 },
    /// Compatibility for an older state snapshot that has only a changed-path
    /// marker. The receiver must fall back to GetSigned for the full file.
    LegacyPull,
}

#[derive(Default)]
struct DecodedInlineMerges {
    deltas: HashMap<String, Vec<u8>>,
    objects: HashMap<String, EdxObjectRef>,
}

impl DecodedInlineMerges {
    fn insert(
        &mut self,
        delta: InlineMergeDelta,
        total_delta_bytes: &mut u64,
    ) -> Result<(), String> {
        let InlineMergeDelta { path, body } = delta;
        if self.deltas.contains_key(&path) || self.objects.contains_key(&path) {
            return Err(format!("duplicate inline merge path: {path}"));
        }
        match body {
            InlineMergeBody::Records(records) => {
                if records.is_empty() || records.len() > MAX_INLINE_MERGE_BYTES {
                    return Err(format!(
                        "inline merge delta for {path} has an invalid byte length"
                    ));
                }
                add_merge_payload_bytes(
                    total_delta_bytes,
                    records.len() as u64,
                    "aggregate inline merge size overflow",
                )?;
                self.deltas.insert(path, records);
            }
            InlineMergeBody::Object { id, size } => {
                if size == 0 || size > MAX_MERGE_DELTA_OBJECT_BYTES {
                    return Err(format!(
                        "merge delta object for {path} has an invalid byte length"
                    ));
                }
                add_merge_payload_bytes(
                    total_delta_bytes,
                    size,
                    "aggregate merge object size overflow",
                )?;
                self.objects.insert(path, EdxObjectRef { id, size });
            }
            InlineMergeBody::LegacyPull => {
                self.deltas.insert(path, Vec::new());
            }
        }
        Ok(())
    }
}

type InlineMergeWire = Vec<(ObjId, Vec<u8>)>;
type InlineMergeEntries<'a> = Vec<(&'a str, &'a [u8])>;

const INLINE_MERGE_MAGIC: &[u8] = b"EPIX-MERGE-2\0";
/// A pushed social update stays a control message. Larger merge containers
/// are pulled over the authenticated source session instead of being copied
/// into every gossip hop.
const MAX_INLINE_MERGE_BYTES: usize = 32 * 1024;
const MAX_INLINE_MERGES: usize = 8;
/// Headroom reserved below the protocol frame cap for the Update fields
/// outside the inline object list: `xite` and `inner_path` (up to
/// MAX_INNER_PATH_BYTES each), five dial-back addresses, per-file diffs'
/// framing, and postcard's own envelope.
const UPDATE_ENVELOPE_HEADROOM: usize = 8 * 1024;
/// Derived from the protocol crate's exported frame cap so a change there
/// moves this budget with it instead of silently drifting past it. Both the
/// send-side fit check and the receive-side marker validation use this one
/// constant.
const UPDATE_FRAME_BUDGET: usize = epix_edx::MAX_FRAME_LEN - UPDATE_ENVELOPE_HEADROOM;

/// Conservative wire cost of one inline entry: the 32-byte ObjId plus the
/// byte payload, with headroom for postcard's length varints and the outer
/// Vec framing. Deliberately an over-estimate — the budget check must never
/// admit a set the frame encoder then rejects.
const INLINE_MERGE_ENTRY_OVERHEAD: usize = 48;

fn inline_merge_wire_len(inline: &InlineMergeWire) -> usize {
    inline
        .iter()
        .map(|(_, bytes)| bytes.len() + INLINE_MERGE_ENTRY_OVERHEAD)
        .sum()
}

fn encode_inline_merge(path: &str, body: InlineMergeBody) -> Result<(ObjId, Vec<u8>), String> {
    let encoded = postcard::to_stdvec(&InlineMergeDelta { path: path.to_string(), body })
    .map_err(|e| format!("failed to encode inline merge marker for {path}: {e}"))?;
    let mut bytes = Vec::with_capacity(INLINE_MERGE_MAGIC.len() + encoded.len());
    bytes.extend_from_slice(INLINE_MERGE_MAGIC);
    bytes.extend_from_slice(&encoded);
    Ok((ObjId::of(&bytes), bytes))
}

fn sorted_inline_merge_entries(
    merges: &HashMap<String, Vec<u8>>,
) -> Result<InlineMergeEntries<'_>, String> {
    if merges.len() > MAX_INLINE_MERGES {
        return Err(format!(
            "update has {} merge paths, maximum is {MAX_INLINE_MERGES}",
            merges.len()
        ));
    }
    let mut entries: Vec<_> = merges.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    for (path, _) in &entries {
        if !safe_inner_path(path) {
            return Err(format!("unsafe merge path in update: {path}"));
        }
    }
    if let Some((path, records)) = entries
        .iter()
        .find(|(_, records)| records.len() as u64 > MAX_MERGE_DELTA_OBJECT_BYTES)
    {
        return Err(format!(
            "merge delta for {path} is {} bytes, maximum is {MAX_MERGE_DELTA_OBJECT_BYTES}",
            records.len()
        ));
    }
    let total = entries.iter().try_fold(0u64, |total, (_, records)| {
        total.checked_add(records.len() as u64)
    });
    if total.is_none_or(|total| total > MAX_MERGE_DELTA_OBJECT_BYTES) {
        return Err(format!(
            "aggregate merge delta payload exceeds {MAX_MERGE_DELTA_OBJECT_BYTES} bytes"
        ));
    }
    Ok(entries.into_iter().map(|(path, records)| (path.as_str(), records.as_slice())).collect())
}

/// Encode the complete signed delta set when every value is small enough and
/// the whole path-complete set fits the Update budget. `None` means callers
/// must register immutable delta objects and encode object markers instead.
fn encode_inline_merge_records(
    merges: &HashMap<String, Vec<u8>>,
) -> Result<Option<InlineMergeWire>, String> {
    let entries = sorted_inline_merge_entries(merges)?;
    if entries.iter().any(|(_, records)| records.len() > MAX_INLINE_MERGE_BYTES) {
        return Ok(None);
    }
    let complete = entries
        .iter()
        .map(|(path, records)| {
            let body = if records.is_empty() {
                InlineMergeBody::LegacyPull
            } else {
                InlineMergeBody::Records(records.to_vec())
            };
            encode_inline_merge(path, body)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((inline_merge_wire_len(&complete) < UPDATE_FRAME_BUDGET).then_some(complete))
}

/// Encode one path-complete object-marker set. Non-empty deltas must already
/// be present in the publisher's Store under the supplied id and size. Empty
/// values are retained only as the legacy full-file pull marker.
fn encode_inline_merge_objects(
    merges: &HashMap<String, Vec<u8>>,
    objects: &HashMap<String, EdxObjectRef>,
) -> Result<InlineMergeWire, String> {
    let entries = sorted_inline_merge_entries(merges)?;
    let markers = entries
        .iter()
        .map(|(path, records)| {
            let body = if records.is_empty() {
                InlineMergeBody::LegacyPull
            } else {
                let object = objects
                    .get(*path)
                    .ok_or_else(|| format!("missing delta object for merge path {path}"))?;
                if object.size != records.len() as u64 || object.id != ObjId::of(records) {
                    return Err(format!("delta object metadata mismatch for merge path {path}"));
                }
                InlineMergeBody::Object { id: object.id, size: object.size }
            };
            encode_inline_merge(path, body)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if inline_merge_wire_len(&markers) >= UPDATE_FRAME_BUDGET {
        return Err("merge path markers do not fit the Update frame budget".into());
    }
    Ok(markers)
}

fn select_update_merge_wire(
    supports_inline: bool,
    candidate_inline: Option<InlineMergeWire>,
    merges: &HashMap<String, Vec<u8>>,
    objects: &HashMap<String, EdxObjectRef>,
) -> Result<InlineMergeWire, String> {
    if !supports_inline {
        return Ok(Vec::new());
    }
    match candidate_inline {
        Some(inline) => Ok(inline),
        None => encode_inline_merge_objects(merges, objects),
    }
}

/// Decode one merge envelope. `INLINE_MERGE` promises that every entry uses
/// this versioned format, so an unknown kind must fail closed. Silently
/// skipping it would answer `Ok` and let a sender retire payload state that
/// this receiver never handled. A future inline kind needs its own negotiated
/// capability or an explicitly optional envelope bit.
fn decode_inline_merge_envelope(id: ObjId, bytes: &[u8]) -> Result<InlineMergeDelta, String> {
    if ObjId::of(bytes) != id {
        return Err("inline merge object hash mismatch".into());
    }
    if !bytes.starts_with(INLINE_MERGE_MAGIC) {
        return Err("unsupported inline object on merge-capable Update".into());
    }
    let delta = postcard::from_bytes::<InlineMergeDelta>(&bytes[INLINE_MERGE_MAGIC.len()..])
        .map_err(|e| format!("malformed inline merge envelope: {e}"))?;
    if !safe_inner_path(&delta.path) {
        return Err(format!("unsafe inline merge path: {}", delta.path));
    }
    Ok(delta)
}

fn add_merge_payload_bytes(
    total: &mut u64,
    size: u64,
    overflow_message: &'static str,
) -> Result<(), String> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| overflow_message.to_string())?;
    if *total > MAX_MERGE_DELTA_OBJECT_BYTES {
        return Err(format!(
            "aggregate merge payload exceeds {MAX_MERGE_DELTA_OBJECT_BYTES} bytes"
        ));
    }
    Ok(())
}

/// Decode only runtime-owned merge envelopes. Other inline object types are
/// rejected for a capability-gated Update. Hash mismatch, malformed postcard,
/// unsafe path, and duplicate path all fail closed before application checks.
fn decode_inline_merges(inline: &[(ObjId, Vec<u8>)]) -> Result<DecodedInlineMerges, String> {
    if inline.len() > MAX_INLINE_MERGES {
        return Err(format!(
            "update has {} inline merge objects, maximum is {MAX_INLINE_MERGES}",
            inline.len()
        ));
    }
    let mut out = DecodedInlineMerges::default();
    let mut total_delta_bytes = 0u64;
    for (id, bytes) in inline {
        let delta = decode_inline_merge_envelope(*id, bytes)?;
        out.insert(delta, &mut total_delta_bytes)?;
    }
    Ok(out)
}

fn decode_update_inline(
    inline: &[(ObjId, Vec<u8>)],
    require_merge_delivery: bool,
) -> Result<DecodedInlineMerges, String> {
    if !require_merge_delivery {
        return Ok(DecodedInlineMerges::default());
    }
    decode_inline_merges(inline)
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

/// Drop a sparse record THIS call reserved when the fetch left it empty. The
/// reserved size comes from the xite owner's content.json, so a record nobody
/// ever filled is a phantom index row plus a sparse/.obao file pair. A record
/// that already existed, or that took any groups, is kept.
///
/// Only ever called from [`ObjClaim::drop`], which guarantees no other fetch of
/// the same object is still filling it.
fn drop_if_unfilled(store: &Store, id: ObjId, fresh: bool) {
    if !fresh {
        return;
    }
    if store.present_bits(id).map(|b| b.is_empty()).unwrap_or(false) {
        let _ = store.remove(id);
    }
}

/// The in-flight claims on an object, by count, plus whether any claim was the
/// one that created the record. An entry is erased when its count reaches zero,
/// so the map is bounded by the number of concurrent fetches.
type ObjClaims = Arc<Mutex<HashMap<ObjId, (usize, bool)>>>;
type MergePrepareCell = tokio::sync::OnceCell<Result<(), String>>;
type MergePrepareGate = Arc<MergePrepareCell>;
type MergePrepareGates = Arc<Mutex<HashMap<ObjId, std::sync::Weak<MergePrepareCell>>>>;
type MergeQuotaMemo = Arc<Mutex<Option<(std::sync::Weak<UpdatePayload>, Arc<MergeQuotaWave>)>>>;

/// One payload fanout's final quota reconciliation. Every peer still owns an
/// independent Store eviction hold through its Update RPC. The last lease
/// clears after its hold and runs the table scan exactly when the object is
/// finally evictable. A later peer may start a new lease and safely reconcile
/// again. Drop-based cleanup also covers cancellation and error paths.
/// `Store::enforce_quota` scans the whole object table; one publish's
/// staggered per-peer leases can drive the wave count to zero many times per
/// batch, so transitions inside this window skip the scan. The fetch paths
/// call `enforce_quota` on their own, covering any residual overshoot -
/// the same tolerance the old flat 5-second throttle had.
const QUOTA_ENFORCE_THROTTLE_MS: u64 = 5_000;

struct MergeQuotaWave {
    store: Arc<Store>,
    quota: u64,
    active: std::sync::atomic::AtomicUsize,
    created: std::time::Instant,
    /// Elapsed ms since `created`, plus 1, of the last enforcement; 0 = never.
    enforced_at: std::sync::atomic::AtomicU64,
}

impl MergeQuotaWave {
    fn new(store: Arc<Store>, quota: u64) -> Arc<Self> {
        Arc::new(Self {
            store,
            quota,
            active: std::sync::atomic::AtomicUsize::new(0),
            created: std::time::Instant::now(),
            enforced_at: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn lease(self: &Arc<Self>) -> MergeQuotaLease {
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        MergeQuotaLease { wave: self.clone() }
    }
}

struct MergeQuotaLease {
    wave: Arc<MergeQuotaWave>,
}

impl Drop for MergeQuotaLease {
    fn drop(&mut self) {
        if self
            .wave
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            let now = self.wave.created.elapsed().as_millis() as u64 + 1;
            let last = self
                .wave
                .enforced_at
                .load(std::sync::atomic::Ordering::Relaxed);
            let due = last == 0 || now.saturating_sub(last) >= QUOTA_ENFORCE_THROTTLE_MS;
            if due
                && self
                    .wave
                    .enforced_at
                    .compare_exchange(
                        last,
                        now,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok()
            {
                let _ = self.wave.store.enforce_quota(self.wave.quota);
            }
        }
    }
}

struct PreparedMergeObjects<'a> {
    _preparations: Vec<MergePrepareGate>,
    _holds: Vec<epix_blob::store::EvictionHold<'a>>,
    quota: Option<MergeQuotaLease>,
    objects: HashMap<String, EdxObjectRef>,
}

impl Drop for PreparedMergeObjects<'_> {
    fn drop(&mut self) {
        // The final quota lease must see every per-peer eviction hold gone.
        // Release completed preparation gates too, so a peer starting after
        // enforcement cannot reuse an `Ok` cell for an object just evicted.
        self._holds.clear();
        self._preparations.clear();
        self.quota.take();
    }
}

/// Fetch guards shared by every runtime adapter that writes into one Store.
/// Same-session Update sources construct a short-lived fetcher, while ordinary
/// downloads use the node's long-lived fetcher. Keying these guards by Store
/// keeps both paths in the same claim and materialization domains.
struct StoreFetchShared {
    claims: ObjClaims,
    materialize_gate: Arc<tokio::sync::Semaphore>,
}

type StoreFetchSharedRegistry = Mutex<HashMap<usize, std::sync::Weak<StoreFetchShared>>>;

fn store_fetch_shared(store: &Arc<Store>) -> Arc<StoreFetchShared> {
    static SHARED: std::sync::OnceLock<StoreFetchSharedRegistry> = std::sync::OnceLock::new();
    let key = Arc::as_ptr(store) as usize;
    let mut registry = SHARED.get_or_init(Default::default).lock().expect("store fetch guards");
    registry.retain(|candidate, shared| *candidate == key || shared.strong_count() > 0);
    if let Some(shared) = registry.get(&key).and_then(std::sync::Weak::upgrade) {
        return shared;
    }
    let shared = Arc::new(StoreFetchShared {
        claims: Arc::default(),
        materialize_gate: Arc::new(tokio::sync::Semaphore::new(MATERIALIZE_CONCURRENCY)),
    });
    registry.insert(key, Arc::downgrade(&shared));
    shared
}

/// A live claim on an object being filled, held for the whole fetch. While any
/// claim on an id exists nobody removes that id's record; the LAST claim to go
/// away removes it if the object is still empty and some claim created it.
///
/// Needed because fetches of one object overlap by design: `maybe_warm_moov`
/// spawns a background read-ahead BEFORE the foreground range fetch of the same
/// file, and a media element issues concurrent Range requests with no
/// per-object serialization. Without the claim the first one to give up
/// unlinked the sparse pair out from under the others, so an in-flight
/// `write_slice` started failing and a range that would have succeeded 404'd.
struct ObjClaim {
    shared: Arc<StoreFetchShared>,
    store: Arc<Store>,
    id: ObjId,
}

impl Drop for ObjClaim {
    fn drop(&mut self) {
        // A poisoned lock only means another fetch panicked: skipping the
        // cleanup leaves one empty record behind, panicking here would abort.
        let Ok(mut claims) = self.shared.claims.lock() else { return };
        let fresh = match claims.get_mut(&self.id) {
            Some(slot) => {
                slot.0 -= 1;
                if slot.0 > 0 {
                    return; // another fetch is still filling this object
                }
                slot.1
            }
            None => return,
        };
        claims.remove(&self.id);
        // Removed while still holding the claims lock, which closes the window
        // between `Store::remove` committing the record delete and unlinking
        // the files: a fetch about to claim this object blocks here instead of
        // slipping its `ensure_sparse` into that gap and having the files it
        // just created deleted underneath it.
        drop_if_unfilled(&self.store, self.id, fresh);
    }
}

/// Assumed total network shard bytes, used to turn a volunteer's byte quota
/// into a keyspace fraction for the responsibility predicate. Nothing on
/// chain or in the DHT sources this in the foundation (discovery is
/// deferred), so it is a tuned constant a network operator picks; the
/// predicate is correct and monotone for any positive value. Override with
/// EPIX_EDX_SHARD_UNIVERSE_BYTES (also how tests make the responsible set
/// deterministic).
const VOLUNTEER_SHARD_UNIVERSE_BYTES: u64 = 1 << 40; // 1 TiB placeholder

fn shard_universe_bytes() -> u64 {
    std::env::var("EPIX_EDX_SHARD_UNIVERSE_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(VOLUNTEER_SHARD_UNIVERSE_BYTES)
}

/// How far ahead of the play position a served range prefetches. Sized for
/// overlay links: a Tor circuit moves a few hundred KB/s, so the pipeline
/// must stay minutes deep for sequential playback to find its bytes already
/// in the store. Read-ahead skips present groups and a seek re-anchors the
/// window, so the cost of a seek away is only the in-flight batches.
const READAHEAD_BYTES: u64 = 48 * 1024 * 1024;

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

/// How long a serve's dialed peer sessions stay reusable — by the next
/// windows of the same file AND its read-ahead. Overlay dials cost tens of
/// seconds, so consecutive 4 MiB windows of one playback must ride the same
/// links instead of redialing per window. Reuse revalidates each cached
/// handle (bitfield refresh) and evicts the dead, so a stale entry costs one
/// cheap round trip, never a wrong serve.
const PEER_CACHE_TTL: u64 = 120;

/// How long a peer session may be reused before it is re-dialed from scratch,
/// however well it is working.
///
/// Reuse re-stamps the TTL, so a session that keeps delivering is never
/// rebuilt - and `peers_for` only rebuilds when the cached links cannot
/// SUPPLY the needed groups. One seeder holding the whole file satisfies that
/// forever, so a stream would pin itself to whichever peers answered first and
/// never pick up one discovered later, however much faster the swarm had
/// become. Measured on a 567 MB film: pinned to a single I2P link it drew
/// 138-358 KB/s against the 795 KB/s the film needed and stalled constantly,
/// while a freshly dialed session over the same swarm reached 794 KB/s.
///
/// Rebuilding periodically costs one concurrent dial round, which the link
/// pool mostly serves warm, and lets a long stream keep finding capacity.
/// "Can supply" is not the same as "can supply fast enough".
const SESSION_MAX_AGE: u64 = 90;

/// How many EDX dials a session opens at once. Dead overlay peers take up to
/// their whole connect timeout to fail, so dialing serially let one dead
/// onion stall the serve for 45s per peer; a small cap keeps a dial burst
/// from flooding the Tor/I2P client.
const SESSION_DIAL_CONCURRENCY: usize = 4;

/// Bound on a cached-session revalidation round trip (one GetBitfield per
/// live link). Much tighter than EDX_FETCH_TIMEOUT: a healthy overlay link
/// answers in a couple of seconds, and a dead one must not stall the serve
/// for the full request timeout before the session falls back to fresh dials.
const SESSION_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a session keeps collecting further dial results once the FIRST
/// usable handle exists. A live seeder must start serving in seconds while
/// dead overlay peers burn their connect timeouts in the background —
/// waiting for every dial to resolve gated cold-start time-to-first-byte
/// on the slowest dead onion (up to ~90 s). Peers resolving within the
/// grace still join the swarm; later ones are dropped, their outcomes
/// still reach the peer registry, and the next session (or the missing-
/// group fallback in `peers_for`) picks them up.
const SESSION_FIRST_HANDLE_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

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

/// The chunk groups of the byte `window` that `present` still lacks - the
/// only groups a range fetch or read-ahead asks the swarm for, so a window
/// overlapping already-held bytes costs no network. Pure (shared by the
/// serve path and `run_readahead`).
fn missing_groups(
    present: &epix_blob::bitfield::GroupBits,
    window: &Range<u64>,
) -> epix_blob::bitfield::GroupBits {
    let want = epix_blob::bitfield::groups_for_bytes(window);
    let mut needed = epix_blob::bitfield::GroupBits::new();
    for gap in present.gaps(&want) {
        needed.add(gap);
    }
    needed
}

/// Whether any handle holds at least one of the `needed` groups — the bar
/// a cached peer session must clear to be reused for a fetch of them. An
/// empty `needed` (nothing to fetch) clears it trivially. Pure.
fn can_supply(handles: &[PeerHandle], needed: &epix_blob::bitfield::GroupBits) -> bool {
    needed.is_empty()
        || needed
            .ranges()
            .iter()
            .any(|r| r.clone().any(|g| handles.iter().any(|h| h.bits.contains(g))))
}

/// The length of the contiguous prefix of the byte `window` whose covering
/// groups are all in `present`, clamped to `size`. What a partial fetch can
/// serve as a shorter 206 instead of a 404. Pure.
fn present_prefix_len(
    present: &epix_blob::bitfield::GroupBits,
    window: &Range<u64>,
    size: u64,
) -> u64 {
    let mut end = window.start;
    for g in epix_blob::bitfield::groups_for_bytes(window) {
        if !present.contains(g) {
            break;
        }
        end = epix_blob::bitfield::bytes_of_group(g, size).end.min(window.end);
    }
    end - window.start
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
/// ungoverned. One instance is shared between serving and fetching. The
/// bulk-lane pacer is armed with the same cap: the choker decides WHO is
/// served, the pacer smooths admitted bulk onto the wire at this rate
/// (whole-request refusal at the per-second bucket is first-paint only
/// now). Ungoverned nodes leave the pacer off too.
pub fn make_choker() -> Option<SharedChoker> {
    if env_on("EPIX_EDX_RECIPROCITY") {
        epix_edx::pace::bulk().set_rate(EDX_UPLOAD_CAP_BPS);
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

/// Cap on one signed body served over `GetSigned`. Deliberately the SAME value
/// as the client's reassembly cap in `epix_edx::fetch`, so anything a peer will
/// accept is something we will serve: a lower serve cap makes a xite whose
/// content.json (or grow-only merge file) crossed it uncloneable over EDX, the
/// exact failure `serve_signed`'s frame chunking exists to avoid. The read
/// stops at the cap, so a file that grows under us is refused rather than read
/// whole, and a peer still cannot name something huge and pick our allocation
/// size.
const MAX_SIGNED_BYTES: u64 = epix_edx::fetch::MAX_SIGNED_BYTES as u64;

/// Bounds on a peer-supplied inner_path. One frame carries ~64 KB, and a path
/// that is not a content.json goes on to the merge-file check, which walks the
/// path one segment at a time doing a filesystem read per segment - quadratic
/// in the path length. A real inner_path is a handful of short segments, so
/// capping the shape here keeps that walk from being a remote CPU lever.
const MAX_INNER_PATH_BYTES: usize = 1024;
const MAX_INNER_PATH_SEGMENTS: usize = 16;

/// True for a well-formed relative inner_path: no absolute path, no `..`, no
/// empty or `.` segment, no backslash, and bounded in length and depth.
/// `XiteStorage::path` rejects the same shapes; checking here keeps a crafted
/// path from reaching the filesystem or the per-segment merge-file walk.
fn safe_inner_path(inner_path: &str) -> bool {
    !inner_path.is_empty()
        && inner_path.len() <= MAX_INNER_PATH_BYTES
        && !inner_path.contains('\\')
        && inner_path.split('/').count() <= MAX_INNER_PATH_SEGMENTS
        && inner_path.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Backs epix-edx signed-content requests with the node's accepted manifest
/// index and exact-chain update application.
struct AppStateProvider {
    state: Arc<AppState>,
}

/// Narrow adapter around the authenticated connection that delivered an
/// Update. It lets the state layer prefer that exact source for both mutable
/// signed files and immutable large objects without depending on EDX types.
struct LiveUpdateSource {
    state: Arc<AppState>,
    address: String,
    source: UpdateSource,
}

#[async_trait::async_trait]
impl InboundEdxSource for LiveUpdateSource {
    async fn fetch_signed(&self, xite: &str, inner_path: &str) -> Result<Option<Vec<u8>>, String> {
        match tokio::time::timeout(
            EDX_FETCH_TIMEOUT,
            epix_edx::fetch::fetch_signed(&self.source.conn, xite, inner_path),
        )
        .await
        {
            Ok(Ok(bytes)) => Ok(Some(bytes)),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_) => Err("same-session GetSigned timed out".into()),
        }
    }

    async fn fetch_object(&self, id: ObjId, size: u64) -> Result<Option<Vec<u8>>, String> {
        let class = match self.source.reach {
            Reach::Clearnet => Class::Clearnet,
            Reach::Overlay => Class::Tor,
        };
        let label = format!("source:{}", hex::encode(&self.source.identity.node_pk));
        RuntimeEdxFetcher::new(self.state.clone(), String::new(), None)
            .fetch_object_over_source(
                &self.address,
                EdxObjectRef { id, size },
                self.source.conn.clone(),
                class,
                label,
                self.source.identity.node_pk.clone(),
            )
            .await
            .map(Some)
    }

    async fn fetch_files(
        &self,
        address: &str,
        want: Vec<EdxWant>,
        staged: Option<serde_json::Value>,
        on_file: Option<EdxBatchProgress>,
    ) -> EdxBatch {
        let class = match self.source.reach {
            Reach::Clearnet => Class::Clearnet,
            Reach::Overlay => Class::Tor,
        };
        let label = format!("source:{}", hex::encode(&self.source.identity.node_pk));
        // The direct path does not dial or sign a new Hello, so its private key
        // and link pool are unused. It still reuses the normal verified object
        // scheduler, sparse store, materializer, and quota enforcement.
        RuntimeEdxFetcher::new(self.state.clone(), String::new(), None)
            .fetch_files_over_source(
                address,
                want,
                staged,
                on_file,
                self.source.conn.clone(),
                class,
                label,
                self.source.identity.node_pk.clone(),
            )
            .await
    }
}

#[async_trait::async_trait]
impl SignedProvider for AppStateProvider {
    async fn get_signed(&self, xite: &str, inner_path: &str) -> Option<Vec<u8>> {
        if !safe_inner_path(inner_path) {
            return None;
        }
        self.state
            .edx_read_verified_signed(xite, inner_path, MAX_SIGNED_BYTES)
            .await
    }

    async fn list_signed(&self, xite: &str, since: u64) -> Vec<(String, u64, u64)> {
        self.state
            .edx_verified_signed_list(xite, since as f64, MAX_SIGNED_BYTES)
            .await
    }

    async fn xite_summary(&self, xite: &str) -> Option<(u64, u64, u64)> {
        let entries = self
            .state
            .edx_verified_signed_list(xite, 0.0, MAX_SIGNED_BYTES)
            .await;
        if entries.is_empty() {
            return None;
        }
        let newest = entries.iter().map(|(_, modified, _)| *modified).max().unwrap_or(0);
        let held_bytes = entries
            .iter()
            .fold(0u64, |total, (_, _, size)| total.saturating_add(*size));
        Some((entries.len() as u64, newest, held_bytes))
    }

    async fn apply_update(
        &self,
        xite: &str,
        inner_path: &str,
        signed: &[u8],
        inline: &[(ObjId, Vec<u8>)],
        modified: f64,
        diffs: &[(String, Vec<u8>)],
        sender_peers: &[String],
        source: UpdateSource,
    ) -> Result<bool, String> {
        let require_merge_delivery =
            caps::supports(source.identity.caps, caps::INLINE_MERGE);
        let decoded = decode_update_inline(inline, require_merge_delivery)?;
        // Lower the EDX message into what the inbound-update path expects:
        // decode regular-file diffs and the bounded merge envelopes. The UI
        // layer verifies the child manifest first, then checks the exact
        // declared merge path and every record signature before writing.
        let payload = UpdatePayload {
            diffs: decode_edx_diffs(diffs),
            merge_deltas: decoded.deltas,
            merge_objects: decoded.objects,
            require_merge_delivery,
        };
        let sender_peers: Vec<PeerAddr> =
            sender_peers.iter().filter_map(|s| PeerAddr::parse(s).ok()).take(5).collect();
        // Same-session pulls only work against a sender that serves the
        // reverse direction of its dialed link. Legacy binaries drop that
        // half and silently ignore our requests, so every live fetch would
        // black-hole for the full fetch timeout, per path, inside this
        // handler. INLINE_MERGE is only advertised by builds that also
        // reverse-serve, so gate the live source on it and send capless
        // senders' updates straight to the dial-out fallback.
        let source: Option<Arc<dyn InboundEdxSource>> = require_merge_delivery.then(|| {
            Arc::new(LiveUpdateSource {
                state: self.state.clone(),
                address: xite.to_string(),
                source,
            }) as Arc<dyn InboundEdxSource>
        });
        // No `sender` PeerAddr is needed. The authenticated `source` preserves
        // the exact live connection for the first pull, and self-declared
        // addresses remain screened fallbacks in `sender_peers`. Promoting the
        // first unverified address to `sender` would put it ahead of the
        // is-own-peer and dialable-network filters. A peer could then name our
        // own address and make us dial ourselves for every missing file.
        let sender = None;
        match self
            .state
            .apply_inbound_update(
                xite,
                inner_path,
                Some(signed.to_vec()),
                Some(modified),
                sender,
                source,
                payload,
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
    /// Filled by the Hello tap for an inbound OVERLAY link, whose accept-time
    /// `peer` is a blank placeholder (see [`adopt_dialback`]). Used only by
    /// `pex`; `kad`/`announce` keep the socket-sourced address.
    dialback: DialbackSlot,
}

/// Cap on the hints one `UpdatesSince` reply carries. The hint log holds up to
/// 10k entries and any peer can fill it with a cheap `Req::Update`, so an
/// uncapped reply lets a ~12-byte request pin megabytes per in-flight serve.
/// The cursor pages: a poller stores the head it got and asks again next
/// interval, so a lagging peer walks the log instead of pulling it whole.
const MAX_UPDATES_PER_REPLY: usize = 512;

#[async_trait::async_trait]
impl ControlProvider for RuntimeControlProvider {
    async fn updates_since(&self, after: u64) -> (Vec<(String, i64)>, u64) {
        let (hints, head) = self.handles.prop.lock().await.since(after);
        // A truncated reply must report the seq of the last hint actually
        // sent, or the poller would skip the rest forever. The log's seqs are
        // contiguous and `head` is the newest entry's seq, so dropping N from
        // the tail moves the reported head back by exactly N.
        let dropped = hints.len().saturating_sub(MAX_UPDATES_PER_REPLY);
        let head = head.saturating_sub(dropped as u64);
        let out = hints
            .into_iter()
            .take(MAX_UPDATES_PER_REPLY)
            .map(|h| (h.xite, h.modified))
            .collect();
        (out, head)
    }

    async fn pex(
        &self,
        xite: &str,
        need: u32,
        have: &[PeerAddr],
        _from: &PeerIdentity,
    ) -> Vec<PeerAddr> {
        // An inbound overlay link's accept-time address is a placeholder that
        // no peer table can hold; the Hello's advertised listen address is the
        // only recordable identity it has.
        let from = {
            let slot = self.dialback.lock().expect("dialback");
            slot.clone().unwrap_or_else(|| self.peer.clone())
        };
        self.state.pex_exchange(xite, need as usize, have.to_vec(), &from).await
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
    shards: bool,
    on_inbound: Option<InboundHook>,
) -> EdxHook {
    let provider: Arc<dyn SignedProvider> = Arc::new(AppStateProvider { state: state.clone() });
    Arc::new(move |peer: PeerAddr, stream| {
        let store = store.clone();
        let provider = provider.clone();
        let privatekey = privatekey.clone();
        let choker = choker.clone();
        let on_inbound = on_inbound.clone();
        let dialback: DialbackSlot = Arc::new(Mutex::new(None));
        let control = control_provider(&state, &control, peer.clone(), dialback.clone());
        let state = state.clone();
        Box::pin(async move {
            let (reg, stream) = ConnHandle::new(Direction::In, peer.clone()).attach(stream);
            let handshake = tokio::time::timeout(
                ACCEPT_HANDSHAKE_TIMEOUT,
                epix_edx::link::accept(stream),
            );
            let Ok(Ok(l)) = handshake.await else { return };
            let mut ctx = serve_ctx(&state, store, provider, privatekey, control, shards);
            if let Some(c) = choker {
                ctx = ctx.with_choker(c);
            }
            let incoming = tap_inbound(reg, l.incoming, peer, on_inbound, dialback);
            serve(l.conn, incoming, Arc::new(ctx), Some(l.handshake_hash)).await;
        })
    })
}

/// The per-connection control provider (see [`RuntimeControlProvider`]).
fn control_provider(
    state: &Arc<AppState>,
    handles: &ControlHandles,
    peer: PeerAddr,
    dialback: DialbackSlot,
) -> Arc<dyn ControlProvider> {
    Arc::new(RuntimeControlProvider {
        state: state.clone(),
        handles: handles.clone(),
        peer,
        dialback,
    })
}

/// A serve context that answers the control plane too (so it advertises
/// `caps::CONTROL`), reports this node's release version in its Hello -
/// which is what the Stats page's `client` column shows - and credits
/// served bytes to the node's upload counters.
fn serve_ctx(
    state: &Arc<AppState>,
    store: Arc<Store>,
    provider: Arc<dyn SignedProvider>,
    privatekey: String,
    control: Arc<dyn ControlProvider>,
    shards: bool,
) -> ServeCtx {
    let mut ctx = ServeCtx::new(store, provider, privatekey)
        .with_version(epix_protocol::self_advert_version())
        .with_control(control)
        .with_shards(shards)
        .with_on_served(upload_recorder(state.clone()))
        .with_foreground(edx_foreground_flag());
    // This runtime verifies and durably unions bounded merge deltas before it
    // acknowledges an Update. Publishers use the bit to distinguish that
    // guarantee from an older peer that decodes `inline` but ignores it.
    ctx.caps |= caps::INLINE_MERGE;
    ctx
}

/// The serve-side upload recorder: resolve the object just served back to
/// its xite + inner_path and credit the dashboard counters (the xite's
/// `bytes_sent`, plus the per-optional-file `uploaded`). The hook fires on
/// blocking serve threads, so the resolution is a sync map read and the
/// accounting hops onto the runtime.
fn upload_recorder(state: Arc<AppState>) -> epix_edx::server::ServedHook {
    let handle = tokio::runtime::Handle::current();
    Arc::new(move |obj, bytes| {
        let Some((address, inner_path)) = state.edx_object_path(&obj) else { return };
        let state = state.clone();
        handle.spawn(async move {
            state.record_upload(&address, &inner_path, bytes).await;
        });
    })
}

/// Build the OVERLAY accept-hook (Tor/I2P/Reticulum): the transport already
/// encrypts, so this skips Noise and serves with no channel binding.
pub fn edx_hook_overlay(
    state: Arc<AppState>,
    store: Arc<Store>,
    privatekey: String,
    choker: Option<SharedChoker>,
    control: ControlHandles,
    shards: bool,
) -> EdxHook {
    let provider: Arc<dyn SignedProvider> = Arc::new(AppStateProvider { state: state.clone() });
    Arc::new(move |peer: PeerAddr, stream| {
        let store = store.clone();
        let provider = provider.clone();
        let privatekey = privatekey.clone();
        let choker = choker.clone();
        let dialback: DialbackSlot = Arc::new(Mutex::new(None));
        let control = control_provider(&state, &control, peer.clone(), dialback.clone());
        let state = state.clone();
        Box::pin(async move {
            let (reg, stream) = ConnHandle::new(Direction::In, peer.clone()).attach(stream);
            let handshake = tokio::time::timeout(
                ACCEPT_HANDSHAKE_TIMEOUT,
                epix_edx::link::accept_overlay(stream),
            );
            let Ok(Ok((conn, incoming))) = handshake.await else { return };
            let mut ctx = serve_ctx(&state, store, provider, privatekey, control, shards);
            if let Some(c) = choker {
                ctx = ctx.with_choker(c);
            }
            // No inbound hook on overlays: reaching us over Tor/I2P/mesh says
            // nothing about whether our clearnet port is open.
            let incoming = tap_inbound(reg, incoming, peer, None, dialback);
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
    /// Whether this node volunteers disk for encrypted shards (advertises
    /// `caps::SHARDS`). Read once from `volunteer_quota_bytes` at setup; a
    /// live re-advertise on toggle is a deferred follow-up.
    shards: bool,
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
            self.shards,
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
            self.shards,
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
    if let Err(e) = write_key_file(&path, &key) {
        state.log("WARN", format!("could not persist EDX node key: {e}")).await;
    }
    key
}

/// Write the node key with owner-only permissions FROM CREATION. A
/// write-then-chmod leaves this node's wire identity readable by every local
/// user for the window in between, and permanently if the chmod fails.
fn write_key_file(path: &std::path::Path, key: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    // `mode` only applies when the file is created, so an existing file (a
    // leftover from a partial write) still needs the explicit chmod. Best
    // effort: a data dir on a filesystem with no unix permissions
    // (exFAT/FAT32/CIFS - a portable install, a USB data dir, a network home)
    // fails this call, and failing the whole write there would leave the node
    // with no persisted identity at all - a new wire identity, and lost
    // reciprocity standing, on every restart - to fix permissions that
    // filesystem cannot represent anyway. The create-time mode above is the
    // real guarantee on a filesystem that has one.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(key.as_bytes())?;
    f.sync_all()
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
    // Volunteer role: advertise caps::SHARDS only when the operator donated
    // disk. Read once here; a live toggle is a deferred follow-up.
    let shards = state.volunteer_quota_bytes().await > 0;
    let es = EdxServe {
        state: state.clone(),
        store,
        privatekey: key,
        choker,
        control: cell.control.clone(),
        shards,
    };
    *guard = Some(es.clone());
    Some(es)
}

/// Per-peer cache of live EDX links, shared by EVERY outbound path: the short
/// control RPCs (PEX, Kad, Announce, UpdatesSince, GetTrackers), the signed
/// fetch/list/push RPCs, and the bulk fetch sessions.
///
/// One link per peer is what the transport wants. A `Conn` is multiplexed and
/// its writer drains the priority lane fully before the bulk one, so a control
/// frame is written ahead of a large transfer sharing the link rather than
/// behind it - the reason concurrent users of one link are correct rather than
/// merely tolerable. Dialing per use instead cost a full Noise-XX handshake
/// each time, and on Tor or I2P a whole fresh circuit: seconds of setup, load
/// on the overlay, and a pile of duplicate rows for one peer on /Stats. The
/// shard loop redialing every peer once per chunk is what made that visible.
///
/// The `Arc<ConnHandle>` is kept beside the `Conn` so the link's diagnostics
/// row lives while it is pooled and so `note_cmd_sent` can annotate it, and the
/// peer's handshake identity rides along because the fetch paths credit peers
/// by node key and would otherwise have to redial to learn it.
/// A pooled link is identified by its peer AND its transfer lane: lane 0 is
/// the shared control link, higher lanes are the extra transfer paths a bulk
/// fetch stripes across (see [`Transport::dial_lane`]).
type LinkKey = (PeerAddr, u8);

/// Last-use lease plus a reverse-request event stream for one pooled link.
/// Local borrowers only renew the lease. Reverse request start/completion also
/// advances `events`, which lets an Update distinguish a peer actively pulling
/// dependencies from one that merely completed Hello and then stopped reading.
struct LinkActivityState {
    last: Mutex<tokio::time::Instant>,
    events: tokio::sync::watch::Sender<u64>,
}

type LinkActivity = Arc<LinkActivityState>;

impl LinkActivityState {
    fn new() -> LinkActivity {
        let (events, _) = tokio::sync::watch::channel(0);
        Arc::new(Self {
            last: Mutex::new(tokio::time::Instant::now()),
            events,
        })
    }

    fn touch(&self) {
        *self.last.lock().expect("link activity") = tokio::time::Instant::now();
    }

    fn note_reverse_request(&self) {
        self.touch();
        self.events
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    fn last(&self) -> tokio::time::Instant {
        *self.last.lock().expect("link activity")
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.events.subscribe()
    }
}

#[derive(Default)]
struct LinkPool {
    conns: Mutex<HashMap<LinkKey, PooledLink>>,
    /// One dial in flight per peer and lane. Looking the cache up and then
    /// dialing is a check-then-act: the announce, PEX and updates loops run on
    /// their own timers and land on the same contact together, so each would
    /// miss the cache and open its own link - the duplicate outbound rows on
    /// /Stats, and on Tor a fresh circuit apiece. Losers of the race wait here
    /// and take the winner's link.
    dialing: Mutex<HashMap<LinkKey, Arc<tokio::sync::Mutex<()>>>>,
}

/// One pooled link, plus when it was last handed out. The instant is what
/// bounds how long a link nobody uses is kept alive. It is a tokio instant
/// rather than a std one so the sweep can be driven by virtual time in tests.
struct PooledLink {
    conn: Conn,
    identity: PeerIdentity,
    reg: Arc<ConnHandle>,
    /// Serves reverse requests on the request half of this outbound link.
    /// It is cancelled when the pool evicts the link, which releases the
    /// task's otherwise intentional `Conn` holder.
    reverse_serve: Option<tokio::task::AbortHandle>,
    activity: LinkActivity,
}

impl Drop for PooledLink {
    fn drop(&mut self) {
        if let Some(task) = &self.reverse_serve {
            task.abort();
        }
    }
}

/// What a pooled dial hands back: the multiplexed link, who the peer proved to
/// be, and the link's row in the diagnostics registry.
type Link = (Conn, PeerIdentity, Arc<ConnHandle>, LinkActivity);

/// A newly opened link also owns the reverse-request loop that consumes the
/// dialer's inbound request channel. Cached hits return the public [`Link`]
/// shape. The task remains an implementation detail of the pool.
type OpenedLink = (
    Conn,
    PeerIdentity,
    Arc<ConnHandle>,
    Option<tokio::task::AbortHandle>,
    LinkActivity,
);

/// One dial result on its way from the session's dial driver to the collector:
/// the peer, what it yielded (`None` = no usable link), and whether this was
/// the peer's FIRST lane - the one that counts as its dial outcome.
type LaneResult =
    (PeerAddr, Option<(Conn, PeerIdentity, epix_blob::bitfield::GroupBits)>, bool);

/// How long a pooled link with no other user may sit unused before it is
/// dropped. A pooled `Conn` keeps its socket open, so an entry nobody touches
/// makes this node the peer that never sends FIN: the far end's own idle reaper
/// cannot free its socket either, and both sides carry a permanent diagnostics
/// row. Short RPCs are seconds apart when active, so re-dialing after a quiet
/// stretch costs one handshake.
const LINK_POOL_IDLE: std::time::Duration = std::time::Duration::from_secs(120);

impl LinkPool {
    /// A live pooled link for `peer`, or None. A closed one is dropped so the
    /// caller redials (reuse-if-not-closed-else-redial, like `epix_edx::Pool`).
    /// Every call also sweeps links that have gone idle, which is what keeps the
    /// pool from pinning sockets (and their Stats rows) open forever.
    ///
    /// A link someone else still holds is NEVER swept, however long since the
    /// pool last handed it out: a bulk session can transfer for many minutes
    /// without asking the pool for anything, and forgetting its link frees
    /// nothing (the session's own handle keeps the socket) while letting the
    /// next caller dial a second link to a peer we are mid-transfer with.
    fn live(&self, peer: &PeerAddr, lane: u8) -> Option<Link> {
        let mut map = self.conns.lock().expect("link pool");
        let now = tokio::time::Instant::now();
        map.retain(|_, l| {
            let reverse_live =
                l.reverse_serve.as_ref().map_or(true, |task| !task.is_finished());
            let pool_holders = 1 + usize::from(l.reverse_serve.is_some());
            let last_activity = l.activity.last();
            !l.conn.is_closed()
                && reverse_live
                && (l.conn.holders() > pool_holders
                    || now.saturating_duration_since(last_activity) < LINK_POOL_IDLE)
        });
        let link = map.get_mut(&(peer.clone(), lane))?;
        link.activity.touch();
        Some((
            link.conn.clone(),
            link.identity.clone(),
            link.reg.clone(),
            link.activity.clone(),
        ))
    }

    fn store(&self, peer: PeerAddr, lane: u8, opened: OpenedLink) {
        let (conn, identity, reg, reverse_serve, activity) = opened;
        self.conns.lock().expect("link pool").insert(
            (peer, lane),
            PooledLink {
                conn,
                identity,
                reg,
                reverse_serve,
                activity,
            },
        );
    }

    /// Drop a peer's cached links (an op errored on it, so a possibly dead
    /// link is not handed to the next caller). Every lane goes: they share the
    /// peer, and the failure being scored is the peer's.
    fn evict(&self, peer: &PeerAddr) {
        self.conns.lock().expect("link pool").retain(|(p, _), _| p != peer);
    }

    /// A pooled link for `peer`, opening at most one even when callers race.
    /// Whoever takes the gate dials; the rest wait and use what it cached. A
    /// dial that fails is not retried by the waiters - piling a second handshake
    /// onto a peer that just refused one only multiplies the timeout, and the
    /// caller will try again on its own schedule anyway.
    ///
    /// The gate is only ever held across `dial`, which the caller bounds by the
    /// peer's connect timeout, so a stalled peer cannot park it indefinitely.
    async fn get_or_dial<F, Fut>(&self, peer: &PeerAddr, lane: u8, dial: F) -> Result<Link, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<OpenedLink, String>>,
    {
        if let Some(hit) = self.live(peer, lane) {
            return Ok(hit);
        }
        let gate = self.dial_gate(peer, lane);
        let Ok(_held) = gate.try_lock() else {
            // Another caller is dialing this very peer and lane. Wait it out
            // rather than opening a second link on the same lane.
            let _queued = gate.lock().await;
            return self.live(peer, lane).ok_or_else(|| "dial in flight failed".to_string());
        };
        // The lookup above and the gate are two steps: a dial may have completed
        // and cached between them.
        if let Some(hit) = self.live(peer, lane) {
            return Ok(hit);
        }
        let opened = dial().await?;
        let link = (
            opened.0.clone(),
            opened.1.clone(),
            opened.2.clone(),
            opened.4.clone(),
        );
        self.store(peer.clone(), lane, opened);
        Ok(link)
    }

    /// This peer+lane's dial gate, created on first use. Gates nobody is
    /// holding are dropped as we pass through, so a long-running node does not
    /// keep one for every peer it has ever dialed.
    fn dial_gate(&self, peer: &PeerAddr, lane: u8) -> Arc<tokio::sync::Mutex<()>> {
        let key = (peer.clone(), lane);
        let mut gates = self.dialing.lock().expect("link pool");
        gates.retain(|k, gate| *k == key || Arc::strong_count(gate) > 1);
        gates.entry(key).or_default().clone()
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
    /// xite (there are many, including tests) can forget to initialize it.
    link_pool: Arc<LinkPool>,
    /// Streaming read-ahead bookkeeping, Arc-shared like the fetcher so every
    /// clone sees the same in-flight/anchor/warmed state.
    streaming: Arc<Mutex<Streaming>>,
    /// Per-object peer sessions, cached so a serve's next windows and its
    /// read-ahead reuse the dialed links instead of redialing through the
    /// overlay. Hits are revalidated and dead links evicted (`peers_for`),
    /// so reuse is only ever a shortcut, never a wrong answer.
    peer_cache: Arc<Mutex<HashMap<ObjId, CachedPeers>>>,
    /// One async preparation cell per merge-delta object currently fanning out
    /// to peers. Concurrent pushes hash-check and insert the shared payload
    /// once, then each keeps its own eviction hold through its Update RPC.
    merge_prepare: MergePrepareGates,
    /// Live per-file transfer telemetry for the UI (peers, rates, failures).
    /// Arc-shared for the same reason as the rest: a serve, its read-ahead and
    /// the scheduler all report into one picture of the same file.
    xfer: Arc<crate::xfer::Xfer>,
    /// One-slot memo of the inline wire encoding for the payload currently
    /// fanning out: an exhaustive publish pushes the same Arc'd payload to up
    /// to 100 peers, and sorting + postcard-encoding + BLAKE3-hashing the
    /// identical delta set once beats doing it per dial. Keyed by payload
    /// identity (Weak + ptr_eq), so a relay's different payload can never
    /// reuse a stale encoding.
    inline_wire_memo: Arc<
        Mutex<
            Option<(
                std::sync::Weak<UpdatePayload>,
                Arc<Result<Option<InlineMergeWire>, String>>,
            )>,
        >,
    >,
    /// One final-quota wave for the Arc'd payload currently fanning out. Every
    /// peer holds the object independently, and the last lease reconciles only
    /// after the last hold drops. Weak payload identity prevents cross-publish
    /// reuse without retaining payload bytes.
    merge_quota_memo: MergeQuotaMemo,
}

struct MaterializeOptions<'a> {
    on_fetched: Option<&'a epix_ui::state::EdxFetchedHook>,
    authority: Option<&'a EdxMaterializeAuthority>,
}

/// Concurrent materialize copies a bulk worker pool may run at once. The
/// copy is GB-scale when the xite tree sits on another filesystem (an SMB
/// mount is the motivating case), runs on the blocking pool, and competes
/// with encode slots and store IO there - while the network fetch it used
/// to serialize behind gains nothing from it. Two, not more: on a network
/// mount concurrent copies mostly serialize against each other anyway.
/// Interactive fetches (a page waiting on the file) bypass the gate.
const MATERIALIZE_CONCURRENCY: usize = 2;

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
    /// The next window planned for a file whose read-ahead task is still
    /// running: the running task picks it up when it finishes, so streaming
    /// keeps the pipeline refilling continuously instead of waiting for the
    /// next Range request to re-arm it.
    queued: HashMap<(String, String), Range<u64>>,
    /// Files whose one-time moov head/tail warm-up has been kicked off.
    warmed: HashSet<(String, String)>,
    /// Objects with a full-file completion pass in flight - at most one per
    /// object, so a browser's burst of Range requests cannot fan out into
    /// duplicate whole-file fetches. Entries are removed when the pass EXITS
    /// (Drop guard), complete or not, so the next Range serve re-arms a
    /// completion that gave up; bounded by the number of concurrent passes.
    completing: HashSet<ObjId>,
    /// Objects with a materialize (move into the xite tree) in flight. A
    /// browser issues Range requests in a burst, and every one of them sees
    /// the same "complete but not yet extern" window between the last group
    /// landing and the rename committing; without this each would spawn its
    /// own blocking move of the same file.
    materializing: HashSet<ObjId>,
    /// Foreground (player-blocking) range fetches currently on the network.
    /// Background completion yields between batches while this is non-zero,
    /// so a seek is not stuck behind the whole-file pull sharing the same few
    /// links (worst on mobile, which has fewer peer paths).
    foreground_fetches: usize,
}

/// Groups per background-completion batch: 1024 x 16 KiB = 16 MiB, a few
/// seconds over a warm session, so the yield check between batches keeps a
/// seek from waiting behind a two-hour film's remainder.
const COMPLETION_BATCH_GROUPS: u64 = 1024;

/// The first [`COMPLETION_BATCH_GROUPS`] of `needed`, so one completion pass
/// stays bounded.
fn completion_batch(needed: &epix_blob::bitfield::GroupBits) -> epix_blob::bitfield::GroupBits {
    let mut batch = epix_blob::bitfield::GroupBits::new();
    let mut left = COMPLETION_BATCH_GROUPS;
    for r in needed.ranges() {
        if left == 0 {
            break;
        }
        let take = (r.end - r.start).min(left);
        batch.add(r.start..r.start + take);
        left -= take;
    }
    batch
}

/// RAII marker for one foreground range fetch; see
/// `Streaming::foreground_fetches`.
struct ForegroundFetch {
    streaming: Arc<Mutex<Streaming>>,
}

impl Drop for ForegroundFetch {
    fn drop(&mut self) {
        if let Ok(mut s) = self.streaming.lock() {
            s.foreground_fetches = s.foreground_fetches.saturating_sub(1);
        }
        // 1 -> 0: the user's playback is no longer blocked on the network.
        if FOREGROUND_FETCHES.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) == 1 {
            set_edx_foreground(false);
        }
    }
}

/// Foreground (player-blocking) range fetches across the WHOLE process,
/// driving the LEDBAT yield on its 0<->1 transitions. Process-wide (not
/// per fetcher) for the same reason the pacer is: connections and
/// fetcher clones are many, the user's uplink is one.
static FOREGROUND_FETCHES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The node-wide "the user's own playback is blocked on the network"
/// flag. Shared into every serve context ([`serve_ctx`]) so the choker's
/// first-paint bucket yields, and mirrored into the bulk pacer so paced
/// serving slows to the yield fraction. Without this both yields were
/// dead switches: each per-connection context held a private
/// always-false bool.
fn edx_foreground_flag() -> Arc<std::sync::atomic::AtomicBool> {
    static FLAG: std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>> =
        std::sync::OnceLock::new();
    FLAG.get_or_init(Default::default).clone()
}

/// Flip both foreground consumers together (the serve contexts' shared
/// flag and the bulk pacer).
fn set_edx_foreground(on: bool) {
    edx_foreground_flag().store(on, std::sync::atomic::Ordering::Relaxed);
    epix_edx::pace::bulk().set_foreground(on);
}

/// A serve's dialed peer session, kept for PEER_CACHE_TTL so consecutive
/// windows and the read-ahead reuse the links.
struct CachedPeers {
    handles: Vec<PeerHandle>,
    node_pks: HashMap<String, Vec<u8>>,
    /// `now_secs` when last reused, for the TTL check.
    at: u64,
    /// `now_secs` when the session was first DIALED. Reuse re-stamps `at`,
    /// so without this a session that keeps working is never rebuilt and can
    /// never pick up a peer discovered later (see [`SESSION_MAX_AGE`]).
    built: u64,
}

/// Clone a peer handle (its `Conn` is a cheap multiplexed clone). `PeerHandle`
/// is not `Clone`, so the peer cache clones field-by-field to hand a serve's
/// links to its background read-ahead.
fn clone_handle(h: &PeerHandle) -> PeerHandle {
    PeerHandle { conn: h.conn.clone(), class: h.class, bits: h.bits.clone(), label: h.label.clone() }
}

/// Attempts at the group blocking a window's prefix before the serve gives up,
/// and how long to wait between them.
///
/// Short on purpose: the player is waiting on this response, so the budget is
/// what a browser will sit through rather than what the swarm might eventually
/// manage. Failing here is not fatal by itself - the caller answers "not yet"
/// and the player re-requests - so this only has to cover the common case where
/// the group is moments away.
const PREFIX_HEAD_ATTEMPTS: u32 = 3;
const PREFIX_HEAD_WAIT: std::time::Duration = std::time::Duration::from_millis(700);

fn merge_delta_object_ready(store: &Store, object: &EdxObjectRef) -> Result<bool, String> {
    match store.info(object.id).map_err(|e| e.to_string())? {
        Some((size, true)) if size == object.size => Ok(true),
        Some((_, true)) => Err("stored merge delta object has the wrong size".into()),
        _ => Ok(false),
    }
}

async fn prepare_merge_delta_object_once(
    store: Arc<Store>,
    payload: Arc<UpdatePayload>,
    path: String,
    object: EdxObjectRef,
    quota: Option<MergeQuotaLease>,
) -> Result<(), String> {
    if object.size == 0 || object.size > MAX_MERGE_DELTA_OBJECT_BYTES {
        return Err("merge delta object size is outside the allowed range".into());
    }
    if merge_delta_object_ready(&store, &object)? {
        return Ok(());
    }
    let insert_store = store.clone();
    let object_id = object.id;
    let object_size = object.size;
    tokio::task::spawn_blocking(move || {
        // A blocking insertion cannot be cancelled once it starts. Keep its
        // own wave lease until the worker exits so an aborted async caller
        // cannot enforce quota and then let this object appear afterward.
        let _quota = quota;
        let records = payload
            .merge_deltas
            .get(&path)
            .ok_or_else(|| "merge delta disappeared before Store insertion".to_string())?;
        if records.len() as u64 != object_size || ObjId::of(records) != object_id {
            return Err("merge delta changed before Store insertion".to_string());
        }
        insert_store
            .insert_bytes(object_id, Ns::Plain, records, now_secs())
            .map_err(|e| e.to_string())?;
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())??;
    match store.info(object.id).map_err(|e| e.to_string())? {
        Some((size, true)) if size == object.size => Ok(()),
        _ => Err("merge delta object preparation did not complete".into()),
    }
}

impl RuntimeEdxFetcher {
    /// Attempts at the group blocking a window's prefix before the serve gives
    /// up, and how long to wait between them.
    ///
    /// Short on purpose: the player is waiting on this response, so the budget
    /// is what a browser will sit through rather than what the swarm might
    /// eventually manage. Failing here is not fatal by itself - the caller
    /// answers "not yet" and the player re-requests - so this only has to cover
    /// the common case where the group is moments away.

    /// Fetch just the one group that is holding up `served`'s contiguous
    /// prefix, and return the prefix length that results.
    ///
    /// Asking for a single group rather than the whole window is the point:
    /// it is the smallest unit that can turn a zero-length answer into a
    /// servable one, it cannot be starved by the groups behind it, and every
    /// peer holding it is a candidate. Returns 0 if it still has not landed,
    /// which the caller reports as unavailable.
    async fn retry_prefix_head(
        &self,
        address: &str,
        store: &Arc<Store>,
        id: ObjId,
        size: u64,
        served: &Range<u64>,
        now: u64,
    ) -> u64 {
        for attempt in 0..PREFIX_HEAD_ATTEMPTS {
            // Re-read each pass: a concurrent read-ahead may have landed it
            // while we waited, in which case there is nothing left to ask for.
            let present = store.present_bits(id).unwrap_or_default();
            let got = present_prefix_len(&present, served, size);
            if got > 0 {
                return got;
            }
            let missing = missing_groups(&present, served);
            let Some(head) = missing.ranges().first().map(|r| r.start) else {
                return 0; // nothing missing yet nothing servable: not ours to fix
            };
            let mut one = epix_blob::bitfield::GroupBits::new();
            one.add(head..head + 1);
            self.fetch_missing(address, store, id, size, &one, now).await;
            if attempt + 1 < PREFIX_HEAD_ATTEMPTS {
                tokio::time::sleep(PREFIX_HEAD_WAIT).await;
            }
        }
        let present = store.present_bits(id).unwrap_or_default();
        present_prefix_len(&present, served, size)
    }

    /// Build a fetcher with an empty control-link cache.
    fn new(state: Arc<AppState>, privatekey: String, choker: Option<SharedChoker>) -> Self {
        Self {
            state,
            privatekey,
            choker,
            link_pool: Arc::default(),
            streaming: Arc::default(),
            peer_cache: Arc::default(),
            merge_prepare: Arc::default(),
            xfer: Arc::default(),
            inline_wire_memo: Arc::default(),
            merge_quota_memo: Arc::default(),
        }
    }

    /// The shared one-shot preparation cell for `id`. Completed cells with no
    /// live callers are retired on the next lookup, so an object evicted after
    /// one publish is checked and prepared again on a later retry.
    fn merge_prepare_gate(&self, id: ObjId) -> MergePrepareGate {
        let mut gates = self.merge_prepare.lock().expect("merge preparation gates");
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(&id).and_then(std::sync::Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(tokio::sync::OnceCell::new());
        gates.insert(id, Arc::downgrade(&gate));
        gate
    }

    fn merge_quota_lease(
        &self,
        store: &Arc<Store>,
        payload: &Arc<UpdatePayload>,
    ) -> MergeQuotaLease {
        let mut memo = self.merge_quota_memo.lock().expect("merge quota memo");
        let wave = memo
            .as_ref()
            .and_then(|(weak, wave)| {
                weak.upgrade()
                    .filter(|live| Arc::ptr_eq(live, payload))
                    .filter(|_| Arc::ptr_eq(&wave.store, store))
                    .map(|_| wave.clone())
            })
            .unwrap_or_else(|| {
                let wave = MergeQuotaWave::new(store.clone(), store_quota());
                *memo = Some((Arc::downgrade(payload), wave.clone()));
                wave
            });
        wave.lease()
    }

    fn inline_merge_candidate(
        &self,
        payload: &Arc<UpdatePayload>,
    ) -> Result<Option<InlineMergeWire>, EdxPushError> {
        let hit = self
            .inline_wire_memo
            .lock()
            .expect("inline wire memo")
            .clone()
            .and_then(|(weak, wire)| {
                weak.upgrade()
                    .filter(|live| Arc::ptr_eq(live, payload))
                    .map(|_| wire)
            });
        let wire = match hit {
            Some(wire) => wire,
            None => {
                let wire = Arc::new(encode_inline_merge_records(&payload.merge_deltas));
                *self.inline_wire_memo.lock().expect("inline wire memo") =
                    Some((Arc::downgrade(payload), wire.clone()));
                wire
            }
        };
        wire.as_ref().clone().map_err(EdxPushError::Refused)
    }

    async fn prepare_merge_delta_object(
        &self,
        store: Arc<Store>,
        payload: Arc<UpdatePayload>,
        path: String,
        object: EdxObjectRef,
        quota: Option<&MergeQuotaLease>,
    ) -> Result<MergePrepareGate, String> {
        let gate = self.merge_prepare_gate(object.id);
        let preparation_quota = quota.map(|lease| lease.wave.lease());
        let prepared = gate
            .get_or_init(|| {
                prepare_merge_delta_object_once(store, payload, path, object, preparation_quota)
            })
            .await
            .clone();
        prepared?;
        Ok(gate)
    }

    async fn prepare_merge_delta_objects<'a>(
        &self,
        store: &'a Arc<Store>,
        payload: Arc<UpdatePayload>,
        quota: Option<MergeQuotaLease>,
    ) -> Result<PreparedMergeObjects<'a>, String> {
        let mut holds = Vec::new();
        let mut preparations = Vec::new();
        let mut objects = HashMap::new();
        for (path, records) in sorted_inline_merge_entries(&payload.merge_deltas)? {
            if records.is_empty() {
                continue;
            }
            let object = EdxObjectRef {
                id: ObjId::of(records),
                size: records.len() as u64,
            };
            holds.push(store.hold_eviction(object.id));
            preparations.push(
                self.prepare_merge_delta_object(
                    store.clone(),
                    payload.clone(),
                    path.to_string(),
                    object,
                    quota.as_ref(),
                )
                .await?,
            );
            objects.insert(path.to_string(), object);
        }
        Ok(PreparedMergeObjects {
            _holds: holds,
            _preparations: preparations,
            quota,
            objects,
        })
    }

    /// Claim `id` for the duration of this fetch and make sure its sparse
    /// record exists. The claim is what makes the "drop the record again if
    /// nothing lands" cleanup safe: it only runs once every concurrent fetch of
    /// the same object is done (see [`ObjClaim`]). Callers hold the returned
    /// guard until they are finished with the object.
    fn claim_object(
        &self,
        store: &Arc<Store>,
        id: ObjId,
        ns: Ns,
        size: u64,
        now: u64,
    ) -> std::io::Result<ObjClaim> {
        let shared = store_fetch_shared(store);
        let claim = {
            let mut claims = shared.claims.lock().expect("claims");
            // Read under the lock: a removal by a departing claim also runs
            // under it, so "did the record exist" cannot go stale here.
            let fresh = !store.contains(id).unwrap_or(false);
            let slot = claims.entry(id).or_insert((0, false));
            slot.0 += 1;
            slot.1 |= fresh;
            ObjClaim { shared: shared.clone(), store: store.clone(), id }
        };
        store.ensure_sparse(id, ns, size, now)?;
        Ok(claim)
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
        lane: u8,
    ) -> Result<OpenedLink, String> {
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
        let mut ctx = ServeCtx::new(store, provider, self.privatekey.clone())
            .with_on_served(upload_recorder(self.state.clone()))
            .with_foreground(edx_foreground_flag())
            .with_version(epix_protocol::self_advert_version());
        if let Some(choker) = &self.choker {
            ctx = ctx.with_choker(choker.clone());
        }
        ctx.caps |= caps::INLINE_MERGE;
        let ctx = Arc::new(ctx);
        // An overlay dial is a circuit build (and, for an onion peer, a
        // descriptor fetch and a rendezvous), so the number in flight at once
        // is bounded process-wide. Each xite's sync opens its own session, and
        // with many xites resyncing on the same tick the node asked Tor for
        // dozens of circuits simultaneously - most of them to peers that never
        // answer. Arti scores those failures against its guards and, past a
        // 70% failure rate, disables them; with no usable guard the onion
        // service cannot publish its descriptor, so the node goes unreachable
        // over Tor. Clearnet dials are cheap and stay unbounded.
        // Same condition as connect_timeout: in Tor-always mode an Ip peer is
        // dialed through an exit circuit, so it costs a circuit too and must
        // be counted. Gating on the address alone left every clearnet dial
        // uncapped in exactly the mode where all of them ride Tor.
        // Bound the whole handshake: a peer that TCP-accepts then stalls the
        // Noise / client_hello exchange must not hang the fetch forever. The
        // permit acquire lives INSIDE the timeout: callers hold the
        // per-(peer,lane) dial gate across this function, and the gate's
        // safety argument is that nothing here waits unboundedly. An
        // uncapped semaphore wait outside the timeout broke that invariant
        // and let one exhausted dial budget park every dial to the peer.
        tokio::time::timeout(peer.connect_timeout(), async {
            let _circuit_slot = match peer.is_overlay() || epix_core::route_all_via_overlay() {
                true => Some(overlay_dial_permit().await),
                false => None,
            };
            let stream = transport.dial_lane(peer, lane).await.map_err(|e| e.to_string())?;
            let (reg, stream) =
                ConnHandle::new(Direction::Out, peer.clone()).attach(stream);
            // Clearnet TCP needs Noise; overlays (Tor/I2P/Reticulum) already
            // encrypt, so they skip it and bind with no handshake hash.
            let (conn, incoming, hh, reach) = if matches!(peer, PeerAddr::Ip(_)) {
                let l = epix_edx::link::dial(stream).await.map_err(|e| e.to_string())?;
                (l.conn, l.incoming, Some(l.handshake_hash), Reach::Clearnet)
            } else {
                let (conn, incoming) =
                    epix_edx::link::dial_overlay(stream).await.map_err(|e| e.to_string())?;
                (conn, incoming, None, Reach::Overlay)
            };
            let identity =
                client_hello(&conn, &ctx, listen, hh).await.map_err(|e| e.to_string())?;
            // List it only once the peer proved it speaks EDX, so a port scan
            // or a half-open TCP connect never shows up on the Stats page.
            reg.activate();
            reg.set_peer(handshake_info(&identity.version, &identity.node_pk));
            // EDX is multiplexed in both directions. Keep consuming the
            // request half of this outbound connection so the peer can pull a
            // manifest, merge file, or large hashed object from the exact
            // source that announced it. NAT and overlay reachability no longer
            // require a second dial for that handoff.
            let activity = LinkActivityState::new();
            let on_activity = {
                let activity = activity.clone();
                Arc::new(move || {
                    activity.note_reverse_request();
                })
            };
            let reverse = tokio::spawn(serve_authenticated_observed(
                conn.clone(),
                incoming,
                ctx,
                identity.clone(),
                reach,
                on_activity.clone(),
                on_activity,
            ));
            let reverse = reverse.abort_handle();
            Ok::<_, String>((conn, identity, reg, Some(reverse), activity))
        })
        .await
        .map_err(|_| "EDX dial timed out".to_string())?
    }

    /// A live EDX link to `peer`: the cached one when it is still open, else a
    /// fresh dial cached for whoever asks next. THE way to reach a peer - every
    /// outbound path goes through here so one peer means one link, and one
    /// overlay circuit, however many things are talking to it at once.
    ///
    /// The transport is resolved inside the dial closure so a cache hit does not
    /// depend on one being installed.
    async fn link(&self, peer: &PeerAddr) -> Result<Link, String> {
        self.link_lane(peer, 0).await
    }

    /// A live EDX link to `peer` on transfer `lane`. Lane 0 is the shared link
    /// [`Self::link`] hands out; higher lanes are independent paths a bulk
    /// fetch stripes across, which over Tor means separate circuits (see
    /// [`Transport::dial_lane`]). Pooled per lane, so a lane's circuit is
    /// reused by later windows rather than rebuilt.
    async fn link_lane(&self, peer: &PeerAddr, lane: u8) -> Result<Link, String> {
        self.link_pool
            .get_or_dial(peer, lane, || async {
                let transport = self.state.transport().await.ok_or("no transport")?;
                self.dial(&transport, peer, lane).await
            })
            .await
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
        let (conn, _identity, reg, _activity) = self.link(peer).await?;
        reg.note_cmd_sent(label, None);
        match tokio::time::timeout(EDX_FETCH_TIMEOUT, f(conn)).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                self.link_pool.evict(peer);
                Err(e.to_string())
            }
            Err(_) => {
                self.link_pool.evict(peer);
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
        authority: Option<&EdxMaterializeAuthority>,
        store: &Arc<Store>,
    ) -> Result<bool, String> {
        // Only salted-convergent (mode 0) shards are fetchable. A mode-1
        // (random-key) shard is keyed by a per-file random key and
        // `ShardEntry` carries no wrapped copy of it, so the salt is not the
        // key material and every chunk would fail its AEAD tag. Refuse the
        // file instead of decrypting with the wrong material.
        if shard.mode != 0 {
            return Err(format!(
                "shard mode {} not supported (random-key shards need per-recipient key wrapping)",
                shard.mode
            ));
        }
        let salt = epix_blob::manifest::edx_salt(content)
            .ok_or("no edx_salt (missing viewing material)")?;
        let now = now_secs();
        let peers = self.state.fetch_session_peers(address, 8).await;

        // Fetch each ciphertext shard object into the store, verified by its
        // BLAKE3 address (== the shard's bao root). The bytes stay in the
        // Store; decrypt streams each chunk back out on demand below, so the
        // whole ciphertext is never resident alongside the plaintext.
        for c in &shard.chunks {
            let id = c.cipher_addr;
            let csize = c.csize as u64;
            if store.is_complete(id).unwrap_or(false) {
                match store.read_bytes(id, now) {
                    // Readable in the Store; decrypt reads it again below.
                    Ok(_) => continue,
                    Err(_) => {
                        // A crash-torn Slab can still be logically complete.
                        // Revalidation converts it to an empty Sparse record
                        // while retaining typed owners, so this same fetch can
                        // refill it instead of skipping it forever.
                        let _ = store.revalidate(id);
                    }
                }
            }
            let mut handles: Vec<PeerHandle> = Vec::new();
            let mut node_pks: HashMap<String, Vec<u8>> = HashMap::new();
            for peer in &peers {
                // Pooled: this loop runs once per chunk over the same peers, so
                // dialing here meant a handshake (and an overlay circuit) per
                // chunk per peer.
                let Ok((conn, identity, reg, _activity)) = self.link(peer).await else { continue };
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
            // Reserve only now that a holder is known, and drop the record
            // again if nothing lands (same reason as `pull_shard_chunk`). The
            // claim defers that drop until any concurrent fetch of the same
            // shard is done, so it never unlinks a record still being filled.
            let _claim =
                self.claim_object(store, id, Ns::Shard, csize, now).map_err(|e| e.to_string())?;
            let needed = needed_groups(store, id, csize).map_err(|e| e.to_string())?;
            let mut swarm = Swarm::new(store.clone(), id, csize);
            let report = match swarm.fetch(&needed, &handles, Deadline::background(), now).await {
                Ok(report) => report,
                Err(e) => return Err(e.to_string()),
            };
            self.credit(address, &report, &node_pks, now).await;
            if !store.is_complete(id).unwrap_or(false) {
                return Err(format!("shard {id} did not complete"));
            }
            store.read_bytes(id, now).map_err(|error| {
                let _ = store.revalidate(id);
                format!("completed shard {id} is unreadable: {error}")
            })?;
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
        let mode = epix_selfenc::Mode::SaltedConvergent;
        let plaintext = epix_selfenc::decrypt(mode, &chunks, &salt, |addr| {
            store.read_bytes(epix_blob::ObjId(*addr), now).ok()
        })
        .map_err(|e| e.to_string())?;
        let expected_entry = content
            .get("files_shard")
            .and_then(|files| files.get(inner_path))
            .ok_or_else(|| format!("missing shard descriptor for {address}/{inner_path}"))?;
        self.state
            .edx_materialize_shard_file(
                address,
                inner_path,
                &plaintext,
                expected_entry,
                authority,
            )
            .await?;
        let _ = store.enforce_quota(store_quota());
        Ok(true)
    }

    /// This node's 20-byte account (its persisted EDX identity key ->
    /// address -> hash160), the volunteer cache identity fed to the XOR
    /// responsibility predicate.
    fn node_account(&self) -> Result<[u8; 20], String> {
        let addr = epix_crypt::privatekey_to_address(&self.privatekey)?;
        epix_crypt::address_to_hash160(&addr)
    }

    /// The VOLUNTEER role: HOLD (never decrypt) the encrypted shards this
    /// node is responsible for, listed in a private file's signed
    /// content.json.
    ///
    /// This is PULL, and safe by construction with no accept-guard: every
    /// `cipher_addr` comes from a content.json the CALLER already
    /// signature-verified, and each shard lands verified by BLAKE3==addr
    /// into `Ns::Shard`, so there is no "grind arbitrary bytes onto our
    /// disk" vector (unlike the deferred `PushBlock`, whose remote-chosen
    /// bytes would need one). The decrypt/materialize tail of
    /// [`Self::fetch_shard_file`] is intentionally absent: a volunteer holds
    /// ciphertext it cannot read, and NO shard-to-xite association is ever
    /// written (an `Ns::Shard` insert records only addr/size/last_access),
    /// preserving the store's deniability property.
    ///
    /// Two gates decide what is pulled:
    /// - the responsibility predicate (this node's `cache_id` XOR-near the
    ///   addr, scaled by its quota share of the shard universe), so a
    ///   volunteer holds only its slice of the keyspace; and
    /// - the donated byte budget: stop before pulling a new shard once
    ///   `Ns::Shard` bytes reach `volunteer_quota_bytes` (the in-flight
    ///   shard may push slightly over - acceptable for a foundation).
    ///
    /// Held shards share the store's single combined LRU with the browse
    /// cache, so `enforce_quota` bounds total disk. A dedicated ns-aware
    /// eviction split (so the two pools never evict each other) is a
    /// deferred refinement. Returns the count newly held; quota 0 (not
    /// volunteering) holds nothing.
    async fn volunteer_hold_file(
        &self,
        address: &str,
        shard: &epix_blob::manifest::ShardEntry,
        store: &Arc<Store>,
    ) -> Result<usize, String> {
        let quota = self.state.volunteer_quota_bytes().await;
        if quota == 0 {
            return Ok(0); // 0 = not volunteering
        }
        let cid = epix_blob::responsibility::cache_id(&self.node_account()?);
        let universe = shard_universe_bytes();
        let now = now_secs();

        // The shards we are responsible for and do not already hold.
        let mut want = Vec::new();
        for chunk in &shard.chunks {
            if !epix_blob::responsibility::responsible(
                &cid,
                chunk.cipher_addr,
                quota,
                universe,
            ) {
                continue;
            }
            if store.is_complete(chunk.cipher_addr).unwrap_or(false) {
                if store.read_bytes(chunk.cipher_addr, now).is_ok() {
                    continue;
                }
                let _ = store.revalidate(chunk.cipher_addr);
            }
            want.push(chunk);
        }
        if want.is_empty() {
            return Ok(0);
        }

        let peers = self.state.fetch_session_peers(address, 8).await;
        let mut held = 0usize;
        for c in want {
            // Soft budget gate: stop before pulling once held shard bytes
            // reach the donated quota.
            if store.ns_bytes(Ns::Shard).map_err(|e| e.to_string())? >= quota {
                break;
            }
            if self.pull_shard_chunk(address, store, c, &peers, now).await? {
                held += 1;
            }
        }
        // Held shards are unpinned (refcount 0), so keep total disk bounded
        // by the global quota alongside the browse cache.
        let _ = store.enforce_quota(store_quota());
        Ok(held)
    }

    /// HOLD one ciphertext shard chunk: find a holder among `peers`, stripe the
    /// object in, and report whether it landed complete. A chunk nobody
    /// reachable holds is skipped, not an error.
    ///
    /// The sparse record is reserved only AFTER a holder is found: an
    /// `ensure_sparse` before the dial lets an unobtainable (or
    /// attacker-declared) `csize` charge the shard budget for bytes never held.
    /// A pull that then stalls removes the record again, for the same reason.
    async fn pull_shard_chunk(
        &self,
        address: &str,
        store: &Arc<Store>,
        chunk: &epix_blob::manifest::ShardChunk,
        peers: &[PeerAddr],
        now: u64,
    ) -> Result<bool, String> {
        let id = chunk.cipher_addr;
        let csize = chunk.csize as u64;

        // Dial the xite's peers and learn who holds this ciphertext
        // object, then stripe it in. Same swarm path as a normal fetch -
        // a shard is an ordinary content-addressed object - minus the
        // decrypt tail.
        let (handles, node_pks) = self.dial_bitfield_handles(address, peers, id).await;
        if handles.is_empty() {
            return Ok(false); // no peer holds this shard now; try the next one
        }
        // Reserve the sparse record only now that a peer can serve it.
        // Creating it earlier let an unobtainable (or attacker-declared)
        // shard count its full claimed `csize` toward the shard budget and
        // global quota with bytes never actually held, tripping the budget
        // gate early and evicting legitimately held objects.
        store.ensure_sparse(id, Ns::Shard, csize, now).map_err(|e| e.to_string())?;
        let needed = needed_groups(store, id, csize).map_err(|e| e.to_string())?;
        let mut swarm = Swarm::new(store.clone(), id, csize);
        if let Ok(report) = swarm.fetch(&needed, &handles, Deadline::background(), now).await {
            self.credit(address, &report, &node_pks, now).await;
        }
        if store.is_complete(id).unwrap_or(false) {
            Ok(true)
        } else {
            // Stalled or failed pull: drop the record so its claimed size
            // does not linger as a phantom in the budget and quota.
            let _ = store.remove(id);
            Ok(false)
        }
    }

    /// Dial each of `peers` and ask what it holds of `id` (one GetBitfield per
    /// peer), returning a [`PeerHandle`] per peer that answered plus each
    /// label's authenticated node key, for crediting. An empty handle list
    /// means no reachable peer holds the object right now.
    async fn dial_bitfield_handles(
        &self,
        address: &str,
        peers: &[PeerAddr],
        id: ObjId,
    ) -> (Vec<PeerHandle>, HashMap<String, Vec<u8>>) {
        let mut handles: Vec<PeerHandle> = Vec::new();
        let mut node_pks: HashMap<String, Vec<u8>> = HashMap::new();
        for peer in peers {
            let Ok((conn, identity, reg, _activity)) = self.link(peer).await else { continue };
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
        (handles, node_pks)
    }

    /// Credit each peer that delivered groups in `report` for the bytes it
    /// served us (reciprocity, when a shared choker is installed), and stamp
    /// its data history in the xite's registry. The registry stamp is what
    /// note_edx_dials cannot record - a peer that answers and holds nothing
    /// scores ConnectOk there, so "never served us a byte" was invisible -
    /// and it is what ranks actual byte sources into the data-session slots
    /// ([`AppState::fetch_session_peers`]).
    async fn credit(
        &self,
        address: &str,
        report: &epix_edx::sched::FetchReport,
        node_pks: &HashMap<String, Vec<u8>>,
        now: u64,
    ) {
        if let Some(choker) = &self.choker {
            let mut c = choker.lock().expect("choker");
            for (label, groups) in &report.by_peer {
                if let Some(pk) = node_pks.get(label) {
                    c.credit_peer(pk, groups * epix_blob::bitfield::GROUP_BYTES, now);
                }
            }
        }
        // Lanes share their peer's label (the address string), so this
        // round-trips; a label that is not an address (test doubles) is
        // simply not a registry peer.
        let served: Vec<PeerAddr> = report
            .by_peer
            .iter()
            .filter(|(_, groups)| **groups > 0)
            .filter_map(|(label, _)| PeerAddr::parse(label).ok())
            .collect();
        self.state.note_edx_served(address, served).await;
    }

    /// Resolve `inner_path`'s object id + size from the root OR the governing
    /// child/per-user content.json (so forum and per-user files resolve too).
    async fn resolve(&self, address: &str, inner_path: &str) -> Result<Option<(ObjId, u64)>, String> {
        Ok(self.state.edx_resolve(address, inner_path).await)
    }

    /// Dial the xite's connectable peers as EDX links and learn what each
    /// holds of `id`. One link per peer, reused for the whole fetch. Also
    /// returns each peer label's authenticated node key, for crediting.
    ///
    /// Dials run CONCURRENTLY (capped) and the serve starts EARLY: once the
    /// first usable handle exists, later dials get only a short grace
    /// instead of gating the serve on the slowest dead onion's connect
    /// timeout. The dial driver keeps running detached, so every outcome
    /// still feeds the xite's peer registry via note_edx_dials — a dead (or
    /// zombie: handshakes, never answers the bitfield) peer sinks (backoff)
    /// instead of being redialed at the top of the list on every window.
    ///
    /// The third return is the dial channel, STILL OPEN: peers and lanes
    /// that resolve after the grace keep landing on it. The bulk path feeds
    /// them into its running fetch (`spawn_late_link_feed`); a caller with
    /// no use for them drops the receiver, which is the old behavior.
    async fn build_peers(
        &self,
        address: &str,
        id: ObjId,
    ) -> Result<
        (
            Vec<PeerHandle>,
            HashMap<String, Vec<u8>>,
            tokio::sync::mpsc::UnboundedReceiver<LaneResult>,
        ),
        String,
    > {
        // Data-session slots: peers with data history for this xite first
        // (see fetch_session_peers) - the gateway-style non-seeder must not
        // occupy one of the 8 dials while a byte source waits below the cut.
        let peers = self.state.fetch_session_peers(address, 8).await;
        if peers.is_empty() {
            return Err("no peers".into());
        }
        let total = peers.len();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        self.spawn_dial_driver(peers, address.to_string(), id, tx);

        let mut handles: Vec<PeerHandle> = Vec::new();
        let mut node_pks: HashMap<String, Vec<u8>> = HashMap::new();
        let mut resolved = 0usize;
        // Armed by the first usable handle: from then on the collection is
        // bounded by the grace, not by the slowest dial.
        let mut grace: Option<tokio::time::Instant> = None;
        while resolved < total {
            let next = tokio::select! {
                r = rx.recv() => r,
                _ = async { tokio::time::sleep_until(grace.unwrap()).await },
                    if grace.is_some() => break,
            };
            let Some((peer, got, primary)) = next else { break };
            // Only a peer's FIRST lane counts as that peer's dial outcome; the
            // extra lanes are bonus paths to a peer already resolved.
            if primary {
                resolved += 1;
            }
            if let Some((conn, identity, bits)) = got {
                if handles.is_empty() {
                    grace = Some(tokio::time::Instant::now() + SESSION_FIRST_HANDLE_GRACE);
                }
                // Lanes of one peer share its label, so crediting, upload
                // accounting and the transfer readout all still see a single
                // peer - only the scheduler sees several places to put work.
                let label = peer.to_string();
                node_pks.insert(label.clone(), identity.node_pk);
                handles.push(PeerHandle { conn, class: Class::of_addr(&peer), bits, label });
            }
        }
        // A lane that lands after the grace window is not lost: it stays warm
        // in the link pool, it reaches the object's cached session via
        // add_cached_lane, and the bulk path joins it into the running fetch
        // through the returned channel.
        self.xfer.note_session(id, address, now_secs(), total as u64, handles.len() as u64);
        if handles.is_empty() {
            return Err("no EDX peer holds this object".into());
        }
        Ok((handles, node_pks, rx))
    }

    /// Open this peer's extra transfer lanes and hand each one to the session
    /// as it lands.
    ///
    /// The bitfield is NOT re-fetched per lane: a lane is another path to the
    /// same node, which holds the same bytes, so asking again would cost a
    /// round trip per lane to learn what we already know. They dial
    /// concurrently, and each is announced the moment it is up so the fetch
    /// widens while the rest are still building.
    ///
    /// Only overlay peers get lanes ([`lanes_for`]); for anything else this
    /// returns without dialing.
    /// Dial `peers` for a session in the background, reporting every usable
    /// link on `tx` as it lands and feeding each peer's outcome back to the
    /// xite's registry when the last one settles.
    ///
    /// Detached from the collector on purpose: the session is handed back as
    /// soon as it has something to fetch over, while this keeps running so a
    /// dead peer is still SCORED (and backed off) rather than silently
    /// redialed at the top of the next window.
    fn spawn_dial_driver(
        &self,
        peers: Vec<PeerAddr>,
        address: String,
        id: ObjId,
        tx: tokio::sync::mpsc::UnboundedSender<LaneResult>,
    ) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut outcomes: Vec<(PeerAddr, bool)> = Vec::new();
            let mut join = tokio::task::JoinSet::new();
            let mut pending = peers.into_iter();
            loop {
                while join.len() < SESSION_DIAL_CONCURRENCY {
                    let Some(peer) = pending.next() else { break };
                    let this = this.clone();
                    let address = address.clone();
                    let tx = tx.clone();
                    join.spawn(async move {
                        this.dial_peer_for_session(peer, address, id, tx).await
                    });
                }
                let Some(res) = join.join_next().await else { break };
                let Ok((peer, dialed)) = res else { continue };
                outcomes.push((peer, dialed));
            }
            // Release the joiner channel BEFORE the scoring await. Scoring
            // takes the xites write lock; holding `tx` across it means a
            // wedged lock keeps every downstream joiner channel open, which
            // parks every in-flight fetch on a join that can never arrive -
            // the freeze becomes self-sealing. Dials are settled here, so
            // the channel has nothing left to say.
            drop(tx);
            this.state.note_edx_dials(&address, outcomes).await;
        });
    }

    /// Dial one peer for a session - lane 0, its bitfield, and its extra
    /// lanes - reporting each usable link on `tx`. Returns the peer's dial
    /// outcome for the registry: `true` when it answered at all, whatever it
    /// then turned out to hold.
    async fn dial_peer_for_session(
        &self,
        peer: PeerAddr,
        address: String,
        id: ObjId,
        tx: tokio::sync::mpsc::UnboundedSender<LaneResult>,
    ) -> (PeerAddr, bool) {
        // Start the extra lanes' circuit builds NOW, next to lane 0's rather
        // than after it. Building them afterwards put them a whole circuit
        // build behind the session's 2s first-handle grace, so they always
        // missed the session that wanted them. In parallel they finish
        // alongside lane 0, and lane 0 still owes a bitfield round trip after
        // that, which is the slack they land in.
        let mut lanes = self.start_extra_lanes(&peer);
        // A peer that cannot be reached, or that answers and then has nothing
        // for us, takes its half-built lanes down with it: leaving circuits to
        // finish for a node that is no use to this fetch is exactly the churn
        // that gets guards disabled.
        let Ok((conn, identity, reg, _activity)) = self.link(&peer).await else {
            lanes.abort_all();
            let _ = tx.send((peer.clone(), None, true));
            return (peer, false);
        };
        reg.note_cmd_sent("GetBitfield", Some(&address));
        let bits = match tokio::time::timeout(
            EDX_FETCH_TIMEOUT,
            epix_edx::fetch::fetch_bitfield(&conn, id),
        )
        .await
        {
            Ok(Ok((_sz, bits))) => bits,
            // A quick refusal: reachable, just nothing usable for this object.
            Ok(Err(_)) => {
                lanes.abort_all();
                let _ = tx.send((peer.clone(), None, true));
                return (peer, true);
            }
            // Handshook but never answered the bitfield: a zombie. Scored as a
            // failed dial so the registry backs it off, instead of rewarding it
            // as reachable and re-burning this timeout at the top of every cold
            // session.
            Err(_) => {
                lanes.abort_all();
                let _ = tx.send((peer.clone(), None, true));
                return (peer, false);
            }
        };
        // Lane 0 goes out FIRST so the fetch can start on it; the extra lanes
        // follow as they land.
        let _ = tx.send((peer.clone(), Some((conn, identity.clone(), bits.clone())), true));
        self.collect_extra_lanes(lanes, id, &peer, &identity, &bits, &tx).await;
        (peer, true)
    }

    fn start_extra_lanes(&self, peer: &PeerAddr) -> tokio::task::JoinSet<Option<Conn>> {
        let mut join = tokio::task::JoinSet::new();
        for lane in 1..lanes_for(peer) {
            let this = self.clone();
            let peer = peer.clone();
            join.spawn(async move {
                this.link_lane(&peer, lane)
                    .await
                    .ok()
                    .map(|(conn, _, _, _)| conn)
            });
        }
        join
    }

    /// Hand each opened lane to the session, as it lands.
    ///
    /// The bitfield is NOT re-fetched per lane: a lane is another path to the
    /// same node, which holds the same bytes, so asking again would cost a
    /// round trip per lane to learn what we already know.
    ///
    /// Each lane goes to two places. To the session still forming, which uses
    /// it if it arrived inside the grace window - the point of dialing lanes
    /// in parallel with lane 0. And to the object's cached session, which the
    /// next window and the read-ahead reuse, so a lane that was slow to build
    /// still joins the transfer moments later instead of idling in the pool
    /// until the sweep takes it.
    async fn collect_extra_lanes(
        &self,
        mut lanes: tokio::task::JoinSet<Option<Conn>>,
        id: ObjId,
        peer: &PeerAddr,
        identity: &PeerIdentity,
        bits: &epix_blob::bitfield::GroupBits,
        tx: &tokio::sync::mpsc::UnboundedSender<LaneResult>,
    ) {
        while let Some(res) = lanes.join_next().await {
            let Ok(Some(conn)) = res else { continue };
            let handle = PeerHandle {
                conn: conn.clone(),
                class: Class::of_addr(peer),
                bits: bits.clone(),
                label: peer.to_string(),
            };
            self.add_cached_lane(id, handle, identity.node_pk.clone());
            let _ = tx.send((peer.clone(), Some((conn, identity.clone(), bits.clone())), false));
        }
    }

    /// Add a freshly opened lane to `id`'s cached peer session.
    ///
    /// A lane is dialed once its peer has answered, which over Tor is a
    /// circuit build later than the session's first-handle grace - so a lane
    /// nearly always arrives after the session that asked for it has closed.
    /// Dropping it there would mean the stripe never forms: the lane would sit
    /// unused in the link pool until the idle sweep took it, and the next
    /// window would redial and lose it the same way. Appending to the cached
    /// session instead means the very next window - the read-ahead, moments
    /// later - fetches across every lane.
    fn add_cached_lane(&self, id: ObjId, handle: PeerHandle, node_pk: Vec<u8>) {
        let now = now_secs();
        let mut cache = self.peer_cache.lock().expect("peer_cache");
        let Some(entry) = cache.get_mut(&id) else { return };
        if now.saturating_sub(entry.at) >= PEER_CACHE_TTL {
            return; // a stale entry the next fetch will rebuild anyway
        }
        entry.node_pks.entry(handle.label.clone()).or_insert(node_pk);
        entry.handles.push(handle);
    }

    /// Feed a session's late dial results into a running bulk fetch: every
    /// lane and peer that resolves after the first-handle grace becomes a
    /// swarm joiner (`Swarm::fetch_growable`) instead of a warm link
    /// nothing reads. Late whole peers - their lane 0 carries a fresh
    /// bitfield - are also appended to the object's cached session, exactly
    /// as `collect_extra_lanes` already does for extra lanes, so a retry
    /// and the read-ahead see them too. Ends when the dial driver settles
    /// every peer (the channel closes) or the fetch returns (the send
    /// fails); dropping `join_tx` then tells the fetch no more are coming.
    fn spawn_late_link_feed(
        &self,
        mut late: tokio::sync::mpsc::UnboundedReceiver<LaneResult>,
        id: ObjId,
        address: String,
        node_pks: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        join_tx: tokio::sync::mpsc::UnboundedSender<PeerHandle>,
    ) {
        let this = self.clone();
        tokio::spawn(async move {
            while let Some((peer, got, primary)) = late.recv().await {
                let Some((conn, identity, bits)) = got else { continue };
                let label = peer.to_string();
                let handle =
                    PeerHandle { conn, class: Class::of_addr(&peer), bits, label: label.clone() };
                node_pks.lock().expect("node pks").insert(label, identity.node_pk.clone());
                if primary {
                    // Extra lanes reach the cache via add_cached_lane on
                    // the dial path already; adding them here too would
                    // duplicate the handle in the cached session.
                    this.add_cached_lane(id, clone_handle(&handle), identity.node_pk);
                }
                if join_tx.send(handle).is_err() {
                    break; // fetch over; the dial driver still scores the rest
                }
                this.xfer.note_session_join(id, &address, now_secs());
            }
        });
    }

    /// Revalidate cached session handles for `id`: refresh each link's
    /// bitfield (the peer may hold more groups than when it was dialed) and
    /// drop handles whose connection died or stopped answering - the
    /// eviction that keeps a dead session from being reused for a whole TTL.
    async fn refresh_handles(&self, handles: Vec<PeerHandle>, id: ObjId) -> Vec<PeerHandle> {
        let mut join = tokio::task::JoinSet::new();
        for h in handles {
            if h.conn.is_closed() {
                continue;
            }
            join.spawn(async move {
                match tokio::time::timeout(
                    SESSION_REFRESH_TIMEOUT,
                    epix_edx::fetch::fetch_bitfield(&h.conn, id),
                )
                .await
                {
                    Ok(Ok((_sz, bits))) => Some(PeerHandle { bits, ..h }),
                    _ => None,
                }
            });
        }
        let mut live = Vec::new();
        while let Some(res) = join.join_next().await {
            if let Ok(Some(h)) = res {
                live.push(h);
            }
        }
        live
    }

    /// Cache a serve's dialed peer session so the next windows of the same
    /// file and its read-ahead reuse the links.
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
        // Re-stamping keeps a working session warm, but the DIAL time is
        // carried over so `SESSION_MAX_AGE` still forces a periodic rescan.
        let built = cache.get(&id).map_or(now, |c| c.built);
        cache.insert(
            id,
            CachedPeers {
                handles: handles.iter().map(clone_handle).collect(),
                node_pks: node_pks.clone(),
                at: now,
                built,
            },
        );
    }

    /// Peer session for `id`, able to supply at least one of the `needed`
    /// groups: reused from the cache when a serve dialed the links within
    /// the TTL, else dialed fresh (concurrently) and cached. Shared by the
    /// range serve, the read-ahead and the moov warm-up, so consecutive
    /// windows of one playback ride the same overlay links.
    ///
    /// A cache hit is REVALIDATED (bitfield refresh per link): handles
    /// whose connection errored are evicted, and the survivors must still
    /// hold something we need — liveness alone would pin a session of peers
    /// that answer bitfields but hold none of the needed groups, with the
    /// per-request re-stamp keeping the useless entry warm forever while a
    /// redial would find the peer that holds them. Only a usable session is
    /// reused and re-stamped, so an actively streaming file keeps its
    /// session for as long as it works.
    async fn peers_for(
        &self,
        address: &str,
        id: ObjId,
        needed: &epix_blob::bitfield::GroupBits,
    ) -> Result<(Vec<PeerHandle>, HashMap<String, Vec<u8>>), String> {
        let now = now_secs();
        let cached = {
            let cache = self.peer_cache.lock().expect("peer_cache");
            cache
                .get(&id)
                .filter(|hit| {
                    now.saturating_sub(hit.at) < PEER_CACHE_TTL
                        && now.saturating_sub(hit.built) < SESSION_MAX_AGE
                })
                .map(|hit| {
                (hit.handles.iter().map(clone_handle).collect::<Vec<_>>(), hit.node_pks.clone())
            })
        };
        if let Some((handles, node_pks)) = cached {
            let live = self.refresh_handles(handles, id).await;
            if !live.is_empty() && can_supply(&live, needed) {
                let node_pks: HashMap<String, Vec<u8>> = live
                    .iter()
                    .filter_map(|h| node_pks.get(&h.label).map(|pk| (h.label.clone(), pk.clone())))
                    .collect();
                self.cache_peers(id, &live, &node_pks);
                return Ok((live, node_pks));
            }
        }
        // The dial channel is dropped: a streaming window is over in
        // seconds, and late lanes reach the NEXT window through the cached
        // session (add_cached_lane) as they always have.
        let (handles, node_pks, _late) = self.build_peers(address, id).await?;
        self.cache_peers(id, &handles, &node_pks);
        Ok((handles, node_pks))
    }

    /// Fetch the groups of a served range the store still lacks. Returns the
    /// failure text rather than erroring: the caller serves whatever
    /// contiguous prefix landed, so a dial, claim or fetch failure must not
    /// throw away bytes that are already committed.
    async fn fetch_missing(
        &self,
        address: &str,
        store: &Arc<Store>,
        id: ObjId,
        size: u64,
        needed: &epix_blob::bitfield::GroupBits,
        now: u64,
    ) -> Option<String> {
        // The cached (revalidated) session from the previous window
        // or read-ahead, else fresh concurrent dials.
        let (handles, node_pks) = match self.peers_for(address, id, needed).await {
            Ok(peers) => peers,
            Err(e) => return Some(e),
        };
        // Reserve the sparse record only now that a peer can serve it, and
        // drop it again if nothing lands (same reason as pull_shard_chunk):
        // reserving before the dial lets an owner-declared size sit in the
        // store for bytes that never arrive. The claim holds that cleanup
        // back while the moov warm-up, or a second concurrent Range request
        // on the same media element, is still filling it.
        let _claim = match self.claim_object(store, id, Ns::Plain, size, now) {
            Ok(claim) => claim,
            Err(e) => return Some(e.to_string()),
        };
        let mut swarm =
            Swarm::new(store.clone(), id, size).with_observer(self.xfer.scope(id, address));
        match swarm.fetch(needed, &handles, Deadline::tight(), now).await {
            Ok(report) => {
                self.credit(address, &report, &node_pks, now).await;
                None
            }
            Err(e) => {
                let e = e.to_string();
                self.xfer.note_error(id, address, now, &e);
                Some(e)
            }
        }
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

    /// On a touch of a large media file, ensure the one-per-object background
    /// download of the COMPLETE file is running.
    ///
    /// Full-file download is the DEFAULT goal for media: playback may start
    /// long before it finishes (the tight-deadline range serves and the
    /// play-order read-ahead race ahead of it), and a seek is still served on
    /// demand the same way, but the whole file keeps downloading regardless of
    /// where the play head is or whether the player pauses. The windowed
    /// read-ahead alone left a paused or seeked-around video permanently
    /// partial: it only ever fetches FORWARD of the play head, so bytes
    /// skipped by a seek were never backfilled and an abandoned player froze
    /// the file mid-download.
    ///
    /// Runs at [`Deadline::background`]: rarest-first, patient, and ordered
    /// behind the streaming tiers by every peer's deadline-aware serving, so
    /// it soaks up idle swarm capacity instead of competing with the bytes
    /// the player needs next. Overlap with the concurrent serves/read-ahead
    /// is reconciled by the store's idempotent verified writes, and each pass
    /// recomputes what is still missing, so nothing already landed is asked
    /// for again.
    ///
    /// Gated by SIZE like the moov warm-up (the content type is not reliably
    /// known here): below the threshold the very first read-ahead window
    /// already spans the file. A file too big for the store quota stays
    /// windowed - completing it could only evict itself or everything else.
    /// `EPIX_EDX_COMPLETE_MEDIA=0` opts a bandwidth/disk-conscious node out,
    /// reverting to fetch-what-you-view.
    /// Mark a foreground (player-blocking) range fetch as on the network for
    /// the guard's lifetime; `run_completion` yields while any is live, and
    /// the process-wide count drives the seeder side's LEDBAT yield (see
    /// [`set_edx_foreground`]).
    fn note_foreground_fetch(&self) -> ForegroundFetch {
        if let Ok(mut s) = self.streaming.lock() {
            s.foreground_fetches += 1;
        }
        if FOREGROUND_FETCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
            set_edx_foreground(true);
        }
        ForegroundFetch { streaming: self.streaming.clone() }
    }

    /// Wait until no foreground range fetch is on the network. Polling is
    /// fine here: only the background completion waits, and 200ms of extra
    /// quiet costs it nothing.
    async fn wait_foreground_idle(&self) {
        loop {
            let busy = self
                .streaming
                .lock()
                .map(|s| s.foreground_fetches > 0)
                .unwrap_or(false);
            if !busy {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    fn maybe_complete_file(
        &self,
        address: &str,
        inner_path: &str,
        id: ObjId,
        size: u64,
        store: &Arc<Store>,
    ) {
        if size < MOOV_MIN_SIZE || size > store_quota() || !env_on("EPIX_EDX_COMPLETE_MEDIA") {
            return;
        }
        if store.is_complete(id).unwrap_or(false) {
            return; // nothing left to complete (fully cached or extern)
        }
        {
            let mut s = self.streaming.lock().expect("streaming");
            if !s.completing.insert(id) {
                return; // a completion pass is already running for this object
            }
        }
        // Released from a Drop guard, not a trailing statement: a panic
        // anywhere in the task would otherwise leak the entry and block this
        // object's completion until restart. Removing on EXIT rather than
        // keeping the entry as a done-marker is what re-arms an unfinished
        // completion - the next Range request retries it, so an actively
        // watched file keeps pulling while an abandoned one stops costing
        // anything (no serves, no re-arms).
        struct Gate {
            streaming: Arc<Mutex<Streaming>>,
            id: ObjId,
        }
        impl Drop for Gate {
            fn drop(&mut self) {
                if let Ok(mut s) = self.streaming.lock() {
                    s.completing.remove(&self.id);
                }
            }
        }
        let gate = Gate { streaming: self.streaming.clone(), id };
        let this = self.clone();
        let address = address.to_string();
        let inner_path = inner_path.to_string();
        tokio::spawn(async move {
            let _gate = gate;
            this.run_completion(&address, &inner_path, id, size).await;
        });
    }

    /// Pull every group of `id` the store still lacks, in passes, until the
    /// object is complete or a pass lands nothing (no dialable peer can
    /// supply what is left - the next Range serve re-arms via
    /// [`Self::maybe_complete_file`]). Each pass recomputes the missing set,
    /// so groups the concurrent serves and read-ahead landed in the meantime
    /// are never refetched, and redials through `peers_for`, whose
    /// SESSION_MAX_AGE rebuild lets a long download pick up peers discovered
    /// after it started. Silent on failure: completion is a background goal
    /// and must never surface an error into a serve.
    async fn run_completion(&self, address: &str, inner_path: &str, id: ObjId, size: u64) {
        let Some(store) = self.state.edx_store().await else { return };
        loop {
            // Yield to any player-blocking fetch before starting the next
            // batch: the deadline tiers order work WITHIN a peer's serving,
            // but this pull still occupies the same few links/circuits a
            // seek needs to dial through.
            self.wait_foreground_idle().await;
            let now = now_secs();
            let Ok(needed) = needed_groups(&store, id, size) else { return };
            if needed.is_empty() {
                break;
            }
            let Ok((handles, node_pks)) = self.peers_for(address, id, &needed).await else {
                return;
            };
            // Reserve only once a holder is known (see `run_readahead`); the
            // claim keeps this pass and the concurrent serves of the same
            // object from dropping the record out from under each other.
            let Ok(_claim) = self.claim_object(&store, id, Ns::Plain, size, now) else { return };
            let mut swarm =
                Swarm::new(store.clone(), id, size).with_observer(self.xfer.scope(id, address));
            // Bounded batch per pass (16 MiB), so a seek arriving mid-download
            // waits out one batch at most, not the whole remaining file.
            let batch = completion_batch(&needed);
            let Ok(report) = swarm.fetch(&batch, &handles, Deadline::background(), now).await
            else {
                return;
            };
            self.credit(address, &report, &node_pks, now).await;
            let _ = store.enforce_quota(store_quota());
            if report.groups_fetched == 0 {
                if batch.count() >= needed.count() {
                    return; // no progress: nothing left that any dialable peer holds
                }
                // The head batch landed nothing; those groups may just not be
                // held anywhere right now. Sweep the full remaining set once
                // before concluding no dialable peer has anything left.
                let Ok(rest) = swarm.fetch(&needed, &handles, Deadline::background(), now).await
                else {
                    return;
                };
                self.credit(address, &rest, &node_pks, now).await;
                let _ = store.enforce_quota(store_quota());
                if rest.groups_fetched == 0 {
                    return;
                }
            }
        }
        // Complete: the file the user has been watching becomes a file they
        // HAVE, without waiting for a further Range request to notice.
        self.maybe_materialize_complete(address, inner_path, id, size, &store).await;
    }

    /// After serving a range, arm the background read-ahead of the NEXT window.
    /// Plans + reserves under the lock: coalesces an unmoved play head and caps
    /// to one in-flight task per file, so a browser's burst of Range requests
    /// cannot fan out into a burst of prefetches. While a task is running the
    /// newest planned window is QUEUED instead of dropped, and the running
    /// task rolls straight into it - so an actively streaming file keeps the
    /// pipeline refilling continuously. Backpressure is inherent - a paused
    /// video issues no Range requests, so nothing re-queues and prefetch
    /// quiesces after the current window with no separate mechanism.
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
            if s.anchor.len() >= MAX_STREAMING_FILES {
                s.anchor.clear(); // bound memory; a cleared file re-anchors once
                s.queued.clear();
            }
            s.anchor.insert(key.clone(), new_anchor);
            if s.inflight.contains(&key) {
                // A read-ahead is already running for this file: hand it the
                // newest window to continue with instead of dropping it.
                s.queued.insert(key, window);
                return;
            }
            s.inflight.insert(key.clone());
            window
        };
        let this = self.clone();
        tokio::spawn(async move {
            let mut window = window;
            loop {
                this.run_readahead(&key.0, id, size, window).await;
                let next = {
                    let mut s = this.streaming.lock().expect("streaming");
                    match s.queued.remove(&key) {
                        Some(w) => Some(w), // roll into the freshest window
                        None => {
                            s.inflight.remove(&key);
                            None
                        }
                    }
                };
                match next {
                    Some(w) => window = w,
                    None => break,
                }
            }
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
        let present = store.present_bits(id).unwrap_or_default();
        let needed = missing_groups(&present, &window);
        if needed.is_empty() {
            return; // already warm
        }
        let Ok((handles, node_pks)) = self.peers_for(address, id, &needed).await else { return };
        // Reserve only once a holder is known: reserving before the dial lets
        // an unobtainable owner-declared size sit in the store for bytes that
        // never arrive. This runs concurrently with the serve of the same
        // object by design, so the claim is what keeps either side from
        // removing a record the other is still filling.
        let Ok(_claim) = self.claim_object(&store, id, Ns::Plain, size, now) else {
            return;
        };
        self.xfer.note_readahead(id, address, now, Some((window.start, window.end)));
        let mut swarm =
            Swarm::new(store.clone(), id, size).with_observer(self.xfer.scope(id, address));
        // Read-ahead IS streaming work - it decides whether playback stalls a
        // minute from now - so it fetches in play order over the fastest peers,
        // not as background bulk spread across whoever is idle.
        if let Ok(report) = swarm.fetch(&needed, &handles, Deadline::prefetch(), now).await {
            self.credit(address, &report, &node_pks, now).await;
        }
        self.xfer.note_readahead(id, address, now_secs(), None);
        let _ = store.enforce_quota(store_quota());
    }

    /// Dial `peers` (up to `cap`) ONCE and keep the links, so a batch fetches
    /// every file over the same connections instead of redialing per file (the
    /// redial-per-file cost of calling `fetch_file` in a loop). Object-
    /// independent: the per-object bitfield is fetched later over these links.
    ///
    /// Dials run CONCURRENTLY and the session is handed back the moment the
    /// FIRST peer answers - the remaining dials continue in the background and
    /// their links join the [`Session`] as they land. See that type for why
    /// waiting for the last dial is what stalled a clone.
    ///
    /// Every dial's outcome is fed back into `address`'s peer registry (via
    /// note_edx_dials), late ones included, so a dead peer sinks and a live one
    /// rises - without that the clone kept redialing the same unranked top-N
    /// and gave up while a reachable seeder sat lower.
    async fn open_session(&self, address: &str, peers: &[PeerAddr], cap: usize) -> Session {
        let mut join = tokio::task::JoinSet::new();
        for peer in peers.iter().take(cap).cloned() {
            let this = self.clone();
            join.spawn(async move {
                let started = std::time::Instant::now();
                let r = this.link(&peer).await;
                (peer, r, started.elapsed())
            });
        }
        let links: Arc<Mutex<Vec<SessionPeer>>> = Arc::new(Mutex::new(Vec::new()));
        let (growth, watch_rx) = tokio::sync::watch::channel(0usize);
        let mut outcomes: Vec<(PeerAddr, bool)> = Vec::new();
        // Wait for ONE live link - with none there is nothing to fetch over.
        // Then keep collecting for a widen window and hand the session back.
        // Peers that are up answer at roughly the same speed as each other, so
        // the window is scaled off the first dial (see session_widen) instead
        // of being a flat wait: a pool-warm or LAN-fast link must not cost the
        // same pause as a Tor rendezvous. What the window never covers is a
        // DEAD peer, whose 15s/45s timeout is the stall this avoids entirely.
        // Anything slower joins the live session below rather than holding up
        // the start.
        let mut widen_until: Option<tokio::time::Instant> = None;
        loop {
            let next = match widen_until {
                Some(end) => match tokio::time::timeout_at(end, join.join_next()).await {
                    Ok(v) => v,
                    Err(_) => break,
                },
                None => join.join_next().await,
            };
            let Some(res) = next else { break };
            let Ok((peer, r, took)) = res else { continue };
            match r {
                Ok((conn, identity, reg, _activity)) => {
                    outcomes.push((peer.clone(), true));
                    links.lock().expect("session").push(SessionPeer {
                        conn,
                        class: Class::of_addr(&peer),
                        label: peer.to_string(),
                        node_pk: identity.node_pk,
                        reg: Some(reg),
                    });
                    widen_until
                        .get_or_insert_with(|| tokio::time::Instant::now() + session_widen(took));
                }
                Err(_) => outcomes.push((peer, false)),
            }
        }
        self.state.note_edx_dials(address, outcomes).await;

        // The rest keep dialing; each link that lands joins the live session
        // and widens the fetch already in progress. Dropping `growth` when
        // this task ends is what tells a waiter no more are coming.
        let (state, addr) = (self.state.clone(), address.to_string());
        let late_links = links.clone();
        tokio::spawn(async move {
            let mut late: Vec<(PeerAddr, bool)> = Vec::new();
            while let Some(res) = join.join_next().await {
                let Ok((peer, r, _)) = res else { continue };
                match r {
                    Ok((conn, identity, reg, _activity)) => {
                        late.push((peer.clone(), true));
                        let count = {
                            let mut held = late_links.lock().expect("session");
                            held.push(SessionPeer {
                                conn,
                                class: Class::of_addr(&peer),
                                label: peer.to_string(),
                                node_pk: identity.node_pk,
                                reg: Some(reg),
                            });
                            held.len()
                        };
                        let _ = growth.send(count);
                    }
                    Err(_) => late.push((peer, false)),
                }
            }
            if !late.is_empty() {
                state.note_edx_dials(&addr, late).await;
            }
        });

        Session { peers: links, growth: watch_rx }
    }

    /// Fetch one order-policy tier over the open session: the GetMany fast path
    /// for small objects, then the swarm for the rest, materializing each file
    /// into `batch` as it lands. `deadline` is the tier's urgency (tight for
    /// the owner-declared first-paint shell, background otherwise).
    #[allow(clippy::too_many_arguments)]
    async fn fetch_tier(
        &self,
        address: &str,
        store: &Arc<Store>,
        session: &Session,
        files: Vec<Res>,
        deadline: Deadline,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
        now: u64,
    ) {
        // GetMany fast path: small whole objects (<= MAX_MANY_ITEM_BYTES) ride
        // one round trip per <= MAX_MANY_ITEMS-id batch over a session peer,
        // avoiding a bitfield + swarm per file - the win for a forum's many
        // tiny post/data files. Larger files, and any small file a peer did not
        // return, drop to the swarm pass below.
        let cap = epix_edx::server::MAX_MANY_ITEM_BYTES;
        let (small, mut remaining): (Vec<Res>, Vec<Res>) =
            files.into_iter().partition(|r| r.size > 0 && r.size <= cap);
        if !small.is_empty() {
            let lacking = self
                .get_many_pass(address, store, &session.peers(), small, progress, batch, now)
                .await;
            remaining.extend(lacking);
        }

        // Swarm pass: large files, plus any small file GetMany could not land.
        //
        // Several objects in flight at once. Each swarm stripes ONE object
        // across the session, so taking them strictly one after another left
        // every link idle between objects - measured on a cold clone over Tor,
        // five large files (stylesheets, jquery, the editor and ethers bundles)
        // took 22s of a 52s core download that way. A sliding window keeps the
        // links busy; materializing stays on this task, which owns `batch`.
        const LARGE_FILE_CONCURRENCY: usize = 4;
        let mut queue = remaining.into_iter();
        let mut fetching: tokio::task::JoinSet<(Res, bool)> = tokio::task::JoinSet::new();
        let mut spawn_next = |fetching: &mut tokio::task::JoinSet<(Res, bool)>| {
            let Some(r) = queue.next() else { return false };
            let this = self.clone();
            // The session is handed down live, not snapshotted: each file
            // starts on the links dialed so far and keeps joining the ones
            // that land while it runs (fetch_one_over_session), so a swarm
            // that began on one link widens as the rest arrive.
            let (store, session) = (store.clone(), session.clone());
            let serving = progress.serving.clone();
            let address = address.to_string();
            fetching.spawn(async move {
                let complete = this
                    .fetch_one_over_session(
                        &address, &store, r.id, r.size, &session, deadline, now, &serving,
                    )
                    .await;
                (r, complete)
            });
            true
        };
        for _ in 0..LARGE_FILE_CONCURRENCY {
            if !spawn_next(&mut fetching) {
                break;
            }
        }
        while let Some(joined) = fetching.join_next().await {
            spawn_next(&mut fetching);
            let Ok((r, complete)) = joined else { continue };
            let done = complete
                && self.materialize_into_batch(address, &r, store, progress, batch).await;
            if !done {
                // This EDX-eligible file went to the msgpack worker (the 1b
                // gate); counted once per distinct file across all retries.
                epix_ui::state::note_edx_fallback_path(address, &r.path);
                batch.missed.push(r.path);
            }
        }
    }

    /// Run the GetMany round trips for one tier's small files over the open
    /// session, materializing each file the moment its bytes land. Returns the
    /// files the store STILL lacks (plus any whose materialize failed), for the
    /// swarm pass.
    ///
    /// The ids are DEALT across the links and pulled from all of them at once,
    /// so a batch downloads from the whole session in parallel rather than
    /// draining one peer end to end - and the loading screen can name how many
    /// peers it is drawing from. Whatever the link that drew it could not serve
    /// is swept across the others afterwards.
    ///
    /// The materialize runs CONCURRENTLY with the round trips, fed by the
    /// per-object hook: a GetMany batch is a whole xite's small files, so
    /// materializing only after the last one arrived left the clone's loading
    /// bar pinned at 0 for the entire download and then jumped it to done, and
    /// kept a forum's posts out of the db (no `file_done`, no re-query) until
    /// the pass ended.
    #[allow(clippy::too_many_arguments)]
    async fn get_many_pass(
        &self,
        address: &str,
        store: &Arc<Store>,
        session: &[SessionPeer],
        small: Vec<Res>,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
        now: u64,
    ) -> Vec<Res> {
        let (ids, by_id) = dedup_obj_ids(&small);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ObjId>();
        let fetch = async {
            // Owned by this block, so it drops when the round trips end and the
            // drain below sees the channel close.
            let tx = tx;
            deal_get_many(session, &ids, store, address, progress, now, &tx).await;
            sweep_get_many(session, &ids, store, address, progress, now, &tx).await;
        };
        let mut done: HashSet<usize> = HashSet::new();
        let drain = async {
            while let Some(id) = rx.recv().await {
                for i in by_id.get(&id).into_iter().flatten().copied() {
                    if done.contains(&i)
                        || !self
                            .materialize_into_batch(address, &small[i], store, progress, batch)
                            .await
                    {
                        continue;
                    }
                    done.insert(i);
                }
            }
        };
        tokio::join!(fetch, drain);
        self.retry_unlanded(address, small, store, progress, batch, &done).await
    }

    /// Anything the landed hook did not carry (already complete before this
    /// pass, or a materialize that failed on its first try) gets one more
    /// chance; the rest are returned for the swarm pass, where a peer that
    /// lacked the whole object may still hold its chunks.
    #[allow(clippy::too_many_arguments)]
    async fn retry_unlanded(
        &self,
        address: &str,
        small: Vec<Res>,
        store: &Arc<Store>,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
        done: &HashSet<usize>,
    ) -> Vec<Res> {
        let mut lacking = Vec::new();
        for (i, r) in small.into_iter().enumerate() {
            if done.contains(&i) {
                continue;
            }
            if store.is_complete(r.id).unwrap_or(false)
                && self.materialize_into_batch(address, &r, store, progress, batch).await
            {
                continue;
            }
            lacking.push(r);
        }
        lacking
    }

    /// Materialize one object the store holds complete into the xite and count
    /// it into `batch` (bytes, progress callback, then `done`). Returns whether
    /// it landed; on a read or materialize failure nothing is counted, so the
    /// caller is free to send the file down another path.
    ///
    /// This is the CLONE path - the one that runs for every file of a xite
    /// you add - so it has to hand big objects over to the xite tree
    /// ([`Self::materialize`]) rather than copy their bytes out. Reading
    /// whole files and writing them back left a cloned xite stored twice,
    /// once as the user's files and once as objects, which on a real node
    /// meant the object store matching the data directory byte for byte.
    async fn materialize_into_batch(
        &self,
        address: &str,
        r: &Res,
        store: &Arc<Store>,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
    ) -> bool {
        let size = match store.info(r.id) {
            Ok(Some((size, _))) => size,
            _ => return false,
        };
        if let Err(e) = self
            .materialize(
                address,
                &r.path,
                r.id,
                size,
                store,
                r.authority.as_ref(),
            )
            .await
        {
            // A record whose bytes cannot be read back (torn write from a
            // killed process, disk/record disagreement) would fail this same
            // way on every retry while the fetch pass skips groups the
            // record claims present. Revalidate in the background - it
            // shrinks or retires the record - so the NEXT pass refetches
            // instead of looping. Mirrors the range-serve path.
            self.state
                .log(
                    "DEBUG",
                    format!("EDX materialize {}/{} failed: {e}; revalidating", address, r.path),
                )
                .await;
            let vstore = store.clone();
            let id = r.id;
            tokio::task::spawn_blocking(move || {
                let _ = vstore.revalidate(id);
            });
            return false;
        }
        batch.bytes += size;
        progress.file(&r.path, size);
        batch.done.push(r.path.clone());
        true
    }

    /// Fetch one object over an already-open session (reused links): learn
    /// which links hold it (one bitfield request each), then stripe it with the
    /// swarm. Returns whether the object is complete in the store afterward.
    /// Every peer the swarm actually drew groups from joins the batch's serving
    /// set, so a big file striped across the session reports the same "from N
    /// peers" the GetMany rounds do.
    ///
    /// Links that finish dialing while THIS file runs join its swarm with a
    /// fresh bitfield (`spawn_session_link_feed`) rather than waiting for
    /// the next file - a clone's large files span the whole dial phase.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_one_over_session(
        &self,
        address: &str,
        store: &Arc<Store>,
        id: ObjId,
        size: u64,
        session: &Session,
        deadline: Deadline,
        now: u64,
        serving: &Arc<Mutex<HashSet<String>>>,
    ) -> bool {
        if store.is_complete(id).unwrap_or(false) {
            return true;
        }
        let snapshot = session.peers();
        let mut handles: Vec<PeerHandle> = Vec::new();
        let mut node_pks: HashMap<String, Vec<u8>> = HashMap::new();
        for p in &snapshot {
            if let Some(reg) = &p.reg {
                reg.note_cmd_sent("GetBitfield", None);
            }
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
        // Reserve only now that a session peer holds it, and drop the record
        // again if nothing lands (see `ObjClaim`).
        let Ok(_claim) = self.claim_object(store, id, Ns::Plain, size, now) else {
            return false;
        };
        let Ok(needed) = needed_groups(store, id, size) else { return false };
        let mut swarm =
            Swarm::new(store.clone(), id, size).with_observer(self.xfer.scope(id, address));
        let node_pks = Arc::new(Mutex::new(node_pks));
        let (join_tx, joiners) = tokio::sync::mpsc::unbounded_channel();
        spawn_session_link_feed(session.clone(), snapshot.len(), id, node_pks.clone(), join_tx);
        if let Ok(report) = swarm.fetch_growable(&needed, handles, joiners, deadline, now).await {
            for (label, _) in report.by_peer.iter().filter(|(_, groups)| **groups > 0) {
                BatchProgress::note_peer(serving, label);
            }
            let pks = node_pks.lock().expect("node pks").clone();
            self.credit(address, &report, &pks, now).await;
        }
        store.is_complete(id).unwrap_or(false)
    }

    /// Resolve each want to an object id + size; split off shard files, and
    /// send anything with no EDX entry straight to the fallback. Returns the
    /// plain files and the shard paths, each in want order; the unresolvable
    /// ones are pushed onto `batch.missed` here.
    ///
    /// A helper of the [`EdxFetcher::fetch_files`] batch below (a trait impl
    /// cannot hold private methods, so its helpers live here).
    async fn resolve_wants(
        &self,
        address: &str,
        want: Vec<EdxWant>,
        content: &Option<serde_json::Value>,
        batch: &mut EdxBatch,
    ) -> (Vec<Res>, Vec<ShardRes>) {
        let mut plain: Vec<Res> = Vec::new();
        let mut shard_paths: Vec<ShardRes> = Vec::new();
        for w in want {
            if content
                .as_ref()
                .is_some_and(|c| epix_blob::manifest::edx_shard_entry(c, &w.inner_path).is_some())
            {
                shard_paths.push(ShardRes {
                    path: w.inner_path,
                    authority: w.authority,
                });
                continue;
            }
            let resolved = match (w.id, w.size) {
                (Some(id), Some(size)) => Some((id, size)),
                _ => self.resolve(address, &w.inner_path).await.ok().flatten(),
            };
            match resolved {
                Some((id, size)) => plain.push(Res {
                    path: w.inner_path,
                    id,
                    size,
                    authority: w.authority,
                }),
                None => batch.missed.push(w.inner_path),
            }
        }
        (plain, shard_paths)
    }

    /// Materialize anything already complete in the store (no network).
    /// Returns the files still to fetch, in want order.
    async fn drain_locally_complete(
        &self,
        address: &str,
        store: &Arc<Store>,
        plain: Vec<Res>,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
    ) -> Vec<Res> {
        let mut pending: Vec<Res> = Vec::new();
        for r in plain {
            // A zero-length file has no chunk groups, so there is nothing for
            // any peer to send. Nothing ever writes a store record for it,
            // `Store::is_complete` answers false on the MISSING record (not on
            // the bits - `GroupBits::is_complete` already says true for size
            // 0), and the fetch below leaves it pending on every pass. One
            // empty file signed into a xite therefore failed the whole clone
            // for every node, forever: the core set never completed, so
            // content.json was never committed and the xite stayed pinned to
            // its previous version. Seen in the wild as a stray SQLite `-wal`
            // sidecar swept into a sign. An empty file is complete by
            // definition - write it here instead of asking the swarm.
            let landed = if r.size == 0 {
                self.materialize_empty(address, &r, progress, batch).await
            } else {
                store.is_complete(r.id).unwrap_or(false)
                    && self.materialize_into_batch(address, &r, store, progress, batch).await
            };
            if landed {
                continue;
            }
            pending.push(r);
        }
        pending
    }

    /// Write a zero-length file straight into the xite tree and count it
    /// landed. No store record is involved: an empty object has no groups to
    /// index, and `files_needed` is satisfied by the file being on disk with
    /// the empty hash. Returns false if the write failed, so the caller leaves
    /// it pending and it is reported missed rather than silently dropped.
    async fn materialize_empty(
        &self,
        address: &str,
        r: &Res,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
    ) -> bool {
        if let Err(e) = self
            .state
            .edx_materialize_file(address, &r.path, r.id, &[], r.authority.as_ref())
            .await
        {
            self.state
                .log(
                    "DEBUG",
                    format!("EDX empty-file materialize {address}/{} failed: {e}", r.path),
                )
                .await;
            return false;
        }
        progress.file(&r.path, 0);
        batch.done.push(r.path.clone());
        true
    }

    /// Encrypted-shard files: no other fetch path exists (they are not in
    /// the plain files map), so fetch each over EDX or drop it. A landed shard
    /// file reports 0 bytes of progress and adds nothing to `batch.bytes` - the
    /// shard path materializes the plaintext itself, out of sight of the batch.
    async fn fetch_shard_paths(
        &self,
        address: &str,
        content: &Option<serde_json::Value>,
        paths: Vec<ShardRes>,
        store: &Arc<Store>,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
    ) {
        for shard_res in paths {
            let path = shard_res.path;
            let got = match content
                .as_ref()
                .and_then(|c| epix_blob::manifest::edx_shard_entry(c, &path).map(|s| (c, s)))
            {
                Some((c, shard)) => {
                    matches!(
                        self.fetch_shard_file(
                            address,
                            &path,
                            c,
                            shard,
                            shard_res.authority.as_ref(),
                            store,
                        )
                        .await,
                        Ok(true)
                    )
                }
                None => false,
            };
            if got {
                progress.file(&path, 0);
                batch.done.push(path);
            } else {
                batch.missed.push(path);
            }
        }
    }

    /// The owner's signed load order (content.json `order_policy`) decides
    /// which files go down first: the declared first-paint shell, then
    /// everything undeclared in the default ladder, then prefetch hints.
    /// Each tier runs its own complete GetMany+swarm pass before the next
    /// one starts, so a large first-paint file still beats a small prefetch
    /// file (a single sorted pass would not - GetMany batches all the small
    /// files ahead of every large one).
    ///
    /// A xite that declares NOTHING is sorted by file type instead
    /// (`policy::default_tier`): markup, styles, scripts and images first,
    /// media and archives last. It used to land in a single tier, which is
    /// how a 1.21 GB xite could finish downloading its index.html and still
    /// not draw - the page's own assets were queued behind a gigabyte of
    /// video nobody was waiting for.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_tiers(
        &self,
        address: &str,
        store: &Arc<Store>,
        session: &Session,
        mut pending: Vec<Res>,
        content: &Option<serde_json::Value>,
        progress: &BatchProgress,
        batch: &mut EdxBatch,
        now: u64,
    ) {
        let policy = content.as_ref().map(OrderPolicy::from_content).unwrap_or_default();
        for tier in [FetchTier::FirstPaint, FetchTier::Default, FetchTier::Prefetch] {
            let (in_tier, rest): (Vec<Res>, Vec<Res>) =
                pending.into_iter().partition(|r| policy.tier(&r.path) == tier);
            pending = rest;
            if in_tier.is_empty() {
                continue;
            }
            // First paint races slow peers (tight); everything else is patient.
            // The deadline is advisory to the peer AND our local wait cap, so it
            // only ever reorders OUR fetching - it is not a serving priority we
            // grant anyone, which is why an owner cannot use it to take service.
            let deadline = match tier {
                FetchTier::FirstPaint => Deadline::tight(),
                _ => Deadline::background(),
            };
            self.fetch_tier(address, store, session, in_tier, deadline, progress, batch, now).await;
        }
    }

    /// If a streamed object has just become complete, move it into the xite
    /// tree in the background.
    ///
    /// This is what closes the gap between "the bytes are on this machine"
    /// and "the user has the file". A range-fetched video used to live only
    /// as a hash-named blob in the object store: not in the xite directory,
    /// not copyable, not re-publishable, and evictable as cache. Once it is
    /// extern it is an ordinary file the user owns.
    ///
    /// Cheap on the serve path: two indexed lookups, and a spawn only on the
    /// single request that observes the transition.
    async fn maybe_materialize_complete(
        &self,
        address: &str,
        inner_path: &str,
        id: ObjId,
        size: u64,
        store: &Arc<Store>,
    ) {
        // Small objects are packed in shared slabs and are materialized by
        // the batch path that fetched them; only whole-file objects move.
        if epix_blob::bundle::is_bundleable(size) {
            return;
        }
        if !store.is_complete(id).unwrap_or(false) || store.is_extern(id).unwrap_or(false) {
            return;
        }
        {
            let mut s = self.streaming.lock().expect("streaming");
            if !s.materializing.insert(id) {
                return; // another Range request is already moving it
            }
        }
        // Released from a Drop guard, not a trailing statement: a panic
        // anywhere in the task would otherwise leak the entry and block this
        // object's materialize until restart.
        struct Claim {
            streaming: Arc<Mutex<Streaming>>,
            id: ObjId,
        }
        impl Drop for Claim {
            fn drop(&mut self) {
                if let Ok(mut s) = self.streaming.lock() {
                    s.materializing.remove(&self.id);
                }
            }
        }
        let claim = Claim { streaming: self.streaming.clone(), id };
        let this = self.clone();
        let address = address.to_string();
        let inner_path = inner_path.to_string();
        tokio::spawn(async move {
            let _claim = claim;
            if let Err(e) = this
                .state
                .edx_materialize_object(&address, &inner_path, id, None)
                .await
            {
                // Not fatal: the bytes are still served from the store, and
                // the next completed range retries the move.
                this.state
                    .log("WARN", format!("materialize {address}/{inner_path}: {e}"))
                    .await;
            }
        });
    }

    /// The body behind both [`EdxFetcher::fetch_file`] entries: resolve,
    /// fetch what the store lacks at `deadline`, materialize. The deadline is
    /// the ONLY difference between the interactive and background variants -
    /// keeping one body means they can never drift apart in anything else.
    async fn fetch_file_at(
        &self,
        address: &str,
        inner_path: &str,
        deadline: Deadline,
        on_fetched: Option<epix_ui::state::EdxFetchedHook>,
    ) -> Result<bool, String> {
        let store = self.state.edx_store().await.ok_or("no EDX store")?;
        // Encrypted-shard file: fetch the ciphertext shards and decrypt.
        let content_bytes =
            self.state.read_file(address, "content.json").await.ok_or("no content.json")?;
        let content: serde_json::Value =
            serde_json::from_slice(&content_bytes).map_err(|e| e.to_string())?;
        if let Some(shard) = epix_blob::manifest::edx_shard_entry(&content, inner_path) {
            return self
                .fetch_shard_file(address, inner_path, &content, shard, None, &store)
                .await;
        }
        let Some((id, size)) = self.resolve(address, inner_path).await? else {
            return Err("no edx entry for file".into());
        };
        let now = now_secs();

        // Already complete in the store: just materialize it.
        if store.is_complete(id).unwrap_or(false) {
            self.materialize_gated(
                address,
                inner_path,
                id,
                size,
                &store,
                MaterializeOptions {
                    on_fetched: on_fetched.as_ref(),
                    authority: None,
                },
            )
            .await?;
            return Ok(true);
        }

        let (handles, node_pks, late) = self.build_peers(address, id).await?;
        // Register the session in the peer cache BEFORE fetching. This is
        // what lets add_cached_lane land the extra overlay lanes still
        // dialing - over Tor they nearly always finish after the
        // first-handle grace, and with no cache entry they were silently
        // dropped, which is how a multi-GB file rode ONE circuit for its
        // whole life. It also hands a retry of this file a warm session
        // instead of a redial.
        self.cache_peers(id, &handles, &node_pks);
        // Reserve the sparse record only now that a peer can serve it, and drop
        // it again if nothing lands (see `ObjClaim`): a manifest entry a
        // visitor touches once must not leave an index row and a sparse/.obao
        // file pair behind forever.
        let _claim =
            self.claim_object(&store, id, Ns::Plain, size, now).map_err(|e| e.to_string())?;
        let needed = needed_groups(&store, id, size).map_err(|e| e.to_string())?;
        let mut swarm =
            Swarm::new(store.clone(), id, size).with_observer(self.xfer.scope(id, address));
        // Links that finish dialing after the grace join the RUNNING fetch:
        // the extra lanes and the slow circuits used to warm a pool nothing
        // read while the fetch stayed frozen on whatever made the 2s cut.
        let node_pks = Arc::new(Mutex::new(node_pks));
        let (join_tx, joiners) = tokio::sync::mpsc::unbounded_channel();
        self.spawn_late_link_feed(late, id, address.to_string(), node_pks.clone(), join_tx);
        let report = match swarm.fetch_growable(&needed, handles, joiners, deadline, now).await {
            Ok(report) => report,
            Err(e) => {
                let e = e.to_string();
                // Stamped fresh: `now` predates the fetch, which can span
                // an hour on a multi-GB file, and last_error reports an age.
                self.xfer.note_error(id, address, now_secs(), &e);
                return Err(e);
            }
        };
        // Hold the (possibly just-completed) object against quota eviction
        // NOW, not in materialize_gated: `credit` awaits first (choker +
        // xites locks), and a sibling pooled file completing in that gap
        // runs `enforce_quota` - at quota its LRU pass could take exactly
        // the bytes this fetch just spent an hour landing. Holds are
        // counted, so the one materialize_gated takes simply overlaps.
        let _hold = store.hold_eviction(id);
        let pks = node_pks.lock().expect("node pks").clone();
        self.credit(address, &report, &pks, now).await;
        if !store.is_complete(id).unwrap_or(false) {
            // The scheduler's silent-exhaustion path (peers ran out of
            // strikes): name it in the telemetry, not just the round log.
            self.xfer.note_error(id, address, now_secs(), "fetch did not complete");
            return Err("fetch did not complete".into());
        }

        self.materialize_gated(
            address,
            inner_path,
            id,
            size,
            &store,
            MaterializeOptions {
                on_fetched: on_fetched.as_ref(),
                authority: None,
            },
        )
        .await?;
        // Cached content grows the store; keep it under quota (own content is
        // pinned, so only cached-from-others objects are evicted).
        let _ = store.enforce_quota(store_quota());
        Ok(true)
    }

    /// [`Self::materialize`] with the pool handoff around it: hold the
    /// completed object against quota eviction, tell the worker pool the
    /// network phase is over (`on_fetched`), and only then run the copy -
    /// pooled callers queue it on the bounded materialize gate.
    ///
    /// The hold closes a real window: a complete-but-not-yet-materialized
    /// object is refcount-0 (`ObjClaim` guards record removal by sibling
    /// claims, not quota eviction), and every OTHER completing file runs
    /// `enforce_quota` - at quota, the LRU pass would take exactly the bytes
    /// this file just spent an hour fetching, and a gate queue makes that
    /// window minutes wide. In-memory on purpose: after a crash the holds
    /// are gone, the object is ordinary cache again, and the file re-checks
    /// as missing and refetches (completing instantly if it survived).
    async fn materialize_gated(
        &self,
        address: &str,
        inner_path: &str,
        id: ObjId,
        size: u64,
        store: &Arc<Store>,
        options: MaterializeOptions<'_>,
    ) -> Result<(), String> {
        let _hold = store.hold_eviction(id);
        let shared = store_fetch_shared(store);
        let _permit = match options.on_fetched {
            Some(fetched) => {
                // Hold taken first: the freed slot's next file can complete
                // and run enforce_quota before our copy starts.
                fetched();
                Some(
                    shared
                        .materialize_gate
                        .acquire()
                        .await
                        .expect("materialize gate is never closed"),
                )
            }
            // Interactive/streaming callers: something is waiting on the
            // file, so never queue it behind bulk copies.
            None => None,
        };
        self.materialize(address, inner_path, id, size, store, options.authority)
            .await
    }

    /// Turn a completed object into the xite's file on disk.
    ///
    /// Small objects live packed in a slab shared with other files, so their
    /// bytes are read out and written (they are small by definition - the
    /// bundle cutoff). Everything else MOVES: the object store hands the
    /// file over to the xite tree and keeps only the outboard, so the user
    /// ends up with one copy at a path they own rather than a second copy
    /// under a hash name. This is the difference between "you streamed a
    /// video" and "you have the video".
    async fn materialize(
        &self,
        address: &str,
        inner_path: &str,
        id: ObjId,
        size: u64,
        store: &Arc<Store>,
        authority: Option<&EdxMaterializeAuthority>,
    ) -> Result<(), String> {
        if epix_blob::bundle::is_bundleable(size) {
            let bytes = store.read_bytes(id, now_secs()).map_err(|e| e.to_string())?;
            return self
                .state
                .edx_materialize_file(address, inner_path, id, &bytes, authority)
                .await;
        }
        self.state
            .edx_materialize_object(address, inner_path, id, authority)
            .await
    }
}

/// The progress state of one batch fetch: the caller's per-file hook plus the
/// set of peers that have actually served bytes in it.
///
/// Carried as one value rather than threading the hook and the peer set
/// separately - every stage of the batch already takes the hook, and the peer
/// set has to ride along with it so a landed file can report how many peers
/// the download is drawing from. Shared (`Arc` inside) because the GetMany
/// round fans out to one task per link.
struct BatchProgress {
    on_file: Option<EdxBatchProgress>,
    /// Labels of the peers that have delivered at least one object.
    serving: Arc<Mutex<HashSet<String>>>,
}

impl BatchProgress {
    fn new(on_file: Option<EdxBatchProgress>) -> Self {
        Self { on_file, serving: Arc::default() }
    }

    /// Record that `label` served bytes for this batch.
    fn note_peer(serving: &Arc<Mutex<HashSet<String>>>, label: &str) {
        serving.lock().unwrap().insert(label.to_string());
    }

    /// Report one materialized file to the caller's hook, with the live count
    /// of peers this batch has drawn from.
    fn file(&self, inner_path: &str, bytes: u64) {
        if let Some(cb) = &self.on_file {
            cb(inner_path, bytes, self.serving.lock().unwrap().len());
        }
    }
}

/// One resolved want inside a batch fetch: the path, its content address, and
/// its declared size. Module-level so the order-policy tier pass can hand a
/// tier's files to [`RuntimeEdxFetcher::fetch_tier`].
struct Res {
    path: String,
    id: ObjId,
    size: u64,
    authority: Option<EdxMaterializeAuthority>,
}

/// One encrypted file resolved from `files_shard`. Its opaque authority is
/// bound to the signed shard descriptor because no plaintext `b3` is public.
struct ShardRes {
    path: String,
    authority: Option<EdxMaterializeAuthority>,
}

/// One peer's reused EDX link for a batch session (dialed once, borrowed by
/// every file's swarm via a cheap `Conn` clone). Clone is cheap for the same
/// reason - it shares the one underlying stream - so a batch can hand the
/// whole session to several concurrent object fetches.
#[derive(Clone)]
struct SessionPeer {
    conn: Conn,
    class: Class,
    label: String,
    node_pk: Vec<u8>,
    /// The link's diagnostics row, kept so requests issued over this reused
    /// link can stamp `last cmd sent` on it.
    reg: Option<Arc<ConnHandle>>,
}

/// How long [`RuntimeEdxFetcher::open_session`] keeps collecting dials after
/// the FIRST peer answers, so the opening deal has more than one link to
/// stripe across, given how long that first dial took.
///
/// Peers that are up complete their handshake at roughly the same speed as
/// each other, so the first success dates the cohort and the window tracks it
/// rather than being a flat pause. That matters because the window can only
/// end early if EVERY dial has settled, and a session almost always has a
/// dead onion peer still counting down its 45s: a flat second was therefore
/// always paid in full, once per session, and a clone opens one per depth
/// level. Measured on a clean clone, that was 3 of the 5.6s to first posts -
/// the largest single cost left - while the link that served everything was
/// pool-warm and answered in ~0ms.
///
/// Clamped at both ends: enough to catch a same-speed cohort, never enough to
/// wait on a dead peer. Slower peers are not lost either way - they join the
/// [`Session`] while the fetch runs.
fn session_widen(first_dial: std::time::Duration) -> std::time::Duration {
    (first_dial * 3).clamp(
        std::time::Duration::from_millis(150),
        std::time::Duration::from_secs(1),
    )
}

/// Transfer lanes opened to one OVERLAY peer, i.e. how many independent
/// circuits a fetch stripes across per seeder.
///
/// A Tor circuit carries about 250 KB/s however fast either end's link is:
/// throughput is its flow-control window (~250 KB in flight) divided by the
/// round trip, and a six-hop onion path runs near a second. Measured on this
/// network, one circuit delivered 102-419 KB/s while the seeder was serving
/// several other peers at once and its own line was idle - the ceiling is the
/// circuit, not the host. Pipelining more requests down one link cannot beat
/// it because they all queue behind the same window; only more circuits can.
///
/// Three is a deliberate compromise. Each lane is a circuit build, and it is
/// circuit churn that gets guards blamed for failures and disabled, which is
/// what takes a node's onion service off the air. Clearnet peers get one lane
/// (a TCP connection has no such ceiling).
fn overlay_lanes() -> u8 {
    std::env::var("EPIX_EDX_ONION_LANES")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(3)
        .clamp(1, 4)
}

/// Lanes to open to `peer`: overlay peers stripe, clearnet does not.
fn lanes_for(peer: &PeerAddr) -> u8 {
    if peer.is_overlay() {
        overlay_lanes()
    } else {
        1
    }
}

/// Overlay dials allowed in flight process-wide (see the call site in
/// `dial`). Generous enough that a normal clone still dials its session in
/// one wave, tight enough that many xites resyncing together cannot hand Tor
/// a burst of circuit builds it will mostly fail.
const MAX_CONCURRENT_OVERLAY_DIALS: usize = 8;

/// The shared overlay-dial slots.
fn overlay_dial_slots() -> &'static tokio::sync::Semaphore {
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS.get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_OVERLAY_DIALS))
}

/// Wait for one of the [`MAX_CONCURRENT_OVERLAY_DIALS`] slots.
///
/// This bounds dials IN FLIGHT, not connections. The permit is released when
/// the dial finishes, an established link holds none (a pooled link never
/// reaches `dial`), and every dial is bounded by `connect_timeout`, so slots
/// always come back. Acquisition is FIFO, so a peer that has to queue is
/// never starved - it dials a moment later. The cap cannot, therefore, close
/// a node into a fixed set of peers.
async fn overlay_dial_permit() -> tokio::sync::SemaphorePermit<'static> {
    overlay_dial_slots().acquire().await.expect("overlay dial slots are never closed")
}

/// Manifest requests kept in flight per link. Held under the seeder's
/// `epix_edx::server::MAX_CONCURRENT_SERVES` (8) so a batch never queues
/// behind its own requests on the serving side.
const REQUESTS_PER_LINK: usize = 4;

/// A peer session that is usable before it has finished opening.
///
/// Dialing continues in the background and each link joins the set as it
/// lands, so a fetch starts on the FIRST peer that answers and gets faster as
/// the others arrive - the BitTorrent shape. Waiting for every dial instead
/// pinned each session to the slowest one: a peer registry is mostly dead
/// gossip addresses and a dead peer costs its whole connect_timeout (15s
/// clearnet, 45s overlay), so a clean clone measured a live seeder answering
/// in 0.0s and then sat 45s behind three dead onion peers before it fetched a
/// single byte. That wait is the "Connecting to peers..." stall.
#[derive(Clone)]
struct Session {
    /// Links in the order they landed; the first is the peer that let the
    /// fetch begin.
    peers: Arc<Mutex<Vec<SessionPeer>>>,
    /// Carries the link count so a waiter can block until the set grows.
    /// The sender lives on the dialing task, so a closed channel means every
    /// dial has settled and no more links are coming.
    growth: tokio::sync::watch::Receiver<usize>,
}

impl Session {
    /// A session backed by the exact authenticated link that delivered an
    /// Update. It has no dial phase and no registry row of its own because the
    /// accepted connection is already tracked by the serve side.
    fn source(conn: Conn, class: Class, label: String, node_pk: Vec<u8>) -> Self {
        let (_growth, growth) = tokio::sync::watch::channel(1usize);
        Self {
            peers: Arc::new(Mutex::new(vec![SessionPeer {
                conn,
                class,
                label,
                node_pk,
                reg: None,
            }])),
            growth,
        }
    }

    /// The links available right now. Callers re-read this at points where
    /// picking up a new peer is cheap (per tier, per queued file), which is
    /// how a fetch already in flight speeds up.
    fn peers(&self) -> Vec<SessionPeer> {
        self.peers.lock().expect("session").clone()
    }

    fn len(&self) -> usize {
        self.peers.lock().expect("session").len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether more links may still arrive. The sender lives on the dialing
    /// task, so a closed channel means every dial has settled.
    fn dialing(&self) -> bool {
        self.growth.has_changed().is_ok()
    }

    /// Wait until the session holds more than `known` links. Returns false
    /// once dialing is over and no more will come, so a caller that has run
    /// out of work to hand out can stop waiting.
    async fn grows_past(&self, known: usize) -> bool {
        let mut growth = self.growth.clone();
        loop {
            if self.len() > known {
                return true;
            }
            if growth.changed().await.is_err() {
                return self.len() > known;
            }
        }
    }
}

/// Turn session links that finish dialing while one file's swarm runs into
/// joiners for it: fetch the newcomer's bitfield for this object and hand
/// the handle to the fetch. The first `staffed` links are the fetch's entry
/// set. Ends when the session stops growing (dialing settled) or the fetch
/// returns (the send fails); dropping `join_tx` then tells the fetch no
/// more are coming.
fn spawn_session_link_feed(
    session: Session,
    mut staffed: usize,
    id: ObjId,
    node_pks: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    join_tx: tokio::sync::mpsc::UnboundedSender<PeerHandle>,
) {
    tokio::spawn(async move {
        while session.grows_past(staffed).await {
            for p in session.peers().into_iter().skip(staffed) {
                staffed += 1;
                if let Some(reg) = &p.reg {
                    reg.note_cmd_sent("GetBitfield", None);
                }
                let Ok(Ok((_sz, bits))) = tokio::time::timeout(
                    EDX_FETCH_TIMEOUT,
                    epix_edx::fetch::fetch_bitfield(&p.conn, id),
                )
                .await
                else {
                    continue;
                };
                node_pks.lock().expect("node pks").insert(p.label.clone(), p.node_pk.clone());
                let handle =
                    PeerHandle { conn: p.conn, class: p.class, bits, label: p.label };
                if join_tx.send(handle).is_err() {
                    return; // the fetch is over
                }
            }
        }
    });
}

/// The distinct object ids of a batch's wants, in caller order, plus the want
/// indices each id belongs to (two paths can share identical bytes -> one id).
///
/// Order is the request order a peer frames its reply in, and the caller sorts
/// by the xite's feed policy - newest user content first - so keeping it is
/// what makes posts stream newest-first.
fn dedup_obj_ids(small: &[Res]) -> (Vec<ObjId>, HashMap<ObjId, Vec<usize>>) {
    let mut ids: Vec<ObjId> = Vec::with_capacity(small.len());
    let mut by_id: HashMap<ObjId, Vec<usize>> = HashMap::new();
    for (i, r) in small.iter().enumerate() {
        by_id
            .entry(r.id)
            .or_insert_with(|| {
                ids.push(r.id);
                Vec::new()
            })
            .push(i);
    }
    (ids, by_id)
}

/// GetMany `ids` over one link, chunked to the wire limit. `landed` fires per
/// object as its bytes verify into the store.
async fn pull_many_chunks(
    conn: &Conn,
    store: &Arc<Store>,
    ids: &[ObjId],
    now: u64,
    landed: &(dyn Fn(ObjId) + Send + Sync),
) {
    for chunk in ids.chunks(epix_edx::server::MAX_MANY_ITEMS) {
        let _ = tokio::time::timeout(
            EDX_FETCH_TIMEOUT,
            epix_edx::fetch::fetch_many(conn, store, chunk, now, Some(landed)),
        )
        .await;
    }
}

/// Round 1 of a GetMany pass: deal the ids round-robin over the links and pull
/// them all at once. Interleaved, not sliced in blocks, so the head of the
/// caller's order - the newest posts, the first-paint shell - goes out to every
/// link immediately instead of queueing behind one peer's whole share.
async fn deal_get_many(
    session: &[SessionPeer],
    ids: &[ObjId],
    store: &Arc<Store>,
    address: &str,
    progress: &BatchProgress,
    now: u64,
    tx: &tokio::sync::mpsc::UnboundedSender<ObjId>,
) {
    let mut round = tokio::task::JoinSet::new();
    for (i, peer) in session.iter().enumerate() {
        let mine: Vec<ObjId> = ids
            .iter()
            .skip(i)
            .step_by(session.len())
            .copied()
            .filter(|id| !store.is_complete(*id).unwrap_or(false))
            .collect();
        if mine.is_empty() {
            continue;
        }
        let (conn, reg) = (peer.conn.clone(), peer.reg.clone());
        let (label, serving) = (peer.label.clone(), progress.serving.clone());
        let (store, tx) = (store.clone(), tx.clone());
        let address = address.to_string();
        round.spawn(async move {
            let landed = move |id: ObjId| {
                BatchProgress::note_peer(&serving, &label);
                let _ = tx.send(id);
            };
            if let Some(reg) = &reg {
                reg.note_cmd_sent("GetMany", Some(&address));
            }
            pull_many_chunks(&conn, &store, &mine, now, &landed).await;
        });
    }
    while round.join_next().await.is_some() {}
}

/// Round 2 of a GetMany pass: whatever the link that drew it could not serve,
/// asked of each link in turn - a peer that was dealt none of an object may
/// still hold it.
async fn sweep_get_many(
    session: &[SessionPeer],
    ids: &[ObjId],
    store: &Arc<Store>,
    address: &str,
    progress: &BatchProgress,
    now: u64,
    tx: &tokio::sync::mpsc::UnboundedSender<ObjId>,
) {
    for peer in session {
        let want: Vec<ObjId> = ids
            .iter()
            .copied()
            .filter(|id| !store.is_complete(*id).unwrap_or(false))
            .collect();
        if want.is_empty() {
            break;
        }
        let landed = |id: ObjId| {
            BatchProgress::note_peer(&progress.serving, &peer.label);
            let _ = tx.send(id);
        };
        if let Some(reg) = &peer.reg {
            reg.note_cmd_sent("GetMany", Some(address));
        }
        pull_many_chunks(&peer.conn, store, &want, now, &landed).await;
    }
}

/// GetSigned one path over one link, firing `on_item` first when it is served
/// so the caller can verify and ingest it mid-pass. `None` when this link could
/// not serve it (dead, or simply does not hold it) - the caller tries another.
async fn fetch_signed_over_link(
    conn: &Conn,
    reg: Option<&ConnHandle>,
    address: &str,
    path: &str,
    on_item: Option<&epix_ui::state::EdxSignedProgress>,
) -> Option<Vec<u8>> {
    if let Some(reg) = reg {
        reg.note_cmd_sent("GetSigned", Some(address));
    }
    let Ok(Ok(bytes)) = tokio::time::timeout(
        EDX_FETCH_TIMEOUT,
        epix_edx::fetch::fetch_signed(conn, address, path),
    )
    .await
    else {
        return None;
    };
    if let Some(cb) = on_item {
        cb(path, &bytes);
    }
    Some(bytes)
}

/// The paths a worker's own link could not serve, walked across the whole
/// session as the serial loop used to do. Bounded: a path nobody holds ends the
/// sweep rather than circling the queue.
/// The shared work one manifest pass's workers pull from and write into:
/// paths still to request, the bytes served, and the paths the link that drew
/// them could not serve (for the sweep over the other links afterwards).
#[derive(Clone, Default)]
struct SignedQueue {
    paths: Arc<Mutex<Vec<String>>>,
    served: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    unserved: Arc<Mutex<Vec<String>>>,
}

/// One worker: take paths off the shared queue and GetSigned each over this
/// link until the queue is empty. Several of these run per link, since a
/// `Conn` is a multiplexer and the seeder serves several requests at once.
async fn drain_signed_queue(
    conn: Conn,
    reg: Option<Arc<ConnHandle>>,
    address: String,
    on_item: Option<epix_ui::state::EdxSignedProgress>,
    work: SignedQueue,
) {
    loop {
        let Some(path) = work.paths.lock().expect("signed queue").pop() else { return };
        match fetch_signed_over_link(
            &conn,
            reg.as_deref(),
            &address,
            &path,
            on_item.as_ref(),
        )
        .await
        {
            Some(bytes) => {
                work.served.lock().expect("signed queue").insert(path, bytes);
            }
            // This link could not serve it; the sweep tries the others.
            // Handing it straight back to the queue risks this same worker
            // popping it right back.
            None => work.unserved.lock().expect("signed queue").push(path),
        }
    }
}

/// Put [`REQUESTS_PER_LINK`] workers on every link that has joined the session
/// since `staffed`, and return the new staffed count. Called each time round
/// the pass's loop, which is how a fetch that began on one peer widens onto
/// the links that finish dialing while it runs.
fn staff_signed_workers(
    session: &Session,
    staffed: usize,
    workers: &mut tokio::task::JoinSet<()>,
    address: &str,
    on_item: &Option<epix_ui::state::EdxSignedProgress>,
    work: &SignedQueue,
) -> usize {
    let mut now_staffed = staffed;
    for p in session.peers().into_iter().skip(staffed) {
        now_staffed += 1;
        for _ in 0..REQUESTS_PER_LINK {
            workers.spawn(drain_signed_queue(
                p.conn.clone(),
                p.reg.clone(),
                address.to_string(),
                on_item.clone(),
                work.clone(),
            ));
        }
    }
    now_staffed
}

async fn sweep_signed_over_session(
    session: &[SessionPeer],
    address: &str,
    paths: Vec<String>,
    on_item: Option<&epix_ui::state::EdxSignedProgress>,
    out: &Mutex<HashMap<String, Vec<u8>>>,
) {
    for path in paths {
        for p in session {
            if let Some(bytes) =
                fetch_signed_over_link(&p.conn, p.reg.as_deref(), address, &path, on_item).await
            {
                out.lock().unwrap().insert(path, bytes);
                break;
            }
        }
    }
}

impl RuntimeEdxFetcher {
    /// Pull one immutable merge delta over the exact authenticated connection
    /// that carried its Update. Bytes stream into the sparse Store through the
    /// ordinary verified range scheduler. They are exposed to the state layer
    /// only after the BLAKE3 root completes.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_object_over_source(
        &self,
        address: &str,
        object: EdxObjectRef,
        conn: Conn,
        class: Class,
        label: String,
        node_pk: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        if object.size == 0 || object.size > MAX_MERGE_DELTA_OBJECT_BYTES {
            return Err("merge delta object size is outside the allowed range".into());
        }
        let store = self.state.edx_store().await.ok_or("no EDX store")?;
        // A concurrent quota pass must not retire a just-completed object in
        // the gap before its verified bytes are copied into state.
        let object_hold = store.hold_eviction(object.id);
        let result = async {
            let now = now_secs();
            if let Some((stored_size, true)) = store.info(object.id).map_err(|e| e.to_string())? {
                if stored_size != object.size {
                    return Err("cached merge delta object has the wrong size".into());
                }
                let bytes = store.read_bytes(object.id, now).map_err(|e| e.to_string())?;
                return (bytes.len() as u64 == object.size)
                    .then_some(bytes)
                    .ok_or_else(|| "cached merge delta object has the wrong size".into());
            }

            let (served_size, bits) = tokio::time::timeout(
                EDX_FETCH_TIMEOUT,
                epix_edx::fetch::fetch_bitfield(&conn, object.id),
            )
            .await
            .map_err(|_| "same-session merge object bitfield timed out".to_string())?
            .map_err(|e| e.to_string())?;
            if served_size != object.size {
                return Err(format!(
                    "merge delta object size mismatch: marker {}, source {served_size}",
                    object.size
                ));
            }

            let _claim = self
                .claim_object(&store, object.id, Ns::Plain, object.size, now)
                .map_err(|e| e.to_string())?;
            let needed = needed_groups(&store, object.id, object.size).map_err(|e| e.to_string())?;
            let mut swarm = Swarm::new(store.clone(), object.id, object.size)
                .with_observer(self.xfer.scope(object.id, address));
            let handle = PeerHandle { conn, class, bits, label: label.clone() };
            let report = swarm
                .fetch(&needed, &[handle], Deadline::tight(), now)
                .await
                .map_err(|e| e.to_string())?;
            self.credit(address, &report, &HashMap::from([(label, node_pk)]), now).await;
            if !store.is_complete(object.id).unwrap_or(false) {
                return Err("merge delta object did not complete".into());
            }
            let bytes = store.read_bytes(object.id, now_secs()).map_err(|e| e.to_string())?;
            (bytes.len() as u64 == object.size)
                .then_some(bytes)
                .ok_or_else(|| "fetched merge delta object has the wrong size".into())
        }
        .await;
        // Failed verified transfers intentionally retain landed groups for a
        // retry, but they are still cache. Drop the in-flight hold first so the
        // configured byte and sparse-reservation quotas can reclaim them.
        drop(object_hold);
        let _ = store.enforce_quota(store_quota());
        result
    }

    /// Pull declared hashed files over the same authenticated connection that
    /// delivered their content.json update. This is the large-payload half of
    /// live publishing: the Update frame stays small, while a movie or other
    /// large object is requested from the known source without a reverse dial.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_files_over_source(
        &self,
        address: &str,
        want: Vec<EdxWant>,
        staged: Option<serde_json::Value>,
        on_file: Option<EdxBatchProgress>,
        conn: Conn,
        class: Class,
        label: String,
        node_pk: Vec<u8>,
    ) -> EdxBatch {
        let mut batch = EdxBatch { done: Vec::new(), missed: Vec::new(), bytes: 0 };
        let Some(store) = self.state.edx_store().await else {
            batch.missed = want.into_iter().map(|w| w.inner_path).collect();
            return batch;
        };
        let now = now_secs();
        let content = match staged {
            Some(content) => Some(content),
            None => self
                .state
                .read_file(address, "content.json")
                .await
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok()),
        };
        let progress = BatchProgress::new(on_file);
        let (plain, shard_paths) = self.resolve_wants(address, want, &content, &mut batch).await;
        let pending =
            self.drain_locally_complete(address, &store, plain, &progress, &mut batch).await;
        // Shard reconstruction has its own multi-holder path. The direct
        // source session applies to normal content-addressed files.
        self.fetch_shard_paths(address, &content, shard_paths, &store, &progress, &mut batch).await;
        if pending.is_empty() {
            return batch;
        }

        let session = Session::source(conn, class, label, node_pk);
        self.fetch_tiers(address, &store, &session, pending, &content, &progress, &mut batch, now)
            .await;
        let _ = store.enforce_quota(store_quota());
        batch
    }
}

struct UpdateFrame<'a> {
    signed: &'a [u8],
    diffs: Vec<(String, Vec<u8>)>,
    inline: InlineMergeWire,
}

fn update_frame<'a>(
    signed: &'a [u8],
    payload: &UpdatePayload,
    inline: InlineMergeWire,
) -> UpdateFrame<'a> {
    let inline_len = inline_merge_wire_len(&inline);
    let candidate_diffs = encode_edx_diffs(&payload.diffs);
    let candidate_len: usize = candidate_diffs
        .iter()
        .map(|(path, bytes)| path.len() + bytes.len() + 16)
        .sum();
    let diffs = if inline_len + candidate_len < UPDATE_FRAME_BUDGET {
        candidate_diffs
    } else {
        Vec::new()
    };
    let diffs_len: usize = diffs
        .iter()
        .map(|(path, bytes)| path.len() + bytes.len() + 16)
        .sum();
    let signed = if signed.len() + inline_len + diffs_len < UPDATE_FRAME_BUDGET {
        signed
    } else {
        &[]
    };
    UpdateFrame {
        signed,
        diffs,
        inline,
    }
}

struct OutboundUpdate<'a> {
    address: &'a str,
    inner_path: &'a str,
    modified: f64,
    sender_peers: Vec<String>,
    frame: UpdateFrame<'a>,
}

/// Closes an Update's source link if its request future is cancelled WHILE
/// the receiver may still pull prepared delta objects back over it. The guard
/// is declared after the prepared object holds, so Rust drops it first: the
/// receiver loses its pull channel before those objects become evictable.
/// Normal Busy, refusal, and success responses disarm it.
///
/// `Conn::shutdown` kills every multiplexed stream on the pooled lane-0 link
/// (concurrent shard swarms, GetSigned, PEX to the same peer), so the guard
/// arms only for updates the receiver must answer with reverse pulls - a
/// legacy peer taking merge deltas as pull-able objects. Inline-only and
/// plain manifest pushes enqueue one complete frame atomically and abandon
/// only the response await, so cancelling them never corrupts the link.
struct UpdateRequestGuard {
    conn: Conn,
    armed: bool,
}

impl UpdateRequestGuard {
    fn new(conn: &Conn, receiver_must_pull: bool) -> Self {
        Self {
            conn: conn.clone(),
            armed: receiver_must_pull,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for UpdateRequestGuard {
    fn drop(&mut self) {
        if self.armed {
            self.conn.shutdown();
        }
    }
}

fn map_update_push_error(error: epix_edx::fetch::PushUpdateError) -> EdxPushError {
    match error {
        epix_edx::fetch::PushUpdateError::Busy {
            message,
            retry_after,
        } => EdxPushError::Busy {
            message,
            retry_after,
        },
        epix_edx::fetch::PushUpdateError::Refused(error) => {
            EdxPushError::Refused(error.to_string())
        }
    }
}

async fn send_update_request(
    conn: &Conn,
    activity: &LinkActivity,
    progress: &epix_ui::state::EdxPushProgress,
    update: OutboundUpdate<'_>,
) -> Result<(), EdxPushError> {
    let mut reverse_events = activity.subscribe();
    let request = epix_edx::fetch::push_update(
        conn,
        update.address,
        update.inner_path,
        update.frame.signed,
        update.modified,
        update.frame.diffs,
        update.sender_peers,
        update.frame.inline,
    );
    tokio::pin!(request);
    let result = tokio::select! {
        result = &mut request => result,
        changed = reverse_events.changed() => {
            if changed.is_ok() {
                progress.active.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            request.await
        }
    };
    result.map_err(map_update_push_error)
}

#[async_trait::async_trait]
impl EdxFetcher for RuntimeEdxFetcher {
    async fn fetch_file(&self, address: &str, inner_path: &str) -> Result<bool, String> {
        // Tight, not background: this is the on-demand path, so something is
        // waiting on these bytes RIGHT NOW - the page the user has open asked
        // for this file. Running it as background bulk meant the visible page
        // queued behind whatever the scheduler was already doing, which is the
        // other half of "the page you are viewing should jump the queue"
        // (the first half is the type ladder in `fetch_tiers`).
        self.fetch_file_at(address, inner_path, Deadline::tight(), None).await
    }

    async fn fetch_file_background(&self, address: &str, inner_path: &str) -> Result<bool, String> {
        // Patient: nothing is waiting, so a slow-but-moving onion transfer
        // should finish rather than be raced and abandoned. This is what the
        // retention completion pass and the optional retry loop use - work
        // that runs behind an already-painted page must never compete at
        // first-paint urgency, nor pay first-paint impatience.
        self.fetch_file_at(address, inner_path, Deadline::background(), None).await
    }

    async fn fetch_file_pooled(
        &self,
        address: &str,
        inner_path: &str,
        fetched: epix_ui::state::EdxFetchedHook,
    ) -> Result<bool, String> {
        // Background patience, plus the slot handoff: `fetched` fires once
        // the object is complete in the store, and the materialize copy
        // then queues on the bounded gate instead of the caller's pool.
        self.fetch_file_at(address, inner_path, Deadline::background(), Some(fetched)).await
    }

    async fn fetch_signed(
        &self,
        peer: PeerAddr,
        address: &str,
        inner_path: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        // Take the peer's link and ask for the signed bytes. No link is Err
        // (peer unreachable - score ConnectFail); a live peer that simply does
        // not serve this content answers with an error we map to Ok(None)
        // (score FileFail), so the caller tries another peer.
        let (conn, _identity, reg, _activity) = self.link(&peer).await?;
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
        on_item: Option<epix_ui::state::EdxSignedProgress>,
    ) -> HashMap<String, Vec<u8>> {
        // Dial the peers ONCE and GetSigned every path over the reused links,
        // so a forum's N user content.json files cost N requests on live
        // connections, not N dials per peer.
        let session = self.open_session(address, &peers, 8).await;
        if session.is_empty() {
            return HashMap::new();
        }
        // First pass: one worker per live link, all pulling from a shared
        // queue, so the requests overlap instead of running down a single link
        // end to end. Serially, a forum's dozen-plus per-user manifests cost a
        // full round trip each - tens of seconds over Tor, minutes when the
        // peers at the front of the list have to time out first - and the whole
        // level had to land before ANY of its posts could be read.
        //
        // The pool is STAFFED AS THE SESSION GROWS (see staff_signed_workers):
        // it starts on the one peer that answered first and adds workers for
        // every link that lands while the queue is still draining, so
        // manifests start arriving immediately and the pass widens instead of
        // waiting to be wide.
        let work = SignedQueue { paths: Arc::new(Mutex::new(paths)), ..Default::default() };
        let mut workers = tokio::task::JoinSet::new();
        let mut staffed = 0usize;
        loop {
            staffed =
                staff_signed_workers(&session, staffed, &mut workers, address, &on_item, &work);
            // Nothing running: either the queue is drained (done) or every
            // link died with work left, in which case a late one can save it.
            if workers.is_empty() {
                let more_to_do = !work.paths.lock().expect("signed queue").is_empty();
                if !more_to_do || !session.grows_past(staffed).await {
                    break;
                }
                continue;
            }
            tokio::select! {
                // A worker finished; loop round to see if any are left.
                _ = workers.join_next() => {}
                // A new peer joined: staff it into the pass in flight.
                grew = session.grows_past(staffed), if session.dialing() => {
                    if !grew {
                        // Dialing is over. Just drain what is running.
                        while workers.join_next().await.is_some() {}
                        break;
                    }
                }
            }
        }

        // Second pass over whatever the first left unserved - a short list by
        // now, and over every link the session ended up with.
        let leftovers = std::mem::take(&mut *work.unserved.lock().expect("signed queue"));
        sweep_signed_over_session(
            &session.peers(),
            address,
            leftovers,
            on_item.as_ref(),
            &work.served,
        )
        .await;
        let served = std::mem::take(&mut *work.served.lock().expect("signed queue"));
        served
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
        let end = start.saturating_add(len).min(size);
        if end <= start {
            return Ok(Some(Vec::new()));
        }
        let served = start..end;

        // Warm the moov head/tail once on the first touch of a large file, so
        // the browser's metadata tail-fetch does not stall the start. Pure
        // background; failures never reach this response.
        self.maybe_warm_moov(address, inner_path, id, size);

        // Full-file download is the default goal for a large media file: keep
        // the whole-object background pull running while this serve and the
        // read-ahead race ahead of it at streaming deadlines. Pure background;
        // failures never reach this response (see `maybe_complete_file`).
        self.maybe_complete_file(address, inner_path, id, size, &store);

        // Serve straight from the store if the covering range is already
        // present; otherwise fetch just the covering chunk groups the store
        // still lacks (a seek fetches on demand - the whole file is the
        // background completion's job above, never this foreground fetch's -
        // and never a group we already hold). A fetch that fell short serves
        // the contiguous prefix that DID land as a shorter range - the
        // browser re-requests the remainder - instead of failing bytes we
        // hold. That includes the case where no peer is currently dialable
        // at all: a dial or claim failure must not fail bytes a previous
        // (partial) fetch already committed, so the prefix check runs even
        // when the fetch could not. Read-ahead below is a pure background
        // addition.
        let bytes = if let Ok(bytes) = store.read_range(id, start, end - start, now) {
            // Whole window already held: the network was not on the critical
            // path for these bytes, which is exactly what a healthy read-ahead
            // looks like from the player's side.
            self.xfer.note_serve(
                id, address, inner_path, size, now, (start, end), bytes.len() as u64, true,
            );
            bytes
        } else {
            // The player is blocked on these bytes and they must come off the
            // network: keep the background completion out of the way for the
            // duration (dropped at the end of this branch).
            let _fg = self.note_foreground_fetch();
            let present = store.present_bits(id).unwrap_or_default();
            let needed = missing_groups(&present, &served);
            let mut fetch_err: Option<String> = None;
            if !needed.is_empty() {
                fetch_err = self.fetch_missing(address, &store, id, size, &needed, now).await;
            }
            let present = store.present_bits(id).unwrap_or_default();
            let mut got = present_prefix_len(&present, &served, size);
            // Nothing servable means the group at the START of the window is
            // the one outstanding: the rest of this path can serve a short
            // prefix, but a zero-length answer has nowhere to go but an error,
            // and an error mid-playback tears the stream down. The group
            // blocking the prefix is worth a second, narrower attempt on its
            // own - the first pass asked for the whole window, so it competed
            // with groups the player does not need yet, and read-ahead or a
            // peer discovered since may have landed it already.
            if got == 0 {
                got = self.retry_prefix_head(address, &store, id, size, &served, now).await;
            }
            if got == 0 {
                let e = fetch_err
                    .unwrap_or_else(|| "no bytes of the requested range are available".into());
                // Only the transfer pane used to hear about this, so a stall
                // that ended a playback left no trace in the log at all.
                self.state
                    .log(
                        "WARN",
                        format!("EDX range {start}-{end} of {inner_path} unavailable: {e}"),
                    )
                    .await;
                self.xfer.note_serve(id, address, inner_path, size, now, (start, end), 0, false);
                self.xfer.note_error(id, address, now, &e);
                return Err(e);
            }
            let bytes = match store.read_range(id, start, got, now) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // The bits said these groups are present and the read
                    // still failed: the record and the disk disagree. For an
                    // extern object that is a deleted/altered xite file; for
                    // a sparse one, a file lost to a crash. Either way the
                    // next request must not hit the same wall - revalidate
                    // shrinks or retires the record so it refetches. In the
                    // background: it can re-hash a whole file, and this
                    // response is already an error.
                    let vstore = store.clone();
                    tokio::task::spawn_blocking(move || {
                        let _ = vstore.revalidate(id);
                    });
                    self.xfer.note_error(id, address, now, &e.to_string());
                    return Err(e.to_string());
                }
            };
            self.xfer.note_serve(
                id, address, inner_path, size, now, (start, end), bytes.len() as u64, false,
            );
            let _ = store.enforce_quota(store_quota());
            bytes
        };

        // The last group of a streamed file just landed: hand the bytes over
        // to the xite tree so what the user watched is now a file they have.
        // Background, and it can never error into this response - the bytes
        // above are already served either way.
        self.maybe_materialize_complete(address, inner_path, id, size, &store).await;

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
        payload: Arc<UpdatePayload>,
        sender_peers: Arc<Vec<String>>,
        progress: Arc<epix_ui::state::EdxPushProgress>,
    ) -> Result<bool, EdxPushError> {
        let (conn, identity, reg, activity) =
            self.link(&peer).await.map_err(EdxPushError::Unreachable)?;
        progress
            .linked
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let supports_inline = caps::supports(identity.caps, caps::INLINE_MERGE);
        if !payload.merge_objects.is_empty() {
            return Err(EdxPushError::Refused(
                "outbound update contains unresolved merge object references".into(),
            ));
        }
        let candidate_inline = self.inline_merge_candidate(&payload)?;
        let delta_store = if supports_inline && candidate_inline.is_none() {
            Some(
                self.state
                    .edx_store()
                    .await
                    .ok_or_else(|| EdxPushError::Refused("no EDX store for merge delta".into()))?,
            )
        } else {
            None
        };
        let has_objects = payload
            .merge_deltas
            .values()
            .any(|records| !records.is_empty());
        let prepared = match delta_store.as_ref() {
            Some(store) => {
                let quota = has_objects.then(|| self.merge_quota_lease(store, &payload));
                Some(
                    self.prepare_merge_delta_objects(store, payload.clone(), quota)
                        .await
                        .map_err(EdxPushError::Refused)?,
                )
            }
            None => None,
        };
        let empty_objects = HashMap::new();
        let delta_objects = prepared
            .as_ref()
            .map_or(&empty_objects, |prepared| &prepared.objects);
        let wire_inline = select_update_merge_wire(
            supports_inline,
            candidate_inline,
            &payload.merge_deltas,
            delta_objects,
        )
        .map_err(EdxPushError::Refused)?;
        // A legacy (non-inline) receiver answers a delta-carrying Update by
        // pulling the prepared objects back over this link; only that case
        // needs the cancellation teardown.
        let receiver_must_pull = !delta_objects.is_empty() && wire_inline.is_empty();
        let frame = update_frame(signed.as_slice(), &payload, wire_inline);
        reg.note_cmd_sent("Update", Some(address));
        let request_guard = UpdateRequestGuard::new(&conn, receiver_must_pull);
        let pushed = send_update_request(
            &conn,
            &activity,
            &progress,
            OutboundUpdate {
                address,
                inner_path,
                modified,
                sender_peers: sender_peers.as_ref().clone(),
                frame,
            },
        )
        .await;
        request_guard.disarm();
        // PreparedMergeObjects drops Store holds before the final shared quota
        // lease, including when this future is cancelled or returns an error.
        drop(prepared);
        pushed?;
        // A capable receiver answers only after inline records or the verified
        // immutable delta object have been authorized, unioned, and written.
        // Legacy empty markers retain the full-file same-session fallback.
        Ok(payload.merge_deltas.is_empty() || supports_inline)
    }

    async fn fetch_files(
        &self,
        address: &str,
        want: Vec<EdxWant>,
        peers: Vec<PeerAddr>,
        staged: Option<serde_json::Value>,
        on_file: Option<EdxBatchProgress>,
    ) -> EdxBatch {
        let mut batch = EdxBatch {
            done: Vec::new(),
            missed: Vec::new(),
            bytes: 0,
        };
        let Some(store) = self.state.edx_store().await else {
            // No store: nothing can be fetched, so every file is missed.
            batch.missed = want.into_iter().map(|w| w.inner_path).collect();
            return batch;
        };
        let now = now_secs();
        // The content.json this pass reads for shard/salt detection and for the
        // order policy. The caller's staged copy wins: a fresh clone holds the
        // verified root in memory for the whole download and commits it only at
        // the end, so reading disk here would find nothing and drop every file
        // into one untiered batch - first paint last.
        let content = match staged {
            Some(c) => Some(c),
            None => self
                .state
                .read_file(address, "content.json")
                .await
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()),
        };

        let progress = BatchProgress::new(on_file);
        let (plain, shard_paths) = self
            .resolve_wants(address, want, &content, &mut batch)
            .await;
        let pending = self
            .drain_locally_complete(address, &store, plain, &progress, &mut batch)
            .await;
        self.fetch_shard_paths(
            address,
            &content,
            shard_paths,
            &store,
            &progress,
            &mut batch,
        )
        .await;

        if pending.is_empty() {
            return batch;
        }

        // Dial the peers ONCE, then fetch every remaining file over the reused
        // links. A file no session peer holds (or that the swarm can't
        // complete) goes to `missed` for the worker.
        let session = self.open_session(address, &peers, 8).await;
        if session.is_empty() {
            // This was silent, and a whole failed clone looked identical to
            // one that never tried the network. Say what happened.
            self.state
                .log(
                    "DEBUG",
                    format!(
                        "EDX {address}: no session peer answered ({} candidate(s)); \
                         {} file(s) to the worker",
                        peers.len(),
                        pending.len()
                    ),
                )
                .await;
            for r in pending {
                epix_ui::state::note_edx_fallback_path(address, &r.path);
                batch.missed.push(r.path);
            }
            return batch;
        }

        self.fetch_tiers(
            address, &store, &session, pending, &content, &progress, &mut batch, now,
        )
        .await;
        if !batch.missed.is_empty() {
            // Name the session that failed: without this a fetch that landed
            // nothing from N live links was indistinguishable from an empty
            // session or an unresolvable manifest.
            self.state
                .log(
                    "DEBUG",
                    format!(
                        "EDX {address}: {} file(s) missed over {} session peer(s)",
                        batch.missed.len(),
                        session.peers().len()
                    ),
                )
                .await;
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
        let (conn, _identity, reg, _activity) = self.link(&peer).await?;
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

    async fn transfer_stats(
        &self,
        address: &str,
        inner_path: &str,
        offset: Option<u64>,
    ) -> serde_json::Value {
        let Ok(Some((id, size))) = self.resolve(address, inner_path).await else {
            return serde_json::Value::Null;
        };
        // What the store holds: in total, and - the number that actually
        // explains a stall - contiguously past the read position. That
        // position is where the last serve ended unless the caller names its
        // own (a seek preview, say); the node's own frontier is exact, where
        // a caller can only estimate it from playback time.
        let head = offset.or_else(|| self.xfer.read_head(id));
        let (have, ahead) = match self.state.edx_store().await {
            Some(store) => match store.present_bits(id) {
                Ok(bits) => (
                    Some(crate::xfer::have_bytes(&bits, size)),
                    head.map(|o| crate::xfer::contiguous_from(&bits, size, o)),
                ),
                Err(_) => (None, None),
            },
            None => (None, None),
        };
        let mut out = self.xfer.snapshot(id, now_secs(), have);
        if let (Some(obj), Some(ahead)) = (out.as_object_mut(), ahead) {
            obj.insert("have_ahead".into(), serde_json::json!(ahead));
        }
        out
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
        // Shares the pool: a peer the warm pool holds open is the same link a
        // fetch or a control RPC uses, instead of a second one beside it.
        let (conn, identity, reg, _activity) = self.link(&peer).await?;
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
    // The xite tree is where a completed object's bytes actually live (see
    // `Loc::Extern`), so the store needs to know where that tree is before
    // it can adopt or materialize anything.
    let cfg = epix_blob::store::StoreConfig {
        xite_root: Some(data_dir.join("data")),
        ..Default::default()
    };
    let store = match Store::open_with(&path, cfg) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            state.log("WARN", format!("EDX store open {}: {e}", path.display())).await;
            return None;
        }
    };
    let tally = match state.set_edx_store(store.clone()).await {
        Ok(tally) => tally,
        Err(error) => {
            state
                .log("WARN", format!("EDX Store activation failed: {error}"))
                .await;
            return None;
        }
    };
    let fetcher = Arc::new(RuntimeEdxFetcher::new(state.clone(), privatekey, choker));
    state.set_edx_fetcher(fetcher.clone()).await;
    // Same object behind both seams: the warm pool needs only a ping, so it
    // takes the narrow one.
    state.set_link_opener(fetcher).await;
    state.log("INFO", format!("EDX object store enabled: registered {tally}")).await;
    Some(store)
}

/// Hold our responsible shards of every private file every served xite
/// declares. This is what makes the volunteer role actually run: the
/// machinery underneath it (self-encryption, the responsibility predicate,
/// the donated-byte budget) has been in place for a while with nothing
/// driving it, so no node ever held a shard.
///
/// Driven off the resync tick rather than a content-update hook because it
/// has to cover the xites a node ALREADY had when the user turned
/// volunteering on, not only the ones whose manifests arrive afterwards.
/// Every gate lives in [`RuntimeEdxFetcher::volunteer_hold_file`], so a node
/// with `volunteer_quota_bytes` at 0 does nothing here beyond the walk.
///
/// The publisher side needs no separate push: signing already inserts an
/// owner's own shards into `Ns::Shard`, and content.json reaches peers
/// through ordinary propagation, so a fresh publish becomes holdable by
/// volunteers as soon as they see the manifest.
/// Per shard-file backoff for [`volunteer_sweep`]: how many consecutive
/// unproductive passes a file has had, and when it is worth trying again.
/// Owned by the resync loop (the sweep's only caller), so it needs no home
/// in AppState and dies with the loop.
#[derive(Clone, Copy, Debug, Default)]
pub struct VolunteerBackoff {
    /// `now_secs` before which the file is skipped.
    next_try: u64,
    /// Consecutive passes that held nothing new.
    streak: u32,
}

/// When to retry after `streak` unproductive passes: one skipped tick per
/// doubling, capped at an hour. A pass that holds nothing usually means
/// either "nothing missing" (a no-op we can cheaply not repeat) or "no
/// reachable peer had the shards" - and redialing up to 8 peers for the
/// same missing shards every 5-minute tick, forever, is exactly the kind
/// of circuit churn Tor punishes. The cap keeps a config change (a raised
/// quota widens responsibility) effective within the hour.
fn volunteer_retry_delay(streak: u32) -> u64 {
    const BASE: u64 = 600; // 10 min: skip at least the next tick
    const CAP: u64 = 3600;
    (BASE << streak.saturating_sub(1).min(3)).min(CAP)
}

pub async fn volunteer_sweep(
    state: &Arc<AppState>,
    backoff: &mut std::collections::HashMap<(String, String), VolunteerBackoff>,
) {
    if state.volunteer_quota_bytes().await == 0 {
        return; // not volunteering
    }
    let files = state.shard_files().await;
    // Drop backoff rows for files no manifest declares any more (a removed
    // or re-signed xite), or the map grows for the life of the process.
    let live: std::collections::HashSet<&(String, String)> = files.iter().collect();
    backoff.retain(|k, _| live.contains(k));
    let now = now_secs();
    let mut held = 0usize;
    for key in files {
        if backoff.get(&key).is_some_and(|b| now < b.next_try) {
            continue;
        }
        let (address, inner_path) = &key;
        let n = match volunteer_hold(state, address, inner_path).await {
            Ok(n) => n,
            // A xite whose peers are all offline right now is not an error,
            // but it earns the same backoff as an empty pass.
            Err(_) => 0,
        };
        if n > 0 {
            held += n;
            backoff.remove(&key);
        } else {
            let b = backoff.entry(key).or_default();
            b.streak = b.streak.saturating_add(1);
            b.next_try = now.saturating_add(volunteer_retry_delay(b.streak));
        }
    }
    if held > 0 {
        state
            .log("INFO", format!("Volunteer cache: holding {held} new encrypted shard(s)"))
            .await;
    }
}

/// Hold this node's responsible encrypted shards of `address`/`inner_path`,
/// read from its already-verified signed content.json. Returns the number of
/// shards newly held, or 0 when the node is not volunteering
/// (`volunteer_quota_bytes` = 0) or the path is not a shard file.
///
/// The node's persisted identity key backs the responsibility predicate, so
/// the node holds the same slice of the keyspace across restarts.
pub async fn volunteer_hold(
    state: &Arc<AppState>,
    address: &str,
    inner_path: &str,
) -> Result<usize, String> {
    let store = state.edx_store().await.ok_or("no EDX store")?;
    let content_bytes =
        state.read_file(address, "content.json").await.ok_or("no content.json")?;
    let content: serde_json::Value =
        serde_json::from_slice(&content_bytes).map_err(|e| e.to_string())?;
    let Some(shard) = epix_blob::manifest::edx_shard_entry(&content, inner_path) else {
        return Ok(0); // not a private/shard file
    };
    let key = node_key(state).await;
    let fetcher = RuntimeEdxFetcher::new(state.clone(), key, make_choker());
    fetcher.volunteer_hold_file(address, &shard, &store).await
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

    fn disconnected_update_source() -> UpdateSource {
        let (local, remote) = tokio::io::duplex(64);
        let (conn, _incoming) = Conn::start(Box::pin(local), true);
        drop(remote);
        UpdateSource {
            conn,
            identity: PeerIdentity {
                node_pk: vec![9; 33],
                address: "test-source".into(),
                caps: caps::INLINE_MERGE,
                version: "test".into(),
            },
            reach: Reach::Clearnet,
        }
    }

    /// The foreground guards drive the process-wide LEDBAT flag: any live
    /// guard holds it up, and the last drop clears it. Asserted relatively
    /// where it must be (other tests in this binary can hold their own
    /// guards concurrently).
    #[tokio::test]
    async fn foreground_fetch_guards_flip_the_shared_yield_flag() {
        use std::sync::atomic::Ordering;
        let state = epix_ui::state::AppState::new("test");
        let fetcher = RuntimeEdxFetcher::new(state, String::new(), None);
        let flag = edx_foreground_flag();
        let a = fetcher.note_foreground_fetch();
        let b = fetcher.note_foreground_fetch();
        assert!(flag.load(Ordering::Relaxed), "a live guard holds the flag up");
        drop(a);
        assert!(flag.load(Ordering::Relaxed), "one guard still in flight");
        drop(b);
        // Our own drops must never leave the flag stuck; only meaningful
        // when no other test currently holds a guard.
        if FOREGROUND_FETCHES.load(Ordering::Relaxed) == 0 {
            assert!(!flag.load(Ordering::Relaxed), "the last drop clears the flag");
        }
    }

    #[test]
    fn short_lived_fetchers_share_store_fetch_guards() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let ordinary = store_fetch_shared(&store);
        let same_session = store_fetch_shared(&store);

        assert!(
            Arc::ptr_eq(&ordinary, &same_session),
            "ordinary and same-session fetchers must coordinate claims for one Store"
        );
        assert!(Arc::ptr_eq(&ordinary.claims, &same_session.claims));
        assert!(Arc::ptr_eq(
            &ordinary.materialize_gate,
            &same_session.materialize_gate
        ));
    }

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

    /// An unproductive volunteer pass skips at least the next 5-minute tick
    /// and backs off doubling to an hour, so shards nobody reachable holds
    /// stop re-dialing 8 peers every tick - while a raised quota still
    /// widens responsibility within the hour.
    #[test]
    fn volunteer_backoff_doubles_to_an_hour() {
        assert_eq!(volunteer_retry_delay(1), 600);
        assert_eq!(volunteer_retry_delay(2), 1200);
        assert_eq!(volunteer_retry_delay(3), 2400);
        assert_eq!(volunteer_retry_delay(4), 3600, "capped");
        assert_eq!(volunteer_retry_delay(30), 3600, "a long streak never overflows");
    }

    /// GetSigned serves signed content only: the content.json files and the
    /// merge files a xite declares. A peer naming a hosted media file, a
    /// traversal path or an absolute path gets nothing, so it cannot pick the
    /// size of the buffer we allocate for it.
    #[tokio::test]
    async fn get_signed_serves_only_signed_paths() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let child_path = "data/users/alice/content.json";
        let mut root = serde_json::json!({
            "address": address,
            "modified": 1.0,
            "files": {},
            "files_merged": { "data/posts.json": { "class": "epix-orset-1" } },
            "includes": {
                (child_path): {
                    "merge_files": {
                        "posts.json": { "class": "epix-orset-1", "max_size": 100_000 }
                    }
                }
            },
        });
        epix_content::sign(&mut root, &key).unwrap();
        let content = serde_json::to_vec(&root).unwrap();
        let mut child = serde_json::json!({
            "address": address,
            "inner_path": child_path,
            "modified": 1.0,
            "files": {},
        });
        epix_content::sign(&mut child, &key).unwrap();
        let child_bytes = serde_json::to_vec(&child).unwrap();
        let posts = serde_json::to_vec(&epix_content::make_container(Vec::new())).unwrap();
        storage.write("content.json", &content).unwrap();
        storage.write(child_path, &child_bytes).unwrap();
        storage.write("data/posts.json", &posts).unwrap();
        storage.write("movie.bin", &vec![7u8; 64 * 1024]).unwrap();
        // Really on disk, so refusing it can only come from the segment-form
        // check - not from an ENOENT that would refuse it either way.
        storage.write("evilcontent.json", b"leak").unwrap();

        let state = AppState::new("provider");
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root),
                },
            )
            .await;
        let p = AppStateProvider { state };

        assert_eq!(p.get_signed(&address, "content.json").await, Some(content));
        assert_eq!(
            p.get_signed(&address, child_path).await,
            Some(child_bytes),
            "a child content.json is signed content too"
        );
        assert_eq!(
            p.get_signed(&address, "data/posts.json").await,
            Some(posts),
            "a declared merge file still propagates"
        );
        assert!(p.get_signed(&address, "movie.bin").await.is_none(), "hosted media is not signed");
        assert!(p.get_signed(&address, "../content.json").await.is_none(), "no traversal");
        assert!(p.get_signed(&address, "/etc/passwd").await.is_none(), "no absolute path");
        assert!(
            p.get_signed(&address, "evilcontent.json").await.is_none(),
            "a file that merely ENDS in content.json is not signed content"
        );
    }

    #[tokio::test]
    async fn signed_provider_excludes_a_revoked_stale_child_from_get_list_and_summary() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let child_path = "data/users/alice/content.json";
        let merge_path = "data/users/alice/posts.json";
        let mut root_v1 = serde_json::json!({
            "address": address,
            "modified": 1.0,
            "files": {},
            "includes": {
                (child_path): {
                    "merge_files": {
                        "posts.json": { "class": "epix-orset-1", "max_size": 100_000 }
                    }
                }
            },
        });
        epix_content::sign(&mut root_v1, &key).unwrap();
        let mut child = serde_json::json!({
            "address": address,
            "inner_path": child_path,
            "modified": 2.0,
            "files": {},
            "files_merged": { "posts.json": { "class": "epix-orset-1" } },
        });
        epix_content::sign(&mut child, &key).unwrap();
        let child_bytes = serde_json::to_vec(&child).unwrap();
        let merge_bytes = serde_json::to_vec(&epix_content::make_container(Vec::new())).unwrap();
        storage
            .write("content.json", &serde_json::to_vec(&root_v1).unwrap())
            .unwrap();
        storage.write(child_path, &child_bytes).unwrap();
        storage.write(merge_path, &merge_bytes).unwrap();

        let state = AppState::new("provider");
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root_v1),
                },
            )
            .await;
        let provider = AppStateProvider { state: state.clone() };
        assert_eq!(provider.get_signed(&address, child_path).await, Some(child_bytes));
        assert_eq!(provider.get_signed(&address, merge_path).await, Some(merge_bytes));
        assert!(provider
            .list_signed(&address, 0)
            .await
            .iter()
            .any(|(path, _, _)| path == child_path));

        let mut root_v2 = serde_json::json!({
            "address": address,
            "modified": 3.0,
            "files": {},
        });
        epix_content::sign(&mut root_v2, &key).unwrap();
        storage
            .write("content.json", &serde_json::to_vec(&root_v2).unwrap())
            .unwrap();
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root_v2),
                },
            )
            .await;
        assert!(storage.exists(child_path));

        assert!(provider.get_signed(&address, child_path).await.is_none());
        assert!(provider.get_signed(&address, merge_path).await.is_none());
        let listed = provider.list_signed(&address, 0).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "content.json");
        assert_eq!(provider.xite_summary(&address).await.map(|summary| summary.0), Some(1));
    }

    /// A peer-supplied inner_path is bounded in length AND depth before it can
    /// reach the merge-file check, which walks the path one segment at a time
    /// with a filesystem read per segment. One frame carries ~64 KB, so without
    /// the bound a single request buys thousands of `open()` calls and
    /// quadratic byte copying on a runtime worker.
    #[test]
    fn safe_inner_path_bounds_length_and_depth() {
        assert!(safe_inner_path("content.json"));
        assert!(safe_inner_path("data/users/alice/data.json"), "a real inner_path still passes");
        assert!(
            !safe_inner_path(&vec!["a"; MAX_INNER_PATH_SEGMENTS + 1].join("/")),
            "one segment past the depth cap is refused"
        );
        assert!(
            !safe_inner_path(&format!("{}/f.json", "x".repeat(MAX_INNER_PATH_BYTES))),
            "past the byte cap is refused"
        );
        assert!(!safe_inner_path(&"a/".repeat(32_000)), "a frame-sized path is refused");
        assert!(!safe_inner_path("../content.json"), "no traversal");
        assert!(!safe_inner_path("/etc/passwd"), "no absolute path");
    }

    /// A signed body past the cap is refused instead of being read whole into
    /// memory.
    #[tokio::test]
    async fn get_signed_refuses_a_body_past_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let mut root = serde_json::json!({
            "address": address,
            "modified": 1.0,
            "files": {},
            "padding": "x".repeat(MAX_SIGNED_BYTES as usize + 1),
        });
        epix_content::sign(&mut root, &key).unwrap();
        let body = serde_json::to_vec(&root).unwrap();
        assert!(body.len() as u64 > MAX_SIGNED_BYTES);
        storage.write("content.json", &body).unwrap();
        let state = AppState::new("provider");
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root),
                },
            )
            .await;
        let p = AppStateProvider { state };
        assert!(p.get_signed(&address, "content.json").await.is_none(), "over the cap: refused");
    }

    /// The serve cap must not sit below the client's reassembly cap (8 MiB in
    /// `epix_edx::fetch`). A body between the two is something every peer would
    /// accept and nobody would serve, so `edx_fetch_signed` fails on every peer
    /// and the xite becomes uncloneable over EDX - the exact failure
    /// `serve_signed`'s frame chunking exists to avoid.
    #[tokio::test]
    async fn get_signed_serves_a_body_the_client_would_still_accept() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let mut root = serde_json::json!({
            "address": address,
            "modified": 1.0,
            "files": {},
            "padding": "x".repeat(5 * 1024 * 1024),
        });
        epix_content::sign(&mut root, &key).unwrap();
        let body = serde_json::to_vec(&root).unwrap();
        assert!(body.len() as u64 <= MAX_SIGNED_BYTES);
        storage.write("content.json", &body).unwrap();
        let state = AppState::new("provider");
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage: storage.clone(),
                    content: Some(root),
                },
            )
            .await;
        let p = AppStateProvider { state };
        assert_eq!(
            p.get_signed(&address, "content.json").await.map(|b| b.len()),
            Some(body.len()),
            "a 5 MiB content.json is under the client's cap, so it must be servable"
        );
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
            _: UpdateSource,
        ) -> Result<bool, String> {
            Ok(true)
        }
    }

    /// An object store that knows which xite tree its objects live in.
    ///
    /// A store adopts big files where they lie and materializes downloads
    /// into the tree rather than keeping a second copy, so it has to be told
    /// the tree's root. Production wires this in [`enable_serving`]
    /// (`<data_dir>/data`); tests put the store and the xite in unrelated
    /// temp dirs, so they say it explicitly. A store built without one still
    /// works for everything else - it just has no extern objects (see
    /// `StoreConfig::xite_root`), which is why the bare `Store::open` calls
    /// below, for clients that only receive slices, are left alone.
    fn test_store(store_dir: &std::path::Path, xite_root: &std::path::Path) -> Store {
        Store::open_with(
            store_dir,
            epix_blob::store::StoreConfig {
                xite_root: Some(xite_root.to_path_buf()),
                ..Default::default()
            },
        )
        .unwrap()
    }

    /// EpixNet-style signed authority chain for a user_contents tree: a
    /// signed `data/users/content.json` parent carrying `user_contents`, and
    /// a signed root content.json declaring that parent under `includes`.
    /// Serving and inbound-update application only trust manifests whose
    /// full authority chain verifies (root -> parent -> per-user child), so
    /// every test tree needs these two signed manifests even when the test
    /// only cares about the per-user child. Returns (parent_bytes,
    /// root_bytes, root_value).
    fn signed_user_chain(
        xite_addr: &str,
        xite_pk: &str,
        user_contents: serde_json::Value,
    ) -> (Vec<u8>, Vec<u8>, serde_json::Value) {
        let mut parent = serde_json::json!({
            "address": xite_addr,
            "inner_path": "data/users/content.json",
            "modified": 1000,
            "files": {},
            "user_contents": user_contents,
        });
        epix_content::sign(&mut parent, xite_pk).unwrap();
        let mut root = serde_json::json!({
            "address": xite_addr,
            "inner_path": "content.json",
            "modified": 1000,
            "files": {},
            "includes": { "data/users/content.json": { "signers": [] } },
        });
        epix_content::sign(&mut root, xite_pk).unwrap();
        (
            serde_json::to_vec(&parent).unwrap(),
            serde_json::to_vec(&root).unwrap(),
            root,
        )
    }

    #[tokio::test]
    async fn enable_serving_quarantines_a_corrupt_loaded_root() {
        let data_dir = tempfile::tempdir().unwrap();
        let privatekey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privatekey).unwrap();
        let xite_dir = data_dir.path().join("data").join(&address);
        let storage = XiteStorage::new(&xite_dir);
        storage.write("content.json", b"not signed json").unwrap();

        let state = AppState::new("corrupt-store-barrier");
        state
            .add_xite(&address, XiteEntry { storage, content: None })
            .await;
        assert!(state.edx_store().await.is_none());
        assert!(state.link_opener().await.is_none());

        let enabled = enable_serving(&state, data_dir.path(), privatekey, None).await;

        // One unverifiable xite is quarantined; it must not take EDX
        // activation (and with it every other xite's serving and all local
        // mutation) down with it.
        assert!(enabled.is_some(), "a corrupt loaded root must be quarantined, not fatal");
        assert!(state.edx_store().await.is_some(), "the Store was not exposed");
        assert!(
            state.link_opener().await.is_some(),
            "fetch/link hooks were not installed after quarantined activation"
        );
    }

    /// Bring up a seeder node serving an EDX xite (index.html + a 400 KB
    /// movie.bin) on a real TCP port. Returns its address, the signed
    /// content.json bytes + value, the movie bytes, and the socket address.
    async fn spawn_seeder(
    ) -> (String, Vec<u8>, serde_json::Value, Vec<u8>, std::net::SocketAddr, Vec<u8>) {
        spawn_seeder_declaring(serde_json::json!({})).await
    }

    /// [`spawn_seeder`], but the owner signs `extra` into content.json first
    /// (`sign` preserves unknown fields), so a test can ship an owner-signed
    /// `order_policy` the way a real xite does.
    async fn spawn_seeder_declaring(
        extra: serde_json::Value,
    ) -> (String, Vec<u8>, serde_json::Value, Vec<u8>, std::net::SocketAddr, Vec<u8>) {
        spawn_seeder_sized(extra, 400_000).await
    }

    /// [`spawn_seeder_declaring`], but with a movie of `movie_len` bytes, so a
    /// test can cross the size gates (MOOV_MIN_SIZE) that a 400 KB file stays
    /// under.
    async fn spawn_seeder_sized(
        extra: serde_json::Value,
        movie_len: usize,
    ) -> (String, Vec<u8>, serde_json::Value, Vec<u8>, std::net::SocketAddr, Vec<u8>) {
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(xite_dir.path());
        storage.write("index.html", &vec![b'h'; 5_000]).unwrap();
        let movie: Vec<u8> = (0..movie_len).map(|i| (i % 251) as u8).collect();
        storage.write("movie.bin", &movie).unwrap();
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        xite.content = Some(extra);
        xite.sign(&privkey, 1000.0).unwrap();
        let content_bytes = xite.storage.read("content.json").unwrap();
        let content: serde_json::Value = serde_json::from_slice(&content_bytes).unwrap();

        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await, "load registers files into the store");
        std::mem::forget(xite_dir); // keep the on-disk files for the test's life
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
                false,
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

    /// Serving over EDX credits the seeder's upload counters through the
    /// serve hook: the xite's `bytes_sent` and the per-optional-file
    /// `uploaded` both move. They froze at 0 when the msgpack file-serve
    /// layer - `record_upload`'s only caller - was deleted.
    #[tokio::test]
    async fn serving_over_edx_credits_upload_counters() {
        // A signed xite whose movie.bin is OPTIONAL, so the per-file
        // uploaded counter applies to it.
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(xite_dir.path());
        storage.write("index.html", &vec![b'h'; 5_000]).unwrap();
        let movie: Vec<u8> = (0..400_000usize).map(|i| (i % 251) as u8).collect();
        storage.write("movie.bin", &movie).unwrap();
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        xite.content = Some(serde_json::json!({ "optional": "movie\\.bin" }));
        xite.sign(&privkey, 1000.0).unwrap();
        let content: serde_json::Value =
            serde_json::from_slice(&xite.storage.read("content.json").unwrap()).unwrap();

        let state_b = AppState::new("uploader");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await, "load registers the files");
        std::mem::forget(xite_dir);
        std::mem::forget(store_dir);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state_b.clone(),
            store_b,
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // A peer pulls the whole optional file over EDX.
        let stream = TcpTransport.dial(&epix_core::PeerAddr::Ip(addr)).await.unwrap();
        let l = epix_edx::link::dial(stream).await.unwrap();
        let cdir = tempfile::tempdir().unwrap();
        let cstore = Arc::new(Store::open(cdir.path()).unwrap());
        let cctx = ServeCtx {
            now: || 0,
            ..ServeCtx::new(cstore.clone(), Arc::new(NoProvider), epix_crypt::new_seed())
        };
        client_hello(&l.conn, &cctx, vec![], Some(l.handshake_hash)).await.unwrap();
        let e = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap();
        let size = movie.len() as u64;
        cstore.ensure_sparse(e.b3, Ns::Plain, size, 1).unwrap();
        epix_edx::fetch::fetch_ranges(&l.conn, &cstore, e.b3, size, &[0..size], 100, 2)
            .await
            .unwrap();

        // The hook credits asynchronously (a spawned task per serve); wait
        // for the full transfer to land rather than racing it. Each credit
        // bumps bytes_sent before the per-file counter, so polling the
        // per-file counter to `size` proves both.
        let per_file = || async {
            state_b
                .optional_file_list(&address, "all", "", 0)
                .await
                .unwrap()
                .iter()
                .find(|f| f["inner_path"] == "movie.bin")
                .and_then(|f| f["uploaded"].as_i64())
                .unwrap_or(0)
        };
        let mut uploaded = 0i64;
        for _ in 0..100 {
            uploaded = per_file().await;
            if uploaded >= size as i64 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(uploaded >= size as i64, "per-file uploaded credited, got {uploaded}");
        let sent = state_b.transfer(&address).await.1;
        assert!(sent >= size, "bytes_sent credited with the served bytes, got {sent}");
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
        let a_store = Arc::new(test_store(a_store_dir.path(), a_dir.path()));
        state_a.set_edx_store(a_store).await.unwrap();
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
        let result = state_a.edx_fetch_file(&address, "movie.bin", false).await;
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
        state_a
            .set_edx_store(Arc::new(test_store(a_store_dir.path(), a_dir.path())))
            .await
            .unwrap();
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
        let batch = state_a.edx_fetch_files(&address, want, peers, None, None).await.unwrap();

        assert!(batch.done.contains(&"index.html".to_string()));
        assert!(batch.done.contains(&"movie.bin".to_string()));
        assert_eq!(batch.missed, vec!["not-declared.bin".to_string()], "undeclared file falls back");
        assert!(batch.bytes >= movie.len() as u64);

        // Both declared files verified onto disk over the one session.
        assert_eq!(XiteStorage::new(a_dir.path()).read("movie.bin").unwrap(), movie);
        assert_eq!(XiteStorage::new(a_dir.path()).read("index.html").unwrap().len(), 5_000);
    }

    /// Stand up a client node against `addr` holding only the signed manifest.
    async fn client_for(
        address: &str,
        content_bytes: &[u8],
        content: &serde_json::Value,
        addr: std::net::SocketAddr,
    ) -> (Arc<AppState>, tempfile::TempDir) {
        let state = AppState::new("node-a");
        let dir = tempfile::tempdir().unwrap();
        XiteStorage::new(dir.path()).write("content.json", content_bytes).unwrap();
        state
            .add_xite(
                address,
                XiteEntry {
                    storage: XiteStorage::new(dir.path()),
                    content: Some(content.clone()),
                },
            )
            .await;
        state.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let store_dir = tempfile::tempdir().unwrap();
        state
            .set_edx_store(Arc::new(test_store(store_dir.path(), dir.path())))
            .await
            .unwrap();
        std::mem::forget(store_dir);
        state
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        state.add_peers(address, [epix_core::PeerAddr::Ip(addr)]).await;
        (state, dir)
    }

    /// The user deletes a materialized file. The extern record then claims
    /// bytes no file backs; a fetch must notice, retire, and REFETCH -
    /// not report success forever with nothing on disk (the eternal
    /// "complete but fileless" loop this regression pins).
    #[tokio::test]
    async fn a_deleted_materialized_file_is_retired_and_refetched() {
        let (address, cb, content, movie, addr, _pk) = spawn_seeder().await;
        let (state, dir) = client_for(&address, &cb, &content, addr).await;

        // Whole-file fetch materializes the movie into the xite tree.
        state.edx_fetch_file(&address, "movie.bin", false).await.unwrap().unwrap();
        let path = dir.path().join("movie.bin");
        assert_eq!(std::fs::read(&path).unwrap(), movie);

        // The user deletes their file out from under the record.
        std::fs::remove_file(&path).unwrap();

        // The next fetch must not claim success: it notices the lie and
        // retires the record...
        let first = state.edx_fetch_file(&address, "movie.bin", false).await.unwrap();
        assert!(first.is_err(), "a fileless 'complete' must not report success: {first:?}");

        // ...so the one after starts clean and actually restores the file.
        assert!(state.edx_fetch_file(&address, "movie.bin", false).await.unwrap().unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), movie, "refetched, byte-for-byte");
    }

    /// Same recovery on the STREAMING path: a range serve against a deleted
    /// extern file errors once, the wired background revalidate retires the
    /// record, and the next range request refetches from the swarm.
    #[tokio::test]
    async fn a_deleted_streamed_file_recovers_on_the_range_path() {
        let (address, cb, content, movie, addr, _pk) = spawn_seeder().await;
        let (state, dir) = client_for(&address, &cb, &content, addr).await;
        let id = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap().b3;
        let store = state.edx_store().await.unwrap();

        state.edx_fetch_file(&address, "movie.bin", false).await.unwrap().unwrap();
        assert!(store.is_extern(id).unwrap());
        std::fs::remove_file(dir.path().join("movie.bin")).unwrap();

        // First range request fails - the bits claimed present, the disk
        // disagreed - and arms the background revalidate.
        let first = state.edx_fetch_range(&address, "movie.bin", 100_000, 50_000).await.unwrap();
        assert!(first.is_err(), "no silent success on a gone file: {first:?}");

        // The revalidate runs off-thread; wait for the retire.
        for _ in 0..100 {
            if !store.contains(id).unwrap() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(!store.contains(id).unwrap(), "the stale record was retired");

        // The next request refetches the covering groups and serves.
        let bytes = match state.edx_fetch_range(&address, "movie.bin", 100_000, 50_000).await {
            Some(Ok(Some(b))) => b,
            other => panic!("range after retire: {other:?}"),
        };
        assert_eq!(bytes, movie[100_000..150_000], "served fresh from the swarm");
    }

    /// The owner-signed `order_policy` reorders OUR fetching: the declared
    /// first-paint file lands before everything else even though the default
    /// ladder would have taken the small files first, and a xite that declares
    /// nothing keeps that default ladder.
    #[tokio::test]
    async fn order_policy_puts_first_paint_ahead_of_the_default_ladder() {
        let want = || {
            vec![EdxWant::path("index.html"), EdxWant::path("movie.bin")]
        };

        // No policy: the type ladder puts the page's own markup first and the
        // movie last, so the 5 KB index.html lands before the 400 KB movie.
        let (address, cb, content, _movie, addr, _pk) = spawn_seeder().await;
        let (state, _dir) = client_for(&address, &cb, &content, addr).await;
        let peers = vec![epix_core::PeerAddr::Ip(addr)];
        let batch = state.edx_fetch_files(&address, want(), peers.clone(), None, None).await.unwrap();
        assert_eq!(
            batch.done,
            vec!["index.html".to_string(), "movie.bin".to_string()],
            "no order_policy -> unchanged default ladder (small first)"
        );

        // Owner declares the movie as the first-paint shell: it now goes FIRST,
        // ahead of the small file the ladder would otherwise have batched.
        let (address, cb, content, _movie, addr, _pk) = spawn_seeder_declaring(serde_json::json!({
            "order_policy": { "first_paint": ["movie.bin"], "prefetch": ["index.html"] }
        }))
        .await;
        assert!(content.get("order_policy").is_some(), "policy rides inside the signed manifest");
        let (state, _dir) = client_for(&address, &cb, &content, addr).await;
        let peers = vec![epix_core::PeerAddr::Ip(addr)];
        let batch = state.edx_fetch_files(&address, want(), peers, None, None).await.unwrap();
        assert_eq!(
            batch.done,
            vec!["movie.bin".to_string(), "index.html".to_string()],
            "first paint before the prefetch hint"
        );
    }

    /// The default ladder sorts by TYPE, and that has to beat sorting by
    /// size - otherwise it is not doing anything the old GetMany batching
    /// did not already do.
    ///
    /// This is mx5kevin's case in miniature: a xite that declares nothing,
    /// whose renderable asset is BIG and whose bulk download is SMALL. Under
    /// small-first the manual would come down before the stylesheet and the
    /// page would sit unstyled waiting on it.
    #[tokio::test]
    async fn the_default_ladder_beats_small_first_when_they_disagree() {
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(xite_dir.path());
        // Renderable but large, vs bulk but small.
        storage.write("css/all.css", &vec![b'c'; 400_000]).unwrap();
        storage.write("docs/manual.pdf", &vec![b'p'; 5_000]).unwrap();
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        xite.sign(&privkey, 1000.0).unwrap();
        let content_bytes = xite.storage.read("content.json").unwrap();
        let content: serde_json::Value = serde_json::from_slice(&content_bytes).unwrap();
        assert!(content.get("order_policy").is_none(), "the xite declares no order");

        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await);
        std::mem::forget(xite_dir);
        std::mem::forget(store_dir);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state_b.clone(),
            store_b,
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        let (state, _dir) = client_for(&address, &content_bytes, &content, addr).await;
        let want = vec![EdxWant::path("docs/manual.pdf"), EdxWant::path("css/all.css")];
        let batch = state
            .edx_fetch_files(&address, want, vec![epix_core::PeerAddr::Ip(addr)], None, None)
            .await
            .unwrap();
        assert_eq!(
            batch.done,
            vec!["css/all.css".to_string(), "docs/manual.pdf".to_string()],
            "the stylesheet the page needs comes down before the document it does not"
        );
    }

    /// A seeder holding `n` small files (`post-0.json` ...), all inside the
    /// GetMany size class, so a fetch of the lot rides one batch.
    async fn spawn_many_small_seeder(
        n: usize,
    ) -> (String, Vec<u8>, serde_json::Value, std::net::SocketAddr) {
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(xite_dir.path());
        for i in 0..n {
            storage.write(&format!("post-{i}.json"), format!("{{\"n\":{i}}}").as_bytes()).unwrap();
        }
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        xite.sign(&privkey, 1000.0).unwrap();
        let content_bytes = xite.storage.read("content.json").unwrap();
        let content: serde_json::Value = serde_json::from_slice(&content_bytes).unwrap();

        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        state_b
            .add_xite(
                &address,
                XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None },
            )
            .await;
        assert!(state_b.load_content_from_disk(&address).await);
        std::mem::forget(xite_dir);
        std::mem::forget(store_dir);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state_b.clone(),
            store_b.clone(),
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
        (address, content_bytes, content, addr)
    }

    /// A SECOND node serving the same xite as [`spawn_many_small_seeder`]:
    /// same files, same signed manifest, so both hold every object and either
    /// can answer for any of them. Returns its address.
    async fn second_seeder_for(
        address: &str,
        content_bytes: &[u8],
        content: &serde_json::Value,
    ) -> std::net::SocketAddr {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        for (path, _) in content["files"].as_object().unwrap() {
            let i: usize = path
                .trim_start_matches("post-")
                .trim_end_matches(".json")
                .parse()
                .expect("only the seeder's post-N.json files");
            storage.write(path, format!("{{\"n\":{i}}}").as_bytes()).unwrap();
        }
        storage.write("content.json", content_bytes).unwrap();

        let state = AppState::new("node-c");
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(test_store(store_dir.path(), dir.path()));
        state.set_edx_store(store.clone()).await.unwrap();
        state
            .add_xite(address, XiteEntry { storage, content: None })
            .await;
        assert!(state.load_content_from_disk(address).await, "second seeder holds every object");
        std::mem::forget(dir);
        std::mem::forget(store_dir);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state.clone(),
            store,
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
        addr
    }

    /// A GetMany batch reports each file as it lands, not once at the end.
    /// The whole batch is one round trip, so materializing only after it
    /// finished pinned the clone's loading bar at zero for the entire
    /// download and kept a forum's posts out of the db until the last one
    /// arrived. Asserted by what is ON DISK when each hook fires: the first
    /// file is materialized while its batch-mates are still missing.
    #[tokio::test]
    async fn a_get_many_batch_reports_each_file_as_it_lands() {
        const N: usize = 6;
        let (address, cb, content, addr) = spawn_many_small_seeder(N).await;
        let (state, dir) = client_for(&address, &cb, &content, addr).await;

        // Files materialized (present on disk), and the serving-peer count, at
        // the moment of each callback.
        let seen: Arc<std::sync::Mutex<Vec<(String, usize, usize)>>> = Arc::default();
        let on_file: EdxBatchProgress = {
            let seen = seen.clone();
            let root = dir.path().to_path_buf();
            Arc::new(move |inner: &str, _bytes: u64, serving: usize| {
                let on_disk =
                    (0..N).filter(|i| root.join(format!("post-{i}.json")).exists()).count();
                seen.lock().unwrap().push((inner.to_string(), on_disk, serving));
            })
        };
        let want: Vec<EdxWant> =
            (0..N).map(|i| EdxWant::path(format!("post-{i}.json"))).collect();
        let batch = state
            .edx_fetch_files(&address, want, vec![epix_core::PeerAddr::Ip(addr)], None, Some(on_file))
            .await
            .unwrap();

        assert_eq!(batch.done.len(), N, "every file landed");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), N, "one report per file");
        assert_eq!(seen[0].1, 1, "the first file is reported with only itself on disk");
        // The bar climbs one file at a time all the way up.
        for (i, (_, on_disk, serving)) in seen.iter().enumerate() {
            assert_eq!(*on_disk, i + 1, "report {i} sees {} files on disk", i + 1);
            assert_eq!(*serving, 1, "the one seeder is reported as the source");
        }
    }

    /// A GetMany batch is dealt across every live link and pulled from all of
    /// them at once, so a download draws on the whole session instead of
    /// draining the first peer end to end - and the count it reports is the
    /// peers actually serving, which is what the loading screen shows.
    #[tokio::test]
    async fn a_get_many_batch_downloads_from_every_peer_in_the_session() {
        const N: usize = 8;
        // Two seeders of the SAME xite: identical files, so both sign the same
        // manifest and either can serve any object.
        let (address, cb, content, addr_a) = spawn_many_small_seeder(N).await;
        let addr_b = second_seeder_for(&address, &cb, &content).await;
        let (state, _dir) = client_for(&address, &cb, &content, addr_a).await;

        let peak: Arc<std::sync::Mutex<usize>> = Arc::default();
        let on_file: EdxBatchProgress = {
            let peak = peak.clone();
            Arc::new(move |_inner: &str, _bytes: u64, serving: usize| {
                let mut p = peak.lock().unwrap();
                *p = (*p).max(serving);
            })
        };
        let want: Vec<EdxWant> =
            (0..N).map(|i| EdxWant::path(format!("post-{i}.json"))).collect();
        let batch = state
            .edx_fetch_files(
                &address,
                want,
                vec![epix_core::PeerAddr::Ip(addr_a), epix_core::PeerAddr::Ip(addr_b)],
                None,
                Some(on_file),
            )
            .await
            .unwrap();

        assert_eq!(batch.done.len(), N, "every file landed");
        assert_eq!(*peak.lock().unwrap(), 2, "the batch was served by BOTH peers, not just the first");
    }

    /// A fresh clone holds its verified content.json in memory (it commits
    /// only once the core set is on disk), so the fetch pass has to take the
    /// order policy from the caller's staged copy. Reading disk instead found
    /// nothing and dropped every file into one untiered batch - first paint
    /// last, on exactly the load that needs it first.
    #[tokio::test]
    async fn a_staged_content_json_still_drives_the_order_policy() {
        let (address, cb, content, _movie, addr, _pk) = spawn_seeder_declaring(serde_json::json!({
            "order_policy": { "first_paint": ["movie.bin"], "prefetch": ["index.html"] }
        }))
        .await;

        // The client has the manifest ONLY as a staged value: nothing on disk,
        // exactly like a clone that has not committed content.json yet.
        let state = AppState::new("node-a");
        let dir = tempfile::tempdir().unwrap();
        state
            .add_xite(
                &address,
                XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content.clone()) },
            )
            .await;
        state.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let store_dir = tempfile::tempdir().unwrap();
        state
            .set_edx_store(Arc::new(test_store(store_dir.path(), dir.path())))
            .await
            .unwrap();
        state
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        state.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;
        assert!(!dir.path().join("content.json").exists(), "manifest is staged, not committed");
        let transaction = state
            .begin_staged_root_transaction(&address, &cb)
            .await
            .expect("signed staged manifest starts a transaction");

        let needed = ["index.html", "movie.bin"]
            .into_iter()
            .map(|path| {
                let entry = &content["files"][path];
                epix_xite::FileEntry {
                    inner_path: path.to_string(),
                    size: entry["size"].as_i64().unwrap(),
                    sha512: entry["sha512"].as_str().unwrap().to_string(),
                }
            })
            .collect();
        let landed: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let on_file: EdxBatchProgress = {
            let landed = landed.clone();
            Arc::new(move |path, _bytes, _peers| landed.lock().unwrap().push(path.to_string()))
        };
        let missed = state
            .edx_first(
                &address,
                needed,
                vec![epix_core::PeerAddr::Ip(addr)],
                Some(&content),
                Some(&transaction),
                Some(on_file),
            )
            .await;
        assert!(missed.is_empty());
        assert_eq!(
            *landed.lock().unwrap(),
            vec!["movie.bin".to_string(), "index.html".to_string()],
            "staged policy puts first paint ahead of the default small-first ladder"
        );
    }

    /// `fetch_signed_many` reports each manifest the moment a peer serves it,
    /// with the exact signed bytes - the hook the sync pass uses to verify
    /// and ingest per-user content.json files mid-pass instead of after the
    /// whole level (a dead-silent stretch over Tor). A path nobody serves
    /// fires nothing.
    #[tokio::test]
    async fn a_signed_batch_reports_each_manifest_as_it_lands() {
        let (address, cb, content, addr) = spawn_many_small_seeder(3).await;
        let (state, _dir) = client_for(&address, &cb, &content, addr).await;

        let seen: Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>> = Arc::default();
        let on_item: epix_ui::state::EdxSignedProgress = {
            let seen = seen.clone();
            Arc::new(move |p: &str, b: &[u8]| {
                seen.lock().unwrap().push((p.to_string(), b.to_vec()));
            })
        };
        let served = state
            .edx_fetch_signed_many(
                &address,
                vec!["content.json".into(), "data/users/nobody/content.json".into()],
                vec![epix_core::PeerAddr::Ip(addr)],
                Some(on_item),
            )
            .await
            .unwrap();
        assert_eq!(served.len(), 1, "only the path the peer holds is served");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "one callback per served path, none for the unserved");
        assert_eq!(seen[0].0, "content.json");
        assert_eq!(seen[0].1, served["content.json"], "callback carries the served bytes");
    }

    /// The overlay dial cap bounds dials IN FLIGHT, not connections: once a
    /// dial finishes its slot frees and the next peer dials. The worry it has
    /// to rule out is a node sealing itself into a fixed set of peers - if the
    /// cap were a connection limit, N nodes pointing at each other would form
    /// a closed pool that never reaches anyone else. It cannot: the permit is
    /// held for the dial only, acquisition is FIFO so a queued peer is never
    /// starved, and every dial is bounded by connect_timeout so slots always
    /// come back.
    #[tokio::test]
    async fn the_overlay_dial_cap_queues_rather_than_excludes() {
        let slots = overlay_dial_slots();
        let held: Vec<_> = (0..MAX_CONCURRENT_OVERLAY_DIALS)
            .map(|_| slots.try_acquire().expect("cap starts empty"))
            .collect();
        assert_eq!(held.len(), MAX_CONCURRENT_OVERLAY_DIALS);

        // Saturated: the next peer waits instead of dialing immediately.
        assert!(slots.try_acquire().is_err(), "the cap is a real bound");
        let queued = tokio::time::timeout(std::time::Duration::from_millis(50), overlay_dial_permit()).await;
        assert!(queued.is_err(), "a 9th dial queues while all slots are busy");

        // One dial finishes: the queued peer goes through. This is the part
        // that makes a closed pool impossible.
        drop(held.into_iter().next().expect("a permit"));
        let now_free = tokio::time::timeout(std::time::Duration::from_secs(5), overlay_dial_permit()).await;
        assert!(now_free.is_ok(), "a freed slot admits the waiting peer");
    }

    /// A session starts on the first peer that ANSWERS instead of waiting for
    /// every dial to settle. A peer that accepts the socket and then never
    /// speaks costs a full connect_timeout (15s clearnet, 45s overlay), and a
    /// registry is mostly dead gossip addresses - holding the fetch behind
    /// them is the "Connecting to peers..." stall, measured at 45s on a clean
    /// clone whose seeder had answered in 0.0s. The live seeder is listed
    /// LAST here, so passing means the fetch really did proceed on the peer
    /// that answered rather than on list order.
    #[tokio::test]
    async fn a_session_fetches_without_waiting_out_a_dead_peer() {
        let (address, cb, content, addr) = spawn_many_small_seeder(3).await;
        let (state, _dir) = client_for(&address, &cb, &content, addr).await;

        // Accepts the connection and then never writes, so the dial hangs to
        // its deadline rather than failing fast the way a refused port would.
        let blackhole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = blackhole.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = blackhole.accept().await {
                held.push(sock);
            }
        });

        let started = std::time::Instant::now();
        let served = state
            .edx_fetch_signed_many(
                &address,
                vec!["content.json".into()],
                vec![epix_core::PeerAddr::Ip(dead), epix_core::PeerAddr::Ip(addr)],
                None,
            )
            .await
            .unwrap();
        let took = started.elapsed();

        assert_eq!(served.len(), 1, "the live peer served the manifest");
        assert!(
            took < std::time::Duration::from_secs(10),
            "must not wait out the dead peer's dial budget, took {took:?}"
        );
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
        let a_store = Arc::new(test_store(a_store_dir.path(), a_dir.path()));
        state_a.set_edx_store(a_store.clone()).await.unwrap();
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

    /// A range fetch asks the swarm only for the groups the store still
    /// lacks: with the first half of the window already present, the seeder
    /// is credited for roughly half the window, never all of it.
    #[tokio::test]
    async fn a_range_fetch_requests_only_the_missing_groups() {
        let (address, content_bytes, content, movie, addr, server_pk) = spawn_seeder().await;

        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        XiteStorage::new(a_dir.path()).write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: Some(content.clone()) })
            .await;
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        let a_store = Arc::new(test_store(a_store_dir.path(), a_dir.path()));
        state_a.set_edx_store(a_store.clone()).await.unwrap();
        let choker: SharedChoker = Arc::new(Mutex::new(Choker::new(EDX_UPLOAD_CAP_BPS)));
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                Some(choker.clone()),
            )))
            .await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;
        std::mem::forget(a_dir);
        std::mem::forget(a_store_dir);

        // The first half of the file is already in the local store.
        let id = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap().b3;
        let size = movie.len() as u64;
        a_store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        let ob = epix_blob::verified::OutboardBytes::from_slice(&movie);
        let held = vec![0..200_000u64];
        let mut slice = Vec::new();
        epix_blob::verified::encode_slice(&movie[..], &ob, &held, &mut slice).unwrap();
        a_store.write_slice(id, &held, &slice[..], 1).unwrap();

        // Fetch the whole file as one range window.
        let bytes = match state_a.edx_fetch_range(&address, "movie.bin", 0, size).await {
            Some(Ok(Some(b))) => b,
            other => panic!("range fetch: {other:?}"),
        };
        assert_eq!(bytes, movie, "the served window is byte-exact");

        // Only the missing half went over the wire: the seeder's
        // reciprocity credit covers about half the file, not the window.
        let credit = choker.lock().unwrap().credit_of(&server_pk);
        assert!(credit > 0, "the seeder served the missing half");
        assert!(
            credit < 300_000,
            "a gap-only fetch must not refetch the present half (credited {credit})"
        );
    }

    /// Bytes the store already holds serve as a shorter 206 even when NO
    /// peer is dialable: a dial (or claim) failure must not preempt the
    /// present-prefix check - the exact seeder-vanished case the partial
    /// salvage work exists for.
    #[tokio::test]
    async fn a_held_prefix_serves_when_no_peer_is_dialable() {
        let (address, content_bytes, content, movie, _addr, _server_pk) = spawn_seeder().await;

        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        XiteStorage::new(a_dir.path()).write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: Some(content.clone()) })
            .await;
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        let a_store = Arc::new(test_store(a_store_dir.path(), a_dir.path()));
        state_a.set_edx_store(a_store.clone()).await.unwrap();
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        // NO peers added: every dial path fails (the seeder vanished).
        std::mem::forget(a_dir);
        std::mem::forget(a_store_dir);

        // A previous partial fetch left the head of the file in the store.
        let id = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap().b3;
        let size = movie.len() as u64;
        a_store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        let ob = epix_blob::verified::OutboardBytes::from_slice(&movie);
        let held = vec![0..200_000u64];
        let mut slice = Vec::new();
        epix_blob::verified::encode_slice(&movie[..], &ob, &held, &mut slice).unwrap();
        a_store.write_slice(id, &held, &slice[..], 1).unwrap();

        // Request the whole file: the held prefix must come back as a
        // shorter range, never an error for bytes the store holds.
        let bytes = match state_a.edx_fetch_range(&address, "movie.bin", 0, size).await {
            Some(Ok(Some(b))) => b,
            other => panic!("range fetch: {other:?}"),
        };
        assert!(
            bytes.len() >= 200_000 && (bytes.len() as u64) < size,
            "a held prefix serves short, got {} of {size}",
            bytes.len()
        );
        assert_eq!(bytes[..], movie[..bytes.len()], "the served prefix is byte-exact");
    }

    /// The gap-only group set a range fetch requests, and the contiguous
    /// prefix a partial window can serve. Pure - no network.
    #[test]
    fn window_helpers_compute_gaps_and_prefix() {
        use epix_blob::bitfield::{GroupBits, GROUP_BYTES};
        let size = 100 * GROUP_BYTES;
        let mut present = GroupBits::new();
        present.add(0..3);
        present.add(5..7);

        let window = 0..10 * GROUP_BYTES;
        let needed = missing_groups(&present, &window);
        assert_eq!(needed.ranges(), [3..5, 7..10], "only the gaps are requested");
        assert!(
            missing_groups(&GroupBits::complete(size), &window).is_empty(),
            "a warm window requests nothing"
        );

        // Prefix: groups 0..3 are present, so exactly their bytes serve.
        assert_eq!(present_prefix_len(&present, &window, size), 3 * GROUP_BYTES);
        // A window starting in a hole serves nothing (the 404 case).
        let hole = 3 * GROUP_BYTES..5 * GROUP_BYTES;
        assert_eq!(present_prefix_len(&present, &hole, size), 0);
        // A fully present span clamps to the window end, not group end.
        let tail = GROUP_BYTES..2 * GROUP_BYTES + 5;
        assert_eq!(present_prefix_len(&present, &tail, size), GROUP_BYTES + 5);
        // The object's final short group counts as covered at `size`.
        let odd_size = 4 * GROUP_BYTES + 100;
        let mut all = GroupBits::new();
        all.add(0..5);
        assert_eq!(present_prefix_len(&all, &(0..odd_size), odd_size), odd_size);
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
        let a_store = Arc::new(test_store(a_store_dir.path(), a_dir.path()));
        state_a.set_edx_store(a_store.clone()).await.unwrap();
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

    /// Full-file download is the default for a large media file: ONE Range
    /// serve in the middle of the file must eventually complete the whole
    /// object in the store with no further requests - including the bytes
    /// BEHIND the served offset, which nothing else covers (the read-ahead
    /// only fetches forward of the play head, and the moov warm-up only the
    /// head and tail spans). A seeked-into video must not stay holey.
    #[tokio::test]
    async fn a_range_serve_arms_the_full_file_download() {
        // Past the media size gate, with a gap between the 1 MiB moov head
        // warm and the served offset that only the completion pass can fill.
        let movie_len = (MOOV_MIN_SIZE + 512 * 1024) as usize;
        let (address, content_bytes, content, movie, addr, _pk) =
            spawn_seeder_sized(serde_json::json!({}), movie_len).await;

        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        XiteStorage::new(a_dir.path()).write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: Some(content.clone()) })
            .await;
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        let a_store = Arc::new(test_store(a_store_dir.path(), a_dir.path()));
        state_a.set_edx_store(a_store.clone()).await.unwrap();
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

        // A single serve at 2 MiB - a seek, as a player that opened mid-film
        // would issue. Between the head warm (ends at 1 MiB) and this offset
        // lies a region no serve, read-ahead or warm-up will ever ask for.
        let (start, len) = (2 * 1024 * 1024u64, 20_000u64);
        let served = match state_a.edx_fetch_range(&address, "movie.bin", start, len).await {
            Some(Ok(Some(b))) => b,
            other => panic!("range fetch: {other:?}"),
        };
        assert_eq!(served, movie[start as usize..(start + len) as usize], "served range is byte-exact");

        // The background completion pulls the ENTIRE file, holes included.
        // Poll for it - the serve did not wait on it.
        let id = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap().b3;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !a_store.is_complete(id).unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "full-file completion never finished the object"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Bytes from inside the hole behind the play head are byte-exact and
        // served from the store.
        let hole = match state_a.edx_fetch_range(&address, "movie.bin", 1_500_000, 40_000).await {
            Some(Ok(Some(b))) => b,
            other => panic!("hole re-read: {other:?}"),
        };
        assert_eq!(hole, movie[1_500_000..1_540_000], "backfilled bytes are byte-exact");
    }

    /// A ShardEntry (data-map) for `plaintext`'s convergent encryption: the
    /// signed-content.json section a volunteer reads. `chunks` and `shards`
    /// are parallel, so `csize` is each ciphertext's length.
    fn shard_entry_from(
        plaintext: &[u8],
        enc: &epix_selfenc::Encrypted,
    ) -> epix_blob::manifest::ShardEntry {
        let chunks = enc
            .chunks
            .iter()
            .zip(&enc.shards)
            .map(|(c, (_addr, ct))| epix_blob::manifest::ShardChunk {
                plain_hash: c.plain_hash,
                cipher_addr: ObjId(c.cipher_addr),
                len: c.len,
                csize: ct.len() as u32,
            })
            .collect();
        epix_blob::manifest::ShardEntry { size: plaintext.len() as u64, mode: 0, chunks }
    }

    /// Serve `store` over EDX on a fresh TCP port, advertising `caps::SHARDS`
    /// (a volunteer that holds shards also serves them). Returns the address;
    /// the backing state/task are leaked to outlive the test.
    async fn serve_edx(store: Arc<Store>) -> std::net::SocketAddr {
        let state = AppState::new("edx-seeder");
        state.set_edx_store(store.clone()).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sa = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state,
            store,
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            true,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
        sa
    }

    /// A seeder holding the given ciphertext shards (Ns::Shard), served over
    /// EDX. Returns its address.
    async fn spawn_shard_seeder(shards: &[(epix_selfenc::Hash, Vec<u8>)]) -> std::net::SocketAddr {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        for (addr, ct) in shards {
            store.insert_bytes(ObjId(*addr), Ns::Shard, ct, 1).unwrap();
        }
        std::mem::forget(dir);
        serve_edx(store).await
    }

    /// Stand up a volunteer node (store + transport + the seeder as a peer for
    /// `address`, with `address` registered so peers resolve) and set its
    /// donated quota. Returns the volunteer state, its store, and the xite
    /// address the peer is registered under.
    async fn volunteer_node(seeder: std::net::SocketAddr, quota: u64) -> (Arc<AppState>, Arc<Store>, String) {
        let state = AppState::new("volunteer");
        let addr = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        let xite_path = xite_dir.path().to_path_buf();
        state
            .add_xite(&addr, XiteEntry { storage: XiteStorage::new(&xite_path), content: None })
            .await;
        std::mem::forget(xite_dir);
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(test_store(store_dir.path(), &xite_path));
        std::mem::forget(store_dir);
        state.set_edx_store(store.clone()).await.unwrap();
        state.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        state.add_peers(&addr, [epix_core::PeerAddr::Ip(seeder)]).await;
        state.config_set("volunteer_quota_bytes", serde_json::json!(quota)).await;
        (state, store, addr)
    }

    /// The volunteer role, end to end: a node pulls the ciphertext shards it is
    /// responsible for (from a data-map it could have read out of a verified
    /// content.json), HOLDS them by address without ever decrypting, and then
    /// serves one back to a fresh client - proving it holds+serves ciphertext
    /// it cannot read.
    #[tokio::test]
    async fn a_volunteer_holds_and_serves_ciphertext_it_never_decrypts() {
        let plaintext: Vec<u8> = (0..300_000usize).map(|i| (i.wrapping_mul(7) % 251) as u8).collect();
        let enc = epix_selfenc::encrypt_convergent(&plaintext, b"owner-salt");
        let shard = shard_entry_from(&plaintext, &enc);
        let seeder = spawn_shard_seeder(&enc.shards).await;

        // Quota >= universe => responsible for every shard; budget never bites.
        let (state_v, v_store, address) = volunteer_node(seeder, u64::MAX).await;
        let fetcher = RuntimeEdxFetcher::new(state_v.clone(), epix_crypt::new_seed(), None);
        let held = fetcher.volunteer_hold_file(&address, &shard, &v_store).await.unwrap();
        assert_eq!(held, enc.shards.len(), "volunteer held every responsible shard");

        // It holds the CIPHERTEXT (verified by address) and never the plaintext.
        let now = now_secs();
        for (addr, ct) in &enc.shards {
            let id = ObjId(*addr);
            assert!(v_store.is_complete(id).unwrap(), "shard {id} held complete");
            assert_eq!(&v_store.read_bytes(id, now).unwrap(), ct, "held bytes are the ciphertext");
        }
        let plain_id = ObjId::of(&plaintext);
        assert!(!v_store.is_complete(plain_id).unwrap(), "volunteer never decrypted to plaintext");
        let total_ct: u64 = enc.shards.iter().map(|(_, ct)| ct.len() as u64).sum();
        assert_eq!(v_store.ns_bytes(Ns::Shard).unwrap(), total_ct, "shard budget counts held ciphertext");

        // HOLDS + SERVES: bring the volunteer up as a seeder and let a fresh
        // client pull one shard back, bao-verified by its address.
        let vol_addr = serve_edx(v_store.clone()).await;
        let stream = TcpTransport.dial(&epix_core::PeerAddr::Ip(vol_addr)).await.unwrap();
        let l = epix_edx::link::dial(stream).await.unwrap();
        let cdir = tempfile::tempdir().unwrap();
        let cstore = Arc::new(Store::open(cdir.path()).unwrap());
        let cctx = ServeCtx {
            caps: caps::MESH,
            now: || 0,
            ..ServeCtx::new(cstore.clone(), Arc::new(NoProvider), epix_crypt::new_seed())
        };
        let ident = client_hello(&l.conn, &cctx, vec![], Some(l.handshake_hash)).await.unwrap();
        assert!(ident.caps & caps::SHARDS != 0, "the volunteer advertises caps::SHARDS");

        let (addr0, ct0) = &enc.shards[0];
        let id0 = ObjId(*addr0);
        let csize = ct0.len() as u64;
        cstore.ensure_sparse(id0, Ns::Shard, csize, 1).unwrap();
        let got =
            epix_edx::fetch::fetch_ranges(&l.conn, &cstore, id0, csize, &[0..csize], 100, 2).await.unwrap();
        assert!(got > 0);
        assert!(cstore.is_complete(id0).unwrap(), "the ciphertext shard transferred");
        assert_eq!(&cstore.read_bytes(id0, 3).unwrap(), ct0, "served shard is the exact ciphertext");
    }

    /// The donated byte budget bounds a volunteer: with a tiny universe every
    /// shard is responsible, but a quota just one shard wide stops the pull
    /// after the first shard instead of holding them all.
    #[tokio::test]
    async fn a_volunteer_stops_when_its_quota_is_reached() {
        // >1 MiB plaintext -> several ~1 MiB ciphertext shards.
        let plaintext: Vec<u8> = (0..3_500_000usize).map(|i| (i.wrapping_mul(13) % 251) as u8).collect();
        let enc = epix_selfenc::encrypt_convergent(&plaintext, b"owner-salt");
        assert!(enc.shards.len() >= 3, "want several shards, got {}", enc.shards.len());
        let shard = shard_entry_from(&plaintext, &enc);
        let seeder = spawn_shard_seeder(&enc.shards).await;

        // Tiny universe => quota >= universe => responsible for everything, so
        // only the byte budget limits the pull. Quota = one shard's worth.
        std::env::set_var("EPIX_EDX_SHARD_UNIVERSE_BYTES", "1");
        let quota = enc.shards[0].1.len() as u64;
        let (state_v, v_store, address) = volunteer_node(seeder, quota).await;
        let fetcher = RuntimeEdxFetcher::new(state_v.clone(), epix_crypt::new_seed(), None);
        let held = fetcher.volunteer_hold_file(&address, &shard, &v_store).await.unwrap();
        std::env::remove_var("EPIX_EDX_SHARD_UNIVERSE_BYTES");

        assert_eq!(held, 1, "the budget gate stops the volunteer after one shard");
        assert!(v_store.ns_bytes(Ns::Shard).unwrap() >= quota, "held about the donated quota");
        let others_held =
            enc.shards[1..].iter().filter(|(a, _)| v_store.is_complete(ObjId(*a)).unwrap()).count();
        assert_eq!(others_held, 0, "no shard beyond the first was held");
    }

    /// Not volunteering (quota 0): the driver holds nothing even when it could.
    #[tokio::test]
    async fn quota_zero_volunteers_nothing() {
        let plaintext: Vec<u8> = (0..200_000usize).map(|i| (i % 251) as u8).collect();
        let enc = epix_selfenc::encrypt_convergent(&plaintext, b"owner-salt");
        let shard = shard_entry_from(&plaintext, &enc);
        let seeder = spawn_shard_seeder(&enc.shards).await;

        let (state_v, v_store, address) = volunteer_node(seeder, 0).await;
        let fetcher = RuntimeEdxFetcher::new(state_v.clone(), epix_crypt::new_seed(), None);
        let held = fetcher.volunteer_hold_file(&address, &shard, &v_store).await.unwrap();
        assert_eq!(held, 0, "quota 0 holds nothing");
        assert_eq!(v_store.ns_bytes(Ns::Shard).unwrap(), 0, "nothing landed in the shard namespace");
    }

    /// Social/forum content over EDX: a per-user file declared in a child
    /// content.json (as forums store each user's posts) is registered by the
    /// seeder and fetched + resolved by a client through the governing child
    /// content.json, not just the root.
    #[tokio::test]
    async fn a_per_user_child_file_transfers_over_edx() {
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(xite_dir.path());
        storage.write("index.html", b"<h1>forum</h1>").unwrap();
        let post = b"a forum post by alice, delivered over EDX not msgpack".to_vec();
        storage.write("data/users/alice/data.json", &post).unwrap();
        // The signed user_contents parent the child verifies against. The
        // serving side only trusts manifests whose whole authority chain
        // verifies, so the parent must be signed and the root must declare it.
        let (parent_bytes, _, _) = signed_user_chain(
            &address,
            &privkey,
            serde_json::json!({
                "cert_signers": {},
                "permissions": {},
                "permission_rules": { ".*": { "max_size": 100000 } },
            }),
        );
        storage.write("data/users/content.json", &parent_bytes).unwrap();
        // A child content.json declaring the per-user file with its b3 (what
        // sign_child stamps in production). Signed with the xite key - always
        // a valid signer - to skip the cert flow.
        let b3 = epix_blob::ObjId::of(&post);
        let mut child = serde_json::json!({
            "files": {
                "data.json": {
                    "size": post.len(),
                    "sha512": XiteStorage::hash_bytes(&post),
                    "b3": b3.to_string(),
                }
            },
            "modified": 1000, "address": address,
            "inner_path": "data/users/alice/content.json",
        });
        epix_content::sign(&mut child, &privkey).unwrap();
        storage
            .write("data/users/alice/content.json", &serde_json::to_vec(&child).unwrap())
            .unwrap();
        let mut xite = Xite::new(epix_core::Address::parse(address.clone()).unwrap(), storage);
        // The root must authorize the user_contents parent, or the walk stops
        // at the root and nothing under data/users/ is served.
        xite.content = Some(serde_json::json!({
            "includes": { "data/users/content.json": { "signers": [] } },
        }));
        xite.sign(&privkey, 1000.0).unwrap();
        let content_bytes = xite.storage.read("content.json").unwrap();

        // Node B: load (registers the root AND the child file) and serve.
        let state_b = AppState::new("node-b");
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await);
        // The per-user file's object is now in the store (child recursion).
        assert!(store_b.contains(b3).unwrap(), "child file registered for serving");
        std::mem::forget(xite_dir);
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
                false,
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
        a_storage.write("data/users/content.json", &parent_bytes).unwrap();
        a_storage
            .write("data/users/alice/content.json", &serde_json::to_vec(&child).unwrap())
            .unwrap();
        state_a
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(a_dir.path()), content: None })
            .await;
        assert!(state_a.load_content_from_disk(&address).await);
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        state_a
            .set_edx_store(Arc::new(test_store(a_store_dir.path(), a_dir.path())))
            .await
            .unwrap();
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;

        let result = state_a.edx_fetch_file(&address, "data/users/alice/data.json", false).await;
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

    #[test]
    fn inline_merge_envelopes_are_bounded_and_content_addressed() {
        let records = br#"{"records":[{"sign":"abc"}]}"#.to_vec();
        let mut merges = HashMap::new();
        merges.insert("posts.json".to_string(), records.clone());
        let wire = encode_inline_merge_records(&merges).unwrap().unwrap();
        assert_eq!(wire.len(), 1);
        assert_eq!(
            decode_inline_merges(&wire).unwrap().deltas.get("posts.json"),
            Some(&records)
        );
        let capless = decode_update_inline(&wire, false).unwrap();
        assert!(capless.deltas.is_empty() && capless.objects.is_empty());

        let mut tampered = wire.clone();
        tampered[0].1.push(0);
        assert!(
            decode_inline_merges(&tampered).is_err(),
            "the object id binds path and bytes"
        );

        // INLINE_MERGE promises this exact envelope format. Silently accepting
        // another kind would give its sender a payload-aware ACK for bytes this
        // receiver discarded.
        let foreign = b"not a runtime merge envelope".to_vec();
        assert!(
            decode_inline_merges(&[(ObjId::of(&foreign), foreign.clone())]).is_err(),
            "a foreign inline object fails closed"
        );
        assert!(
            decode_inline_merges(&[(ObjId::of(b"other"), foreign)]).is_err(),
            "a corrupt hash also fails closed"
        );

        // Garbage BEHIND our magic is ours to judge - still fatal.
        let mut ours = INLINE_MERGE_MAGIC.to_vec();
        ours.extend_from_slice(&[0xFF; 8]);
        assert!(
            decode_inline_merges(&[(ObjId::of(&ours), ours)]).is_err(),
            "a malformed envelope behind the merge magic fails closed"
        );
    }

    #[test]
    fn update_push_errors_preserve_busy_hints_and_refuse_limits() {
        let delay = std::time::Duration::from_secs(3);
        assert!(matches!(
            map_update_push_error(epix_edx::fetch::PushUpdateError::Busy {
                message: "try later".into(),
                retry_after: Some(delay),
            }),
            EdxPushError::Busy {
                message,
                retry_after: Some(got),
            } if message == "try later" && got == delay
        ));

        let limit = std::io::Error::new(std::io::ErrorKind::QuotaExceeded, "peer: 413 hard limit");
        assert!(matches!(
            map_update_push_error(epix_edx::fetch::PushUpdateError::Refused(limit)),
            EdxPushError::Refused(message) if message.contains("hard limit")
        ));
    }

    #[test]
    fn oversized_inline_merge_becomes_an_explicit_object_marker() {
        let merges = HashMap::from([(
            "posts.json".to_string(),
            vec![7; MAX_INLINE_MERGE_BYTES.saturating_add(1)],
        )]);
        assert!(encode_inline_merge_records(&merges).unwrap().is_none());
        let records = merges.get("posts.json").unwrap();
        let object = EdxObjectRef { id: ObjId::of(records), size: records.len() as u64 };
        let wire = encode_inline_merge_objects(
            &merges,
            &HashMap::from([("posts.json".to_string(), object)]),
        )
        .unwrap();
        let decoded = decode_inline_merges(&wire).unwrap();
        assert!(decoded.deltas.is_empty());
        assert_eq!(decoded.objects.get("posts.json"), Some(&object));
    }

    #[test]
    fn merge_quota_wave_reconciles_after_the_final_eviction_hold() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let bytes = vec![7u8; 4096];
        let id = ObjId::of(&bytes);
        store.insert_bytes(id, Ns::Plain, &bytes, 1).unwrap();

        let wave = MergeQuotaWave::new(store.clone(), 0);
        let hold_a = store.hold_eviction(id);
        let lease_a = wave.lease();
        let hold_b = store.hold_eviction(id);
        let lease_b = wave.lease();
        let insertion_lease = wave.lease();

        drop(hold_a);
        drop(lease_a);
        assert!(
            store.contains(id).unwrap(),
            "an earlier peer cannot evict an object another fanout RPC still serves"
        );

        drop(hold_b);
        drop(lease_b);
        assert!(
            store.contains(id).unwrap(),
            "a blocking insertion lease delays reconciliation after async callers cancel"
        );
        drop(insertion_lease);
        assert!(
            !store.contains(id).unwrap(),
            "the last cancellation-safe lease enforces after the final hold drops"
        );
    }

    #[test]
    fn aggregate_over_budget_uses_markers_for_every_merge_path() {
        let per_delta = UPDATE_FRAME_BUDGET / 2;
        assert!(per_delta <= MAX_INLINE_MERGE_BYTES);
        let merges = HashMap::from([
            ("comments.json".to_string(), vec![1; per_delta]),
            ("posts.json".to_string(), vec![2; per_delta]),
            ("reactions.json".to_string(), vec![3; 128]),
        ]);
        assert!(encode_inline_merge_records(&merges).unwrap().is_none());
        let objects = merges
            .iter()
            .map(|(path, records)| {
                (
                    path.clone(),
                    EdxObjectRef { id: ObjId::of(records), size: records.len() as u64 },
                )
            })
            .collect();
        let wire = encode_inline_merge_objects(&merges, &objects).unwrap();
        let decoded = decode_inline_merges(&wire).unwrap();
        assert!(decoded.deltas.is_empty());
        assert_eq!(decoded.objects.len(), merges.len());
        assert!(inline_merge_wire_len(&wire) < UPDATE_FRAME_BUDGET);
    }

    #[test]
    fn more_than_eight_merge_paths_are_refused_instead_of_truncated() {
        let merges = (0..=MAX_INLINE_MERGES)
            .map(|i| (format!("merge-{i}.json"), Vec::new()))
            .collect::<HashMap<_, _>>();
        let err = encode_inline_merge_records(&merges).unwrap_err();
        assert!(err.contains("maximum"), "unexpected refusal: {err}");
    }

    #[test]
    fn metadata_only_update_has_a_valid_empty_inline_set() {
        let wire = encode_inline_merge_records(&HashMap::new()).unwrap().unwrap();
        assert!(wire.is_empty());
        let decoded = decode_inline_merges(&wire).unwrap();
        assert!(decoded.deltas.is_empty());
        assert!(decoded.objects.is_empty());
    }

    #[test]
    fn unsafe_merge_path_is_refused_instead_of_omitted() {
        let merges = HashMap::from([(
            "../escape.json".to_string(),
            br#"{"records":[]}"#.to_vec(),
        )]);
        let err = encode_inline_merge_records(&merges).unwrap_err();
        assert!(
            err.contains("unsafe merge path"),
            "unexpected refusal: {err}"
        );
    }

    #[test]
    fn merge_delta_object_over_eight_mib_is_refused() {
        let merges = HashMap::from([(
            "posts.json".to_string(),
            vec![0; MAX_MERGE_DELTA_OBJECT_BYTES as usize + 1],
        )]);
        let err = encode_inline_merge_records(&merges).unwrap_err();
        assert!(err.contains("maximum"), "unexpected refusal: {err}");
    }

    #[test]
    fn aggregate_eight_object_markers_over_cap_are_refused() {
        let each = MAX_MERGE_DELTA_OBJECT_BYTES as usize / MAX_INLINE_MERGES + 1;
        let merges = (0..MAX_INLINE_MERGES)
            .map(|i| (format!("merge-{i}.json"), vec![i as u8; each]))
            .collect::<HashMap<_, _>>();
        let err = encode_inline_merge_records(&merges).unwrap_err();
        assert!(err.contains("aggregate"), "unexpected sender refusal: {err}");

        let wire = (0..MAX_INLINE_MERGES)
            .map(|i| {
                encode_inline_merge(
                    &format!("merge-{i}.json"),
                    InlineMergeBody::Object {
                        id: ObjId([i as u8; 32]),
                        size: each as u64,
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let err = decode_inline_merges(&wire).err().expect("aggregate markers must fail closed");
        assert!(err.contains("aggregate"), "unexpected receiver refusal: {err}");
    }

    #[tokio::test]
    async fn merge_delta_preparation_gate_deduplicates_one_object() {
        let fetcher = RuntimeEdxFetcher::new(AppState::new("prepare-gate"), String::new(), None);
        let id = ObjId::of(b"shared merge delta");
        let first = fetcher.merge_prepare_gate(id);
        let second = fetcher.merge_prepare_gate(id);
        assert!(Arc::ptr_eq(&first, &second));

        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_calls = calls.clone();
        let second_calls = calls.clone();
        let (a, b) = tokio::join!(
            first.get_or_init(|| async move {
                first_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::task::yield_now().await;
                Ok(())
            }),
            second.get_or_init(|| async move {
                second_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }),
        );
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn an_evicted_merge_delta_is_prepared_again_before_later_fanout() {
        let state = AppState::new("prepare-after-eviction");
        let fetcher = RuntimeEdxFetcher::new(state, String::new(), None);
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let records = br#"{"record_format":"epix-orset-1","posts":[{"id":1}]}"#.to_vec();
        let id = ObjId::of(&records);
        let payload = Arc::new(UpdatePayload {
            merge_deltas: HashMap::from([("posts.json".to_string(), records)]),
            ..UpdatePayload::default()
        });

        {
            let prepared = fetcher
                .prepare_merge_delta_objects(&store, payload.clone(), None)
                .await
                .expect("first fanout prepares the merge object");
            assert_eq!(
                prepared.objects.get("posts.json").map(|object| object.id),
                Some(id)
            );
            assert!(store.contains(id).unwrap());
        }
        store.enforce_quota(0).unwrap();
        assert!(
            !store.contains(id).unwrap(),
            "the first fanout object was evicted"
        );

        let prepared = fetcher
            .prepare_merge_delta_objects(&store, payload, None)
            .await
            .expect("later fanout reinserts an evicted merge object");
        assert_eq!(
            prepared.objects.get("posts.json").map(|object| object.id),
            Some(id)
        );
        assert!(
            store.contains(id).unwrap(),
            "an object must exist before it is advertised to the later peer"
        );
    }

    /// A rejected update must not become a propagation hint. Otherwise peers
    /// can announce a version whose files they never verified or obtained.
    #[tokio::test]
    async fn a_rejected_edx_update_does_not_record_a_gossip_hint() {
        let state = AppState::new("relay");
        let store = Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new()));
        state.set_prop_store(store.clone());
        let provider = AppStateProvider { state: state.clone() };

        let res = provider
            .apply_update(
                "1SomeXite",
                "content.json",
                b"{}",
                &[],
                4242.0,
                &[],
                &[],
                disconnected_update_source(),
            )
            .await;
        assert!(res.is_err(), "a xite we don't host is rejected: {res:?}");

        let (hints, head) = store.lock().await.since(0);
        assert_eq!(head, 0);
        assert!(hints.is_empty(), "a rejected update must not be advertised");
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

        // --- Node B (receiver): a forum xite holding v1 of alice's posts ---
        let xite_pk = epix_crypt::new_seed();
        let xite_addr = epix_crypt::privatekey_to_address(&xite_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user_addr = epix_crypt::privatekey_to_address(&user_pk).unwrap();
        let user_dir = format!("data/users/{user_addr}");

        let b_dir = tempfile::tempdir().unwrap();
        let b_path = b_dir.path().to_path_buf();
        let storage = XiteStorage::new(b_dir.path());
        // The signed user_contents parent (plus the signed root authorizing
        // it) the pushed child verifies against.
        let (parent_bytes, root_bytes, root) = signed_user_chain(
            &xite_addr,
            &xite_pk,
            serde_json::json!({
                "cert_signers": {},
                "permissions": {},
                "permission_rules": { ".*": { "max_size": 100000 } },
            }),
        );
        storage.write("content.json", &root_bytes).unwrap();
        storage.write("data/users/content.json", &parent_bytes).unwrap();
        let data_v1: &[u8] = br#"{ "posts": [ {"post_id":1,"title":"First"} ] }"#;
        storage.write(&format!("{user_dir}/data.json"), data_v1).unwrap();
        let mut c1 = serde_json::json!({
            "address": xite_addr,
            "inner_path": format!("{user_dir}/content.json"),
            "modified": 1000,
            "files": { "data.json": { "size": data_v1.len(), "sha512": XiteStorage::hash_bytes(data_v1) } },
        });
        epix_content::sign(&mut c1, &user_pk).unwrap();
        storage
            .write(&format!("{user_dir}/content.json"), &serde_json::to_vec(&c1).unwrap())
            .unwrap();

        let state_b = AppState::new("node-b");
        state_b
            .add_xite(&xite_addr, XiteEntry { storage: XiteStorage::new(&b_path), content: Some(root) })
            .await;
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(test_store(store_dir.path(), b_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
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
                false,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // --- Node A (publisher): v2 adds a reply; push the signed child + diff ---
        let data_v2: &[u8] =
            br#"{ "posts": [ {"post_id":1,"title":"First"}, {"post_id":2,"title":"Reply"} ] }"#;
        let mut c2 = serde_json::json!({
            "address": xite_addr,
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
        state_a
            .set_edx_store(Arc::new(Store::open(a_store_dir.path()).unwrap()))
            .await
            .unwrap();
        std::mem::forget(a_store_dir);
        let fetcher =
            RuntimeEdxFetcher::new(state_a.clone(), epix_crypt::new_seed(), None);

        let progress = Arc::new(epix_ui::state::EdxPushProgress::default());
        let pushed = fetcher
            .push_update(
                epix_core::PeerAddr::Ip(addr),
                &xite_addr,
                &format!("{user_dir}/content.json"),
                Arc::new(serde_json::to_vec(&c2).unwrap()),
                2000.0,
                Arc::new(UpdatePayload {
                    diffs,
                    merge_deltas: HashMap::new(),
                    merge_objects: HashMap::new(),
                    require_merge_delivery: false,
                }),
                Arc::new(Vec::new()),
                progress.clone(),
            )
            .await;
        assert!(pushed.is_ok(), "the peer accepted the EDX update push");
        assert!(
            progress.linked.load(std::sync::atomic::Ordering::Relaxed),
            "the link came up"
        );

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
            hints.iter().any(|h| h.xite == xite_addr && h.modified == 2000),
            "the EDX update recorded a propagation hint, got {hints:?}"
        );
    }

    /// The common EpixPost/EpixTalk path stays entirely inside one Update
    /// round trip: negotiate INLINE_MERGE, verify the signed record against the
    /// pushed child manifest, union it, and only then answer Ok. The publisher
    /// has no advertised dial-back address and the receiver has no transport,
    /// so no pull or later anti-entropy pass can make this assertion pass.
    #[tokio::test]
    async fn portless_publisher_delivers_small_inline_post_before_update_ack() {
        let xite_key = epix_crypt::new_seed();
        let xite_addr = epix_crypt::privatekey_to_address(&xite_key).unwrap();
        let author_key = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&author_key).unwrap();
        let user_dir = format!("data/users/{author}");
        let child_path = format!("{user_dir}/content.json");
        let posts_path = format!("{user_dir}/posts.json");
        let (parent_bytes, root_bytes, root) = signed_user_chain(
            &xite_addr,
            &xite_key,
            serde_json::json!({
                "cert_signers": {},
                "permissions": {},
                "permission_rules": {
                    ".*": {
                        "max_size": 1_000_000,
                        "merge_files": {
                            "posts.json": {
                                "class": "epix-orset-1",
                                "max_size": 1_000_000
                            }
                        }
                    }
                }
            }),
        );
        let mut old_child = serde_json::json!({
            "address": xite_addr,
            "inner_path": child_path,
            "modified": 1000,
            "files": {},
            "files_merged": { "posts.json": { "class": "epix-orset-1" } }
        });
        epix_content::sign(&mut old_child, &author_key).unwrap();
        let mut new_child = old_child.clone();
        new_child["modified"] = serde_json::json!(2000);
        new_child.as_object_mut().unwrap().remove("signs");
        epix_content::sign(&mut new_child, &author_key).unwrap();
        let new_child_bytes = serde_json::to_vec(&new_child).unwrap();

        let nonce = epix_crypt::new_seed();
        let date_added = now_secs() as i64;
        let mut record = serde_json::json!({
            "post_id": epix_content::derive_post_id(&author, &nonce, date_added),
            "nonce": nonce,
            "author": author,
            "clock": epix_core::now_ms(),
            "supersedes": 0,
            "deleted": false,
            "body": "visible before the Update ACK",
            "date_added": date_added,
        });
        let record_sign =
            epix_crypt::sign(&epix_content::record_signed_data(&record), &author_key).unwrap();
        record["sign"] = serde_json::json!(record_sign.clone());
        let delta = serde_json::to_vec(&epix_content::make_container(vec![record])).unwrap();
        assert!(delta.len() < MAX_INLINE_MERGE_BYTES);

        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_storage = XiteStorage::new(receiver_dir.path());
        receiver_storage.write("content.json", &root_bytes).unwrap();
        receiver_storage
            .write("data/users/content.json", &parent_bytes)
            .unwrap();
        receiver_storage
            .write(&child_path, &serde_json::to_vec(&old_child).unwrap())
            .unwrap();
        receiver_storage
            .write(
                &posts_path,
                &serde_json::to_vec(&epix_content::make_container(Vec::new())).unwrap(),
            )
            .unwrap();
        let receiver = AppState::new("receiver-small-inline");
        receiver
            .add_xite(
                &xite_addr,
                XiteEntry {
                    storage: receiver_storage.clone(),
                    content: Some(root.clone()),
                },
            )
            .await;
        let receiver_store_dir = tempfile::tempdir().unwrap();
        let receiver_store = Arc::new(test_store(
            receiver_store_dir.path(),
            receiver_dir.path(),
        ));
        receiver
            .set_edx_store(receiver_store.clone())
            .await
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            receiver,
            receiver_store.clone(),
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        let server_task = tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        let publisher_dir = tempfile::tempdir().unwrap();
        let publisher_storage = XiteStorage::new(publisher_dir.path());
        publisher_storage.write("content.json", &root_bytes).unwrap();
        publisher_storage
            .write("data/users/content.json", &parent_bytes)
            .unwrap();
        publisher_storage.write(&child_path, &new_child_bytes).unwrap();
        publisher_storage.write(&posts_path, &delta).unwrap();
        let publisher = AppState::new("publisher-small-inline");
        publisher
            .add_xite(
                &xite_addr,
                XiteEntry {
                    storage: publisher_storage,
                    content: Some(root),
                },
            )
            .await;
        publisher.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let publisher_store_dir = tempfile::tempdir().unwrap();
        publisher
            .set_edx_store(Arc::new(test_store(
                publisher_store_dir.path(),
                publisher_dir.path(),
            )))
            .await
            .unwrap();
        assert!(publisher.own_dialable_addresses().await.is_empty());
        let fetcher = RuntimeEdxFetcher::new(publisher, epix_crypt::new_seed(), None);

        let progress = Arc::new(epix_ui::state::EdxPushProgress::default());
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fetcher.push_update(
                PeerAddr::Ip(receiver_addr),
                &xite_addr,
                &child_path,
                Arc::new(new_child_bytes),
                2000.0,
                Arc::new(UpdatePayload {
                    diffs: HashMap::new(),
                    merge_deltas: HashMap::from([("posts.json".to_string(), delta.clone())]),
                    merge_objects: HashMap::new(),
                    require_merge_delivery: false,
                }),
                Arc::new(Vec::new()),
                progress.clone(),
            ),
        )
        .await
        .expect("small inline delivery must finish in one short round trip");
        assert!(matches!(pushed, Ok(true)), "the capable peer acknowledged the inline payload");
        assert!(
            !progress.active.load(std::sync::atomic::Ordering::Relaxed),
            "a handshake plus inline ACK is not reverse-transfer activity"
        );

        let received: serde_json::Value =
            serde_json::from_slice(&receiver_storage.read(&posts_path).unwrap()).unwrap();
        assert!(epix_content::records_of(&received).iter().any(|record| {
            record.get("sign").and_then(serde_json::Value::as_str) == Some(record_sign.as_str())
        }));
        assert!(
            !receiver_store.contains(ObjId::of(&delta)).unwrap(),
            "a small delta rode inline rather than the immutable-object fallback"
        );
        server_task.abort();
    }

    /// A publisher behind NAT has no address the receiver can dial. Its mature
    /// posts.json is already past GetSigned's 8 MiB cap, and the new signed
    /// delta is too large for the Update frame. The receiver must therefore
    /// stream the immutable delta object over the exact outbound session.
    #[tokio::test]
    async fn portless_publisher_reverse_serves_large_merge_on_its_update_session() {
        let xite_key = epix_crypt::new_seed();
        let xite_addr = epix_crypt::privatekey_to_address(&xite_key).unwrap();
        let author_key = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&author_key).unwrap();
        let user_dir = format!("data/users/{author}");
        let child_path = format!("{user_dir}/content.json");
        let posts_path = format!("{user_dir}/posts.json");

        let (parent_bytes, root_bytes, root) = signed_user_chain(
            &xite_addr,
            &xite_key,
            serde_json::json!({
                "cert_signers": {},
                "permissions": {},
                "permission_rules": {
                    ".*": {
                        "max_size": 20_000_000,
                        "merge_files": {
                            "posts.json": {
                                "class": "epix-orset-1",
                                "max_size": 20_000_000
                            }
                        }
                    }
                }
            }),
        );
        let mut old_child = serde_json::json!({
            "address": xite_addr,
            "inner_path": child_path,
            "modified": 1000,
            "files": {},
            "files_merged": {
                "posts.json": { "class": "epix-orset-1" }
            }
        });
        epix_content::sign(&mut old_child, &author_key).unwrap();
        let mut new_child = old_child.clone();
        new_child["modified"] = serde_json::json!(2000);
        new_child.as_object_mut().unwrap().remove("signs");
        epix_content::sign(&mut new_child, &author_key).unwrap();
        let new_child_bytes = serde_json::to_vec(&new_child).unwrap();

        let base_nonce = epix_crypt::new_seed();
        let base_date = now_secs() as i64 - 1;
        let mut base_record = serde_json::json!({
            "post_id": epix_content::derive_post_id(&author, &base_nonce, base_date),
            "nonce": base_nonce,
            "author": author,
            "clock": epix_core::now_ms().saturating_sub(1),
            "supersedes": 0,
            "deleted": false,
            "body": "b".repeat(MAX_SIGNED_BYTES as usize + 1024),
            "date_added": base_date,
        });
        let base_sign =
            epix_crypt::sign(&epix_content::record_signed_data(&base_record), &author_key).unwrap();
        base_record["sign"] = serde_json::json!(base_sign);
        let base_posts =
            serde_json::to_vec(&epix_content::make_container(vec![base_record.clone()])).unwrap();
        assert!(
            base_posts.len() as u64 > MAX_SIGNED_BYTES,
            "the existing merge file must be impossible to serve via GetSigned"
        );

        let nonce = epix_crypt::new_seed();
        let date_added = now_secs() as i64;
        let mut record = serde_json::json!({
            "post_id": epix_content::derive_post_id(&author, &nonce, date_added),
            "nonce": nonce,
            "author": author,
            "clock": epix_core::now_ms(),
            "supersedes": 0,
            "deleted": false,
            "body": "x".repeat(MAX_INLINE_MERGE_BYTES + 8 * 1024),
            "date_added": date_added,
        });
        let record_sign =
            epix_crypt::sign(&epix_content::record_signed_data(&record), &author_key).unwrap();
        record["sign"] = serde_json::json!(record_sign);
        let delta =
            serde_json::to_vec(&epix_content::make_container(vec![record.clone()])).unwrap();
        let delta_id = ObjId::of(&delta);
        let published_posts =
            serde_json::to_vec(&epix_content::make_container(vec![base_record, record])).unwrap();
        assert!(
            delta.len() > MAX_INLINE_MERGE_BYTES,
            "the merge delta must be too large for Update.inline"
        );

        // Receiver. It can accept the publisher's TCP connection, but it has
        // no outbound transport and receives no advertised dial-back address.
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_storage = XiteStorage::new(receiver_dir.path());
        receiver_storage.write("content.json", &root_bytes).unwrap();
        receiver_storage
            .write("data/users/content.json", &parent_bytes)
            .unwrap();
        receiver_storage
            .write(&child_path, &serde_json::to_vec(&old_child).unwrap())
            .unwrap();
        receiver_storage.write(&posts_path, &base_posts).unwrap();
        let receiver = AppState::new("receiver");
        receiver
            .add_xite(
                &xite_addr,
                XiteEntry {
                    storage: receiver_storage.clone(),
                    content: Some(root.clone()),
                },
            )
            .await;
        let receiver_store_dir = tempfile::tempdir().unwrap();
        let receiver_store = Arc::new(test_store(
            receiver_store_dir.path(),
            receiver_dir.path(),
        ));
        receiver
            .set_edx_store(receiver_store.clone())
            .await
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            receiver.clone(),
            receiver_store.clone(),
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        let server_task = tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // Portless publisher. Its xite tree is served by the reverse request
        // loop attached to the same connection used for Req::Update.
        let publisher_dir = tempfile::tempdir().unwrap();
        let publisher_storage = XiteStorage::new(publisher_dir.path());
        publisher_storage.write("content.json", &root_bytes).unwrap();
        publisher_storage
            .write("data/users/content.json", &parent_bytes)
            .unwrap();
        publisher_storage.write(&child_path, &new_child_bytes).unwrap();
        publisher_storage.write(&posts_path, &published_posts).unwrap();
        let publisher = AppState::new("publisher");
        publisher
            .add_xite(
                &xite_addr,
                XiteEntry {
                    storage: publisher_storage,
                    content: Some(root),
                },
            )
            .await;
        publisher.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let publisher_store_dir = tempfile::tempdir().unwrap();
        publisher
            .set_edx_store(Arc::new(test_store(
                publisher_store_dir.path(),
                publisher_dir.path(),
            )))
            .await
            .unwrap();
        assert!(
            publisher.own_dialable_addresses().await.is_empty(),
            "the publisher must not advertise a reverse-dial route"
        );
        let fetcher = RuntimeEdxFetcher::new(publisher, epix_crypt::new_seed(), None);
        let payload = UpdatePayload {
            diffs: HashMap::new(),
            merge_deltas: HashMap::from([("posts.json".to_string(), delta)]),
            merge_objects: HashMap::new(),
            require_merge_delivery: false,
        };

        let progress = Arc::new(epix_ui::state::EdxPushProgress::default());
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            fetcher.push_update(
                PeerAddr::Ip(receiver_addr),
                &xite_addr,
                &child_path,
                Arc::new(new_child_bytes),
                2000.0,
                Arc::new(payload),
                Arc::new(Vec::new()),
                progress.clone(),
            ),
        )
        .await
        .expect("same-session pull must complete well below the gossip interval");
        assert!(
            matches!(pushed, Ok(true)),
            "the receiver acknowledged durable merge delivery"
        );
        assert!(
            progress.active.load(std::sync::atomic::Ordering::Relaxed),
            "the same-session object pull marks real reverse activity"
        );

        // Req::Update is answered only after the receiver's synchronous merge
        // pull. No polling is needed here: the record must already be on disk.
        let received: serde_json::Value =
            serde_json::from_slice(&receiver_storage.read(&posts_path).unwrap()).unwrap();
        let received = epix_content::records_of(&received);
        assert_eq!(received.len(), 2, "the new post joined the mature base before ACK");
        assert!(
            received.iter().any(|record| {
                record.get("sign").and_then(serde_json::Value::as_str)
                    == Some(record_sign.as_str())
            }),
            "the receiver stored the signed publisher delta record"
        );
        assert!(receiver_store.is_complete(delta_id).unwrap(), "the delta object hash completed");
        server_task.abort();
    }

    /// A non-inline hashed file follows the same NAT-safe path as a large
    /// merge file. The receiver verifies and materializes the object from the
    /// publisher's outbound Update session before advertising the new version.
    #[tokio::test]
    async fn portless_publisher_reverse_serves_large_hashed_file_before_hint() {
        let xite_key = epix_crypt::new_seed();
        let xite_addr = epix_crypt::privatekey_to_address(&xite_key).unwrap();
        let author_key = epix_crypt::new_seed();
        let author = epix_crypt::privatekey_to_address(&author_key).unwrap();
        let user_dir = format!("data/users/{author}");
        let child_path = format!("{user_dir}/content.json");
        let file_path = format!("{user_dir}/large.bin");

        let (parent_bytes, root_bytes, root) = signed_user_chain(
            &xite_addr,
            &xite_key,
            serde_json::json!({
                "cert_signers": {},
                "permissions": {},
                "permission_rules": { ".*": { "max_size": 8 * 1024 * 1024 } }
            }),
        );
        let mut old_child = serde_json::json!({
            "address": xite_addr,
            "inner_path": child_path,
            "modified": 1000,
            "files": {}
        });
        epix_content::sign(&mut old_child, &author_key).unwrap();

        // Multiple object groups make this a verified range transfer, not a
        // small control-frame payload or a one-chunk fixture.
        let large_file: Vec<u8> = (0usize..2 * 1024 * 1024 + 317)
            .map(|i| (i.wrapping_mul(31) % 251) as u8)
            .collect();
        let file_id = ObjId::of(&large_file);
        let file_sha512 = XiteStorage::hash_bytes(&large_file);
        let mut new_child = serde_json::json!({
            "address": xite_addr,
            "inner_path": child_path,
            "modified": 2000,
            "files": {
                "large.bin": {
                    "size": large_file.len(),
                    "sha512": file_sha512,
                    "b3": file_id.to_string()
                }
            }
        });
        epix_content::sign(&mut new_child, &author_key).unwrap();
        let new_child_bytes = serde_json::to_vec(&new_child).unwrap();

        // Receiver. It has no outbound transport and starts without the file
        // or a propagation hint for the incoming child version. Its tree uses
        // the production `<data_dir>/data/<address>` layout: the inbound
        // hashed-file promotion stages under `<data>/.epix-stage`, and the
        // object store only adopts/materializes paths inside its xite root.
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_data_root = receiver_dir.path().join("data");
        let receiver_xite_dir = receiver_data_root.join(&xite_addr);
        let receiver_storage = XiteStorage::new(&receiver_xite_dir);
        receiver_storage.write("content.json", &root_bytes).unwrap();
        receiver_storage
            .write("data/users/content.json", &parent_bytes)
            .unwrap();
        receiver_storage
            .write(&child_path, &serde_json::to_vec(&old_child).unwrap())
            .unwrap();
        let receiver = AppState::new("receiver-large-file");
        receiver
            .add_xite(
                &xite_addr,
                XiteEntry {
                    storage: receiver_storage.clone(),
                    content: Some(root.clone()),
                },
            )
            .await;
        let receiver_store_dir = tempfile::tempdir().unwrap();
        let receiver_store = Arc::new(test_store(
            receiver_store_dir.path(),
            &receiver_data_root,
        ));
        receiver
            .set_edx_store(receiver_store.clone())
            .await
            .unwrap();
        let receiver_hints =
            Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new()));
        receiver.set_prop_store(receiver_hints.clone());
        assert!(!receiver_storage.exists(&file_path));
        assert!(receiver_hints.lock().await.since(0).0.is_empty());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            receiver.clone(),
            receiver_store.clone(),
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        let server_task = tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // Publisher. The object store adopts the signed child file for range
        // serving, but the node advertises no address the receiver can dial.
        let publisher_dir = tempfile::tempdir().unwrap();
        let publisher_storage = XiteStorage::new(publisher_dir.path());
        publisher_storage.write("content.json", &root_bytes).unwrap();
        publisher_storage
            .write("data/users/content.json", &parent_bytes)
            .unwrap();
        publisher_storage.write(&child_path, &new_child_bytes).unwrap();
        publisher_storage.write(&file_path, &large_file).unwrap();
        let publisher = AppState::new("publisher-large-file");
        publisher
            .add_xite(
                &xite_addr,
                XiteEntry {
                    storage: publisher_storage,
                    content: Some(root),
                },
            )
            .await;
        publisher.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let publisher_store_dir = tempfile::tempdir().unwrap();
        let publisher_store = Arc::new(test_store(
            publisher_store_dir.path(),
            publisher_dir.path(),
        ));
        publisher
            .set_edx_store(publisher_store.clone())
            .await
            .unwrap();
        let registered = publisher
            .edx_register_xite(&xite_addr)
            .await
            .expect("the signed child is EDX-registerable");
        assert!(registered.0 > 0, "the publisher registered at least one object");
        assert!(publisher_store.contains(file_id).unwrap(), "the large file is serveable");
        assert!(
            publisher.own_dialable_addresses().await.is_empty(),
            "the publisher must not advertise a reverse-dial route"
        );

        let fetcher = RuntimeEdxFetcher::new(publisher, epix_crypt::new_seed(), None);
        let progress = Arc::new(epix_ui::state::EdxPushProgress::default());
        let pushed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fetcher.push_update(
                PeerAddr::Ip(receiver_addr),
                &xite_addr,
                &child_path,
                Arc::new(new_child_bytes),
                2000.0,
                Arc::new(UpdatePayload::default()),
                Arc::new(Vec::new()),
                progress.clone(),
            ),
        )
        .await
        .expect("the outbound Update session connected");
        assert!(matches!(pushed, Ok(true)), "the child manifest was accepted");
        assert!(
            progress.active.load(std::sync::atomic::Ordering::Relaxed),
            "the same-session file pull marks real reverse activity"
        );

        // The hint is persistent. Whenever it first becomes observable, the
        // file must already exist and verify against the signed SHA-512 entry.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let file_ready = receiver_storage.verify(&file_path, &file_sha512);
            let hinted = receiver_hints
                .lock()
                .await
                .since(0)
                .0
                .iter()
                .any(|hint| hint.xite == xite_addr && hint.modified == 2000);
            if hinted {
                assert!(file_ready, "the propagation hint preceded the verified file");
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the reverse-session file transfer never produced a propagation hint"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(receiver_storage.read(&file_path).unwrap(), large_file);
        assert!(receiver_store.contains(file_id).unwrap());
        assert!(receiver_store.is_complete(file_id).unwrap());
        server_task.abort();
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
        let xite_dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(xite_dir.path());
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
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        state_b
            .add_xite(&address, XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None })
            .await;
        assert!(state_b.load_content_from_disk(&address).await, "load stores shard ciphertext");
        std::mem::forget(xite_dir);
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
                false,
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
        state_a
            .set_edx_store(Arc::new(test_store(a_store_dir.path(), a_dir.path())))
            .await
            .unwrap();
        state_a
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_a.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        state_a.add_peers(&address, [epix_core::PeerAddr::Ip(addr)]).await;

        // Fetch the shard file: fetch ciphertext shards over EDX, decrypt.
        let result = state_a.edx_fetch_file(&address, "private/secret.txt", false).await;
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
        state_a
            .set_edx_store(Arc::new(test_store(a_store_dir.path(), a_dir.path())))
            .await
            .unwrap();
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

        assert!(state_a.edx_fetch_file(&address, "movie.bin", false).await.unwrap().is_ok());

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
        let store_dir = tempfile::tempdir().unwrap();
        let xite_root = tempfile::tempdir().unwrap();
        state_a
            .set_edx_store(Arc::new(test_store(store_dir.path(), xite_root.path())))
            .await
            .unwrap();
        std::mem::forget(store_dir);
        std::mem::forget(xite_root);
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
        let xite_dir = tempfile::tempdir().unwrap();
        let state_b = AppState::new("node-b");
        state_b
            .add_xite(
                &address,
                XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None },
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
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        std::mem::forget(xite_dir);
        std::mem::forget(store_dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state_b.clone(),
            store_b,
            epix_crypt::new_seed(),
            None,
            control,
            false,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });

        // Client: no xites, just the EDX stack.
        let state_a = AppState::new("node-a");
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        state_a
            .set_edx_store(Arc::new(Store::open(a_store_dir.path()).unwrap()))
            .await
            .unwrap();
        std::mem::forget(a_store_dir);
        let fetcher =
            RuntimeEdxFetcher::new(state_a.clone(), epix_crypt::new_seed(), None);
        let peer = PeerAddr::Ip(addr);

        // The handshake advertises the control plane and the release version.
        let transport = state_a.transport().await.unwrap();
        let (_conn, identity, _reg, _reverse, _activity) =
            fetcher.dial(&transport, &peer, 0).await.unwrap();
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
        state
            .set_edx_store(Arc::new(Store::open(dir.path()).unwrap()))
            .await
            .unwrap();
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

        // Letting the warm handle go no longer ends the link: the pool keeps it,
        // so the next caller to want this peer gets THIS connection instead of
        // dialing a second one beside it (over Tor, a second circuit).
        drop(link);
        let again = fetcher.open_link(peer.clone()).await.expect("warm link");
        let rows: Vec<_> = epix_protocol::registry::snapshot()
            .into_iter()
            .filter(|s| s.addr == peer && s.peer.as_ref().is_some_and(|p| p.protocol == "edx"))
            .collect();
        assert_eq!(rows.len(), 1, "one peer must mean one link, not a row per caller: {rows:?}");
        assert_eq!(rows[0].id, row.id, "the second caller reused the link rather than redialing");

        // Kept, but not forever: once the pool lets go and no caller holds it,
        // the IO tasks end and the row leaves the Stats page.
        drop(again);
        fetcher.link_pool.evict(&peer);
        let delisted = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !epix_protocol::registry::snapshot().iter().any(|s| s.addr == peer) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert_eq!(delisted, Ok(true), "a link nobody holds leaves the Stats page");
    }

    /// The health prober's full arc over a real socket: two peers restored
    /// from peers.json mid-failure-streak (benched, cooldown already expired -
    /// the restore shape, so the test never waits out a ~30s cooldown). One
    /// answers the probe's dial + Ping and is reinstated - visible through
    /// `connectable_peers` - the other refuses the dial and steps to its next
    /// cooldown, staying benched.
    #[tokio::test]
    async fn probe_pass_reinstates_a_recovered_peer_and_rebenches_a_dead_one() {
        let (_address, _content_bytes, _content, _movie, addr, _pk) = spawn_seeder().await;
        let alive = PeerAddr::Ip(addr);
        // A dead peer: bind a port, then drop the listener so dials are refused.
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = PeerAddr::Ip(dead_listener.local_addr().unwrap());
        drop(dead_listener);

        let root = tempfile::tempdir().unwrap();
        let xite = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        std::fs::create_dir_all(root.path().join("private")).unwrap();
        std::fs::write(
            root.path().join("private/peers.json"),
            serde_json::to_vec(&serde_json::json!({
                xite: [
                    { "addr": alive.to_string(), "rep": -3, "errors": 3, "seen": 0 },
                    { "addr": dead.to_string(), "rep": -3, "errors": 3, "seen": 0 },
                ],
            }))
            .unwrap(),
        )
        .unwrap();
        let state = AppState::with_data_dir("client", root.path());
        state.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let store_dir = tempfile::tempdir().unwrap();
        state
            .set_edx_store(Arc::new(Store::open(store_dir.path()).unwrap()))
            .await
            .unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        state
            .add_xite(xite, XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None })
            .await;

        // Both restored peers are benched and due a probe.
        let due = state.probe_candidates(10).await;
        assert_eq!(due.len(), 2, "{due:?}");
        assert!(due.iter().all(|c| c.failures == 3), "{due:?}");

        let opener: Arc<dyn LinkOpener> =
            Arc::new(RuntimeEdxFetcher::new(state.clone(), epix_crypt::new_seed(), None));
        crate::probe_pass(&state, opener).await;

        // The answering peer is back in selection (dial backoff lifted; its
        // streak waits for a real fetch to clear); the refusing one is in a
        // (grown) backoff, and neither is due another probe before its
        // re-armed cooldown.
        let connectable = state.connectable_peers(xite, 10).await;
        assert!(connectable.contains(&alive), "recovered peer reinstated: {connectable:?}");
        assert!(!connectable.contains(&dead), "dead peer stays benched: {connectable:?}");
        assert!(state.probe_candidates(10).await.is_empty());
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
        state_b.set_edx_store(store_b.clone()).await.unwrap();
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
            false,
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
            state
                .set_edx_store(Arc::new(test_store(sd.path(), dir.path())))
                .await
                .unwrap();
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
        assert!(c1.edx_fetch_file(&address, "index.html", false).await.unwrap().is_ok());
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
        assert!(c3.edx_fetch_file(&address, "movie.bin", false).await.unwrap().is_ok());
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

    /// The production topology exactly: ConnHandle::attach + tap_inbound +
    /// serve, with a peer that Hellos then goes silent while holding the
    /// socket open. The registry row must disappear once the idle reaper
    /// fires; a row that outlives IDLE_TIMEOUT is the /Stats leak.
    #[tokio::test(start_paused = true)]
    async fn idle_inbound_link_delists_from_the_registry() {
        let peer = PeerAddr::parse("198.51.100.7:26552").unwrap();
        let (srv_io, cli_io) = tokio::io::duplex(64 * 1024);

        let state = AppState::new("reap-test");
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        std::mem::forget(dir);
        let ctx = ServeCtx::new(
            store,
            Arc::new(AppStateProvider { state: state.clone() }),
            epix_crypt::new_seed(),
        );

        // Exactly what edx_hook_overlay does.
        let (reg, stream) = ConnHandle::new(Direction::In, peer.clone()).attach(Box::pin(srv_io));
        let server = tokio::spawn({
            let peer = peer.clone();
            async move {
                let (conn, incoming) = epix_edx::link::accept_overlay(stream).await.unwrap();
                let incoming = tap_inbound(reg, incoming, peer, None, Arc::new(Mutex::new(None)));
                serve(conn, incoming, Arc::new(ctx), None).await
            }
        });

        // Client: Hello, then silence, holding the link open.
        let (conn, _in) = epix_edx::link::dial_overlay(Box::pin(cli_io)).await.unwrap();
        let cdir = tempfile::tempdir().unwrap();
        let cstore = Arc::new(Store::open(cdir.path()).unwrap());
        std::mem::forget(cdir);
        let cctx = ServeCtx::new(
            cstore,
            Arc::new(AppStateProvider { state: AppState::new("client") }),
            epix_crypt::new_seed(),
        );
        client_hello(&conn, &cctx, vec![], None).await.unwrap();

        // The row is listed while the link is live.
        let listed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if epix_protocol::registry::snapshot().iter().any(|s| s.addr == peer) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(listed.is_ok(), "the inbound link should be listed after Hello");

        // Walk past IDLE_TIMEOUT with the peer silent but still connected.
        tokio::time::sleep(epix_edx::server::IDLE_TIMEOUT + std::time::Duration::from_secs(30))
            .await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(60), server).await.is_ok(),
            "serve() never returned after IDLE_TIMEOUT"
        );

        // Give the writer/reader/tap tasks a chance to wind down.
        for _ in 0..500 {
            tokio::task::yield_now().await;
            if !epix_protocol::registry::snapshot().iter().any(|s| s.addr == peer) {
                return;
            }
        }
        let rows: Vec<_> = epix_protocol::registry::snapshot()
            .into_iter()
            .filter(|s| s.addr == peer)
            .map(|s| format!("id={} idle={}s open={}s", s.id, s.idle_secs, s.opened_secs))
            .collect();
        panic!("reaped link is STILL listed on /Stats: {rows:?}");
    }


    /// A stand-in for what a handshake established. The pool only carries the
    /// identity from dial to caller, so its contents do not matter here.
    fn test_identity() -> PeerIdentity {
        PeerIdentity {
            node_pk: vec![7; 32],
            address: String::new(),
            caps: 0,
            version: "test".into(),
        }
    }

    fn test_link_activity() -> LinkActivity {
        LinkActivityState::new()
    }

    #[tokio::test]
    async fn cancelling_an_update_closes_its_reverse_pull_session() {
        let (source_io, peer_io) = tokio::io::duplex(1024);
        let (source, _source_incoming) = Conn::start(source_io, true);
        let (_peer, _peer_incoming) = Conn::start(peer_io, false);
        let guard = UpdateRequestGuard::new(&source, true);

        drop(guard);

        assert!(
            source.is_closed(),
            "holds cannot release while a cancelled receiver can still pull"
        );
    }

    /// A pooled control link that nobody uses must be dropped, not held for the
    /// life of the process. A pooled Conn keeps its socket open, so a stale
    /// entry makes this node the peer that never sends FIN: the far end's idle
    /// reaper cannot free its socket either, and the Arc<ConnHandle> parked
    /// beside the Conn keeps a row on /Stats that no longer has traffic.
    #[tokio::test(start_paused = true)]
    async fn an_idle_pooled_control_link_is_swept() {
        let peer = PeerAddr::parse("198.51.100.11:26552").unwrap();
        let (a, _b) = tokio::io::duplex(4096);
        let (reg, stream) = ConnHandle::new(Direction::Out, peer.clone()).attach(Box::pin(a));
        let (conn, _incoming) = epix_edx::conn::Conn::start(stream, true);

        let pool = LinkPool::default();
        pool.store(
            peer.clone(),
            0,
            (conn, test_identity(), reg, None, test_link_activity()),
        );
        assert!(pool.live(&peer, 0).is_some(), "a fresh pooled link is reused");

        // Still fresh: a sweep must not cut a link that is being used.
        tokio::time::advance(LINK_POOL_IDLE / 2).await;
        assert!(pool.live(&peer, 0).is_some(), "a link used within the window survives");

        // `live` above refreshed activity, so the window restarts from there.
        tokio::time::advance(LINK_POOL_IDLE + std::time::Duration::from_secs(1)).await;
        assert!(pool.live(&peer, 0).is_none(), "an idle pooled link is swept");
        assert!(
            pool.conns.lock().expect("link pool").is_empty(),
            "the sweep must DROP the entry, not just decline to hand it out: the Conn and the \
             Arc<ConnHandle> it holds are what keep the socket and the Stats row alive"
        );
    }

    /// A portless publisher can spend minutes answering reverse range requests
    /// without borrowing its outbound link from the pool. Completed reverse
    /// work refreshes the shared activity clock so an unrelated pool sweep
    /// cannot abort that still-productive source session between requests.
    #[tokio::test(start_paused = true)]
    async fn reverse_request_activity_keeps_a_pooled_link_alive() {
        let peer = PeerAddr::parse("198.51.100.22:26552").unwrap();
        let (local, _remote) = tokio::io::duplex(4096);
        let (reg, stream) = ConnHandle::new(Direction::Out, peer.clone()).attach(Box::pin(local));
        let (conn, _incoming) = epix_edx::conn::Conn::start(stream, true);
        let task_conn = conn.clone();
        let reverse = tokio::spawn(async move {
            std::future::pending::<()>().await;
            drop(task_conn);
        });
        let activity = test_link_activity();

        let pool = LinkPool::default();
        pool.store(
            peer.clone(),
            0,
            (
                conn,
                test_identity(),
                reg,
                Some(reverse.abort_handle()),
                activity.clone(),
            ),
        );
        tokio::time::advance(LINK_POOL_IDLE + std::time::Duration::from_secs(1)).await;
        activity.note_reverse_request();

        assert!(
            pool.live(&peer, 0).is_some(),
            "a completed reverse request refreshes the source session"
        );
        pool.evict(&peer);
        assert!(reverse.await.unwrap_err().is_cancelled());
    }

    /// The outbound reverse-serve task intentionally holds a Conn clone. It
    /// must count as pool ownership, not active transfer use, and must be
    /// cancelled when the idle entry is evicted.
    #[tokio::test(start_paused = true)]
    async fn sweeping_a_pooled_link_stops_its_reverse_serve_loop() {
        let peer = PeerAddr::parse("198.51.100.21:26552").unwrap();
        let (local, _remote) = tokio::io::duplex(4096);
        let (reg, stream) = ConnHandle::new(Direction::Out, peer.clone()).attach(Box::pin(local));
        let (conn, _incoming) = epix_edx::conn::Conn::start(stream, true);
        let task_conn = conn.clone();
        let reverse = tokio::spawn(async move {
            std::future::pending::<()>().await;
            drop(task_conn);
        });

        let pool = LinkPool::default();
        pool.store(
            peer.clone(),
            0,
            (
                conn,
                test_identity(),
                reg,
                Some(reverse.abort_handle()),
                test_link_activity(),
            ),
        );
        tokio::time::advance(LINK_POOL_IDLE + std::time::Duration::from_secs(1)).await;
        assert!(pool.live(&peer, 0).is_none(), "the reverse task does not pin an idle link");
        assert!(reverse.await.unwrap_err().is_cancelled(), "eviction cancels reverse serving");
    }

    /// A pooled control link is opened ONCE however many callers ask for it at
    /// the same moment. The announce, PEX and updates loops fire on their own
    /// timers and converge on the same contacts, so a plain check-then-dial let
    /// each of them open a link to one peer: duplicate outbound rows on /Stats,
    /// and on Tor a separate circuit for every one of them.
    #[tokio::test]
    async fn concurrent_control_callers_share_one_dial() {
        let peer = PeerAddr::parse("198.51.100.12:26552").unwrap();
        let pool = Arc::new(LinkPool::default());
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Keep the duplex's far end alive for the length of the test: dropping
        // it closes the Conn, and a closed link is swept as dead on lookup.
        let held = Arc::new(Mutex::new(Vec::new()));

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (pool, dials, held, peer) =
                (pool.clone(), dials.clone(), held.clone(), peer.clone());
            set.spawn(async move {
                pool.get_or_dial(&peer, 0, || async {
                    dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // A real dial takes a handshake; yield so the racers pile up
                    // behind this one the way they do against a live peer.
                    tokio::task::yield_now().await;
                    let (a, b) = tokio::io::duplex(4096);
                    held.lock().expect("held").push(b);
                    let (reg, stream) =
                        ConnHandle::new(Direction::Out, peer.clone()).attach(Box::pin(a));
                    let (conn, _incoming) = epix_edx::conn::Conn::start(stream, true);
                    Ok((conn, test_identity(), reg, None, test_link_activity()))
                })
                .await
                .is_ok()
            });
        }
        let mut served = 0;
        while let Some(res) = set.join_next().await {
            if res.expect("task") {
                served += 1;
            }
        }

        assert_eq!(
            dials.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "eight concurrent control callers must share ONE dial to the peer, not open one each"
        );
        assert_eq!(served, 8, "every caller gets a link back");
        assert_eq!(pool.conns.lock().expect("link pool").len(), 1, "one pooled link per peer");
    }

    /// A link someone is still transferring over must survive the idle sweep.
    /// The pool's clock only advances when the pool is ASKED for the peer, and a
    /// bulk session runs for minutes without asking - so an idle-only rule drops
    /// the entry mid-transfer, frees nothing (the session still holds the
    /// socket) and lets the next caller dial a second link to a peer we are
    /// already talking to.
    #[tokio::test(start_paused = true)]
    async fn a_link_still_in_use_survives_the_idle_sweep() {
        let peer = PeerAddr::parse("198.51.100.14:26552").unwrap();
        let (a, _b) = tokio::io::duplex(4096);
        let (reg, stream) = ConnHandle::new(Direction::Out, peer.clone()).attach(Box::pin(a));
        let (conn, _incoming) = epix_edx::conn::Conn::start(stream, true);

        let pool = LinkPool::default();
        pool.store(
            peer.clone(),
            0,
            (conn.clone(), test_identity(), reg, None, test_link_activity()),
        );
        // `conn` here stands in for the session's handle: the pool is not the
        // only holder.
        tokio::time::advance(LINK_POOL_IDLE * 3).await;
        let hit = pool.live(&peer, 0);
        assert!(hit.is_some(), "a link with another holder is not swept, however long it is idle");
        drop(hit);

        // The session finishes and drops its handle. Now the pool is the last
        // holder, so the entry is ordinary idle state and the sweep takes it.
        drop(conn);
        tokio::time::advance(LINK_POOL_IDLE + std::time::Duration::from_secs(1)).await;
        assert!(pool.live(&peer, 0).is_none(), "once nobody is using it, an idle link is swept");
    }

    /// A dial that fails must not be retried by everyone queued behind it: each
    /// retry costs another connect timeout against a peer that just refused, and
    /// the next control op will try again on its own schedule anyway.
    #[tokio::test]
    async fn a_failed_control_dial_is_not_retried_by_the_racers() {
        let peer = PeerAddr::parse("198.51.100.13:26552").unwrap();
        let pool = Arc::new(LinkPool::default());
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let (pool, dials, peer) = (pool.clone(), dials.clone(), peer.clone());
            set.spawn(async move {
                pool.get_or_dial(&peer, 0, || async {
                    dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    Err::<OpenedLink, String>("unreachable".into())
                })
                .await
                .is_ok()
            });
        }
        while let Some(res) = set.join_next().await {
            assert!(!res.expect("task"), "a failed dial fails every caller");
        }

        assert_eq!(
            dials.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the racers must not each re-dial a peer that just failed"
        );
        assert!(pool.conns.lock().expect("link pool").is_empty(), "nothing cached on failure");
    }

    /// Lanes are separate links to the SAME peer, so the pool must key on both
    /// - keying on the peer alone would make lane 1 evict lane 0 on store and
    /// hand a caller asking for lane 2 whatever link happened to be there,
    /// collapsing the stripe back onto one circuit.
    #[tokio::test]
    async fn the_pool_keeps_one_link_per_lane() {
        let peer = PeerAddr::parse("198.51.100.12:26552").unwrap();
        let pool = LinkPool::default();
        for lane in 0..3u8 {
            let (a, _b) = tokio::io::duplex(4096);
            let (reg, stream) = ConnHandle::new(Direction::Out, peer.clone()).attach(Box::pin(a));
            let (conn, _incoming) = epix_edx::conn::Conn::start(stream, true);
            pool.store(
                peer.clone(),
                lane,
                (conn, test_identity(), reg, None, test_link_activity()),
            );
        }
        assert_eq!(pool.conns.lock().expect("link pool").len(), 3);
        for lane in 0..3u8 {
            assert!(pool.live(&peer, lane).is_some(), "lane {lane} must have its own link");
        }
        assert!(pool.live(&peer, 3).is_none(), "an undialed lane is not somebody else's link");

        // A failure is the PEER's, so eviction takes every lane with it.
        pool.evict(&peer);
        assert!(pool.conns.lock().expect("link pool").is_empty());
    }

    /// Striping only pays where a path has a per-circuit ceiling. A clearnet
    /// peer has none, and giving it extra lanes would just be extra sockets.
    #[test]
    fn only_overlay_peers_get_extra_lanes() {
        let clearnet = PeerAddr::parse("198.51.100.13:26552").unwrap();
        assert_eq!(lanes_for(&clearnet), 1);

        let onion = PeerAddr::parse(
            "onion://23ln3zocykjirek4fzujxrroxh2w5yrouobioeuxyjwbo2izsaduzxad.onion:26552",
        )
        .or_else(|_| {
            PeerAddr::parse("23ln3zocykjirek4fzujxrroxh2w5yrouobioeuxyjwbo2izsaduzxad.onion:26552")
        })
        .expect("onion address parses");
        assert!(onion.is_overlay());
        assert!(lanes_for(&onion) > 1, "an onion peer stripes across circuits");
        assert!(lanes_for(&onion) <= 4, "and the stripe stays bounded");
    }

    /// The per-peer gates are bookkeeping, not state: a node that dials a lot of
    /// peers over its life must not keep one around for every peer it ever saw.
    #[tokio::test]
    async fn idle_dial_gates_do_not_accumulate() {
        let pool = LinkPool::default();
        for i in 0..50u8 {
            let peer = PeerAddr::parse(&format!("198.51.100.{i}:26552")).unwrap();
            let _ = pool
                .get_or_dial(&peer, 0, || async {
                    Err::<OpenedLink, String>("unreachable".into())
                })
                .await;
        }
        let gates = pool.dialing.lock().expect("link pool").len();
        assert!(gates <= 1, "gates for peers nobody is dialing must be dropped, found {gates}");
    }

    /// A push whose signed content.json did not fit one frame arrives with an
    /// EMPTY body and must be pulled back over GetSigned. The EDX
    /// `SignedProvider` has no per-connection address, so the publisher's
    /// declared dial-back address is the only sender the fetch-back can use;
    /// without it every body-less push fails with "Can't download updated file".
    #[tokio::test]
    async fn a_body_less_update_is_fetched_back_from_the_publisher() {
        use epix_ui::state::XiteEntry;

        let xite_pk = epix_crypt::new_seed();
        let xite_addr = epix_crypt::privatekey_to_address(&xite_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user_addr = epix_crypt::privatekey_to_address(&user_pk).unwrap();
        let user_dir = format!("data/users/{user_addr}");
        let child_path = format!("{user_dir}/content.json");

        // The signed rules chain the pushed child verifies against, on both
        // nodes: a signed user_contents parent plus the signed root that
        // authorizes it.
        let (parent_bytes, root_bytes, root) = signed_user_chain(
            &xite_addr,
            &xite_pk,
            serde_json::json!({
                "cert_signers": {},
                "permissions": {},
                "permission_rules": { ".*": { "max_size": 100000 } },
            }),
        );
        let data: &[u8] = br#"{ "posts": [] }"#;
        let child = |modified: i64| {
            let mut c = serde_json::json!({
                "address": xite_addr,
                "inner_path": child_path,
                "modified": modified,
                "files": {
                    "data.json": { "size": data.len(), "sha512": XiteStorage::hash_bytes(data) }
                },
            });
            epix_content::sign(&mut c, &user_pk).unwrap();
            serde_json::to_vec(&c).unwrap()
        };

        // Publisher P: an EDX server that serves v2 of the child over GetSigned.
        let p_dir = tempfile::tempdir().unwrap();
        let p_storage = XiteStorage::new(p_dir.path());
        p_storage.write("content.json", &root_bytes).unwrap();
        p_storage.write("data/users/content.json", &parent_bytes).unwrap();
        p_storage.write(&child_path, &child(2000)).unwrap();
        let state_p = AppState::new("publisher");
        state_p
            .add_xite(&xite_addr, XiteEntry { storage: XiteStorage::new(p_dir.path()), content: None })
            .await;
        let p_store_dir = tempfile::tempdir().unwrap();
        let p_store = Arc::new(test_store(p_store_dir.path(), p_dir.path()));
        state_p.set_edx_store(p_store.clone()).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p_addr = listener.local_addr().unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state_p.clone(),
            p_store,
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        tokio::spawn(async move {
            let _ = server.serve(listener).await;
        });
        std::mem::forget(p_dir);
        std::mem::forget(p_store_dir);

        // Receiver R: holds v1 of the same child, and can dial P.
        let r_dir = tempfile::tempdir().unwrap();
        let r_storage = XiteStorage::new(r_dir.path());
        r_storage.write("content.json", &root_bytes).unwrap();
        r_storage.write("data/users/content.json", &parent_bytes).unwrap();
        r_storage.write(&child_path, &child(1000)).unwrap();
        r_storage.write(&format!("{user_dir}/data.json"), data).unwrap();
        let state_r = AppState::new("receiver");
        state_r
            .add_xite(
                &xite_addr,
                XiteEntry { storage: XiteStorage::new(r_dir.path()), content: Some(root) },
            )
            .await;
        state_r.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let r_store_dir = tempfile::tempdir().unwrap();
        state_r
            .set_edx_store(Arc::new(test_store(r_store_dir.path(), r_dir.path())))
            .await
            .unwrap();
        state_r
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state_r.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        std::mem::forget(r_dir);
        std::mem::forget(r_store_dir);

        // The push carries no body, only the publisher's dial-back addresses.
        // The FIRST one is dead (a bound-then-released port, so the dial is
        // refused at once): a publisher declares every address it might be
        // reachable at and only some of them work, so the refetch has to walk
        // past a dead entry instead of trying the head of the list alone.
        let dead = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let provider = AppStateProvider { state: state_r.clone() };
        let applied = provider
            .apply_update(
                &xite_addr,
                &child_path,
                &[],
                &[],
                2000.0,
                &[],
                &[PeerAddr::Ip(dead).to_string(), PeerAddr::Ip(p_addr).to_string()],
                disconnected_update_source(),
            )
            .await;
        assert_eq!(applied, Ok(true), "the body-less push was fetched back and applied");
    }

    /// `UpdatesSince` must not hand a peer the whole hint log in one reply: the
    /// log is peer-fillable, so the reply is capped and the cursor pages. The
    /// reported head has to stop at the last hint actually sent, or the poller
    /// would skip everything that was trimmed.
    #[tokio::test]
    async fn updates_since_caps_its_reply_and_pages_the_cursor() {
        let prop = Arc::new(tokio::sync::Mutex::new(epix_propagation::PropagationStore::new()));
        {
            let mut store = prop.lock().await;
            for i in 0..(MAX_UPDATES_PER_REPLY * 2) {
                store.record(&format!("xite{i}"), i as i64);
            }
        }
        let mut handles = ControlHandles::detached();
        handles.prop = prop.clone();
        let provider = RuntimeControlProvider {
            state: AppState::new("node"),
            handles,
            peer: PeerAddr::parse("9.9.9.9:26552").unwrap(),
            dialback: Arc::new(Mutex::new(None)),
        };

        let (first, head) = provider.updates_since(0).await;
        assert_eq!(first.len(), MAX_UPDATES_PER_REPLY, "the reply is capped");
        assert_eq!(first[0].0, "xite0");
        assert_eq!(
            first.last().unwrap().0,
            format!("xite{}", MAX_UPDATES_PER_REPLY - 1),
            "the cap trims the NEWEST entries, not the oldest"
        );
        assert_eq!(head, MAX_UPDATES_PER_REPLY as u64, "the cursor stops at the last hint sent");

        // The poller re-asks from the head it got: nothing is skipped.
        let (second, head2) = provider.updates_since(head).await;
        assert_eq!(second.len(), MAX_UPDATES_PER_REPLY);
        assert_eq!(second[0].0, format!("xite{}", MAX_UPDATES_PER_REPLY));
        assert_eq!(head2, (MAX_UPDATES_PER_REPLY * 2) as u64, "the second page reaches the head");
    }

    /// An inbound overlay link is accepted under a blank placeholder address.
    /// Its Hello's advertised onion address is the only identity PEX can record
    /// it under, so a Tor-only seeder whose first contact is a Pex must still
    /// land in the xite's peer table.
    #[tokio::test]
    async fn an_inbound_overlay_pex_records_the_requesters_advertised_address() {
        let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let xite_dir = tempfile::tempdir().unwrap();
        let state_b = AppState::new("overlay-seeder");
        state_b
            .add_xite(
                &address,
                XiteEntry { storage: XiteStorage::new(xite_dir.path()), content: None },
            )
            .await;
        let store_dir = tempfile::tempdir().unwrap();
        let store_b = Arc::new(test_store(store_dir.path(), xite_dir.path()));
        state_b.set_edx_store(store_b.clone()).await.unwrap();
        std::mem::forget(xite_dir);
        std::mem::forget(store_dir);

        // Exactly what an inbound Tor link looks like to the accept loop.
        let placeholder = PeerAddr::Onion { host: String::new(), port: 0 };
        let advertised = PeerAddr::Onion { host: "a".repeat(56), port: 26552 };
        assert!(advertised.pack().is_some(), "the advertised address is wire-packable");

        let (srv_io, cli_io) = tokio::io::duplex(64 * 1024);
        let hook = edx_hook_overlay(
            state_b.clone(),
            store_b,
            epix_crypt::new_seed(),
            None,
            ControlHandles::detached(),
            false,
        );
        tokio::spawn(hook(placeholder, Box::pin(srv_io)));

        let (conn, _incoming) = epix_edx::link::dial_overlay(Box::pin(cli_io)).await.unwrap();
        let cdir = tempfile::tempdir().unwrap();
        let cstore = Arc::new(Store::open(cdir.path()).unwrap());
        std::mem::forget(cdir);
        let cctx = ServeCtx::new(cstore, Arc::new(NoProvider), epix_crypt::new_seed());
        client_hello(&conn, &cctx, vec![advertised.clone()], None).await.unwrap();

        match conn
            .request(Req::Pex { xite: address.clone(), need: 5, peers: Vec::new() })
            .await
            .unwrap()
        {
            epix_edx::msg::Resp::Peers { .. } => {}
            other => panic!("expected Peers, got {other:?}"),
        }

        let known = state_b.pex_peers(&address, 10, &HashSet::new()).await;
        assert!(
            known.contains(&advertised),
            "the overlay requester must be recorded under its advertised address, got {known:?}"
        );
    }

    /// A range fetch that finds no holder must leave NO record behind: the size
    /// is the xite owner's unvalidated claim, so a record nothing ever fills is
    /// a phantom object the store carries forever.
    #[tokio::test]
    async fn a_range_fetch_with_no_holder_leaves_no_record() {
        let (address, content_bytes, content, _movie, _addr, _pk) = spawn_seeder().await;

        let state_a = AppState::new("node-a");
        let a_dir = tempfile::tempdir().unwrap();
        XiteStorage::new(a_dir.path()).write("content.json", &content_bytes).unwrap();
        state_a
            .add_xite(
                &address,
                XiteEntry {
                    storage: XiteStorage::new(a_dir.path()),
                    content: Some(content.clone()),
                },
            )
            .await;
        state_a.set_transport(Arc::new(TcpTransport) as Arc<dyn Transport>).await;
        let a_store_dir = tempfile::tempdir().unwrap();
        let a_store = Arc::new(test_store(a_store_dir.path(), a_dir.path()));
        state_a.set_edx_store(a_store.clone()).await.unwrap();
        std::mem::forget(a_dir);
        std::mem::forget(a_store_dir);
        let fetcher = RuntimeEdxFetcher::new(state_a.clone(), epix_crypt::new_seed(), None);

        // No peer was ever added for this xite, so nothing can serve the range.
        let id = epix_blob::manifest::edx_entry(&content, "movie.bin").unwrap().b3;
        assert!(fetcher.fetch_range(&address, "movie.bin", 0, 50_000).await.is_err());
        assert!(
            !a_store.contains(id).unwrap(),
            "a failed range fetch must not reserve the owner-declared size"
        );
    }

    /// Mode-1 (random-key) shards are keyed by a per-file random key that the
    /// manifest carries no copy of, so decrypting them with the public xite
    /// salt could only fail. Refuse the file with a clear reason instead.
    #[tokio::test]
    async fn a_random_key_shard_is_refused_not_decrypted_with_the_salt() {
        let state = AppState::new("node");
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        std::mem::forget(dir);
        let fetcher = RuntimeEdxFetcher::new(state, epix_crypt::new_seed(), None);

        let content = serde_json::json!({ "edx_salt": "00112233" });
        let shard = epix_blob::manifest::ShardEntry { size: 10, mode: 1, chunks: Vec::new() };
        let err = fetcher
            .fetch_shard_file("1Xite", "private.txt", &content, shard, None, &store)
            .await
            .unwrap_err();
        assert!(err.contains("mode 1"), "expected a mode refusal, got {err}");
    }

    /// The persisted EDX identity key is owner-only from the moment it exists:
    /// a write-then-chmod leaves this node's wire identity readable by every
    /// local user in between, and forever if the chmod fails.
    #[cfg(unix)]
    #[test]
    fn the_node_key_file_is_owner_only_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edx-node.key");
        write_key_file(&path, "deadbeef").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "node key file mode");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "deadbeef");

        // A leftover from a partial write is tightened too: the create-time
        // mode only applies to a file we create, so the rewrite still chmods.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_key_file(&path, "cafebabe").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "an existing key file is tightened, not left readable");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "cafebabe");
    }

    /// A fetch that gives up must not delete a record ANOTHER fetch of the same
    /// object is still filling. The two overlap by design (the moov warm-up is
    /// spawned before the foreground range fetch, and a media element issues
    /// concurrent Range requests), and unlinking the sparse pair mid-flight
    /// fails the other side's `write_slice` and 404s a range that would have
    /// succeeded.
    #[test]
    fn a_claimed_object_is_not_dropped_while_another_fetch_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let fetcher = RuntimeEdxFetcher::new(AppState::new("node"), epix_crypt::new_seed(), None);
        let id = ObjId([9u8; 32]);

        // Two overlapping fetches of the same object; neither lands a group.
        let background = fetcher.claim_object(&store, id, Ns::Plain, 4096, 1).unwrap();
        let foreground = fetcher.claim_object(&store, id, Ns::Plain, 4096, 1).unwrap();
        assert!(store.contains(id).unwrap(), "the record was reserved");

        drop(foreground);
        assert!(
            store.contains(id).unwrap(),
            "a fetch that gave up must leave the record for the one still filling it"
        );

        drop(background);
        assert!(!store.contains(id).unwrap(), "the last claim to go drops the empty record");
    }

    /// The cleanup only drops a record THIS fetch reserved: a record that was
    /// already there when the fetch started stays put.
    #[test]
    fn a_claim_never_drops_an_object_it_did_not_reserve() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let fetcher = RuntimeEdxFetcher::new(AppState::new("node"), epix_crypt::new_seed(), None);
        let id = ObjId([8u8; 32]);

        store.ensure_sparse(id, Ns::Plain, 4096, 1).unwrap();
        drop(fetcher.claim_object(&store, id, Ns::Plain, 4096, 1).unwrap());
        assert!(store.contains(id).unwrap(), "a pre-existing record is left alone");
    }

    /// Build a state whose only xite declares `files`, staged (nothing on
    /// disk) - the shape a clone is in while it downloads.
    async fn staged_only_node(
        files: serde_json::Value,
    ) -> (
        Arc<AppState>,
        String,
        serde_json::Value,
        Vec<u8>,
        tempfile::TempDir,
    ) {
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let mut content = serde_json::json!({ "address": address, "modified": 1, "files": files });
        epix_content::sign(&mut content, &key).unwrap();
        let signed = serde_json::to_vec(&content).unwrap();
        let state = AppState::new("node-a");
        let dir = tempfile::tempdir().unwrap();
        state
            .add_xite(
                &address,
                XiteEntry { storage: XiteStorage::new(dir.path()), content: Some(content.clone()) },
            )
            .await;
        let store_dir = tempfile::tempdir().unwrap();
        state
            .set_edx_store(Arc::new(test_store(store_dir.path(), dir.path())))
            .await
            .unwrap();
        state
            .set_edx_fetcher(Arc::new(RuntimeEdxFetcher::new(
                state.clone(),
                epix_crypt::new_seed(),
                None,
            )))
            .await;
        (state, address, content, signed, dir)
    }

    /// A zero-length file needs no bytes from anyone, so it must land with NO
    /// peers and no transport at all.
    ///
    /// Regression: an empty file has no chunk groups, so no peer could ever
    /// serve it and the store never held a record for it. It stayed in every
    /// fetch pass forever, the clone's core set never completed, and
    /// content.json was never committed - one stray empty file (a SQLite
    /// `-wal` sidecar swept into a sign) pinned a whole xite to its previous
    /// version on every node in the network.
    #[tokio::test]
    async fn a_zero_length_file_lands_without_any_peer() {
        let empty = ObjId::of(&[]).to_string();
        let empty_sha512 = XiteStorage::hash_bytes(&[]);
        let (state, address, content, signed, dir) = staged_only_node(serde_json::json!({
            "empty.txt": { "b3": empty, "size": 0, "sha512": empty_sha512 },
        }))
        .await;
        let transaction = state
            .begin_staged_root_transaction(&address, &signed)
            .await
            .expect("signed staged manifest starts a transaction");

        // No transport, no peers: if this needed the network it cannot pass.
        let missed = state
            .edx_first(
                &address,
                vec![epix_xite::FileEntry {
                    inner_path: "empty.txt".to_string(),
                    size: 0,
                    sha512: XiteStorage::hash_bytes(&[]),
                }],
                vec![],
                Some(&content),
                Some(&transaction),
                None,
            )
            .await;

        assert!(missed.is_empty(), "nothing was handed to the fallback worker");
        let written = dir.path().join("empty.txt");
        assert!(written.is_file(), "the empty file was written into the xite tree");
        assert_eq!(std::fs::metadata(&written).unwrap().len(), 0, "and it is empty");
    }

    /// The empty-file shortcut is scoped to size 0: a file with real bytes and
    /// no record still goes to the network (and is missed when nobody answers),
    /// so this cannot become a way to fake a file into a xite.
    #[tokio::test]
    async fn a_non_empty_file_is_never_shortcut_to_disk() {
        let (state, address, content, _signed, dir) = staged_only_node(serde_json::json!({
            "real.bin": {
                "b3": ObjId([3u8; 32]).to_string(),
                "size": 64,
                "sha512": XiteStorage::hash_bytes(&[0u8; 64])
            },
        }))
        .await;

        let batch = state
            .edx_fetch_files(&address, vec![EdxWant::path("real.bin")], vec![], Some(content), None)
            .await
            .unwrap();

        assert!(batch.done.is_empty(), "a file with bytes is never landed locally");
        assert_eq!(batch.missed, vec!["real.bin".to_string()], "it goes to the fallback worker");
        assert!(!dir.path().join("real.bin").exists(), "and nothing was written to the xite tree");
    }
}
