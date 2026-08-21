//! The EDX protocol server: answers a connection's inbound requests
//! against the object store and a signed-content provider.
//!
//! Serving is streaming end to end: `GetRange` encodes the verified
//! slice DIRECTLY into ≤64 KiB Data frames through a writer adapter (a
//! spawn_blocking encode thread feeding the connection's frame queue via
//! blocking_send) — a multi-GB range never materializes in memory, and a
//! peer Cancel aborts the encode between frames.
//!
//! Control-plane limits enforced here, per connection: a Hello gate for
//! accepted links (nothing else is answered first; wrong net or bad channel
//! binding kills the connection), a concurrent-serve semaphore, and
//! per-request caps on range count/bytes and GetMany item count/size. A dialer
//! that already authenticated its peer with [`client_hello`] enters the same
//! request loop through [`serve_authenticated`]. Cross-peer fairness (choking)
//! sits a layer above and only shapes BULK data; these caps are the hard
//! backstop.

use std::sync::Arc;
use std::time::Duration;

use epix_blob::store::Store;
use epix_blob::ObjId;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use crate::choke::{Choker, Reach, ServeDecision};
use crate::conn::{Conn, Incoming};
use crate::msg::{caps, err, Frame, FrameBody, Hello, HelloAck, Req, Resp, NET_ID};
use crate::noise;
use crate::MAX_FRAME_LEN;
use std::sync::Mutex;

/// Per-request caps (hard backstops, not tuning knobs).
pub const MAX_RANGES_PER_REQ: usize = 64;
pub const MAX_BYTES_PER_REQ: u64 = 64 << 20;
pub const MAX_MANY_ITEMS: usize = 256;
pub const MAX_MANY_ITEM_BYTES: u64 = 64 * 1024;
/// Concurrent non-Update serve tasks per connection.
pub const MAX_CONCURRENT_SERVES: usize = 8;
/// Concurrent Update applications per connection. Updates have their own
/// admission lane because an application may synchronously request signed or
/// content-addressed data back over the same duplex session. Sharing every
/// permit with those dependency requests creates a circular wait when both
/// endpoints receive a full Update batch at once.
pub const MAX_CONCURRENT_UPDATES: usize = 8;
/// Concurrent range-encode threads across the WHOLE process. The encode
/// runs on tokio's blocking pool, which the node shares with store and
/// database IO, and each thread can sit on the connection's send stall
/// deadline waiting for its peer. Without this, enough slow peers starve
/// every other blocking caller. Serving is bound by peer link speed, not
/// by encode parallelism, so a small number is plenty.
pub const MAX_ENCODE_THREADS: usize = 32;
/// Global bound on serves ADMITTED to the encode stage: the running
/// [`MAX_ENCODE_THREADS`] plus a bounded queue behind them. Per
/// connection [`MAX_CONCURRENT_SERVES`] caps data/control concurrency and
/// [`MAX_CONCURRENT_UPDATES`] caps update application, but connections are
/// many, and every one of them parking its serves on the encode semaphore was
/// an unbounded process-wide queue. Past this bound the request waits out one
/// short drain window ([`ENCODE_QUEUE_WAIT`]) and is then refused with a typed
/// retry-after instead of waiting silently for an unbounded time.
pub const MAX_ENCODE_QUEUE: usize = MAX_ENCODE_THREADS * 3;
/// How long a serve may wait for queue admission before it is refused.
/// Refusing instantly regressed legacy clients: they parked here without
/// bound before, they count a BUSY as a strike toward exhausting a seeder
/// (three in a row and our sole-seeder role is struck out), and a load
/// spike that fills the queue usually drains within seconds.
const ENCODE_QUEUE_WAIT: Duration = Duration::from_secs(15);
/// Retry hint when the global serve queue is full: long enough for a
/// slice of the queue to drain, short enough to refill a freed queue.
const ENCODE_QUEUE_RETRY_SECS: u64 = 5;
/// Retry hint when one connection's serve slots are all taken: those
/// serves are actively streaming, so a slot frees soon.
const SERVE_SLOTS_RETRY_SECS: u64 = 2;
/// How long a connection may sit after the link comes up before sending
/// its `Hello`. Bounds the slot an authenticated-but-silent peer holds.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an established connection may sit idle (no request) before it
/// is dropped and its inbound slot released.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// A GetRange for an OBJECT no larger than this is treated as first-paint
/// (index.html, bundles, small assets), exempt from choking up to the
/// per-peer free budget. Keyed on the object's total size, not the request
/// size: a scheduler batch out of a multi-GB video is bulk even when the
/// batch itself is small, so media transfers never burn the free budget.
pub const FIRST_PAINT_OBJECT_BYTES: u64 = 4 << 20;

/// The [`MAX_ENCODE_THREADS`] permits, shared by every connection.
static ENCODE_SLOTS: std::sync::LazyLock<Semaphore> =
    std::sync::LazyLock::new(|| Semaphore::new(MAX_ENCODE_THREADS));

/// The [`MAX_ENCODE_QUEUE`] admission permits (running + queued serves).
static ENCODE_QUEUE: std::sync::LazyLock<Semaphore> =
    std::sync::LazyLock::new(|| Semaphore::new(MAX_ENCODE_QUEUE));

/// Admission to the encode stage. A full queue is waited out for
/// [`ENCODE_QUEUE_WAIT`] (waiters are bounded by the per-connection serve
/// slots, so this cannot rebuild the unbounded parking lot the queue bound
/// removed); None means refuse with the retry hint.
async fn encode_queue_slot() -> Option<tokio::sync::SemaphorePermit<'static>> {
    match tokio::time::timeout(ENCODE_QUEUE_WAIT, ENCODE_QUEUE.acquire()).await {
        Ok(Ok(permit)) => Some(permit),
        // Timed out; the never-closed semaphore cannot error otherwise.
        _ => None,
    }
}

/// Signed-content access the server delegates to (the real node backs
/// this with its xite registry; tests use a fixture). Async because the
/// node's registry is behind async locks and disk IO.
#[async_trait::async_trait]
pub trait SignedProvider: Send + Sync + 'static {
    /// Raw signed content.json bytes (root or per-user path).
    async fn get_signed(&self, xite: &str, inner_path: &str) -> Option<Vec<u8>>;
    /// Signed files changed since `since`: (inner_path, modified, size).
    async fn list_signed(&self, xite: &str, since: u64) -> Vec<(String, u64, u64)>;
    /// (signed_files, newest_modified, held_bytes) or None if unknown xite.
    async fn xite_summary(&self, xite: &str) -> Option<(u64, u64, u64)>;
    /// Verify + apply a pushed signed update. `signed` is the content.json
    /// body; `inline` are small whole objects that ride along; `modified` is
    /// the version; `diffs` are per-file encoded action lists (the provider
    /// decodes them) so data files patch in place; `sender_peers` are the
    /// publisher's dial-back addresses. `source` identifies the authenticated
    /// connection that delivered the update, so the provider can pull missing
    /// signed content back over the same NAT-safe session and account for the
    /// peer and transport class. Ok(true) = accepted and new, Ok(false) =
    /// stale/known.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<bool, String>;
}

/// Control-plane access the server delegates to: propagation poll, PEX,
/// tracker-set gossip, DHT RPC, tracker announce. Separate from
/// [`SignedProvider`]
/// because a pure content node (tests, embedded fetchers) serves content
/// without any of this; `ServeCtx.control = None` answers these requests
/// UNSUPPORTED and the node must not advertise `caps::CONTROL`.
///
/// `Kad`/`Announce` payloads are opaque here — their shape belongs to
/// `epix-dht-net` / `epix-discovery`, mirroring how `Update::diffs` stays
/// neutral in this crate.
#[async_trait::async_trait]
pub trait ControlProvider: Send + Sync + 'static {
    /// Propagation hints recorded after `after`: (xite, modified) pairs
    /// plus the new head cursor.
    async fn updates_since(&self, after: u64) -> (Vec<(String, i64)>, u64);
    /// Peer exchange: connectable peers for `xite` the requester lacks
    /// (its known set rides in `have`), capped at `need`. `from` is the
    /// established identity of the requester (reputation / recording).
    async fn pex(
        &self,
        xite: &str,
        need: u32,
        have: &[epix_core::PeerAddr],
        from: &PeerIdentity,
    ) -> Vec<epix_core::PeerAddr>;
    /// The working tracker set (`epix://host:port`), Beacon gossip.
    async fn trackers(&self) -> Vec<String>;
    /// One Kademlia RPC (opaque payload owned by epix-dht-net).
    async fn kad(&self, payload: &[u8], from: &PeerIdentity) -> Result<Vec<u8>, String>;
    /// One tracker announce (opaque payload owned by epix-discovery).
    async fn announce(&self, payload: &[u8], from: &PeerIdentity) -> Result<Vec<u8>, String>;
}

/// Upload-accounting callback: (object served, bytes that went on the
/// wire). Fired from serve paths after the bytes were actually sent, off
/// the async runtime (blocking threads included), so it must not block.
pub type ServedHook = Arc<dyn Fn(ObjId, u64) + Send + Sync>;

/// Everything a serve loop needs.
pub struct ServeCtx {
    pub store: Arc<Store>,
    pub provider: Arc<dyn SignedProvider>,
    /// Control-plane services (None = content-only node; control
    /// requests answer UNSUPPORTED and `caps::CONTROL` must not be set).
    pub control: Option<Arc<dyn ControlProvider>>,
    /// This node's identity key (hex) for Hello/HelloAck binding sigs.
    pub privatekey: String,
    /// The release version this node announces in Hello/HelloAck (the
    /// Stats page's `client` column). Empty = unset.
    pub version: String,
    /// Capability bits to advertise.
    pub caps: u32,
    /// Unix-seconds clock (injectable for tests).
    pub now: fn() -> u64,
    /// Shared upload governor (reciprocity choke + global cap). Bulk
    /// GetRange serving consults it; None disables governance (tests /
    /// unmetered nodes that want to serve everything).
    pub choker: Option<Arc<Mutex<Choker>>>,
    /// Whether the user's own foreground traffic is currently active
    /// (drives the LEDBAT yield). A real node updates this live.
    pub foreground: Arc<std::sync::atomic::AtomicBool>,
    /// Called with (object, bytes) after a serve actually sent data, so
    /// the node can credit its upload counters. None = no accounting.
    pub on_served: Option<ServedHook>,
}

/// The peer identity a completed handshake established.
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    pub node_pk: Vec<u8>,
    pub address: String,
    pub caps: u32,
    /// The peer's self-reported release version (empty if it sent none).
    /// Reporting only - nothing is gated on it.
    pub version: String,
}

/// Authenticated origin of a pushed update.
///
/// The connection is the live session that carried `Req::Update`. Providers
/// should prefer it over opening a reverse connection to a self-declared
/// address. `identity` and `reach` come from the same completed Hello exchange
/// and let callers label, tune, and account for a same-session pull without
/// trusting update payload fields.
#[derive(Clone)]
pub struct UpdateSource {
    pub conn: Conn,
    pub identity: PeerIdentity,
    pub reach: Reach,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ServeCtx {
    /// Ungoverned context (serves everything): tests and unmetered nodes.
    pub fn new(store: Arc<Store>, provider: Arc<dyn SignedProvider>, privatekey: String) -> Self {
        Self {
            store,
            provider,
            control: None,
            privatekey,
            version: String::new(),
            caps: caps::MESH | caps::RETRY_AFTER,
            now: now_unix,
            choker: None,
            foreground: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            on_served: None,
        }
    }

    /// Attach the shared upload governor.
    pub fn with_choker(mut self, choker: Arc<Mutex<Choker>>) -> Self {
        self.choker = Some(choker);
        self
    }

    /// Share the node's foreground-activity flag (the LEDBAT yield's
    /// input). Contexts are built per connection, so without a shared
    /// flag each one holds a private always-false bool and the yield
    /// never engages.
    pub fn with_foreground(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.foreground = flag;
        self
    }

    /// Attach the upload-accounting hook (fired after bytes are served).
    pub fn with_on_served(mut self, hook: ServedHook) -> Self {
        self.on_served = Some(hook);
        self
    }

    /// Announce this node's release version to peers (Hello/HelloAck).
    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }

    /// Attach the control-plane services and advertise `caps::CONTROL`.
    pub fn with_control(mut self, control: Arc<dyn ControlProvider>) -> Self {
        self.control = Some(control);
        self.caps |= caps::CONTROL;
        self
    }

    /// Advertise `caps::SHARDS` when this node volunteers disk to hold
    /// encrypted shards it cannot read. Serving availability/bytes of a
    /// held shard needs no extra state (a shard is an ordinary
    /// content-addressed object), so this only flips the advertised bit;
    /// the actual holding is driven by the runtime's volunteer pull.
    pub fn with_shards(mut self, on: bool) -> Self {
        if on {
            self.caps |= caps::SHARDS;
        }
        self
    }
}

/// Build our Hello/HelloAck binding signature for this session. `role` is
/// the side WE are: the dialer signs its `Hello` as the initiator, the
/// acceptor its `HelloAck` as the responder, so neither signature can be
/// reflected back as the other. `handshake_hash` is Some on Noise links,
/// None on overlay links (their transport already authenticates the
/// endpoint).
fn binding_sig(
    privatekey: &str,
    handshake_hash: Option<&[u8; 32]>,
    role: noise::Role,
) -> std::io::Result<Vec<u8>> {
    match handshake_hash {
        Some(h) => noise::sign_binding(h, privatekey, role),
        None => Ok(Vec::new()),
    }
}

/// Validate a peer's Hello/HelloAck identity claims. `role` is the side
/// the PEER is, so a responder that echoes the dialer's own node_pk and
/// binding signature back fails the check. Returns the established
/// identity or an error string (which kills the connection).
fn check_identity(
    net: &str,
    node_pk: &[u8],
    sig: &[u8],
    peer_caps: u32,
    version: String,
    handshake_hash: Option<&[u8; 32]>,
    role: noise::Role,
) -> Result<PeerIdentity, String> {
    if net != NET_ID {
        return Err(format!("wrong net {net:?}"));
    }
    let address =
        epix_crypt::pubkey_to_address(node_pk).map_err(|e| format!("bad node_pk: {e}"))?;
    if let Some(hash) = handshake_hash {
        if !noise::verify_binding(hash, node_pk, sig, role) {
            return Err(format!("channel binding failed for {address}"));
        }
    }
    Ok(PeerIdentity { node_pk: node_pk.to_vec(), address, caps: peer_caps, version })
}

/// Client side of the handshake: send Hello, await + verify HelloAck.
pub async fn client_hello(
    conn: &Conn,
    ctx: &ServeCtx,
    listen: Vec<epix_core::PeerAddr>,
    handshake_hash: Option<[u8; 32]>,
) -> std::io::Result<PeerIdentity> {
    let hello = Hello {
        net: NET_ID.into(),
        node_pk: epix_crypt::private_to_compressed_pubkey(&ctx.privatekey)
            .map_err(std::io::Error::other)?,
        binding_sig: binding_sig(&ctx.privatekey, handshake_hash.as_ref(), noise::Role::Initiator)?,
        caps: ctx.caps,
        listen,
        version: ctx.version.clone(),
    };
    match conn.request(Req::Hello(hello)).await? {
        Resp::HelloAck(ack) => check_identity(
            &ack.net,
            &ack.node_pk,
            &ack.binding_sig,
            ack.caps,
            ack.version,
            handshake_hash.as_ref(),
            noise::Role::Responder,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)),
        Resp::Err { code, msg } => Err(std::io::Error::other(format!("hello refused {code}: {msg}"))),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected HelloAck, got {other:?}"),
        )),
    }
}

/// The bounded Hello gate: the FIRST request must be a valid Hello, and a
/// peer that completes the handshake and then never speaks would otherwise
/// hold its inbound slot forever. EDX is the only inbound path now, so
/// without the timeout a few hundred stalled sockets exhaust MAX_INBOUND
/// and the node goes deaf to new peers. Returns the verified identity, or
/// None when the connection must drop.
async fn hello_gate(
    conn: &Conn,
    incoming: &mut mpsc::Receiver<Incoming>,
    ctx: &Arc<ServeCtx>,
    handshake_hash: Option<&[u8; 32]>,
) -> Option<PeerIdentity> {
    let first = tokio::time::timeout(HELLO_TIMEOUT, incoming.recv()).await.ok()??;
    // Destructured whole: matching on `first.req` alone is a partial move, so
    // the un-moved `_budget` would live as long as the caller does and never
    // refund the Hello's share of the connection's inbound byte budget.
    let Incoming { stream: hello_stream, req: hello_req, _budget: hello_budget } = first;
    let Req::Hello(hello) = hello_req else {
        let _ = conn
            .respond(hello_stream, Resp::Err { code: err::BAD_REQUEST, msg: "hello first".into() })
            .await;
        return None;
    };
    let checked = check_identity(
        &hello.net,
        &hello.node_pk,
        &hello.binding_sig,
        hello.caps,
        hello.version,
        handshake_hash,
        noise::Role::Initiator,
    );
    let id = match checked {
        Ok(id) => id,
        Err(e) => {
            let _ =
                conn.respond(hello_stream, Resp::Err { code: err::BAD_REQUEST, msg: e }).await;
            return None;
        }
    };
    let ack = HelloAck {
        net: NET_ID.into(),
        node_pk: epix_crypt::private_to_compressed_pubkey(&ctx.privatekey).ok()?,
        binding_sig: binding_sig(&ctx.privatekey, handshake_hash, noise::Role::Responder).ok()?,
        caps: ctx.caps,
        observed: None,
        version: ctx.version.clone(),
    };
    if conn.respond(hello_stream, Resp::HelloAck(ack)).await.is_err() {
        return None;
    }
    // Answered: give the units back to the connection's inbound budget.
    drop(hello_budget);
    Some(id)
}

/// Run the serve loop for one connection until it closes. The FIRST
/// request must be a valid Hello; anything else (or a failed identity
/// check) drops the connection. Returns the peer identity once the
/// connection ends (for reputation accounting).
pub async fn serve(
    conn: Conn,
    mut incoming: mpsc::Receiver<Incoming>,
    ctx: Arc<ServeCtx>,
    handshake_hash: Option<[u8; 32]>,
) -> Option<PeerIdentity> {
    let identity = hello_gate(&conn, &mut incoming, &ctx, handshake_hash.as_ref()).await?;
    let reach = if handshake_hash.is_some() { Reach::Clearnet } else { Reach::Overlay };
    Some(serve_requests(conn, incoming, ctx, identity, reach, true, None).await)
}

/// Notification that a request served on an authenticated outbound link has
/// completed. A connection pool uses this to renew the reverse-serving lease
/// after a long range response, without exposing pool state to this crate.
pub type ServeActivityHook = Arc<dyn Fn() + Send + Sync>;

/// Serve reverse requests on a link whose peer was already authenticated by
/// [`client_hello`]. No second `Hello` is expected or accepted.
///
/// `identity` must be the value returned by `client_hello` for this exact
/// connection. `reach` must describe the same link, just as [`serve`] derives it
/// from the presence of a Noise handshake hash. The request path is otherwise
/// identical to `serve`: governor accounting, concurrent-serve admission, Busy
/// replies, and every per-request cap are shared.
///
/// Unlike an accepted socket, an outbound pooled link does not consume an
/// inbound accept slot. This loop therefore remains available until `incoming`
/// closes instead of applying [`IDLE_TIMEOUT`]. The connection pool owns that
/// link's idle lifetime.
pub async fn serve_authenticated(
    conn: Conn,
    incoming: mpsc::Receiver<Incoming>,
    ctx: Arc<ServeCtx>,
    identity: PeerIdentity,
    reach: Reach,
) -> PeerIdentity {
    serve_requests(conn, incoming, ctx, identity, reach, false, None).await
}

/// [`serve_authenticated`] with a completion hook for connection-pool lease
/// tracking. The hook fires after each request handler finishes and before its
/// connection handle and admission permit are released.
pub async fn serve_authenticated_tracked(
    conn: Conn,
    incoming: mpsc::Receiver<Incoming>,
    ctx: Arc<ServeCtx>,
    identity: PeerIdentity,
    reach: Reach,
    on_activity: ServeActivityHook,
) -> PeerIdentity {
    serve_requests(conn, incoming, ctx, identity, reach, false, Some(on_activity)).await
}

/// Result of assigning one established request to its bounded handler lane.
enum RequestAdmission {
    Admitted(OwnedSemaphorePermit),
    Busy(&'static str),
    Closed,
}

/// Receive one request, applying the idle timeout only to accepted links.
async fn next_request(
    incoming: &mut mpsc::Receiver<Incoming>,
    reap_idle: bool,
) -> Option<Incoming> {
    if reap_idle {
        tokio::time::timeout(IDLE_TIMEOUT, incoming.recv()).await.ok().flatten()
    } else {
        incoming.recv().await
    }
}

/// Assign Updates and dependency serves to their independent bounded lanes.
async fn admit_request(
    req: &Req,
    serves: &Arc<Semaphore>,
    updates: &Arc<Semaphore>,
) -> RequestAdmission {
    if matches!(req, Req::Update { .. }) {
        // Do not let a ninth Update park the dispatcher ahead of a nested
        // dependency request. The admitted Updates keep running and the
        // excess one gets the ordinary bounded-retry response.
        return match updates.clone().try_acquire_owned() {
            Ok(permit) => RequestAdmission::Admitted(permit),
            Err(_) => RequestAdmission::Busy("update slots busy"),
        };
    }

    // A bounded wait keeps a full serve lane from parking the dispatcher
    // forever. A timeout means BUSY, while semaphore closure ends the loop.
    match tokio::time::timeout(IDLE_TIMEOUT, serves.clone().acquire_owned()).await {
        Ok(Ok(permit)) => RequestAdmission::Admitted(permit),
        Ok(Err(_)) => RequestAdmission::Closed,
        Err(_) => RequestAdmission::Busy("serve slots busy"),
    }
}

/// The established-request loop shared by accepted and outbound links.
async fn serve_requests(
    conn: Conn,
    mut incoming: mpsc::Receiver<Incoming>,
    ctx: Arc<ServeCtx>,
    identity: PeerIdentity,
    reach: Reach,
    reap_idle: bool,
    on_activity: Option<ServeActivityHook>,
) -> PeerIdentity {

    // Register the connection with the governor (reachability from the
    // authenticated link type). Unchoke slots are
    // ranked over CONNECTED peers, so this is what admits the peer to the
    // competition; the matching note_disconnected runs from a drop guard,
    // so it also fires if this future is cancelled mid-serve (an accept
    // loop aborting per-conn tasks) - an unpaired note_connected would
    // leave a phantom conns>0 account squatting the connected set and
    // immune to table eviction forever.
    struct Connected {
        ctx: Arc<ServeCtx>,
        node_pk: Vec<u8>,
    }
    impl Drop for Connected {
        fn drop(&mut self) {
            if let Some(choker) = &self.ctx.choker {
                choker.lock().expect("choker").note_disconnected(&self.node_pk, (self.ctx.now)());
            }
        }
    }
    let _connected = ctx.choker.as_ref().map(|choker| {
        choker.lock().expect("choker").note_connected(&identity.node_pk, reach, (ctx.now)());
        Connected { ctx: ctx.clone(), node_pk: identity.node_pk.clone() }
    });
    let identity = Arc::new(identity);

    // Accepted links reap idle peers to release their inbound slot. An
    // authenticated outbound link follows its pool's lifetime instead and
    // keeps reverse serving until the incoming channel closes.
    let serves = Arc::new(Semaphore::new(MAX_CONCURRENT_SERVES));
    let updates = Arc::new(Semaphore::new(MAX_CONCURRENT_UPDATES));
    loop {
        let Some(inc) = next_request(&mut incoming, reap_idle).await else {
            break;
        };
        // Updates and the requests they may synchronously issue back over this
        // same duplex link need independent bounded lanes. If eight Updates on
        // each endpoint occupied the one shared semaphore, all sixteen could
        // wait for GetSigned/GetBitfield/GetRange requests that neither request
        // loop had a permit left to dispatch.
        let permit = match admit_request(&inc.req, &serves, &updates).await {
            RequestAdmission::Admitted(permit) => permit,
            RequestAdmission::Busy(message) => {
                let _ = conn
                    .respond(
                        inc.stream,
                        busy_resp(&identity, SERVE_SLOTS_RETRY_SECS, message),
                    )
                    .await;
                continue;
            }
            // The semaphore is ours and never closed; treat closure as fatal.
            RequestAdmission::Closed => break,
        };
        let conn = conn.clone();
        let ctx = ctx.clone();
        let identity = identity.clone();
        let on_activity = on_activity.clone();
        tokio::spawn(async move {
            handle(conn, ctx, identity, reach, inc).await;
            if let Some(on_activity) = on_activity {
                on_activity();
            }
            drop(permit);
        });
    }
    // The connection is gone: `_connected`'s drop tells the governor, so
    // the peer stops competing for unchoke slots (the account and its
    // credit stay for when the peer returns).
    (*identity).clone()
}

async fn handle(
    conn: Conn,
    ctx: Arc<ServeCtx>,
    identity: Arc<PeerIdentity>,
    reach: Reach,
    inc: Incoming,
) {
    let stream = inc.stream;
    match inc.req {
        Req::Hello(_) => {
            let _ = conn
                .respond(stream, Resp::Err { code: err::BAD_REQUEST, msg: "already hello'd".into() })
                .await;
        }
        Req::GetRange { obj, ranges, deadline_ms, .. } => {
            serve_range(conn, ctx, identity, stream, obj, ranges, deadline_ms).await;
        }
        Req::GetMany { objs } => {
            serve_many(conn, ctx, identity, stream, objs).await;
        }
        Req::GetBitfield { obj } => {
            serve_bitfield(conn, ctx, stream, obj).await;
        }
        Req::GetSigned { xite, inner_path } => {
            serve_get_signed(conn, ctx, stream, xite, inner_path).await;
        }
        Req::ListSigned { xite, since } => {
            let entries = ctx.provider.list_signed(&xite, since).await;
            serve_signed_list(conn, stream, entries).await;
        }
        Req::HasXite { xite } => {
            serve_xite_summary(conn, ctx, stream, xite).await;
        }
        Req::HaveRanges { .. } => {
            // Availability notification: consumed by the fetch scheduler
            // (see fetch.rs); as a server there is nothing to answer.
        }
        Req::HasShards { addrs } => {
            serve_shard_mask(conn, ctx, stream, addrs).await;
        }
        Req::Update { xite, inner_path, signed, inline, modified, diffs, sender_peers } => {
            let resp = match ctx
                .provider
                .apply_update(
                    &xite,
                    &inner_path,
                    &signed,
                    &inline,
                    modified,
                    &diffs,
                    &sender_peers,
                    UpdateSource {
                        conn: conn.clone(),
                        identity: (*identity).clone(),
                        reach,
                    },
                )
                .await
            {
                Ok(_) => Resp::Ok,
                Err(e) => Resp::Err { code: err::BAD_REQUEST, msg: e },
            };
            let _ = conn.respond(stream, resp).await;
        }
        // Control plane (caps::CONTROL). A content-only node (no control
        // provider) answers UNSUPPORTED so a mis-gated dialer fails fast
        // instead of hanging.
        Req::UpdatesSince { after } => {
            serve_updates_since(conn, ctx, stream, after).await;
        }
        Req::Pex { xite, need, peers } => {
            serve_pex(conn, ctx, identity, stream, xite, need, peers).await;
        }
        Req::GetTrackers => {
            serve_trackers(conn, ctx, stream).await;
        }
        Req::Kad { payload } => {
            serve_kad(conn, ctx, identity, stream, payload).await;
        }
        Req::Announce { payload } => {
            serve_announce(conn, ctx, identity, stream, payload).await;
        }
    }
}

/// The reply for a control request on a node that doesn't serve control.
fn unsupported() -> Resp {
    Resp::Err { code: err::UNSUPPORTED, msg: "control plane not served".into() }
}

/// The refusal reply: a typed `Busy` carrying the comeback hint for a
/// peer that advertised [`caps::RETRY_AFTER`] in its Hello, the legacy
/// `Err { BUSY }` for everyone older (postcard variants are positional,
/// so an unknown appended variant would break an old peer's parse — the
/// caps bit is what makes the append safe to actually send).
fn busy_resp(identity: &PeerIdentity, retry_after_secs: u64, msg: &str) -> Resp {
    if identity.caps & caps::RETRY_AFTER != 0 {
        Resp::Busy {
            retry_after_ms: retry_after_secs.saturating_mul(1000).min(u32::MAX as u64) as u32,
        }
    } else {
        Resp::Err { code: err::BUSY, msg: msg.into() }
    }
}

/// Byte budget for one batched reply frame, leaving room for the frame
/// header and postcard's length prefixes.
const BATCH_BUDGET: usize = MAX_FRAME_LEN - 4096;

/// Answer `GetBitfield`: the object's size plus its present-group runs.
async fn serve_bitfield(conn: Conn, ctx: Arc<ServeCtx>, stream: u64, obj: ObjId) {
    let resp = match ctx.store.info(obj).and_then(|info| {
        Ok(match info {
            Some((size, _)) => {
                let bits = ctx.store.present_bits(obj)?;
                Resp::Bitfield { size, runs: bits.to_wire() }
            }
            None => Resp::Err { code: err::NOT_FOUND, msg: format!("{obj}") },
        })
    }) {
        Ok(r) => r,
        Err(e) => Resp::Err { code: err::INTERNAL, msg: e.to_string() },
    };
    let _ = conn.respond(stream, resp).await;
}

/// Answer `GetSigned`: stream the signed body, or NOT_FOUND.
async fn serve_get_signed(
    conn: Conn,
    ctx: Arc<ServeCtx>,
    stream: u64,
    xite: String,
    inner_path: String,
) {
    match ctx.provider.get_signed(&xite, &inner_path).await {
        Some(bytes) => serve_signed(conn, stream, bytes).await,
        None => {
            let _ = conn
                .respond(
                    stream,
                    Resp::Err { code: err::NOT_FOUND, msg: format!("{xite}/{inner_path}") },
                )
                .await;
        }
    }
}

/// Answer `HasXite` with the provider's summary, or NOT_FOUND.
async fn serve_xite_summary(conn: Conn, ctx: Arc<ServeCtx>, stream: u64, xite: String) {
    let resp = match ctx.provider.xite_summary(&xite).await {
        Some((signed_files, newest_modified, held_bytes)) => {
            Resp::XiteSummary { signed_files, newest_modified, held_bytes }
        }
        None => Resp::Err { code: err::NOT_FOUND, msg: xite },
    };
    let _ = conn.respond(stream, resp).await;
}

/// Answer `HasShards`: one packed bit per requested addr, set iff we hold
/// it complete. Answered for anything held, independent of the volunteer
/// responsibility predicate (responsibility governs only what we PULL,
/// never what we serve of what we already have). Needs the store only -
/// no control provider, no cap.
async fn serve_shard_mask(conn: Conn, ctx: Arc<ServeCtx>, stream: u64, addrs: Vec<ObjId>) {
    let mut bits = vec![0u8; addrs.len().div_ceil(8)];
    for (i, a) in addrs.iter().enumerate() {
        if ctx.store.is_complete(*a).unwrap_or(false) {
            bits[i / 8] |= 1 << (i % 8);
        }
    }
    let _ = conn.respond(stream, Resp::ShardMask { bits }).await;
}

/// Answer `UpdatesSince` from the control provider, or UNSUPPORTED on a
/// content-only node.
async fn serve_updates_since(conn: Conn, ctx: Arc<ServeCtx>, stream: u64, after: u64) {
    match &ctx.control {
        Some(c) => {
            let (updates, head) = c.updates_since(after).await;
            serve_updates(conn, stream, updates, head).await;
        }
        None => {
            let _ = conn.respond(stream, unsupported()).await;
        }
    }
}

/// Answer `Pex` from the control provider, or UNSUPPORTED.
async fn serve_pex(
    conn: Conn,
    ctx: Arc<ServeCtx>,
    identity: Arc<PeerIdentity>,
    stream: u64,
    xite: String,
    need: u32,
    peers: Vec<epix_core::PeerAddr>,
) {
    let resp = match &ctx.control {
        Some(c) => Resp::Peers { peers: c.pex(&xite, need, &peers, &identity).await },
        None => unsupported(),
    };
    let _ = conn.respond(stream, resp).await;
}

/// Answer `GetTrackers` with as much of the working set as fits one
/// frame, or UNSUPPORTED.
async fn serve_trackers(conn: Conn, ctx: Arc<ServeCtx>, stream: u64) {
    let resp = match &ctx.control {
        Some(c) => {
            // One unchunked frame, so the set has to fit in it: an
            // oversize frame fails to encode in the writer task and
            // tears down the WHOLE multiplexed connection. A truncated
            // tracker set still works (gossip brings the rest), so
            // degrade rather than fail.
            let mut trackers: Vec<String> = Vec::new();
            let mut bytes = 0usize;
            for t in c.trackers().await {
                // string bytes + its length varint, generously rounded.
                bytes += t.len() + 8;
                if bytes > BATCH_BUDGET {
                    break;
                }
                trackers.push(t);
            }
            Resp::Trackers { trackers }
        }
        None => unsupported(),
    };
    let _ = conn.respond(stream, resp).await;
}

/// Answer `Kad`: one Kademlia RPC through the control provider, or
/// UNSUPPORTED.
async fn serve_kad(
    conn: Conn,
    ctx: Arc<ServeCtx>,
    identity: Arc<PeerIdentity>,
    stream: u64,
    payload: Vec<u8>,
) {
    let resp = match &ctx.control {
        Some(c) => match c.kad(&payload, &identity).await {
            Ok(bytes) => Resp::Payload { bytes },
            Err(e) => Resp::Err { code: err::BAD_REQUEST, msg: e },
        },
        None => unsupported(),
    };
    let _ = conn.respond(stream, resp).await;
}

/// Answer `Announce`: one tracker announce through the control provider,
/// or UNSUPPORTED.
async fn serve_announce(
    conn: Conn,
    ctx: Arc<ServeCtx>,
    identity: Arc<PeerIdentity>,
    stream: u64,
    payload: Vec<u8>,
) {
    let resp = match &ctx.control {
        Some(c) => match c.announce(&payload, &identity).await {
            Ok(bytes) => Resp::Payload { bytes },
            Err(e) => Resp::Err { code: err::BAD_REQUEST, msg: e },
        },
        None => unsupported(),
    };
    let _ = conn.respond(stream, resp).await;
}

/// Send `Signed` across as many frames as it takes. A large xite's
/// content.json is bigger than one frame, and an oversize frame fails to
/// encode in the writer task, which tears down the WHOLE multiplexed
/// connection (not just this stream); refusing it instead simply made such
/// a xite unclonable. The client concatenates until the terminal frame
/// (`fetch::fetch_signed`).
async fn serve_signed(conn: Conn, stream: u64, bytes: Vec<u8>) {
    let mut rest = &bytes[..];
    while rest.len() > BATCH_BUDGET {
        let (head, tail) = rest.split_at(BATCH_BUDGET);
        rest = tail;
        // A peer that gave up mid-body stops the rest of it.
        if conn.take_cancelled(stream) {
            return;
        }
        if conn
            .send(Frame {
                stream,
                body: FrameBody::Resp { last: false, resp: Resp::Signed { bytes: head.to_vec() } },
            })
            .await
            .is_err()
        {
            return;
        }
    }
    let _ = conn
        .send(Frame {
            stream,
            body: FrameBody::Resp { last: true, resp: Resp::Signed { bytes: rest.to_vec() } },
        })
        .await;
}

/// Send `SignedList` across as many frames as it takes. A xite with
/// thousands of per-user content.json files overflows a single frame, and
/// an oversize frame fails to encode in the writer task, which tears down
/// the WHOLE multiplexed connection (not just this stream). Chunking like
/// `serve_many` keeps a big forum servable.
async fn serve_signed_list(conn: Conn, stream: u64, entries: Vec<(String, u64, u64)>) {
    let mut batch: Vec<(String, u64, u64)> = Vec::new();
    let mut bytes = 0usize;
    for e in entries {
        // path bytes + two varints, generously rounded.
        let cost = e.0.len() + 24;
        if bytes + cost > BATCH_BUDGET && !batch.is_empty() {
            let items = std::mem::take(&mut batch);
            bytes = 0;
            if conn
                .send(Frame {
                    stream,
                    body: FrameBody::Resp { last: false, resp: Resp::SignedList { entries: items } },
                })
                .await
                .is_err()
            {
                return;
            }
        }
        bytes += cost;
        batch.push(e);
    }
    let _ = conn
        .send(Frame {
            stream,
            body: FrameBody::Resp { last: true, resp: Resp::SignedList { entries: batch } },
        })
        .await;
}

/// Send `Updates` across as many frames as it takes, for the same reason
/// as [`serve_signed_list`]. `head` rides on the FINAL frame only: the
/// cursor is only valid once the receiver has every hint before it, so a
/// truncated poll must not advance it.
async fn serve_updates(conn: Conn, stream: u64, updates: Vec<(String, i64)>, head: u64) {
    let mut batch: Vec<(String, i64)> = Vec::new();
    let mut bytes = 0usize;
    for u in updates {
        let cost = u.0.len() + 16;
        if bytes + cost > BATCH_BUDGET && !batch.is_empty() {
            let items = std::mem::take(&mut batch);
            bytes = 0;
            if conn
                .send(Frame {
                    stream,
                    body: FrameBody::Resp {
                        last: false,
                        resp: Resp::Updates { updates: items, head: 0 },
                    },
                })
                .await
                .is_err()
            {
                return;
            }
        }
        bytes += cost;
        batch.push(u);
    }
    let _ = conn
        .send(Frame {
            stream,
            body: FrameBody::Resp { last: true, resp: Resp::Updates { updates: batch, head } },
        })
        .await;
}

async fn serve_range(
    conn: Conn,
    ctx: Arc<ServeCtx>,
    identity: Arc<PeerIdentity>,
    stream: u64,
    obj: ObjId,
    ranges: Vec<(u64, u64)>,
    deadline_ms: u32,
) {
    // Saturating accumulation: a plain .sum() wraps in release, so two
    // ranges of size 2^63 would sum to 0 and slip past the byte cap.
    let total: u64 =
        ranges.iter().map(|(s, e)| e.saturating_sub(*s)).fold(0u64, u64::saturating_add);
    if ranges.len() > MAX_RANGES_PER_REQ || total > MAX_BYTES_PER_REQ {
        let _ = conn
            .respond(stream, Resp::Err { code: err::LIMIT, msg: "range caps exceeded".into() })
            .await;
        return;
    }

    // What actually goes on the wire, not what was asked for: the encoder
    // rounds every range outward to a whole chunk group and adds proof
    // bytes, so a 1-byte range costs a full group. Charging the requested
    // size would let 64 one-byte ranges draw ~1 MiB while accounting for
    // 64 bytes, which is the global cap and the foreground yield gone.
    const GROUP: u64 = epix_blob::bitfield::GROUP_BYTES;
    let charged: u64 = ranges
        .iter()
        .map(|&(s, e)| {
            if e > s {
                (e.div_ceil(GROUP) - s / GROUP).saturating_mul(GROUP)
            } else {
                0
            }
        })
        .fold(0u64, u64::saturating_add);

    // A first-paint-sized OBJECT, or an explicitly tight-deadline request
    // (streaming seek), streams on the connection's priority lane so it
    // preempts a large background range; a patient bulk range (no deadline)
    // yields to it. This is the deadline tier the plan calls for, enforced
    // at the writer rather than only advertised to the peer. Classified by
    // the object's TOTAL size (one store stat), not the request size: a
    // small batch out of a huge video is bulk, not first-paint, so media
    // never drains the free budget meant for page assets. An unknown
    // object falls back to the request size (it fails NOT_FOUND below
    // anyway).
    let obj_size = ctx.store.info(obj).ok().flatten().map(|(size, _)| size);
    let first_paint = obj_size.unwrap_or(charged) <= FIRST_PAINT_OBJECT_BYTES;
    let bulk = !first_paint && deadline_ms == 0;

    // Bulk governance: consult the choker. First-paint objects (index +
    // small bundles) are exempt up to the free budget; a choked or
    // throttled peer is refused with the comeback hint (typed when its
    // Hello advertised the cap) so it retries HERE at the right moment
    // instead of striking us out. Control-plane bypasses this.
    if let Some(choker) = &ctx.choker {
        let foreground = ctx.foreground.load(std::sync::atomic::Ordering::Relaxed);
        let now = (ctx.now)();
        let (decision, retry_secs) = {
            let mut c = choker.lock().expect("choker");
            let d = c.decide(&identity.node_pk, charged, first_paint, foreground, now);
            (d, c.retry_after_secs(d, now))
        };
        match decision {
            ServeDecision::Serve | ServeDecision::FirstPaint => {}
            ServeDecision::Choked | ServeDecision::Throttled => {
                let _ = conn.respond(stream, busy_resp(&identity, retry_secs, "choked")).await;
                return;
            }
        }
    }

    let byte_ranges: Vec<std::ops::Range<u64>> =
        ranges.iter().map(|(s, e)| *s..*e).collect();

    // Bounded global admission to the encode stage: at most
    // MAX_ENCODE_QUEUE serves running-or-queued process-wide; past that
    // the request rides out one drain window and is then refused with a
    // retry hint rather than parked on the encode semaphore without bound.
    let Some(_queue_slot) = encode_queue_slot().await else {
        let _ = conn
            .respond(stream, busy_resp(&identity, ENCODE_QUEUE_RETRY_SECS, "serve queue full"))
            .await;
        return;
    };
    // Take a process-wide encode slot before spending a blocking thread, so
    // encodes can never dominate the pool the whole node shares (see
    // ENCODE_SLOTS). Held for the encode's lifetime.
    let Ok(_encode_slot) = ENCODE_SLOTS.acquire().await else {
        let _ = conn
            .respond(stream, Resp::Err { code: err::INTERNAL, msg: "encoder closed".into() })
            .await;
        return;
    };

    // Encode on a blocking thread, streaming frames through the writer
    // adapter as they fill — bounded memory, cancellable between frames.
    let store = ctx.store.clone();
    let now = (ctx.now)();
    let writer_conn = conn.clone();
    let res = tokio::task::spawn_blocking(move || {
        let mut sink = FrameSink::new(writer_conn, stream, bulk);
        store.encode_slice(obj, &byte_ranges, &mut sink, now)?;
        sink.finish()
    })
    .await;

    match res {
        Ok(Ok(())) => {
            // FrameSink sent the terminal frame: the whole range went out,
            // so credit what was put on the wire (the charged bytes).
            if let Some(hook) = &ctx.on_served {
                hook(obj, charged);
            }
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
            // Peer cancelled: nothing more to send.
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            // The lane is closed: there is nowhere to put an error frame.
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
            // The peer stopped draining its lane and `blocking_send`'s stall
            // deadline fired. The queue is still full, so an error frame
            // would only pile onto it (holding this encode slot for up to
            // the write deadline). Tear the link down instead: aborting
            // silently left the peer waiting out its own stream timeout
            // (up to 120s) against a response that was never coming, while
            // a dropped link fails its read at once.
            conn.shutdown();
        }
        Ok(Err(e)) => {
            let code =
                if e.kind() == std::io::ErrorKind::NotFound { err::NOT_FOUND } else { err::INTERNAL };
            let _ = conn.respond(stream, Resp::Err { code, msg: e.to_string() }).await;
        }
        Err(join_err) => {
            let _ = conn
                .respond(stream, Resp::Err { code: err::INTERNAL, msg: join_err.to_string() })
                .await;
        }
    }
}

/// Per-item cost of a `Many` batch beyond the payload itself: a 32-byte
/// ObjId (postcard writes `[u8; 32]` raw) plus the payload's length varint.
/// Unbudgeted, a full 256-item batch overshoots the frame cap by more than
/// the slack, and an oversize frame kills the whole connection.
const MANY_ITEM_OVERHEAD: usize = 35;

async fn serve_many(
    conn: Conn,
    ctx: Arc<ServeCtx>,
    identity: Arc<PeerIdentity>,
    stream: u64,
    objs: Vec<ObjId>,
) {
    if objs.len() > MAX_MANY_ITEMS {
        let _ = conn
            .respond(stream, Resp::Err { code: err::LIMIT, msg: "too many items".into() })
            .await;
        return;
    }
    let now = (ctx.now)();

    // Size the reply before reading a byte of it, so it can be charged to
    // the governor item by item. Without this a peer draws up to
    // MAX_MANY_ITEMS * MAX_MANY_ITEM_BYTES per request with no accounting at
    // all, which is the global cap, the foreground yield and reciprocity
    // choking defeated by picking one request type.
    let Some(mut servable) = many_servable(&conn, ctx.store.clone(), stream, objs).await else {
        return;
    };
    let asked = servable.len();

    let (bulk, refused_retry) = admit_many(&ctx, &identity, &mut servable, now);
    if servable.is_empty() && asked > 0 {
        // Not one item fits right now. Say BUSY (with the comeback hint)
        // rather than send an empty batch, which would read as "we hold
        // none of these".
        let _ = conn
            .respond(stream, busy_resp(&identity, refused_retry.unwrap_or(1), "choked"))
            .await;
        return;
    }

    // Same bounded global admission as the range path.
    let Some(_queue_slot) = encode_queue_slot().await else {
        let _ = conn
            .respond(stream, busy_resp(&identity, ENCODE_QUEUE_RETRY_SECS, "serve queue full"))
            .await;
        return;
    };
    // Take the same process-wide encode slot the range path takes. This
    // blocking thread also parks on the peer's drain rate (blocking_send's
    // stall deadline), so without the permit GetMany starves the shared
    // blocking pool through a request type the cap did not cover.
    let Ok(_encode_slot) = ENCODE_SLOTS.acquire().await else {
        let _ = conn
            .respond(stream, Resp::Err { code: err::INTERNAL, msg: "encoder closed".into() })
            .await;
        return;
    };

    // Read and frame on a blocking thread too: `read_bytes` is synchronous
    // file IO, up to MAX_MANY_ITEMS times. Frames go out through the same
    // blocking senders the range encoder uses, so backpressure and the send
    // stall deadline still apply.
    let store = ctx.store.clone();
    let writer_conn = conn.clone();
    let on_served = ctx.on_served.clone();
    let res = tokio::task::spawn_blocking(move || {
        read_and_frame_many(&store, &writer_conn, stream, servable, now, bulk, on_served)
    })
    .await;
    if let Err(join_err) = res {
        // The terminal frame never went out, so the peer's stream would hang
        // on the reply that ends it.
        let _ = conn
            .respond(stream, Resp::Err { code: err::INTERNAL, msg: join_err.to_string() })
            .await;
    }
}

/// The `GetMany` sizing pass: which of `objs` the store can serve whole
/// (present, complete, within the per-item cap), with sizes, in request
/// order. Runs off the handler task because `info` is synchronous store IO
/// and a full batch is MAX_MANY_ITEMS of them, same reason serve_range
/// encodes on a blocking thread. On a join failure it answers the stream
/// INTERNAL and returns None, so the caller must only return, not reply.
async fn many_servable(
    conn: &Conn,
    store: Arc<Store>,
    stream: u64,
    objs: Vec<ObjId>,
) -> Option<Vec<(ObjId, u64)>> {
    let sized = tokio::task::spawn_blocking(move || {
        objs.into_iter()
            .filter_map(|obj| match store.info(obj) {
                Ok(Some((size, true))) if size <= MAX_MANY_ITEM_BYTES => Some((obj, size)),
                _ => None,
            })
            .collect()
    })
    .await;
    match sized {
        Ok(v) => Some(v),
        Err(join_err) => {
            let _ = conn
                .respond(stream, Resp::Err { code: err::INTERNAL, msg: join_err.to_string() })
                .await;
            None
        }
    }
}

/// The `GetMany` admission pass. GetMany is cold sync of small whole
/// blobs, so each item is charged as first-paint: a normal xite sync draws
/// on the free budget and then falls through to the global cap and the
/// unchoke set, exactly like a range serve past its free budget.
///
/// Charged ITEM BY ITEM, not as one batch. A full batch is up to
/// MAX_MANY_ITEMS * MAX_MANY_ITEM_BYTES (16 MiB) while the global cap is
/// a per-SECOND budget of a few MB, so one decision for the whole batch
/// throttles any large batch deterministically, for every peer, forever.
/// The batch is cut where the governor stops admitting instead; the
/// client sees the rest as missing and asks the next peer (fetch_many
/// reports missing ids, and get_many_pass re-asks per peer).
///
/// Truncates `servable` to the admitted prefix (untouched without a
/// choker) and returns (bulk, refused_retry): `bulk` is true when any
/// admitted item drew past the free budget, which routes the reply onto
/// the bulk lane; `refused_retry` is the comeback hint (secs) of the
/// decision that cut the batch, `None` when nothing was refused.
/// Synchronous, so the choker guard is never held across an await.
fn admit_many(
    ctx: &ServeCtx,
    identity: &PeerIdentity,
    servable: &mut Vec<(ObjId, u64)>,
    now: u64,
) -> (bool, Option<u64>) {
    let mut bulk = false;
    let mut refused_retry = None;
    if let Some(choker) = &ctx.choker {
        let foreground = ctx.foreground.load(std::sync::atomic::Ordering::Relaxed);
        let mut c = choker.lock().expect("choker");
        let mut admitted = 0usize;
        for (_, size) in servable.iter() {
            let decision = c.decide(&identity.node_pk, *size, true, foreground, now);
            match decision {
                ServeDecision::FirstPaint => {}
                // Past the free budget this is ordinary bulk upload: it must
                // not preempt governed ranges on the priority lane.
                ServeDecision::Serve => bulk = true,
                ServeDecision::Choked | ServeDecision::Throttled => {
                    refused_retry = Some(c.retry_after_secs(decision, now));
                    break;
                }
            }
            admitted += 1;
        }
        servable.truncate(admitted);
    }
    (bulk, refused_retry)
}

/// The `GetMany` read+frame stage, run on a blocking thread: read each
/// admitted item, pack items into frames under BATCH_BUDGET, and send
/// every frame of the stream on the one lane `bulk` picked (mixing them
/// would let the terminal frame overtake data the peer has not seen yet).
/// An unreadable item is silently omitted (the client refetches); the
/// terminal frame goes out unless a send fails first. `on_served` is
/// credited per item, after the frame carrying it was actually sent.
fn read_and_frame_many(
    store: &Store,
    conn: &Conn,
    stream: u64,
    servable: Vec<(ObjId, u64)>,
    now: u64,
    bulk: bool,
    on_served: Option<ServedHook>,
) {
    let sizes = |items: &[(ObjId, Vec<u8>)]| -> Vec<(ObjId, u64)> {
        items.iter().map(|(obj, bytes)| (*obj, bytes.len() as u64)).collect()
    };
    let credit = |items: Vec<(ObjId, u64)>| {
        if let Some(hook) = &on_served {
            for (obj, bytes) in items {
                hook(obj, bytes);
            }
        }
    };
    let mut batch: Vec<(ObjId, Vec<u8>)> = Vec::new();
    let mut batch_bytes = 0usize;
    for (obj, _) in servable {
        let bytes = match store.read_bytes(obj, now) {
            Ok(b) => b,
            Err(_) => continue, // absent/corrupt: silently omitted, client refetches
        };
        let cost = bytes.len() + MANY_ITEM_OVERHEAD;
        if batch_bytes + cost > BATCH_BUDGET && !batch.is_empty() {
            let out = std::mem::take(&mut batch);
            batch_bytes = 0;
            let served = sizes(&out);
            let frame = Frame {
                stream,
                body: FrameBody::Resp { last: false, resp: Resp::Many { items: out } },
            };
            if let Err(e) = send_on_lane(conn, frame, bulk) {
                stalled_teardown(conn, &e);
                return;
            }
            credit(served);
        }
        batch_bytes += cost;
        batch.push((obj, bytes));
    }
    let served = sizes(&batch);
    let frame =
        Frame { stream, body: FrameBody::Resp { last: true, resp: Resp::Many { items: batch } } };
    match send_on_lane(conn, frame, bulk) {
        Ok(()) => credit(served),
        Err(e) => stalled_teardown(conn, &e),
    }
}

/// Send-stall handling shared by the blocking serve paths: a TimedOut from
/// `blocking_send` means the peer stopped draining its lane, and an error
/// frame cannot follow it there (the lane is full; queueing one holds an
/// encode slot up to the write deadline). Tear the link down so the peer's
/// read fails now instead of after its own stream timeout. Any other error
/// means the lane is already gone and there is nothing to do.
fn stalled_teardown(conn: &Conn, e: &std::io::Error) {
    if e.kind() == std::io::ErrorKind::TimedOut {
        conn.shutdown();
    }
}

/// Blocking-send one frame on the connection's bulk or priority lane.
fn send_on_lane(conn: &Conn, frame: Frame, bulk: bool) -> std::io::Result<()> {
    if bulk {
        conn.blocking_send_bulk(frame)
    } else {
        conn.blocking_send(frame)
    }
}

/// `io::Write` adapter that turns encoded slice bytes into ≤64 KiB Data
/// frames pushed onto the connection's outbound queue via blocking_send
/// (it runs on a spawn_blocking thread). Checks peer-cancel between
/// frames and reports it as `ErrorKind::Interrupted`.
struct FrameSink {
    conn: Conn,
    stream: u64,
    buf: Vec<u8>,
    /// Route frames through the connection's bulk lane (background range)
    /// vs the priority lane (first-paint / tight deadline).
    bulk: bool,
}

impl FrameSink {
    fn new(conn: Conn, stream: u64, bulk: bool) -> Self {
        Self { conn, stream, buf: Vec::with_capacity(MAX_FRAME_LEN), bulk }
    }

    fn send(&mut self, last: bool) -> std::io::Result<()> {
        if self.conn.take_cancelled(self.stream) {
            return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "peer cancelled"));
        }
        let bytes = std::mem::take(&mut self.buf);
        let frame = Frame { stream: self.stream, body: FrameBody::Data { last, bytes } };
        // The error is returned as-is so its KIND survives: `blocking_send`
        // answers BrokenPipe for a closed lane and TimedOut when its stall
        // deadline fires on a peer that stopped draining. Flattening both to
        // BrokenPipe hid a stalled peer behind a closed connection.
        if self.bulk {
            self.conn.blocking_send_bulk(frame)
        } else {
            self.conn.blocking_send(frame)
        }
    }

    /// Flush the tail and send the terminal frame.
    fn finish(mut self) -> std::io::Result<()> {
        self.send(true)
    }
}

impl std::io::Write for FrameSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            let room = MAX_FRAME_LEN - self.buf.len();
            let take = room.min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == MAX_FRAME_LEN {
                self.send(false)?;
            }
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::choke::{Choker, Reach, FIRST_PAINT_FREE_BYTES};
    use crate::frame;
    use epix_blob::Ns;

    const TEST_KEY: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";

    /// Signed-content provider that answers every path with one fixed body.
    struct Fixture {
        signed: Option<Vec<u8>>,
        /// When set, `get_signed` never returns, so the serve it runs under
        /// keeps its concurrency permit for good (the permit-starvation test).
        block: bool,
    }

    #[async_trait::async_trait]
    impl SignedProvider for Fixture {
        async fn get_signed(&self, _xite: &str, _inner_path: &str) -> Option<Vec<u8>> {
            if self.block {
                std::future::pending::<()>().await;
            }
            self.signed.clone()
        }
        async fn list_signed(&self, _xite: &str, _since: u64) -> Vec<(String, u64, u64)> {
            Vec::new()
        }
        async fn xite_summary(&self, _xite: &str) -> Option<(u64, u64, u64)> {
            None
        }
        async fn apply_update(
            &self,
            _xite: &str,
            _inner_path: &str,
            _signed: &[u8],
            _inline: &[(ObjId, Vec<u8>)],
            _modified: f64,
            _diffs: &[(String, Vec<u8>)],
            _sender_peers: &[String],
            _source: UpdateSource,
        ) -> Result<bool, String> {
            Ok(true)
        }
    }

    type PulledUpdate = (Vec<u8>, String, Reach);

    struct PullingFixture {
        pulled: Arc<Mutex<Option<PulledUpdate>>>,
    }

    #[async_trait::async_trait]
    impl SignedProvider for PullingFixture {
        async fn get_signed(&self, _xite: &str, _inner_path: &str) -> Option<Vec<u8>> {
            None
        }

        async fn list_signed(&self, _xite: &str, _since: u64) -> Vec<(String, u64, u64)> {
            Vec::new()
        }

        async fn xite_summary(&self, _xite: &str) -> Option<(u64, u64, u64)> {
            None
        }

        async fn apply_update(
            &self,
            xite: &str,
            _inner_path: &str,
            _signed: &[u8],
            _inline: &[(ObjId, Vec<u8>)],
            _modified: f64,
            _diffs: &[(String, Vec<u8>)],
            _sender_peers: &[String],
            source: UpdateSource,
        ) -> Result<bool, String> {
            let bytes = crate::fetch::fetch_signed(
                &source.conn,
                xite,
                "data/users/alice/posts.json",
            )
            .await
            .map_err(|e| e.to_string())?;
            *self.pulled.lock().unwrap() =
                Some((bytes, source.identity.address, source.reach));
            Ok(true)
        }
    }

    /// Both endpoints use this provider in the circular admission regression.
    /// Every Update waits until all sixteen handlers are active, then pulls a
    /// signed dependency back through the same session that delivered it.
    struct CircularPullingFixture {
        barrier: Arc<tokio::sync::Barrier>,
        body: Vec<u8>,
    }

    #[async_trait::async_trait]
    impl SignedProvider for CircularPullingFixture {
        async fn get_signed(&self, _xite: &str, _inner_path: &str) -> Option<Vec<u8>> {
            Some(self.body.clone())
        }

        async fn list_signed(&self, _xite: &str, _since: u64) -> Vec<(String, u64, u64)> {
            Vec::new()
        }

        async fn xite_summary(&self, _xite: &str) -> Option<(u64, u64, u64)> {
            None
        }

        async fn apply_update(
            &self,
            xite: &str,
            _inner_path: &str,
            _signed: &[u8],
            _inline: &[(ObjId, Vec<u8>)],
            _modified: f64,
            _diffs: &[(String, Vec<u8>)],
            _sender_peers: &[String],
            source: UpdateSource,
        ) -> Result<bool, String> {
            self.barrier.wait().await;
            let got = crate::fetch::fetch_signed(&source.conn, xite, "dependency.json")
                .await
                .map_err(|e| e.to_string())?;
            if got != self.body {
                return Err("same-session dependency body mismatch".into());
            }
            Ok(true)
        }
    }

    fn store_in(dir: &tempfile::TempDir) -> Arc<Store> {
        Arc::new(Store::open(dir.path()).unwrap())
    }

    fn peer() -> Arc<PeerIdentity> {
        Arc::new(PeerIdentity {
            node_pk: vec![7u8; 33],
            address: "test".into(),
            caps: 0,
            version: String::new(),
        })
    }

    fn ctx_for(store: Arc<Store>, provider: Fixture) -> ServeCtx {
        ServeCtx { now: || 0, ..ServeCtx::new(store, Arc::new(provider), TEST_KEY.into()) }
    }

    /// A server-side `Conn` plus the raw far end its frames land on.
    fn wired() -> (Conn, mpsc::Receiver<Incoming>, tokio::io::DuplexStream) {
        let (far, near) = tokio::io::duplex(1 << 20);
        let (conn, incoming) = Conn::start(near, false);
        (conn, incoming, far)
    }

    /// Next frame off the wire. The timeout only fires when a reply never
    /// arrives at all, which is exactly how an unencodable frame reads.
    async fn next_frame(far: &mut tokio::io::DuplexStream) -> Frame {
        tokio::time::timeout(Duration::from_secs(5), frame::read_frame(far))
            .await
            .expect("a reply frame must arrive")
            .expect("the reply frame decodes")
    }

    /// A receiver can pull a merge file back through the connection carrying
    /// Update while the publisher is still waiting for that Update's response.
    /// This is the NAT-safe publish path and also proves the reverse serve loop
    /// starts after client_hello without requiring another Hello.
    #[tokio::test]
    async fn an_update_source_supports_same_session_pull() {
        const PUBLISHER_KEY: &str =
            "2222222222222222222222222222222222222222222222222222222222222222";
        let merge = br#"{"record_format":"epix-orset-1","post":[{"post_id":7}]}"#.to_vec();
        let (publisher_io, receiver_io) = tokio::io::duplex(1 << 20);
        let (publisher, publisher_incoming) = Conn::start(publisher_io, true);
        let (receiver, receiver_incoming) = Conn::start(receiver_io, false);

        let publisher_dir = tempfile::tempdir().unwrap();
        let publisher_ctx = Arc::new(ServeCtx {
            now: || 0,
            ..ServeCtx::new(
                store_in(&publisher_dir),
                Arc::new(Fixture { signed: Some(merge.clone()), block: false }),
                PUBLISHER_KEY.into(),
            )
        });

        let pulled = Arc::new(Mutex::new(None));
        let receiver_dir = tempfile::tempdir().unwrap();
        let receiver_ctx = Arc::new(ServeCtx {
            now: || 0,
            ..ServeCtx::new(
                store_in(&receiver_dir),
                Arc::new(PullingFixture { pulled: pulled.clone() }),
                TEST_KEY.into(),
            )
        });
        tokio::spawn(serve(receiver, receiver_incoming, receiver_ctx, None));

        let receiver_identity = client_hello(&publisher, &publisher_ctx, vec![], None)
            .await
            .expect("receiver authenticates");
        tokio::spawn(serve_authenticated(
            publisher.clone(),
            publisher_incoming,
            publisher_ctx,
            receiver_identity,
            Reach::Overlay,
        ));

        tokio::time::timeout(
            Duration::from_secs(5),
            crate::fetch::push_update(
                &publisher,
                "1Forum",
                "data/users/alice/content.json",
                br#"{"modified":2000}"#,
                2000.0,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
        )
        .await
        .expect("same-session pull must not stall")
        .expect("receiver accepts the update");

        let got = pulled.lock().unwrap().clone().expect("provider pulled the merge file");
        assert_eq!(got.0, merge);
        assert_eq!(got.1, epix_crypt::privatekey_to_address(PUBLISHER_KEY).unwrap());
        assert_eq!(got.2, Reach::Overlay);
        publisher.shutdown();
    }

    /// Eight Updates in each direction used to consume every shared serve
    /// permit. Once all handlers tried to pull a dependency through the same
    /// sessions, neither endpoint could admit the requests needed to finish
    /// those Updates. Dependency traffic has its own bounded admission lane.
    #[tokio::test]
    async fn circular_updates_do_not_block_same_session_pull() {
        let body = br#"{"record_format":"epix-orset-1"}"#.to_vec();
        let barrier = Arc::new(tokio::sync::Barrier::new(MAX_CONCURRENT_UPDATES * 2));
        let (a_io, b_io) = tokio::io::duplex(1 << 20);
        let (a, a_incoming) = Conn::start(a_io, true);
        let (b, b_incoming) = Conn::start(b_io, false);

        let a_dir = tempfile::tempdir().unwrap();
        let a_ctx = Arc::new(ServeCtx {
            now: || 0,
            ..ServeCtx::new(
                store_in(&a_dir),
                Arc::new(CircularPullingFixture {
                    barrier: barrier.clone(),
                    body: body.clone(),
                }),
                TEST_KEY.into(),
            )
        });
        let b_dir = tempfile::tempdir().unwrap();
        let b_ctx = Arc::new(ServeCtx {
            now: || 0,
            ..ServeCtx::new(
                store_in(&b_dir),
                Arc::new(CircularPullingFixture { barrier, body }),
                TEST_KEY.into(),
            )
        });

        tokio::spawn(serve_authenticated(
            a.clone(),
            a_incoming,
            a_ctx,
            (*peer()).clone(),
            Reach::Overlay,
        ));
        tokio::spawn(serve_authenticated(
            b.clone(),
            b_incoming,
            b_ctx,
            (*peer()).clone(),
            Reach::Overlay,
        ));

        let mut pushes = tokio::task::JoinSet::new();
        for _ in 0..MAX_CONCURRENT_UPDATES {
            let conn = a.clone();
            pushes.spawn(async move {
                crate::fetch::push_update(
                    &conn,
                    "1Forum",
                    "content.json",
                    br#"{"modified":2000}"#,
                    2000.0,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
                .await
            });
            let conn = b.clone();
            pushes.spawn(async move {
                crate::fetch::push_update(
                    &conn,
                    "1Forum",
                    "content.json",
                    br#"{"modified":2000}"#,
                    2000.0,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
                .await
            });
        }

        tokio::time::timeout(Duration::from_secs(5), async move {
            while let Some(result) = pushes.join_next().await {
                result.expect("push task completes").expect("peer accepts the Update");
            }
        })
        .await
        .expect("circular same-session pulls must not stall");

        a.shutdown();
        b.shutdown();
    }

    #[tokio::test]
    async fn tracked_authenticated_serve_reports_completed_requests() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (client_io, server_io) = tokio::io::duplex(1 << 20);
        let (client, _client_incoming) = Conn::start(client_io, true);
        let (server, server_incoming) = Conn::start(server_io, false);
        let dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(ctx_for(
            store_in(&dir),
            Fixture { signed: Some(b"tracked".to_vec()), block: false },
        ));
        let completed = Arc::new(AtomicUsize::new(0));
        let hook_count = completed.clone();
        tokio::spawn(serve_authenticated_tracked(
            server,
            server_incoming,
            ctx,
            (*peer()).clone(),
            Reach::Overlay,
            Arc::new(move || {
                hook_count.fetch_add(1, Ordering::Relaxed);
            }),
        ));

        let got = crate::fetch::fetch_signed(&client, "1Forum", "content.json")
            .await
            .expect("signed response succeeds");
        assert_eq!(got, b"tracked");
        tokio::time::timeout(Duration::from_secs(1), async {
            while completed.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completion hook fires");
        assert_eq!(completed.load(Ordering::Relaxed), 1);
        client.shutdown();
    }

    /// A full 256-item batch of near-budget blobs must stay inside the
    /// frame cap. Budgeting only the payloads ignored 35 bytes of per-item
    /// encoding overhead, so the reply overflowed, failed to encode in the
    /// writer task, and took the WHOLE multiplexed connection down.
    #[tokio::test]
    async fn a_full_many_batch_stays_under_the_frame_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let mut ids = Vec::new();
        for i in 0..MAX_MANY_ITEMS as u32 {
            let data: Vec<u8> = (0..240u32).map(|j| (i + j) as u8).collect();
            let id = ObjId::of(&data);
            store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
            ids.push(id);
        }
        let ctx = Arc::new(ctx_for(store, Fixture { signed: None, block: false }));
        let (conn, _incoming, mut far) = wired();
        tokio::spawn(serve_many(conn, ctx, peer(), 4, ids));

        let mut items = 0usize;
        loop {
            let frame = next_frame(&mut far).await;
            assert!(frame::encode(&frame).is_ok(), "every reply frame must be encodable");
            match frame.body {
                FrameBody::Resp { last, resp: Resp::Many { items: got } } => {
                    items += got.len();
                    if last {
                        break;
                    }
                }
                other => panic!("expected Many, got {other:?}"),
            }
        }
        assert_eq!(items, MAX_MANY_ITEMS, "every held item arrives");
    }

    /// GetMany is governed like any other serve. It used to consult the
    /// choker at no point, so a peer that had served us nothing could draw
    /// unmetered megabytes on the priority lane by picking one request type.
    #[tokio::test]
    async fn many_is_choked_once_the_free_budget_is_spent() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let data = vec![9u8; 4096];
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

        let peer = peer();
        // Cap above the free budget: this test spends the whole budget in
        // one call and is about the choke, not the governor.
        let choker = Arc::new(Mutex::new(Choker::new(1 << 40)));
        {
            let mut c = choker.lock().unwrap();
            // The peer has already spent its whole free budget, and holds
            // no unchoke slot (it was never connected in the choker), so
            // past the budget it is choked.
            c.note_peer(&peer.node_pk, Reach::Clearnet, 0);
            assert_eq!(
                c.decide(&peer.node_pk, FIRST_PAINT_FREE_BYTES, true, false, 0),
                ServeDecision::FirstPaint
            );
        }
        let ctx = Arc::new(ctx_for(store, Fixture { signed: None, block: false }).with_choker(choker));
        let (conn, _incoming, mut far) = wired();
        tokio::spawn(serve_many(conn, ctx, peer, 6, vec![id]));

        match next_frame(&mut far).await.body {
            FrameBody::Resp { resp: Resp::Err { code, .. }, .. } => {
                assert_eq!(code, err::BUSY, "a freeloader past its budget is choked")
            }
            other => panic!("expected BUSY, got {other:?}"),
        }
    }

    /// The typed Busy refusal is gated on the PEER's caps bit: an old peer
    /// keeps receiving the legacy `Err { BUSY }` it can decode (postcard
    /// variants are positional, so an unknown appended variant would break
    /// its parse), while a peer that advertised `caps::RETRY_AFTER` gets
    /// the machine-readable comeback hint.
    #[tokio::test]
    async fn busy_is_typed_only_for_peers_that_advertise_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        // A bulk-sized object; the requesting peer holds no unchoke slot
        // (never connected in the choker), so bulk is Choked.
        let data = vec![5u8; FIRST_PAINT_OBJECT_BYTES as usize + 1];
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
        let choker = Arc::new(Mutex::new(Choker::new(1 << 40)));
        let ctx =
            Arc::new(ctx_for(store, Fixture { signed: None, block: false }).with_choker(choker));

        // Legacy peer (caps 0): plain BUSY.
        let (conn, _incoming, mut far) = wired();
        tokio::spawn(serve_range(conn, ctx.clone(), peer(), 2, id, vec![(0, 1024)], 0));
        match next_frame(&mut far).await.body {
            FrameBody::Resp { resp: Resp::Err { code, .. }, .. } => {
                assert_eq!(code, err::BUSY, "an old peer gets the BUSY it can decode")
            }
            other => panic!("expected legacy BUSY, got {other:?}"),
        }

        // A peer that advertised the cap: typed Busy pointing at the next
        // unchoke rotation (ctx clock is 0, so exactly one rotation out).
        let newer = Arc::new(PeerIdentity {
            node_pk: vec![8u8; 33],
            address: "test-new".into(),
            caps: caps::RETRY_AFTER,
            version: String::new(),
        });
        let (conn, _incoming2, mut far2) = wired();
        tokio::spawn(serve_range(conn, ctx, newer, 4, id, vec![(0, 1024)], 0));
        match next_frame(&mut far2).await.body {
            FrameBody::Resp { resp: Resp::Busy { retry_after_ms }, .. } => {
                assert_eq!(
                    retry_after_ms as u64,
                    crate::choke::OPTIMISTIC_ROTATE_SECS * 1000,
                    "the hint points at the next rotation"
                );
            }
            other => panic!("expected typed Busy, got {other:?}"),
        }
    }

    /// The choker is charged what goes on the wire (whole chunk groups plus
    /// proof), not the byte count the peer asked for. Charging the request
    /// let 64 one-byte ranges draw ~1 MiB while accounting for 64 bytes,
    /// which is the per-second bucket gone. The bucket refuses only
    /// first-paint now (bulk is paced at the writer instead), so the probe
    /// object is first-paint sized.
    #[tokio::test]
    async fn scattered_one_byte_ranges_are_charged_by_chunk_group() {
        const GROUP: u64 = epix_blob::bitfield::GROUP_BYTES;

        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        // A first-paint-sized object spanning MAX_RANGES_PER_REQ groups.
        let data = vec![7u8; (MAX_RANGES_PER_REQ as u64 * GROUP) as usize];
        let id = ObjId::of(&data);
        store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

        let peer = peer();
        let choker = Arc::new(Mutex::new(Choker::new(100_000)));
        let ctx = Arc::new(ctx_for(store, Fixture { signed: None, block: false }).with_choker(choker));

        // 64 scattered one-byte ranges: charged as 64 whole groups (1 MiB),
        // over the 100 KB/s bucket, so the first-paint serve is refused.
        let ranges: Vec<(u64, u64)> =
            (0..MAX_RANGES_PER_REQ as u64).map(|i| (i * GROUP, i * GROUP + 1)).collect();
        let (conn, _incoming, mut far) = wired();
        tokio::spawn(serve_range(conn, ctx.clone(), peer.clone(), 8, id, ranges, 0));
        match next_frame(&mut far).await.body {
            FrameBody::Resp { resp: Resp::Err { code, .. }, .. } => {
                assert_eq!(code, err::BUSY, "64 one-byte ranges cost 64 whole chunk groups")
            }
            other => panic!("expected BUSY, got {other:?}"),
        }

        // Control: ONE range of the same shape is a single group, which
        // fits under the bucket, so it serves off the free budget.
        let (conn, _incoming2, mut far2) = wired();
        tokio::spawn(serve_range(conn, ctx, peer, 10, id, vec![(0, 1)], 0));
        match next_frame(&mut far2).await.body {
            FrameBody::Data { .. } => {}
            other => panic!("expected Data, got {other:?}"),
        }
    }

    /// First-paint classification keys on the OBJECT's total size, not the
    /// request's: a small scheduler batch out of a multi-MB video is bulk,
    /// so it neither burns the free budget nor slips past the choke, while
    /// the same peer's small page assets still serve exempt.
    #[tokio::test]
    async fn classification_keys_on_object_size_not_request_size() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        // A "video": bigger than the first-paint object cutoff.
        let big = vec![5u8; FIRST_PAINT_OBJECT_BYTES as usize + 1];
        let big_id = ObjId::of(&big);
        store.insert_bytes(big_id, Ns::Plain, &big, 1).unwrap();
        // A page asset: small.
        let small = vec![6u8; 2048];
        let small_id = ObjId::of(&small);
        store.insert_bytes(small_id, Ns::Plain, &small, 1).unwrap();

        let peer = peer();
        // The peer holds no bulk unchoke slot (never connected in the
        // choker), so its bulk requests are choked while its first-paint
        // requests ride the free budget.
        let choker = Arc::new(Mutex::new(Choker::new(1_000_000_000)));
        choker.lock().unwrap().note_peer(&peer.node_pk, Reach::Clearnet, 0);
        let ctx =
            Arc::new(ctx_for(store, Fixture { signed: None, block: false }).with_choker(choker));

        // A small range of the BIG object is bulk: the choked peer waits.
        let (conn, _incoming, mut far) = wired();
        tokio::spawn(serve_range(conn, ctx.clone(), peer.clone(), 4, big_id, vec![(0, 1024)], 0));
        match next_frame(&mut far).await.body {
            FrameBody::Resp { resp: Resp::Err { code, .. }, .. } => {
                assert_eq!(code, err::BUSY, "a batch out of a big object is bulk")
            }
            other => panic!("expected BUSY, got {other:?}"),
        }

        // The SAME choked peer's request for a small object is first-paint:
        // served off the (untouched) free budget.
        let (conn, _incoming2, mut far2) = wired();
        tokio::spawn(serve_range(conn, ctx, peer, 6, small_id, vec![(0, 2048)], 0));
        match next_frame(&mut far2).await.body {
            FrameBody::Data { .. } => {}
            other => panic!("expected Data, got {other:?}"),
        }
    }

    /// A signed body too large for one frame is chunked, not refused. An
    /// oversize frame fails to encode inside the writer task and tears the
    /// whole connection down, and refusing it instead made a big xite's
    /// content.json unclonable, so the reply streams like SignedList does.
    #[tokio::test]
    async fn an_oversize_signed_body_is_chunked_across_frames() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let body: Vec<u8> =
            (0..BATCH_BUDGET * 2 + 17).map(|i| (i.wrapping_mul(31) % 251) as u8).collect();
        let ctx = Arc::new(ctx_for(store, Fixture { signed: Some(body.clone()), block: false }));
        let (conn, _incoming, mut far) = wired();
        let inc = Incoming {
            stream: 12,
            req: Req::GetSigned { xite: "1Abc".into(), inner_path: "content.json".into() },
            _budget: None,
        };
        tokio::spawn(handle(conn, ctx, peer(), Reach::Clearnet, inc));

        let mut got: Vec<u8> = Vec::new();
        let mut frames = 0usize;
        loop {
            let frame = next_frame(&mut far).await;
            assert!(frame::encode(&frame).is_ok(), "every reply frame must be encodable");
            match frame.body {
                FrameBody::Resp { last, resp: Resp::Signed { bytes } } => {
                    frames += 1;
                    got.extend_from_slice(&bytes);
                    if last {
                        break;
                    }
                }
                other => panic!("expected Signed, got {other:?}"),
            }
        }
        assert!(frames > 1, "a body over one frame must span frames, got {frames}");
        assert_eq!(got, body, "the frames reassemble byte-identically");
    }

    /// The batch is charged to the governor item by item, and cut where the
    /// governor stops admitting. Charging the WHOLE batch in one decision
    /// compared a request of up to 16 MiB against a per-second cap of a few
    /// MB, so every sizeable batch was Throttled deterministically, for every
    /// peer, and the small-file sync path never recovered.
    #[tokio::test]
    async fn a_batch_over_the_global_cap_is_cut_short_not_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let mut ids = Vec::new();
        for i in 0..40u32 {
            let data: Vec<u8> = (0..4096u32).map(|j| (i.wrapping_mul(7) + j) as u8).collect();
            let id = ObjId::of(&data);
            store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();
            ids.push(id);
        }

        let peer = peer();
        let choker = Arc::new(Mutex::new(Choker::new(100_000)));
        {
            let mut c = choker.lock().unwrap();
            // This is about the byte cap, not reciprocity: the items ride
            // the free budget, whose bytes count against the cap, so the
            // cap alone cuts the batch.
            c.note_peer(&peer.node_pk, Reach::Clearnet, 0);
        }
        let ctx =
            Arc::new(ctx_for(store, Fixture { signed: None, block: false }).with_choker(choker));
        let (conn, _incoming, mut far) = wired();
        tokio::spawn(serve_many(conn, ctx, peer, 14, ids));

        let mut items = 0usize;
        loop {
            let frame = next_frame(&mut far).await;
            assert!(frame::encode(&frame).is_ok(), "every reply frame must be encodable");
            match frame.body {
                FrameBody::Resp { last, resp: Resp::Many { items: got } } => {
                    items += got.len();
                    if last {
                        break;
                    }
                }
                other => panic!("expected Many, got {other:?}"),
            }
        }
        // 100_000 / 4096 = 24 whole items fit this second's cap; the other 16
        // come back missing and the client asks the next peer for them.
        assert_eq!(items, 24, "the batch is served up to the cap, not refused whole");
    }

    /// A connection with every serve slot busy is answered BUSY and kept.
    /// Breaking the loop instead dropped the waiting request with no reply at
    /// all and let `incoming` go away under the in-flight serves, so every
    /// later request the peer sent was silently black-holed.
    #[tokio::test(start_paused = true)]
    async fn a_full_serve_queue_answers_busy_and_keeps_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_in(&dir);
        let ctx = Arc::new(ctx_for(store, Fixture { signed: None, block: true }));
        let (conn, _incoming, mut far) = wired();
        let (tx, rx) = mpsc::channel::<Incoming>(MAX_CONCURRENT_SERVES + 4);
        tokio::spawn(serve(conn, rx, ctx, None));

        let hello = Hello {
            net: NET_ID.into(),
            node_pk: epix_crypt::private_to_compressed_pubkey(TEST_KEY).unwrap(),
            binding_sig: Vec::new(),
            caps: 0,
            listen: Vec::new(),
            version: String::new(),
        };
        tx.send(Incoming { stream: 2, req: Req::Hello(hello), _budget: None }).await.unwrap();
        match next_frame(&mut far).await.body {
            FrameBody::Resp { resp: Resp::HelloAck(_), .. } => {}
            other => panic!("expected HelloAck, got {other:?}"),
        }

        // Pin every serve slot on a handler that never returns, then ask for
        // one more thing.
        let get = || Req::GetSigned { xite: "1Abc".into(), inner_path: "content.json".into() };
        for i in 0..MAX_CONCURRENT_SERVES as u64 {
            tx.send(Incoming { stream: 4 + i, req: get(), _budget: None }).await.unwrap();
        }
        tx.send(Incoming { stream: 100, req: get(), _budget: None }).await.unwrap();

        // The wait for a slot is bounded by IDLE_TIMEOUT, and virtual time
        // jumps there because nothing else can make progress.
        let frame = tokio::time::timeout(IDLE_TIMEOUT * 4, frame::read_frame(&mut far))
            .await
            .expect("the starved request must be answered")
            .expect("the reply frame decodes");
        assert_eq!(frame.stream, 100, "the answer is for the request that waited");
        match frame.body {
            FrameBody::Resp { resp: Resp::Err { code, .. }, .. } => {
                assert_eq!(code, err::BUSY, "a full serve queue answers BUSY")
            }
            other => panic!("expected BUSY, got {other:?}"),
        }
    }
}
