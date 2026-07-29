//! The EDX protocol server: answers a connection's inbound requests
//! against the object store and a signed-content provider.
//!
//! Serving is streaming end to end: `GetRange` encodes the verified
//! slice DIRECTLY into ≤64 KiB Data frames through a writer adapter (a
//! spawn_blocking encode thread feeding the connection's frame queue via
//! blocking_send) — a multi-GB range never materializes in memory, and a
//! peer Cancel aborts the encode between frames.
//!
//! Control-plane limits enforced here, per connection: a Hello gate
//! (nothing else is answered first; wrong net or bad channel binding
//! kills the connection), a concurrent-serve semaphore, and per-request
//! caps on range count/bytes and GetMany item count/size. Cross-peer
//! fairness (choking) sits a layer above and only shapes BULK data;
//! these caps are the hard backstop.

use std::sync::Arc;

use epix_blob::store::Store;
use epix_blob::ObjId;
use tokio::sync::{mpsc, Semaphore};

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
/// Concurrent serve tasks per connection.
pub const MAX_CONCURRENT_SERVES: usize = 8;
/// A GetRange no larger than this is treated as first-paint (index.html +
/// first bundles), exempt from choking up to the per-peer free budget.
pub const FIRST_PAINT_OBJECT_BYTES: u64 = 1 << 20;

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
    /// publisher's dial-back addresses. Ok(true) = accepted and new,
    /// Ok(false) = stale/known.
    async fn apply_update(
        &self,
        xite: &str,
        inner_path: &str,
        signed: &[u8],
        inline: &[(ObjId, Vec<u8>)],
        modified: f64,
        diffs: &[(String, Vec<u8>)],
        sender_peers: &[String],
    ) -> Result<bool, String>;
}

/// Control-plane access the server delegates to (the successors to the
/// legacy msgpack control commands: propagation poll, PEX, tracker-set
/// gossip, DHT RPC, tracker announce). Separate from [`SignedProvider`]
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
    /// plus the new head cursor (`meshGetUpdates` successor).
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

/// Everything a serve loop needs.
pub struct ServeCtx {
    pub store: Arc<Store>,
    pub provider: Arc<dyn SignedProvider>,
    /// Control-plane services (None = content-only node; control
    /// requests answer UNSUPPORTED and `caps::CONTROL` must not be set).
    pub control: Option<Arc<dyn ControlProvider>>,
    /// This node's identity key (hex) for Hello/HelloAck binding sigs.
    pub privatekey: String,
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
}

/// The peer identity a completed handshake established.
#[derive(Clone, Debug)]
pub struct PeerIdentity {
    pub node_pk: Vec<u8>,
    pub address: String,
    pub caps: u32,
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
            caps: caps::MESH,
            now: now_unix,
            choker: None,
            foreground: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Attach the shared upload governor.
    pub fn with_choker(mut self, choker: Arc<Mutex<Choker>>) -> Self {
        self.choker = Some(choker);
        self
    }

    /// Attach the control-plane services and advertise `caps::CONTROL`.
    pub fn with_control(mut self, control: Arc<dyn ControlProvider>) -> Self {
        self.control = Some(control);
        self.caps |= caps::CONTROL;
        self
    }
}

/// Build our Hello/HelloAck binding signature for this session.
/// `handshake_hash` is Some on Noise links, None on overlay links (their
/// transport already authenticates the endpoint).
fn binding_sig(privatekey: &str, handshake_hash: Option<&[u8; 32]>) -> std::io::Result<Vec<u8>> {
    match handshake_hash {
        Some(h) => noise::sign_binding(h, privatekey),
        None => Ok(Vec::new()),
    }
}

/// Validate a peer's Hello/HelloAck identity claims. Returns the
/// established identity or an error string (which kills the connection).
fn check_identity(
    net: &str,
    node_pk: &[u8],
    sig: &[u8],
    peer_caps: u32,
    handshake_hash: Option<&[u8; 32]>,
) -> Result<PeerIdentity, String> {
    if net != NET_ID {
        return Err(format!("wrong net {net:?}"));
    }
    let address =
        epix_crypt::pubkey_to_address(node_pk).map_err(|e| format!("bad node_pk: {e}"))?;
    if let Some(hash) = handshake_hash {
        if !noise::verify_binding(hash, node_pk, sig) {
            return Err(format!("channel binding failed for {address}"));
        }
    }
    Ok(PeerIdentity { node_pk: node_pk.to_vec(), address, caps: peer_caps })
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
        binding_sig: binding_sig(&ctx.privatekey, handshake_hash.as_ref())?,
        caps: ctx.caps,
        listen,
    };
    match conn.request(Req::Hello(hello)).await? {
        Resp::HelloAck(ack) => {
            check_identity(&ack.net, &ack.node_pk, &ack.binding_sig, ack.caps, handshake_hash.as_ref())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
        }
        Resp::Err { code, msg } => Err(std::io::Error::other(format!("hello refused {code}: {msg}"))),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected HelloAck, got {other:?}"),
        )),
    }
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
    // Hello gate.
    let first = incoming.recv().await?;
    let identity = match first.req {
        Req::Hello(hello) => {
            match check_identity(
                &hello.net,
                &hello.node_pk,
                &hello.binding_sig,
                hello.caps,
                handshake_hash.as_ref(),
            ) {
                Ok(id) => {
                    let ack = HelloAck {
                        net: NET_ID.into(),
                        node_pk: match epix_crypt::private_to_compressed_pubkey(&ctx.privatekey) {
                            Ok(pk) => pk,
                            Err(_) => return None,
                        },
                        binding_sig: binding_sig(&ctx.privatekey, handshake_hash.as_ref())
                            .ok()?,
                        caps: ctx.caps,
                        observed: None,
                    };
                    if conn.respond(first.stream, Resp::HelloAck(ack)).await.is_err() {
                        return None;
                    }
                    id
                }
                Err(e) => {
                    let _ = conn
                        .respond(first.stream, Resp::Err { code: err::BAD_REQUEST, msg: e })
                        .await;
                    return None;
                }
            }
        }
        _ => {
            let _ = conn
                .respond(
                    first.stream,
                    Resp::Err { code: err::BAD_REQUEST, msg: "hello first".into() },
                )
                .await;
            return None;
        }
    };

    // Register the peer with the governor (reachability from the link
    // type: overlay links have no handshake hash).
    let reach = if handshake_hash.is_some() { Reach::Clearnet } else { Reach::Overlay };
    if let Some(choker) = &ctx.choker {
        choker.lock().expect("choker").note_peer(&identity.node_pk, reach, (ctx.now)());
    }
    let identity = Arc::new(identity);

    let serves = Arc::new(Semaphore::new(MAX_CONCURRENT_SERVES));
    while let Some(inc) = incoming.recv().await {
        let Ok(permit) = serves.clone().acquire_owned().await else { break };
        let conn = conn.clone();
        let ctx = ctx.clone();
        let identity = identity.clone();
        tokio::spawn(async move {
            handle(conn, ctx, identity, inc).await;
            drop(permit);
        });
    }
    Some((*identity).clone())
}

async fn handle(conn: Conn, ctx: Arc<ServeCtx>, identity: Arc<PeerIdentity>, inc: Incoming) {
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
            serve_many(conn, ctx, stream, objs).await;
        }
        Req::GetBitfield { obj } => {
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
        Req::GetSigned { xite, inner_path } => {
            let resp = match ctx.provider.get_signed(&xite, &inner_path).await {
                Some(bytes) => Resp::Signed { bytes },
                None => Resp::Err { code: err::NOT_FOUND, msg: format!("{xite}/{inner_path}") },
            };
            let _ = conn.respond(stream, resp).await;
        }
        Req::ListSigned { xite, since } => {
            let entries = ctx.provider.list_signed(&xite, since).await;
            let _ = conn.respond(stream, Resp::SignedList { entries }).await;
        }
        Req::HasXite { xite } => {
            let resp = match ctx.provider.xite_summary(&xite).await {
                Some((signed_files, newest_modified, held_bytes)) => {
                    Resp::XiteSummary { signed_files, newest_modified, held_bytes }
                }
                None => Resp::Err { code: err::NOT_FOUND, msg: xite },
            };
            let _ = conn.respond(stream, resp).await;
        }
        Req::HaveRanges { .. } => {
            // Availability notification: consumed by the fetch scheduler
            // (see fetch.rs); as a server there is nothing to answer.
        }
        Req::Update { xite, inner_path, signed, inline, modified, diffs, sender_peers } => {
            let resp = match ctx
                .provider
                .apply_update(&xite, &inner_path, &signed, &inline, modified, &diffs, &sender_peers)
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
            let resp = match &ctx.control {
                Some(c) => {
                    let (updates, head) = c.updates_since(after).await;
                    Resp::Updates { updates, head }
                }
                None => unsupported(),
            };
            let _ = conn.respond(stream, resp).await;
        }
        Req::Pex { xite, need, peers } => {
            let resp = match &ctx.control {
                Some(c) => Resp::Peers { peers: c.pex(&xite, need, &peers, &identity).await },
                None => unsupported(),
            };
            let _ = conn.respond(stream, resp).await;
        }
        Req::GetTrackers => {
            let resp = match &ctx.control {
                Some(c) => Resp::Trackers { trackers: c.trackers().await },
                None => unsupported(),
            };
            let _ = conn.respond(stream, resp).await;
        }
        Req::Kad { payload } => {
            let resp = match &ctx.control {
                Some(c) => match c.kad(&payload, &identity).await {
                    Ok(bytes) => Resp::Payload { bytes },
                    Err(e) => Resp::Err { code: err::BAD_REQUEST, msg: e },
                },
                None => unsupported(),
            };
            let _ = conn.respond(stream, resp).await;
        }
        Req::Announce { payload } => {
            let resp = match &ctx.control {
                Some(c) => match c.announce(&payload, &identity).await {
                    Ok(bytes) => Resp::Payload { bytes },
                    Err(e) => Resp::Err { code: err::BAD_REQUEST, msg: e },
                },
                None => unsupported(),
            };
            let _ = conn.respond(stream, resp).await;
        }
    }
}

/// The reply for a control request on a node that doesn't serve control.
fn unsupported() -> Resp {
    Resp::Err { code: err::UNSUPPORTED, msg: "control plane not served".into() }
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

    // A first-paint-sized object, or an explicitly tight-deadline request
    // (streaming seek), streams on the connection's priority lane so it
    // preempts a large background range; a patient bulk range (no deadline)
    // yields to it. This is the deadline tier the plan calls for, enforced
    // at the writer rather than only advertised to the peer.
    let first_paint = total <= FIRST_PAINT_OBJECT_BYTES;
    let bulk = !first_paint && deadline_ms == 0;

    // Bulk governance: consult the choker. First-paint objects (index +
    // small bundles) are exempt up to the free budget; a choked peer is
    // told BUSY so it retries elsewhere (the swarm self-heals), and a
    // throttled one likewise. Control-plane and first-paint bypass this.
    if let Some(choker) = &ctx.choker {
        let foreground = ctx.foreground.load(std::sync::atomic::Ordering::Relaxed);
        let decision = choker.lock().expect("choker").decide(
            &identity.node_pk,
            total,
            first_paint,
            foreground,
            (ctx.now)(),
        );
        match decision {
            ServeDecision::Serve | ServeDecision::FirstPaint => {}
            ServeDecision::Choked | ServeDecision::Throttled => {
                let _ = conn
                    .respond(stream, Resp::Err { code: err::BUSY, msg: "choked".into() })
                    .await;
                return;
            }
        }
    }

    let byte_ranges: Vec<std::ops::Range<u64>> =
        ranges.iter().map(|(s, e)| *s..*e).collect();

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
        Ok(Ok(())) => {} // FrameSink sent the terminal frame.
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {
            // Peer cancelled: nothing more to send.
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

async fn serve_many(conn: Conn, ctx: Arc<ServeCtx>, stream: u64, objs: Vec<ObjId>) {
    if objs.len() > MAX_MANY_ITEMS {
        let _ = conn
            .respond(stream, Resp::Err { code: err::LIMIT, msg: "too many items".into() })
            .await;
        return;
    }
    let now = (ctx.now)();
    let mut batch: Vec<(ObjId, Vec<u8>)> = Vec::new();
    let mut batch_bytes = 0usize;
    for obj in objs {
        let bytes = match ctx.store.info(obj) {
            Ok(Some((size, true))) if size <= MAX_MANY_ITEM_BYTES => {
                match ctx.store.read_bytes(obj, now) {
                    Ok(b) => b,
                    Err(_) => continue, // absent/corrupt: silently omitted, client refetches
                }
            }
            _ => continue,
        };
        if batch_bytes + bytes.len() > MAX_FRAME_LEN - 4096 && !batch.is_empty() {
            let out = std::mem::take(&mut batch);
            batch_bytes = 0;
            if conn
                .send(Frame { stream, body: FrameBody::Resp { last: false, resp: Resp::Many { items: out } } })
                .await
                .is_err()
            {
                return;
            }
        }
        batch_bytes += bytes.len();
        batch.push((obj, bytes));
    }
    let _ = conn
        .send(Frame { stream, body: FrameBody::Resp { last: true, resp: Resp::Many { items: batch } } })
        .await;
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
        if self.bulk {
            self.conn.blocking_send_bulk(frame)
        } else {
            self.conn.blocking_send(frame)
        }
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "conn closed"))
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
