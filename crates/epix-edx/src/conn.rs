//! Multiplexed connection + outbound pool.
//!
//! Ground truth from the plan: the retired msgpack connection was
//! `&mut self`, one request in flight, "keep reading" past non-matching
//! ids, and there is no pool. EDX needs concurrent streams over one
//! ordered `PeerStream` and a pool keyed by peer.
//!
//! Rather than bridge futures-io yamux into a tokio codebase, the frame
//! format already carries a `stream` id, so multiplexing is a thin
//! native layer: one writer task (serializes frames from an mpsc queue),
//! one reader task (routes each inbound frame by stream id), a waiter map
//! (single-response requests), and per-stream data channels (streaming
//! responses). Stream ids are partitioned by role — the dialer uses odd
//! ids, the acceptor even — so a server-initiated stream never collides
//! with a client request. This is the "app-level multiplexing over the
//! single ordered stream, portable across overlays" baseline; it removes
//! app-level head-of-line blocking (transport-level HOL over one ordered
//! overlay stream remains, as the plan notes).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use crate::frame::{self};
use crate::msg::{Frame, FrameBody, Req, Resp};

/// Deadline on one frame write. A peer that stops reading (zero window, no
/// FIN) parks the writer inside `write_all` forever, and the whole
/// connection with it: both lanes fill, encode threads park in
/// [`Conn::blocking_send`], and `gone` is never dropped, so the reader stays
/// in `read_frame` and the socket - plus its registry row - leaks for the
/// life of the process. Overlay links skip Noise entirely, so this is the
/// only I/O deadline they have; on clearnet it backs up the Noise pumps,
/// which is why it carries the same value as `noise::IDLE_RECORD_TIMEOUT`.
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(600);

/// Deadline on a blocking send into a full lane. The blocking sender is a
/// spawn_blocking encode thread, so once the lane is full it is held at the
/// peer's download rate rather than the encode's; without a bound, slow or
/// wedged peers pin tokio's blocking pool, which the whole process shares
/// with store and database IO. A peer that has not drained 16 MiB of queued
/// frames in this long is gone.
const SEND_STALL_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a blocking sender parks between attempts on a full lane. It only
/// ever sleeps when the lane is full, i.e. when we are already 256 frames
/// ahead of the peer, so this costs nothing on a link that keeps up.
const SEND_POLL: Duration = Duration::from_millis(100);

/// Queued inbound bytes per connection, in KiB (the budget is a `Semaphore`
/// and its permits are `u32`). The inbound channels are bounded in frame
/// COUNT, and one request frame may be ~68 KiB, so without this a peer buys
/// megabytes of resident memory per connection with a few hundred bytes of
/// request. 1 MiB leaves room for a dozen max-size requests in flight.
const INBOUND_QUEUE_UNITS: u32 = 1024;

/// A streaming response: `Data`/`Resp` frames delivered in order until a
/// frame with `last = true`. Carries the stream `id` it was allocated so
/// the caller can [`Conn::cancel`] exactly this stream (duplicate-on-
/// timeout, endgame, seek-abandon).
pub struct StreamRx {
    /// The allocated stream id (odd for the dialer, even for the acceptor).
    pub id: u64,
    rx: mpsc::Receiver<FrameBody>,
    /// Held so `Drop` can unregister this stream's waiter.
    shared: Arc<Shared>,
}

impl StreamRx {
    /// Await the next response frame, or `None` when the stream ends
    /// (terminal frame delivered or the connection closed).
    pub async fn recv(&mut self) -> Option<FrameBody> {
        self.rx.recv().await
    }
}

impl Drop for StreamRx {
    /// The reader drops a waiter only when a TERMINAL frame arrives, so
    /// every other ending - a caller that times out and drops its future, an
    /// early return on an error frame, a peer that answers with
    /// `last: false` - would otherwise leave an entry in `waiters` for the
    /// life of the connection. Unlike `cancelled`, that map has no cap, and
    /// pooled control links live for hours.
    fn drop(&mut self) {
        self.shared.waiters.lock().expect("waiters").remove(&self.id);
    }
}

/// Handle to a live multiplexed connection. Cloneable; all clones share
/// the one underlying stream via the writer queue. When every `Conn`
/// clone drops, the writer's queue closes and both tasks wind down.
#[derive(Clone)]
pub struct Conn {
    /// Priority lane: control frames (Hello/Ack/Ping/Pong/Cancel/Resp) and
    /// first-paint range data. The writer drains this fully before touching
    /// `bulk`, so tight traffic preempts a large background transfer sharing
    /// the connection.
    outbound: mpsc::Sender<Frame>,
    /// Bulk lane: background range data. Yields to `outbound` in the writer.
    bulk: mpsc::Sender<Frame>,
    inner: Arc<ConnInner>,
    shared: Arc<Shared>,
}

struct ConnInner {
    /// Next locally-initiated stream id (odd for dialer, even for acceptor).
    next_stream: AtomicU64,
    step: u64,
}

/// State the reader/writer tasks share with the handles. Deliberately
/// does NOT contain the outbound sender — a task holding its own queue's
/// sender would keep itself alive forever.
struct Shared {
    /// req_stream -> where to deliver its response frames.
    waiters: Mutex<HashMap<u64, mpsc::Sender<FrameBody>>>,
    /// Streams the PEER cancelled that we may be serving; serve tasks
    /// poll [`Conn::take_cancelled`] between frames and abort encode.
    cancelled: Mutex<std::collections::HashSet<u64>>,
    /// Set when either connection task has stopped.
    closed: std::sync::atomic::AtomicBool,
    /// Bytes of fetch batches in flight on this link, summed across every
    /// `Conn` clone - i.e. across every swarm sharing the connection. See
    /// [`Conn::charge_fetch`].
    queued_fetch: AtomicU64,
}

/// Inbound request delivered to the server side, with the stream id to
/// answer on.
pub struct Incoming {
    pub stream: u64,
    pub req: Req,
    /// This request's share of the connection's inbound byte budget. Held
    /// for as long as the request is queued or being served, and refunded
    /// when the server side drops it. `None` for a request that was never
    /// charged (a test fixture built by hand).
    pub(crate) _budget: Option<OwnedSemaphorePermit>,
}

impl Conn {
    /// Wrap a secured/ordered stream. `dialer` picks the id parity.
    /// Inbound requests arrive on the returned receiver; drop it to
    /// ignore server-side traffic (a pure client).
    pub fn start<S>(stream: S, dialer: bool) -> (Conn, mpsc::Receiver<Incoming>)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (hi_tx, hi_rx) = mpsc::channel::<Frame>(256);
        let (lo_tx, lo_rx) = mpsc::channel::<Frame>(256);
        let (in_tx, in_rx) = mpsc::channel::<Incoming>(64);

        let inner = Arc::new(ConnInner {
            next_stream: AtomicU64::new(if dialer { 1 } else { 2 }),
            step: 2,
        });
        let shared = Arc::new(Shared {
            waiters: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(std::collections::HashSet::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
            queued_fetch: AtomicU64::new(0),
        });

        // Teardown signal: the writer owns `gone_tx` and the reader awaits
        // `gone_rx`, so the reader unblocks the moment the writer stops (see
        // spawn_reader). Without it a client's reader would sit in `read_frame`
        // until the PEER closed, holding the socket - and its registry row -
        // open long after the last `Conn` handle was dropped.
        let (gone_tx, gone_rx) = mpsc::channel::<()>(1);
        let in_budget = Arc::new(Semaphore::new(INBOUND_QUEUE_UNITS as usize));
        spawn_writer(write_half, hi_rx, lo_rx, shared.clone(), gone_tx);
        // The reader answers Pings on the priority lane (Pong is control). It
        // holds a WEAK sender: a strong clone would keep the writer's queue
        // open forever, so the writer could never observe the last handle
        // going away.
        spawn_reader(read_half, shared.clone(), hi_tx.downgrade(), in_tx, gone_rx, in_budget);

        (Conn { outbound: hi_tx, bulk: lo_tx, inner, shared }, in_rx)
    }

    fn alloc_stream(&self) -> u64 {
        self.inner.next_stream.fetch_add(self.inner.step, Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Relaxed)
    }

    /// How many handles share this link. The reader and writer tasks hold
    /// `Shared`, never `ConnInner`, so this counts `Conn` clones only: `1`
    /// means the caller holds the last one. A pool needs this to tell a link
    /// nobody is using (safe to forget) from one carrying a transfer right now.
    /// Forgetting the latter frees nothing and only lets the next caller open a
    /// second link to a peer we are already talking to.
    pub fn holders(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Send a single-response request and await its `Resp`.
    pub async fn request(&self, req: Req) -> std::io::Result<Resp> {
        let mut rx = self.request_stream(req).await?;
        match rx.recv().await {
            Some(FrameBody::Resp { resp, .. }) => Ok(resp),
            Some(other) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected Resp, got {other:?}"),
            )),
            None => Err(closed_err()),
        }
    }

    /// Send a request and return a receiver of its response frames (for
    /// streaming replies: many `Data` frames then a terminal one).
    pub async fn request_stream(&self, req: Req) -> std::io::Result<StreamRx> {
        if self.is_closed() {
            return Err(closed_err());
        }
        let stream = self.alloc_stream();
        let (tx, rx) = mpsc::channel::<FrameBody>(64);
        self.shared.waiters.lock().expect("waiters").insert(stream, tx);
        if self
            .outbound
            .send(Frame { stream, body: FrameBody::Req(req) })
            .await
            .is_err()
            // Re-check AFTER insert: if the reader/writer died in between
            // and cleared the map, our waiter would otherwise dangle and
            // the caller would await a response that can never arrive.
            || self.is_closed()
        {
            self.shared.waiters.lock().expect("waiters").remove(&stream);
            return Err(closed_err());
        }
        Ok(StreamRx { id: stream, rx, shared: self.shared.clone() })
    }

    /// Round-trip a frame-level Ping and return the measured RTT.
    ///
    /// Liveness + latency for a link the caller keeps warm. It rides the
    /// priority lane and is answered by the peer's reader task, so it works
    /// on any EDX link - no request handler, no capability, no store.
    pub async fn ping(&self) -> std::io::Result<std::time::Duration> {
        if self.is_closed() {
            return Err(closed_err());
        }
        let stream = self.alloc_stream();
        let (tx, rx) = mpsc::channel::<FrameBody>(1);
        self.shared.waiters.lock().expect("waiters").insert(stream, tx);
        // Wrapped in a StreamRx purely for its Drop: a ping the caller
        // abandons, or one a peer never answers, must not leave a waiter.
        let mut rx = StreamRx { id: stream, rx, shared: self.shared.clone() };
        let start = std::time::Instant::now();
        // Same post-send close re-check as request_stream: a waiter inserted
        // after the reader cleared the map would never be woken.
        if self.outbound.send(Frame { stream, body: FrameBody::Ping }).await.is_err()
            || self.is_closed()
        {
            return Err(closed_err());
        }
        match rx.recv().await {
            Some(FrameBody::Pong) => Ok(start.elapsed()),
            Some(other) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected Pong, got {other:?}"),
            )),
            None => Err(closed_err()),
        }
    }

    /// Answer an inbound request stream with a single response.
    pub async fn respond(&self, stream: u64, resp: Resp) -> std::io::Result<()> {
        self.send(Frame { stream, body: FrameBody::Resp { last: true, resp } }).await
    }

    /// Send one frame of a multi-frame response (data streaming) on the
    /// PRIORITY lane. Use for control and first-paint data.
    pub async fn send(&self, frame: Frame) -> std::io::Result<()> {
        self.outbound.send(frame).await.map_err(|_| closed_err())
    }

    /// Blocking [`Self::send`] for spawn_blocking encode threads. Applies
    /// the same queue backpressure, just synchronously, and gives up after
    /// [`SEND_STALL_TIMEOUT`] so a peer that stops draining cannot hold an
    /// OS thread from the shared blocking pool.
    pub fn blocking_send(&self, frame: Frame) -> std::io::Result<()> {
        blocking_send_within(&self.outbound, frame, SEND_STALL_TIMEOUT)
    }

    /// Send one frame of a BULK (background range) response. It rides the
    /// low-priority lane, so a first-paint or control frame on the same
    /// connection is written ahead of it instead of stuck behind a large
    /// transfer. Order within a stream is preserved (a stream sticks to one
    /// lane).
    pub async fn send_bulk(&self, frame: Frame) -> std::io::Result<()> {
        self.bulk.send(frame).await.map_err(|_| closed_err())
    }

    /// Blocking [`Self::send_bulk`] for spawn_blocking encode threads. Same
    /// stall deadline as [`Self::blocking_send`].
    pub fn blocking_send_bulk(&self, frame: Frame) -> std::io::Result<()> {
        blocking_send_within(&self.bulk, frame, SEND_STALL_TIMEOUT)
    }

    /// Cancel an in-flight request stream (stops the peer's encode).
    pub async fn cancel(&self, stream: u64) -> std::io::Result<()> {
        self.shared.waiters.lock().expect("waiters").remove(&stream);
        self.send(Frame { stream, body: FrameBody::Cancel }).await
    }

    /// Best-effort synchronous cancel for Drop paths (no await). When an
    /// in-flight fetch future is abandoned - a duplicate racer another peer
    /// beat, a seek that moved on, a deadline give-up - its guard fires this
    /// to tell the peer to stop encoding a slice we no longer need. Uses
    /// `try_send` so it never blocks a drop; a momentarily full outbound
    /// queue just skips the frame (the stream still ends when the request or
    /// connection does). Clears the local waiter either way.
    pub fn cancel_now(&self, stream: u64) {
        self.shared.waiters.lock().expect("waiters").remove(&stream);
        let _ = self.outbound.try_send(Frame { stream, body: FrameBody::Cancel });
    }

    /// Whether the peer cancelled `stream` (consumes the flag). Serve
    /// tasks call this between Data frames and stop encoding on true.
    pub fn take_cancelled(&self, stream: u64) -> bool {
        self.shared.cancelled.lock().expect("cancelled").remove(&stream)
    }

    /// Bytes of fetch batches currently in flight on this link, across
    /// every clone of the handle - which is every swarm sharing the
    /// connection (the link pool hands out clones of one `Conn` per lane).
    /// The scheduler scales its stall windows and batch caps by this, so a
    /// batch queued behind ANOTHER swarm's traffic on a shared circuit
    /// reads as queue depth, not as a stall. A plain atomic: reading it
    /// takes no lock, so the scheduler cannot deadlock against the
    /// connection's own locks.
    pub fn queued_fetch_bytes(&self) -> u64 {
        self.shared.queued_fetch.load(Ordering::Relaxed)
    }

    /// Charge `bytes` of fetch work to this link's queue counter for as
    /// long as the returned guard lives. The refund is the guard's `Drop`,
    /// so a batch future that is cancelled mid-race (an abandoned racer, a
    /// fetch that completed elsewhere) refunds the link exactly like a
    /// completed one - a leak here would permanently inflate every sharing
    /// swarm's stall windows.
    pub fn charge_fetch(&self, bytes: u64) -> FetchCharge {
        self.shared.queued_fetch.fetch_add(bytes, Ordering::Relaxed);
        FetchCharge { shared: self.shared.clone(), bytes }
    }
}

/// One fetch batch's bytes charged against a link's queued-fetch counter
/// (see [`Conn::charge_fetch`]). Refunds on drop.
pub struct FetchCharge {
    shared: Arc<Shared>,
    bytes: u64,
}

impl Drop for FetchCharge {
    fn drop(&mut self) {
        self.shared.queued_fetch.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

fn closed_err() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "connection closed")
}

/// What one inbound request costs against [`INBOUND_QUEUE_UNITS`], in KiB.
/// Rounded up so every request costs at least one unit, and clamped to the
/// whole budget: a request asking for more permits than the budget holds
/// would never be granted.
fn queue_units(req: &Req) -> u32 {
    let bytes = postcard::experimental::serialized_size(req).unwrap_or(frame::FRAME_HARD_CAP);
    (bytes / 1024 + 1).min(INBOUND_QUEUE_UNITS as usize) as u32
}

/// Queue `frame`, waiting at most `deadline` for lane room. Polls rather
/// than parking on the channel because the caller is an OS thread from the
/// blocking pool: `blocking_send` would hold it for as long as the peer
/// takes to drain, which is unbounded. Only sleeps while the lane is full.
fn blocking_send_within(
    tx: &mpsc::Sender<Frame>,
    mut frame: Frame,
    deadline: Duration,
) -> std::io::Result<()> {
    let start = std::time::Instant::now();
    loop {
        match tx.try_send(frame) {
            Ok(()) => return Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(closed_err()),
            Err(mpsc::error::TrySendError::Full(f)) => {
                if start.elapsed() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "peer is not draining the outbound queue",
                    ));
                }
                frame = f;
                std::thread::sleep(SEND_POLL);
            }
        }
    }
}

fn spawn_writer<W>(
    mut w: tokio::io::WriteHalf<W>,
    mut hi: mpsc::Receiver<Frame>,
    mut lo: mpsc::Receiver<Frame>,
    shared: Arc<Shared>,
    // Dropped when this task ends, which is the reader's cue to stop.
    gone: mpsc::Sender<()>,
) where
    W: AsyncWrite + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // Priority drain: a ready priority frame always goes before any
            // bulk frame (biased polls `hi` first), so first-paint/control
            // traffic preempts a large background range on the same conn.
            // `else` fires only when BOTH lanes are closed and drained.
            let frame = tokio::select! {
                biased;
                Some(f) = hi.recv() => f,
                Some(f) = lo.recv() => f,
                else => break,
            };
            if !matches!(
                tokio::time::timeout(WRITE_STALL_TIMEOUT, frame::write_frame(&mut w, &frame)).await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
        shared.closed.store(true, Ordering::Relaxed);
        // Wake every pending waiter (their rx sees the sender drop).
        shared.waiters.lock().expect("waiters").clear();
        drop(gone);
    });
}

fn spawn_reader<R>(
    mut r: tokio::io::ReadHalf<R>,
    shared: Arc<Shared>,
    outbound: mpsc::WeakSender<Frame>,
    in_tx: mpsc::Sender<Incoming>,
    mut gone: mpsc::Receiver<()>,
    in_budget: Arc<Semaphore>,
) where
    R: AsyncRead + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // Stop on either a dead socket or the writer winding down (the
            // last `Conn` handle dropped). Reading past that would keep the
            // read half - and so the whole stream - alive indefinitely.
            let frame = tokio::select! {
                biased;
                _ = gone.recv() => break,
                f = frame::read_frame(&mut r) => match f {
                    Ok(f) => f,
                    Err(_) => break,
                },
            };
            if !route_frame(frame, &shared, &outbound, &in_tx, &mut gone, &in_budget).await {
                break;
            }
        }
        // On EVERY exit path: mark closed, then wake every pending waiter
        // (their rx sees the sender drop). A request that raced the teardown
        // would otherwise await a response that can never arrive.
        shared.closed.store(true, Ordering::Relaxed);
        shared.waiters.lock().expect("waiters").clear();
    });
}

/// Route one inbound frame by kind. Returns false when the reader should
/// stop (teardown signalled while waiting for inbound budget).
async fn route_frame(
    frame: Frame,
    shared: &Shared,
    outbound: &mpsc::WeakSender<Frame>,
    in_tx: &mpsc::Sender<Incoming>,
    gone: &mut mpsc::Receiver<()>,
    in_budget: &Arc<Semaphore>,
) -> bool {
    match frame.body {
        FrameBody::Req(req) => {
            return admit_request(frame.stream, req, in_tx, gone, in_budget).await;
        }
        FrameBody::Cancel => {
            // Peer aborted a stream: drop any local waiter for it
            // and flag it for serve tasks streaming on that id.
            shared.waiters.lock().expect("waiters").remove(&frame.stream);
            let mut cancelled = shared.cancelled.lock().expect("cancelled");
            // Bounded: a peer spamming Cancels can't grow this set.
            if cancelled.len() > 4096 {
                cancelled.clear();
            }
            cancelled.insert(frame.stream);
        }
        FrameBody::Ping => {
            if let Some(tx) = outbound.upgrade() {
                let _ = tx.send(Frame { stream: frame.stream, body: FrameBody::Pong }).await;
            }
        }
        FrameBody::Pong => deliver_pong(shared, frame.stream).await,
        body => deliver_response(shared, frame.stream, body).await,
    }
    true
}

/// Inbound request: hand to the server side, but charge its bytes to the
/// connection's budget first. The inbound queues are bounded in frame
/// count, so without this a peer can park megabytes of decoded requests
/// per connection for the cost of sending them. Waiting here stops reading
/// the socket, which is the backpressure we want; the peer is never
/// disconnected for it. Returns false when the reader should stop.
async fn admit_request(
    stream: u64,
    req: Req,
    in_tx: &mpsc::Sender<Incoming>,
    gone: &mut mpsc::Receiver<()>,
    in_budget: &Arc<Semaphore>,
) -> bool {
    let units = queue_units(&req);
    let permit = tokio::select! {
        biased;
        _ = gone.recv() => return false,
        p = in_budget.clone().acquire_many_owned(units) => match p {
            Ok(p) => p,
            Err(_) => return false,
        },
    };
    if in_tx.send(Incoming { stream, req, _budget: Some(permit) }).await.is_err() {
        // No server handler; ignore.
    }
    true
}

/// Deliver a Pong to the Ping that allocated this stream, so `Conn::ping`
/// can time the round trip. A Pong nobody waits on (peer echo of an
/// abandoned ping) is dropped.
async fn deliver_pong(shared: &Shared, stream: u64) {
    let tx = {
        let map = shared.waiters.lock().expect("waiters");
        map.get(&stream).cloned()
    };
    if let Some(tx) = tx {
        let _ = tx.send(FrameBody::Pong).await;
        shared.waiters.lock().expect("waiters").remove(&stream);
    }
}

/// Response/data frame: route to the waiter, and drop the waiter when the
/// terminal frame arrives.
async fn deliver_response(shared: &Shared, stream: u64, body: FrameBody) {
    let last = matches!(
        &body,
        FrameBody::Resp { last: true, .. } | FrameBody::Data { last: true, .. }
    );
    let tx = {
        let map = shared.waiters.lock().expect("waiters");
        map.get(&stream).cloned()
    };
    if let Some(tx) = tx {
        let _ = tx.send(body).await;
        if last {
            shared.waiters.lock().expect("waiters").remove(&stream);
        }
    }
}

/// Outbound connection pool keyed by a caller-chosen key (normally the
/// peer address string). One live `Conn` per key; a dead one is replaced
/// on next `get_or_connect`.
pub struct Pool<K> {
    conns: Mutex<HashMap<K, Conn>>,
}

impl<K: std::hash::Hash + Eq + Clone> Default for Pool<K> {
    fn default() -> Self {
        Self { conns: Mutex::new(HashMap::new()) }
    }
}

impl<K: std::hash::Hash + Eq + Clone> Pool<K> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a live pooled connection for `key`, or build one with
    /// `connect` (an async closure yielding a fresh `Conn`). A pooled
    /// connection that has closed is discarded and rebuilt.
    pub async fn get_or_connect<F, Fut, E>(&self, key: K, connect: F) -> Result<Conn, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Conn, E>>,
    {
        if let Some(c) = self.live(&key) {
            return Ok(c);
        }
        let c = connect().await?;
        self.conns.lock().expect("pool").insert(key, c.clone());
        Ok(c)
    }

    fn live(&self, key: &K) -> Option<Conn> {
        let mut map = self.conns.lock().expect("pool");
        match map.get(key) {
            Some(c) if !c.is_closed() => Some(c.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    pub fn len(&self) -> usize {
        self.conns.lock().expect("pool").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_blob::ObjId;

    /// Wire two Conns together over an in-memory duplex and run a trivial
    /// echo server that answers GetBitfield with a Bitfield and streams a
    /// GetRange as several Data frames.
    async fn linked() -> (Conn, Conn) {
        let (a, b) = tokio::io::duplex(1 << 18);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        let srv = server.clone();
        tokio::spawn(async move {
            while let Some(inc) = server_in.recv().await {
                let srv = srv.clone();
                match inc.req {
                    Req::GetBitfield { .. } => {
                        let _ = srv
                            .respond(inc.stream, Resp::Bitfield { size: 1, runs: vec![1] })
                            .await;
                    }
                    Req::GetRange { .. } => {
                        for i in 0..3u8 {
                            let _ = srv
                                .send(Frame {
                                    stream: inc.stream,
                                    body: FrameBody::Data { last: false, bytes: vec![i; 10] },
                                })
                                .await;
                        }
                        let _ = srv
                            .send(Frame {
                                stream: inc.stream,
                                body: FrameBody::Data { last: true, bytes: vec![9; 2] },
                            })
                            .await;
                    }
                    _ => {
                        let _ = srv.respond(inc.stream, Resp::Ok).await;
                    }
                }
            }
        });
        (client, server)
    }

    #[tokio::test]
    async fn single_response_request() {
        let (client, _server) = linked().await;
        let resp = client.request(Req::GetBitfield { obj: ObjId([1; 32]) }).await.unwrap();
        assert_eq!(resp, Resp::Bitfield { size: 1, runs: vec![1] });
    }

    #[tokio::test]
    async fn streaming_response_frames_in_order_until_last() {
        let (client, _server) = linked().await;
        let mut rx = client
            .request_stream(Req::GetRange {
                obj: ObjId([2; 32]),
                size: 32,
                ranges: vec![(0, 32)],
                deadline_ms: 0,
            })
            .await
            .unwrap();
        let mut chunks = Vec::new();
        while let Some(body) = rx.recv().await {
            match body {
                FrameBody::Data { last, bytes } => {
                    chunks.push(bytes);
                    if last {
                        break;
                    }
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0], vec![0; 10]);
        assert_eq!(chunks[3], vec![9; 2]);
    }

    #[tokio::test]
    async fn concurrent_streams_do_not_block_each_other() {
        // Fire many requests without awaiting; all must resolve. If the
        // layer serialized (one in flight), this would deadlock the test
        // under the bounded channels.
        let (client, _server) = linked().await;
        let mut handles = Vec::new();
        for i in 0..50u8 {
            let c = client.clone();
            handles.push(tokio::spawn(async move {
                c.request(Req::GetBitfield { obj: ObjId([i; 32]) }).await.unwrap()
            }));
        }
        for h in handles {
            assert!(matches!(h.await.unwrap(), Resp::Bitfield { .. }));
        }
    }

    #[tokio::test]
    async fn dialer_and_acceptor_ids_never_collide() {
        let (a, b) = tokio::io::duplex(1024);
        let (dialer, _) = Conn::start(a, true);
        let (acceptor, _) = Conn::start(b, false);
        let d: Vec<u64> = (0..5).map(|_| dialer.alloc_stream()).collect();
        let ac: Vec<u64> = (0..5).map(|_| acceptor.alloc_stream()).collect();
        assert!(d.iter().all(|x| x % 2 == 1));
        assert!(ac.iter().all(|x| x % 2 == 0));
        assert!(d.iter().all(|x| !ac.contains(x)));
    }

    /// The warm pool's liveness probe: a Ping must come back as a Pong on the
    /// same stream, without any request handler on the peer side (the reader
    /// answers it). A dead link must error instead of hanging.
    #[tokio::test]
    async fn ping_round_trips_and_fails_on_a_dead_link() {
        let (a, b) = tokio::io::duplex(1024);
        let (client, _client_in) = Conn::start(a, true);
        // No serve loop on the far side at all - just the connection tasks.
        let (_server, _server_in) = Conn::start(b, false);
        client.ping().await.expect("peer answered the ping");

        let (a, b) = tokio::io::duplex(64);
        let (client, _in) = Conn::start(a, true);
        drop(b);
        tokio::task::yield_now().await;
        assert!(client.ping().await.is_err(), "a closed link must not hang the ping");
    }

    /// Dropping the last handle must tear the connection down on OUR side,
    /// without waiting for the peer to close. The warm pool churns links every
    /// cycle, and a reader left parked in `read_frame` would hold the socket
    /// (and its Stats-page row) open for as long as the peer stayed quiet.
    #[tokio::test]
    async fn dropping_the_last_handle_closes_the_stream() {
        let (a, b) = tokio::io::duplex(1024);
        let (client, client_in) = Conn::start(a, true);
        // The peer never closes; it just sits there holding its own half.
        let (_server, _server_in) = Conn::start(b, false);
        client.ping().await.expect("link is up");

        drop(client);
        drop(client_in);
        // The far side sees EOF only if our halves were really dropped.
        let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if _server.is_closed() {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert_eq!(closed, Ok(true), "the peer saw the connection close");
    }

    /// Every stream that ends without a terminal frame - a dropped future, an
    /// early return - must take its waiter entry with it, or a long-lived
    /// pooled link grows a map that nothing ever prunes.
    #[tokio::test]
    async fn dropping_a_stream_rx_unregisters_its_waiter() {
        let (a, b) = tokio::io::duplex(1024);
        let (client, _in) = Conn::start(a, true);
        // Connection tasks only on the far side, so nothing ever answers.
        let (_server, _server_in) = Conn::start(b, false);

        let rx = client.request_stream(Req::GetBitfield { obj: ObjId([1; 32]) }).await.unwrap();
        assert_eq!(client.shared.waiters.lock().expect("waiters").len(), 1);
        drop(rx);
        assert!(client.shared.waiters.lock().expect("waiters").is_empty());
    }

    /// `request` returns on the FIRST Resp whether or not it is terminal, so a
    /// peer answering every control RPC with `last: false` looked healthy to
    /// the pool while leaking one waiter per call.
    #[tokio::test]
    async fn a_non_terminal_resp_leaves_no_waiter_behind() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, _in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);
        tokio::spawn(async move {
            while let Some(inc) = server_in.recv().await {
                let _ = server
                    .send(Frame {
                        stream: inc.stream,
                        body: FrameBody::Resp { last: false, resp: Resp::Ok },
                    })
                    .await;
            }
        });

        let resp = client.request(Req::GetTrackers).await.unwrap();
        assert_eq!(resp, Resp::Ok);
        assert!(client.shared.waiters.lock().expect("waiters").is_empty());
    }

    /// A peer that stops reading produces no error and no FIN, so before the
    /// write deadline the writer parked in `write_all` for good: the lanes
    /// stayed full, `gone` was never dropped, and the reader held the socket
    /// (and its registry row) for the life of the process.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_stops_reading_cannot_wedge_the_writer_forever() {
        let (a, b) = tokio::io::duplex(64);
        let (conn, _in) = Conn::start(a, true);
        // The peer keeps its half open and never reads a byte.
        let _peer = b;
        let body = FrameBody::Data { last: false, bytes: vec![0u8; 4096] };
        conn.send(Frame { stream: 1, body }).await.unwrap();

        for _ in 0..1000 {
            if conn.is_closed() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert!(conn.is_closed(), "the write deadline must tear a wedged link down");
    }

    /// `holders` counts live handles and nothing else. A pool leans on it to
    /// keep a cached link that a transfer is still running over, so counting
    /// the reader/writer tasks (which never hold a `Conn`) would make every
    /// link look busy forever and the pool would never let one go.
    #[tokio::test]
    async fn holders_counts_conn_clones_only() {
        let (a, _b) = tokio::io::duplex(4096);
        let (conn, _incoming) = Conn::start(Box::pin(a), true);
        assert_eq!(conn.holders(), 1, "a lone handle is the last holder");

        let second = conn.clone();
        assert_eq!(conn.holders(), 2, "a clone is another user of the same link");
        let third = second.clone();
        assert_eq!(conn.holders(), 3);

        drop(third);
        drop(second);
        assert_eq!(conn.holders(), 1, "handles going away releases the link back to its owner");
    }

    /// The blocking senders run on spawn_blocking threads from a pool the
    /// whole process shares, so waiting on a lane the peer never drains has
    /// to be bounded.
    #[test]
    fn a_blocking_send_gives_up_on_a_lane_that_never_drains() {
        let (tx, rx) = mpsc::channel::<Frame>(1);
        let mk = || Frame { stream: 1, body: FrameBody::Data { last: false, bytes: vec![0u8; 8] } };
        let deadline = Duration::from_millis(50);

        blocking_send_within(&tx, mk(), deadline).expect("the first frame fits");
        let err = blocking_send_within(&tx, mk(), deadline).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

        drop(rx);
        let err = blocking_send_within(&tx, mk(), deadline).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    /// The inbound channels are bounded in frame COUNT, and one request frame
    /// can be ~68 KiB, so the byte budget is what keeps a peer from parking
    /// megabytes per connection by pipelining large requests.
    #[tokio::test(start_paused = true)]
    async fn inbound_requests_are_bounded_by_bytes_not_frame_count() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (client, _client_in) = Conn::start(a, true);
        let (_server, mut server_in) = Conn::start(b, false);

        // ~64 KiB each: the 64-slot inbound channel would take all 40, the
        // 1 MiB budget takes about 15.
        for _ in 0..40 {
            client.request_stream(Req::Kad { payload: vec![7u8; 64 * 1024] }).await.unwrap();
        }
        // Paused time only advances once every task has parked, so by the
        // time this returns the reader has queued all it is allowed to.
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut queued = Vec::new();
        while let Ok(inc) = server_in.try_recv() {
            queued.push(inc);
        }
        assert!(!queued.is_empty(), "the budget must admit requests");
        assert!(queued.len() <= 16, "budget exceeded: {} requests queued", queued.len());

        // Serving them refunds the budget, so the rest arrive.
        drop(queued);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(server_in.try_recv().is_ok(), "the budget is refunded as requests are consumed");
    }

    #[tokio::test]
    async fn request_on_dead_connection_errors() {
        let (a, b) = tokio::io::duplex(64);
        let (client, _in) = Conn::start(a, true);
        drop(b); // kill the peer
        // Give the reader task a tick to observe EOF.
        tokio::task::yield_now().await;
        let res = client.request(Req::GetBitfield { obj: ObjId([0; 32]) }).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn priority_frame_preempts_queued_bulk() {
        // A tiny duplex so the writer blocks partway through the first frame
        // and can dequeue only one before we enqueue the rest. We queue a
        // run of bulk frames, then one priority frame, and read the wire
        // order off the raw far end. With a strict FIFO writer the priority
        // frame would come LAST; the two-lane writer must place it near the
        // front (at most one already-in-flight bulk frame ahead of it).
        let (a, mut b) = tokio::io::duplex(64);
        let (conn, _in) = Conn::start(a, true);

        // Bulk frames on even stream ids 2,4,...,16; payload > 64 so the
        // writer stalls inside the first one until we start reading.
        for i in 0..8u64 {
            conn.send_bulk(Frame {
                stream: 2 + i * 2,
                body: FrameBody::Data { last: false, bytes: vec![0u8; 2048] },
            })
            .await
            .unwrap();
        }
        // One priority frame, enqueued AFTER all the bulk frames.
        conn.send(Frame {
            stream: 999,
            body: FrameBody::Data { last: false, bytes: vec![1u8; 2048] },
        })
        .await
        .unwrap();

        // Drain the wire in order and find where the priority frame landed.
        let mut order = Vec::new();
        for _ in 0..9 {
            order.push(frame::read_frame(&mut b).await.unwrap().stream);
        }
        let hi_pos = order.iter().position(|s| *s == 999).unwrap();
        assert!(
            hi_pos <= 1,
            "priority frame should preempt queued bulk (pos {hi_pos}), order = {order:?}"
        );
    }

    /// The queued-fetch counter is one number per LINK: every clone reads
    /// the same value, and dropping a charge refunds it whatever ended the
    /// batch. Swarms sharing a circuit size their stall windows off this,
    /// so a leaked or per-clone counter would poison every later fetch on
    /// the link.
    #[tokio::test]
    async fn fetch_charges_are_shared_across_clones_and_refund_on_drop() {
        let (a, _b) = tokio::io::duplex(64);
        let (conn, _in) = Conn::start(a, true);
        let clone = conn.clone();

        let c1 = conn.charge_fetch(1000);
        assert_eq!(clone.queued_fetch_bytes(), 1000, "a clone sees the link's charge");
        let c2 = clone.charge_fetch(500);
        assert_eq!(conn.queued_fetch_bytes(), 1500, "charges from clones accumulate");

        drop(c1);
        assert_eq!(conn.queued_fetch_bytes(), 500, "dropping a charge refunds its bytes");
        drop(c2);
        assert_eq!(conn.queued_fetch_bytes(), 0);
    }

    #[tokio::test]
    async fn pool_reuses_live_and_replaces_dead() {
        let pool: Pool<String> = Pool::new();
        let built = Arc::new(AtomicU64::new(0));

        let make = || {
            let built = built.clone();
            async move {
                built.fetch_add(1, Ordering::Relaxed);
                let (a, _b) = tokio::io::duplex(64);
                let (c, _in) = Conn::start(a, true);
                // Leak _b so the conn stays open for this test's lifetime.
                std::mem::forget(_b);
                Ok::<_, ()>(c)
            }
        };

        let c1 = pool.get_or_connect("peer".into(), make).await.unwrap();
        let _c2 = pool.get_or_connect("peer".into(), make).await.unwrap();
        assert_eq!(built.load(Ordering::Relaxed), 1, "second call reused the pooled conn");
        assert_eq!(pool.len(), 1);

        // Mark it closed and confirm a rebuild happens.
        c1.shared.closed.store(true, Ordering::Relaxed);
        let _c3 = pool.get_or_connect("peer".into(), make).await.unwrap();
        assert_eq!(built.load(Ordering::Relaxed), 2, "dead conn was replaced");
    }
}
