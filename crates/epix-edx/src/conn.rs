//! Multiplexed connection + outbound pool.
//!
//! Ground truth from the plan: today's `epix-protocol::Connection` is
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

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::frame::{self};
use crate::msg::{Frame, FrameBody, Req, Resp};

/// A streaming response: `Data`/`Resp` frames delivered in order until a
/// frame with `last = true`. Carries the stream `id` it was allocated so
/// the caller can [`Conn::cancel`] exactly this stream (duplicate-on-
/// timeout, endgame, seek-abandon).
pub struct StreamRx {
    /// The allocated stream id (odd for the dialer, even for the acceptor).
    pub id: u64,
    rx: mpsc::Receiver<FrameBody>,
}

impl StreamRx {
    /// Await the next response frame, or `None` when the stream ends
    /// (terminal frame delivered or the connection closed).
    pub async fn recv(&mut self) -> Option<FrameBody> {
        self.rx.recv().await
    }
}

/// Handle to a live multiplexed connection. Cloneable; all clones share
/// the one underlying stream via the writer queue. When every `Conn`
/// clone drops, the writer's queue closes and both tasks wind down.
#[derive(Clone)]
pub struct Conn {
    outbound: mpsc::Sender<Frame>,
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
}

/// Inbound request delivered to the server side, with the stream id to
/// answer on.
pub struct Incoming {
    pub stream: u64,
    pub req: Req,
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
        let (out_tx, out_rx) = mpsc::channel::<Frame>(256);
        let (in_tx, in_rx) = mpsc::channel::<Incoming>(64);

        let inner = Arc::new(ConnInner {
            next_stream: AtomicU64::new(if dialer { 1 } else { 2 }),
            step: 2,
        });
        let shared = Arc::new(Shared {
            waiters: Mutex::new(HashMap::new()),
            cancelled: Mutex::new(std::collections::HashSet::new()),
            closed: std::sync::atomic::AtomicBool::new(false),
        });

        spawn_writer(write_half, out_rx, shared.clone());
        spawn_reader(read_half, shared.clone(), out_tx.clone(), in_tx);

        (Conn { outbound: out_tx, inner, shared }, in_rx)
    }

    fn alloc_stream(&self) -> u64 {
        self.inner.next_stream.fetch_add(self.inner.step, Ordering::Relaxed)
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Relaxed)
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
        Ok(StreamRx { id: stream, rx })
    }

    /// Answer an inbound request stream with a single response.
    pub async fn respond(&self, stream: u64, resp: Resp) -> std::io::Result<()> {
        self.send(Frame { stream, body: FrameBody::Resp { last: true, resp } }).await
    }

    /// Send one frame of a multi-frame response (data streaming).
    pub async fn send(&self, frame: Frame) -> std::io::Result<()> {
        self.outbound.send(frame).await.map_err(|_| closed_err())
    }

    /// Blocking [`Self::send`] for spawn_blocking encode threads. Applies
    /// the same queue backpressure, just synchronously.
    pub fn blocking_send(&self, frame: Frame) -> std::io::Result<()> {
        self.outbound.blocking_send(frame).map_err(|_| closed_err())
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
}

fn closed_err() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "connection closed")
}

fn spawn_writer<W>(
    mut w: tokio::io::WriteHalf<W>,
    mut rx: mpsc::Receiver<Frame>,
    shared: Arc<Shared>,
) where
    W: AsyncWrite + Send + 'static,
{
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if frame::write_frame(&mut w, &frame).await.is_err() {
                break;
            }
        }
        shared.closed.store(true, Ordering::Relaxed);
        // Wake every pending waiter (their rx sees the sender drop).
        shared.waiters.lock().expect("waiters").clear();
    });
}

fn spawn_reader<R>(
    mut r: tokio::io::ReadHalf<R>,
    shared: Arc<Shared>,
    outbound: mpsc::Sender<Frame>,
    in_tx: mpsc::Sender<Incoming>,
) where
    R: AsyncRead + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let frame = match frame::read_frame(&mut r).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match frame.body {
                FrameBody::Req(req) => {
                    // Inbound request: hand to the server side.
                    if in_tx.send(Incoming { stream: frame.stream, req }).await.is_err() {
                        // No server handler; ignore.
                    }
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
                    let _ = outbound
                        .send(Frame { stream: frame.stream, body: FrameBody::Pong })
                        .await;
                }
                FrameBody::Pong => {}
                body => {
                    // Response/data frame: route to the waiter, and drop
                    // the waiter when the terminal frame arrives.
                    let last = matches!(
                        &body,
                        FrameBody::Resp { last: true, .. } | FrameBody::Data { last: true, .. }
                    );
                    let tx = {
                        let map = shared.waiters.lock().expect("waiters");
                        map.get(&frame.stream).cloned()
                    };
                    if let Some(tx) = tx {
                        let _ = tx.send(body).await;
                        if last {
                            shared.waiters.lock().expect("waiters").remove(&frame.stream);
                        }
                    }
                }
            }
        }
        shared.closed.store(true, Ordering::Relaxed);
        shared.waiters.lock().expect("waiters").clear();
    });
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
