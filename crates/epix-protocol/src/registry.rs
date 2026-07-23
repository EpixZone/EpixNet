//! Process-wide registry of live peer connections, for the diagnostics Stats
//! page. Mirrors the Python client's `ConnectionServer.connections` list:
//! every outbound [`crate::Connection`] and every inbound served stream
//! registers itself while open, so the UI can show the real links (direction,
//! bytes, last command, xites touched) instead of a synthetic count. Entries
//! deregister on drop, so the snapshot is always the live truth.

use crate::HandshakeInfo;
use epix_core::PeerAddr;
use epix_transport::PeerStream;
use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Which side opened the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

/// Live per-connection state. Updated from the hot read/write path, so every
/// field is an atomic or behind a short std mutex - nothing is held across an
/// await point.
pub struct ConnEntry {
    id: u64,
    direction: Direction,
    opened: Instant,
    /// Inbound connections rebind this after the handshake adopts the peer's
    /// dial-back address (an ephemeral source port is not an identity).
    addr: Mutex<PeerAddr>,
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    last_activity: Mutex<Instant>,
    /// Last request command we sent (outbound) / received (inbound).
    last_cmd_sent: Mutex<String>,
    last_cmd_recv: Mutex<String>,
    /// Last measured round-trip of a `ping` on this connection; -1 = never.
    ping_ms: AtomicI64,
    /// The peer's handshake identity, once known.
    peer: Mutex<Option<HandshakeInfo>>,
    /// Xite addresses requests on this connection referenced (`site` param).
    xites: Mutex<HashSet<String>>,
}

impl ConnEntry {
    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    fn record_recv(&self, n: u64) {
        self.bytes_recv.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    fn record_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    fn note_cmd(&self, slot: &Mutex<String>, cmd: &str, xite: Option<&str>) {
        cmd.clone_into(&mut slot.lock().unwrap());
        if let Some(x) = xite.filter(|x| !x.is_empty()) {
            self.xites.lock().unwrap().insert(x.to_string());
        }
        self.touch();
    }
}

/// One row of [`snapshot`]: plain data, safe to render or serialize.
#[derive(Debug, Clone)]
pub struct ConnSnapshot {
    pub id: u64,
    pub direction: Direction,
    pub addr: PeerAddr,
    pub opened_secs: u64,
    pub idle_secs: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub last_cmd_sent: String,
    pub last_cmd_recv: String,
    pub ping_ms: Option<i64>,
    pub peer: Option<HandshakeInfo>,
    pub xites: Vec<String>,
}

/// Cumulative counters since process start (live counts come from the
/// snapshot itself).
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnTotals {
    pub made: u64,
    pub incoming: u64,
    pub outgoing: u64,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static TOTAL_MADE: AtomicU64 = AtomicU64::new(0);
static TOTAL_IN: AtomicU64 = AtomicU64::new(0);
static TOTAL_OUT: AtomicU64 = AtomicU64::new(0);

fn live() -> &'static Mutex<HashMap<u64, Arc<ConnEntry>>> {
    static LIVE: OnceLock<Mutex<HashMap<u64, Arc<ConnEntry>>>> = OnceLock::new();
    LIVE.get_or_init(Default::default)
}

/// A registration owned by one connection. Listing happens on [`activate`]
/// (idempotent), so an inbound socket that never speaks the protocol - a
/// port scanner, a BT crawler - is never shown; deregistration happens on
/// drop, whichever way the connection ends.
///
/// [`activate`]: ConnHandle::activate
pub struct ConnHandle {
    entry: Arc<ConnEntry>,
    active: AtomicBool,
}

impl ConnHandle {
    pub fn new(direction: Direction, addr: PeerAddr) -> Self {
        let entry = Arc::new(ConnEntry {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            direction,
            opened: Instant::now(),
            addr: Mutex::new(addr),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            last_activity: Mutex::new(Instant::now()),
            last_cmd_sent: Mutex::new(String::new()),
            last_cmd_recv: Mutex::new(String::new()),
            ping_ms: AtomicI64::new(-1),
            peer: Mutex::new(None),
            xites: Mutex::new(HashSet::new()),
        });
        Self {
            entry,
            active: AtomicBool::new(false),
        }
    }

    /// List the connection in the registry (first call only).
    pub fn activate(&self) {
        if self.active.swap(true, Ordering::Relaxed) {
            return;
        }
        TOTAL_MADE.fetch_add(1, Ordering::Relaxed);
        match self.entry.direction {
            Direction::In => TOTAL_IN.fetch_add(1, Ordering::Relaxed),
            Direction::Out => TOTAL_OUT.fetch_add(1, Ordering::Relaxed),
        };
        live()
            .lock()
            .unwrap()
            .insert(self.entry.id, self.entry.clone());
    }

    /// Record a request command sent to the peer.
    pub fn note_cmd_sent(&self, cmd: &str, xite: Option<&str>) {
        self.entry.note_cmd(&self.entry.last_cmd_sent, cmd, xite);
    }

    /// Record a request command received from the peer.
    pub fn note_cmd_recv(&self, cmd: &str, xite: Option<&str>) {
        self.entry.note_cmd(&self.entry.last_cmd_recv, cmd, xite);
    }

    /// Rebind the displayed peer address (inbound handshake adoption).
    pub fn set_addr(&self, addr: PeerAddr) {
        *self.entry.addr.lock().unwrap() = addr;
    }

    /// Record the peer's handshake identity.
    pub fn set_peer(&self, peer: HandshakeInfo) {
        *self.entry.peer.lock().unwrap() = Some(peer);
    }

    /// Record a measured ping round-trip on this connection.
    pub fn set_ping_ms(&self, ms: i64) {
        self.entry.ping_ms.store(ms, Ordering::Relaxed);
    }

    /// Wrap `stream` so its raw bytes are counted against this connection.
    pub fn count_stream(&self, stream: PeerStream) -> PeerStream {
        Box::pin(CountingStream {
            inner: stream,
            entry: self.entry.clone(),
        })
    }
}

impl Drop for ConnHandle {
    fn drop(&mut self) {
        if self.active.load(Ordering::Relaxed) {
            live().lock().unwrap().remove(&self.entry.id);
        }
    }
}

/// All live (activated) connections, oldest first.
pub fn snapshot() -> Vec<ConnSnapshot> {
    let mut out: Vec<ConnSnapshot> = live()
        .lock()
        .unwrap()
        .values()
        .map(|e| {
            let ping = e.ping_ms.load(Ordering::Relaxed);
            ConnSnapshot {
                id: e.id,
                direction: e.direction,
                addr: e.addr.lock().unwrap().clone(),
                opened_secs: e.opened.elapsed().as_secs(),
                idle_secs: e.last_activity.lock().unwrap().elapsed().as_secs(),
                bytes_sent: e.bytes_sent.load(Ordering::Relaxed),
                bytes_recv: e.bytes_recv.load(Ordering::Relaxed),
                last_cmd_sent: e.last_cmd_sent.lock().unwrap().clone(),
                last_cmd_recv: e.last_cmd_recv.lock().unwrap().clone(),
                ping_ms: (ping >= 0).then_some(ping),
                peer: e.peer.lock().unwrap().clone(),
                xites: {
                    let mut x: Vec<String> = e.xites.lock().unwrap().iter().cloned().collect();
                    x.sort();
                    x
                },
            }
        })
        .collect();
    out.sort_by_key(|s| s.id);
    out
}

/// Cumulative totals since process start.
pub fn totals() -> ConnTotals {
    ConnTotals {
        made: TOTAL_MADE.load(Ordering::Relaxed),
        incoming: TOTAL_IN.load(Ordering::Relaxed),
        outgoing: TOTAL_OUT.load(Ordering::Relaxed),
    }
}

/// A pass-through stream that counts raw bytes into a [`ConnEntry`], so the
/// per-connection in/out columns cover everything on the wire (framing,
/// handshakes, `streamFile` raw tails), like the Python client's counters.
struct CountingStream {
    inner: PeerStream,
    entry: Arc<ConnEntry>,
}

impl AsyncRead for CountingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = self.inner.as_mut().poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let n = buf.filled().len() - before;
            if n > 0 {
                self.entry.record_recv(n as u64);
            }
        }
        res
    }
}

impl AsyncWrite for CountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = self.inner.as_mut().poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.entry.record_sent(*n as u64);
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.as_mut().poll_shutdown(cx)
    }
}
