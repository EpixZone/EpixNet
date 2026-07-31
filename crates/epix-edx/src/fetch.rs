//! Client-side fetch operations: the verified paths from a peer's
//! answers into the local store.
//!
//! Everything here is trustless toward the serving peer: range bytes are
//! bao-verified against the object root as they decode into the store
//! (`Store::write_slice`), GetMany blobs are whole-hash verified by
//! `Store::insert_bytes`, and signed content is returned raw for the
//! caller to signature-verify (`epix-content`). A lying peer costs a
//! wasted fetch, never corrupt state.

use std::ops::Range;
use std::sync::Arc;

use epix_blob::bitfield::GroupBits;
use epix_blob::store::Store;
use epix_blob::{Ns, ObjId};

use crate::conn::Conn;
use crate::msg::{err, FrameBody, Req, Resp};

// Client-side caps on a multi-frame reply. The peer decides when a stream
// ends (`last: true`), so every drain loop needs its own budget or a peer
// that never terminates grows our accumulator without bound. The honest
// server fills each frame to BATCH_BUDGET before sending the next, so a
// real reply hits its entry cap long before the frame cap.
const MAX_LIST_ENTRIES: usize = 100_000;
const MAX_UPDATE_HINTS: usize = 100_000;
const MAX_REPLY_FRAMES: usize = 4096;
/// Cap on a reassembled `GetSigned` body. Generous for a content.json (the
/// biggest real ones are a couple of MiB) and finite, so a peer cannot
/// stream unbounded bytes into our RAM on a request that has no other size
/// hint. Public because the serving side caps its read at the same value:
/// serving less than a client accepts makes such a xite uncloneable.
pub const MAX_SIGNED_BYTES: usize = 8 << 20;

/// How long one `GetRange` stream waits for its NEXT frame. A peer that
/// answers once and then stalls would otherwise hold the stream open until
/// the whole connection dies. The scheduler caps the total wait, so this
/// only has to catch that, and stays generous.
const RANGE_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn proto_err(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

fn remote_err(code: u16, msg: &str) -> std::io::Error {
    let kind = match code {
        err::NOT_FOUND => std::io::ErrorKind::NotFound,
        err::LIMIT | err::BUSY => std::io::ErrorKind::QuotaExceeded,
        _ => std::io::ErrorKind::Other,
    };
    std::io::Error::new(kind, format!("peer: {code} {msg}"))
}

/// Fires a best-effort `Conn::cancel_now` for its stream when dropped while
/// still armed, so an abandoned in-flight fetch stops the peer's encode
/// (see `fetch_many`; the range path uses [`RangeGuard`], which also
/// salvages). Disarm (`armed = false`) once the reply arrives.
struct CancelOnAbandon<'a> {
    conn: &'a Conn,
    stream: u64,
    armed: bool,
}

impl Drop for CancelOnAbandon<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.conn.cancel_now(self.stream);
        }
    }
}

/// New slice bytes between incremental verified commits. Each flush
/// re-decodes the buffered prefix from the start, so the threshold trades
/// redundant hashing (cheap, blake3) against how many bytes a mid-transfer
/// failure can lose. 256 KiB means a 1 MiB batch dying at 90% keeps ~3/4.
const FLUSH_BYTES: usize = 256 * 1024;

/// A reader that bumps the shared progress counter as the verified decode
/// consumes it, so a flush's own disk commit counts as transfer liveness:
/// the scheduler's stall watcher (`sched::race_batch`) must never mistake
/// our disk-commit latency for a peer that stopped sending.
struct BumpReads<'a> {
    inner: &'a [u8],
    progress: &'a std::sync::atomic::AtomicU64,
}

impl std::io::Read for BumpReads<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = std::io::Read::read(&mut self.inner, buf)?;
        if n > 0 {
            self.progress.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(n)
    }
}

/// The receive buffer of one in-flight `GetRange`, with incremental
/// verified commits: a flush decodes the buffered slice prefix into the
/// store (`Store::write_slice_partial`), so the groups received so far
/// survive a later timeout or abandonment. At most one flush runs at a
/// time and the frame loop never awaits a running one (it reaps finished
/// flushes between frames), so the loop keeps reading — and the shared
/// progress counter keeps moving — while the disk works; an awaited flush
/// would freeze the counter and read as a peer stall to the scheduler.
/// Each flush is still a SHORT blocking task, never one that lives for the
/// whole transfer, which would hold tokio's paused test clock
/// (auto-advance is inhibited while a blocking task runs) and deadlock the
/// sim harness.
struct SliceSink {
    store: Arc<Store>,
    obj: ObjId,
    ranges: Vec<Range<u64>>,
    now: u64,
    buf: Vec<u8>,
    /// `buf` length at the last flush; a drop with nothing new skips the
    /// salvage pass.
    flushed: usize,
    /// The one in-flight incremental commit, reaped between frames.
    pending: Option<tokio::task::JoinHandle<std::io::Result<u64>>>,
}

impl SliceSink {
    /// Start the decode-and-commit of the buffered prefix on the blocking
    /// pool. Mid-stream the buffer legitimately ends inside a leaf, so
    /// `UnexpectedEof` is expected on a non-`terminal` flush — the groups
    /// that did verify are committed regardless; any other decode error
    /// means the peer sent bytes that do not verify. Resolves to the
    /// verified payload bytes the pass wrote.
    fn spawn_flush(
        &mut self,
        terminal: bool,
        progress: &Arc<std::sync::atomic::AtomicU64>,
    ) -> tokio::task::JoinHandle<std::io::Result<u64>> {
        self.flushed = self.buf.len();
        let store = self.store.clone();
        let obj = self.obj;
        let ranges = self.ranges.clone();
        let bytes = self.buf.clone();
        let now = self.now;
        let progress = progress.clone();
        tokio::task::spawn_blocking(move || {
            let reader = BumpReads { inner: &bytes[..], progress: &progress };
            let res = store.write_slice_partial(obj, &ranges, reader, now);
            match res {
                Ok(held) => Ok(held),
                Err(e) if !terminal && e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
                Err(e) => Err(e),
            }
        })
    }

    /// Take one data frame of the slice: bounds-check it against the
    /// request's byte `cap`, buffer it, and keep the incremental commit
    /// pipeline moving. Returns whether the frame was the terminal one.
    async fn absorb(
        &mut self,
        last: bool,
        bytes: &[u8],
        cap: u64,
        progress: &Arc<std::sync::atomic::AtomicU64>,
    ) -> std::io::Result<bool> {
        // The byte cap is the only bound on the frame loop, so a frame
        // that adds no bytes must not be allowed to repeat forever.
        // FrameSink only emits a non-terminal frame once it is full
        // (server.rs), so no honest server sends one.
        if bytes.is_empty() && !last {
            return Err(proto_err("peer sent an empty non-terminal data frame"));
        }
        if self.buf.len() as u64 + bytes.len() as u64 > cap {
            return Err(proto_err("peer sent more slice bytes than the request implies"));
        }
        progress.fetch_add(bytes.len() as u64, std::sync::atomic::Ordering::Relaxed);
        self.buf.extend_from_slice(bytes);
        if last {
            return Ok(true);
        }
        // Incremental verified commit of the received prefix, so a
        // failure later in the transfer keeps these groups. Reap a
        // finished commit (surfacing verify errors) and start the
        // next once enough new bytes buffered — never awaiting a
        // running one, so the frame loop (and the progress counter
        // the stall watcher reads) is never frozen by the disk.
        self.reap(false).await?;
        if self.pending.is_none() && self.buf.len() - self.flushed >= FLUSH_BYTES {
            let flush = self.spawn_flush(false, progress);
            self.pending = Some(flush);
        }
        Ok(false)
    }

    /// Reap the in-flight flush: with `wait` it is awaited, otherwise only
    /// a FINISHED one is collected (never blocking the frame loop). A
    /// flush error (bytes that failed verification) surfaces here.
    async fn reap(&mut self, wait: bool) -> std::io::Result<()> {
        let Some(handle) = &self.pending else { return Ok(()) };
        if !wait && !handle.is_finished() {
            return Ok(());
        }
        let handle = self.pending.take().expect("pending flush");
        handle.await.map_err(|e| std::io::Error::other(e.to_string()))??;
        Ok(())
    }
}

/// Fires when an in-flight `GetRange` is dropped while still armed (the
/// scheduler abandoning a stalled batch or a losing duplicate racer, a
/// caller timing the future out): a best-effort Cancel so the peer stops
/// encoding, plus a detached salvage decode of any received-but-unflushed
/// bytes — everything that verifies stays in the store. Disarm once the
/// terminal frame lands (the final flush commits everything).
struct RangeGuard<'a> {
    conn: &'a Conn,
    stream: u64,
    armed: bool,
    sink: SliceSink,
}

impl Drop for RangeGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.conn.cancel_now(self.stream);
        if self.sink.buf.len() > self.sink.flushed {
            let store = self.sink.store.clone();
            let obj = self.sink.obj;
            let ranges = std::mem::take(&mut self.sink.ranges);
            let bytes = std::mem::take(&mut self.sink.buf);
            let now = self.sink.now;
            // A plain thread, not the runtime's blocking pool: drop may run
            // while the runtime itself is shutting down.
            std::thread::spawn(move || {
                let _ = store.write_slice_partial(obj, &ranges, &bytes[..], now);
            });
        }
    }
}

/// Fetch byte ranges of `obj` from a peer and land them (verified) in
/// the store. The object must already be `ensure_sparse`'d. Returns the
/// verified payload bytes written.
pub async fn fetch_ranges(
    conn: &Conn,
    store: &Arc<Store>,
    obj: ObjId,
    size: u64,
    ranges: &[Range<u64>],
    deadline_ms: u32,
    now: u64,
) -> std::io::Result<usize> {
    let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
    fetch_ranges_observed(conn, store, obj, size, ranges, deadline_ms, now, &progress).await
}

/// [`fetch_ranges`], reporting liveness: `progress` is bumped by every
/// received byte (and by the incremental commits decoding them), so the
/// scheduler can tell a slow-but-moving transfer from a stalled one
/// (`sched::race_batch`'s stall-only duplication).
///
/// Progress is durable: every FLUSH_BYTES the buffered slice prefix is
/// verified-decoded into the store, and abandonment salvages the tail
/// ([`RangeGuard`]) — a timeout keeps every group that made it, instead of
/// discarding the whole batch.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_ranges_observed(
    conn: &Conn,
    store: &Arc<Store>,
    obj: ObjId,
    size: u64,
    ranges: &[Range<u64>],
    deadline_ms: u32,
    now: u64,
    progress: &Arc<std::sync::atomic::AtomicU64>,
) -> std::io::Result<usize> {
    let req_ranges: Vec<(u64, u64)> = ranges.iter().map(|r| (r.start, r.end)).collect();
    let mut rx = conn
        .request_stream(Req::GetRange { obj, size, ranges: req_ranges, deadline_ms })
        .await?;

    // Cancel-on-abandon + salvage: the scheduler duplicates a stalled range
    // onto other peers (`sched::race_batch`) and drops the losers the
    // moment one wins. A dropped fetch future must tell its peer to STOP
    // encoding, or the loser keeps pushing a full slice we already have
    // from the winner; anything received that still verifies is committed
    // rather than thrown away. Disarmed once the terminal frame lands, so
    // a cleanly completed fetch never cancels.
    let mut guard = RangeGuard {
        conn,
        stream: rx.id,
        armed: true,
        sink: SliceSink {
            store: store.clone(),
            obj,
            ranges: ranges.to_vec(),
            now,
            buf: Vec::new(),
            flushed: 0,
            pending: None,
        },
    };

    // Bounded: requested bytes + ~2% outboard overhead + 1 MiB slack.
    let requested: u64 = ranges.iter().map(|r| r.end - r.start).sum();
    let cap = (requested + requested / 50 + (1 << 20)).min(crate::server::MAX_BYTES_PER_REQ * 2);
    loop {
        // Per-frame deadline: the byte cap only bounds a peer that keeps
        // sending, not one that answers a frame and then goes quiet.
        let next = match tokio::time::timeout(RANGE_FRAME_TIMEOUT, rx.recv()).await {
            Ok(next) => next,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "peer stalled mid-slice",
                ))
            }
        };
        match next {
            Some(FrameBody::Data { last, bytes }) => {
                if guard.sink.absorb(last, &bytes, cap, progress).await? {
                    break;
                }
            }
            Some(FrameBody::Resp { resp: Resp::Err { code, msg }, .. }) => {
                return Err(remote_err(code, &msg));
            }
            Some(other) => return Err(proto_err(format!("unexpected frame {other:?}"))),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed mid-slice",
                ))
            }
        }
    }
    // The stream ended on its own; there is nothing to cancel and the final
    // flush commits everything, so the salvage pass has nothing to add.
    guard.armed = false;
    guard.sink.reap(true).await?;
    let held = guard
        .sink
        .spawn_flush(true, progress)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))??;
    Ok(held as usize)
}

/// Push a signed update to a peer: the content.json `signed` body plus the
/// version `modified`, per-file `diffs` (`inner_path -> encoded actions`),
/// the publisher's `sender_peers` dial-back addresses, and any `inline`
/// small objects. Returns Ok when the peer accepted it (whether newly
/// applied or already-known); Err on a protocol rejection or a closed link.
#[allow(clippy::too_many_arguments)]
pub async fn push_update(
    conn: &Conn,
    xite: &str,
    inner_path: &str,
    signed: &[u8],
    modified: f64,
    diffs: Vec<(String, Vec<u8>)>,
    sender_peers: Vec<String>,
    inline: Vec<(ObjId, Vec<u8>)>,
) -> std::io::Result<()> {
    match conn
        .request(Req::Update {
            xite: xite.into(),
            inner_path: inner_path.into(),
            signed: signed.to_vec(),
            inline,
            modified,
            diffs,
            sender_peers,
        })
        .await?
    {
        Resp::Ok => Ok(()),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected Ok, got {other:?}"))),
    }
}

/// Fetch a signed content.json (raw bytes — caller verifies signature).
/// A big site's content.json does not fit one frame (see `serve_signed`),
/// so this drains the stream until the terminal frame and concatenates,
/// instead of taking the first response. Bounded by [`MAX_SIGNED_BYTES`]:
/// the request carries no size hint, so without a cap a peer could stream
/// bytes into our RAM for as long as it liked.
pub async fn fetch_signed(conn: &Conn, xite: &str, inner_path: &str) -> std::io::Result<Vec<u8>> {
    let mut rx = conn
        .request_stream(Req::GetSigned { xite: xite.into(), inner_path: inner_path.into() })
        .await?;
    let mut out: Vec<u8> = Vec::new();
    let mut frames = 0usize;
    loop {
        match rx.recv().await {
            Some(FrameBody::Resp { last, resp: Resp::Signed { bytes } }) => {
                frames += 1;
                if frames > MAX_REPLY_FRAMES || out.len() + bytes.len() > MAX_SIGNED_BYTES {
                    return Err(proto_err("oversize Signed reply"));
                }
                out.extend_from_slice(&bytes);
                if last {
                    return Ok(out);
                }
            }
            Some(FrameBody::Resp { resp: Resp::Err { code, msg }, .. }) => {
                return Err(remote_err(code, &msg))
            }
            Some(other) => return Err(proto_err(format!("expected Signed, got {other:?}"))),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed mid-signed",
                ))
            }
        }
    }
}

/// Signed files changed since `since`: (inner_path, modified, size).
/// A big xite's list spans several frames (see `serve_signed_list`), so
/// this drains the stream until the terminal frame instead of taking the
/// first response.
pub async fn list_signed(
    conn: &Conn,
    xite: &str,
    since: u64,
) -> std::io::Result<Vec<(String, u64, u64)>> {
    let mut rx = conn.request_stream(Req::ListSigned { xite: xite.into(), since }).await?;
    let mut out: Vec<(String, u64, u64)> = Vec::new();
    let mut frames = 0usize;
    loop {
        match rx.recv().await {
            Some(FrameBody::Resp { last, resp: Resp::SignedList { entries } }) => {
                frames += 1;
                if frames > MAX_REPLY_FRAMES || out.len() + entries.len() > MAX_LIST_ENTRIES {
                    return Err(proto_err("oversize SignedList reply"));
                }
                out.extend(entries);
                if last {
                    return Ok(out);
                }
            }
            Some(FrameBody::Resp { resp: Resp::Err { code, msg }, .. }) => {
                return Err(remote_err(code, &msg))
            }
            Some(other) => return Err(proto_err(format!("expected SignedList, got {other:?}"))),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed mid-list",
                ))
            }
        }
    }
}

/// Verify and insert one GetMany frame's items. Charges every item's bytes
/// against the reply budget (`received`/`cap`), skips ids we did not ask
/// for, and hash-verifies each kept blob on insert. Returns how many blobs
/// were inserted; their ids are added to `got`.
async fn store_many_items(
    store: &Arc<Store>,
    want: &std::collections::HashSet<ObjId>,
    items: Vec<(ObjId, Vec<u8>)>,
    now: u64,
    received: &mut u64,
    cap: u64,
    got: &mut std::collections::HashSet<ObjId>,
) -> std::io::Result<usize> {
    let mut inserted = 0usize;
    for (id, bytes) in items {
        // Unrequested bytes count against the budget too, or a
        // peer could stream junk blobs at us for free.
        *received += bytes.len() as u64;
        if *received > cap {
            return Err(proto_err("peer sent more GetMany bytes than the request implies"));
        }
        // Never persist a blob we did not ask for: insert_bytes
        // only proves the bytes hash to `id`, not that we wanted it.
        if !want.contains(&id) {
            continue;
        }
        // insert_bytes re-verifies BLAKE3(bytes) == id; a lying
        // peer's blob fails here and is not counted.
        let store = store.clone();
        let ok =
            tokio::task::spawn_blocking(move || store.insert_bytes(id, Ns::Plain, &bytes, now))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        if ok.is_ok() {
            got.insert(id);
            inserted += 1;
        }
    }
    Ok(inserted)
}

/// Fetch many small whole blobs in one round trip; each is hash-verified
/// on insert. Returns (inserted, missing) — missing ids simply weren't
/// in the response (the peer doesn't have them; try elsewhere).
pub async fn fetch_many(
    conn: &Conn,
    store: &Arc<Store>,
    objs: &[ObjId],
    now: u64,
) -> std::io::Result<(usize, Vec<ObjId>)> {
    let mut rx = conn.request_stream(Req::GetMany { objs: objs.to_vec() }).await?;
    // Same contract as fetch_ranges: an abandoned or timed-out GetMany must
    // tell the peer to stop encoding instead of leaving it streaming.
    let mut guard = CancelOnAbandon { conn, stream: rx.id, armed: true };
    let want: std::collections::HashSet<ObjId> = objs.iter().copied().collect();
    // What an honest serve_many can send at most: one item per requested id,
    // each at most MAX_MANY_ITEM_BYTES.
    let cap = objs.len() as u64 * crate::server::MAX_MANY_ITEM_BYTES;
    let mut received = 0u64;
    let mut frames = 0usize;
    let mut got: std::collections::HashSet<ObjId> = std::collections::HashSet::new();
    let mut inserted = 0usize;
    loop {
        match rx.recv().await {
            Some(FrameBody::Resp { last, resp: Resp::Many { items } }) => {
                frames += 1;
                if frames > MAX_REPLY_FRAMES {
                    return Err(proto_err(
                        "peer sent more GetMany frames than the request implies",
                    ));
                }
                inserted +=
                    store_many_items(store, &want, items, now, &mut received, cap, &mut got)
                        .await?;
                if last {
                    break;
                }
            }
            Some(FrameBody::Resp { resp: Resp::Err { code, msg }, .. }) => {
                return Err(remote_err(code, &msg));
            }
            Some(other) => return Err(proto_err(format!("unexpected frame {other:?}"))),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed mid-batch",
                ))
            }
        }
    }
    // The stream ended on its own; there is nothing to cancel.
    guard.armed = false;
    let missing = objs.iter().filter(|o| !got.contains(o)).copied().collect();
    Ok((inserted, missing))
}

/// Which chunk groups of `obj` the peer holds.
pub async fn fetch_bitfield(conn: &Conn, obj: ObjId) -> std::io::Result<(u64, GroupBits)> {
    match conn.request(Req::GetBitfield { obj }).await? {
        Resp::Bitfield { size, runs } => {
            let bits = GroupBits::from_wire(&runs)
                .ok_or_else(|| proto_err("malformed bitfield runs"))?;
            Ok((size, bits))
        }
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected Bitfield, got {other:?}"))),
    }
}

/// Which of `addrs` the peer holds COMPLETE, as a bool per addr in the
/// same order (mirrors `fetch_bitfield` but for many objects at once). One
/// round trip regardless of how many shards a private file has; the packed
/// mask is unpacked LSB-first. A peer that answers a too-short mask (fewer
/// bits than addrs) reads as "not held" for the missing tail.
pub async fn fetch_has_shards(conn: &Conn, addrs: &[ObjId]) -> std::io::Result<Vec<bool>> {
    match conn.request(Req::HasShards { addrs: addrs.to_vec() }).await? {
        Resp::ShardMask { bits } => Ok((0..addrs.len())
            .map(|i| bits.get(i / 8).map(|b| b & (1 << (i % 8)) != 0).unwrap_or(false))
            .collect()),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected ShardMask, got {other:?}"))),
    }
}

// --- Control plane (caps::CONTROL): the client helpers. All are
// single-response requests on the priority lane.

/// Propagation hints after `after`: (xite, modified) pairs + new cursor.
/// Spans frames on a busy relay (see `serve_updates`); `head` is taken
/// from the terminal frame, so a truncated poll never advances the cursor
/// past hints the caller did not receive.
pub async fn updates_since(conn: &Conn, after: u64) -> std::io::Result<(Vec<(String, i64)>, u64)> {
    let mut rx = conn.request_stream(Req::UpdatesSince { after }).await?;
    let mut out: Vec<(String, i64)> = Vec::new();
    let mut frames = 0usize;
    loop {
        match rx.recv().await {
            Some(FrameBody::Resp { last, resp: Resp::Updates { updates, head } }) => {
                frames += 1;
                if frames > MAX_REPLY_FRAMES || out.len() + updates.len() > MAX_UPDATE_HINTS {
                    return Err(proto_err("oversize Updates reply"));
                }
                out.extend(updates);
                if last {
                    return Ok((out, head));
                }
            }
            Some(FrameBody::Resp { resp: Resp::Err { code, msg }, .. }) => {
                return Err(remote_err(code, &msg))
            }
            Some(other) => return Err(proto_err(format!("expected Updates, got {other:?}"))),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "connection closed mid-poll",
                ))
            }
        }
    }
}

/// Peer exchange for `xite`: send what we know, get what we lack.
pub async fn pex(
    conn: &Conn,
    xite: &str,
    need: u32,
    have: Vec<epix_core::PeerAddr>,
) -> std::io::Result<Vec<epix_core::PeerAddr>> {
    match conn.request(Req::Pex { xite: xite.into(), need, peers: have }).await? {
        Resp::Peers { peers } => Ok(peers),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected Peers, got {other:?}"))),
    }
}

/// The peer's working tracker set (Beacon gossip).
pub async fn get_trackers(conn: &Conn) -> std::io::Result<Vec<String>> {
    match conn.request(Req::GetTrackers).await? {
        Resp::Trackers { trackers } => Ok(trackers),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected Trackers, got {other:?}"))),
    }
}

/// One Kademlia RPC (payload encoded/decoded by epix-dht-net).
pub async fn kad(conn: &Conn, payload: Vec<u8>) -> std::io::Result<Vec<u8>> {
    match conn.request(Req::Kad { payload }).await? {
        Resp::Payload { bytes } => Ok(bytes),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected Payload, got {other:?}"))),
    }
}

/// One tracker announce (payload encoded/decoded by epix-discovery).
pub async fn announce(conn: &Conn, payload: Vec<u8>) -> std::io::Result<Vec<u8>> {
    match conn.request(Req::Announce { payload }).await? {
        Resp::Payload { bytes } => Ok(bytes),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected Payload, got {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::Frame;
    use epix_blob::verified::{encode_slice, OutboardBytes};

    fn test_data(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
    }

    /// A fetch abandoned mid-flight - the state a losing duplicate racer is
    /// left in when `sched::race_batch` drops it - must tell the serving peer
    /// to stop encoding. Here the server never answers, so the fetch stays
    /// suspended; dropping it must fire a Cancel for its stream.
    #[tokio::test]
    async fn dropping_an_inflight_fetch_cancels_the_stream() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, _client_in) = Conn::start(a, true);
        // Keep the server's incoming receiver bound so the connection stays
        // open; its reader records inbound Cancel frames with no handler.
        let (server, mut server_in) = Conn::start(b, false);

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let obj = ObjId::of(b"unanswered");
        let size = 1000u64;
        store.ensure_sparse(obj, Ns::Plain, size, 1).unwrap();

        // Box::pin so `drop(fut)` drops the underlying future (running the
        // CancelOnAbandon guard); tokio::pin! would only drop a &mut.
        let want = [0..size];
        let mut fut = Box::pin(fetch_ranges(&client, &store, obj, size, &want, 0, 1));

        // Drive the fetch until the server receives its GetRange, capturing
        // the real stream id. The fetch itself never completes (unanswered).
        let stream = tokio::select! {
            _ = &mut fut => panic!("fetch must not complete without a response"),
            inc = server_in.recv() => inc.expect("server received the GetRange").stream,
        };

        // Abandon it: the Drop guard fires a synchronous best-effort Cancel.
        drop(fut);

        let saw_cancel = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if server.take_cancelled(stream) {
                    break true;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a dropped in-flight fetch should cancel its peer stream");
        assert!(saw_cancel);
    }

    /// The mirror case: a fetch that completes cleanly must NOT cancel - the
    /// guard has to disarm once the terminal frame lands, or every healthy
    /// fetch would spam the peer with a pointless Cancel.
    #[tokio::test]
    async fn a_completed_fetch_does_not_cancel() {
        let data = test_data(50_000);
        let obj = ObjId::of(&data);
        let size = data.len() as u64;
        // The canonical bao slice for the whole object: exactly what a real
        // serve_range streams and what write_slice verifies against.
        let ob = OutboardBytes::from_slice(&data);
        let ranges = vec![0..size];
        let mut slice = Vec::new();
        encode_slice(&data[..], &ob, &ranges, &mut slice).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        // Server: answer the one GetRange with the slice, chunked into frames.
        let srv = server.clone();
        let server_task = tokio::spawn(async move {
            let inc = server_in.recv().await.expect("GetRange");
            assert!(matches!(inc.req, Req::GetRange { .. }));
            let stream = inc.stream;
            let mut off = 0usize;
            while off < slice.len() {
                let end = (off + 60_000).min(slice.len());
                let last = end == slice.len();
                srv.send(Frame {
                    stream,
                    body: FrameBody::Data { last, bytes: slice[off..end].to_vec() },
                })
                .await
                .unwrap();
                off = end;
            }
            stream
        });

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        store.ensure_sparse(obj, Ns::Plain, size, 1).unwrap();

        let got = fetch_ranges(&client, &store, obj, size, &ranges, 0, 2).await.unwrap();
        assert!(got > 0, "fetch received and verified the slice");
        assert!(store.is_complete(obj).unwrap(), "the object completed locally");

        let stream = server_task.await.unwrap();
        // Any erroneous Cancel is emitted synchronously as fetch_ranges
        // returns; give it time to cross, then confirm none was sent.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(!server.take_cancelled(stream), "a completed fetch must not cancel its stream");
    }

    /// A transfer that dies mid-slice must KEEP the groups that already
    /// verified: the encoded prefix a stalling peer managed to send is
    /// decoded and committed as it arrives, not discarded with the batch.
    /// (A 1 MiB batch over a slow onion circuit used to sit exactly on the
    /// deadline cliff and throw away every received byte on timeout.)
    #[tokio::test]
    async fn a_truncated_slice_keeps_its_verified_prefix() {
        let data = test_data(200_000);
        let obj = ObjId::of(&data);
        let size = data.len() as u64;
        let ob = OutboardBytes::from_slice(&data);
        let ranges = vec![0..size];
        let mut slice = Vec::new();
        encode_slice(&data[..], &ob, &ranges, &mut slice).unwrap();

        let (a, b) = tokio::io::duplex(1 << 20);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        // Server: send HALF the slice, then go silent with the stream open.
        let half = slice.len() / 2;
        let srv = server.clone();
        tokio::spawn(async move {
            let inc = server_in.recv().await.expect("GetRange");
            let mut off = 0usize;
            while off < half {
                let end = (off + 50_000).min(half);
                let body = FrameBody::Data { last: false, bytes: slice[off..end].to_vec() };
                if srv.send(Frame { stream: inc.stream, body }).await.is_err() {
                    return;
                }
                off = end;
            }
            std::future::pending::<()>().await;
        });

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        store.ensure_sparse(obj, Ns::Plain, size, 1).unwrap();

        // No terminal frame ever comes: abandon the fetch, exactly what the
        // scheduler's stall failure does to a batch.
        let fut = Box::pin(fetch_ranges(&client, &store, obj, size, &ranges, 0, 2));
        let abandoned = tokio::time::timeout(std::time::Duration::from_millis(500), fut).await;
        assert!(abandoned.is_err(), "the truncated fetch must not complete");

        // The detached decode drains and commits what verified; poll for it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let present = loop {
            let bits = store.present_bits(obj).unwrap();
            if !bits.is_empty() {
                break bits;
            }
            assert!(std::time::Instant::now() < deadline, "no partial group was committed");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        assert!(!store.is_complete(obj).unwrap(), "only a prefix arrived");
        assert!(present.contains(0), "the committed prefix starts at group 0");
        let g = epix_blob::bitfield::GROUP_BYTES as usize;
        let got = store.read_range(obj, 0, g as u64, 3).unwrap();
        assert_eq!(got, data[..g], "committed prefix bytes verify and read back");
    }

    /// An empty non-terminal Data frame adds no bytes, so the byte cap can
    /// never trip on it: a peer could send them forever and keep the fetch
    /// alive. The honest server never emits one, so it must be rejected.
    #[tokio::test]
    async fn an_empty_non_terminal_data_frame_is_rejected() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        let srv = server.clone();
        tokio::spawn(async move {
            let inc = server_in.recv().await.expect("server received the GetRange");
            let body = FrameBody::Data { last: false, bytes: vec![] };
            for _ in 0..4 {
                let frame = Frame { stream: inc.stream, body: body.clone() };
                if srv.send(frame).await.is_err() {
                    return;
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let obj = ObjId::of(b"empty-frames");
        let size = 1000u64;
        store.ensure_sparse(obj, Ns::Plain, size, 1).unwrap();

        let want = [0..size];
        let err = fetch_ranges(&client, &store, obj, size, &want, 0, 1).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        drop(server);
    }

    /// A GetMany answer may only carry blobs we asked for. An unrequested
    /// blob still hashes to its own id, so insert_bytes would accept it and
    /// fsync attacker-chosen bytes into the slab.
    #[tokio::test]
    async fn fetch_many_ignores_blobs_it_did_not_request() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        let wanted = test_data(1024);
        let junk = test_data(2048);
        let want_id = ObjId::of(&wanted);
        let junk_id = ObjId::of(&junk);

        let srv = server.clone();
        tokio::spawn(async move {
            let inc = server_in.recv().await.expect("server received the GetMany");
            let _ = srv
                .send(Frame {
                    stream: inc.stream,
                    body: FrameBody::Resp {
                        last: true,
                        resp: Resp::Many { items: vec![(want_id, wanted), (junk_id, junk)] },
                    },
                })
                .await;
        });

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        let (inserted, missing) = fetch_many(&client, &store, &[want_id], 3).await.unwrap();
        assert_eq!(inserted, 1, "only the requested blob counts");
        assert!(missing.is_empty(), "the requested blob arrived");
        assert!(store.contains(want_id).unwrap(), "the requested blob landed");
        assert!(!store.contains(junk_id).unwrap(), "an unrequested blob must never be stored");
        drop(server);
    }

    /// The peer decides when a streamed list ends, so a peer that never
    /// sets `last` must not be able to grow our accumulator without bound.
    #[tokio::test]
    async fn an_endless_signed_list_is_cut_off() {
        const PER_FRAME: usize = 10_000;

        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        let srv = server.clone();
        tokio::spawn(async move {
            let inc = server_in.recv().await.expect("server received the ListSigned");
            // Just past MAX_LIST_ENTRIES, every frame non-terminal.
            for _ in 0..(MAX_LIST_ENTRIES / PER_FRAME + 1) {
                let entries: Vec<(String, u64, u64)> =
                    (0..PER_FRAME).map(|_| (String::new(), 0, 0)).collect();
                let frame = Frame {
                    stream: inc.stream,
                    body: FrameBody::Resp { last: false, resp: Resp::SignedList { entries } },
                };
                if srv.send(frame).await.is_err() {
                    return;
                }
            }
        });

        let err = list_signed(&client, "1Abc", 0).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        drop(server);
    }

    /// A signed body larger than one frame arrives as several `Signed`
    /// frames and must reassemble byte-identically (see `serve_signed`).
    #[tokio::test]
    async fn a_chunked_signed_body_reassembles() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        let body = test_data(150_000);
        let expect = body.clone();
        let srv = server.clone();
        tokio::spawn(async move {
            let inc = server_in.recv().await.expect("server received the GetSigned");
            let mut off = 0usize;
            while off < body.len() {
                let end = (off + 60_000).min(body.len());
                let last = end == body.len();
                let frame = Frame {
                    stream: inc.stream,
                    body: FrameBody::Resp {
                        last,
                        resp: Resp::Signed { bytes: body[off..end].to_vec() },
                    },
                };
                if srv.send(frame).await.is_err() {
                    return;
                }
                off = end;
            }
        });

        let got = fetch_signed(&client, "1Abc", "content.json").await.unwrap();
        assert_eq!(got, expect, "every chunk survives reassembly");
        drop(server);
    }

    /// The peer decides when a streamed body ends and `GetSigned` carries no
    /// size hint, so a peer that never sets `last` must not be able to grow
    /// our accumulator without bound.
    #[tokio::test]
    async fn an_endless_signed_body_is_cut_off() {
        const PER_FRAME: usize = 60_000;

        let (a, b) = tokio::io::duplex(1 << 16);
        let (client, _client_in) = Conn::start(a, true);
        let (server, mut server_in) = Conn::start(b, false);

        let srv = server.clone();
        tokio::spawn(async move {
            let inc = server_in.recv().await.expect("server received the GetSigned");
            // Just past MAX_SIGNED_BYTES, every frame non-terminal.
            for _ in 0..(MAX_SIGNED_BYTES / PER_FRAME + 1) {
                let frame = Frame {
                    stream: inc.stream,
                    body: FrameBody::Resp {
                        last: false,
                        resp: Resp::Signed { bytes: vec![0u8; PER_FRAME] },
                    },
                };
                if srv.send(frame).await.is_err() {
                    return;
                }
            }
        });

        let err = fetch_signed(&client, "1Abc", "content.json").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        drop(server);
    }
}
