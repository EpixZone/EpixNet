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
/// (see `fetch_ranges`). Disarm (`armed = false`) once the slice arrives.
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

/// Fetch byte ranges of `obj` from a peer and land them (verified) in
/// the store. The object must already be `ensure_sparse`'d. Returns the
/// slice size received.
pub async fn fetch_ranges(
    conn: &Conn,
    store: &Arc<Store>,
    obj: ObjId,
    size: u64,
    ranges: &[Range<u64>],
    deadline_ms: u32,
    now: u64,
) -> std::io::Result<usize> {
    let req_ranges: Vec<(u64, u64)> = ranges.iter().map(|r| (r.start, r.end)).collect();
    let mut rx = conn
        .request_stream(Req::GetRange { obj, size, ranges: req_ranges, deadline_ms })
        .await?;

    // Cancel-on-abandon: the scheduler duplicates a stalled range onto other
    // peers (`sched::race_batch`) and drops the losers the moment one wins.
    // A dropped fetch future must tell its peer to STOP encoding, or the
    // loser keeps pushing a full slice we already have from the winner. The
    // guard fires a best-effort Cancel on drop while armed; it also covers
    // seek-abandon and deadline give-up. Disarmed once the terminal frame
    // lands, so a cleanly completed fetch never cancels.
    let mut guard = CancelOnAbandon { conn, stream: rx.id, armed: true };

    // Collect the slice. Bounded: requested bytes + outboard overhead.
    let requested: u64 = ranges.iter().map(|r| r.end - r.start).sum();
    // Requested bytes + ~2% outboard overhead + 1 MiB slack.
    let cap = (requested + requested / 50 + (1 << 20)).min(crate::server::MAX_BYTES_PER_REQ * 2);
    let mut slice = Vec::new();
    loop {
        match rx.recv().await {
            Some(FrameBody::Data { last, bytes }) => {
                if slice.len() as u64 + bytes.len() as u64 > cap {
                    return Err(proto_err("peer sent more slice bytes than the request implies"));
                }
                slice.extend_from_slice(&bytes);
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
                    "connection closed mid-slice",
                ))
            }
        }
    }
    // The stream ended on its own; there is nothing to cancel.
    guard.armed = false;

    // Verified decode into the sparse store (blocking IO off the runtime).
    let store = store.clone();
    let ranges = ranges.to_vec();
    let len = slice.len();
    tokio::task::spawn_blocking(move || store.write_slice(obj, &ranges, &slice[..], now))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))??;
    Ok(len)
}

/// Fetch a signed content.json (raw bytes — caller verifies signature).
pub async fn fetch_signed(conn: &Conn, xite: &str, inner_path: &str) -> std::io::Result<Vec<u8>> {
    match conn
        .request(Req::GetSigned { xite: xite.into(), inner_path: inner_path.into() })
        .await?
    {
        Resp::Signed { bytes } => Ok(bytes),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected Signed, got {other:?}"))),
    }
}

/// Signed files changed since `since`: (inner_path, modified, size).
pub async fn list_signed(
    conn: &Conn,
    xite: &str,
    since: u64,
) -> std::io::Result<Vec<(String, u64, u64)>> {
    match conn.request(Req::ListSigned { xite: xite.into(), since }).await? {
        Resp::SignedList { entries } => Ok(entries),
        Resp::Err { code, msg } => Err(remote_err(code, &msg)),
        other => Err(proto_err(format!("expected SignedList, got {other:?}"))),
    }
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
    let mut got: std::collections::HashSet<ObjId> = std::collections::HashSet::new();
    let mut inserted = 0usize;
    loop {
        match rx.recv().await {
            Some(FrameBody::Resp { last, resp: Resp::Many { items } }) => {
                for (id, bytes) in items {
                    // insert_bytes re-verifies BLAKE3(bytes) == id; a lying
                    // peer's blob fails here and is not counted.
                    let store = store.clone();
                    let ok = tokio::task::spawn_blocking(move || {
                        store.insert_bytes(id, Ns::Plain, &bytes, now)
                    })
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                    if ok.is_ok() {
                        got.insert(id);
                        inserted += 1;
                    }
                }
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
}
