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
