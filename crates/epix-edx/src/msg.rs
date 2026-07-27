//! The EDX message set (postcard-encoded).
//!
//! COMPATIBILITY RULE: postcard encodes enum variants by index. Variants
//! may only ever be APPENDED to `Req`, `Resp`, and `FrameBody` — never
//! reordered, renamed-in-place, or removed — or every deployed node
//! misparses the wire. The `wire_indices_frozen` test pins the current
//! assignment.
//!
//! Requests that stream (GetRange, GetMany) answer with `Data` frames on
//! the same stream id; everything else answers with a single `Resp`.
//! `HaveRanges` is a notification (no response). Object bytes always
//! travel as verified bao slices (`docs/edx-slice-format.md`) except
//! `GetMany`, whose sub-4 KiB whole blobs are verified by whole-blob
//! hash on arrival.

use epix_blob::ObjId;
use epix_core::PeerAddr;
use serde::{Deserialize, Serialize};

/// Network identifier — connections to another net are refused.
pub const NET_ID: &str = "epixnet-edx-1";

/// Capability bitflags in `Hello::caps`.
pub mod caps {
    /// Serves the encrypted-shard namespace (disk cache node).
    pub const SHARDS: u32 = 1 << 0;
    /// Accepts `Update` pushes for xites it seeds.
    pub const MESH: u32 = 1 << 1;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    /// Must equal [`NET_ID`].
    pub net: String,
    /// Compressed secp256k1 node public key (33 bytes; the node identity
    /// shares the chain/xite keyspace).
    pub node_pk: Vec<u8>,
    /// On Noise links: signature by `node_pk` over the channel-binding
    /// transcript (proof of possession — see `noise.rs`). Empty on
    /// overlay links, whose transport already authenticates the endpoint.
    pub binding_sig: Vec<u8>,
    /// Capability bitflags (`caps::*`).
    pub caps: u32,
    /// Addresses this node can be dialed back on (the legacy handshake's
    /// dial-back adoption pattern, carried over).
    pub listen: Vec<PeerAddr>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HelloAck {
    pub net: String,
    pub node_pk: Vec<u8>,
    pub binding_sig: Vec<u8>,
    pub caps: u32,
    /// The dialer's address as this node observed it (dial-back info).
    pub observed: Option<PeerAddr>,
}

/// One requested byte range of an object.
pub type ByteRange = (u64, u64); // start, end (exclusive)

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Req {
    /// Handshake; must be the first request on a connection.
    Hello(Hello),
    /// Fetch a signed content.json (root or per-user) — the mutable
    /// entry point, verified by SIGNATURE on the receiving side.
    GetSigned { xite: String, inner_path: String },
    /// `listModified` successor: signed files changed since `since`
    /// (unix seconds) — how forum/social xites discover per-user changes.
    ListSigned { xite: String, since: u64 },
    /// Verified multi-range fetch: the heart of streaming/seek. Answered
    /// by `Data` frames carrying one bao slice for exactly these ranges.
    /// `deadline_ms` is a HINT for the server's own send ordering among
    /// this peer's streams — never a cross-peer priority (fair-share is
    /// enforced per peer).
    GetRange { obj: ObjId, size: u64, ranges: Vec<ByteRange>, deadline_ms: u32 },
    /// One-round-trip cold sync of many small whole blobs (each verified
    /// whole-hash client-side). Answered by `Resp::Many` frames.
    GetMany { objs: Vec<ObjId> },
    /// Which chunk groups of `obj` the peer holds.
    GetBitfield { obj: ObjId },
    /// Aggregate per-xite availability summary (avoids N per-user
    /// bitfield exchanges on a forum).
    HasXite { xite: String },
    /// Notification: these groups of `obj` became available here (RLE
    /// runs, present-first). No response.
    HaveRanges { obj: ObjId, runs: Vec<u64> },
    /// Push publish: a signed content.json + optional inline small
    /// objects (a forum post rides in one push, as today). Answered Ok.
    Update { xite: String, inner_path: String, signed: Vec<u8>, inline: Vec<(ObjId, Vec<u8>)> },
    // --- Stage 4+ appends only below this line (postcard indices!) ---
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Resp {
    HelloAck(HelloAck),
    /// Raw signed content.json bytes (caller verifies the signature).
    Signed { bytes: Vec<u8> },
    /// (inner_path, modified, size) of signed files changed since `since`.
    SignedList { entries: Vec<(String, u64, u64)> },
    /// RLE runs (present-first) of held chunk groups.
    Bitfield { size: u64, runs: Vec<u64> },
    /// Per-xite summary: signed units held, newest `modified` seen,
    /// total bytes held of that xite's objects.
    XiteSummary { signed_files: u64, newest_modified: u64, held_bytes: u64 },
    /// Batch of whole small blobs for `GetMany` (split across frames as
    /// needed; the frame's `last` flag closes the stream).
    Many { items: Vec<(ObjId, Vec<u8>)> },
    Ok,
    Err { code: u16, msg: String },
    // --- append only (postcard indices!) ---
}

/// Error codes for `Resp::Err`.
pub mod err {
    pub const NOT_FOUND: u16 = 404;
    pub const BUSY: u16 = 429;
    pub const BAD_REQUEST: u16 = 400;
    pub const LIMIT: u16 = 413;
    pub const INTERNAL: u16 = 500;
}

/// One multiplexed frame. `stream` ids are chosen by the requester and
/// must be unique among its in-flight requests (the dialer uses odd ids,
/// the acceptor even ids, so server-initiated notifications never
/// collide with client requests).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub stream: u64,
    pub body: FrameBody,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FrameBody {
    Req(Req),
    Resp { last: bool, resp: Resp },
    /// Streaming payload chunk (bao slice bytes for GetRange).
    Data { last: bool, bytes: Vec<u8> },
    /// Abort an in-flight stream (duplicate-on-timeout, endgame,
    /// seek-abandon). The server stops encoding mid-slice.
    Cancel,
    Ping,
    Pong,
    // --- append only (postcard indices!) ---
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(frame: &Frame) -> Frame {
        let bytes = postcard::to_stdvec(frame).unwrap();
        postcard::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn frames_round_trip() {
        let frames = [
            Frame {
                stream: 1,
                body: FrameBody::Req(Req::GetRange {
                    obj: ObjId([7; 32]),
                    size: 734_003_200,
                    ranges: vec![(0, 65536), (100_000_000, 100_065_536)],
                    deadline_ms: 250,
                }),
            },
            Frame {
                stream: 2,
                body: FrameBody::Resp {
                    last: true,
                    resp: Resp::SignedList {
                        entries: vec![("data/users/a/content.json".into(), 1_700_000_000, 4096)],
                    },
                },
            },
            Frame { stream: 3, body: FrameBody::Data { last: false, bytes: vec![0xAB; 1000] } },
            Frame { stream: 3, body: FrameBody::Cancel },
        ];
        for f in &frames {
            assert_eq!(&round_trip(f), f);
        }
    }

    /// Postcard encodes variants by index: this pins the current
    /// assignment so an accidental reorder fails CI instead of the net.
    #[test]
    fn wire_indices_frozen() {
        // FrameBody discriminants.
        let probes: Vec<(Frame, u8)> = vec![
            (Frame { stream: 0, body: FrameBody::Req(Req::Hello(Hello {
                net: String::new(), node_pk: vec![], binding_sig: vec![],
                caps: 0, listen: vec![] })) }, 0),
            (Frame { stream: 0, body: FrameBody::Resp { last: true, resp: Resp::Ok } }, 1),
            (Frame { stream: 0, body: FrameBody::Data { last: true, bytes: vec![] } }, 2),
            (Frame { stream: 0, body: FrameBody::Cancel }, 3),
            (Frame { stream: 0, body: FrameBody::Ping }, 4),
            (Frame { stream: 0, body: FrameBody::Pong }, 5),
        ];
        for (frame, disc) in probes {
            let bytes = postcard::to_stdvec(&frame).unwrap();
            // Layout: varint(stream=0) then varint(discriminant).
            assert_eq!(bytes[1], disc, "FrameBody discriminant moved: {frame:?}");
        }

        // Req discriminants (encoded after FrameBody::Req = 0).
        let reqs: Vec<(Req, u8)> = vec![
            (Req::GetSigned { xite: String::new(), inner_path: String::new() }, 1),
            (Req::ListSigned { xite: String::new(), since: 0 }, 2),
            (Req::GetRange { obj: ObjId([0; 32]), size: 0, ranges: vec![], deadline_ms: 0 }, 3),
            (Req::GetMany { objs: vec![] }, 4),
            (Req::GetBitfield { obj: ObjId([0; 32]) }, 5),
            (Req::HasXite { xite: String::new() }, 6),
            (Req::HaveRanges { obj: ObjId([0; 32]), runs: vec![] }, 7),
            (Req::Update {
                xite: String::new(), inner_path: String::new(),
                signed: vec![], inline: vec![],
            }, 8),
        ];
        for (req, disc) in reqs {
            let bytes =
                postcard::to_stdvec(&Frame { stream: 0, body: FrameBody::Req(req.clone()) })
                    .unwrap();
            assert_eq!(bytes[2], disc, "Req discriminant moved: {req:?}");
        }

        // Resp discriminants (encoded after FrameBody::Resp = 1 and its
        // `last` bool).
        let resps: Vec<(Resp, u8)> = vec![
            (
                Resp::HelloAck(HelloAck {
                    net: String::new(),
                    node_pk: vec![],
                    binding_sig: vec![],
                    caps: 0,
                    observed: None,
                }),
                0,
            ),
            (Resp::Signed { bytes: vec![] }, 1),
            (Resp::SignedList { entries: vec![] }, 2),
            (Resp::Bitfield { size: 0, runs: vec![] }, 3),
            (Resp::XiteSummary { signed_files: 0, newest_modified: 0, held_bytes: 0 }, 4),
            (Resp::Many { items: vec![] }, 5),
            (Resp::Ok, 6),
            (Resp::Err { code: 0, msg: String::new() }, 7),
        ];
        for (resp, disc) in resps {
            let bytes = postcard::to_stdvec(&Frame {
                stream: 0,
                body: FrameBody::Resp { last: true, resp: resp.clone() },
            })
            .unwrap();
            // Layout: varint(stream=0), FrameBody disc(Resp=1), last bool,
            // then the Resp discriminant.
            assert_eq!(bytes[3], disc, "Resp discriminant moved: {resp:?}");
        }
    }

    #[test]
    fn typical_control_frames_are_tiny() {
        let f = Frame {
            stream: 9,
            body: FrameBody::Req(Req::GetRange {
                obj: ObjId([1; 32]),
                size: 1 << 30,
                ranges: vec![(0, 1 << 20)],
                deadline_ms: 100,
            }),
        };
        let bytes = postcard::to_stdvec(&f).unwrap();
        assert!(bytes.len() < 64, "GetRange should be ~45 bytes, got {}", bytes.len());
    }
}
