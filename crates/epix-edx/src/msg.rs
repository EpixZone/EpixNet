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
//! `GetMany`, whose sub-64 KiB whole blobs (`server::MAX_MANY_ITEM_BYTES`)
//! are verified by whole-blob hash on arrival.

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
    /// Serves the full CONTROL plane (`UpdatesSince`, `Pex`,
    /// `GetTrackers`, `Kad`, `Announce`). A content-only node (an
    /// embedded fetcher, a test fixture) leaves this clear and answers
    /// those requests UNSUPPORTED.
    pub const CONTROL: u32 = 1 << 2;
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
    /// Addresses this node can be dialed back on: an inbound connection
    /// arrives from an ephemeral port, so without this the receiver could
    /// never dial the caller back.
    pub listen: Vec<PeerAddr>,
    /// The node's release version (e.g. `0.3.9`) - it feeds the Stats
    /// page's `client` column. Empty when the node advertises no version.
    /// APPENDED: postcard encodes struct fields positionally, so new
    /// fields go at the END of `Hello`/`HelloAck`, never in the middle.
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HelloAck {
    pub net: String,
    pub node_pk: Vec<u8>,
    pub binding_sig: Vec<u8>,
    pub caps: u32,
    /// The dialer's address as this node observed it (dial-back info).
    pub observed: Option<PeerAddr>,
    /// This node's release version (see [`Hello::version`]). Appended.
    pub version: String,
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
    /// Signed files changed since `since`
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
    /// Push publish: a signed content.json plus everything a receiver needs
    /// to apply it without a second round trip - optional inline small
    /// objects (a forum post rides in one push), the version `modified` (so
    /// a receiver can short-circuit a stale push), the per-file line diffs
    /// (`inner_path -> encoded actions`) so data files patch in place instead
    /// of refetching, and the publisher's dial-back addresses so a NATed
    /// publisher can still be pulled from. Answered Ok (accepted, whether
    /// newly applied or already-known) or Err.
    Update {
        xite: String,
        inner_path: String,
        signed: Vec<u8>,
        inline: Vec<(ObjId, Vec<u8>)>,
        modified: f64,
        /// `inner_path -> encoded action list` (the runtime lowers
        /// `epix_content` diff actions to bytes; epix-edx stays neutral).
        diffs: Vec<(String, Vec<u8>)>,
        /// The publisher's self-declared dialable addresses.
        sender_peers: Vec<String>,
    },
    // --- Stage 4+ appends only below this line (postcard indices!) ---
    //
    // CONTROL PLANE (gated by `caps::CONTROL`). Domain payloads that belong to another crate's protocol ride as
    // opaque bytes (same neutrality rule as `Update::diffs`) — epix-edx
    // must not depend on epix-dht / epix-discovery.
    /// Store-and-forward propagation hints recorded after the caller's
    /// cursor. Answered `Resp::Updates`.
    UpdatesSince { after: u64 },
    /// Peer exchange for one xite. `peers` are addresses
    /// the caller already knows (so the answer excludes them); `need` caps
    /// how many to return. Answered `Resp::Peers`.
    Pex { xite: String, need: u32, peers: Vec<PeerAddr> },
    /// The peer's working tracker set (Beacon gossip). Answered
    /// `Resp::Trackers`.
    GetTrackers,
    /// One Kademlia RPC, encoded by `epix-dht-net`.
    /// Answered `Resp::Payload`.
    Kad { payload: Vec<u8> },
    /// `announce` successor: a tracker announce/answer, encoded by
    /// `epix-discovery` (the tracker payload shape is its own protocol).
    /// Answered `Resp::Payload`.
    Announce { payload: Vec<u8> },
    // --- ENCRYPTED-SHARD VOLUNTEER role appends only below this line ---
    /// Bulk availability probe: which of these shard/object addrs the peer
    /// holds COMPLETE. Answered `Resp::ShardMask`. A fetcher of a private
    /// file uses it to pick which volunteer to pull each shard from in one
    /// round trip instead of one `GetBitfield` per shard.
    HasShards { addrs: Vec<ObjId> },
    // DEFERRED (follow-up, not built here): the PUSH accept path.
    //   PushBlock { xite: String, inner_path: String, signed: Vec<u8>,
    //               cipher_addr: ObjId, bytes: Vec<u8> } -> Resp::Ok/Err
    // PULL (the volunteer driver) needs no accept-guard because it only
    // stores an addr it found inside a signature it verified itself. PUSH
    // lets a remote peer choose what lands on our disk, so it needs a real
    // anti-grinding guard before it can exist:
    //   verify(signed) && edx_shard_entry(content).chunks.any(ca==cipher_addr)
    //     && responsible(cipher_addr) && under_quota && rate_ok(source)
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
    //
    // CONTROL PLANE replies (see the matching `Req` variants).
    /// Propagation hints after the caller's cursor, plus the new cursor.
    Updates { updates: Vec<(String, i64)>, head: u64 },
    /// Connectable peers the caller lacked, plus our own reachable
    /// overlay self-addresses.
    Peers { peers: Vec<PeerAddr> },
    /// Working tracker set (`epix://host:port` strings).
    Trackers { trackers: Vec<String> },
    /// Opaque reply for `Kad`/`Announce`, decoded by the owning crate.
    Payload { bytes: Vec<u8> },
    // --- ENCRYPTED-SHARD VOLUNTEER role appends only below this line ---
    /// Bitmask (LSB-first, byte i bit j => `addrs[i*8+j]`) of which
    /// requested addrs the responder holds COMPLETE. Length =
    /// ceil(addrs.len()/8). Packed to one bit per shard so a large private
    /// file's probe stays small.
    ShardMask { bits: Vec<u8> },
}

/// Error codes for `Resp::Err`.
pub mod err {
    pub const NOT_FOUND: u16 = 404;
    pub const BUSY: u16 = 429;
    pub const BAD_REQUEST: u16 = 400;
    pub const LIMIT: u16 = 413;
    pub const INTERNAL: u16 = 500;
    /// Control-plane request on a node without a control provider.
    pub const UNSUPPORTED: u16 = 501;
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
                stream: 0,
                body: FrameBody::Req(Req::Hello(Hello {
                    net: NET_ID.into(),
                    node_pk: vec![2; 33],
                    binding_sig: vec![9; 64],
                    caps: caps::MESH | caps::CONTROL,
                    listen: vec![PeerAddr::parse("1.2.3.4:26552").unwrap()],
                    version: "0.3.9".into(),
                })),
            },
            Frame {
                stream: 0,
                body: FrameBody::Resp {
                    last: true,
                    resp: Resp::HelloAck(HelloAck {
                        net: NET_ID.into(),
                        node_pk: vec![3; 33],
                        binding_sig: vec![],
                        caps: caps::MESH,
                        observed: Some(PeerAddr::parse("5.6.7.8:26552").unwrap()),
                        version: "0.3.9".into(),
                    }),
                },
            },
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
            Frame {
                stream: 4,
                body: FrameBody::Req(Req::Update {
                    xite: "1Abc".into(),
                    inner_path: "data/users/alice/content.json".into(),
                    signed: vec![1, 2, 3, 4],
                    inline: vec![(ObjId([9; 32]), vec![5, 6, 7])],
                    modified: 1_700_000_123.5,
                    diffs: vec![("data/users/alice/data.json".into(), vec![b'[', b']'])],
                    sender_peers: vec!["abc.onion:15441".into(), "1.2.3.4:15441".into()],
                }),
            },
            // Control plane.
            Frame { stream: 5, body: FrameBody::Req(Req::UpdatesSince { after: 42 }) },
            Frame {
                stream: 6,
                body: FrameBody::Req(Req::Pex {
                    xite: "1Abc".into(),
                    need: 10,
                    peers: vec![PeerAddr::parse("1.2.3.4:26552").unwrap()],
                }),
            },
            Frame { stream: 7, body: FrameBody::Req(Req::GetTrackers) },
            Frame { stream: 8, body: FrameBody::Req(Req::Kad { payload: vec![1, 2, 3] }) },
            Frame { stream: 9, body: FrameBody::Req(Req::Announce { payload: vec![4, 5] }) },
            Frame {
                stream: 10,
                body: FrameBody::Resp {
                    last: true,
                    resp: Resp::Updates { updates: vec![("1Abc".into(), 1_700_000_000)], head: 7 },
                },
            },
            Frame {
                stream: 11,
                body: FrameBody::Resp {
                    last: true,
                    resp: Resp::Peers {
                        peers: vec![PeerAddr::parse("5.6.7.8:26552").unwrap()],
                    },
                },
            },
            Frame {
                stream: 12,
                body: FrameBody::Resp {
                    last: true,
                    resp: Resp::Trackers { trackers: vec!["epix://t.example:6969".into()] },
                },
            },
            Frame {
                stream: 13,
                body: FrameBody::Resp { last: true, resp: Resp::Payload { bytes: vec![9] } },
            },
            // Encrypted-shard volunteer role.
            Frame {
                stream: 14,
                body: FrameBody::Req(Req::HasShards {
                    addrs: vec![ObjId([1; 32]), ObjId([2; 32]), ObjId([3; 32])],
                }),
            },
            Frame {
                stream: 14,
                body: FrameBody::Resp { last: true, resp: Resp::ShardMask { bits: vec![0b0000_0101] } },
            },
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
                caps: 0, listen: vec![], version: String::new() })) }, 0),
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
                modified: 0.0, diffs: vec![], sender_peers: vec![],
            }, 8),
            // Control plane.
            (Req::UpdatesSince { after: 0 }, 9),
            (Req::Pex { xite: String::new(), need: 0, peers: vec![] }, 10),
            (Req::GetTrackers, 11),
            (Req::Kad { payload: vec![] }, 12),
            (Req::Announce { payload: vec![] }, 13),
            // Encrypted-shard volunteer role.
            (Req::HasShards { addrs: vec![] }, 14),
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
                    version: String::new(),
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
            // Control plane.
            (Resp::Updates { updates: vec![], head: 0 }, 8),
            (Resp::Peers { peers: vec![] }, 9),
            (Resp::Trackers { trackers: vec![] }, 10),
            (Resp::Payload { bytes: vec![] }, 11),
            // Encrypted-shard volunteer role.
            (Resp::ShardMask { bits: vec![] }, 12),
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

        // Struct fields are positional too: `version` was APPENDED to the
        // handshake structs, so it must encode LAST (len-prefixed string at
        // the tail) - moving it would shift every field a peer parses.
        let hello = Hello {
            net: String::new(),
            node_pk: vec![],
            binding_sig: vec![],
            caps: 0,
            listen: vec![],
            version: "1.2.3".into(),
        };
        assert!(
            postcard::to_stdvec(&hello).unwrap().ends_with(b"\x051.2.3"),
            "Hello::version must stay the last field"
        );
        let ack = HelloAck {
            net: String::new(),
            node_pk: vec![],
            binding_sig: vec![],
            caps: 0,
            observed: None,
            version: "1.2.3".into(),
        };
        assert!(
            postcard::to_stdvec(&ack).unwrap().ends_with(b"\x051.2.3"),
            "HelloAck::version must stay the last field"
        );
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
