//! Tracker announce in postcard form, for `EDX Req::Announce{payload}`.
//!
//! EDX carries the announce as opaque bytes so `epix-edx` never depends on
//! this crate. The payload shape is the tracker protocol's own business, and
//! it lives here: the same semantic fields as the msgpack announce in
//! [`crate::tracker`], only the outer envelope changes. Packed peer
//! addresses stay byte-identical (`PeerAddr::pack`), so a bucket copied from
//! a msgpack reply into a postcard one is the same bytes.
//!
//! COMPATIBILITY RULE: postcard encodes struct fields positionally. Fields
//! may only ever be APPENDED to these structs - never reordered, retyped, or
//! removed - or deployed nodes misparse the wire.

use crate::tracker::AnnounceParams;
use epix_core::{Error, IpType, PeerAddr, Result};
use serde::{Deserialize, Serialize};

/// An `announce` request. Mirrors the msgpack request field for field.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AnnounceReq {
    /// Xite tracker hashes (`sha256(address)`) to query.
    pub hashes: Vec<[u8; 32]>,
    /// Our onion self-addresses (b32 host, no `.onion`). One per hash, or a
    /// single value that applies to every hash.
    pub onions: Vec<String>,
    /// Our i2p self-addresses (b32 host, no `.i2p`), same pairing rule.
    pub i2p: Vec<String>,
    /// Our fileserver port (0 if not accepting inbound).
    pub port: u16,
    /// Address types we want back (`ipv4`/`ipv6`/`onion`/`i2p`).
    pub need_types: Vec<String>,
    /// Max peers per xite.
    pub need_num: u32,
    /// Types the tracker should record us under.
    pub add: Vec<String>,
    /// The challenge nonce echoed back from the first reply. Empty on the
    /// first announce.
    pub onion_sign_this: String,
    /// Answers the challenge: `(32-byte onion identity pubkey, 64-byte
    /// ed25519 signature over `onion_sign_this`)`. Empty on the first
    /// announce; without it a challenging tracker never registers our onions.
    pub onion_signs: Vec<(Vec<u8>, Vec<u8>)>,
    // --- append only (postcard fields are positional!) ---
}

/// The peers a tracker knows for one hash, bucketed by address type. Each
/// entry is one compact packed address (`PeerAddr::pack`): 6 bytes ipv4, 18
/// ipv6, b32-decoded onion host + 2, i2p destination hash + 2.
///
/// The msgpack reply also carries an `ip4` alias of `ipv4` for old EpixNet
/// clients. Nothing speaking postcard is old, so it is not repeated here.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PeerBuckets {
    pub ipv4: Vec<Vec<u8>>,
    pub ipv6: Vec<Vec<u8>>,
    pub onion: Vec<Vec<u8>>,
    pub i2p: Vec<Vec<u8>>,
    // --- append only (postcard fields are positional!) ---
}

impl PeerBuckets {
    /// Bucket and pack peers for a reply. Unpackable peers, and types the
    /// announce buckets don't carry (rns), are skipped.
    pub fn pack(peers: &[PeerAddr]) -> Self {
        let mut out = PeerBuckets::default();
        for p in peers {
            let Some(packed) = p.pack() else { continue };
            match p.ip_type() {
                IpType::Ipv4 => out.ipv4.push(packed),
                IpType::Ipv6 => out.ipv6.push(packed),
                IpType::Onion => out.onion.push(packed),
                IpType::I2p => out.i2p.push(packed),
                IpType::Rns => {}
            }
        }
        out
    }

    /// Unpack every bucket into peer addresses, dropping malformed entries.
    pub fn unpack(&self) -> Vec<PeerAddr> {
        let mut peers = Vec::new();
        for packed in self.ipv4.iter().chain(&self.ipv6) {
            peers.extend(PeerAddr::unpack_ip(packed));
        }
        for packed in &self.onion {
            peers.extend(PeerAddr::unpack_onion(packed));
        }
        for packed in &self.i2p {
            peers.extend(PeerAddr::unpack_i2p(packed));
        }
        peers
    }
}

/// An `announce` reply. Mirrors the msgpack reply field for field.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AnnounceResp {
    /// One bucket set per request hash, in request order.
    pub peers: Vec<PeerBuckets>,
    /// Ownership challenge: the tracker will only register the onions we
    /// advertised once we re-announce with a signature over this nonce.
    /// Empty when the tracker isn't challenging.
    pub onion_sign_this: String,
    /// Set instead of `peers` when the tracker refused (e.g. tracker
    /// disabled). Empty on success.
    pub error: String,
    // --- append only (postcard fields are positional!) ---
}

/// Encode a request for `Req::Announce{payload}`.
pub fn encode_request(req: &AnnounceReq) -> Result<Vec<u8>> {
    postcard::to_stdvec(req).map_err(|e| Error::Protocol(format!("announce encode: {e}")))
}

/// Decode a request from `Req::Announce{payload}` (server side).
pub fn decode_request(bytes: &[u8]) -> Result<AnnounceReq> {
    postcard::from_bytes(bytes).map_err(|e| Error::Protocol(format!("announce decode: {e}")))
}

/// Encode a reply for `Resp::Payload{bytes}` (server side).
pub fn encode_reply(resp: &AnnounceResp) -> Result<Vec<u8>> {
    postcard::to_stdvec(resp).map_err(|e| Error::Protocol(format!("announce reply encode: {e}")))
}

/// Decode a reply from `Resp::Payload{bytes}`.
pub fn decode_reply(bytes: &[u8]) -> Result<AnnounceResp> {
    postcard::from_bytes(bytes).map_err(|e| Error::Protocol(format!("announce reply decode: {e}")))
}

/// Build the first announce from the same params the msgpack path takes.
pub fn build_request(params: &AnnounceParams<'_>) -> AnnounceReq {
    AnnounceReq {
        hashes: params.hashes.to_vec(),
        onions: params.onions.to_vec(),
        i2p: params.i2p.to_vec(),
        port: params.port,
        need_types: params.need_types.iter().map(|t| t.to_string()).collect(),
        need_num: params.need_num.clamp(0, u32::MAX as i64) as u32,
        add: params.add.iter().map(|t| t.to_string()).collect(),
        onion_sign_this: String::new(),
        onion_signs: Vec::new(),
    }
}

/// Build the second announce that answers the tracker's ownership challenge,
/// or None when there is nothing to prove (no challenge, no signer, or no
/// onions advertised). The peers already came back on the first reply, so
/// this call asks for none.
pub fn build_signed_request(params: &AnnounceParams<'_>, challenge: &str) -> Option<AnnounceReq> {
    let signer = params.onion_signer?;
    if challenge.is_empty() || params.onions.is_empty() {
        return None;
    }
    let sig = signer.sign(challenge.as_bytes());
    let mut req = build_request(params);
    req.need_num = 0;
    req.onion_sign_this = challenge.to_string();
    req.onion_signs = vec![(signer.public_key().to_vec(), sig.to_vec())];
    Some(req)
}

/// A decoded reply, ready for the two-call flow: take `peers`, and if
/// `onion_sign_this` is set feed it to [`build_signed_request`] and announce
/// once more so the tracker registers our onions.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AnnounceReply {
    pub peers: Vec<PeerAddr>,
    /// The ownership challenge to answer, if the tracker issued one.
    pub onion_sign_this: Option<String>,
}

/// Parse reply bytes from `Resp::Payload{bytes}` into peers plus the
/// challenge. A tracker-side `error` fails the call rather than silently
/// reporting zero peers.
pub fn parse_reply(bytes: &[u8]) -> Result<AnnounceReply> {
    let resp = decode_reply(bytes)?;
    if !resp.error.is_empty() {
        return Err(Error::Protocol(format!("announce: {}", resp.error)));
    }
    let mut peers = Vec::new();
    for bucket in &resp.peers {
        peers.extend(bucket.unpack());
    }
    let onion_sign_this = (!resp.onion_sign_this.is_empty()).then_some(resp.onion_sign_this);
    Ok(AnnounceReply { peers, onion_sign_this })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker::OnionSigner;

    struct FakeSigner;
    impl OnionSigner for FakeSigner {
        fn public_key(&self) -> [u8; 32] {
            [7; 32]
        }
        fn sign(&self, msg: &[u8]) -> [u8; 64] {
            let mut sig = [0u8; 64];
            sig[..msg.len().min(64)].copy_from_slice(&msg[..msg.len().min(64)]);
            sig
        }
    }

    #[test]
    fn request_round_trips() {
        let req = AnnounceReq {
            hashes: vec![[1; 32], [2; 32], [3; 32]],
            onions: vec!["aaaabbbbccccdddd".into(), "eeeeffffgggghhhh".into()],
            i2p: vec!["iiiijjjjkkkkllll.b32".into()],
            port: 26552,
            need_types: vec!["ipv4".into(), "ipv6".into(), "onion".into(), "i2p".into()],
            need_num: 20,
            add: vec!["ipv4".into(), "onion".into()],
            onion_sign_this: "nonce-1234".into(),
            onion_signs: vec![([9u8; 32].to_vec(), [8u8; 64].to_vec())],
        };
        let bytes = encode_request(&req).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), req);
    }

    #[test]
    fn reply_round_trips_with_identical_packed_bytes() {
        let resp = AnnounceResp {
            peers: vec![
                PeerBuckets {
                    ipv4: vec![vec![127, 0, 0, 1, 0x67, 0x2B], vec![8, 8, 8, 8, 0, 1]],
                    ipv6: vec![vec![0xFE; 18]],
                    onion: vec![vec![0xAB; 37]],
                    i2p: vec![vec![0xCD; 34]],
                },
                PeerBuckets { ipv4: vec![vec![1, 2, 3, 4, 5, 6]], ..Default::default() },
                PeerBuckets::default(),
            ],
            onion_sign_this: "nonce-1234".into(),
            error: String::new(),
        };
        let bytes = encode_reply(&resp).unwrap();
        let back = decode_reply(&bytes).unwrap();
        assert_eq!(back, resp);
        // The packed addresses are the payload's whole point: byte-identical.
        assert_eq!(back.peers[0].ipv4[0], vec![127, 0, 0, 1, 0x67, 0x2B]);
        assert_eq!(back.peers[0].onion[0], vec![0xAB; 37]);
        assert_eq!(back.peers[1].ipv4[0], vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn packs_and_unpacks_every_bucket_type() {
        let peers = vec![
            PeerAddr::parse("127.0.0.1:11111").unwrap(),
            PeerAddr::parse("[::1]:15441").unwrap(),
            PeerAddr::Onion { host: "aaaaaaaaaaaaaaaa".into(), port: 15441 },
            PeerAddr::I2p {
                // 52 base32 chars = the 32-byte destination hash.
                dest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32".into(),
                port: 0,
            },
        ];
        let buckets = PeerBuckets::pack(&peers);
        assert_eq!(buckets.ipv4.len(), 1);
        assert_eq!(buckets.ipv6.len(), 1);
        assert_eq!(buckets.onion.len(), 1);
        assert_eq!(buckets.i2p.len(), 1);
        let resp = AnnounceResp { peers: vec![buckets], ..Default::default() };
        let parsed = parse_reply(&encode_reply(&resp).unwrap()).unwrap();
        assert_eq!(parsed.peers.len(), 4);
        assert!(parsed.peers.contains(&peers[0]));
        assert!(parsed.peers.contains(&peers[2]));
        assert!(parsed.onion_sign_this.is_none());
    }

    #[test]
    fn challenge_flow_builds_a_second_request() {
        let signer = FakeSigner;
        let hashes = [[5u8; 32]];
        let onions = ["aaaabbbbccccdddd".to_string()];
        let params = AnnounceParams {
            hashes: &hashes,
            port: 26552,
            need_types: &["ipv4", "onion"],
            need_num: 20,
            add: &["onion"],
            onions: &onions,
            i2p: &[],
            onion_signer: Some(&signer),
        };

        let first = build_request(&params);
        assert_eq!(first.need_num, 20);
        assert!(first.onion_signs.is_empty());
        assert_eq!(first.hashes, hashes.to_vec());

        // First reply hands back peers plus the challenge.
        let resp = AnnounceResp {
            peers: vec![PeerBuckets {
                ipv4: vec![vec![1, 2, 3, 4, 0x67, 0x2B]],
                ..Default::default()
            }],
            onion_sign_this: "prove-it".into(),
            error: String::new(),
        };
        let parsed = parse_reply(&encode_reply(&resp).unwrap()).unwrap();
        assert_eq!(parsed.peers.len(), 1);
        let challenge = parsed.onion_sign_this.unwrap();

        // Second announce proves onion ownership and asks for no more peers.
        let signed = build_signed_request(&params, &challenge).unwrap();
        assert_eq!(signed.need_num, 0);
        assert_eq!(signed.onion_sign_this, "prove-it");
        assert_eq!(signed.onion_signs[0].0, [7u8; 32].to_vec());
        assert_eq!(signed.onion_signs[0].1.len(), 64);
        assert_eq!(&signed.onion_signs[0].1[..8], b"prove-it");
        let bytes = encode_request(&signed).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), signed);
    }

    #[test]
    fn no_second_request_without_a_challenge_or_onions() {
        let signer = FakeSigner;
        let hashes = [[5u8; 32]];
        let onions = ["aaaabbbbccccdddd".to_string()];
        let mut params = AnnounceParams {
            hashes: &hashes,
            port: 0,
            need_types: &["ipv4"],
            need_num: 20,
            add: &[],
            onions: &onions,
            i2p: &[],
            onion_signer: Some(&signer),
        };
        assert!(build_signed_request(&params, "").is_none());
        params.onions = &[];
        assert!(build_signed_request(&params, "prove-it").is_none());
        params.onions = &onions;
        params.onion_signer = None;
        assert!(build_signed_request(&params, "prove-it").is_none());
    }

    #[test]
    fn tracker_error_surfaces() {
        let resp = AnnounceResp { error: "Tracker disabled".into(), ..Default::default() };
        let err = parse_reply(&encode_reply(&resp).unwrap()).unwrap_err();
        assert!(err.to_string().contains("Tracker disabled"));
    }

    /// Postcard encodes struct fields POSITIONALLY, so reordering or
    /// inserting a field silently misdecodes against deployed trackers
    /// instead of failing to compile. These golden vectors pin the layout
    /// (the struct-shaped analog of `epix_edx::msg::wire_indices_frozen`).
    /// If one of these fails, you changed the wire: append instead.
    #[test]
    fn wire_layout_frozen() {
        let req = AnnounceReq {
            hashes: vec![[1u8; 32]],
            onions: vec!["abc".into()],
            i2p: vec!["def".into()],
            port: 26552,
            need_types: vec!["ipv4".into()],
            need_num: 20,
            add: vec!["onion".into()],
            onion_sign_this: "chal".into(),
            onion_signs: vec![(vec![2u8; 4], vec![3u8; 4])],
        };
        let hex: String =
            encode_request(&req).unwrap().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0101010101010101010101010101010101010101010101010101010101010101\
             0101036162630103646566b8cf010104697076341401056f6e696f6e046368616c\
             0104020202020403030303"
                .replace(['\n', ' '], ""),
            "AnnounceReq field layout changed"
        );

        let resp = AnnounceResp {
            peers: vec![PeerBuckets {
                ipv4: vec![vec![9, 9]],
                ipv6: vec![],
                onion: vec![],
                i2p: vec![],
            }],
            onion_sign_this: "c".into(),
            error: String::new(),
        };
        let hex: String =
            encode_reply(&resp).unwrap().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "0101020909000000016300", "AnnounceResp field layout changed");
    }
}
