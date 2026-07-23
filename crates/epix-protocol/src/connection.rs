//! A client connection to a peer: handshake + the FileRequest command set.

use crate::msg::{read_msg, send_msg, vget, vmap};
use epix_core::{Error, PeerAddr, Result};
use epix_transport::{PeerStream, Transport};
use rmpv::Value;
use std::collections::HashMap;

/// The handshake info exchanged with a peer.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub version: String,
    pub rev: i64,
    pub protocol: String,
    pub peer_id: String,
    pub fileserver_port: u16,
    pub crypt_supported: Vec<String>,
}

/// A `pex` reply's peers, packed by bucket. Unpack with `PeerAddr::unpack_ip`
/// (ipv4/ipv6), `PeerAddr::unpack_onion` (onion), `PeerAddr::unpack_i2p`
/// (i2p), `PeerAddr::unpack_rns` (rns).
#[derive(Debug, Clone, Default)]
pub struct PexReply {
    pub ipv4: Vec<Vec<u8>>,
    pub ipv6: Vec<Vec<u8>>,
    pub onion: Vec<Vec<u8>>,
    pub i2p: Vec<Vec<u8>>,
    pub rns: Vec<Vec<u8>>,
}

/// A `findHashIds` reply: which peers hold each optional-file hash id (packed
/// addresses, bucketed by type) and which hash ids the answering peer itself
/// holds (`my`).
#[derive(Debug, Clone, Default)]
pub struct FindHashIdsReply {
    pub ipv4: HashMap<u16, Vec<Vec<u8>>>,
    pub ipv6: HashMap<u16, Vec<Vec<u8>>>,
    pub onion: HashMap<u16, Vec<Vec<u8>>>,
    pub my: Vec<u16>,
}

pub(crate) fn parse_handshake(v: &Value) -> HandshakeInfo {
    let s = |k: &str| vget(v, k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let i = |k: &str| vget(v, k).and_then(|x| x.as_i64()).unwrap_or(0);
    HandshakeInfo {
        version: s("version"),
        rev: i("rev"),
        protocol: s("protocol"),
        peer_id: s("peer_id"),
        fileserver_port: i("fileserver_port") as u16,
        crypt_supported: vget(v, "crypt_supported")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    }
}

fn random_peer_id() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::fill(&mut b);
    format!("-EpixRS-{}", hex::encode(b))
}

/// Build the handshake request params: the base fields every peer expects,
/// plus the dial-back self-advertisement matching the connection's transport
/// class. The overlay key names mirror the address kinds (`onion` is the
/// Python client's own handshake key; `i2p`/`rns` are EpixNet extensions old
/// nodes ignore - both sides look keys up by name, so extras are wire-safe).
///
/// The advertised `fileserver_port` doubles as the overlay dial-back port (the
/// onion service maps it 1:1), so it is sent whenever we advertise anything -
/// but `port_opened` stays strictly clearnet-truthful: only true when a public
/// inbound peer confirmed the port, and never in Always mode (clearnet is
/// closed there, whatever the OS listener does).
fn handshake_params(advert: &crate::advert::SelfAdvert, target: &PeerAddr) -> Value {
    // The real release version (from EPIX_VERSION / the git tag) rides in via
    // the advert; epix-protocol's own crate version is only the fallback for
    // an unseeded advert (tests, wire-spike).
    let version = if advert.version.is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        advert.version.clone()
    };
    let mut params = vec![
        ("version", Value::from(version)),
        ("rev", Value::from(8192i64)),
        ("peer_id", Value::from(random_peer_id())),
        ("protocol", Value::from("v2")),
        ("use_bin_type", Value::from(true)),
        ("fileserver_port", Value::from(advert.fileserver_port as i64)),
        ("crypt_supported", Value::Array(vec![])),
        ("port_opened", Value::from(advert.port_opened && !advert.tor_always)),
    ];
    if let Some((key, host)) = self_address_claim(advert, target) {
        params.push((key, Value::from(host)));
    }
    vmap(params)
}

/// The single dial-back self-address to advertise on a connection to `target`,
/// as `(handshake key, host)`, or `None` when we have nothing to offer (not
/// seeding, or the address for that transport isn't up).
///
/// One self-address per connection, matching its transport class: our onion on
/// Tor-bound wires, i2p on i2p, rns on mesh. A DIRECT clearnet dial advertises
/// no overlay address (the peer sees our real IP; claiming the onion there
/// would link the two) - unless Always mode routes the dial through Tor, where
/// the visible source is an exit node and the onion is our only dialable
/// identity.
fn self_address_claim(
    advert: &crate::advert::SelfAdvert,
    target: &PeerAddr,
) -> Option<(&'static str, String)> {
    if advert.fileserver_port == 0 {
        return None;
    }
    match target {
        PeerAddr::Onion { .. } => advert.onion.clone().map(|h| ("onion", h)),
        PeerAddr::I2p { .. } => advert.i2p.clone().map(|d| ("i2p", d)),
        PeerAddr::Rns(_) => advert.rns.clone().map(|r| ("rns", r)),
        PeerAddr::Ip(_) if advert.tor_always => advert.onion.clone().map(|h| ("onion", h)),
        PeerAddr::Ip(_) => None,
    }
}

/// A live connection to one peer. Request/response is matched by `req_id`.
pub struct Connection {
    stream: PeerStream,
    buf: Vec<u8>,
    next_req_id: i64,
    /// The address this connection was dialed to - picks which of our own
    /// self-addresses the handshake advertises (see [`crate::advert`]).
    addr: PeerAddr,
    pub peer: Option<HandshakeInfo>,
    /// Stats-page registration; deregisters when the connection drops.
    reg: crate::registry::ConnHandle,
}

impl Connection {
    /// Dial `addr` over `transport` and wrap the resulting stream.
    pub async fn connect(transport: &dyn Transport, addr: &PeerAddr) -> Result<Self> {
        let stream = transport.dial(addr).await?;
        let reg = crate::registry::ConnHandle::new(crate::registry::Direction::Out, addr.clone());
        reg.activate();
        let stream = reg.count_stream(stream);
        Ok(Self { stream, buf: Vec::new(), next_req_id: 0, addr: addr.clone(), peer: None, reg })
    }

    fn next_id(&mut self) -> i64 {
        let id = self.next_req_id;
        self.next_req_id += 1;
        id
    }

    /// Send `{cmd, req_id, params}` and return the matching `response` map.
    /// Inbound requests and unrelated responses are skipped.
    pub async fn request(&mut self, cmd: &str, params: Value) -> Result<Value> {
        let xite = vget(&params, "site").and_then(|v| v.as_str()).map(str::to_string);
        self.reg.note_cmd_sent(cmd, xite.as_deref());
        let req_id = self.next_id();
        let msg = vmap(vec![
            ("cmd", Value::from(cmd)),
            ("req_id", Value::from(req_id)),
            ("params", params),
        ]);
        send_msg(&mut self.stream, &msg).await?;

        loop {
            let resp = read_msg(&mut self.stream, &mut self.buf).await?;
            let is_response = vget(&resp, "cmd").and_then(|v| v.as_str()) == Some("response");
            let to = vget(&resp, "to").and_then(|v| v.as_i64());
            if is_response && to == Some(req_id) {
                if let Some(err) = vget(&resp, "error") {
                    return Err(Error::Protocol(format!("peer error on `{cmd}`: {err}")));
                }
                return Ok(resp);
            }
            // Not ours - keep reading (a well-behaved peer answers our req_id).
        }
    }

    /// Perform the protocol handshake (plaintext, no crypt negotiation yet).
    /// Advertises the self-address matching this connection's transport class
    /// (see [`crate::advert`]) so the peer can dial us back.
    pub async fn handshake(&mut self) -> Result<HandshakeInfo> {
        let params = crate::advert::with_self_advert(|a| handshake_params(a, &self.addr));
        let resp = self.request("handshake", params).await?;
        let hs = parse_handshake(&resp);
        self.peer = Some(hs.clone());
        self.reg.set_peer(hs.clone());
        Ok(hs)
    }

    /// `ping` → `true` if the peer answers `Pong!`. Peers send the body as a
    /// msgpack string or (more commonly) binary, so accept either.
    pub async fn ping(&mut self) -> Result<bool> {
        let start = std::time::Instant::now();
        let resp = self.request("ping", Value::Map(vec![])).await?;
        let body = vget(&resp, "body");
        let is_pong = body.and_then(|v| v.as_str()) == Some("Pong!")
            || body.and_then(|v| v.as_slice()) == Some(b"Pong!".as_slice());
        if is_pong {
            self.reg.set_ping_ms(start.elapsed().as_millis() as i64);
        }
        Ok(is_pong)
    }

    /// Download exactly `size` bytes starting at `offset` (`getFile` with
    /// `read_bytes`), for pulling a single big-file piece. Returns fewer bytes
    /// only if the file ends early.
    pub async fn get_file_range(
        &mut self,
        xite: &str,
        inner_path: &str,
        offset: u64,
        size: u64,
    ) -> Result<Vec<u8>> {
        const CHUNK: u64 = 1024 * 512; // FILE_BUFF: the peer caps a response here
        let mut out = Vec::new();
        let mut location = offset;
        let end = offset + size;
        while (out.len() as u64) < size {
            let read_bytes = (end - location).min(CHUNK);
            let params = vmap(vec![
                ("site", Value::from(xite)),
                ("inner_path", Value::from(inner_path)),
                ("location", Value::from(location as i64)),
                ("read_bytes", Value::from(read_bytes as i64)),
            ]);
            let resp = self.request("getFile", params).await?;
            let body = vget(&resp, "body")
                .ok_or_else(|| Error::Protocol("getFile response has no body".into()))?;
            let chunk: &[u8] = match body {
                Value::Binary(b) => b.as_slice(),
                Value::String(s) => s.as_bytes(),
                other => return Err(Error::Protocol(format!("getFile body has type {other:?}"))),
            };
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(chunk);
            location += chunk.len() as u64;
            if (chunk.len() as u64) < read_bytes {
                break; // short read → end of file
            }
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// Publish an updated `content.json` to the peer (`update` FileRequest). The
    /// peer verifies `body`'s signature before accepting, so a bad update is
    /// rejected on their side. `body` is the raw content.json bytes.
    pub async fn update(
        &mut self,
        xite: &str,
        inner_path: &str,
        body: &[u8],
        modified: f64,
        diffs: Option<Value>,
        sender_peers: &[String],
    ) -> Result<Value> {
        let mut fields = vec![
            ("site", Value::from(xite)),
            ("inner_path", Value::from(inner_path)),
            ("body", Value::Binary(body.to_vec())),
            // The version being pushed; receivers skip validation when they
            // already have this or newer (EpixNet peers send it too).
            ("modified", Value::from(modified)),
        ];
        // Per-file line diffs (`file -> [["=",n]|["-",n]|["+",[lines]]]`) so
        // receivers patch their copies of changed data files instead of
        // fetching them back - which they often can't (publisher behind NAT).
        if let Some(diffs) = diffs {
            fields.push(("diffs", diffs));
        }
        // Addresses WE can be dialed at (onion/i2p/open clearnet), so the
        // receiver can fetch the pushed version's files straight from us:
        // the socket address it sees is useless for that when we sit behind
        // NAT, and no other peer has the new files yet.
        if !sender_peers.is_empty() {
            fields.push((
                "sender_peers",
                Value::Array(sender_peers.iter().map(|s| Value::from(s.as_str())).collect()),
            ));
        }
        self.request("update", vmap(fields)).await
    }

    /// Ask the peer for its working announcer list (`getTrackers`, the
    /// AnnounceShare exchange): responds `{"trackers": ["epix://host:port"…]}`.
    pub async fn get_trackers(&mut self) -> Result<Value> {
        self.request("getTrackers", vmap(vec![])).await
    }

    /// Exchange peers (`pex`): send some of our connectable peers (packed by
    /// type) and `need`, get back the peer's peers we don't have. Returns the
    /// packed peer byte-lists by bucket (`ipv4`, `ipv6`, `onion`); the caller
    /// unpacks with `PeerAddr::unpack_*` (kept out of the protocol layer).
    pub async fn pex(
        &mut self,
        xite: &str,
        peers: Vec<Vec<u8>>,
        peers_ipv6: Vec<Vec<u8>>,
        peers_onion: Vec<Vec<u8>>,
        peers_i2p: Vec<Vec<u8>>,
        peers_rns: Vec<Vec<u8>>,
        need: i64,
    ) -> Result<PexReply> {
        let pack = |list: Vec<Vec<u8>>| Value::Array(list.into_iter().map(Value::Binary).collect());
        let mut params = vec![
            ("site", Value::from(xite)),
            ("need", Value::from(need)),
            ("peers", pack(peers)),
        ];
        if !peers_ipv6.is_empty() {
            params.push(("peers_ipv6", pack(peers_ipv6)));
        }
        if !peers_onion.is_empty() {
            params.push(("peers_onion", pack(peers_onion)));
        }
        if !peers_i2p.is_empty() {
            params.push(("peers_i2p", pack(peers_i2p)));
        }
        if !peers_rns.is_empty() {
            params.push(("peers_rns", pack(peers_rns)));
        }
        let resp = self.request("pex", vmap(params)).await?;
        let extract = |field: &str| -> Vec<Vec<u8>> {
            match vget(&resp, field) {
                Some(Value::Array(list)) => list
                    .iter()
                    .filter_map(|v| match v {
                        Value::Binary(b) => Some(b.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            }
        };
        Ok(PexReply {
            ipv4: extract("peers"),
            ipv6: extract("peers_ipv6"),
            onion: extract("peers_onion"),
            i2p: extract("peers_i2p"),
            rns: extract("peers_rns"),
        })
    }

    /// Ask which content.json files the peer changed after `since` (ms).
    /// Returns `{inner_path: modified}`.
    pub async fn list_modified(&mut self, xite: &str, since: f64) -> Result<Value> {
        let params = vmap(vec![("site", Value::from(xite)), ("since", Value::from(since))]);
        self.request("listModified", params).await
    }

    /// Ask which optional files the peer holds (`getHashfield`); returns the
    /// packed hash-id bytes (unpack with `epix_xite::Hashfield::from_bytes`).
    pub async fn get_hashfield(&mut self, xite: &str) -> Result<Vec<u8>> {
        let params = vmap(vec![("site", Value::from(xite))]);
        let resp = self.request("getHashfield", params).await?;
        match vget(&resp, "hashfield_raw") {
            Some(Value::Binary(b)) => Ok(b.clone()),
            _ => Err(Error::Protocol("getHashfield response has no hashfield_raw".into())),
        }
    }

    /// Tell the peer which optional files we hold (`setHashfield`).
    pub async fn set_hashfield(&mut self, xite: &str, hashfield_raw: Vec<u8>) -> Result<Value> {
        let params = vmap(vec![
            ("site", Value::from(xite)),
            ("hashfield_raw", Value::Binary(hashfield_raw)),
        ]);
        self.request("setHashfield", params).await
    }

    /// Ask the peer which peers it knows hold each optional-file hash id
    /// (`findHashIds`). Returns `(hash_id -> packed peer addrs)` buckets for
    /// ipv4/ipv6/onion plus the hash ids the peer itself holds - the same
    /// shape EpixNet's `actionFindHashIds` answers. Unpack the packed
    /// addresses with `epix_core::PeerAddr::unpack_ip`/`unpack_onion`.
    pub async fn find_hash_ids(&mut self, xite: &str, hash_ids: &[u16]) -> Result<FindHashIdsReply> {
        let params = vmap(vec![
            ("site", Value::from(xite)),
            (
                "hash_ids",
                Value::Array(hash_ids.iter().map(|id| Value::from(*id as i64)).collect()),
            ),
        ]);
        let resp = self.request("findHashIds", params).await?;
        let bucket = |key: &str| -> HashMap<u16, Vec<Vec<u8>>> {
            let mut out = HashMap::new();
            if let Some(Value::Map(entries)) = vget(&resp, key) {
                for (k, v) in entries {
                    let (Some(id), Value::Array(addrs)) = (k.as_i64(), v) else { continue };
                    if !(0..=u16::MAX as i64).contains(&id) {
                        continue;
                    }
                    let packed: Vec<Vec<u8>> = addrs
                        .iter()
                        .filter_map(|a| match a {
                            Value::Binary(b) => Some(b.clone()),
                            _ => None,
                        })
                        .collect();
                    out.insert(id as u16, packed);
                }
            }
            out
        };
        let my = match vget(&resp, "my") {
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(|v| v.as_i64())
                .filter(|n| (0..=u16::MAX as i64).contains(n))
                .map(|n| n as u16)
                .collect(),
            _ => Vec::new(),
        };
        Ok(FindHashIdsReply {
            ipv4: bucket("peers"),
            ipv6: bucket("peers_ipv6"),
            onion: bucket("peers_onion"),
            my,
        })
    }

    /// Push an optional file directly to the peer (`pushFile`); the peer
    /// verifies size + sha512 against content.json before accepting.
    pub async fn push_file(&mut self, xite: &str, inner_path: &str, body: &[u8]) -> Result<Value> {
        let params = vmap(vec![
            ("site", Value::from(xite)),
            ("inner_path", Value::from(inner_path)),
            ("body", Value::Binary(body.to_vec())),
        ]);
        self.request("pushFile", params).await
    }

    /// Ask which pieces of each big file the peer holds (`getPiecefields`).
    /// Returns `sha512 -> packed piecefield bytes`; the caller unpacks with
    /// `epix_xite::Piecefield` (kept out of the protocol layer to avoid a cycle).
    pub async fn get_piecefields(
        &mut self,
        xite: &str,
    ) -> Result<std::collections::HashMap<String, Vec<u8>>> {
        let params = vmap(vec![("site", Value::from(xite))]);
        let resp = self.request("getPiecefields", params).await?;
        let mut out = std::collections::HashMap::new();
        if let Some(Value::Map(entries)) = vget(&resp, "piecefields_packed") {
            for (k, v) in entries {
                if let (Some(sha), Value::Binary(bytes)) = (k.as_str(), v) {
                    out.insert(sha.to_string(), bytes.clone());
                }
            }
        }
        Ok(out)
    }

    /// Download a whole file, following `location`/`size` across chunks.
    pub async fn get_file(&mut self, xite: &str, inner_path: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut location = 0i64;
        loop {
            let params = vmap(vec![
                // "site" is the on-the-wire field name (the xite address) - kept
                // verbatim because EpixNet peers parse this exact key.
                ("site", Value::from(xite)),
                ("inner_path", Value::from(inner_path)),
                ("location", Value::from(location)),
            ]);
            let resp = self.request("getFile", params).await?;
            let body = vget(&resp, "body")
                .ok_or_else(|| Error::Protocol("getFile response has no body".into()))?;
            let chunk: &[u8] = match body {
                Value::Binary(b) => b.as_slice(),
                Value::String(s) => s.as_bytes(),
                other => {
                    return Err(Error::Protocol(format!("getFile body has type {other:?}")))
                }
            };
            out.extend_from_slice(chunk);

            let size = vget(&resp, "size").and_then(|v| v.as_i64()).unwrap_or(out.len() as i64);
            let next = vget(&resp, "location").and_then(|v| v.as_i64()).unwrap_or(size);
            if out.len() as i64 >= size || next <= location {
                break;
            }
            location = next;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advert::SelfAdvert;

    fn key<'a>(params: &'a Value, k: &str) -> Option<&'a Value> {
        vget(params, k)
    }

    #[test]
    fn handshake_params_default_advert_is_the_legacy_shape() {
        // A node that never set an advert (or a test harness) sends exactly
        // the pre-Phase-6 fields: port 0, port_opened false, no self-address.
        let p = handshake_params(&SelfAdvert::default(), &PeerAddr::parse("1.2.3.4:1").unwrap());
        assert_eq!(key(&p, "fileserver_port").and_then(|v| v.as_i64()), Some(0));
        assert_eq!(key(&p, "port_opened").and_then(|v| v.as_bool()), Some(false));
        assert!(key(&p, "onion").is_none());
        assert!(key(&p, "i2p").is_none());
        assert!(key(&p, "rns").is_none());
        assert_eq!(key(&p, "protocol").and_then(|v| v.as_str()), Some("v2"));
    }

    #[test]
    fn handshake_params_advertise_by_transport_class() {
        let advert = SelfAdvert {
            version: "0.3.9".into(),
            fileserver_port: 26552,
            port_opened: true,
            tor_always: false,
            onion: Some("abcdefghij234567".into()),
            i2p: Some("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq".into()),
            rns: Some("0123456789abcdef0123456789abcdef".into()),
        };

        // Onion target: onion advertised, nothing else.
        let p = handshake_params(&advert, &PeerAddr::parse("2gzyxa5ihm7nsggfxnu5.onion:1").unwrap());
        assert_eq!(key(&p, "onion").and_then(|v| v.as_str()), Some("abcdefghij234567"));
        assert!(key(&p, "i2p").is_none() && key(&p, "rns").is_none());

        // I2p target: i2p only.
        let p = handshake_params(
            &advert,
            &PeerAddr::parse("ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.i2p:1").unwrap(),
        );
        assert!(key(&p, "i2p").is_some());
        assert!(key(&p, "onion").is_none() && key(&p, "rns").is_none());

        // Rns target: rns only.
        let p = handshake_params(&advert, &PeerAddr::parse("rns:00112233445566778899aabbccddeeff").unwrap());
        assert!(key(&p, "rns").is_some());
        assert!(key(&p, "onion").is_none() && key(&p, "i2p").is_none());

        // DIRECT clearnet target: the real port, port_opened as confirmed, and
        // NO overlay address - a clearnet handshake must not link IP and onion.
        let p = handshake_params(&advert, &PeerAddr::parse("1.2.3.4:26552").unwrap());
        assert_eq!(key(&p, "fileserver_port").and_then(|v| v.as_i64()), Some(26552));
        assert_eq!(key(&p, "port_opened").and_then(|v| v.as_bool()), Some(true));
        assert!(key(&p, "onion").is_none() && key(&p, "i2p").is_none() && key(&p, "rns").is_none());

        // Every target carries the node's real release version, not the
        // epix-protocol crate version.
        assert_eq!(key(&p, "version").and_then(|v| v.as_str()), Some("0.3.9"));
    }

    #[test]
    fn handshake_params_version_falls_back_to_the_crate_version() {
        // An unseeded advert (tests, wire-spike) reports epix-protocol's own
        // crate version rather than an empty string.
        let p = handshake_params(&SelfAdvert::default(), &PeerAddr::parse("1.2.3.4:1").unwrap());
        assert_eq!(
            key(&p, "version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn handshake_params_always_mode_advertises_onion_to_clearnet() {
        // In Always mode a clearnet dial rides Tor: the peer sees an exit IP,
        // so the onion is our only dialable identity - advertise it. The port
        // rides along (the receiver builds onion:port from it), but
        // port_opened stays false: clearnet is closed.
        let advert = SelfAdvert {
            version: "0.3.9".into(),
            fileserver_port: 26552,
            port_opened: true, // even if something confirmed it, Always overrides
            tor_always: true,
            onion: Some("abcdefghij234567".into()),
            i2p: None,
            rns: None,
        };
        let p = handshake_params(&advert, &PeerAddr::parse("1.2.3.4:26552").unwrap());
        assert_eq!(key(&p, "onion").and_then(|v| v.as_str()), Some("abcdefghij234567"));
        assert_eq!(key(&p, "fileserver_port").and_then(|v| v.as_i64()), Some(26552));
        assert_eq!(key(&p, "port_opened").and_then(|v| v.as_bool()), Some(false));

        // Not seeding (port 0): nothing to dial back - no self-address at all.
        let advert = SelfAdvert { fileserver_port: 0, ..advert };
        let p = handshake_params(&advert, &PeerAddr::parse("1.2.3.4:26552").unwrap());
        assert!(key(&p, "onion").is_none());
    }
}
