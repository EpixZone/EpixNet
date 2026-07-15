//! Inbound file server - the seeding counterpart to the download path.
//!
//! Implements [`epix_protocol::RequestHandler`] so other peers can pull our
//! files over the wire protocol (`getFile`/`streamFile`), plus `ping` and a
//! minimal `pex`. Without this the node could download from peers but never
//! serve, so it could not seed content, Bigfile pieces, or optional files.
//!
//! Feature-gated behind `inbound-seeding` (off for mobile, which should not
//! accept inbound connections).

use crate::state::InboundUpdate;
use crate::AppState;
use async_trait::async_trait;
use epix_core::{IpType, PeerAddr};
use epix_protocol::RequestHandler;
use rmpv::Value;
use std::collections::HashSet;
use std::sync::Arc;

/// The largest chunk a single `getFile` response returns (EpixNet's FILE_BUFF).
const FILE_BUFF: usize = 1024 * 512;

/// Serves our local xite files to peers.
pub struct FileService {
    state: Arc<AppState>,
}

impl FileService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// `getPiecefields {site}` - report which pieces of each big file we hold,
    /// keyed by the file's sha512, so a downloader only asks us for pieces we
    /// actually have.
    async fn get_piecefields(&self, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        let packed = self.state.our_piecefields(&site).await;
        let map: Vec<(Value, Value)> = packed
            .into_iter()
            .map(|(sha512, bytes)| (Value::from(sha512), Value::Binary(bytes)))
            .collect();
        vmap(vec![("piecefields_packed", Value::Map(map))])
    }

    async fn get_file(&self, peer: &PeerAddr, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        let inner_path = vget_str(params, "inner_path").unwrap_or_default();
        let location = vget_i64(params, "location").unwrap_or(0).max(0) as u64;
        let read_bytes = vget_i64(params, "read_bytes")
            .map(|n| (n.max(0) as usize).min(FILE_BUFF))
            .unwrap_or(FILE_BUFF);

        match self.state.serve_file_chunk(&site, &inner_path, location, read_bytes).await {
            Some((chunk, total)) => {
                let sent = chunk.len() as u64;
                let next = location + sent;
                // Account for what we serve to peers so the Stats seeding graph
                // (file_bytes_sent) reflects upload traffic, not just downloads.
                self.state.record_transfer(&site, peer, 0, sent).await;
                vmap(vec![
                    ("body", Value::Binary(chunk)),
                    ("size", Value::from(total as i64)),
                    ("location", Value::from(next as i64)),
                ])
            }
            None => vmap(vec![("error", Value::from("File not found"))]),
        }
    }

    /// `update {site, inner_path, body, modified}` - a peer pushing us a newer
    /// content.json (the receive half of publish). Response strings match
    /// EpixNet's `FileRequest.actionUpdate` so Python senders behave the same
    /// against a Rust node.
    async fn update(&self, peer: &PeerAddr, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        let inner_path = vget_str(params, "inner_path").unwrap_or_default();
        let body = vget(params, "body").and_then(|v| match v {
            Value::Binary(b) => Some(b.clone()),
            Value::String(s) => s.as_str().map(|s| s.as_bytes().to_vec()),
            _ => None,
        });
        let modified = vget(params, "modified")
            .and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|n| n as f64)));
        // Optional per-file diffs (`inner_path -> [actions]`); applied to skip
        // re-downloading changed data files.
        let diffs = parse_diffs(vget(params, "diffs"));

        match self
            .state
            .apply_inbound_update(&site, &inner_path, body, modified, Some(peer.clone()), diffs)
            .await
        {
            Ok(InboundUpdate::Applied) => {
                // Like EpixNet, piggyback our optional-file hashfield on the
                // ack so the publisher learns what we hold without a
                // getHashfield round-trip.
                let mut fields =
                    vec![("ok", Value::from(format!("Thanks, file {inner_path} updated!")))];
                if let Some(hashfield) = self.state.hashfield_bytes(&site).await {
                    if !hashfield.is_empty() {
                        fields.push(("hashfield_raw", Value::Binary(hashfield)));
                    }
                }
                vmap(fields)
            }
            Ok(InboundUpdate::NotChanged) => vmap(vec![("ok", Value::from("File not changed"))]),
            Err(e) => vmap(vec![("error", Value::from(e))]),
        }
    }

    /// `pex {site, peers, peers_ipv6?, peers_onion?, need}` - peer exchange.
    /// Absorb the peers the requester sent (plus the requester itself), then
    /// reply with connectable peers of ours they don't already have, packed by
    /// type. This is a primary peer-discovery path alongside trackers/DHT.
    async fn pex(&self, peer: &PeerAddr, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        if !self.state.has_any_alias(&site).await {
            return vmap(vec![("error", Value::from("Unknown site"))]);
        }
        let need = vget_i64(params, "need").unwrap_or(5).clamp(0, 100) as usize;

        // Collect the peers they sent (and their own address) to add + exclude
        // from the reply.
        let mut got: Vec<PeerAddr> = Vec::new();
        for field in ["peers", "peers_ipv6", "peers_onion", "peers_i2p", "peers_rns"] {
            if let Some(Value::Array(list)) = vget(params, field) {
                for packed in list {
                    if let Value::Binary(bytes) = packed {
                        let parsed = match field {
                            "peers_onion" => PeerAddr::unpack_onion(bytes),
                            "peers_i2p" => PeerAddr::unpack_i2p(bytes),
                            "peers_rns" => PeerAddr::unpack_rns(bytes),
                            _ => PeerAddr::unpack_ip(bytes),
                        };
                        if let Some(p) = parsed {
                            got.push(p);
                        }
                    }
                }
            }
        }
        let mut exclude: HashSet<String> = got.iter().map(|p| p.to_string()).collect();
        // The requester connected from an ephemeral port; only add it back as a
        // dialable peer if the handshake gave us its real fileserver port.
        if peer.ip_type() != epix_core::IpType::Rns {
            exclude.insert(peer.to_string());
        }
        self.state.add_peers(&site, got).await;

        // Reply with our connectable peers they lack, bucketed by type.
        let ours = self.state.pex_peers(&site, need, &exclude).await;
        let mut buckets: std::collections::HashMap<&str, Vec<Value>> = std::collections::HashMap::new();
        for p in ours {
            if let (Some(field), Some(packed)) = (p.ip_type().pex_field(), p.pack()) {
                buckets.entry(field).or_default().push(Value::Binary(packed));
            }
        }

        // Advertise our own reachable overlay addresses (onion + i2p + mesh)
        // so peers can reach us over an anonymity network or mesh link and
        // gossip us on. Clearnet self-advertising is left to trackers (they
        // see our source IP:port).
        let fs_port = self.state.fileserver_port().await;
        let mut self_addrs: Vec<PeerAddr> = Vec::new();
        if let Some(onion) = self.state.onion_address().await {
            self_addrs.push(PeerAddr::Onion { host: onion, port: fs_port });
        }
        if let Some(i2p) = self.state.i2p_address().await {
            self_addrs.push(PeerAddr::I2p { dest: i2p, port: fs_port });
        }
        if let Some(hex) = self.state.rns_address().await {
            if let Ok(p) = PeerAddr::parse(&format!("rns:{hex}")) {
                self_addrs.push(p);
            }
        }
        for p in self_addrs {
            if exclude.contains(&p.to_string()) {
                continue; // they already have us
            }
            if let (Some(field), Some(packed)) = (p.ip_type().pex_field(), p.pack()) {
                buckets.entry(field).or_default().push(Value::Binary(packed));
            }
        }

        let mut reply = vec![("peers", Value::Array(buckets.remove("peers").unwrap_or_default()))];
        if let Some(v6) = buckets.remove("peers_ipv6") {
            reply.push(("peers_ipv6", Value::Array(v6)));
        }
        if let Some(onion) = buckets.remove("peers_onion") {
            reply.push(("peers_onion", Value::Array(onion)));
        }
        if let Some(i2p) = buckets.remove("peers_i2p") {
            reply.push(("peers_i2p", Value::Array(i2p)));
        }
        if let Some(rns) = buckets.remove("peers_rns") {
            reply.push(("peers_rns", Value::Array(rns)));
        }
        vmap(reply)
    }

    /// `announce {hashes, port, need_types, need_num, add?, onions?, i2p?}` -
    /// act as a tracker (like EpixNet's Bootstrapper). Record the announcing
    /// peer for each hash - its clearnet source (if it asked to be added), plus
    /// any onion/i2p self-addresses it sent - then return the peers we know for
    /// each hash, bucketed by type. This is how a fresh node bootstraps peers
    /// from a tracker address alone, and the only way onion/i2p-only nodes
    /// (which clearnet trackers can't record) get discovered.
    async fn announce(&self, peer: &PeerAddr, params: &Value) -> Value {
        if !self.state.tracker_enabled().await {
            return vmap(vec![("error", Value::from("Tracker disabled"))]);
        }
        let hashes = parse_hashes(params);
        if hashes.is_empty() {
            return vmap(vec![("peers", Value::Array(Vec::new()))]);
        }
        let port = vget_i64(params, "port").unwrap_or(0).clamp(0, u16::MAX as i64) as u16;
        let need_num = vget_i64(params, "need_num").unwrap_or(20).clamp(0, 100) as usize;
        let add = string_list(params, "add");
        let need = crate::tracker::NeedTypes::from_list(&string_list(params, "need_types"));

        // Record the announcer's addresses, collecting them so it never gets
        // itself back in the results.
        let mut mine: HashSet<String> = HashSet::new();
        // Clearnet: source IP + the port it announced, if it asked to be added.
        if port != 0 {
            if let PeerAddr::Ip(sa) = peer {
                let wants = if sa.is_ipv6() {
                    add.iter().any(|t| t == "ipv6")
                } else {
                    add.iter().any(|t| t == "ipv4" || t == "ip4")
                };
                if wants {
                    let mut a = *sa;
                    a.set_port(port);
                    let addr = PeerAddr::Ip(a);
                    self.state.tracker_announce(&hashes, &addr).await;
                    mine.insert(addr.to_string());
                }
            }
        }
        // If the announce arrived over i2p, the source destination is authoritative.
        if let PeerAddr::I2p { dest, .. } = peer {
            if !dest.is_empty() {
                self.state.tracker_announce(&hashes, peer).await;
                mine.insert(peer.to_string());
            }
        }
        // Onion / i2p self-addresses from the request. Parallel arrays map to
        // hashes one-to-one; a single value applies to every hash.
        for (field, is_onion) in [("onions", true), ("i2p", false)] {
            let list = string_list(params, field);
            for (i, host) in list.iter().enumerate() {
                if host.is_empty() {
                    continue;
                }
                let addr = if is_onion {
                    PeerAddr::Onion { host: host.clone(), port }
                } else {
                    PeerAddr::I2p { dest: host.clone(), port }
                };
                let hs: &[[u8; 32]] = if list.len() == hashes.len() {
                    std::slice::from_ref(&hashes[i])
                } else {
                    &hashes
                };
                self.state.tracker_announce(hs, &addr).await;
                mine.insert(addr.to_string());
            }
        }

        // Reply: the peers we know for each hash, bucketed by type.
        let limit = need_num.min(30);
        let mut per_hash: Vec<Value> = Vec::with_capacity(hashes.len());
        for h in &hashes {
            let peers = self.state.tracker_peer_list(h, &mine, limit, need).await;
            per_hash.push(pack_peer_buckets(&peers));
        }
        vmap(vec![("peers", Value::Array(per_hash))])
    }

    /// `listModified {site, since}` - report our content.json files modified
    /// after `since`, so a peer can pull only what changed instead of polling
    /// each file.
    async fn list_modified(&self, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        if !self.state.has_any_alias(&site).await {
            return vmap(vec![("error", Value::from("Unknown site"))]);
        }
        let since = vget(params, "since")
            .and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|n| n as f64)))
            .unwrap_or(0.0);
        let modified = self.state.list_modified(&site, since).await;
        let pairs: Vec<(Value, Value)> = modified
            .into_iter()
            .map(|(k, v)| (Value::from(k), Value::from(v.as_f64().unwrap_or(0.0))))
            .collect();
        vmap(vec![("modified_files", Value::Map(pairs))])
    }

    /// `getHashfield {site}` - report which optional files we hold, as a packed
    /// hash-id array, so a peer knows what optional content to request from us.
    async fn get_hashfield(&self, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        match self.state.hashfield_bytes(&site).await {
            Some(bytes) => vmap(vec![("hashfield_raw", Value::Binary(bytes))]),
            None => vmap(vec![("error", Value::from("Unknown site"))]),
        }
    }

    /// `setHashfield {site, hashfield_raw}` - a peer telling us which optional
    /// files it holds; stored so `findHashIds` can route downloaders to it.
    async fn set_hashfield(&self, peer: &PeerAddr, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        let raw = match vget(params, "hashfield_raw") {
            Some(Value::Binary(b)) => b.clone(),
            Some(Value::String(s)) => s.as_bytes().to_vec(),
            _ => return vmap(vec![("error", Value::from("Missing hashfield_raw"))]),
        };
        if self.state.set_peer_hashfield(&site, peer, &raw).await {
            vmap(vec![("ok", Value::from("Updated"))])
        } else {
            vmap(vec![("error", Value::from("Unknown site"))])
        }
    }

    /// `findHashIds {site, hash_ids}` - for each optional-file hash id, which
    /// peers we know hold it (packed, bucketed by ip type), plus which we hold
    /// ourselves (`my`). Lets a downloader locate a rare optional file.
    async fn find_hash_ids(&self, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        if !self.state.has_any_alias(&site).await {
            return vmap(vec![("error", Value::from("Unknown site"))]);
        }
        let hash_ids: Vec<u16> = match vget(params, "hash_ids") {
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(|v| v.as_i64())
                .filter(|n| (0..=u16::MAX as i64).contains(n))
                .map(|n| n as u16)
                .collect(),
            _ => Vec::new(),
        };
        let (v4, v6, onion, mine) = self.state.find_hash_ids(&site, &hash_ids).await;
        // Pack each bucket as {hash_id: [binary addr]}.
        let bucket = |m: std::collections::HashMap<u16, Vec<Vec<u8>>>| -> Value {
            Value::Map(
                m.into_iter()
                    .map(|(id, addrs)| {
                        (
                            Value::from(id as i64),
                            Value::Array(addrs.into_iter().map(Value::Binary).collect()),
                        )
                    })
                    .collect(),
            )
        };
        vmap(vec![
            ("peers", bucket(v4)),
            ("peers_ipv6", bucket(v6)),
            ("peers_onion", bucket(onion)),
            ("my", Value::Array(mine.into_iter().map(|id| Value::from(id as i64)).collect())),
        ])
    }

    /// `pushFile {site, inner_path, body}` - a peer pushing an optional file
    /// directly. Verified (size + sha512) against content.json before writing.
    async fn push_file(&self, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        let inner_path = vget_str(params, "inner_path").unwrap_or_default();
        let body = match vget(params, "body") {
            Some(Value::Binary(b)) => b.clone(),
            Some(Value::String(s)) => s.as_bytes().to_vec(),
            _ => return vmap(vec![("error", Value::from("Missing params"))]),
        };
        if inner_path.is_empty() || body.is_empty() {
            return vmap(vec![("error", Value::from("Missing params"))]);
        }
        match self.state.apply_push_file(&site, &inner_path, &body).await {
            Ok(msg) => vmap(vec![("ok", Value::from(msg))]),
            Err(e) => vmap(vec![("error", Value::from(e))]),
        }
    }

    /// `checkport {port}` - the peer asks us to test whether its fileserver
    /// port is reachable from our side (so it can tell if it's behind a
    /// closed NAT). We dial back the requester's IP at `port`.
    async fn checkport(&self, peer: &PeerAddr, params: &Value) -> Value {
        let port = vget_i64(params, "port").unwrap_or(0);
        let PeerAddr::Ip(addr) = peer else {
            return vmap(vec![("status", Value::from("closed"))]);
        };
        let ip = addr.ip();
        if !(1..=65535).contains(&port) {
            return vmap(vec![
                ("status", Value::from("closed")),
                ("ip_external", Value::from(ip.to_string())),
            ]);
        }
        let target = std::net::SocketAddr::new(ip, port as u16);
        let open = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(target),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
        vmap(vec![
            ("status", Value::from(if open { "open" } else { "closed" })),
            ("ip_external", Value::from(ip.to_string())),
        ])
    }
}

#[async_trait]
impl RequestHandler for FileService {
    async fn handle(&self, peer: &PeerAddr, cmd: &str, params: &Value) -> Value {
        match cmd {
            "ping" => vmap(vec![("body", Value::Binary(b"Pong!".to_vec()))]),
            "getFile" | "streamFile" => self.get_file(peer, params).await,
            "update" => self.update(peer, params).await,
            "pex" => self.pex(peer, params).await,
            "announce" => self.announce(peer, params).await,
            "listModified" => self.list_modified(params).await,
            "checkport" => self.checkport(peer, params).await,
            // AnnounceShare/Beacon: peers exchange their working announcer
            // lists (`epix://host:port` strings), so the tracker set spreads
            // through the network itself.
            "getTrackers" => {
                let mut trackers: Vec<Value> = Vec::new();
                for t in self.state.shared_trackers().await.into_iter()
                    .chain(self.state.extra_trackers().await)
                {
                    let s = format!("epix://{t}");
                    if !trackers.iter().any(|v| v.as_str() == Some(&s)) {
                        trackers.push(Value::from(s));
                    }
                }
                vmap(vec![("trackers", Value::Array(trackers))])
            }
            "getHashfield" => self.get_hashfield(params).await,
            "setHashfield" => self.set_hashfield(peer, params).await,
            "findHashIds" => self.find_hash_ids(params).await,
            "pushFile" => self.push_file(params).await,
            "getPiecefields" => self.get_piecefields(params).await,
            // A peer pushing us its piecefields: acknowledge (our downloader
            // re-queries piecefields when it needs them, so we don't retain).
            "setPiecefields" => vmap(vec![("ok", Value::from("Updated"))]),
            // Unknown/unsupported request: empty body (the server still wraps it
            // as a response so the peer isn't left hanging).
            _ => Value::Map(vec![]),
        }
    }
}

/// Parse an `update`'s `diffs` param (`inner_path -> [["=",n]|["-",n]|["+",[lines]]]`)
/// into per-file diff actions. Malformed entries are skipped (the file then
/// downloads normally).
fn parse_diffs(v: Option<&Value>) -> std::collections::HashMap<String, Vec<epix_content::DiffAction>> {
    let mut out = std::collections::HashMap::new();
    let Some(Value::Map(entries)) = v else { return out };
    for (path, actions) in entries {
        let Some(path) = path.as_str() else { continue };
        let Value::Array(list) = actions else { continue };
        let mut parsed = Vec::new();
        for action in list {
            if let Some(a) = rmpv_to_diff_action(action) {
                parsed.push(a);
            } else {
                parsed.clear();
                break; // a malformed action invalidates the whole file's diff
            }
        }
        if !parsed.is_empty() {
            out.insert(path.to_string(), parsed);
        }
    }
    out
}

/// Encode per-file diff actions as an `update`'s `diffs` wire value - the
/// inverse of [`parse_diffs`]. Insert lines go as binary so a Python receiver
/// patches with raw bytes.
pub(crate) fn encode_diffs(
    diffs: &std::collections::HashMap<String, Vec<epix_content::DiffAction>>,
) -> Value {
    use epix_content::DiffAction;
    Value::Map(
        diffs
            .iter()
            .map(|(path, actions)| {
                let wire = actions
                    .iter()
                    .map(|a| match a {
                        DiffAction::Equal(n) => {
                            Value::Array(vec!["=".into(), (*n as u64).into()])
                        }
                        DiffAction::Remove(n) => {
                            Value::Array(vec!["-".into(), (*n as u64).into()])
                        }
                        DiffAction::Insert(lines) => Value::Array(vec![
                            "+".into(),
                            Value::Array(
                                lines.iter().map(|l| Value::Binary(l.clone())).collect(),
                            ),
                        ]),
                    })
                    .collect();
                (Value::from(path.as_str()), Value::Array(wire))
            })
            .collect(),
    )
}

/// Parse one rmpv diff action (`["=",n]` / `["-",n]` / `["+",[lines]]`).
fn rmpv_to_diff_action(v: &Value) -> Option<epix_content::DiffAction> {
    use epix_content::DiffAction;
    let arr = v.as_array()?;
    match arr.first()?.as_str()? {
        "=" => Some(DiffAction::Equal(arr.get(1)?.as_u64()? as usize)),
        "-" => Some(DiffAction::Remove(arr.get(1)?.as_u64()? as usize)),
        "+" => {
            let lines = arr
                .get(1)?
                .as_array()?
                .iter()
                .map(|l| match l {
                    Value::String(s) => s.as_bytes().to_vec(),
                    Value::Binary(b) => b.clone(),
                    _ => Vec::new(),
                })
                .collect();
            Some(DiffAction::Insert(lines))
        }
        _ => None,
    }
}

/// Build a msgpack map from string-keyed pairs.
fn vmap(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

/// Read a string field from a msgpack map param.
fn vget_str(params: &Value, key: &str) -> Option<String> {
    vget(params, key).and_then(|v| match v {
        Value::String(s) => s.as_str().map(str::to_string),
        Value::Binary(b) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    })
}

/// Read an integer field from a msgpack map param.
fn vget_i64(params: &Value, key: &str) -> Option<i64> {
    vget(params, key).and_then(Value::as_i64)
}

fn vget<'a>(params: &'a Value, key: &str) -> Option<&'a Value> {
    match params {
        Value::Map(fields) => fields
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

/// Read an announce `hashes` array (32-byte binary xite hashes).
fn parse_hashes(params: &Value) -> Vec<[u8; 32]> {
    match vget(params, "hashes") {
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(|v| match v {
                Value::Binary(b) if b.len() == 32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(b);
                    Some(a)
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Read a msgpack array of strings (string or binary elements).
fn string_list(params: &Value, key: &str) -> Vec<String> {
    match vget(params, key) {
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => s.as_str().map(str::to_string),
                Value::Binary(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Pack peers into an announce reply's per-hash bucket map (`ipv4`/`ip4`/
/// `ipv6`/`onion`/`i2p`). `ip4` mirrors `ipv4` for old EpixNet clients.
fn pack_peer_buckets(peers: &[PeerAddr]) -> Value {
    let (mut ipv4, mut ipv6, mut onion, mut i2p) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for p in peers {
        let Some(packed) = p.pack() else { continue };
        match p.ip_type() {
            IpType::Ipv4 => ipv4.push(Value::Binary(packed)),
            IpType::Ipv6 => ipv6.push(Value::Binary(packed)),
            IpType::Onion => onion.push(Value::Binary(packed)),
            IpType::I2p => i2p.push(Value::Binary(packed)),
            IpType::Rns => {}
        }
    }
    vmap(vec![
        ("ipv4", Value::Array(ipv4.clone())),
        ("ip4", Value::Array(ipv4)),
        ("ipv6", Value::Array(ipv6)),
        ("onion", Value::Array(onion)),
        ("i2p", Value::Array(i2p)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::XiteEntry;
    use epix_xite::XiteStorage;
    use serde_json::json;

    #[tokio::test]
    async fn serves_a_file_chunk_over_the_handler() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage.write("index.html", b"hello seeding world").unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1Seed", XiteEntry { storage, content: Some(json!({ "address": "1Seed" })) })
            .await;
        let svc = FileService::new(state.clone());
        let peer = PeerAddr::parse("1.2.3.4:1").unwrap();

        // ping
        let pong = svc.handle(&peer, "ping", &Value::Map(vec![])).await;
        assert_eq!(vget(&pong, "body"), Some(&Value::Binary(b"Pong!".to_vec())));

        // getFile whole file
        let params = vmap(vec![
            ("site", Value::from("1Seed")),
            ("inner_path", Value::from("index.html")),
            ("location", Value::from(0i64)),
        ]);
        let resp = svc.handle(&peer, "getFile", &params).await;
        assert_eq!(vget(&resp, "body"), Some(&Value::Binary(b"hello seeding world".to_vec())));
        assert_eq!(vget_i64(&resp, "size"), Some(19));
        assert_eq!(vget_i64(&resp, "location"), Some(19));

        // getFile ranged
        let params = vmap(vec![
            ("site", Value::from("1Seed")),
            ("inner_path", Value::from("index.html")),
            ("location", Value::from(6i64)),
            ("read_bytes", Value::from(7i64)),
        ]);
        let resp = svc.handle(&peer, "getFile", &params).await;
        assert_eq!(vget(&resp, "body"), Some(&Value::Binary(b"seeding".to_vec())));

        // Missing file -> error body.
        let params = vmap(vec![
            ("site", Value::from("1Seed")),
            ("inner_path", Value::from("nope.txt")),
        ]);
        let resp = svc.handle(&peer, "getFile", &params).await;
        assert!(vget(&resp, "error").is_some());

        // Served bytes are accounted as sent (feeds the Stats seeding graph):
        // 19 for the whole file + 7 for the range, nothing for the miss.
        assert_eq!(state.transfer("1Seed").await.1, 26);
    }

    /// Build a signed content.json for `address` at version `modified`.
    fn signed_content(address: &str, privkey: &str, modified: i64) -> (serde_json::Value, Vec<u8>) {
        let mut content = json!({ "address": address, "modified": modified, "files": {} });
        epix_content::sign(&mut content, privkey).unwrap();
        let bytes = serde_json::to_vec(&content).unwrap();
        (content, bytes)
    }

    fn update_params(site: &str, inner_path: &str, body: &[u8], modified: i64) -> Value {
        vmap(vec![
            ("site", Value::from(site)),
            ("inner_path", Value::from(inner_path)),
            ("body", Value::Binary(body.to_vec())),
            ("modified", Value::from(modified as f64)),
        ])
    }

    #[tokio::test]
    async fn inbound_update_verifies_applies_and_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();

        let (v1, v1_bytes) = signed_content(&address, &privkey, 1000);
        storage.write("content.json", &v1_bytes).unwrap();

        let state = AppState::new("test");
        state.add_xite(&address, XiteEntry { storage, content: Some(v1) }).await;
        let svc = FileService::new(state.clone());
        let peer = PeerAddr::parse("1.2.3.4:1234").unwrap();

        // A newer, validly signed version is accepted and stored.
        let (_v2, v2_bytes) = signed_content(&address, &privkey, 2000);
        let params = update_params(&address, "content.json", &v2_bytes, 2000);
        let resp = svc.handle(&peer, "update", &params).await;
        assert_eq!(vget_str(&resp, "ok").as_deref(), Some("Thanks, file content.json updated!"));
        let stored = state.content(&address).await.unwrap();
        assert_eq!(stored.get("modified").and_then(|m| m.as_i64()), Some(2000));
        // The sender was recorded as a peer.
        assert!(state.connectable_peers(&address, 10).await.contains(&peer));

        // Replaying the same version is a no-op.
        let resp = svc.handle(&peer, "update", &params).await;
        assert_eq!(vget_str(&resp, "ok").as_deref(), Some("File not changed"));

        // A tampered body (modified bumped without re-signing) is rejected and
        // the stored content is untouched.
        let mut forged: serde_json::Value = serde_json::from_slice(&v2_bytes).unwrap();
        forged["modified"] = json!(3000);
        let forged_bytes = serde_json::to_vec(&forged).unwrap();
        let params = update_params(&address, "content.json", &forged_bytes, 3000);
        let resp = svc.handle(&peer, "update", &params).await;
        assert!(vget_str(&resp, "error").unwrap().contains("invalid"));
        let stored = state.content(&address).await.unwrap();
        assert_eq!(stored.get("modified").and_then(|m| m.as_i64()), Some(2000));

        // Unknown site.
        let params = update_params("1Unknown", "content.json", &v2_bytes, 2000);
        let resp = svc.handle(&peer, "update", &params).await;
        assert_eq!(vget_str(&resp, "error").as_deref(), Some("Unknown site"));

        // Only content.json may be pushed.
        let params = update_params(&address, "index.html", b"<html>", 2000);
        let resp = svc.handle(&peer, "update", &params).await;
        assert_eq!(vget_str(&resp, "error").as_deref(), Some("Only content.json update allowed"));

        // An older version short-circuits via the modified hint (no body parse).
        let params = update_params(&address, "content.json", &v1_bytes, 1000);
        let resp = svc.handle(&peer, "update", &params).await;
        assert_eq!(vget_str(&resp, "ok").as_deref(), Some("File not changed"));
    }

    #[tokio::test]
    async fn inbound_update_accepts_user_content() {
        // A peer pushes a per-user content.json (an EpixTalk post): it is
        // verified against the parent's user_contents rules and stored, a
        // forged bump is rejected, and a replay short-circuits.
        let site_key = epix_crypt::new_seed();
        let site = epix_crypt::privatekey_to_address(&site_key).unwrap();
        let users_content = json!({
            "address": site,
            "inner_path": "data/users/content.json",
            "user_contents": { "permissions": {}, "cert_signers": {} }
        });
        let users_bytes = serde_json::to_vec(&users_content).unwrap();

        // A "sender" node signs a user data file with its own auth key.
        let sender_root = tempfile::tempdir().unwrap();
        let sender = AppState::with_data_dir("test", sender_root.path());
        let sender_storage = XiteStorage::new(sender_root.path().join("data").join(&site));
        sender_storage.write("data/users/content.json", &users_bytes).unwrap();
        sender
            .add_xite(&site, XiteEntry {
                storage: sender_storage.clone(),
                content: Some(json!({ "address": site, "files": {} })),
            })
            .await;
        let auth = sender.user_auth_address(&site).await.unwrap();
        let user_path = format!("data/users/{auth}/content.json");
        sender
            .write_file(&site, &format!("data/users/{auth}/data.json"), br#"{"topic":[]}"#)
            .await
            .unwrap();
        sender.sign_user_content(&site, &user_path, None, None).await.unwrap();
        let signed = sender_storage.read(&user_path).unwrap();
        let modified = serde_json::from_slice::<serde_json::Value>(&signed).unwrap()["modified"]
            .as_f64()
            .unwrap();

        // The receiver serves the site (root + the user_contents parent) but
        // has never seen this user.
        let recv_root = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(recv_root.path());
        storage.write("data/users/content.json", &users_bytes).unwrap();
        let state = AppState::new("test");
        state
            .add_xite(&site, XiteEntry {
                storage: storage.clone(),
                content: Some(json!({ "address": site, "files": {} })),
            })
            .await;
        let svc = FileService::new(state.clone());
        let peer = PeerAddr::parse("1.2.3.4:1234").unwrap();

        let push = |body: Vec<u8>, hint: f64| {
            vmap(vec![
                ("site", Value::from(site.as_str())),
                ("inner_path", Value::from(user_path.as_str())),
                ("body", Value::Binary(body)),
                ("modified", Value::from(hint)),
            ])
        };
        let resp = svc.handle(&peer, "update", &push(signed.clone(), modified)).await;
        assert_eq!(
            vget_str(&resp, "ok").as_deref(),
            Some(format!("Thanks, file {user_path} updated!").as_str())
        );
        assert_eq!(storage.read(&user_path).unwrap(), signed, "child stored verbatim");
        // The accepted child now shows up in our listModified reply.
        assert!(state.list_modified(&site, 0.0).await.contains_key(&user_path));

        // Replaying the same version is a no-op (hint vs the on-disk child).
        let resp = svc.handle(&peer, "update", &push(signed.clone(), modified)).await;
        assert_eq!(vget_str(&resp, "ok").as_deref(), Some("File not changed"));

        // A forged bump (modified raised without re-signing) is rejected and
        // the stored child is untouched.
        let mut forged: serde_json::Value = serde_json::from_slice(&signed).unwrap();
        forged["modified"] = json!(modified + 100.0);
        let forged_bytes = serde_json::to_vec(&forged).unwrap();
        let resp = svc.handle(&peer, "update", &push(forged_bytes, modified + 100.0)).await;
        assert!(vget_str(&resp, "error").unwrap().contains("invalid"));
        assert_eq!(storage.read(&user_path).unwrap(), signed);
    }

    #[tokio::test]
    async fn pex_absorbs_and_returns_peers() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let state = AppState::new("test");
        state
            .add_xite("1Pex", XiteEntry { storage, content: Some(json!({ "address": "1Pex" })) })
            .await;
        // We know two public peers already.
        state
            .add_peers(
                "1Pex",
                [
                    PeerAddr::parse("8.8.8.8:15441").unwrap(),
                    PeerAddr::parse("1.1.1.1:15441").unwrap(),
                ],
            )
            .await;
        let svc = FileService::new(state.clone());
        let requester = PeerAddr::parse("9.9.9.9:15441").unwrap();

        // Requester sends one peer we don't have and asks for peers back.
        let sent = PeerAddr::parse("4.4.4.4:15441").unwrap().pack().unwrap();
        let params = vmap(vec![
            ("site", Value::from("1Pex")),
            ("need", Value::from(10i64)),
            ("peers", Value::Array(vec![Value::Binary(sent)])),
        ]);
        let resp = svc.handle(&requester, "pex", &params).await;

        // We learned the sent peer.
        let known = state.connectable_peers("1Pex", 20).await;
        assert!(known.contains(&PeerAddr::parse("4.4.4.4:15441").unwrap()));

        // We returned our peers, but not the one they sent.
        let Some(Value::Array(returned)) = vget(&resp, "peers").cloned() else {
            panic!("no peers in pex reply");
        };
        let returned: Vec<PeerAddr> = returned
            .iter()
            .filter_map(|v| match v {
                Value::Binary(b) => PeerAddr::unpack_ip(b),
                _ => None,
            })
            .collect();
        assert!(returned.contains(&PeerAddr::parse("8.8.8.8:15441").unwrap()));
        assert!(!returned.contains(&PeerAddr::parse("4.4.4.4:15441").unwrap()));

        // Unknown site errors.
        let params = vmap(vec![("site", Value::from("1None")), ("need", Value::from(5i64))]);
        let resp = svc.handle(&requester, "pex", &params).await;
        assert_eq!(vget_str(&resp, "error").as_deref(), Some("Unknown site"));
    }

    #[tokio::test]
    async fn pex_absorbs_and_advertises_i2p() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let state = AppState::new("test");
        state
            .add_xite("1Pex", XiteEntry { storage, content: Some(json!({ "address": "1Pex" })) })
            .await;
        state.set_fileserver_port(15441).await;
        // We are reachable over I2P and should advertise it in PEX.
        let our_i2p = "narvewf7cmhowltv4vybkf4y4zgt63xxf2kbiantnzrb3slglw2q.b32";
        state.set_i2p_address(our_i2p).await;
        let svc = FileService::new(state.clone());
        let requester = PeerAddr::parse("9.9.9.9:15441").unwrap();

        // Requester sends an i2p peer we don't have (packed 32-byte hash + port).
        let mut packed = vec![7u8; 32];
        packed.extend_from_slice(&0u16.to_le_bytes());
        let sent = PeerAddr::unpack_i2p(&packed).unwrap();
        let params = vmap(vec![
            ("site", Value::from("1Pex")),
            ("need", Value::from(10i64)),
            ("peers_i2p", Value::Array(vec![Value::Binary(sent.pack().unwrap())])),
        ]);
        let resp = svc.handle(&requester, "pex", &params).await;

        // We learned the sent i2p peer.
        let known = state.connectable_peers("1Pex", 20).await;
        assert!(known.contains(&sent), "should absorb the peers_i2p they sent");

        // The reply advertises our own i2p address and not the one they sent.
        let Some(Value::Array(returned)) = vget(&resp, "peers_i2p").cloned() else {
            panic!("no peers_i2p in pex reply");
        };
        let returned: Vec<PeerAddr> = returned
            .iter()
            .filter_map(|v| match v {
                Value::Binary(b) => PeerAddr::unpack_i2p(b),
                _ => None,
            })
            .collect();
        let ours = PeerAddr::I2p { dest: our_i2p.into(), port: 15441 };
        assert!(returned.contains(&ours), "reply should advertise our own i2p address");
        assert!(!returned.contains(&sent), "should not echo back their peer");
    }

    #[tokio::test]
    async fn announce_tracker_records_and_serves_overlay_peers() {
        let state = AppState::new("test");
        let svc = FileService::new(state.clone());
        let hash = vec![42u8; 32];

        // Peer A (clearnet) announces the hash, requesting ipv4 + i2p peers.
        let a = PeerAddr::parse("8.8.8.8:12345").unwrap();
        let a_params = vmap(vec![
            ("hashes", Value::Array(vec![Value::Binary(hash.clone())])),
            ("port", Value::from(15441i64)),
            ("add", Value::Array(vec![Value::from("ipv4")])),
            ("need_types", Value::Array(vec![Value::from("ipv4"), Value::from("i2p")])),
            ("need_num", Value::from(20i64)),
        ]);
        svc.handle(&a, "announce", &a_params).await;

        // Peer B announces the same hash with a clearnet source + an i2p self-address.
        let b = PeerAddr::parse("9.9.9.9:23456").unwrap();
        let b_i2p = "narvewf7cmhowltv4vybkf4y4zgt63xxf2kbiantnzrb3slglw2q.b32";
        let b_params = vmap(vec![
            ("hashes", Value::Array(vec![Value::Binary(hash.clone())])),
            ("port", Value::from(26552i64)),
            ("add", Value::Array(vec![Value::from("ipv4"), Value::from("i2p")])),
            ("i2p", Value::Array(vec![Value::from(b_i2p)])),
            ("need_types", Value::Array(vec![Value::from("ipv4")])),
            ("need_num", Value::from(20i64)),
        ]);
        svc.handle(&b, "announce", &b_params).await;

        // A re-announces: it should now discover B's clearnet and i2p addresses,
        // but never itself.
        let resp = svc.handle(&a, "announce", &a_params).await;
        let Some(Value::Array(per_hash)) = vget(&resp, "peers").cloned() else {
            panic!("no peers in announce reply");
        };
        assert_eq!(per_hash.len(), 1);
        let bucket = &per_hash[0];

        let unpack = |b: &Value, key: &str, f: fn(&[u8]) -> Option<PeerAddr>| -> Vec<PeerAddr> {
            match vget(b, key) {
                Some(Value::Array(l)) => l.iter().filter_map(|v| match v {
                    Value::Binary(bytes) => f(bytes),
                    _ => None,
                }).collect(),
                _ => Vec::new(),
            }
        };
        let ipv4 = unpack(bucket, "ipv4", PeerAddr::unpack_ip);
        let i2p = unpack(bucket, "i2p", PeerAddr::unpack_i2p);
        assert!(ipv4.contains(&PeerAddr::parse("9.9.9.9:26552").unwrap()), "A discovers B's clearnet");
        assert!(
            i2p.contains(&PeerAddr::I2p { dest: b_i2p.into(), port: 26552 }),
            "A discovers B's i2p address through the tracker"
        );
        assert!(!ipv4.contains(&PeerAddr::parse("8.8.8.8:15441").unwrap()), "A never gets itself");
    }

    #[tokio::test]
    async fn announce_tracker_can_be_disabled() {
        let state = AppState::new("test");
        state.config_set("tracker", serde_json::json!("disable")).await;
        let svc = FileService::new(state.clone());
        let params = vmap(vec![
            ("hashes", Value::Array(vec![Value::Binary(vec![1u8; 32])])),
            ("port", Value::from(15441i64)),
        ]);
        let resp = svc.handle(&PeerAddr::parse("8.8.8.8:1").unwrap(), "announce", &params).await;
        assert_eq!(vget_str(&resp, "error").as_deref(), Some("Tracker disabled"));
    }

    #[tokio::test]
    async fn list_modified_reports_newer_content() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        // listModified reads content.json from disk (root + includes + per-user).
        let content = json!({ "address": "1Mod", "modified": 5000 });
        storage.write("content.json", content.to_string().as_bytes()).unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1Mod", XiteEntry { storage, content: Some(content) })
            .await;
        let svc = FileService::new(state);
        let peer = PeerAddr::parse("8.8.8.8:1").unwrap();

        // since older than our version -> content.json listed.
        let params = vmap(vec![("site", Value::from("1Mod")), ("since", Value::from(1000.0))]);
        let resp = svc.handle(&peer, "listModified", &params).await;
        let Some(Value::Map(files)) = vget(&resp, "modified_files").cloned() else {
            panic!("no modified_files");
        };
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0.as_str(), Some("content.json"));

        // since newer than our version -> empty.
        let params = vmap(vec![("site", Value::from("1Mod")), ("since", Value::from(9000.0))]);
        let resp = svc.handle(&peer, "listModified", &params).await;
        let Some(Value::Map(files)) = vget(&resp, "modified_files").cloned() else {
            panic!("no modified_files");
        };
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn parse_diffs_reads_wire_actions() {
        // A wire diffs map with one file's action list.
        let diffs = Value::Map(vec![(
            Value::from("data.json"),
            Value::Array(vec![
                Value::Array(vec![Value::from("="), Value::from(2i64)]),
                Value::Array(vec![Value::from("-"), Value::from(3i64)]),
                Value::Array(vec![
                    Value::from("+"),
                    Value::Array(vec![Value::from("new")]),
                ]),
            ]),
        )]);
        let parsed = parse_diffs(Some(&diffs));
        assert_eq!(parsed.len(), 1);
        let actions = &parsed["data.json"];
        assert_eq!(actions.len(), 3);
        // Applies correctly against an old value.
        let out = epix_content::patch(b"ab_old", actions).unwrap();
        assert_eq!(out, b"abnew");

        // A malformed action drops that file's diff entirely.
        let bad = Value::Map(vec![(
            Value::from("x"),
            Value::Array(vec![Value::Array(vec![Value::from("?"), Value::from(1i64)])]),
        )]);
        assert!(parse_diffs(Some(&bad)).is_empty());
    }

    #[tokio::test]
    async fn hashfield_and_pushfile_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let optional_body = b"optional data";
        let sha = XiteStorage::hash_bytes(optional_body);
        let content = json!({
            "address": "1Opt",
            "modified": 1,
            "files": {},
            "files_optional": { "big.dat": { "size": optional_body.len(), "sha512": sha } },
        });
        let state = AppState::new("test");
        state.add_xite("1Opt", XiteEntry { storage, content: Some(content) }).await;
        let svc = FileService::new(state.clone());
        let peer = PeerAddr::parse("8.8.8.8:15441").unwrap();

        // We don't hold the optional file yet -> empty hashfield.
        let resp = svc.handle(&peer, "getHashfield", &vmap(vec![("site", Value::from("1Opt"))])).await;
        assert_eq!(vget(&resp, "hashfield_raw"), Some(&Value::Binary(vec![])));

        // A peer pushes the optional file; verified + written + advertised.
        let params = vmap(vec![
            ("site", Value::from("1Opt")),
            ("inner_path", Value::from("big.dat")),
            ("body", Value::Binary(optional_body.to_vec())),
        ]);
        let resp = svc.handle(&peer, "pushFile", &params).await;
        assert_eq!(vget_str(&resp, "ok").as_deref(), Some("File pushed"));
        assert_eq!(state.read_file("1Opt", "big.dat").await.as_deref(), Some(&optional_body[..]));

        // Now our hashfield advertises it (hash id of the file's sha512).
        let resp = svc.handle(&peer, "getHashfield", &vmap(vec![("site", Value::from("1Opt"))])).await;
        let expected = epix_xite::Hashfield::hash_id(&sha).unwrap().to_le_bytes().to_vec();
        assert_eq!(vget(&resp, "hashfield_raw"), Some(&Value::Binary(expected)));

        // A tampered push (wrong bytes for the declared hash) is rejected.
        let params = vmap(vec![
            ("site", Value::from("1Opt")),
            ("inner_path", Value::from("big.dat")),
            ("body", Value::Binary(b"tampered data!".to_vec())),
        ]);
        let resp = svc.handle(&peer, "pushFile", &params).await;
        assert!(vget_str(&resp, "error").is_some());
    }

    #[tokio::test]
    async fn set_and_find_hash_ids_locates_peers() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let state = AppState::new("test");
        state
            .add_xite("1Find", XiteEntry { storage, content: Some(json!({ "address": "1Find" })) })
            .await;
        let svc = FileService::new(state.clone());

        // A peer advertises holding hash id 0x1234.
        let holder = PeerAddr::parse("8.8.8.8:15441").unwrap();
        let mut hf = epix_xite::Hashfield::new();
        hf.add_id(0x1234);
        let params = vmap(vec![
            ("site", Value::from("1Find")),
            ("hashfield_raw", Value::Binary(hf.to_bytes())),
        ]);
        let resp = svc.handle(&holder, "setHashfield", &params).await;
        assert_eq!(vget_str(&resp, "ok").as_deref(), Some("Updated"));

        // findHashIds returns that peer for 0x1234 in the ipv4 bucket.
        let params = vmap(vec![
            ("site", Value::from("1Find")),
            ("hash_ids", Value::Array(vec![Value::from(0x1234i64), Value::from(0x9999i64)])),
        ]);
        let resp = svc.handle(&holder, "findHashIds", &params).await;
        let Some(Value::Map(v4)) = vget(&resp, "peers").cloned() else { panic!("no peers") };
        // One entry keyed by hash id 0x1234, containing the packed holder.
        assert_eq!(v4.len(), 1);
        let (id, addrs) = &v4[0];
        assert_eq!(id.as_i64(), Some(0x1234));
        let Value::Array(addrs) = addrs else { panic!() };
        assert_eq!(addrs.len(), 1);
        let Value::Binary(packed) = &addrs[0] else { panic!() };
        assert_eq!(PeerAddr::unpack_ip(packed).unwrap(), holder);
    }

    #[tokio::test]
    async fn checkport_reports_closed_for_dead_port() {
        let state = AppState::new("test");
        let svc = FileService::new(state);
        // 127.0.0.1 with a very unlikely-open high port -> closed, echoes IP.
        let peer = PeerAddr::parse("127.0.0.1:1").unwrap();
        let params = vmap(vec![("port", Value::from(1i64))]);
        let resp = svc.handle(&peer, "checkport", &params).await;
        assert_eq!(vget_str(&resp, "status").as_deref(), Some("closed"));
        assert_eq!(vget_str(&resp, "ip_external").as_deref(), Some("127.0.0.1"));
    }
}
