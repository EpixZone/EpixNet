//! Mainline DHT (BEP5) `get_peers`, just enough to discover seeders for a bare
//! magnet.
//!
//! A trackerless magnet names only the info-hash, so the one way to find who has
//! the data is the mainline DHT: an iterative Kademlia lookup that walks toward
//! the info-hash asking `get_peers`, collecting `values` (peers) and following
//! `nodes` (closer contacts) until it converges or the time budget runs out.
//! This is UDP - Tor carries no UDP - so discovery is inherently clearnet; the
//! swarm can still tunnel the actual peer connections through Tor afterwards.
//!
//! This is deliberately a discovery-only client: no routing table is persisted,
//! nothing is announced, and it is one-shot per stream. It is not a good DHT
//! citizen's full node, just enough to locate peers.

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::bencode::{self, Value};

/// Public routers that seed a fresh lookup with their neighbors.
const BOOTSTRAP: &[&str] = &[
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401",
    "router.bitcomet.com:6881",
];

/// How many of the closest not-yet-queried nodes to query per round.
const ALPHA: usize = 8;
/// A single `recv` waits at most this long before we send the next round.
const RECV_WINDOW: Duration = Duration::from_millis(400);
/// Hard cap on queries so a pathological swarm can't make us loop forever.
const MAX_QUERIES: usize = 400;

/// One known DHT contact: its node id and address.
struct Contact {
    id: [u8; 20],
    addr: SocketAddrV4,
}

/// Find peers for `info_hash` via an iterative mainline `get_peers`, returning
/// up to `max_peers` distinct addresses or whatever was found before `budget`
/// elapsed. Best-effort: any error (no network, no UDP) yields an empty list.
pub async fn get_peers(
    info_hash: [u8; 20],
    max_peers: usize,
    budget: Duration,
) -> Vec<SocketAddrV4> {
    match lookup(info_hash, max_peers, budget).await {
        Ok(peers) => peers,
        Err(_) => Vec::new(),
    }
}

async fn lookup(
    info_hash: [u8; 20],
    max_peers: usize,
    budget: Duration,
) -> std::io::Result<Vec<SocketAddrV4>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let node_id: [u8; 20] = rand::random();
    let deadline = Instant::now() + budget;

    let mut peers: HashSet<SocketAddrV4> = HashSet::new();
    let mut queried: HashSet<SocketAddrV4> = HashSet::new();
    // Candidate contacts to query, kept sorted (closest to info_hash first).
    let mut candidates: Vec<Contact> = Vec::new();
    let mut queries_sent = 0usize;

    // Seed from the bootstrap routers (resolved fresh each run).
    for host in BOOTSTRAP {
        if let Ok(addrs) = tokio::net::lookup_host(host).await {
            for a in addrs {
                if let SocketAddr::V4(v4) = a {
                    if queried.insert(v4) {
                        send_get_peers(&socket, v4, &node_id, &info_hash).await;
                        queries_sent += 1;
                    }
                }
            }
        }
    }

    let mut buf = vec![0u8; 4096];
    while Instant::now() < deadline && peers.len() < max_peers && queries_sent < MAX_QUERIES {
        // Drain replies for a short window.
        let window_end = (Instant::now() + RECV_WINDOW).min(deadline);
        loop {
            let now = Instant::now();
            if now >= window_end {
                break;
            }
            match timeout(window_end - now, socket.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) => {
                    parse_response(&buf[..n], &mut peers, &mut candidates, &queried, &info_hash);
                }
                _ => break, // timeout or error: move on to the next round
            }
        }

        // Query the closest not-yet-queried candidates.
        sort_by_distance(&mut candidates, &info_hash);
        let mut sent_this_round = 0;
        let mut i = 0;
        while i < candidates.len() && sent_this_round < ALPHA && queries_sent < MAX_QUERIES {
            let addr = candidates[i].addr;
            if queried.insert(addr) {
                send_get_peers(&socket, addr, &node_id, &info_hash).await;
                queries_sent += 1;
                sent_this_round += 1;
            }
            i += 1;
        }
        // Don't stop just because this round had no fresh nodes to ask: the
        // bootstrap routers can take longer than one recv window to reply over
        // clearnet UDP, so keep draining until the time budget runs out. Only a
        // full peer set or the deadline ends the lookup.
    }

    Ok(peers.into_iter().take(max_peers).collect())
}

/// Send a `get_peers` query to one node. Errors are ignored (UDP, best-effort).
async fn send_get_peers(
    socket: &UdpSocket,
    addr: SocketAddrV4,
    node_id: &[u8; 20],
    info_hash: &[u8; 20],
) {
    let query = Value::Dict(
        [
            (b"t".to_vec(), Value::Bytes(b"ep".to_vec())),
            (b"y".to_vec(), Value::Bytes(b"q".to_vec())),
            (b"q".to_vec(), Value::Bytes(b"get_peers".to_vec())),
            (
                b"a".to_vec(),
                Value::Dict(
                    [
                        (b"id".to_vec(), Value::Bytes(node_id.to_vec())),
                        (b"info_hash".to_vec(), Value::Bytes(info_hash.to_vec())),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
        ]
        .into_iter()
        .collect(),
    );
    let _ = socket.send_to(&bencode::encode(&query), SocketAddr::V4(addr)).await;
}

/// Parse a KRPC reply: pull `values` (peers) and `nodes` (new candidates).
fn parse_response(
    bytes: &[u8],
    peers: &mut HashSet<SocketAddrV4>,
    candidates: &mut Vec<Contact>,
    queried: &HashSet<SocketAddrV4>,
    info_hash: &[u8; 20],
) {
    let Ok(root) = bencode::decode(bytes) else { return };
    let Some(r) = root.get("r") else { return };

    // `values`: a list of compact 6-byte peer addresses.
    if let Some(Value::List(items)) = r.get("values") {
        for item in items {
            if let Some(b) = item.as_bytes() {
                for p in parse_compact_peers(b) {
                    peers.insert(p);
                }
            }
        }
    }

    // `nodes`: compact 26-byte contacts (20-byte id + 4-byte ip + 2-byte port).
    if let Some(nodes) = r.get("nodes").and_then(Value::as_bytes) {
        for chunk in nodes.chunks_exact(26) {
            let mut id = [0u8; 20];
            id.copy_from_slice(&chunk[0..20]);
            let ip = Ipv4Addr::new(chunk[20], chunk[21], chunk[22], chunk[23]);
            let port = u16::from_be_bytes([chunk[24], chunk[25]]);
            let addr = SocketAddrV4::new(ip, port);
            if port == 0 || queried.contains(&addr) || id == *info_hash {
                continue;
            }
            if !candidates.iter().any(|c| c.addr == addr) {
                candidates.push(Contact { id, addr });
            }
        }
    }
}

/// Decode a run of compact 6-byte peer entries (`ip[4] port[2]`, big-endian).
fn parse_compact_peers(bytes: &[u8]) -> Vec<SocketAddrV4> {
    bytes
        .chunks_exact(6)
        .filter_map(|c| {
            let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            let port = u16::from_be_bytes([c[4], c[5]]);
            (port != 0).then_some(SocketAddrV4::new(ip, port))
        })
        .collect()
}

/// Sort candidates by XOR distance of their id to the target (closest first).
fn sort_by_distance(candidates: &mut [Contact], target: &[u8; 20]) {
    candidates.sort_by(|a, b| xor_distance(&a.id, target).cmp(&xor_distance(&b.id, target)));
}

/// The Kademlia XOR metric as a 20-byte array (compared big-endian).
fn xor_distance(id: &[u8; 20], target: &[u8; 20]) -> [u8; 20] {
    let mut d = [0u8; 20];
    for i in 0..20 {
        d[i] = id[i] ^ target[i];
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_peers_decode() {
        // 1.2.3.4:0x1a2b and 255.0.0.1:80, plus a trailing partial (ignored).
        let bytes = [1, 2, 3, 4, 0x1a, 0x2b, 255, 0, 0, 1, 0, 80, 9, 9];
        let peers = parse_compact_peers(&bytes);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], "1.2.3.4:6699".parse().unwrap());
        assert_eq!(peers[1], "255.0.0.1:80".parse().unwrap());
    }

    #[test]
    fn compact_peers_skip_zero_port() {
        let bytes = [1, 2, 3, 4, 0, 0];
        assert!(parse_compact_peers(&bytes).is_empty());
    }

    #[test]
    fn xor_distance_orders_closest_first() {
        let target = [0u8; 20];
        let mut near = [0u8; 20];
        near[19] = 1;
        let mut far = [0u8; 20];
        far[0] = 1;
        assert!(xor_distance(&near, &target) < xor_distance(&far, &target));

        let mut cands = vec![
            Contact { id: far, addr: "1.1.1.1:1".parse().unwrap() },
            Contact { id: near, addr: "2.2.2.2:2".parse().unwrap() },
        ];
        sort_by_distance(&mut cands, &target);
        assert_eq!(cands[0].addr, "2.2.2.2:2".parse::<SocketAddrV4>().unwrap());
    }

    #[test]
    fn parse_response_collects_values_and_nodes() {
        let mut peers = HashSet::new();
        let mut cands = Vec::new();
        let queried = HashSet::new();
        let ih = [0u8; 20];

        // r = { values: ["<6-byte peer>"], nodes: "<26-byte contact>" }
        let peer = vec![10u8, 0, 0, 5, 0x1f, 0x90]; // 10.0.0.5:8080
        let mut node = vec![7u8; 20];
        node.extend_from_slice(&[192, 168, 1, 9, 0x1a, 0xe1]); // 192.168.1.9:6881
        let r = Value::Dict(
            [
                (b"values".to_vec(), Value::List(vec![Value::Bytes(peer)])),
                (b"nodes".to_vec(), Value::Bytes(node)),
            ]
            .into_iter()
            .collect(),
        );
        let root = Value::Dict([(b"r".to_vec(), r)].into_iter().collect());

        parse_response(&bencode::encode(&root), &mut peers, &mut cands, &queried, &ih);
        assert!(peers.contains(&"10.0.0.5:8080".parse().unwrap()));
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].addr, "192.168.1.9:6881".parse::<SocketAddrV4>().unwrap());
    }
}
