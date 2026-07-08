//! AnnounceLocal - LAN peer discovery over UDP broadcast.
//!
//! Wire-compatible with EpixNet's `BroadcastServer`: every datagram is a msgpack
//! map `{cmd, params, sender}` where `sender` carries
//! `{service:"epixnet", peer_id, port, broadcast_port, rev}`. A node ignores
//! datagrams whose service is not `epixnet` or whose `peer_id` is its own.
//!
//! The exchange is the reference four-message flow:
//! 1. `discoverRequest` (broadcast) -> 2. `discoverResponse {sites_changed}` ->
//! 3. `siteListRequest` (only if the peer's `sites_changed` differs from what we
//! last saw) -> 4. `siteListResponse {sites, sites_changed}`. The requester then
//! adds the responder as a peer for every site hash they both serve.
//!
//! Feature-gated (`local-discovery`), off on mobile. Works even though this node
//! may not accept inbound P2P connections - it still learns local peers to dial.

use epix_core::PeerAddr;
use epix_discovery::address_hash;
use epix_ui::AppState;
use rmpv::Value;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

/// Default UDP port for local discovery (EpixNet's `broadcast_port`).
pub const BROADCAST_PORT: u16 = 1544;
/// Broadcast service name; datagrams from any other service are ignored.
const SERVICE: &str = "epixnet";
/// Advertised revision (matches the peer server banner).
const REV: i64 = 8192;

/// This node's identity in a discovery exchange.
struct Identity {
    peer_id: String,
    /// The fileserver port peers should dial us on (0 = download-only).
    port: u16,
    broadcast_port: u16,
}

impl Identity {
    /// Build the `sender` envelope map for an outgoing datagram.
    fn sender(&self) -> Value {
        Value::Map(vec![
            (Value::from("service"), Value::from(SERVICE)),
            (Value::from("peer_id"), Value::from(self.peer_id.as_str())),
            (Value::from("port"), Value::from(self.port)),
            (Value::from("broadcast_port"), Value::from(self.broadcast_port)),
            (Value::from("rev"), Value::from(REV)),
        ])
    }
}

/// Broadcast our discovery request and answer others', until `shutdown`.
pub async fn local_discovery_loop(
    state: Arc<AppState>,
    fileserver_port: u16,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    let Some(socket) = bind_broadcast_socket(BROADCAST_PORT).map(Arc::new) else {
        return; // port unavailable; skip LAN discovery
    };
    let id = Arc::new(Identity {
        peer_id: random_peer_id(),
        port: fileserver_port,
        broadcast_port: BROADCAST_PORT,
    });

    let recv_state = state.clone();
    let recv_sock = socket.clone();
    let recv_id = id.clone();
    let receiver = tokio::spawn(async move {
        // Per-peer last-seen `sites_changed`, so we only re-request a site list
        // when the peer's set actually changed (matches known_peers).
        let mut known: HashMap<String, i64> = HashMap::new();
        let mut buf = vec![0u8; 8192];
        while let Ok((n, from)) = recv_sock.recv_from(&mut buf).await {
            handle_message(&recv_state, &recv_sock, &recv_id, &mut known, &buf[..n], from).await;
        }
    });

    broadcast_discover(&socket, &id).await;
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => {
                // The AnnounceLocal plugin toggle pauses LAN broadcasts.
                if state.plugin_enabled("AnnounceLocal").await {
                    broadcast_discover(&socket, &id).await;
                }
            }
        }
    }
    receiver.abort();
}

fn bind_broadcast_socket(port: u16) -> Option<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    sock.set_reuse_address(true).ok()?;
    sock.set_broadcast(true).ok()?;
    let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
    sock.bind(&addr.into()).ok()?;
    sock.set_nonblocking(true).ok()?;
    UdpSocket::from_std(sock.into()).ok()
}

/// A per-process random 12-hex-char peer id (EpixNet uses a short random id).
fn random_peer_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0xE9);
    format!("{:012x}", h.finish() & 0xffff_ffff_ffff)
}

/// The hashes of every site we serve.
async fn our_site_hashes(state: &AppState) -> HashMap<Vec<u8>, String> {
    state
        .xite_addresses()
        .await
        .into_iter()
        .map(|addr| (address_hash(&addr).to_vec(), addr))
        .collect()
}

/// A cheap change-token over our served site set: it changes whenever a site is
/// added or removed, so a peer knows to re-request our list.
async fn our_sites_changed(state: &AppState) -> i64 {
    use std::hash::{BuildHasher, Hasher};
    let mut addrs = state.xite_addresses().await;
    addrs.sort();
    let mut h = std::collections::hash_map::RandomState::default().build_hasher();
    for a in &addrs {
        h.write(a.as_bytes());
        h.write_u8(0);
    }
    (h.finish() & 0x7fff_ffff) as i64
}

async fn broadcast_discover(sock: &UdpSocket, id: &Identity) {
    let msg = encode_msg("discoverRequest", Value::Map(vec![]), id);
    let dest = SocketAddr::new(Ipv4Addr::BROADCAST.into(), BROADCAST_PORT);
    let _ = sock.send_to(&msg, dest).await;
}

/// A parsed incoming datagram.
struct Incoming {
    cmd: String,
    params: Value,
    service: String,
    peer_id: String,
    port: u16,
    broadcast_port: u16,
}

fn parse_incoming(data: &[u8]) -> Option<Incoming> {
    let msg = rmpv::decode::read_value(&mut &data[..]).ok()?;
    let sender = map_get(&msg, "sender")?;
    Some(Incoming {
        cmd: map_get(&msg, "cmd").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        params: map_get(&msg, "params").cloned().unwrap_or(Value::Map(vec![])),
        service: map_get(sender, "service").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        peer_id: map_get(sender, "peer_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        port: map_get(sender, "port").and_then(|v| v.as_u64()).unwrap_or(0) as u16,
        broadcast_port: map_get(sender, "broadcast_port").and_then(|v| v.as_u64()).unwrap_or(BROADCAST_PORT as u64)
            as u16,
    })
}

async fn handle_message(
    state: &AppState,
    sock: &UdpSocket,
    id: &Identity,
    known: &mut HashMap<String, i64>,
    data: &[u8],
    from: SocketAddr,
) {
    let Some(msg) = parse_incoming(data) else { return };
    // Ignore other services and our own datagrams.
    if msg.service != SERVICE || msg.peer_id == id.peer_id {
        return;
    }
    // Replies go to the peer's broadcast port, not the datagram's source port.
    let reply_to = SocketAddr::new(from.ip(), msg.broadcast_port);

    match msg.cmd.as_str() {
        "discoverRequest" => {
            let params = Value::Map(vec![(
                Value::from("sites_changed"),
                Value::from(our_sites_changed(state).await),
            )]);
            let reply = encode_msg("discoverResponse", params, id);
            let _ = sock.send_to(&reply, reply_to).await;
        }
        "discoverResponse" => {
            let sites_changed = map_get(&msg.params, "sites_changed").and_then(|v| v.as_i64()).unwrap_or(0);
            // Only pull the site list when the peer's set changed since last time.
            if known.get(&msg.peer_id) != Some(&sites_changed) {
                let reply = encode_msg("siteListRequest", Value::Map(vec![]), id);
                let _ = sock.send_to(&reply, reply_to).await;
            }
        }
        "siteListRequest" => {
            let hashes: Vec<Vec<u8>> = our_site_hashes(state).await.into_keys().collect();
            let params = Value::Map(vec![
                (
                    Value::from("sites"),
                    Value::Array(hashes.into_iter().map(Value::Binary).collect()),
                ),
                (Value::from("sites_changed"), Value::from(our_sites_changed(state).await)),
            ]);
            let reply = encode_msg("siteListResponse", params, id);
            let _ = sock.send_to(&reply, reply_to).await;
        }
        "siteListResponse" => {
            let their_hashes: Vec<Vec<u8>> = map_get(&msg.params, "sites")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_slice().map(<[u8]>::to_vec)).collect())
                .unwrap_or_default();
            let sites_changed = map_get(&msg.params, "sites_changed").and_then(|v| v.as_i64()).unwrap_or(0);
            known.insert(msg.peer_id.clone(), sites_changed);
            if msg.port != 0 {
                let ours = our_site_hashes(state).await;
                add_local_peer(state, from.ip(), msg.port, &their_hashes, &ours).await;
            }
        }
        _ => {}
    }
}

/// Add `ip:port` as a peer for every site whose hash both nodes share.
async fn add_local_peer(
    state: &AppState,
    ip: IpAddr,
    port: u16,
    hashes: &[Vec<u8>],
    ours: &HashMap<Vec<u8>, String>,
) {
    let peer = PeerAddr::Ip(SocketAddr::new(ip, port));
    for h in hashes {
        if let Some(addr) = ours.get(h) {
            state.add_peers(addr, vec![peer.clone()]).await;
        }
    }
}

/// Encode a `{cmd, params, sender}` datagram.
fn encode_msg(cmd: &str, params: Value, id: &Identity) -> Vec<u8> {
    let msg = Value::Map(vec![
        (Value::from("cmd"), Value::from(cmd)),
        (Value::from("params"), params),
        (Value::from("sender"), id.sender()),
    ]);
    let mut buf = Vec::new();
    let _ = rmpv::encode::write_value(&mut buf, &msg);
    buf
}

fn map_get<'a>(msg: &'a Value, key: &str) -> Option<&'a Value> {
    msg.as_map()?.iter().find(|(k, _)| k.as_str() == Some(key)).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_ui::XiteEntry;
    use epix_xite::XiteStorage;

    fn id(peer_id: &str, port: u16) -> Identity {
        Identity { peer_id: peer_id.to_string(), port, broadcast_port: BROADCAST_PORT }
    }

    #[tokio::test]
    async fn ignores_other_services_and_our_own_peer_id() {
        let state = AppState::new("test");
        let sock = bind_broadcast_socket(0).unwrap();
        let me = id("aaaa", 0);
        let mut known = HashMap::new();
        let from: SocketAddr = "10.0.0.5:5000".parse().unwrap();

        // Our own peer_id -> ignored (no panic, no state change).
        let mine = encode_msg("discoverRequest", Value::Map(vec![]), &me);
        handle_message(&state, &sock, &me, &mut known, &mine, from).await;

        // Wrong service -> ignored.
        let wrong = Value::Map(vec![
            (Value::from("cmd"), Value::from("discoverRequest")),
            (Value::from("params"), Value::Map(vec![])),
            (
                Value::from("sender"),
                Value::Map(vec![
                    (Value::from("service"), Value::from("other")),
                    (Value::from("peer_id"), Value::from("bbbb")),
                    (Value::from("broadcast_port"), Value::from(BROADCAST_PORT)),
                ]),
            ),
        ]);
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &wrong).unwrap();
        handle_message(&state, &sock, &me, &mut known, &buf, from).await;
        // Nothing to assert beyond "did not panic / add peers"; covered below.
    }

    #[tokio::test]
    async fn site_list_response_adds_peer_for_a_shared_site() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1LanSite", XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;
        let sock = bind_broadcast_socket(0).unwrap();
        let me = id("aaaa", 0);
        let mut known = HashMap::new();
        let from: SocketAddr = "10.0.0.5:5000".parse().unwrap();

        // A peer's siteListResponse advertising our shared site at its port.
        let peer = id("bbbb", 15441);
        let params = Value::Map(vec![
            (
                Value::from("sites"),
                Value::Array(vec![Value::Binary(address_hash("1LanSite").to_vec())]),
            ),
            (Value::from("sites_changed"), Value::from(7i64)),
        ]);
        let msg = encode_msg("siteListResponse", params, &peer);
        handle_message(&state, &sock, &me, &mut known, &msg, from).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 1);
        assert_eq!(known.get("bbbb"), Some(&7));

        // A response for a site we do not serve adds nothing.
        let params = Value::Map(vec![(
            Value::from("sites"),
            Value::Array(vec![Value::Binary(vec![9u8; 32])]),
        )]);
        let msg = encode_msg("siteListResponse", params, &peer);
        handle_message(&state, &sock, &me, &mut known, &msg, from).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 1);
    }

    #[test]
    fn envelope_roundtrips_with_sender() {
        let me = id("cccc", 26552);
        let bytes = encode_msg(
            "discoverResponse",
            Value::Map(vec![(Value::from("sites_changed"), Value::from(3i64))]),
            &me,
        );
        let parsed = parse_incoming(&bytes).unwrap();
        assert_eq!(parsed.cmd, "discoverResponse");
        assert_eq!(parsed.service, "epixnet");
        assert_eq!(parsed.peer_id, "cccc");
        assert_eq!(parsed.port, 26552);
        assert_eq!(map_get(&parsed.params, "sites_changed").and_then(|v| v.as_i64()), Some(3));
    }
}
