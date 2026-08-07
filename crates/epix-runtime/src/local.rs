//! AnnounceLocal - LAN peer discovery over UDP broadcast.
//!
//! A separate little protocol from the peer wire: every datagram is a postcard
//! [`Msg`] carrying a command, its params, and a `sender` envelope
//! (`{service:"epixnet", peer_id, port, broadcast_port, rev}`). A node ignores
//! datagrams whose service is not `epixnet` or whose `peer_id` is its own.
//!
//! COMPATIBILITY RULE: postcard encodes enum variants by index and struct
//! fields positionally, so [`Cmd`] variants and [`Msg`]/[`Sender`]/[`Params`]
//! fields may only ever be APPENDED - never reordered, renamed-in-place, or
//! removed - or nodes on different releases stop seeing each other on the LAN.
//!
//! The exchange is the reference four-message flow:
//! 1. `DiscoverRequest` (broadcast) -> 2. `DiscoverResponse {sites_changed}` ->
//!    3. `SiteListRequest` (only if the peer's `sites_changed` differs from what
//!    we last saw) -> 4. `SiteListResponse {sites, sites_changed}`. The
//!    requester then adds the responder as a peer for every site hash they both
//!    serve.
//!
//! Compiled into every build (`local-discovery`), phones included, so an
//! isolated or air-gapped LAN works without a custom build - this is the one
//! discovery path that needs no internet, no tracker and no DHT. It is off
//! until the `local_discovery` config key turns it on: a participating node
//! answers any stranger's request with the hashes of every xite it serves.
//! Works even though this node may not accept inbound P2P connections - it
//! still learns local peers to dial.
//!
//! Two switches, deliberately: `local_discovery` (config, restart) decides
//! whether this loop exists at all, and the `AnnounceLocal` plugin toggle is
//! the live pause - it stops both our broadcasts and our replies.

use epix_core::PeerAddr;
use epix_discovery::address_hash;
use epix_ui::AppState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

/// Default UDP port for local discovery.
pub const BROADCAST_PORT: u16 = 1544;
/// Broadcast service name; datagrams from any other service are ignored.
const SERVICE: &str = "epixnet";
/// Advertised revision.
const REV: i64 = 8192;

/// Which of the four messages a datagram is. APPEND-ONLY (postcard indices).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Cmd {
    DiscoverRequest,
    DiscoverResponse,
    SiteListRequest,
    SiteListResponse,
}

/// Who sent a datagram. APPEND-ONLY (postcard field order).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Sender {
    service: String,
    peer_id: String,
    /// The fileserver port peers should dial us on (0 = download-only).
    port: u16,
    broadcast_port: u16,
    rev: i64,
}

/// The union of every message's body; unused fields stay empty. Flat rather
/// than per-command so appending a field never shifts another command's
/// layout. APPEND-ONLY (postcard field order).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Params {
    /// A change token over the sender's served-site set.
    sites_changed: i64,
    /// The sender's served-site hashes (`SiteListResponse` only).
    sites: Vec<[u8; 32]>,
}

/// One datagram. APPEND-ONLY (postcard field order).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Msg {
    cmd: Cmd,
    params: Params,
    sender: Sender,
}

/// This node's identity in a discovery exchange.
struct Identity {
    peer_id: String,
    port: u16,
    broadcast_port: u16,
}

impl Identity {
    /// The `sender` envelope for an outgoing datagram.
    fn sender(&self) -> Sender {
        Sender {
            service: SERVICE.to_string(),
            peer_id: self.peer_id.clone(),
            port: self.port,
            broadcast_port: self.broadcast_port,
            rev: REV,
        }
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
            // The AnnounceLocal toggle silences inbound handling too, not just
            // our own broadcasts: answering a DiscoverRequest/SiteListRequest
            // hands the asker our served-xite hashes, so a node with the plugin
            // off must not reply either. Drop the datagram unread.
            if !recv_state.plugin_enabled("AnnounceLocal").await {
                continue;
            }
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

/// A per-process random 12-hex-char peer id.
fn random_peer_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u8(0xE9);
    format!("{:012x}", h.finish() & 0xffff_ffff_ffff)
}

/// The hashes of every site we serve.
async fn our_site_hashes(state: &AppState) -> HashMap<[u8; 32], String> {
    state
        .xite_addresses()
        .await
        .into_iter()
        .map(|addr| (address_hash(&addr), addr))
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
    let msg = encode_msg(Cmd::DiscoverRequest, Params::default(), id);
    let dest = SocketAddr::new(Ipv4Addr::BROADCAST.into(), BROADCAST_PORT);
    let _ = sock.send_to(&msg, dest).await;
}

async fn handle_message(
    state: &AppState,
    sock: &UdpSocket,
    id: &Identity,
    known: &mut HashMap<String, i64>,
    data: &[u8],
    from: SocketAddr,
) {
    let Ok(msg) = postcard::from_bytes::<Msg>(data) else { return };
    // Ignore other services and our own datagrams.
    if msg.sender.service != SERVICE || msg.sender.peer_id == id.peer_id {
        return;
    }
    // Replies go to the peer's broadcast port, not the datagram's source port.
    let reply_to = SocketAddr::new(from.ip(), msg.sender.broadcast_port);

    match msg.cmd {
        Cmd::DiscoverRequest => {
            let params =
                Params { sites_changed: our_sites_changed(state).await, ..Params::default() };
            let reply = encode_msg(Cmd::DiscoverResponse, params, id);
            let _ = sock.send_to(&reply, reply_to).await;
        }
        Cmd::DiscoverResponse => {
            // Only pull the site list when the peer's set changed since last time.
            if known.get(&msg.sender.peer_id) != Some(&msg.params.sites_changed) {
                let reply = encode_msg(Cmd::SiteListRequest, Params::default(), id);
                let _ = sock.send_to(&reply, reply_to).await;
            }
        }
        Cmd::SiteListRequest => {
            let params = Params {
                sites: our_site_hashes(state).await.into_keys().collect(),
                sites_changed: our_sites_changed(state).await,
            };
            let reply = encode_msg(Cmd::SiteListResponse, params, id);
            let _ = sock.send_to(&reply, reply_to).await;
        }
        Cmd::SiteListResponse => {
            known.insert(msg.sender.peer_id.clone(), msg.params.sites_changed);
            if msg.sender.port != 0 {
                let ours = our_site_hashes(state).await;
                add_local_peer(state, from.ip(), msg.sender.port, &msg.params.sites, &ours).await;
            }
        }
    }
}

/// Add `ip:port` as a peer for every site whose hash both nodes share.
async fn add_local_peer(
    state: &AppState,
    ip: IpAddr,
    port: u16,
    hashes: &[[u8; 32]],
    ours: &HashMap<[u8; 32], String>,
) {
    let peer = PeerAddr::Ip(SocketAddr::new(ip, port));
    for h in hashes {
        if let Some(addr) = ours.get(h) {
            state.add_peers(addr, vec![peer.clone()]).await;
        }
    }
}

/// Encode one datagram. An encode failure can only mean an out-of-memory
/// allocator, so an empty (undecodable) datagram is a fine last resort.
fn encode_msg(cmd: Cmd, params: Params, id: &Identity) -> Vec<u8> {
    let msg = Msg { cmd, params, sender: id.sender() };
    postcard::to_stdvec(&msg).unwrap_or_default()
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
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1LanSite", XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;
        let sock = bind_broadcast_socket(0).unwrap();
        let me = id("aaaa", 0);
        let mut known = HashMap::new();
        let from: SocketAddr = "10.0.0.5:5000".parse().unwrap();
        let shared = Params {
            sites: vec![address_hash("1LanSite")],
            sites_changed: 7,
        };

        // Our own peer_id -> ignored, even though the site matches.
        let mine = encode_msg(Cmd::SiteListResponse, shared.clone(), &id("aaaa", 15441));
        handle_message(&state, &sock, &me, &mut known, &mine, from).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 0);

        // Wrong service -> ignored.
        let mut wrong = Msg {
            cmd: Cmd::SiteListResponse,
            params: shared,
            sender: id("bbbb", 15441).sender(),
        };
        wrong.sender.service = "other".into();
        let bytes = postcard::to_stdvec(&wrong).unwrap();
        handle_message(&state, &sock, &me, &mut known, &bytes, from).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 0);
        assert!(known.is_empty());
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

        // A peer's SiteListResponse advertising our shared site at its port.
        let peer = id("bbbb", 15441);
        let params = Params { sites: vec![address_hash("1LanSite")], sites_changed: 7 };
        let msg = encode_msg(Cmd::SiteListResponse, params, &peer);
        handle_message(&state, &sock, &me, &mut known, &msg, from).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 1);
        assert_eq!(known.get("bbbb"), Some(&7));

        // A response for a site we do not serve adds nothing.
        let params = Params { sites: vec![[9u8; 32]], ..Params::default() };
        let msg = encode_msg(Cmd::SiteListResponse, params, &peer);
        handle_message(&state, &sock, &me, &mut known, &msg, from).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 1);
    }

    #[test]
    fn envelope_roundtrips_with_sender() {
        let me = id("cccc", 26552);
        let bytes =
            encode_msg(Cmd::DiscoverResponse, Params { sites_changed: 3, ..Params::default() }, &me);
        let parsed: Msg = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.cmd, Cmd::DiscoverResponse);
        assert_eq!(parsed.sender.service, "epixnet");
        assert_eq!(parsed.sender.peer_id, "cccc");
        assert_eq!(parsed.sender.port, 26552);
        assert_eq!(parsed.params.sites_changed, 3);
    }

    /// The postcard variant indices are the wire: pin them so an insertion in
    /// the middle of `Cmd` is caught here rather than by two releases that
    /// cannot see each other on the LAN.
    #[test]
    fn cmd_wire_indices_frozen() {
        for (i, cmd) in [
            Cmd::DiscoverRequest,
            Cmd::DiscoverResponse,
            Cmd::SiteListRequest,
            Cmd::SiteListResponse,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(postcard::to_stdvec(&cmd).unwrap(), vec![i as u8], "{cmd:?}");
        }
    }
}
