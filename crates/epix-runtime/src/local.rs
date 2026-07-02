//! AnnounceLocal - LAN peer discovery over UDP broadcast.
//!
//! Each node broadcasts the address hashes of the sites it serves; a node that
//! shares any of them replies, and both add the other as a peer. Feature-gated
//! (`local-discovery`), off on mobile per the plan. Discovery works even though
//! this node does not accept incoming P2P connections - it learns other local
//! peers to connect to.

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

/// Default UDP port for local discovery (matches EpixNet's `broadcast_port`).
pub const BROADCAST_PORT: u16 = 1544;

/// Broadcast our sites and add discovered local peers, until `shutdown`.
pub async fn local_discovery_loop(
    state: Arc<AppState>,
    fileserver_port: u16,
    shutdown: Arc<Notify>,
    period: Duration,
) {
    let Some(socket) = bind_broadcast_socket(BROADCAST_PORT).map(Arc::new) else {
        return; // port unavailable; skip LAN discovery
    };
    let recv_state = state.clone();
    let recv_sock = socket.clone();
    let receiver = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        while let Ok((n, from)) = recv_sock.recv_from(&mut buf).await {
            handle_message(&recv_state, &recv_sock, &buf[..n], from, fileserver_port).await;
        }
    });

    broadcast_discover(&state, &socket, fileserver_port).await;
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            _ = tick.tick() => broadcast_discover(&state, &socket, fileserver_port).await,
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

/// Map of `address_hash -> serving address` for every site we serve.
async fn our_site_hashes(state: &AppState) -> HashMap<Vec<u8>, String> {
    state
        .xite_addresses()
        .await
        .into_iter()
        .map(|addr| (address_hash(&addr).to_vec(), addr))
        .collect()
}

async fn broadcast_discover(state: &AppState, sock: &UdpSocket, our_port: u16) {
    let hashes: Vec<Vec<u8>> = our_site_hashes(state).await.into_keys().collect();
    if hashes.is_empty() {
        return;
    }
    let msg = encode_msg("discoverRequest", our_port, &hashes);
    let dest = SocketAddr::new(Ipv4Addr::BROADCAST.into(), BROADCAST_PORT);
    let _ = sock.send_to(&msg, dest).await;
}

async fn handle_message(
    state: &AppState,
    sock: &UdpSocket,
    data: &[u8],
    from: SocketAddr,
    our_port: u16,
) {
    let Ok(msg) = rmpv::decode::read_value(&mut &data[..]) else { return };
    let cmd = map_get(&msg, "cmd").and_then(|v| v.as_str()).unwrap_or("");
    let their_port = map_get(&msg, "port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let their_hashes = map_get(&msg, "sites")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_slice().map(|s| s.to_vec())).collect::<Vec<_>>())
        .unwrap_or_default();
    if their_port == 0 {
        return;
    }
    let ours = our_site_hashes(state).await;

    match cmd {
        "discoverRequest" => {
            let matching: Vec<Vec<u8>> =
                their_hashes.iter().filter(|h| ours.contains_key(*h)).cloned().collect();
            if matching.is_empty() {
                return;
            }
            add_local_peer(state, from.ip(), their_port, &matching, &ours).await;
            let reply = encode_msg("discoverResponse", our_port, &matching);
            let _ = sock.send_to(&reply, from).await;
        }
        "discoverResponse" => {
            add_local_peer(state, from.ip(), their_port, &their_hashes, &ours).await;
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

fn encode_msg(cmd: &str, port: u16, hashes: &[Vec<u8>]) -> Vec<u8> {
    let sites = Value::Array(hashes.iter().map(|h| Value::Binary(h.clone())).collect());
    let msg = Value::Map(vec![
        (Value::from("cmd"), Value::from(cmd)),
        (Value::from("port"), Value::from(port)),
        (Value::from("sites"), sites),
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

    #[tokio::test]
    async fn discover_response_adds_peer_for_a_shared_site() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1LanSite", XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
            .await;
        let sock = bind_broadcast_socket(0).expect("bind udp");

        // A local node responds advertising our site at its ip:port.
        let hash = address_hash("1LanSite").to_vec();
        let msg = encode_msg("discoverResponse", 15441, &[hash]);
        let from: SocketAddr = "10.0.0.5:5000".parse().unwrap();
        handle_message(&state, &sock, &msg, from, 0).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 1, "the LAN peer was added");

        // A response for a site we do not serve adds nothing.
        let other = encode_msg("discoverResponse", 15441, &[vec![9u8; 32]]);
        handle_message(&state, &sock, &other, from, 0).await;
        assert_eq!(state.peer_counts("1LanSite").await.total, 1);
    }
}
