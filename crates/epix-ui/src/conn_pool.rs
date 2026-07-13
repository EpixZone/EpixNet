//! A small pool of warm peer connections, so the dashboard's connection stats
//! (count, incoming/onion split, ping) reflect real live links instead of
//! reading zero. Mirrors EpixNet keeping connections open in its
//! ConnectionServer, but bounded to a handful of peers.

use epix_core::PeerAddr;
use epix_protocol::Connection;
use epix_transport::Transport;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// A live connection plus its last measured ping (ms, `-1` = not yet pinged).
struct PeerConn {
    conn: Arc<Mutex<Connection>>,
    last_ping_ms: Arc<AtomicI64>,
    onion: bool,
}

/// Aggregate connection stats for the chart/collector.
#[derive(Default, Clone, Debug)]
pub struct ConnectionStats {
    pub total: i64,
    /// Incoming connections. This node dials out, so 0 for now.
    pub incoming: i64,
    pub onion: i64,
    pub ping_avg: i64,
    pub ping_min: i64,
}

/// A bounded pool of warm connections keyed by peer address.
pub struct ConnectionPool {
    conns: Mutex<HashMap<PeerAddr, PeerConn>>,
    max: usize,
}

const PING_TIMEOUT: Duration = Duration::from_secs(5);

impl ConnectionPool {
    pub fn new(max: usize) -> Self {
        Self { conns: Mutex::new(HashMap::new()), max }
    }

    /// The peer addresses we currently hold a live connection to.
    pub async fn connected_addrs(&self) -> Vec<PeerAddr> {
        self.conns.lock().await.keys().cloned().collect()
    }

    /// The last ping (ms) recorded for a peer, if connected.
    pub async fn ping_for(&self, addr: &PeerAddr) -> Option<i64> {
        let conns = self.conns.lock().await;
        conns.get(addr).and_then(|c| {
            let v = c.last_ping_ms.load(Ordering::Relaxed);
            (v >= 0).then_some(v)
        })
    }

    /// Open connections to `peers` we are not already connected to, up to the
    /// pool's cap. Clearnet + onion only (mesh peers are skipped here). Peers are
    /// dialed concurrently, so one slow/unreachable peer does not hold up the
    /// rest, and the pool lock is not held while dialing.
    pub async fn ensure(&self, transport: Arc<dyn Transport>, peers: &[PeerAddr]) {
        let (have, room) = {
            let conns = self.conns.lock().await;
            (conns.keys().cloned().collect::<Vec<_>>(), self.max.saturating_sub(conns.len()))
        };
        if room == 0 {
            return;
        }
        // Try a few more than `room` so some failures still fill the slots.
        let to_dial: Vec<PeerAddr> = peers
            .iter()
            .filter(|a| !have.contains(a) && !matches!(a, PeerAddr::Rns(_)))
            .take(room * 3)
            .cloned()
            .collect();
        let mut set = tokio::task::JoinSet::new();
        for addr in to_dial {
            let transport = transport.clone();
            set.spawn(async move {
                let onion = matches!(addr, PeerAddr::Onion { .. });
                // Overlay-aware dial bound: a flat few-second deadline meant
                // the warm pool could never hold an onion/i2p connection.
                let conn = tokio::time::timeout(addr.connect_timeout(), async {
                    let mut conn = Connection::connect(transport.as_ref(), &addr).await.ok()?;
                    conn.handshake().await.ok()?;
                    Some(conn)
                })
                .await
                .ok()
                .flatten();
                conn.map(|conn| (addr, onion, conn))
            });
        }
        while let Some(res) = set.join_next().await {
            let Ok(Some((addr, onion, conn))) = res else { continue };
            let mut conns = self.conns.lock().await;
            if conns.len() >= self.max || conns.contains_key(&addr) {
                continue;
            }
            conns.insert(
                addr,
                PeerConn {
                    conn: Arc::new(Mutex::new(conn)),
                    last_ping_ms: Arc::new(AtomicI64::new(-1)),
                    onion,
                },
            );
        }
    }

    /// Ping every held connection concurrently, updating each ping and dropping
    /// any that fail. The pool lock is not held while pinging.
    pub async fn ping_all(&self) {
        let entries: Vec<(PeerAddr, Arc<Mutex<Connection>>, Arc<AtomicI64>)> = {
            let conns = self.conns.lock().await;
            conns
                .iter()
                .map(|(a, c)| (a.clone(), c.conn.clone(), c.last_ping_ms.clone()))
                .collect()
        };
        let mut set = tokio::task::JoinSet::new();
        for (addr, conn, last_ping) in entries {
            set.spawn(async move {
                let start = Instant::now();
                let mut guard = conn.lock().await;
                let ok = matches!(
                    tokio::time::timeout(PING_TIMEOUT, guard.ping()).await,
                    Ok(Ok(true))
                );
                drop(guard);
                if ok {
                    last_ping.store(start.elapsed().as_millis() as i64, Ordering::Relaxed);
                }
                (addr, ok)
            });
        }
        let mut dead = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok((addr, false)) = res {
                dead.push(addr);
            }
        }
        if !dead.is_empty() {
            let mut conns = self.conns.lock().await;
            for addr in dead {
                conns.remove(&addr);
            }
        }
    }

    /// Current aggregate stats.
    pub async fn stats(&self) -> ConnectionStats {
        let conns = self.conns.lock().await;
        let pings: Vec<i64> = conns
            .values()
            .map(|c| c.last_ping_ms.load(Ordering::Relaxed))
            .filter(|v| *v >= 0)
            .collect();
        let ping_avg =
            if pings.is_empty() { 0 } else { pings.iter().sum::<i64>() / pings.len() as i64 };
        let ping_min = pings.iter().copied().min().unwrap_or(0);
        ConnectionStats {
            total: conns.len() as i64,
            incoming: 0,
            onion: conns.values().filter(|c| c.onion).count() as i64,
            ping_avg,
            ping_min,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_protocol::msg::{read_msg, send_msg, vget, vmap};
    use epix_transport::TcpTransport;
    use rmpv::Value as RVal;
    use tokio::net::TcpListener;

    /// A mock peer that answers handshake + ping, so the pool can connect to it.
    async fn spawn_mock_peer() -> PeerAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut stream: epix_transport::PeerStream = Box::pin(sock);
                    let mut buf = Vec::new();
                    while let Ok(req) = read_msg(&mut stream, &mut buf).await {
                        let cmd = vget(&req, "cmd").and_then(|v| v.as_str()).unwrap_or("");
                        let req_id = vget(&req, "req_id").and_then(|v| v.as_i64()).unwrap_or(0);
                        let resp = match cmd {
                            "handshake" => vmap(vec![
                                ("cmd", RVal::from("response")),
                                ("to", RVal::from(req_id)),
                                ("protocol", RVal::from("v2")),
                                ("peer_id", RVal::from("-Mock-000000000001")),
                                ("crypt_supported", RVal::Array(vec![])),
                            ]),
                            "ping" => vmap(vec![
                                ("cmd", RVal::from("response")),
                                ("to", RVal::from(req_id)),
                                ("body", RVal::from("Pong!")),
                            ]),
                            _ => vmap(vec![
                                ("cmd", RVal::from("response")),
                                ("to", RVal::from(req_id)),
                                ("error", RVal::from("?")),
                            ]),
                        };
                        if send_msg(&mut stream, &resp).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        PeerAddr::Ip(addr)
    }

    #[tokio::test]
    async fn pool_connects_pings_and_reports_stats() {
        let peer = spawn_mock_peer().await;
        let pool = ConnectionPool::new(4);
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport);

        pool.ensure(transport.clone(), &[peer.clone()]).await;
        assert_eq!(pool.stats().await.total, 1, "connected to the mock peer");

        pool.ping_all().await;
        let stats = pool.stats().await;
        assert_eq!(stats.total, 1);
        assert_eq!(stats.incoming, 0);
        assert_eq!(stats.onion, 0);
        assert!(pool.ping_for(&peer).await.is_some(), "ping recorded");
        assert!(stats.ping_avg >= 0 && stats.ping_min >= 0);

        // ensure is idempotent - no duplicate connection to the same peer.
        pool.ensure(transport, &[peer.clone()]).await;
        assert_eq!(pool.stats().await.total, 1);
    }

    #[tokio::test]
    async fn pool_respects_the_cap_and_skips_mesh_peers() {
        let pool = ConnectionPool::new(1);
        let p1 = spawn_mock_peer().await;
        let p2 = spawn_mock_peer().await;
        let transport: Arc<dyn Transport> = Arc::new(TcpTransport);
        // A mesh (Rns) peer is skipped; the cap of 1 is honoured.
        pool.ensure(transport, &[PeerAddr::Rns([0u8; 16]), p1, p2]).await;
        assert_eq!(pool.stats().await.total, 1);
    }
}
