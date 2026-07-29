//! A small pool of warm peer connections, so the dashboard's connection stats
//! (count, incoming/onion split, ping) reflect real live links instead of
//! reading zero. Mirrors EpixNet keeping connections open in its
//! ConnectionServer, but bounded to a handful of peers.
//!
//! The links themselves are EDX links, opened by the runtime through
//! [`LinkOpener`]. epix-ui holds no transport or protocol code, so the pool
//! only sees the two things it needs: a ping and a version string.

use async_trait::async_trait;
use epix_core::PeerAddr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// One live EDX link the pool keeps warm. Liveness and RTT only - content
/// transfer runs on its own links through the `EdxFetcher`.
#[async_trait]
pub trait PeerLink: Send + Sync {
    /// The peer's advertised client version, from its EDX Hello.
    fn version(&self) -> &str;
    /// Round-trip a frame-level Ping and return the RTT in ms. `Err` means the
    /// link is dead and the pool should drop it.
    async fn ping(&self) -> Result<i64, String>;
}

/// Opens warm links for the pool. The runtime installs one (it owns the EDX
/// client and the transports); without it the pool simply stays empty.
#[async_trait]
pub trait LinkOpener: Send + Sync {
    async fn open_link(&self, peer: PeerAddr) -> Result<Arc<dyn PeerLink>, String>;
}

/// A live link plus its last measured ping (ms, `-1` = not yet pinged).
struct PeerConn {
    link: Arc<dyn PeerLink>,
    last_ping_ms: Arc<AtomicI64>,
    /// The peer's client version, copied out at connect time so the Stats page
    /// renders it without touching the link.
    version: String,
}

/// One live pooled connection, as the Stats page lists it.
pub struct ConnDetail {
    pub addr: PeerAddr,
    pub ping_ms: Option<i64>,
    pub version: String,
}

/// Aggregate connection stats for the chart/collector and status endpoints.
/// Built from the process-wide connection registry
/// (`epix_protocol::registry`), so it covers every real link - warm pool,
/// worker/resync fetches, and inbound peers - not just the pool.
#[derive(Default, Clone, Debug)]
pub struct ConnectionStats {
    pub total: i64,
    /// Live inbound connections (peers that dialed us).
    pub incoming: i64,
    /// Per-network split (clearnet + onion + i2p + mesh = total).
    pub clearnet: i64,
    pub onion: i64,
    pub i2p: i64,
    pub mesh: i64,
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

    /// Open links to `peers` we are not already connected to, up to the pool's
    /// cap. Clearnet + onion only (mesh peers are skipped here). Peers are
    /// dialed concurrently, so one slow/unreachable peer does not hold up the
    /// rest, and the pool lock is not held while dialing.
    pub async fn ensure(&self, opener: Arc<dyn LinkOpener>, peers: &[PeerAddr]) {
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
            let opener = opener.clone();
            // The opener applies its own overlay-aware dial bound, so an
            // onion/i2p peer is not cut off by a clearnet-sized deadline.
            set.spawn(async move { opener.open_link(addr.clone()).await.ok().map(|l| (addr, l)) });
        }
        while let Some(res) = set.join_next().await {
            let Ok(Some((addr, link))) = res else { continue };
            let mut conns = self.conns.lock().await;
            if conns.len() >= self.max || conns.contains_key(&addr) {
                continue;
            }
            let version = link.version().to_string();
            conns.insert(
                addr,
                PeerConn { link, last_ping_ms: Arc::new(AtomicI64::new(-1)), version },
            );
        }
    }

    /// One row per live connection: address, last ping, and the peer's client
    /// version - what the Stats page shows so an operator can see which node
    /// versions the network runs (Phase 6 handshake surfacing).
    pub async fn connection_details(&self) -> Vec<ConnDetail> {
        let conns = self.conns.lock().await;
        let mut out: Vec<ConnDetail> = conns
            .iter()
            .map(|(addr, c)| {
                let v = c.last_ping_ms.load(Ordering::Relaxed);
                ConnDetail {
                    addr: addr.clone(),
                    ping_ms: (v >= 0).then_some(v),
                    version: c.version.clone(),
                }
            })
            .collect();
        // Stable order for the page: by address string.
        out.sort_by_key(|d| d.addr.to_string());
        out
    }

    /// Ping every held connection concurrently, updating each ping and dropping
    /// any that fail. The pool lock is not held while pinging.
    pub async fn ping_all(&self) {
        let entries: Vec<(PeerAddr, Arc<dyn PeerLink>, Arc<AtomicI64>)> = {
            let conns = self.conns.lock().await;
            conns
                .iter()
                .map(|(a, c)| (a.clone(), c.link.clone(), c.last_ping_ms.clone()))
                .collect()
        };
        let mut set = tokio::task::JoinSet::new();
        for (addr, link, last_ping) in entries {
            set.spawn(async move {
                match tokio::time::timeout(PING_TIMEOUT, link.ping()).await {
                    Ok(Ok(ms)) => {
                        last_ping.store(ms, Ordering::Relaxed);
                        (addr, true)
                    }
                    _ => (addr, false),
                }
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

    /// How many connections the pool currently holds.
    pub async fn len(&self) -> usize {
        self.conns.lock().await.len()
    }

    /// Whether the pool holds no connections.
    pub async fn is_empty(&self) -> bool {
        self.conns.lock().await.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link that answers pings until `alive` is cleared.
    struct MockLink {
        version: String,
        alive: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl PeerLink for MockLink {
        fn version(&self) -> &str {
            &self.version
        }
        async fn ping(&self) -> Result<i64, String> {
            if self.alive.load(Ordering::Relaxed) {
                Ok(7)
            } else {
                Err("link closed".into())
            }
        }
    }

    struct MockOpener {
        alive: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl LinkOpener for MockOpener {
        async fn open_link(&self, peer: PeerAddr) -> Result<Arc<dyn PeerLink>, String> {
            // Mesh peers must never reach the opener.
            assert!(!matches!(peer, PeerAddr::Rns(_)), "mesh peers are skipped by the pool");
            Ok(Arc::new(MockLink { version: "0.9.9".into(), alive: self.alive.clone() }))
        }
    }

    fn opener() -> (Arc<dyn LinkOpener>, Arc<std::sync::atomic::AtomicBool>) {
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        (Arc::new(MockOpener { alive: alive.clone() }), alive)
    }

    #[tokio::test]
    async fn pool_connects_pings_and_reports_details() {
        let peer = PeerAddr::parse("127.0.0.1:11111").unwrap();
        let pool = ConnectionPool::new(4);
        let (opener, alive) = opener();

        pool.ensure(opener.clone(), &[peer.clone()]).await;
        assert_eq!(pool.len().await, 1, "opened a link to the peer");

        pool.ping_all().await;
        assert_eq!(pool.len().await, 1);
        assert_eq!(pool.ping_for(&peer).await, Some(7), "ping recorded");

        // ensure is idempotent - no duplicate connection to the same peer.
        pool.ensure(opener, &[peer.clone()]).await;
        assert_eq!(pool.len().await, 1);

        // The peer's version is retained for the Stats page.
        let details = pool.connection_details().await;
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].version, "0.9.9");
        assert_eq!(details[0].ping_ms, Some(7));

        // A link that stops answering is dropped from the pool.
        alive.store(false, Ordering::Relaxed);
        pool.ping_all().await;
        assert!(pool.is_empty().await, "a dead link is evicted");
    }

    #[tokio::test]
    async fn pool_respects_the_cap_and_skips_mesh_peers() {
        let pool = ConnectionPool::new(1);
        let (opener, _alive) = opener();
        let p1 = PeerAddr::parse("127.0.0.1:11111").unwrap();
        let p2 = PeerAddr::parse("127.0.0.1:11112").unwrap();
        // A mesh (Rns) peer is skipped; the cap of 1 is honoured.
        pool.ensure(opener, &[PeerAddr::Rns([0u8; 16]), p1, p2]).await;
        assert_eq!(pool.len().await, 1);
    }
}
