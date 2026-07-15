//! The value store: `key (site hash) -> peers hosting it`, with expiry.

use crate::id::NodeId;
use epix_core::PeerAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cap on peers kept per key. Announce is unauthenticated (any node can claim
/// any address for any key), so an attacker could otherwise loop distinct
/// fabricated onion/i2p addresses and grow one key's list without bound. When
/// full, the oldest entry is evicted - a genuine host re-announces every round,
/// so real peers churn back in while a one-shot flood ages out. K-per-key is
/// far above the K closest honest announcers a real site attracts.
const MAX_PEERS_PER_KEY: usize = 128;

pub struct PeerStore {
    entries: HashMap<NodeId, Vec<(PeerAddr, Instant)>>,
    ttl: Duration,
}

impl PeerStore {
    pub fn new(ttl: Duration) -> Self {
        Self { entries: HashMap::new(), ttl }
    }

    /// Record that `peer` hosts `key` (refreshes the timestamp if already known).
    pub fn add(&mut self, key: NodeId, peer: PeerAddr) {
        let list = self.entries.entry(key).or_default();
        match list.iter_mut().find(|(p, _)| *p == peer) {
            Some(entry) => entry.1 = Instant::now(),
            None => {
                if list.len() >= MAX_PEERS_PER_KEY {
                    // Drop expired first; only evict the oldest if still full.
                    list.retain(|(_, t)| t.elapsed() < self.ttl);
                    if list.len() >= MAX_PEERS_PER_KEY {
                        if let Some(oldest) =
                            (0..list.len()).min_by_key(|&i| list[i].1)
                        {
                            list.remove(oldest);
                        }
                    }
                }
                list.push((peer, Instant::now()));
            }
        }
    }

    /// The non-expired peers hosting `key`.
    pub fn get(&self, key: &NodeId) -> Vec<PeerAddr> {
        self.entries
            .get(key)
            .map(|list| {
                list.iter()
                    .filter(|(_, t)| t.elapsed() < self.ttl)
                    .map(|(p, _)| p.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Drop expired entries.
    pub fn expire(&mut self) {
        for list in self.entries.values_mut() {
            list.retain(|(_, t)| t.elapsed() < self.ttl);
        }
        self.entries.retain(|_, list| !list.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_and_dedups_peers() {
        let mut store = PeerStore::new(Duration::from_secs(60));
        let key = NodeId::hash(b"site");
        let a = PeerAddr::parse("1.1.1.1:1").unwrap();
        let b = PeerAddr::parse("2.2.2.2:2").unwrap();
        store.add(key, a.clone());
        store.add(key, b.clone());
        store.add(key, a.clone()); // refresh, not duplicate
        let peers = store.get(&key);
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&a) && peers.contains(&b));
        assert!(store.get(&NodeId::hash(b"other")).is_empty());
    }

    #[test]
    fn per_key_peer_count_is_capped() {
        let mut store = PeerStore::new(Duration::from_secs(3600));
        let key = NodeId::hash(b"site");
        // A flood of distinct fabricated addresses for one key.
        for i in 0..(MAX_PEERS_PER_KEY + 50) {
            store.add(key, PeerAddr::parse(&format!("10.0.{}.{}:1", i / 250, i % 250)).unwrap());
        }
        assert_eq!(store.get(&key).len(), MAX_PEERS_PER_KEY, "list stays capped");

        // A genuine host that keeps announcing is retained (re-announce
        // refreshes its timestamp, so it is never the oldest evicted).
        let host = PeerAddr::parse("203.0.113.9:26552").unwrap();
        for _ in 0..10 {
            store.add(key, host.clone());
            for i in 0..20 {
                store.add(key, PeerAddr::parse(&format!("11.0.{}.{}:1", i / 250, i % 250)).unwrap());
            }
        }
        assert!(store.get(&key).contains(&host), "re-announcing host survives the cap");
    }
}
