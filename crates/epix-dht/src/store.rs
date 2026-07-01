//! The value store: `key (site hash) -> peers hosting it`, with expiry.

use crate::id::NodeId;
use epix_core::PeerAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

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
            None => list.push((peer, Instant::now())),
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
}
