//! In-memory announce tracker.
//!
//! Lets this node answer `announce` like EpixNet's Bootstrapper: it records
//! which peers announced for each xite hash and hands that list back to others
//! announcing the same hash. This is how a fresh node with only a tracker
//! address bootstraps peers - including onion/i2p peers, which clearnet
//! trackers can't record.
//!
//! Peers expire after [`TTL_SECS`] if not re-announced. Total hashes and peers
//! per hash are capped so a flood of junk announces can't exhaust memory. There
//! is no persistence: a restarted tracker refills within an announce cycle.

use epix_core::{IpType, PeerAddr};
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;

/// Drop peers not re-announced within this window (EpixNet expires at 40 min;
/// we keep an hour, roughly two announce cycles).
const TTL_SECS: i64 = 60 * 60;
/// Cap distinct hashes tracked and peers per hash, to bound memory.
const MAX_HASHES: usize = 20_000;
const MAX_PEERS_PER_HASH: usize = 200;

/// Which peer types a requester wants back (from the announce `need_types`).
#[derive(Debug, Clone, Copy, Default)]
pub struct NeedTypes {
    pub ipv4: bool,
    pub ipv6: bool,
    pub onion: bool,
    pub i2p: bool,
}

impl NeedTypes {
    /// Parse an announce `need_types`/`add` list (`ipv4`/`ip4`/`ipv6`/`onion`/`i2p`).
    pub fn from_list(list: &[String]) -> Self {
        let has = |name: &str| list.iter().any(|t| t == name);
        NeedTypes {
            ipv4: has("ipv4") || has("ip4"),
            ipv6: has("ipv6"),
            onion: has("onion"),
            i2p: has("i2p"),
        }
    }

    fn wants(&self, t: IpType) -> bool {
        match t {
            IpType::Ipv4 => self.ipv4,
            IpType::Ipv6 => self.ipv6,
            IpType::Onion => self.onion,
            IpType::I2p => self.i2p,
            IpType::Rns => false,
        }
    }
}

struct Entry {
    addr: PeerAddr,
    announced: i64,
}

/// Tracker peer store: `hash -> (peer string -> entry)`.
#[derive(Default)]
pub struct TrackerDb {
    peers: RwLock<HashMap<[u8; 32], HashMap<String, Entry>>>,
}

impl TrackerDb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `addr` as a live peer for each of `hashes` at `now` (epoch secs).
    /// New hashes/peers past the caps are dropped; refreshes always apply.
    pub async fn announce(&self, hashes: &[[u8; 32]], addr: &PeerAddr, now: i64) {
        let key = addr.to_string();
        let mut map = self.peers.write().await;
        for h in hashes {
            let at_hash_cap = map.len() >= MAX_HASHES && !map.contains_key(h);
            if at_hash_cap {
                continue;
            }
            let bucket = map.entry(*h).or_default();
            if bucket.contains_key(&key) || bucket.len() < MAX_PEERS_PER_HASH {
                bucket.insert(key.clone(), Entry { addr: addr.clone(), announced: now });
            }
        }
    }

    /// Live peers for `hash`, most-recently-announced first, up to `limit`,
    /// excluding `exclude` (the announcer's own addresses) and keeping only the
    /// types in `need`.
    pub async fn peer_list(
        &self,
        hash: &[u8; 32],
        exclude: &HashSet<String>,
        limit: usize,
        now: i64,
        need: NeedTypes,
    ) -> Vec<PeerAddr> {
        let map = self.peers.read().await;
        let Some(bucket) = map.get(hash) else { return Vec::new() };
        let mut live: Vec<&Entry> = bucket
            .values()
            .filter(|e| now - e.announced <= TTL_SECS)
            .filter(|e| need.wants(e.addr.ip_type()))
            .filter(|e| !exclude.contains(&e.addr.to_string()))
            .collect();
        live.sort_by(|a, b| b.announced.cmp(&a.announced));
        live.into_iter().take(limit).map(|e| e.addr.clone()).collect()
    }

    /// Drop expired peers and empty/over-cap hashes. Call periodically.
    pub async fn expire(&self, now: i64) {
        let mut map = self.peers.write().await;
        for bucket in map.values_mut() {
            bucket.retain(|_, e| now - e.announced <= TTL_SECS);
        }
        map.retain(|_, b| !b.is_empty());
        if map.len() > MAX_HASHES {
            let excess = map.len() - MAX_HASHES;
            let drop: Vec<[u8; 32]> = map.keys().take(excess).copied().collect();
            for k in drop {
                map.remove(&k);
            }
        }
    }

    /// `(hashes tracked, total peer entries)` for the Stats page.
    pub async fn stats(&self) -> (usize, usize) {
        let map = self.peers.read().await;
        let peers = map.values().map(|b| b.len()).sum();
        (map.len(), peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[tokio::test]
    async fn records_and_serves_by_hash_and_type() {
        let db = TrackerDb::new();
        let a = PeerAddr::parse("8.8.8.8:15441").unwrap();
        let b = PeerAddr::parse("1.1.1.1:15441").unwrap();
        db.announce(&[h(1)], &a, 1000).await;
        db.announce(&[h(1)], &b, 1000).await;

        // Requester b asks for hash 1, excluding itself: gets a.
        let mut excl = HashSet::new();
        excl.insert(b.to_string());
        let need = NeedTypes { ipv4: true, ..Default::default() };
        let got = db.peer_list(&h(1), &excl, 10, 1000, need).await;
        assert_eq!(got, vec![a.clone()]);

        // A different hash is empty.
        assert!(db.peer_list(&h(2), &HashSet::new(), 10, 1000, need).await.is_empty());

        // need_types that don't include ipv4 filter it out.
        let none = NeedTypes { onion: true, ..Default::default() };
        assert!(db.peer_list(&h(1), &HashSet::new(), 10, 1000, none).await.is_empty());
    }

    #[tokio::test]
    async fn expires_stale_peers() {
        let db = TrackerDb::new();
        let a = PeerAddr::parse("8.8.8.8:15441").unwrap();
        db.announce(&[h(1)], &a, 1000).await;
        let need = NeedTypes { ipv4: true, ..Default::default() };
        // Well past the TTL: filtered at read and removed by expire.
        let later = 1000 + TTL_SECS + 1;
        assert!(db.peer_list(&h(1), &HashSet::new(), 10, later, need).await.is_empty());
        db.expire(later).await;
        assert_eq!(db.stats().await, (0, 0));
    }

    #[tokio::test]
    async fn keeps_i2p_peers() {
        let db = TrackerDb::new();
        let i2p = PeerAddr::I2p {
            dest: "narvewf7cmhowltv4vybkf4y4zgt63xxf2kbiantnzrb3slglw2q.b32".into(),
            port: 0,
        };
        db.announce(&[h(9)], &i2p, 500).await;
        let need = NeedTypes { i2p: true, ..Default::default() };
        let got = db.peer_list(&h(9), &HashSet::new(), 10, 500, need).await;
        assert_eq!(got, vec![i2p]);
    }
}
