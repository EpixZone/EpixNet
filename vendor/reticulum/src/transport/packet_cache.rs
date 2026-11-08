use std::{
    cmp::min,
    collections::{BTreeSet, HashMap},
    time::{Duration, Instant},
};

use crate::{hash::Hash, packet::Packet};

pub struct PacketTrack {
    pub time: Instant,
    pub min_hops: u8,
}

pub struct PacketCache {
    map: HashMap<Hash, PacketTrack>,
    oldest: BTreeSet<(Instant, Hash)>,
}

const MAX_CACHED_PACKETS: usize = 4096;

impl PacketCache {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            oldest: BTreeSet::new(),
        }
    }

    pub fn release(&mut self, duration: Duration) {
        while self.oldest.first().is_some_and(|(time, _)| time.elapsed() > duration) {
            self.remove_oldest();
        }
    }

    fn remove_oldest(&mut self) {
        if let Some((_, hash)) = self.oldest.pop_first() { self.map.remove(&hash); }
    }

    pub fn update(&mut self, packet: &Packet) -> bool {
        let hash = packet.hash();

        let mut is_new_packet = false;

        let track = self.map.get_mut(&hash);
        if let Some(track) = track {
            self.oldest.remove(&(track.time, hash));
            track.time = Instant::now();
            track.min_hops = min(packet.header.hops, track.min_hops);
            self.oldest.insert((track.time, hash));
        } else {
            is_new_packet = true;
            if self.map.len() >= MAX_CACHED_PACKETS { self.remove_oldest(); }
            let now = Instant::now();
            self.oldest.insert((now, hash));

            self.map.insert(
                hash,
                PacketTrack {
                    time: now,
                    min_hops: packet.header.hops,
                },
            );
        }

        is_new_packet
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;

    #[test]
    fn packet_flood_is_bounded_and_recent_duplicates_still_match() {
        let mut cache = PacketCache::new();
        let mut recent = Packet::default();
        for index in 0..MAX_CACHED_PACKETS + 100 {
            let mut packet = Packet::default();
            packet.data.write(&(index as u64).to_be_bytes()).unwrap();
            assert!(cache.update(&packet));
            recent = packet;
        }
        assert_eq!(cache.map.len(), MAX_CACHED_PACKETS);
        assert_eq!(cache.oldest.len(), MAX_CACHED_PACKETS);
        assert!(!cache.update(&recent));
        assert_eq!(cache.oldest.len(), MAX_CACHED_PACKETS);
        cache.release(Duration::from_secs(3600));
        assert_eq!(cache.map.len(), MAX_CACHED_PACKETS);
    }
}
