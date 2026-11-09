use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, HeaderType, IfacFlag, Packet};

pub struct LinkEntry {
    pub proof_timeout: Instant,
    pub last_activity: Instant,
    pub next_hop: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    pub remaining_hops: u8,
    pub validated: bool,
}

const ACTIVE_LINK_IDLE: Duration = Duration::from_secs(3600);

#[cfg(test)]
mod bounds_tests {
    use super::*;

    fn request(index: u64) -> Packet {
        let mut packet = Packet::default();
        packet.data.write(&index.to_be_bytes()).unwrap();
        packet
    }

    #[test]
    fn bounded_admission_preserves_validated_links_and_reuses_expired_slots() {
        let mut table = LinkTable::new();
        let destination = AddressHash::new([1; 16]);
        let iface = AddressHash::new([2; 16]);
        for index in 0..crate::transport::MAX_LOGICAL_LINKS as u64 {
            assert!(table.add(&request(index), destination, iface, iface));
        }
        let keep = LinkId::from(&request(0));
        table.0.get_mut(&keep).unwrap().validated = true;
        let extra = request(crate::transport::MAX_LOGICAL_LINKS as u64);
        assert!(!table.add(&extra, destination, iface, iface));
        assert!(table.add(&request(0), destination, iface, iface));
        assert_eq!(table.0.len(), crate::transport::MAX_LOGICAL_LINKS);
        for entry in table.0.values_mut() {
            entry.proof_timeout = Instant::now() - Duration::from_secs(1);
        }
        assert!(table.add(&extra, destination, iface, iface));
        assert_eq!(table.0.len(), 2);
        assert!(table.0[&keep].validated);
    }

    #[test]
    fn idle_validated_relays_expire_while_recent_traffic_preserves_active_routes() {
        let mut table = LinkTable::new();
        let destination = AddressHash::new([1; 16]);
        let iface = AddressHash::new([2; 16]);
        for index in 0..crate::transport::MAX_LOGICAL_LINKS as u64 {
            assert!(table.add(&request(index), destination, iface, iface));
        }
        for entry in table.0.values_mut() {
            entry.validated = true;
            entry.last_activity = Instant::now() - ACTIVE_LINK_IDLE - Duration::from_secs(1);
        }
        let recent = [
            LinkId::from(&request(0)),
            LinkId::from(&request(1)),
            LinkId::from(&request(2)),
        ];
        assert_eq!(table.original_destination(&recent[0]), Some(destination));
        let mut keepalive = Packet::default();
        keepalive.destination = recent[1];
        assert!(table.handle_keepalive(&keepalive).is_some());
        let mut proof = Packet::default();
        proof.destination = recent[2];
        assert!(table.handle_proof(&proof).is_some());
        assert!(table.add(
            &request(crate::transport::MAX_LOGICAL_LINKS as u64),
            destination,
            iface,
            iface
        ));
        assert_eq!(table.0.len(), 4, "idle completed relays reclaim capacity");
        for id in recent {
            assert!(table.0[&id].validated);
        }
    }
}

fn send_backwards(packet: &Packet, entry: &LinkEntry) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            hops: packet.header.hops + 1,
            ..packet.header
        },
        ifac: None,
        destination: packet.destination,
        transport: Some(entry.next_hop),
        context: packet.context,
        data: packet.data,
    };

    (propagated, entry.received_from)
}

pub struct LinkTable(HashMap<LinkId, LinkEntry>);

impl LinkTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        next_hop: AddressHash,
    ) -> bool {
        let link_id = LinkId::from(link_request);

        if self.0.contains_key(&link_id) {
            return true;
        }
        self.remove_stale();
        if self.0.len() >= super::MAX_LOGICAL_LINKS {
            return false;
        }

        let now = Instant::now();

        let entry = LinkEntry {
            proof_timeout: now + Duration::from_secs(600), // TODO
            last_activity: now,
            next_hop,
            received_from,
            original_destination: destination,
            remaining_hops: 0,
            validated: false,
        };

        self.0.insert(link_id, entry);
        true
    }

    pub(super) fn protected_destinations(&self) -> impl Iterator<Item = AddressHash> + '_ {
        self.0.values().map(|entry| entry.original_destination)
    }

    pub fn original_destination(&mut self, link_id: &LinkId) -> Option<AddressHash> {
        self.0
            .get_mut(link_id)
            .filter(|e| e.validated)
            .map(|entry| {
                entry.last_activity = Instant::now();
                entry.original_destination
            })
    }

    pub fn handle_keepalive(&mut self, packet: &Packet) -> Option<(Packet, AddressHash)> {
        self.0.get_mut(&packet.destination).map(|entry| {
            entry.last_activity = Instant::now();
            send_backwards(packet, entry)
        })
    }

    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        match self.0.get_mut(&proof.destination) {
            Some(entry) => {
                entry.remaining_hops = proof.header.hops;
                entry.validated = true;
                entry.last_activity = Instant::now();

                Some(send_backwards(proof, entry))
            }
            None => None,
        }
    }

    pub fn remove_stale(&mut self) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
            let expired = if entry.validated {
                now.duration_since(entry.last_activity) >= ACTIVE_LINK_IDLE
            } else {
                entry.proof_timeout <= now
            };
            if expired {
                stale.push(*link_id);
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
    }
}
