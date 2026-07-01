//! The Kademlia routing table: k-buckets of known contacts.

use crate::id::{Contact, NodeId, BITS};

/// Contacts per bucket (Kademlia `k`).
pub const K: usize = 8;

pub struct RoutingTable {
    local: NodeId,
    buckets: Vec<Vec<Contact>>,
}

impl RoutingTable {
    pub fn new(local: NodeId) -> Self {
        Self { local, buckets: vec![Vec::new(); BITS] }
    }

    /// Learn a contact. Existing contacts move to most-recently-seen; full
    /// buckets keep the incumbents (a real node would ping the LRU first).
    pub fn insert(&mut self, contact: Contact) {
        let idx = match self.local.bucket_index(&contact.id) {
            Some(i) => i,
            None => return, // ourselves
        };
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|c| c.id == contact.id) {
            let existing = bucket.remove(pos);
            bucket.push(existing);
        } else if bucket.len() < K {
            bucket.push(contact);
        }
    }

    /// The `count` known contacts closest (by XOR distance) to `target`.
    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<Contact> {
        let mut all: Vec<Contact> = self.buckets.iter().flatten().cloned().collect();
        all.sort_by(|a, b| target.distance(&a.id).cmp(&target.distance(&b.id)));
        all.truncate(count);
        all
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_core::PeerAddr;

    fn contact(seed: &str) -> Contact {
        Contact::new(NodeId::hash(seed.as_bytes()), PeerAddr::parse("1.2.3.4:1").unwrap())
    }

    #[test]
    fn closest_returns_the_nearest_by_xor_distance() {
        let local = NodeId::hash(b"local");
        let mut rt = RoutingTable::new(local);
        let contacts: Vec<Contact> = (0..20).map(|i| contact(&format!("n{i}"))).collect();
        for c in &contacts {
            rt.insert(c.clone());
        }
        let target = NodeId::hash(b"target");
        let got = rt.closest(&target, 5);
        assert_eq!(got.len(), 5);

        // Brute-force the true nearest 5 and compare the sets.
        let mut expected = contacts.clone();
        expected.sort_by(|a, b| target.distance(&a.id).cmp(&target.distance(&b.id)));
        let expected_ids: Vec<_> = expected.iter().take(5).map(|c| c.id).collect();
        let got_ids: Vec<_> = got.iter().map(|c| c.id).collect();
        assert_eq!(got_ids, expected_ids);
    }

    #[test]
    fn insert_ignores_self() {
        let local = NodeId::hash(b"me");
        let mut rt = RoutingTable::new(local);
        rt.insert(Contact::new(local, PeerAddr::parse("1.2.3.4:1").unwrap()));
        assert_eq!(rt.len(), 0);
    }
}
