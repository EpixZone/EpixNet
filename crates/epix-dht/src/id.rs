//! Node/key identifiers and the Kademlia XOR distance metric.

use epix_core::PeerAddr;
use sha2::{Digest, Sha256};

pub const ID_LEN: usize = 32;
pub const BITS: usize = ID_LEN * 8;

/// A 256-bit identifier - both node IDs and lookup keys live in the same space.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; ID_LEN]);

impl NodeId {
    pub fn new(bytes: [u8; ID_LEN]) -> Self {
        NodeId(bytes)
    }

    /// Derive an id by hashing bytes - e.g. a xite address → its lookup key, or
    /// a peer identity → its node id.
    pub fn hash(data: &[u8]) -> Self {
        NodeId(Sha256::digest(data).into())
    }

    /// XOR distance to another id (big-endian; compare as a 256-bit number).
    pub fn distance(&self, other: &NodeId) -> [u8; ID_LEN] {
        let mut d = [0u8; ID_LEN];
        for i in 0..ID_LEN {
            d[i] = self.0[i] ^ other.0[i];
        }
        d
    }

    /// k-bucket index for `other` relative to `self`: the position of the most
    /// significant differing bit (0..BITS). `None` when the ids are equal.
    pub fn bucket_index(&self, other: &NodeId) -> Option<usize> {
        let d = self.distance(other);
        for (i, byte) in d.iter().enumerate() {
            if *byte != 0 {
                return Some(BITS - 1 - (i * 8 + byte.leading_zeros() as usize));
            }
        }
        None
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeId({}…)", &self.to_hex()[..8])
    }
}

/// A node in the DHT: its id and how to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub id: NodeId,
    pub addr: PeerAddr,
}

impl Contact {
    pub fn new(id: NodeId, addr: PeerAddr) -> Self {
        Self { id, addr }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_is_symmetric_and_zero_to_self() {
        let a = NodeId::hash(b"a");
        let b = NodeId::hash(b"b");
        assert_eq!(a.distance(&b), b.distance(&a));
        assert_eq!(a.distance(&a), [0u8; ID_LEN]);
        assert_eq!(a.bucket_index(&a), None);
    }

    #[test]
    fn bucket_index_tracks_the_leading_differing_bit() {
        let zero = NodeId::new([0u8; ID_LEN]);
        // Differ only in the least-significant bit -> distance 1 -> bucket 0.
        let mut one = [0u8; ID_LEN];
        one[ID_LEN - 1] = 1;
        assert_eq!(zero.bucket_index(&NodeId::new(one)), Some(0));
        // Differ in the most-significant bit -> the top bucket (BITS-1).
        let mut top = [0u8; ID_LEN];
        top[0] = 0x80;
        assert_eq!(zero.bucket_index(&NodeId::new(top)), Some(BITS - 1));
    }
}
