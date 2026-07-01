//! Merkle inclusion-proof verification (SHA-256), matching the Epix chain's
//! `xid` proof format.

use crate::{ChainError, Result};
use sha2::{Digest, Sha256};

/// Recompute the Merkle root from `leaf_hash` up through `siblings` (bottom to
/// top), ordering each pair by the current index's parity, and check it equals
/// `expected_root`. All hashes are hex strings.
pub fn verify_proof(
    leaf_hash: &str,
    leaf_index: u64,
    siblings: &[String],
    expected_root: &str,
) -> Result<bool> {
    let mut current = hex::decode(leaf_hash).map_err(|e| ChainError::Malformed(format!("leaf hash: {e}")))?;
    let mut idx = leaf_index;
    for sibling_hex in siblings {
        let sibling = hex::decode(sibling_hex)
            .map_err(|e| ChainError::Malformed(format!("sibling hash: {e}")))?;
        let combined: Vec<u8> = if idx % 2 == 0 {
            [current.as_slice(), sibling.as_slice()].concat()
        } else {
            [sibling.as_slice(), current.as_slice()].concat()
        };
        current = Sha256::digest(&combined).to_vec();
        idx /= 2;
    }
    Ok(hex::encode(current) == expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn h(a: &[u8], b: &[u8]) -> String {
        hex::encode(Sha256::digest([a, b].concat()))
    }

    #[test]
    fn verifies_a_known_proof_and_rejects_tampering() {
        // A 4-leaf tree. Leaf index 1 (second leaf).
        let leaves: Vec<[u8; 1]> = vec![[0], [1], [2], [3]];
        let lh: Vec<String> = leaves.iter().map(|l| hex::encode(Sha256::digest(l))).collect();
        // level 1
        let n01 = h(&hex::decode(&lh[0]).unwrap(), &hex::decode(&lh[1]).unwrap());
        let n23 = h(&hex::decode(&lh[2]).unwrap(), &hex::decode(&lh[3]).unwrap());
        let root = h(&hex::decode(&n01).unwrap(), &hex::decode(&n23).unwrap());

        // Proof for leaf index 1: siblings = [leaf0, n23].
        let siblings = vec![lh[0].clone(), n23.clone()];
        assert!(verify_proof(&lh[1], 1, &siblings, &root).unwrap());

        // Wrong index -> fails.
        assert!(!verify_proof(&lh[1], 0, &siblings, &root).unwrap());
        // Tampered sibling -> fails.
        let mut bad = siblings.clone();
        bad[0] = lh[2].clone();
        assert!(!verify_proof(&lh[1], 1, &bad, &root).unwrap());
    }
}
