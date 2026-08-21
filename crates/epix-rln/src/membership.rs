//! The xID-anchored membership tree.

use rln::prelude::{Fr, PoseidonHash, RLNMerkleProof, DEFAULT_TREE_DEPTH};
use zerokit_utils::merkle_tree::{OptimalMerkleConfig, OptimalMerkleTree, ZerokitMerkleTree};

use crate::{RlnError, RlnIdentity};

/// The membership tree that ECX proofs verify against.
///
/// Leaves are rate commitments `Poseidon(id_commitment, user_message_limit)`,
/// not raw identity commitments. The root is the public anchor a proof binds to;
/// because removing a leaf (a ban) changes the root, a banned member's future
/// proofs no longer verify against the current root. This is a sparse in-memory
/// tree; on the network its contents are the xID holders in good standing, and
/// every node derives the same root from the same (self-validating) membership
/// set.
pub struct Membership {
    tree: OptimalMerkleTree<PoseidonHash>,
    limit: u32,
}

impl Membership {
    /// Build a membership tree from an ordered roster of member identity
    /// commitments (the owner-signed list): leaf `i` is
    /// `rate_commitment(commitments[i], user_message_limit)`. Every node that
    /// has the same signed roster derives the same root.
    pub fn from_commitments(
        commitments: &[Fr],
        user_message_limit: u32,
    ) -> Result<Self, RlnError> {
        let mut m = Self::new(user_message_limit)?;
        let limit = Fr::from(u64::from(user_message_limit));
        for (i, c) in commitments.iter().enumerate() {
            m.tree
                .set(i, crate::rate_commitment(*c, limit))
                .map_err(|e| RlnError::Membership(e.to_string()))?;
        }
        Ok(m)
    }

    /// A new, empty membership tree with the given per-epoch message allowance.
    pub fn new(user_message_limit: u32) -> Result<Self, RlnError> {
        if user_message_limit == 0 {
            return Err(RlnError::Membership(
                "user message limit must be at least one".into(),
            ));
        }
        let tree = OptimalMerkleTree::new(
            DEFAULT_TREE_DEPTH,
            Fr::from(0u64),
            OptimalMerkleConfig::default(),
        )
        .map_err(|e| RlnError::Membership(e.to_string()))?;
        Ok(Self { tree, limit: user_message_limit })
    }

    /// The per-epoch message allowance bound into every member's leaf.
    pub fn user_message_limit(&self) -> u32 {
        self.limit
    }

    /// The current membership root.
    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    /// Add (or replace) the member at `index`, storing its rate commitment.
    pub fn insert(&mut self, index: usize, identity: &RlnIdentity) -> Result<(), RlnError> {
        self.tree
            .set(index, identity.rate_commitment(self.limit))
            .map_err(|e| RlnError::Membership(e.to_string()))
    }

    /// Ban the member at `index` by resetting its leaf to the default value.
    /// Their subsequent proofs stop verifying against the new root.
    pub fn remove(&mut self, index: usize) -> Result<(), RlnError> {
        self.tree.delete(index).map_err(|e| RlnError::Membership(e.to_string()))
    }

    /// The Merkle proof for the member at `index`, in the form the prover needs.
    pub(crate) fn merkle_proof(&self, index: usize) -> Result<RLNMerkleProof, RlnError> {
        let proof = self.tree.proof(index).map_err(|e| RlnError::Membership(e.to_string()))?;
        Ok(RLNMerkleProof::from(&proof))
    }
}
