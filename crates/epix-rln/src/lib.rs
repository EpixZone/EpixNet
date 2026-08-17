//! Anonymous rate-limiting for the ECX pool via Rate-Limiting Nullifiers (RLN).
//!
//! A pool record can be admitted only if it carries an RLN proof showing the
//! sender is a member in good standing (a leaf in the xID-anchored membership
//! tree) AND has not exceeded its per-epoch message allowance, all WITHOUT
//! revealing which member sent it. If a member double-signals within an epoch,
//! the scheme's Shamir shares reveal that member's secret, which is what powers
//! the reputation-based eviction described in the ECX design: the offending
//! identity is removed from the membership tree, and rejoining costs a fresh
//! (paid) xID.
//!
//! This crate wraps the audited zerokit `rln` crate. The heavy crypto (the
//! Groth16 circuit, Poseidon, the nullifier math) is zerokit's; this crate is
//! the thin, EpixNet-shaped seam over it. The membership tree, epoch nullifier
//! tracking, and pool-admission wiring build on top of this in follow-up work.
//!
//! Status: the verifier primitive and the proof/verify/recover round-trip are
//! implemented and tested (`tests/round_trip.rs`). Membership, reputation, and
//! the pool `verify_pool_record` hook are WIP.

pub use rln;

use rln::prelude::{hash_to_field_le, Fr, Hasher, PoseidonHash};

/// Merkle tree depth the bundled RLN circuit is built for. The membership tree
/// must use this depth for proofs to verify.
pub use rln::prelude::DEFAULT_TREE_DEPTH as RLN_TREE_DEPTH;

/// The per-epoch external nullifier that binds a proof to a rate-limit window.
///
/// Two proofs from the same identity that share this value expose the identity
/// secret (via [`rln::prelude::compute_id_secret`]) — the double-signal that
/// triggers a reputation slash. `domain` is a fixed protocol/domain separator
/// so nullifiers from ECX cannot collide with any other RLN application on the
/// same identities.
pub fn external_nullifier(epoch: Fr, domain: Fr) -> Fr {
    Hasher::<PoseidonHash>::hash_pair(epoch, domain)
}

/// The membership-tree leaf for a member: the rate commitment
/// `Poseidon(id_commitment, user_message_limit)`. The xID-anchored tree stores
/// these, not raw identity commitments — the circuit re-derives the same value,
/// which is how a member's per-epoch allowance is bound into their leaf.
pub fn rate_commitment(id_commitment: Fr, user_message_limit: Fr) -> Fr {
    Hasher::<PoseidonHash>::hash_pair(id_commitment, user_message_limit)
}

/// Hash an opaque message (the pool record's signed bytes, say) to the field
/// element the circuit binds as the signal `x`. The verifier re-derives this
/// from the record and rejects a proof whose bound signal does not match, so a
/// proof cannot be lifted onto a different record.
pub fn message_signal(bytes: &[u8]) -> Fr {
    hash_to_field_le(bytes)
}
