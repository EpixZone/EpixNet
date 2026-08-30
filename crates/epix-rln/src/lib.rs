//! Anonymous rate-limiting for the ECX pool via Rate-Limiting Nullifiers (RLN).
//!
//! A pool record can be admitted only if it carries an RLN proof showing the
//! sender is a member in good standing (a leaf in the xID-anchored membership
//! tree) AND has not exceeded its per-epoch message allowance, all WITHOUT
//! revealing which member sent it. If a member double-signals within an epoch,
//! the scheme's Shamir shares reveal that member's secret, which powers the
//! reputation-based eviction from the ECX design: the offending identity is
//! removed from the membership tree, and rejoining costs a fresh (paid) xID.
//!
//! This crate wraps the audited zerokit `rln` crate. The heavy crypto (the
//! Groth16 circuit, Poseidon, the nullifier math) is zerokit's; this crate is
//! the thin, EpixNet-shaped seam over it:
//!
//! - [`RlnIdentity`] — a member's keys, derived deterministically from a seed so
//!   they can be anchored to an xID.
//! - [`Membership`] — the xID-anchored membership tree (leaves are rate
//!   commitments); `insert` adds a member, `remove` is a ban.
//! - [`Rln`] — the stateless prover/verifier; [`Rln::prove`] builds the proof
//!   blob a record carries, [`Rln::verify`] checks it and returns the nullifier
//!   and share the node needs.
//! - [`NullifierLog`] — per-epoch nullifier tracking; a second, distinct share
//!   for the same nullifier is a double-signal and yields the offender's secret.
//!
//! Still WIP: the `verify_pool_record` admission hook and send-path wiring in
//! the node/pool crates. This crate is the engine those call into.

use rln::prelude::{
    hash_to_field_le, CanonicalDeserialize, CanonicalSerialize, Fr, Hasher, PoseidonHash,
};

pub use rln;

/// Merkle tree depth the bundled RLN circuit is built for. The membership tree
/// must use this depth for proofs to verify.
pub use rln::prelude::DEFAULT_TREE_DEPTH as RLN_TREE_DEPTH;

mod engine;
mod identity;
mod membership;
mod nullifier;
mod pool;

pub use engine::{Rln, Slot, Verified, MAX_UNITS_PER_PROOF};
pub use identity::{commitment_of_secret, RlnIdentity};
pub use membership::Membership;
pub use nullifier::{NullifierId, NullifierLog, Observation, RecordId};
pub use pool::{Admission, PoolGate};

/// Canonical 32-byte key for a BN254 scalar, used to index nullifiers and
/// commitments in hash maps.
pub(crate) fn fr_key(f: &Fr) -> Result<[u8; 32], RlnError> {
    let mut v = Vec::with_capacity(32);
    f.serialize_compressed(&mut v).map_err(|e| RlnError::Serialize(e.to_string()))?;
    let mut out = [0u8; 32];
    if v.len() != out.len() {
        return Err(RlnError::Serialize(format!("scalar serialized to {} bytes", v.len())));
    }
    out.copy_from_slice(&v);
    Ok(out)
}

/// Errors from the RLN engine. Crypto-layer failures carry the underlying
/// message; logic failures (a proof for the wrong epoch, a proof that does not
/// verify) are typed so callers can react to them.
#[derive(Debug, thiserror::Error)]
pub enum RlnError {
    #[error("membership tree error: {0}")]
    Membership(String),
    #[error("witness build failed: {0}")]
    Witness(String),
    #[error("proof generation failed: {0}")]
    Prove(String),
    #[error("proof verification error: {0}")]
    Verify(String),
    #[error("proof (de)serialization failed: {0}")]
    Serialize(String),
    #[error("proof is bound to a different epoch than the record")]
    EpochMismatch,
    #[error("proof did not verify against the accepted membership roots")]
    InvalidProof,
    #[error("proof values are missing the nullifier or share")]
    MalformedValues,
    #[error("proof spends {got} units but the record's size bucket requires {want}")]
    WrongUnits { got: u32, want: u32 },
    #[error("proof only partially replays an already-spent allowance range")]
    PartialOverlap,
    #[error("secret recovery failed: {0}")]
    Recover(String),
}

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

/// The allowance-unit cost of a record whose sealed `ct` is `ct_len` bytes,
/// given the pool's smallest padding bucket. The smallest bucket costs 1 unit; a
/// bucket k times larger costs k units (rounded up). It is deterministic, so the
/// sender and every verifier compute the same cost from the record alone — a
/// prover cannot under-declare a big record's cost. Pools must size their
/// buckets so the largest costs at most [`MAX_UNITS_PER_PROOF`] units.
pub fn bucket_weight(ct_len: usize, smallest_bucket: usize) -> u32 {
    if smallest_bucket == 0 {
        return 1;
    }
    (ct_len.div_ceil(smallest_bucket).max(1)) as u32
}

/// Hex-encode an identity commitment (its 32-byte canonical form) for the
/// owner-signed membership roster.
pub fn commitment_to_hex(commitment: &Fr) -> String {
    fr_key(commitment).map(hex::encode).unwrap_or_default()
}

/// Parse a hex-encoded identity commitment (from the roster) back to a field
/// element, or `None` if it is not 32 valid canonical bytes.
pub fn commitment_from_hex(s: &str) -> Option<Fr> {
    let bytes = hex::decode(s).ok()?;
    Fr::deserialize_compressed(&bytes[..]).ok()
}
