//! The node-side RLN admission gate for one ECX pool.

use std::collections::HashMap;

use rln::prelude::Fr;

use crate::{
    commitment_of_secret, fr_key, Membership, NullifierLog, Observation, Rln, RlnError, RlnIdentity,
    Verified,
};

/// Owns the RLN engine, the membership tree, and the nullifier log for one pool,
/// and decides what to do with each record: admit it, drop it as a duplicate,
/// reject it, or — on a double-signal — evict its sender.
///
/// The node drives this: it enrolls the pool's members (from the xID-anchored
/// membership set), calls [`PoolGate::prove`] on the send path to attach a proof
/// to a record, and [`PoolGate::admit`] at ingest to gate incoming records.
pub struct PoolGate {
    engine: Rln,
    membership: Membership,
    log: NullifierLog,
    // commitment key -> tree index, so a recovered secret can be traced to a leaf.
    index_of: HashMap<[u8; 32], usize>,
}

/// The gate's decision for one record.
#[derive(Debug)]
pub enum Admission {
    /// Verified and within the rate limit: admit the record.
    Admit,
    /// A re-broadcast of an already-seen record: drop it as a duplicate.
    Duplicate,
    /// The proof did not verify — a bad proof, a non-member, the wrong epoch, or
    /// a signal that does not match the record. Do not admit.
    Reject(RlnError),
    /// The sender exceeded its per-epoch allowance: the double-signal revealed
    /// its secret, reported here as its commitment. The record is NOT admitted
    /// (the rate limit is enforced). Structural removal is left to the caller —
    /// under the owner-signed model the owner drops the member from its roster;
    /// [`PoolGate::evict_member`] is available for callers that remove locally.
    RateExceeded { offender_commitment: Fr },
}

impl PoolGate {
    /// A new gate. `domain` scopes external nullifiers to this pool;
    /// `user_message_limit` is the per-epoch message allowance.
    pub fn new(domain: Fr, user_message_limit: u32) -> Result<Self, RlnError> {
        Ok(Self {
            engine: Rln::new(domain),
            membership: Membership::new(user_message_limit)?,
            log: NullifierLog::new(),
            index_of: HashMap::new(),
        })
    }

    /// Build a gate from an owner-signed roster of member identity commitments.
    /// No member secrets are needed — the owner vouches for the list — so this
    /// is how a node builds a gate from the signed roster it reads out of the
    /// pool's content. Leaf `i` is the rate commitment of `commitments[i]`.
    pub fn from_roster(
        domain: Fr,
        user_message_limit: u32,
        commitments: &[Fr],
    ) -> Result<Self, RlnError> {
        let membership = Membership::from_commitments(commitments, user_message_limit)?;
        let mut index_of = HashMap::new();
        for (i, c) in commitments.iter().enumerate() {
            index_of.insert(fr_key(c)?, i);
        }
        Ok(Self { engine: Rln::new(domain), membership, log: NullifierLog::new(), index_of })
    }

    /// Enroll a member at `index`, remembering its commitment for ban lookup.
    pub fn enroll(&mut self, index: usize, identity: &RlnIdentity) -> Result<(), RlnError> {
        self.membership.insert(index, identity)?;
        self.index_of.insert(fr_key(&identity.commitment())?, index);
        Ok(())
    }

    /// The current membership root — the root fresh proofs should target.
    pub fn root(&self) -> Fr {
        self.membership.root()
    }

    /// Forget nullifiers for epochs before `oldest` (bounds memory).
    pub fn prune_before(&mut self, oldest: u64) {
        self.log.prune_before(oldest);
    }

    /// Produce the RLN proof blob for one of this gate's members to attach to a
    /// record (the send side). `ct` is the record's sealed payload — the same
    /// bytes [`PoolGate::admit`] re-derives the signal from.
    pub fn prove(
        &self,
        identity: &RlnIdentity,
        member_index: usize,
        epoch: u64,
        message_id: u32,
        ct: &[u8],
    ) -> Result<Vec<u8>, RlnError> {
        self.engine.prove(identity, &self.membership, member_index, epoch, message_id, ct)
    }

    /// Prove as `identity`, looking up its own index in this gate's roster.
    /// Errors if the identity is not a member. Convenience over [`Self::prove`]
    /// for the send path, which knows the member but not its index.
    pub fn prove_as(
        &self,
        identity: &RlnIdentity,
        epoch: u64,
        message_id: u32,
        ct: &[u8],
    ) -> Result<Vec<u8>, RlnError> {
        let key = fr_key(&identity.commitment())?;
        let index = *self
            .index_of
            .get(&key)
            .ok_or_else(|| RlnError::Membership("identity is not a member of this pool".into()))?;
        self.prove(identity, index, epoch, message_id, ct)
    }

    /// Admit (or not) a record carrying `rln_proof` for `epoch`, whose bound
    /// message is `ct` (the record's sealed payload).
    ///
    /// `accepted_roots` is the window of membership roots currently honored —
    /// typically the current root plus a small grace history, so a proof made
    /// against a just-superseded root still verifies (see the finality
    /// grace-period discussion; membership shifts the root the same way).
    pub fn admit(
        &mut self,
        rln_proof: &[u8],
        ct: &[u8],
        epoch: u64,
        accepted_roots: &[Fr],
    ) -> Admission {
        let verified: Verified = match self.engine.verify(rln_proof, accepted_roots, epoch, ct) {
            Ok(v) => v,
            Err(e) => return Admission::Reject(e),
        };
        match self.log.observe(epoch, verified.nullifier, verified.share) {
            Ok(Observation::Fresh) => Admission::Admit,
            Ok(Observation::Replay) => Admission::Duplicate,
            Ok(Observation::DoubleSignal { recovered_secret }) => {
                Admission::RateExceeded { offender_commitment: commitment_of_secret(&recovered_secret) }
            }
            Err(e) => Admission::Reject(e),
        }
    }

    /// Structurally remove the member with `commitment` from the tree — a ban
    /// that changes the root. Under the owner-signed model this happens when the
    /// owner regenerates its roster; a future self-validating model would have
    /// every node call this on a reveal. Returns whether a member was found.
    pub fn evict_member(&mut self, commitment: &Fr) -> bool {
        if let Ok(key) = fr_key(commitment) {
            if let Some(index) = self.index_of.remove(&key) {
                let _ = self.membership.remove(index);
                return true;
            }
        }
        false
    }
}
