//! The node-side RLN admission gate for one ECX pool.

use std::collections::HashMap;

use rln::prelude::{Fr, SecretFr};

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
    /// The sender exceeded its per-epoch allowance. Its secret was recovered and
    /// the identity has been evicted from the membership tree (the root changed).
    /// Do not admit; propagate the ban.
    Evicted { offender_commitment: Fr },
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
            Ok(Observation::DoubleSignal { recovered_secret }) => self.evict(&recovered_secret),
            Err(e) => Admission::Reject(e),
        }
    }

    /// Evict the identity behind a recovered secret and report its commitment.
    fn evict(&mut self, secret: &SecretFr) -> Admission {
        let commitment = commitment_of_secret(secret);
        if let Ok(key) = fr_key(&commitment) {
            if let Some(index) = self.index_of.remove(&key) {
                let _ = self.membership.remove(index);
            }
        }
        Admission::Evicted { offender_commitment: commitment }
    }
}
