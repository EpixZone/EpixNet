//! The node-side RLN admission gate for one ECX pool.

use std::collections::HashMap;

use rln::prelude::Fr;

use crate::{
    commitment_of_secret, fr_key, Membership, NullifierId, NullifierLog, Observation, RecordId,
    Rln, RlnError, RlnIdentity, Verified,
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
    /// A re-broadcast of an already-seen logical record. Suppress delivery,
    /// but a newly verified transport wrapper may replace the retained copy.
    Duplicate {
        keep_record: bool,
        /// The same logical record remains the gate's survivor. A caller may
        /// retain a newly verified transport wrapper, such as a current-root
        /// reproof, while suppressing application delivery.
        replace_record: bool,
        evicted_records: Vec<RecordId>,
    },
    /// A same-signal proof partially overlaps an accepted allowance window.
    /// Exactly one deterministic window survives, but this is not slashing
    /// evidence because the Shamir shares are identical.
    Overlap {
        keep_record: bool,
        evicted_records: Vec<RecordId>,
    },
    /// The proof touches durable double-signal evidence and must not be stored
    /// or delivered.
    Quarantined,
    /// The proof did not verify — a bad proof, a non-member, the wrong epoch, or
    /// a signal that does not match the record. Do not admit.
    Reject(RlnError),
    /// The sender exceeded its per-epoch allowance: the double-signal revealed
    /// its secret, reported here as its commitment. The record is NOT admitted
    /// (the rate limit is enforced). Structural removal is left to the caller —
    /// under the owner-signed model the owner drops the member from its roster;
    /// [`PoolGate::evict_member`] is available for callers that remove locally.
    RateExceeded {
        offender_commitment: Fr,
        /// Stable ids of every previously accepted record in the conflicting
        /// component. All are quarantined and the incoming offender record is
        /// never persisted.
        evicted_records: Vec<RecordId>,
        /// Nullifiers to persist as poison before the caller removes any
        /// conflicting records from public shards.
        poisoned_nullifiers: Vec<NullifierId>,
    },
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

    pub fn root_id(&self) -> Result<[u8; 32], RlnError> {
        crate::fr_key(&self.membership.root())
    }

    /// Whether `identity` is enrolled in this gate's roster (used by the send
    /// path and the footprint UI to tell a member from a non-member).
    pub fn is_member(&self, identity: &RlnIdentity) -> bool {
        fr_key(&identity.commitment()).map(|k| self.index_of.contains_key(&k)).unwrap_or(false)
    }

    /// Forget nullifiers for epochs before `oldest` (bounds memory).
    pub fn prune_before(&mut self, oldest: u64) {
        self.log.prune_before(oldest);
    }

    /// Produce the RLN proof blob for one of this gate's members to attach to a
    /// record (the send side), spending `weight` allowance units starting at
    /// `first_unit`. `ct` is the record's sealed payload — the same bytes
    /// [`PoolGate::admit`] re-derives the signal from. The send path chooses
    /// `weight` from the record's size bucket and `first_unit` from the member's
    /// local usage ledger (so a fresh unit range is spent each time).
    pub fn prove(
        &self,
        identity: &RlnIdentity,
        member_index: usize,
        epoch: u64,
        first_unit: u32,
        weight: u32,
        ct: &[u8],
    ) -> Result<Vec<u8>, RlnError> {
        self.engine
            .prove(identity, &self.membership, member_index, epoch, first_unit, weight, ct)
    }

    /// Prove as `identity`, looking up its own index in this gate's roster.
    /// Errors if the identity is not a member. Convenience over [`Self::prove`]
    /// for the send path, which knows the member but not its index.
    pub fn prove_as(
        &self,
        identity: &RlnIdentity,
        epoch: u64,
        first_unit: u32,
        weight: u32,
        ct: &[u8],
    ) -> Result<Vec<u8>, RlnError> {
        let key = fr_key(&identity.commitment())?;
        let index = *self
            .index_of
            .get(&key)
            .ok_or_else(|| RlnError::Membership("identity is not a member of this pool".into()))?;
        self.prove(identity, index, epoch, first_unit, weight, ct)
    }

    /// Admit (or not) a record carrying `rln_proof` for `epoch`, whose bound
    /// message is `ct` and whose size bucket costs `weight` units.
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
        weight: u32,
        accepted_roots: &[Fr],
    ) -> Admission {
        let record_id = fr_key(&crate::message_signal(rln_proof)).unwrap_or([0; 32]);
        self.admit_with_id(record_id, rln_proof, ct, epoch, weight, accepted_roots)
    }

    /// [`Self::admit`] with a stable logical id for the pool record. The id lets
    /// the gate select a deterministic survivor across partitions while still
    /// allowing proof, PoW, and signature wrappers to be replaced.
    pub fn admit_with_id(
        &mut self,
        record_id: RecordId,
        rln_proof: &[u8],
        ct: &[u8],
        epoch: u64,
        weight: u32,
        accepted_roots: &[Fr],
    ) -> Admission {
        let verified: Verified =
            match self.engine.verify(rln_proof, accepted_roots, epoch, ct, weight) {
                Ok(v) => v,
                Err(e) => return Admission::Reject(e),
            };
        match self.log.observe(epoch, record_id, &verified.slots) {
            Ok(Observation::Fresh) => Admission::Admit,
            Ok(Observation::Replay {
                keep_record,
                evicted_records,
            }) => Admission::Duplicate {
                keep_record,
                replace_record: self.log.contains_record(epoch, &record_id),
                evicted_records,
            },
            Ok(Observation::PartialOverlap {
                keep_record,
                evicted_records,
            }) => Admission::Overlap {
                keep_record,
                evicted_records,
            },
            Ok(Observation::Quarantined) => Admission::Quarantined,
            Ok(Observation::DoubleSignal {
                recovered_secret,
                conflicting_records,
                poisoned_nullifiers,
            }) => Admission::RateExceeded {
                offender_commitment: commitment_of_secret(&recovered_secret),
                evicted_records: conflicting_records,
                poisoned_nullifiers,
            },
            Err(e) => Admission::Reject(e),
        }
    }

    /// Import durable double-signal poison after it has been fsynced by the
    /// caller.
    pub fn poison_nullifiers(&mut self, epoch: u64, keys: &[NullifierId]) {
        self.log.poison(epoch, keys);
    }

    /// Verify a record without mutating admission state and report whether it
    /// touches durable double-signal poison.
    pub fn proof_touches_poisoned(
        &self,
        rln_proof: &[u8],
        ct: &[u8],
        epoch: u64,
        weight: u32,
        accepted_roots: &[Fr],
    ) -> Result<bool, RlnError> {
        let verified = self
            .engine
            .verify(rln_proof, accepted_roots, epoch, ct, weight)?;
        let mut keys = Vec::with_capacity(verified.slots.len());
        for slot in &verified.slots {
            keys.push(fr_key(&slot.nullifier)?);
        }
        Ok(self.log.touches_poisoned(epoch, &keys))
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
