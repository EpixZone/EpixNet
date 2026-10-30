//! Shared-data source policies and records.
//!
//! A consumer xite holds one directly granted read on one source. The source
//! owner signs a policy naming the writers and their keys; only policies the
//! host has accepted by digest can change the writer set. Writers sign
//! records that bind a payload digest to the accepted policy. Verified
//! payloads are inert bytes and confer no further access.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;

use crate::envelope::{self, field};
use crate::{digest, AuthenticationError, MAX_RECORD};

const POLICY_KIND: &str = "evx.source-policy.v1";
const POLICY_KEYS: &[&str] = &["kind", "source", "owner", "version", "writers"];
const RECORD_KIND: &str = "evx.record.v1";
const RECORD_KEYS: &[&str] = &[
    "kind",
    "source",
    "writer",
    "policy_digest",
    "sequence",
    "payload_digest",
];
/// Most writers one policy may name.
const MAX_WRITERS: usize = 64;

/// Host-issued read authority for one consumer over one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedReadGrant {
    /// The xite that reads.
    pub consumer_xite: String,
    /// The source being read.
    pub source: String,
    /// The owner whose signature a policy must carry.
    pub owner: String,
    /// Raw Ed25519 public key of the owner.
    pub owner_public_key: [u8; 32],
    /// Policy digests the host has explicitly accepted.
    pub accepted_policy_digests: BTreeSet<String>,
}

impl SharedReadGrant {
    /// Build a grant, validating the identifiers and the owner key.
    pub fn new(
        consumer_xite: impl Into<String>,
        source: impl Into<String>,
        owner: impl Into<String>,
        owner_public_key: [u8; 32],
        accepted_policy_digests: BTreeSet<String>,
    ) -> Result<Self, AuthenticationError> {
        let consumer_xite = consumer_xite.into();
        let source = source.into();
        let owner = owner.into();
        for value in [&consumer_xite, &source, &owner] {
            evx_api::validate_identifier(value)
                .map_err(|_| AuthenticationError::new("invalid fixture identifier"))?;
        }
        VerifyingKey::from_bytes(&owner_public_key)
            .map_err(|_| AuthenticationError::new("invalid Ed25519 public key"))?;
        Ok(SharedReadGrant {
            consumer_xite,
            source,
            owner,
            owner_public_key,
            accepted_policy_digests,
        })
    }
}

/// A record whose signature, provenance and payload digest all verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecord {
    consumer_xite: String,
    source: String,
    writer: String,
    policy_digest: String,
    policy_version: u64,
    sequence: u64,
    record_digest: String,
    payload_digest: String,
    payload: Vec<u8>,
}

impl VerifiedRecord {
    /// The consumer the grant was issued to.
    pub fn consumer_xite(&self) -> &str {
        &self.consumer_xite
    }

    /// The source the record belongs to.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The writer whose accepted key verified the record.
    pub fn writer(&self) -> &str {
        &self.writer
    }

    /// Digest of the policy in force when the record verified.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Version of the policy in force when the record verified.
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Writer sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// SHA-256 of the canonical signed record body.
    pub fn record_digest(&self) -> &str {
        &self.record_digest
    }

    /// SHA-256 of the payload, as signed.
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }

    /// The payload bytes. Opaque data; interpreting them grants nothing.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Verifier for one directly granted source.
///
/// Replay floors here are process-local; durable protection across restarts
/// is the host's responsibility.
#[derive(Debug)]
pub struct SharedDataVerifier {
    grant: SharedReadGrant,
    policy_version: u64,
    policy_digest: Option<String>,
    writers: BTreeMap<String, [u8; 32]>,
    records: BTreeMap<String, (u64, String)>,
}

impl SharedDataVerifier {
    /// A verifier with no accepted policy; every record is refused until
    /// [`accept_policy`](Self::accept_policy) succeeds.
    pub fn new(grant: SharedReadGrant) -> Self {
        SharedDataVerifier {
            grant,
            policy_version: 0,
            policy_digest: None,
            writers: BTreeMap::new(),
            records: BTreeMap::new(),
        }
    }

    /// The grant in force.
    pub fn grant(&self) -> &SharedReadGrant {
        &self.grant
    }

    /// Replace the grant, for example after the host accepts a new policy
    /// digest. Accepted policy state and replay floors are kept.
    pub fn set_grant(&mut self, grant: SharedReadGrant) {
        self.grant = grant;
    }

    /// Version of the accepted policy, or 0 if none.
    pub fn policy_version(&self) -> u64 {
        self.policy_version
    }

    /// Digest of the accepted policy, if any.
    pub fn policy_digest(&self) -> Option<&str> {
        self.policy_digest.as_deref()
    }

    /// Accept an owner-signed policy whose digest the host has accepted,
    /// replacing the writer set. Returns the policy digest.
    pub fn accept_policy(&mut self, envelope: &[u8]) -> Result<String, AuthenticationError> {
        let signed = envelope::verify_envelope(envelope, &self.grant.owner_public_key)?;
        let body = &signed.body;
        envelope::shape(body, POLICY_KEYS)?;
        if field(body, "kind").as_str() != Some(POLICY_KIND)
            || field(body, "source").as_str() != Some(self.grant.source.as_str())
            || field(body, "owner").as_str() != Some(self.grant.owner.as_str())
        {
            return Err(AuthenticationError::new("source policy identity mismatch"));
        }
        let version = envelope::positive(field(body, "version"))?;
        let policy_digest = digest(&signed.bytes);
        if !self.grant.accepted_policy_digests.contains(&policy_digest) {
            return Err(AuthenticationError::new(
                "source policy requires host acceptance",
            ));
        }
        if version < self.policy_version
            || (version == self.policy_version
                && self.policy_digest.as_deref() != Some(policy_digest.as_str()))
        {
            return Err(AuthenticationError::new(
                "source policy rollback or version conflict",
            ));
        }
        let writers = field(body, "writers")
            .as_object()
            .filter(|writers| (1..=MAX_WRITERS).contains(&writers.len()))
            .ok_or_else(|| AuthenticationError::new("invalid writer policy"))?;
        let mut parsed = BTreeMap::new();
        for (writer, encoded_key) in writers {
            evx_api::validate_identifier(writer)
                .map_err(|_| AuthenticationError::new("invalid fixture identifier"))?;
            let encoded_key = envelope::hex_digest(encoded_key)?;
            let invalid_key = || AuthenticationError::new("invalid writer public key");
            let key: [u8; 32] = hex::decode(encoded_key)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(invalid_key)?;
            VerifyingKey::from_bytes(&key).map_err(|_| invalid_key())?;
            parsed.insert(writer.clone(), key);
        }
        self.policy_version = version;
        self.policy_digest = Some(policy_digest.clone());
        self.writers = parsed;
        Ok(policy_digest)
    }

    /// Verify one record claimed to be from `writer`.
    ///
    /// The caller chooses the claimed writer, but only the key the accepted
    /// policy assigns to that writer can authenticate the envelope; neither
    /// the payload nor the envelope supplies a key. Repeating the same record
    /// is idempotent; a lower sequence or a different record at the same
    /// sequence is refused.
    pub fn verify_record(
        &mut self,
        writer: &str,
        envelope: &[u8],
        payload: &[u8],
    ) -> Result<VerifiedRecord, AuthenticationError> {
        let Some(key) = self.writers.get(writer) else {
            return Err(AuthenticationError::new(
                "writer is not authorized by accepted policy",
            ));
        };
        if payload.len() > MAX_RECORD {
            return Err(AuthenticationError::new("record payload limit"));
        }
        let signed = envelope::verify_envelope(envelope, key)?;
        let body = &signed.body;
        envelope::shape(body, RECORD_KEYS)?;
        if field(body, "kind").as_str() != Some(RECORD_KIND)
            || field(body, "source").as_str() != Some(self.grant.source.as_str())
            || field(body, "writer").as_str() != Some(writer)
            || field(body, "policy_digest").as_str() != self.policy_digest.as_deref()
        {
            return Err(AuthenticationError::new("record provenance mismatch"));
        }
        let sequence = envelope::positive(field(body, "sequence"))?;
        let payload_digest = envelope::hex_digest(field(body, "payload_digest"))?;
        if digest(payload) != payload_digest {
            return Err(AuthenticationError::new("record payload digest mismatch"));
        }
        let record_digest = digest(&signed.bytes);
        if let Some((previous_sequence, previous_digest)) = self.records.get(writer) {
            if sequence < *previous_sequence
                || (sequence == *previous_sequence && record_digest != *previous_digest)
            {
                return Err(AuthenticationError::new(
                    "record rollback or sequence conflict",
                ));
            }
        }
        self.records
            .insert(writer.to_string(), (sequence, record_digest.clone()));
        let Some(policy_digest) = self.policy_digest.clone() else {
            return Err(AuthenticationError::new("record provenance mismatch"));
        };
        Ok(VerifiedRecord {
            consumer_xite: self.grant.consumer_xite.clone(),
            source: self.grant.source.clone(),
            writer: writer.to_string(),
            policy_digest,
            policy_version: self.policy_version,
            sequence,
            record_digest,
            payload_digest: payload_digest.to_string(),
            payload: payload.to_vec(),
        })
    }
}
