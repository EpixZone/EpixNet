use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use super::{generate_key, invalid_public_key, public, with};
use crate::{
    canonical_bytes, digest, sign_envelope, AuthenticationError, SharedDataVerifier,
    SharedReadGrant, VerifiedRecord, MAX_RECORD,
};

struct Shared {
    owner: SigningKey,
    writer: SigningKey,
    attacker: SigningKey,
    policy: Value,
    policy_digest: String,
    grant: SharedReadGrant,
    verifier: SharedDataVerifier,
    payload: Vec<u8>,
    record: Value,
}

impl Shared {
    fn new() -> Shared {
        let owner = generate_key();
        let writer = generate_key();
        let attacker = generate_key();
        let policy = json!({
            "kind": "evx.source-policy.v1", "source": "game-shared", "owner": "game-owner",
            "version": 1, "writers": {"player-one": hex::encode(public(&writer))},
        });
        let policy_digest = digest(&canonical_bytes(&policy).unwrap());
        let grant = SharedReadGrant::new(
            "game-reader",
            "game-shared",
            "game-owner",
            public(&owner),
            BTreeSet::from([policy_digest.clone()]),
        )
        .unwrap();
        let mut verifier = SharedDataVerifier::new(grant.clone());
        verifier
            .accept_policy(&sign_envelope(&policy, &owner))
            .unwrap();
        let payload = br#"{"score":42,"other_source":"unapproved-game"}"#.to_vec();
        let record = json!({
            "kind": "evx.record.v1", "source": "game-shared", "writer": "player-one",
            "policy_digest": policy_digest, "sequence": 1, "payload_digest": digest(&payload),
        });
        Shared {
            owner,
            writer,
            attacker,
            policy,
            policy_digest,
            grant,
            verifier,
            payload,
            record,
        }
    }

    fn verify(&mut self) -> Result<VerifiedRecord, AuthenticationError> {
        self.verify_as(None, None, None, "player-one")
    }

    fn verify_as(
        &mut self,
        body: Option<&Value>,
        key: Option<&SigningKey>,
        payload: Option<&[u8]>,
        writer: &str,
    ) -> Result<VerifiedRecord, AuthenticationError> {
        let envelope = sign_envelope(body.unwrap_or(&self.record), key.unwrap_or(&self.writer));
        let payload = payload.map_or_else(|| self.payload.clone(), <[u8]>::to_vec);
        self.verifier.verify_record(writer, &envelope, &payload)
    }
}

#[test]
fn verified_record_preserves_provenance_and_inert_payload() {
    let mut sh = Shared::new();
    let record = sh.verify().unwrap();
    assert_eq!(record.source(), sh.grant.source);
    assert_eq!(record.writer(), "player-one");
    assert_eq!(record.consumer_xite(), "game-reader");
    assert_eq!(record.policy_digest(), sh.policy_digest);
    assert_eq!(record.policy_version(), 1);
    assert_eq!(record.sequence(), 1);
    assert_eq!(record.payload(), sh.payload);
    assert_eq!(record.payload_digest(), digest(&sh.payload));
    assert_eq!(
        record.record_digest(),
        digest(&canonical_bytes(&sh.record).unwrap())
    );
    // The reference asserts FrozenInstanceError on `record.source = ...`;
    // VerifiedRecord has no public mutators, so the type enforces it.
}

#[test]
fn payload_reference_cannot_grant_transitive_source_access() {
    let mut sh = Shared::new();
    sh.verify().unwrap();
    let foreign = with(
        &sh.record,
        &[("source", json!("unapproved-game")), ("sequence", json!(2))],
    );
    assert!(sh
        .verify_as(Some(&foreign), None, None, "player-one")
        .is_err());
}

#[test]
fn unknown_writer_and_key_substitution_fail() {
    let mut sh = Shared::new();
    assert!(sh.verify_as(None, None, None, "other-player").is_err());
    let attacker = sh.attacker.clone();
    assert!(sh
        .verify_as(None, Some(&attacker), None, "player-one")
        .is_err());
    let substituted = with(
        &sh.record,
        &[("public_key", json!(hex::encode(public(&attacker))))],
    );
    assert!(sh
        .verify_as(Some(&substituted), None, None, "player-one")
        .is_err());
}

#[test]
fn input_payload_and_provenance_tampering_fail() {
    let mut sh = Shared::new();
    assert!(sh
        .verify_as(None, None, Some(br#"{"score":999}"#), "player-one")
        .is_err());
    for changes in [
        [("source", json!("other-source"))],
        [("writer", json!("other-player"))],
        [("policy_digest", json!("0".repeat(64)))],
    ] {
        let body = with(&sh.record, &changes);
        assert!(
            sh.verify_as(Some(&body), None, None, "player-one").is_err(),
            "accepted {changes:?}"
        );
    }
}

#[test]
fn owner_signature_required_for_policy() {
    let mut sh = Shared::new();
    let forged = sign_envelope(&sh.policy, &sh.attacker);
    assert!(sh.verifier.accept_policy(&forged).is_err());
}

#[test]
fn signed_new_writer_does_not_silently_inherit_trust() {
    let mut sh = Shared::new();
    let mut writers = sh.policy["writers"].clone();
    writers["other-player"] = json!(hex::encode(public(&sh.attacker)));
    let expanded = with(&sh.policy, &[("version", json!(2)), ("writers", writers)]);
    let envelope = sign_envelope(&expanded, &sh.owner);
    assert!(sh.verifier.accept_policy(&envelope).is_err());
    assert_eq!(sh.verifier.policy_digest(), Some(sh.policy_digest.as_str()));
}

#[test]
fn explicitly_accepted_signed_policy_update_and_rollback() {
    let mut sh = Shared::new();
    let updated = with(
        &sh.policy,
        &[
            ("version", json!(2)),
            (
                "writers",
                json!({"player-one": hex::encode(public(&sh.attacker))}),
            ),
        ],
    );
    let new_digest = digest(&canonical_bytes(&updated).unwrap());
    let mut grant = sh.grant.clone();
    grant.accepted_policy_digests = BTreeSet::from([sh.policy_digest.clone(), new_digest.clone()]);
    sh.verifier.set_grant(grant);
    let envelope = sign_envelope(&updated, &sh.owner);
    assert_eq!(sh.verifier.accept_policy(&envelope).unwrap(), new_digest);
    let rollback = sign_envelope(&sh.policy, &sh.owner);
    assert!(sh.verifier.accept_policy(&rollback).is_err());
    let body = with(&sh.record, &[("policy_digest", json!(new_digest))]);
    assert!(sh.verify_as(Some(&body), None, None, "player-one").is_err());
    let attacker = sh.attacker.clone();
    assert_eq!(
        sh.verify_as(Some(&body), Some(&attacker), None, "player-one")
            .unwrap()
            .policy_version(),
        2
    );
}

#[test]
fn repeat_is_idempotent_but_sequence_conflict_and_replay_fail() {
    let mut sh = Shared::new();
    let first = sh.verify().unwrap();
    assert_eq!(first, sh.verify().unwrap());
    let conflicting_payload = br#"{"score":43}"#;
    let body = with(
        &sh.record,
        &[("payload_digest", json!(digest(conflicting_payload)))],
    );
    assert!(sh
        .verify_as(Some(&body), None, Some(conflicting_payload), "player-one")
        .is_err());
    let next = with(&sh.record, &[("sequence", json!(2))]);
    assert_eq!(
        sh.verify_as(Some(&next), None, None, "player-one")
            .unwrap()
            .sequence(),
        2
    );
    assert!(sh.verify().is_err());
}

#[test]
fn oversized_and_unsigned_records_fail() {
    let mut sh = Shared::new();
    let oversized = vec![b'x'; MAX_RECORD + 1];
    assert!(sh
        .verify_as(None, None, Some(&oversized), "player-one")
        .is_err());
    let unsigned = canonical_bytes(&sh.record).unwrap();
    assert!(sh
        .verifier
        .verify_record("player-one", &unsigned, &sh.payload)
        .is_err());
}

#[test]
fn policy_requires_well_formed_writer_keys() {
    let mut sh = Shared::new();
    let bad = with(
        &sh.policy,
        &[
            ("version", json!(2)),
            (
                "writers",
                json!({"player-one": hex::encode(invalid_public_key())}),
            ),
        ],
    );
    let bad_digest = digest(&canonical_bytes(&bad).unwrap());
    let mut grant = sh.grant.clone();
    grant.accepted_policy_digests.insert(bad_digest);
    sh.verifier.set_grant(grant);
    let envelope = sign_envelope(&bad, &sh.owner);
    assert!(sh.verifier.accept_policy(&envelope).is_err());
    assert_eq!(sh.verifier.policy_version(), 1);
}
