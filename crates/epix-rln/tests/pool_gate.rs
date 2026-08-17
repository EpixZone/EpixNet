//! The node-side pool admission gate end to end: a non-member is rejected, an
//! honest record is admitted, a re-broadcast is a duplicate, and a second
//! message in one epoch evicts the sender. This mirrors what the node's
//! `verify_pool_record` ingest hook will drive, with `ct` standing in for a
//! record's sealed payload.

use epix_rln::{
    commitment_from_hex, commitment_to_hex, Admission, Membership, PoolGate, RlnIdentity,
};
use rln::prelude::Fr;

const DOMAIN: u64 = 0x0EC0_0002;
const LIMIT: u32 = 1;

#[test]
fn gate_admits_dedups_rejects_nonmember_and_evicts_double_signal() {
    let mut gate = PoolGate::new(Fr::from(DOMAIN), LIMIT).expect("gate");

    let alice = RlnIdentity::from_seed(b"alice.epix/ecx");
    gate.enroll(0, &alice).expect("enroll alice");
    let root = gate.root();
    let epoch = 500u64;

    // --- a non-member cannot get a record admitted ---
    let mallory = RlnIdentity::from_seed(b"mallory.epix/ecx"); // never enrolled
    let ct_m = b"mallory payload";
    let forged = gate.prove(&mallory, 5, epoch, 0, ct_m).expect("prove (empty slot)");
    assert!(
        matches!(gate.admit(&forged, ct_m, epoch, &[root]), Admission::Reject(_)),
        "a non-member's proof must not verify against the membership root"
    );

    // --- an honest message is admitted ---
    let ct1 = b"alice payload one";
    let p1 = gate.prove(&alice, 0, epoch, 0, ct1).expect("prove 1");
    assert!(matches!(gate.admit(&p1, ct1, epoch, &[root]), Admission::Admit));

    // --- a re-broadcast of the same record is a duplicate, not a violation ---
    assert!(matches!(gate.admit(&p1, ct1, epoch, &[root]), Admission::Duplicate));

    // --- a second, distinct message in the same epoch is dropped (rate limit)
    //     and reveals the offender; detection alone does NOT change the root ---
    let ct2 = b"alice payload two";
    let p2 = gate.prove(&alice, 0, epoch, 0, ct2).expect("prove 2");
    match gate.admit(&p2, ct2, epoch, &[root]) {
        Admission::RateExceeded { offender_commitment } => {
            assert_eq!(offender_commitment, alice.commitment(), "reveal must identify alice");
        }
        other => panic!("second message in one epoch must exceed the rate, got {other:?}"),
    }
    assert_eq!(gate.root(), root, "detection alone must not change the root (owner-signed model)");

    // --- explicit (owner-driven) eviction removes alice and changes the root ---
    assert!(gate.evict_member(&alice.commitment()), "alice was a member");
    assert_ne!(gate.root(), root, "structural eviction changes the root");
}

#[test]
fn owner_roster_root_matches_enrollment_and_hex_roundtrips() {
    let alice = RlnIdentity::from_seed(b"alice.epix/ecx");
    let bob = RlnIdentity::from_seed(b"bob.epix/ecx");

    // A commitment survives the hex encode/decode used in the signed roster.
    let hex = commitment_to_hex(&alice.commitment());
    assert_eq!(commitment_from_hex(&hex), Some(alice.commitment()));

    // Building the tree from an owner roster yields the same root as enrolling
    // the same members one by one, so every node with the signed list agrees.
    let roster = Membership::from_commitments(&[alice.commitment(), bob.commitment()], LIMIT)
        .expect("roster tree");
    let mut gate = PoolGate::new(Fr::from(DOMAIN), LIMIT).expect("gate");
    gate.enroll(0, &alice).expect("enroll alice");
    gate.enroll(1, &bob).expect("enroll bob");
    assert_eq!(roster.root(), gate.root(), "owner-list root must match enrollment");
}
