//! The node-side pool admission gate end to end: a non-member is rejected, an
//! honest record is admitted, a re-broadcast is a duplicate, and a second
//! message in one epoch evicts the sender. This mirrors what the node's
//! `verify_pool_record` ingest hook will drive, with `ct` standing in for a
//! record's sealed payload.

use epix_rln::{Admission, PoolGate, RlnIdentity};
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

    // --- a second, distinct message in the same epoch evicts alice ---
    let ct2 = b"alice payload two";
    let p2 = gate.prove(&alice, 0, epoch, 0, ct2).expect("prove 2");
    match gate.admit(&p2, ct2, epoch, &[root]) {
        Admission::Evicted { offender_commitment } => {
            assert_eq!(offender_commitment, alice.commitment(), "must evict alice specifically");
        }
        other => panic!("second message in one epoch must evict, got {other:?}"),
    }
    assert_ne!(gate.root(), root, "eviction must change the membership root");
}
