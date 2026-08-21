//! The RLN engine end to end with SIZE-WEIGHTED allowances: a record spends one
//! allowance unit per size-bucket, the verifier enforces exactly that many
//! DISTINCT units, reusing a spent unit double-signals, and the per-epoch cap is
//! enforced by the circuit itself.

use epix_rln::{
    bucket_weight, commitment_of_secret, Membership, NullifierLog, Observation, Rln, RlnError,
    RlnIdentity, MAX_UNITS_PER_PROOF,
};
use rln::prelude::Fr;

const DOMAIN: u64 = 0x0EC0_0001;
/// Eight allowance units per identity per epoch.
const LIMIT: u32 = 8;

fn member() -> (Rln, Membership, RlnIdentity, Fr) {
    let rln = Rln::new(Fr::from(DOMAIN));
    let mut m = Membership::new(LIMIT).unwrap();
    let id = RlnIdentity::from_seed(b"alice.epix/ecx");
    m.insert(0, &id).unwrap();
    let root = m.root();
    (rln, m, id, root)
}

#[test]
fn bucket_weight_maps_size_to_units() {
    // Smallest bucket = 1 unit; multiples cost proportionally; partials round up.
    assert_eq!(bucket_weight(8192, 8192), 1);
    assert_eq!(bucket_weight(32768, 8192), 4);
    assert_eq!(bucket_weight(100, 8192), 1);
    assert_eq!(bucket_weight(8193, 8192), 2);
}

#[test]
fn weighted_spend_reuse_reveals_and_underpay_rejected() {
    let (rln, m, id, root) = member();
    let mut log = NullifierLog::new();
    let epoch = 100u64;

    // A 3-unit record proves 3 distinct units; the verifier accepts it as 3.
    let ct1 = b"a three-unit record";
    let p1 = rln.prove(&id, &m, 0, epoch, 0, 3, ct1).unwrap();
    let v1 = rln.verify(&p1, &[root], epoch, ct1, 3).unwrap();
    assert_eq!(v1.slots.len(), 3, "a 3-unit record carries 3 slots");
    assert!(matches!(
        log.observe(epoch, [1; 32], &v1.slots).unwrap(),
        Observation::Fresh
    ));

    // A different record spending the NEXT fresh unit is fine.
    let ct2 = b"a one-unit record";
    let p2 = rln.prove(&id, &m, 0, epoch, 3, 1, ct2).unwrap();
    let v2 = rln.verify(&p2, &[root], epoch, ct2, 1).unwrap();
    assert!(matches!(
        log.observe(epoch, [2; 32], &v2.slots).unwrap(),
        Observation::Fresh
    ));

    // Reusing an already-spent unit (0) in a NEW record double-signals: the
    // offender's secret is recovered and identifies exactly Alice.
    let ct3 = b"reuse of unit zero";
    let p3 = rln.prove(&id, &m, 0, epoch, 0, 1, ct3).unwrap();
    let v3 = rln.verify(&p3, &[root], epoch, ct3, 1).unwrap();
    match log.observe(epoch, [3; 32], &v3.slots).unwrap() {
        Observation::DoubleSignal {
            recovered_secret, ..
        } => {
            assert_eq!(commitment_of_secret(&recovered_secret), id.commitment());
        }
        _ => panic!("reusing a spent unit must double-signal"),
    }

    // Under-pay attack: a 1-unit proof presented for a record the pool costs at 3
    // units is rejected — the verifier, not the client, enforces the cost.
    let ct4 = b"an underpay attempt";
    let p4 = rln.prove(&id, &m, 0, epoch, 4, 1, ct4).unwrap();
    assert!(matches!(
        rln.verify(&p4, &[root], epoch, ct4, 3),
        Err(RlnError::WrongUnits { got: 1, want: 3 })
    ));
}

#[test]
fn partial_same_signal_overlap_is_rejected_without_burning_new_units() {
    let (rln, m, id, root) = member();
    let mut log = NullifierLog::new();
    let epoch = 101u64;
    let ct = b"one ciphertext with sliding allowance windows";

    let first = rln.prove(&id, &m, 0, epoch, 0, 2, ct).unwrap();
    let first = rln.verify(&first, &[root], epoch, ct, 2).unwrap();
    assert!(matches!(
        log.observe(epoch, [1; 32], &first.slots).unwrap(),
        Observation::Fresh
    ));

    // Same signal means the overlapping slot has the same Shamir share. The
    // old any-new rule admitted this sliding window and burned unit 2.
    let overlap = rln.prove(&id, &m, 0, epoch, 1, 2, ct).unwrap();
    let overlap = rln.verify(&overlap, &[root], epoch, ct, 2).unwrap();
    assert!(matches!(
        log.observe(epoch, [2; 32], &overlap.slots).unwrap(),
        Observation::PartialOverlap {
            keep_record: false,
            ref evicted_records,
        } if evicted_records.is_empty()
    ));

    // Opposite first-seen order selects the same lower record id and explicitly
    // evicts the prior window, so persisted callers can converge too.
    let mut opposite = NullifierLog::new();
    assert!(matches!(
        opposite.observe(epoch, [2; 32], &overlap.slots).unwrap(),
        Observation::Fresh
    ));
    assert!(matches!(
        opposite.observe(epoch, [1; 32], &first.slots).unwrap(),
        Observation::PartialOverlap {
            keep_record: true,
            ref evicted_records,
        } if evicted_records == &vec![[2; 32]]
    ));

    // Equivalent wrappers carrying the exact same proof also converge by id.
    assert!(matches!(
        opposite.observe(epoch, [0; 32], &first.slots).unwrap(),
        Observation::Replay {
            keep_record: true,
            ref evicted_records,
        } if evicted_records == &vec![[1; 32]]
    ));

    // Unit 2 remained fresh because the rejected overlap mutated no state.
    let fresh = rln
        .prove(&id, &m, 0, epoch, 2, 1, b"fresh unit two")
        .unwrap();
    let fresh = rln
        .verify(&fresh, &[root], epoch, b"fresh unit two", 1)
        .unwrap();
    assert!(matches!(
        log.observe(epoch, [3; 32], &fresh.slots).unwrap(),
        Observation::Fresh
    ));
}

#[test]
fn cannot_spend_beyond_the_epoch_allowance() {
    let (rln, m, id, _root) = member();
    // Spending a unit index >= the limit is impossible: the circuit binds every
    // active message-id below user_message_limit, so witness build fails.
    let over = rln.prove(&id, &m, 0, 100, LIMIT, 1, b"over the cap");
    assert!(matches!(over, Err(RlnError::Witness(_))), "unit >= limit is unprovable");

    // A single record wider than one proof's slot count is rejected up front.
    let too_wide = rln.prove(&id, &m, 0, 100, 0, MAX_UNITS_PER_PROOF as u32 + 1, b"too wide");
    assert!(matches!(too_wide, Err(RlnError::Witness(_))));
}
