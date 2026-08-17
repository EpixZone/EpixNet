//! The RLN engine end to end: membership, prove/verify, the per-epoch nullifier
//! log, the double-signal reveal, and eviction. This is the behaviour the pool
//! admission hook will drive.

use epix_rln::{
    commitment_of_secret, Membership, NullifierLog, Observation, Rln, RlnError, RlnIdentity,
};
use rln::prelude::Fr;

/// A fixed ECX domain separator scoping external nullifiers to this application.
const DOMAIN: u64 = 0x0EC0_0001;
/// One message per identity per epoch.
const LIMIT: u32 = 1;

fn engine() -> Rln {
    Rln::new(Fr::from(DOMAIN))
}

#[test]
fn deterministic_identity_from_seed() {
    let a = RlnIdentity::from_seed(b"alice.epix/ecx");
    let a_again = RlnIdentity::from_seed(b"alice.epix/ecx");
    let bob = RlnIdentity::from_seed(b"bob.epix/ecx");
    assert_eq!(a.commitment(), a_again.commitment(), "same seed must reproduce the identity");
    assert_ne!(a.commitment(), bob.commitment(), "different seeds must differ");
}

#[test]
fn admit_replay_reject_double_signal_and_ban() {
    let rln = engine();
    let mut members = Membership::new(LIMIT).expect("membership tree");
    let mut log = NullifierLog::new();

    let alice = RlnIdentity::from_seed(b"alice.epix/ecx");
    let alice_idx = 0usize;
    members.insert(alice_idx, &alice).expect("enroll alice");
    let root = members.root();
    let epoch = 1_000u64;

    // --- honest message: proves, verifies against the root, logs as Fresh ---
    let msg1 = b"first record bytes";
    let blob1 = rln.prove(&alice, &members, alice_idx, epoch, 0, msg1).expect("prove 1");
    let v1 = rln.verify(&blob1, &[root], epoch, msg1).expect("verify 1");
    assert!(matches!(log.observe(epoch, v1.nullifier, v1.share).unwrap(), Observation::Fresh));

    // A re-broadcast of the SAME record is a replay, not a new violation.
    assert!(matches!(log.observe(epoch, v1.nullifier, v1.share).unwrap(), Observation::Replay));

    // --- the proof is bound to its epoch, its root, and its record ---
    // Wrong epoch:
    assert!(matches!(
        rln.verify(&blob1, &[root], epoch + 1, msg1),
        Err(RlnError::EpochMismatch)
    ));
    // A root outside the accepted set (a non-member / stale root):
    assert!(matches!(
        rln.verify(&blob1, &[Fr::from(0x1234u64)], epoch, msg1),
        Err(RlnError::InvalidProof)
    ));
    // The proof lifted onto a different record (signal mismatch):
    assert!(matches!(
        rln.verify(&blob1, &[root], epoch, b"tampered record"),
        Err(RlnError::InvalidProof)
    ));

    // --- double-signal: a SECOND message in the same epoch reveals the secret ---
    let msg2 = b"second record, same epoch";
    let blob2 = rln.prove(&alice, &members, alice_idx, epoch, 0, msg2).expect("prove 2");
    let v2 = rln.verify(&blob2, &[root], epoch, msg2).expect("verify 2");
    assert_eq!(v1.nullifier, v2.nullifier, "same identity + epoch => same nullifier");

    let recovered = match log.observe(epoch, v2.nullifier, v2.share).unwrap() {
        Observation::DoubleSignal { recovered_secret } => recovered_secret,
        _ => panic!("a second message in one epoch must be a double-signal"),
    };
    // The revealed secret identifies exactly alice — this is the ban lookup.
    assert_eq!(
        commitment_of_secret(&recovered),
        alice.commitment(),
        "the reveal must identify the offender"
    );

    // --- ban: evicting alice changes the root; her proofs no longer verify ---
    members.remove(alice_idx).expect("evict alice");
    let banned_root = members.root();
    assert_ne!(root, banned_root, "a ban must change the membership root");

    let msg3 = b"post-ban record";
    let blob3 = rln.prove(&alice, &members, alice_idx, epoch, 0, msg3).expect("prove 3");
    assert!(
        matches!(rln.verify(&blob3, &[banned_root], epoch, msg3), Err(RlnError::InvalidProof)),
        "a banned member must not verify against the new root"
    );
}

#[test]
fn honest_members_stay_within_limit_across_epochs() {
    let rln = engine();
    let mut members = Membership::new(LIMIT).expect("membership tree");
    let mut log = NullifierLog::new();

    let bob = RlnIdentity::from_seed(b"bob.epix/ecx");
    members.insert(1, &bob).expect("enroll bob");
    let root = members.root();

    // One message in each of two epochs: both Fresh, no reveal.
    for epoch in [10u64, 11u64] {
        let msg = format!("bob says hi in epoch {epoch}");
        let blob = rln.prove(&bob, &members, 1, epoch, 0, msg.as_bytes()).expect("prove");
        let v = rln.verify(&blob, &[root], epoch, msg.as_bytes()).expect("verify");
        assert!(
            matches!(log.observe(epoch, v.nullifier, v.share).unwrap(), Observation::Fresh),
            "one message per epoch is always fresh"
        );
    }
}
