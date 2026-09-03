//! End-to-end RLN round-trip against the vendored zerokit circuit:
//!
//!   register an identity -> prove membership + rate compliance -> verify ->
//!   double-signal in one epoch -> recover the offender's secret.
//!
//! This is the property the whole reputation-slash design rests on: an honest
//! member stays anonymous, but a member who exceeds its per-epoch allowance
//! leaks its own secret, which lets the network evict it. Proving it here
//! confirms the patched (sled-gated) zerokit build works end to end in the
//! EpixNet workspace.

use epix_rln::{external_nullifier, message_signal, rate_commitment, RLN_TREE_DEPTH};
// rand 0.9+ dropped rngs::OsRng; seed the crate's bridge RNG from OS entropy
// instead (rln's generate() speaks the rand_core 0.6 traits the bridge has).
use epix_rln::SeededChaCha;
use rand_core06::SeedableRng;
use rln::prelude::{compute_id_secret, Fr, IdentityKeys, PoseidonHash, RLNBuilder, RLNWitnessInput};
use zerokit_utils::merkle_tree::{FullMerkleConfig, FullMerkleTree, ZerokitMerkleTree};

#[test]
fn rln_prove_verify_and_recover_on_double_signal() {
    // 1. An identity: the anonymous member. Its commitment is public; its secret
    //    is what a double-signal will leak.
    let mut rng = SeededChaCha::from_seed(rand::random::<[u8; 32]>());
    let id = IdentityKeys::generate::<PoseidonHash, _>(&mut rng);

    // A per-user allowance of a single message per epoch, bound into the leaf.
    let limit = Fr::from(1u64);

    // 2. A membership tree holding this member's rate commitment as a leaf. On
    //    the real network this is the xID-anchored tree; here it is a
    //    single-member tree. The leaf is H(id_commitment, limit), NOT the raw
    //    id_commitment — the circuit re-derives it.
    let mut tree = FullMerkleTree::<PoseidonHash>::new(
        RLN_TREE_DEPTH,
        Fr::from(0u64),
        FullMerkleConfig::default(),
    )
    .expect("build membership tree");
    tree.set(0, rate_commitment(id.id_commitment(), limit)).expect("insert member");
    let root = tree.root();
    let merkle_proof = tree.proof(0).expect("membership proof");

    // 3. The stateless verifier/prover, using the circuit resources embedded in
    //    the crate (no external files).
    let rln = RLNBuilder::stateless().build();

    // 4. One epoch (the rate-limit window).
    let epoch = external_nullifier(Fr::from(1_000u64), Fr::from(0x0ECDu64));

    let prove = |signal: &[u8]| {
        let x = message_signal(signal);
        let witness = RLNWitnessInput::new_single()
            .identity_secret(id.identity_secret())
            .user_message_limit(limit)
            .merkle_proof(&merkle_proof)
            .x(x)
            .external_nullifier(epoch)
            .message_id(Fr::from(0u64))
            .build()
            .expect("build witness");
        let (proof, values) = rln.generate_proof(&witness).expect("generate proof");
        (x, proof, values)
    };

    // 5. TWO different messages in the SAME epoch — exceeding the allowance of 1.
    let (x1, proof1, values1) = prove(b"first message");
    let (x2, proof2, values2) = prove(b"second message");

    // Both proofs verify against the finalized membership root and their signals.
    assert!(
        rln.verify_with_roots(&proof1, &values1, &x1, &[root]).expect("verify 1"),
        "first proof must verify"
    );
    assert!(
        rln.verify_with_roots(&proof2, &values2, &x2, &[root]).expect("verify 2"),
        "second proof must verify"
    );

    // Same identity + same epoch => same nullifier: this is what the node uses to
    // notice a double-signal before doing any secret recovery.
    assert_eq!(values1.nullifier(), values2.nullifier(), "double-signal must collide");

    // 6. The reputation slash: two shares of the same polynomial reveal the
    //    offender's identity secret. An honest member (one message per epoch)
    //    never produces a second share, so its secret stays safe.
    let share1 = (values1.x(), values1.y().expect("share y1"));
    let share2 = (values2.x(), values2.y().expect("share y2"));
    let recovered = compute_id_secret(share1, share2).expect("recover id secret");
    assert_eq!(
        *recovered,
        *id.identity_secret(),
        "recovered secret must equal the double-signalling member's"
    );
}
