//! Known-answer tests for deterministic identity derivation.
//!
//! `RlnIdentity::from_seed` promises: same seed, same identity, on every
//! node, forever. Everything downstream leans on that - membership rosters
//! carry the derived commitments, and a member whose commitment changed
//! would silently fall out of every group. These fixed vectors pin the
//! whole derivation pipeline (keccak seed hash, the ChaCha20 stream, ark's
//! field sampling), so a dependency bump that shifts ANY of it fails here
//! instead of on the network.

use epix_rln::commitment_to_hex;
use epix_rln::RlnIdentity;

#[test]
fn seeded_identity_commitments_never_change() {
    let vectors: &[(&[u8], &str)] = &[
        (b"epix-rln-golden-1" as &[u8], "d50d60eeca25c7a370323196b31a5895af5225a8befbdb1fa54807603b1cea1f"),
        (b"epix-rln-golden-2", "d38b063c34c3f3923acbc780045fcea290688ae709e834f85a579acdaa819527"),
        (b"", "259f576ab0038fbdfad79a4d505a63f29ad0bbcc0989b310bf6618b256e18401"),
    ];
    for (seed, expected) in vectors {
        let derived = commitment_to_hex(&RlnIdentity::from_seed(seed).commitment());
        assert_eq!(
            &derived, expected,
            "identity derivation changed for seed {:?} - this breaks every \
             existing member identity derived from that seed",
            String::from_utf8_lossy(seed)
        );
    }
}
