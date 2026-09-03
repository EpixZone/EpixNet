//! The deterministic RNG identity derivation runs on, bridged across rand
//! generations.
//!
//! The vendored `rln` and the arkworks 0.5 stack sample through the rand 0.8
//! / `rand_core` 0.6 traits, while the workspace runs the current
//! `rand_chacha`. This adapter exposes the modern `ChaCha20Rng` through the
//! old traits, so the crate stays on the latest crypto releases without
//! forking the vendor.
//!
//! SAFETY OF THE BRIDGE: the ChaCha20 keystream for a given 32-byte seed is
//! algorithmically fixed and `rand_chacha` documents its output stream as
//! stable, so the derived identities are byte-identical to the ones the old
//! `rand_chacha 0.3` produced. That is not taken on faith - the known-answer
//! test in `tests/identity_golden.rs` pins commitments captured under 0.3,
//! and fails the build if any part of the derivation ever drifts.

// rand_core 0.10 renamed the method-bearing trait: `Rng` carries
// next_u32/next_u64/fill_bytes and `RngCore` is a marker supertrait.
use rand_chacha::rand_core::{Rng as ModernRng, SeedableRng as ModernSeedableRng};
use rand_chacha::ChaCha20Rng;

/// [`ChaCha20Rng`] exposed through the `rand_core` 0.6 traits.
pub struct SeededChaCha(ChaCha20Rng);

impl rand_core06::RngCore for SeededChaCha {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core06::CryptoRng for SeededChaCha {}

impl rand_core06::SeedableRng for SeededChaCha {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(<ChaCha20Rng as ModernSeedableRng>::from_seed(seed))
    }
}
