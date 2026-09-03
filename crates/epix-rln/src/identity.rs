//! Member identities, anchored to xID.

use rln::prelude::{Fr, Hasher, IdentityKeys, PoseidonHash, SecretFr};

/// An RLN member identity.
///
/// Derive it deterministically from the member's xID key material with
/// [`RlnIdentity::from_seed`] so membership is anchored to a paid, permanent
/// xID, and so the member can always reconstruct the same identity (there is no
/// per-device secret to lose).
pub struct RlnIdentity {
    keys: IdentityKeys,
}

impl RlnIdentity {
    /// Deterministically derive an identity from a domain-separated `seed` (for
    /// example a hash of the member's xID signing key). The same seed always
    /// produces the same identity.
    pub fn from_seed(seed: &[u8]) -> Self {
        Self {
            keys: IdentityKeys::generate_seeded::<PoseidonHash, crate::SeededChaCha>(seed),
        }
    }

    /// The public identity commitment `H(identity_secret)`.
    pub fn commitment(&self) -> Fr {
        self.keys.id_commitment()
    }

    /// The membership-tree leaf for this identity at the given per-epoch
    /// allowance: `Poseidon(commitment, user_message_limit)`.
    pub fn rate_commitment(&self, user_message_limit: u32) -> Fr {
        crate::rate_commitment(self.commitment(), Fr::from(u64::from(user_message_limit)))
    }

    /// The identity secret. Crate-internal: it only ever feeds a witness inside
    /// [`crate::Rln::prove`] and never leaves the process.
    pub(crate) fn secret(&self) -> SecretFr {
        self.keys.identity_secret()
    }
}

/// Recompute the public identity commitment from a (recovered) identity secret.
///
/// After a double-signal reveals a secret via
/// [`rln::prelude::compute_id_secret`], the node uses this to learn which
/// member's commitment it is, and hence which leaf to evict. Mirrors the
/// circuit's own `id_commitment = H([identity_secret])`.
pub fn commitment_of_secret(secret: &SecretFr) -> Fr {
    Hasher::<PoseidonHash>::hash_list(&[**secret])
}
