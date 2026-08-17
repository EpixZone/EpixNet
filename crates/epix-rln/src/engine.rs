//! The stateless RLN prover/verifier over the bundled circuit.

use rln::prelude::{
    ArkGroth16Backend, CanonicalDeserialize, CanonicalSerialize, Fr, PoseidonHash, RLNBuilder,
    RLNProof, RLNWitnessInput, Stateless, RLN,
};

use crate::{external_nullifier, message_signal, Membership, RlnError, RlnIdentity};

/// The stateless RLN engine: it proves and verifies against caller-supplied
/// membership roots (the tree lives in [`Membership`], not here). Cheap to
/// clone-share across the node since it only holds the circuit resources.
pub struct Rln {
    inner: RLN<Stateless, ArkGroth16Backend<PoseidonHash>>,
    domain: Fr,
}

/// What a successful [`Rln::verify`] returns: everything the node needs to feed
/// the [`crate::NullifierLog`].
pub struct Verified {
    /// The nullifier. Equal for two messages from the same identity in the same
    /// epoch; that equality is what flags a double-signal.
    pub nullifier: Fr,
    /// This proof's Shamir share `(x, y)`. Two distinct shares for one nullifier
    /// recover the offender's identity secret.
    pub share: (Fr, Fr),
    /// The membership root the proof was made against (one of the accepted set).
    pub root: Fr,
}

impl Rln {
    /// Build the stateless engine. `domain` is a fixed ECX domain separator that
    /// scopes external nullifiers to this application, so an identity's ECX
    /// nullifiers never collide with those of any other RLN app.
    pub fn new(domain: Fr) -> Self {
        Self { inner: RLNBuilder::stateless().build(), domain }
    }

    /// Produce the RLN proof blob a pool record carries.
    ///
    /// `epoch` is the rate-limit window, `message` the record's canonical signed
    /// bytes (the verifier re-derives the bound signal from these), and
    /// `message_id` must be in `0..user_message_limit`.
    pub fn prove(
        &self,
        identity: &RlnIdentity,
        membership: &Membership,
        member_index: usize,
        epoch: u64,
        message_id: u32,
        message: &[u8],
    ) -> Result<Vec<u8>, RlnError> {
        let ext = external_nullifier(Fr::from(epoch), self.domain);
        let witness = RLNWitnessInput::new_single()
            .identity_secret(identity.secret())
            .user_message_limit(Fr::from(u64::from(membership.user_message_limit())))
            .merkle_proof(membership.merkle_proof(member_index)?)
            .x(message_signal(message))
            .external_nullifier(ext)
            .message_id(Fr::from(u64::from(message_id)))
            .build()
            .map_err(|e| RlnError::Witness(e.to_string()))?;

        let (proof, values) =
            self.inner.generate_proof(&witness).map_err(|e| RlnError::Prove(e.to_string()))?;

        let mut bytes = Vec::new();
        RLNProof::new(proof, values)
            .serialize_compressed(&mut bytes)
            .map_err(|e| RlnError::Serialize(e.to_string()))?;
        Ok(bytes)
    }

    /// Verify a proof `blob` for `epoch` and the record `message`, against the
    /// set of currently accepted membership roots.
    ///
    /// Returns the nullifier and share on success. Any verification failure —
    /// bad SNARK, a root outside `accepted_roots`, or a signal that does not
    /// match the record — is a rejection ([`RlnError::InvalidProof`]); the node
    /// should simply not admit the record.
    pub fn verify(
        &self,
        blob: &[u8],
        accepted_roots: &[Fr],
        epoch: u64,
        message: &[u8],
    ) -> Result<Verified, RlnError> {
        let bundle = RLNProof::deserialize_compressed(blob)
            .map_err(|e| RlnError::Serialize(e.to_string()))?;

        // Bind the proof to THIS epoch. external_nullifier is a public input, so
        // a prover could otherwise pick a different one to avoid the nullifier
        // collision and evade the rate limit. Recompute it and require a match.
        let ext = external_nullifier(Fr::from(epoch), self.domain);
        if bundle.values.external_nullifier() != ext {
            return Err(RlnError::EpochMismatch);
        }

        let x = message_signal(message);
        match self.inner.verify_with_roots(&bundle.proof, &bundle.values, &x, accepted_roots) {
            Ok(true) => {}
            // Ok(false) = invalid SNARK; Err = InvalidRoot / InvalidSignal. All
            // mean "do not admit", so collapse to one rejection.
            _ => return Err(RlnError::InvalidProof),
        }

        let nullifier = bundle.values.nullifier().ok_or(RlnError::MalformedValues)?;
        let y = bundle.values.y().ok_or(RlnError::MalformedValues)?;
        Ok(Verified { nullifier, share: (bundle.values.x(), y), root: bundle.values.root() })
    }
}
