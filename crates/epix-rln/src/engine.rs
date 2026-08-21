//! The stateless RLN prover/verifier over the bundled multi-message-id circuit.
//!
//! ECX uses the **multi** circuit exclusively (`max_out_4`): one proof spends
//! `weight` allowance units — where a record's weight is its size bucket in
//! units of the pool's smallest bucket — as `weight` active message-id slots.
//! Each active slot carries its own nullifier and Shamir share in the PUBLIC
//! proof values, so the verifier itself enforces that a k-unit record burns k
//! DISTINCT units; a prover cannot under-pay by repeating a message-id, and
//! reusing a unit across records collides nullifiers and reveals the secret.

use rln::prelude::{
    default_graph_multi, default_zkey_multi, ArkGroth16Backend, CanonicalDeserialize,
    CanonicalSerialize, Fr, PoseidonHash, RLNBuilder, RLNProof, RLNWitnessInput, Stateless, RLN,
};

use crate::{external_nullifier, fr_key, message_signal, Membership, RlnError, RlnIdentity};

/// Max allowance units one proof can spend — the circuit's slot count. A record
/// whose size bucket exceeds `MAX_UNITS_PER_PROOF × smallest bucket` cannot be
/// proven and is therefore unusable on an RLN pool (declare buckets accordingly).
pub use rln::prelude::DEFAULT_MAX_OUT as MAX_UNITS_PER_PROOF;

/// One active message-id slot of a verified proof: its nullifier and its
/// Shamir share `(x, y)`. Two distinct shares for one nullifier (across
/// records) recover the prover's identity secret.
#[derive(Debug, Clone)]
pub struct Slot {
    pub nullifier: Fr,
    pub share: (Fr, Fr),
}

/// What a successful [`Rln::verify`] returns: everything the node needs to feed
/// the [`crate::NullifierLog`].
pub struct Verified {
    /// The proof's active slots (exactly the record's weight, all distinct).
    pub slots: Vec<Slot>,
    /// The membership root the proof was made against (one of the accepted set).
    pub root: Fr,
}

/// The stateless RLN engine: it proves and verifies against caller-supplied
/// membership roots (the tree lives in [`Membership`], not here).
pub struct Rln {
    inner: RLN<Stateless, ArkGroth16Backend<PoseidonHash>>,
    domain: Fr,
}

impl Rln {
    /// Build the stateless engine on the multi-message-id circuit. `domain` is a
    /// fixed per-pool separator scoping external nullifiers to this application.
    pub fn new(domain: Fr) -> Self {
        let inner = RLNBuilder::stateless()
            .graph(default_graph_multi().clone())
            .zkey(default_zkey_multi().clone())
            .build();
        Self { inner, domain }
    }

    /// Produce the RLN proof blob a pool record carries, spending units
    /// `first_unit .. first_unit + weight` of the member's per-epoch allowance.
    ///
    /// `message` is the record's sealed payload (`ct`); the verifier re-derives
    /// the bound signal from it. `weight` must be `1..=MAX_UNITS_PER_PROOF` and
    /// `first_unit + weight <= user_message_limit` (the circuit enforces the
    /// latter; violating it fails witness build).
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        &self,
        identity: &RlnIdentity,
        membership: &Membership,
        member_index: usize,
        epoch: u64,
        first_unit: u32,
        weight: u32,
        message: &[u8],
    ) -> Result<Vec<u8>, RlnError> {
        if weight == 0 || weight as usize > MAX_UNITS_PER_PROOF {
            return Err(RlnError::Witness(format!(
                "weight {weight} outside 1..={MAX_UNITS_PER_PROOF}"
            )));
        }
        let ext = external_nullifier(Fr::from(epoch), self.domain);
        let mut ids = Vec::with_capacity(MAX_UNITS_PER_PROOF);
        let mut selectors = Vec::with_capacity(MAX_UNITS_PER_PROOF);
        for i in 0..MAX_UNITS_PER_PROOF as u32 {
            let active = i < weight;
            // Inactive slots are zeroed; the circuit ignores them via the selector.
            ids.push(Fr::from(if active { u64::from(first_unit + i) } else { 0 }));
            selectors.push(active);
        }
        let witness = RLNWitnessInput::new_multi()
            .identity_secret(identity.secret())
            .user_message_limit(Fr::from(u64::from(membership.user_message_limit())))
            .merkle_proof(membership.merkle_proof(member_index)?)
            .x(message_signal(message))
            .external_nullifier(ext)
            .message_ids(ids)
            .selector_used(selectors)
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
    /// accepted membership roots, requiring it to spend EXACTLY
    /// `expected_units` distinct units (the record's size-bucket weight).
    pub fn verify(
        &self,
        blob: &[u8],
        accepted_roots: &[Fr],
        epoch: u64,
        message: &[u8],
        expected_units: u32,
    ) -> Result<Verified, RlnError> {
        let bundle = RLNProof::deserialize_compressed(blob)
            .map_err(|e| RlnError::Serialize(e.to_string()))?;

        // Bind the proof to THIS epoch: external_nullifier is a public input, so
        // a prover could otherwise pick another window to dodge the nullifier
        // collision. Recompute and require a match.
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

        let slots = active_slots(&bundle)?;
        // The verifier — not the prover's client — enforces the record's cost:
        // exactly `expected_units` active slots, all with distinct nullifiers
        // (distinct nullifiers ⇔ distinct message-ids under a fixed epoch).
        if slots.len() != expected_units as usize {
            return Err(RlnError::WrongUnits { got: slots.len() as u32, want: expected_units });
        }
        for i in 0..slots.len() {
            for j in (i + 1)..slots.len() {
                if fr_key(&slots[i].nullifier)? == fr_key(&slots[j].nullifier)? {
                    return Err(RlnError::WrongUnits {
                        got: slots.len() as u32 - 1,
                        want: expected_units,
                    });
                }
            }
        }
        Ok(Verified { slots, root: bundle.values.root() })
    }

    /// Extract a blob's active slots WITHOUT any SNARK verification. Only for
    /// warm-scanning locally stored records that already passed admission when
    /// they were written — never for inbound records.
    pub fn peek_slots(&self, blob: &[u8]) -> Result<Vec<Slot>, RlnError> {
        let bundle = RLNProof::deserialize_compressed(blob)
            .map_err(|e| RlnError::Serialize(e.to_string()))?;
        active_slots(&bundle)
    }
}

/// The (nullifier, share) of each ACTIVE slot in a proof's public values.
fn active_slots(bundle: &RLNProof) -> Result<Vec<Slot>, RlnError> {
    let nullifiers = bundle.values.nullifiers().ok_or(RlnError::MalformedValues)?;
    let ys = bundle.values.ys().ok_or(RlnError::MalformedValues)?;
    let selectors = bundle.values.selector_used().ok_or(RlnError::MalformedValues)?;
    if nullifiers.len() != ys.len() || ys.len() != selectors.len() {
        return Err(RlnError::MalformedValues);
    }
    let x = bundle.values.x();
    Ok(nullifiers
        .iter()
        .zip(ys)
        .zip(selectors)
        .filter(|(_, &used)| used)
        .map(|((n, y), _)| Slot { nullifier: *n, share: (x, *y) })
        .collect())
}
