# xID finality — chain-signed digest attestation + thin client verify (DESIGN v2)

**Status: design v2 REVIEWED (adversarial, 2026-08-14) → verdict needs-changes.
Not yet implemented.** Spans two repos: a `x/xid` change (EpixChain) and a thin
verifier (EpixNet `crates/epix-chain`).

## Review outcome — required changes (blocking, must fold in before implementing)

Resolved sub-decisions: **mechanism = C-ve (ABCI++ vote extensions)** — the digest
is recomputed every block, so per-tx signing chases a moving target; vote
extensions re-sign gaslessly inside every precommit. **Key = separate registered
attestation key** — the consensus key never signs app data (no cross-protocol
reuse, smaller blast radius).

**TWO LIVE forgery holes in today's resolver, independent of finality — fix first:**

1. `resolver.rs` verifies the Merkle path against the RPC-supplied `leaf_hash` but
   never recomputes `leaf_hash = sha256(canonical(domain payload))` nor checks the
   entry name == queried name → a hostile RPC serves a genuine proof of a real leaf
   with arbitrary `domain` data and it passes. (CLAUDE.md's "no need to reconstruct
   leaf from domain data" is WRONG and is the root cause.)
2. `attestation.rs::resolve_name` returns the RPC `record` with NO proof binding it
   to the finalized digest — record-level RPC trust off a whole-state digest.

**Finality hardening (all required):**

- Verify each attestation against the **PINNED** pubkey (never the RPC-supplied
  one); require the full `(valcons→pubkey,power)` triple to match a pinned row.
- **Strict** threshold `sum*3 > 2*total` (not ≥), against the pinned total.
- Dedup by `valcons` within a consensus round. Require the full threshold in one
  round. Never sum valid votes from different rounds.
- Canonical sign-bytes: fixed-width big-endian `height(u64)`+`block_time(i64 nanos)`,
  length-prefixed `chain_id`+`digest`, fixed-length domain tag. Freeze a byte-layout
  KAT; client reconstructs over the digest it independently bound to `proof_root`.
- Freshness: `|now−block_time| ≤ skew` **and** `height ≥ max_height_seen`. Persist
  the accepted height and digest atomically before returning success. Reject a
  lower height and a different digest at the same height after restart.
- Weak-subjectivity: ship the pin with `pinned_at_time`; **fail closed** when
  `now − pinned_at_time > WS_PERIOD` (< unbonding/2), and reject bundles whose height
  lags the pin beyond the window.
- Power-drift safety buffer: require e.g. **≥80% of pinned power** (not bare 2/3) and
  re-pin on any add/remove/jail/unbond and on >threshold share drift.
- Threshold by **voting power, not validator count** (chain currently counts
  validators; must switch), and `block_time` is BFT-time (size skew accordingly).
- **Equivocation slashing** — DECIDED: **no slashing** (combined-push, small
  operator-controlled set). The honest claim is therefore "signed by **>2/3 of a
  pinned validator set** (no equivocation penalty)", and the exposure is bounded by
  the WS pin-expiry + the ≥80% power safety-buffer above — NOT claimed equal to
  consensus finality.

**Delivery: one combined push** (both forgery-hole fixes + chain-side
vote-extension attestation + client verifier) on `feat/xid-finality-verification`,
landed as a single reviewed unit.

Full findings: workflow `w7fh379aw` synthesis. The body below is the v2 design the
above amends.

### FINAL DESIGN — consensus-key vote extensions (validators only upgrade)

The shipped design **supersedes the separate-attest-key approach described in the
body below** (`MsgRegisterAttestKey` etc., now removed). Instead of a registered
attest key, it uses **CometBFT's own vote-extension signature**: every validator's
`ExtendVote` payload `{height, block_time, digest}` is signed by its **consensus
key** by CometBFT (the `ExtensionSignature`) as part of the precommit. So:

- **Validators do nothing but upgrade** — no key generation, no registration, no
  config file. Works with HSM / remote signers (the app never touches the key).
- **Slashable for free** — the attestation *is* the validator's precommit, so
  equivocation is covered by CometBFT double-sign slashing (the earlier "no
  equivocation penalty" caveat is gone).
- **Chain** (`evmd/vote_extensions.go`): `PreBlocker` reconstructs
  `MarshalDelimited(CanonicalVoteExtension{extension, height, round, chain_id})`,
  verifies each `ExtensionSignature` against the validator's staking `ConsPubKey`
  (mirrors `baseapp.ValidateVoteExtensions`), uses REAL staking power, persists the
  signature + raw extension + round.
- **Client** (`finality.rs`): pins the **consensus** validator set (already at
  `/validators`), reproduces the same `CanonicalVoteExtension` bytes (hand-rolled
  protobuf — proto3, so a zero `round` field is omitted, the subtle bit), and
  verifies. Still just N ed25519 verifies; no ics23/tendermint-rs.
- **Devnet-verified**: no registration → `finalized: true` automatically; the two
  cross-repo KATs verify the live validator's real consensus-key signature + leaf
  preimage.

### Implementation status — COMPLETE + devnet-verified (2026-08-15)

- ✅ **Client verifier core** — `crates/epix-chain/src/finality.rs`:
  `verify_finality()` + `attest_sign_bytes()` (pinned-pubkey verify, per-round
  valcons dedup, one-round quorum, strict `sum*3 > total*2` + ≥80% buffer,
  freshness, monotonic height, WS pin-expiry) + `parse_bundle()`.
- ✅ **Client leaf-binding** — `leaf.rs` `verify_and_parse_leaf()` hashes the chain's
  canonical `leaf_preimage`, binds the name, parses the snapshot. 5 vectors.
- ✅ **Client config + resolver wiring** — pinned set / chain_id / skew / ws_period /
  durable height-and-digest checkpoint / `xid_verify_finality` gate; `resolver.rs`
  does leaf-binding + `verify_finality_gated`. Missing pins fail startup unless a
  developer explicitly enables the pre-upgrade insecure compatibility mode.
- ✅ **Chain (`x/xid` + evmd)** — `MsgRegisterAttestKey` (+ CLI), ABCI++
  vote-extension signing (`ExtendVote`/`VerifyVoteExtension`/`PrepareProposal`
  wrap/`PreBlocker` verify+majority-block_time+persist), power-based
  `IsDigestFinalized`, `leaf_preimage` in `resolve_with_proof`, extended query. Full
  `make build` green. Completed the proto-gen migration (deleted 6 hand-written
  placeholder files).
- ✅ **Cross-repo KATs** — the `attest_sign_bytes` KAT (Go↔Rust byte-identical) plus
  two REAL-devnet KATs (`devnet_finality_kat`, `devnet_leaf_kat`): the client
  verifies a live devnet validator's ed25519 signature and its exact leaf preimage.
- ✅ **Devnet end-to-end** — single-validator devnet, vote extensions enabled at
  height 3, attest key registered → `finalized: true` (power-based), the client's
  `verify_finality` + `verify_and_parse_leaf` accept the live data; negatives reject.

**Rollout**: `xid_verify_finality` ships OFF; enable it after the chain upgrade sets
`VoteExtensionsEnableHeight`, validators register attest keys, and a pinned validator
set is shipped to clients. Chain commits: `feat/xid-finality-attestation`
(e2a5bc97…1f88c009). Client commits: `feat/xid-finality-verification`.

---

**Original v2 design (amended by the review outcome above):**

## Why v2 supersedes the light-client design

v1 proposed a client-side CometBFT light client (verify the block commit + ICS23
the digest under `AppHash`). **Rejected for this deployment** because:

- **EpixNet runs on mobile.** A light client drags in `tendermint-rs` + `ics23`,
  and per digest does header hashing + N precommit-signature checks + a two-level
  ICS23 proof, plus fetching commits/validator-sets/proofs. Too heavy on a phone.
- **Chain upgrades are cheap here** (small, operator-controlled validator set).

So move the cryptography **onto the chain** (validators sign the digest) and make
the client do only a few `ed25519` verifies + a voting-power sum. No ICS23, no
tendermint-rs, no header verification.

## Goal (unchanged)

Cryptographic **client-side** proof that a resolved `name → digest` is finalized by
≥2/3 of validator voting power. No trusting a bare RPC `finalized` boolean.

## Trust model

- **name → digest**: existing client-side domain Merkle proof — *unchanged*.
- **digest → finalized**: client verifies `ed25519` signatures from validators over
  a domain-separated message binding the digest, summing to ≥2/3 voting power,
  against a **config-pinned validator set** (weak subjectivity). The
  `auto:consensus` boolean is no longer trusted.

## Feasibility facts (mainnet, 2026-08-14)

`chain_id = epix_1916-1`; consensus keys ed25519; small validator set with
`voting_power` exposed at `api.epix.zone/cosmos/base/tendermint/v1beta1/validatorsets/latest`;
xid store key `xid`; the `MsgAttestStateDigest{Signer,Digest,Signature}` message and
an `Attestation{ValidatorAddr,Digest,Signature,Height}` store already exist in
`x/xid` — but `SubmitAttestation` never verifies `Signature`, and BeginBlock
auto-writes `Signature:"auto:consensus"`. v2 makes those signatures real.

## Sign-bytes & keys — the two critical security decisions (for review)

1. **Domain separation / key choice.** A validator signature over app data MUST NOT
   be reinterpretable as a CometBFT consensus vote (or vice versa). Two options:
   - **(preferred) Separate attestation key**: each validator registers an
     `ed25519` attestation pubkey on-chain (a `Msg` signed by its *operator* key
     binds `valcons → attest_pubkey`); it signs digests with that key. No consensus
     key reuse at all.
   - **(fallback) Consensus key + strong domain prefix**: sign
     `SHA256("EPIX-XID-ATTEST-v1" ‖ chain_id ‖ height ‖ block_time ‖ digest)`. The
     prefix must be unambiguous vs CometBFT's canonical-vote sign-bytes. Review must
     confirm no cross-protocol collision is possible.
2. **Freshness binding.** The signed message includes `height` **and `block_time`**,
   so a stale-but-valid replay (a hostile RPC serving an old digest + its real old
   signatures) is caught: the client requires `|now − block_time| ≤ skew` and
   `height ≥ max_height_seen` (monotonic). Without this, C is replayable.

## Chain side (`x/xid`) — produce + persist per-validator digest signatures

Two mechanisms; review to choose:

- **C-msg (simpler):** validators run a lightweight signer that submits
  `MsgAttestStateDigest` with a real signature over the sign-bytes above;
  `SubmitAttestation` **verifies** it (against the registered attest key or
  domain-separated consensus key) before storing `{valcons, sig, voting_power,
  height, block_time}`. Cost: each validator runs a signer + pays gas per
  attestation; a digest is "final" only once enough attest txs land.
- **C-ve (cleaner, gasless):** ABCI++ **vote extensions** (Cosmos SDK v0.50 /
  CometBFT v0.38). `ExtendVote` signs the digest; the app collects per-validator
  signatures from `ExtendedCommitInfo` and persists them. No validator daemon, no
  gas, tied to consensus participation. Cost: more chain-dev; vote-extension timing
  (the digest signed lags one block).

Keep `auto:consensus` as telemetry only; the **signed** attestations are what the
client verifies.

## Query (what the client fetches)

`GET /xid/v1/attestations?digest=…` returns:
`{ digest, height, block_time, total_voting_power,
   attestations: [ { validator_consensus_addr, ed25519_pubkey, voting_power, signature } ] }`.
Pubkeys + powers are included so the client only needs its **pinned set** to
cross-check identities, not a second fetch.

## Client side (thin — mobile-friendly)

1. Resolve `name` → domain Merkle proof → `proof_root` (unchanged, client-verified).
2. Fetch the signed attestation bundle for `proof_root`.
3. For each attestation: confirm the validator + pubkey + power match the **pinned
   validator set**; verify the `ed25519` signature over the domain-separated
   sign-bytes.
4. Require summed verified voting power in one consensus round to exceed 2/3 of
   the pinned total and meet the configured safety buffer.
5. **Freshness**: `|now − block_time| ≤ skew` and `height` monotonic non-decreasing.
   Atomically persist the accepted height and digest before returning success.
6. Bind `proof_root == attested digest`; fail closed on any failure.

**Deps: `ed25519` verification only** (light; likely already in-tree). No `ics23`,
no `tendermint-rs`, no header verification. Cost per resolve ≈ N cheap `ed25519`
verifies (small N), cacheable per digest.

## Trust anchor (weak subjectivity)

- Pin `{ valcons → (ed25519 pubkey, voting_power) }` + `chain_id` in
  config/app, re-pinned on validator-set changes (governance / app release). Small,
  slowly-changing set.
- **Optional later**: accept a pinned-set *update* only if signed by ≥2/3 of the
  current pinned set (signed transitions), removing manual re-pin. Out of scope for
  v1 of this feature.

## Config & rollout

- The pinned validator set + `chain_id` must ship as trusted release data after
  the chain upgrade. This is a merge blocker.
- Missing, unreadable, or invalid pins fail startup. Pre-upgrade developers can
  set `EPIX_XID_ALLOW_INSECURE_LEGACY=1` explicitly. Official releases must not.
- `xid_finality_checkpoint.json` stores the highest accepted height and digest.
  Checkpoint load, verification, and publication all fail closed.

## Testing

- **Frozen vectors** from real chain data: a `{digest, height, block_time,
  attestations[], pinned_set}` bundle verified fully offline.
- Negatives: tamper a sig; drop signers below 2/3; wrong pubkey; stale `block_time`;
  non-monotonic `height`; digest≠proof_root; a validator not in the pinned set →
  each must reject.
- Cross-protocol: prove a valid consensus vote can't be replayed as an attestation
  and vice versa (domain separation).

## Non-goals / residuals

- Liveness/censorship (RPC withholding answers) is unchanged — this closes
  *forgery + stale replay*, not availability.
- Weak subjectivity: a client whose pinned set is far out of date must re-pin from a
  trusted source (standard).
- Validator-set-change handling in v1 is manual re-pin; signed transitions are a
  later enhancement.
