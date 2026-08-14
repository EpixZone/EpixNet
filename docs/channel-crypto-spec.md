# Epix Channel — Cryptographic Protocol Specification

**Status:** pre-production, **review-gated**. This document specifies the sealed
envelope protocol as implemented in `crates/epix-pairwise-engine` and the
anonymous record class in `crates/epix-content/src/pool.rs`. It exists so an
external cryptographer can audit the construction against the published Signal
X3DH / Double Ratchet specifications and against the code, *before* any
confidentiality claim is relied upon. Nothing here has had external review yet.

**Scope:** the *pairwise* engine (1:1 and small groups via per-recipient
fan-out). The group engine (`epix-group-engine`, MLS-backed) is out of scope.

---

## 1. Notation and primitives

| Symbol | Meaning |
|---|---|
| `‖` | byte concatenation |
| `x_le` | little-endian encoding of integer `x` |
| `b64(·)` | standard base64 |
| `∅` | empty byte string |

All keys are 32 bytes unless stated. Implementation: `curve.rs`, `crypto.rs`.

- **X25519** (`curve.rs`, over the `curve25519-elligator2` Montgomery fork):
  - `DH(sk, pk) = clamp(sk) · pk` (Montgomery ladder).
  - `PUB(sk) = clamp(sk) · basepoint`.
- **Elligator2** (`curve.rs`):
  - `ELL_ENC(sk, tweak) → repr | ⊥`: the uniform 32-byte representative of
    `PUB(sk)`. Fails ~50% of the time (key not representable); the caller retries
    with a fresh key. `tweak` randomizes the unused high bits.
  - `ELL_DEC(repr) → pk`: inverse, for a well-formed representative.
- **HKDF-SHA256** (`crypto.rs::kdf`):
  `KDF(context, salt, ikm, L) = HKDF-Expand(HKDF-Extract(salt, ikm), info=context, L)`.
  Convenience `KDF32 = KDF(·,·,·, 32)`. `context` is an ASCII domain-separation
  string; `L ≤ 255·32`.
- **HMAC-SHA256** (`crypto.rs::mac`): `MAC(key, data) = HMAC-SHA256(key, data)` (32 B).
- **AEAD** (`crypto.rs`): ChaCha20-Poly1305, 16-byte tag.
  `SEAL(key, nonce12, ad, pt) = ct‖tag`; `OPEN(key, nonce12, ad, ct) = pt | ⊥`.
- **Nonce derivation** (`ratchet.rs::nonce_from`):
  `NONCE(label, tag) = KDF(label, ∅, tag, 12)`.

> **Deliberate deviation #1.** The Signal specs use HKDF-SHA256 for KDFs and
> HMAC-SHA256 for chain steps; we match both. An earlier build used BLAKE3 here —
> it was switched to HKDF-SHA256 specifically so this review is a diff against the
> reference, not a re-analysis of a bespoke KDF. The domain-separation `context`
> strings (`epix-channel/…/v1`) are ours.

---

## 2. Identity keys and the published bundle

Each channel identity has a 32-byte **seed** handed to the engine by the node
(`AppState::derive_consumer_seed("channel", auth_address)`); the node master seed
never reaches the engine. Implementation: `keys.rs`.

- **Identity key** `IK`: `IK_priv = KDF32("epix-channel/ik/v1", ∅, seed)`, `IK_pub = PUB(IK_priv)`. Permanent.
- **Signed prekey** `SPK` for weekly index `idx`:
  `SPK_priv(idx) = KDF32("epix-channel/spk/v1", ∅, seed ‖ idx_le32)`, `SPK_pub(idx) = PUB(SPK_priv(idx))`.
  `idx = ⌊now_ms / (7·86400·1000)⌋` (weekly rotation; `current_spk_idx`).
- **No one-time prekeys.** There is no server to consume-once against. **This is
  a real forward-secrecy gap for the first message and it is NOT closed by SPK
  rotation:** `SPK_priv(idx)` is a pure function of the seed for *every* index and
  is never deleted, so an attacker who later compromises the seed recomputes the
  SPK for any past `idx` and, with the retained pool, recovers the full X3DH `SK`
  — hence the plaintext *and* the sender identity of every first-contact (n=0)
  message. Every message from the first reply onward is protected by the DH
  ratchet. Real first-message FS would require a stored-then-deleted responder
  secret mixed into `SK` (genuinely hard serverless). See §7 and §10.

**Published bundle** (`build_bundle`) — the identity's `data/users/<xid>/data.json`
payload; **public material only**:

```json
{ "v": 2, "xid": "<name>", "ik": "<b64 IK_pub>", "spk": "<b64 SPK_pub(idx)>", "spk_idx": <idx> }
```

`verify_bundle` checks structure only. **Bundle authenticity** is *not* self-contained:
it rests on (a) the node verifying the signature on the per-user `data.json`
(only **active, non-revoked** linked keys are accepted signers — `xid_signers::resolve`),
(b) the sealed-sender cross-check in §6.3 (the first message's inner `IK_a` must
match the sender's published bundle, enforced at the node layer), and (c) an
on-chain **revocation gate**: the channel bundle path (`load_published_bundles` →
M1, `channelSend`, `channelKeyLookup`) drops any bundle whose xID has no active
linked identity, via the Merkle-verified `xid_identity::name_has_active_identity`,
failing OPEN when the chain is unreachable. A reviewer should treat "does bundle X
belong to a still-valid xid Y" as delegated to those layers, not to the engine.
**Residual:** the channel IK is node-seed-derived, not bound to the linked chain
key, so the gate retires the *bundle/attribution* of a revoked identity, not the
IK itself; true per-key IK retirement would require binding IK to the linked key.

---

## 3. X3DH key agreement

No one-time prekey; the initiator's ephemeral is also its first-contact detection
tag. Implementation: initiator `ratchet.rs::begin`, responder `ratchet.rs::open_first`.

**Initiator (Alice)** has `seed_A` (⇒ `IK_A`), and Bob's bundle `(IK_B, SPK_B, idx_B)`:

1. Sample a **representable ephemeral** `EK_A`: loop `ELL_ENC(EK_A, tweak)` until it
   yields a representative `tag` (the first-contact detection tag, §5.2).
2. `DH1 = DH(IK_A_priv, SPK_B)`  ·  `DH2 = DH(EK_A, IK_B)`  ·  `DH3 = DH(EK_A, SPK_B)`
3. `SK = KDF32("epix-channel/x3dh/v1", salt = 0xFF^32, ikm = DH1‖DH2‖DH3)`

**Responder (Bob)** recovers the same values from the first record's `tag` and
header:

1. `EK_A = ELL_DEC(tag)`; `DH2 = DH(IK_B_priv, EK_A)`; derive `fc_key` (§6.3) and
   open the first-contact header → learn `IK_A`, `ratchet_pub_A`, `idx_B`, `sender_xid`.
2. `SPK_B_priv = SPK_priv(idx_B)`; `DH1 = DH(SPK_B_priv, IK_A)`; `DH3 = DH(SPK_B_priv, EK_A)`.
3. `SK` as above (the three DH values match by X25519 symmetry).

> **Deliberate deviation #2.** Signal's X3DH puts the `F = 0xFF^32` curve-domain
> constant as an `ikm` *prefix*; we pass it as the HKDF *salt*. Also Signal
> optionally binds associated identity data into `info`; ours is the fixed context
> string. Both are self-consistent choices to confirm in review, not known
> weaknesses.

Sender authenticity is **implicit from `SK`** (only the `IK_A`-holder can form
`DH1`) plus the `sender_xid`↔bundle cross-check — i.e. **sealed sender** with no
signature over content (deniable). See §7.

---

## 4. Double Ratchet

Signal Double Ratchet (symmetric-key + DH ratchet, skipped-key storage) with
**header encryption**. Session state: `ratchet.rs::Session`. KDF chains:

- **Root KDF** (`kdf_rk`): `(rk', ck) = split64( KDF("epix-channel/rk/v1", salt=rk, ikm=dh_out, 64) )`.
- **Chain KDF** (`kdf_ck`): `ck' = MAC(ck, 0x02)`, `mk = MAC(ck, 0x01)`.
- **Message key split** (`mk_keynonce`): `(mk_key, mk_nonce) = split(KDF("epix-channel/mk/v1", salt=mk, ikm=∅, 44))` → 32-byte key ‖ 12-byte nonce.

**Init.** Alice (`role 0`): `dhs =` fresh keypair, `dhr_pub = SPK_B`,
`(rk, cks) = kdf_rk(SK, DH(dhs_priv, SPK_B))`. Bob (`role 1`): `dhs = SPK_B keypair`,
`rk = SK`, `cks = ckr = ⊥`; his first receive triggers a DH-ratchet step
(`dh_ratchet`) that reproduces `ckr = cks_Alice` by X25519 symmetry.

**DH ratchet** (`dh_ratchet`): on a header carrying a new `dhr`, set `pn=ns`,
reset counters, `(rk, ckr) = kdf_rk(rk, DH(dhs_priv, dhr))`, generate a fresh
`dhs`, `(rk, cks) = kdf_rk(rk, DH(dhs_priv', dhr))`.

**Skipped keys.** `skip_message_keys` advances the receive chain storing `mk`s for
gaps; `MAX_SKIP = 64` refuses absurd jumps, and `ratchet_decrypt_key` returns
`None` explicitly when a skip is refused (rather than deriving a wrong-index key
that only the AEAD would reject). **Both** skipped stores are hard-capped and
evicted oldest-first: skipped message keys (`skipped_mk`) and skipped header keys
(`skipped_hk`, in `header_key_for`) are each bounded to `MAX_SKIP` entries — this
is what keeps the retained-key set from growing without limit over the indefinite
pool. The published tag window (`LOOKAHEAD`) is kept **equal** to `MAX_SKIP` (§5.1),
so any record whose tag is registered is also openable and vice-versa: there is no
longer a "recoverable-by-the-ratchet but never-registered" gap. A head-of-chain
loss only stalls a direction past `MAX_SKIP` consecutive records — a rare, hard
case that still surfaces as an ordinary `NoMatch` (a UI "session stalled, ask the
peer to resend" signal needs node-level session-liveness tracking; §10).

**Headers** (plaintext, fixed width, then AEAD):

- **Established** (`EST_HDR_PLAIN = 40`): `dhs_pub(32) ‖ pn_le(4) ‖ ns_le(4)`.
  Sealed with the tag-chain **header key** `hk` (§5.1), nonce `NONCE("est-hdr", tag)`,
  AD `= tag`. Block = 40 + 16 = **56**.
- **First contact** (`FC_HDR_PLAIN = 128`): `IK_a(32) ‖ ratchet_pub_a(32) ‖ idx_le(4) ‖ xid_len_le(2) ‖ xid(≤58) ‖ zeros`.
  Sealed with `fc_key` (§6.3), nonce `NONCE("fc-hdr", tag)`, AD `= tag`. Block = 128 + 16 = **144**.

Established and first-contact records are byte-indistinguishable to an observer
(both are `tag ‖ opaque bucket-padded ct`; header type is not in cleartext).

---

## 5. Detection tag chains

The transport is a flat pool everyone replicates; a recipient must find *their*
records cheaply, without a per-record trial decryption and without a linkable
tag. Two tiers.

### 5.1 Established (Tier 1) — forward-secure tag chain

Each direction has a tag-chain key `tck`. Per index `i` (implementation
`tag_of`/`hk_of`/`next_tck`):

- `tag_i = MAC(tck_i, "tag")` — the record's **public** detection tag.
- `hk_i  = MAC(tck_i, "hdr")` — the header key for that record.
- `tck_{i+1} = MAC(tck_i, "chain")`, then `tck_i` is deleted (forward secrecy of past tags).

Seeds (`begin`/`open_first`): `tck_send = KDF32("epix-channel/tck/v1", salt=SK, ikm="a2b"|"b2a")`,
`tck_recv` the mirror. Alice sends on `a2b`; Bob sends on `b2a`.

**Detection = O(1)** exact-match of `tag_i` against a stored set of expected tags.
A session publishes a **window** of the next `LOOKAHEAD = 64` receive tags
(`window_tags`) to that set; `header_key_for` fast-forwards over gaps (storing
skipped `hk`s, bounded by `MAX_SKIP`). Past tags are unlinkable (PRF outputs from
a deleted chain state).

> **Deliberate deviation #3.** Signal has no such tag chain (its server routes by
> account). This is bespoke. It is *not* Fuzzy Message Detection: full replication
> already makes *fetching* signal-free, so exact-match tags suffice. Review focus:
> the tag is a PRF output that leaks nothing about the key; a stalled chain past
> `LOOKAHEAD`/`MAX_SKIP` must fail closed (it does), and ideally surface a
> "session stalled" signal (a node-level follow-up). `LOOKAHEAD == MAX_SKIP`, so
> a registered tag is always openable.

### 5.2 First contact (Tier 2) — Elligator2 tag

The first record's tag is `ELL_ENC(EK_A, tweak)` — the uniform representative of
the initiator's ephemeral. It is indistinguishable from a Tier-1 PRF tag.
Detection probe (`fc_candidate`), per identity per otherwise-unmatched record:
`EK_A = ELL_DEC(tag)`; `DH2 = DH(IK_priv, EK_A)`; `fc_key = KDF32("epix-channel/fc-hdr/v1", salt=tag, ikm=DH2)`;
`OPEN(fc_key, NONCE("fc-hdr", tag), tag, ct[..144]) ≠ ⊥`. Cost: **1 Elligator
decode + 1 X25519 + 1 AEAD open** per identity per candidate.

---

## 6. Record body and message lifecycle

### 6.1 Payload

`build_payload` → JSON, then padded/sealed (never sent in the clear):
`{ "c": conv_hex, "m": [members], "s": subject, "b": body, "t": sent_ms }`.

`pad_payload(p, width) = len_le(4) ‖ p ‖ zeros` to `width`. Body block =
`SEAL(mk_key, mk_nonce, ad=tag, padded)`. `choose_bucket` picks the smallest
declared bucket `≥ header_block + 16 + 4 + payload_len`, so record sizes fall into
a few fixed classes.

### 6.2 Record ciphertext

`ct = header_block ‖ body_block`. Established: `56 ‖ (bucket-56)`. First contact:
`144 ‖ (bucket-144)`.

### 6.3 First-contact key

`fc_key = KDF32("epix-channel/fc-hdr/v1", salt=tag, ikm=DH2)` where `DH2 =
DH(EK_A, IK_B) = DH(IK_B_priv, EK_A)`. Note `DH2` is *also* one of the three X3DH
inputs; domain separation is by the distinct HKDF `context`/`salt`. **Review
focus:** confirm using `DH2` for both `SK` (inside a 3-DH KDF) and `fc_key`
(directly) introduces no cross-protocol interaction.

### 6.4 Lifecycle

- **`seal`** — initiator's first message: first-contact record (§4 FC header + body
  at `n=0`); thereafter established records. Responder/subsequent: established.
- **detect** — Tier-1 tag-set hit (`open`) else Tier-2 probe (`fc_candidate` →
  `open_first`).
- **`open_first`** — responder path: derive `SK`, init Bob's ratchet, decrypt the
  `n=0` body, record `conv_id` from the payload, publish the next receive window.
- **`open`** — established: recover `hk` for the tag index, decrypt the header,
  advance/ratchet to the message key, decrypt the body, publish the next window.

Sent messages are recorded to the sender's private index directly and **never**
posted encrypted-to-self.

---

## 7. Security properties (claims to be checked)

- **Confidentiality / integrity** — X3DH-derived `SK`, Double Ratchet message keys,
  ChaCha20-Poly1305 AEAD with `ad = tag`.
- **Forward secrecy (established messages)** — symmetric-ratchet chain keys are
  advanced then dropped; tag-chain `tck` deleted per step. A seed compromise does
  **not** recover past *established* message keys or ratchet state — that state is
  random per-session and never re-derivable from the seed. **Caveat (no OPK):**
  first-contact (n=0) messages have **no** forward secrecy against seed compromise
  — see §2. There is no `gen`/rekey mechanism in the code; do not assume one.
- **Post-compromise security** — the DH ratchet reintroduces fresh entropy each
  round-trip. Note the detection **tag chain has FS but NOT PCS**: it is decoupled
  from the DH ratchet, so a one-time compromise of a live `tck` yields all future
  tags + header keys for that direction (message bodies still heal via the ratchet).
- **Sealed sender** — sender identity appears only inside the encrypted
  first-contact header; established records carry no sender field. A first-contact
  message proves knowledge of `IK_a` via `DH1`, but the recipient binds that to a
  *name* only by the node's mandatory check `sender_ik(published_bundle) == ik_a`
  (`process_record`); without it the free-text `sender_xid` is spoofable.
- **Deniability** — no signature over message content (the pool record's ECDSA is
  by a throwaway ephemeral author over the *record*, not the plaintext).
- **Metadata privacy** — anonymous pool records: fresh ephemeral author, no
  sender/recipient/conv fields, size-padded to buckets, day-granular `epoch`. See
  the pool record class (`epix-content/src/pool.rs`) and the design doc
  `docs/channels.md`.

**Residual leaks (honest):** account existence + bundle contents per xid; coarse
liveness from bundle-update times; total pool volume + per-record size class + day;
**publish origin to a directly-connected peer** (largest residual — mitigated by
Tor-Always). **Seed compromise** (with the retained pool) fully recovers the
**content and sender identity of every first-contact (n=0) message** to that
identity, and reveals which pool records were first-contacts to it; it does
**not** recover the content of established (n≥1) messages, whose ratchet state is
not seed-derivable.

---

## 8. Parameters

| Name | Value | Where |
|---|---|---|
| `LOOKAHEAD` | 64 | published receive-tag window (== `MAX_SKIP`) |
| `MAX_SKIP` | 64 | skipped keys, jump bound, self-healable head gap |
| `FC_HDR_PLAIN` / block | 128 / 144 | first-contact header |
| `EST_HDR_PLAIN` / block | 40 / 56 | established header |
| AEAD tag | 16 | ChaCha20-Poly1305 |
| SPK rotation | weekly (`⌊now/7d⌋`) | `current_spk_idx` |
| X3DH salt | `0xFF^32` | `begin`/`open_first` |
| chain-KDF constants | `mk = MAC(ck,0x01)`, `ck' = MAC(ck,0x02)` | `kdf_ck` |

**HKDF context strings:** `epix-channel/{ik,spk,x3dh,fc-hdr,rk,mk,tck}/v1`, plus
nonce labels `{est-hdr, fc-hdr}` and MAC labels `{tag, hdr, chain}`.

---

## 9. Deviations from stock Signal (summary for the reviewer)

1. HKDF-SHA256 / HMAC-SHA256 (matches Signal) but with our own `info`/context strings.
2. X3DH: `F=0xFF^32` as HKDF salt (not ikm prefix); no one-time prekeys.
3. Elligator2 first-contact tags (uniform, unlinkable) — not in Signal.
4. Forward-secure detection **tag chains** for O(1) matching over a replicated pool — not in Signal.
5. Header encryption keyed by the tag chain (`hk`), a variant of Signal's HE Double Ratchet.
6. `DH2` reused across `SK` (inside 3-DH KDF) and `fc_key` (direct), separated by context/salt.
7. Nonces derived deterministically from the public `tag` via HKDF (uniqueness argued per-header-key).

---

## 10. Review checklist / open questions

- [ ] X3DH transcript: is implicit `SK` authenticity + node-layer bundle cross-check sufficient, or is an explicit transcript MAC warranted?
- [ ] `DH2` cross-use (§6.3) — any interaction between `SK` and `fc_key`?
- [ ] X3DH salt = `0xFF^32` — confirm no weakening vs. Signal's ikm-prefix `F`.
- [ ] Nonce derived from public `tag` — confirm `(key, nonce)` uniqueness across all record types and skipped-key replays.
- [ ] `MAX_SKIP`/`LOOKAHEAD` — DoS/stall bounds; behavior at chain exhaustion.
- [ ] SPK rotation with no OPK — FS gap before first reply; is weekly rotation the right bound?
- [ ] Elligator2 representative uniformity as delivered by `curve25519-elligator2` (tweak handling of high bits).
- [ ] Constant-time / side-channel posture of the DH and AEAD paths.
- [ ] Frozen test vectors (`§ tests/vectors`) match an independent implementation.

---

*Pair this spec with the frozen test vectors and the two-state-machine interop
test (both in `crates/epix-pairwise-engine/tests/`), and with the design/threat
model in `docs/channels.md`.*
