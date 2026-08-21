# Group channels — `epix-group-engine` design

**Status: foundation landed** (`crates/epix-group-engine`). The forward-secure
key-management core is implemented and tested; the authenticity, membership, and
node-wiring layers below are the next phases. Do **not** rely on it for real group
confidentiality until the signature layer + review land.

## Why not just fan-out?

Today a group message is sent as **N per-recipient pairwise records** (the
`channelSend` fan-out). That is correct and unlinkable, but costs one pool record
per recipient per message. For real groups this is a **Sender-Keys** design (as in
Signal/WhatsApp groups): one member seals **one** group record that every member
detects and opens.

## What's implemented (the core)

Each member owns a per-group **`SenderChain`**:

- **Message-key chain** (forward secrecy): `mk_i = MAC(ck_i, 0x01)`,
  `ck_{i+1} = MAC(ck_i, 0x02)`, delete `ck_i`.
- **Detection-tag chain** (unlinkable detection): `tag_i = MAC(dck_i, "gtag")`,
  `dck_{i+1} = MAC(dck_i, "gchain")` — the pairwise engine's tag chain, per
  sender-in-group. `LOOKAHEAD == MAX_SKIP == 256`, so any registered tag is
  openable and realistic reorder/loss self-heals (same guarantee as the pairwise
  engine's F3 fix).
- **Out-of-order receive**: `recv_key(n)` ratchets forward storing skipped keys
  (bounded by `MAX_SKIP`), replays a stored skip, or fails closed on an absurd
  jump. It reports the outstanding gap as `GroupOpened.pending` (the same
  delivery-gap hint the pairwise engine surfaces).

`GroupSession` holds a member's own send chain + a receive chain per other member,
with `seal` / `open`, plus `my_bootstrap` / `add_member` for key distribution.
Primitives match the pairwise engine: HKDF-SHA256 / HMAC-SHA256 / ChaCha20-Poly1305.

## Key distribution — reuse the pairwise engine

A member bootstraps another member's receive chain by shipping its
`SenderChain::bootstrap()` (the chain's current `ck`/`dck` + indices) **once over
an existing pairwise session** — i.e. as a normal pairwise message with a
control-type payload. That is the only place the pairwise engine is used: key
distribution, not per-message. On join / membership change, the joining member
sends its bootstrap to everyone and collects theirs.

## The transport: one pool record per group message

A group message is a single `epix-pool-1` record whose `tag` is the sender's group
detection tag and whose `ct` is `AEAD(mk, nonce, ad=tag, payload)`, posted under a
fresh throwaway author exactly like a pairwise record — so from outside a group
message is indistinguishable from a 1:1 message, and the pool stays metadata-free.
The node registers every member's `window_tags()` in the private index and routes
a matched tag to `GroupSession::open(sender_xid, n, tag, ct)`.

## Not yet (ordered)

1. **Per-sender message signatures (REQUIRED before use).** A group record is
   currently authenticated only by the sender key, which every member holds, so a
   member could forge a message as another member. Real Sender Keys attach a
   per-sender signature; the verifying public key ships in the bootstrap. Add an
   Ed25519 (or the existing secp256k1) per-group signing key: sign the record,
   verify on open, reject on mismatch.
2. **Membership changes / rekey.** Add/remove a member → the removed member must
   lose forward access. Sender Keys handle *add* cheaply (send bootstraps) but
   *remove* requires everyone to rotate their sender chain (re-bootstrap). This is
   exactly the property **MLS** provides natively (efficient, forward-secure
   membership changes with post-compromise security). If group PCS-on-membership
   matters, this is where to swap the core for MLS (e.g. OpenMLS) behind the same
   `GroupSession` API — the pool transport and detection-tag scheme are reusable.
3. **Node wiring.** A group variant of the channel plugin: `channelGroupCreate`,
   `channelGroupInvite` (ships bootstraps over pairwise), a `GroupEngine` bound in
   the capability registry, group records on the same pool, and the private index
   storing per-member receive chains.
4. **Review.** Same gate as the pairwise engine: spec + frozen vectors + external
   review before any confidentiality claim.

## Relationship to the pairwise engine

Same threat model, same pool, same primitives, same F3 window semantics. The group
engine is additive — small groups keep working via pairwise fan-out today; the
Sender-Keys path is the scale-up, and MLS is the drop-in for strong membership PCS.
