# Count privacy — single-record multi-key transport

**Status: landed** (`crates/epix-envelope/src/multislot.rs`). Closes the recipient
**device/recipient-count side channel** that a naive per-device fan-out opened.

## The leak this closes

A message to `mud.epix` must reach every one of mud's linked devices. The first
cut ([`channel-multi-device.md`](channel-multi-device.md)) did that by posting one
pool record per device. But records are flooded to peers as a batch, so a peer
directly connected to the *sender* could **count the records in the burst** and
recover the recipient's device count. Linked-identity counts are **public on
chain**, so a *unique* count (mud has 3, nobody else does) deanonymizes the
recipient — a leak about the recipient, inferred at send time, that the recipient
cannot control. (An external pool *reader* never saw this — the legs are
unlinkable by any public field — only a peer who can batch-count the push did;
audited in the git history of this PR.)

## The fix: one fixed-width record per send

A send now packs **all** its destinations (every device of every recipient) into
ONE pool record carrying a **fixed** number of slots, [`SLOTS`] = 8. The
observable record count is therefore independent of how many devices or
recipients the message actually reaches — a 1-device DM and an 8-destination
group are byte-identical in shape.

```
ct = [ SLOTS × 32B detection-tag ]     real device tags + uniform random dummies
     [ SLOTS × 512B keyslot ]          per-device pairwise seal of K_msg (or dummy)
     [ 4B body_len ][ body_ct ]        ONE shared AEAD body under a fresh K_msg
     [ random pad → pad bucket ]
```

- The public pool record is unchanged (`{v, epoch, tag, ct, pow, author, sign}`);
  the **frozen `epix-pool-1` primitive is untouched**. The record's `tag` is a
  fresh **random routing** value (shard placement only) — the real detection tags
  live inside the opaque `ct`.
- **The ratchet engine is untouched.** Each real slot is a normal per-device
  pairwise seal — of the tiny key payload `K_msg ‖ H(body_ct)` instead of the
  message — so per-device Double Ratchet, forward secrecy, and the sealed-sender
  anti-spoof are all preserved. The one new primitive is the shared-body AEAD
  (ChaCha20-Poly1305 under a fresh single-use key), bound to each keyslot by the
  hash so no substituted body is ever accepted.
- **Dummies are indistinguishable.** A dummy slot is a uniform-random 32B tag +
  uniform-random 512B block — the same shape as a real (pseudorandom tag +
  AEAD-random keyslot) — so the real count is unrecoverable even by position.
- **Cheap on the wire.** The body is encrypted once and shared; only the small
  key is wrapped per device, so hiding the count costs ~SLOTS×512B per record, not
  SLOTS×message.

## Receive

Each recipient device scans the `ct`'s SLOTS tags for one of its own
(Tier-1 O(SLOTS) hashset lookups), opens the matching keyslot with its normal
pairwise session → `K_msg` → decrypts the one shared body. A record not addressed
to a node matches no slot and is skipped. One record reaches many recipients: each
independently opens its own slot of the *same* record (tested).

## Chosen parameters

- `SLOTS = 8` — hides any realistic personal multi-device set and small groups in
  one record. There is **no on-chain cap** on linked identities (verified in
  `x/xid`: `LinkIdentity` checks only ownership + address-uniqueness, no count
  param), so a send to more than `SLOTS` destinations spans the minimum number of
  fixed-width records — leaking only ">SLOTS", never the exact count.
- `KEYSLOT_LEN = 512` — fits the first-contact header block (144) + framing + the
  64B key payload; first-contact and established keyslots pad to the same size, so
  they are byte-equal and indistinguishable from a dummy.
- Pool `pad_buckets` widened to `[8192, 32768, 131072]` with `max_record_bytes
  200000` (the fixed slot overhead is ~4.4KB; the smallest record is ~8KB). This
  is an **owner-signed content.json descriptor change** — it takes effect when the
  mail site is re-signed (same step as the cutover runbook).

## Cost & residuals (honest)

- **Fixed ~8KB floor per record** — the price of a constant width. Fine at mail
  volume; notable on Tor. Larger `SLOTS` widens the floor.
- **Tier-2 first-contact probing is SLOTS× per foreign record** (probe each slot).
  Only records that miss Tier-1 pay it, and each probe is one cheap DH; still, at
  scale it is 8× the pre-multislot first-contact cost.
- **Groups > SLOTS destinations** span `ceil(N/SLOTS)` records. They are
  cryptographically unlinkable (fresh routing tag / author / `K_msg` / shard each),
  but if appended back-to-back a peer watching the flood could correlate the
  simultaneous same-size records by transport timing+size and read off a *bucketed*
  destination count (e.g. 3 records ⇒ 17–24 destinations) — slightly stronger than
  a bare ">SLOTS". **Now mitigated (`channel.rs::append_records_jittered`):** the
  first record is posted immediately (byte-identical to a normal single-record
  send, so it adds no signal), and the remaining records are dribbled out from a
  detached task with a random per-record gap (`channel_burst_jitter_max_secs`,
  default 60s), so they are no longer a simultaneous same-size burst. A determined
  global observer with long-window statistics can still infer *something* (jitter ≠
  mixnet), but the real-time burst-count is gone. Below SLOTS there is no such leak
  (one record) and no delay. The deferred records are already sealed with their
  ratchet advanced+persisted, so a deferred append is crash-safe: an unlucky
  shutdown may only fail to *deliver* a large-group send to some recipients, and a
  resend re-posts on the advanced ratchet (no key reuse).
- **Send origin** to a directly-connected peer (that you sent *something*) is
  unchanged — closed only by Tor-Always + send jitter, as before. This fix removes
  the *recipient* count from what that peer can infer, not the fact of a send.
- Slots are **shuffled** (real + dummy), so real slots are not a fixed prefix —
  defense-in-depth in case real/dummy content indistinguishability ever regresses.

### Multiple channel identities on ONE node — supported

A single count-hiding record legitimately carries a slot for several recipients, so
a node hosting **two or more channel identities** (e.g. two personas of one
operator on one machine — distinct from two *devices* of a name, which are separate
nodes) that are both addressed in the same record delivers the message to **every**
addressed local identity, one inbox row each. `process_record` returns
`Vec<ProcessOutcome>` (one per delivered slot); it scans every (identity × slot),
and idempotency + the `processed` set are keyed on **`(sign_h, identity_id)`** —
so a slot still deferred for one identity (its sender bundle not yet synced) is
re-checked independently of another identity's delivered slot in the same record,
and a rescan produces no duplicates. The record-wide `msg.sign_h` UNIQUE became
`UNIQUE(sign_h, identity_id)`; a pre-existing db is migrated in place
(`ChannelDb` schema v2) preserving all messages and ratchet state. The related
first-contact **scan-abort** bug (a deferred slot aborting the record's remaining
slots) is fixed too: the anti-spoof deferral returns `None` so the scan continues.

## Tests

`crates/epix-channel/tests/indexer.rs`:
- `multislot_hides_destination_count` — a 1-destination and a 3-destination send
  produce single records of **identical size**, each with exactly `SLOTS` slots of
  one fixed keyslot length.
- `multislot_one_record_reaches_multiple_recipients` — bob and carol each index
  their own slot of the **same** record.
- the existing end-to-end / first-contact / reply / group / spoof / multi-device
  tests all pass over the multi-slot transport unchanged.

`crates/epix-envelope/src/multislot.rs` unit tests: ct pack/unpack round-trip and
fixed-width padding; `pack` rejects an over-large body; the shared-body hash
binding rejects a substituted body and a wrong key; keyslot payload round-trip.
