# Metadata-private channels (mail, forum, DMs) over the anonymous envelope pool

This documents the design and the operational cutover for moving Epix messaging
from a content-private / metadata-public model to full metadata privacy: no
observer, node operator, or future pool-holder can learn who talks to whom, when,
or that a given user posted anything at all. Mail is the first surface; the same
substrate carries encrypted forums and DMs.

## Vocabulary (the north star)

One primitive, named consistently at every layer:

- **Envelope** — a sealed, size-padded, day-bucketed, anonymous record in the
  pool. The wire unit; completely app-neutral.
- **Pool** — the fully-replicated, PoW-gated anonymous transport the envelopes
  live in (weekly + fanout shards). Fetching signals nothing.
- **Channel** — the encrypted audience an envelope is addressed to, and its
  membership/permission context. **This is the unifier**: a 1:1 mail thread is a
  2-member channel; a forum category is an N-member channel with post/read
  permissions. "Mail" and "forum" are channel *types* / UI surfaces, not separate
  architectures.
- **Message** — a decrypted unit inside a channel.
- **Engine** — the crypto that seals/opens envelopes for a channel. Pairwise
  (X3DH + Double Ratchet, `epix-pairwise-engine`) today; a group engine
  (MLS / sender-keys) for large permissioned channels later. Both implement the
  same `epix_envelope::Engine` seam.

## Channels: one primitive, many surfaces

Everything below the `Engine` is **channel-agnostic** — the pool, the detection
tags, the trial-decrypt indexer, and the private index don't care whether an
envelope was sealed for a 2-member DM or an N-member forum category:

- **Read access = channel membership** (you hold the channel key). Removing a
  member + rotating the key locks them out of future messages (post-compromise
  security). Adding a member grants it going forward.
- **Post access / moderation = an app-layer ACL** the readers enforce (the
  envelope names its sender; readers ignore posts from unauthorized members). The
  crypto guarantees only members *read*; the ACL decides who is *heard*.
- **Visibility = the per-channel detection tag** is unpredictable without the
  channel key, so outsiders can't even detect a channel's envelopes.

**The one hard problem** for large channels: MLS wants group operations
(member add/remove "Commits") applied in a total order per channel, but the pool
is eventually-consistent (partial order). Solvable (designated sequencer per
category / single-committer epochs / fork-and-heal) but it is the real design
work the group engine needs. Pairwise mail sidesteps it (no shared group state).

**Recommended crate path**: the next store crate is `epix-channel` (channels +
members + messages), NOT a second mail-specific schema — mail, forum, and DMs are
UI surfaces over one channel store. The group engine is `epix-group-proto`
(MLS-backed), a sibling of `epix-pairwise-engine`, behind the same `Engine` seam.

## Layers

1. **Generic anonymous envelope pool** (`epix-content::pool`, `epix-ui::pool`).
   A reusable primitive — *any* xite can declare a `pool` in its root
   content.json and get a fully-replicated, PoW-gated, size-padded, day-bucketed
   set of anonymous sealed records sharded by week and fanout
   (`pool/w<week>/<xx>.json`, class `epix-pool-1`). The node appends, inbound-
   merges (grow-only union, no signer ACL — records self-verify via PoW + a
   throwaway-key signature), sweeps the current week, backfills history
   newest-first, and broadcasts every landed record on a delta bus. It knows
   nothing about mail.

2. **Private index + capability/feed registries** (`epix-ui`). A generic typed
   capability registry (`install_capability`/`capability::<T>`) lets a plugin
   stash state its WS commands retrieve; a generic `LocalFeedSource` registry
   folds private (never-shared) rows into `feedQuery`/`notification_query`.

3. **Channel consumer** (`epix-plugins::channel`, `epix-channel`). The `ChannelPlugin` owns
   the private `<data_root>/private/channels.db` (decrypted threads/messages, FTS5
   search, ratchet sessions, the detection-tag set), subscribes to the pool
   delta bus, trial-decrypts each record (Tier-1 O(1) tag lookup; Tier-2 cheap
   first-contact probe per identity), and serves the `channel*` WS commands. The
   private index lives outside every xite dir, so peers can never fetch it.

4. **Crypto engine** (`epix-pairwise-engine`). Real X25519 X3DH + Double Ratchet
   (symmetric + DH ratchet) with header encryption, forward-secure detection-tag
   chains, and Elligator2 first-contact tags. Drop-in for the test-only
   `FakeEngine` via the `epix_envelope::Engine` trait.

## Guarantees & residuals

- **Sender anonymity**: each pool record is posted under a fresh throwaway
  keypair; the sender's own copy is never posted (written straight to the private
  index). Nothing in a record ties it to its author.
- **Recipient anonymity**: detection is local trial-decryption; fetching any
  shard signals nothing (full replication, exhaustively enumerable paths).
- **Content**: X3DH + Double Ratchet → forward secrecy and post-compromise
  security; ChaCha20-Poly1305 AEAD.
- **Residuals** (honest): account existence + bundle per xID; coarse liveness
  from bundle-update times; total pool volume + per-record size bucket + day;
  **send-origin visible to directly-connected peers** (mitigated by Tor-Always +
  publish jitter); a seed compromise exposes the *first* message of a session
  (no one-time prekeys) — every later message stays protected by the ratchet.
- **Deviations to review before production**: BLAKE3 KDFs instead of
  HKDF-SHA256 (not Signal-wire-compatible); no OPKs; alpha `curve25519-elligator2`.
  Freeze test vectors + external crypto review before real cutover.

## Config (node)

`channel_enabled`, `channel_xite`, `channel_backfill_weeks` (0=all, newest-first),
`channel_send_jitter_max_secs`, `channel_burst_jitter_max_secs` (default 60; the
random per-record gap that spaces the SECOND-and-later records of a >SLOTS
multi-record send so the flood can't be counted as one send — `0` disables; see
[`channel-count-privacy.md`](channel-count-privacy.md)), `channel_feed_snippets`,
and `channel_allow_insecure_engine` (DEV only — runs the FakeEngine, which provides
no confidentiality).

## Site (mail xite) changes

- **content.json**: `pool.channels` descriptor (dir `pool`, class `epix-pool-1`,
  `since_week`, `fanout` 16, `pow_bits` 20, `pad_buckets` [512,2048,8192],
  `sync_order` newest_first); `distribution.paths["pool/"]` complete retention;
  `ignore` excludes `pool/`. Re-sign + publish via the node UI.
- **dbschema.json** → v3 (drops the old `message`/`conversation` tables on
  rebuild); shrinks to keyvalue bundle-discovery only. Pool shards are NOT
  dbschema-mapped (envelopes never enter the shared sqlite).
- **data/users/content.json** + default template: `permission_rules` trimmed to
  `files_allowed: data.json`, `max_size` 8192; the `messages.json` merge file is
  removed (its absence deletes legacy mailboxes on resync).
- **js/Channel.js**: the client API over the `channel*` commands. Remaining UI rewiring
  (User.js send → `Mail.send`, ThreadStore → `Mail.threads`/`Mail.conversation`,
  StartScreen → `Mail.publishKeyBundle`, MessageCreate → `Mail.keyLookup`,
  SearchBar → `Mail.search`, delete `js/utils/Crypto.js`/`SearchIndex.js`, and
  the `mailEvent` branch in the app's `onRequest`) follows this API.

## Hard cutover (≈13 users, coordinated)

The `epix-orset-1` merge never removes a version, so tombstoning cannot scrub the
already-leaked legacy metadata; the goal is to stop *serving* it via file
deletion. Ordered:

- **Phase 0**: all users upgrade to the node release with mail; owner sets
  `channel_enabled` + `channel_xite`.
- **Phase A** (per user): `channelMigrateLegacy` imports decryptable legacy messages
  into the private index (implemented alongside this cutover).
- **Phase B** (per user): `Mail.publishKeyBundle` overwrites `data.json` with the
  bundle only and re-signs the user's content.json.
- **Phase C** (owner, single publish): ship the new JS + content.json (pool) +
  dbschema v3. DB rebuild drops old tables; `messages.json` deleted on resync;
  legacy `data.json` >8 KB invalid until republished. **C follows B for all
  users** (owner greps `data/users/*/data.json` bundle-only first; keeps a
  pre-C offline archive of `data/users/`).

## Verification (forbidden-metadata checklist — must return nothing)

```
grep -lE '"(from_xid|to|recipient|members|conv_id|peer_xid|subject|seq|author)"' pool/w*/*.json
grep -lr '\.epix' pool/                     # no xid in any shard
grep -lr '<plaintext marker>' pool/         # no cleartext body
grep -lE '"(conversations|ct|peer_xid|my_seq|from_xid)"' data/users/*/data.json
ls data/users/*/messages.json               # none post-cutover
find data/users -name data.json -size +8k   # none
sqlite3 data/users/epixchannels.db '.tables'    # keyvalue/json only
# The private index is un-fetchable: request its path over the wire → refused.
```
