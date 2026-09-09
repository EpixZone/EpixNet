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

## Identities and the hub

- **One channel identity per linked xID.** A node holds any number of linked
  identities (see users.json `identities`, the `identity*` WS commands and the
  Config page's Identities section). Each has its own channel key material
  (`derive_consumer_seed("channel", <linked address>)`), its own key bundle
  directory `data/users/<name>.epix/` in the hub, its own RLN membership, and its
  own inbox in the private index (`identity` rows; every identity-scoped table
  carries `identity_id`). A xite's `channel*` commands act as the identity that
  xite currently uses (the node-wide default, or the xite's own choice); an
  explicit `{auth_address}` / `{xid}` parameter names another held identity.
  With no identity, reads answer empty and sends fail with `xID required`.
- **The hub is the xID xite** (`epix1xauthduuyn63k6kj54jzgp4l8nnjlhrsyaku8c`,
  `channel_xite`). It holds every identity's bundle and the pool. Epix Mail is
  a client, like any xite that holds a channel grant. The node auto-adds the hub
  when channels are on, so channels work for a user who never opens Mail.
- **Setup is automatic and node-side.** Linking an identity derives its keys and
  publishes its bundle into the hub (`epix-plugins::channel_setup`): the node
  writes the bundle, signs the identity's `content.json` *as that identity*, and
  publishes. It retries while the hub is not synced or the chain is unreachable
  and reports `published / pending / failed / off` on the Config page and in
  `channelSessionInfo.identity.setup`. This replaces the earlier explicit
  "Generate encryption keys" step: **every linked identity has a public channel
  account unless its channels are turned off first** (`channelIdentitySetEnabled`).
- **Client gate.** Only Epix Mail, a trusted operator session, or a xite holding
  `ADMIN`, `CHANNELS` (whole inbox) or `Channels:<app>` (one app's threads) may
  call `channel*`. Events (`channelEvent`) are routed to client xites whose
  effective identity matches the event's identity, never to the hub.
- **Shared allowance.** The RLN usage ledger stays per node: every identity a
  node holds spends from one allowance, so outbound volume cannot reveal how
  many personas the node runs. Membership (`member` in `channelRlnStatus`) is
  per identity.

## Channels for every xite (app scope)

Mail is one client. Any xite can carry its own private conversations (DMs in
Talk, encrypted comments, ...) over the same pool, identities and hub:

- **Grant.** The xite asks for `Channels:<app>` through the normal permission
  prompt (`wrapperPermissionAdd`); `<app>` is a short lowercase token such as
  `talk`. `CHANNELS` grants the whole inbox (every app) and is what a mail-type
  client holds; Epix Mail has it implicitly. `permissionDetails` explains both.
- **Scope.** A `Channels:<app>` xite sees, sends and edits only its app's
  threads: `channelThreads`, `channelSearch`, `channelSend`, `channelConversation`,
  `channelMarkRead`, `channelSetConvState`, `channelDeleteLocal` and the `unread`
  count in `channelSessionInfo` are confined to the granted app, and asking for
  another app is refused. A full grant defaults to every app on reads and to
  `mail` on sends; it may pass `{app}` to narrow a read or to tag a send.
- **The tag travels inside the sealed body.** `channelSend([recipients, subject,
  body, {conv_id?, app?}])` puts `a: <app>` in the shared AEAD body next to the
  sender, members, subject and time (`epix-envelope::multislot`). Nothing about
  the app is visible in the pool record. Mail bodies omit the field, so they stay
  byte-identical to the pre-app format and a node that predates the tag reads
  every message as mail. The recipient's indexer stores it as `thread.app`
  (`channels.db` v7); a conversation keeps the app of its first message.
- **Events.** `channelSubscribe([{app?}])` registers the calling xite for
  `channelEvent`s (in memory: call it on every page load). Events carry `app`
  and reach a client only when its scope matches and its effective identity is
  the one the message landed in.
- **Dashboard.** Feed rows deep-link to the xite subscribed for the row's app,
  else to Mail. The mail badge counts unread threads of the apps without a
  subscribed client; each subscribed app gets a badge of its own (`channel:<app>`).

A second client therefore needs `wrapperPermissionAdd("Channels:talk")`, then
`channelSessionInfo`, `channelSubscribe`, `channelKeyLookup`, `channelSend` with
`{app: "talk"}`, and `channelThreads` / `channelConversation` as usual.

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
- **Residuals** (honest): account existence + bundle per xID, published on-chain
  (strictly more than "has an account" — the identity key, current prekey, and
  linked-device count are public); coarse liveness from bundle-update times; total
  pool volume + per-record size bucket + day; **send-origin visible to
  directly-connected peers** — closed by Tor-Always, with optional
  `channel_send_jitter_max_secs` decorrelating send time from the pool write on
  non-Tor deployments; a seed compromise exposes the *first* message of a session
  (no one-time prekeys) — every later message stays protected by the ratchet.
- **Deviations to review before production**: HKDF-SHA256/HMAC-SHA256 chains (an
  early BLAKE3 build was switched to HKDF so review is a line-diff against Signal;
  blake3 now survives only as the multi-slot body-binding hash); no OPKs (the first
  message of a session has no forward secrecy); alpha `curve25519-elligator2` for
  first-contact tags; the count-hiding multi-slot construction. Freeze test vectors
  and get external crypto review before real cutover.

## Config (node)

`channel_enabled`, `channel_xite` (the hub; blank = the xID xite; test networks
only), `channel_legacy_xites` (pools still indexed read-only during the hub
cutover, one per line; default Epix Mail's old pool, blank once the cutover is
done), `channel_legacy_mail_xite` (where `messages.json` legacy mail is read
from; default Epix Mail), `channel_feed_per_identity` (badge unread mail per
identity on the dashboard; off collapses the badges so a shared screen does not
show which personas the node holds), `channel_backfill_weeks` (0=all, newest-first),
`channel_send_jitter_max_secs` (default 0 = off; when set, the WHOLE send is
delayed by a random `0..=max` seconds and detached from the send handler so a
directly-connected peer can't bind "user pressed send" to the pool write —
recommended on non-Tor deployments), `channel_burst_jitter_max_secs` (default 60;
the random per-record gap that spaces the second-and-later records of an
over-`SLOTS` multi-record send so the flood can't be counted as one send — `0`
disables; see [`channel-count-privacy.md`](channel-count-privacy.md)),
`channel_feed_snippets`, and `channel_allow_insecure_engine` (DEV only — runs the
FakeEngine, which provides no confidentiality).

## Hub xite (the xID xite) contents

- **content.json**: `pool.channels` descriptor (dir `pool`, class `epix-pool-1`,
  `since_week`, `fanout` 16, `pow_bits` 20, `pad_buckets` [8192,32768,131072],
  `max_record_bytes` 200000, `sync_order` newest_first); `includes` for
  `data/users/content.json`; `distribution.paths` `data/users/` (feed) and `pool/`
  (package), complete retention; `ignore` covers `data/users/.*|pool/.*`.
- **data/users/content.json**: `cert_signers {"xid.epix": ["chain"]}` and
  `permission_rules {".*": {files_allowed: "data\.json|data-[0-9a-z]+\.json",
  max_size: 8192}}`.
- The wizard app itself is untouched; `siteSign` keeps these fields across the
  app's own releases.

## Site (mail xite) changes (historical: the first cutover, when Mail hosted the pool)

- **content.json**: `pool.channels` descriptor (dir `pool`, class `epix-pool-1`,
  `since_week`, `fanout` 16, `pow_bits` 20, `pad_buckets` [8192,32768,131072],
  `max_record_bytes` 200000 (widened for the count-hiding multi-slot record — the
  fixed slot overhead is ~4.4KB, smallest record ~8KB), `sync_order` newest_first);
  `distribution.paths["pool/"]` complete retention;
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
  cert-aware, auth-signed v3 bundle and re-signs the user's content.json.
  Unsigned v2 bundles are a hard cutover and must be republished. If an RLN
  roster was generated from the pre-cutover raw per-xite auth identity, regenerate
  its member commitment from the same cert-aware linked identity used by channels.
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
