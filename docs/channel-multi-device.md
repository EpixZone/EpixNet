# Multi-device channel delivery

**Status: landed** (node + site). A channel name (`mud.epix`) can have more than
one **linked identity/device**, and a message sent to that name reaches *every*
active device, so the recipient can read and reply on whichever one they use —
the send seals a per-device slot for every device into ONE fixed-width record
(see [`channel-count-privacy.md`](channel-count-privacy.md)), and the receiver's
anti-spoof accepts a message sealed from **any** of the sender's linked keys.

This closes the "adding a linked identity is cosmetic" half of the xID audit:
before this, a name had exactly one channel identity (IK derived from a single
node seed), a second device would clobber the first's `data.json`, and a send
resolved only that one bundle.

## The model

- **Each device publishes its own authenticated v3 bundle.** A device's channel identity key (IK)
  is derived from *its own* node seed (`derive_consumer_seed("channel", auth)`),
  so two devices already have distinct IKs. The bundle carries its cert-aware
  linked address as `auth` plus `auth_sig`, a domain-separated signature by that
  linked key over the full `(v, xid, auth, ik, spk, spk_idx)` tuple. Unsigned v2
  bundles are rejected. Devices write to distinct files below.
- **Send reaches every device — in ONE record.** `channelSend` resolves every
  published bundle for each recipient name (grouped, active-filtered, deduped) and
  packs them all into a single fixed-width **multi-slot** record via `send_multi`.
  (The first cut sealed one record *per device*, which leaked the recipient's
  device count to a peer counting the burst; that is now closed — see
  [`channel-count-privacy.md`](channel-count-privacy.md).) The sender's own copy is
  still recorded exactly once.
- **Receive already handles multiplicity.** The indexer trial-decrypts against
  every local identity, so a device opens its own leg with no change.

## Bundle storage (cutover-safe)

User directories are **name-keyed by cert** (`data/users/<name>.epix/`, cert
authority `xid.epix`), and the site's `permission_rules` historically allowed a
single `data.json`. Multi-device needs more than one bundle per name without two
devices clobbering each other:

- `permission_rules.files_allowed` now allows `data.json` **and**
  `data-<auth>.json` (regex `data\.json|data-[0-9a-z]+\.json`; `epix1…` addresses
  are bech32, so this is filesystem- and regex-safe). Updated in both
  `data/users/content.json` and `data-default/users/content-default.json`
  (owner-signed — takes effect when the site is re-signed, same step as the
  cutover runbook).
- **Slot selection** (`Channel.js publishKeyBundle`): a device takes the primary
  `data.json` slot when it is free or already **its own**, and its per-device
  `data-<auth>.json` slot only when a *different* device already holds the
  primary. So single-device users stay on `data.json` — readable even by nodes
  that only look at `data.json` — and a second device never overwrites the first.
- The node reads **both** `data.json` and every `data-<auth>.json`, requires a
  valid v3 `auth_sig`, binds a secondary filename to that authenticated `auth`,
  groups by the cert-gated directory name, and **dedups by IK keeping
  the freshest `spk_idx`** — so a legacy `data.json` left beside a device file
  cannot downgrade a valid device tuple.

## Revocation is per-device

`load_published_bundles` applies revocation at two granularities. Unknown chain
status remains fail-open only until this node has observed a finalized
revocation:

- **name-level observation**: a name with no active linked identity drops every
  currently known bundle/session tuple. It does not permanently block a future
  newly linked auth/IK;
- **per-device**: when the chain returns a **non-empty** active-address set
  (`xid_active_addrs`), a bundle whose own `auth` is positively absent from it is
  dropped. The exact `(xid, auth/IK)` tombstone is durable, so a later resolver
  outage or restart cannot reopen it while a sibling/new device remains usable.

## Anti-spoof: match, or DEFER (never mis-attribute)

The sealed-sender first-contact check (`open_first_contact`) resolves *all* of a
claimed sender's published device bundles and trusts the message iff the
transcript-bound `ik_a` equals **one** of them. If none match, the record is
**deferred** (returned `NoMatch`, left *unprocessed*) rather than dropped
for-good — because "no match" now has two causes that can't be told apart from
the transcript alone:

1. a **forgery** (the `ik_a` isn't any of the sender's keys), or
2. a **genuine message from a device whose bundle hasn't synced here yet**.

Deferring makes case (2) index correctly once that device's bundle arrives, while
case (1) is simply re-probed (a bounded, PoW-gated cost) and — since its IK never
matches — can never be indexed. This is the one behavior change to the previous
"non-matching bundle → mark processed, drop" rule; the change is required for
multi-device correctness and does not weaken spoof protection (a forgery is still
never trusted).

## Residual / not done

- **Shared-directory write convergence.** Two active devices both write into the
  same `data/users/<name>/` and its per-user `content.json` is single-signer, so
  a simultaneous first-publish from two devices can race (last signer wins until
  the other republishes; self-heals). Rare (device-adds), bounded, and documented
  here. The robust upgrade is a per-user **signed-CRDT merge file** of device
  bundles (union semantics, each device signs its own entry) — deferred; the node
  read/fan-out path is already agnostic to how the bundles are stored.
- **Read/unread state is per-device** (private index per node), as with the base
  design.

## Tests

- `epix-channel/tests/indexer.rs::multi_device_sender_any_linked_key_accepted` —
  a send from device 2 is accepted when both device bundles are known; a node
  that has only device 1's bundle **defers** (no thread, no mis-attribution) and
  then indexes the same record once device 2's bundle syncs.
- `epix-pairwise-engine::keys` rejects unsigned v2, swapped `auth`, malformed,
  and noncanonical v3 signatures.
- `epix-plugins` `multi_device_tests` covers per-device filtering, global IK
  conflicts across the fixed-slot boundary, duplicate recipients, and filename
  binding to authenticated `auth`.
