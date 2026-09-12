# Channel hub cutover: from the Mail-hosted pool to the xID xite

How to move channels from the Epix Mail xite (which hosted the pool and every
user's key bundle) to the hub - the xID xite - with per-identity, node-side
setup. Coordinated, and partly destructive at the last step. Keep backups.

## What changes

- The pool (`pool/`) and the key bundles (`data/users/<name>.epix/`) live in the
  xID xite (`epix1xauthduuyn63k6kj54jzgp4l8nnjlhrsyaku8c`). Epix Mail becomes a
  client: its content.json no longer declares a pool or user-content rules.
- The node publishes a key bundle per linked identity itself
  (`epix-plugins::channel_setup`), signing the identity's content.json as that
  identity. No client-side `fileWrite` + `sitePublish` any more.
- During the transition the node also indexes Mail's old pool read-only
  (`channel_legacy_xites`, default = Mail) and reads bundles from both places
  for inbound anti-spoof checks. Sends go to the hub only.
- Nothing in the private index moves: `channels.db` keeps threads, sessions and
  `processed` marks (keyed by record signature, not by pool); established
  ratchets continue on the hub.

## Order

1. **Hub owner** adds the pool descriptor and the user-content rules to the xID
   xite's content.json (see "Hub xite contents" in `channels.md`), re-signs and
   publishes. The address does not change. `data/users/content.json` is an
   include with `signers: []`, so it needs its own signature by the owner key
   (`siteSign` with that `inner_path`): signing the root does not sign it, and
   an unsigned include is rejected as a governing parent, which leaves every
   identity's setup at `pending: no verified governing parent for
   data/users/<name>.epix/content.json` until it is signed.
2. **Node release N** ships: `channel_xite` default = the hub,
   `channel_legacy_xites` default = Mail, per-identity setup, the Mail client
   update in the same window. On first boot every node auto-adds the hub and
   every enabled linked identity republishes its bundle there. A node that set
   `channel_xite` to Mail during the first cutover is migrated on boot: the
   value is treated as blank and cleared from the config (logged as
   `channels: channel_xite named Epix Mail ...`), since Mail no longer declares
   a pool and keeping it would wait for a hub that never comes. Inbox history is
   intact; records still landing in Mail's pool keep arriving via the legacy
   read. Users see Config > Identities show "channels: pending" for a moment,
   then "published"; Mail shows the onboarding banner until then.
3. **Grace window** (at least two weeks): N nodes send to the hub only. A
   recipient still on N-1 cannot read those; the re-signed Mail client tells
   N-1 users to update (its `server_info.rev` gate).
4. **Mail owner** re-signs Mail's content.json without pool/user-content rules
   (the client repo already carries that content.json). Peers delete Mail's
   `pool/` and `data/users/*` on resync. This is the point of no return for
   N-1 nodes. Keep an offline archive of Mail's `data/users/` first.
5. **Release N+1**: `channel_legacy_xites` default blank. The legacy read path
   stays for test networks.

## Pre-flight, per node

- `channelSessionInfo.identity.outbox_pending == 0`: a queued record written
  before outbox rows carried recovery material cannot re-route to the hub.
- `channel_encrypt_at_rest` unchanged across the upgrade.

## Verify (must return nothing, on every peer)

```
grep -lE '"(from_xid|to|recipient|members|conv_id|peer_xid|subject)"' data/<hub>/pool/**/*.json
grep -lr '\.epix' data/<hub>/pool/                # no xid in the pool
# (`author` is legitimately present: it is the record's throwaway signing key, not the sender)
find data/<hub>/data/users -name data.json -size +8k  # none
```

Every `data/<hub>/data/users/<name>.epix/content.json` carries `cert_user_id`,
`cert_auth_type: xid`, `cert_sign`, and is signed by that identity's linked
address.

## Rollback

- Steps 1-3 are reversible: point `channel_xite` back at Mail and restart; the
  hub's bundles are simply unused.
- Step 4 deletes Mail's pool and bundles on peers. Restore from the offline
  archive and re-sign Mail's content.json with the old rules to serve them again.
