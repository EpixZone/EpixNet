# Epix Mail → metadata-private channels — cutover runbook

How to move the live Epix Mail site (`epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa`)
from the old **metadata-public** model (per-user `messages.json` with plaintext
recipient lists) to the **anonymous channel pool**. This is a **coordinated,
partly destructive** operation across all users; do it in order.

> The migration *import* is non-destructive and idempotent — it only reads the
> old files and writes the private `channels.db`. The destructive part is
> **Phase C** (dropping `messages.json` from the shared site). Keep the backups.

## 0. Prerequisites (all users)

- Everyone runs a node build that includes the channel API (`channel_enabled`,
  the `channel*` WS commands). Verify: `serverInfo.rev` on each node is ≥ the
  release that shipped this PR.
- `channel_xite` = the mail site address; `channel_allow_insecure_engine` = **false**
  (the real `PairwiseEngine`). Optional: `channel_encrypt_at_rest = true`.

## 1. Re-sign the site with the fixed JS (owner, one command)

The browser-boot fixes (Page.channel ordering, MessageThread `msg_id`,
notifyNewMail) are already on disk in `data/<addr>/js/`. content.json must be
re-signed so peers (and a hard browser refresh) pick them up. **This needs the
site's owner private key** (shown once at site creation — it is NOT stored in the
data dir). A content.json backup is at `/tmp/content.json.live-backup-*`.

Via the running node (preferred — repacks + registers the EDX bundle correctly):

```
# in the node UI: Sidebar → Sign & Publish,  or over the admin socket / WS siteSign
```

Or offline via the CLI (no node running):

```
EPIX_DATA_DIR=~/.local/share/EpixNet \
  epix-server siteSign epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa <OWNER_PRIVATEKEY> --full
```

Verify content.json now matches the loose JS (sha512 of `js/EpixMail.js` equals
its `files` entry), then **hard-refresh** the browser (`Ctrl/Cmd+Shift+R`) — a
plain reload keeps the cached old JS.

## 2. Import legacy mail into each user's private index (per user, non-destructive)

Each user runs `channelMigrateLegacy` once (WS command, or it can be wired to a
Settings button). It scans every `data/users/*/messages.json`, ECIES-decrypts the
copy addressed to that user with their mail key, and writes it into `channels.db`.
Idempotent — re-running imports nothing new. Nothing is deleted.

Check: `channelThreads` now returns the historical conversations; `channelSearch`
finds old bodies.

## 3. Publish a bundle-only `data.json` per user (per user)

Each user runs `channelKeyBundlePublish`, which overwrites their
`data/users/<xid>/data.json` with the bundle-only payload
(`{v:2, xid, ik, spk, spk_idx}`) and re-signs their per-user content, dropping
`messages.json` from their `files_merged`. **Do NOT tombstone `messages.json`** —
Phase 4 removes it by rule.

Owner gate before Phase 4: confirm every user's `data.json` is bundle-only and
under 4 KB:

```
grep -Lc '"ik"' data/users/*/data.json      # every file should contain "ik"
find data/users -name data.json -size +4k    # expect: none
```

## 4. Ship the new content.json + dbschema v3 (owner, single signed publish) — DESTRUCTIVE

Publish the root content.json that: (a) declares the `pool.channels` descriptor,
(b) bumps dbschema to v3 (drops the old `message`/`conversation` tables), and
(c) no longer allows `messages.json` under `data/users/`. On every peer this
**deletes `messages.json` on resync**. Do this only **after** Phase 3 for all
users. Keep an offline archive of `data/users/` first.

## 5. Verify (must return nothing on every peer)

```
grep -lE '"(from_xid|to|recipient|members|conv_id|peer_xid|subject|author)"' data/<addr>/pool/**/*.json
grep -lr '\.epix' data/<addr>/pool/                 # no xid in the pool
ls data/<addr>/data/users/*/messages.json           # none after Phase 4
find data/<addr>/data/users -name data.json -size +4k   # none
```

The pool records must contain only `{author, ct, epoch, pow, sign, tag, v}` with a
throwaway `author` (not the sender's identity).

## Rollback

- Phases 1–3 are reversible: restore the content.json backup and the users'
  `data.json`/`messages.json` from the pre-cutover archive, re-sign.
- Phase 4 is the point of no return for *serving* the old plaintext (the files
  are deleted on peers). The plaintext was already metadata-public, so this
  removes exposure rather than adding it — but keep the offline archive.

## Deployment posture

Run nodes in **Tor-Always** mode: the only residual metadata leak is that a
directly-connected clearnet peer can see a node inject *an* anonymous record at
send time (that you sent *something*, not to whom or what). Tor-Always + publish
jitter closes that.
