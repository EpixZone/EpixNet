# Requiring xID finality: the validator pin

Client-side xID finality verification is a **setting plus a pinned validator
set**, not a flag on its own. When a pin is installed, the node REQUIRES every
xID resolution to be a Merkle proof rooted at a state digest signed by more than
two thirds of the pinned voting power, and fails closed otherwise (a malicious or
lagging RPC cannot forge a resolution). Without a pin, startup fails closed.

## Merge blocker

The v0.7.2 attestation upgrade is LIVE on mainnet (executed at height 5360000;
signed attestations verified being served). The remaining blocker is release
packaging only: capture the bootstrap pin with `scripts/capture_xid_pin.py`,
verify it against a second independent RPC, and include it in the release's
default data dir before shipping. Never fabricate a placeholder pin.

## How the node turns it on

At boot the node reads `xid_pin.json` from its data root:

- present and valid: `install_finality_pin` loads it and enables verification
  (logged: `xID finality: pinned N validators; resolution now requires >2/3
  attestation`).
- absent: startup fails closed. For pre-upgrade development only, an operator
  can explicitly set `EPIX_XID_ALLOW_INSECURE_LEGACY=1`. This is logged as an
  insecure compatibility mode and must not be set in an official release.
- unreadable or invalid: startup fails closed, even when the compatibility
  variable is set.

The node also restores `xid_finality_checkpoint.json` from the data root. It
contains the highest accepted height and digest. Every newer checkpoint is
written atomically and synced before the resolution succeeds. Corruption, an
I/O error, a lower height, or a different digest at the same height fails closed.

So **requiring finality means shipping `xid_pin.json`**. Drop the trusted file
in, restart, and confirm the finality log line.

## Why the pin can only be captured AFTER the chain upgrade

The pin is the mainnet validator set that signs xID state digests. Those
signatures only exist once the **v0.7.2 attestation upgrade** is live (before
then there is nothing to pin). This is exactly why this branch must not be merged
to `main` until the chain upgrade completes: capture the pin from mainnet first,
validate it, include it in release packaging, then merge.

## Capturing the pin (post-upgrade)

Capture the FULL consensus validator set - not the attestation signers - with:

```bash
python3 scripts/capture_xid_pin.py            # default RPC https://rpc.epix.zone
python3 scripts/capture_xid_pin.py https://other-rpc.example   # cross-check
```

The script reads a settled recent height from the CometBFT RPC, fetches
`/validators` (every bonded validator, including any not currently signing
vote extensions), derives each `valcons` as
`bech32("epixvalcons", sha256(consensus_pubkey)[..20])`, and writes
`xid_pin.json`.

Why the full set and not the signers: the light client bootstraps by requiring
the pin to EQUAL the validator set at the pin height (hash-bound to that
header's `validators_hash`) - the trust splice. A signer-derived pin omits any
validator that missed the block or has not upgraded its vote-extension
signing, and then never matches. A non-signing validator in the pin only
counts toward the >2/3 denominator; capture never has to wait for a
fully-signed height.

The capture step is the ONE trusted operation (the pin is the root of trust):
verify the output against a second independent RPC before shipping, and place
it where the node reads it (its data root, or the release's default data
dir). Verify the boot log shows `resolution now requires >2/3 attestation`.


## Re-pinning is automatic: the light client

The shipped pin is only the COLD-START ANCHOR. From it, the node's embedded
CometBFT light client (`epix_chain::lightclient`, `spawn_xid_lightclient`)
skip-verifies signed headers forward and republishes each verified validator
set as the active pin - so the trusted set tracks the LIVE set, validator
churn and maintenance never strand resolution, and no re-pin release is ever
shipped. A node that connects at least once per trusting period (2/3 of the
21-day unbonding period, ~14 days) never needs a new `xid_pin.json`; a
year-old binary keeps working.

Manual re-pinning remains only for a node offline LONGER than the trusting
period (its anchor can no longer be extended - the node logs
`light-client trust anchor ... older than the trusting period`): drop in a
freshly captured `xid_pin.json` (procedure above) and restart. The static
weak-subjectivity window (`XID_WS_PERIOD_SECS`, default 7 days) still applies
as the fail-closed backstop whenever the light client is disabled
(`xid_lc_enabled=false`).

Config: `xid_lc_enabled` (default true), `xid_lc_interval_secs` (default 900),
`xid_trusting_period_secs` (default 1209600), `EPIX_CMT_RPC_URL` (default
`https://rpc.epix.zone`; routed through the same chain egress as every other
chain fetch, so Tor-Always covers it).
