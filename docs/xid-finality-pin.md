# Requiring xID finality: the validator pin

Client-side xID finality verification is a **setting plus a pinned validator
set**, not a flag on its own. When a pin is installed, the node REQUIRES every
xID resolution to be a Merkle proof rooted at a state digest signed by more than
two thirds of the pinned voting power, and fails closed otherwise (a malicious or
lagging RPC cannot forge a resolution). Without a pin, startup fails closed.

## Merge blocker

The chain upgrade that produces signed mainnet attestations is scheduled but is
not live yet. A real `xid_pin.json` cannot be captured before that height. Do not
merge or ship this branch until the post-upgrade pin has been captured, checked,
and included in release packaging. Never fabricate a placeholder pin.

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

Run against a mainnet REST endpoint a few blocks after v0.7.2 executes, at a
height where every bonded validator has signed (so the pin covers the full
voting power — the finality denominator). Requires `curl` and `jq`.

```bash
API=https://api.epix.zone

DIGEST=$(curl -s "$API/xid/v1/state_digest" | jq -r .digest)
ATT=$(curl -s "$API/xid/v1/attestations?digest=$DIGEST")
CHAIN_ID=$(curl -s "$API/cosmos/base/tendermint/v1beta1/node_info" | jq -r .default_node_info.network)
NOW=$(date +%s)

echo "$ATT" | jq \
  --arg chain "$CHAIN_ID" \
  --argjson t "$NOW" \
  '{
     chain_id: $chain,
     pinned_at_height: (.height | tonumber),
     pinned_at_unix: $t,
     validators: [ .attestations[]
       | select((.voting_power | tonumber) > 0)
       | { valcons: .validator_cons_addr,
           pubkey: .ed25519_pubkey,
           voting_power: (.voting_power | tonumber) } ]
   }' > xid_pin.json

# Completeness check: the pinned power MUST equal the chain's total bonded power,
# i.e. every bonded validator signed at this height. If it does not, a validator
# missed the block — recapture at another height rather than pin a partial set
# (a partial pin lowers the 2/3 denominator).
PINNED=$(jq '[.validators[].voting_power] | add' xid_pin.json)
TOTAL=$(echo "$ATT" | jq -r '.total_voting_power | tonumber')
[ "$PINNED" = "$TOTAL" ] && echo "OK: pinned full bonded power ($PINNED)" \
  || echo "WARN: pinned $PINNED of $TOTAL — recapture at a fully-signed height"
```

Then place `xid_pin.json` where the node ships it (its data root, or the
release's default data dir) and restart. Verify the boot log shows
`resolution now requires >2/3 attestation`.

## Re-pinning (weak subjectivity)

A pin has a validity window (`XID_WS_PERIOD_SECS`, default 7 days, kept below the
chain's unbonding period). Ship a fresh `xid_pin.json` within that window as the
validator set rotates, the same way any light client re-pins.
