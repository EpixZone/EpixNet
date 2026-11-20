# VRF beacon verification: what is missing (design note)

Status: NEEDS DECISION. Nothing is implemented. Today the VRF commands
(`vrfGetBeacon`, `vrfLatestBeacon`, `vrfMultiBlockBeacon` in
`crates/epix-ui/src/command.rs`, backed by `crates/epix-chain/src/vrf.rs`)
return whatever the configured chain REST endpoint answers for
`/vrf/v1/beacon/{h}`. A hostile or compromised endpoint can hand a xite any
"randomness" it likes. `vrfLatestBeacon` reads the unverified REST head and
returns the beacon at `head - 1`. (`vrfDeriveRandom` is pure: it hashes a
caller-supplied beacon and fetches nothing, so it is only as trustworthy as
the beacon the xite passes in.)

## Why the xID machinery cannot verify a beacon as is

The xID path does NOT check Merkle proofs of chain state against app hashes.
It works like this:

1. `x/xid` keeps its own SHA-256 Merkle tree over xID domains; its root is the
   "state digest" (`merkle.rs`, `leaf.rs`, `resolver.rs`).
2. Validators sign `(height, block_time, digest)` in their ABCI++ vote
   extensions; the client verifies more than 2/3 of the pinned voting power
   signed it (`finality.rs`, `attestation.rs`).
3. The CometBFT light client (`lightclient.rs`) only keeps that pinned
   validator set current. It verifies one header per cycle (hourly by default,
   `xid_lc_interval_secs`), persists only the latest one, and exposes no app
   hash to the rest of the crate.

The VRF store is not covered by the xID digest, and the crate has no ICS23 /
IAVL proof verifier (`Cargo.toml` excludes `ics23` on purpose, for mobile
weight). So there is nothing existing to plug a beacon proof into.

## What the chain already provides (checked against mainnet, 2026-11-20)

- Store `vrf`, key `0x01 || height (u64 big endian)`, value is the JSON
  `{"height","beacon","proposer","timestamp"}` written in that block's
  `EndBlock` (`x/vrf/types/keys.go`, `x/vrf/keeper/state.go`). Beacons older
  than `LookbackBlocks` (default 256) are pruned from state.
- CometBFT `abci_query?path="/store/vrf/key"&data=0x01..&height=H&prove=true`
  returns the value plus two proof ops: `ics23:iavl` (key in the `vrf` IAVL
  root) and `ics23:simple` (key `vrf` in the multistore root). Standard SDK
  semantics: that proof commits to the state after block `H`, which is the
  `app_hash` in header `H+1`.
- Proof retention is short: `rpc.epix.zone` answered proven queries for
  versions up to about 100 blocks back and refused at 150 ("ensure height has
  not been pruned"). `rpc-epix.onenov.xyz` refused at 300; `rpc-epix.dnsarz.net`
  answered at 300. The light client's trusted header is usually much older
  than that, so its stored `app_hash` is useless for this.
- Beacons form a hash chain over headers. On mainnet
  `beacon[N] = SHA256(beacon[N-1] || hex(block_hash[N]) || bech32 valcons of
  header[N].proposer || unix(header[N].time) || "")`: the data-hash term is
  always empty (the SDK FinalizeBlock context header does not carry
  `DataHash`), despite the keeper comment. The block hash still commits to the
  transactions, so this is a doc inaccuracy, not an entropy loss.

## What a verified implementation needs

1. An ICS23 verifier: add the `ics23` crate (prost based) and verify both
   proof ops with `iavl_spec` and `tendermint_spec`. This reverses the
   explicit "no ics23" choice in `Cargo.toml`; decide whether the mobile
   size cost is acceptable.
2. On-demand light-client verification near head: a new `lightclient` API that
   skip-verifies a header at a chosen recent height `V` from the trusted state
   (reusing `verify_forward`), returning its `app_hash` without waiting for the
   hourly cycle. Cost per call: one `/commit`, two `/validators`, a handful of
   ed25519 verifies; cache per `V` for a few seconds.
3. Read path: query `BeaconKey(h)` at version `V - 1` with `prove=true` against
   the CometBFT RPC (`EPIX_CMT_RPC_URL`, not the REST endpoints), verify against
   `app_hash(V)`, check the decoded JSON `height == h`. Any beacon still in
   state (the last 256 blocks) is provable this way because it is present at
   every version from `h` to `h + 256`.
4. `vrfLatestBeacon`: return the beacon at `V - 1` for the freshly verified `V`
   (a block's beacon exists only after its `EndBlock`, and header `V` commits
   the state after block `V - 1`).
5. `vrfMultiBlockBeacon` (up to 256 blocks): either 256 proven queries at one
   version, or ONE proven anchor beacon plus the hash-chain rule above over
   headers that are linked back from verified header `V` via `last_block_id`
   (no ICS23 per beacon).
6. Failure mode: refuse with `{error}` when no verified header or proof is
   available. If an unverified mode is wanted, mirror xID
   (`xid_verify_finality` / `EPIX_XID_ALLOW_INSECURE_LEGACY`) rather than
   inventing a new switch.

## Alternative without ICS23 (chain upgrade)

Add the beacon (or a root over the retained beacons) to what validators
already sign in vote extensions, or fold it into the xID state digest. The
client then reuses `finality.rs` unchanged and only needs one ed25519 quorum
check per beacon. This is consensus breaking and needs a coordinated upgrade.

## Decisions needed

- ICS23 client-side (no chain change, larger client) or vote-extension
  attestation (chain upgrade, thin client)?
- Is a proof window of about 100 blocks on the default RPC acceptable, or
  should the default CometBFT RPC keep more recent versions?
- Should an unverified fallback exist at all for VRF, given xites use it for
  raffles and games?
