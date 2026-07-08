# Tor tail: what's done, what's blocked, what's deferred

The in-process Arti Tor transport landed earlier (dial `.onion` peers, host an
onion service for inbound, a local SOCKS listener, `tor: disable/enable/always`
config). Three follow-ups were listed in PLAN.md. Here is where each stands
after review.

## AnnounceEpix onion announce - the advertising half is DONE

Announcing our onion address to trackers works. `SelfAdvert.onion` carries our
`.onion` host into `announce` (`crates/epix-xite/src/announcer.rs`), and our own
tracker absorbs onion self-addresses on the receiving side
(`crates/epix-ui/src/fileserve.rs`, the `announce` handler's `onions` loop), so
onion-only nodes get discovered. This is exercised by
`announce_tracker_records_and_serves_overlay_peers`.

## AnnounceEpix onion **sign-proof** - blocked on Arti key access

EpixNet's Bootstrapper tracker can challenge an announcer to prove it controls
the onion it advertises: it returns `onion_sign_this` (a timestamped nonce), the
announcer signs it with the onion service's **ed25519 identity key**, and the
tracker verifies with `CryptRsa.verify` (v3 onions use ed25519) before adding
the address (`plugins/disabled-Bootstrapper/BootstrapperPlugin.py`
`checkOnionSigns`).

We cannot answer that challenge today: **Arti does not expose the hidden-service
identity key for arbitrary signing.** `arti-client`'s `launch_onion_service`
hands back a `RunningOnionService` and manages the `HsIdKeypair` inside its
`KeyMgr`/keystore; there is no public API to sign a caller-supplied message with
that key. Reaching into the keystore to extract the raw expanded secret would be
fragile and version-locked, and it works against Arti's key-isolation design.

Impact is limited and one-sided:
- Our **own** trackers never issue `onion_sign_this` (they add onion addresses
  on trust, exactly like an EpixNet tracker with the Bootstrapper's challenge
  turned off), so Rust-to-Rust onion discovery already works.
- Only a Python tracker running the Bootstrapper with challenges enabled would
  reject our onion announce. That is the interop gap.

Path forward when it matters: either an upstream Arti API to sign with the HS
key, or a separate node-managed ed25519 key advertised alongside the onion (a
protocol change on both sides). Neither is worth a fragile hack now; tracked
here so the gap is explicit.

## StemPort - not applicable to in-process Arti (deferred by design)

StemPort was EpixNet's transport over a system Tor daemon's control port
(stem/ADD_ONION). Our decision (see PLAN.md "Tor via Arti") is one in-process
Tor code path on every platform, with **no sidecar tor process anywhere**. There
is no control port to speak to, so StemPort has nothing to port. It stays
removed by design, not pending.

## `--tor always` zero-direct-IP - an integration checkpoint, not code

The routing invariant is already in the code: in `TorMode::Always`,
`MixedTransport::dial` sends **every** peer address - including plain
`PeerAddr::Ip` - through the Tor client, never a direct `TcpTransport` connection
(`crates/epix-tor/src/lib.rs`, the `route_all` arm). The server binary wires
`tor: always` to `route_all = true`.

What remains is the live checkpoint from the plan: boot with `tor always`, run a
full clone + seed cycle, and confirm zero direct-IP peer connections (e.g. by
watching the socket table). That needs a bootstrapped Tor circuit (~45s) and a
reachable peer, so it is an integration test against real infrastructure, in the
same bucket as "a Python peer reaches our onion inbound" - both are verification
runs that need a Tor-connected environment, not new code. The unit-level proof
(the `route_all` dial arm) is in place and covered by the Tor transport's own
tests.

## Summary

| Item | State |
|------|-------|
| Announce our onion to trackers | Done (advertise + absorb) |
| Onion sign-proof to a challenging tracker | Blocked on Arti HS key access; one-sided interop gap |
| StemPort | N/A by design (no sidecar tor) |
| `--tor always` routing invariant | Done (MixedTransport route_all) |
| `--tor always` live zero-direct-IP run | Integration checkpoint, needs Tor infra |
