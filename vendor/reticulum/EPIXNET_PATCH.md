# Reticulum routed-link and Channel fixes

This is the library from BeeChat Reticulum-rs revision
`dc4e03bb08a2069d03ba038bcc63eb9358201dd5`, the existing EpixNet pin:
https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs/tree/dc4e03bb08a2069d03ba038bcc63eb9358201dd5

The upstream MIT license is retained. `provenance.json` records the SHA-256
of every upstream and vendored source file and the exact `EPIXNET.patch`.
`Cargo.toml.orig` preserves the original package manifest. The vendored
manifest omits the daemon workspace and unused example targets. Only the
library, build script, required protobuf files, README, and license are copied.
The application root lockfile resolves the same dependencies.

The production changes are limited to `src/transport.rs` and `src/channel.rs`:

- Route initial and retried link requests through the learned transport hop.
  Preserve direct one-hop requests and the existing no-path behavior.
- Find outbound links by their actual link ID so public close cancels them.
- Permit Channel retransmissions through duplicate filtering.
- Re-encrypt retries with the same Channel sequence and payload, as official
  Python Reticulum `Packet.resend()` does. Keep the original delivery handle
  and accept signed receipts for the bounded set of attempted packet hashes.
- Subscribe before spawning the receiver so already acknowledged first bytes
  cannot be lost between channel creation and subscription.
- Bound inbound sequence buffering across wraparound. Stop on receiver lag,
  closed event streams, or exhausted retries instead of skipping stream bytes.
- Expose closure state and allow callers to discard consumed receipt history.

No cryptographic primitive, signature verification, or key format is changed.
The application announces a separate signed `epix.node.v2` destination for
Channel streams. Existing `epix.node` destinations retain the legacy raw
protocol; a client upgrades only after receiving a valid v2 announcement with
both public identity keys matching the legacy destination.

The lab reproduced failure through the official Python Reticulum 1.6.0
router, an oversized-packet failure on a real configured 500-byte interface,
and failures under dropped/reordered frames. The corrected adapter transfers
signed 16 KiB xite content with data loss, reordering, and lost receipts.
These are isolated software link tests, not physical LoRa or Bluetooth tests.

Focused upstream tests cover receipt tracking after fresh retries, bounded
retry attempts and hash aliases, sequence wraparound, receiver lag, and
outbound close by link ID. Run them from the application workspace so the
root lockfile seeds the standalone vendor test graph:

```sh
cp Cargo.lock vendor/reticulum/Cargo.lock
cargo test --manifest-path vendor/reticulum/Cargo.toml --lib --offline
rm vendor/reticulum/Cargo.lock
cargo test -p epix-reticulum --locked
```

Remove the patch only after an upstream revision passes these regressions,
the official-router interoperability lab, and mixed legacy/v2 peer tests.
