# Python EpixNet interoperability

## Current status

**Python and Rust nodes no longer talk to each other.** Since 2026-07-28
(commit `8a16c618`, "edx: retire msgpack, EDX is the only peer protocol")
the Rust node speaks only EDX on the wire. Its inbound accept loop
(`crates/epix-protocol/src/server.rs`) drops any connection whose first byte
is not the EDX magic, so a Python peer's msgpack handshake is closed straight
away, and the Rust node never dials the msgpack protocol. A Python node and a
Rust node cannot share a swarm: they do not exchange peers, files or
published updates.

What still holds is compatibility of the data, not of the wire:

- **Keys, addresses and signatures.** `epix-crypt` is bit-for-bit compatible
  with Python's `CryptEpix.py` (addresses, WIF keys, message signatures, HD
  key derivation); `crates/epix-crypt/tests/differential.rs` checks it
  against vectors generated from the Python implementation.
- **content.json.** `epix-content` signs and verifies the same canonical JSON
  (Python's `json.dumps(obj, sort_keys=True)`), checked against Python
  `ContentManager` vectors in `crates/epix-content/tests/differential.rs`. A
  Python-signed content.json verifies in the Rust node with the same key.
- **Serving a Python-made xite.** EDX addresses files by BLAKE3 (`b3`)
  entries in content.json, which Python never writes. The Rust node loads
  such a xite but has nothing to serve for it over EDX until its owner
  re-signs it with the Rust node, which adds the `b3` entries.
- **Data directory.** The Rust node keeps its xite registry in
  `private/xites.json`. On first start it copies a Python-era
  `private/sites.json` across once and leaves the original in place.

## History: the 2026-07-07 wire verification

Before EDX replaced it, the Rust node also spoke the Python msgpack protocol.
On 2026-07-07 a Rust node and Python EpixNet 0.2.7 ran side by side on one
machine over loopback TCP, and the following worked:

- Python's client against the Rust server: `peerPing`, `peerGetFile` (through
  Python's `streamFile` download path), `listModified` and `pex`.
- Publishing in both directions: a Python-signed `sitePublish` was accepted and
  stored by the Rust node, and a Rust-signed content.json pushed with the
  `interop_push` example was accepted by the Python node, which then fetched
  the changed file from the Rust file server.

That run led to two fixes in the msgpack layer (the handshake reply's
`fileserver_port`, and `streamFile` replies framed as `stream_bytes` plus a raw
tail). Both, the `interop_push` example and the steps to rerun the test were
removed with the msgpack protocol on 2026-07-28. The signing and content.json
compatibility it exercised is what the differential tests above still cover.
