# EpixNet patch to `rln` (zerokit) 3.0.0

Vendored copy of the audited zerokit `rln` crate, with one **minimal, additive**
change so it can coexist with EpixNet's arti/Tor stack. The circuit, protocol,
Poseidon, and nullifier code are **unmodified** — only the build surface changes.

## Why

Upstream `rln` hard-depends on `sled` (its persistent Merkle-tree backend) with
the `compression` feature, which links the native `zstd` library. EpixNet's Tor
stack pulls `async-compression`, which also links `zstd`. Cargo forbids two
crates in one build linking the same native library (`links = "zstd"`), so
upstream `rln` cannot be added to the node as-is.

EpixNet uses only the **stateless** RLN verifier/prover and manages its own
xID-anchored membership tree, so the sled-backed tree is dead weight for us.

## What changed (all gated, upstream-mergeable)

- `Cargo.toml`: `sled`, `pmtree`, and `safer-ffi` are now `optional`. New
  features: `stateful = [dep:sled, dep:pmtree]` and `ffi = [stateful, dep:safer-ffi]`.
  `default = []` (also drops `parallel`/rayon to match the workspace's
  spawn_blocking model). `pmtree/parallel` -> `pmtree?/parallel`.
- `src/lib.rs`: `pub mod pm_tree` is `#[cfg(feature = "stateful")]`; `pub mod ffi`
  is `#[cfg(feature = "ffi")]`.
- `src/prelude.rs`: the `pm_tree` re-exports are `#[cfg(feature = "stateful")]`
  (the circuit-default re-exports next to them are kept).

Nothing else is touched. The stateless path (`RLNBuilder::stateless`, the
`protocol`/`circuit` modules, `compute_id_secret`) references `pm_tree` only in
doc comments, so gating the sled backend off is sufficient. Enabling the
`stateful` feature restores upstream behaviour exactly.

## Verifying the diff against upstream

    cargo download rln==3.0.0   # or fetch the .crate from static.crates.io
    diff -ru <upstream>/ vendor/rln/   # expect only Cargo.toml, src/lib.rs,
                                       # src/prelude.rs, and this file
