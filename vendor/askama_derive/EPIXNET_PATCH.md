# Askama configuration parser maintenance patch

Based on crates.io `askama_derive` 0.16.0, upstream
<https://github.com/askama-rs/askama>, commit
`229e8bbd1682a51b073e4eceed2186511c4d670a`.
The registry archive SHA-256 is
`e1c7065972a130eafa84215f21352ae15b4a7393da48c1f5e103904490736738`.
The upstream MIT and Apache-2.0 licenses, commit provenance, normalized manifest,
original manifest, source, unit tests, benchmarks and template fixtures are
retained. The unused upstream `Cargo.lock` is omitted; the application's root
lockfile resolves production dependencies.

UniFFI 0.32.2 enables Askama's configuration feature for its binding templates.
That feature pulls in `basic-toml`, which is archived and affected by
[RUSTSEC-2026-0374](https://rustsec.org/advisories/RUSTSEC-2026-0374.html).
No fixed `basic-toml` release exists. Published Askama 0.16.1 still depends on it.

This is a backport of the two-file change in
[upstream PR 771](https://github.com/askama-rs/askama/pull/771), merged at
`d47daf8767805c0c4dfb456145fc857bfd9c1d2c` from patch commit
`3863808cf594054f7644979ed92caaafc878f378`. The production delta is limited to:

- Replace the optional `basic-toml` dependency with `toml >=1.0.7, <2`, using
  only its `parse` and `serde` features and disabling default features.
- Update the configuration feature's dependency and call `toml::from_str`.

The normalized `Cargo.toml` is patched in place. `Cargo.toml.orig` remains an
unchanged provenance copy. The package and its registry parser dependency stay
at 0.16.0; template parsing and generated bindings retain the existing APIs.
Using this backport avoids unrelated generator changes already present on
upstream's main branch and a second Git-sourced parser crate.

Validation should run the existing library tests, including the 17 tests in
`src/config.rs` for template directories and globs, custom syntaxes, escaping
and whitespace. Their fixtures are retained under `templates/` and
`empty_test_config.toml`. Run these using the shared build target:

```sh
cargo test --manifest-path vendor/askama_derive/Cargo.toml --lib
```

A standalone vendor test may create `vendor/askama_derive/Cargo.lock`; discard
that test lockfile afterward. Also build the `epix-ffi` binding generator with
its `cli` feature and exercise Kotlin/Swift generation, so the real UniFFI
`askama.toml` template directories are checked. Run the security scanners on
the root lockfile and confirm `basic-toml` is absent.

Remove this vendor patch when a published Askama release includes PR 771 and
is compatible with the selected UniFFI version. Upgrade Askama's matched
runtime, macro and parser packages together, then remove the root workspace
patch and this directory.
