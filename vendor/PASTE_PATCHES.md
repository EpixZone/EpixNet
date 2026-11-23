# Identifier macro maintenance patches

These crates use the versions expected by EpixNet's RLN and Tendermint verification.
Each vendored directory includes the upstream source, license and commit metadata from its crates.io release.

| Crate | Version | crates.io archive SHA-256 |
| --- | --- | --- |
| `ark-ff` | 0.5.0 | `a177aba0ed1e0fbb62aa9f6d0502e9b46dad8c2eab04c14258a1212d2557ea70` |
| `flex-error` | 0.4.4 | `c606d892c9de11507fa0dcffc116434f94e105d0bbdc4e405b61519464c49d7b` |

The ark-ff 0.5.0 source never uses the paste macro. Its manifest drops that dependency, following [arkworks/algebra PR 994](https://github.com/arkworks-rs/algebra/pull/994).

The flex-error release uses this macro to build error type identifiers. Its public macro import now uses [pastey](https://github.com/as1100k/pastey). The flex-error manifest also omits the upstream workspace README path, which points outside the published crate.
