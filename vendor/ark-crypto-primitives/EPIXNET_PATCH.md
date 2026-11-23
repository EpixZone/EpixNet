# Optional derive dependency for ark-crypto-primitives 0.5.0

The registry archive SHA-256 is
`1e0c292754729c8a190e50414fd1a37093c786c709899f29c9f7daccecfa855e`.
The upstream commit is `455d599aae0aa81acf1c2faadf37def63a25a291`.
Both upstream licenses are included.

EpixNet's Groth16 prover and verifier use the `snark` and `sponge` features.
The upstream manifest also builds the unmaintained `derivative` macro when
only those features are selected. The patched manifests and macro import
enable it for the `crh`, `encryption` and `signature` features that use it.
Commitment and Merkle tree support already enable `crh`.

The arithmetic, proof formats and implementations of the optional features
are the upstream 0.5.0 sources. [Upstream source](https://github.com/arkworks-rs/crypto-primitives/tree/455d599aae0aa81acf1c2faadf37def63a25a291/crypto-primitives)
