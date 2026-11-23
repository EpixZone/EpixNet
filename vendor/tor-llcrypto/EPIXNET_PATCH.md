# Arti RSA and key storage

EpixNet uses the published Arti 0.47.0 packages from Tor Project commit
`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087`. Three of those packages need
dependency changes for [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).
The first patched RustCrypto RSA release is 0.10.0. Both Arti 0.47.0 and
0.48.0 specify RSA 0.9.

| Vendored crate | SHA-256 of the published 0.47.0 crate |
| --- | --- |
| tor-llcrypto | `95f921a609ff73736e8e21d11dbee6617cd7568841790f2e3327295627a51b75` |
| tor-key-forge | `5534581a7f347ffcade7ea32ecccdbc035d36468bc8c03b0dce83363b6d41801` |
| tor-keymgr | `e269210a2ba305bf6524990a3c37aab4529b92a01f3d15ef6af23c067c8eb2c4` |

`tor-llcrypto` uses RustCrypto RSA 0.10 for legacy Tor signature verification,
signing, and PKCS#1 encoding. Directory fingerprints require the canonical
PKCS#1 public key encoding. Arti's existing known-answer test covers its
fingerprint, DER bytes and signatures.

Both keystore crates use the same pinned upstream SSH codec,
`ssh-key 0.7.0-rc.12`, which supports RSA 0.10. The Arti SSH fork requires
RSA 0.9. The upstream codec supports the 1024-bit relay keys and the standard
OpenSSH encoding that the fork was added for. A keystore regression test
exercises generation, export, import, signing and verification of a Tor
RSA identity. The existing identity key formats and algorithm identifiers
remain in use.

The original manifests and source revision records are included alongside the
compiled manifests. The application resolves dependencies through the root
lockfile. Remove these patches together once a released Arti family supports
the patched cryptographic dependencies.
