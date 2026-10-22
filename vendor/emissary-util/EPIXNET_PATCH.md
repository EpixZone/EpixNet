# EpixNet patch

Source: [eepnet/emissary at 4495edc6e67eccfa7d4bbb0c7b309febbf2e6a32](https://github.com/eepnet/emissary/tree/4495edc6e67eccfa7d4bbb0c7b309febbf2e6a32/emissary-util), package `emissary-util` 0.4.0.

This copy upgrades `zip` from 4.x to 9.0.5 to remove RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369. The deflate backend and reseed signature verification are unchanged. The reseeder reads individual ZIP entries into memory and does not use filesystem extraction.

The manifest expands the original workspace metadata and dependency values so this package can build independently. `emissary-core` remains pinned to the exact original upstream revision. Upstream source, certificate assets, signed SU3 test fixture and license files are preserved.

Validation includes the upstream signed SU3 parsing and invalid-signature tests, EpixNet I2P tests, mobile feature profiles and a live embedded reseed smoke.

Remove this patch when upstream publishes or commits the ZIP upgrade with compatible mobile TLS features. Do not replace it with an advisory ignore.
