# Arti dependency updates

The application uses the published Arti 2.7.0 sources from Tor Project commit
`ce8bc6e0998bd5a4efdf06dd62dce53c98ea1087`. The separately published
`pwd-grp` 1.0.2 is from Tor Project commit
`2698f45a241a95ec92246ed50f592a5c7352aa47` in
[its upstream repository](https://gitlab.torproject.org/tpo/core/rust-pwd-grp).
Each package retains its published manifest, source revision record and license.
The root application and fuzz workspaces provide their dependency locks.

* Token-pasting macros use the maintained `pastey` package. The existing exported
  macro paths and names are preserved for callers.
* Time formatting, parsing and Serde in Arti use the local `tor-time-format` package.
  Config files, guard state and onion-service records retain their wire formats.
* The HTTP proxy URI fallback encodes credentials without logging the username.
* Onion-service request queue tests draw a fresh random nonce per request. Their mock verifier checks the solution bytes.
* Serde derives for public onion-service discovery keys use their existing string
  representation. The Arti consumers select only the `serde_with` macros they use.
* `tor-key-forge` and `tor-keymgr` are already under `vendor/` with the RSA migration.
  The remaining published packages in the table are under `vendor/arti/`.

EpixNet selects Tokio with Rustls explicitly for all Tor connections. Arti binds
the TLS certificate to the relay's directory identity in its channel handshake.
The upstream `native-tls` feature and runtime names also use this Rustls
transport in the EpixNet build. The separate native client implementation is
removed. This change is limited to Tor relay links.

The runtime TLS tests use the upstream expired, password-protected test identity
in `tor-rtcompat/testdata/expired-server-identity.pfx`. The macOS and Windows
native TLS backends can import the PKCS#12 fixture. The descriptor tests use
public, deterministic expected text in `tor-netdoc/testdata`. Only the public
authority certificate from the simulated relay's keys directory is used.

| Published package | Version | SHA-256 of crates.io archive |
| --- | --- | --- |
| arti-client | 0.47.0 | `43e6531f26fe6f44d71dabdc63b7845bae81547cc738aa942f0e3e482f776388` |
| pwd-grp | 1.0.2 | `0e2023f41b5fcb7c30eb5300a5733edfaa9e0e0d502d51b586f65633fd39e40c` |
| retry-error | 0.14.0 | `90a0dea62e6084ede74beea58ee263fd2d70bdb59260a3bf3ede338dfb76f5cc` |
| slotmap-careful | 0.9.0 | `7dae6673c710ab011fc8d2ff604b16201df0a59f943976d911d83bbac2a1854f` |
| tor-basic-utils | 0.47.0 | `e44c7b006f22966d44a2a0a6c1ee71e472c62182c7f0460077df3294d52f23c4` |
| tor-cell | 0.47.0 | `b2d6398fd085306de5af739899d0390674b8646d4ff6cfb69d65f40a5f9d88da` |
| tor-chanmgr | 0.47.0 | `431ba53bf020ea8681ef0c2fbf0f0f854997fca9afe1b2c081f41f14ec00cf5d` |
| tor-checkable | 0.47.0 | `e58a50a2dbf5d21758c9e2dbaaf085403670b8bf52475c815dd1185698b7af9a` |
| tor-circmgr | 0.47.0 | `8b6b55747c690e0c931c5a081640ffdca6d1003c01b57b8102afcbdbaf3ec3fd` |
| tor-config | 0.47.0 | `b849c69c695b9534cf945c0422b85eaf5760bb6141a73c47b72fd6f95ea4d719` |
| tor-dircommon | 0.47.0 | `c16065e5166e529492d1be856e1e40316e2532053027c6b7ab5a4a53c14d8c51` |
| tor-dirmgr | 0.47.0 | `34ea5e77b43bf1ef5fa213a89cb67080f218df6b418c82527e6bb9862a39aef5` |
| tor-error | 0.47.0 | `ca01de513501849b2298e4f16f8760832ef43344b10fe17600daed9a35128b24` |
| tor-guardmgr | 0.47.0 | `87694603d6dcee5e0b050f0e7ac8be86348eb78ecb90c36ee8b70bd5822f3eff` |
| tor-hscrypto | 0.47.0 | `6613c5336b71ebd34b8d90c233a7b6b06a0b81899d0545c656b0cac6f24e54a2` |
| tor-hsservice | 0.47.0 | `55809560d9295dcc2ee77002c5a4275d1f5f5a54203de7cd6acb52215f5344bd` |
| tor-key-forge | 0.47.0 | `5534581a7f347ffcade7ea32ecccdbc035d36468bc8c03b0dce83363b6d41801` |
| tor-keymgr | 0.47.0 | `e269210a2ba305bf6524990a3c37aab4529b92a01f3d15ef6af23c067c8eb2c4` |
| tor-linkspec | 0.47.0 | `d287978bd5e1ffbe7ca2eb8daadb4e06e42d084bdad26bea4d4bbe1ff877e10f` |
| tor-log-ratelim | 0.47.0 | `2096a87f0691f0781bf564249c524d62b5338c3954ba1c6ef10ec90df1d97733` |
| tor-memquota | 0.47.0 | `96853fc516264fe2ebefbe40d276b6a3b84e15fc08b74fd7a85e2c5df9f11c37` |
| tor-memquota-cost | 0.47.0 | `f5e5712bfe2995a60eddcc32d07e2e38a42120318a8f5411d621bf0a8fa77219` |
| tor-netdir | 0.47.0 | `cd22ffd4d6aa9389ec8e20e9b0d579d61101682c5ec8379115a388e473e83297` |
| tor-netdoc | 0.47.0 | `78dc8a397a86fd00b17607941b204281dd8a77a6018ca8eedc257bdccb4f3aa7` |
| tor-persist | 0.47.0 | `e7a3bc60cbe74bf41cd63e2506a9a16bd52047668771578b12ff2453ec4c7522` |
| tor-protover | 0.47.0 | `3e69fbc196208a9d6232d2c38e32806f3bb064792fd84ac6ee12b5ba1e482240` |
| tor-rtcompat | 0.47.0 | `99036f7a4fa9735e0beac7f241592da1a072c94a018e4fa702001700f5922291` |
| tor-rtmock | 0.47.0 | `9140515718465f1ede62fa33e96cc929acf075a3893cb349d1c606976c846a21` |
