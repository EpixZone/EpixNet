# Release validation record

Local work on 2026-09-16. EpixNet source is committed in
[PR #490](https://github.com/EpixZone/EpixNet/pull/490), and wallet
[PR #18](https://github.com/EpixZone/epix-wallet/pull/18) is merged and published.
The artifacts below are packaging candidates, not approved for store submission.
Epix Sites publication and the remaining device/operational checks are still open.

## Published wallet and exact package builds

- EpixNet built source: `829c6536e29f4fb18f52bdef46acc415afbcc956`, clean at build
  time. Later documentation-only commits do not change this recorded revision.
- Wallet source: `c31832e1aabd89ee29691951ac673cfe961a3f1a`, immutable release
  [`wallet-c31832e1aabd`](https://github.com/EpixZone/epix-wallet/releases/tag/wallet-c31832e1aabd).
  Release workflow [35167624281](https://github.com/EpixZone/epix-wallet/actions/runs/35167624281)
  passed. The SHA-256 matches GitHub's asset digest:
  `30d2c66ef1e0f9c49322f117f0a1a82c43b12a0634a0c6b9fb662370c6fe0fdc`.
  Build metadata confirms clean source, provider protocol 1, the live TechSonix
  terms/privacy URLs and analytics disabled. The release wallet guard passes.
- The wallet's final Sonar fix uses a raw Windows Git path. Its quality gate
  passes with zero new issues and zero security hotspots; all PR checks passed.
- Local artifact directory: `dist/mobile/0.5.11-829c653/` (ignored by Git).
  `release-manifest.json` records versions, hashes, provenance and limitations;
  `ios-unsigned-archive-files.json` records every archive file's hash.

| Artifact | Result |
| --- | --- |
| `EpixNet-0.5.11-5011.apk` | Signed with the existing Android release key; 401,468,554 bytes; SHA-256 `22a138e1e6c85abb8d59d8a1591e3725d2cdea8ec1686a2767c7548e19a338d6` |
| `EpixNet-0.5.11-5011.aab` | Signed with the existing Android release key; 225,364,291 bytes; SHA-256 `b70efbc4a1010917d488a73e2dbcfba1aea5a9a1ce5dbfe653b67a355f35af35` |
| `EpixNet-unsigned.xcarchive` | Release archive succeeds; iOS 0.5.11 build 1, `zone.epix.EpixNet`; package scan passes; unsigned and not installable/uploadable as supplied |

Android is `zone.epix.app`, version 0.5.11 / code 5011, arm64-v8a, target SDK 36.
Both packages contain 17 native libraries passing the 16 KB checks; APK native
entries are ZIP-aligned. `apksigner`, `jarsigner` and official bundletool 1.18.3
validation pass. The certificate SHA-256 is
`a756664ccbb4ff4f4168e27ea56e62f4dac045103d4e89c0e7118007df0c5326`.
Java reports the Android certificate as self-signed without a timestamp, and
reports a JarInputStream manifest warning because of ZIP entry order; JarFile
signature verification and bundletool structural validation pass.

All 108 published wallet files were checked inside each Android package and the
iOS archive. Android's manifest differs only by the required `geckoViewAddons`
permission; the remaining files match byte-for-byte. All iOS wallet files match.
The iOS archive has one native executable, no external non-system library links,
the required permission text and privacy resources, and no BitTorrent feature.

The signed iOS archive attempt failed: Xcode found no development provisioning
profile for `zone.epix.EpixNet` and reported no registered team devices. The only
installed signing identity is a macOS Developer ID certificate. The owner is
configuring iOS signing; an Apple Distribution certificate and App Store profile
can be used for distribution. The unsigned archive verifies compilation and
packaging only. No IPA, TestFlight upload or Play upload has been produced.
Confirm that the proposed build numbers are unused in the store records.

## Earlier interactive QA

The isolated Android QA emulator was shut down and its generated data/cache
removed after testing; the pre-existing user emulator was left alone.

## Completed checks

| Area | Evidence |
| --- | --- |
| BitTorrent boundary | Separate iOS, Android and desktop target graphs pass; earlier discovery/xite tests passed 84 without BT and 88 with BT |
| iOS bridge regressions | Extracted actual Swift methods: untrusted frames, stale replies, failed vault saves, origin/port/tab isolation, cancellation and deep links pass |
| Desktop | `cargo check -p epix-browser --locked` passes after the shared proxy extraction |
| Private TLS proxy | Four Rust tests pass, including a real CONNECT/TLS/HTTP exchange and rejection of public-host certificate issuance |
| Android 16 KB inspection | Six checker regressions pass; signed APK and AAB each contain 17 native libraries passing ELF/RELRO checks; APK native entries are ZIP-aligned |
| Android runtime smoke | Signed APK installed and launched on isolated API 37.1 arm64 emulator, actual page size 16,384; process stays alive and crash buffer was empty |
| Wallet source | Extension typecheck and production webpack build pass; build output includes the page provider. Three mobile approval-transport tests pass, including close-during-navigation; local build has five webpack warnings |
| Epix Sites | Node syntax checks and moderation VM regressions pass |
| iOS device compile | Unsigned Debug build for generic iOS device passes; simulator and device package scans pass and bundled wallet matches latest staged QA output. This is not a signed archive/install |
| Native iOS UI | Xcode 26.6 / iOS 26.5 simulator: dashboard renders, xID opens at its own HTTPS origin, Connect Wallet detects Epix Wallet and opens onboarding; dismiss returns to xID; fresh iPad acquisition and portrait/landscape dashboard layouts verified |

The Android emulator window is not exposed by the current UI automation surface;
runtime smoke/log checks do **not** establish full visual or interaction QA.
No wallet seed was imported and no blockchain transaction was performed.
No physical iOS device was connected (`devicectl list devices`); device compile
was unsigned. Wallet UI setup requires the owner to enter a disposable test
password, so approval/recovery/camera tests remain pending that handoff.

## Dashboard publication

[EpixDash PR #37](https://github.com/EpixZone/EpixDash-Xite/pull/37) merged on
2026-09-16 at 20:49:19 UTC, merge commit
`6978546f9fdad932a3d3f5ad242d96cb880b37c5`. The owner then confirmed signing and
publication. Read-only inspection of the running iPad simulator node's
network-acquired dashboard cache verified:

- Dashboard address `epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g`, domain
  `dashboard.epix`, content manifest `modified: 1789592459`.
- `js/Head.js`, `js/FeedList.js` and `css/all.css` each match their manifest
  SHA-512 digest (the first 64 hexadecimal characters).
- The feed source no longer renders the DeFlix tile, and the header source
  contains the conditional **Feed / Discover** label.

Before publication, JavaScript syntax, whitespace and actual rendered-output
checks passed for empty/populated feed transitions and the ten remaining tiles.
This post-publication check verifies downloaded content, not a fresh visual
reload or release screenshot. Epix Sites moderation and the updated wallet
artifact have not been published by this dashboard release.

## Packaging changes

iOS now has camera usage text in the actual target plist, a bundled required-reason
privacy manifest, build-derived versions, explicit static Rust linking and
development/release wallet asset checks. The private `.epix` TLS trust remains
app-scoped. The wallet uses protected native storage and a nonpersistent WebKit
document; backgrounding closes the decrypted document and cancels requests.

Android uses compile SDK 37 / target SDK 36, AGP 9.1.1 / Gradle 9.3.1,
GeckoView 155.0.20260903215306 and JNA 5.19.1. Rust and pinned-source Snowflake
build with 16 KB-compatible linkage. Play bundles require explicit signing and
wallet release validation. Wallet downloads are checked against the pinned hash.

## Reproduce focused checks

```sh
python3 scripts/check-platform-features.py
python3 scripts/test_android_native.py
python3 scripts/test_mobile_wallet.py
cargo test -p epix-browser-net --locked
python3 shells/ios/tests/run-regressions.py
python3 scripts/check-mobile-wallet.py shells/wallet-ext
python3 scripts/check-ios-package.py /path/to/EpixNet.app
# Required for a submission candidate; passes with the current published pin:
python3 scripts/check-mobile-wallet.py shells/wallet-ext --release
python3 scripts/check-android-native.py --require libepix_ffi.so \
  --require libepix_snowflake.so \
  shells/android/app/build/outputs/apk/release/app-release.apk \
  shells/android/app/build/outputs/bundle/release/app-release.aab
```

Wallet: `yarn workspace @keplr-wallet/extension typecheck`; build with
`NODE_ENV=production BUILD_MANIFEST_V2=true BUILD_OUTPUT=build/mobile-store yarn webpack`
in `apps/extension`. Store builds additionally require published policy URLs,
`EPIX_MOBILE_STORE_BUILD=1`, clean committed source and a pinned artifact.

Sites: `node --test tests/store-safety.test.cjs` in the EpixSites-Xite repository.

## Still required for the exact candidate

- Review the committed source and rebuild if application code or the wallet pin
  changes. The exact current package hashes and versions are recorded above.
  Earlier Android QA hashes and limitations remain in `.store-build/android-qa-artifacts.json`.
- Simulator package scan confirms no developer-machine library paths and all
  four current required-reason categories are bundled. Unsigned device compile also passes. Finish
  device archive/privacy/signing validation and test installation on a physical device.
- Exercise wallet create/import/backup/recovery, lock/unlock, approval/rejection,
  signing with a disposable funded test identity, timeout, navigation and upgrade.
- Expand iPad testing beyond the verified dashboard/rotation; test Android back/tabs, QR camera denial, nearby-network denial,
  first install, offline/retry, network changes and sustained foreground/background use.
- Complete signed-content moderation/deletion checks, operational contacts,
  rights/payment assessments, TestFlight and Play internal/pre-launch reports.
- Capture screenshots from the exact final builds, not the development simulator.

The earlier Android QA AAB predates the shared proxy changes and uses the older
wallet. It is superseded by the exact packages above. The release gate now passes
with the published wallet pin; this does not waive the remaining submission work.

## Historical Debug build outcomes

Both simulator and generic-device Debug builds passed after the iPad orientation
metadata fix. The device build is unsigned. Both packages pass
`check-ios-package.py`; their wallet bundles match the latest local QA output.
At that stage, Android `validateStoreWallet` failed as intended on the old
published wallet, and the iOS wallet release check rejected modified source and
missing policy URLs. Publishing and pinning the new wallet resolved those
specific blockers; both current Release builds pass the wallet guard.
