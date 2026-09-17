# Release validation record

Local work on 2026-09-16. Source remains uncommitted across EpixNet, epix-wallet
and EpixSites-Xite. Local artifacts are QA builds, not approved store candidates.
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
# Required for a submission candidate; expected to fail on the current local wallet:
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

- Rebuild every package after final source and wallet pin changes. Record source
  revisions, artifact hashes, versions, signing identity and successful checks. Local Android QA hashes and
  artifact limitations are recorded in `.store-build/android-qa-artifacts.json`.
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

The signed Android AAB generated earlier in this session predates later shared
proxy changes and uses the previously pinned wallet. Keep it as a packaging-test
artifact only. A release gate now correctly prevents rebuilding it as a store
candidate until the new wallet is published and pinned.

## Final local build outcomes

Both simulator and generic-device Debug builds passed after the iPad orientation
metadata fix. The device build is unsigned. Both packages pass
`check-ios-package.py`; their wallet bundles match the latest local QA output.
The Android `validateStoreWallet` task fails as intended on the old published
wallet (missing new provider/provenance metadata). The local iOS wallet release
check fails as intended for modified source and missing policy URLs. These are
explicit release blockers, not ignored test failures.
