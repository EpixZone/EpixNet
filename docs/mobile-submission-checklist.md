# Mobile submission checklist

Prepared September 16, 2026 from local source and current official store
documentation. This is a prioritized work plan; unchecked items are not
completed. Store-console configuration has not been completed. Native packaging and
simulator results are recorded in the [submission package](store-submission/README.md). See [mobile-store-readiness.md](mobile-store-readiness.md)
for the dashboard inspection and completed BitTorrent boundary work.

## Scope already established

- Organization enrollment with Apple and Google is confirmed by the owner.
- The legal publisher is **TechSonix, Inc.**, confirmed by the owner. Public
  policy pages are being prepared in `TechSonix/techsonix.com` for GitHub Pages.
- Keep the dashboard as the homepage. Curated bookmarks are not prohibited.
- Keep desktop and Android functionality when a restriction is specific to iOS.
- The iOS Rust profile excludes BitTorrent media and tracker discovery;
  desktop and Android retain it. Dependency checks and host tests have passed.
- The DeFlix dashboard tile removal is published at the owner's request;
  its community directory listing remains available. No policy violation has
  been established by this change.

## 1. Correct and validate the mobile packages

- [x] Camera purpose text in the actual iOS target plist, bundled required-reason
  privacy manifest, versions derived from build settings.
- [x] iOS page wallet provider and external approval transport implemented;
  xID-to-wallet onboarding verified in the simulator. Full signing QA remains.
- [x] iOS private TLS origins, frame/port/tab bridge restrictions, protected
  vault writes and background document teardown implemented and regression-tested.
- [x] Android compile SDK 37 / target SDK 36, compatible AGP/Gradle, GeckoView
  and JNA updates; native 16 KB build and package checks.
- [x] Signed Android APK/AAB packaging test and isolated 16 KB emulator launch.
- [x] Build gates for signing, version code and immutable mobile wallet/policy config.
- [x] Simulator and unsigned device builds pass, including self-contained native links.
- [ ] Verify final signed iOS archive, privacy report and signing.
- [ ] Publish and pin the changed wallet, configure real policy URLs, then rebuild
  the exact store candidates. Local uncommitted QA bundles are not eligible.
- [ ] Finish physical-device, permission-denial, iPad, upgrade and wallet QA.

Full Xcode 26.6 is installed; the earlier Command Line Tools-only assessment was
incorrect. See [the validation record](store-submission/release-validation.md)
for actual evidence and remaining limitations.

## 2. Verify the integrated community experiences

- [x] Dashboard tile removal and small-screen **Discover** label when no feed
  entries exist: [PR #37](https://github.com/EpixZone/EpixDash-Xite/pull/37)
  merged, signed and published by the owner; updated files verified in the
  iPad node's network cache against the content manifest.
- [ ] Test terms acceptance before contributing, report content/user,
  block/mute user, content filtering, and moderator response in the promoted
  social xites and directory. Existing moderation code is a starting point;
  demonstrate the full workflow on both mobile platforms.
- [ ] Review Epix Sites specifically: `js/Site.js` requires a certificate for
  reports and describes them as public signed records; `js/utils/Trust.js`
  gives paid `.epix` identities vote weight and has a narrow report taxonomy.
  Provide an accessible reporting/support path for people without a paid xID
  and for private abuse or rights complaints. This is a recommended product
  safeguard, not a claim that the policies mandate anonymous voting.
- [ ] Establish who monitors reports, how urgent complaints are handled, and
  how action is enforced in the shipped app. Community vote thresholds must
  not be the only means of handling substantiated serious complaints.
- [ ] Verify default content filters and age controls. Inspect the Flagged
  audit view so retaining moderation evidence does not re-expose prohibited
  material. Determine the intended audience before completing ratings.
- [ ] Document DeFlix catalog provenance and license conditions for the
  distribution territories. Existing public-domain/CC labels are claims to
  verify. Decide whether to feature it after this assessment; a community
  directory listing does not by itself establish infringement or compliance.

Google's [UGC policy](https://support.google.com/googleplay/android-developer/answer/9876937?hl=en)
explicitly covers specialized clients directing users to UGC platforms.
Apple's [review guidelines](https://developer.apple.com/app-store/review/guidelines/)
cover integrated UGC and unauthorized media. These checks concern EpixNet's
integrated experiences; they do not assume that every website reachable in a
general browser is operated by EpixNet.

Local Epix Sites source now includes rule acceptance, contributor/owner blocks
and safe audit rows, with regression tests. Publication and operational checks
remain pending; see [the moderation runbook](store-submission/moderation-runbook.md).

## 3. Settle wallet, identity and data behavior

- [ ] Inventory the actual embedded wallet features and supported countries.
  Complete Google's [financial-features declaration](https://support.google.com/googleplay/android-developer/answer/13849271?hl=en)
  and assess its [wallet policy](https://support.google.com/googleplay/android-developer/answer/16329703?hl=en)
  against the actual custody/services model. Organization enrollment alone
  does not resolve this assessment.
- [ ] Resolve the treatment of paid xID registration and any digital features
  it enables under the applicable store payment rules and storefronts. Do not
  assume that a cryptocurrency payment bypasses those rules or that every
  blockchain domain purchase necessarily requires in-app purchase.
- [ ] Map data flows: IP addresses and peer announcements, downloaded/seeded
  xites, signed public posts/reports, chain transactions, wallet RPC services,
  diagnostics, and any third-party services in the pinned wallet build.
  Distinguish on-device storage, user-directed publication, and collection by
  the company or partners before completing store privacy forms.
- [ ] Publish/verify privacy policy, terms/community rules, and support/abuse
  contact URLs; make them accessible in the app. Match disclosures to actual
  routing defaults, sharing, retention and optional permissions.
- [ ] Determine which identity/profile flows constitute app-account creation
  and implement the applicable deletion paths: see
  [Apple](https://developer.apple.com/support/offering-account-deletion-in-your-app/)
  and [Google](https://support.google.com/googleplay/android-developer/answer/13327111?hl=en).
  Explain immutable chain records and independently replicated data honestly;
  deleting a local wallet must not be represented as erasing those records.
- [ ] Complete Apple's [encryption/export assessment](https://developer.apple.com/help/app-store-connect/manage-app-information/overview-of-export-compliance)
  for the actual cryptography included. Do not set an exemption flag without
  determining that it applies.

## 4. Test the exact release candidates

- [ ] Fresh install with no staged xites: dashboard/xID acquisition, useful
  progress, offline/failure states, retry and recovery.
- [ ] Address/search navigation, external web pages, `epix://` links, tabs,
  downloads, iPhone/iPad layouts for supported device families, Android back
  behavior, and permission denial.
- [ ] Wallet create/import/lock/unlock, storage isolation, connection approvals,
  cancellation and supported hardware-wallet flows using disposable test
  identities. Verify backup/recovery and that app upgrades retain the vault.
- [ ] Native bridge authorization and isolation between websites, especially
  loopback-served xites and the wallet. Confirm secrets stay out of logs.
- [ ] Wi-Fi/cellular changes, Tor/I2P readiness and routing claims, offline
  operation, foreground/background/resume behavior, battery, storage growth,
  memory pressure and long-running sync.
- [ ] Verify iOS BitTorrent exclusion in the release dependency graph/package
  and runtime behavior; verify Android retains its intended features.
- [ ] Run TestFlight and Play internal testing with the actual signed builds;
  address validation errors, crashes and Play pre-launch findings. Desktop
  responsive testing does not substitute for these checks.

## 5. Prepare and submit the store records

- [ ] Confirm company display/contact details, release countries, app IDs,
  signing arrangements, version, category, supported devices and release mode.
- [ ] Supply icons, screenshots captured from the release builds, descriptions,
  support/privacy URLs, and any required rights documentation.
- [ ] Answer privacy/data-safety, ads, financial features, content/target-age
  and permission declarations from the audited behavior. Apple's
  [rating questionnaire](https://developer.apple.com/help/app-store-connect/reference/app-information/age-ratings-values-and-definitions)
  includes unrestricted browsing, UGC and social capabilities.
- [ ] Write reviewer instructions covering the embedded node, dashboard,
  community directory, wallet/xID, routing controls, moderation/deletion,
  and platform differences. Provide working disposable review access where
  needed so reviewers can exercise features without acquiring cryptocurrency
  or depending on personal accounts. Arrange any Apple demo-mode exception
  in advance; do not alter behavior specifically for reviewers.
- [ ] Confirm that bootstrap infrastructure, xites, support links and required
  services stay available during review. Upload the validated builds, resolve
  console checks, submit, and select manual release if desired.

Google's [review preparation guide](https://support.google.com/googleplay/android-developer/answer/9859455?hl=en)
lists the app-content declarations. Store-console setup and submission remain
pending. Dashboard publication is complete; Epix Sites moderation and the
updated wallet artifact still require publication.

Recommended order: package defects and iOS wallet functionality first;
moderation/data/payment assessments next; then signed-device QA, store assets,
declarations, and submission. The owner supplies business choices, signing
access, support contacts and operational moderation commitments; engineering
can implement and verify the corresponding product behavior.
