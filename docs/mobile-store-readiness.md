# Mobile store readiness

Policy/source review: September 16, 2026. This is an implementation plan, not
an approval guarantee or a completed store-readiness audit.

The ordered release work and newly inspected packaging gaps are tracked in
[mobile-submission-checklist.md](mobile-submission-checklist.md).

## Platform scope

Apply an iOS-specific restriction to the iOS build, without removing the same
feature from desktop or Android. Requirements shared by both mobile stores
still need to be addressed on both platforms.

| Behavior | Desktop | Android | iOS |
| --- | --- | --- | --- |
| Launch dashboard | Keep | Keep | Keep unless a specific content/feature issue requires a change |
| Dashboard navigation | Keep | Keep | No search-only access requirement |
| BitTorrent media engine and tracker discovery | Included | Included | Excluded at build time |
| Epix peer discovery | Keep | Keep | Keep |

Apple's [default-browser requirements](https://developer.apple.com/documentation/Xcode/preparing-your-app-to-be-the-default-browser)
allow an address field, search tools, or curated bookmarks on launch. They do
not require an empty page. Requiring manual navigation does not exempt a
feature from review. Disclose the actual functionality and provide reviewers
with access; do not change behavior specifically for reviewers.

## Dashboard inspection

Verified September 16, 2026 against the local EpixNet, EpixDash-Xite,
EpixNet-xAuth, EpixTalk-Xite, and DeFlix-Xite sources, with a running desktop
node and browser inspection at desktop and 390-by-844 phone viewport sizes.

- All three shell defaults open `dashboard.epix`: desktop
  `crates/epix-browser/src/main.rs`, iOS
  `shells/ios/EpixBrowser/AppDelegate.swift`, and Android
  `shells/android/app/src/main/java/zone/epix/app/MainActivity.kt`.
- The initial xite list contains Dashboard and xID. Channels are enabled by
  default and automatically ensure the xID hub is available; see
  `crates/epix-ui/src/config_schema.rs` and
  `crates/epix-plugins/src/channel.rs`. Browsing Dashboard does not require
  connecting a wallet or signing in to xID.
- The Discovery welcome view is now a fixed list of 10 destinations in the
  sibling repository `EpixDash-Xite/js/FeedList.js`, `renderWelcome()`:
  Epix Talk, Epix Blog, Epix Post, Epix Mail, Epix Sites, Epix Wiki,
  Epix Documentation, xID, Explorer, and VRF Debugger.
- With no subscribed feed entries, the feed panel automatically displays
  Discovery. On a phone-width viewport the initial segment is **Xites**;
  the small-screen toggle now says **Discover** when there are no feed entries
  and **Feed** when entries exist. Desktop displays both panels.
- The tiles are ordinary xite navigation links. They say **Activate** before
  the xite is present locally and **Visit** afterward. The inspected link
  renderer is not a native application installer.

The owner subsequently requested removal of the DeFlix dashboard tile and the
conditional mobile Discover label. Both changes are merged in
[EpixDash PR #37](https://github.com/EpixZone/EpixDash-Xite/pull/37), signed and
published by the owner. The iPad simulator node downloaded the updated files;
their hashes match the content manifest. DeFlix remains discoverable through
xite search. See the [publication evidence](store-submission/release-validation.md#dashboard-publication).

There is no identified policy reason to replace this homepage with a blank
page or require DuckDuckGo searches. Apple's default-browser guidance
expressly permits curated bookmarks. This does not establish approval of
every promoted destination or its integration with native capabilities.

The test used a newly rebuilt `epix-server --locked` binary and an isolated
temporary data directory. Dashboard's signed files were staged from its local
repository; the running node used the network and synchronized xID. This
verified the dashboard web UI, not native mobile release behavior or a full
unstaged first-install download. No wallet transaction was performed. Subsequent native work found Xcode 26.6 installed. The iOS 26.5 simulator now
loads Dashboard and xID and opens wallet onboarding; see the
[validation record](store-submission/release-validation.md) for scope and gaps.

### Findings requiring follow-through

- **Social features:** Dashboard includes mute/block management, and Epix
  Talk's `js/Admin.js` already has topic/comment report queues and moderation
  actions. These are existing controls, not proof that moderation is missing.
  Verify reporting, blocking, filtering, contact information, and operational
  response across each promoted social experience, including mobile layouts.
- **xID registration:** The inspected xID UI exposes wallet connection,
  registration, and EPIX-denominated fees. Its price page says fees are burned.
  Assess how paid names relate to app features and digital services under
  Apple's payment rules, especially section 3.1.1. This is a review question,
  not a finding that every blockchain name registration requires IAP.
- **DeFlix rights:** The local catalog contains 1,142 entries: 1,025 labeled
  public domain and 117 with Creative Commons labels. Those are catalog
  declarations, not verified rights evidence. Check provenance, license
  conditions, and distribution territories for the promoted catalog.
- **Developer enrollment:** The owner confirms organization/company
  enrollment with both Apple and Google. Treat that prerequisite as supplied;
  it does not establish compliance of wallet activities or payment flows.

## Implemented build boundary

The existing `bittorrent` feature now includes tracker discovery as well as
the media engine. It gates both the background `bt_trackers` announce loop
and announces through the general xite tracker list. Builds without it return
an unsupported-feature error for BT tracker URLs, including imported ones,
while continuing to use Epix trackers in mixed lists. Tracker URL parsing is
retained for configuration compatibility; it does not contact a tracker.

Desktop and Android production profiles already enable `bittorrent`. The iOS
build script does not. Low-level discovery/xite crate callers that need BT
must now explicitly enable their `bittorrent` feature too.

Check the profiles in separate Cargo invocations to avoid workspace feature
unification masking an unwanted dependency:

```sh
python3 scripts/check-platform-features.py
cargo test -p epix-discovery -p epix-xite --locked
cargo test -p epix-discovery -p epix-xite --features epix-xite/bittorrent --locked
```

The dependency guard checks the media engine and each feature forwarding layer,
and checks that desktop/Android retain the functionality. It fails if Cargo
cannot resolve a profile. Mobile dependency checks use the actual ARM64 target
graphs including Tor bridges. Host compilation checks omit the separately
vendored bridges artifact; native release builds still need their platform
SDKs and device QA.

Validation for this change: 84 tests passed without BitTorrent and 88 with it;
the three platform dependency checks passed. Both mobile feature profiles
passed `cargo check` on the macOS host. Subsequent native compilation and simulator tests are recorded in
[release validation](store-submission/release-validation.md). Signed Android
APK/AAB packaging tests now exist, but those artifacts are not final candidates.

## Remaining assessment

- **Dashboard and bundled social experiences:** Inventory promoted sites,
  feeds, posting, reporting, blocking, moderation, and age controls. Google's
  [UGC policy](https://support.google.com/googleplay/android-developer/answer/9876937?hl=en)
  explicitly includes specialized browsers directing users to UGC platforms.
  Apple addresses UGC in section 1.2 of its review guidelines.
- **Media rights:** Audit media downloading, streaming, web seeds, and catalog
  presentation against Apple section 5.2.3 and Google's
  [intellectual-property policy](https://support.google.com/googleplay/android-developer/answer/9888072?hl=en).
  Removing a protocol does not establish authorization to distribute content.
- **Web apps and bridges:** Determine whether any integrated xites fall under
  Apple's section 4.7 mini-app rules, and inspect native API exposure and
  remote-code behavior. Ordinary browsing and an integrated software catalog
  need different assessments.
- **Wallet:** Organization enrollment is confirmed by the owner for both
  stores. Check supported wallet activities and territories, the xID payment
  flow, and Google's
  [financial-feature declarations](https://support.google.com/googleplay/android-developer/answer/13849271?hl=en).
- **Privacy and release behavior:** Verify peer-sharing disclosures, privacy
  policy, store data declarations, permissions, deletion behavior where
  applicable, and permitted background activity. Test the actual release
  binaries, age ratings, and reviewer access.

Apple policy references above are to the
[App Review Guidelines](https://developer.apple.com/app-store/review/guidelines/).
Google also requires [behavior transparency](https://support.google.com/googleplay/android-developer/answer/17006354?hl=en)
and accurate [user-data disclosures](https://support.google.com/googleplay/android-developer/answer/10144311?hl=en).
