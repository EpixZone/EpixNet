# Mobile shell regression tests

These tests compile the production methods directly from the shell sources, so
the assertions exercise the implementation used by the app.

## iOS host bridge and navigation

On macOS with Command Line Tools installed:

```sh
python3 shells/ios/tests/run-regressions.py
swiftc -frontend -parse shells/ios/EpixBrowser/AppDelegate.swift
```

The runner uses Foundation with small WebKit doubles. It verifies deep-link
paths and encoding, rejects wallet bridge messages from other documents,
origins, frames and sheets, and checks queued replies after navigation and
sheet replacement. It also checks that the wallet's hash-based navigation
retains storage access. This does not replace an Xcode build or simulator test.

## Android navigation

With one running Android emulator, JDK 17+, Kotlin, and Android SDK platform
and build tools 36 installed:

```sh
export JAVA_HOME=/path/to/jdk
export ANDROID_HOME=/path/to/android-sdk
export KOTLINC=/path/to/kotlinc/bin/kotlinc
# Optional override when the SDK's D8 is older than Kotlin supports:
export D8_JAR=/path/to/r8-8.13.19.jar
python3 shells/android/tests/run-url-regressions.py
```

The runner compiles the shell's navigation methods to Dex and executes them
on the emulator with real Android `Uri` and `Intent` classes. Browser widgets
are test doubles. It checks typed and external deep links, encoded path/query/
fragment preservation, ordinary HTTPS URLs, and search. Full APK launch,
GeckoView rendering, wallet onboarding, and the Rust core need separate tests.

### Browser system Back on Android 16+

With the full APK running on an API 36+ emulator:

1. From Dashboard, open the xID xite. Press Android Back (also test an edge
   gesture). It must return to Dashboard without leaving the app. The toolbar's
   Back/Forward buttons and system Back must navigate the same page history.
2. Open another xID page, navigate within it, and go Back one entry at a time.
   At Dashboard with no earlier page, Android Back may return to the launcher.
3. Switch between a tab with history and a fresh tab. System Back handling must
   reflect the selected tab, not history changes in background tabs.
4. With the on-screen keyboard open, Back must dismiss it before navigating.
   Navigating or switching tabs after editing the address must show the reached
   page's address. Repeat with the wallet open: wallet Back must stay inside its
   dialog history.

The app uses the lifecycle-aware AndroidX Back dispatcher. An Activity-level
`onBackPressed` override is not dispatched when targeting Android 16+ with
predictive Back enabled, even if the current Gecko session has history.

## Android wallet keyboard (issue #531)

On a disposable Android emulator with the debug APK installed and no wallet:

1. Enable the on-screen keyboard even with the emulator's hardware keyboard
   connected (`adb shell settings put secure show_ime_with_hard_keyboard 1`).
   Record the previous setting and restore it after the test.
2. Open the Epix wallet button, choose **Import an existing wallet**, then
   select **Use recovery phrase or private key**.
3. Tap a recovery-word field. Verify the keyboard appears and enter a test word
   by tapping the on-screen keys. Hardware/`adb shell input text` entry alone
   does not test this bug: it worked even while the dialog blocked the IME.
4. Verify later fields remain reachable, and repeat with **24 words** and
   **Private key**. Use only public test data; no wallet needs to be saved.
5. Close and reopen the wallet and repeat the keyboard check. Confirm the
   browser address bar still accepts input after closing the sheet.

For diagnosis, `adb shell dumpsys window windows` must not show
`ALT_FOCUSABLE_IM` on the wallet dialog. Before the fix, the field gained a
caret but the dialog retained that flag and the on-screen keyboard stayed hidden.


## Android wallet UI development and navigation

The wallet UI lives in the separate `EpixZone/epix-wallet` repository. Build its
Firefox extension, then point Android at the resulting directory:

```sh
cd shells/android
EPIX_WALLET_DIST=/absolute/path/to/epix-wallet/apps/extension/build/firefox \
  ./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`EPIX_WALLET_DIST` must contain `manifest.json`. Gradle tracks the directory's
contents, assigns local builds a content-based version to refresh Gecko's script
cache, and restages changes; omitting the variable restores `wallet-ext.rev`.
The override is for local verification, not a release pin. Ship wallet changes
through the normal wallet release process and update `shells/wallet-ext.rev` to
that release before distributing them in a normal Android build.

Use a small phone viewport (the regression was verified at 328 CSS pixels wide):

- The animated introduction, Create, Import, and hardware-wallet actions should
  fit without scrolling. The illustration must remain animated on small screens.
- Headings, Back, Help, wrapped button labels, and phrase-verification inputs must
  fit without overlap. New-wallet safety warnings remain readable before reveal.
- Tap inputs with the actual on-screen keyboard. The focused field and final
  form actions must remain reachable as the viewport shrinks.
- Use real touch taps when testing native Back/edge gestures.
  Back dismisses the keyboard first, then returns one setup step or closes an
  open wallet modal; at the root it closes the sheet.
- Test 12/24-word recovery, multiline paste with a public test phrase, private-key
  entry, invalid input alerts, password validation, and completion. Finish must
  appear before the completion page's external links.
- With a disposable, unfunded account, check Deposit/QR, settings, history, and
  return navigation. Do not submit transactions. Remove only that test account
  afterward and restore emulator keyboard/display settings.
