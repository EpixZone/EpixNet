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

### Wallet extension tab lifecycle

Use the pinned GeckoView build and a disposable profile. These checks require
the real extension and GeckoView controller; a view or session test double
cannot verify that the extension's pending tab ID is attached correctly.

1. Launch with no wallet. The wallet's unsolicited first-run tab must stay
   hidden. Open the wallet button and enter registration or import. Its
   `tabs.create` request must replace the small popup with the taller sheet.
2. Check logcat for `tabs.create is not supported` and session-opening
   exceptions. Neither should appear for that user-requested tab. Previously
   the app opened and navigated a different session itself, so the register
   page appeared even though Gecko rejected the extension's tab request.
3. Navigate back within the wallet, close it, and reopen it. Check the normal
   toolbar popup and extension action popups as well as full registration
   pages. There must be one visible wallet sheet and one navigation per tab.
4. With Android camera permission unset, use the QR import page's **Open
   camera** button. Check the actual permission prompt and scan a disposable
   wallet transfer. Denying permission must show the scanner error. Do not
   pregrant camera permission to make this check pass.
5. Complete registration with an unfunded test account. When the wallet
   closes its registration tab using `tabs.remove`, its sheet must close and
   normal browser input must still work.

### Wallet camera process and permission routing

The pinned GeckoView 155 build uses engine revision
`5fdfd0092780e85643e2cddc0e1b590c8b9ef860`. Its
[permission process actor](https://hg.mozilla.org/releases/mozilla-release/file/5fdfd0092780e85643e2cddc0e1b590c8b9ef860/mobile/shared/actors/GeckoViewPermissionProcessChild.sys.mjs)
handles Android device permission before device enumeration. The actor's
[registration](https://hg.mozilla.org/releases/mozilla-release/file/5fdfd0092780e85643e2cddc0e1b590c8b9ef860/mobile/shared/components/geckoview/GeckoViewStartup.sys.mjs)
does not enable it in the parent process. With extensions running in that
process, the device permission request has no observer. The
[media manager fallback](https://hg.mozilla.org/releases/mozilla-release/file/5fdfd0092780e85643e2cddc0e1b590c8b9ef860/dom/media/MediaManager.cpp#l2041)
then resolves enumeration to an empty device list, producing `NotFoundError`
without an Android camera prompt, even when the device has a working camera.

The shell sets the supported `extensionsProcessEnabled(true)` runtime builder
option before Gecko starts or loads a previously installed wallet. The runtime
is retained for the app process and uses `applicationContext`, so recreating
the Activity does not create a second Gecko runtime or retain an old Activity.
This enables the normal permission route; Android camera permission and the
wallet session's media delegate still control access.

Check on an emulator with a configured camera or a physical Android device:

1. Start with camera permission unset. Open the wallet QR import page and tap
   **Open camera**. Android must show its real camera permission dialog.
   Grant through that dialog and verify a live video preview. Do not grant
   permission using `adb`, settings, or a debugging API before this check.
2. On a separate disposable profile, deny the permission prompt. The scanner
   must show its error and must not start video capture.
3. Close the scanner, reopen it, then close the wallet sheet while scanning.
   Capture must stop when the scanner or sheet closes. A regular browser tab
   must not inherit the wallet's camera authorization.
4. Scan a fresh transfer generated by the desktop wallet, enter its transfer
   password, and complete the normal Android import flow. Compare the imported
   public address with the desktop account. Use an unfunded test wallet.
5. Recreate the Activity without killing the app process, then reopen the
   wallet. There must be no second-runtime initialization error. Also restart
   the app with the wallet already installed and repeat the camera check.

For diagnosis in a debug build, compare the wallet target's RDP `processID`
with the app PID. The wallet must use an extension child process. Logcat should
show `GeckoView:AndroidPermission` when Android permission is needed, followed
by `GeckoView:MediaPermission` for the wallet page. Device enumeration and a
rendered preview alone do not establish that QR decoding or import succeeded.
