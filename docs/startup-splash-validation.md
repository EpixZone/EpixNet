# Startup progress on desktop and mobile

Foreground desktop launches show a native window while the local node, browser
profile, and wallet extension start. Android and iOS show corresponding stages
in their startup overlays. Progress counts completed local startup stages; it
is not an estimate of remaining time or peer discovery. Network connections
continue in the background.

All three shells use the checked-in white Epix mark, a dark background, and a
1.2-second rotation. The 96-point mark has 144 points of clearance so its
corners cannot overlap the text. Mobile layouts scroll when landscape or large
text requires more room. Progress does not move backward during an attempt;
retrying a failed start resets it.

## Desktop lifecycle

On Windows, the launcher opens the requested xite directly and closes the
splash when a visible Firefox window appears in its owned process tree. This
includes Firefox's child browser process and excludes unrelated profiles.
A detection timeout keeps a still-running browser and the node alive, with the
tray available. A browser that exits during startup reports an error.

On macOS and Linux, the splash closes after a visible top-level browser tab has
painted its one-time loopback startup page. That page acknowledges the launcher
and replaces itself with the requested xite. The acknowledgement uses an unpredictable launch
token and exact Host/Origin checks. Its fetch uses CORS mode with no referrer:
Firefox otherwise sends an opaque Origin for a same-origin-mode POST under this
referrer policy, preventing acknowledgement even though the browser opens.

The native event loop continues into the tray so closing the splash does not
stop the node. Closing and reopening the browser continues to use that node.
Quitting allows blocking runtime work a bounded two-second shutdown grace.
Failed macOS/Linux browser handoffs stop and reap the owned browser before showing an error,
so the failed launch cannot retain the managed profile lock.

The Windows splash has no caption buttons and uses a thin, smoothly animated
progress bar. Its native control retains an accessible progress range. The
splash and owned browser windows display the Epix icon. Other desktop platforms
retain their native minimize control. Escape minimizes it
while starting and dismisses an error. Errors restore a minimized splash and
also appear in the launcher log. Background launches, secondary launches into an
existing node, and hosts without a display skip the splash. `EPIX_NO_SPLASH=1`
also disables it for troubleshooting.

## Automated regression commands

```sh
cargo test --workspace --locked
cargo test -p epix-browser --locked
cargo test -p epix-node boot_progress_ --locked
cargo test -p epix-ffi --lib --locked
cargo run -p epix-browser --example splash_preview -- --verify
python3 shells/ios/tests/run-startup-regressions.py
# Set KOTLINC and JAVA_HOME to a Kotlin compiler and JDK:
python3 shells/android/tests/run-startup-regressions.py
```

The preview command inspects native macOS presentation-layer geometry; it is a
no-op on other platforms. Mobile host fixtures compile production startup
methods against small doubles. These check progress, retry, navigation ownership,
and cleanup; they do not substitute for native rendering or a full app launch.

The browser suite exercises the handoff over real loopback HTTP connections,
including stale tokens, rejected origins, bounded cancellation and response
draining. With Node.js installed, it also executes the actual page script with
controlled visibility and animation frames. Isolated node/FFI tests boot an
offline node, check each stage and listener ownership, and exercise failure then
retry without contaminating the parent process's global routing state.

The `Startup UI` workflow additionally compiles the production iOS splash methods
against UIKit, runs them in an iPhone simulator, and retains screenshots and
layout results. This covers native presentation with a node-state double; it is
not a full Rust/iOS application boot.

## Validation performed for this change

- The full Rust workspace suite passed. The final browser suite passed 55 tests;
  its opt-in fresh Firefox warmup test remained ignored in that command.
- A real macOS launcher regression first confirmed that the previous executable
  showed no window during certificate warmup. The new executable showed the
  native splash in all five samples during the same pause.
- A native macOS regression reproduced the mark drifting around an incorrect
  layer anchor. After the fix, 18 live presentation frames over a full rotation
  retained the same center and stayed within the 144-point canvas.
- A real packaged-browser launch reproduced Firefox's rejected opaque Origin.
  After the fetch fix, the requested dashboard page appeared and the splash
  disappeared in 6.7 seconds. The local node remained available after browser
  close, and a secondary app launch reopened the browser successfully.
- The full Android APK, including its Rust library and release feature set,
  passed cold start and malformed-settings retry on a disposable API 36 AVD.
  The splash stayed over the initial blank page, then dismissed when the
  dashboard's discovery wrapper appeared. Restoring the settings and using the
  real error page's retry action succeeded in the same application process.
  This confirms the first page, not completion of a remote xite download.
- Android native widget checks covered portrait, landscape, 200% text, errors,
  and disabled animation. Kotlin compilation used the generated UniFFI API and
  the application's GeckoView dependency.
- iOS host checks reproduced and fixed stale failed stages advancing a retry,
  backward progress, and clipped landscape content. All 37 checks passed.
  Full Swift parsing and Swift/Kotlin binding generation also passed.
- The iOS simulator fixture passed 56 native UIKit assertions on an iPhone SE
  running iOS 26.2, across portrait and landscape. Screenshots were inspected;
  the animation, layout, progress and cleanup checks passed. This fixture
  executes production startup methods with a node-state double, not a full
  Rust/iOS application or WebKit boot.
- Windows renderer metadata was compiled against the pinned Windows API crate;
  GTK renderer metadata was compiled against the real Rust GTK APIs. Neither
  check is a Windows/Linux GUI runtime test. CI builds the Linux workspace.

Each reported regression was demonstrated before its fix. Browser fixtures used
disposable data directories, stopped their own processes, and restored the shared
Mozilla certificate and native messaging files. Android tests used a fresh AVD
and left existing emulator data unchanged. Local macOS lacked an iOS SDK; the
native iOS fixture runs on GitHub's macOS runner.

## Windows startup checks

Run on Windows with the bundled Firefox ESR installed:

```powershell
cargo test -p epix-browser --release --locked
$env:EPIX_TEST_FIREFOX = "$env:LOCALAPPDATA\Epix\firefox\firefox.exe"
cargo test -p epix-browser --release --locked native_browser_window_is_detected_without_a_page_acknowledgement -- --ignored --nocapture
cargo run -p epix-browser --release --locked --example splash_preview -- --verify
```

The browser regression uses a disposable profile and an `about:blank` tab. It
checks that the native child window is found without a page acknowledgement,
then closes only its own process tree. The timeout regression checks that a
live process survives a presentation deadline. The preview checks the native
window icon and absence of the minimize style, then exercises indeterminate,
determinate, complete, and error presentation.

The Windows native preview passed with both small and taskbar icon handles set
and `WS_MINIMIZEBOX` absent. A separate live check opened two disposable Firefox
ESR 140.16 profiles. Both browser windows were detected through their launcher
process trees, and neither profile's enumeration included the other window.
The installed Firefox also acknowledged the existing loopback page in a clean
profile. The installed application log still recorded handoff timeouts in the
managed profile, so the Windows fix removes that profile-dependent startup gate.

The browser suite passed 57 tests on Windows, with its two optional Firefox
checks skipped in that command. The native browser-window check was then run
explicitly against the installed Firefox and passed, including eventual small
and taskbar icon assignment. Icon assertions allow the browser UI thread to
finish initializing and exercise the repeated tray update. The PAC-routing
regression and the release build also passed.

The installed launcher was backed up and replaced with the release build. With
the existing managed profile, the Dashboard opened, the splash dismissed, and
the launcher logged successful window detection and tray creation. The launcher
and browser remained running beyond the previous 60-second handoff deadline.
