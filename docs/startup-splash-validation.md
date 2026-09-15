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

The splash closes after a visible top-level browser tab has painted its
one-time loopback startup page. That page acknowledges the launcher and replaces
itself with the requested xite. The acknowledgement uses an unpredictable launch
token and exact Host/Origin checks. Its fetch uses CORS mode with no referrer:
Firefox otherwise sends an opaque Origin for a same-origin-mode POST under this
referrer policy, preventing acknowledgement even though the browser opens.

The native event loop continues into the tray so closing the splash does not
stop the node. Closing and reopening the browser continues to use that node.
Quitting allows blocking runtime work a bounded two-second shutdown grace.
Failed browser handoffs stop and reap the owned browser before showing an error,
so the failed launch cannot retain the managed profile lock.

The splash has a minimize control and no close control. Escape minimizes it
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
