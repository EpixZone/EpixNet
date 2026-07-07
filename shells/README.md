# Epix shells (Phase 8)

The product shells that wrap the shared Rust core. All three consume the same
engine through one of two entry points:

- **`epix-node`** (`crates/epix-node`) - the embeddable node: resolve a `.epix`
  name, clone + verify the xite, serve the UI + peer network, run the background
  loops, and (default on) in-process Tor. The standalone `epix-server` binary
  and the desktop shell call this directly.
- **`epix-ffi`** (`crates/epix-ffi`) - a UniFFI wrapper over `epix-node` for the
  mobile shells. `EpixNode.start(config)` boots the node on its own runtime;
  `ui_url` / `state` / `onion_address` / `tor_status` / `resolve` drive the UI.

One engine, one code path. A change to resolution, verification, or Tor is made
once in the core and every shell gets it.

## Running the desktop browser locally

```
scripts/run-browser.sh              # opens dashboard.epix
scripts/run-browser.sh talk.epix    # a specific xite
```

Use the script rather than a bare `cargo run -p epix-browser`: cargo won't
build the native-messaging host (`epix-nmh`) as a side effect, and the browser
extension needs it for the **Tor status icon** and name resolution. If
`epix-nmh` is missing or stale the Tor icon shows "Off" even when Tor is up. The
script builds both, then runs. (The packaged app already bundles both.)

## What is verified in this repo

- `epix-node`, `epix-ffi`, `epix-tor` all compile and their unit tests pass on
  the host (macOS/Linux).
- The Kotlin and Swift bindings **generate** from the built `epix-ffi` library
  (`uniffi-bindgen generate --library …`), with the full `EpixNode` surface.
- In-process Tor bootstraps a real client and completes an onion circuit
  (`cargo test -p epix-tor -- --ignored`).

## What needs a platform toolchain (not built in CI here)

The shell projects below are complete source + config, but building them needs
tools not present in this environment. They are scaffolds: the load-bearing
integration points (core embedding, node boot, web view wiring, `epix://`
registration) are in place; the browser-policy layer (per-engine CSP/clearnet
enforcement, secure-context handling) is the remaining work, tracked in
`../Epix/PLAN.md` (Workstream B/C + Phase 8b spikes).

### Desktop - real Firefox (`crates/epix-browser`)

The desktop browser is **real Firefox**, not a WebView, so you get genuine
extension support. `epix-browser` is a launcher that bundles the node with
Firefox: it boots the embedded node, writes a managed Firefox profile whose
proxy PAC routes every `*.epix` host to the node (clearnet stays DIRECT), and
launches Firefox at the xite. The node serves `*.epix` hosts in
transparent-proxy mode (`Host: dashboard.epix` -> that xite, host-relative
wrapper URLs), so the address bar reads `dashboard.epix`.

```
cargo run -p epix-browser            # opens dashboard.epix
cargo run -p epix-browser talk.epix  # opens a specific xite
```

Needs Firefox installed (or `EPIX_FIREFOX=/path/to/firefox`). Verified end to
end on macOS: Firefox loads `dashboard.epix` through the node's proxy.

What works now (all verified on macOS):
- **Secure origins**: the node serves `.epix` over real https via a per-install
  local CA (`crates/epix-browser/src/ca.rs` + `proxy.rs`); xites are secure
  contexts, no warning.
- **Clearnet-block extension + native host**: a bundled WebExtension
  (`shells/browser-ext`) blocks `.epix` pages from reaching clearnet (per-site
  toggle), with a Rust native-messaging host (`crates/epix-nmh`) for resolution
  and settings.
- **On-demand resolve+clone**: type any `talk.epix` and the node resolves it
  on-chain and clones it live.

**Packaging (self-contained install).** The shipping app bundles Firefox, so
the user does not need Firefox installed:

```
packaging/macos/build-app.sh          # -> dist/Epix.app (bundles Firefox)
```

`Epix.app` contains the launcher, the native host, and a full Firefox under
`Contents/Resources/firefox/`; the launcher prefers that bundled Firefox over
any system one. It registers the `epix://` scheme. The script ad-hoc signs for
local use; a release build uses Firefox ESR + a Developer ID signature +
notarization (see the notes in the script). Remaining: the ESR-based signed +
notarized release build, and Windows/Linux installers.

### Android (`android/`) - Kotlin + GeckoView

Verified end to end on an arm64 emulator (Android 16 / API 37): the node boots
in-process, Tor bootstraps, the dashboard clones from the network and renders,
and `epix://` deep links clone + open xites. Run from the repo root:

```
export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/<version>

# 1. Build the core per ABI into jniLibs (needs the NDK + `cargo install cargo-ndk`
#    and `rustup target add aarch64-linux-android`). Add `-t armeabi-v7a` for
#    32-bit devices. Default features: Tor on, and the embedded I2P router on by
#    default too (it's a no-transit leaf, so ~Tor-client footprint; switch it
#    off in Config). The embedded router cross-compiles here because our
#    emissary fork's reseeder uses rustls, not OpenSSL - see crates/epix-i2p.
cargo ndk -t arm64-v8a -o shells/android/app/src/main/jniLibs \
    build -p epix-ffi --release

# 2. Generate the Kotlin bindings from the built library:
cargo run -p epix-ffi --features cli --bin uniffi-bindgen -- generate \
    --library target/aarch64-linux-android/release/libepix_ffi.so \
    --language kotlin --out-dir shells/android/app/src/main/java

# 3. Build the APK (Android Studio, or the Gradle wrapper directly). The JDK is
#    the one bundled with Android Studio; local.properties points at the SDK.
cd shells/android
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" \
    ./gradlew assembleDebug

# 4. Install + launch on a running emulator/device:
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n zone.epix.app/.MainActivity
```

Step 1 rebuilds the `.so`; rerun step 2 after any core change that alters the
FFI surface. Both outputs (`app/src/main/jniLibs`, `app/src/main/java/uniffi`)
are gitignored - they are build artifacts.

`MainActivity` loads the core (`System.loadLibrary("epix_ffi")`), boots the node
on a coroutine, and points GeckoView at the local node URL. The `epix://`
intent-filter is in `AndroidManifest.xml`. Interception the Tor-Browser-Android
way (a bundled built-in WebExtension via `installBuiltIn` + `webRequest`) is the
next step - GeckoView has no `shouldInterceptRequest`.

The shell looks like a browser: an address bar (type `talk.epix`, an `epix1…`
address, a bare word for `<word>.epix`, or any URL) and, Brave-style, the Epix
icon next to it. The bar shows `talk.epix/…`, not the local node plumbing. The
icon wears the Tor state as a badge with the desktop extension's colors (gray
off, amber connecting, purple ready, green when clearnet is routed through
Tor); tapping it opens the Epix panel - current xite, Tor status, our onion
address, and the "Route clearnet through Tor" switch. It polls `torStatus()` /
`onionAddress()` on the FFI every 5 seconds, like the extension polls the
native host. Hardware back navigates page history. The iOS shell has the same
chrome.

The "Route clearnet through Tor" switch (default on, opt-out, like the desktop
extension) points the web engine's proxy at the node's Tor SOCKS listener
(127.0.0.1:43111, the same one the desktop launcher's PAC uses). The node's own
loopback is excluded, so the UI and every `.epix` page (served from 127.0.0.1)
load directly while clearnet requests exit through Tor. Android sets GeckoView's
`network.proxy.*` prefs live; iOS 17+ sets `WKWebsiteDataStore.proxyConfigurations`.
Both apply immediately, no relaunch (the desktop version applies on relaunch).

### iOS (`ios/`) - Swift + WKWebView

```
# 1. Build the core as a staticlib for the device/simulator. Add `i2p-embedded`
#    to bundle the I2P router (on by default, like desktop/Android); it needs no
#    native deps beyond what the Tor build already links (rustls reuses ring),
#    so it builds wherever this does.
cargo build -p epix-ffi --release --no-default-features --features tor,i2p-embedded \
    --target aarch64-apple-ios
# 2. Generate the Swift bindings:
cargo run -p epix-ffi --features cli --bin uniffi-bindgen -- generate \
    --library target/aarch64-apple-ios/release/libepix_ffi.a \
    --language swift --out-dir ios/EpixBrowser/Generated
# 3. Open the Xcode project, link libepix_ffi.a + the generated module, and add
#    ios/EpixBrowser/epix-icon.png as a bundle resource (the Epix button's
#    logo; the app falls back to a system glyph without it). Run.
```

`AppDelegate` boots the node and loads the local URL in a WKWebView. `epix://`
is registered via `CFBundleURLTypes` in `Info.plist`.

**Open spike (Phase 8b #1):** custom-scheme pages in WKWebView are not secure
contexts. This scaffold loads the loopback origin directly (sidesteps the custom
scheme, exposes the port). The three escapes - the `com.apple.developer.web-browser`
entitlement, iOS 17 `proxyConfigurations`, or accepting degraded xites - are in
PLAN.md.
