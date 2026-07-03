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

### Desktop (`desktop/`) - Tauri v2

A native window over the embedded node, with a tray, `epix://` deep links, and
single-instance handoff (a clicked link routes to the running window).

```
cargo install tauri-cli --version '^2'
cd shells/desktop
cargo tauri dev      # or: cargo tauri build
```

The window opens on a loading page, the node boots on a background thread, and
the window is navigated to `http://127.0.0.1:43110/<xite>/` once serving.
`epix://` is registered via `tauri.conf.json` (macOS bundle) and at runtime
(Windows/Linux).

### Android (`android/`) - Kotlin + GeckoView

```
# 1. Build the core for each Android ABI (needs the NDK + cargo-ndk):
cargo ndk -t arm64-v8a -t armeabi-v7a -o app/src/main/jniLibs \
    build -p epix-ffi --release --no-default-features --features tor
# 2. Generate the Kotlin bindings:
cargo run -p epix-ffi --features cli --bin uniffi-bindgen -- generate \
    --library target/aarch64-linux-android/release/libepix_ffi.so \
    --language kotlin --out-dir app/src/main/java
# 3. Open shells/android in Android Studio and run.
```

`MainActivity` loads the core (`System.loadLibrary("epix_ffi")`), boots the node
on a coroutine, and points GeckoView at the local node URL. The `epix://`
intent-filter is in `AndroidManifest.xml`. Interception the Tor-Browser-Android
way (a bundled built-in WebExtension via `installBuiltIn` + `webRequest`) is the
next step - GeckoView has no `shouldInterceptRequest`.

### iOS (`ios/`) - Swift + WKWebView

```
# 1. Build the core as a staticlib for the device/simulator:
cargo build -p epix-ffi --release --no-default-features --features tor \
    --target aarch64-apple-ios
# 2. Generate the Swift bindings:
cargo run -p epix-ffi --features cli --bin uniffi-bindgen -- generate \
    --library target/aarch64-apple-ios/release/libepix_ffi.a \
    --language swift --out-dir ios/EpixBrowser/Generated
# 3. Open the Xcode project, link libepix_ffi.a + the generated module, run.
```

`AppDelegate` boots the node and loads the local URL in a WKWebView. `epix://`
is registered via `CFBundleURLTypes` in `Info.plist`.

**Open spike (Phase 8b #1):** custom-scheme pages in WKWebView are not secure
contexts. This scaffold loads the loopback origin directly (sidesteps the custom
scheme, exposes the port). The three escapes - the `com.apple.developer.web-browser`
entitlement, iOS 17 `proxyConfigurations`, or accepting degraded xites - are in
PLAN.md.
