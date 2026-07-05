# EpixNet for iOS

The EpixNet node as a native iOS app: the whole Rust node (peer network,
DHT, Tor, chain resolver, UI server) compiles into the app via the
`epix-ffi` crate, and a SwiftUI shell points a WKWebView at the node's
local UI (`http://127.0.0.1:43210`). One process, no external server.

## Requirements

- Xcode 15 or newer, with the active developer directory pointing at
  Xcode (not the Command Line Tools):

      sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer

- Rust with the iOS targets:

      rustup target add aarch64-apple-ios aarch64-apple-ios-sim

## Build and run

Open `ios/EpixNet.xcodeproj` in Xcode, pick a simulator, press Run.

Or from the command line:

    xcodebuild -project ios/EpixNet.xcodeproj -scheme EpixNet \
      -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build

The first build compiles the whole Rust workspace for iOS (a few
minutes); afterwards only changed crates rebuild.

## How the build works

The Xcode target's first build phase runs `build-rust.sh`, which:

1. builds `epix-ffi` (staticlib) in **release** mode for the active
   platform's target triple - release is required: debug builds of the
   deep async call chains (Tor, reqwest) overflow iOS thread stacks;
2. generates the Swift bindings into `ios/Generated/` with UniFFI.

The app target then compiles `Generated/epix_ffi.swift` alongside the
shell, uses `Generated/epix_ffiFFI.h` as the bridging header, and links
`libepix_ffi.a` from `target/<triple>/release/`.

`ios/Generated/` is build output - it is gitignored, not committed.

## Ports

The app binds the UI to `127.0.0.1:43210` and the peer fileserver to
`26553` (seeded into the app's `config.json` on first launch), not the
desktop defaults. The iOS simulator shares the Mac's network namespace,
so the defaults would collide with a desktop node running on the same
machine.

## Known limitations

- Foreground-only: iOS suspends the process shortly after backgrounding,
  so the node syncs and seeds only while the app is open. Background
  refresh tasks are future work.
- Tor is off by default in the shell (`torMode: "disable"`); flip to
  `enable`/`always` in `EpixNet/App.swift` to route through Arti.
- Device (non-simulator) builds need a signing team configured in Xcode.
