# Build EpixNet for iOS

Building the iOS app is more involved than the desktop version, and it can only be done on a **Mac** with **Xcode**. This guide is aimed at people comfortable with Xcode. There is no ready-made iOS download yet. If you just want to try EpixNet, the [desktop releases and guides](../../README.md#get-started) are much easier.

The iOS app runs the same EpixNet node as the desktop, compiled into the app through the `epix-ffi` crate, with a UIKit shell that shows `.epix` sites in a web view. Tor and I2P are built in. The contributor notes in [`ios/README.md`](../../ios/README.md) cover the same build in more depth.

## 1. Install Xcode

Install **Xcode** from the Mac App Store (Xcode 26 or newer for current App Store submissions), open it once, and let it finish setting up. Then make sure the command line tools point at Xcode, not at the standalone Command Line Tools:

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
```

## 2. Install the desktop build tools

Follow steps 1 and 2 of the [macOS guide](macos.md) to get the Apple command line tools, the protobuf compiler (`protoc`) and **Rust**.

## 3. Add the iOS build targets to Rust

One target is for real devices, the other for the simulator on an Apple silicon Mac:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

## 4. Get the code

```sh
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet
```

## 5. Stage the wallet

The app bundles the Epix Wallet from `shells/wallet-ext`, and the build checks it first: the folder must hold a wallet build that includes `mobileProvider.bundle.js` and `epix-mobile-build.json`. A Debug build accepts a local wallet build; a Release build requires the pinned wallet (`shells/wallet-ext.rev`) and real policy URLs. See [`shells/wallet-ext/README.md`](../../shells/wallet-ext/README.md) for how the pinned build is fetched and how to use a local one.

## 6. Build and run the app

Open `ios/EpixNet.xcodeproj` in Xcode, pick a simulator, and press **Run**. Or from the command line:

```sh
xcodebuild -project ios/EpixNet.xcodeproj -scheme EpixNet \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

The first build compiles the whole Rust node for iOS and takes a few minutes; afterwards only changed crates rebuild. Building for a real device needs a signing team configured in Xcode.

## How the build works

The Xcode target's first build phase runs [`ios/build-rust.sh`](../../ios/build-rust.sh). You do not run cargo yourself. The script:

1. checks the staged wallet (`scripts/check-mobile-wallet.py`, with `--release` for Release builds);
2. picks the Rust target from the platform Xcode is building for: `aarch64-apple-ios-sim` for the simulator, `aarch64-apple-ios` for a device;
3. builds `epix-ffi` as a static library, always in release mode (debug builds of the deep async code in Tor and the HTTP client overflow iOS thread stacks), with the features `tor`, `i2p-embedded`, `bridges`, `mesh` and `local-discovery`;
4. generates the Swift bindings with UniFFI into `ios/Generated/`.

The app then compiles `ios/Generated/epix_ffi.swift`, uses `ios/Generated/epix_ffiFFI.h` as its bridging header, and links `libepix_ffi.a` from `target/<target>/release/`. `ios/Generated/` is build output and is not committed.

The script also runs on its own, which is handy for checking the Rust side without Xcode:

```sh
PLATFORM_NAME=iphonesimulator ios/build-rust.sh
PLATFORM_NAME=iphoneos        ios/build-rust.sh
```

## Notes

- **Features.** The iOS build deliberately leaves out the `bittorrent` feature (the media engine and tracker discovery); do not add it there. `bridges` adds Tor Snowflake bridges for censored networks: its library is downloaded from a pinned release and checked against a recorded digest during the build, and if it is unavailable the node falls back to a direct Tor connection.
- **Offline transports.** `mesh` (a Reticulum mesh) and `local-discovery` (peer discovery over LAN broadcast) work with no internet at all. Both ship switched off: the `mesh` and `local_discovery` settings default to off, and while they are off the node starts no task and opens no socket for either. LAN discovery also needs `NSLocalNetworkUsageDescription` in `Info.plist` (already present); without it iOS drops the broadcasts without an error.
- **Ports.** The app serves its UI on `127.0.0.1:43210` and its file server on `26553`, not the desktop defaults, because the simulator shares the Mac's network and would otherwise collide with a desktop node.
- **Foreground only.** iOS suspends the app shortly after it goes to the background, so the node syncs and seeds only while the app is open.
- The embedded I2P router builds with no extra system libraries. Contributor notes for all the shells live in [`shells/README.md`](../../shells/README.md).
