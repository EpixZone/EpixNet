# Build EpixNet for iOS

Building the iOS app is more involved than the desktop version, and it can only be done on a **Mac** with **Xcode**. This guide is aimed at people comfortable with Xcode. If you just want to try EpixNet, the [desktop guides](../../README.md#get-started) are much easier.

The iOS app runs the same EpixNet node as the desktop, wrapped in an app that shows `.epix` sites in a web view. Tor and I2P are built in.

## 1. Install Xcode

Install **Xcode** from the Mac App Store, open it once, and let it finish setting up. This also gives you the iOS build tools.

## 2. Install the desktop build tools

Follow steps 1 and 2 of the [macOS guide](macos.md) to get **Rust** and the Apple command line tools.

## 3. Add the iOS build target to Rust

```sh
rustup target add aarch64-apple-ios
```

## 4. Get the code

```sh
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet
```

## 5. Build the EpixNet core for iOS

This compiles the node into a static library the app links against:

```sh
cargo build -p epix-ffi --release --no-default-features --features tor,i2p-embedded \
    --target aarch64-apple-ios
```

Then generate the Swift code that talks to it:

```sh
cargo run -p epix-ffi --features cli --bin uniffi-bindgen -- generate \
    --library target/aarch64-apple-ios/release/libepix_ffi.a \
    --language swift --out-dir ios/EpixBrowser/Generated
```

## 6. Build the app

Open the Xcode project in `ios/`, link `libepix_ffi.a` and the generated Swift module, then build and run on a simulator or a device.

## Notes

- Tor is on by default. The embedded I2P router is also available and builds with no extra system libraries (it shares the same crypto as Tor).
- Full contributor notes for the shell live in [`shells/README.md`](../../shells/README.md).
