# Build EpixNet for Android

Building the Android app is more involved than the desktop version, because you also need Google's Android tools. This guide is aimed at people comfortable installing developer tools. If you just want to try EpixNet, the [desktop guides](../../README.md#get-started) are much easier.

The Android app runs the same EpixNet node as the desktop, wrapped in an app that uses GeckoView (Firefox's engine) to show `.epix` sites. Tor and I2P are built in.

## 1. Install the desktop build tools first

Follow steps 1 and 2 of the [macOS](macos.md) or [Linux](linux.md) guide (or [Windows](windows.md)) to get **Rust** and a **C compiler**. You build the Android library from your normal computer.

## 2. Install the Android tools

1. Install **Android Studio**: https://developer.android.com/studio
2. Open it once and let it download the **SDK**.
3. In Android Studio, open **SDK Manager -> SDK Tools**, check **NDK (Side by side)**, and install it.
4. Point Rust at the NDK by setting `ANDROID_NDK_HOME`, for example:
   ```sh
   export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/<version>
   ```

## 3. Add the Android build pieces to Rust

```sh
rustup target add aarch64-linux-android
cargo install cargo-ndk
```

## 4. Get the code

```sh
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet
```

## 5. Build the EpixNet core for Android

This compiles the node into a native library the app loads. Android enables
the `bittorrent` feature (the iOS build does not — see [ios.md](ios.md)), so
Android can stream open-licensed media referenced by magnet links:

```sh
cargo ndk -t arm64-v8a -o shells/android/app/src/main/jniLibs \
    build -p epix-ffi --release --features bittorrent
```

Then generate the Kotlin code that talks to it:

```sh
cargo run -p epix-ffi --features cli --bin uniffi-bindgen -- generate \
    --library target/aarch64-linux-android/release/libepix_ffi.so \
    --language kotlin --out-dir shells/android/app/src/main/java
```

## 6. Build and install the app

Open `shells/android/` in Android Studio and press Run, or use the command line:

```sh
cd shells/android
echo "sdk.dir=$HOME/Library/Android/sdk" > local.properties
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Notes

- Tor is on by default. The embedded I2P router is also on by default; it is a lightweight leaf (it only carries your own traffic), so it costs about as much as Tor. You can switch it off in the app's Config screen.
- Full contributor notes for the shell live in [`shells/README.md`](../../shells/README.md).
