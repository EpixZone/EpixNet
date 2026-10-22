# Install or build EpixNet for Android

The Android app runs the same EpixNet node as the desktop, wrapped in an app that uses GeckoView (Firefox's engine) to show `.epix` sites. Tor and I2P are built in.

## Install the APK

Download `epix-android-<version>.apk` from the [latest stable release](https://github.com/EpixZone/EpixNet/releases/latest), open it on your phone, and allow installation from that source when Android asks. The official APK requires Android 8 or later on a 64-bit ARM device. The `.aab` asset is for app stores, not direct installation.

Install newer official APKs over the existing app to keep its data. Official GitHub releases use the same `zone.epix.app` package and signing key. Locally built debug APKs use a different key and cannot replace an official release in place.

## Updates with Obtainium

[Obtainium](https://obtainium.imranr.dev/) can track EpixNet's GitHub releases and install APK updates:

1. Install Obtainium, then [add EpixNet to Obtainium](https://apps.obtainium.imranr.dev/redirect?r=obtainium://app/%7B%22id%22%3A%22zone.epix.app%22%2C%22url%22%3A%22https%3A%2F%2Fgithub.com%2FEpixZone%2FEpixNet%22%2C%22author%22%3A%22EpixZone%22%2C%22name%22%3A%22EpixNet%22%7D). You can also choose **Add App** and enter `https://github.com/EpixZone/EpixNet` as the source URL.
2. Use the **GitHub** source and leave prereleases disabled for stable updates. The releases contain one Android APK, so the default APK selection works. If you set an APK filename filter, use `^epix-android-.*\.apk$`.
3. Install or update EpixNet through Obtainium, granting Android's install permission when prompted. Keep background update checks enabled to discover new releases.

For [background installation](https://wiki.obtainium.imranr.dev/app_tracking/#silent-installation), Obtainium requires Android 12 or later, a sufficiently recent target API, an installed version that Obtainium installed, and background updates enabled both globally and for EpixNet. Its selection must resolve to one APK. Silent updates are best effort; Android may still require an installation prompt.

## Build from source

The steps below are for developers and require Google's Android tools in addition to Rust.

### 1. Install the desktop build tools first

Follow steps 1 and 2 of the [macOS](macos.md) or [Linux](linux.md) guide (or [Windows](windows.md)) to get **Rust** and a **C compiler**. You build the Android library from your normal computer.

### 2. Install the Android tools

1. Install **Android Studio**: https://developer.android.com/studio
2. Open it once and let it download the **SDK**.
3. In Android Studio, open **SDK Manager -> SDK Tools**, check **NDK (Side by side)**, and install it.
4. Point Rust at the NDK by setting `ANDROID_NDK_HOME`, for example:
   ```sh
   export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/<version>
   ```

### 3. Add the Android build pieces to Rust

```sh
rustup target add aarch64-linux-android
cargo install cargo-ndk
```

### 4. Get the code

```sh
git clone https://github.com/EpixZone/EpixNet.git
cd EpixNet
```

### 5. Build the EpixNet core for Android

This compiles the node into a native library the app loads. Android enables
the `bittorrent` feature (the iOS build does not — see [ios.md](ios.md)), so
Android can stream open-licensed media referenced by magnet links:

```sh
cargo ndk -t arm64-v8a -o shells/android/app/src/main/jniLibs \
    build -p epix-ffi --release --features bittorrent
```

The default features add `mesh` and `local-discovery` — the transports that
work with no internet at all (a Reticulum mesh, or peer discovery over LAN
broadcast). Both ship disabled: the `mesh` and `local_discovery` config keys
default to off, and with them off the node spawns no task and binds no socket
for either. Turning LAN discovery on also makes the shell hold a
`WifiManager.MulticastLock`; without it Android filters the broadcast replies
and the node finds nobody.

Then generate the Kotlin code that talks to it:

```sh
cargo run -p epix-ffi --features cli --bin uniffi-bindgen -- generate \
    --library target/aarch64-linux-android/release/libepix_ffi.so \
    --language kotlin --out-dir shells/android/app/src/main/java
```

### 6. Build and install the app

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
