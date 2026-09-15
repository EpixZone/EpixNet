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
