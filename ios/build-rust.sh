#!/bin/bash
# Build the Rust node (epix-ffi) for the active iOS platform and generate the
# Swift bindings the app compiles against.
#
# Invoked by the EpixNet Xcode target as its first build phase (Xcode sets
# PLATFORM_NAME). Runs standalone too:
#
#   PLATFORM_NAME=iphonesimulator ios/build-rust.sh
#   PLATFORM_NAME=iphoneos        ios/build-rust.sh
set -euo pipefail

cd "$(dirname "$0")/.." # repo root

PLATFORM="${PLATFORM_NAME:-iphonesimulator}"
case "$PLATFORM" in
  iphonesimulator) TRIPLE=aarch64-apple-ios-sim ;;
  iphoneos)        TRIPLE=aarch64-apple-ios ;;
  *) echo "error: unsupported PLATFORM_NAME '$PLATFORM'" >&2; exit 1 ;;
esac

# Xcode's script environment points the C toolchain at the iOS SDK, which
# breaks the HOST builds cargo also needs (build scripts, proc-macros).
# Cargo locates the iOS SDK itself via xcrun, so scrub the injected bits.
unset SDKROOT CPATH LIBRARY_PATH

# cargo/rustup live outside Xcode's PATH.
export PATH="$HOME/.cargo/bin:$PATH"

# Keep the whole Rust link (including the cdylib crate-type) on one minimum
# OS version; rustc's default (iOS 10) is older than the C deps support.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"

rustup target add "$TRIPLE" >/dev/null 2>&1 || true

# Release: debug builds of the deep async stacks (Tor, reqwest) overflow
# thread stacks on iOS.
#
# Explicit feature list (matches epix-ffi's default, but stated so the App
# Store guarantee is legible and can't drift): the iOS binary is built WITHOUT
# the `bittorrent` feature, so it contains no BitTorrent code (App Store
# 5.2.3). Magnet-referenced media plays from HTTPS web seeds instead. Do NOT
# add `bittorrent` here - the Android build (docs/install/android.md) is where
# it belongs. CI's "Assert no BitTorrent in the iOS profile" step enforces this.
cargo build -p epix-ffi --release --target "$TRIPLE" \
  --no-default-features --features tor,i2p-embedded,bridges

# Swift bindings, generated from the metadata baked into the built library.
cargo run -q -p epix-ffi --features cli --bin uniffi-bindgen -- \
  generate --library "target/$TRIPLE/release/libepix_ffi.a" \
  --language swift --out-dir ios/Generated
