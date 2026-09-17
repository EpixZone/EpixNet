#!/usr/bin/env bash
# Build the pinned source with Android's 16 KB load AND RELRO alignment.
# The v0.2.0 prebuilt .so uses 4 KB pages and cannot be shipped to 16 KB devices.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed Android NDK}"
source_dir=${1:?Usage: build-android-snowflake.sh /path/to/pinned/epix-iptproxy}
expected=$(cat "$repo/crates/iptproxy-sys/iptproxy-android.rev")
actual=$(git -C "$source_dir" rev-parse HEAD)
if [[ "$actual" != "$expected" ]] || [[ -n $(git -C "$source_dir" status --porcelain --untracked-files=no) ]]; then
    echo "error: Snowflake source must be a clean checkout of $expected" >&2
    exit 1
fi
case $(uname -s) in
    Darwin) ndk_host=darwin-x86_64 ;;
    Linux) ndk_host=linux-x86_64 ;;
    *) echo "error: unsupported NDK host" >&2; exit 1 ;;
esac
destination="$repo/shells/android/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$destination"
cd "$source_dir"
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$ndk_host/bin/aarch64-linux-android26-clang" \
    go build -mod=readonly -trimpath -buildmode=c-shared \
    -ldflags='-checklinkname=0 -linkmode=external -extldflags=-Wl,-z,max-page-size=16384,-z,common-page-size=16384' \
    -o "$destination/libepix_snowflake.so" .
python3 "$repo/scripts/check-android-native.py" "$destination/libepix_snowflake.so"
