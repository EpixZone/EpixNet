#!/usr/bin/env bash
# Download Firefox ESR for bundling into the release app. The shipping bundle
# uses ESR (a stable ~yearly cadence we can security-patch on our schedule, and
# it honors the unsigned-extension pref the bundled Epix Wallet needs).
#
# Usage: packaging/fetch-firefox-esr.sh [os]   (os: osx | linux | win64)
# On Linux, add --if-needed to reuse the same completed download.
# EPIX_FF_VERSION overrides the pinned release (include the esr suffix).
# Writes into packaging/firefox-esr/. build-app.sh picks it up automatically.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Pin the release: firefox-esr-latest can still select the previous ESR series
# during Mozilla's overlap period, leaving new bundles on the retiring branch.
VERSION="${EPIX_FF_VERSION:-153.4.0esr}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?esr$ ]]; then
  echo "invalid EPIX_FF_VERSION '$VERSION' (expected a release such as 153.4.0esr)" >&2
  exit 1
fi
OS="${1:-osx}"
if (( $# > 1 )) && [[ "$OS" != linux || $# != 2 || "$2" != --if-needed ]]; then
  echo "usage: $0 [osx | linux [--if-needed] | win64]" >&2
  exit 1
fi
MOZILLA_OS="$OS"
# Mozilla's `linux` product is i686, even on a 64-bit host. Never bundle it
# with our 64-bit Rust executables (the old Linux release did exactly that).
if [ "$OS" = linux ]; then
  case "${EPIX_ARCH:-$(uname -m)}" in
    x86_64|amd64) MOZILLA_OS=linux64 ;;
    aarch64|arm64) MOZILLA_OS=linux64-aarch64 ;;
    *) echo "unsupported Linux architecture: ${EPIX_ARCH:-$(uname -m)}" >&2; exit 1 ;;
  esac
fi
LANG_="${EPIX_FF_LANG:-en-US}"
OUT="$REPO_ROOT/packaging/firefox-esr"
mkdir -p "$OUT"

URL="https://download.mozilla.org/?product=firefox-${VERSION}-ssl&os=${MOZILLA_OS}&lang=${LANG_}"
if [[ "$OS" == linux ]]; then
  # Serialize the cache check and installation, including unconditional downloads.
  exec 9>"$OUT/.linux-download.lock"
  flock 9
  STAMP="$OUT/.linux-source-url"
  if [[ ${2:-} == --if-needed && -f "$STAMP" && "$(<"$STAMP")" == "$URL" &&
        -f "$OUT/firefox/firefox" && -x "$OUT/firefox/firefox" && -f "$OUT/firefox/libxul.so" ]]; then
    echo "· reusing Firefox $VERSION ($OS, $LANG_)"
    exit 0
  fi
fi
echo "· downloading Firefox $VERSION ($OS, $LANG_)"

case "$OS" in
  osx)
    DMG="$OUT/firefox-esr.dmg"
    curl --fail --location --retry 3 -o "$DMG" "$URL"
    MP="$(mktemp -d)"
    hdiutil attach "$DMG" -nobrowse -mountpoint "$MP" >/dev/null
    rm -rf "$OUT/Firefox.app"
    cp -R "$MP/Firefox.app" "$OUT/Firefox.app"
    hdiutil detach "$MP" >/dev/null
    rm -f "$DMG"
    echo "· ready: $OUT/Firefox.app"
    echo "  build with: EPIX_BUNDLE_FIREFOX=\"$OUT/Firefox.app\" packaging/macos/build-app.sh"
    ;;
  linux)
    # Extract into an empty tree so a new ESR cannot retain obsolete files.
    TMP="$(mktemp -d "$OUT/.firefox-XXXXXX")"
    cleanup_linux() {
      if [[ -d "$TMP/previous" && ! -e "$OUT/firefox" ]]; then
        mv "$TMP/previous" "$OUT/firefox"
      fi
      rm -rf "$TMP"
    }
    trap cleanup_linux EXIT
    curl --fail --location --retry 3 -o "$TMP/archive.tar.xz" "$URL"
    tar -C "$TMP" -xf "$TMP/archive.tar.xz"
    test -f "$TMP/firefox/firefox"
    test -x "$TMP/firefox/firefox"
    test -f "$TMP/firefox/libxul.so"
    printf '%s\n' "$URL" > "$TMP/source-url"
    # An interrupted replacement must never leave the old URL on a new tree.
    rm -f "$STAMP"
    if [[ -e "$OUT/firefox" ]]; then mv "$OUT/firefox" "$TMP/previous"; fi
    mv "$TMP/firefox" "$OUT/firefox"
    mv "$TMP/source-url" "$STAMP"
    echo "· ready: $OUT/firefox/ (Linux)"
    ;;
  win64)
    curl --fail --location --retry 3 -o "$OUT/firefox-esr.exe" "$URL"
    # The ESR installer is a 7z self-extractor; the browser lives under core/.
    if command -v 7z >/dev/null 2>&1; then
      rm -rf "$OUT/extract" "$OUT/firefox"
      7z x -y "$OUT/firefox-esr.exe" -o"$OUT/extract" >/dev/null
      mkdir -p "$OUT/firefox"
      cp -R "$OUT/extract/core/." "$OUT/firefox/"
      rm -rf "$OUT/extract" "$OUT/firefox-esr.exe"
      echo "· ready: $OUT/firefox/ (Windows)"
    else
      echo "· downloaded $OUT/firefox-esr.exe (install 7z to auto-extract into firefox/)"
    fi
    ;;
  *)
    echo "unknown os '$OS' (use osx | linux | win64)"; exit 1
    ;;
esac
