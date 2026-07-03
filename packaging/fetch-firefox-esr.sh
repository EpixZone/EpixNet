#!/usr/bin/env bash
# Download Firefox ESR for bundling into the release app. The shipping bundle
# uses ESR (a stable ~yearly cadence we can security-patch on our schedule, and
# it honors the unsigned-extension pref our clearnet-block extension needs).
#
# Usage: packaging/fetch-firefox-esr.sh [os]   (os: osx | linux | win64)
# Writes into packaging/firefox-esr/. build-app.sh picks it up automatically.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OS="${1:-osx}"
LANG_="${EPIX_FF_LANG:-en-US}"
OUT="$REPO_ROOT/packaging/firefox-esr"
mkdir -p "$OUT"

URL="https://download.mozilla.org/?product=firefox-esr-latest&os=${OS}&lang=${LANG_}"
echo "· downloading Firefox ESR ($OS, $LANG_)"

case "$OS" in
  osx)
    DMG="$OUT/firefox-esr.dmg"
    curl -L -o "$DMG" "$URL"
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
    curl -L -o "$OUT/firefox-esr.tar.xz" "$URL"
    tar -C "$OUT" -xf "$OUT/firefox-esr.tar.xz"
    rm -f "$OUT/firefox-esr.tar.xz"
    echo "· ready: $OUT/firefox/ (Linux)"
    ;;
  win64)
    curl -L -o "$OUT/firefox-esr.exe" "$URL"
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
