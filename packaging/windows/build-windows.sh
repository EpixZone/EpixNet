#!/usr/bin/env bash
# Assemble the Epix Windows install tree and build the NSIS installer. Runs on a
# Windows CI runner (Git Bash) or locally with makensis. Signing is done
# separately by the release workflow (Azure Trusted Signing) on the produced
# installer + exes.
#
# Usage: packaging/windows/build-windows.sh [output-dir]
#   EPIX_BUNDLE_FIREFOX=/path/to/firefox   dir containing firefox.exe
#   EPIX_VERSION=x.y.z                     release version (from the tag)
#   EPIX_SKIP_BUILD=1                      reuse target/ instead of cargo build
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"
STAGE="$OUT_DIR/epix-windows"
VERSION="${EPIX_VERSION:-0.1.0}"
mkdir -p "$OUT_DIR"

if [ "${EPIX_SKIP_BUILD:-0}" != "1" ]; then
  ( cd "$REPO_ROOT" && cargo build --release -p epix-browser -p epix-nmh \
      --target x86_64-pc-windows-msvc )
fi
BINDIR="$REPO_ROOT/target/x86_64-pc-windows-msvc/release"

rm -rf "$STAGE"; mkdir -p "$STAGE/firefox"
cp "$BINDIR/epix-browser.exe" "$STAGE/epix-browser.exe"
cp "$BINDIR/epix-nmh.exe" "$STAGE/epix-nmh.exe"

# Bundle Firefox ESR (fetch-firefox-esr.sh win64 then extract, or a provided dir).
FF="${EPIX_BUNDLE_FIREFOX:-$REPO_ROOT/packaging/firefox-esr/firefox}"
if [ -d "$FF" ]; then
  cp -R "$FF/." "$STAGE/firefox/"
else
  echo "warning: no Firefox to bundle at $FF (extract the ESR installer there)"
fi

OUT_FILE="$OUT_DIR/Epix-Setup-$VERSION.exe"
echo "· building installer -> $OUT_FILE"
makensis -DSTAGE_DIR="$STAGE" -DOUT_FILE="$OUT_FILE" -DVERSION="$VERSION" \
  "$REPO_ROOT/packaging/windows/installer.nsi"
echo "· done: $OUT_FILE"
