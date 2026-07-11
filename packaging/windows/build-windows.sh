#!/usr/bin/env bash
# Assemble the Epix Windows install tree and build the NSIS installer. Runs on a
# Windows CI runner (Git Bash) or locally with makensis. Signing is done
# separately by the release workflow (Azure Trusted Signing): our exes are
# signed between the stage and pack phases (so the copies *inside* the
# installer are signed), then the installer itself.
#
# Usage: packaging/windows/build-windows.sh [output-dir]
#   EPIX_BUNDLE_FIREFOX=/path/to/firefox   dir containing firefox.exe
#   EPIX_VERSION=x.y.z                     release version (from the tag)
#   EPIX_SKIP_BUILD=1                      reuse target/ instead of cargo build
#   EPIX_PHASE=stage|pack|all              stage = build + assemble the tree,
#                                          pack = makensis on an existing tree
#                                          (sign the staged exes in between);
#                                          default all (local, unsigned)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"
STAGE="$OUT_DIR/epix-windows"
VERSION="${EPIX_VERSION:-0.1.0}"
PHASE="${EPIX_PHASE:-all}"
mkdir -p "$OUT_DIR"

if [ "$PHASE" != "pack" ]; then
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

  # Firefox enterprise policies: trust the launcher's local CA so https://*.epix
  # is a secure context (no NSS certutil on Windows) - the launcher writes the
  # CA itself to %LOCALAPPDATA%\Mozilla\Certificates\epix-ca.pem at each run -
  # and default urlbar search to DuckDuckGo (SearchEngines is ESR-only; the
  # bundle is ESR). Mozilla's app update stays ON (security patches); the Epix
  # window/taskbar icon is applied at runtime by the launcher (icon.rs), not by
  # patching firefox.exe, so updates never undo it.
  mkdir -p "$STAGE/firefox/distribution"
  cat > "$STAGE/firefox/distribution/policies.json" <<'POLICIES'
{
  "policies": {
    "Certificates": {
      "Install": ["epix-ca.pem"]
    },
    "SearchEngines": {
      "Default": "DuckDuckGo"
    }
  }
}
POLICIES
  echo "· staged: $STAGE"
fi

if [ "$PHASE" != "stage" ]; then
  OUT_FILE="$OUT_DIR/Epix-Setup-$VERSION.exe"
  echo "· building installer -> $OUT_FILE"
  makensis -DSTAGE_DIR="$STAGE" -DOUT_FILE="$OUT_FILE" -DVERSION="$VERSION" \
    "$REPO_ROOT/packaging/windows/installer.nsi"
  echo "· done: $OUT_FILE"
fi
