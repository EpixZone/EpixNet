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
#   EPIX_PHASE=stage|pack|portable|all     stage = build + assemble the tree,
#                                          pack = makensis + the portable zip
#                                          on an existing tree (sign the
#                                          staged exes in between),
#                                          portable = only the zip;
#                                          default all (local, unsigned)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"
STAGE="$OUT_DIR/epix-windows"
VERSION="${EPIX_VERSION:-0.1.0}"
PHASE="${EPIX_PHASE:-all}"
case "$PHASE" in
  stage|pack|portable|all) ;;
  *) echo "EPIX_PHASE must be stage, pack, portable or all" >&2; exit 2 ;;
esac
mkdir -p "$OUT_DIR"

if [ "$PHASE" = "stage" ] || [ "$PHASE" = "all" ]; then
  if [ "${EPIX_SKIP_BUILD:-0}" != "1" ]; then
    ( cd "$REPO_ROOT" && cargo build --release -p epix-browser -p epix-nmh -p evx-worker \
        --target x86_64-pc-windows-msvc )
  fi
  BINDIR="$REPO_ROOT/target/x86_64-pc-windows-msvc/release"

  rm -rf "$STAGE"; mkdir -p "$STAGE/firefox"
  cp "$BINDIR/epix-browser.exe" "$STAGE/epix-browser.exe"
  cp "$BINDIR/epix-nmh.exe" "$STAGE/epix-nmh.exe"
  # The EVX worker the node launches inside an AppContainer. It lives beside
  # the launcher, which is where the node looks for it (docs/evx-windows.md).
  cp "$BINDIR/evx-worker.exe" "$STAGE/evx-worker.exe"
  python3 "$REPO_ROOT/packaging/windows/verify-evx-worker.py" "$STAGE/evx-worker.exe"

  # In-process Snowflake bridge library (loaded at runtime beside the exe),
  # fetched by iptproxy-sys's build.rs into the target dir. Best-effort: absent
  # in a bridges-off build.
  cp "$BINDIR"/epix_snowflake-*.dll "$STAGE/" 2>/dev/null || true

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
  python3 "$REPO_ROOT/packaging/firefox-addons/install.py" "$STAGE/firefox"
  echo "· staged: $STAGE"
fi

if [ "$PHASE" = "pack" ] || [ "$PHASE" = "all" ]; then
  OUT_FILE="$OUT_DIR/Epix-Setup-$VERSION.exe"
  echo "· building installer -> $OUT_FILE"
  makensis -DSTAGE_DIR="$STAGE" -DOUT_FILE="$OUT_FILE" -DVERSION="$VERSION" \
    "$REPO_ROOT/packaging/windows/installer.nsi"
  echo "· done: $OUT_FILE"
fi

# The portable zip: the same signed tree, unpacked anywhere, no installer.
# make-portable.py adds the marker and Firefox policies for portable use.
if [ "$PHASE" != "stage" ]; then
  python3 "$REPO_ROOT/packaging/windows/make-portable.py" "$STAGE" \
    "$OUT_DIR/EpixNet-Portable-$VERSION-x64.zip"
fi
