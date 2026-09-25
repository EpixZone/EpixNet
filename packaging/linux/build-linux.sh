#!/usr/bin/env bash
# Assemble a self-contained Epix tree for Linux: the launcher + native host + a
# bundled Firefox + a .desktop file that registers the epix:// scheme, plus the
# standalone epix-server for running a headless node on a server (no Firefox,
# no desktop). Produces a tarball, .deb, RPM and AppImage.
#
# Build deps: protobuf-compiler libudev-dev pkg-config, plus GTK/AppIndicator
# for the system tray: libgtk-3-dev libayatana-appindicator3-dev libxdo-dev.
# Runtime: GTK3 (on every desktop); the AppIndicator lib is dlopened, so if it
# is missing the launcher just runs without a tray instead of failing to start.
#
# Usage: packaging/linux/build-linux.sh [output-dir]
#   EPIX_BUNDLE_FIREFOX=/path/to/firefox   dir containing the firefox binary
#   EPIX_FORMATS=tar,deb,rpm,appimage      choose output formats
#   EPIX_SKIP_BUILD=1                     package existing release binaries
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
STAGE="$OUT_DIR/epix-linux"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then TARGET_DIR="$REPO_ROOT/$TARGET_DIR"; fi
VERSION="${EPIX_VERSION:-$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null || echo 0.1.0)}"
VERSION="${VERSION#v}"
export EPIX_VERSION="$VERSION"

# Check the bundle before an expensive Rust build. Mozilla's `linux` product
# used to silently put i686 Firefox alongside the x86_64 launcher.
FF="${EPIX_BUNDLE_FIREFOX:-$REPO_ROOT/packaging/firefox-esr/firefox}"
python3 "$REPO_ROOT/packaging/linux/package-linux.py" --check-firefox "$FF"

if [ "${EPIX_SKIP_BUILD:-0}" != 1 ]; then
  ( cd "$REPO_ROOT" && cargo build --release --locked -p epix-browser -p epix-nmh -p epix-server )
fi

rm -rf "$STAGE"; mkdir -p "$STAGE/firefox"
cp "$TARGET_DIR/release/epix-browser" "$STAGE/epix-browser"
cp "$TARGET_DIR/release/epix-nmh" "$STAGE/epix-nmh"
# The standalone node for headless servers: no Firefox, no GTK, honors
# EPIX_HEADLESS / EPIX_UI_ADDR. See docs/install/linux.md.
cp "$TARGET_DIR/release/epix-server" "$STAGE/epix-server"

# Bundle Firefox ESR (fetch-firefox-esr.sh linux) or a provided dir.
cp -a "$FF/." "$STAGE/firefox/"
"${CC:-cc}" -shared -fPIC -O2 -Wall -Wextra -Werror \
  "$REPO_ROOT/packaging/linux/sandbox-probe.c" \
  -o "$STAGE/firefox/libepix-sandbox-probe.so"
cp "$REPO_ROOT/LICENSE" "$STAGE/LICENSE"

# Firefox enterprise policies: trust the launcher's local CA so https://*.epix
# is a secure context on machines without NSS certutil (the launcher writes
# the CA itself to ~/.mozilla/certificates/epix-ca.pem at each run), and
# default urlbar search to DuckDuckGo (ESR-only policy; the bundle is ESR).
mkdir -p "$STAGE/firefox/distribution"
cat > "$STAGE/firefox/distribution/policies.json" <<'POLICIES'
{
  "policies": {
    "DisableAppUpdate": true,
    "Certificates": {
      "Install": ["epix-ca.pem"]
    },
    "SearchEngines": {
      "Default": "DuckDuckGo"
    }
  }
}
POLICIES

# Hicolor icons for the .desktop entry, prebuilt from the assets repo
# (images/icons/generated/linux) and checked in under packaging/linux/icons.
for s in 48 64 128 256 512; do
  mkdir -p "$STAGE/icons/hicolor/${s}x${s}/apps"
  cp "$REPO_ROOT/packaging/linux/icons/epix-$s.png" \
    "$STAGE/icons/hicolor/${s}x${s}/apps/epix.png"
done

# .desktop entry registering epix:// (installed to ~/.local/share/applications).
# StartupWMClass matches the --class/--name the launcher passes to Firefox, so
# the shell shows the Epix icon (not Firefox's) for the browser window.
cp "$REPO_ROOT/packaging/linux/epix.desktop" "$STAGE/epix.desktop"

cat > "$STAGE/install.sh" <<'INSTALL'
#!/usr/bin/env bash
# Register Epix with the desktop: the launcher (bundled Firefox next to it) and
# the epix:// handler. The native-messaging host manifest is written by the
# launcher at first run (~/.mozilla/native-messaging-hosts).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
mkdir -p "$DATA/applications"
# Desktop Exec is not shell syntax. Quote the path and escape reserved bytes
# (including field-code percent signs) without interpolating it into sed.
launcher="$HERE/epix-browser"
launcher="${launcher//\\/\\\\\\\\}"
launcher="${launcher//\"/\\\\\"}"
launcher="${launcher//\$/\\\\\$}"
launcher="${launcher//\`/\\\\\`}"
launcher="${launcher//%/%%}"
while IFS= read -r line; do
  if [[ "$line" == Exec=* ]]; then
    # A fixed executable lets GIO validate the entry even when the bundle's
    # pathname contains a literal percent (expanded later as a field code).
    printf 'Exec=/usr/bin/env "%s" %%u\n' "$launcher"
  else
    printf '%s\n' "$line"
  fi
done < "$HERE/epix.desktop" > "$DATA/applications/epix.desktop"
# Hicolor icons (Icon=epix in the .desktop resolves through this theme dir).
for d in "$HERE"/icons/hicolor/*/apps; do
  size="$(basename "$(dirname "$d")")"
  mkdir -p "$DATA/icons/hicolor/$size/apps"
  cp "$d/epix.png" "$DATA/icons/hicolor/$size/apps/epix.png"
done
gtk-update-icon-cache "$DATA/icons/hicolor" 2>/dev/null || true
update-desktop-database "$DATA/applications" 2>/dev/null || true
xdg-mime default epix.desktop x-scheme-handler/epix 2>/dev/null || true
echo "Epix installed. Run: $HERE/epix-browser"
INSTALL
chmod +x "$STAGE/install.sh"

python3 "$REPO_ROOT/packaging/linux/package-linux.py" \
  --stage "$STAGE" --output "$OUT_DIR" --version "$VERSION" \
  --formats "${EPIX_FORMATS:-tar,deb,rpm,appimage}"
