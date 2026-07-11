#!/usr/bin/env bash
# Assemble a self-contained Epix tree for Linux: the launcher + native host + a
# bundled Firefox + a .desktop file that registers the epix:// scheme. Produces
# a tarball. (Untested in CI here - Linux scaffold; the Rust cores are the same
# ones built and tested on the host.)
#
# Build deps: protobuf-compiler libudev-dev pkg-config, plus GTK/AppIndicator
# for the system tray: libgtk-3-dev libayatana-appindicator3-dev libxdo-dev.
# Runtime: GTK3 (on every desktop); the AppIndicator lib is dlopened, so if it
# is missing the launcher just runs without a tray instead of failing to start.
#
# Usage: packaging/linux/build-linux.sh [output-dir]
#   EPIX_BUNDLE_FIREFOX=/path/to/firefox   dir containing the firefox binary
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"
STAGE="$OUT_DIR/epix-linux"
VERSION="${EPIX_VERSION:-0.1.0}"

( cd "$REPO_ROOT" && cargo build --release -p epix-browser -p epix-nmh )

rm -rf "$STAGE"; mkdir -p "$STAGE/firefox"
cp "$REPO_ROOT/target/release/epix-browser" "$STAGE/epix-browser"
cp "$REPO_ROOT/target/release/epix-nmh" "$STAGE/epix-nmh"

# Bundle Firefox ESR (fetch-firefox-esr.sh linux) or a provided dir.
FF="${EPIX_BUNDLE_FIREFOX:-$REPO_ROOT/packaging/firefox-esr/firefox}"
if [ -d "$FF" ]; then
  cp -R "$FF/." "$STAGE/firefox/"
else
  echo "warning: no Firefox to bundle (run packaging/fetch-firefox-esr.sh linux)"
fi

# Firefox enterprise policies: trust the launcher's local CA so https://*.epix
# is a secure context on machines without NSS certutil (the launcher writes
# the CA itself to ~/.mozilla/certificates/epix-ca.pem at each run), and
# default urlbar search to DuckDuckGo (ESR-only policy; the bundle is ESR).
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
cat > "$STAGE/epix.desktop" <<DESKTOP
[Desktop Entry]
Name=EpixNet
Exec=$STAGE/epix-browser %u
Icon=epix
Type=Application
Terminal=false
Categories=Network;WebBrowser;
MimeType=x-scheme-handler/epix;
StartupWMClass=EpixNet
DESKTOP

cat > "$STAGE/install.sh" <<'INSTALL'
#!/usr/bin/env bash
# Register Epix with the desktop: the launcher (bundled Firefox next to it) and
# the epix:// handler. The native-messaging host manifest is written by the
# launcher at first run (~/.mozilla/native-messaging-hosts).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HOME/.local/share/applications"
sed "s|Exec=.*epix-browser|Exec=$HERE/epix-browser|" "$HERE/epix.desktop" \
  > "$HOME/.local/share/applications/epix.desktop"
# Hicolor icons (Icon=epix in the .desktop resolves through this theme dir).
for d in "$HERE"/icons/hicolor/*/apps; do
  size="$(basename "$(dirname "$d")")"
  mkdir -p "$HOME/.local/share/icons/hicolor/$size/apps"
  cp "$d/epix.png" "$HOME/.local/share/icons/hicolor/$size/apps/epix.png"
done
gtk-update-icon-cache "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
xdg-mime default epix.desktop x-scheme-handler/epix 2>/dev/null || true
echo "Epix installed. Run: $HERE/epix-browser"
INSTALL
chmod +x "$STAGE/install.sh"

TARBALL="$OUT_DIR/epix-linux-$VERSION.tar.gz"
tar -C "$OUT_DIR" -czf "$TARBALL" "$(basename "$STAGE")"
echo "· done: $TARBALL"
echo "  install: tar xzf epix-linux-$VERSION.tar.gz && ./epix-linux/install.sh"
