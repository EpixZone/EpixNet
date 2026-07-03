#!/usr/bin/env bash
# Assemble a self-contained Epix tree for Linux: the launcher + native host + a
# bundled Firefox + a .desktop file that registers the epix:// scheme. Produces
# a tarball. (Untested in CI here - Linux scaffold; the Rust cores are the same
# ones built and tested on the host.)
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

# .desktop entry registering epix:// (installed to ~/.local/share/applications).
cat > "$STAGE/epix.desktop" <<DESKTOP
[Desktop Entry]
Name=Epix
Exec=$STAGE/epix-browser %u
Type=Application
Terminal=false
Categories=Network;WebBrowser;
MimeType=x-scheme-handler/epix;
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
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
xdg-mime default epix.desktop x-scheme-handler/epix 2>/dev/null || true
echo "Epix installed. Run: $HERE/epix-browser"
INSTALL
chmod +x "$STAGE/install.sh"

TARBALL="$OUT_DIR/epix-linux-$VERSION.tar.gz"
tar -C "$OUT_DIR" -czf "$TARBALL" "$(basename "$STAGE")"
echo "· done: $TARBALL"
echo "  install: tar xzf epix-linux-$VERSION.tar.gz && ./epix-linux/install.sh"
