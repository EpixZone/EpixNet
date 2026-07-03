#!/usr/bin/env bash
# Assemble Epix.app: the launcher + native host + a bundled Firefox, so the app
# is self-contained (a user installs Epix and gets everything - no separate
# Firefox install). Registers the epix:// scheme.
#
# Usage: packaging/macos/build-app.sh [output-dir]
#   EPIX_BUNDLE_FIREFOX=/path/to/Firefox.app  override which Firefox to bundle
#   EPIX_SKIP_BUILD=1                          skip cargo build (reuse target/)
#
# The shipping bundle should use Firefox ESR (stable, we patch on our cadence)
# and be signed with a Developer ID + notarized (see NOTES at the bottom). This
# script ad-hoc signs so the app runs locally for testing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"
APP="$OUT_DIR/Epix.app"
IDENTIFIER="zone.epix.browser"
VERSION="0.1.0"

echo "· building release binaries"
if [ "${EPIX_SKIP_BUILD:-0}" != "1" ]; then
  ( cd "$REPO_ROOT" && cargo build --release -p epix-browser -p epix-nmh )
fi
LAUNCHER="$REPO_ROOT/target/release/epix-browser"
NMH="$REPO_ROOT/target/release/epix-nmh"
[ -x "$LAUNCHER" ] || { echo "missing $LAUNCHER"; exit 1; }
[ -x "$NMH" ] || { echo "missing $NMH"; exit 1; }

# Pick a Firefox to bundle: explicit override, else prefer ESR > Developer >
# release (the launcher enables the extension only on ESR/Developer/Nightly).
pick_firefox() {
  if [ -n "${EPIX_BUNDLE_FIREFOX:-}" ]; then echo "$EPIX_BUNDLE_FIREFOX"; return; fi
  for p in \
    "/Applications/Firefox ESR.app" \
    "/Applications/Firefox Developer Edition.app" \
    "/Applications/Firefox Nightly.app" \
    "/Applications/Firefox.app"; do
    [ -d "$p" ] && { echo "$p"; return; }
  done
}
FIREFOX_APP="$(pick_firefox)"
[ -n "$FIREFOX_APP" ] && [ -d "$FIREFOX_APP" ] || {
  echo "no Firefox found to bundle; install one or set EPIX_BUNDLE_FIREFOX"; exit 1; }
echo "· bundling Firefox: $FIREFOX_APP"

echo "· assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/firefox"
cp "$LAUNCHER" "$APP/Contents/MacOS/epix-browser"
cp "$NMH" "$APP/Contents/MacOS/epix-nmh"
# Copy the whole Firefox.app under Resources/firefox, keeping its name so the
# launcher's edition detection (ESR/Developer) still works.
cp -R "$FIREFOX_APP" "$APP/Contents/Resources/firefox/"

# Icon: generate an .icns from a rendered PNG.
"$REPO_ROOT/packaging/macos/make-icon.sh" "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Epix</string>
  <key>CFBundleDisplayName</key><string>Epix</string>
  <key>CFBundleIdentifier</key><string>$IDENTIFIER</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>epix-browser</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>CFBundleURLTypes</key>
  <array>
    <dict>
      <key>CFBundleURLName</key><string>$IDENTIFIER</string>
      <key>CFBundleURLSchemes</key><array><string>epix</string></array>
    </dict>
  </array>
</dict>
</plist>
PLIST

# Ad-hoc sign so the app + nested Firefox run locally. (Release: Developer ID.)
echo "· ad-hoc codesigning"
codesign --force --deep --sign - "$APP" 2>/dev/null || \
  echo "  (codesign warned; the app still runs locally)"

# Register with LaunchServices so epix:// links open the app.
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
  -f "$APP" 2>/dev/null || true

echo "· done: $APP"
echo "  run:      open \"$APP\""
echo "  epix://:  open epix://dashboard.epix"
