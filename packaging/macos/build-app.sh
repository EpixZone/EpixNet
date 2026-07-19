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
APP="$OUT_DIR/EpixNet.app"
IDENTIFIER="zone.epix.browser"
# Version comes from the tag in CI (EPIX_VERSION), else a default.
VERSION="${EPIX_VERSION:-0.1.0}"
# notarytool args, populated during signing if credentials are present.
NOTARY_ARGS=()

echo "· building release binaries"
if [ "${EPIX_SKIP_BUILD:-0}" != "1" ]; then
  ( cd "$REPO_ROOT" && cargo build --release -p epix-browser -p epix-nmh )
fi
LAUNCHER="$REPO_ROOT/target/release/epix-browser"
NMH="$REPO_ROOT/target/release/epix-nmh"
[ -x "$LAUNCHER" ] || { echo "missing $LAUNCHER"; exit 1; }
[ -x "$NMH" ] || { echo "missing $NMH"; exit 1; }

# The shipped binaries must only load system libraries. A Homebrew/MacPorts
# dylib path baked in here (e.g. liblzma from pkg-config) makes the app crash
# at launch on every Mac that doesn't have that exact library installed.
for bin in "$LAUNCHER" "$NMH"; do
  bad="$(otool -L "$bin" | tail -n +2 | awk '{print $1}' \
        | grep -v -e '^/usr/lib/' -e '^/System/' -e '^@' || true)"
  if [ -n "$bad" ]; then
    echo "error: $bin links non-system libraries that won't exist on user machines:"
    echo "$bad" | sed 's/^/  /'
    echo "hint: rebuild without EPIX_SKIP_BUILD; liblzma must be static (see epix-tor/Cargo.toml)"
    exit 1
  fi
done

# Pick a Firefox to bundle: explicit override, a fetched ESR (fetch-firefox-esr.sh),
# else prefer an installed ESR > Developer > release (the launcher enables the
# extension only on ESR/Developer/Nightly).
pick_firefox() {
  if [ -n "${EPIX_BUNDLE_FIREFOX:-}" ]; then echo "$EPIX_BUNDLE_FIREFOX"; return; fi
  if [ -d "$REPO_ROOT/packaging/firefox-esr/Firefox.app" ]; then
    echo "$REPO_ROOT/packaging/firefox-esr/Firefox.app"; return
  fi
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

# Rebrand the bundled Firefox so the Dock shows EpixNet while browsing: our
# icon over firefox.icns, and the display name. The .app folder name and the
# firefox binary stay as-is (the launcher's edition detection and Mozilla's
# internal paths depend on them). Re-signed below, so the edits don't leave a
# broken signature. Best-effort: a Firefox layout change must not fail the build.
BUNDLED_FF="$(find "$APP/Contents/Resources/firefox" -maxdepth 1 -name "*.app" | head -1)"
if [ -n "$BUNDLED_FF" ]; then
  echo "· rebranding the bundled Firefox as EpixNet"
  FF_ICNS="$BUNDLED_FF/Contents/Resources/firefox.icns"
  [ -f "$FF_ICNS" ] && cp "$APP/Contents/Resources/AppIcon.icns" "$FF_ICNS"
  /usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName EpixNet" \
    "$BUNDLED_FF/Contents/Info.plist" 2>/dev/null || true
  /usr/libexec/PlistBuddy -c "Set :CFBundleName EpixNet" \
    "$BUNDLED_FF/Contents/Info.plist" 2>/dev/null || true

  # Give the bundled Firefox its own bundle identifier. Firefox ESR ships as
  # org.mozilla.firefox - the same id a user's installed Firefox uses - so macOS
  # sees two apps claiming one identifier and, at launch, pops "Open existing
  # Firefox application?" defaulting to the user's plain Firefox. That copy has
  # none of our profile policy (the CA trust that makes https://*.epix valid),
  # extension, or prefs, so a cert error and missing customizations follow. A
  # unique id makes our copy the sole owner of its identifier, so it always
  # launches itself and the prompt never appears. (find_firefox locates it by
  # path and edition detection reads application.ini, so neither depends on this
  # id.)
  /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier zone.epix.firefox" \
    "$BUNDLED_FF/Contents/Info.plist" 2>/dev/null || true

  # Firefox enterprise policy: trust the launcher's local CA so https://*.epix
  # is a secure context on machines without NSS certutil. Must be baked in
  # here, before signing - the launcher never edits the sealed .app at runtime.
  # It writes the CA itself to ~/Library/Application Support/Mozilla/
  # Certificates/epix-ca.pem at each run.
  # SearchEngines (default DuckDuckGo) is ESR-only; the bundle is ESR.
  # DisableAppUpdate: this Firefox lives inside our code-signed .app and can't
  # rewrite itself in place (it would break both its own and the outer app's
  # signature), so its updater only ever nags "couldn't update automatically".
  # Turn it off; EpixNet controls the ESR version and ships a newer one by
  # publishing a new build (see the header - we patch on our cadence). Windows
  # keeps updates on: there Firefox installs to a writable dir and self-patches.
  mkdir -p "$BUNDLED_FF/Contents/Resources/distribution"
  cat > "$BUNDLED_FF/Contents/Resources/distribution/policies.json" <<'POLICIES'
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
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>EpixNet</string>
  <key>CFBundleDisplayName</key><string>EpixNet</string>
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

# Re-signing Firefox under our identity drops the entitlements Mozilla shipped.
# Without com.apple.security.cs.allow-jit the hardened runtime denies the JIT's
# executable memory and Firefox crashes at launch (js::jit::InitializeJit()
# failed). Re-apply the security-relevant entitlements. --deep applies these to
# every nested binary (main process + plugin-container content/GPU processes),
# which all need them. Mozilla's team-specific keys (application-identifier,
# web-browser.public-key-credential) are intentionally omitted - they'd fail to
# sign/notarize under a different Team ID.
FF_ENTITLEMENTS="$OUT_DIR/firefox.entitlements.plist"
cat > "$FF_ENTITLEMENTS" <<'ENTS'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.cs.allow-jit</key><true/>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
  <key>com.apple.security.cs.allow-dyld-environment-variables</key><true/>
  <key>com.apple.security.device.audio-input</key><true/>
  <key>com.apple.security.device.camera</key><true/>
</dict>
</plist>
ENTS

# Sign. With EPIX_SIGN_ID set (a Developer ID Application identity), do a real
# hardened-runtime signature; otherwise ad-hoc so it runs locally.
if [ -n "${EPIX_SIGN_ID:-}" ]; then
  echo "· codesigning with Developer ID: $EPIX_SIGN_ID"
  # Sign inner code first (nested Firefox, with its entitlements), then our
  # binaries, then the outer app - all hardened runtime. The outer app is signed
  # without --deep so it does not re-sign Firefox and strip its entitlements.
  codesign --force --deep --options runtime --timestamp \
    --entitlements "$FF_ENTITLEMENTS" \
    --sign "$EPIX_SIGN_ID" "$APP/Contents/Resources/firefox/"*.app
  codesign --force --options runtime --timestamp \
    --sign "$EPIX_SIGN_ID" "$APP/Contents/MacOS/epix-nmh" "$APP/Contents/MacOS/epix-browser"
  codesign --force --options runtime --timestamp --sign "$EPIX_SIGN_ID" "$APP"
  codesign --verify --deep --strict "$APP" && echo "  signature verified"

  # Notarize with either a stored notarytool profile (local) or direct
  # credentials (CI: APPLE_ID + APPLE_TEAM_ID + APPLE_APP_PASSWORD).
  if [ -n "${EPIX_NOTARIZE_PROFILE:-}" ]; then
    NOTARY_ARGS=(--keychain-profile "$EPIX_NOTARIZE_PROFILE")
  elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    NOTARY_ARGS=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD")
  fi
  if [ "${#NOTARY_ARGS[@]}" -gt 0 ]; then
    echo "· notarizing the app (this can take minutes)"
    ZIP="$OUT_DIR/EpixNet.zip"
    ditto -c -k --keepParent "$APP" "$ZIP"
    xcrun notarytool submit "$ZIP" "${NOTARY_ARGS[@]}" --wait
    xcrun stapler staple "$APP"
    rm -f "$ZIP"
    echo "  notarized + stapled"
  else
    echo "· skipping notarization (no credentials)"
  fi
else
  echo "· ad-hoc codesigning (set EPIX_SIGN_ID for a release signature)"
  # Same as above: Firefox with its entitlements first, then the outer app
  # WITHOUT --deep so Firefox's entitlements survive.
  codesign --force --deep --entitlements "$FF_ENTITLEMENTS" --sign - \
    "$APP/Contents/Resources/firefox/"*.app 2>/dev/null || \
    echo "  (firefox ad-hoc sign warned)"
  codesign --force --sign - "$APP/Contents/MacOS/epix-nmh" "$APP/Contents/MacOS/epix-browser" 2>/dev/null || true
  codesign --force --sign - "$APP" 2>/dev/null || \
    echo "  (codesign warned; the app still runs locally)"
fi

# Guard: the bundled Firefox must keep its JIT entitlement, or it crashes at
# launch on user machines (js::jit::InitializeJit() failed). Catch a regression
# here instead of shipping it.
FF_MAIN="$(find "$APP/Contents/Resources/firefox" -maxdepth 3 -type f -name firefox | head -1)"
if [ -n "$FF_MAIN" ]; then
  if ! codesign -d --entitlements :- "$FF_MAIN" 2>/dev/null | grep -q "com.apple.security.cs.allow-jit"; then
    echo "error: bundled Firefox is missing com.apple.security.cs.allow-jit;"
    echo "       it would crash at launch. Signing must pass --entitlements."
    exit 1
  fi
fi

# Register with LaunchServices so epix:// links open the app.
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
  -f "$APP" 2>/dev/null || true

# Package a DMG for distribution (EPIX_MAKE_DMG=1). The app inside is already
# stapled, so the DMG passes Gatekeeper; notarize the DMG too when we can.
if [ "${EPIX_MAKE_DMG:-0}" = "1" ]; then
  DMG="$OUT_DIR/Epix-$VERSION.dmg"
  echo "· building $DMG"
  rm -f "$DMG"
  hdiutil create -volname "EpixNet" -srcfolder "$APP" -ov -format UDZO "$DMG" >/dev/null
  if [ -n "${EPIX_SIGN_ID:-}" ]; then
    codesign --force --sign "$EPIX_SIGN_ID" --timestamp "$DMG" || true
    if [ "${#NOTARY_ARGS[@]}" -gt 0 ]; then
      xcrun notarytool submit "$DMG" "${NOTARY_ARGS[@]}" --wait || true
      xcrun stapler staple "$DMG" || true
    fi
  fi
  echo "· done: $DMG"
fi

echo "· done: $APP"
echo "  run:      open \"$APP\""
echo "  epix://:  open epix://dashboard.epix"

# NOTES (release checklist):
#  1. Bundle ESR:  packaging/fetch-firefox-esr.sh osx
#  2. Sign:        EPIX_SIGN_ID="Developer ID Application: Your Org (TEAMID)"
#  3. Notarize:    xcrun notarytool store-credentials epix-notary \
#                     --apple-id you@org.com --team-id TEAMID --password <app-specific>
#                  then EPIX_NOTARIZE_PROFILE=epix-notary
#  Nesting Mozilla's already-signed Firefox is the thorny part: re-signing it
#  with our Developer ID (above) is required so the outer notarization passes.
