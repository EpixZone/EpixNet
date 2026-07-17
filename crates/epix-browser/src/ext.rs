//! Install the bundled Epix Wallet WebExtension + native-messaging host into a
//! Firefox profile.
//!
//! The wallet extension (the forked Keplr build, staged at `shells/wallet-ext`)
//! is embedded in the binary and written out as an XPI into
//! `<profile>/extensions/<id>.xpi`. It carries the whole Epix browser policy -
//! the wallet, the clearnet-block enforcement, and the Tor/I2P panel - so it
//! fully replaces the old standalone `browser-ext`. The native-messaging
//! manifest is written to Firefox's per-user host directory, pointing at the
//! `epix-nmh` binary (a sibling of this launcher) and allowing the wallet id.
//! Prefs to allow the unsigned extension (Developer Edition / ESR) are set by
//! the profile writer.
//!
//! `shells/wallet-ext` is a build artifact (gitignored): when it is missing or
//! stale, this crate's `build.rs` downloads the wallet build pinned by
//! `shells/wallet-ext.rev` (its immutable `wallet-<rev>` release) before
//! `include_dir!` embeds it (see `shells/wallet-ext/README.md` for local-build
//! overrides and how to bump the pin).

use include_dir::{include_dir, Dir};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The wallet extension files, embedded at build time.
static EXT: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../shells/wallet-ext");

/// The retired standalone extension's id (pre-wallet); cleaned out of existing
/// profiles by [`migrate_legacy_extension`].
pub const LEGACY_EXT_ID: &str = "browser-ext@epix.zone";

/// The starter chrome theme, embedded at build time.
static THEME: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../shells/browser-theme");

/// The Epix chrome theme add-on (a WebExtension theme carrying a light and a
/// dark colour set), embedded at build time. Unlike the wallet it is in-repo
/// source, so it refreshes whenever the launcher binary is rebuilt.
static THEME_ADDON: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../shells/epix-theme");

/// Epix-branded replacements for the wallet's toolbar icon. The wallet draws its
/// toolbar button on a canvas from `assets/toolbar-{16,48}.png` and overlays a
/// status dot; substituting these bytes at XPI-pack time rebrands the icon (a
/// white Epix mark on a dark disc, legible on light and dark chrome) while the
/// wallet keeps drawing its own status light on top. Embedded here, not edited
/// into the wallet build, so a wallet re-download can't clobber them.
static WALLET_TOOLBAR_16: &[u8] = include_bytes!("../assets/wallet-toolbar-16.png");
static WALLET_TOOLBAR_48: &[u8] = include_bytes!("../assets/wallet-toolbar-48.png");

/// Bump when the wallet REPACKING logic changes (icon substitution, manifest
/// transform, JS patches) but the wallet build itself does not. Folded into the
/// version stamp so an otherwise-unchanged wallet still repacks and reloads once,
/// picking up the new packing.
const WALLET_PACK_VERSION: u32 = 8;

/// The extension id (must match the wallet `manifest.json`'s Firefox gecko id).
pub const EXT_ID: &str = "wallet@epix.zone";
/// The theme add-on id (must match `shells/epix-theme/manifest.json`'s gecko
/// id). Firefox is told to activate it via the `extensions.activeThemeID` pref.
pub const THEME_EXT_ID: &str = "theme@epix.zone";
/// The native-messaging host name (must match the wallet's native bridge).
pub const NMH_NAME: &str = "zone.epix.nmh";

/// Migrate a profile off the retired standalone `browser-ext`: delete its
/// stale XPI (Firefox removes the add-on when the file is gone) and hand its
/// toolbar slot to the wallet. Firefox pins the widget placement in prefs.js's
/// `browser.uiCustomization.state`; new extensions start unpinned behind the
/// puzzle-piece menu, so without this the old Tor icon stays in the toolbar
/// and the wallet is invisible. Must run before Firefox launches (it rewrites
/// prefs.js on exit).
pub fn migrate_legacy_extension(profile: &Path) {
    let _ = std::fs::remove_file(
        profile.join("extensions").join(format!("{LEGACY_EXT_ID}.xpi")),
    );
    let prefs = profile.join("prefs.js");
    let Ok(s) = std::fs::read_to_string(&prefs) else { return };
    // Widget ids are the extension id with `@`/`.` mapped to `_`, plus
    // "-browser-action", JSON-escaped inside the pref's JS string.
    let old_widget = "browser-ext_epix_zone-browser-action";
    let new_widget = "wallet_epix_zone-browser-action";
    if !s.contains(old_widget) {
        return;
    }
    // Drop any existing (unpinned) wallet placement so the rename below
    // doesn't duplicate it, then give the wallet the old icon's slot.
    let out = s
        .replace(&format!("\\\"{new_widget}\\\","), "")
        .replace(&format!(",\\\"{new_widget}\\\""), "")
        .replace(&format!("\\\"{new_widget}\\\""), "")
        .replace(old_widget, new_widget);
    let _ = std::fs::write(&prefs, out);
}

/// Pin the wallet's toolbar button for profiles where it sits unpinned in the
/// unified-extensions (puzzle-piece) menu. Initial placement is decided only
/// at install time - fresh installs land on the toolbar via `default_area` in
/// the wallet manifest - and reinstalling to redo it would wipe the
/// extension's storage, which holds the keyring. Same string-level prefs.js
/// surgery as [`migrate_legacy_extension`]; runs before Firefox launches.
/// A wallet the user deliberately dragged off the toolbar is not in that
/// menu's placements, so it stays wherever the user put it.
pub fn ensure_wallet_pinned(profile: &Path) {
    let prefs = profile.join("prefs.js");
    let Ok(s) = std::fs::read_to_string(&prefs) else { return };
    // The widget id as it appears JSON-escaped inside the pref's JS string.
    let widget = "\\\"wallet_epix_zone-browser-action\\\"";

    let Some(ua_open) = find_area(&s, "unified-extensions-area") else { return };
    let Some(ua_len) = s[ua_open..].find(']') else { return };
    if !s[ua_open..ua_open + ua_len].contains(widget) {
        return; // not unpinned-by-default; nothing to move
    }
    // Remove it from the menu placements…
    let cleaned = s[ua_open..ua_open + ua_len]
        .replace(&format!("{widget},"), "")
        .replace(&format!(",{widget}"), "")
        .replace(widget, "");
    let s = format!("{}{}{}", &s[..ua_open], cleaned, &s[ua_open + ua_len..]);
    // …and append it to the toolbar.
    let Some(nav_open) = find_area(&s, "nav-bar") else { return };
    let Some(nav_len) = s[nav_open..].find(']') else { return };
    let insert =
        if nav_len == 0 { widget.to_string() } else { format!(",{widget}") };
    let mut out = s;
    out.insert_str(nav_open + nav_len, &insert);
    let _ = std::fs::write(&prefs, out);
}

/// Ensure a flexible spacer exists in the nav-bar. The chrome CSS orders it into
/// the gap that separates the Epix button (pinned by the address bar) from the
/// right-aligned extensions cluster; without a spacer to grow into that gap, the
/// two would sit next to each other. Firefox recreates a spring from its id, so
/// adding `customizableui-special-spring2` to the placements is enough. Profiles
/// that already have that spring (or any layout with it) are left untouched. Runs
/// before Firefox launches; on a first-ever run prefs.js doesn't exist yet, so
/// this no-ops and the next launch adds it (same as the other prefs.js surgery).
pub fn ensure_epix_spacer(profile: &Path) {
    let prefs = profile.join("prefs.js");
    let Ok(s) = std::fs::read_to_string(&prefs) else { return };
    let spring = "\\\"customizableui-special-spring2\\\"";
    let Some(nav_open) = find_area(&s, "nav-bar") else { return };
    let Some(nav_len) = s[nav_open..].find(']') else { return };
    let arr = &s[nav_open..nav_open + nav_len];
    if arr.contains(spring) {
        return; // already has the spring the CSS targets
    }
    // Place it right after the wallet if present (keeps the DOM tidy; the CSS
    // reorders regardless), else at the front of the nav-bar.
    let wallet = "\\\"wallet_epix_zone-browser-action\\\"";
    let (at, insert) = match arr.find(wallet) {
        Some(wpos) => (nav_open + wpos + wallet.len(), format!(",{spring}")),
        None if nav_len == 0 => (nav_open, spring.to_string()),
        None => (nav_open, format!("{spring},")),
    };
    let mut out = s;
    out.insert_str(at, &insert);
    let _ = std::fs::write(&prefs, out);
}

/// Make the Epix theme the active theme the first time it is available, then
/// never touch it again so the user can switch themes and have it stick.
///
/// Firefox installs a *sideloaded* theme as disabled, and the
/// `extensions.activeThemeID` pref alone will not switch to it, so we flip the
/// state directly in the add-on database (`extensions.json`) and drop Firefox's
/// fast-start theme cache so it rebuilds from our edit. A marker file guards the
/// one-shot. Best-effort: any unexpected shape is left alone (the browser just
/// keeps Firefox's default theme, which still follows light/dark).
///
/// On a fresh profile Firefox has not written `extensions.json` yet, and on the
/// launch that first ships the theme it is not in the DB yet; in both cases we
/// do nothing and no marker is written, so the next launch tries again. Must run
/// before Firefox launches (it rewrites `extensions.json`/`prefs.js`).
pub fn activate_theme_once(profile: &Path) {
    let marker = profile.join(".epix-theme-activated");
    if marker.exists() {
        return;
    }
    let db_path = profile.join("extensions.json");
    let Ok(raw) = std::fs::read_to_string(&db_path) else { return };
    let Ok(mut db) = serde_json::from_str::<serde_json::Value>(&raw) else { return };
    let Some(addons) = db.get_mut("addons").and_then(|a| a.as_array_mut()) else { return };

    // Wait until Firefox has actually registered our theme before deciding.
    if !addons.iter().any(|a| a["id"] == THEME_EXT_ID) {
        return;
    }
    let ours_active = addons
        .iter()
        .any(|a| a["id"] == THEME_EXT_ID && a["active"] == true);
    let default_active = addons
        .iter()
        .any(|a| a["id"] == "default-theme@mozilla.org" && a["active"] == true);
    // Already ours, or the user has switched to some non-default theme: in
    // either case stop trying (mark done) and respect what is there.
    if ours_active || !default_active {
        let _ = std::fs::write(&marker, b"");
        return;
    }

    // Installed but inactive while still on the default theme: activate ours.
    for a in addons.iter_mut() {
        if a["type"] != "theme" {
            continue;
        }
        let is_ours = a["id"] == THEME_EXT_ID;
        a["active"] = is_ours.into();
        a["userDisabled"] = (!is_ours).into();
    }
    if std::fs::write(&db_path, db.to_string()).is_err() {
        return;
    }
    // Force Firefox to recompute the active theme (and its startup cache).
    let _ = std::fs::remove_file(profile.join("addonStartup.json.lz4"));
    set_prefs_js_string(profile, "extensions.activeThemeID", THEME_EXT_ID);
    let _ = std::fs::write(&marker, b"");
}

/// Set (or replace) a quoted string pref in prefs.js. Firefox is not running
/// when this is called (same contract as the other prefs.js surgery here).
fn set_prefs_js_string(profile: &Path, key: &str, value: &str) {
    let path = profile.join("prefs.js");
    let Ok(s) = std::fs::read_to_string(&path) else { return };
    let line = format!("user_pref(\"{key}\", \"{value}\");");
    let needle = format!("user_pref(\"{key}\",");
    let out = if let Some(pos) = s.find(&needle) {
        let end = s[pos..].find('\n').map(|e| pos + e).unwrap_or(s.len());
        format!("{}{}{}", &s[..pos], line, &s[end..])
    } else {
        format!("{}\n{}\n", s.trim_end_matches('\n'), line)
    };
    let _ = std::fs::write(&path, out);
}

/// Byte offset just past `\"<area>\":[` inside prefs.js's
/// `browser.uiCustomization.state` line, or `None` when either is absent.
fn find_area(s: &str, area: &str) -> Option<usize> {
    let line = s.find("browser.uiCustomization.state")?;
    let key = format!("\\\"{area}\\\":[");
    let rel = s[line..].find(&key)?;
    Some(line + rel + key.len())
}

/// Write the extension as an XPI into the profile's `extensions/` dir. Firefox
/// installs it on startup (with the unsigned-extensions pref, on ESR/Developer).
///
/// The `manifest.json` version is stamped with a short hash of the whole
/// embedded extension, so it changes exactly when the wallet build changes.
/// Firefox reloads an add-on only when its version changes (a same-version XPI,
/// even rewritten, keeps serving cached bytecode) - stamping guarantees a fresh
/// build is actually picked up, without reinstalling on every unchanged launch.
pub fn install_extension(profile: &Path) -> Result<(), String> {
    // Fold the substitute toolbar icons into the version stamp, so changing them
    // (or the wallet build) bumps the add-on version and forces Firefox to
    // reload - otherwise a same-version XPI keeps serving the cached old icon.
    let extra = bytes_hash(WALLET_TOOLBAR_16)
        .wrapping_add(bytes_hash(WALLET_TOOLBAR_48))
        .wrapping_add(bytes_hash(EPIX_URLBAR_JS))
        .wrapping_add(WALLET_PACK_VERSION);
    // The wallet renders its (status-overlaid) toolbar icon only at the sizes in
    // its `M=[16,48]` list, and its own small canvas render is softer than
    // Firefox downscaling a large image. `write_dir_to_zip` patches the list to
    // `[48]` so the wallet renders a single crisp 48px icon and Firefox scales it
    // down to the ~24px button; `transform_manifest` likewise trims the
    // `default_icon` to only 48px so the icon Firefox shows BEFORE the script
    // runs is a crisp downscale too, not a fuzzy 16px upscale.
    install_addon_xpi(profile, &EXT, EXT_ID, extra, &[("epix-urlbar.js", EPIX_URLBAR_JS)])
}

/// Install the Epix chrome theme add-on as an XPI. It is enabled by the same
/// unsigned-sideload prefs as the wallet, and activated (made the current theme
/// instead of Firefox's built-in default) by the `extensions.activeThemeID`
/// pref the profile writer sets. Colours - including light/dark - live in the
/// add-on, so the chrome CSS no longer needs to (and no longer does) hardcode
/// them, which is what lets other Firefox themes apply.
pub fn install_theme_addon(profile: &Path) -> Result<(), String> {
    install_addon_xpi(profile, &THEME_ADDON, THEME_EXT_ID, 0, &[])
}

/// Zip an embedded add-on dir into `<profile>/extensions/<id>.xpi`, stamping its
/// `manifest.json` version with a content hash so Firefox reloads it only when
/// the embedded files change (see [`stamp_manifest_version`]). `extra_stamp` folds
/// in bytes not part of `dir` (e.g. the wallet's substitute icons) so those also
/// bump the version; `extra_files` are added to the archive after the dir.
fn install_addon_xpi(
    profile: &Path,
    dir: &Dir,
    ext_id: &str,
    extra_stamp: u32,
    extra_files: &[(&str, &[u8])],
) -> Result<(), String> {
    let ext_dir = profile.join("extensions");
    std::fs::create_dir_all(&ext_dir).map_err(|e| format!("extensions dir: {e}"))?;
    let xpi_path = ext_dir.join(format!("{ext_id}.xpi"));

    let stamp = (ext_content_hash(dir).wrapping_add(extra_stamp)) % 1_000_000;
    // Only (re)write the XPI when its content actually changed. Rewriting an
    // identical XPI still changes the file's timestamp, and Firefox reinstalls a
    // sideloaded add-on whose file it sees as new on every launch - which tears
    // down and recreates the toolbar button, flickering the wallet icon through
    // its reload on each start. A sidecar records the stamp the on-disk XPI was
    // built from; if it still matches, leave the file (and its mtime) untouched.
    let marker = profile.join(format!(".{ext_id}.xpi.salt"));
    let stamp_str = stamp.to_string();
    if xpi_path.exists()
        && std::fs::read_to_string(&marker).map_or(false, |m| m.trim() == stamp_str)
    {
        return Ok(());
    }

    let file = std::fs::File::create(&xpi_path).map_err(|e| format!("create xpi: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    write_dir_to_zip(&mut zip, dir, "", &opts, stamp)?;
    for (name, bytes) in extra_files {
        zip.start_file(*name, opts).map_err(|e| format!("zip entry {name}: {e}"))?;
        zip.write_all(bytes).map_err(|e| format!("zip write {name}: {e}"))?;
    }
    zip.finish().map_err(|e| format!("finish xpi: {e}"))?;
    let _ = std::fs::write(&marker, &stamp_str);
    Ok(())
}

/// A stable short hash of every embedded extension file (path + contents), used
/// as a build-identifying version stamp.
fn ext_content_hash(dir: &Dir) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    fn walk(dir: &Dir, h: &mut impl Hasher) {
        for file in dir.files() {
            file.path().to_string_lossy().hash(h);
            file.contents().hash(h);
        }
        for sub in dir.dirs() {
            walk(sub, h);
        }
    }
    walk(dir, &mut h);
    // Keep it in a range Firefox accepts as a version component.
    (h.finish() % 1_000_000) as u32
}

/// Make the wallet render its toolbar icon at a single 48px size so Firefox
/// downscales that to the ~24px button - a crisp path, unlike the wallet's own
/// small-canvas render (which looks soft even at 1:1) or an upscale from 16px.
/// The wallet hardcodes the sole array `[16,48]` (the sizes it draws the icon +
/// status dot at); rewrite it to `[48]`. Returns `None` when the pattern isn't
/// present exactly once (any non-matching JS file, or a changed wallet build),
/// leaving the file untouched - the icon then falls back to the stock 16/48
/// sizes, never broken.
fn patch_wallet_icon_sizes(contents: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(contents).ok()?;
    let needle = "[16,48]";
    if text.matches(needle).count() != 1 {
        return None;
    }
    Some(text.replacen(needle, "[48]", 1).into_bytes())
}

/// Spin a plain (dot-less) Epix mark while the node is genuinely connecting, then
/// show the static icon with its status dot once live. This is the JS half of the
/// loading animation; it handles a real (cold) connect, where the node takes tens
/// of seconds to bootstrap and the wallet's polls report "off"/"boot" that whole
/// time. The visible-on-window-open flourish for a warm reopen is done in CSS (see
/// epix-managed.css), because that case connects during Firefox startup, before
/// the window is painted, so a JS-timer spin finishes unseen. The two are
/// complementary: CSS fires on toolbar render (window appears), JS covers the long
/// real wait.
///
/// The wallet renders its toolbar icon from a status poll: `o(status)` draws the
/// base + a status dot via `S(base,size,color)` and de-dupes on status change.
/// The statuses are "off"/"boot" (not connected) and "ready"/"routed" (live). We:
///   1. Inject a controller by the icon cache (`c`) that each frame rotates the
///      largest cached base and `setIcon`s it with *no* dot, at ~10fps.
///   2. Start the spin at module init and eagerly preload the base bitmaps into
///      `c`, so it animates from load rather than only on a not-connected poll.
///   3. Hook the render so the first live status stops the spin; the wallet's own
///      static render then paints the dotted icon.
///   4. Suppress the dot in the static render for the not-connected states too, so
///      the mark is dot-less until the connection is live.
///
/// Returns `None` when the injection anchor isn't present exactly once (a changed
/// wallet build), leaving the file untouched - the icon then simply never spins,
/// never breaks. Names are double-underscore-prefixed so they can't collide with
/// the wallet's single-letter minified identifiers.
fn patch_wallet_boot_spin(contents: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(contents).ok()?;
    // The icon module: `e` is the extension API, `n` the browserAction, `c` the
    // (lazy) base-bitmap cache, `M`/`U`/`S` the sizes/colours/draw fn, and `o(i)`
    // the render fn whose generator body opens here.
    let anchor = "let c=null,a=\"\";const o=i=>g(this,void 0,void 0,(function*(){const o=null!=i?i:\"none\";";
    if text.matches(anchor).count() != 1 {
        return None;
    }
    // Spin controller, used for the genuine long connect (cold boot): `__el`
    // eagerly primes `c` (mirrors the wallet's own fetch, only sets `c` if still
    // null so it never clobbers a concurrent load); `__ed` draws a dot-less
    // rotated frame each tick; `__es`/`__ex` start/stop. It starts at init and the
    // hook stops it the instant a live status renders, so the mark spins dot-less
    // from load until connected. (A warm reopen finishes connecting during Firefox
    // startup, before the window is painted, so its visible flourish comes from the
    // CSS chrome animation instead - see epix-managed.css - which fires on toolbar
    // render, i.e. exactly when the window appears.)
    let controller = concat!(
        "let __ea=null,__ang=0;",
        "const __ec=z=>{const G=globalThis;if(G.OffscreenCanvas)return new G.OffscreenCanvas(z,z).getContext(\"2d\");",
        "if(G.document){const q=G.document.createElement(\"canvas\");return q.width=q.height=z,q.getContext(\"2d\")}return null};",
        "const __eb=()=>{if(!c)return null;let k=-1,b=null;for(const[q,v]of c)q>k&&(k=q,b=v);return b};",
        "const __el=()=>{if(c)return;try{Promise.all(M.map(z=>fetch(e.runtime.getURL(\"assets/toolbar-\"+z+\".png\")).then(r=>r.blob()).then(b=>createImageBitmap(b)).then(b=>[z,b]))).then(ps=>{c||(c=new Map(ps))}).catch(()=>{})}catch(_){}};",
        "const __ed=()=>{if(!c)return;const t={};for(const z of M){const b=c.get(z)||__eb();if(!b)continue;",
        "const x=__ec(z);if(!x)continue;x.translate(z/2,z/2),x.rotate(__ang),x.translate(-z/2,-z/2),x.drawImage(b,0,0,z,z);",
        "t[z]=x.getImageData(0,0,z,z)}",
        "if(Object.keys(t).length===M.length)try{const p=n.setIcon({imageData:t});p&&p.catch&&p.catch(()=>{})}catch(_){}__ang+=Math.PI/10};",
        "const __es=()=>{__ea||(__ang=0,__ea=setInterval(__ed,100))};",
        "const __ex=()=>{__ea&&(clearInterval(__ea),__ea=null)};",
        "__el(),__es();",
    );
    // Hook at the top of the render generator: a live status stops the spin (the
    // static render then draws the dot), any not-connected status keeps it running.
    let hook = "(\"ready\"===i||\"routed\"===i)?__ex():__es();";
    let replacement = [
        "let c=null,a=\"\";",
        controller,
        "const o=i=>g(this,void 0,void 0,(function*(){",
        hook,
        "const o=null!=i?i:\"none\";",
    ]
    .concat();
    let mut out = text.replacen(anchor, &replacement, 1);
    // Best-effort: only draw the status dot for the live states, so the static
    // render is dot-less while not connected (matches the spin, kills any flash).
    let dot = "const r=i?U[i]:null";
    if out.matches(dot).count() == 1 {
        out = out.replacen(dot, "const r=\"ready\"===i||\"routed\"===i?U[i]:null", 1);
    }
    Some(out.into_bytes())
}

/// Apply every wallet JS transform in order: force a single 48px render size,
/// then add the connecting spin. Each is a no-op (returns its input unchanged)
/// when its pattern is absent, so non-wallet `.js` files pass straight through.
fn patch_wallet_js(contents: &[u8]) -> Vec<u8> {
    let sized = patch_wallet_icon_sizes(contents);
    let base: &[u8] = sized.as_deref().unwrap_or(contents);
    patch_wallet_boot_spin(base).unwrap_or_else(|| base.to_vec())
}

/// URL-bar navigation for bare xite addresses. A bech32 `epix1…` address has no
/// dot, so Firefox's fixup sends it to the default search engine instead of
/// navigating (a dotted `name.epix` navigates natively). This background script
/// catches exactly that search - a main-frame query that IS a bech32 address -
/// before it leaves, and goes to the xite instead, like the mobile shells'
/// address bars. Scoped to DuckDuckGo, the managed profile's default engine.
const EPIX_URLBAR_JS: &[u8] = concat!(
    "// Managed by epix-browser (added at pack time).\n",
    "(() => {\n",
    "  const api = globalThis.browser || globalThis.chrome;\n",
    "  if (!api || !api.webRequest) return;\n",
    "  const ADDR = /^epix1[a-z0-9]{20,80}$/;\n",
    "  api.webRequest.onBeforeRequest.addListener(\n",
    "    (details) => {\n",
    "      try {\n",
    "        const q = (new URL(details.url).searchParams.get(\"q\") || \"\").trim();\n",
    "        if (ADDR.test(q)) return { redirectUrl: \"https://\" + q + \"/\" };\n",
    "      } catch (_) {}\n",
    "      return {};\n",
    "    },\n",
    "    { urls: [\"*://duckduckgo.com/*\", \"*://*.duckduckgo.com/*\"], types: [\"main_frame\"] },\n",
    "    [\"blocking\"]\n",
    "  );\n",
    "})();\n",
)
.as_bytes();

/// Add the URL-bar script to the wallet's background page, right after the
/// polyfill so it registers before the wallet's own bundles. A no-op when the
/// anchor isn't present exactly once (a changed wallet build) - the search
/// then simply keeps its default behaviour, never breaks.
fn patch_background_html(contents: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(contents).ok()?;
    let anchor = "<script src=\"browser-polyfill.js\"></script>";
    if text.matches(anchor).count() != 1 {
        return None;
    }
    let replacement = format!("{anchor}<script src=\"epix-urlbar.js\"></script>");
    Some(text.replacen(anchor, &replacement, 1).into_bytes())
}

/// A stable short hash of a byte slice (same family as [`ext_content_hash`]).
fn bytes_hash(bytes: &[u8]) -> u32 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    (h.finish() % 1_000_000) as u32
}

/// Transform a bundled `manifest.json` for packing: stamp its version with the
/// build stamp, and (for the wallet) trim the `browser_action`/`action`
/// `default_icon` to only the 48px source. Firefox picks a `default_icon` by
/// nearest size, so with a 16 and a 48 it would upscale the 16px one to the 24px
/// button (fuzzy) for the brief moment before the wallet's script sets its own
/// icon; leaving only 48 makes that pre-script icon a crisp downscale instead.
/// Falls back to the plain version stamp if the manifest can't be parsed.
fn transform_manifest(contents: &[u8], stamp: u32) -> Vec<u8> {
    let Ok(mut m) = serde_json::from_slice::<serde_json::Value>(contents) else {
        return stamp_manifest_version(contents, stamp);
    };
    if let Some(v) = m.get("version").and_then(|x| x.as_str()) {
        m["version"] = serde_json::Value::String(format!("{v}.{stamp}"));
    }
    for key in ["browser_action", "action"] {
        if let Some(ba) = m.get_mut(key).and_then(|b| b.as_object_mut()) {
            let has48 = ba.get("default_icon").and_then(|d| d.get("48")).is_some();
            if has48 {
                ba.insert(
                    "default_icon".to_string(),
                    serde_json::json!({ "48": "assets/toolbar-48.png" }),
                );
            }
        }
    }
    serde_json::to_vec(&m).unwrap_or_else(|_| stamp_manifest_version(contents, stamp))
}

/// Rewrite `manifest.json`'s `"version": "X.Y.Z"` to `"X.Y.Z.<stamp>"` so the
/// add-on version tracks the build.
fn stamp_manifest_version(contents: &[u8], stamp: u32) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else { return contents.to_vec() };
    let needle = "\"version\":";
    let Some(vpos) = text.find(needle) else { return contents.to_vec() };
    let after = &text[vpos + needle.len()..];
    // Find the value string: first quote, then the closing quote.
    let Some(q1) = after.find('"') else { return contents.to_vec() };
    let rest = &after[q1 + 1..];
    let Some(q2) = rest.find('"') else { return contents.to_vec() };
    let version = &rest[..q2];
    let stamped = format!("{version}.{stamp}");
    let start = vpos + needle.len() + q1 + 1;
    let end = start + q2;
    let mut out = String::with_capacity(text.len() + 8);
    out.push_str(&text[..start]);
    out.push_str(&stamped);
    out.push_str(&text[end..]);
    out.into_bytes()
}

fn write_dir_to_zip(
    zip: &mut zip::ZipWriter<std::fs::File>,
    dir: &Dir,
    prefix: &str,
    opts: &zip::write::FileOptions<'_, ()>,
    stamp: u32,
) -> Result<(), String> {
    for file in dir.files() {
        let name = file.path().file_name().unwrap().to_string_lossy();
        let entry = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        zip.start_file(&entry, *opts).map_err(|e| format!("zip entry {entry}: {e}"))?;
        // Stamp only the root manifest so the add-on version tracks the build;
        // swap the wallet's toolbar icons for the Epix-branded ones; and patch
        // its JS (single 48px render size, plus the connecting spin). All are
        // no-ops for the theme add-on, which has none of these entries.
        let stamped;
        let patched;
        let bytes: &[u8] = match entry.as_str() {
            "manifest.json" => {
                stamped = transform_manifest(file.contents(), stamp);
                &stamped
            }
            "assets/toolbar-16.png" => WALLET_TOOLBAR_16,
            "assets/toolbar-48.png" => WALLET_TOOLBAR_48,
            // The wallet's background page gains the URL-bar address script
            // (packed alongside via `extra_files`).
            "background.html" => {
                patched = patch_background_html(file.contents())
                    .unwrap_or_else(|| file.contents().to_vec());
                &patched
            }
            _ if entry.ends_with(".js") => {
                patched = patch_wallet_js(file.contents());
                &patched
            }
            _ => file.contents(),
        };
        zip.write_all(bytes).map_err(|e| format!("zip write {entry}: {e}"))?;
    }
    for sub in dir.dirs() {
        let name = sub.path().file_name().unwrap().to_string_lossy();
        let p = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        write_dir_to_zip(zip, sub, &p, opts, stamp)?;
    }
    Ok(())
}

/// Launcher-owned chrome files, always rewritten (not just written once): the
/// managed sheet carries the launcher's rules, so a new build's rules must reach
/// existing profiles.
const ALWAYS_WRITE: &[&str] = &["epix-managed.css"];

/// Marker identifying the current userChrome.css starter. A profile whose
/// userChrome.css lacks it and still matches an untouched prior default is
/// refreshed (see [`is_prior_default_userchrome`]).
const USERCHROME_MARKER: &str = "epix-userchrome v2";

/// Install the chrome theme into `<profile>/chrome/`. `epix-managed.css` and the
/// mono icon are rewritten every launch so the launcher's rules and artwork
/// always land, including on pre-existing profiles. The editable starters
/// (userChrome.css, userContent.css) are written only when absent so a user's
/// edits survive - with one exception: a userChrome.css that is still an
/// untouched pre-theme-add-on default is refreshed, because its old hardcoded
/// dark palette would override the theme add-on and block other themes.
pub fn install_theme(profile: &Path) -> Result<(), String> {
    let chrome = profile.join("chrome");
    std::fs::create_dir_all(&chrome).map_err(|e| format!("chrome dir: {e}"))?;
    const USERCHROME: &str = "userChrome.css";
    for file in THEME.files() {
        let name = file.path().file_name().unwrap();
        let name_str = name.to_string_lossy();
        let dest = chrome.join(name);
        let always = ALWAYS_WRITE.iter().any(|f| *f == name_str);
        // Replace an untouched pre-add-on userChrome default (marker-less and
        // byte-matching a known shipped default); leave a customized file alone.
        let refresh_uc = name_str == USERCHROME
            && dest.exists()
            && std::fs::read_to_string(&dest).map_or(false, |s| {
                !s.contains(USERCHROME_MARKER) && is_prior_default_userchrome(&s)
            });
        if always || !dest.exists() || refresh_uc {
            std::fs::write(&dest, file.contents())
                .map_err(|e| format!("write {}: {e}", dest.display()))?;
        }
    }
    // Ensure userChrome.css pulls in the managed rules. A profile created before
    // epix-managed.css existed has a userChrome.css without the import; prepend
    // it (an `@import` is valid at the very top, ahead of the comment).
    let uc = chrome.join(USERCHROME);
    if let Ok(s) = std::fs::read_to_string(&uc) {
        if !s.contains("epix-managed.css") {
            let _ = std::fs::write(&uc, format!("@import \"epix-managed.css\";\n{s}"));
        }
    }
    Ok(())
}

/// Whether `s` is an untouched userChrome.css default shipped before the theme
/// add-on (so it is safe to overwrite). The palette+rules body [`OLD_STARTER_BODY`]
/// stayed identical across a few header shapes: a commented `@import` (current
/// repo default), a bare `@import` (older profiles), and the original with no
/// import the launcher later prepended. Accept any of them. Compared with line
/// endings and surrounding whitespace normalized, so CRLF/LF and trailing
/// newlines don't matter; any real edit changes the body and is preserved.
fn is_prior_default_userchrome(s: &str) -> bool {
    let norm = |x: &str| x.replace('\r', "").trim().to_string();
    let cur = norm(s);
    [
        format!("{OLD_MANAGED_COMMENT}\n{OLD_IMPORT_LINE}\n\n{OLD_STARTER_BODY}"),
        format!("{OLD_IMPORT_LINE}\n{OLD_STARTER_BODY}"),
        OLD_STARTER_BODY.to_string(),
    ]
    .iter()
    .any(|v| norm(v) == cur)
}

/// The leading managed-rules comment the most recent pre-add-on default carried
/// above its `@import`.
const OLD_MANAGED_COMMENT: &str = "/* Managed rules (hide dead chrome, size the wallet button). Kept in a separate\n * file the launcher rewrites every launch; this @import must stay at the top. */";

/// The managed-sheet import line, present (bare or commented) in pre-add-on
/// defaults after their first launch.
const OLD_IMPORT_LINE: &str = "@import \"epix-managed.css\";";

/// The dark-hardcoded body (palette + rules) shared by every userChrome.css
/// default shipped before the theme add-on, kept verbatim so an untouched copy
/// can be detected and refreshed regardless of which header shape wraps it.
const OLD_STARTER_BODY: &str = r##"/* Epix browser chrome theme (starter).
 *
 * This restyles Firefox's chrome to look like Epix. It is written into the
 * profile's chrome/ dir on first launch and NOT overwritten afterwards, so you
 * can edit it live: change a value, restart the browser, see it. This is the
 * CSS-only styling surface (full native rebrand is fork/unbranded-build work).
 *
 * Requires toolkit.legacyUserProfileCustomizations.stylesheets=true (the
 * launcher sets it).
 */

:root {
  --epix-bg: #0b0e14;
  --epix-bg2: #111725;
  --epix-fg: #cbd5e1;
  --epix-accent: #8a4bdb;
  --epix-border: #1e293b;
}

/* Toolbar + tab strip background. */
#navigator-toolbox {
  background-color: var(--epix-bg) !important;
  border-bottom: 1px solid var(--epix-border) !important;
}
#nav-bar,
#TabsToolbar,
#PersonalToolbar {
  background-color: var(--epix-bg) !important;
  color: var(--epix-fg) !important;
}

/* Address bar. */
#urlbar,
#searchbar {
  background-color: var(--epix-bg2) !important;
  color: var(--epix-fg) !important;
  border: 1px solid var(--epix-border) !important;
  border-radius: 8px !important;
}
#urlbar[focused="true"] {
  border-color: var(--epix-accent) !important;
}

/* Tabs. */
.tabbrowser-tab {
  color: var(--epix-fg) !important;
}
.tab-background[selected] {
  background-color: var(--epix-bg2) !important;
  border-top: 2px solid var(--epix-accent) !important;
}

/* Toolbar buttons inherit the accent on hover. */
toolbarbutton:hover {
  fill: var(--epix-accent) !important;
}"##;

/// Write the native-messaging host manifest so Firefox can launch `epix-nmh`.
/// On macOS/Linux it goes in Firefox's per-user host dir; on Windows Firefox
/// reads the manifest location from the registry, so we also set that key.
pub fn install_native_host() -> Result<(), String> {
    let nmh = nmh_binary().ok_or("epix-nmh binary not found next to the launcher")?;
    let dir = native_host_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("native host dir: {e}"))?;
    let manifest_path = dir.join(format!("{NMH_NAME}.json"));
    std::fs::write(&manifest_path, serde_json_manifest(&nmh))
        .map_err(|e| format!("write native host manifest: {e}"))?;
    #[cfg(windows)]
    set_windows_native_host_registry(&manifest_path)?;
    Ok(())
}

/// Point Firefox at the native-host manifest via the registry (Windows only):
/// `HKCU\Software\Mozilla\NativeMessagingHosts\<name>` = the manifest path.
#[cfg(windows)]
fn set_windows_native_host_registry(manifest_path: &Path) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(format!("Software\\Mozilla\\NativeMessagingHosts\\{NMH_NAME}"))
        .map_err(|e| format!("create registry key: {e}"))?;
    key.set_value("", &manifest_path.to_string_lossy().to_string())
        .map_err(|e| format!("set registry value: {e}"))?;
    Ok(())
}

fn serde_json_manifest(nmh: &Path) -> String {
    // Build with serde_json so the path is correctly escaped. On Windows
    // `nmh.display()` is a backslash path (C:\Users\...), and interpolating it
    // raw into a JSON string produces invalid escapes (\U, \A, \E) - or worse a
    // real tab from \t in a name like \username. Firefox's native-messaging
    // manifest parser rejects the file, so sendNativeMessage fails and the
    // wallet's Tor/I2P shield, Ledger bridge, and clearnet toggle all go dead.
    serde_json::json!({
        "name": NMH_NAME,
        "description": "Epix native messaging host",
        "path": nmh.to_string_lossy(),
        "type": "stdio",
        "allowed_extensions": [EXT_ID],
    })
    .to_string()
}

/// Where the native-messaging host manifest is written.
fn native_host_dir() -> PathBuf {
    if cfg!(windows) {
        // Windows reads the path from the registry, so any stable dir works.
        let appdata = std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
        return appdata.join("Epix");
    }
    let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."));
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Mozilla/NativeMessagingHosts")
    } else {
        home.join(".mozilla/native-messaging-hosts")
    }
}

/// The `epix-nmh` binary, a sibling of this launcher (dev: target/<profile>/).
fn nmh_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("EPIX_NMH") {
        let p = PathBuf::from(p);
        if p.exists() {
            return Some(p);
        }
    }
    // Exec plumbing, not a trust decision: current_exe comes from the kernel
    // (not argv[0]), and anyone able to replace files next to the launcher
    // already runs code as this user.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let exe = std::env::current_exe().ok()?;
    let sibling = exe.parent()?.join(if cfg!(windows) { "epix-nmh.exe" } else { "epix-nmh" });
    sibling.exists().then_some(sibling)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch profile dir with a securely-created unique name (via `tempfile`,
    /// not a predictable name under the shared temp dir). Field `.0` is the path;
    /// the `TempDir` guard removes the directory when the profile is dropped.
    struct TmpProfile(PathBuf, #[allow(dead_code)] tempfile::TempDir);
    impl TmpProfile {
        fn new() -> Self {
            let td = tempfile::tempdir().unwrap();
            TmpProfile(td.path().to_path_buf(), td)
        }
        fn chrome(&self, name: &str) -> String {
            std::fs::read_to_string(self.0.join("chrome").join(name)).unwrap()
        }
    }

    // A fresh profile gets every template, and the launcher-owned files carry
    // the current content (v2 userChrome, the mono icon).
    #[test]
    fn fresh_profile_gets_all_theme_files() {
        let p = TmpProfile::new();
        install_theme(&p.0).unwrap();
        let managed = p.chrome("epix-managed.css");
        // Only the account button is hidden; the puzzle button is kept and
        // ordered just right of the Epix button (not hidden).
        assert_eq!(managed.matches("display: none").count(), 1, "only fxa should be hidden");
        assert!(managed.contains("#fxa-toolbar-menu-button"));
        assert!(managed.contains("#unified-extensions-button"));
        assert!(managed.contains("order: 1"), "Epix button ordered next to the address bar");
        assert!(
            managed.contains("[id$=\"-browser-action\"]"),
            "pinned extensions ordered into the right cluster"
        );
        assert!(p.chrome("userChrome.css").contains(USERCHROME_MARKER));
        assert!(std::fs::metadata(p.0.join("chrome/userContent.css")).is_ok());
    }

    // The managed sheet is always rewritten, even over stale bytes.
    #[test]
    fn managed_sheet_is_always_refreshed() {
        let p = TmpProfile::new();
        let chrome = p.0.join("chrome");
        std::fs::create_dir_all(&chrome).unwrap();
        std::fs::write(chrome.join("epix-managed.css"), "STALE").unwrap();
        install_theme(&p.0).unwrap();
        assert_ne!(p.chrome("epix-managed.css"), "STALE");
    }

    // The commented-@import default (current repo default before the add-on).
    fn old_default_v1() -> String {
        format!("{OLD_MANAGED_COMMENT}\n{OLD_IMPORT_LINE}\n\n{OLD_STARTER_BODY}")
    }
    // The bare-@import default older profiles carry (e.g. the one installed on
    // this machine) - the header shape that a naive exact match would miss.
    fn old_default_v0() -> String {
        format!("{OLD_IMPORT_LINE}\n{OLD_STARTER_BODY}")
    }

    // An untouched pre-add-on userChrome default is refreshed to v2 (its old
    // hardcoded dark palette, which would override the theme add-on, is gone),
    // even with CRLF line endings and a trailing newline - for BOTH the
    // commented-@import and the bare-@import header shapes.
    #[test]
    fn untouched_old_default_userchrome_is_refreshed() {
        for old in [old_default_v1(), old_default_v0()] {
            let p = TmpProfile::new();
            let chrome = p.0.join("chrome");
            std::fs::create_dir_all(&chrome).unwrap();
            let old_crlf = format!("{}\r\n", old.replace('\n', "\r\n"));
            std::fs::write(chrome.join("userChrome.css"), old_crlf).unwrap();
            install_theme(&p.0).unwrap();
            let uc = p.chrome("userChrome.css");
            assert!(uc.contains(USERCHROME_MARKER), "old default should be refreshed to v2");
            assert!(!uc.contains("--epix-bg: #0b0e14"), "old hardcoded palette should be gone");
        }
    }

    // A user-customized userChrome.css is left untouched.
    #[test]
    fn customized_userchrome_is_preserved() {
        let p = TmpProfile::new();
        let chrome = p.0.join("chrome");
        std::fs::create_dir_all(&chrome).unwrap();
        let mine = "@import \"epix-managed.css\";\n/* my tweak */\n#nav-bar { color: red }\n";
        std::fs::write(chrome.join("userChrome.css"), mine).unwrap();
        install_theme(&p.0).unwrap();
        assert_eq!(p.chrome("userChrome.css"), mine);
    }

    // The nav-bar spacer is added once, right after the wallet, and not
    // duplicated on a second run (nor when a profile already has it).
    #[test]
    fn epix_spacer_added_after_wallet_and_idempotent() {
        let p = TmpProfile::new();
        std::fs::create_dir_all(&p.0).unwrap();
        let esc =
            |ids: &[&str]| ids.iter().map(|i| format!("\\\"{i}\\\"")).collect::<Vec<_>>().join(",");
        let nav = esc(&[
            "urlbar-container",
            "wallet_epix_zone-browser-action",
            "unified-extensions-button",
        ]);
        let state = format!(
            "user_pref(\"browser.uiCustomization.state\", \"{{\\\"placements\\\":{{\\\"nav-bar\\\":[{nav}]}}}}\");\n"
        );
        std::fs::write(p.0.join("prefs.js"), &state).unwrap();

        ensure_epix_spacer(&p.0);
        let out = std::fs::read_to_string(p.0.join("prefs.js")).unwrap();
        assert_eq!(out.matches("customizableui-special-spring2").count(), 1, "added once");
        let wallet = "\\\"wallet_epix_zone-browser-action\\\"";
        let spring = "\\\"customizableui-special-spring2\\\"";
        assert!(out.contains(&format!("{wallet},{spring}")), "spring sits right after the wallet");

        ensure_epix_spacer(&p.0);
        let out2 = std::fs::read_to_string(p.0.join("prefs.js")).unwrap();
        assert_eq!(out2.matches("customizableui-special-spring2").count(), 1, "not duplicated");
    }

    #[test]
    fn prior_default_matches_all_header_shapes() {
        assert!(is_prior_default_userchrome(&old_default_v1()));
        assert!(is_prior_default_userchrome(&old_default_v0()));
        assert!(is_prior_default_userchrome(OLD_STARTER_BODY)); // pre-@import original
        assert!(is_prior_default_userchrome(&format!("\n  {}\r\n", old_default_v0())));
        assert!(!is_prior_default_userchrome("something else"));
        // A real edit to the body is preserved, not treated as a default.
        assert!(!is_prior_default_userchrome(&old_default_v0().replace("#0b0e14", "#000000")));
    }

    // Build a minimal extensions.json like Firefox writes, with the given
    // active theme id and our theme present but (by default) disabled.
    fn write_ext_db(profile: &Path, active_theme: &str, include_ours: bool, ours_active: bool) {
        let mut addons = vec![serde_json::json!({
            "id": "default-theme@mozilla.org", "type": "theme",
            "active": active_theme == "default-theme@mozilla.org",
            "userDisabled": active_theme != "default-theme@mozilla.org",
        })];
        if include_ours {
            addons.push(serde_json::json!({
                "id": THEME_EXT_ID, "type": "theme",
                "active": ours_active, "userDisabled": !ours_active,
            }));
        }
        if active_theme != "default-theme@mozilla.org" && active_theme != THEME_EXT_ID {
            addons.push(serde_json::json!({
                "id": active_theme, "type": "theme", "active": true, "userDisabled": false,
            }));
        }
        let db = serde_json::json!({ "schemaVersion": 36, "addons": addons });
        std::fs::write(profile.join("extensions.json"), db.to_string()).unwrap();
    }

    fn theme_states(profile: &Path) -> Vec<(String, bool, bool)> {
        let raw = std::fs::read_to_string(profile.join("extensions.json")).unwrap();
        let db: serde_json::Value = serde_json::from_str(&raw).unwrap();
        db["addons"].as_array().unwrap().iter()
            .filter(|a| a["type"] == "theme")
            .map(|a| (a["id"].as_str().unwrap().to_string(), a["active"] == true, a["userDisabled"] == true))
            .collect()
    }

    // On the default theme with ours installed-but-disabled: activate ours,
    // disable the default, drop the startup cache, and write the marker.
    #[test]
    fn activate_theme_switches_from_default_once() {
        let p = TmpProfile::new();
        std::fs::write(p.0.join("addonStartup.json.lz4"), b"cache").unwrap();
        std::fs::write(p.0.join("prefs.js"), "user_pref(\"x\", 1);\n").unwrap();
        write_ext_db(&p.0, "default-theme@mozilla.org", true, false);
        activate_theme_once(&p.0);
        let st = theme_states(&p.0);
        assert!(st.iter().any(|(id, active, dis)| id == THEME_EXT_ID && *active && !*dis));
        assert!(st.iter().any(|(id, active, _)| id == "default-theme@mozilla.org" && !*active));
        assert!(!p.0.join("addonStartup.json.lz4").exists(), "startup cache should be dropped");
        assert!(p.0.join(".epix-theme-activated").exists(), "marker should be written");
        assert!(std::fs::read_to_string(p.0.join("prefs.js")).unwrap().contains(THEME_EXT_ID));
    }

    // A user who picked a different theme is respected (we don't reactivate),
    // and we mark done so we never fight them.
    #[test]
    fn activate_theme_respects_user_choice() {
        let p = TmpProfile::new();
        write_ext_db(&p.0, "firefox-compact-dark@mozilla.org", true, false);
        activate_theme_once(&p.0);
        let st = theme_states(&p.0);
        assert!(st.iter().any(|(id, active, _)| id == "firefox-compact-dark@mozilla.org" && *active));
        assert!(st.iter().any(|(id, active, _)| id == THEME_EXT_ID && !*active), "ours stays inactive");
        assert!(p.0.join(".epix-theme-activated").exists());
    }

    // Before Firefox has registered our theme, do nothing and leave no marker,
    // so a later launch retries.
    #[test]
    fn activate_theme_waits_until_theme_registered() {
        let p = TmpProfile::new();
        write_ext_db(&p.0, "default-theme@mozilla.org", false, false);
        activate_theme_once(&p.0);
        assert!(!p.0.join(".epix-theme-activated").exists(), "must retry next launch");
        // No extensions.json at all (truly fresh profile): also a no-op, no marker.
        let p2 = TmpProfile::new();
        std::fs::create_dir_all(&p2.0).unwrap();
        activate_theme_once(&p2.0);
        assert!(!p2.0.join(".epix-theme-activated").exists());
    }

    // Once the marker exists we never touch the DB again (idempotent / hands-off).
    #[test]
    fn activate_theme_is_one_shot() {
        let p = TmpProfile::new();
        write_ext_db(&p.0, "default-theme@mozilla.org", true, false);
        std::fs::write(p.0.join(".epix-theme-activated"), b"").unwrap();
        activate_theme_once(&p.0);
        let st = theme_states(&p.0);
        assert!(st.iter().any(|(id, active, _)| id == THEME_EXT_ID && !*active), "should stay untouched");
    }

    // The theme add-on is written as a valid XPI whose manifest still parses as
    // JSON after version stamping, carries the expected gecko id, and defines
    // both a light (`theme`) and a dark (`dark_theme`) colour set.
    #[test]
    fn theme_addon_xpi_is_a_valid_theme() {
        let p = TmpProfile::new();
        install_theme_addon(&p.0).unwrap();
        let xpi = p.0.join("extensions").join(format!("{THEME_EXT_ID}.xpi"));
        let f = std::fs::File::open(&xpi).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        let mut s = String::new();
        {
            use std::io::Read;
            zip.by_name("manifest.json").unwrap().read_to_string(&mut s).unwrap();
        }
        let m: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(m["applications"]["gecko"]["id"], THEME_EXT_ID);
        // Version was stamped from "1.0.0" to a 4-part build version.
        let v = m["version"].as_str().unwrap();
        assert_eq!(v.split('.').count(), 4, "version should be stamped: {v}");
        assert!(m["theme"]["colors"].is_object());
        assert!(m["dark_theme"]["colors"].is_object());
    }

    // The wallet XPI ships the Epix-branded toolbar icons in place of the
    // wallet's own, so its canvas draws our badge (with its status light on
    // top), and its icon-size list is patched to a single 48px render.
    #[test]
    fn wallet_xpi_uses_epix_toolbar_icons() {
        let p = TmpProfile::new();
        install_extension(&p.0).unwrap();
        let xpi = p.0.join("extensions").join(format!("{EXT_ID}.xpi"));
        let f = std::fs::File::open(&xpi).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        use std::io::Read;
        for (name, expected) in
            [("assets/toolbar-16.png", WALLET_TOOLBAR_16), ("assets/toolbar-48.png", WALLET_TOOLBAR_48)]
        {
            let mut buf = Vec::new();
            zip.by_name(name).unwrap().read_to_end(&mut buf).unwrap();
            assert_eq!(buf, expected, "{name} should be the Epix badge");
        }
        // The icon-size list was patched from [16,48] to a lone 48. Identify it
        // by the status-color map that immediately follows it, and confirm the
        // old list is gone everywhere.
        let names: Vec<String> = zip.file_names().map(String::from).collect();
        let mut found_patch = false;
        for name in names.iter().filter(|n| n.ends_with(".js")) {
            let mut s = String::new();
            if zip.by_name(name).unwrap().read_to_string(&mut s).is_ok() {
                assert!(!s.contains("[16,48]"), "old size list should be gone in {name}");
                if s.contains("[48],U={off:") {
                    found_patch = true;
                }
            }
        }
        assert!(found_patch, "the patched [48] size list should sit before the status colors");

        // The manifest's default_icon is trimmed to only 48px (crisp pre-script
        // icon), and its version is stamped.
        let mut mf = String::new();
        zip.by_name("manifest.json").unwrap().read_to_string(&mut mf).unwrap();
        let mj: serde_json::Value = serde_json::from_str(&mf).unwrap();
        let di = &mj["browser_action"]["default_icon"];
        assert!(di["48"].is_string(), "default_icon keeps 48px");
        assert!(di["16"].is_null(), "default_icon drops 16px (would be fuzzy at 24px)");
        assert_eq!(mj["version"].as_str().unwrap().split('.').count(), 4, "version stamped");
    }

    #[test]
    fn transform_manifest_trims_default_icon_and_stamps_version() {
        let src = br#"{"version":"1.2.3","browser_action":{"default_icon":{"16":"assets/toolbar-16.png","48":"assets/toolbar-48.png"},"default_popup":"popup.html"}}"#;
        let out = transform_manifest(src, 42);
        let m: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(m["version"], "1.2.3.42");
        assert_eq!(m["browser_action"]["default_icon"]["48"], "assets/toolbar-48.png");
        assert!(m["browser_action"]["default_icon"]["16"].is_null());
        assert_eq!(m["browser_action"]["default_popup"], "popup.html", "other keys preserved");
        // A manifest without a browser_action (the theme) just gets its version stamped.
        let theme = br#"{"version":"1.0.0","theme":{"colors":{}}}"#;
        let t: serde_json::Value = serde_json::from_slice(&transform_manifest(theme, 7)).unwrap();
        assert_eq!(t["version"], "1.0.0.7");
        assert!(t["theme"]["colors"].is_object());
    }

    // An unchanged XPI is left in place (mtime preserved) so Firefox doesn't
    // reinstall the add-on every launch; a content change rewrites it.
    #[test]
    fn xpi_not_rewritten_when_unchanged() {
        let p = TmpProfile::new();
        install_extension(&p.0).unwrap();
        let xpi = p.0.join("extensions").join(format!("{EXT_ID}.xpi"));
        let marker = p.0.join(format!(".{EXT_ID}.xpi.salt"));
        assert!(marker.exists(), "stamp sidecar written");
        let mtime1 = std::fs::metadata(&xpi).unwrap().modified().unwrap();

        std::thread::sleep(std::time::Duration::from_millis(40));
        install_extension(&p.0).unwrap(); // unchanged -> skipped
        let mtime2 = std::fs::metadata(&xpi).unwrap().modified().unwrap();
        assert_eq!(mtime1, mtime2, "unchanged XPI must not be rewritten");

        std::fs::write(&marker, "different").unwrap(); // simulate a content change
        std::thread::sleep(std::time::Duration::from_millis(40));
        install_extension(&p.0).unwrap(); // stamp mismatch -> rewritten
        let mtime3 = std::fs::metadata(&xpi).unwrap().modified().unwrap();
        assert_ne!(mtime2, mtime3, "changed content must rewrite the XPI");
    }

    // The size-list patch is defensive: only a lone `[16,48]` is rewritten.
    #[test]
    fn patch_wallet_icon_sizes_is_targeted() {
        assert_eq!(patch_wallet_icon_sizes(b"var M=[16,48],U={}").unwrap(), b"var M=[48],U={}");
        // Not present -> untouched (None).
        assert!(patch_wallet_icon_sizes(b"no sizes here").is_none());
        // Ambiguous (more than one) -> untouched, to avoid mis-patching.
        assert!(patch_wallet_icon_sizes(b"[16,48] and [16,48]").is_none());
    }

    // The spin patch injects a dot-less spin controller before `o` that starts at
    // init and preloads the base, a start/stop hook at the top of `o`'s generator
    // body, and suppresses the static dot for not-connected states. No-op w/o anchor.
    #[test]
    fn patch_wallet_boot_spin_injects_at_anchor() {
        let src = b"let c=null,a=\"\";const o=i=>g(this,void 0,void 0,(function*(){const o=null!=i?i:\"none\";if(o!==a){const r=i?U[i]:null}}))";
        let out = patch_wallet_boot_spin(src).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        // controller present, and the spin frame draws NO dot (bare mark)
        assert!(s.contains("setInterval(__ed,100)"));
        assert!(s.contains("t[z]=x.getImageData(0,0,z,z)"));
        assert!(!s.contains("U.boot"), "spin frame must not draw a dot");
        // starts at init and eagerly preloads the base cache
        assert!(s.contains("__el(),__es();"), "spin must start at module init");
        assert!(s.contains("e.runtime.getURL(\"assets/toolbar-\""), "must preload base bitmaps");
        // no leftover diagnostics
        assert!(!s.contains("EPIXSPIN"), "diagnostic dumps must be gone");
        // hook sits right after the generator opens: live status stops the spin
        assert!(s.contains("(function*(){(\"ready\"===i||\"routed\"===i)?__ex():__es();const o=null!=i?i:\"none\";"));
        // the static render only colours the dot once connected
        assert!(s.contains("const r=\"ready\"===i||\"routed\"===i?U[i]:null"));
        // original body is preserved after the hook
        assert!(s.contains("if(o!==a)"));
        // no anchor -> left untouched
        assert!(patch_wallet_boot_spin(b"nothing to see here").is_none());
    }

    // The .js pipeline chains both transforms: size list first, then the spin.
    #[test]
    fn patch_wallet_js_chains_sizes_then_spin() {
        let src = b"var M=[16,48];let c=null,a=\"\";const o=i=>g(this,void 0,void 0,(function*(){const o=null!=i?i:\"none\";}))";
        let out = patch_wallet_js(src);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.contains("M=[48]"), "icon-size patch should apply");
        assert!(s.contains("(\"ready\"===i||\"routed\"===i)?__ex():__es();"), "spin patch should apply");
        // A file matching neither pattern passes through byte-for-byte.
        let plain = b"function unrelated(){return 1}";
        assert_eq!(patch_wallet_js(plain), plain);
    }

    // The background page gains the URL-bar address script, after the polyfill
    // and before the wallet's own bundles; a changed page is left untouched.
    #[test]
    fn patch_background_html_inserts_urlbar_script() {
        let src = b"<html><head><script src=\"browser-polyfill.js\"></script><script defer=\"defer\" src=\"background.bundle.js\"></script></head></html>";
        let out = patch_background_html(src).unwrap();
        let s = std::str::from_utf8(&out).unwrap();
        let poly = s.find("browser-polyfill.js").unwrap();
        let urlbar = s.find("epix-urlbar.js").unwrap();
        let bundle = s.find("background.bundle.js").unwrap();
        assert!(poly < urlbar && urlbar < bundle, "script order polyfill < urlbar < bundles: {s}");
        // No anchor -> untouched.
        assert!(patch_background_html(b"<html>changed build</html>").is_none());
        // The injected script only rewrites bech32-address searches.
        let js = std::str::from_utf8(EPIX_URLBAR_JS).unwrap();
        assert!(js.contains("duckduckgo.com"), "scoped to the managed default engine");
        assert!(js.contains("main_frame"), "only top-level navigations");
        assert!(js.contains("^epix1[a-z0-9]{20,80}$"), "exact bech32 query match");
    }

    // The packed wallet XPI carries the URL-bar script and loads it from the
    // background page.
    #[test]
    fn install_extension_packs_urlbar_script() {
        let p = TmpProfile::new();
        std::fs::create_dir_all(&p.0).unwrap();
        install_extension(&p.0).unwrap();
        let xpi = p.0.join("extensions").join(format!("{EXT_ID}.xpi"));
        let file = std::fs::File::open(&xpi).unwrap();
        let mut zip = zip::ZipArchive::new(file).unwrap();
        {
            let mut entry = zip.by_name("epix-urlbar.js").expect("epix-urlbar.js packed");
            let mut js = String::new();
            std::io::Read::read_to_string(&mut entry, &mut js).unwrap();
            assert!(js.contains("onBeforeRequest"), "intercept registered: {js}");
        }
        let mut entry = zip.by_name("background.html").expect("background page present");
        let mut html = String::new();
        std::io::Read::read_to_string(&mut entry, &mut html).unwrap();
        assert!(html.contains("epix-urlbar.js"), "background page loads the script: {html}");
    }
}
