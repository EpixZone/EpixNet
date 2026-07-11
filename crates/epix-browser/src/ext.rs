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

/// The extension id (must match the wallet `manifest.json`'s Firefox gecko id).
pub const EXT_ID: &str = "wallet@epix.zone";
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
    let ext_dir = profile.join("extensions");
    std::fs::create_dir_all(&ext_dir).map_err(|e| format!("extensions dir: {e}"))?;
    let xpi_path = ext_dir.join(format!("{EXT_ID}.xpi"));

    let salt = ext_content_hash(&EXT);
    let file = std::fs::File::create(&xpi_path).map_err(|e| format!("create xpi: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    write_dir_to_zip(&mut zip, &EXT, "", &opts, salt)?;
    zip.finish().map_err(|e| format!("finish xpi: {e}"))?;
    Ok(())
}

/// A stable short hash of every embedded extension file (path + contents), used
/// as a build-identifying version salt.
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

/// Rewrite `manifest.json`'s `"version": "X.Y.Z"` to `"X.Y.Z.<salt>"` so the
/// add-on version tracks the build.
fn stamp_manifest_version(contents: &[u8], salt: u32) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(contents) else { return contents.to_vec() };
    let needle = "\"version\":";
    let Some(vpos) = text.find(needle) else { return contents.to_vec() };
    let after = &text[vpos + needle.len()..];
    // Find the value string: first quote, then the closing quote.
    let Some(q1) = after.find('"') else { return contents.to_vec() };
    let rest = &after[q1 + 1..];
    let Some(q2) = rest.find('"') else { return contents.to_vec() };
    let version = &rest[..q2];
    let stamped = format!("{version}.{salt}");
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
    salt: u32,
) -> Result<(), String> {
    for file in dir.files() {
        let name = file.path().file_name().unwrap().to_string_lossy();
        let entry = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        zip.start_file(&entry, *opts).map_err(|e| format!("zip entry {entry}: {e}"))?;
        // Stamp only the root manifest so the add-on version tracks the build.
        if entry == "manifest.json" {
            let stamped = stamp_manifest_version(file.contents(), salt);
            zip.write_all(&stamped).map_err(|e| format!("zip write {entry}: {e}"))?;
        } else {
            zip.write_all(file.contents()).map_err(|e| format!("zip write {entry}: {e}"))?;
        }
    }
    for sub in dir.dirs() {
        let name = sub.path().file_name().unwrap().to_string_lossy();
        let p = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        write_dir_to_zip(zip, sub, &p, opts, salt)?;
    }
    Ok(())
}

/// Install the chrome theme into `<profile>/chrome/`. The editable starter
/// sheets (userChrome.css, userContent.css) are written only when absent so a
/// user's edits survive; `epix-managed.css` (hide dead chrome, size the wallet
/// button) is rewritten every launch and `@import`ed from userChrome.css, so
/// those managed rules always land, including on pre-existing profiles.
pub fn install_theme(profile: &Path) -> Result<(), String> {
    let chrome = profile.join("chrome");
    std::fs::create_dir_all(&chrome).map_err(|e| format!("chrome dir: {e}"))?;
    const MANAGED: &str = "epix-managed.css";
    for file in THEME.files() {
        let name = file.path().file_name().unwrap();
        let dest = chrome.join(name);
        // Always refresh the managed sheet; write the editable ones only once.
        if name == std::ffi::OsStr::new(MANAGED) || !dest.exists() {
            std::fs::write(&dest, file.contents())
                .map_err(|e| format!("write {}: {e}", dest.display()))?;
        }
    }
    // Ensure userChrome.css pulls in the managed rules. A profile created before
    // epix-managed.css existed has a userChrome.css without the import; prepend
    // it (an `@import` is valid at the very top, ahead of the comment).
    let uc = chrome.join("userChrome.css");
    if let Ok(s) = std::fs::read_to_string(&uc) {
        if !s.contains(MANAGED) {
            let _ = std::fs::write(&uc, format!("@import \"{MANAGED}\";\n{s}"));
        }
    }
    Ok(())
}

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
    let exe = std::env::current_exe().ok()?;
    let sibling = exe.parent()?.join(if cfg!(windows) { "epix-nmh.exe" } else { "epix-nmh" });
    sibling.exists().then_some(sibling)
}
