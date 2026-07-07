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
//! `shells/wallet-ext` is a build artifact (gitignored): produce it with the
//! wallet's `yarn build` and stage it before compiling this crate (see
//! `shells/README.md`). A committed placeholder keeps a fresh checkout building.

use include_dir::{include_dir, Dir};
use std::io::Write;
use std::path::{Path, PathBuf};

/// The wallet extension files, embedded at build time.
static EXT: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../shells/wallet-ext");

/// The starter chrome theme, embedded at build time.
static THEME: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../../shells/browser-theme");

/// The extension id (must match the wallet `manifest.json`'s Firefox gecko id).
pub const EXT_ID: &str = "wallet@epix.zone";
/// The native-messaging host name (must match the wallet's native bridge).
pub const NMH_NAME: &str = "zone.epix.nmh";

/// Write the extension as an XPI into the profile's `extensions/` dir. Firefox
/// installs it on startup (with the unsigned-extensions pref, on ESR/Developer).
pub fn install_extension(profile: &Path) -> Result<(), String> {
    let ext_dir = profile.join("extensions");
    std::fs::create_dir_all(&ext_dir).map_err(|e| format!("extensions dir: {e}"))?;
    let xpi_path = ext_dir.join(format!("{EXT_ID}.xpi"));

    let file = std::fs::File::create(&xpi_path).map_err(|e| format!("create xpi: {e}"))?;
    let mut zip = zip::ZipWriter::new(file);
    let opts: zip::write::FileOptions<'_, ()> =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    write_dir_to_zip(&mut zip, &EXT, "", &opts)?;
    zip.finish().map_err(|e| format!("finish xpi: {e}"))?;
    Ok(())
}

fn write_dir_to_zip(
    zip: &mut zip::ZipWriter<std::fs::File>,
    dir: &Dir,
    prefix: &str,
    opts: &zip::write::FileOptions<'_, ()>,
) -> Result<(), String> {
    for file in dir.files() {
        let name = file.path().file_name().unwrap().to_string_lossy();
        let entry = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        zip.start_file(&entry, *opts).map_err(|e| format!("zip entry {entry}: {e}"))?;
        zip.write_all(file.contents()).map_err(|e| format!("zip write {entry}: {e}"))?;
    }
    for sub in dir.dirs() {
        let name = sub.path().file_name().unwrap().to_string_lossy();
        let p = if prefix.is_empty() { name.to_string() } else { format!("{prefix}/{name}") };
        write_dir_to_zip(zip, sub, &p, opts)?;
    }
    Ok(())
}

/// Install the starter chrome theme into `<profile>/chrome/`, but only files
/// that don't exist yet - so a user's edits to userChrome.css survive relaunch.
pub fn install_theme(profile: &Path) -> Result<(), String> {
    let chrome = profile.join("chrome");
    std::fs::create_dir_all(&chrome).map_err(|e| format!("chrome dir: {e}"))?;
    for file in THEME.files() {
        let name = file.path().file_name().unwrap();
        let dest = chrome.join(name);
        if !dest.exists() {
            std::fs::write(&dest, file.contents())
                .map_err(|e| format!("write {}: {e}", dest.display()))?;
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
    // Small hand-rolled JSON to avoid a serde_json dep here.
    format!(
        "{{\n  \"name\": \"{NMH_NAME}\",\n  \"description\": \"Epix native messaging host\",\n  \"path\": \"{}\",\n  \"type\": \"stdio\",\n  \"allowed_extensions\": [\"{EXT_ID}\"]\n}}\n",
        nmh.display()
    )
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
