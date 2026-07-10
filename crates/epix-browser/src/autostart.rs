//! Cross-platform "open at login" for the desktop launcher.
//!
//! Registers EpixNet to start with the OS in `--background` mode: the node and
//! the tray come up, but no browser window - the user opens it from the tray
//! when they want it. macOS uses a LaunchAgent plist, Windows the per-user Run
//! registry key, Linux an XDG autostart `.desktop` entry.
//!
//! Everything here is best-effort and per-user (no admin). The tray reads the
//! real state back with [`is_enabled`], so a failed write just leaves the
//! toggle where it was.

#[cfg(not(target_os = "windows"))]
use std::path::PathBuf;

/// Identifier used for the login item across platforms.
const LABEL: &str = "zone.epix.EpixNet";

/// The launcher executable, or an error if it can't be found.
fn exe() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("current_exe: {e}"))
}

// ---------------------------------------------------------------- macOS -----
#[cfg(target_os = "macos")]
fn plist_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME not set")?;
    Ok(PathBuf::from(home).join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
}

#[cfg(target_os = "macos")]
pub fn is_enabled() -> bool {
    plist_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(target_os = "macos")]
pub fn set_enabled(on: bool) -> Result<(), String> {
    let path = plist_path()?;
    if !on {
        // Missing is fine (already off).
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("remove plist: {e}"))?;
        }
        return Ok(());
    }
    let exe = exe()?;
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>--background</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
</dict>
</plist>
"#,
        exe.display()
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create LaunchAgents: {e}"))?;
    }
    std::fs::write(&path, plist).map_err(|e| format!("write plist: {e}"))
}

// -------------------------------------------------------------- Windows -----
#[cfg(target_os = "windows")]
fn run_key() -> Result<winreg::RegKey, String> {
    use winreg::enums::HKEY_CURRENT_USER;
    winreg::RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            winreg::enums::KEY_READ | winreg::enums::KEY_WRITE,
        )
        .map_err(|e| format!("open Run key: {e}"))
}

#[cfg(target_os = "windows")]
pub fn is_enabled() -> bool {
    run_key().ok().and_then(|k| k.get_value::<String, _>("EpixNet").ok()).is_some()
}

#[cfg(target_os = "windows")]
pub fn set_enabled(on: bool) -> Result<(), String> {
    let key = run_key()?;
    if !on {
        match key.delete_value("EpixNet") {
            Ok(()) => Ok(()),
            // Already absent is success.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("delete Run value: {e}")),
        }
    } else {
        let exe = exe()?;
        let cmd = format!("\"{}\" --background", exe.display());
        key.set_value("EpixNet", &cmd).map_err(|e| format!("set Run value: {e}"))
    }
}

// ---------------------------------------------------------------- Linux -----
#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_path() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or("HOME/XDG_CONFIG_HOME not set")?;
    Ok(base.join("autostart").join("epixnet.desktop"))
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn is_enabled() -> bool {
    desktop_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn set_enabled(on: bool) -> Result<(), String> {
    let path = desktop_path()?;
    if !on {
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("remove autostart: {e}"))?;
        }
        return Ok(());
    }
    let exe = exe()?;
    let desktop = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=EpixNet\n\
         Exec={} --background\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        exe.display()
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create autostart dir: {e}"))?;
    }
    std::fs::write(&path, desktop).map_err(|e| format!("write autostart: {e}"))
}
