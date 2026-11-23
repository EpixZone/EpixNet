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
//!
//! A launch with `--data-dir` (or `EPIX_DATA_DIR`) writes that folder into the
//! login item too, because a login session has neither. The default folder,
//! including one moved on the Config page, needs no argument.

#[cfg(not(target_os = "windows"))]
use std::path::PathBuf;
use std::path::Path;
use std::sync::OnceLock;

/// LaunchAgent label (macOS). Windows uses the "EpixNet" Run value name and
/// Linux the `epixnet.desktop` filename instead.
#[cfg(any(target_os = "macos", test))]
const LABEL: &str = "zone.epix.EpixNet";

/// The data folder this instance was started with, when not the default.
static DATA_DIR: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Remember the data folder chosen at launch, so the login item this instance
/// writes reopens the same folder.
pub fn use_data_dir(folder: std::path::PathBuf) {
    let _ = DATA_DIR.set(folder);
}

/// What a login item passes after the launcher path.
fn login_arguments(data_dir: Option<&Path>) -> Result<Vec<String>, String> {
    let mut arguments = vec!["--background".to_string()];
    if let Some(folder) = data_dir {
        let folder = folder.to_str().ok_or("Autostart data folder must be valid UTF-8")?;
        if folder.chars().any(char::is_control) {
            return Err("Autostart data folder must not contain control characters".into());
        }
        arguments.extend(["--data-dir".to_string(), folder.to_string()]);
    }
    Ok(arguments)
}

/// The launcher executable, so the login item relaunches this same binary.
/// Only ever written into a per-user autostart entry, never used for a trust or
/// privilege decision.
fn exe() -> Result<std::path::PathBuf, String> {
    // nosemgrep: rust.lang.security.current-exe.current-exe
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
    let exe = exe.to_str().ok_or("Autostart path must be valid UTF-8")?;
    let plist = launch_agent_plist(exe, &login_arguments(DATA_DIR.get().map(PathBuf::as_path))?);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create LaunchAgents: {e}"))?;
    }
    std::fs::write(&path, plist).map_err(|e| format!("write plist: {e}"))
}

#[cfg(any(target_os = "macos", test))]
fn launch_agent_plist(exe: &str, arguments: &[String]) -> String {
    let xml = |value: &str| {
        value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    };
    let program: String = std::iter::once(exe)
        .chain(arguments.iter().map(String::as_str))
        .map(|value| format!("    <string>{}</string>\n", xml(value)))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{program}  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
</dict>
</plist>
"#
    )
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
        let arguments = login_arguments(DATA_DIR.get().map(std::path::PathBuf::as_path))?;
        let cmd = run_command(&exe.display().to_string(), &arguments);
        key.set_value("EpixNet", &cmd).map_err(|e| format!("set Run value: {e}"))
    }
}

/// The Run value: the quoted launcher, then each argument, quoted when it
/// needs it. Backslashes before a quote are doubled, as the C runtime's
/// command-line parser expects, so `C:\data\` stays one argument.
#[cfg(any(target_os = "windows", test))]
fn run_command(exe: &str, arguments: &[String]) -> String {
    let mut command = format!("\"{exe}\"");
    for argument in arguments {
        command.push(' ');
        if !argument.is_empty() && !argument.contains([' ', '\t', '"']) {
            command.push_str(argument);
            continue;
        }
        command.push('"');
        let mut backslashes = 0;
        for ch in argument.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    command.push_str(&"\\".repeat(backslashes * 2 + 1));
                    command.push('"');
                    backslashes = 0;
                }
                _ => {
                    command.push_str(&"\\".repeat(backslashes));
                    command.push(ch);
                    backslashes = 0;
                }
            }
        }
        command.push_str(&"\\".repeat(backslashes * 2));
        command.push('"');
    }
    command
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

/// The temporary directory names used by the bundled AppImage runtime.
/// AppRun also sets APPDIR for manually extracted bundles, so containment
/// alone cannot distinguish those from an inherited APPIMAGE variable.
#[cfg(all(unix, not(target_os = "macos")))]
fn appimage_directory(path: &std::path::Path) -> Option<bool> {
    let name = path.file_name()?.to_str()?;
    if name.strip_prefix(".mount_").is_some_and(|s| !s.is_empty()) {
        return Some(false);
    }
    let hash = name.strip_prefix("appimage_extracted_")?;
    (hash.len() == 32 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some(true)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_launcher() -> Result<(PathBuf, bool), String> {
    let current = exe()?;
    let Some(appdir) = std::env::var_os("APPDIR").map(PathBuf::from) else {
        return Ok((current, false));
    };
    let Some(extracted) = appimage_directory(&appdir) else {
        return Ok((current, false));
    };
    // Ignore runtime variables inherited by a separate native installation.
    let in_appdir = appdir.is_absolute()
        && appdir.canonicalize().ok().is_some_and(|dir| current.starts_with(dir));
    if !in_appdir {
        return Ok((current, false));
    }
    let image = std::env::var_os("APPIMAGE").map(PathBuf::from).ok_or("APPIMAGE not set")?;
    use std::os::unix::fs::PermissionsExt;
    if !image.is_absolute()
        || !image.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    {
        return Err("APPIMAGE must name an existing, executable absolute file".into());
    }
    // The runtime consumes --appimage-extract-and-run without setting the
    // equivalent environment variable. Its extraction directory preserves
    // that choice for the next login, including on systems without FUSE.
    Ok((image, extracted || std::env::var_os("APPIMAGE_EXTRACT_AND_RUN").is_some()))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_argument(value: &str) -> String {
    let mut escaped = String::from("\"");
    for ch in value.chars() {
        match ch {
            // Escape both the desktop string and Exec argument layers.
            '\\' => escaped.push_str(r"\\\\"),
            '"' => escaped.push_str(r#"\\""#),
            '$' => escaped.push_str(r"\\$"),
            '`' => escaped.push_str(r"\\`"),
            '%' => escaped.push_str("%%"),
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

/// Repair only the old, exact generated entry pointing into a temporary
/// AppImage directory. Missing, disabled, symlinked and customized entries
/// retain the user's choices.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn refresh_enabled() -> Result<(), String> {
    let path = desktop_path()?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("read autostart metadata: {e}")),
    };
    if !metadata.file_type().is_file() {
        return Ok(());
    }
    let entry = std::fs::read_to_string(&path).map_err(|e| format!("read autostart: {e}"))?;
    let Some(old) = entry
        .strip_prefix("[Desktop Entry]\nType=Application\nName=EpixNet\nExec=\"")
        .and_then(|s| s.strip_suffix("\" --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"))
    else {
        return Ok(());
    };
    if old.chars().any(char::is_control) || old.contains('"') {
        return Ok(());
    }
    let old = std::path::Path::new(old);
    if old.is_absolute() && old.ends_with("usr/bin/epix-browser") {
        if let Some(dir) = old.ancestors().nth(3) {
            if appimage_directory(dir).is_some() {
                // Old entries never named a data folder; keep it that way.
                write_desktop_entry(&path, None)?;
            }
        }
    }
    Ok(())
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
    write_desktop_entry(&path, DATA_DIR.get().map(PathBuf::as_path))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn write_desktop_entry(path: &Path, data_dir: Option<&Path>) -> Result<(), String> {
    let arguments = login_arguments(data_dir)?;
    let (launcher, extract) = linux_launcher()?;
    let launcher = launcher.to_str().ok_or("Autostart path must be valid UTF-8")?;
    if launcher.chars().any(char::is_control) {
        return Err("Autostart path must not contain control characters".into());
    }
    // A fixed executable avoids GIO treating a literal percent in argv[0]
    // as a field code. Unlike `env`, the shell also accepts paths with '='.
    // The pathname is a separate argument, never part of the shell program.
    let script = if extract {
        r#"export APPIMAGE_EXTRACT_AND_RUN=1; exec "$0" "$@""#
    } else {
        r#"exec "$0" "$@""#
    };
    let exec: Vec<String> = [desktop_argument(script), desktop_argument(launcher)]
        .into_iter()
        .chain(arguments.iter().map(|argument| desktop_argument(argument)))
        .collect();
    let desktop = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=EpixNet\n\
         Exec=/bin/sh -c {}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        exec.join(" ")
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create autostart dir: {e}"))?;
    }
    std::fs::write(path, desktop).map_err(|e| format!("write autostart: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_arguments_add_only_a_chosen_data_folder() {
        assert_eq!(login_arguments(None).unwrap(), ["--background"]);
        assert_eq!(
            login_arguments(Some(Path::new("/srv/epix data"))).unwrap(),
            ["--background", "--data-dir", "/srv/epix data"]
        );
        assert!(login_arguments(Some(Path::new("/bad\nfolder"))).is_err());
    }

    #[test]
    fn run_command_keeps_each_folder_one_argument() {
        let exe = r"C:\Users\me\AppData\Local\Epix\epix-browser.exe";
        let run = |folder: &str| {
            run_command(exe, &login_arguments(Some(Path::new(folder))).unwrap())
        };
        assert_eq!(
            run_command(exe, &login_arguments(None).unwrap()),
            format!("\"{exe}\" --background")
        );
        assert_eq!(run(r"D:\EpixData"), format!(r#""{exe}" --background --data-dir D:\EpixData"#));
        assert_eq!(
            run(r"D:\Epix Data\"),
            format!(r#""{exe}" --background --data-dir "D:\Epix Data\\""#)
        );
        assert_eq!(
            run(r"D:\a b\c"),
            format!(r#""{exe}" --background --data-dir "D:\a b\c""#)
        );
    }

    #[test]
    fn launch_agent_lists_each_argument_and_escapes_xml() {
        let plist = launch_agent_plist(
            "/Applications/Epix.app/Contents/MacOS/epix-browser",
            &login_arguments(Some(Path::new("/Users/me/R&D <data>"))).unwrap(),
        );
        assert!(plist.contains(
            "    <string>/Applications/Epix.app/Contents/MacOS/epix-browser</string>\n    \
             <string>--background</string>\n    <string>--data-dir</string>\n    \
             <string>/Users/me/R&amp;D &lt;data&gt;</string>\n  </array>"
        ), "{plist}");
    }
}
