//! Data-root resolution for a desktop node. The default location is the
//! conventional per-OS application-data directory, and the user can point the
//! node somewhere else with a `data_dir` entry in `<default>/epixnet.conf` -
//! the same file and key the Python client uses, so a customized Python
//! install carries over.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// Resolve an operator-selected data directory, including a not-yet-created
/// suffix. Resolve symlinks in the existing prefix before overlap checks. Never
/// accept parent traversal or control characters that could inject INI entries.
pub(crate) fn resolve_data_directory(path: &Path) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};

    if !path.is_absolute()
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || path
            .as_os_str()
            .to_string_lossy()
            .chars()
            .any(char::is_control)
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "The data directory must be an absolute path without '..' or control characters",
        ));
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {
                let mut resolved = ancestor.canonicalize()?;
                if !resolved.is_dir() {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "The data directory is not a directory",
                    ));
                }
                for name in suffix.into_iter().rev() {
                    resolved.push(name);
                }
                return Ok(resolved);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                suffix.push(ancestor.file_name().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "The data directory has no existing parent",
                    )
                })?);
                ancestor = ancestor.parent().ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        "The data directory has no existing parent",
                    )
                })?;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The conventional per-OS data root: `~/Library/Application Support/EpixNet`
/// on macOS, `%APPDATA%\EpixNet` on Windows, `$XDG_DATA_HOME/EpixNet` or
/// `~/.local/share/EpixNet` on Linux. Ignores any user override - this is
/// where `epixnet.conf` itself lives.
pub fn default_data_root() -> PathBuf {
    let base = if cfg!(target_os = "macos") {
        home().join("Library/Application Support")
    } else if cfg!(target_os = "windows") {
        std::env::var("APPDATA").map(PathBuf::from).unwrap_or_else(|_| home().join("AppData/Roaming"))
    } else {
        std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home().join(".local/share"))
    };
    base.join("EpixNet")
}

/// The effective data root: `EPIX_DATA_DIR` if set (tests, extra nodes), else
/// a portable copy's `Data` folder, else the `data_dir` configured in
/// `<default>/epixnet.conf`, else the default.
pub fn data_root() -> PathBuf {
    if let Ok(dir) = std::env::var("EPIX_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(portable) = portable_data_root() {
        return portable;
    }
    let default = default_data_root();
    read_conf_data_dir(&default.join("epixnet.conf")).unwrap_or(default)
}

/// A file that turns on portable mode when it sits beside the executable.
pub const PORTABLE_MARKER: &str = "epixnet-portable.txt";

/// The folder a portable copy keeps its data in, beside the marker.
pub const PORTABLE_DATA_DIR: &str = "Data";

/// The `Data` folder of a portable copy: the executable's folder holds
/// [`PORTABLE_MARKER`]. Windows only, where the portable zip ships. On Linux
/// the AppImage's own portable home folder covers this.
pub fn portable_data_root() -> Option<PathBuf> {
    if !cfg!(windows) {
        return None;
    }
    // Locating our own files, not a trust decision: current_exe comes from
    // the kernel, and whoever can write beside it already runs as this user.
    // nosemgrep: rust.lang.security.current-exe.current-exe
    let exe = std::env::current_exe().ok()?;
    portable_data_root_in(exe.parent()?)
}

fn portable_data_root_in(folder: &Path) -> Option<PathBuf> {
    folder
        .join(PORTABLE_MARKER)
        .is_file()
        .then(|| folder.join(PORTABLE_DATA_DIR))
}

/// Where a launch keeps its data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchDataDir {
    /// The per-user default, or the folder a Config page move saved.
    Default,
    /// A folder named with `--data-dir` or `EPIX_DATA_DIR`.
    Chosen(PathBuf),
    /// The `Data` folder of a portable copy.
    Portable(PathBuf),
}

/// The launch option that picks a data folder, like `EPIX_DATA_DIR`.
pub const DATA_DIR_OPTION: &str = "--data-dir";

/// Remove `--data-dir <folder>` or `--data-dir=<folder>` from launch
/// arguments and return the folder. With `leading_only`, only options before
/// the first other argument count, so an action's own arguments keep their
/// meaning. Giving the option twice, or without a folder, is an error.
pub fn take_data_dir_option(
    args: &mut Vec<std::ffi::OsString>,
    leading_only: bool,
) -> Result<Option<PathBuf>, String> {
    let missing = || format!("{DATA_DIR_OPTION} requires a folder path");
    let mut found = None;
    let mut index = 0;
    while index < args.len() {
        let inline = args[index]
            .to_str()
            .and_then(|arg| arg.strip_prefix(DATA_DIR_OPTION))
            .and_then(|rest| rest.strip_prefix('='))
            .map(std::ffi::OsString::from);
        let value = if args[index] == DATA_DIR_OPTION {
            if index + 1 == args.len() {
                return Err(missing());
            }
            let value = args.remove(index + 1);
            args.remove(index);
            value
        } else if let Some(value) = inline {
            args.remove(index);
            value
        } else if leading_only {
            break;
        } else {
            index += 1;
            continue;
        };
        // A following option is a forgotten folder, not a folder named "--x".
        if value.is_empty() || value.to_string_lossy().starts_with('-') {
            return Err(missing());
        }
        if found.replace(PathBuf::from(value)).is_some() {
            return Err(format!("Specify {DATA_DIR_OPTION} only once"));
        }
    }
    Ok(found)
}

/// Select this launch's data folder: a `--data-dir` folder, else
/// `EPIX_DATA_DIR`, else a portable copy's `Data` folder, else the default
/// (which a Config page move may have relocated). A chosen or portable folder
/// is exported as an absolute `EPIX_DATA_DIR`, so every child process uses
/// the same folder: the browser handoff, the wallet's native host and a
/// restart. Call it before the process starts any thread, because it changes
/// the environment.
pub fn apply_launch_data_dir(option: Option<PathBuf>) -> Result<LaunchDataDir, String> {
    let chosen = option.or_else(|| {
        std::env::var_os("EPIX_DATA_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    });
    let portable = portable_data_root();
    let (folder, is_portable) = match chosen {
        Some(folder) => {
            let absolute = std::path::absolute(&folder)
                .map_err(|e| format!("Cannot use data folder {}: {e}", folder.display()))?;
            // A restart inherits the portable folder as EPIX_DATA_DIR.
            let is_portable = portable.as_ref() == Some(&absolute);
            (absolute, is_portable)
        }
        None => match portable {
            Some(portable) => (portable, true),
            None => return Ok(LaunchDataDir::Default),
        },
    };
    std::env::set_var("EPIX_DATA_DIR", &folder);
    Ok(if is_portable {
        LaunchDataDir::Portable(folder)
    } else {
        LaunchDataDir::Chosen(folder)
    })
}

/// The default location's `epixnet.conf` - the same file the Python client
/// keeps its settings in, so a customized Python install carries over. This is
/// always in the default data root, even when that file's own `data_dir` key
/// relocates everything else.
pub fn default_conf_path() -> PathBuf {
    default_data_root().join("epixnet.conf")
}

/// Every `key = value` assignment in an epixnet.conf. The file is Python
/// configparser INI (`[section]` headers and `#`/`;` comments ignored); values
/// are trimmed and empties dropped. On a duplicate key the last wins, matching
/// configparser (Python EpixNet writes `language` twice, for instance).
pub fn read_conf(conf: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(conf) else { return map };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[')
        {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let (key, value) = (key.trim(), value.trim());
            if !key.is_empty() && !value.is_empty() {
                map.insert(key.to_string(), value.to_string());
            }
        }
    }
    map
}

/// The value of `key` in an epixnet.conf, if present and non-empty.
pub fn read_conf_value(conf: &Path, key: &str) -> Option<String> {
    read_conf(conf).remove(key)
}

/// The `data_dir` value in an epixnet.conf, if present. The Python client uses
/// this key to relocate the data root.
pub fn read_conf_data_dir(conf: &Path) -> Option<PathBuf> {
    read_conf_value(conf, "data_dir").map(PathBuf::from)
}

/// Delete the assignment lines for `keys` from an epixnet.conf, preserving every
/// other line (comments, `[section]` headers, blank lines, and every other
/// key). Used once a value has been migrated into config.json, so the stale INI
/// entry can't shadow it and a later hand-edit of the moved key can't confuse.
/// A missing file is a no-op success.
pub fn remove_conf_keys(conf: &Path, keys: &[&str]) -> std::io::Result<()> {
    let text = match std::fs::read_to_string(conf) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| match line.trim().split_once('=') {
            Some((key, _)) => !keys.contains(&key.trim()),
            None => true, // comments, section headers, blank lines
        })
        .collect();
    std::fs::write(conf, kept.join("\n") + "\n")
}

/// Set (or with `None`, remove) the `data_dir` entry in an epixnet.conf,
/// preserving every other line. Creates the file with the Python client's
/// header if it doesn't exist.
pub fn write_conf_data_dir(conf: &Path, dir: Option<&Path>) -> std::io::Result<()> {
    let text = crate::data_relocation::read_config(conf)?.unwrap_or_default();
    crate::data_relocation::atomic_write_config(conf, render_conf_data_dir(&text, dir).as_bytes())
}

pub(crate) fn render_conf_data_dir(text: &str, dir: Option<&Path>) -> String {
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| l.trim().split_once('=').map(|(k, _)| k.trim()) != Some("data_dir"))
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        lines.push("# epixnet config file".to_string());
    }
    if let Some(dir) = dir {
        if !lines.iter().any(|l| l.trim() == "[global]") {
            lines.push("[global]".to_string());
        }
        let at = lines.iter().position(|l| l.trim() == "[global]").unwrap() + 1;
        lines.insert(at, format!("data_dir = {}", dir.display()));
    }
    lines.join("\n") + "\n"
}

fn home() -> PathBuf {
    // Last resort for a degenerate environment (HOME and USERPROFILE both
    // unset): the working directory, NOT the temp dir - the data root holds
    // the node's private keys, which must not live somewhere world-shared
    // and wiped on reboot. Operators in such environments set EPIX_DATA_DIR.
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_directory_resolves_missing_suffix_and_rejects_unsafe_input() {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_data_directory(&root.path().join("new/nested")).unwrap(),
            root.path().canonicalize().unwrap().join("new/nested")
        );
        for input in [
            PathBuf::from("relative"),
            root.path().join("../other"),
            root.path().join("bad\nui_ip=0.0.0.0"),
            root.path().join("bad\rname"),
            root.path().join("bad\0name"),
        ] {
            assert!(resolve_data_directory(&input).is_err(), "{input:?}");
        }
        let file = root.path().join("file");
        std::fs::write(&file, b"existing").unwrap();
        assert!(resolve_data_directory(&file).is_err());
        assert!(resolve_data_directory(&file.join("child")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn data_directory_resolves_aliases_and_rejects_dangling_links() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let actual = root.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        let alias = root.path().join("alias");
        symlink(&actual, &alias).unwrap();
        assert_eq!(
            resolve_data_directory(&alias.join("new")).unwrap(),
            actual.canonicalize().unwrap().join("new")
        );
        let dangling = root.path().join("dangling");
        symlink(root.path().join("missing"), &dangling).unwrap();
        assert!(resolve_data_directory(&dangling).is_err());
    }

    #[test]
    fn conf_data_dir_round_trips_and_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("epixnet.conf");
        // The Python client's file shape survives a set + clear.
        std::fs::write(&conf, "# epixnet config file\n[global]\nfileserver_port = 20790").unwrap();
        assert_eq!(read_conf_data_dir(&conf), None);

        write_conf_data_dir(&conf, Some(Path::new("/somewhere/else"))).unwrap();
        assert_eq!(read_conf_data_dir(&conf), Some(PathBuf::from("/somewhere/else")));
        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(text.contains("fileserver_port = 20790"), "other keys kept: {text}");

        // Setting again replaces rather than duplicates; None removes.
        write_conf_data_dir(&conf, Some(Path::new("/third"))).unwrap();
        assert_eq!(std::fs::read_to_string(&conf).unwrap().matches("data_dir").count(), 1);
        write_conf_data_dir(&conf, None).unwrap();
        assert_eq!(read_conf_data_dir(&conf), None);
    }

    #[test]
    fn conf_created_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("epixnet.conf");
        write_conf_data_dir(&conf, Some(Path::new("/data/root"))).unwrap();
        assert_eq!(read_conf_data_dir(&conf), Some(PathBuf::from("/data/root")));
        assert!(std::fs::read_to_string(&conf).unwrap().starts_with("# epixnet config file"));
    }

    #[test]
    fn default_root_ends_with_epixnet() {
        assert!(default_data_root().ends_with("EpixNet"));
    }

    #[test]
    fn read_conf_parses_python_ini_keys() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("epixnet.conf");
        // The shape Python EpixNet writes: header comment, [global], and a mix
        // of keys - including `language` twice (configparser keeps the last).
        std::fs::write(
            &conf,
            "# epixnet config file\n[global]\nlanguage = en\ntor=always\n\
             fileserver_port=48333\n; a comment\nlanguage=fr\n",
        )
        .unwrap();
        let map = read_conf(&conf);
        assert_eq!(read_conf_value(&conf, "tor").as_deref(), Some("always"));
        assert_eq!(map.get("fileserver_port").map(String::as_str), Some("48333"));
        assert_eq!(map.get("language").map(String::as_str), Some("fr"), "last duplicate wins");
        assert_eq!(read_conf_value(&conf, "absent"), None);
        // A missing file is an empty map, never an error.
        assert!(read_conf(&dir.path().join("nope.conf")).is_empty());
    }

    #[test]
    fn remove_conf_keys_drops_only_named_keys() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("epixnet.conf");
        std::fs::write(
            &conf,
            "# epixnet config file\n[global]\ntor=always\ndata_dir = /keep/me\n\
             fileserver_port=48333\nui_port=42222\n",
        )
        .unwrap();
        remove_conf_keys(&conf, &["tor", "fileserver_port"]).unwrap();
        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(!text.contains("tor="), "migrated key removed: {text}");
        assert!(!text.contains("fileserver_port"), "migrated key removed: {text}");
        // Everything else is preserved: comment, header, still-used keys.
        assert!(text.contains("# epixnet config file"));
        assert!(text.contains("[global]"));
        assert!(text.contains("data_dir = /keep/me"));
        assert!(text.contains("ui_port=42222"));
        // A missing file is a no-op success.
        remove_conf_keys(&dir.path().join("nope.conf"), &["tor"]).unwrap();
    }

    #[test]
    fn portable_marker_puts_data_beside_the_executable() {
        let folder = tempfile::tempdir().unwrap();
        assert_eq!(portable_data_root_in(folder.path()), None);
        // A folder of that name is not the marker.
        std::fs::create_dir(folder.path().join(PORTABLE_MARKER)).unwrap();
        assert_eq!(portable_data_root_in(folder.path()), None);
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join(PORTABLE_MARKER), b"portable").unwrap();
        assert_eq!(
            portable_data_root_in(other.path()),
            Some(other.path().join("Data"))
        );
    }

    fn os_args(args: &[&str]) -> Vec<std::ffi::OsString> {
        args.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn data_dir_option_is_removed_in_both_spellings() {
        for (input, rest) in [
            (&["--data-dir", "/n", "dashboard.epix"][..], &["dashboard.epix"][..]),
            (&["--data-dir=/n", "--background"][..], &["--background"][..]),
            (&["--background", "--data-dir", "/n"][..], &["--background"][..]),
        ] {
            let mut args = os_args(input);
            assert_eq!(
                take_data_dir_option(&mut args, false).unwrap(),
                Some(PathBuf::from("/n")),
                "{input:?}"
            );
            assert_eq!(args, os_args(rest), "{input:?}");
        }
        let mut args = os_args(&["dashboard.epix"]);
        assert_eq!(take_data_dir_option(&mut args, false).unwrap(), None);
        assert_eq!(args, os_args(&["dashboard.epix"]));
        // Similar names are not the option.
        let mut args = os_args(&["--data-directory", "/n"]);
        assert_eq!(take_data_dir_option(&mut args, false).unwrap(), None);
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn leading_data_dir_option_stops_at_the_first_other_argument() {
        let mut args = os_args(&["--data-dir", "/n", "siteSign", "--data-dir", "x"]);
        assert_eq!(
            take_data_dir_option(&mut args, true).unwrap(),
            Some(PathBuf::from("/n"))
        );
        assert_eq!(args, os_args(&["siteSign", "--data-dir", "x"]));
        let mut args = os_args(&["siteSign", "--data-dir", "x"]);
        assert_eq!(take_data_dir_option(&mut args, true).unwrap(), None);
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn data_dir_option_rejects_missing_empty_and_repeated_folders() {
        for input in [
            &["--data-dir"][..],
            &["--data-dir="][..],
            &["--data-dir", ""][..],
            &["--data-dir", "--background"][..],
            &["--data-dir", "/a", "--data-dir=/b"][..],
        ] {
            let mut args = os_args(input);
            assert!(take_data_dir_option(&mut args, false).is_err(), "{input:?}");
        }
    }
}
