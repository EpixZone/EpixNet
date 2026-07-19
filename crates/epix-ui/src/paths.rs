//! Data-root resolution for a desktop node. The default location is the
//! conventional per-OS application-data directory, and the user can point the
//! node somewhere else with a `data_dir` entry in `<default>/epixnet.conf` -
//! the same file and key the Python client uses, so a customized Python
//! install carries over.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
/// the `data_dir` configured in `<default>/epixnet.conf`, else the default.
pub fn data_root() -> PathBuf {
    if let Ok(dir) = std::env::var("EPIX_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    let default = default_data_root();
    read_conf_data_dir(&default.join("epixnet.conf")).unwrap_or(default)
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
    let mut lines: Vec<String> = std::fs::read_to_string(conf)
        .unwrap_or_default()
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
    if let Some(parent) = conf.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(conf, lines.join("\n") + "\n")
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
}
