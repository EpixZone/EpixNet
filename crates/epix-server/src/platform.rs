//! Platform integration for a persistent desktop node: the data directory, a
//! and log-file rotation. Node ownership is enforced by epix-node. Replaces the earlier
//! temp-directory data location so a node keeps its identity, xites, and config
//! across restarts in the conventional per-OS location.

use std::path::PathBuf;

/// The shared data root: `EPIX_DATA_DIR` if set, else the `data_dir`
/// configured in the default location's `epixnet.conf` (the same file and key
/// the Python client uses), else the conventional per-OS application-data
/// location (`~/Library/Application Support/EpixNet` on macOS,
/// `%APPDATA%\EpixNet` on Windows, `$XDG_DATA_HOME/EpixNet` or
/// `~/.local/share/EpixNet` on Linux). Laid out like Python EpixNet - node
/// files (`users.json`, `sites.json`, config) under `private/`, per-xite dirs
/// under `data/` - so a Python install's identity and xites carry over as-is.
pub fn data_root() -> PathBuf {
    epix_node::data_root()
}

/// Rotate `root/debug.log` if it exceeds `max_bytes` (rename to `debug.log.old`,
/// replacing any previous one), then return the log path to append to. Called
/// once at startup, matching EpixNet's rollover-on-start.
pub fn log_path(root: &std::path::Path, max_bytes: u64) -> PathBuf {
    let path = root.join("debug.log");
    if std::fs::metadata(&path).map(|m| m.len() > max_bytes).unwrap_or(false) {
        let _ = std::fs::rename(&path, root.join("debug.log.old"));
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins_for_data_root() {
        // Set + restore is racy across tests, but this crate has only this test.
        std::env::set_var("EPIX_DATA_DIR", "/tmp/epix-test-root");
        assert_eq!(data_root(), PathBuf::from("/tmp/epix-test-root"));
        std::env::remove_var("EPIX_DATA_DIR");
        // Without the override the machine's epixnet.conf may point anywhere,
        // so only the env behavior is asserted here (the default-location
        // resolution is covered in epix-ui's paths tests).
    }

    #[test]
    fn log_rotates_when_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("debug.log");
        std::fs::write(&log, vec![b'x'; 100]).unwrap();
        // Limit below the size -> rotated to .old, fresh path returned.
        let p = log_path(dir.path(), 50);
        assert_eq!(p, log);
        assert!(dir.path().join("debug.log.old").exists());
        // Under the limit -> not rotated.
        std::fs::write(&log, b"small").unwrap();
        let _ = std::fs::remove_file(dir.path().join("debug.log.old"));
        let _ = log_path(dir.path(), 1000);
        assert!(!dir.path().join("debug.log.old").exists());
    }

}
