//! Platform integration for a persistent desktop node: the data directory, a
//! single-instance lock, and log-file rotation. Replaces the earlier
//! temp-directory data location so a node keeps its identity, sites, and config
//! across restarts in the conventional per-OS location.

use std::path::PathBuf;

/// The shared data root: `EPIX_DATA_DIR` if set, else the conventional per-OS
/// application-data location (`~/Library/Application Support/EpixNet` on macOS,
/// `%APPDATA%\EpixNet` on Windows, `$XDG_DATA_HOME/EpixNet` or
/// `~/.local/share/EpixNet` on Linux). Holds `sites.json`, `users.json`,
/// `config.json`, the resolve cache, logs, and per-xite subdirectories.
pub fn data_root() -> PathBuf {
    if let Ok(dir) = std::env::var("EPIX_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
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

fn home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
}

/// Acquire the single-instance lock in `root/lock.pid`. Returns the held lock
/// (keep it alive for the process lifetime) on success, or `Err` if another
/// instance already holds it. On non-unix targets this is a no-op success.
pub fn acquire_lock(root: &std::path::Path) -> Result<InstanceLock, ()> {
    let path = root.join("lock.pid");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|_| ())?;
        // Non-blocking exclusive lock; EWOULDBLOCK means another node holds it.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            return Err(());
        }
        // Record our PID for humans inspecting the file.
        let mut f = &file;
        let _ = f.set_len(0);
        let _ = writeln!(f, "{}", std::process::id());
        Ok(InstanceLock { _file: Some(file) })
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&path, std::process::id().to_string());
        Ok(InstanceLock { _file: None })
    }
}

/// Holds the single-instance lock; dropping it (at process exit) releases it.
pub struct InstanceLock {
    _file: Option<std::fs::File>,
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
        // Without the override it lands under a real per-OS base, ending in EpixNet.
        assert!(data_root().ends_with("EpixNet"));
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

    #[cfg(unix)]
    #[test]
    fn lock_is_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_lock(dir.path()).expect("first lock");
        // A second acquire in-process on the same file also conflicts (flock is
        // per open-file-description; a fresh open here contends).
        assert!(acquire_lock(dir.path()).is_err(), "second lock is refused");
        drop(first);
        assert!(acquire_lock(dir.path()).is_ok(), "lock is free after drop");
    }
}
