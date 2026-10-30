//! Bind a host-owned state tree to exactly one execution backend.
//!
//! Every check goes through `evx_workspace::Dir`, so both platforms apply
//! the same rules: a private root directory (mode 0700 on Unix, a protected
//! DACL on Windows), a private regular marker with one link whose open
//! handle is the entry the directory names, and a directory flush after
//! the write.

use std::io::{Read, Write};
use std::path::Path;

use evx_workspace::sys::{file_privacy, Dir, Kind, Privacy};

pub(crate) const MARKER: &str = "backend.json";
pub(crate) const DIRECT: &str = "{\"version\":1,\"profile\":\"direct-worker-v1\"}";

/// Most bytes a marker may hold; the real ones are under 100.
const MAX_MARKER: u64 = 4096;

fn fail() -> String {
    "EVX backend binding unavailable or mismatched".to_string()
}

pub(crate) fn direct_lifecycle(root: &Path) -> (
    Option<std::sync::Arc<evx_supervisor::direct_lifecycle::DirectLifecycle>>, Option<String>,
) {
    use evx_supervisor::direct_lifecycle::DirectLifecycle;
    let opened = (|| -> Result<std::sync::Arc<DirectLifecycle>, String> {
        let journal = root.join("lifecycle");
        match std::fs::symlink_metadata(&journal) {
            Ok(_) => return DirectLifecycle::open(&journal).map_err(|error| error.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(format!("execution lifecycle unavailable: {error}")),
        }
        let fresh = match std::fs::symlink_metadata(root) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::read_dir(root).map_err(|error| error.to_string())?.next().is_none()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            _ => false,
        };
        if !fresh {
            DirectLifecycle::prepare_legacy(&journal).map_err(|error| error.to_string())?;
            return DirectLifecycle::open(&journal).map_err(|error| error.to_string());
        }
        create_private_root(root)?;
        DirectLifecycle::provision_fresh(&journal).map_err(|error| error.to_string())
    })();
    match opened {
        Ok(lifecycle) => (Some(lifecycle), None),
        Err(error) => (None, Some(error)),
    }
}

/// Open `root`'s parent directory and name `root` within it, creating the
/// parent when absent.
fn open_parent(root: &Path) -> Result<(Dir, &str), String> {
    let parent = root.parent().ok_or("state root has no parent")?;
    let name = root.file_name().and_then(|name| name.to_str()).ok_or("state root has no name")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    // The parent is host-owned and trusted; resolve it (a `private` directory
    // may be a link to another volume) before the final open, which never
    // follows a link.
    let parent = std::fs::canonicalize(parent).map_err(|error| error.to_string())?;
    let parent = Dir::open_root(&parent).map_err(|error| error.to_string())?;
    Ok((parent, name))
}

/// Create `root` as a private directory, or tighten an existing empty one.
fn create_private_root(root: &Path) -> Result<(), String> {
    let (parent, name) = open_parent(root)?;
    if !parent.create_private_dir(name).map_err(|error| error.to_string())? {
        parent.open_dir(name).and_then(|dir| dir.make_private()).map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Owner-only, and on Unix exactly `mode`.
fn private(privacy: &Privacy, mode: u32) -> bool {
    privacy.is_private() && privacy.mode.is_none_or(|actual| actual == mode)
}

/// Create or adopt the root as a private real directory. A legacy direct
/// root created with the default mode is tightened before the check.
fn open_root(parent: &Dir, name: &str, allow_legacy_direct: bool) -> Result<(Dir, bool), String> {
    let fresh = parent.create_private_dir(name).map_err(|_| fail())?;
    let root = parent.open_dir(name).map_err(|_| fail())?;
    if root.stat_self().map_err(|_| fail())?.kind != Kind::Directory {
        return Err(fail());
    }
    if !fresh && allow_legacy_direct {
        root.make_private().map_err(|_| fail())?;
    }
    if !private(&root.privacy().map_err(|_| fail())?, 0o700) {
        return Err(fail());
    }
    Ok((root, fresh))
}

/// Write the marker when absent; an existing one is left as it is.
fn create_marker(root: &Dir, expected: &str) -> Result<(), String> {
    let mut file = match root.create_new(MARKER) {
        Ok(file) => file,
        Err(_) if root.stat(MARKER).map_err(|_| fail())?.is_some() => return Ok(()),
        Err(_) => return Err(fail()),
    };
    file.write_all(expected.as_bytes()).map_err(|_| fail())?;
    file.sync_all().map_err(|_| fail())
}

/// Reopen the marker through the root and require a private regular file
/// with one link that is the entry the directory names.
fn read_marker(root: &Dir) -> Result<Vec<u8>, String> {
    let named = root.stat(MARKER).map_err(|_| fail())?.ok_or_else(fail)?;
    let (file, stat) = root.open_read(MARKER).map_err(|_| fail())?.ok_or_else(fail)?;
    let privacy = file_privacy(&file).map_err(|_| fail())?;
    if stat.kind != Kind::Regular
        || stat.links != 1
        || stat.size > MAX_MARKER
        || stat.identity != named.identity
        || !private(&privacy, 0o600)
    {
        return Err(fail());
    }
    let mut actual = Vec::new();
    file.take(MAX_MARKER + 1).read_to_end(&mut actual).map_err(|_| fail())?;
    Ok(actual)
}

pub(crate) fn bind(root: &Path, expected: &str, allow_legacy_direct: bool) -> Result<(), String> {
    let (parent, name) = open_parent(root).map_err(|_| fail())?;
    let (root, fresh) = open_root(&parent, name, allow_legacy_direct)?;
    if !fresh && !allow_legacy_direct && root.stat(MARKER).map_err(|_| fail())?.is_none() {
        // Never adopt an older state tree or a partial Apple initialization.
        return Err(fail());
    }
    create_marker(&root, expected)?;
    if read_marker(&root)? != expected.as_bytes() {
        return Err(fail());
    }
    root.sync().map_err(|_| fail())?;
    parent.sync().map_err(|_| fail())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separate_profiles_never_adopt_each_others_state_or_lost_apple_markers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        bind(&root, DIRECT, true).unwrap();
        assert!(bind(&root, "apple-pool-a", false).is_err());
        bind(&root, DIRECT, true).unwrap();
        let apple = temp.path().join("apple");
        bind(&apple, "apple-pool-a", false).unwrap();
        bind(&apple, "apple-pool-a", false).unwrap();
        assert!(bind(&apple, "apple-pool-b", false).is_err());
        assert!(bind(&apple, DIRECT, true).is_err());
        std::fs::remove_file(apple.join(MARKER)).unwrap();
        assert!(bind(&apple, "apple-pool-a", false).is_err());
        assert!(!apple.join(MARKER).exists());
        let legacy = temp.path().join("legacy");
        std::fs::create_dir(&legacy).unwrap();
        std::fs::write(legacy.join("state.sqlite"), b"legacy direct fixture").unwrap();
        assert!(bind(&legacy, "apple-pool-a", false).is_err());
        bind(&legacy, DIRECT, true).unwrap();
    }

    #[test]
    fn a_marker_that_is_not_a_private_regular_file_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        bind(&root, DIRECT, true).unwrap();
        std::fs::remove_file(root.join(MARKER)).unwrap();
        std::fs::create_dir(root.join(MARKER)).unwrap();
        assert!(bind(&root, DIRECT, true).is_err());
        std::fs::remove_dir(root.join(MARKER)).unwrap();
        std::fs::write(root.join(MARKER), vec![b' '; MAX_MARKER as usize + 1]).unwrap();
        assert!(bind(&root, DIRECT, true).is_err());
        let file = temp.path().join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        assert!(bind(&file, DIRECT, true).is_err());
    }
}
