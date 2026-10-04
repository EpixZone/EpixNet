//! Bind a host-owned state tree to exactly one execution backend.

use std::io::{Read, Write};
use std::path::Path;

pub(crate) const MARKER: &str = "backend.json";
pub(crate) const DIRECT: &str = "{\"version\":1,\"profile\":\"direct-worker-v1\"}";

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
        std::fs::create_dir_all(root).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())?; }
        DirectLifecycle::provision_fresh(&journal).map_err(|error| error.to_string())
    })();
    match opened {
        Ok(lifecycle) => (Some(lifecycle), None),
        Err(error) => (None, Some(error)),
    }
}

pub(crate) fn bind(root: &Path, expected: &str, allow_legacy_direct: bool) -> Result<(), String> {
    let fail = || "EVX backend binding unavailable or mismatched".to_string();
    let parent = root.parent().ok_or_else(fail)?;
    std::fs::create_dir_all(parent).map_err(|_| fail())?;
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    { use std::os::unix::fs::DirBuilderExt; builder.mode(0o700); }
    let fresh = match builder.create(root) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => return Err(fail()),
    };
    let root_metadata = std::fs::symlink_metadata(root).map_err(|_| fail())?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() { return Err(fail()); }
    let path = root.join(MARKER);
    if !fresh && !allow_legacy_direct && std::fs::symlink_metadata(&path).is_err() {
        // Never adopt an older state tree or a partial Apple initialization.
        return Err(fail());
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(expected.as_bytes()).map_err(|_| fail())?;
            file.sync_all().map_err(|_| fail())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
        Err(_) => return Err(fail()),
    }
    let named = std::fs::symlink_metadata(&path).map_err(|_| fail())?;
    if !named.is_file() || named.file_type().is_symlink() || named.len() > 4096 { return Err(fail()); }
    let file = std::fs::File::open(&path).map_err(|_| fail())?;
    let metadata = file.metadata().map_err(|_| fail())?;
    if !metadata.is_file() || metadata.len() > 4096 { return Err(fail()); }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != root_metadata.uid() || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || (metadata.dev(), metadata.ino()) != (named.dev(), named.ino()) {
            return Err(fail());
        }
    }
    file.sync_all().map_err(|_| fail())?;
    let mut actual = Vec::new();
    file.take(4097).read_to_end(&mut actual).map_err(|_| fail())?;
    if actual != expected.as_bytes() { return Err(fail()); }
    #[cfg(unix)]
    {
        std::fs::File::open(root).and_then(|file| file.sync_all()).map_err(|_| fail())?;
        std::fs::File::open(parent).and_then(|file| file.sync_all()).map_err(|_| fail())?;
    }
    Ok(())
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
}
