use fs_mistrust::{Error, Mistrust};
use rustix::fs::{fchmod, fstat, open, openat, Mode, OFlags};
use std::{io, path::Path};

/// Arti creates private directories, but Linux copies and older profiles can
/// leave an existing directory readable by other users. Only repair the mode
/// when Arti identifies those read/search bits on this exact directory.
pub(super) fn secure_existing_directory(
    policy: &Mistrust,
    tor: &Path,
    name: &str,
) -> io::Result<()> {
    let path = std::path::absolute(tor.join(name))?;
    let checked_mode = match policy.verifier().require_directory().check(&path) {
        Ok(()) | Err(Error::NotFound(_)) => return Ok(()),
        Err(Error::BadPermission(bad, mode, bits)) if bad == path && bits & 0o022 == 0 => mode,
        Err(error) => return Err(io::Error::other(error)),
    };

    // Bind both opens to directories and never follow a link at either name.
    // The permission change applies to the open directory, not a path lookup.
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let parent = open(tor, flags, Mode::empty())?;
    let dir = openat(parent, name, flags, Mode::empty())?;
    let stat = fstat(&dir)?;
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Tor storage belongs to another user",
        ));
    }
    if stat.st_mode & 0o777 != checked_mode {
        return Err(io::Error::other(
            "Tor directory permissions changed during startup",
        ));
    }
    fchmod(dir, Mode::from_raw_mode(stat.st_mode & !0o077))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn copied_state_becomes_private_and_can_be_opened_again() {
        let tor = tempfile::tempdir().unwrap();
        let policy = Mistrust::default();
        let state = tor.path().join("state");
        secure_existing_directory(&policy, tor.path(), "state").unwrap();
        assert!(!state.exists());
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).unwrap();
        let contents = state.join("saved");
        fs::write(&contents, b"existing state").unwrap();
        assert!(policy.verifier().secure_dir(&state).is_err());
        secure_existing_directory(&policy, tor.path(), "state").unwrap();
        assert_eq!(
            fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o700
        );
        policy.verifier().secure_dir(&state).unwrap();
        secure_existing_directory(&policy, tor.path(), "state").unwrap();
        assert_eq!(fs::read(contents).unwrap(), b"existing state");
    }

    #[test]
    fn leaves_untrusted_and_linked_directories_for_the_owner() {
        let root = tempfile::tempdir().unwrap();
        let policy = Mistrust::default();
        let target = root.path().join("existing");
        fs::create_dir(&target).unwrap();
        let original = fs::metadata(&target).unwrap().permissions();
        let mode = original.mode() | 0o002;
        fs::set_permissions(&target, fs::Permissions::from_mode(mode)).unwrap();
        assert!(secure_existing_directory(&policy, root.path(), "existing").is_err());
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode(), mode);

        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, root.path().join("state")).unwrap();
        assert!(secure_existing_directory(&policy, root.path(), "state").is_err());
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn reports_a_writable_parent_without_changing_the_profile() {
        let root = tempfile::tempdir().unwrap();
        let tor = root.path().join("tor");
        fs::create_dir_all(tor.join("state")).unwrap();
        let original = fs::metadata(&tor).unwrap().permissions().mode();
        fs::set_permissions(&tor, fs::Permissions::from_mode(original | 0o002)).unwrap();
        let message = secure_existing_directory(&Mistrust::default(), &tor, "state")
            .unwrap_err()
            .to_string();
        assert!(message.contains("Incorrect permissions"));
        assert!(message.contains("tor"));
        assert_eq!(
            fs::metadata(&tor).unwrap().permissions().mode(),
            original | 0o002
        );
    }
}
