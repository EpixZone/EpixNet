//! Platform filesystem primitives shared by crates that cannot contain
//! platform `unsafe` code themselves.

use std::{io, path::Path};

#[cfg(windows)]
fn checked_relative_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a canonical relative path",
        ));
    }
    Ok(())
}

#[cfg(windows)]
static WINDOWS_TEMP_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(windows)]
fn pin_windows_directory(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("durable operation crosses a reparse point: {}", path.display()),
        ));
    }
    Ok(directory)
}

#[cfg(windows)]
fn pin_windows_parent(path: &Path) -> io::Result<Vec<std::fs::File>> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let absolute_parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()?.join(parent)
    };
    let mut anchor = std::path::PathBuf::new();
    let mut names = Vec::new();
    for component in absolute_parent.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir if names.is_empty() => {
                anchor.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "durable operation parent is not canonical",
                ));
            }
        }
    }
    let mut current = anchor;
    let mut pinned = vec![pin_windows_directory(&current)?];
    for name in names {
        current.push(name);
        pinned.push(pin_windows_directory(&current)?);
    }
    Ok(pinned)
}

/// Open one regular file below `root` while every ancestor is pinned against
/// replacement and every reparse point is rejected.
#[cfg(windows)]
pub fn open_regular_file_beneath(root: &Path, relative: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    checked_relative_path(relative)?;
    let path = root.join(relative);
    let _pinned = pin_windows_parent(&path)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("xite file is not a regular non-reparse file: {}", path.display()),
        ));
    }
    Ok(file)
}

/// Read one regular file below `root` through a pinned, non-reparse handle.
#[cfg(windows)]
pub fn read_regular_file_beneath(root: &Path, relative: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;

    let mut file = open_regular_file_beneath(root, relative)?;
    let expected_len = file.metadata()?.len();
    let mut bytes = Vec::with_capacity(usize::try_from(expected_len).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("xite file changed while reading: {}", root.join(relative).display()),
        ));
    }
    Ok(bytes)
}

/// Walk regular files below `root` without following reparse points. Directory
/// handles omit delete sharing, so an enumerated branch cannot be swapped
/// while it is being classified.
#[cfg(windows)]
pub fn list_regular_files_beneath(root: &Path, max_entries: usize) -> io::Result<Vec<String>> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let root_handle = pin_windows_directory(&root)?;
    let mut stack = vec![(root.clone(), std::path::PathBuf::new(), root_handle)];
    let mut files = Vec::new();
    let mut visited = 0usize;
    while let Some((absolute, relative, directory_handle)) = stack.pop() {
        let entries = std::fs::read_dir(&absolute)?;
        for entry in entries {
            let entry = entry?;
            visited = visited.saturating_add(1);
            if visited > max_entries {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("xite walk exceeds {max_entries} entries"),
                ));
            }
            let name = entry.file_name();
            let child_absolute = absolute.join(&name);
            let child_relative = relative.join(&name);
            let metadata = std::fs::symlink_metadata(&child_absolute)?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("xite walk crosses a reparse point: {}", child_absolute.display()),
                ));
            }
            if metadata.is_dir() {
                let child_handle = pin_windows_directory(&child_absolute)?;
                stack.push((child_absolute, child_relative, child_handle));
            } else if metadata.is_file() {
                files.push(
                    child_relative
                        .to_str()
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "xite path is not UTF-8")
                        })?
                        .replace('\\', "/"),
                );
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("xite walk found a non-regular entry: {}", child_absolute.display()),
                ));
            }
        }
        drop(directory_handle);
    }
    files.sort();
    Ok(files)
}

#[cfg(windows)]
fn move_file_write_through(source: &Path, destination: &Path, replace: bool) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_parent = source
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no parent"))?;
    let destination_parent = destination.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent")
    })?;
    let pinned_source = pin_windows_parent(source)?;
    let pinned_destination = if source_parent == destination_parent {
        Vec::new()
    } else {
        pin_windows_parent(destination)?
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            flags,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(pinned_destination);
    drop(pinned_source);
    Ok(())
}

/// Atomically replace `destination` with `source` and make the rename durable.
/// Both paths must be on the same filesystem.
#[cfg(windows)]
pub fn replace_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    move_file_write_through(source, destination, true)
}

/// Atomically install `source` at an absent `destination` and make the rename
/// durable. An existing destination is never replaced.
#[cfg(windows)]
pub fn install_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    move_file_write_through(source, destination, false)
}

/// Create every missing component in `directory`. Each new entry is installed
/// with a write-through rename while all existing non-reparse ancestors are
/// pinned against replacement.
#[cfg(windows)]
pub fn create_parent_directories_write_through(directory: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let absolute = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()?.join(directory)
    };
    let mut anchor = std::path::PathBuf::new();
    let mut names = Vec::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir if names.is_empty() => {
                anchor.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => names.push(name.to_os_string()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "durable directory path is not canonical",
                ));
            }
        }
    }
    let mut current = anchor;
    let mut pinned = vec![pin_windows_directory(&current)?];
    for name in names {
        let next = current.join(&name);
        match std::fs::symlink_metadata(&next) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("durable directory crosses a reparse point: {}", next.display()),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let sequence = WINDOWS_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let temporary = current.join(format!(
                    ".epix-directory-{}-{sequence}.tmp",
                    std::process::id()
                ));
                std::fs::create_dir(&temporary)?;
                if let Err(error) = install_file_write_through(&temporary, &next) {
                    let _ = std::fs::remove_dir(&temporary);
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                let metadata = std::fs::symlink_metadata(&next)?;
                if !metadata.is_dir()
                    || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("durable directory was replaced: {}", next.display()),
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        current = next;
        pinned.push(pin_windows_directory(&current)?);
    }
    Ok(())
}

/// Make `path` durably absent without following a reparse point. Windows has
/// no portable directory fsync. Moving the exact entry to a reserved sibling
/// with `MOVEFILE_WRITE_THROUGH` makes the authoritative name removal durable.
#[cfg(windows)]
pub fn remove_file_write_through(path: &Path) -> io::Result<()> {
    use std::io::Write;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let _pinned = pin_windows_parent(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let mut tombstone_name = std::ffi::OsString::from(".");
    tombstone_name.push(name);
    tombstone_name.push(".epix-delete.tmp");
    let tombstone = parent.join(tombstone_name);

    // An already-absent name still routes through the tombstone move: the
    // preceding unlink may not be durable yet, so a placeholder entry is
    // installed and durably removed in its place. The placeholder must never
    // survive this call — the caller asked for absence.
    let mut created_placeholder = false;
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            created_placeholder = true;
            file.write_all(&[])?;
            file.sync_all()?;
            file.metadata()?
        }
        Err(error) => return Err(error),
    };
    let moved = (|| {
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable delete target is not a regular file",
            ));
        }
        // Two attempts: a tombstone left by a crashed prior delete — or one
        // installed by a concurrent delete of the same name — is cleaned up
        // and the move retried once.
        for attempt in 0..2 {
            match std::fs::symlink_metadata(&tombstone) {
                Ok(metadata) => {
                    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                        || !metadata.is_file()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "durable-delete tombstone is not a regular file",
                        ));
                    }
                    let mut permissions = metadata.permissions();
                    permissions.set_readonly(false);
                    std::fs::set_permissions(&tombstone, permissions)?;
                    std::fs::remove_file(&tombstone)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            match install_file_write_through(path, &tombstone) {
                Ok(()) => return Ok(()),
                Err(error)
                    if attempt == 0 && error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        unreachable!("second install attempt returns")
    })();
    if let Err(error) = moved {
        if created_placeholder {
            let _ = std::fs::remove_file(path);
        }
        return Err(error);
    }

    if let Ok(metadata) = std::fs::symlink_metadata(&tombstone) {
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 && metadata.is_file() {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(&tombstone, permissions);
            let _ = std::fs::remove_file(&tombstone);
        }
    }
    Ok(())
}

/// Atomically replace `destination` with `source` and sync the parent entry.
#[cfg(unix)]
pub fn replace_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(unix)]
pub fn install_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::hard_link(source, destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    std::fs::File::open(parent)?.sync_all()?;
    std::fs::remove_file(source)?;
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(any(unix, windows)))]
pub fn replace_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::rename(source, destination)
}


#[cfg(not(any(unix, windows)))]
pub fn install_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    std::fs::hard_link(source, destination)?;
    std::fs::remove_file(source)
}
