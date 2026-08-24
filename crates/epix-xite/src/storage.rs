//! On-disk storage for a single xite (its `data/<address>/` directory).

use epix_core::{Error, Result};
use sha2::{Digest, Sha512};
use std::{
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static DURABLE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn read_open_file_bounded(
    file: std::fs::File,
    max_bytes: u64,
) -> std::io::Result<Vec<u8>> {
    let expected_len = file.metadata()?.len();
    if expected_len > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("xite file exceeds the {max_bytes}-byte limit"),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(expected_len).unwrap_or(0));
    file.take(max_bytes.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "xite file changed while reading",
        ));
    }
    Ok(bytes)
}

/// Opens the operator-configured storage root. The root path is trusted
/// configuration, so symlinks in its own ancestry are followed (a data dir
/// under `/var` on macOS or relocated to another disk must keep working);
/// only the untrusted content BENEATH the root is walked with `NOFOLLOW`
/// by the callers. `DIRECTORY` still guarantees every resolved component
/// is a directory. With `create`, missing root components are created and
/// their parents synced, matching the durable-write requirements.
#[cfg(unix)]
fn open_xite_root(root: &Path, create: bool) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};

    let root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    if root
        .components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "xite storage root is not a canonical absolute path",
        ));
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    // Open the configured root directly instead of walking down from "/".
    // The root's ancestry is trusted configuration (see above), and sandboxed
    // platforms refuse to open their upper directories at all: on Android,
    // SELinux denies apps read on "/", so a walk from "/" made every storage
    // read and durable write fail with EACCES even though the data dir
    // itself was fully accessible.
    match rustix::fs::open(&root, flags, Mode::empty()) {
        Ok(directory) => return Ok(std::fs::File::from(directory)),
        Err(error)
            if create && std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(std::io::Error::from(error)),
    }
    // A missing root component: durably create it under its nearest existing
    // ancestor. Recursing on the parent opens only the directories that are
    // actually being created into, never the ancestry above them.
    let parent = root.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "xite storage root has no parent")
    })?;
    let name = root.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "xite storage root is not a canonical absolute path",
        )
    })?;
    let directory = open_xite_root(parent, true)?;
    match rustix::fs::mkdirat(&directory, name, Mode::from_bits_truncate(0o755)) {
        Ok(()) => directory.sync_all()?,
        Err(error)
            if std::io::Error::from(error).kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(std::io::Error::from(error)),
    }
    rustix::fs::openat(&directory, name, flags, Mode::empty())
        .map(std::fs::File::from)
        .map_err(std::io::Error::from)
}

#[cfg(unix)]
fn open_regular_file_beneath(root: &Path, relative: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};

    let mut directory = open_xite_root(root, false)?;
    let mut components = relative.components().collect::<Vec<_>>();
    let Some(Component::Normal(final_name)) = components.pop() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "xite read has no final component",
        ));
    };
    for component in components {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "xite read path is not canonical",
            ));
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(std::io::Error::from)?;
    }
    let file = rustix::fs::openat(
        &directory,
        final_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(std::fs::File::from)
    .map_err(std::io::Error::from)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "xite read target is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn list_regular_files_beneath(root: &Path, max_entries: usize) -> std::io::Result<Vec<String>> {
    use rustix::fs::{FileType, Mode, OFlags};
    use std::os::unix::ffi::OsStrExt;

    let root = open_xite_root(root, false)?;
    let mut stack = vec![(root, PathBuf::new())];
    let mut files = Vec::new();
    let mut visited = 0usize;
    while let Some((directory, relative)) = stack.pop() {
        let entries = rustix::fs::Dir::read_from(&directory).map_err(std::io::Error::from)?;
        for entry in entries {
            let entry = entry.map_err(std::io::Error::from)?;
            let name_bytes = entry.file_name().to_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            visited = visited.saturating_add(1);
            if visited > max_entries {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("xite walk exceeds {max_entries} entries"),
                ));
            }
            let name = std::ffi::OsStr::from_bytes(name_bytes);
            let opened = rustix::fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(std::fs::File::from)
            .map_err(std::io::Error::from)?;
            let metadata = rustix::fs::fstat(&opened).map_err(std::io::Error::from)?;
            let file_type = FileType::from_raw_mode(metadata.st_mode);
            let child = relative.join(name);
            if file_type.is_dir() {
                stack.push((opened, child));
            } else if file_type.is_file() {
                files.push(
                    child
                        .to_str()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "xite path is not UTF-8",
                            )
                        })?
                        .to_string(),
                );
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("xite walk found a non-regular entry: {}", child.display()),
                ));
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(windows)]
fn create_directory_durable(directory: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    if directory.is_dir() {
        return Ok(());
    }
    let parent = directory
        .parent()
        .ok_or_else(|| std::io::Error::other("directory has no parent"))?;
    let name = directory
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("directory");
    let sequence = DURABLE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{name}.epix-durable-dir-{}-{sequence}.tmp",
        std::process::id()
    ));
    std::fs::create_dir(&temporary)?;
    let source = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = directory
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(source.as_ptr(), destination.as_ptr(), MOVEFILE_WRITE_THROUGH)
    };
    if result != 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    let _ = std::fs::remove_dir(&temporary);
    if directory.is_dir() {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(windows))]
fn create_directory_durable(directory: &Path) -> std::io::Result<()> {
    match std::fs::create_dir(directory) {
        Ok(()) => {}
        Err(error)
            if error.kind() == std::io::ErrorKind::AlreadyExists && directory.is_dir() => {}
        Err(error) => return Err(error),
    }
    let parent = directory
        .parent()
        .ok_or_else(|| std::io::Error::other("directory has no parent"))?;
    std::fs::File::open(parent)?.sync_all()
}

/// Create every missing directory in `parent` and make each new directory
/// entry durable before returning.
pub fn create_parent_directories_durable(parent: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut current = Some(parent);
    while let Some(directory) = current {
        if directory.exists() {
            if !directory.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotADirectory,
                    format!("{} is not a directory", directory.display()),
                ));
            }
            break;
        }
        missing.push(directory.to_path_buf());
        current = directory.parent();
    }
    for directory in missing.iter().rev() {
        create_directory_durable(directory)?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_atomic_durable_beneath(root: &Path, inner_path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    let mut directory = open_xite_root(root, true)?;

    let mut components = Path::new(inner_path).components().collect::<Vec<_>>();
    let Some(std::path::Component::Normal(final_name)) = components.pop() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "durable xite path has no final component",
        ));
    };
    for component in components {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "durable xite path is not canonical",
            ));
        };
        match rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => directory = std::fs::File::from(next),
            Err(error)
                if std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound =>
            {
                match rustix::fs::mkdirat(
                    &directory,
                    name,
                    Mode::from_bits_truncate(0o755),
                ) {
                    Ok(()) => directory.sync_all()?,
                    Err(error)
                        if std::io::Error::from(error).kind()
                            == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(std::io::Error::from(error)),
                }
                directory = rustix::fs::openat(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(std::fs::File::from)
                .map_err(std::io::Error::from)?;
            }
            Err(error) => return Err(std::io::Error::from(error)),
        }
    }

    let display_name = final_name.to_string_lossy();
    let mut last_error = None;
    for _ in 0..32 {
        let sequence = DURABLE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = std::ffi::OsString::from(format!(
            ".{display_name}.epix-durable-{}-{sequence}.tmp",
            std::process::id()
        ));
        let opened = rustix::fs::openat(
            &directory,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        );
        let mut file = match opened {
            Ok(file) => std::fs::File::from(file),
            Err(error)
                if std::io::Error::from(error).kind()
                    == std::io::ErrorKind::AlreadyExists =>
            {
                last_error = Some(std::io::Error::from(error));
                continue;
            }
            Err(error) => return Err(std::io::Error::from(error)),
        };
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = rustix::fs::unlinkat(&directory, &temporary, rustix::fs::AtFlags::empty());
            return Err(error);
        }
        let temporary_metadata = file.metadata()?;
        // SMB/CIFS (and some AV filters) refuse a rename transiently while a
        // reader holds a lease on the destination. A node once served a
        // four-day-old content.json because a commit gave up on the first
        // EBUSY, so sharing violations get a short retry ladder before the
        // commit fails.
        let mut renamed = Ok(());
        for wait_ms in [0u64, 100, 400, 1500] {
            if wait_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(wait_ms));
            }
            renamed = rustix::fs::renameat(&directory, &temporary, &directory, final_name);
            match renamed {
                Ok(()) => break,
                Err(errno) => {
                    let transient = matches!(
                        errno,
                        rustix::io::Errno::BUSY
                            | rustix::io::Errno::ACCESS
                            | rustix::io::Errno::TXTBSY
                    );
                    if !transient {
                        break;
                    }
                }
            }
        }
        if let Err(error) = renamed {
            let _ = rustix::fs::unlinkat(&directory, &temporary, rustix::fs::AtFlags::empty());
            return Err(std::io::Error::from(error));
        }
        directory.sync_all()?;
        let installed = rustix::fs::openat(
            &directory,
            final_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(std::io::Error::from)?;
        let installed_metadata = installed.metadata()?;
        if !installed_metadata.is_file()
            || installed_metadata.dev() != temporary_metadata.dev()
            || installed_metadata.ino() != temporary_metadata.ino()
            || installed_metadata.len() != bytes.len() as u64
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "durable xite destination was replaced",
            ));
        }
        if read_open_file_bounded(installed, bytes.len() as u64)? != bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "durable xite destination bytes changed during replacement",
            ));
        }
        return Ok(());
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::other("could not allocate durable xite temporary file")
    }))
}

#[cfg(windows)]
fn write_atomic_durable_beneath(root: &Path, inner_path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::{Read, Write};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE,
        FILE_SHARE_DELETE, FILE_SHARE_READ,
    };

    fn open_pinned_directory(path: &Path) -> std::io::Result<std::fs::File> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };

        let directory = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("xite path crosses a reparse point: {}", path.display()),
            ));
        }
        Ok(directory)
    }

    let root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    epix_fs::create_parent_directories_write_through(&root)?;
    let relative = Path::new(inner_path);
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "durable xite path is not canonical",
        ));
    }
    let destination_parent = root
        .join(relative)
        .parent()
        .ok_or_else(|| std::io::Error::other("durable xite path has no parent"))?
        .to_path_buf();
    epix_fs::create_parent_directories_write_through(&destination_parent)?;
    let mut anchor = PathBuf::new();
    let mut descendants = Vec::new();
    for component in root.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir
                if descendants.is_empty() =>
            {
                anchor.push(component.as_os_str());
            }
            std::path::Component::Normal(name) => descendants.push(name.to_os_string()),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "xite storage root is not canonical",
                ));
            }
        }
    }
    let mut current = anchor;
    let mut pinned = vec![open_pinned_directory(&current)?];
    for name in descendants {
        current.push(&name);
        pinned.push(open_pinned_directory(&current)?);
    }

    let mut components = Path::new(inner_path).components().collect::<Vec<_>>();
    let Some(std::path::Component::Normal(final_name)) = components.pop() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "durable xite path has no final component",
        ));
    };
    for component in components {
        let std::path::Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "durable xite path is not canonical",
            ));
        };
        current.push(name);
        match std::fs::create_dir(&current) {
            Ok(()) => {
                let _ = pinned.last().and_then(|directory| directory.sync_all().ok());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        pinned.push(open_pinned_directory(&current)?);
    }
    let display_name = final_name.to_string_lossy();
    let mut last_error = None;
    for _ in 0..32 {
        let sequence = DURABLE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary_name = std::ffi::OsString::from(format!(
            ".{display_name}.epix-durable-{}-{sequence}.tmp",
            std::process::id()
        ));
        let temporary_path = current.join(&temporary_name);
        let mut file = match std::fs::OpenOptions::new()
            .access_mode(FILE_GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "durable xite temporary is a reparse point",
            ));
        }
        if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&temporary_path);
            return Err(error);
        }

        let destination_path = current.join(final_name);
        if let Err(error) = epix_fs::replace_file_write_through(
            &temporary_path,
            &destination_path,
        ) {
            drop(file);
            let _ = std::fs::remove_file(&temporary_path);
            return Err(error);
        }
        drop(file);
        let mut installed = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&destination_path)?;
        let installed_metadata = installed.metadata()?;
        if !installed_metadata.is_file()
            || installed_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || installed_metadata.len() != bytes.len() as u64
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "durable xite destination was replaced",
            ));
        }
        let mut installed_bytes = Vec::with_capacity(bytes.len());
        installed.read_to_end(&mut installed_bytes)?;
        if installed_bytes != bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "durable xite destination bytes changed during replacement",
            ));
        }
        return Ok(());
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::other("could not allocate durable xite temporary file")
    }))
}

#[cfg(not(any(unix, windows)))]
fn write_atomic_durable_beneath(root: &Path, inner_path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let destination = root.join(inner_path);
    let parent = destination
        .parent()
        .ok_or_else(|| std::io::Error::other("destination has no parent"))?;
    create_parent_directories_durable(parent)?;
    let temporary = destination.with_extension("epix-durable.tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, &destination)?;
    Ok(())
}

#[cfg(unix)]
fn delete_durable_beneath(root: &Path, inner_path: &str) -> std::io::Result<()> {
    use rustix::fs::{AtFlags, Mode, OFlags};

    let mut directory = open_xite_root(root, false)?;

    let mut components = Path::new(inner_path).components().collect::<Vec<_>>();
    let Some(Component::Normal(final_name)) = components.pop() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "durable xite path has no final component",
        ));
    };
    for component in components {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "durable xite path is not canonical",
            ));
        };
        match rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(next) => directory = std::fs::File::from(next),
            Err(error)
                if std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound =>
            {
                // A prior interrupted delete may already have removed this
                // directory. Sync its nearest surviving parent before the
                // recovery receipt can be retired.
                directory.sync_all()?;
                return Ok(());
            }
            Err(error) => return Err(std::io::Error::from(error)),
        }
    }

    match rustix::fs::openat(
        &directory,
        final_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => {
            let file = std::fs::File::from(file);
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "durable delete target is not a regular file",
                ));
            }
        }
        Err(error)
            if std::io::Error::from(error).kind() == std::io::ErrorKind::NotFound =>
        {
            directory.sync_all()?;
            return Ok(());
        }
        Err(error) => return Err(std::io::Error::from(error)),
    }
    rustix::fs::unlinkat(&directory, final_name, AtFlags::empty())
        .map_err(std::io::Error::from)?;
    directory.sync_all()
}

#[cfg(windows)]
fn delete_durable_beneath(root: &Path, inner_path: &str) -> std::io::Result<()> {
    let destination = root.join(inner_path);
    epix_fs::remove_file_write_through(&destination)
}

#[cfg(not(any(unix, windows)))]
fn delete_durable_beneath(root: &Path, inner_path: &str) -> std::io::Result<()> {
    let destination = root.join(inner_path);
    match std::fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "durable delete target is not a regular file",
            ));
        }
        Ok(_) => std::fs::remove_file(&destination)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if let Some(parent) = destination.parent() {
        if parent.is_dir() {
            std::fs::File::open(parent)?.sync_all()?;
        } else if let Some(ancestor) = parent.ancestors().find(|path| path.is_dir()) {
            std::fs::File::open(ancestor)?.sync_all()?;
        }
    }
    Ok(())
}

/// Files for one xite live under `root`. Cheap to clone (just a path), so each
/// download worker can hold its own handle.
#[derive(Debug, Clone)]
pub struct XiteStorage {
    root: PathBuf,
}

impl XiteStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve `inner_path` under the xite root, rejecting traversal/absolute paths.
    pub fn path(&self, inner_path: &str) -> Result<PathBuf> {
        let rel = Path::new(inner_path);
        for c in rel.components() {
            match c {
                Component::Normal(_) | Component::CurDir => {}
                _ => return Err(Error::Other(format!("unsafe inner_path: {inner_path}"))),
            }
        }
        Ok(self.root.join(rel))
    }

    pub fn exists(&self, inner_path: &str) -> bool {
        self.path(inner_path).map(|p| p.is_file()).unwrap_or(false)
    }

    pub fn read(&self, inner_path: &str) -> Result<Vec<u8>> {
        self.read_bounded(inner_path, u64::MAX)
    }

    /// Read one regular file without following links and reject it before
    /// allocation when its recorded size exceeds `max_bytes`.
    pub fn read_bounded(&self, inner_path: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let relative = Path::new(inner_path);
        self.path(inner_path)?;
        #[cfg(unix)]
        {
            let file = open_regular_file_beneath(&self.root, relative).map_err(Error::Io)?;
            return read_open_file_bounded(file, max_bytes).map_err(Error::Io);
        }
        #[cfg(windows)]
        {
            let file = epix_fs::open_regular_file_beneath(&self.root, relative)
                .map_err(Error::Io)?;
            return read_open_file_bounded(file, max_bytes).map_err(Error::Io);
        }
        #[cfg(not(any(unix, windows)))]
        {
            let path = self.root.join(relative);
            let metadata = std::fs::symlink_metadata(&path).map_err(Error::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::Other(format!(
                    "xite read target is not a regular file: {}",
                    path.display()
                )));
            }
            let file = std::fs::File::open(path).map_err(Error::Io)?;
            read_open_file_bounded(file, max_bytes).map_err(Error::Io)
        }
    }

    /// Read one bounded byte range through the same no-link capability walk
    /// as full-file reads. The returned handle remains bound to the checked
    /// regular file even if an ancestor is concurrently renamed.
    pub fn read_range(
        &self,
        inner_path: &str,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>> {
        let relative = Path::new(inner_path);
        self.path(inner_path)?;
        #[cfg(unix)]
        let mut file = open_regular_file_beneath(&self.root, relative).map_err(Error::Io)?;
        #[cfg(windows)]
        let mut file = epix_fs::open_regular_file_beneath(&self.root, relative)
            .map_err(Error::Io)?;
        #[cfg(not(any(unix, windows)))]
        let mut file = {
            let path = self.root.join(relative);
            let metadata = std::fs::symlink_metadata(&path).map_err(Error::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::Other(format!(
                    "xite range target is not a regular file: {}",
                    path.display()
                )));
            }
            std::fs::File::open(path).map_err(Error::Io)?
        };
        file.seek(SeekFrom::Start(offset)).map_err(Error::Io)?;
        let mut bytes = vec![0u8; length];
        let read = file.read(&mut bytes).map_err(Error::Io)?;
        bytes.truncate(read);
        Ok(bytes)
    }

    pub fn write(&self, inner_path: &str, bytes: &[u8]) -> Result<()> {
        self.write_atomic_durable(inner_path, bytes)
    }

    /// Write `inner_path` atomically. Now an alias for
    /// [`Self::write_atomic_durable`]: sibling temp file, fsync, one atomic
    /// rename over the target (retried briefly on transient sharing
    /// violations), parent directory synced. There is no in-place fallback -
    /// a replace that still fails after the retries fails the commit.
    pub fn write_atomic(&self, inner_path: &str, bytes: &[u8]) -> Result<()> {
        self.write_atomic_durable(inner_path, bytes)
    }

    /// Strict durable atomic replacement. The old file is never truncated in
    /// place. The new sibling is fully written and synced before one atomic
    /// replace, and the replace is made durable before success is returned.
    pub fn write_atomic_durable(&self, inner_path: &str, bytes: &[u8]) -> Result<()> {
        self.path(inner_path)?;
        write_atomic_durable_beneath(&self.root, inner_path, bytes).map_err(Error::Io)
    }

    /// Delete a stored file, pruning any directories the removal left empty.
    pub fn delete(&self, inner_path: &str) -> Result<()> {
        self.delete_durable(inner_path)
    }

    /// Delete one recovery-critical file without following links or pruning
    /// its parent directory, then persist the parent entry change.
    pub fn delete_durable(&self, inner_path: &str) -> Result<()> {
        self.path(inner_path)?;
        delete_durable_beneath(&self.root, inner_path).map_err(Error::Io)
    }

    /// content.json file hash: hex of the first 32 bytes of SHA-512
    /// (`sha512(bytes).hexdigest()[:64]`).
    pub fn hash_bytes(bytes: &[u8]) -> String {
        let digest = Sha512::digest(bytes);
        hex::encode(&digest[..32])
    }

    /// Stream a stored file into its truncated SHA-512 hash and exact size.
    /// Memory use stays fixed for multi-gigabyte files.
    pub fn hash_file(&self, inner_path: &str) -> Result<(u64, String)> {
        let relative = Path::new(inner_path);
        self.path(inner_path)?;
        #[cfg(unix)]
        let mut file = open_regular_file_beneath(&self.root, relative).map_err(Error::Io)?;
        #[cfg(windows)]
        let mut file = epix_fs::open_regular_file_beneath(&self.root, relative)
            .map_err(Error::Io)?;
        #[cfg(not(any(unix, windows)))]
        let mut file = {
            let path = self.root.join(relative);
            let metadata = std::fs::symlink_metadata(&path).map_err(Error::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(Error::Other(format!(
                    "xite hash target is not a regular file: {}",
                    path.display()
                )));
            }
            std::fs::File::open(path).map_err(Error::Io)?
        };
        let mut hasher = Sha512::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(Error::Io(error)),
            };
            hasher.update(&buffer[..read]);
            size = size
                .checked_add(read as u64)
                .ok_or_else(|| Error::Other("stored file size exceeds u64".to_string()))?;
        }
        let digest = hasher.finalize();
        Ok((size, hex::encode(&digest[..32])))
    }

    /// True if the stored file exists and matches `expected_sha512`.
    /// Display paths (the Files tab, the startup hashfield scan) use
    /// [`Self::present_at_size`] instead so one render never re-hashes files.
    pub fn verify(&self, inner_path: &str, expected_sha512: &str) -> bool {
        self.hash_file(inner_path)
            .map(|(_, digest)| digest == expected_sha512)
            .unwrap_or(false)
    }

    /// True if the stored file exists at exactly `size` bytes: one stat, no
    /// read. The cheap presence check for display/inventory paths; a torn
    /// file at the right size is caught by the download path's hash verify
    /// and the explicit verify commands, not here.
    pub fn present_at_size(&self, inner_path: &str, size: u64) -> bool {
        self.path(inner_path)
            .ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| m.is_file() && m.len() == size)
            .unwrap_or(false)
    }

    /// Every file under the root as an `inner_path` (relative, forward slashes).
    pub fn list_files_checked(&self, max_entries: usize) -> Result<Vec<String>> {
        #[cfg(unix)]
        {
            return list_regular_files_beneath(&self.root, max_entries).map_err(Error::Io);
        }
        #[cfg(windows)]
        {
            return epix_fs::list_regular_files_beneath(&self.root, max_entries)
                .map_err(Error::Io);
        }
        #[cfg(not(any(unix, windows)))]
        {
            let mut out = Vec::new();
            let mut stack = vec![self.root.clone()];
            let mut visited = 0usize;
            while let Some(dir) = stack.pop() {
                for entry in std::fs::read_dir(&dir).map_err(Error::Io)? {
                    let entry = entry.map_err(Error::Io)?;
                    visited = visited.saturating_add(1);
                    if visited > max_entries {
                        return Err(Error::Other(format!(
                            "xite walk exceeds {max_entries} entries"
                        )));
                    }
                    let metadata = std::fs::symlink_metadata(entry.path()).map_err(Error::Io)?;
                    if metadata.file_type().is_symlink() {
                        return Err(Error::Other(format!(
                            "xite walk crosses a symlink: {}",
                            entry.path().display()
                        )));
                    }
                    if metadata.is_dir() {
                        stack.push(entry.path());
                    } else if metadata.is_file() {
                        let rel = entry
                            .path()
                            .strip_prefix(&self.root)
                            .map_err(|_| Error::Other("xite walk escaped storage".into()))?
                            .to_str()
                            .ok_or_else(|| Error::Other("xite path is not UTF-8".into()))?
                            .replace('\\', "/");
                        out.push(rel);
                    } else {
                        return Err(Error::Other(format!(
                            "xite walk found a non-regular entry: {}",
                            entry.path().display()
                        )));
                    }
                }
            }
            out.sort();
            Ok(out)
        }
    }

    /// Lists every regular file beneath the root. A walk error (an unsafe
    /// entry, a non-UTF-8 name, or an oversized tree) is surfaced to the
    /// caller rather than collapsed into an empty listing, which would
    /// present a populated xite as empty.
    pub fn list_files(&self) -> Result<Vec<String>> {
        self.list_files_checked(100_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        let s = XiteStorage::new("/tmp/xite");
        assert!(s.path("ok/file.txt").is_ok());
        assert!(s.path("../escape").is_err());
        assert!(s.path("/etc/passwd").is_err());
        assert!(s.path("a/../../b").is_err());
    }

    #[test]
    fn hash_matches_known_vector() {
        // sha512("")[:32] hex
        let h = XiteStorage::hash_bytes(b"");
        assert_eq!(&h[..16], "cf83e1357eefb8bd");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn hash_file_streams_small_and_multiple_buffers() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let small = b"streamed sha512";
        storage.write("small.bin", small).unwrap();
        assert_eq!(
            storage.hash_file("small.bin").unwrap(),
            (small.len() as u64, XiteStorage::hash_bytes(small))
        );

        let large: Vec<u8> = (0usize..(1024 * 1024 + 123))
            .map(|index| (index.wrapping_mul(37) % 251) as u8)
            .collect();
        storage.write("large.bin", &large).unwrap();
        assert_eq!(
            storage.hash_file("large.bin").unwrap(),
            (large.len() as u64, XiteStorage::hash_bytes(&large))
        );
        assert!(storage.verify("large.bin", &XiteStorage::hash_bytes(&large)));
    }

    #[test]
    fn present_at_size_stats_files() {
        let dir = tempfile::tempdir().unwrap();
        let s = XiteStorage::new(dir.path());
        s.write("f.bin", b"abcd").unwrap();
        assert!(s.present_at_size("f.bin", 4));
        assert!(!s.present_at_size("f.bin", 5), "wrong size is not present");
        assert!(!s.present_at_size("missing.bin", 4));
        assert!(!s.present_at_size("../escape", 4), "unsafe paths refuse");
    }

    #[cfg(unix)]
    #[test]
    fn checked_walk_and_read_reject_symlinked_ancestors() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"outside").unwrap();
        symlink(outside.path(), root.path().join("leak")).unwrap();
        let storage = XiteStorage::new(root.path());

        assert!(storage.read("leak/secret.txt").is_err());
        assert!(storage.list_files_checked(100).is_err());
        assert_eq!(std::fs::read(outside.path().join("secret.txt")).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn writes_and_deletes_reject_symlinked_ancestors() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let sentinel = outside.path().join("secret.txt");
        std::fs::write(&sentinel, b"outside").unwrap();
        symlink(outside.path(), root.path().join("leak")).unwrap();
        let storage = XiteStorage::new(root.path());

        assert!(storage.write("leak/new.txt", b"attacker").is_err());
        assert!(storage.write_atomic("leak/secret.txt", b"attacker").is_err());
        assert!(storage.delete("leak/secret.txt").is_err());
        assert!(!outside.path().join("new.txt").exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn checked_walk_rejects_a_symlink_loop_without_recursing() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        symlink(".", root.path().join("loop")).unwrap();
        let storage = XiteStorage::new(root.path());

        assert!(storage.list_files_checked(100).is_err());
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let s = XiteStorage::new(dir.path());

        // Creates missing parent dirs like plain write.
        s.write_atomic("sub/content.json", b"v1").unwrap();
        assert_eq!(s.read("sub/content.json").unwrap(), b"v1");

        // Replaces the previous version in place.
        s.write_atomic("sub/content.json", b"v2-longer-content").unwrap();
        assert_eq!(s.read("sub/content.json").unwrap(), b"v2-longer-content");

        // No temp file survives the rename.
        let leftovers: Vec<String> = s
            .list_files()
            .unwrap()
            .into_iter()
            .filter(|f| f.ends_with(".epixtmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn durable_atomic_write_replaces_without_leaving_a_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());

        storage.write_atomic_durable("merge/posts.json", b"old union").unwrap();
        storage
            .write_atomic_durable("merge/posts.json", b"new durable union")
            .unwrap();

        assert_eq!(storage.read("merge/posts.json").unwrap(), b"new durable union");
        let leftovers = storage
            .list_files()
            .unwrap()
            .into_iter()
            .filter(|path| path.contains(".epix-durable-"))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "durable temp files left behind: {leftovers:?}");
    }
}
