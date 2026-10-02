//! Confined, single-read artifact capture.
//!
//! Every path component is opened relative to its parent descriptor with
//! `O_NOFOLLOW`, intermediate components must be directories, and the final
//! file must be a regular file with exactly one link and a bounded size. The
//! bytes read through that one descriptor are what gets digested and kept; a
//! path is never reopened later.

use std::io::Read as _;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags};

use crate::{AuthenticationError, MAX_ARTIFACT};

/// A capture strategy: given the root directory descriptor and a validated
/// relative path, produce the captured bytes. Tests substitute one to race
/// file replacement against capture.
pub(crate) type CaptureFn<'a> =
    dyn FnMut(BorrowedFd<'_>, &str) -> Result<Vec<u8>, AuthenticationError> + 'a;

fn denied() -> AuthenticationError {
    AuthenticationError::new("artifact capture denied")
}

/// Open the artifact root itself without following a symlink.
pub(crate) fn open_root(root: &Path) -> Result<OwnedFd, AuthenticationError> {
    rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| denied())
}

/// Read one confined descriptor; the caller verifies those exact bytes.
pub(crate) fn capture_file(
    root: BorrowedFd<'_>,
    path: &str,
) -> Result<Vec<u8>, AuthenticationError> {
    let parts = evx_api::validate_relative_path(path)
        .map_err(|_| AuthenticationError::new("artifact path outside allowed namespace"))?;
    let Some((name, directories)) = parts.split_last() else {
        return Err(AuthenticationError::new(
            "artifact path outside allowed namespace",
        ));
    };
    let mut directory: Option<OwnedFd> = None;
    for part in directories {
        let current = directory.as_ref().map_or(root, |fd| fd.as_fd());
        let next = rustix::fs::openat(
            current,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| denied())?;
        directory = Some(next);
    }
    let current = directory.as_ref().map_or(root, |fd| fd.as_fd());
    let file = rustix::fs::openat(
        current,
        *name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| denied())?;
    let info = rustix::fs::fstat(&file).map_err(|_| denied())?;
    let bounded = u64::try_from(info.st_size).is_ok_and(|size| size <= MAX_ARTIFACT as u64);
    if !FileType::from_raw_mode(info.st_mode).is_file() || info.st_nlink != 1 || !bounded {
        return Err(AuthenticationError::new(
            "artifact is not a bounded isolated regular file",
        ));
    }
    let mut data = Vec::new();
    std::fs::File::from(file)
        .take(MAX_ARTIFACT as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| denied())?;
    if data.len() > MAX_ARTIFACT {
        return Err(AuthenticationError::new("artifact size limit"));
    }
    Ok(data)
}
