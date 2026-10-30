//! Platform seam: an open directory as the only authority for file access.
//!
//! Every operation names a single path component relative to an already
//! open directory and never follows a symbolic link, junction or other
//! reparse point in that component. The two implementations behind this
//! module are the existing `rustix` code on Unix and handle-relative NT
//! opens on Windows (`docs/evx-windows-backend.md`). The contract is the
//! same on both:
//!
//! - [`Dir`] is an owned handle to a directory. Child opens go through it,
//!   so a rename of an ancestor after the open cannot redirect them.
//! - [`Stat`] reports what the trusted side needs to decide: the kind, the
//!   size, the link count and a durable [`Identity`].
//! - [`Privacy`] answers "may anyone but this user reach it": the Unix uid
//!   and mode bits, or the Windows owner and DACL.
//! - [`Lease`] is the cross-process workspace lease. Holding it excludes a
//!   second supervisor; an inherited copy keeps it alive after the holder
//!   dies, so a confined helper that is still writing keeps the workspace
//!   leased. A quarantined holder forgets the lease instead of releasing it.

use std::path::Path;

use evx_api::Denied;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{file_privacy, file_stat, try_lock_file, unlock_file, Dir, Lease};
/// The value a confined helper inherits to keep a lease alive: a descriptor
/// number on Unix, a handle value on Windows.
#[cfg(unix)]
pub type RawLease = std::os::fd::RawFd;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{file_privacy, file_stat, try_lock_file, unlock_file, Dir, Lease};
/// The value a confined helper inherits to keep a lease alive: a descriptor
/// number on Unix, a handle value on Windows.
#[cfg(windows)]
pub type RawLease = std::os::windows::io::RawHandle;

/// The frozen byte encoding of a path for digests that name a location: the
/// raw bytes on Unix (so existing records keep their digests), UTF-8 on
/// Windows. A path that cannot be encoded is refused rather than guessed.
pub fn path_bytes(path: &Path) -> Result<Vec<u8>, Denied> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        path.to_str()
            .map(|text| text.as_bytes().to_vec())
            .ok_or_else(|| Denied::new("path encoding"))
    }
}

/// What a directory entry is, without following it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An ordinary file.
    Regular,
    /// A directory.
    Directory,
    /// Anything else: a link, a reparse point, a device, a socket, a FIFO.
    Other,
}

/// Durable identity of a file or directory on its volume: device and inode
/// on Unix, volume serial number and file index on Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Identity(pub [u64; 2]);

/// Metadata of one entry, taken without following links.
#[derive(Clone, Copy, Debug)]
pub struct Stat {
    pub kind: Kind,
    pub size: u64,
    pub links: u64,
    pub identity: Identity,
}

/// One directory listing entry.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
}

/// Who can reach a file or directory.
#[derive(Clone, Copy, Debug)]
pub struct Privacy {
    /// The calling user owns it.
    pub owned: bool,
    /// Someone other than the owner and the system has any permission.
    pub shared: bool,
    /// The exact permission bits on Unix; `None` where modes do not exist.
    pub mode: Option<u32>,
}

impl Privacy {
    /// Owner-only: the caller owns it and nobody else may reach it.
    pub fn is_private(&self) -> bool {
        self.owned && !self.shared
    }
}

/// Validate one path component for a handle-relative operation. Separators
/// and the two directory aliases never reach the operating system.
pub(crate) fn component(name: &str) -> Result<&str, Denied> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.bytes().any(|b| matches!(b, b'/' | b'\\' | 0))
    {
        return Err(Denied::new("invalid path component"));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_are_single_names() {
        assert!(component("state.txt").is_ok());
        assert!(component("").is_err());
        assert!(component(".").is_err());
        assert!(component("..").is_err());
        assert!(component("a/b").is_err());
        assert!(component("a\\b").is_err());
        assert!(component("a\0b").is_err());
        assert!(component(&"x".repeat(256)).is_err());
    }
}
