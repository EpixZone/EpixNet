//! Unix implementation: descriptor-relative `rustix` calls with
//! `O_NOFOLLOW`, `O_CLOEXEC` and `O_NONBLOCK`, exactly as the workspace used
//! them before this seam existed.

use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

use evx_api::Denied;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{
    fchmod, flock, fstat, mkdirat, openat, renameat, statat, unlinkat, AtFlags, FileType,
    FlockOperation, Mode, OFlags,
};
use rustix::io::Errno;

use super::{component, Entry, Identity, Kind, Privacy, Stat};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const REGULAR: OFlags = OFlags::NOFOLLOW.union(OFlags::NONBLOCK).union(OFlags::CLOEXEC);

/// An open directory descriptor.
#[derive(Debug)]
pub struct Dir(OwnedFd);

/// The workspace lease: an exclusive `flock` on the directory descriptor.
/// The descriptor itself is what a helper inherits, so the lock travels
/// with it. The lease holds a duplicate, which shares the open file
/// description and therefore the lock, so releasing through it releases
/// the lock the directory took.
#[derive(Debug)]
pub struct Lease {
    fd: OwnedFd,
    held: bool,
}

fn convert(stat: rustix::fs::Stat) -> Stat {
    let kind = match FileType::from_raw_mode(stat.st_mode as rustix::fs::RawMode) {
        FileType::RegularFile => Kind::Regular,
        FileType::Directory => Kind::Directory,
        _ => Kind::Other,
    };
    #[allow(clippy::unnecessary_cast)]
    Stat {
        kind,
        size: stat.st_size.max(0) as u64,
        links: stat.st_nlink as u64,
        identity: Identity([stat.st_dev as u64, stat.st_ino as u64]),
    }
}

fn privacy_of(stat: rustix::fs::Stat) -> Privacy {
    let mode = u32::from(stat.st_mode) & 0o7777;
    Privacy {
        owned: stat.st_uid == rustix::process::geteuid().as_raw(),
        shared: mode & 0o077 != 0,
        mode: Some(mode),
    }
}

impl Dir {
    /// Open a directory by path. The final component is not followed.
    pub fn open_root(path: &Path) -> Result<Dir, Denied> {
        openat(rustix::fs::CWD, path, DIRECTORY, Mode::empty())
            .map(Dir)
            .map_err(|_| Denied::new("workspace root unavailable"))
    }

    /// Open a child directory without following links.
    pub fn open_dir(&self, name: &str) -> Result<Dir, Denied> {
        openat(&self.0, component(name)?, DIRECTORY, Mode::empty())
            .map(Dir)
            .map_err(|_| Denied::new("workspace directory"))
    }

    /// A second descriptor for the same directory, close-on-exec like the
    /// first.
    pub fn try_clone(&self) -> Result<Dir, Denied> {
        rustix::io::fcntl_dupfd_cloexec(&self.0, 0)
            .map(Dir)
            .map_err(|_| Denied::new("workspace descriptor"))
    }

    /// Create a child directory with mode 0700. `Ok(false)` when it exists.
    pub fn create_dir(&self, name: &str) -> Result<bool, Denied> {
        match mkdirat(&self.0, component(name)?, Mode::RWXU) {
            Ok(()) => Ok(true),
            Err(Errno::EXIST) => Ok(false),
            Err(_) => Err(Denied::new("workspace directory")),
        }
    }

    /// Create a host-private child directory. On Unix this is
    /// [`Dir::create_dir`]; on Windows it also applies a protected DACL.
    pub fn create_private_dir(&self, name: &str) -> Result<bool, Denied> {
        self.create_dir(name)
    }

    /// Metadata of a child without following it; `None` when absent.
    pub fn stat(&self, name: &str) -> Result<Option<Stat>, Denied> {
        match statat(&self.0, component(name)?, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(convert(stat))),
            Err(Errno::NOENT) => Ok(None),
            Err(_) => Err(Denied::new("workspace stat")),
        }
    }

    /// Metadata of this directory.
    pub fn stat_self(&self) -> Result<Stat, Denied> {
        fstat(&self.0)
            .map(convert)
            .map_err(|_| Denied::new("workspace stat"))
    }

    /// Open a child for reading without following it; `None` when absent.
    /// The caller checks the returned [`Stat`] before trusting the bytes.
    pub fn open_read(&self, name: &str) -> Result<Option<(File, Stat)>, Denied> {
        self.open_file(name, OFlags::RDONLY | REGULAR)
    }

    /// Open an existing child for reading and writing; `None` when absent.
    pub fn open_write(&self, name: &str) -> Result<Option<(File, Stat)>, Denied> {
        self.open_file(name, OFlags::RDWR | REGULAR)
    }

    fn open_file(&self, name: &str, flags: OFlags) -> Result<Option<(File, Stat)>, Denied> {
        let fd = match openat(&self.0, component(name)?, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(Denied::new("workspace operation denied")),
        };
        let stat = fstat(&fd).map_err(|_| Denied::new("workspace stat"))?;
        Ok(Some((File::from(fd), convert(stat))))
    }

    /// Create a child that must not exist yet, mode 0600, write-only.
    pub fn create_new(&self, name: &str) -> Result<File, Denied> {
        openat(
            &self.0,
            component(name)?,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
        .map_err(|_| Denied::new("workspace operation denied"))
    }

    /// Rename one child over another within this directory.
    pub fn rename(&self, from: &str, to: &str) -> Result<(), Denied> {
        renameat(&self.0, component(from)?, &self.0, component(to)?)
            .map_err(|_| Denied::new("workspace operation denied"))
    }

    /// Remove a child that is not a directory.
    pub fn unlink(&self, name: &str) -> Result<(), Denied> {
        unlinkat(&self.0, component(name)?, AtFlags::empty())
            .map_err(|_| Denied::new("workspace operation denied"))
    }

    /// List the entries without following any of them. The listing uses a
    /// fresh descriptor so it never shares an offset with the caller's.
    pub fn entries(&self) -> Result<Vec<Entry>, Denied> {
        let reader =
            rustix::fs::Dir::read_from(&self.0).map_err(|_| Denied::new("workspace listing"))?;
        let mut entries = Vec::new();
        for entry in reader {
            let entry = entry.map_err(|_| Denied::new("workspace listing"))?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| Denied::new("workspace name encoding"))?
                .to_owned();
            if name == "." || name == ".." {
                continue;
            }
            let stat = statat(&self.0, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| Denied::new("workspace stat"))?;
            let stat = convert(stat);
            entries.push(Entry {
                name,
                kind: stat.kind,
                size: stat.size,
            });
        }
        Ok(entries)
    }

    /// Flush the directory itself, so a completed rename is durable.
    pub fn sync(&self) -> Result<(), Denied> {
        rustix::fs::fsync(&self.0).map_err(|_| Denied::new("workspace operation denied"))
    }

    /// Durable identity of this directory.
    pub fn identity(&self) -> Result<Identity, Denied> {
        Ok(self.stat_self()?.identity)
    }

    /// Who can reach this directory.
    pub fn privacy(&self) -> Result<Privacy, Denied> {
        fstat(&self.0)
            .map(privacy_of)
            .map_err(|_| Denied::new("workspace stat"))
    }

    /// Restrict this directory to its owner (mode 0700).
    pub fn make_private(&self) -> Result<(), Denied> {
        fchmod(&self.0, Mode::RWXU).map_err(|_| Denied::new("workspace operation denied"))
    }

    /// Take the exclusive workspace lease, or report that another holder
    /// has it.
    pub fn lease(&self) -> Result<Lease, Denied> {
        match flock(&self.0, FlockOperation::NonBlockingLockExclusive) {
            // Close-on-exec: only the helper that is meant to inherit the
            // lease gets it, through the spawn path that clears the flag.
            Ok(()) => match rustix::io::fcntl_dupfd_cloexec(&self.0, 0) {
                Ok(fd) => Ok(Lease { fd, held: true }),
                Err(_) => {
                    let _ = flock(&self.0, FlockOperation::Unlock);
                    Err(Denied::new("workspace lease"))
                }
            },
            Err(Errno::WOULDBLOCK) => Err(Denied::new("workspace busy")),
            Err(_) => Err(Denied::new("workspace lease")),
        }
    }

    /// The raw descriptor number.
    pub fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }

}

impl From<OwnedFd> for Dir {
    /// Adopt an inherited directory descriptor the caller already owns.
    fn from(fd: OwnedFd) -> Dir {
        Dir(fd)
    }
}

impl From<Dir> for OwnedFd {
    /// Release the directory as a plain descriptor.
    fn from(dir: Dir) -> OwnedFd {
        dir.0
    }
}

impl AsFd for Dir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Lease {
    /// The descriptor a helper inherits to keep the lease alive.
    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Release the lease.
    pub fn release(mut self) {
        self.unlock();
    }

    /// Keep the lease forever: a quarantined workspace is never released.
    pub fn forget(mut self) {
        self.held = false;
    }

    fn unlock(&mut self) {
        if self.held {
            self.held = false;
            let _ = flock(&self.fd, FlockOperation::Unlock);
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.unlock();
    }
}

/// Metadata of an open file.
pub fn file_stat(file: &File) -> Result<Stat, Denied> {
    fstat(file)
        .map(convert)
        .map_err(|_| Denied::new("workspace stat"))
}

/// Who can reach an open file.
pub fn file_privacy(file: &File) -> Result<Privacy, Denied> {
    fstat(file)
        .map(privacy_of)
        .map_err(|_| Denied::new("workspace stat"))
}

/// Try an exclusive non-blocking lock on an open file. `Ok(false)` when
/// another holder has it.
pub fn try_lock_file(file: &File) -> Result<bool, Denied> {
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(Errno::WOULDBLOCK) => Ok(false),
        Err(_) => Err(Denied::new("workspace lock")),
    }
}

/// Release a lock taken with [`try_lock_file`].
pub fn unlock_file(file: &File) -> Result<(), Denied> {
    flock(file, FlockOperation::Unlock).map_err(|_| Denied::new("workspace lock"))
}
