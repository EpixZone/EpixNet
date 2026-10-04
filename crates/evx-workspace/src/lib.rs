//! Private workspace operations.
//!
//! Every operation starts from an already-open directory descriptor for the
//! workspace root and walks one validated component at a time with
//! `O_NOFOLLOW | O_DIRECTORY`. Files must be regular with a link count of one.
//! Writes stage into a `.pending-<random>` sibling, `fsync`, then `rename`
//! over the target after the caller authorizes the commit. Nothing here resolves
//! a path string against the host filesystem. Symlinks and special files are
//! refused. A link-count snapshot cannot prove origin under concurrent hard-link
//! replacement: an opened alias can disappear before fstat. The trusted broker
//! must verify read bytes against host-owned write provenance before releasing
//! them to a guest. This crate alone is not that provenance boundary.
//!
//! The same code runs in the trusted supervisor (for quota accounting) and in
//! the OS-confined file helper (for the actual read or write), which is why
//! this crate has no dependency on either.

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{
    fstat, fsync, mkdirat, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode, OFlags,
};

use evx_api::{validate_relative_path, Denied, Response, MAX_ENTRIES, MAX_FILE};

const MAX_DEPTH: usize = 8;
const STAGING_PREFIX: &str = ".pending-";

/// Open a workspace root. Refuses symlinks and non-directories.
pub fn open_root(path: &std::path::Path) -> Result<OwnedFd, Denied> {
    openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Denied::new("workspace root unavailable"))
}

/// Bytes and entry count currently used, walking at most `MAX_DEPTH` levels
/// and `MAX_ENTRIES` entries. Symlinks are counted as entries but never
/// followed. Fails closed if the workspace is larger than the bounds.
pub fn usage(root: BorrowedFd<'_>) -> Result<(u64, usize), Denied> {
    let mut total = 0u64;
    let mut count = 0usize;
    walk(root, 0, &mut |fd, name, kind, size| {
        count += 1;
        if count > MAX_ENTRIES {
            return Err(Denied::new("workspace entry limit"));
        }
        if kind == FileType::RegularFile {
            total += size;
        }
        let _ = (fd, name);
        Ok(())
    })?;
    Ok((total, count))
}

/// Remove abandoned staging files left by a helper that died before commit.
/// Call only while holding the workspace lease.
pub fn cleanup_staging(root: BorrowedFd<'_>) -> Result<(), Denied> {
    let mut visited = 0usize;
    walk(root, 0, &mut |fd, name, kind, _| {
        visited += 1;
        if visited > MAX_ENTRIES {
            return Err(Denied::new("workspace entry limit"));
        }
        if kind == FileType::RegularFile && is_staging_name(name) {
            let st = statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| Denied::new("workspace stat"))?;
            if st.st_nlink == 1 {
                let _ = unlinkat(fd, name, AtFlags::empty());
            }
        }
        Ok(())
    })
}

fn is_staging_name(name: &str) -> bool {
    name.len() == STAGING_PREFIX.len() + 32
        && name.starts_with(STAGING_PREFIX)
        && name[STAGING_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
}

type Visitor<'a> = dyn FnMut(BorrowedFd<'_>, &str, FileType, u64) -> Result<(), Denied> + 'a;

fn walk(
    dir: BorrowedFd<'_>,
    depth: usize,
    visit: &mut Visitor<'_>,
) -> Result<(), Denied> {
    if depth > MAX_DEPTH {
        return Err(Denied::new("directory depth limit"));
    }
    // read_from reopens the directory so the listing never shares a file
    // offset with the caller's descriptor.
    let reader = rustix::fs::Dir::read_from(dir).map_err(|_| Denied::new("workspace listing"))?;
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
        let st = statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Denied::new("workspace stat"))?;
        let kind = FileType::from_raw_mode(st.st_mode as rustix::fs::RawMode);
        visit(dir, &name, kind, st.st_size as u64)?;
        if kind == FileType::Directory {
            let child = openat(
                dir,
                name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Denied::new("workspace directory"))?;
            walk(child.as_fd(), depth + 1, visit)?;
        }
    }
    Ok(())
}

/// Open the parent directory of a validated relative path, optionally creating
/// intermediate directories with mode 0700.
fn parent_fd(root: BorrowedFd<'_>, parts: &[&str], create: bool) -> Result<OwnedFd, Denied> {
    let mut fd = rustix::io::dup(root).map_err(|_| Denied::new("workspace descriptor"))?;
    for part in &parts[..parts.len() - 1] {
        if create {
            match mkdirat(fd.as_fd(), *part, Mode::RWXU) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(Denied::new("workspace directory")),
            }
        }
        let child = openat(
            fd.as_fd(),
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Denied::new("workspace directory"))?;
        fd = child;
    }
    Ok(fd)
}

/// Read one bounded regular file.
pub fn read(root: BorrowedFd<'_>, path: &str) -> Result<Response, Denied> {
    let parts = validate_relative_path(path)?;
    let parent = parent_fd(root, &parts, false)?;
    let fd = openat(
        parent.as_fd(),
        *parts.last().expect("validated path has a component"),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::NOENT {
            Denied::new("workspace file absent")
        } else {
            Denied::new("workspace operation denied")
        }
    })?;
    let st = fstat(&fd).map_err(|_| Denied::new("workspace stat"))?;
    let kind = FileType::from_raw_mode(st.st_mode as rustix::fs::RawMode);
    if kind != FileType::RegularFile || st.st_nlink != 1 {
        return Err(Denied::new("not an isolated regular file"));
    }
    if st.st_size as u64 > MAX_FILE as u64 {
        return Err(Denied::new("file read limit"));
    }
    let mut file = std::fs::File::from(fd);
    let mut data = Vec::with_capacity(MAX_FILE + 1);
    std::io::Read::by_ref(&mut file)
        .take(MAX_FILE as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|_| Denied::new("workspace operation denied"))?;
    if data.len() > MAX_FILE {
        return Err(Denied::new("file read limit"));
    }
    Ok(Response::Read {
        ok: true,
        data_b64: B64.encode(&data),
        bytes: data.len(),
    })
}

/// A staged write awaiting commit authorization.
pub struct StagedWrite {
    parent: OwnedFd,
    temp: String,
    target: String,
    bytes: usize,
}

impl StagedWrite {
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Promote the staged bytes over the target. The rename itself is the
    /// effect; a failure after it returns an error even though the file
    /// changed, which the caller must report as an uncertain effect.
    pub fn commit(
        self,
        after_replace: Option<&dyn Fn() -> Result<(), Denied>>,
    ) -> Result<Response, Denied> {
        let result = (|| {
            renameat(
                self.parent.as_fd(),
                self.temp.as_str(),
                self.parent.as_fd(),
                self.target.as_str(),
            )
            .map_err(|_| Denied::new("workspace operation denied"))?;
            if let Some(hook) = after_replace {
                hook()?;
            }
            fsync(self.parent.as_fd()).map_err(|_| Denied::new("workspace operation denied"))?;
            Ok(Response::Write {
                ok: true,
                bytes: self.bytes,
            })
        })();
        let _ = unlinkat(self.parent.as_fd(), self.temp.as_str(), AtFlags::empty());
        result
    }

    /// Discard the staged bytes.
    pub fn abort(self) {
        let _ = unlinkat(self.parent.as_fd(), self.temp.as_str(), AtFlags::empty());
    }
}

/// Validate quota, stage the bytes durably and return a handle for commit.
pub fn stage_write(
    root: BorrowedFd<'_>,
    path: &str,
    text: &str,
    storage_limit: u64,
) -> Result<StagedWrite, Denied> {
    let data = text.as_bytes();
    if data.len() > MAX_FILE {
        return Err(Denied::new("file write limit"));
    }
    let parts = validate_relative_path(path)?;
    let (used, count) = usage(root)?;
    // The temporary copy counts against the quota even when replacing.
    if used + data.len() as u64 > storage_limit {
        return Err(Denied::new("storage quota exceeded"));
    }
    if count + parts.len() + 1 > MAX_ENTRIES {
        return Err(Denied::new("workspace entry limit"));
    }
    let parent = parent_fd(root, &parts, true)?;
    let target = parts
        .last()
        .expect("validated path has a component")
        .to_string();
    match statat(parent.as_fd(), target.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => {
            let kind = FileType::from_raw_mode(st.st_mode as rustix::fs::RawMode);
            if kind != FileType::RegularFile || st.st_nlink != 1 {
                return Err(Denied::new("not an isolated regular file"));
            }
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(_) => return Err(Denied::new("workspace operation denied")),
    }
    let temp = format!("{STAGING_PREFIX}{}", random_hex());
    let fd = openat(
        parent.as_fd(),
        temp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| Denied::new("workspace operation denied"))?;
    let staged = StagedWrite {
        parent,
        temp,
        target,
        bytes: data.len(),
    };
    let mut file = std::fs::File::from(fd);
    if file.write_all(data).is_err() || file.sync_all().is_err() {
        staged.abort();
        return Err(Denied::new("workspace operation denied"));
    }
    Ok(staged)
}

fn random_hex() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn root() -> (tempfile::TempDir, OwnedFd) {
        let dir = tempfile::tempdir().unwrap();
        let fd = open_root(dir.path()).unwrap();
        (dir, fd)
    }

    #[test]
    fn write_then_read_round_trip() {
        let (dir, fd) = root();
        let staged = stage_write(fd.as_fd(), "state/presence.txt", "game fixture", 4096).unwrap();
        assert!(matches!(
            staged.commit(None).unwrap(),
            Response::Write {
                ok: true,
                bytes: 12
            }
        ));
        let read = read(fd.as_fd(), "state/presence.txt").unwrap();
        match read {
            Response::Read {
                data_b64, bytes, ..
            } => {
                assert_eq!(bytes, 12);
                assert_eq!(B64.decode(data_b64).unwrap(), b"game fixture");
            }
            other => panic!("{other:?}"),
        }
        assert!(dir.path().join("state/presence.txt").exists());
        assert_eq!(usage(fd.as_fd()).unwrap(), (12, 2));
    }

    #[test]
    fn links_special_files_and_escapes_are_refused() {
        let (dir, fd) = root();
        let outside = dir
            .path()
            .parent()
            .unwrap()
            .join(format!("evx-ws-outside-{}", random_hex()));
        std::fs::write(&outside, "secret").unwrap();
        symlink(&outside, dir.path().join("outside-link")).unwrap();
        std::fs::hard_link(&outside, dir.path().join("hard-link")).unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        symlink(dir.path().join("real"), dir.path().join("dir-link")).unwrap();
        std::fs::write(dir.path().join("real/private.txt"), "x").unwrap();
        assert!(read(fd.as_fd(), "outside-link").is_err());
        assert!(read(fd.as_fd(), "hard-link").is_err());
        assert!(read(fd.as_fd(), "dir-link/private.txt").is_err());
        assert!(read(fd.as_fd(), "../outside").is_err());
        assert!(stage_write(fd.as_fd(), "outside-link", "changed", 4096).is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "secret");
        std::fs::remove_file(&outside).unwrap();
    }

    #[test]
    fn quota_and_entry_limits_fail_before_mutation() {
        let (dir, fd) = root();
        assert!(stage_write(fd.as_fd(), "big.txt", &"x".repeat(100), 50).is_err());
        assert!(stage_write(fd.as_fd(), "a/b/c/d/e/f/g/h/i.txt", "x", 4096).is_err());
        let long = format!("must-not-create/{}", "x".repeat(300));
        assert!(stage_write(fd.as_fd(), &long, "x", 4096).is_err());
        assert!(!dir.path().join("must-not-create").exists());
        assert_eq!(usage(fd.as_fd()).unwrap(), (0, 0));
    }

    #[test]
    fn staging_cleanup_only_removes_orphans() {
        let (dir, fd) = root();
        let staged = stage_write(fd.as_fd(), "s.txt", "x", 4096).unwrap();
        let temp_name = staged.temp.clone();
        std::mem::forget(staged);
        assert!(dir.path().join(&temp_name).exists());
        std::fs::write(dir.path().join(".pending-not-hex"), "keep").unwrap();
        cleanup_staging(fd.as_fd()).unwrap();
        assert!(!dir.path().join(&temp_name).exists());
        assert!(dir.path().join(".pending-not-hex").exists());
    }

    #[test]
    fn staged_parent_replacement_cannot_redirect_commit() {
        let (dir, fd) = root();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("score.txt"), "outside secret").unwrap();
        let staged = stage_write(fd.as_fd(), "round/score.txt", "updated", 4096).unwrap();
        std::fs::rename(dir.path().join("round"), dir.path().join("retired")).unwrap();
        symlink(outside.path(), dir.path().join("round")).unwrap();
        staged.commit(None).unwrap();
        assert_eq!(std::fs::read(outside.path().join("score.txt")).unwrap(), b"outside secret");
        assert_eq!(std::fs::read(dir.path().join("retired/score.txt")).unwrap(), b"updated");
        assert!(read(fd.as_fd(), "round/score.txt").is_err());
    }

    #[test]
    fn target_link_inserted_after_staging_cannot_redirect_commit() {
        for hard in [false, true] {
            let (dir, fd) = root();
            let outside = tempfile::tempdir().unwrap();
            let secret = outside.path().join("secret");
            std::fs::write(&secret, "outside secret").unwrap();
            let staged = stage_write(fd.as_fd(), "score.txt", "updated", 4096).unwrap();
            let target = dir.path().join("score.txt");
            if hard { std::fs::hard_link(&secret, &target).unwrap(); }
            else { symlink(&secret, &target).unwrap(); }
            staged.commit(None).unwrap();
            assert_eq!(std::fs::read(&secret).unwrap(), b"outside secret");
            assert_eq!(std::fs::read(&target).unwrap(), b"updated");
            assert!(!target.is_symlink());
        }
    }


}
