//! Private workspace operations.
//!
//! Every operation starts from an already-open directory ([`Dir`]) for the
//! workspace root and walks one validated component at a time without
//! following links. Files must be regular with a link count of one. Writes
//! stage into a `.pending-<random>` sibling, flush, then rename over the
//! target after the caller authorizes the commit. Nothing here resolves a
//! path string against the host filesystem. Links, reparse points and
//! special files are refused. A link-count snapshot cannot prove origin
//! under concurrent hard-link replacement: an opened alias can disappear
//! before it is examined. The trusted broker must verify read bytes against
//! host-owned write provenance before releasing them to a guest. This crate
//! alone is not that provenance boundary.
//!
//! The same code runs in the trusted supervisor (for quota accounting) and
//! in the OS-confined file helper (for the actual read or write), which is
//! why this crate has no dependency on either. The platform seam is
//! [`sys`]: `openat` and `flock` on Unix, handle-relative NT opens and an
//! exclusive directory handle on Windows (`docs/evx-windows-backend.md`).

// Only the platform modules may use `unsafe`, for the raw OS calls.
#![deny(unsafe_code)]

use std::io::{Read, Write};
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use evx_api::{validate_relative_path, Denied, Response, MAX_ENTRIES, MAX_FILE};

pub mod sys;
pub use sys::{Dir, Entry, Identity, Kind, Lease, Privacy, Stat};

const MAX_DEPTH: usize = 8;
const STAGING_PREFIX: &str = ".pending-";

/// Open a workspace root. Refuses links and non-directories.
pub fn open_root(path: &Path) -> Result<Dir, Denied> {
    Dir::open_root(path)
}

/// Bytes and entry count currently used, walking at most `MAX_DEPTH` levels
/// and `MAX_ENTRIES` entries. Links are counted as entries but never
/// followed. Fails closed if the workspace is larger than the bounds.
pub fn usage(root: &Dir) -> Result<(u64, usize), Denied> {
    let mut total = 0u64;
    let mut count = 0usize;
    walk(root, 0, &mut |_, _, kind, size| {
        count += 1;
        if count > MAX_ENTRIES {
            return Err(Denied::new("workspace entry limit"));
        }
        if kind == Kind::Regular {
            total += size;
        }
        Ok(())
    })?;
    Ok((total, count))
}

/// Remove abandoned staging files left by a helper that died before commit.
/// Call only while holding the workspace lease.
pub fn cleanup_staging(root: &Dir) -> Result<(), Denied> {
    let mut visited = 0usize;
    walk(root, 0, &mut |dir, name, kind, _| {
        visited += 1;
        if visited > MAX_ENTRIES {
            return Err(Denied::new("workspace entry limit"));
        }
        if kind == Kind::Regular && is_staging_name(name) {
            let stat = dir.stat(name)?.ok_or_else(|| Denied::new("workspace stat"))?;
            if stat.links == 1 {
                let _ = dir.unlink(name);
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

type Visitor<'a> = dyn FnMut(&Dir, &str, Kind, u64) -> Result<(), Denied> + 'a;

fn walk(dir: &Dir, depth: usize, visit: &mut Visitor<'_>) -> Result<(), Denied> {
    if depth > MAX_DEPTH {
        return Err(Denied::new("directory depth limit"));
    }
    for entry in dir.entries()? {
        visit(dir, &entry.name, entry.kind, entry.size)?;
        if entry.kind == Kind::Directory {
            let child = dir.open_dir(&entry.name)?;
            walk(&child, depth + 1, visit)?;
        }
    }
    Ok(())
}

/// Open the parent directory of a validated relative path, optionally
/// creating intermediate directories.
fn parent(root: &Dir, parts: &[&str], create: bool) -> Result<Dir, Denied> {
    let mut dir = root.try_clone()?;
    for part in &parts[..parts.len() - 1] {
        if create {
            dir.create_dir(part)?;
        }
        dir = dir.open_dir(part)?;
    }
    Ok(dir)
}

/// Read one bounded regular file.
pub fn read(root: &Dir, path: &str) -> Result<Response, Denied> {
    let parts = validate_relative_path(path)?;
    let parent = parent(root, &parts, false)?;
    let name = *parts.last().expect("validated path has a component");
    let (mut file, stat) = parent
        .open_read(name)?
        .ok_or_else(|| Denied::new("workspace file absent"))?;
    if stat.kind != Kind::Regular || stat.links != 1 {
        return Err(Denied::new("not an isolated regular file"));
    }
    if stat.size > MAX_FILE as u64 {
        return Err(Denied::new("file read limit"));
    }
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
    parent: Dir,
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
            self.parent.rename(&self.temp, &self.target)?;
            if let Some(hook) = after_replace {
                hook()?;
            }
            self.parent.sync()?;
            Ok(Response::Write {
                ok: true,
                bytes: self.bytes,
            })
        })();
        let _ = self.parent.unlink(&self.temp);
        result
    }

    /// Discard the staged bytes.
    pub fn abort(self) {
        let _ = self.parent.unlink(&self.temp);
    }
}

/// Validate quota, stage the bytes durably and return a handle for commit.
pub fn stage_write(
    root: &Dir,
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
    let parent = parent(root, &parts, true)?;
    let target = parts
        .last()
        .expect("validated path has a component")
        .to_string();
    if let Some(stat) = parent.stat(&target)? {
        if stat.kind != Kind::Regular || stat.links != 1 {
            return Err(Denied::new("not an isolated regular file"));
        }
    }
    let temp = format!("{STAGING_PREFIX}{}", random_hex());
    let mut file = parent.create_new(&temp)?;
    let staged = StagedWrite {
        parent,
        temp,
        target,
        bytes: data.len(),
    };
    if file.write_all(data).is_err() || file.sync_all().is_err() {
        drop(file);
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

    fn root() -> (tempfile::TempDir, Dir) {
        let dir = tempfile::tempdir().unwrap();
        let root = open_root(dir.path()).unwrap();
        (dir, root)
    }

    #[cfg(unix)]
    fn symlink(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    /// A junction plays the symbolic link's part on Windows: it needs no
    /// privilege and is a reparse point like a symbolic link.
    #[cfg(windows)]
    fn symlink(target: &Path, link: &Path) {
        if target.is_dir() {
            let output = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
        } else {
            std::os::windows::fs::symlink_file(target, link).unwrap();
        }
    }

    /// Whether this host can create file symbolic links (Developer Mode or
    /// the privilege); directory junctions always work.
    fn file_symlinks_available(dir: &Path) -> bool {
        #[cfg(windows)]
        {
            std::fs::write(dir.join("probe-target"), b"x").unwrap();
            std::os::windows::fs::symlink_file(dir.join("probe-target"), dir.join("probe-link"))
                .is_ok()
        }
        #[cfg(unix)]
        {
            let _ = dir;
            true
        }
    }

    #[test]
    fn write_then_read_round_trip() {
        let (dir, fd) = root();
        let staged = stage_write(&fd, "state/presence.txt", "game fixture", 4096).unwrap();
        assert!(matches!(
            staged.commit(None).unwrap(),
            Response::Write {
                ok: true,
                bytes: 12
            }
        ));
        let read = read(&fd, "state/presence.txt").unwrap();
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
        assert_eq!(usage(&fd).unwrap(), (12, 2));
    }

    #[test]
    fn links_special_files_and_escapes_are_refused() {
        let (dir, fd) = root();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret");
        std::fs::write(&secret, "secret").unwrap();
        std::fs::hard_link(&secret, dir.path().join("hard-link")).unwrap();
        std::fs::create_dir(dir.path().join("real")).unwrap();
        symlink(&dir.path().join("real"), &dir.path().join("dir-link"));
        std::fs::write(dir.path().join("real/private.txt"), "x").unwrap();
        if file_symlinks_available(outside.path()) {
            symlink(&secret, &dir.path().join("outside-link"));
            assert!(read(&fd, "outside-link").is_err());
            assert!(stage_write(&fd, "outside-link", "changed", 4096).is_err());
        }
        assert!(read(&fd, "hard-link").is_err());
        assert!(read(&fd, "dir-link/private.txt").is_err());
        assert!(read(&fd, "../outside").is_err());
        assert_eq!(std::fs::read_to_string(&secret).unwrap(), "secret");
    }

    #[test]
    fn quota_and_entry_limits_fail_before_mutation() {
        let (dir, fd) = root();
        assert!(stage_write(&fd, "big.txt", &"x".repeat(100), 50).is_err());
        assert!(stage_write(&fd, "a/b/c/d/e/f/g/h/i.txt", "x", 4096).is_err());
        let long = format!("must-not-create/{}", "x".repeat(300));
        assert!(stage_write(&fd, &long, "x", 4096).is_err());
        assert!(!dir.path().join("must-not-create").exists());
        assert_eq!(usage(&fd).unwrap(), (0, 0));
    }

    #[test]
    fn staging_cleanup_only_removes_orphans() {
        let (dir, fd) = root();
        let staged = stage_write(&fd, "s.txt", "x", 4096).unwrap();
        let temp_name = staged.temp.clone();
        std::mem::forget(staged);
        assert!(dir.path().join(&temp_name).exists());
        std::fs::write(dir.path().join(".pending-not-hex"), "keep").unwrap();
        cleanup_staging(&fd).unwrap();
        assert!(!dir.path().join(&temp_name).exists());
        assert!(dir.path().join(".pending-not-hex").exists());
    }

    #[test]
    fn staged_parent_replacement_cannot_redirect_commit() {
        let (dir, fd) = root();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("score.txt"), "outside secret").unwrap();
        let staged = stage_write(&fd, "round/score.txt", "updated", 4096).unwrap();
        // On Unix the parent is renamed away and a link planted in its
        // place; the commit still lands in the directory that was opened.
        // On Windows the open directory handle refuses the rename itself,
        // and the commit lands in the only `round` there is. Either way the
        // outside file is untouched.
        let renamed = std::fs::rename(dir.path().join("round"), dir.path().join("retired")).is_ok();
        if renamed {
            symlink(outside.path(), &dir.path().join("round"));
        }
        staged.commit(None).unwrap();
        assert_eq!(std::fs::read(outside.path().join("score.txt")).unwrap(), b"outside secret");
        let landed = if renamed { "retired/score.txt" } else { "round/score.txt" };
        assert_eq!(std::fs::read(dir.path().join(landed)).unwrap(), b"updated");
        if renamed {
            assert!(read(&fd, "round/score.txt").is_err());
        }
    }

    #[test]
    fn target_link_inserted_after_staging_cannot_redirect_commit() {
        for hard in [false, true] {
            let (dir, fd) = root();
            let outside = tempfile::tempdir().unwrap();
            let secret = outside.path().join("secret");
            std::fs::write(&secret, "outside secret").unwrap();
            if !hard && !file_symlinks_available(outside.path()) {
                continue;
            }
            let staged = stage_write(&fd, "score.txt", "updated", 4096).unwrap();
            let target = dir.path().join("score.txt");
            if hard {
                std::fs::hard_link(&secret, &target).unwrap();
            } else {
                symlink(&secret, &target);
            }
            staged.commit(None).unwrap();
            assert_eq!(std::fs::read(&secret).unwrap(), b"outside secret");
            assert_eq!(std::fs::read(&target).unwrap(), b"updated");
            assert!(!target.is_symlink());
        }
    }
}
