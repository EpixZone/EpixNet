//! On-disk storage for a single xite (its `data/<address>/` directory).

use epix_core::{Error, Result};
use sha2::{Digest, Sha512};
use std::path::{Component, Path, PathBuf};

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
        std::fs::read(self.path(inner_path)?).map_err(Error::Io)
    }

    pub fn write(&self, inner_path: &str, bytes: &[u8]) -> Result<()> {
        let p = self.path(inner_path)?;
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        std::fs::write(&p, bytes).map_err(Error::Io)
    }

    /// Write `inner_path` atomically: write a sibling temp file, fsync it, then
    /// rename it over the target (an atomic replace on a single filesystem), and
    /// best-effort fsync the parent directory. Used for the `content.json` commit
    /// so a crash mid-write never leaves a half-written commit marker. Data files
    /// use plain [`Self::write`] - they are hash-verified, so a torn one just
    /// fails `verify` and is re-downloaded.
    pub fn write_atomic(&self, inner_path: &str, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let p = self.path(inner_path)?;
        let parent =
            p.parent().ok_or_else(|| Error::Other(format!("no parent dir: {inner_path}")))?;
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("content.json");
        let tmp = parent.join(format!("{name}.epixtmp"));
        {
            let mut f = std::fs::File::create(&tmp).map_err(Error::Io)?;
            f.write_all(bytes).map_err(Error::Io)?;
            f.sync_all().map_err(Error::Io)?;
        }
        if let Err(e) = std::fs::rename(&tmp, &p) {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        // Best-effort durability of the rename itself.
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Delete a stored file, pruning any directories the removal left empty.
    pub fn delete(&self, inner_path: &str) -> Result<()> {
        let p = self.path(inner_path)?;
        std::fs::remove_file(&p).map_err(Error::Io)?;
        // Best effort: remove now-empty parent dirs up to (not including) root.
        let mut dir = p.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d == self.root || std::fs::remove_dir(&d).is_err() {
                break;
            }
            dir = d.parent().map(Path::to_path_buf);
        }
        Ok(())
    }

    /// content.json file hash: hex of the first 32 bytes of SHA-512
    /// (`sha512(bytes).hexdigest()[:64]`).
    pub fn hash_bytes(bytes: &[u8]) -> String {
        let digest = Sha512::digest(bytes);
        hex::encode(&digest[..32])
    }

    /// True if the stored file exists and matches `expected_sha512`.
    pub fn verify(&self, inner_path: &str, expected_sha512: &str) -> bool {
        match self.read(inner_path) {
            Ok(bytes) => Self::hash_bytes(&bytes) == expected_sha512,
            Err(_) => false,
        }
    }

    /// Every file under the root as an `inner_path` (relative, forward slashes).
    pub fn list_files(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(rel) = p.strip_prefix(&self.root) {
                    out.push(rel.to_string_lossy().replace('\\', "/"));
                }
            }
        }
        out
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
            .into_iter()
            .filter(|f| f.ends_with(".epixtmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }
}
