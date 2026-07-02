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
}
