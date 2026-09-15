//! Local wallet staging, shared with the browser regression tests.
use std::io::Read;
use std::path::Path;

/// Track every source asset: JavaScript can change without a manifest bump.
/// Reuse identical staged trees so incremental builds do not rewrite the XPI.
pub fn stage_from_local(src: &Path, dest: &Path) {
    println!("cargo:rerun-if-changed={}", src.display());
    if !src.join("manifest.json").is_file() {
        panic!("EPIX_WALLET_DIST={} has no manifest.json; point it at the wallet's apps/extension/build/firefox directory", src.display());
    }
    if same_tree(src, dest, true).unwrap_or(false) {
        return;
    }
    clear_dir_keep_readme(dest);
    copy_dir(src, dest).expect("copy EPIX_WALLET_DIST into shells/wallet-ext");
}

fn same_tree(a: &Path, b: &Path, root: bool) -> std::io::Result<bool> {
    fn names(dir: &Path, root: bool) -> std::io::Result<Vec<std::ffi::OsString>> {
        let mut result = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let name = entry?.file_name();
            if !root || name != "README.md" {
                result.push(name);
            }
        }
        result.sort();
        Ok(result)
    }
    let entries = names(a, root)?;
    if entries != names(b, root)? {
        return Ok(false);
    }
    for name in entries {
        let a = a.join(&name);
        let b = b.join(&name);
        if a.is_dir() && b.is_dir() {
            if !same_tree(&a, &b, false)? {
                return Ok(false);
            }
        } else if !a.is_file() || !b.is_file() || !same_file(&a, &b)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Compare in bounded chunks: built wallet bundles can be hundreds of MB.
fn same_file(a: &Path, b: &Path) -> std::io::Result<bool> {
    let mut a = std::fs::File::open(a)?;
    let mut b = std::fs::File::open(b)?;
    let size = a.metadata()?.len();
    if size != b.metadata()?.len() {
        return Ok(false);
    }
    let mut remaining = size;
    let mut left = [0u8; 65536];
    let mut right = [0u8; 65536];
    while remaining > 0 {
        let n = remaining.min(left.len() as u64) as usize;
        a.read_exact(&mut left[..n])?;
        b.read_exact(&mut right[..n])?;
        if left[..n] != right[..n] {
            return Ok(false);
        }
        remaining -= n as u64;
    }
    Ok(true)
}

/// Remove everything in `dir` except README.md (the one git-tracked file).
pub fn clear_dir_keep_readme(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() == "README.md" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
}

pub fn copy_dir(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "epix-stage-{}-{nonce}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            // Fail on collision; never reuse someone else's directory.
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn source(&self) -> PathBuf {
            let src = self.0.join("source");
            std::fs::create_dir_all(src.join("assets")).unwrap();
            std::fs::write(src.join("manifest.json"), r#"{"version":"1"}"#).unwrap();
            src
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn changed_bundle_with_unchanged_manifest_is_staged() {
        let fixture = Fixture::new();
        let src = fixture.source();
        let dest = fixture.0.join("dest");
        std::fs::write(src.join("assets/background.js"), "old code").unwrap();
        stage_from_local(&src, &dest);
        std::fs::write(src.join("assets/background.js"), "new code").unwrap();
        stage_from_local(&src, &dest);
        assert_eq!(
            std::fs::read_to_string(dest.join("assets/background.js")).unwrap(),
            "new code"
        );
    }

    #[test]
    fn removed_assets_are_removed_and_readme_preserved() {
        let fixture = Fixture::new();
        let src = fixture.source();
        let dest = fixture.0.join("dest");
        std::fs::write(src.join("old.js"), "old").unwrap();
        stage_from_local(&src, &dest);
        std::fs::write(dest.join("README.md"), "tracked instructions").unwrap();
        std::fs::remove_file(src.join("old.js")).unwrap();
        std::fs::write(src.join("assets/new.js"), "new").unwrap();
        stage_from_local(&src, &dest);
        assert!(!dest.join("old.js").exists());
        assert_eq!(
            std::fs::read_to_string(dest.join("assets/new.js")).unwrap(),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(dest.join("README.md")).unwrap(),
            "tracked instructions"
        );
    }

    #[test]
    fn identical_tree_is_reused_and_large_files_compare_past_first_chunk() {
        let fixture = Fixture::new();
        let src = fixture.source();
        let dest = fixture.0.join("dest");
        let mut bytes = vec![b'x'; 131073];
        std::fs::write(src.join("large.js"), &bytes).unwrap();
        stage_from_local(&src, &dest);
        std::fs::write(dest.join("README.md"), "tracked").unwrap();
        let before = std::fs::metadata(dest.join("large.js"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(same_tree(&src, &dest, true).unwrap());
        stage_from_local(&src, &dest);
        assert_eq!(
            before,
            std::fs::metadata(dest.join("large.js"))
                .unwrap()
                .modified()
                .unwrap()
        );
        *bytes.last_mut().unwrap() = b'y';
        std::fs::write(src.join("large.js"), &bytes).unwrap();
        assert!(!same_tree(&src, &dest, true).unwrap());
        stage_from_local(&src, &dest);
        assert_eq!(std::fs::read(dest.join("large.js")).unwrap(), bytes);
    }
}
