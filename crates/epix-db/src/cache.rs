//! Lifetime tracking for disposable node-private SQLite cache files.

use epix_core::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

type Registry = (Mutex<HashMap<PathBuf, Weak<CacheLease>>>, Condvar);

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| (Mutex::new(HashMap::new()), Condvar::new()))
}

fn absolute(path: &Path) -> Result<PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let name = path
                .file_name()
                .ok_or_else(|| Error::Db("invalid private cache path".into()))?;
            Ok(parent.canonicalize()?.join(name))
        }
        Err(error) => Err(error.into()),
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn remove_files(path: &Path) -> Result<()> {
    // The retirement marker remains if any deletion fails. A later private
    // cache cleanup may retry after permissions/storage become available.
    for suffix in ["-wal", "-shm", ""] {
        remove_if_present(&sibling(path, suffix))?;
    }
    remove_if_present(&sibling(path, ".retired"))?;
    Ok(())
}

#[derive(Debug)]
pub(crate) struct CacheLease {
    path: PathBuf,
    retired: AtomicBool,
}

impl CacheLease {
    /// Acquire before any SQLite handle opens. A zero-strong Weak can mean its
    /// destructor is waiting for this mutex; wait for cleanup instead of opening
    /// a new database which that destructor would subsequently unlink.
    pub(crate) fn acquire(path: &Path) -> Result<Arc<Self>> {
        let path = absolute(path)?;
        let (mutex, changed) = registry();
        let mut entries = mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(entry) = entries.get(&path) {
                if let Some(lease) = entry.upgrade() {
                    return Ok(lease);
                }
                entries = changed
                    .wait(entries)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            } else {
                let lease = Arc::new(Self {
                    path: path.clone(),
                    retired: AtomicBool::new(false),
                });
                entries.insert(path, Arc::downgrade(&lease));
                return Ok(lease);
            }
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A validated same-path owner can take over a cache awaiting its last old
    /// reader. The caller must still reverify source authority before exposure.
    pub(crate) fn revive(&self) -> Result<()> {
        let _registry = registry()
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        remove_if_present(&sibling(&self.path, ".retired"))?;
        self.retired.store(false, Ordering::Release);
        Ok(())
    }

    pub(crate) fn retire(&self) -> Result<()> {
        let _registry = registry()
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let marker = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(sibling(&self.path, ".retired"))?;
        marker.sync_all()?;
        self.retired.store(true, Ordering::Release);
        Ok(())
    }

    /// Delete only disposable node-private caches. The caller owns this path
    /// policy; this helper supplies synchronization, not path authorization.
    pub(crate) fn discard(path: &Path) -> Result<bool> {
        let path = absolute(path)?;
        let (mutex, changed) = registry();
        let mut entries = mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match entries.get(&path) {
                Some(entry) if entry.strong_count() != 0 => return Ok(false),
                Some(_) => {
                    entries = changed
                        .wait(entries)
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                }
                None => {
                    remove_files(&path)?;
                    return Ok(true);
                }
            }
        }
    }
}

impl Drop for CacheLease {
    fn drop(&mut self) {
        let (mutex, changed) = registry();
        let mut entries = mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.retired.load(Ordering::Acquire) {
            let _ = remove_files(&self.path);
        }
        entries.remove(&self.path);
        changed.notify_all();
    }
}
