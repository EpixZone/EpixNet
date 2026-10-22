//! Bounded, disposable headroom for the durable xite-removal journal.
//!
//! The reserve is not a removal receipt. Consuming it never authorizes a tree
//! deletion, and an already-full upgrade may have no reserve to consume.

use epix_xite::XiteStorage;
use serde::Serialize;
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

const RESERVE_NAME: &str = "deletion-reserve";
const RESERVE_BYTES: u64 = 16 * 1024 * 1024;
const MAGIC: &[u8] = b"EpixNet deletion metadata reserve v1\n";
const CHUNK: usize = 64 * 1024;

pub(crate) struct DeletionReserve {
    directory: PathBuf,
    operation: Mutex<()>,
}

enum ReserveRelease {
    Absent,
    Released { sync_warning: Option<io::Error> },
}

fn as_io(error: epix_core::Error) -> io::Error {
    match error {
        epix_core::Error::Io(error) => error,
        error => io::Error::new(io::ErrorKind::InvalidInput, error.to_string()),
    }
}

fn capacity_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded
    )
}

impl DeletionReserve {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            operation: Mutex::new(()),
        }
    }

    fn storage(&self) -> XiteStorage {
        XiteStorage::new(&self.directory)
    }

    fn checked_reserve(&self) -> io::Result<Option<Metadata>> {
        let metadata = match std::fs::symlink_metadata(self.directory.join(RESERVE_NAME)) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > RESERVE_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unrecognized deletion reserve",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "deletion reserve is hard-linked",
                ));
            }
        }
        // Creation can stop before the header is complete, including directly
        // after create_new. Only an exact prefix at this reserved pathname is
        // an interrupted header; any different byte remains unrecognized.
        // This range reader also rejects symlinks and Windows reparse points.
        let header_len = metadata.len().min(MAGIC.len() as u64) as usize;
        let header = self
            .storage()
            .read_range(RESERVE_NAME, 0, header_len)
            .map_err(as_io)?;
        if header.len() != header_len || !MAGIC.starts_with(&header) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unrecognized deletion reserve",
            ));
        }
        Ok(Some(metadata))
    }

    /// Call only while the removal journal is known to be empty. Existing
    /// pending removals get the available space before any reserve refill.
    pub(crate) fn ensure(&self) -> io::Result<()> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_locked(RESERVE_BYTES)
    }

    fn ensure_locked(&self, bytes: u64) -> io::Result<()> {
        self.ensure_with(bytes, allocate)
    }

    fn ensure_with(
        &self,
        bytes: u64,
        allocate: impl FnOnce(&mut File, u64) -> io::Result<()>,
    ) -> io::Result<()> {
        if let Some(metadata) = self.checked_reserve()? {
            let allocated = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    metadata.blocks().saturating_mul(512) >= bytes
                }
                #[cfg(not(unix))]
                {
                    true
                }
            };
            if metadata.len() >= bytes && allocated {
                return Ok(());
            }
            // A marked partial reserve is left by an interrupted/failed
            // allocation. Rebuild only this disposable, validated file.
            self.storage().delete_durable(RESERVE_NAME).map_err(as_io)?;
        }
        let path = self.directory.join(RESERVE_NAME);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // create_new refuses an existing file or link instead of truncating it.
        let mut file = options.open(&path)?;
        let result = (|| {
            file.write_all(MAGIC)?;
            file.sync_all()?;
            allocate(&mut file, bytes)?;
            file.sync_all()?;
            sync_directory(&self.directory)
        })();
        drop(file);
        if let Err(error) = result {
            // A failed live refill must return its partial allocation, not
            // consume the last free bytes on an already-full upgrade.
            if let Err(cleanup) = self.storage().delete_durable(RESERVE_NAME).map_err(as_io) {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; could not remove incomplete deletion reserve: {cleanup}"),
                ));
            }
            return Err(error);
        }
        Ok(())
    }

    fn release_locked(&self) -> io::Result<ReserveRelease> {
        self.release_locked_with(|| self.storage().delete_durable(RESERVE_NAME).map_err(as_io))
    }

    fn release_locked_with(
        &self,
        delete: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<ReserveRelease> {
        if self.checked_reserve()?.is_none() {
            return Ok(ReserveRelease::Absent);
        }
        match delete() {
            Ok(()) => Ok(ReserveRelease::Released { sync_warning: None }),
            Err(error) => {
                // Durable deletion can unlink successfully and then fail its
                // directory sync. The reclaimed space is already usable; the
                // successful journal retry syncs this same directory and thus
                // settles both changes. Absence must be confirmed, not guessed
                // from the error kind, before treating the reserve as released.
                match std::fs::symlink_metadata(self.directory.join(RESERVE_NAME)) {
                    Err(absent) if absent.kind() == io::ErrorKind::NotFound => {
                        Ok(ReserveRelease::Released {
                            sync_warning: Some(error),
                        })
                    }
                    _ => Err(error),
                }
            }
        }
    }

    fn recover_capacity<T>(&self, write: impl FnMut() -> io::Result<T>) -> io::Result<T> {
        self.recover_capacity_with(write, || self.release_locked())
    }

    fn recover_capacity_with<T>(
        &self,
        mut write: impl FnMut() -> io::Result<T>,
        release: impl FnOnce() -> io::Result<ReserveRelease>,
    ) -> io::Result<T> {
        let _operation = self
            .operation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match write() {
            Ok(value) => Ok(value),
            Err(first) if capacity_error(&first) => {
                let released = release().map_err(|release| {
                    io::Error::new(first.kind(), format!(
                        "{first}; could not release deletion reserve: {release}. Free device storage and retry"
                    ))
                })?;
                let ReserveRelease::Released { sync_warning } = released else {
                    return Err(io::Error::new(
                        first.kind(),
                        format!(
                        "{first}; no deletion reserve is available. Free device storage and retry"
                    ),
                    ));
                };
                write().map_err(|retry| {
                    let release_note = sync_warning
                        .map(|warning| format!("; reserve unlink durability warning: {warning}"))
                        .unwrap_or_default();
                    io::Error::new(retry.kind(), format!(
                        "{retry}; deletion metadata retry failed after releasing reserved space (initial error: {first}{release_note}). Free device storage and retry"
                    ))
                })
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn write_journal(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.recover_capacity(|| {
            self.storage()
                .write_atomic_durable(name, bytes)
                .map_err(as_io)
        })
    }
}

fn allocate(file: &mut File, bytes: u64) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        match rustix::fs::fallocate(&*file, rustix::fs::FallocateFlags::empty(), 0, bytes) {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error,
                    rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::NOSYS
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    // Do not use set_len: it may create a sparse file with no useful headroom.
    let buffer = [0u8; CHUNK];
    let mut remaining = bytes.saturating_sub(MAGIC.len() as u64);
    while remaining > 0 {
        let length = remaining.min(CHUNK as u64) as usize;
        file.write_all(&buffer[..length])?;
        remaining -= length as u64;
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(directory)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // The reserve contains no recovery authority. File contents are synced;
        // journal installation and reserve unlink use the durable storage API.
        let _ = directory;
        Ok(())
    }
}

/// Enforce the installed format's byte limit before allocating or replacing
/// its on-disk counterpart. Encoded output never exceeds `limit` bytes.
pub(crate) fn encode_bounded(value: &impl Serialize, limit: usize) -> Result<Vec<u8>, String> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "removal-intent size limit exceeded",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer_pretty(&mut output, value)
        .map_err(|error| format!("could not encode removal intents: {error}"))?;
    Ok(output.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn reserve() -> (tempfile::TempDir, DeletionReserve) {
        let directory = tempfile::tempdir().unwrap();
        let reserve = DeletionReserve::new(directory.path().to_path_buf());
        reserve.ensure_locked(128 * 1024).unwrap();
        (directory, reserve)
    }

    #[test]
    fn capacity_recovery_releases_real_headroom_and_retries_once() {
        let (directory, reserve) = reserve();
        let path = directory.path().join(RESERVE_NAME);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert!(std::fs::metadata(&path).unwrap().blocks() * 512 >= 128 * 1024);
        }
        let calls = AtomicUsize::new(0);
        reserve
            .recover_capacity(|| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(io::Error::from(io::ErrorKind::StorageFull));
                }
                assert!(!path.exists());
                reserve
                    .storage()
                    .write_atomic_durable("xite-removals.json", b"{}")
                    .map_err(as_io)
            })
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            std::fs::read(directory.path().join("xite-removals.json")).unwrap(),
            b"{}"
        );
        assert!(
            !path.exists(),
            "the write retry must not refill the reserve"
        );
        reserve.ensure_locked(128 * 1024).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn post_unlink_sync_failure_still_retries_the_journal_once() {
        let (directory, reserve) = reserve();
        let path = directory.path().join(RESERVE_NAME);
        let calls = AtomicUsize::new(0);
        reserve
            .recover_capacity_with(
                || {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Err(io::Error::from(io::ErrorKind::StorageFull));
                    }
                    reserve
                        .storage()
                        .write_atomic_durable("xite-removals.json", b"{}")
                        .map_err(as_io)
                },
                || {
                    reserve.release_locked_with(|| {
                        // Execute the unlink, then inject the failure at the
                        // durable-delete boundary before its directory sync.
                        std::fs::remove_file(&path)?;
                        Err(io::Error::new(
                            io::ErrorKind::StorageFull,
                            "post-unlink sync fault",
                        ))
                    })
                },
            )
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(directory.path().join("xite-removals.json")).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn failed_journal_retry_preserves_the_post_unlink_sync_error() {
        let (directory, reserve) = reserve();
        let path = directory.path().join(RESERVE_NAME);
        let calls = AtomicUsize::new(0);
        let error = reserve
            .recover_capacity_with::<()>(
                || {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(io::Error::new(
                            io::ErrorKind::StorageFull,
                            "initial capacity fault",
                        ))
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::QuotaExceeded,
                            "journal retry fault",
                        ))
                    }
                },
                || {
                    reserve.release_locked_with(|| {
                        std::fs::remove_file(&path)?;
                        Err(io::Error::new(
                            io::ErrorKind::StorageFull,
                            "post-unlink sync fault",
                        ))
                    })
                },
            )
            .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(error.kind(), io::ErrorKind::QuotaExceeded);
        for expected in [
            "initial capacity fault",
            "post-unlink sync fault",
            "journal retry fault",
        ] {
            assert!(error.to_string().contains(expected), "{error}");
        }
        assert!(!path.exists());
    }

    #[test]
    fn failed_unlink_keeps_the_reserve_and_does_not_retry() {
        let (directory, reserve) = reserve();
        let path = directory.path().join(RESERVE_NAME);
        let calls = AtomicUsize::new(0);
        let error = reserve
            .recover_capacity_with::<()>(
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::from(io::ErrorKind::StorageFull))
                },
                || {
                    reserve.release_locked_with(|| {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "unlink denied",
                        ))
                    })
                },
            )
            .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(error.to_string().contains("unlink denied"));
        assert!(path.exists());
    }

    #[test]
    fn retry_bound_and_non_capacity_errors_preserve_their_meaning() {
        let (directory, reserve) = reserve();
        let calls = AtomicUsize::new(0);
        let denied = reserve
            .recover_capacity::<()>(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            })
            .unwrap_err();
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(directory.path().join(RESERVE_NAME).exists());
        calls.store(0, Ordering::SeqCst);
        let full = reserve
            .recover_capacity::<()>(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::from(io::ErrorKind::QuotaExceeded))
            })
            .unwrap_err();
        assert_eq!(full.kind(), io::ErrorKind::QuotaExceeded);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(full.to_string().contains("Free device storage"));
    }

    #[test]
    fn absent_reserve_does_not_invent_capacity_or_retry() {
        let directory = tempfile::tempdir().unwrap();
        let reserve = DeletionReserve::new(directory.path().to_path_buf());
        let calls = AtomicUsize::new(0);
        let error = reserve
            .recover_capacity::<()>(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::from(io::ErrorKind::StorageFull))
            })
            .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(error.to_string().contains("no deletion reserve"));
        assert!(!directory.path().join(RESERVE_NAME).exists());
    }

    #[test]
    fn failed_live_allocation_returns_its_partial_space() {
        let directory = tempfile::tempdir().unwrap();
        let reserve = DeletionReserve::new(directory.path().to_path_buf());
        let error = reserve
            .ensure_with(128 * 1024, |file, _| {
                file.write_all(&[0u8; CHUNK])?;
                file.sync_all()?;
                Err(io::Error::from(io::ErrorKind::StorageFull))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert!(!directory.path().join(RESERVE_NAME).exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn partial_marked_reserve_recovers_but_unknown_files_survive() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(RESERVE_NAME);
        let reserve = DeletionReserve::new(directory.path().to_path_buf());
        std::fs::write(&path, MAGIC).unwrap();
        reserve.ensure_locked(128 * 1024).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 128 * 1024);
        std::fs::write(&path, b"operator data").unwrap();
        assert!(reserve.ensure_locked(128 * 1024).is_err());
        assert!(reserve.release_locked().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"operator data");
    }

    #[test]
    fn interrupted_headers_can_be_replenished_or_released() {
        for length in [0, 1, MAGIC.len() - 1, MAGIC.len()] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join(RESERVE_NAME);
            let reserve = DeletionReserve::new(directory.path().to_path_buf());
            std::fs::write(&path, &MAGIC[..length]).unwrap();
            reserve.ensure_locked(128 * 1024).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().len(), 128 * 1024);
            std::fs::write(&path, &MAGIC[..length]).unwrap();
            assert!(matches!(
                reserve.release_locked().unwrap(),
                ReserveRelease::Released { .. }
            ));
            assert!(!path.exists());
        }
    }

    #[test]
    fn mismatched_short_headers_are_never_consumed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(RESERVE_NAME);
        let reserve = DeletionReserve::new(directory.path().to_path_buf());
        for bytes in [b"X".as_slice(), b"EpixNat".as_slice()] {
            std::fs::write(&path, bytes).unwrap();
            assert!(reserve.ensure_locked(128 * 1024).is_err());
            assert!(reserve.release_locked().is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[cfg(unix)]
    #[test]
    fn reserve_never_follows_links_or_consumes_hardlinks() {
        let directory = tempfile::tempdir().unwrap();
        let reserve = DeletionReserve::new(directory.path().to_path_buf());
        let target = directory.path().join("keep");
        let path = directory.path().join(RESERVE_NAME);
        std::fs::write(&target, MAGIC).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(reserve.ensure_locked(128 * 1024).is_err());
        assert!(reserve.release_locked().is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(reserve.ensure_locked(128 * 1024).is_err());
        assert!(reserve.release_locked().is_err());
        assert_eq!(std::fs::read(&target).unwrap(), MAGIC);
    }

    #[test]
    fn serialization_limit_covers_exact_pretty_encoded_bytes() {
        let value = serde_json::json!({"a": "value"});
        let expected = serde_json::to_vec_pretty(&value).unwrap();
        assert_eq!(encode_bounded(&value, expected.len()).unwrap(), expected);
        assert!(encode_bounded(&value, expected.len() - 1)
            .unwrap_err()
            .contains("size limit"));
    }
}
