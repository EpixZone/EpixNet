//! Persistence of the per-xite activation checkpoint.
//!
//! `evx_activation::ActivationLoader` holds the version floor in memory and
//! leaves persisting it to the host; `evx-state` has no table for it yet.
//! Until it does, the service keeps one small JSON file per xite under
//! `<private>/evx/checkpoints/<address>.json`, written atomically through
//! `evx_workspace::Dir` (temporary file, flush, handle-relative rename,
//! directory flush) so a crash mid-write leaves either the old floor or the
//! new one and never a torn file, on Unix and Windows alike.
//!
//! A file that exists but does not decode is an error, not an empty floor:
//! starting from version 0 would let a rollback be admitted, which is the
//! one thing the checkpoint exists to refuse. The operator sees the error in
//! the run result and can inspect the file; nothing is overwritten.

use std::path::{Path, PathBuf};

use evx_activation::ActivationCheckpoint;
use evx_workspace::sys::Dir;

/// Most bytes a checkpoint file may hold. A real one is under 200 bytes; a
/// larger file is not a checkpoint this build wrote.
const MAX_CHECKPOINT_FILE: u64 = 4096;

/// Where `xite`'s checkpoint lives under `dir`. The caller has already
/// validated `xite` as an identifier, so it is a plain file name.
pub(crate) fn path(dir: &Path, xite: &str) -> PathBuf {
    dir.join(format!("{xite}.json"))
}

/// The stored floor for `xite`, or the empty floor when none was stored.
pub(crate) fn load(dir: &Path, xite: &str) -> Result<ActivationCheckpoint, String> {
    let path = path(dir, xite);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ActivationCheckpoint::default());
        }
        Err(error) => return Err(format!("activation checkpoint unreadable: {error}")),
    };
    if !metadata.is_file() || metadata.len() > MAX_CHECKPOINT_FILE {
        return Err("activation checkpoint is not a regular file of the expected size".into());
    }
    let raw = std::fs::read(&path).map_err(|error| format!("activation checkpoint unreadable: {error}"))?;
    serde_json::from_slice(&raw).map_err(|_| "activation checkpoint is corrupt".to_string())
}

/// Replace `xite`'s stored floor with `checkpoint`, atomically.
/// The caller holds the workspace admission lease across this call.
pub(crate) fn admit(dir: &Path, xite: &str, expected: &ActivationCheckpoint, candidate: &ActivationCheckpoint) -> Result<(), String> {
    // Compilation happens before the lease is acquired. A second host using
    // this data root may have admitted newer content during that interval.
    if &load(dir, xite)? != expected {
        return Err("activation checkpoint changed before admission; inspect and retry".into());
    }
    if candidate != expected {
        store(dir, xite, candidate)?;
    }
    Ok(())
}

/// Write one checkpoint while the caller owns its admission lease.
pub(crate) fn store(dir: &Path, xite: &str, checkpoint: &ActivationCheckpoint) -> Result<(), String> {
    let target = format!("{xite}.json");
    let tmp = format!("{xite}.json.tmp-{}", std::process::id());
    let raw = serde_json::to_vec(checkpoint).map_err(|error| format!("checkpoint encode: {error}"))?;
    let directory = Dir::open_root(dir)
        .map_err(|error| format!("activation checkpoint not persisted: {error}"))?;
    let result = write_replacing(&directory, &tmp, &target, &raw);
    if result.is_err() {
        let _ = directory.unlink(&tmp);
    }
    result.map_err(|error| format!("activation checkpoint not persisted: {error}"))
}

/// Write `raw` to `tmp`, flush it, rename it over `target` and flush the
/// directory, all relative to `directory`. A stale `tmp` of an earlier
/// process with this id is removed first; anything else in its place fails.
fn write_replacing(directory: &Dir, tmp: &str, target: &str, raw: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let _ = directory.unlink(tmp);
    let mut file = directory.create_new(tmp).map_err(|error| error.to_string())?;
    file.write_all(raw).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    drop(file);
    directory.rename(tmp, target).map_err(|error| error.to_string())?;
    directory.sync().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn another_hosts_newer_admission_cannot_be_overwritten_by_a_stale_loader() {
        let dir = tempfile::tempdir().unwrap();
        let stale_floor = load(dir.path(), "xite-a").unwrap();
        let newer = ActivationCheckpoint::new(2, Some("bb".repeat(32)));
        store(dir.path(), "xite-a", &newer).unwrap();
        let older = ActivationCheckpoint::new(1, Some("aa".repeat(32)));
        assert!(admit(dir.path(), "xite-a", &stale_floor, &older).is_err());
        assert_eq!(load(dir.path(), "xite-a").unwrap(), newer);
    }

    #[test]
    fn a_missing_file_is_the_empty_floor_and_a_stored_one_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path(), "xite-a").unwrap(), ActivationCheckpoint::default());
        let floor = ActivationCheckpoint::new(1_700_000_000_000, Some("ab".repeat(32)));
        store(dir.path(), "xite-a", &floor).unwrap();
        assert_eq!(load(dir.path(), "xite-a").unwrap(), floor);
        assert_eq!(load(dir.path(), "xite-b").unwrap(), ActivationCheckpoint::default());
        assert!(!dir.path().join(format!("xite-a.json.tmp-{}", std::process::id())).exists());
    }

    #[test]
    fn a_corrupt_or_oversized_file_is_an_error_not_an_empty_floor() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(path(dir.path(), "xite-a"), b"{\"version\": 1, \"extra\": true}").unwrap();
        assert!(load(dir.path(), "xite-a").is_err());
        std::fs::write(path(dir.path(), "xite-b"), b"not json").unwrap();
        assert!(load(dir.path(), "xite-b").is_err());
        std::fs::write(path(dir.path(), "xite-c"), vec![b' '; MAX_CHECKPOINT_FILE as usize + 1]).unwrap();
        assert!(load(dir.path(), "xite-c").is_err());
    }
}
