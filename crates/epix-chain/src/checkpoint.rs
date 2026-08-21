//! Durable monotonic checkpoint for client-side xID finality.
//!
//! Signature verification and checkpoint publication share one process-wide
//! lock. This makes the security decision linearizable across every resolver in
//! the process. The checkpoint is written before memory advances, so a failed
//! disk write cannot turn an unpersisted height into an accepted result.

use crate::finality::{FinalityBundle, PinnedSet};
use fslock_guard::LockFileGuard;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const CHECKPOINT_VERSION: u32 = 2;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityCheckpoint {
    pub version: u32,
    pub chain_id: String,
    /// Hash of the exact pinned validator trust root and pin coordinates.
    pub pin_fingerprint: String,
    pub pinned_at_height: u64,
    pub pinned_at_unix: i64,
    /// A floor-only row is persisted as soon as a pin is installed. It blocks
    /// an older-pin process before the new pin has verified its first bundle.
    pub verified: bool,
    pub height: u64,
    /// Empty only for a floor-only row.
    pub digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PinBinding {
    chain_id: String,
    fingerprint: String,
    pinned_at_height: u64,
    pinned_at_unix: i64,
}

impl PinBinding {
    fn new(pinned: &PinnedSet) -> Self {
        Self {
            chain_id: pinned.chain_id.clone(),
            fingerprint: pinned_set_fingerprint(pinned),
            pinned_at_height: pinned.pinned_at_height,
            pinned_at_unix: pinned.pinned_at_unix,
        }
    }
}

struct CheckpointState {
    path: Option<PathBuf>,
    pin: Option<PinBinding>,
    checkpoint: Option<FinalityCheckpoint>,
}

impl CheckpointState {
    const fn empty() -> Self {
        Self {
            path: None,
            pin: None,
            checkpoint: None,
        }
    }

    fn configure(
        &mut self,
        path: PathBuf,
        pinned: &PinnedSet,
    ) -> Result<Option<FinalityCheckpoint>, String> {
        let path = canonical_checkpoint_path(path)?;
        if let Some(current) = &self.path {
            if current != &path {
                return Err(format!(
                    "xID finality checkpoint already configured at {}; refusing to switch to {}",
                    current.display(),
                    path.display()
                ));
            }
        }

        let pin = PinBinding::new(pinned);
        let _process_lock = lock_checkpoint_file(&path)?;
        let checkpoint = match read_checkpoint(&path)? {
            Some(checkpoint) if checkpoint_matches_pin(&checkpoint, &pin) => checkpoint,
            Some(checkpoint) if pin_supersedes_checkpoint(&pin, &checkpoint) => {
                let floor = floor_checkpoint(&pin);
                write_checkpoint(&path, &floor)?;
                floor
            }
            Some(checkpoint) => {
                return Err(format!(
                    "xID finality checkpoint trust root {} does not match installed pin {}",
                    checkpoint.pin_fingerprint, pin.fingerprint
                ));
            }
            None => {
                let floor = floor_checkpoint(&pin);
                write_checkpoint(&path, &floor)?;
                floor
            }
        };

        self.path = Some(path);
        self.pin = Some(pin);
        self.checkpoint = Some(checkpoint);
        Ok(self.verified_checkpoint())
    }

    #[cfg(test)]
    fn record_verified(&mut self, height: u64, digest_hex: &str) -> Result<(), String> {
        let path = self.configured_path()?.to_path_buf();
        let _process_lock = lock_checkpoint_file(&path)?;
        self.refresh_from_disk_locked()?;
        self.record_verified_locked(height, digest_hex)
    }

    /// Record while both the in-process mutex and the checkpoint lock file are
    /// already held. Every call refreshes from disk before entering this helper.
    fn record_verified_locked(&mut self, height: u64, digest_hex: &str) -> Result<(), String> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| "xID finality checkpoint persistence is not configured".to_string())?;
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| "xID finality checkpoint pin is not configured".to_string())?;
        let digest_hex = canonical_digest(digest_hex)?;
        if height < pin.pinned_at_height {
            return Err(format!(
                "xID finality height rollback: {height} is below pin floor {}",
                pin.pinned_at_height
            ));
        }

        if let Some(current) = &self.checkpoint {
            if height < current.height {
                return Err(format!(
                    "xID finality height rollback: {height} is below persisted height {}",
                    current.height
                ));
            }
            if height == current.height {
                if current.verified && digest_hex != current.digest_hex {
                    return Err(format!(
                        "xID finality conflict at height {height}: digest differs from persisted checkpoint"
                    ));
                }
                if current.verified {
                    return Ok(());
                }
            }
        }

        let next = FinalityCheckpoint {
            version: CHECKPOINT_VERSION,
            chain_id: pin.chain_id.clone(),
            pin_fingerprint: pin.fingerprint.clone(),
            pinned_at_height: pin.pinned_at_height,
            pinned_at_unix: pin.pinned_at_unix,
            verified: true,
            height,
            digest_hex,
        };
        write_checkpoint(path, &next)?;
        self.checkpoint = Some(next);
        Ok(())
    }

    fn height(&self) -> u64 {
        self.checkpoint.as_ref().map(|c| c.height).unwrap_or(0)
    }

    fn verified_checkpoint(&self) -> Option<FinalityCheckpoint> {
        self.checkpoint
            .as_ref()
            .filter(|checkpoint| checkpoint.verified)
            .cloned()
    }

    fn matches(&self, height: u64, digest_hex: &str) -> bool {
        let Ok(digest_hex) = canonical_digest(digest_hex) else {
            return false;
        };
        self.checkpoint
            .as_ref()
            .is_some_and(|c| c.verified && c.height == height && c.digest_hex == digest_hex)
    }

    fn configured_path(&self) -> Result<&Path, String> {
        self.path
            .as_deref()
            .ok_or_else(|| "xID finality checkpoint persistence is not configured".to_string())
    }

    /// Re-read the durable value while the checkpoint lock file is held. A
    /// second process may have advanced it since this process configured its
    /// in-memory state. Missing, conflicting, or lower disk state after memory
    /// advanced is a rollback and fails closed.
    fn refresh_from_disk_locked(&mut self) -> Result<(), String> {
        let path = self.configured_path()?.to_path_buf();
        let pin = self
            .pin
            .as_ref()
            .ok_or_else(|| "xID finality checkpoint pin is not configured".to_string())?;
        let disk = read_checkpoint(&path)?.ok_or_else(|| {
            format!(
                "xID finality checkpoint {} disappeared after configuration",
                path.display()
            )
        })?;
        if !checkpoint_matches_pin(&disk, pin) {
            return Err(format!(
                "xID finality checkpoint trust root {} does not match this process pin {}",
                disk.pin_fingerprint, pin.fingerprint
            ));
        }

        match (&self.checkpoint, &disk) {
            (Some(memory), disk) if disk.height < memory.height => {
                return Err(format!(
                    "xID finality checkpoint rollback on disk: height {} is below in-memory height {}",
                    disk.height, memory.height
                ));
            }
            (Some(memory), disk)
                if disk.height == memory.height
                    && memory.verified
                    && (!disk.verified || disk.digest_hex != memory.digest_hex) =>
            {
                return Err(format!(
                    "xID finality checkpoint conflict at height {}: disk digest differs from memory",
                    disk.height
                ));
            }
            _ => {}
        }
        self.checkpoint = Some(disk);
        Ok(())
    }
}

static CHECKPOINT: Mutex<CheckpointState> = Mutex::new(CheckpointState::empty());

pub(crate) fn configure(
    path: impl Into<PathBuf>,
    pinned: &PinnedSet,
) -> Result<Option<FinalityCheckpoint>, String> {
    lock()?.configure(path.into(), pinned)
}

pub(crate) fn height() -> u64 {
    CHECKPOINT.lock().map(|state| state.height()).unwrap_or(0)
}

pub(crate) fn matches(height: u64, digest_hex: &str) -> bool {
    let Ok(mut state) = CHECKPOINT.lock() else {
        return false;
    };
    let Ok(path) = state.configured_path().map(Path::to_path_buf) else {
        return false;
    };
    let Ok(_process_lock) = lock_checkpoint_file(&path) else {
        return false;
    };
    if state.refresh_from_disk_locked().is_err() {
        return false;
    }
    state.matches(height, digest_hex)
}

/// Run one synchronous publication while the exact checkpoint remains locked.
/// The action must not call back into checkpoint APIs.
pub(crate) fn publish_if_current<T>(
    height: u64,
    digest_hex: &str,
    publish: impl FnOnce() -> T,
) -> Option<T> {
    publish_if_current_in(&CHECKPOINT, height, digest_hex, publish)
}

fn publish_if_current_in<T>(
    checkpoint: &Mutex<CheckpointState>,
    height: u64,
    digest_hex: &str,
    publish: impl FnOnce() -> T,
) -> Option<T> {
    let mut state = checkpoint.lock().ok()?;
    let path = state.configured_path().ok()?.to_path_buf();
    let _process_lock = lock_checkpoint_file(&path).ok()?;
    state.refresh_from_disk_locked().ok()?;
    if !state.matches(height, digest_hex) {
        return None;
    }
    let published = publish();
    drop(state);
    Some(published)
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    *CHECKPOINT.lock().unwrap() = CheckpointState::empty();
}

#[cfg(test)]
pub(crate) fn record_for_test(height: u64, digest_hex: &str) -> Result<(), String> {
    lock()?.record_verified(height, digest_hex)
}

/// Verify against the latest checkpoint and publish the result durably while
/// holding the same lock. Fetching the RPC bundle happens before this call, so
/// the lock only covers local signature checks and one small atomic file write.
pub(crate) fn verify_and_commit(
    bundle: &FinalityBundle,
    pinned: &PinnedSet,
    now_unix: i64,
) -> Result<u64, String> {
    let mut state = lock()?;
    let path = state.configured_path()?.to_path_buf();
    let _process_lock = lock_checkpoint_file(&path)?;
    state.refresh_from_disk_locked()?;
    let requested_pin = PinBinding::new(pinned);
    if state.pin.as_ref() != Some(&requested_pin) {
        return Err(
            "xID finality checkpoint is not configured for this pinned validator set".into(),
        );
    }
    let params = crate::finality_params(now_unix, state.height());
    let height = crate::verify_finality(bundle, pinned, &params)
        .map_err(|e| format!("finality proof rejected: {e:?}"))?;
    state.record_verified_locked(height, &bundle.digest_hex)?;
    Ok(height)
}

fn lock() -> Result<std::sync::MutexGuard<'static, CheckpointState>, String> {
    CHECKPOINT
        .lock()
        .map_err(|_| "xID finality checkpoint lock poisoned".to_string())
}

fn canonical_digest(digest_hex: &str) -> Result<String, String> {
    let digest = hex::decode(digest_hex)
        .map_err(|_| "xID finality checkpoint digest is not hexadecimal".to_string())?;
    if digest.len() != 32 {
        return Err("xID finality checkpoint digest is not 32 bytes".into());
    }
    Ok(hex::encode(digest))
}

/// Deterministically bind the durable checkpoint to the complete trust root,
/// not just its chain id. Length prefixes avoid ambiguous concatenations.
pub(crate) fn pinned_set_fingerprint(pinned: &PinnedSet) -> String {
    fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    let mut validators: Vec<_> = pinned.validators.iter().collect();
    validators.sort_by_key(|(valcons, _)| *valcons);
    let mut hasher = Sha256::new();
    hasher.update(b"epix-xid-finality-pin-v1\0");
    hash_bytes(&mut hasher, pinned.chain_id.as_bytes());
    hasher.update(pinned.pinned_at_height.to_be_bytes());
    hasher.update(pinned.pinned_at_unix.to_be_bytes());
    hasher.update((validators.len() as u64).to_be_bytes());
    for (valcons, validator) in validators {
        hash_bytes(&mut hasher, valcons.as_bytes());
        hasher.update(validator.pubkey);
        hasher.update(validator.voting_power.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

fn floor_checkpoint(pin: &PinBinding) -> FinalityCheckpoint {
    FinalityCheckpoint {
        version: CHECKPOINT_VERSION,
        chain_id: pin.chain_id.clone(),
        pin_fingerprint: pin.fingerprint.clone(),
        pinned_at_height: pin.pinned_at_height,
        pinned_at_unix: pin.pinned_at_unix,
        verified: false,
        height: pin.pinned_at_height,
        digest_hex: String::new(),
    }
}

fn checkpoint_matches_pin(checkpoint: &FinalityCheckpoint, pin: &PinBinding) -> bool {
    checkpoint.chain_id == pin.chain_id
        && checkpoint.pin_fingerprint == pin.fingerprint
        && checkpoint.pinned_at_height == pin.pinned_at_height
        && checkpoint.pinned_at_unix == pin.pinned_at_unix
}

fn pin_supersedes_checkpoint(pin: &PinBinding, checkpoint: &FinalityCheckpoint) -> bool {
    pin.chain_id == checkpoint.chain_id
        && pin.pinned_at_height > checkpoint.pinned_at_height
        && pin.pinned_at_height >= checkpoint.height
        && pin.pinned_at_unix >= checkpoint.pinned_at_unix
}

fn canonical_checkpoint_path(path: PathBuf) -> Result<PathBuf, String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "xID finality checkpoint path has no parent: {}",
            path.display()
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "cannot create xID finality checkpoint directory {}: {e}",
            parent.display()
        )
    })?;
    let canonical_parent = parent.canonicalize().map_err(|e| {
        format!(
            "cannot canonicalize xID finality checkpoint directory {}: {e}",
            parent.display()
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        format!(
            "xID finality checkpoint path has no file name: {}",
            path.display()
        )
    })?;
    Ok(canonical_parent.join(file_name))
}

fn checkpoint_lock_path(path: &Path) -> Result<PathBuf, String> {
    let file_name = path.file_name().ok_or_else(|| {
        format!(
            "xID finality checkpoint path has no file name: {}",
            path.display()
        )
    })?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

fn lock_checkpoint_file(path: &Path) -> Result<LockFileGuard, String> {
    let lock_path = checkpoint_lock_path(path)?;
    LockFileGuard::lock(&lock_path).map_err(|e| {
        format!(
            "cannot lock xID finality checkpoint {}: {e}",
            lock_path.display()
        )
    })
}

fn read_checkpoint(path: &Path) -> Result<Option<FinalityCheckpoint>, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let checkpoint: FinalityCheckpoint = serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid xID finality checkpoint {}: {e}", path.display()))?;
            validate_checkpoint(&checkpoint)?;
            Ok(Some(checkpoint))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "cannot read xID finality checkpoint {}: {e}",
            path.display()
        )),
    }
}

fn validate_checkpoint(checkpoint: &FinalityCheckpoint) -> Result<(), String> {
    if checkpoint.version != CHECKPOINT_VERSION {
        return Err(format!(
            "unsupported xID finality checkpoint version {}",
            checkpoint.version
        ));
    }
    if checkpoint.chain_id.trim().is_empty() || checkpoint.chain_id.trim() != checkpoint.chain_id {
        return Err("xID finality checkpoint chain id is not canonical".into());
    }
    if checkpoint.pinned_at_height == 0 || checkpoint.pinned_at_unix <= 0 {
        return Err("xID finality checkpoint pin coordinates must be positive".into());
    }
    if checkpoint.height < checkpoint.pinned_at_height {
        return Err("xID finality checkpoint height is below its pin floor".into());
    }
    let fingerprint = canonical_digest(&checkpoint.pin_fingerprint)?;
    if fingerprint != checkpoint.pin_fingerprint {
        return Err(
            "xID finality checkpoint pin fingerprint must use canonical lowercase hex".into(),
        );
    }
    if checkpoint.verified {
        let canonical = canonical_digest(&checkpoint.digest_hex)?;
        if canonical != checkpoint.digest_hex {
            return Err("xID finality checkpoint digest must use canonical lowercase hex".into());
        }
    } else if checkpoint.height != checkpoint.pinned_at_height || !checkpoint.digest_hex.is_empty()
    {
        return Err("xID finality floor row has an invalid height or digest".into());
    }
    Ok(())
}

fn write_checkpoint(path: &Path, checkpoint: &FinalityCheckpoint) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| {
        format!(
            "xID finality checkpoint path has no parent: {}",
            path.display()
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "cannot create xID finality checkpoint directory {}: {e}",
            parent.display()
        )
    })?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        format!(
            "cannot create temporary xID finality checkpoint in {}: {e}",
            parent.display()
        )
    })?;
    serde_json::to_writer(&mut tmp, checkpoint)
        .map_err(|e| format!("cannot encode xID finality checkpoint: {e}"))?;
    tmp.write_all(b"\n")
        .map_err(|e| format!("cannot write xID finality checkpoint: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("cannot sync xID finality checkpoint: {e}"))?;
    let persisted = persist_checkpoint(tmp, path)?;
    persisted
        .sync_all()
        .map_err(|e| format!("cannot sync published xID finality checkpoint: {e}"))?;

    // On Unix, fsync the directory as part of the durability contract. The
    // Windows path below uses MOVEFILE_WRITE_THROUGH for the same contract.
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|e| format!("cannot sync xID finality checkpoint directory: {e}"))?;
    Ok(())
}

#[cfg(not(windows))]
fn persist_checkpoint(tmp: tempfile::NamedTempFile, path: &Path) -> Result<std::fs::File, String> {
    tmp.persist(path).map_err(|e| {
        format!(
            "cannot atomically replace xID finality checkpoint {}: {}",
            path.display(),
            e.error
        )
    })
}

#[cfg(windows)]
fn persist_checkpoint(tmp: tempfile::NamedTempFile, path: &Path) -> Result<std::fs::File, String> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let (file, temp_path) = tmp.keep().map_err(|e| {
        format!(
            "cannot retain temporary xID finality checkpoint {}: {}",
            path.display(),
            e.error
        )
    })?;
    let source: Vec<u16> = temp_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers for the
    // duration of this call. The source handle permits rename sharing.
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        let error = std::io::Error::last_os_error();
        drop(file);
        let _ = std::fs::remove_file(&temp_path);
        return Err(format!(
            "cannot atomically replace xID finality checkpoint {}: {error}",
            path.display()
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    const CHAIN: &str = "epix_1917-1";
    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const D3: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn pin_at(height: u64, unix: i64, seed: u8) -> PinnedSet {
        let validators = std::collections::HashMap::from([(
            "epixvalcons1test".to_string(),
            crate::finality::PinnedValidator {
                pubkey: [seed; 32],
                voting_power: 1,
            },
        )]);
        PinnedSet::new(validators, CHAIN, unix, height).unwrap()
    }

    fn pin() -> PinnedSet {
        pin_at(1, 1, 1)
    }

    /// Helper entry point for the cross-process regression below. The harness
    /// starts only this exact test in a child, lets it load height 100, then
    /// releases it after another process has durably advanced to height 200.
    #[test]
    fn cross_process_stale_writer_worker() {
        if std::env::var_os("EPIX_CHECKPOINT_STALE_WORKER").is_none() {
            return;
        }
        let path = PathBuf::from(std::env::var_os("EPIX_CHECKPOINT_PATH").unwrap());
        let ready = PathBuf::from(std::env::var_os("EPIX_CHECKPOINT_READY").unwrap());
        let release = PathBuf::from(std::env::var_os("EPIX_CHECKPOINT_RELEASE").unwrap());

        let mut stale = CheckpointState::empty();
        assert_eq!(stale.configure(path, &pin()).unwrap().unwrap().height, 100);
        std::fs::write(&ready, b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !release.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent never released stale writer"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            stale.record_verified(150, D3).is_err(),
            "a process with stale memory must re-read and reject a lower disk height"
        );
    }

    #[test]
    fn stale_child_process_cannot_overwrite_a_newer_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid-finality.json");
        let ready = dir.path().join("stale-ready");
        let release = dir.path().join("release-stale");

        let mut initial = CheckpointState::empty();
        initial.configure(path.clone(), &pin()).unwrap();
        initial.record_verified(100, D1).unwrap();

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("checkpoint::tests::cross_process_stale_writer_worker")
            .arg("--nocapture")
            .env("EPIX_CHECKPOINT_STALE_WORKER", "1")
            .env("EPIX_CHECKPOINT_PATH", &path)
            .env("EPIX_CHECKPOINT_READY", &ready)
            .env("EPIX_CHECKPOINT_RELEASE", &release)
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "stale child did not become ready"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let mut newer = CheckpointState::empty();
        newer.configure(path.clone(), &pin()).unwrap();
        newer.record_verified(200, D2).unwrap();
        std::fs::write(&release, b"go").unwrap();

        assert!(child.wait().unwrap().success());
        let disk: FinalityCheckpoint =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(disk.height, 200);
        assert_eq!(disk.digest_hex, D2);
    }

    /// Helper entry point for the re-pin regression below. The child loads the
    /// old trust root, then attempts a write after the parent installs a new one.
    #[test]
    fn cross_process_old_pin_writer_worker() {
        if std::env::var_os("EPIX_CHECKPOINT_OLD_PIN_WORKER").is_none() {
            return;
        }
        let path = PathBuf::from(std::env::var_os("EPIX_CHECKPOINT_PATH").unwrap());
        let ready = PathBuf::from(std::env::var_os("EPIX_CHECKPOINT_READY").unwrap());
        let release = PathBuf::from(std::env::var_os("EPIX_CHECKPOINT_RELEASE").unwrap());

        let mut old_process = CheckpointState::empty();
        assert_eq!(
            old_process.configure(path, &pin()).unwrap().unwrap().height,
            100
        );
        std::fs::write(&ready, b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !release.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent never installed the new pin"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let error = old_process.record_verified(300, D3).unwrap_err();
        assert!(
            error.contains("trust root"),
            "old-pin write failed for an unexpected reason: {error}"
        );
    }

    #[test]
    fn old_pin_child_cannot_poison_a_new_pin_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid-finality.json");
        let ready = dir.path().join("old-pin-ready");
        let release = dir.path().join("new-pin-installed");

        let mut initial = CheckpointState::empty();
        initial.configure(path.clone(), &pin()).unwrap();
        initial.record_verified(100, D1).unwrap();

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("checkpoint::tests::cross_process_old_pin_writer_worker")
            .arg("--nocapture")
            .env("EPIX_CHECKPOINT_OLD_PIN_WORKER", "1")
            .env("EPIX_CHECKPOINT_PATH", &path)
            .env("EPIX_CHECKPOINT_READY", &ready)
            .env("EPIX_CHECKPOINT_RELEASE", &release)
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "old-pin child did not become ready"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let new_pin = pin_at(200, 2, 2);
        let mut repinned = CheckpointState::empty();
        assert_eq!(repinned.configure(path.clone(), &new_pin).unwrap(), None);
        std::fs::write(&release, b"go").unwrap();

        assert!(child.wait().unwrap().success());
        let disk: FinalityCheckpoint =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(disk.pin_fingerprint, pinned_set_fingerprint(&new_pin));
        assert_eq!(disk.height, 200);
        assert!(!disk.verified);
        assert!(disk.digest_hex.is_empty());
    }

    #[test]
    fn pin_fingerprint_is_order_independent_and_binds_all_trust_fields() {
        fn two_validator_pin(reverse: bool, power: u64) -> PinnedSet {
            let mut validators = std::collections::HashMap::new();
            let entries = [
                (
                    "epixvalcons1alpha".to_string(),
                    crate::finality::PinnedValidator {
                        pubkey: [1; 32],
                        voting_power: 3,
                    },
                ),
                (
                    "epixvalcons1beta".to_string(),
                    crate::finality::PinnedValidator {
                        pubkey: [2; 32],
                        voting_power: power,
                    },
                ),
            ];
            if reverse {
                for entry in entries.into_iter().rev() {
                    validators.insert(entry.0, entry.1);
                }
            } else {
                for entry in entries {
                    validators.insert(entry.0, entry.1);
                }
            }
            PinnedSet::new(validators, CHAIN, 10, 20).unwrap()
        }

        let first = two_validator_pin(false, 5);
        let reversed = two_validator_pin(true, 5);
        assert_eq!(
            pinned_set_fingerprint(&first),
            pinned_set_fingerprint(&reversed)
        );
        assert_ne!(
            pinned_set_fingerprint(&first),
            pinned_set_fingerprint(&two_validator_pin(false, 6))
        );
        assert_ne!(
            pinned_set_fingerprint(&pin_at(20, 10, 1)),
            pinned_set_fingerprint(&pin_at(21, 10, 1))
        );
        assert_ne!(
            pinned_set_fingerprint(&pin_at(20, 10, 1)),
            pinned_set_fingerprint(&pin_at(20, 11, 1))
        );
        assert_ne!(
            pinned_set_fingerprint(&pin_at(20, 10, 1)),
            pinned_set_fingerprint(&pin_at(20, 10, 2))
        );
    }

    #[test]
    fn checkpoint_survives_reload_and_rejects_rollback_or_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid-finality.json");
        let mut first = CheckpointState::empty();
        assert_eq!(first.configure(path.clone(), &pin()).unwrap(), None);
        first.record_verified(200, D1).unwrap();

        let mut reloaded = CheckpointState::empty();
        let checkpoint = reloaded.configure(path, &pin()).unwrap().unwrap();
        assert_eq!(checkpoint.height, 200);
        assert_eq!(checkpoint.digest_hex, D1);
        assert!(reloaded.record_verified(199, D1).is_err());
        assert!(reloaded.record_verified(200, D2).is_err());
        reloaded.record_verified(200, D1).unwrap();
    }

    #[test]
    fn repin_ignores_a_restored_checkpoint_below_the_new_pin_height() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid-finality.json");
        let mut previous = CheckpointState::empty();
        previous.configure(path.clone(), &pin()).unwrap();
        previous.record_verified(41, D1).unwrap();

        let mut repinned = CheckpointState::empty();
        assert_eq!(
            repinned.configure(path.clone(), &pin_at(42, 2, 2)).unwrap(),
            None
        );
        assert_eq!(repinned.height(), 42);
        assert!(!repinned.matches(41, D1));

        repinned.record_verified(42, D2).unwrap();
        let disk: FinalityCheckpoint =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(disk.height, 42);
        assert_eq!(disk.digest_hex, D2);
    }

    #[test]
    fn repin_below_a_verified_checkpoint_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid-finality.json");
        let mut previous = CheckpointState::empty();
        previous.configure(path.clone(), &pin()).unwrap();
        previous.record_verified(100, D1).unwrap();

        let mut repinned = CheckpointState::empty();
        assert!(repinned.configure(path.clone(), &pin_at(99, 2, 2)).is_err());
        let disk: FinalityCheckpoint =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(disk.pin_fingerprint, pinned_set_fingerprint(&pin()));
        assert_eq!(disk.height, 100);
        assert_eq!(disk.digest_hex, D1);
    }

    #[test]
    fn failed_persist_does_not_advance_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid-finality.json");
        let mut state = CheckpointState::empty();
        state.configure(path.clone(), &pin()).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(state.record_verified(200, D1).is_err());
        assert_eq!(state.height(), 1);
    }

    #[test]
    fn serialized_publication_never_finishes_at_the_lower_height() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xid-finality.json");
        let mut initial = CheckpointState::empty();
        initial.configure(path.clone(), &pin()).unwrap();
        let state = Arc::new(Mutex::new(initial));
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for (height, digest) in [(100, D1), (200, D2)] {
            let state = Arc::clone(&state);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                state.lock().unwrap().record_verified(height, digest)
            }));
        }
        barrier.wait();
        for thread in threads {
            let _ = thread.join().unwrap();
        }
        assert_eq!(state.lock().unwrap().height(), 200);

        let bytes = std::fs::read(path).unwrap();
        let disk: FinalityCheckpoint = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(disk.height, 200);
        assert_eq!(disk.digest_hex, D2);
    }

    #[test]
    fn cache_publication_and_checkpoint_advance_share_one_linearization_lock() {
        let dir = tempfile::tempdir().unwrap();
        let checkpoint_path = dir.path().join("xid-finality.json");
        let cache_path = dir.path().join("resolve-cache.json");
        let stale_temp = dir.path().join("resolve-cache.h41.tmp");

        let mut initial = CheckpointState::empty();
        initial.configure(checkpoint_path, &pin()).unwrap();
        initial.record_verified(41, D1).unwrap();
        let state = Arc::new(Mutex::new(initial));
        std::fs::write(&cache_path, b"height-40").unwrap();
        std::fs::write(&stale_temp, b"height-41").unwrap();

        let action_started = Arc::new(Barrier::new(2));
        let release_action = Arc::new(Barrier::new(2));
        let order = Arc::new(AtomicU64::new(0));
        let (advance_started_tx, advance_started_rx) = std::sync::mpsc::channel();

        let publisher = {
            let state = Arc::clone(&state);
            let action_started = Arc::clone(&action_started);
            let release_action = Arc::clone(&release_action);
            let order = Arc::clone(&order);
            let cache_path = cache_path.clone();
            let stale_temp = stale_temp.clone();
            std::thread::spawn(move || {
                publish_if_current_in(&state, 41, D1, || {
                    action_started.wait();
                    release_action.wait();
                    std::fs::rename(stale_temp, cache_path).unwrap();
                    order.fetch_add(1, Ordering::SeqCst) + 1
                })
                .unwrap()
            })
        };
        let advancer = {
            let state = Arc::clone(&state);
            let action_started = Arc::clone(&action_started);
            let order = Arc::clone(&order);
            std::thread::spawn(move || {
                action_started.wait();
                advance_started_tx.send(()).unwrap();
                state.lock().unwrap().record_verified(42, D2).unwrap();
                order.fetch_add(1, Ordering::SeqCst) + 1
            })
        };

        advance_started_rx.recv().unwrap();
        assert!(
            state.try_lock().is_err(),
            "the exact-current helper must retain the checkpoint lock during publication"
        );
        release_action.wait();
        assert_eq!(publisher.join().unwrap(), 1);
        assert_eq!(advancer.join().unwrap(), 2);

        // Once height 42 is current, even a fully prepared height-41 writer is
        // refused before rename and cannot clobber a current cache entry.
        std::fs::write(&cache_path, b"height-42").unwrap();
        let late_stale = dir.path().join("resolve-cache.late-h41.tmp");
        std::fs::write(&late_stale, b"late-height-41").unwrap();
        assert!(publish_if_current_in(&state, 41, D1, || {
            std::fs::rename(&late_stale, &cache_path).unwrap();
        })
        .is_none());
        assert_eq!(std::fs::read(&cache_path).unwrap(), b"height-42");
        assert!(late_stale.exists());
    }

    #[test]
    fn load_rejects_wrong_chain_and_noncanonical_digest() {
        let dir = tempfile::tempdir().unwrap();
        let trusted = pin();
        let fingerprint = pinned_set_fingerprint(&trusted);
        let wrong_chain = dir.path().join("wrong-chain.json");
        std::fs::write(
            &wrong_chain,
            serde_json::to_vec(&serde_json::json!({
                "version": CHECKPOINT_VERSION,
                "chain_id": "other",
                "pin_fingerprint": fingerprint,
                "pinned_at_height": 1,
                "pinned_at_unix": 1,
                "verified": true,
                "height": 1,
                "digest_hex": D1,
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(CheckpointState::empty()
            .configure(wrong_chain, &trusted)
            .is_err());

        let noncanonical = dir.path().join("noncanonical.json");
        std::fs::write(
            &noncanonical,
            serde_json::to_vec(&serde_json::json!({
                "version": CHECKPOINT_VERSION,
                "chain_id": CHAIN,
                "pin_fingerprint": pinned_set_fingerprint(&trusted),
                "pinned_at_height": 1,
                "pinned_at_unix": 1,
                "verified": true,
                "height": 1,
                "digest_hex": "AA".repeat(32),
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(CheckpointState::empty()
            .configure(noncanonical, &trusted)
            .is_err());
    }
}
