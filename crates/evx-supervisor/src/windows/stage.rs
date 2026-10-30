//! The trusted worker image and its staged, package-readable copy.
//!
//! The worker is trusted to the same degree as the executable that loads
//! this crate. It is pinned once: local disk only, no reparse point in any
//! path component, a regular file with one link, hashed, and held open with
//! `FILE_SHARE_READ` so the bytes that were hashed stay the bytes on disk.
//! The staged copy lives at `<staging>/worker/<sha256>/evx-worker.exe`,
//! written from the held bytes, re-hashed, protected with a DACL for the
//! owner, SYSTEM and `ALL RESTRICTED APPLICATION PACKAGES` (`S-1-15-2-2`,
//! which every LPAC token carries and no ordinary AppContainer does), and
//! held open the same way for the backend's lifetime.

use evx_workspace::sys::file_stat;
use evx_workspace::Kind;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::{Arc, Mutex};

use evx_api::Denied;
use evx_windows_native::{current_user_sid_text, local_app_data, protect};
use sha2::{Digest, Sha256};

const STAGED_NAME: &str = "evx-worker.exe";
const MAX_IMAGE: u64 = 512 * 1024 * 1024;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// The group every less-privileged AppContainer token carries.
const ALL_RESTRICTED_PACKAGES: &str = "S-1-15-2-2";
/// A staged sibling younger than this is never pruned.
const PRUNE_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

fn denied(reason: &str) -> Denied {
    Denied::new(format!("worker unavailable: {reason}"))
}

/// The staged worker, its pinned source and the container registry.
pub struct WindowsBackend {
    source_path: PathBuf,
    _source: File,
    stage_dir: PathBuf,
    staged_path: PathBuf,
    _staged: File,
    sha256: String,
}

impl std::fmt::Debug for WindowsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsBackend")
            .field("source", &self.source_path)
            .field("staged", &self.staged_path)
            .field("sha256", &self.sha256)
            .finish()
    }
}

impl WindowsBackend {
    /// Pin `worker` and stage it under `staging`, a host-private directory
    /// on a local disk that is created if absent.
    pub fn new(worker: &Path, staging: &Path) -> Result<Arc<Self>, Denied> {
        let (source, bytes) = pin(worker)?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let stage_dir = prepare_staging(staging, &sha256)?;
        let staged_path = stage_dir.join(STAGED_NAME);
        let staged = stage(&stage_dir, &staged_path, &bytes, &sha256)?;
        prune_stale_siblings(&staging.join("worker"), &sha256);
        Ok(Arc::new(WindowsBackend {
            source_path: worker.to_path_buf(),
            _source: source,
            stage_dir,
            staged_path,
            _staged: staged,
            sha256,
        }))
    }

    /// The process-wide backend for `worker`, staged under
    /// [`default_staging_root`](Self::default_staging_root). Built on first
    /// use for a `Config` without an explicit backend and kept for the life
    /// of the process, so the pinned image stays pinned.
    pub fn default_for(worker: &Path) -> Result<Arc<Self>, Denied> {
        static DEFAULTS: Mutex<Option<HashMap<PathBuf, Arc<WindowsBackend>>>> = Mutex::new(None);
        let mut defaults = DEFAULTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let map = defaults.get_or_insert_with(HashMap::new);
        if let Some(backend) = map.get(worker) {
            return Ok(backend.clone());
        }
        let backend = Self::new(worker, &Self::default_staging_root()?)?;
        map.insert(worker.to_path_buf(), backend.clone());
        Ok(backend)
    }

    /// `%LOCALAPPDATA%\Epix\evx-stage`, resolved through the shell rather
    /// than the environment. There is no fallback: a staged executable
    /// image never goes under a shared temporary directory with a
    /// predictable name, so a host without a per-user local application
    /// data folder has no default backend.
    pub fn default_staging_root() -> Result<PathBuf, Denied> {
        let wide = local_app_data()
            .map_err(|e| Denied::new(format!("local application data unavailable: {e}")))?;
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&wide))
            .join("Epix")
            .join("evx-stage"))
    }

    /// The pinned source image.
    pub fn source(&self) -> &Path {
        &self.source_path
    }

    /// The staged image a child executes.
    pub fn staged_worker(&self) -> &Path {
        &self.staged_path
    }

    /// The staged image's directory: the working directory of a guest or
    /// compiler, which an LPAC token can open.
    pub fn stage_dir(&self) -> &Path {
        &self.stage_dir
    }

    /// SHA-256 of the pinned image, hex.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

use std::os::windows::ffi::OsStringExt;

/// Refuse anything but a local disk path whose existing components are all
/// ordinary (no reparse point anywhere).
fn require_plain_local_path(path: &Path, must_exist: bool) -> Result<(), Denied> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => {}
        _ => return Err(denied("local disk path required")),
    }
    let mut current = PathBuf::from(path.components().next().expect("prefix").as_os_str());
    for component in components {
        current.push(component);
        if current.parent().is_none() {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                return Err(denied("path component is a reparse point"));
            }
            Ok(_) => {}
            Err(_) if !must_exist => {}
            Err(_) => return Err(denied("path unavailable")),
        }
    }
    Ok(())
}

fn open_pinned(path: &Path) -> Result<File, Denied> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| denied("image cannot be opened"))
}

/// A regular, unlinked, bounded image read through an already open handle.
fn read_image(file: &File) -> Result<Vec<u8>, Denied> {
    let stat = file_stat(file).map_err(|_| denied("image metadata"))?;
    if stat.kind != Kind::Regular {
        return Err(denied("image is not a regular file"));
    }
    if stat.links != 1 {
        return Err(denied(
            "image has more than one link; copy the worker beside the executable (Cargo hard-links target binaries)",
        ));
    }
    if stat.size > MAX_IMAGE {
        return Err(denied("image exceeds the size limit"));
    }
    let mut bytes = Vec::with_capacity(stat.size as usize);
    (file)
        .take(MAX_IMAGE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| denied("image read failed"))?;
    if bytes.len() as u64 > MAX_IMAGE {
        return Err(denied("image exceeds the size limit"));
    }
    Ok(bytes)
}

/// Pin the trusted image: validate the path, hold it open and read it.
fn pin(worker: &Path) -> Result<(File, Vec<u8>), Denied> {
    require_plain_local_path(worker, true)?;
    let file = open_pinned(worker)?;
    let bytes = read_image(&file)?;
    Ok((file, bytes))
}

/// The protected DACL of the staging root: owner and SYSTEM only.
fn private_sddl(owner: &str) -> String {
    format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})")
}

/// The protected DACL of a staged image and its directory: the owner and
/// SYSTEM in full, every LPAC token read and execute.
fn readable_sddl(owner: &str) -> String {
    format!(
        "{}(A;OICI;GRGX;;;{ALL_RESTRICTED_PACKAGES})",
        private_sddl(owner)
    )
}

/// Create `<staging>/worker/<sha256>` with its DACLs. Idempotent.
fn prepare_staging(staging: &Path, sha256: &str) -> Result<PathBuf, Denied> {
    require_plain_local_path(staging, false)?;
    let owner = current_user_sid_text().map_err(|_| denied("owner identity"))?;
    let created = !staging.exists();
    std::fs::create_dir_all(staging).map_err(|_| denied("staging directory"))?;
    if created {
        protect(staging, &private_sddl(&owner)).map_err(|_| denied("staging directory DACL"))?;
    }
    require_plain_local_path(staging, true)?;
    let stage_dir = staging.join("worker").join(sha256);
    std::fs::create_dir_all(&stage_dir).map_err(|_| denied("staging directory"))?;
    protect(&stage_dir, &readable_sddl(&owner)).map_err(|_| denied("staging directory DACL"))?;
    require_plain_local_path(&stage_dir, true)?;
    Ok(stage_dir)
}

/// Open an existing staged copy and accept it only if it is the hashed image.
fn adopt_staged(staged_path: &Path, sha256: &str) -> Option<File> {
    let file = open_pinned(staged_path).ok()?;
    let bytes = read_image(&file).ok()?;
    (hex::encode(Sha256::digest(&bytes)) == sha256).then_some(file)
}

/// Write the image beside its final name and rename it into place. A
/// staged copy another host holds open cannot be replaced: the rename
/// fails and the existing copy is checked instead.
fn stage(stage_dir: &Path, staged_path: &Path, bytes: &[u8], sha256: &str) -> Result<File, Denied> {
    if let Some(file) = adopt_staged(staged_path, sha256) {
        return Ok(file);
    }
    let owner = current_user_sid_text().map_err(|_| denied("owner identity"))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pending = stage_dir.join(format!(".pending-{}-{nanos}", std::process::id()));
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        std::io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        drop(file);
        protect(&pending, &readable_sddl(&owner))?;
        std::fs::rename(&pending, staged_path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&pending);
        return adopt_staged(staged_path, sha256)
            .ok_or_else(|| denied("staged image hash differs"));
    }
    adopt_staged(staged_path, sha256).ok_or_else(|| denied("staged image hash differs"))
}

/// Whether the staged image at `path` is held open by some process. The
/// backend holds its own with `FILE_SHARE_READ`, so an open that shares
/// nothing fails with a sharing violation exactly when a holder exists.
/// Anything but a clean open or a missing file counts as held.
fn image_held(path: &Path) -> bool {
    match OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(_) => false,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Whether `path` changed within the last minute: another host may be
/// between writing its image and opening it, so it is left alone.
fn recently_written(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age < PRUNE_GRACE)
}

/// Remove every `worker/<other sha>` beside the image just staged whose
/// copy no process holds open. Best effort: a failure here never fails the
/// backend, and a held or freshly written image is skipped.
fn prune_stale_siblings(worker_root: &Path, keep: &str) {
    let Ok(entries) = std::fs::read_dir(worker_root) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name() == keep {
            continue;
        }
        let dir = entry.path();
        let plain_dir = std::fs::symlink_metadata(&dir).is_ok_and(|metadata| {
            metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
        });
        let image = dir.join(STAGED_NAME);
        if !plain_dir || image_held(&image) || recently_written(&image) {
            continue;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Make `path` look old enough for `prune_stale_siblings`.
    fn backdate(path: &Path) {
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(std::time::SystemTime::now() - 2 * PRUNE_GRACE)
            .unwrap();
    }

    #[test]
    fn staging_prunes_unheld_stale_siblings_and_keeps_held_ones() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let staging = root.join("stage");
        let worker_root = staging.join("worker");
        let stale = worker_root.join("0".repeat(64));
        let held = worker_root.join("1".repeat(64));
        let fresh = worker_root.join("2".repeat(64));
        for sibling in [&stale, &held, &fresh] {
            std::fs::create_dir_all(sibling).unwrap();
            std::fs::write(sibling.join(STAGED_NAME), b"old image").unwrap();
        }
        backdate(&stale.join(STAGED_NAME));
        backdate(&held.join(STAGED_NAME));
        let holder = open_pinned(&held.join(STAGED_NAME)).unwrap();
        let image = fixture_image(&root, "worker.exe");
        let backend = WindowsBackend::new(&image, &staging).unwrap();
        assert!(backend.staged_worker().is_file());
        assert!(!stale.exists(), "unheld stale sibling survived");
        assert!(held.exists(), "held sibling was pruned");
        assert!(fresh.exists(), "freshly written sibling was pruned");
        drop(holder);
        // The backend's own image is held, so a second backend for another
        // image keeps it.
        let other = root.join("other.exe");
        let mut bytes = std::fs::read(&image).unwrap();
        bytes.push(b'x');
        std::fs::write(&other, &bytes).unwrap();
        let second = WindowsBackend::new(&other, &staging).unwrap();
        assert_ne!(second.sha256(), backend.sha256());
        assert!(backend.staged_worker().is_file());
        assert!(!held.exists(), "released sibling survived the next staging");
    }

    fn junction(link: &Path, target: &Path) {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    fn fixture_image(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        path
    }

    #[test]
    fn staging_pins_hashes_and_adopts_an_identical_copy() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let image = fixture_image(&root, "worker.exe");
        let staging = root.join("stage");
        let first = WindowsBackend::new(&image, &staging).unwrap();
        assert_eq!(first.sha256().len(), 64);
        assert!(first.staged_worker().starts_with(first.stage_dir()));
        assert!(first
            .stage_dir()
            .ends_with(Path::new("worker").join(first.sha256())));
        // The held copy cannot be replaced or deleted while pinned.
        assert!(std::fs::write(first.staged_worker(), b"replaced").is_err());
        assert!(std::fs::remove_file(first.staged_worker()).is_err());
        // A second backend for the same image adopts the staged copy.
        let second = WindowsBackend::new(&image, &staging).unwrap();
        assert_eq!(second.staged_worker(), first.staged_worker());
        // The staged directory grants every LPAC token read and execute.
        let dacl = std::process::Command::new("icacls")
            .arg(first.stage_dir())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&dacl.stdout);
        assert!(
            text.contains("ALL RESTRICTED APPLICATION PACKAGES"),
            "{text}"
        );
        assert!(!text.contains("ALL APPLICATION PACKAGES:"), "{text}");
    }

    #[test]
    fn a_held_staged_copy_with_different_bytes_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let image = fixture_image(&root, "worker.exe");
        let staging = root.join("stage");
        let sha256 = hex::encode(Sha256::digest(std::fs::read(&image).unwrap()));
        let stage_dir = staging.join("worker").join(&sha256);
        std::fs::create_dir_all(&stage_dir).unwrap();
        let planted = stage_dir.join(STAGED_NAME);
        std::fs::write(&planted, b"not the worker").unwrap();
        let holder = open_pinned(&planted).unwrap();
        let error = WindowsBackend::new(&image, &staging)
            .unwrap_err()
            .to_string();
        assert!(error.contains("hash differs"), "{error}");
        drop(holder);
        // Unheld, the stale copy is replaced by the hashed image.
        let backend = WindowsBackend::new(&image, &staging).unwrap();
        assert_eq!(
            std::fs::read(backend.staged_worker()).unwrap(),
            std::fs::read(&image).unwrap()
        );
    }

    #[test]
    fn reparse_components_links_and_relative_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        let image = fixture_image(&real, "worker.exe");
        let staging = root.join("stage");
        junction(&root.join("jump"), &real);
        let through_junction = root.join("jump").join("worker.exe");
        assert!(std::fs::metadata(&through_junction).is_ok());
        assert!(WindowsBackend::new(&through_junction, &staging).is_err());
        assert!(WindowsBackend::new(&image, &root.join("jump").join("stage")).is_err());
        std::fs::hard_link(&image, real.join("alias.exe")).unwrap();
        assert!(WindowsBackend::new(&image, &staging).is_err());
        std::fs::remove_file(real.join("alias.exe")).unwrap();
        assert!(WindowsBackend::new(Path::new("worker.exe"), &staging).is_err());
        assert!(WindowsBackend::new(&root.join("missing.exe"), &staging).is_err());
        WindowsBackend::new(&image, &staging).unwrap();
    }
}
