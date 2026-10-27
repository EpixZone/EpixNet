//! Offline, recoverable relocation of the node's `private/` and `data/` trees.
//!
//! Queueing never snapshots a live node. Startup holds both data-root leases,
//! copies into a private staging directory, and commits the config last. A
//! failed attempt is rolled back before taking a fresh snapshot; an identity
//! file left by a partial copy is never mistaken for an existing profile.

use serde::{Deserialize, Serialize};
use std::ffi::{OsStr, OsString};
use std::fs::File;
#[cfg(windows)]
use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

const PLAN: &str = ".epixnet-relocation.json";
const CONTROL_LOCK: &str = ".epixnet-relocation.lock";
const DATA_LOCK: &str = "lock.pid";
const PARTS: [&str; 2] = ["private", "data"];
const MAX_PLAN: u64 = 64 * 1024;

#[cfg(windows)]
#[path = "data_relocation_windows.rs"]
mod windows_permissions;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn context(error: io::Error, operation: &str, path: &Path) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {}: {error}", path.display()),
    )
}

/// Exclusive cooperative ownership, retained for the lifetime of a node.
/// The lock file must not be removed, including on normal shutdown.
#[derive(Debug)]
pub struct DataRootLease {
    root: PathBuf,
    directory: Directory,
    _lock: Lease,
}

impl DataRootLease {
    pub fn acquire(root: &Path) -> io::Result<Self> {
        let root = trusted_root(root)?;
        let directory = Directory::open(&root, true)?;
        let lock = Lease::acquire(&directory, DATA_LOCK)?;
        directory.assert_bound()?;
        Ok(Self {
            root,
            directory,
            _lock: lock,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Debug)]
struct Lease(File);

impl Lease {
    fn acquire(directory: &Directory, name: &str) -> io::Result<Self> {
        let file = directory.open_lock(name.as_ref())?;
        #[cfg(not(target_os = "android"))]
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("Another EpixNet process owns {}", directory.path.display()),
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        #[cfg(target_os = "android")]
        {
            use std::os::fd::AsRawFd;
            // Android's std File::try_lock is not implemented on all supported
            // runtimes. flock uses the same descriptor and never follows a path.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(file))
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        #[cfg(not(target_os = "android"))]
        let _ = self.0.unlock();
        #[cfg(target_os = "android")]
        {
            use std::os::fd::AsRawFd;
            unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Identity(u64, u64);

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Operation {
    CopyNew,
    SwitchExisting,
}

#[derive(Debug, Deserialize, Serialize)]
struct Snapshot {
    name: String,
    identity: Identity,
    // Persisted before the first promotion. Each destination entry must have
    // the original staging directory's identity before recovery may remove it.
    parts: Vec<(String, Identity)>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Plan {
    version: u32,
    conf: PathBuf,
    default: PathBuf,
    source: PathBuf,
    source_identity: Identity,
    target: PathBuf,
    target_identity: Identity,
    operation: Operation,
    snapshot: Option<Snapshot>,
}

// NodeOptions and EPIX_DATA_DIR are trusted caller paths and historically
// accept relative paths. Config-page input is validated separately.
fn trusted_root(root: &Path) -> io::Result<PathBuf> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let mut ancestor = absolute.as_path();
    let mut suffix = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut path) => {
                for name in suffix.into_iter().rev() {
                    path.push(name);
                }
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                suffix.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| invalid("Cannot resolve data root"))?
                        .to_os_string(),
                );
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| invalid("Cannot resolve data root"))?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn control(conf: &Path) -> io::Result<(Directory, Lease)> {
    let parent = conf
        .parent()
        .ok_or_else(|| invalid("Config has no parent directory"))?;
    let directory = Directory::open(&crate::paths::resolve_data_directory(parent)?, true)?;
    let lock = Lease::acquire(&directory, CONTROL_LOCK)?;
    Ok((directory, lock))
}

fn read_plan(directory: &Directory) -> io::Result<Option<Plan>> {
    let Some(file) = directory.read_optional(PLAN.as_ref())? else {
        return Ok(None);
    };
    let plan: Plan = serde_json::from_slice(&read_bounded(file, MAX_PLAN)?)
        .map_err(|error| invalid(format!("Invalid pending data move: {error}")))?;
    if plan.version != 1 || plan.source == plan.target {
        return Err(invalid("Unsupported pending data move"));
    }
    if plan.operation == Operation::SwitchExisting && plan.snapshot.is_some() {
        return Err(invalid(
            "An existing-profile switch cannot own a copied snapshot",
        ));
    }
    check_lexical_paths(&plan.source, &plan.target)?;
    absolute_path(&plan.conf)?;
    absolute_path(&plan.default)?;
    if let Some(snapshot) = &plan.snapshot {
        if !snapshot.name.starts_with(".epixnet-relocation-")
            || !single_name(snapshot.name.as_ref())
            || snapshot.parts.len() > PARTS.len()
            || snapshot
                .parts
                .iter()
                .enumerate()
                .any(|(i, (name, _))| name != PARTS[i])
        {
            return Err(invalid("Invalid data move staging record"));
        }
    }
    Ok(Some(plan))
}

fn save_plan(directory: &Directory, plan: &Plan) -> io::Result<()> {
    let bytes = serde_json::to_vec(plan).map_err(io::Error::other)?;
    directory.atomic_write(PLAN.as_ref(), &bytes)
}

/// The requested root, used by the Config page's restart-required indicator.
pub fn pending_target(conf: &Path) -> io::Result<Option<PathBuf>> {
    let parent = conf
        .parent()
        .ok_or_else(|| invalid("Config has no parent directory"))?;
    if !parent.exists() {
        return Ok(None);
    }
    let directory = Directory::open(&crate::paths::resolve_data_directory(parent)?, false)?;
    let plan = read_plan(&directory)?;
    if plan.as_ref().is_some_and(|plan| {
        plan.conf.file_name() != conf.file_name()
            || plan.conf.parent() != Some(directory.path.as_path())
    }) {
        return Err(invalid(
            "Pending data move belongs to a different configuration",
        ));
    }
    Ok(plan.map(|plan| plan.target))
}

/// Queue a copy or an explicit switch to an existing identity. Does not copy
/// source data or change the effective config. Selecting the current root
/// cancels a request which has not begun applying.
pub fn queue_request(
    conf: &Path,
    current: &Path,
    target: &Path,
    default: &Path,
) -> io::Result<String> {
    let current = crate::paths::resolve_data_directory(current)?;
    let target = crate::paths::resolve_data_directory(target)?;
    let default = crate::paths::resolve_data_directory(default)?;
    let (control, _lock) = control(conf)?;
    if let Some(plan) = read_plan(&control)? {
        if plan.conf
            != control.path.join(
                conf.file_name()
                    .ok_or_else(|| invalid("Config has no filename"))?,
            )
            || plan.default != default
        {
            return Err(invalid(
                "Pending data move belongs to a different configuration",
            ));
        }
        if plan.snapshot.is_some() {
            return Err(invalid("An interrupted data move must finish recovering at startup before changing its destination"));
        }
    }
    if current == target {
        commit_conf(
            &control,
            conf,
            (current != default).then_some(current.as_path()),
        )?;
        control.remove_optional_file(PLAN.as_ref())?;
        return Ok(format!(
            "Data directory is already {}; pending move cancelled",
            current.display()
        ));
    }
    check_paths(&current, &target)?;
    if configured_root(&control, conf, &default)? != current {
        return Err(invalid(
            "The configured data directory changed; restart before queueing a move",
        ));
    }
    let source = Directory::open(&current, false)?;
    let destination = DataRootLease::acquire(&target)?;
    let operation = if has_identity(&destination.directory)? {
        Operation::SwitchExisting
    } else {
        require_empty_parts(&destination.directory)?;
        if !has_identity(&source)? {
            return Err(invalid(
                "The source data directory has no regular identity file",
            ));
        }
        Operation::CopyNew
    };
    save_plan(
        &control,
        &Plan {
            version: 1,
            conf: control.path.join(
                conf.file_name()
                    .ok_or_else(|| invalid("Config has no filename"))?,
            ),
            default,
            source: current,
            source_identity: source.identity()?,
            target: target.clone(),
            target_identity: destination.directory.identity()?,
            operation,
            snapshot: None,
        },
    )?;
    Ok(format!("Data directory change to {} queued. Restart EpixNet to apply it; the old directory is kept as a backup.", target.display()))
}

/// Apply a queued move before opening any node database, CA or browser profile.
/// On error the original config remains selected, except when a completed
/// transaction has already committed it. The caller must not boot on an error.
pub fn prepare_startup(conf: &Path, default: &Path) -> io::Result<DataRootLease> {
    prepare_with_hook(conf, default, |_| Ok(())).map_err(|error| {
        let plan = conf.parent().unwrap_or_else(|| Path::new(".")).join(PLAN);
        io::Error::new(error.kind(), format!("Data directory preparation failed: {error}. Source data is retained. Resolve the error and restart to retry; pending move metadata, if present, is {}.", plan.display()))
    })
}

fn prepare_with_hook(
    conf: &Path,
    default: &Path,
    mut checkpoint: impl FnMut(&str) -> io::Result<()>,
) -> io::Result<DataRootLease> {
    let default = crate::paths::resolve_data_directory(default)?;
    let (control, _lock) = control(conf)?;
    let effective = configured_root(&control, conf, &default)?;
    let Some(mut plan) = read_plan(&control)? else {
        let lease = DataRootLease::acquire(&effective)?;
        control.assert_bound()?;
        if configured_root(&control, conf, &default)? != effective {
            return Err(invalid(
                "The configured data directory changed during startup",
            ));
        }
        return Ok(lease);
    };
    // Displaying a queued request must work even when its drive is absent.
    // Applying it still requires fresh canonical and identity validation.
    check_paths(&plan.source, &plan.target)?;
    if plan.conf
        != control.path.join(
            conf.file_name()
                .ok_or_else(|| invalid("Config has no filename"))?,
        )
        || plan.default != default
    {
        return Err(invalid(
            "Pending data move belongs to a different configuration",
        ));
    }
    if effective != plan.source && effective != plan.target {
        return Err(invalid(
            "The configured data directory changed after this move was queued",
        ));
    }
    // Acquisition is nonblocking, so opposite moves cannot deadlock.
    let source = DataRootLease::acquire(&plan.source)?;
    let target = DataRootLease::acquire(&plan.target)?;
    if source.directory.identity()? != plan.source_identity
        || target.directory.identity()? != plan.target_identity
    {
        return Err(invalid(
            "A queued data directory was replaced; refusing to move it",
        ));
    }
    if effective == plan.target {
        // A crash after config commit must not undo a completed move.
        if plan.operation == Operation::CopyNew {
            let snapshot = plan
                .snapshot
                .as_ref()
                .ok_or_else(|| invalid("Missing committed move record"))?;
            if snapshot.parts.len() != PARTS.len() {
                return Err(invalid("Incomplete committed move record"));
            }
            for (name, identity) in &snapshot.parts {
                if target.directory.child(name.as_ref(), false)?.identity()? != *identity {
                    return Err(invalid(
                        "Committed data directory does not match its move record",
                    ));
                }
            }
        }
        control.assert_bound()?;
        target.directory.assert_bound()?;
        finish(&control, &target.directory, &plan)?;
        target.directory.assert_bound()?;
        return Ok(target);
    }
    if let Some(snapshot) = &plan.snapshot {
        rollback(&target.directory, snapshot)?;
        plan.snapshot = None;
        save_plan(&control, &plan)?;
    }
    if plan.operation == Operation::SwitchExisting {
        if !has_identity(&target.directory)? {
            return Err(invalid(
                "The destination identity disappeared after the switch was queued",
            ));
        }
    } else {
        require_empty_parts(&target.directory)?;
        let name = random_name(".epixnet-relocation-")?;
        let stage = target.directory.create_child(name.as_ref())?;
        plan.snapshot = Some(Snapshot {
            name,
            identity: stage.identity()?,
            parts: Vec::new(),
        });
        save_plan(&control, &plan)?;
        checkpoint("stage-created")?;
        for part in PARTS {
            let output = stage.create_child(part.as_ref())?;
            if let Some(input) = source.directory.optional_child(part.as_ref())? {
                copy_tree(&input, &output)?;
            }
            output.sync()?;
            checkpoint(part)?;
        }
        if !has_identity(&stage)? {
            return Err(invalid("The source identity disappeared during the move"));
        }
        let parts = PARTS
            .iter()
            .map(|name| {
                Ok((
                    name.to_string(),
                    stage.child(name.as_ref(), false)?.identity()?,
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        plan.snapshot.as_mut().unwrap().parts = parts;
        stage.sync()?;
        save_plan(&control, &plan)?;
        checkpoint("snapshot-ready")?;
        for part in PARTS {
            stage.move_new(part.as_ref(), &target.directory, part.as_ref())?;
            checkpoint(if part == "private" {
                "promoted-private"
            } else {
                "promoted-data"
            })?;
        }
    }
    checkpoint("before-config")?;
    source.directory.assert_bound()?;
    target.directory.assert_bound()?;
    control.assert_bound()?;
    if configured_root(&control, conf, &default)? != plan.source {
        return Err(invalid(
            "The configured data directory changed during relocation",
        ));
    }
    commit_conf(
        &control,
        conf,
        (plan.target != default).then_some(plan.target.as_path()),
    )?;
    checkpoint("after-config")?;
    target.directory.assert_bound()?;
    control.assert_bound()?;
    if configured_root(&control, conf, &default)? != plan.target {
        return Err(invalid(
            "The configured data directory changed after relocation",
        ));
    }
    finish(&control, &target.directory, &plan)?;
    target.directory.assert_bound()?;
    Ok(target)
}

fn finish(control: &Directory, target: &Directory, plan: &Plan) -> io::Result<()> {
    if let Some(snapshot) = &plan.snapshot {
        target.remove_tree(snapshot.name.as_ref(), &snapshot.identity)?;
    }
    control.remove_optional_file(PLAN.as_ref())
}

fn rollback(target: &Directory, snapshot: &Snapshot) -> io::Result<()> {
    for (name, identity) in &snapshot.parts {
        // Only the exact directories promoted by this transaction can be
        // removed. Existing or substituted user entries are never merged.
        target.remove_tree(name.as_ref(), identity)?;
    }
    target.remove_tree(snapshot.name.as_ref(), &snapshot.identity)
}

fn check_paths(source: &Path, target: &Path) -> io::Result<()> {
    check_lexical_paths(source, target)?;
    if crate::paths::resolve_data_directory(source)? != source
        || crate::paths::resolve_data_directory(target)? != target
    {
        return Err(invalid(
            "Data directories must be canonical, separate, non-overlapping paths",
        ));
    }
    Ok(())
}

fn absolute_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || path
            .as_os_str()
            .to_string_lossy()
            .chars()
            .any(char::is_control)
    {
        return Err(invalid(
            "Pending data move paths must be absolute without traversal or control characters",
        ));
    }
    Ok(())
}

fn check_lexical_paths(source: &Path, target: &Path) -> io::Result<()> {
    absolute_path(source)?;
    absolute_path(target)?;
    if source.starts_with(target) || target.starts_with(source) {
        return Err(invalid("Pending data move paths must not overlap"));
    }
    Ok(())
}

fn has_identity(root: &Directory) -> io::Result<bool> {
    // Validate both components even when an identity already exists.
    let private = root.optional_child("private".as_ref())?;
    let data = root.optional_child("data".as_ref())?;
    match private {
        Some(private) => {
            Ok(private.read_optional("users.json".as_ref())?.is_some() && data.is_some())
        }
        None => Ok(false),
    }
}

fn require_empty_parts(root: &Directory) -> io::Result<()> {
    for name in PARTS {
        if root.entry_exists(name.as_ref())? {
            return Err(invalid(format!("Destination already contains {name} without an existing identity. Choose a clean directory; existing files will not be overwritten.")));
        }
    }
    Ok(())
}

fn copy_tree(source: &Directory, target: &Directory) -> io::Result<()> {
    for name in source.names()? {
        let operation = || -> io::Result<()> {
            if source.entry_is_directory(&name)? {
                let input = source.child(&name, false)?;
                let output = target.create_child(&name)?;
                copy_tree(&input, &output)?;
                output.sync()
            } else {
                let mut input = source.read_file(&name)?;
                let mut output = target.create_file(&name)?;
                io::copy(&mut input, &mut output)?;
                // Private files stay owner-only on Unix rather than inheriting
                // permissive source modes. Preserve only executable bits.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    output.set_permissions(std::fs::Permissions::from_mode(
                        0o600 | (input.metadata()?.permissions().mode() & 0o100),
                    ))?;
                }
                output.sync_all()
            }
        };
        operation().map_err(|error| context(error, "Copy", &source.path.join(&name)))?;
    }
    target.sync()
}

fn read_bounded(file: File, maximum: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(invalid("Relocation metadata is too large"));
    }
    Ok(bytes)
}

fn random_name(prefix: &str) -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(format!("{prefix}{}", hex::encode(bytes)))
}

fn single_name(name: &OsStr) -> bool {
    let mut parts = Path::new(name).components();
    matches!(parts.next(), Some(Component::Normal(_))) && parts.next().is_none()
}

/// A pinned non-link directory. Unix operations use directory descriptors;
/// Windows holds every ancestor without DELETE sharing for the operation.
#[derive(Debug)]
struct Directory {
    path: PathBuf,
    file: File,
    #[cfg(windows)]
    _parents: Vec<File>,
}

/// Scoped private storage for native credentials and addon receipts. The parent
/// is selected by native code, never a page request. Every leaf stays relative
/// to a pinned directory, and existing directories must already be private.
#[derive(Debug)]
pub(crate) struct ProtectedDirectory(Directory);

/// Pinned read-only view used only for a node-selected xite root. It keeps the
/// strict regular-file reader semantics while bounding each relative read.
#[derive(Debug)]
pub(crate) struct NativeReadDirectory(Directory);

impl NativeReadDirectory {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self(Directory::open(path, false)?))
    }
    pub(crate) fn assert_bound(&self) -> io::Result<()> {
        self.0.assert_bound()
    }
    pub(crate) fn read(&self, path: &str, limit: u64) -> io::Result<Vec<u8>> {
        self.0.assert_bound()?;
        let mut names = path.split('/').peekable();
        let mut child = None;
        while let Some(name) = names.next() {
            if !single_name(name.as_ref()) {
                return Err(invalid("Invalid native read path"));
            }
            let parent = child.as_ref().unwrap_or(&self.0);
            if names.peek().is_none() {
                let bytes = read_bounded(parent.read_file(name.as_ref())?, limit)?;
                parent.assert_bound()?;
                self.0.assert_bound()?;
                return Ok(bytes);
            }
            child = Some(parent.child(name.as_ref(), false)?);
        }
        Err(invalid("Empty native read path"))
    }
}

impl ProtectedDirectory {
    pub(crate) fn open_child(parent: &Path, name: &str) -> io::Result<Self> {
        let parent = Directory::open(&trusted_root(parent)?, false)?;
        Self::child_of(&parent, name)
    }

    fn child_of(parent: &Directory, name: &str) -> io::Result<Self> {
        parent.assert_bound()?;
        let child = match parent.create_child(name.as_ref()) {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                parent.child(name.as_ref(), false)?
            }
            Err(error) => return Err(error),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = child.file.metadata()?;
            // SAFETY: geteuid takes no arguments and cannot fail.
            if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Native storage must be owner-only",
                ));
            }
        }
        #[cfg(windows)]
        windows_permissions::verify_private_directory(&child.file)?;
        parent.assert_bound()?;
        child.assert_bound()?;
        Ok(Self(child))
    }

    pub(crate) fn child(&self, name: &str) -> io::Result<Self> {
        Self::child_of(&self.0, name)
    }

    pub(crate) fn read(&self, name: &str, limit: u64) -> io::Result<Option<Vec<u8>>> {
        self.0.assert_bound()?;
        let bytes = self
            .0
            .read_optional(name.as_ref())?
            .map(|file| read_bounded(file, limit))
            .transpose()?;
        self.0.assert_bound()?;
        Ok(bytes)
    }

    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.0.assert_bound()?;
        drop(self.0.read_optional(name.as_ref())?);
        let temporary = random_name(".epix-write-")?;
        let result = (|| {
            let mut file = self.0.create_file(temporary.as_ref())?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            self.0.assert_bound()?;
            self.0.replace(temporary.as_ref(), name.as_ref())
        })();
        if result.is_err() {
            let _ = self.0.remove_optional_file(temporary.as_ref());
        }
        result
    }

    pub(crate) fn create_new(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        self.0.assert_bound()?;
        let mut file = self.0.create_file(name.as_ref())?;
        let result = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = result {
            let _ = self.0.remove_optional_file(name.as_ref());
            return Err(error);
        }
        self.0.sync()?;
        self.0.assert_bound()?;
        Ok(self.0.path.join(name))
    }

    pub(crate) fn path(&self, name: &str) -> io::Result<PathBuf> {
        if !single_name(name.as_ref()) {
            return Err(invalid("Invalid native storage name"));
        }
        self.0.assert_bound()?;
        Ok(self.0.path.join(name))
    }

    pub(crate) fn remove(&self, name: &str) -> io::Result<()> {
        self.0.assert_bound()?;
        self.0.remove_optional_file(name.as_ref())
    }

    pub(crate) fn discard_addon_spools_except(&self, keep: Option<&str>) -> io::Result<()> {
        self.0.assert_bound()?;
        let names = self.0.names()?;
        if names.len() > 64 {
            return Err(invalid("Unexpected native spool count"));
        }
        for name in names {
            let Some(name) = name.to_str() else { continue };
            let spool = name
                .strip_suffix(".xpi")
                .is_some_and(|id| lower_hex(id, 64));
            let temporary = name
                .strip_prefix(".epix-write-")
                .is_some_and(|id| lower_hex(id, 32));
            if (spool && Some(name) != keep) || temporary {
                self.0.remove_optional_file(name.as_ref())?;
            }
        }
        Ok(())
    }

    pub(crate) fn addon_profile(&self, id: &str) -> io::Result<Self> {
        if !lower_hex(id, 64) {
            return Err(invalid("Invalid addon profile ID"));
        }
        let names = self.0.names()?;
        let profiles = names
            .iter()
            .filter_map(|n| n.to_str())
            .filter(|n| lower_hex(n, 64))
            .count();
        if names.len() > 64 || (profiles >= 16 && !names.iter().any(|n| n == id)) {
            return Err(invalid("Persistent addon profile limit"));
        }
        self.child(id)
    }

    /// Count owned stage and interrupted receipt files, including profiles
    /// not opened in this process. Never delete another profile's receipt.
    pub(crate) fn addon_spool_bytes(&self) -> io::Result<u64> {
        self.0.assert_bound()?;
        let names = self.0.names()?;
        if names.len() > 64 {
            return Err(invalid("Unexpected addon profile count"));
        }
        let mut total = 0u64;
        let mut profiles = 0;
        for name in names {
            let Some(id) = name.to_str().filter(|n| lower_hex(n, 64)) else {
                continue;
            };
            profiles += 1;
            if profiles > 16 {
                return Err(invalid("Persistent addon profile limit"));
            }
            let directory = Self::child_of(&self.0, id)?;
            let files = directory.0.names()?;
            if files.len() > 64 {
                return Err(invalid("Unexpected native spool count"));
            }
            for file in files {
                let Some(name) = file.to_str() else { continue };
                let spool = name
                    .strip_suffix(".xpi")
                    .is_some_and(|id| lower_hex(id, 64));
                let temporary = name
                    .strip_prefix(".epix-write-")
                    .is_some_and(|id| lower_hex(id, 32));
                if spool || temporary {
                    total = total
                        .checked_add(directory.0.read_file(file.as_ref())?.metadata()?.len())
                        .ok_or_else(|| invalid("Native addon storage size overflow"))?;
                }
            }
            directory.0.assert_bound()?;
        }
        self.0.assert_bound()?;
        Ok(total)
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Directory {
    fn open(path: &Path, create: bool) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("Expected an absolute directory"));
        }
        let mut anchor = PathBuf::new();
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::Prefix(_) | Component::RootDir if names.is_empty() => {
                    anchor.push(component)
                }
                Component::Normal(name) => names.push(name.to_os_string()),
                _ => return Err(invalid("Invalid directory component")),
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            Self::walk_search_only(&anchor, &names, create)
        }
        #[cfg(target_vendor = "apple")]
        {
            Self::open_apple(path, create)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            let mut current = Self::anchor(&anchor)?;
            for name in names {
                current = current.child(&name, create)?;
            }
            Ok(current)
        }
    }

    fn identity(&self) -> io::Result<Identity> {
        file_identity(&self.file)
    }

    fn assert_bound(&self) -> io::Result<()> {
        if Self::open(&self.path, false)?.identity()? != self.identity()? {
            return Err(invalid(format!(
                "Data move directory was replaced: {}",
                self.path.display()
            )));
        }
        Ok(())
    }

    fn optional_child(&self, name: &OsStr) -> io::Result<Option<Self>> {
        match self.child(name, false) {
            Ok(directory) => Ok(Some(directory)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn read_optional(&self, name: &OsStr) -> io::Result<Option<File>> {
        match self.read_file(name) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn atomic_write(&self, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
        self.assert_bound()?;
        // Refuse an existing link/special target rather than silently replacing
        // it. Replacing a regular entry is safe and never follows its contents.
        drop(self.read_optional(name)?);
        let temporary = random_name(".epix-write-")?;
        let mut file = self.create_file(temporary.as_ref())?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        self.assert_bound()?;
        self.replace(temporary.as_ref(), name)
    }

    fn remove_optional_file(&self, name: &OsStr) -> io::Result<()> {
        if self.read_optional(name)?.is_some() {
            self.remove_file(name)?;
        }
        Ok(())
    }

    fn remove_tree(&self, name: &OsStr, identity: &Identity) -> io::Result<()> {
        let Some(directory) = self.optional_child(name)? else {
            return Ok(());
        };
        if directory.identity()? != *identity {
            return Err(invalid(format!(
                "Refusing to remove replaced move directory {}",
                directory.path.display()
            )));
        }
        directory.clear()?;
        drop(directory);
        self.remove_directory(name)
    }

    fn clear(&self) -> io::Result<()> {
        for name in self.names()? {
            if self.entry_is_directory(&name)? {
                let child = self.child(&name, false)?;
                child.clear()?;
                drop(child);
                self.remove_directory(&name)?;
            } else {
                // Validate without following links, including during cleanup.
                drop(self.read_file(&name)?);
                self.remove_file(&name)?;
            }
        }
        self.sync()
    }
}

fn config_text(directory: &Directory, conf: &Path) -> io::Result<String> {
    let name = conf
        .file_name()
        .ok_or_else(|| invalid("Config has no filename"))?;
    directory
        .read_optional(name)?
        .map(|file| String::from_utf8(read_bounded(file, 1024 * 1024)?).map_err(io::Error::other))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn configured_root(directory: &Directory, conf: &Path, default: &Path) -> io::Result<PathBuf> {
    let text = config_text(directory, conf)?;
    let value = text
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            (key.trim() == "data_dir" && !value.trim().is_empty())
                .then(|| PathBuf::from(value.trim()))
        })
        .last()
        .unwrap_or_else(|| default.to_path_buf());
    trusted_root(&value)
}

fn commit_conf(directory: &Directory, conf: &Path, root: Option<&Path>) -> io::Result<()> {
    let bytes = crate::paths::render_conf_data_dir(&config_text(directory, conf)?, root);
    directory.atomic_write(
        conf.file_name()
            .ok_or_else(|| invalid("Config has no filename"))?,
        bytes.as_bytes(),
    )
}

/// Atomic config replacement using the same non-link parent/leaf contract as
/// the move journal. Kept crate-private for paths.rs.
pub(crate) fn atomic_write_config(conf: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = conf
        .parent()
        .ok_or_else(|| invalid("Config has no parent"))?;
    let directory = Directory::open(&crate::paths::resolve_data_directory(parent)?, true)?;
    directory.atomic_write(
        conf.file_name()
            .ok_or_else(|| invalid("Config has no filename"))?,
        bytes,
    )
}

pub(crate) fn read_config(conf: &Path) -> io::Result<Option<String>> {
    let parent = conf
        .parent()
        .ok_or_else(|| invalid("Config has no parent"))?;
    if !parent.exists() {
        return Ok(None);
    }
    let directory = Directory::open(&crate::paths::resolve_data_directory(parent)?, false)?;
    directory
        .read_optional(
            conf.file_name()
                .ok_or_else(|| invalid("Config has no filename"))?,
        )?
        .map(|file| String::from_utf8(read_bounded(file, 1024 * 1024)?).map_err(io::Error::other))
        .transpose()
}

#[cfg(unix)]
fn file_identity(file: &File) -> io::Result<Identity> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok(Identity(meta.dev(), meta.ino()))
}

#[cfg(unix)]
impl Directory {
    /// Ancestors may allow search without directory listing, notably Android's
    /// /data. O_PATH pins each inode without asking to enumerate it. Only the
    /// final node-owned directory is reopened for reading and syncing.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn walk_search_only(anchor: &Path, names: &[OsString], create: bool) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        let search = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let readable = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory: File = rustix::fs::open(anchor, search, Mode::empty())?.into();
        let mut path = anchor.to_path_buf();
        for name in names {
            let next = match rustix::fs::openat(&directory, name, search, Mode::empty()) {
                Ok(file) => file,
                Err(rustix::io::Errno::NOENT) if create => {
                    // An O_PATH descriptor cannot be fsynced. Before creating
                    // anything, obtain a readable handle to the same parent
                    // inode so the new entry can be made durable. Existing
                    // protected ancestors never need this extra access.
                    let parent: File =
                        rustix::fs::openat(&directory, ".", readable, Mode::empty())?.into();
                    match rustix::fs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                        Ok(()) => parent.sync_all()?,
                        Err(rustix::io::Errno::EXIST) => {}
                        Err(error) => return Err(error.into()),
                    }
                    rustix::fs::openat(&directory, name, search, Mode::empty())?
                }
                Err(error) => return Err(error.into()),
            };
            directory = next.into();
            path.push(name);
        }
        let file = rustix::fs::openat(&directory, ".", readable, Mode::empty())?;
        Ok(Self {
            path,
            file: file.into(),
        })
    }

    /// macOS 11 and iOS 14 support a kernel-checked whole-path no-symlink open.
    /// Opening only the final directory avoids requesting list permission on
    /// app-container ancestors. O_SEARCH would raise the supported OS minimum.
    #[cfg(target_vendor = "apple")]
    fn open_apple(path: &Path, create: bool) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        // Darwin rejects combining O_NOFOLLOW_ANY with ordinary O_NOFOLLOW.
        let flags = OFlags::RDONLY
            | OFlags::DIRECTORY
            | OFlags::CLOEXEC
            | OFlags::from_bits_retain(libc::O_NOFOLLOW_ANY as _);
        match rustix::fs::open(path, flags, Mode::empty()) {
            Ok(file) => Ok(Self {
                path: path.to_path_buf(),
                file: file.into(),
            }),
            Err(rustix::io::Errno::NOENT) if create => {
                let parent = Self::open(
                    path.parent()
                        .ok_or_else(|| invalid("Directory has no parent"))?,
                    true,
                )?;
                let name = path
                    .file_name()
                    .ok_or_else(|| invalid("Directory has no name"))?;
                match parent.create_child(name) {
                    Ok(directory) => Ok(directory),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        parent.child(name, false)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    fn anchor(path: &Path) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        let file = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self {
            path: path.to_path_buf(),
            file: file.into(),
        })
    }

    fn child(&self, name: &OsStr, create: bool) -> io::Result<Self> {
        use rustix::fs::{Mode, OFlags};
        if !single_name(name) {
            return Err(invalid("Invalid child name"));
        }
        if create {
            match rustix::fs::mkdirat(&self.file, name, Mode::from_raw_mode(0o700)) {
                Ok(()) => self.sync()?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let file = rustix::fs::openat(
            &self.file,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self {
            path: self.path.join(name),
            file: file.into(),
        })
    }

    fn create_child(&self, name: &OsStr) -> io::Result<Self> {
        if !single_name(name) {
            return Err(invalid("Invalid child name"));
        }
        rustix::fs::mkdirat(&self.file, name, rustix::fs::Mode::from_raw_mode(0o700))?;
        self.sync()?;
        self.child(name, false)
    }

    fn open_regular(&self, name: &OsStr, flags: rustix::fs::OFlags) -> io::Result<File> {
        use rustix::fs::{Mode, OFlags};
        if !single_name(name) {
            return Err(invalid("Invalid file name"));
        }
        let file: File = rustix::fs::openat(
            &self.file,
            name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )?
        .into();
        if !file.metadata()?.is_file() {
            return Err(invalid("Expected a regular non-link file"));
        }
        Ok(file)
    }
    fn read_file(&self, name: &OsStr) -> io::Result<File> {
        self.open_regular(name, rustix::fs::OFlags::RDONLY)
    }
    fn open_lock(&self, name: &OsStr) -> io::Result<File> {
        self.open_regular(name, rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CREATE)
    }
    fn create_file(&self, name: &OsStr) -> io::Result<File> {
        self.open_regular(
            name,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
        )
    }
    fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    fn names(&self) -> io::Result<Vec<OsString>> {
        use std::os::unix::ffi::OsStrExt;
        let mut names = Vec::new();
        for entry in rustix::fs::Dir::read_from(&self.file)? {
            let entry = entry?;
            let name = OsStr::from_bytes(entry.file_name().to_bytes());
            if name != "." && name != ".." {
                names.push(name.to_os_string());
            }
        }
        names.sort();
        Ok(names)
    }

    fn entry_exists(&self, name: &OsStr) -> io::Result<bool> {
        match rustix::fs::statat(&self.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn entry_is_directory(&self, name: &OsStr) -> io::Result<bool> {
        let stat = rustix::fs::statat(&self.file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let kind = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        match kind {
            rustix::fs::FileType::Directory => Ok(true),
            rustix::fs::FileType::RegularFile => Ok(false),
            _ => Err(invalid(
                "Data directories cannot contain links or special files",
            )),
        }
    }
    fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        rustix::fs::unlinkat(&self.file, name, rustix::fs::AtFlags::empty())?;
        self.sync()
    }
    fn remove_directory(&self, name: &OsStr) -> io::Result<()> {
        rustix::fs::unlinkat(&self.file, name, rustix::fs::AtFlags::REMOVEDIR)?;
        self.sync()
    }
    fn replace(&self, source: &OsStr, target: &OsStr) -> io::Result<()> {
        rustix::fs::renameat(&self.file, source, &self.file, target)?;
        self.sync()
    }
    fn move_new(&self, source: &OsStr, target: &Directory, name: &OsStr) -> io::Result<()> {
        rustix::fs::renameat_with(
            &self.file,
            source,
            &target.file,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        target.sync()?;
        self.sync()
    }
}

#[cfg(windows)]
fn file_identity(file: &File) -> io::Result<Identity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Identity(
        info.dwVolumeSerialNumber as u64,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    ))
}

#[cfg(windows)]
fn regular_metadata(meta: &Metadata, directory: bool) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        }
    {
        return Err(invalid("Expected a regular non-reparse entry"));
    }
    Ok(())
}

#[cfg(windows)]
impl Directory {
    fn anchor(path: &Path) -> io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        regular_metadata(&file.metadata()?, true)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            _parents: Vec::new(),
        })
    }
    fn child(&self, name: &OsStr, create: bool) -> io::Result<Self> {
        if !single_name(name) {
            return Err(invalid("Invalid child name"));
        }
        let path = self.path.join(name);
        if create && !self.entry_exists(name)? {
            return self.create_child(name);
        }
        let mut child = Self::anchor(&path)?;
        child._parents = self
            ._parents
            .iter()
            .map(File::try_clone)
            .collect::<io::Result<_>>()?;
        child._parents.push(self.file.try_clone()?);
        Ok(child)
    }
    fn create_child(&self, name: &OsStr) -> io::Result<Self> {
        if !single_name(name) {
            return Err(invalid("Invalid child name"));
        }
        let temporary = self.path.join(random_name(".epix-directory-")?);
        let created = windows_permissions::create_private_directory(&temporary, &self.file)?;
        let expected = file_identity(&created)?;
        // WRITE_THROUGH rename needs a delete-capable handle. Release this
        // no-delete handle only while installing, then require the same inode
        // before any private bytes may be written through the new directory.
        drop(created);
        if let Err(error) = epix_fs::install_file_write_through(&temporary, &self.path.join(name)) {
            let _ = std::fs::remove_dir(&temporary);
            return Err(error);
        }
        let directory = self.child(name, false)?;
        if directory.identity()? != expected {
            return Err(invalid(
                "A new private directory was replaced during installation",
            ));
        }
        Ok(directory)
    }
    fn read_file(&self, name: &OsStr) -> io::Result<File> {
        epix_fs::open_regular_file_beneath(&self.path, Path::new(name))
    }
    fn open_output(&self, name: &OsStr, new: bool) -> io::Result<File> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        if !single_name(name) {
            return Err(invalid("Invalid file name"));
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(!new)
            .create_new(new)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(name))?;
        regular_metadata(&file.metadata()?, false)?;
        Ok(file)
    }
    fn open_lock(&self, name: &OsStr) -> io::Result<File> {
        self.open_output(name, false)
    }
    fn create_file(&self, name: &OsStr) -> io::Result<File> {
        self.open_output(name, true)
    }
    fn sync(&self) -> io::Result<()> {
        Ok(())
    } // Windows promotion uses WRITE_THROUGH.
    fn names(&self) -> io::Result<Vec<OsString>> {
        let mut names = std::fs::read_dir(&self.path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }
    fn entry_exists(&self, name: &OsStr) -> io::Result<bool> {
        match std::fs::symlink_metadata(self.path.join(name)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
    fn entry_is_directory(&self, name: &OsStr) -> io::Result<bool> {
        let metadata = std::fs::symlink_metadata(self.path.join(name))?;
        regular_metadata(&metadata, metadata.is_dir())?;
        Ok(metadata.is_dir())
    }
    fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        epix_fs::remove_file_write_through(&self.path.join(name))
    }
    fn remove_directory(&self, name: &OsStr) -> io::Result<()> {
        let tombstone = self.path.join(random_name(".epix-removed-directory-")?);
        epix_fs::install_file_write_through(&self.path.join(name), &tombstone)?;
        std::fs::remove_dir(tombstone)
    }
    fn replace(&self, source: &OsStr, target: &OsStr) -> io::Result<()> {
        epix_fs::replace_file_write_through(&self.path.join(source), &self.path.join(target))
    }
    fn move_new(&self, source: &OsStr, target: &Directory, name: &OsStr) -> io::Result<()> {
        epix_fs::install_file_write_through(&self.path.join(source), &target.path.join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _temp: tempfile::TempDir,
        source: PathBuf,
        target: PathBuf,
        default: PathBuf,
        conf: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let source = base.join("source");
            let target = base.join("target space # %20 ü");
            let default = base.join("default");
            let conf = default.join("epixnet.conf");
            std::fs::create_dir_all(source.join("private")).unwrap();
            std::fs::create_dir(source.join("data")).unwrap();
            std::fs::write(source.join("private/users.json"), b"public test identity").unwrap();
            std::fs::write(source.join("private/config.json"), b"before queue").unwrap();
            std::fs::write(source.join("data/content.json"), b"public content").unwrap();
            crate::paths::write_conf_data_dir(&conf, Some(&source)).unwrap();
            Self {
                _temp: temp,
                source,
                target,
                default,
                conf,
            }
        }
        fn queue(&self) -> io::Result<String> {
            queue_request(&self.conf, &self.source, &self.target, &self.default)
        }
        fn apply(&self) -> io::Result<DataRootLease> {
            prepare_startup(&self.conf, &self.default)
        }
        fn configured(&self) -> PathBuf {
            crate::paths::read_conf_data_dir(&self.conf).unwrap_or_else(|| self.default.clone())
        }
    }

    #[test]
    fn queue_is_offline_and_copies_the_latest_source_state() {
        let fixture = Fixture::new();
        let live = DataRootLease::acquire(&fixture.source).unwrap();
        let before = std::fs::read(&fixture.conf).unwrap();
        fixture.queue().unwrap();
        assert_eq!(std::fs::read(&fixture.conf).unwrap(), before);
        assert_eq!(
            pending_target(&fixture.conf).unwrap(),
            Some(fixture.target.clone())
        );
        assert!(!fixture.target.join("private").exists());
        assert_eq!(
            fixture.apply().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        std::fs::write(
            fixture.source.join("private/config.json"),
            b"latest after queue",
        )
        .unwrap();
        drop(live);
        let lease = fixture.apply().unwrap();
        assert_eq!(lease.root(), fixture.target);
        assert_eq!(fixture.configured(), fixture.target);
        assert_eq!(
            std::fs::read(fixture.target.join("private/config.json")).unwrap(),
            b"latest after queue"
        );
        assert_eq!(
            std::fs::read(fixture.source.join("private/config.json")).unwrap(),
            b"latest after queue"
        );
        assert_eq!(pending_target(&fixture.conf).unwrap(), None);
        assert!(DataRootLease::acquire(&fixture.target).is_err());
        drop(lease);
        assert!(DataRootLease::acquire(&fixture.target).is_ok());
    }

    #[test]
    fn interrupted_snapshot_never_turns_into_an_existing_identity_switch() {
        let fixture = Fixture::new();
        fixture.queue().unwrap();
        let result = prepare_with_hook(&fixture.conf, &fixture.default, |stage| {
            if stage == "private" {
                Err(io::Error::other("fixture copy interruption"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err());
        assert_eq!(fixture.configured(), fixture.source);
        assert!(!fixture.target.join("private/users.json").exists());
        assert!(
            fixture.queue().is_err(),
            "interrupted copy cannot be recategorized as a switch"
        );
        std::fs::write(
            fixture.source.join("private/config.json"),
            b"new source state",
        )
        .unwrap();
        let lease = fixture.apply().unwrap();
        assert_eq!(
            std::fs::read(fixture.target.join("private/config.json")).unwrap(),
            b"new source state"
        );
        assert!(fixture.target.join("data/content.json").is_file());
        drop(lease);
    }

    #[cfg(unix)]
    #[test]
    fn repeated_source_link_failure_cannot_commit_an_incomplete_identity() {
        let fixture = Fixture::new();
        let outside = fixture.default.join("outside");
        std::fs::write(&outside, b"outside sentinel").unwrap();
        let link = fixture.source.join("data/link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        fixture.queue().unwrap();
        for _ in 0..2 {
            assert!(fixture.apply().is_err());
            assert_eq!(fixture.configured(), fixture.source);
            assert!(!fixture.target.join("private/users.json").exists());
            assert_eq!(std::fs::read(&outside).unwrap(), b"outside sentinel");
        }
        std::fs::remove_file(link).unwrap();
        let lease = fixture.apply().unwrap();
        assert!(fixture.target.join("data/content.json").is_file());
        drop(lease);
    }

    #[cfg(unix)]
    #[test]
    fn existing_server_flock_blocks_a_new_root_lease() {
        use std::os::fd::AsRawFd;
        let fixture = Fixture::new();
        let old_server = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fixture.source.join("lock.pid"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(old_server.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert_eq!(
            DataRootLease::acquire(&fixture.source).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(old_server);
        assert!(DataRootLease::acquire(&fixture.source).is_ok());
    }

    #[test]
    fn crash_recovery_never_selects_a_partial_snapshot() {
        for crash in [
            "stage-created",
            "private",
            "data",
            "snapshot-ready",
            "promoted-private",
            "promoted-data",
            "before-config",
            "after-config",
        ] {
            let fixture = Fixture::new();
            fixture.queue().unwrap();
            let result = prepare_with_hook(&fixture.conf, &fixture.default, |stage| {
                if stage == crash {
                    Err(io::Error::other(format!("fixture crash at {stage}")))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err(), "{crash}");
            assert_eq!(
                fixture.configured(),
                if crash == "after-config" {
                    fixture.target.clone()
                } else {
                    fixture.source.clone()
                }
            );
            std::fs::write(
                fixture.source.join("private/config.json"),
                b"changed before retry",
            )
            .unwrap();
            let lease = fixture.apply().unwrap();
            let expected: &[u8] = if crash == "after-config" {
                b"before queue"
            } else {
                b"changed before retry"
            };
            assert_eq!(
                std::fs::read(fixture.target.join("private/config.json")).unwrap(),
                expected,
                "{crash}"
            );
            assert_eq!(
                std::fs::read(fixture.target.join("data/content.json")).unwrap(),
                b"public content"
            );
            assert_eq!(pending_target(&fixture.conf).unwrap(), None);
            assert!(fixture.source.join("private/users.json").is_file());
            drop(lease);
        }
    }

    #[test]
    fn destination_entries_are_never_overwritten_or_recognized_as_partial_profiles() {
        for component in ["private", "data"] {
            let fixture = Fixture::new();
            std::fs::create_dir_all(fixture.target.join(component)).unwrap();
            let sentinel = fixture.target.join(component).join("sentinel");
            std::fs::write(&sentinel, b"keep me").unwrap();
            if component == "private" {
                std::fs::write(
                    fixture.target.join("private/users.json"),
                    b"legacy partial identity",
                )
                .unwrap();
            }
            assert!(fixture.queue().is_err());
            assert_eq!(std::fs::read(sentinel).unwrap(), b"keep me");
            assert_eq!(fixture.configured(), fixture.source);
        }
    }

    #[test]
    fn existing_profile_switch_and_queue_cancellation_preserve_both_identities() {
        let fixture = Fixture::new();
        fixture.queue().unwrap();
        queue_request(
            &fixture.conf,
            &fixture.source,
            &fixture.source,
            &fixture.default,
        )
        .unwrap();
        assert_eq!(pending_target(&fixture.conf).unwrap(), None);
        std::fs::create_dir(fixture.target.join("private")).unwrap();
        std::fs::create_dir(fixture.target.join("data")).unwrap();
        std::fs::write(
            fixture.target.join("private/users.json"),
            b"other public test identity",
        )
        .unwrap();
        fixture.queue().unwrap();
        let lease = fixture.apply().unwrap();
        assert_eq!(
            std::fs::read(fixture.target.join("private/users.json")).unwrap(),
            b"other public test identity"
        );
        assert_eq!(
            std::fs::read(fixture.source.join("private/users.json")).unwrap(),
            b"public test identity"
        );
        assert!(!fixture.target.join("data/content.json").exists());
        drop(lease);
    }

    #[test]
    fn active_destination_and_changed_config_are_rejected() {
        let fixture = Fixture::new();
        let target = DataRootLease::acquire(&fixture.target).unwrap();
        assert_eq!(
            fixture.queue().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(target);
        fixture.queue().unwrap();
        let unrelated = fixture.default.join("unrelated");
        crate::paths::write_conf_data_dir(&fixture.conf, Some(&unrelated)).unwrap();
        assert!(fixture.apply().is_err());
        assert!(!fixture.target.join("private").exists());
        assert_eq!(fixture.configured(), unrelated);
    }

    #[test]
    fn unavailable_or_replaced_target_stays_visible_but_cannot_be_applied() {
        for replace in [false, true] {
            let fixture = Fixture::new();
            fixture.queue().unwrap();
            // Keep the original inode alive, making replacement deterministic
            // even on filesystems which immediately reuse deleted inode IDs.
            std::fs::rename(&fixture.target, fixture.target.with_extension("removed")).unwrap();
            if replace {
                std::fs::create_dir(&fixture.target).unwrap();
                std::fs::write(fixture.target.join("sentinel"), b"unrelated target").unwrap();
            }
            assert_eq!(
                pending_target(&fixture.conf).unwrap(),
                Some(fixture.target.clone())
            );
            assert!(fixture.apply().is_err());
            assert_eq!(fixture.configured(), fixture.source);
            if replace {
                assert_eq!(
                    std::fs::read(fixture.target.join("sentinel")).unwrap(),
                    b"unrelated target"
                );
            }
        }
    }

    #[test]
    fn pending_display_rejects_nonabsolute_traversal_and_control_paths() {
        for target in [
            PathBuf::from("relative"),
            PathBuf::from("/safe/../outside"),
            PathBuf::from("/bad\nsetting=value"),
        ] {
            let fixture = Fixture::new();
            fixture.queue().unwrap();
            let directory = Directory::open(&fixture.default, false).unwrap();
            let mut plan = read_plan(&directory).unwrap().unwrap();
            plan.target = target;
            save_plan(&directory, &plan).unwrap();
            assert!(pending_target(&fixture.conf).is_err());
            assert!(fixture.apply().is_err());
            assert_eq!(fixture.configured(), fixture.source);
        }
    }

    #[test]
    fn a_substituted_promoted_directory_is_never_cleaned_up() {
        let fixture = Fixture::new();
        fixture.queue().unwrap();
        assert!(prepare_with_hook(&fixture.conf, &fixture.default, |stage| {
            if stage == "promoted-private" {
                Err(io::Error::other("fixture crash"))
            } else {
                Ok(())
            }
        })
        .is_err());
        std::fs::rename(
            fixture.target.join("private"),
            fixture.target.join("saved-copy"),
        )
        .unwrap();
        std::fs::create_dir(fixture.target.join("private")).unwrap();
        let sentinel = fixture.target.join("private/sentinel");
        std::fs::write(&sentinel, b"unrelated replacement").unwrap();
        assert!(fixture.apply().is_err());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"unrelated replacement");
        assert_eq!(fixture.configured(), fixture.source);
    }

    #[test]
    fn trusted_relative_roots_remain_supported_but_queue_inputs_stay_absolute() {
        let temp = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let relative = temp
            .path()
            .strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .join("child");
        let lease = DataRootLease::acquire(&relative).unwrap();
        assert!(lease.root().is_absolute());
        drop(lease);
        let parent_path = temp.path().join("child/../second");
        let lease = DataRootLease::acquire(&parent_path).unwrap();
        assert_eq!(
            lease.root(),
            temp.path().canonicalize().unwrap().join("second")
        );
        drop(lease);
        let fixture = Fixture::new();
        assert!(queue_request(
            &fixture.conf,
            &fixture.source,
            Path::new("relative"),
            &fixture.default
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn owned_roots_below_search_only_ancestors_can_be_leased_and_created() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let restricted = temp.path().canonicalize().unwrap().join("search-only");
        let owned = restricted.join("owned");
        std::fs::create_dir_all(&owned).unwrap();
        std::fs::set_permissions(&restricted, std::fs::Permissions::from_mode(0o111)).unwrap();
        // Restore permissions even if an assertion below fails so the fixture
        // cannot leave an inaccessible temporary tree behind.
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            }
        }
        let _restore = Restore(restricted);
        for root in [owned.clone(), owned.join("new/nested")] {
            let lease = DataRootLease::acquire(&root).unwrap();
            assert_eq!(lease.root(), root);
            assert_eq!(
                DataRootLease::acquire(&root).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            std::fs::write(root.join("sentinel"), b"owned directory is usable").unwrap();
            lease.directory.assert_bound().unwrap();
            drop(lease);
            assert_eq!(
                std::fs::read(root.join("sentinel")).unwrap(),
                b"owned directory is usable"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn search_only_traversal_does_not_follow_ancestor_links() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let outside = base.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"outside unchanged").unwrap();
        symlink(&outside, base.join("link")).unwrap();
        // Directory::open consumes an already normalized bound path. It must
        // reject a replacement link even though the explicit operator root
        // normalizer intentionally accepts existing aliases before binding.
        assert!(Directory::open(&base.join("link/new"), true).is_err());
        assert!(!outside.join("new").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"outside unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn links_special_files_and_lockfile_substitution_leave_outside_sentinels_untouched() {
        use std::os::unix::fs::symlink;
        for attack in ["source-link", "destination-link", "lock-link", "fifo"] {
            let fixture = Fixture::new();
            let outside = fixture.default.join("outside");
            std::fs::write(&outside, b"outside sentinel").unwrap();
            match attack {
                "source-link" => symlink(&outside, fixture.source.join("data/evil")).unwrap(),
                "destination-link" => {
                    std::fs::create_dir_all(&fixture.target).unwrap();
                    symlink(&fixture.default, fixture.target.join("private")).unwrap();
                }
                "lock-link" => {
                    std::fs::create_dir_all(&fixture.target).unwrap();
                    symlink(&outside, fixture.target.join(DATA_LOCK)).unwrap();
                }
                "fifo" => {
                    use std::os::unix::ffi::OsStrExt;
                    let path = std::ffi::CString::new(
                        fixture.source.join("data/pipe").as_os_str().as_bytes(),
                    )
                    .unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            if fixture.queue().is_ok() {
                assert!(fixture.apply().is_err(), "{attack}");
            }
            assert_eq!(fixture.configured(), fixture.source);
            assert_eq!(
                std::fs::read(outside).unwrap(),
                b"outside sentinel",
                "{attack}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn renamed_root_or_control_parent_is_rejected_before_config_commit() {
        for which in ["source", "target", "control"] {
            let fixture = Fixture::new();
            fixture.queue().unwrap();
            let root = match which {
                "source" => &fixture.source,
                "target" => &fixture.target,
                _ => &fixture.default,
            };
            let moved = root.with_extension("moved");
            let result = prepare_with_hook(&fixture.conf, &fixture.default, |stage| {
                if stage == "before-config" {
                    std::fs::rename(root, &moved)?;
                    std::fs::create_dir(root)?;
                    std::fs::write(root.join("sentinel"), b"replacement untouched")?;
                }
                Ok(())
            });
            assert!(result.is_err(), "{which}");
            assert_eq!(
                std::fs::read(root.join("sentinel")).unwrap(),
                b"replacement untouched"
            );
            let conf = if which == "control" {
                moved.join("epixnet.conf")
            } else {
                fixture.conf.clone()
            };
            assert_eq!(
                crate::paths::read_conf_data_dir(&conf),
                Some(fixture.source.clone())
            );
            assert!(!root.join("private/users.json").exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn strict_reader_rejects_live_writer_and_offline_copy_succeeds_after_close() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        let fixture = Fixture::new();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(fixture.source.join("data/content.json"))
            .unwrap();
        assert_eq!(
            epix_fs::open_regular_file_beneath(&fixture.source, Path::new("data/content.json"))
                .unwrap_err()
                .raw_os_error(),
            Some(32)
        );
        fixture.queue().unwrap();
        assert!(fixture.apply().is_err());
        assert_eq!(fixture.configured(), fixture.source);
        drop(writer);
        let lease = fixture.apply().unwrap();
        assert_eq!(
            std::fs::read(fixture.target.join("data/content.json")).unwrap(),
            b"public content"
        );
        drop(lease);
    }

    #[test]
    fn wal_writer_fixture() {
        let Some(path) = std::env::var_os("EPIX_RELOCATION_WAL_FIXTURE") else {
            return;
        };
        let connection = rusqlite::Connection::open(path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES ('committed before abrupt exit');").unwrap();
        // Simulate the node's process::exit shutdown: no SQLite close/checkpoint.
        std::process::exit(0);
    }

    #[test]
    fn offline_copy_retains_committed_wal_rows_after_abrupt_exit() {
        let fixture = Fixture::new();
        let database = fixture.source.join("private/chart.db");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "data_relocation::tests::wal_writer_fixture",
                "--nocapture",
            ])
            .env("EPIX_RELOCATION_WAL_FIXTURE", &database)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(fixture.source.join("private/chart.db-wal").is_file());
        fixture.queue().unwrap();
        let lease = fixture.apply().unwrap();
        let connection =
            rusqlite::Connection::open(fixture.target.join("private/chart.db")).unwrap();
        assert_eq!(
            connection
                .query_row("SELECT value FROM fixture", [], |row| row
                    .get::<_, String>(0))
                .unwrap(),
            "committed before abrupt exit"
        );
        assert_eq!(
            connection
                .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        drop(connection);
        drop(lease);
    }
}
