//! Durable direct-child admission. This directory is host-private and never
//! passed to a worker. A lease descriptor is concurrency control, not proof of
//! process death. An owned terminal wait4 reap completes an invocation. A new
//! kernel boot can clear process ownership without clearing uncertain effects.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use evx_api::Denied;
use rustix::fd::OwnedFd;
use rustix::fs::{
    flock, fstat, fsync, mkdirat, openat, renameat, FileType, FlockOperation, Mode, OFlags,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::boot_session::BootSession;
use crate::process::Role;

const BINDING: &str = "binding.json";
const JOURNAL: &str = "lifecycle.json";
const LOCK: &str = "lifecycle.lock";
const PENDING: &str = "lifecycle.pending";
const MAX_METADATA: usize = 64 * 1024;
const MAX_ACTIVE: usize = 128;

fn denied() -> Denied {
    Denied::new("direct lifecycle state unavailable")
}
fn quarantine() -> Denied {
    Denied::Quarantined("direct lifecycle has unresolved worker ownership".into())
}
fn reboot_required() -> Denied {
    Denied::Quarantined("execution disabled: restart the operating system, then reopen EpixNet to recover process ownership; workspace effects still require reconciliation".into())
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    path: String,
    root: [u64; 2],
    lock: [u64; 2],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Active {
    xite: String,
    role: String,
    invocation: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    #[serde(default)]
    boot: Option<BootSession>,
    #[serde(default)]
    reboot_required: bool,
    session: u64,
    next: u64,
    active: Vec<Active>,
}

/// Retain one context per host session. Opening a new session is possible only
/// with no unresolved children in the current kernel boot; it invalidates every
/// older handle. Recovery across a verified boot change preserves file and job
/// uncertainty. No API guesses death from a PID, lock or elapsed time.
#[derive(Debug)]
pub struct DirectLifecycle {
    path: PathBuf,
    binding: Binding,
    session: u64,
    boot: BootSession,
    gate: Mutex<()>,
}

/// One host-selected xite scope. This is never supplied by a guest message.
#[derive(Clone, Debug)]
pub struct DirectScope {
    context: Arc<DirectLifecycle>,
    xite: String,
}

impl DirectLifecycle {
    /// Provision only an independently established fresh host state directory.
    /// The dedicated directory must not exist, including after partial setup.
    /// A missing journal under a legacy state root is not evidence of freshness.
    pub fn provision_fresh(path: &Path) -> Result<Arc<Self>, Denied> {
        let boot = BootSession::current()?;
        Self::provision(path, boot.clone(), false)?;
        Self::open_on_boot(path, boot)
    }

    /// Establish a reboot barrier for legacy state without process authority.
    /// This cannot authorize execution in the current boot. Existing metadata
    /// is never replaced, and user workspaces/grants are not modified.
    pub fn prepare_legacy(path: &Path) -> Result<(), Denied> {
        let path = canonical_path(path)?;
        let parent = evx_workspace::open_root(path.parent().ok_or_else(denied)?)?;
        let info = fstat(&parent).map_err(|_| denied())?;
        if info.st_uid != rustix::process::geteuid().as_raw() {
            return Err(denied());
        }
        // Earlier state roots used the default directory mode. Tighten only
        // this already-open host-owned directory, never a followed symlink.
        rustix::fs::fchmod(&parent, Mode::RWXU).map_err(|_| denied())?;
        fsync(&parent).map_err(|_| denied())?;
        Self::provision(&path, BootSession::current()?, true)
    }

    fn provision(path: &Path, boot: BootSession, reboot_required: bool) -> Result<(), Denied> {
        let path = canonical_path(path)?;
        let parent = evx_workspace::open_root(path.parent().ok_or_else(denied)?)?;
        directory_identity(&parent)?;
        mkdirat(&parent, path.file_name().ok_or_else(denied)?, Mode::RWXU).map_err(|_| denied())?;
        let root = evx_workspace::open_root(&path)?;
        let identity = directory_identity(&root)?;
        create(&root, LOCK, &[])?;
        let lock = safe_open(&root, LOCK, true)?;
        let binding = Binding {
            version: 1,
            path: hex::encode(Sha256::digest(path.as_os_str().as_bytes())),
            root: identity,
            lock: identity_of(&lock)?,
        };
        create(
            &root,
            BINDING,
            &serde_json::to_vec(&binding).map_err(|_| denied())?,
        )?;
        create(
            &root,
            JOURNAL,
            &serde_json::to_vec(&Journal {
                version: 2,
                boot: Some(boot),
                reboot_required,
                session: 0,
                next: 0,
                active: Vec::new(),
            })
            .map_err(|_| denied())?,
        )?;
        fsync(&root).map_err(|_| denied())?;
        fsync(&parent).map_err(|_| denied())?;
        Ok(())
    }

    /// Reopen existing state without repairing or recreating any missing file.
    /// Possible invocations from an earlier host session in this kernel boot
    /// prevent admission. A verified new boot clears only process ownership.
    pub fn open(path: &Path) -> Result<Arc<Self>, Denied> {
        Self::open_on_boot(path, BootSession::current()?)
    }

    fn open_on_boot(path: &Path, boot: BootSession) -> Result<Arc<Self>, Denied> {
        let path = canonical_path(path)?;
        let root = evx_workspace::open_root(&path)?;
        let identity = directory_identity(&root)?;
        let binding: Binding = read(&root, BINDING)?;
        if binding.version != 1
            || binding.root != identity
            || binding.path != hex::encode(Sha256::digest(path.as_os_str().as_bytes()))
        {
            return Err(denied());
        }
        let mut context = Self {
            path,
            binding,
            session: 0,
            boot,
            gate: Mutex::new(()),
        };
        context.session = context.with_journal(|root, journal| {
            if journal.version == 1 {
                // Old journals did not record a kernel boot. Never guess the
                // age of an unresolved child; first persist a reboot barrier.
                journal.version = 2;
                journal.boot = Some(context.boot.clone());
                journal.reboot_required = !journal.active.is_empty();
                if journal.reboot_required {
                    persist(root, journal)?;
                    return Err(reboot_required());
                }
            } else if journal.boot.as_ref() != Some(&context.boot) {
                // A different kernel boot proves all prior direct children
                // stopped. File provenance and job uncertainty stay untouched.
                journal.active.clear();
                journal.reboot_required = false;
                journal.boot = Some(context.boot.clone());
            }
            if journal.reboot_required || !journal.active.is_empty() {
                return Err(reboot_required());
            }
            journal.session = advance(journal.session)?;
            persist(root, journal)?;
            Ok(journal.session)
        })?;
        Ok(Arc::new(context))
    }

    /// Read-only admission/status validation. Active children of this retained
    /// session are allowed; another session or missing authority is refused.
    pub fn validate(&self) -> Result<(), Denied> {
        self.with_journal(|_, journal| {
            if self.matches_session(journal) {
                Ok(())
            } else {
                Err(quarantine())
            }
        })
    }

    fn matches_session(&self, journal: &Journal) -> bool {
        journal.version == 2
            && journal.boot.as_ref() == Some(&self.boot)
            && !journal.reboot_required
            && journal.session == self.session
    }

    pub fn scope(self: &Arc<Self>, xite: &str) -> Result<DirectScope, Denied> {
        evx_api::validate_identifier(xite)?;
        self.validate()?;
        Ok(DirectScope {
            context: self.clone(),
            xite: xite.into(),
        })
    }

    fn with_journal<T>(
        &self,
        action: impl FnOnce(&OwnedFd, &mut Journal) -> Result<T, Denied>,
    ) -> Result<T, Denied> {
        let _gate = self.gate.lock().map_err(|_| quarantine())?;
        let root = evx_workspace::open_root(&self.path)?;
        if directory_identity(&root)? != self.binding.root
            || read::<Binding>(&root, BINDING)? != self.binding
        {
            return Err(denied());
        }
        let lock = safe_open(&root, LOCK, true)?;
        if identity_of(&lock)? != self.binding.lock
            || fstat(&lock).map_err(|_| denied())?.st_size != 0
        {
            return Err(denied());
        }
        // Another host thread may fork while a CLOEXEC journal lock is open.
        // Its child keeps that file description until exec. Retry this short
        // lock window, but never interpret acquisition as proof of child death.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::WOULDBLOCK) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    return Err(Denied::new("direct lifecycle busy"))
                }
                Err(_) => return Err(denied()),
            }
        }
        match openat(
            &root,
            PENDING,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err(denied()),
        }
        let mut journal: Journal = read(&root, JOURNAL)?;
        validate_journal(&journal)?;
        // A visible replacement after a failed sync is not durable authority
        // until both the file and its containing directory are synced again.
        fsync(safe_open(&root, JOURNAL, false)?).map_err(|_| denied())?;
        fsync(&root).map_err(|_| denied())?;
        action(&root, &mut journal)
    }
}

impl DirectScope {
    pub fn xite(&self) -> &str {
        &self.xite
    }
    pub fn validate(&self) -> Result<(), Denied> {
        self.context.validate()
    }

    pub(crate) fn begin(&self, role: Role) -> Result<DirectInvocation, Denied> {
        let invocation = self.context.with_journal(|root, journal| {
            if !self.context.matches_session(journal) {
                return Err(quarantine());
            }
            let own: Vec<_> = journal
                .active
                .iter()
                .filter(|entry| entry.xite == self.xite)
                .collect();
            if !(own.is_empty() || role == Role::File && own.len() == 1 && own[0].role == "guest") {
                return Err(quarantine());
            }
            if journal.active.len() >= MAX_ACTIVE {
                return Err(Denied::new("direct lifecycle active limit"));
            }
            journal.next = advance(journal.next)?;
            journal.active.push(Active {
                xite: self.xite.clone(),
                role: role.name().into(),
                invocation: journal.next,
            });
            persist(root, journal)?;
            Ok(journal.next)
        })?;
        Ok(DirectInvocation {
            scope: self.clone(),
            role,
            invocation,
            complete: false,
        })
    }
}

/// Drop intentionally leaves the record active. Only the trusted process
/// owner may call complete after wait4 returned this exact child PID.
pub(crate) struct DirectInvocation {
    scope: DirectScope,
    role: Role,
    invocation: u64,
    complete: bool,
}
impl DirectInvocation {
    pub(crate) fn complete(&mut self) -> Result<(), Denied> {
        if self.complete {
            return Ok(());
        }
        self.scope.context.with_journal(|root, journal| {
            if !self.scope.context.matches_session(journal) {
                return Err(quarantine());
            }
            let index = journal
                .active
                .iter()
                .position(|entry| {
                    entry.xite == self.scope.xite
                        && entry.role == self.role.name()
                        && entry.invocation == self.invocation
                })
                .ok_or_else(quarantine)?;
            journal.active.remove(index);
            persist(root, journal)
        })?;
        self.complete = true;
        Ok(())
    }
}

fn advance(value: u64) -> Result<u64, Denied> {
    value
        .checked_add(1)
        .filter(|next| *next <= i64::MAX as u64)
        .ok_or_else(denied)
}
fn validate_journal(journal: &Journal) -> Result<(), Denied> {
    if !matches!(journal.version, 1 | 2)
        || (journal.version == 1 && (journal.boot.is_some() || journal.reboot_required))
        || (journal.version == 2
            && journal
                .boot
                .as_ref()
                .is_none_or(|boot| boot.validate().is_err()))
        || journal.session > i64::MAX as u64
        || journal.next > i64::MAX as u64
        || journal.active.len() > MAX_ACTIVE
    {
        return Err(denied());
    }
    let mut ids = BTreeSet::new();
    let mut roles = BTreeSet::new();
    for entry in &journal.active {
        evx_api::validate_identifier(&entry.xite).map_err(|_| denied())?;
        if !matches!(entry.role.as_str(), "guest" | "compiler" | "file")
            || entry.invocation == 0
            || entry.invocation > journal.next
            || !ids.insert(entry.invocation)
            || !roles.insert((&entry.xite, &entry.role))
        {
            return Err(denied());
        }
    }
    Ok(())
}
fn canonical_path(path: &Path) -> Result<PathBuf, Denied> {
    let name = path.file_name().ok_or_else(denied)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(std::fs::canonicalize(parent)
        .map_err(|_| denied())?
        .join(name))
}
#[allow(clippy::unnecessary_cast)]
fn identity_of(fd: &OwnedFd) -> Result<[u64; 2], Denied> {
    let info = fstat(fd).map_err(|_| denied())?;
    Ok([info.st_dev as u64, info.st_ino as u64])
}
fn directory_identity(fd: &OwnedFd) -> Result<[u64; 2], Denied> {
    let info = fstat(fd).map_err(|_| denied())?;
    if FileType::from_raw_mode(info.st_mode as rustix::fs::RawMode) != FileType::Directory
        || info.st_uid != rustix::process::geteuid().as_raw()
        || info.st_mode & 0o7777 != 0o700
    {
        return Err(denied());
    }
    identity_of(fd)
}
fn safe_open(root: &OwnedFd, name: &str, writable: bool) -> Result<OwnedFd, Denied> {
    let fd = openat(
        root,
        name,
        (if writable {
            OFlags::RDWR
        } else {
            OFlags::RDONLY
        }) | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| denied())?;
    let info = fstat(&fd).map_err(|_| denied())?;
    if FileType::from_raw_mode(info.st_mode as rustix::fs::RawMode) != FileType::RegularFile
        || info.st_uid != rustix::process::geteuid().as_raw()
        || info.st_mode & 0o7777 != 0o600
        || info.st_nlink != 1
        || info.st_size < 0
        || info.st_size as u64 > MAX_METADATA as u64
    {
        return Err(denied());
    }
    Ok(fd)
}
fn read<T: serde::de::DeserializeOwned>(root: &OwnedFd, name: &str) -> Result<T, Denied> {
    let mut bytes = Vec::new();
    std::fs::File::from(safe_open(root, name, false)?)
        .take(MAX_METADATA as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| denied())?;
    if bytes.len() > MAX_METADATA {
        return Err(denied());
    }
    evx_api::strict::parse_typed(&bytes).map_err(|_| denied())
}
fn create(root: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), Denied> {
    let fd = openat(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| denied())?;
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).map_err(|_| denied())?;
    file.sync_all().map_err(|_| denied())
}
#[cfg(test)]
thread_local! { static FAIL_PERSIST: std::cell::Cell<u8> = const { std::cell::Cell::new(0) }; }
fn persist(root: &OwnedFd, journal: &Journal) -> Result<(), Denied> {
    let bytes = serde_json::to_vec(journal).map_err(|_| denied())?;
    if bytes.len() > MAX_METADATA {
        return Err(denied());
    }
    create(root, PENDING, &bytes)?;
    #[cfg(test)]
    if FAIL_PERSIST.with(|fail| {
        if fail.get() == 1 {
            fail.set(0);
            true
        } else {
            false
        }
    }) {
        return Err(denied());
    }
    renameat(root, PENDING, root, JOURNAL).map_err(|_| denied())?;
    #[cfg(test)]
    if FAIL_PERSIST.with(|fail| {
        if fail.get() == 2 {
            fail.set(0);
            true
        } else {
            false
        }
    }) {
        return Err(denied());
    }
    fsync(root).map_err(|_| denied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, PathBuf, Arc<DirectLifecycle>) {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.path().join("lifecycle");
        let context = DirectLifecycle::provision_fresh(&path).unwrap();
        (parent, path, context)
    }

    #[test]
    fn transient_inherited_journal_lock_is_bounded_and_retried() {
        let (_parent, path, context) = fixture();
        let root = evx_workspace::open_root(&path).unwrap();
        let lock = safe_open(&root, LOCK, true).unwrap();
        flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            drop(lock);
        });
        let result = context.validate();
        release.join().unwrap();
        result.unwrap();
    }

    #[test]
    fn provisioning_is_explicit_and_never_repairs_existing_state() {
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("lifecycle");
        assert!(DirectLifecycle::open(&path).is_err());
        std::fs::create_dir(&path).unwrap();
        assert!(DirectLifecycle::provision_fresh(&path).is_err());
        assert!(std::fs::read_dir(&path).unwrap().next().is_none());
    }

    #[test]
    fn positive_completion_allows_reopen_and_invalidates_old_sessions() {
        let (_parent, path, context) = fixture();
        let scope = context.scope("game-a").unwrap();
        let mut token = scope.begin(Role::Compiler).unwrap();
        token.complete().unwrap();
        token.complete().unwrap();
        let reopened = DirectLifecycle::open(&path).unwrap();
        assert!(context.validate().is_err());
        assert!(scope.begin(Role::Guest).is_err());
        reopened.validate().unwrap();
    }

    #[test]
    fn dropped_invocation_is_durable_quarantine_for_every_role() {
        for role in [Role::Guest, Role::File, Role::Compiler] {
            let (_parent, path, context) = fixture();
            drop(context.scope("game-a").unwrap().begin(role).unwrap());
            assert!(matches!(
                DirectLifecycle::open(&path),
                Err(Denied::Quarantined(_))
            ));
        }
    }

    #[test]
    fn roles_are_bound_to_scope_and_only_guest_helper_overlap() {
        let (_parent, path, context) = fixture();
        let a = context.scope("game-a").unwrap();
        let b = context.scope("game-b").unwrap();
        assert_eq!(a.xite(), "game-a");
        let mut guest = a.begin(Role::Guest).unwrap();
        assert!(a.begin(Role::Compiler).is_err());
        let mut file = a.begin(Role::File).unwrap();
        assert!(a.begin(Role::File).is_err());
        let mut other = b.begin(Role::Compiler).unwrap();
        context.validate().unwrap();
        file.complete().unwrap();
        guest.complete().unwrap();
        other.complete().unwrap();
        DirectLifecycle::open(&path).unwrap();
    }

    #[test]
    fn lost_or_replaced_files_never_reinitialize() {
        for name in [BINDING, JOURNAL, LOCK] {
            let (_parent, path, context) = fixture();
            std::fs::remove_file(path.join(name)).unwrap();
            assert!(context.validate().is_err());
            assert!(DirectLifecycle::open(&path).is_err());
            assert!(!path.join(name).exists());
        }
        let (_parent, path, context) = fixture();
        std::fs::remove_file(path.join(LOCK)).unwrap();
        std::fs::write(path.join(LOCK), "").unwrap();
        std::fs::set_permissions(path.join(LOCK), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(context.validate().is_err());
    }

    #[test]
    fn metadata_links_modes_and_namespace_replacement_are_rejected() {
        let (parent, path, context) = fixture();
        std::fs::hard_link(path.join(JOURNAL), parent.path().join("linked")).unwrap();
        assert!(context.validate().is_err());
        std::fs::remove_file(parent.path().join("linked")).unwrap();
        std::fs::set_permissions(path.join(JOURNAL), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(context.validate().is_err());
        std::fs::set_permissions(path.join(JOURNAL), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let moved = parent.path().join("old");
        std::fs::rename(&path, &moved).unwrap();
        symlink(&moved, &path).unwrap();
        assert!(context.validate().is_err());
        assert!(DirectLifecycle::open(&path).is_err());
    }

    #[test]
    fn bounded_strict_metadata_rejects_corruption() {
        for value in [b"{\"version\":1,\"version\":1}".as_slice(), b"{}", b"[]"] {
            let (_parent, path, context) = fixture();
            std::fs::write(path.join(JOURNAL), value).unwrap();
            assert!(context.validate().is_err());
        }
        let (_parent, path, context) = fixture();
        std::fs::write(path.join(JOURNAL), vec![b' '; MAX_METADATA + 1]).unwrap();
        assert!(context.validate().is_err());
    }

    #[test]
    fn failed_persistence_never_grants_an_invocation() {
        for stage in [1, 2] {
            let (_parent, path, context) = fixture();
            let scope = context.scope("game-a").unwrap();
            FAIL_PERSIST.with(|fail| fail.set(stage));
            assert!(scope.begin(Role::Guest).is_err());
            assert!(DirectLifecycle::open(&path).is_err());
            assert!(scope.begin(Role::Guest).is_err());
        }
    }

    #[test]
    fn stale_completion_cannot_remove_another_token() {
        let (_parent, _path, context) = fixture();
        let mut token = context.scope("game-a").unwrap().begin(Role::Guest).unwrap();
        token.invocation += 1;
        assert!(token.complete().is_err());
        assert!(context.scope("game-a").unwrap().begin(Role::Guest).is_err());
    }

    #[test]
    fn concurrent_xites_share_one_serialized_durable_journal() {
        let (_parent, path, context) = fixture();
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let context = context.clone();
                std::thread::spawn(move || {
                    let mut token = context
                        .scope(&format!("game-{n}"))
                        .unwrap()
                        .begin(Role::Compiler)
                        .unwrap();
                    token.complete().unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        DirectLifecycle::open(&path).unwrap();
    }

    #[test]
    fn legacy_barrier_requires_a_different_boot_and_preserves_neighbor_data() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = parent.path().join("game-data");
        std::fs::write(&marker, b"keep score").unwrap();
        let path = parent.path().join("lifecycle");
        let first = BootSession::fixture(1);
        let second = BootSession::fixture(2);
        DirectLifecycle::provision(&path, first.clone(), true).unwrap();
        assert!(DirectLifecycle::open_on_boot(&path, first.clone()).is_err());
        assert!(DirectLifecycle::open_on_boot(&path, first).is_err());
        assert_eq!(std::fs::read(&marker).unwrap(), b"keep score");
        let context = DirectLifecycle::open_on_boot(&path, second.clone()).unwrap();
        context.validate().unwrap();
        let mut invocation = context.scope("game").unwrap().begin(Role::Guest).unwrap();
        invocation.complete().unwrap();
        DirectLifecycle::open_on_boot(&path, second).unwrap();
        assert_eq!(std::fs::read(&marker).unwrap(), b"keep score");
    }

    #[test]
    fn a_new_kernel_boot_clears_process_uncertainty_but_not_external_effects() {
        let parent = tempfile::tempdir().unwrap();
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.path().join("lifecycle");
        let first = BootSession::fixture(1);
        DirectLifecycle::provision(&path, first.clone(), false).unwrap();
        let context = DirectLifecycle::open_on_boot(&path, first.clone()).unwrap();
        let scope = context.scope("game").unwrap();
        let mut old = scope.begin(Role::File).unwrap();
        let effects = parent.path().join("pending-provenance");
        std::fs::write(&effects, b"uncertain effect").unwrap();
        assert!(DirectLifecycle::open_on_boot(&path, first).is_err());
        let reopened = DirectLifecycle::open_on_boot(&path, BootSession::fixture(2)).unwrap();
        reopened.validate().unwrap();
        assert!(old.complete().is_err());
        assert!(scope.begin(Role::Guest).is_err());
        assert_eq!(std::fs::read(effects).unwrap(), b"uncertain effect");
    }

    #[test]
    fn version_one_active_records_need_a_newly_recorded_reboot_barrier() {
        for active in [false, true] {
            let (_parent, path, _context) = fixture();
            let legacy = serde_json::json!({"version":1,"session":4,"next":8,
                "active": if active { vec![serde_json::json!({"xite":"game","role":"file","invocation":8})] } else { vec![] }});
            std::fs::write(path.join(JOURNAL), serde_json::to_vec(&legacy).unwrap()).unwrap();
            let boot = BootSession::fixture(1);
            let opened = DirectLifecycle::open_on_boot(&path, boot.clone());
            assert_eq!(opened.is_err(), active);
            if active {
                assert!(DirectLifecycle::open_on_boot(&path, boot).is_err());
            }
            let upgraded = DirectLifecycle::open_on_boot(&path, BootSession::fixture(2)).unwrap();
            upgraded.validate().unwrap();
            let root = evx_workspace::open_root(&path).unwrap();
            let journal: Journal = read(&root, JOURNAL).unwrap();
            assert_eq!(journal.version, 2);
            assert_eq!(journal.next, 8);
            assert!(journal.session > 4);
        }
    }

    #[test]
    fn changed_boot_never_repairs_corrupt_metadata_or_interrupted_persistence() {
        let (_parent, path, context) = fixture();
        let scope = context.scope("game").unwrap();
        FAIL_PERSIST.with(|fail| fail.set(1));
        assert!(scope.begin(Role::Guest).is_err());
        assert!(DirectLifecycle::open_on_boot(&path, BootSession::fixture(2)).is_err());
        assert!(path.join(PENDING).exists());
        let (_parent, path, _context) = fixture();
        std::fs::write(path.join(JOURNAL), b"bad metadata").unwrap();
        assert!(DirectLifecycle::open_on_boot(&path, BootSession::fixture(2)).is_err());
        assert_eq!(std::fs::read(path.join(JOURNAL)).unwrap(), b"bad metadata");
    }
}
