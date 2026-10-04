//! Host-only control and lifecycle state for one permanently assigned Apple slot.
//! No path in this module is passed to a service or native helper.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use evx_api::Denied;
use rustix::fd::OwnedFd;
use rustix::fs::{
    flock, fstat, fsync, mkdirat, openat, renameat, unlinkat, AtFlags, FileType, FlockOperation,
    Mode, OFlags,
};
use serde::{Deserialize, Serialize};

use crate::apple_slots::AppleSlotAssignment;
use crate::process::Role;

const BINDING: &str = "binding.json";
const JOURNAL: &str = "lifecycle.json";
const LOCK: &str = "lifecycle.lock";
const PENDING: &str = "lifecycle.pending";
const MAX_METADATA: usize = 8192;

fn denied() -> Denied {
    Denied::new("Apple workspace control unavailable")
}
fn quarantine() -> Denied {
    Denied::Quarantined("Apple slot has an unresolved worker lifecycle".into())
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    xite: String,
    slot: String,
    guest: String,
    compiler: String,
    file: String,
    root: [u64; 2],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    session: u64,
    next: u64,
    active: BTreeMap<String, u64>,
}

/// One host session for a permanent service slot. Clones of the Arc share a
/// session. Reopening an active session is quarantined, never recovered by
/// acquiring a filesystem lock or reconciling file contents.
#[derive(Debug)]
pub struct AppleWorkspace {
    assignment: AppleSlotAssignment,
    path: PathBuf,
    binding: Binding,
    session: u64,
}

impl AppleWorkspace {
    /// Create only the first host control record for an already assigned slot,
    /// or reopen its existing record. This never provisions service containers.
    /// Lost or partially initialized controls are not reconstructed.
    pub fn open(assignment: AppleSlotAssignment) -> Result<Arc<Self>, Denied> {
        let (path, binding) = assignment.with_workspace(|registry, expected| {
            let root = evx_workspace::open_root(registry)?;
            match mkdirat(&root, "workspaces", Mode::RWXU) {
                Ok(()) => fsync(&root).map_err(|_| denied())?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(denied()),
            }
            let controls = directory_at(&root, "workspaces")?;
            let slot = &assignment.services().slot;
            if expected.is_none() {
                // Existing-but-unregistered controls may be an interrupted
                // initialization. They do not prove a fresh lease namespace.
                mkdirat(&controls, slot.as_str(), Mode::RWXU).map_err(|_| denied())?;
            }
            let directory = directory_at(&controls, slot)?;
            let identity = directory_identity(&directory)?;
            if expected.is_some_and(|expected| expected != identity) {
                return Err(denied());
            }
            let binding = Binding {
                version: 1,
                xite: assignment.xite().into(),
                slot: slot.clone(),
                guest: assignment.services().guest.service.clone(),
                compiler: assignment.services().compiler.service.clone(),
                file: assignment.services().file.service.clone(),
                root: identity,
            };
            if expected.is_none() {
                create(&directory, LOCK, &[])?;
                create(
                    &directory,
                    BINDING,
                    &serde_json::to_vec(&binding).map_err(|_| denied())?,
                )?;
                create(
                    &directory,
                    JOURNAL,
                    &serde_json::to_vec(&Journal {
                        version: 1,
                        session: 0,
                        next: 0,
                        active: BTreeMap::new(),
                    })
                    .map_err(|_| denied())?,
                )?;
                fsync(&directory).map_err(|_| denied())?;
                fsync(&controls).map_err(|_| denied())?;
            } else {
                let actual: Binding = read(&directory, BINDING)?;
                if actual != binding {
                    return Err(denied());
                }
            }
            Ok(((registry.join("workspaces").join(slot), binding), identity))
        })?;
        let mut workspace = Self {
            assignment,
            path,
            binding,
            session: 0,
        };
        workspace.session = workspace.with_journal(|directory, journal| {
            if !journal.active.is_empty() {
                return Err(quarantine());
            }
            journal.session = journal
                .session
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or_else(denied)?;
            persist(directory, journal)?;
            Ok(journal.session)
        })?;
        Ok(Arc::new(workspace))
    }

    pub fn xite(&self) -> &str {
        self.assignment.xite()
    }

    /// Host control location, not guest data. Never pass it to a service.
    pub(crate) fn control_path(&self) -> &Path {
        &self.path
    }

    fn with_journal<T>(
        &self,
        action: impl FnOnce(&OwnedFd, &mut Journal) -> Result<T, Denied>,
    ) -> Result<T, Denied> {
        self.assignment.with_workspace(|registry, expected| {
            if expected != Some(self.binding.root)
                || registry.join("workspaces").join(&self.binding.slot) != self.path
            {
                return Err(denied());
            }
            let directory = evx_workspace::open_root(&self.path)?;
            if directory_identity(&directory)? != self.binding.root {
                return Err(denied());
            }
            let binding: Binding = read(&directory, BINDING)?;
            if binding != self.binding {
                return Err(denied());
            }
            let lock = safe_open(&directory, LOCK, true)?;
            if fstat(&lock).map_err(|_| denied())?.st_size != 0 {
                return Err(denied());
            }
            // All cooperating accesses also hold the registry lock. A busy
            // journal lock signals an unexpected host, so do not wait on it.
            flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| denied())?;
            match openat(
                &directory,
                PENDING,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            ) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => return Err(denied()),
            }
            let mut journal: Journal = read(&directory, JOURNAL)?;
            if journal.version != 1
                || journal.active.len() > 2
                || journal.active.values().collect::<BTreeSet<_>>().len() != journal.active.len()
                || journal.active.iter().any(|(role, id)| {
                    !matches!(role.as_str(), "guest" | "compiler" | "file")
                        || *id == 0
                        || *id > journal.next
                })
                || journal.active.contains_key("compiler") && journal.active.len() != 1
            {
                return Err(denied());
            }
            // Re-establish durability of a visible snapshot after a previous
            // rename/sync failure before deriving any authority from it.
            fsync(safe_open(&directory, JOURNAL, false)?).map_err(|_| denied())?;
            sync_directory(&directory)?;
            let result = action(&directory, &mut journal)?;
            Ok((result, self.binding.root))
        })
    }

    pub(crate) fn validate(&self) -> Result<(), Denied> {
        self.with_journal(|_, journal| {
            if journal.session != self.session {
                return Err(quarantine());
            }
            Ok(())
        })
    }

    fn require_idle(&self) -> Result<(), Denied> {
        self.with_journal(|_, journal| {
            if journal.session != self.session || !journal.active.is_empty() {
                return Err(quarantine());
            }
            Ok(())
        })
    }

    /// Persist possible execution before any service admission attempt.
    pub(crate) fn begin(self: &Arc<Self>, role: Role) -> Result<AppleInvocation, Denied> {
        let invocation = self.with_journal(|directory, journal| {
            if journal.session != self.session || journal.active.contains_key(role.name()) {
                return Err(quarantine());
            }
            let compatible = journal.active.is_empty()
                || role == Role::File
                    && journal.active.len() == 1
                    && journal.active.contains_key("guest");
            if !compatible {
                return Err(quarantine());
            }
            journal.next = journal
                .next
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or_else(denied)?;
            journal.active.insert(role.name().into(), journal.next);
            persist(directory, journal)?;
            Ok(journal.next)
        })?;
        Ok(AppleInvocation {
            workspace: self.clone(),
            role,
            invocation,
            complete: false,
        })
    }

    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub fn config(self: &Arc<Self>, authority_directory: PathBuf) -> crate::Config {
        let mut apple = self.assignment.xpc_config(authority_directory);
        apple.workspace = Some(self.clone());
        let mut config = crate::Config::new(PathBuf::new());
        config.apple_xpc = Some(apple);
        config
    }

    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub(crate) fn matches(&self, config: &crate::apple::AppleXpcConfig) -> bool {
        let slot = self.assignment.services();
        config.guest_service == slot.guest.service
            && config.guest_requirement == slot.guest.requirement
            && config.compiler_service == slot.compiler.service
            && config.compiler_requirement == slot.compiler.requirement
            && config.file_service == slot.file.service
            && config.file_requirement == slot.file.requirement
            && config.workspace.as_ref().is_some_and(|workspace| {
                workspace.path == self.path && workspace.session == self.session
            })
    }

    /// Checked activation compiler path. Raw compilation remains a trusted
    /// transport primitive and is never a node declaration input.
    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub fn compile_module(
        &self,
        config: &crate::Config,
        bytes: &[u8],
    ) -> Result<crate::CompiledArtifact, Denied> {
        self.check_config(config)?;
        crate::compile_module(config, bytes)
    }

    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub fn compile_text(
        &self,
        config: &crate::Config,
        bytes: &[u8],
    ) -> Result<crate::CompiledArtifact, Denied> {
        self.check_config(config)?;
        crate::compile_text(config, bytes)
    }

    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub(crate) fn check_config(&self, config: &crate::Config) -> Result<(), Denied> {
        if !config.worker_args.is_empty()
            || !config
                .apple_xpc
                .as_ref()
                .is_some_and(|apple| self.matches(apple))
        {
            return Err(Denied::new("Apple workspace backend mismatch"));
        }
        self.require_idle()
    }
}

/// Dropping a token preserves the durable unresolved invocation. Only the
/// trusted transport's confirmed child-reap observation may complete it.
pub(crate) struct AppleInvocation {
    workspace: Arc<AppleWorkspace>,
    role: Role,
    invocation: u64,
    complete: bool,
}

impl AppleInvocation {
    pub(crate) fn complete(&mut self) -> Result<(), Denied> {
        if self.complete {
            return Ok(());
        }
        self.workspace.with_journal(|directory, journal| {
            if journal.session != self.workspace.session
                || journal.active.get(self.role.name()) != Some(&self.invocation)
            {
                return Err(quarantine());
            }
            journal.active.remove(self.role.name());
            persist(directory, journal)
        })?;
        self.complete = true;
        Ok(())
    }
}

fn directory_at(parent: &OwnedFd, name: &str) -> Result<OwnedFd, Denied> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| denied())?;
    directory_identity(&fd)?;
    Ok(fd)
}

#[allow(clippy::unnecessary_cast)]
fn directory_identity(fd: &OwnedFd) -> Result<[u64; 2], Denied> {
    let metadata = fstat(fd).map_err(|_| denied())?;
    if FileType::from_raw_mode(metadata.st_mode as rustix::fs::RawMode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err(denied());
    }
    Ok([metadata.st_dev as u64, metadata.st_ino as u64])
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
    let metadata = fstat(&fd).map_err(|_| denied())?;
    if FileType::from_raw_mode(metadata.st_mode as rustix::fs::RawMode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_nlink != 1
        || metadata.st_size < 0
        || metadata.st_size as u64 > MAX_METADATA as u64
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
thread_local! { static FAIL_SYNC: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

fn sync_directory(root: &OwnedFd) -> Result<(), Denied> {
    #[cfg(test)]
    if FAIL_SYNC.with(|fail| {
        let remaining = fail.get();
        fail.set(remaining.saturating_sub(1));
        remaining == 1
    }) {
        return Err(denied());
    }
    fsync(root).map_err(|_| denied())
}

fn persist(root: &OwnedFd, journal: &Journal) -> Result<(), Denied> {
    let bytes = serde_json::to_vec(journal).map_err(|_| denied())?;
    if bytes.len() > MAX_METADATA {
        return Err(denied());
    }
    let result = (|| {
        create(root, PENDING, &bytes)?;
        renameat(root, PENDING, root, JOURNAL).map_err(|_| denied())?;
        sync_directory(root)
    })();
    let _ = unlinkat(root, PENDING, AtFlags::empty());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_slots::{
        AppleServiceIdentity, AppleServiceSlot, AppleSlotInventory, AppleSlotRegistry,
    };
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, AppleSlotAssignment, Arc<AppleWorkspace>) {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let service = |role| AppleServiceIdentity {
            service: format!("org.example.game.{role}"),
            requirement: "fixture".into(),
        };
        let registry = AppleSlotRegistry::provision_fresh(
            &temp.path().join("registry"),
            [9; 32],
            AppleSlotInventory::new(vec![AppleServiceSlot {
                slot: "first".into(),
                guest: service("guest"),
                compiler: service("compiler"),
                file: service("file"),
            }])
            .unwrap(),
        )
        .unwrap();
        let assignment = registry.allocate("game").unwrap();
        let workspace = AppleWorkspace::open(assignment.clone()).unwrap();
        (temp, assignment, workspace)
    }

    #[test]
    fn guest_and_file_share_one_session_but_competing_roles_refuse() {
        let (_temp, assignment, workspace) = fixture();
        let mut guest = workspace.begin(Role::Guest).unwrap();
        let mut file = workspace.begin(Role::File).unwrap();
        assert!(workspace.begin(Role::Compiler).is_err());
        assert!(workspace.begin(Role::Guest).is_err());
        assert!(workspace.begin(Role::File).is_err());
        assert!(matches!(
            AppleWorkspace::open(assignment.clone()),
            Err(Denied::Quarantined(_))
        ));
        file.complete().unwrap();
        guest.complete().unwrap();
        let mut compiler = workspace.begin(Role::Compiler).unwrap();
        assert!(workspace.begin(Role::File).is_err());
        compiler.complete().unwrap();
        let reopened = AppleWorkspace::open(assignment).unwrap();
        assert!(workspace.validate().is_err());
        reopened.validate().unwrap();
    }

    #[test]
    fn dropped_invocation_remains_quarantined_and_file_recovery_cannot_clear_it() {
        let (_temp, assignment, workspace) = fixture();
        let broker = crate::Broker::new_apple(
            workspace.clone(),
            evx_api::Grant::new("game", true).unwrap(),
            evx_api::Limits::default(),
        )
        .unwrap();
        let config = workspace.config(PathBuf::new());
        drop(workspace.begin(Role::Guest).unwrap());
        assert!(matches!(
            crate::reconcile_workspace(&config, &broker),
            Err(Denied::Quarantined(_))
        ));
        drop(broker);
        drop(workspace);
        assert!(matches!(
            AppleWorkspace::open(assignment),
            Err(Denied::Quarantined(_))
        ));
    }

    #[test]
    fn stale_completion_cannot_clear_a_successor() {
        let (_temp, assignment, workspace) = fixture();
        let mut first = workspace.begin(Role::Guest).unwrap();
        let mut stale = AppleInvocation {
            workspace: workspace.clone(),
            role: first.role,
            invocation: first.invocation,
            complete: false,
        };
        first.complete().unwrap();
        let mut successor = workspace.begin(Role::Guest).unwrap();
        assert!(stale.complete().is_err());
        assert!(AppleWorkspace::open(assignment.clone()).is_err());
        successor.complete().unwrap();
        AppleWorkspace::open(assignment).unwrap();
    }

    #[test]
    fn failed_start_durability_cannot_return_admission_or_erase_uncertainty() {
        let (_temp, assignment, workspace) = fixture();
        // The first sync verifies the prior record; the second is after the
        // active record's rename. No start token may escape that failure.
        FAIL_SYNC.with(|fail| fail.set(2));
        assert!(workspace.begin(Role::Compiler).is_err());
        FAIL_SYNC.with(|fail| fail.set(0));
        assert!(matches!(
            AppleWorkspace::open(assignment),
            Err(Denied::Quarantined(_))
        ));
    }

    #[test]
    fn missing_or_replaced_controls_never_create_an_independent_lease() {
        let (_temp, assignment, workspace) = fixture();
        let path = workspace.path.clone();
        std::fs::remove_dir_all(&path).unwrap();
        assert!(workspace.begin(Role::Guest).is_err());
        assert!(AppleWorkspace::open(assignment.clone()).is_err());
        assert!(!path.exists());
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(AppleWorkspace::open(assignment).is_err());
    }

    #[test]
    fn missing_corrupt_linked_or_unsafe_metadata_refuses() {
        for name in [BINDING, JOURNAL, LOCK] {
            let (_temp, assignment, workspace) = fixture();
            std::fs::remove_file(workspace.path.join(name)).unwrap();
            assert!(AppleWorkspace::open(assignment).is_err());
            assert!(!workspace.path.join(name).exists());
        }
        for mutation in [
            "corrupt",
            "unknown",
            "duplicate",
            "linked",
            "mode",
            "symlink",
            "pending",
        ] {
            let (temp, assignment, workspace) = fixture();
            let path = workspace.path.join(JOURNAL);
            match mutation {
                "corrupt" => std::fs::write(path, b"bad").unwrap(),
                "duplicate" => std::fs::write(
                    path,
                    b"{\"version\":1,\"session\":1,\"next\":1,\"active\":{\"guest\":1,\"file\":1}}",
                )
                .unwrap(),
                "unknown" => std::fs::write(
                    path,
                    b"{\"version\":1,\"session\":1,\"next\":0,\"active\":{},\"extra\":0}",
                )
                .unwrap(),
                "linked" => std::fs::hard_link(path, temp.path().join("alias")).unwrap(),
                "mode" => {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "symlink" => {
                    std::fs::rename(&path, temp.path().join("other")).unwrap();
                    symlink(temp.path().join("other"), path).unwrap();
                }
                "pending" => std::fs::write(workspace.path.join(PENDING), b"interrupted").unwrap(),
                _ => unreachable!(),
            }
            assert!(AppleWorkspace::open(assignment).is_err(), "{mutation}");
        }
    }

    #[test]
    fn bound_config_rejects_role_substitution_and_other_grants_before_compilation() {
        let (_temp, _assignment, workspace) = fixture();
        let mut config = workspace.config(PathBuf::new());
        assert!(crate::Broker::new_apple(
            workspace.clone(),
            evx_api::Grant::new("other-game", true).unwrap(),
            evx_api::Limits::default()
        )
        .is_err());
        let broker = crate::Broker::new_apple(
            workspace.clone(),
            evx_api::Grant::new("game", true).unwrap(),
            evx_api::Limits::default(),
        )
        .unwrap();
        broker.check_backend(&config).unwrap();
        assert!(
            broker.usage().is_err(),
            "host metadata must not be reported as guest storage"
        );
        assert!(
            broker.helper_lease_fd().is_none(),
            "host authority fd must never reach a service"
        );
        config.apple_xpc.as_mut().unwrap().file_service = "org.example.other.file".into();
        assert!(broker.check_backend(&config).is_err());
        assert!(workspace.compile_module(&config, b"not wasm").is_err());
        assert!(crate::reconcile_workspace(&config, &broker).is_err());
    }

    #[test]
    fn invocation_counter_overflow_refuses_without_erasing_state() {
        let (_temp, _assignment, workspace) = fixture();
        workspace
            .with_journal(|directory, journal| {
                journal.next = i64::MAX as u64;
                persist(directory, journal)
            })
            .unwrap();
        assert!(workspace.begin(Role::Guest).is_err());
        workspace.require_idle().unwrap();
    }
}
