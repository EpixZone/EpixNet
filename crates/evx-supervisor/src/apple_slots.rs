//! Permanent Apple service/container assignments in host-private storage.
//!
//! This store is outside every confined service's authority. It rejects lost,
//! malformed and unsafe state, but does not authenticate writes by an
//! unconfined local owner or detect restoration of an older valid snapshot.
//! Provisioning requires independently established fresh service containers.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use evx_api::Denied;
use rustix::fd::OwnedFd;
use rustix::fs::{
    flock, fstat, fsync, mkdirat, openat, renameat, unlinkat, AtFlags, FileType, FlockOperation,
    Mode, OFlags,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const STATE: &str = "registry.json";
const LOCK: &str = "registry.lock";
const PENDING: &str = "registry.pending";
const MAX_STATE: usize = 128 * 1024;
pub const MAX_APPLE_SLOTS: usize = 64;
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(test)]
thread_local! {
    static FAIL_DIRECTORY_SYNCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn denied(reason: &str) -> Denied {
    Denied::new(format!("Apple slot registry: {reason}"))
}

/// Trusted package policy, never an execution declaration or guest value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleServiceIdentity {
    pub service: String,
    pub requirement: String,
}

/// The three permanent private container identities reserved for one xite.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleServiceSlot {
    pub slot: String,
    pub guest: AppleServiceIdentity,
    pub compiler: AppleServiceIdentity,
    pub file: AppleServiceIdentity,
}

/// A bounded, validated inventory from trusted host packaging.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleSlotInventory {
    slots: BTreeMap<String, AppleServiceSlot>,
    digest: String,
}

impl AppleSlotInventory {
    pub fn new(slots: Vec<AppleServiceSlot>) -> Result<Self, Denied> {
        if slots.is_empty() || slots.len() > MAX_APPLE_SLOTS {
            return Err(denied("invalid pool size"));
        }
        let mut services = BTreeSet::new();
        let mut inventory = BTreeMap::new();
        for slot in slots {
            evx_api::validate_identifier(&slot.slot)?;
            for identity in [&slot.guest, &slot.compiler, &slot.file] {
                let service = &identity.service;
                if service.len() > 255
                    || !service.contains('.')
                    || service.split('.').any(|part| {
                        part.is_empty()
                            || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    })
                    || identity.requirement.is_empty()
                    || identity.requirement.len() > 2048
                    || identity.requirement.chars().any(char::is_control)
                {
                    return Err(denied("invalid service identity"));
                }
                // Container paths may live on a case-insensitive filesystem.
                if !services.insert(service.to_ascii_lowercase()) {
                    return Err(denied("duplicate service/container identity"));
                }
            }
            if inventory.insert(slot.slot.clone(), slot).is_some() {
                return Err(denied("duplicate slot identity"));
            }
        }
        // Signing requirements are current trusted package policy. Changing
        // them must not silently change which permanent containers are used.
        let identities: Vec<_> = inventory
            .values()
            .map(|slot| {
                (
                    &slot.slot,
                    &slot.guest.service,
                    &slot.compiler.service,
                    &slot.file.service,
                )
            })
            .collect();
        let bytes = serde_json::to_vec(&identities).map_err(|_| denied("inventory encoding"))?;
        Ok(Self {
            slots: inventory,
            digest: hex::encode(Sha256::digest(bytes)),
        })
    }
}

/// A permanent assignment, returned only after its snapshot is durable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppleSlotAssignment {
    xite: String,
    services: AppleServiceSlot,
    registry: PathBuf,
    installation: String,
    inventory: AppleSlotInventory,
}

impl AppleSlotAssignment {
    pub fn xite(&self) -> &str {
        &self.xite
    }
    pub fn services(&self) -> &AppleServiceSlot {
        &self.services
    }

    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub(crate) fn with_workspace<T>(
        &self,
        action: impl FnOnce(&Path, Option<[u64; 2]>) -> Result<(T, [u64; 2]), Denied>,
    ) -> Result<T, Denied> {
        let mut registry =
            AppleSlotRegistry::open_directory(&self.registry, [0; 32], self.inventory.clone())?;
        registry.installation = self.installation.clone();
        let lock = registry.acquire()?;
        let mut record = registry.load(&lock)?;
        if record.assignments.get(&self.xite) != Some(&self.services.slot) {
            return Err(denied("permanent assignment unavailable"));
        }
        registry.ensure_durable()?;
        let expected = record.workspace_controls.get(&self.services.slot).copied();
        let (result, identity) = action(&self.registry, expected)?;
        if let Some(expected) = expected {
            if expected != identity {
                return Err(denied("workspace control replaced"));
            }
        } else {
            record
                .workspace_controls
                .insert(self.services.slot.clone(), identity);
            registry.persist(&record)?;
        }
        registry.ensure_durable()?;
        Ok(result)
    }

    /// Select the production adapter's currently implemented roles. The file
    /// identity stays reserved even while its transport is unavailable.
    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub fn xpc_config(&self, authority_directory: PathBuf) -> crate::apple::AppleXpcConfig {
        crate::apple::AppleXpcConfig {
            guest_service: self.services.guest.service.clone(),
            guest_requirement: self.services.guest.requirement.clone(),
            compiler_service: self.services.compiler.service.clone(),
            compiler_requirement: self.services.compiler.requirement.clone(),
            file_service: self.services.file.service.clone(),
            file_requirement: self.services.file.requirement.clone(),
            authority_directory,
            workspace: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    installation: String,
    inventory: String,
    root_device: u64,
    root_inode: u64,
    lock_device: u64,
    lock_inode: u64,
    assignments: BTreeMap<String, String>,
    #[serde(default)]
    workspace_controls: BTreeMap<String, [u64; 2]>,
}

/// Host-owned, append-only assignments. Opening never creates missing state.
///
/// The parent and this directory must be trusted host-private locations,
/// excluded from every service sandbox. A caller-supplied installation ID
/// comes from trusted installation metadata, not from this registry itself.
pub struct AppleSlotRegistry {
    directory: OwnedFd,
    path: PathBuf,
    installation: String,
    inventory: AppleSlotInventory,
    device: u64,
    inode: u64,
}

impl AppleSlotRegistry {
    /// One-time trusted provisioning. The caller must independently establish
    /// that every listed service container has never held another xite's data.
    /// Trusted installation policy must reserve this pool exclusively for this
    /// one registry path; provisioning a second store for the same pool is invalid.
    /// An absent registry, reinstall or empty host directory is NOT that proof.
    /// Existing directories, including partial earlier provisioning, refuse.
    pub fn provision_fresh(
        path: &Path,
        installation: [u8; 32],
        inventory: AppleSlotInventory,
    ) -> Result<Self, Denied> {
        let (parent, name, path) = parent(path)?;
        mkdirat(&parent, name.as_str(), Mode::RWXU)
            .map_err(|_| denied("fresh directory required"))?;
        let registry = Self::open_directory(&path, installation, inventory)?;
        let lock = openat(
            &registry.directory,
            LOCK,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| denied("provisioning lock"))?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| denied("provisioning lock"))?;
        fsync(&lock).map_err(|_| denied("provisioning durability"))?;
        let metadata = safe_file(&lock, 0)?;
        let (lock_device, lock_inode) = file_identity(&metadata);
        let record = Record {
            version: 1,
            installation: registry.installation.clone(),
            inventory: registry.inventory.digest.clone(),
            root_device: registry.device,
            root_inode: registry.inode,
            lock_device,
            lock_inode,
            assignments: BTreeMap::new(),
            workspace_controls: BTreeMap::new(),
        };
        registry.persist(&record)?;
        fsync(&parent).map_err(|_| denied("provisioning parent durability"))?;
        Ok(registry)
    }

    pub fn open(
        path: &Path,
        installation: [u8; 32],
        inventory: AppleSlotInventory,
    ) -> Result<Self, Denied> {
        let (_, _, path) = parent(path)?;
        let registry = Self::open_directory(&path, installation, inventory)?;
        let lock = registry.acquire()?;
        registry.load(&lock)?;
        Ok(registry)
    }

    fn open_directory(
        path: &Path,
        installation: [u8; 32],
        inventory: AppleSlotInventory,
    ) -> Result<Self, Denied> {
        let directory =
            evx_workspace::open_root(path).map_err(|_| denied("directory unavailable"))?;
        let metadata = safe_directory(&directory)?;
        let (device, inode) = file_identity(&metadata);
        Ok(Self {
            directory,
            path: path.into(),
            installation: hex::encode(installation),
            inventory,
            device,
            inode,
        })
    }

    fn acquire(&self) -> Result<OwnedFd, Denied> {
        self.check_namespace()?;
        // Open a new file description for every operation. Sharing or duping
        // one flock fd would not serialize concurrent calls in this process.
        let lock = openat(
            &self.directory,
            LOCK,
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| denied("lock unavailable"))?;
        safe_file(&lock, 0)?;
        let deadline = Instant::now() + LOCK_TIMEOUT;
        loop {
            match flock(&lock, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR)
                    if Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => return Err(denied("allocation busy or unavailable")),
            }
        }
        self.check_namespace()?;
        Ok(lock)
    }

    fn check_namespace(&self) -> Result<(), Denied> {
        let current = evx_workspace::open_root(&self.path)
            .map_err(|_| denied("directory lost or replaced"))?;
        let metadata = safe_directory(&current)?;
        if file_identity(&metadata) != (self.device, self.inode) {
            return Err(denied("directory lost or replaced"));
        }
        Ok(())
    }

    fn load(&self, lock: &OwnedFd) -> Result<Record, Denied> {
        for entry in
            rustix::fs::Dir::read_from(&self.directory).map_err(|_| denied("directory listing"))?
        {
            let entry = entry.map_err(|_| denied("directory listing"))?;
            match entry
                .file_name()
                .to_str()
                .map_err(|_| denied("unknown directory entry"))?
            {
                "." | ".." | STATE | LOCK => {}
                "workspaces" => {
                    let fd = openat(
                        &self.directory,
                        "workspaces",
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| denied("unsafe workspace controls"))?;
                    safe_directory(&fd)?;
                }
                _ => return Err(denied("unknown or interrupted registry state")),
            }
        }
        let fd = openat(
            &self.directory,
            STATE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| denied("state unavailable; never recreated automatically"))?;
        safe_file(&fd, MAX_STATE)?;
        let mut bytes = Vec::new();
        std::fs::File::from(fd)
            .take(MAX_STATE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| denied("state read"))?;
        if bytes.len() > MAX_STATE {
            return Err(denied("state size"));
        }
        let record: Record =
            evx_api::strict::parse_typed(&bytes).map_err(|_| denied("invalid state"))?;
        let metadata = safe_file(lock, 0)?;
        if record.version != 1
            || record.installation != self.installation
            || record.inventory != self.inventory.digest
            || record.root_device != self.device
            || record.root_inode != self.inode
            || (record.lock_device, record.lock_inode) != file_identity(&metadata)
            || record.assignments.len() > self.inventory.slots.len()
        {
            return Err(denied("state identity mismatch"));
        }
        let mut used = BTreeSet::new();
        for (xite, slot) in &record.assignments {
            evx_api::validate_identifier(xite)?;
            if !self.inventory.slots.contains_key(slot) || !used.insert(slot) {
                return Err(denied("invalid or duplicate slot assignment"));
            }
        }
        if record.workspace_controls.len() > used.len()
            || record
                .workspace_controls
                .keys()
                .any(|slot| !used.contains(slot))
        {
            return Err(denied("invalid workspace control binding"));
        }
        Ok(record)
    }

    fn persist(&self, record: &Record) -> Result<(), Denied> {
        let bytes = serde_json::to_vec(record).map_err(|_| denied("state encoding"))?;
        if bytes.len() > MAX_STATE {
            return Err(denied("state size"));
        }
        let fd = openat(
            &self.directory,
            PENDING,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| denied("state staging"))?;
        let result = (|| {
            let mut file = std::fs::File::from(fd);
            file.write_all(&bytes).map_err(|_| denied("state write"))?;
            file.sync_all().map_err(|_| denied("state durability"))?;
            renameat(&self.directory, PENDING, &self.directory, STATE)
                .map_err(|_| denied("state replacement"))?;
            self.sync_directory()
        })();
        // Only our own staging file is removed on an ordinary failed write.
        // Crash leftovers remain a fail-closed condition on the next open.
        let _ = unlinkat(&self.directory, PENDING, AtFlags::empty());
        result
    }

    fn sync_directory(&self) -> Result<(), Denied> {
        #[cfg(test)]
        if FAIL_DIRECTORY_SYNCS.with(|remaining| {
            let count = remaining.get();
            remaining.set(count.saturating_sub(1));
            count > 0
        }) {
            return Err(denied("directory durability"));
        }
        fsync(&self.directory).map_err(|_| denied("directory durability"))
    }

    fn ensure_durable(&self) -> Result<(), Denied> {
        // A prior call may have renamed successfully and then failed to sync.
        // Reopening cannot distinguish that state from a completed write.
        // Re-establish durability before returning usable slot authority.
        let state = openat(
            &self.directory,
            STATE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| denied("state unavailable"))?;
        safe_file(&state, MAX_STATE)?;
        fsync(&state).map_err(|_| denied("state durability"))?;
        self.sync_directory()?;
        let (parent, _, _) = parent(&self.path)?;
        fsync(&parent).map_err(|_| denied("parent durability"))
    }

    pub fn lookup(&self, xite: &str) -> Result<Option<AppleSlotAssignment>, Denied> {
        evx_api::validate_identifier(xite)?;
        let lock = self.acquire()?;
        let record = self.load(&lock)?;
        let assignment = record
            .assignments
            .get(xite)
            .map(|slot| AppleSlotAssignment {
                xite: xite.into(),
                services: self.inventory.slots[slot].clone(),
                registry: self.path.clone(),
                installation: self.installation.clone(),
                inventory: self.inventory.clone(),
            });
        if assignment.is_some() {
            self.ensure_durable()?;
        }
        Ok(assignment)
    }

    /// Stable identity for binding a trusted host state store to this pool.
    /// This detects a different installation/inventory/root, not rollback or
    /// arbitrary valid edits by the unconfined owner.
    pub fn identity(&self) -> Result<String, Denied> {
        let lock = self.acquire()?;
        let record = self.load(&lock)?;
        self.ensure_durable()?;
        let identity = serde_json::to_vec(&(
            &record.installation, &record.inventory, record.root_device,
            record.root_inode, record.lock_device, record.lock_inode,
        )).map_err(|_| denied("identity encoding"))?;
        Ok(hex::encode(Sha256::digest(identity)))
    }

    /// Return an existing assignment or permanently consume one unused slot.
    /// No service may launch until this method has returned success.
    pub fn allocate(&self, xite: &str) -> Result<AppleSlotAssignment, Denied> {
        evx_api::validate_identifier(xite)?;
        let lock = self.acquire()?;
        let mut record = self.load(&lock)?;
        let slot = match record.assignments.get(xite) {
            Some(slot) => slot.clone(),
            None => {
                let used: BTreeSet<_> = record.assignments.values().collect();
                let slot = self
                    .inventory
                    .slots
                    .keys()
                    .find(|slot| !used.contains(slot))
                    .cloned()
                    .ok_or_else(|| denied("permanent slot pool exhausted"))?;
                record.assignments.insert(xite.into(), slot.clone());
                self.persist(&record)?;
                slot
            }
        };
        self.ensure_durable()?;
        Ok(AppleSlotAssignment {
            xite: xite.into(),
            services: self.inventory.slots[&slot].clone(),
            registry: self.path.clone(),
            installation: self.installation.clone(),
            inventory: self.inventory.clone(),
        })
    }
}

fn parent(path: &Path) -> Result<(OwnedFd, String, PathBuf), Denied> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| denied("invalid directory path"))?;
    let parent = path
        .parent()
        .ok_or_else(|| denied("invalid directory path"))?;
    let parent = std::fs::canonicalize(parent).map_err(|_| denied("trusted parent unavailable"))?;
    let fd = evx_workspace::open_root(&parent).map_err(|_| denied("trusted parent unavailable"))?;
    safe_directory(&fd)?;
    Ok((fd, name.into(), parent.join(name)))
}

fn safe_directory(fd: &OwnedFd) -> Result<rustix::fs::Stat, Denied> {
    let metadata = fstat(fd).map_err(|_| denied("directory metadata"))?;
    if FileType::from_raw_mode(metadata.st_mode as rustix::fs::RawMode) != FileType::Directory
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err(denied("unsafe directory"));
    }
    Ok(metadata)
}

// Stat field widths and aliases differ between supported Unix platforms.
#[allow(clippy::unnecessary_cast)]
fn file_identity(metadata: &rustix::fs::Stat) -> (u64, u64) {
    (metadata.st_dev as u64, metadata.st_ino as u64)
}

fn safe_file(fd: &OwnedFd, max: usize) -> Result<rustix::fs::Stat, Denied> {
    let metadata = fstat(fd).map_err(|_| denied("file metadata"))?;
    if FileType::from_raw_mode(metadata.st_mode as rustix::fs::RawMode) != FileType::RegularFile
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_size < 0
        || metadata.st_size as u64 > max as u64
    {
        return Err(denied("unsafe file"));
    }
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn an_uncertain_snapshot_is_not_returned_without_retrying_durability() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = |role| AppleServiceIdentity {
            service: format!("com.example.fixture.{role}"),
            requirement: "fixture requirement".into(),
        };
        let inventory = AppleSlotInventory::new(vec![AppleServiceSlot {
            slot: "first".into(),
            guest: identity("guest"),
            compiler: identity("compiler"),
            file: identity("file"),
        }])
        .unwrap();
        let path = temp.path().join("slots");
        let registry =
            AppleSlotRegistry::provision_fresh(&path, [9; 32], inventory.clone()).unwrap();
        FAIL_DIRECTORY_SYNCS.with(|remaining| remaining.set(2));
        assert!(registry.allocate("game-a").is_err());
        // The rename happened. A newly opened handle must not trust mere
        // visibility as proof that the assignment reached durable storage.
        let reopened = AppleSlotRegistry::open(&path, [9; 32], inventory).unwrap();
        let after_error = reopened.lookup("game-a");
        FAIL_DIRECTORY_SYNCS.with(|remaining| remaining.set(0));
        assert!(
            after_error.is_err(),
            "unsynced assignment escaped as usable authority"
        );
        assert_eq!(
            reopened.allocate("game-a").unwrap().services().slot,
            "first"
        );
        assert!(reopened.allocate("game-b").is_err());
    }
}
