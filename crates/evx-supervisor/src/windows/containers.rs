//! AppContainer profiles per workspace and the workspace DACL.
//!
//! Three less-privileged AppContainer profiles exist per workspace, with
//! deterministic names so the mapping is permanent and needs no registry:
//!
//! ```text
//! Epix.Evx.<24 hex of SHA-256(canonical workspace path)>.g   guest
//! Epix.Evx.<24 hex ...>.f                                    file helper, read and write
//! Epix.Evx.<24 hex ...>.r                                    file-read helper, read only
//! ```
//!
//! The compiler touches no files and uses one fixed profile,
//! `Epix.Evx.compiler`. Profiles are created on first use and never deleted
//! automatically; test fixtures delete theirs through
//! [`forget`](Containers::forget). The workspace directory receives, once per host process,
//! a protected inheritable DACL: owner and SYSTEM in full, the `.f` profile
//! modify (read, write, add file, add subdirectory, delete, delete child),
//! the `.r` profile read and list. The guest profile has no ACE anywhere
//! but the staged image, which every LPAC token may read.
//!
//! Preparation also resets every existing descendant to pure inheritance,
//! because the system's own propagation silently skips a directory whose
//! lease handle is held (the lease shares neither delete nor the
//! `MAXIMUM_ALLOWED` open the propagation walker makes), and a file written
//! before preparation would otherwise stay invisible to the helpers.
//! Files created after preparation inherit the entries at creation.
//!
//! `CreateAppContainerProfile` also creates `%LOCALAPPDATA%\Packages\<name>`
//! with an `AC` subtree (`Temp` and friends) that carries a full-control
//! entry for the package SID: persistent writable storage outside the
//! broker's quota and provenance. Every container therefore locks that
//! tree on creation and on adoption: a protected DACL naming the owner and
//! SYSTEM only on the package folder, then every descendant reset to pure
//! inheritance with the same walker, so no package entry remains anywhere.
//! Measured on Windows 11: AppContainer process start does not recreate
//! the folders or their entries, and a worker starts without them.
//!
//! The registry is process-wide: profiles are operating-system objects
//! named by the workspace, not by any backend instance, so `Broker::new`
//! can prepare a workspace before a lease exists.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use evx_api::Denied;
use evx_windows_native::{
    current_user_sid_text, delete_profile, inherit_dacl, local_app_data, protect_handle, Profile,
};
use evx_workspace::sys::path_bytes;
use evx_workspace::{Dir, Kind};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Security::PSID;

use crate::process::Role;

pub(crate) const COMPILER_PROFILE: &str = "Epix.Evx.compiler";
/// Bounds of the preparation walk; a larger workspace fails closed.
const MAX_PREPARED_ENTRIES: usize = 4096;
const MAX_PREPARED_DEPTH: usize = 8;
/// FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE |
/// FILE_DELETE_CHILD: what a staged write and its cleanup need.
const MODIFY: &str = "0x1301FF";
/// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE: read, list and traverse.
const READ_LIST: &str = "0x1200A9";
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const SHARE_ALL: u32 = 0x7;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn denied(reason: &str) -> Denied {
    Denied::new(format!("worker container unavailable: {reason}"))
}

/// One retained AppContainer profile.
pub(crate) struct Container {
    profile: Profile,
}

// SAFETY: the package SID is immutable after creation and freed exactly once
// on drop; the userenv module handle is process-wide. Nothing in `Profile`
// is thread-affine, so sharing it between the event loop and spawns is sound.
unsafe impl Send for Container {}
unsafe impl Sync for Container {}

impl Container {
    fn create(name: &str) -> Result<Arc<Self>, Denied> {
        let mut profile = Profile::create(name).map_err(|e| denied(&e.to_string()))?;
        profile.retain();
        lock_package_folder(name)?;
        Ok(Arc::new(Container { profile }))
    }

    /// The package SID, valid while this container lives.
    pub(crate) fn sid(&self) -> PSID {
        self.profile.sid()
    }

    #[cfg(test)]
    pub(crate) fn name(&self) -> &str {
        self.profile.name()
    }

    pub(crate) fn sid_text(&self) -> Result<String, Denied> {
        self.profile.sid_text().map_err(|_| denied("package SID"))
    }
}

/// The three profiles of one prepared workspace.
pub(crate) struct Workspace {
    guest: Arc<Container>,
    file: Arc<Container>,
    read: Arc<Container>,
}

/// Every container this backend has created, by workspace key.
pub(crate) struct Containers {
    compiler: Mutex<Option<Arc<Container>>>,
    workspaces: Mutex<HashMap<String, Arc<Workspace>>>,
}

/// The 24 hex characters that name a workspace's profiles.
pub(crate) fn workspace_key(workspace: &Path) -> Result<String, Denied> {
    let canonical = canonical(workspace)?;
    let bytes = path_bytes(&canonical).map_err(|_| denied("workspace path encoding"))?;
    Ok(hex::encode(Sha256::digest(bytes))[..24].to_string())
}

/// The guest, file helper and file-read helper profile names of `workspace`.
pub(crate) fn workspace_profile_names(workspace: &Path) -> Result<[String; 3], Denied> {
    let key = workspace_key(workspace)?;
    Ok(["g", "f", "r"].map(|role| format!("Epix.Evx.{key}.{role}")))
}

/// `%LOCALAPPDATA%\Packages\<name>`: the per-profile folder the OS creates.
pub(crate) fn package_folder(name: &str) -> Result<PathBuf, Denied> {
    use std::os::windows::ffi::OsStringExt;
    let local = local_app_data().map_err(|_| denied("local application data"))?;
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&local))
        .join("Packages")
        .join(name))
}

/// The supervisor's own canonical form: the resolved parent plus the final
/// name, which is never followed.
fn canonical(workspace: &Path) -> Result<std::path::PathBuf, Denied> {
    let name = workspace
        .file_name()
        .ok_or_else(|| denied("workspace name"))?;
    let parent = workspace
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(std::fs::canonicalize(parent)
        .map_err(|_| denied("workspace parent"))?
        .join(name))
}

/// The process-wide registry.
pub(crate) fn containers() -> &'static Containers {
    static REGISTRY: OnceLock<Containers> = OnceLock::new();
    REGISTRY.get_or_init(Containers::new)
}

/// Create the workspace's profiles and apply its DACL, once per host
/// process. Called by `Broker::new` before any lease exists and by every
/// spawn that names a workspace.
pub(crate) fn prepare(workspace: &Path) -> Result<(), Denied> {
    containers().workspace(workspace).map(|_| ())
}

/// Prove the profile API works by creating (or adopting) the compiler
/// profile, which every host needs anyway. No separate probe profile.
pub(crate) fn probe() -> Result<(), Denied> {
    containers().compiler().map(|_| ())
}

impl Containers {
    fn new() -> Self {
        Containers {
            compiler: Mutex::new(None),
            workspaces: Mutex::new(HashMap::new()),
        }
    }

    /// The profile for `role` in `mode`, preparing the workspace on first
    /// use. The compiler never touches the workspace and ignores it.
    pub(crate) fn select(
        &self,
        role: Role,
        mode: &str,
        workspace: &Path,
    ) -> Result<Arc<Container>, Denied> {
        if role == Role::Compiler {
            return self.compiler();
        }
        let prepared = self.workspace(workspace)?;
        Ok(match (role, mode) {
            (Role::Guest, _) => prepared.guest.clone(),
            (_, "file-read") => prepared.read.clone(),
            _ => prepared.file.clone(),
        })
    }

    fn compiler(&self) -> Result<Arc<Container>, Denied> {
        let mut slot = self
            .compiler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(container) = slot.as_ref() {
            return Ok(container.clone());
        }
        let container = Container::create(COMPILER_PROFILE)?;
        *slot = Some(container.clone());
        Ok(container)
    }

    fn workspace(&self, workspace: &Path) -> Result<Arc<Workspace>, Denied> {
        let key = workspace_key(workspace)?;
        let mut map = self
            .workspaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(prepared) = map.get(&key) {
            return Ok(prepared.clone());
        }
        // Refuse a junction or a missing directory before any profile exists.
        open_plain_directory(workspace).map_err(|_| denied("workspace directory"))?;
        let [guest, file, read] = workspace_profile_names(workspace)?;
        let prepared = Arc::new(Workspace {
            guest: Container::create(&guest)?,
            file: Container::create(&file)?,
            read: Container::create(&read)?,
        });
        prepare_workspace(workspace, &prepared)?;
        map.insert(key, prepared.clone());
        Ok(prepared)
    }

    /// Delete the three profiles of `workspace` and their package folders,
    /// and forget them here, so the next use creates them afresh. For test
    /// fixtures whose workspaces are disposable; production never calls it,
    /// matching the rule that a workspace is never reassigned.
    pub(crate) fn forget(&self, workspace: &Path) -> Result<(), Denied> {
        let key = workspace_key(workspace)?;
        self.workspaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
        let mut outcome = Ok(());
        for name in workspace_profile_names(workspace)? {
            if let Err(error) = delete_profile_storage(&name) {
                outcome = Err(error);
            }
        }
        outcome
    }
}

/// Delete one profile and whatever the OS left of its package folder.
fn delete_profile_storage(name: &str) -> Result<(), Denied> {
    delete_profile(name).map_err(|e| denied(&e.to_string()))?;
    let folder = package_folder(name)?;
    match std::fs::remove_dir_all(&folder) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(denied("package folder removal")),
    }
}

/// The protected DACL of a package folder: owner and SYSTEM only.
fn private_sddl(owner: &str) -> String {
    format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})")
}

/// Strip the package SID from `%LOCALAPPDATA%\Packages\<name>` and its
/// whole subtree. A folder the OS did not create is nothing to lock.
fn lock_package_folder(name: &str) -> Result<(), Denied> {
    let folder = package_folder(name)?;
    let directory = match open_plain_directory(&folder) {
        Ok(directory) => directory,
        Err(_) if !folder.exists() => return Ok(()),
        Err(error) => return Err(error),
    };
    let owner = current_user_sid_text().map_err(|_| denied("owner identity"))?;
    protect_handle(directory.as_raw_handle(), &private_sddl(&owner))
        .map_err(|_| denied("package folder DACL"))?;
    drop(directory);
    let root = Dir::open_root(&folder).map_err(|_| denied("package folder"))?;
    let mut visited = 0;
    reset_descendants(&root, 0, &mut visited)
}

/// The protected inheritable DACL a prepared workspace carries.
pub(crate) fn workspace_sddl(owner: &str, file: &str, read: &str) -> String {
    format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})(A;OICI;{MODIFY};;;{file})(A;OICI;{READ_LIST};;;{read})"
    )
}

/// Open a plain directory (no reparse point in its final component, so a
/// planted junction cannot redirect the DACL) with the access to replace
/// its DACL.
fn open_plain_directory(path: &Path) -> Result<std::fs::File, Denied> {
    let directory = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| denied("directory unavailable"))?;
    let attributes = directory
        .metadata()
        .map_err(|_| denied("directory unavailable"))?
        .file_attributes();
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied("not a plain directory"));
    }
    Ok(directory)
}

/// Apply the workspace DACL through a handle opened without following a
/// final-component reparse point, then reset every existing descendant to
/// inherit it.
fn prepare_workspace(workspace: &Path, prepared: &Workspace) -> Result<(), Denied> {
    let owner = current_user_sid_text().map_err(|_| denied("owner identity"))?;
    let sddl = workspace_sddl(
        &owner,
        &prepared.file.sid_text()?,
        &prepared.read.sid_text()?,
    );
    let directory = open_plain_directory(workspace).map_err(|_| denied("workspace directory"))?;
    protect_handle(directory.as_raw_handle(), &sddl).map_err(|_| denied("workspace DACL"))?;
    drop(directory);
    let root = Dir::open_root(workspace).map_err(|_| denied("workspace directory"))?;
    let mut visited = 0;
    reset_descendants(&root, 0, &mut visited)
}

/// Reset every descendant of `dir` to inherit its DACL, walking through
/// handles only and never following a reparse point.
fn reset_descendants(dir: &Dir, depth: usize, visited: &mut usize) -> Result<(), Denied> {
    if depth > MAX_PREPARED_DEPTH {
        return Err(denied("workspace depth limit"));
    }
    for entry in dir.entries().map_err(|_| denied("workspace listing"))? {
        *visited += 1;
        if *visited > MAX_PREPARED_ENTRIES {
            return Err(denied("workspace entry limit"));
        }
        if entry.kind == Kind::Other {
            continue;
        }
        let handle = dir
            .open_security(Some(&entry.name))
            .map_err(|_| denied("workspace entry"))?;
        inherit_dacl(handle.as_raw_handle()).map_err(|_| denied("workspace entry DACL"))?;
        drop(handle);
        if entry.kind == Kind::Directory {
            let child = dir
                .open_dir(&entry.name)
                .map_err(|_| denied("workspace entry"))?;
            reset_descendants(&child, depth + 1, visited)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_are_deterministic_per_workspace_and_role() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let workspace = root.join("game-a");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(workspace.join("state")).unwrap();
        std::fs::write(
            workspace.join("state").join("existing.txt"),
            b"before preparation",
        )
        .unwrap();
        // A held lease blocks the system's own propagation to children; the
        // explicit reset below must not depend on it.
        let held = evx_workspace::Dir::open_root(&workspace).unwrap();
        let _lease = held.lease().unwrap();
        let containers = Containers::new();
        let key = workspace_key(&workspace).unwrap();
        assert_eq!(key.len(), 24);
        assert_eq!(workspace_key(&dir.path().join("game-a")).unwrap(), key);
        let guest = containers.select(Role::Guest, "run", &workspace).unwrap();
        let file = containers.select(Role::File, "file", &workspace).unwrap();
        let read = containers
            .select(Role::File, "file-read", &workspace)
            .unwrap();
        let compiler = containers
            .select(Role::Compiler, "compile", &workspace)
            .unwrap();
        assert_eq!(guest.name(), format!("Epix.Evx.{key}.g"));
        assert_eq!(file.name(), format!("Epix.Evx.{key}.f"));
        assert_eq!(read.name(), format!("Epix.Evx.{key}.r"));
        assert_eq!(compiler.name(), COMPILER_PROFILE);
        let sids: std::collections::BTreeSet<_> = [&guest, &file, &read, &compiler]
            .iter()
            .map(|c| c.sid_text().unwrap())
            .collect();
        assert_eq!(sids.len(), 4);
        // Selecting again reuses the same containers.
        assert!(Arc::ptr_eq(
            &guest,
            &containers.select(Role::Guest, "run", &workspace).unwrap()
        ));
        // The workspace names exactly the two helper profiles.
        let dacl = std::process::Command::new("icacls")
            .arg(&workspace)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&dacl.stdout);
        assert!(
            text.contains(&file.sid_text().unwrap()) || text.contains(file.name()),
            "{text}"
        );
        assert!(
            text.contains(&read.sid_text().unwrap()) || text.contains(read.name()),
            "{text}"
        );
        assert!(
            !text.contains(&guest.sid_text().unwrap()) && !text.contains(guest.name()),
            "{text}"
        );
        // A file that existed before preparation carries the helper ACEs too.
        let existing = std::process::Command::new("icacls")
            .arg(workspace.join("state").join("existing.txt"))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&existing.stdout);
        assert!(
            text.contains(&file.sid_text().unwrap()) || text.contains(file.name()),
            "{text}"
        );
        assert!(
            text.contains(&read.sid_text().unwrap()) || text.contains(read.name()),
            "{text}"
        );
        // A planted junction in place of the workspace is refused.
        drop((_lease, held));
        let moved = root.join("moved");
        std::fs::rename(&workspace, &moved).unwrap();
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&workspace)
            .arg(&moved)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(Containers::new()
            .select(Role::Guest, "run", &workspace)
            .is_err());
        containers.forget(&workspace).unwrap();
        for name in workspace_profile_names(&workspace).unwrap() {
            assert!(!package_folder(&name).unwrap().exists(), "{name}");
        }
    }

    /// Every ACE in the icacls listing of `path`, one per line.
    fn aces(path: &Path) -> Vec<String> {
        let output = std::process::Command::new("icacls")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.contains(":("))
            .map(|line| line.trim().to_string())
            .collect()
    }

    /// Every ACE in `folder` and its whole subtree.
    fn tree_aces(folder: &Path) -> Vec<String> {
        let mut found = Vec::new();
        let mut pending = vec![folder.to_path_buf()];
        while let Some(path) = pending.pop() {
            found.extend(
                aces(&path)
                    .into_iter()
                    .map(|ace| format!("{}: {ace}", path.display())),
            );
            if path.is_dir() {
                pending.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            }
        }
        found
    }

    #[test]
    fn package_folders_carry_no_package_entry_after_creation_or_adoption() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(dir.path()).unwrap().join("game-c");
        std::fs::create_dir(&workspace).unwrap();
        let names = workspace_profile_names(&workspace).unwrap();
        // Start from the OS default: no profile, no folder.
        for name in &names {
            delete_profile_storage(name).unwrap();
        }
        let containers = Containers::new();
        let guest = containers.select(Role::Guest, "run", &workspace).unwrap();
        let compiler = containers
            .select(Role::Compiler, "compile", &workspace)
            .unwrap();
        let mut folders: Vec<_> = names.iter().map(|n| package_folder(n).unwrap()).collect();
        folders.push(package_folder(compiler.name()).unwrap());
        for folder in &folders {
            assert!(folder.is_dir(), "{}", folder.display());
            for ace in tree_aces(folder) {
                assert!(!ace.contains("S-1-15-2-"), "{ace}");
            }
        }
        // Adoption by a fresh registry (a profile that already exists, as
        // after a restart) re-locks a folder someone re-opened.
        let ac = folders[0].join("AC");
        let sid = guest.sid_text().unwrap();
        let granted = std::process::Command::new("icacls")
            .arg(&ac)
            .arg("/grant")
            .arg(format!("*{sid}:(OI)(CI)F"))
            .output()
            .unwrap();
        assert!(granted.status.success(), "{granted:?}");
        assert!(aces(&ac).iter().any(|ace| ace.contains(&sid)));
        Containers::new()
            .select(Role::Guest, "run", &workspace)
            .unwrap();
        let after = aces(&ac);
        assert!(
            !after.iter().any(|ace| ace.contains("S-1-15-2-")),
            "{after:?}"
        );
        containers.forget(&workspace).unwrap();
    }
}
