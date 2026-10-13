//! Current-process signed policy and first-use provisioning for the Developer ID
//! host. Service data is never adopted after loss of its host-private registry.
use crate::apple_slots::{AppleServiceSlot, AppleSlotInventory, AppleSlotRegistry};
use evx_api::Denied;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::ffi::{c_char, CString};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

#[repr(C)]
struct Policy {
    bundle: [u8; libc::PATH_MAX as usize],
    identifier: [u8; 256],
    team: [u8; 32],
    manifest_sha256: [u8; 65],
}
unsafe extern "C" {
    fn evx_xpc_system_applications_directory(uid: u32, gid: u32, mode: u32) -> i32;
    fn evx_apple_package_policy(
        fixture: bool,
        expected_team: *const c_char,
        out: *mut Policy,
    ) -> i32;
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    profile: String,
    host_identifier: String,
    team_identifier: String,
    slots: Vec<AppleServiceSlot>,
}
/// Verified host policy plus the permanently bound private registry.
pub struct ApplePackage {
    pub registry: AppleSlotRegistry,
    pub host_identifier: String,
    pub state_root: PathBuf,
    pub profile: String,
}
fn denied() -> Denied {
    Denied::new("signed Apple package or permanent registry unavailable")
}
fn text(bytes: &[u8]) -> Result<&str, Denied> {
    let end = bytes.iter().position(|b| *b == 0).ok_or_else(denied)?;
    std::str::from_utf8(&bytes[..end]).map_err(|_| denied())
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 180
        && value.contains('.')
        && value
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}
fn safe_directory(path: &Path) -> Result<(), Denied> {
    let metadata = fs::symlink_metadata(path).map_err(|_| denied())?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    // SAFETY: plain metadata values; the native helper reads the OS admin group.
    let system_applications = path == Path::new("/Applications")
        && unsafe {
            evx_xpc_system_applications_directory(metadata.uid(), metadata.gid(), metadata.mode())
                != 0
        };
    if !metadata.is_dir()
        || (metadata.mode() & 0o022 != 0
            && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
            && !system_applications)
        || ![0, uid].contains(&metadata.uid())
    {
        return Err(denied());
    }
    Ok(())
}
fn private_parents(path: &Path) -> Result<(), Denied> {
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(_) => safe_directory(&current)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(|_| denied())?;
                File::open(current.parent().ok_or_else(denied)?)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| denied())?;
            }
            Err(_) => return Err(denied()),
        }
    }
    Ok(())
}
fn provision(
    host: &str,
    slots: Vec<AppleServiceSlot>,
) -> Result<(AppleSlotRegistry, PathBuf), Denied> {
    let authority = crate::apple::authority_directory(host)?;
    let parent = authority.parent().ok_or_else(denied)?;
    private_parents(parent)?;
    let root = parent.join("EVXProduction");
    let inventory = AppleSlotInventory::new(slots.clone())?;
    let installation: [u8; 32] =
        Sha256::digest(format!("evx-apple-production-v1:{host}").as_bytes()).into();
    let registry_path = root.join("registry");
    let registry = match fs::symlink_metadata(&root) {
        Ok(metadata) => {
            safe_directory(&root)?;
            if metadata.mode() & 0o077 != 0 {
                return Err(denied());
            }
            AppleSlotRegistry::open(&registry_path, installation, inventory)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The exclusive directory is also a permanent interrupted-provision
            // barrier. A second host never treats a partial attempt as fresh.
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .map_err(|_| denied())?;
            File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(|_| denied())?;
            let containers = authority
                .ancestors()
                .find(|p| p.file_name().is_some_and(|n| n == "Containers"))
                .ok_or_else(denied)?;
            for slot in &slots {
                for role in [&slot.guest, &slot.compiler, &slot.file] {
                    match fs::symlink_metadata(containers.join(&role.service)) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                        _ => return Err(Denied::new("fresh Apple pool cannot be established: service container already exists or cannot be inspected")),
                    }
                }
            }
            AppleSlotRegistry::provision_fresh(&registry_path, installation, inventory)?
        }
        Err(_) => return Err(denied()),
    };
    Ok((registry, root.join("node-state")))
}
impl ApplePackage {
    /// Authenticate this running Developer ID host against the Team ID embedded
    /// at compilation by EPIX_EVX_TEAM_ID, then open its fixed private registry.
    pub fn current() -> Result<Self, Denied> {
        Self::load(false)
    }
    /// Explicit ad-hoc mechanics fixture. Production assembly never calls this.
    pub fn current_for_fixture() -> Result<Self, Denied> {
        Self::load(true)
    }
    fn load(fixture: bool) -> Result<Self, Denied> {
        let team = CString::new(env!("EVX_RELEASE_TEAM_ID")).map_err(|_| denied())?;
        let mut policy = Policy {
            bundle: [0; libc::PATH_MAX as usize],
            identifier: [0; 256],
            team: [0; 32],
            manifest_sha256: [0; 65],
        };
        // SAFETY: fixed-layout writable output and terminated immutable input.
        if unsafe { evx_apple_package_policy(fixture, team.as_ptr(), &mut policy) } != 0 {
            return Err(denied());
        }
        let host = text(&policy.identifier)?;
        if !identifier(host) {
            return Err(denied());
        }
        let bundle = Path::new(text(&policy.bundle)?);
        let path = bundle.join("Contents/Resources/evx-services.json");
        for parent in path.ancestors().skip(1) {
            safe_directory(parent)?;
        }
        let meta = fs::symlink_metadata(&path).map_err(|_| denied())?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o022 != 0
            || meta.len() > 128 * 1024
        {
            return Err(denied());
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| denied())?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| denied())?;
        if hex::encode(Sha256::digest(&bytes)) != text(&policy.manifest_sha256)? {
            return Err(denied());
        }
        let manifest: Manifest = evx_api::strict::parse_typed(&bytes).map_err(|_| denied())?;
        let profile = if fixture {
            "apple-xpc-fixture"
        } else {
            "apple-xpc-developer-id"
        };
        if manifest.schema != 1
            || manifest.profile != profile
            || manifest.host_identifier != host
            || manifest.team_identifier != text(&policy.team)?
        {
            return Err(denied());
        }
        for (n, slot) in manifest.slots.iter().enumerate() {
            if slot.slot != format!("slot-{n:03}") {
                return Err(denied());
            }
            for (name, role) in [
                ("guest", &slot.guest),
                ("compiler", &slot.compiler),
                ("file", &slot.file),
            ] {
                if role.service != format!("{host}.evx.{}.{name}", slot.slot) {
                    return Err(denied());
                }
            }
        }
        let (registry, state_root) = provision(host, manifest.slots)?;
        Ok(Self {
            registry,
            host_identifier: host.into(),
            state_root,
            profile: profile.into(),
        })
    }
}
