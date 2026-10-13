use std::collections::BTreeSet;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use evx_supervisor::apple_slots::{
    AppleServiceIdentity, AppleServiceSlot, AppleSlotInventory, AppleSlotRegistry, MAX_APPLE_SLOTS,
};

const INSTALLATION: [u8; 32] = [7; 32];

fn slots(count: usize) -> Vec<AppleServiceSlot> {
    (0..count)
        .map(|i| {
            let identity = |role| {
                let service = format!("com.example.evx.slot{i}.{role}");
                AppleServiceIdentity {
                    requirement: format!("identifier \"{service}\""),
                    service,
                }
            };
            AppleServiceSlot {
                slot: format!("slot-{i:02}"),
                guest: identity("guest"),
                compiler: identity("compiler"),
                file: identity("file"),
            }
        })
        .collect()
}

fn inventory(count: usize) -> AppleSlotInventory {
    AppleSlotInventory::new(slots(count)).unwrap()
}

fn fixture(count: usize) -> (tempfile::TempDir, AppleSlotRegistry) {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let registry = AppleSlotRegistry::provision_fresh(
        &temp.path().join("slots"),
        INSTALLATION,
        inventory(count),
    )
    .unwrap();
    (temp, registry)
}

#[test]
fn provisioning_requires_a_private_parent_and_a_new_directory() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = temp.path().join("slots");
    assert!(AppleSlotRegistry::provision_fresh(&path, INSTALLATION, inventory(1)).is_err());
    assert!(!path.exists());
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(AppleSlotRegistry::provision_fresh(&path, INSTALLATION, inventory(1)).is_err());
    assert!(std::fs::read_dir(&path).unwrap().next().is_none());
}

fn change_record(root: &Path, change: impl FnOnce(&mut serde_json::Value)) {
    let path = root.join("registry.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    change(&mut value);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn assignment_is_permanent_across_reopen_and_exhaustion() {
    let (temp, registry) = fixture(2);
    let identity = registry.identity().unwrap();
    assert!(registry.lookup("game-a").unwrap().is_none());
    let a = registry.allocate("game-a").unwrap();
    let b = registry.allocate("game-b").unwrap();
    assert_eq!(a.xite(), "game-a");
    assert_ne!(a.services().slot, b.services().slot);
    assert_eq!(registry.allocate("game-a").unwrap(), a);
    assert!(registry.allocate("game-c").is_err());
    drop(registry);
    let reopened =
        AppleSlotRegistry::open(&temp.path().join("slots"), INSTALLATION, inventory(2)).unwrap();
    assert_eq!(reopened.identity().unwrap(), identity);
    assert_eq!(reopened.allocate("game-a").unwrap(), a);
    assert_eq!(reopened.lookup("game-b").unwrap(), Some(b));
    assert!(reopened.allocate("game-c").is_err());
    let (_other_temp, other) = fixture(2);
    assert_ne!(other.identity().unwrap(), identity);
}

#[test]
fn inventory_rejects_duplicate_role_container_and_slot_identities() {
    let mut definitions = slots(2);
    definitions[1].compiler.service = definitions[0].guest.service.clone();
    assert!(AppleSlotInventory::new(definitions).is_err());
    let mut definitions = slots(2);
    definitions[1].file.service = definitions[0].guest.service.to_uppercase();
    assert!(AppleSlotInventory::new(definitions).is_err());
    let mut definitions = slots(2);
    definitions[1].slot = definitions[0].slot.clone();
    assert!(AppleSlotInventory::new(definitions).is_err());
    assert!(AppleSlotInventory::new(vec![]).is_err());
    assert!(AppleSlotInventory::new(slots(MAX_APPLE_SLOTS + 1)).is_err());
}

#[test]
fn invalid_and_oversized_trusted_identity_inputs_refuse() {
    for service in [
        "no-dot".into(),
        "a..b".into(),
        "a/b.c".into(),
        "a.\0b".into(),
        "x".repeat(256),
    ] {
        let mut definitions = slots(1);
        definitions[0].guest.service = service;
        assert!(AppleSlotInventory::new(definitions).is_err());
    }
    for requirement in [String::new(), "x".repeat(2049), "bad\0requirement".into()] {
        let mut definitions = slots(1);
        definitions[0].guest.requirement = requirement;
        assert!(AppleSlotInventory::new(definitions).is_err());
    }
    let (_temp, registry) = fixture(1);
    assert!(registry.allocate("../other").is_err());
    assert!(registry.lookup("").is_err());
}

#[test]
fn changed_inventory_refuses_but_trusted_signing_policy_upgrade_preserves_assignment() {
    let (temp, registry) = fixture(2);
    let original = registry.allocate("game-a").unwrap();
    let path = temp.path().join("slots");
    assert!(AppleSlotRegistry::open(&path, INSTALLATION, inventory(3)).is_err());
    assert!(AppleSlotRegistry::open(&path, [8; 32], inventory(2)).is_err());
    let mut changed = slots(2);
    changed[0].guest.service = "com.example.different.guest".into();
    assert!(AppleSlotRegistry::open(
        &path,
        INSTALLATION,
        AppleSlotInventory::new(changed).unwrap()
    )
    .is_err());
    let mut upgraded = slots(2);
    upgraded[0]
        .guest
        .requirement
        .push_str(" and anchor apple generic");
    upgraded.reverse(); // Input order is not pool identity.
    let reopened = AppleSlotRegistry::open(
        &path,
        INSTALLATION,
        AppleSlotInventory::new(upgraded).unwrap(),
    )
    .unwrap();
    let after = reopened.allocate("game-a").unwrap();
    assert_eq!(after.services().slot, original.services().slot);
    assert_eq!(
        after.services().guest.service,
        original.services().guest.service
    );
    assert_ne!(
        after.services().guest.requirement,
        original.services().guest.requirement
    );
}

#[test]
fn missing_state_lock_and_directory_are_never_recreated() {
    for missing in ["registry.json", "registry.lock"] {
        let (temp, registry) = fixture(1);
        registry.allocate("game-a").unwrap();
        let path = temp.path().join("slots");
        std::fs::remove_file(path.join(missing)).unwrap();
        assert!(registry.allocate("game-b").is_err());
        assert!(AppleSlotRegistry::open(&path, INSTALLATION, inventory(1)).is_err());
        assert!(AppleSlotRegistry::provision_fresh(&path, INSTALLATION, inventory(1)).is_err());
        assert!(!path.join(missing).exists());
    }
    let (temp, registry) = fixture(1);
    let path = temp.path().join("slots");
    std::fs::remove_dir_all(&path).unwrap();
    assert!(registry.allocate("game-a").is_err());
    assert!(AppleSlotRegistry::open(&path, INSTALLATION, inventory(1)).is_err());
    assert!(!path.exists());
}

#[test]
fn corruption_duplicate_keys_unknown_fields_and_crash_leftovers_refuse() {
    for bytes in [
        b"not JSON".as_slice(),
        b"{\"version\":1,\"version\":1}".as_slice(),
        &[0xff],
    ] {
        let (temp, registry) = fixture(1);
        let path = temp.path().join("slots/registry.json");
        std::fs::write(&path, bytes).unwrap();
        assert!(registry.allocate("game-a").is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    let (temp, registry) = fixture(1);
    change_record(&temp.path().join("slots"), |value| {
        value["unknown"] = true.into()
    });
    assert!(registry.lookup("game-a").is_err());
    let (temp, registry) = fixture(1);
    std::fs::write(
        temp.path().join("slots/registry.pending"),
        b"interrupted write",
    )
    .unwrap();
    assert!(registry.allocate("game-a").is_err());
    assert!(temp.path().join("slots/registry.pending").exists());
}

#[test]
fn duplicate_out_of_pool_and_wrong_root_bindings_refuse() {
    for mutation in 0..4 {
        let (temp, registry) = fixture(2);
        registry.allocate("game-a").unwrap();
        change_record(&temp.path().join("slots"), |value| match mutation {
            0 => value["assignments"]["game-b"] = value["assignments"]["game-a"].clone(),
            1 => value["assignments"]["game-a"] = "slot-unknown".into(),
            2 => value["root_inode"] = 0.into(),
            _ => value["lock_inode"] = 0.into(),
        });
        assert!(registry.lookup("game-a").is_err());
    }
}

#[test]
fn unsafe_modes_symlinks_hardlinks_and_oversized_files_refuse() {
    for filename in ["registry.json", "registry.lock"] {
        let (temp, registry) = fixture(1);
        let path = temp.path().join("slots").join(filename);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(registry.allocate("game-a").is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, temp.path().join("extra-link")).unwrap();
        assert!(registry.allocate("game-a").is_err());
        std::fs::remove_file(temp.path().join("extra-link")).unwrap();
        std::fs::rename(&path, temp.path().join("old-file")).unwrap();
        symlink(temp.path().join("old-file"), &path).unwrap();
        assert!(registry.allocate("game-a").is_err());
    }
    let (temp, registry) = fixture(1);
    std::fs::write(
        temp.path().join("slots/registry.json"),
        vec![b' '; 128 * 1024 + 1],
    )
    .unwrap();
    assert!(registry.allocate("game-a").is_err());
    let (temp, registry) = fixture(1);
    std::fs::set_permissions(
        temp.path().join("slots"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(registry.lookup("game-a").is_err());
}

#[test]
fn replaced_directory_and_lock_do_not_reuse_old_authority() {
    let (temp, registry) = fixture(1);
    let path = temp.path().join("slots");
    std::fs::rename(&path, temp.path().join("old-slots")).unwrap();
    symlink(temp.path().join("old-slots"), &path).unwrap();
    assert!(registry.allocate("game-a").is_err());
    assert!(AppleSlotRegistry::open(&path, INSTALLATION, inventory(1)).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(registry.lookup("game-a").is_err());
    let (temp, registry) = fixture(1);
    let lock = temp.path().join("slots/registry.lock");
    std::fs::rename(&lock, temp.path().join("old-lock")).unwrap();
    std::fs::write(&lock, []).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(registry.allocate("game-a").is_err());
}

#[test]
fn one_handle_serializes_threads_without_lost_assignments() {
    let (_temp, registry) = fixture(8);
    let registry = Arc::new(registry);
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let registry = registry.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                registry.allocate(&format!("game-{i}")).unwrap()
            })
        })
        .collect();
    let assigned: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        assigned
            .iter()
            .map(|a| a.services().slot.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        8
    );
    for assignment in assigned {
        assert_eq!(
            registry.lookup(assignment.xite()).unwrap().as_ref(),
            Some(&assignment)
        );
    }
}

#[test]
fn simultaneous_same_xite_allocations_consume_only_one_slot() {
    let (temp, registry) = fixture(1);
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let handle =
                AppleSlotRegistry::open(&temp.path().join("slots"), INSTALLATION, inventory(1))
                    .unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                handle.allocate("game-a").unwrap()
            })
        })
        .collect();
    let expected = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(expected.iter().all(|assignment| assignment == &expected[0]));
    assert_eq!(
        registry.lookup("game-a").unwrap().as_ref(),
        Some(&expected[0])
    );
    assert!(registry.allocate("game-b").is_err());
}

#[test]
fn independent_processes_allocate_disjoint_permanent_slots() {
    let (temp, registry) = fixture(6);
    let children: Vec<_> = (0..6)
        .map(|i| {
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "allocation_subprocess", "--ignored"])
                .env("EVX_TEST_SLOT_ROOT", temp.path().join("slots"))
                .env("EVX_TEST_SLOT_XITE", format!("game-{i}"))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        if (0..6).all(|i| temp.path().join(format!("ready-game-{i}")).exists()) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // Release every child even if startup failed, then collect all exits.
    std::fs::write(temp.path().join("allocate-now"), []).unwrap();
    for child in children {
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    assert!(
        ready,
        "all independent processes must reach the allocation barrier"
    );
    let assigned: BTreeSet<_> = (0..6)
        .map(|i| {
            registry
                .lookup(&format!("game-{i}"))
                .unwrap()
                .unwrap()
                .services()
                .slot
                .clone()
        })
        .collect();
    assert_eq!(assigned.len(), 6);
}

#[test]
#[ignore = "subprocess fixture, invoked by independent_processes_allocate_disjoint_permanent_slots"]
fn allocation_subprocess() {
    let root = std::env::var_os("EVX_TEST_SLOT_ROOT").unwrap();
    let xite = std::env::var("EVX_TEST_SLOT_XITE").unwrap();
    let registry = AppleSlotRegistry::open(Path::new(&root), INSTALLATION, inventory(6)).unwrap();
    let parent = Path::new(&root).parent().unwrap();
    assert!(xite.starts_with("game-") && xite[5..].bytes().all(|b| b.is_ascii_digit()));
    std::fs::write(parent.join(format!("ready-{xite}")), []).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !parent.join("allocate-now").exists() {
        assert!(
            Instant::now() < deadline,
            "parent allocation barrier timeout"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let first = registry.allocate(&xite).unwrap();
    assert_eq!(registry.allocate(&xite).unwrap(), first);
}

#[test]
fn a_busy_host_lock_refuses_within_a_bounded_wait() {
    let (temp, registry) = fixture(1);
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(temp.path().join("slots/registry.lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let started = Instant::now();
    assert!(registry.allocate("game-a").is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    drop(lock);
    assert!(registry.lookup("game-a").unwrap().is_none());
}

#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
#[test]
fn assignment_builds_the_real_adapter_configuration() {
    let (temp, registry) = fixture(1);
    let assignment = registry.allocate("game-a").unwrap();
    let authority = temp.path().join("authority");
    let config = assignment.xpc_config(authority.clone());
    assert_eq!(config.guest_service, assignment.services().guest.service);
    assert_eq!(
        config.compiler_service,
        assignment.services().compiler.service
    );
    assert_eq!(
        config.guest_requirement,
        assignment.services().guest.requirement
    );
    assert_eq!(config.authority_directory, authority);
}
