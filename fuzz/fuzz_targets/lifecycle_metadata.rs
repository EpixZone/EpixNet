#![no_main]

use std::os::unix::fs::{symlink, PermissionsExt};

use evx_supervisor::direct_lifecycle::DirectLifecycle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 65_537 {
        return;
    }
    // This exercises corrupt host-control metadata and refusal paths. It
    // never launches a compiler or worker and never uses an existing root.
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().join("lifecycle");
    let original = DirectLifecycle::provision_fresh(&root).unwrap();
    let neighbor = temp.path().join("game-score");
    std::fs::write(&neighbor, b"score=42").unwrap();
    let target = root.join(if data[0] & 1 == 0 { "lifecycle.json" } else { "binding.json" });
    let unsafe_metadata = match (data[0] >> 1) % 5 {
        0 => {
            std::fs::write(&target, &data[1..]).unwrap();
            false
        }
        1 => {
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
            true
        }
        2 => {
            std::fs::remove_file(&target).unwrap();
            symlink(&neighbor, &target).unwrap();
            true
        }
        3 => {
            std::fs::remove_file(&target).unwrap();
            std::fs::hard_link(&neighbor, &target).unwrap();
            true
        }
        _ => {
            std::fs::write(root.join("lifecycle.pending"), &data[1..]).unwrap();
            true
        }
    };
    let reopened = DirectLifecycle::open(&root);
    if unsafe_metadata {
        assert!(reopened.is_err());
        assert!(original.validate().is_err());
    } else if let Ok(context) = reopened {
        context.validate().unwrap();
        assert_eq!(context.scope("game").unwrap().xite(), "game");
    }
    assert_eq!(std::fs::read(&neighbor).unwrap(), b"score=42");
});
