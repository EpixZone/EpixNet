#![cfg(all(target_os = "macos", feature = "apple-xpc"))]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;

use evx_activation::{ActivationLoader, XiteGrant};
use evx_api::{Grant, Limits, Status};
use evx_supervisor::apple_slots::{AppleServiceIdentity, AppleServiceSlot, AppleSlotInventory, AppleSlotRegistry};
use evx_supervisor::apple_workspace::AppleWorkspace;
use evx_supervisor::{Broker, RunOptions};

#[test]
fn substituted_backend_is_rejected_before_compiler_admission() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let identity = |role| AppleServiceIdentity {
        service: format!("org.example.no-installed-service.{role}"),
        requirement: "anchor apple".into(),
    };
    let registry = AppleSlotRegistry::provision_fresh(&temp.path().join("registry"), [7;32],
        AppleSlotInventory::new(vec![AppleServiceSlot { slot: "first".into(), guest: identity("guest"),
            compiler: identity("compiler"), file: identity("file") }]).unwrap()).unwrap();
    let assignment = registry.allocate("other-game").unwrap();
    let workspace = AppleWorkspace::open(assignment).unwrap();
    let authority = temp.path().join("authority");
    std::fs::create_dir(&authority).unwrap();
    std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = workspace.config(authority);

    let key = ed25519_dalek::SigningKey::from_bytes(&[12;32]);
    let public = key.verifying_key().to_bytes();
    let profiles = ["evx-core-v1".to_string()].into_iter().collect();
    let grant = XiteGrant::new("game", "publisher", public, BTreeSet::new(), profiles).unwrap();
    let mut loader = ActivationLoader::new(grant);
    let mut grant = Grant::new("game", true).unwrap();
    grant.publisher = Some("publisher".into());
    grant.publisher_public_key = Some(public);
    grant.runtime_profiles.insert("evx-core-v1".into());
    let direct = temp.path().join("direct");
    std::fs::create_dir(&direct).unwrap();
    let broker = Broker::new(&direct, grant, Limits::default()).unwrap();
    let bytes = evx_runtime::text_to_binary(r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 42))"#).unwrap();
    std::fs::write(temp.path().join("game.wasm"), &bytes).unwrap();
    let envelope = evx_activation::sign_envelope(&serde_json::json!({
        "kind":"evx.activation.v1", "xite":"game", "publisher":"publisher", "version":1,
        "runtime_profile":"evx-core-v1", "entry":"game.wasm", "artifact_format":"wasm-core-v1",
        "files":{"game.wasm":evx_activation::digest(&bytes)}, "capabilities":[]
    }), &key);
    let outcome = evx_host::run_activation(&config, &mut loader, &envelope, temp.path(), &broker, RunOptions::default());
    let journal: serde_json::Value = serde_json::from_slice(&std::fs::read(temp.path().join("registry/workspaces/first/lifecycle.json")).unwrap()).unwrap();
    assert!(journal["active"].as_object().unwrap().is_empty(), "substituted backend reached compiler admission: {journal}");
    assert_eq!(outcome.result.status, Status::Denied, "{:?}", outcome.result);
    assert!(!outcome.result.worker_started);
    assert!(outcome.activation.is_none());
}
