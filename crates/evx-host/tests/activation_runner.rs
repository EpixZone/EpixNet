#![allow(clippy::field_reassign_with_default)]
#![cfg(any(target_os = "macos", target_os = "linux"))]
//! Signed fixture programs execute through the real contained supervisor.
//! Port of `test_activation_runner.py`, plus the two-phase admission fix.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use evx_activation::{sign_envelope, ActivationLoader, XiteGrant};
use evx_api::{Capability, Grant, Limits, Status};
use evx_host::run_activation;
use evx_supervisor::{Broker, Config, RunOptions};

const CALC: &str = r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#;

/// Build and locate `evx-worker` relative to this test binary's target dir;
/// the build is a no-op when fresh and never serves a stale worker.
fn worker_binary() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut command = std::process::Command::new(cargo);
        command
            .args(["build", "-p", "evx-worker", "--locked"])
            .current_dir(manifest.join("../.."));
        if evx_runtime::engine::backend_name().starts_with("pulley") {
            command.args(["--features", "evx-runtime/pulley"]);
        }
        if !cfg!(debug_assertions) {
            command.arg("--release");
        }
        assert!(command
            .status()
            .expect("cargo build -p evx-worker")
            .success());
        let exe = std::env::current_exe().unwrap();
        let profile_dir = exe.parent().and_then(std::path::Path::parent).unwrap();
        std::fs::canonicalize(profile_dir.join("evx-worker")).unwrap()
    })
    .clone()
}

fn call_wat(request: serde_json::Value) -> String {
    let payload = serde_json::to_vec(&request).unwrap();
    let data: String = payload.iter().map(|b| format!("\\{b:02x}")).collect();
    format!(
        r#"(module (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1) (data (i32.const 0) "{data}")
  (func (export "run") (result i32) i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call))"#,
        payload.len()
    )
}

struct Harness {
    _dir: tempfile::TempDir,
    artifacts: PathBuf,
    workspace: PathBuf,
    key: SigningKey,
    loader: ActivationLoader,
    broker: Broker,
    config: Config,
    body: serde_json::Value,
    envelope: Vec<u8>,
}

impl Harness {
    fn new() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let artifacts = root.join("published-artifacts");
        let workspace = root.join("private-workspace");
        std::fs::create_dir(&artifacts).unwrap();
        std::fs::create_dir(&workspace).unwrap();
        let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let public_key = key.verifying_key().to_bytes();
        let capabilities: BTreeSet<Capability> = Capability::all().into_iter().collect();
        let profiles: BTreeSet<String> = ["evx-core-v1".to_string()].into_iter().collect();
        let grant = XiteGrant::new(
            "game-one",
            "publisher-one",
            public_key,
            capabilities.clone(),
            profiles.clone(),
        )
        .unwrap();
        let loader = ActivationLoader::new(grant);
        let mut broker_grant = Grant::new("game-one", true).unwrap();
        broker_grant.publisher = Some("publisher-one".into());
        broker_grant.publisher_public_key = Some(public_key);
        broker_grant.runtime_profiles = profiles;
        let broker = Broker::new(&workspace, broker_grant, Limits::default()).unwrap();
        let mut harness = Harness {
            _dir: dir,
            artifacts,
            workspace,
            key,
            loader,
            broker,
            config: Config::new(worker_binary()),
            body: serde_json::Value::Null,
            envelope: Vec::new(),
        };
        harness.publish(CALC, 1, &[], true);
        harness
    }

    fn publish(&mut self, wat: &str, version: u64, capabilities: &[&str], binary: bool) {
        let data = if binary {
            evx_runtime::text_to_binary(wat).unwrap()
        } else {
            wat.as_bytes().to_vec()
        };
        let entry = if binary { "main.wasm" } else { "main.wat" };
        std::fs::write(self.artifacts.join(entry), &data).unwrap();
        self.body = serde_json::json!({
            "kind": "evx.activation.v1", "xite": "game-one", "publisher": "publisher-one",
            "version": version, "runtime_profile": "evx-core-v1", "entry": entry,
            "artifact_format": if binary { "wasm-core-v1" } else { "wat" },
            "files": { entry: evx_activation::digest(&data) },
            "capabilities": capabilities,
        });
        self.envelope = sign_envelope(&self.body, &self.key);
    }

    fn run(&mut self) -> evx_host::ActivationOutcome {
        self.run_with(RunOptions::default())
    }

    fn run_with(&mut self, options: RunOptions) -> evx_host::ActivationOutcome {
        run_activation(
            &self.config,
            &mut self.loader,
            &self.envelope,
            &self.artifacts,
            &self.broker,
            options,
        )
    }
}

fn assert_no_worker(outcome: &evx_host::ActivationOutcome) {
    assert_eq!(
        outcome.result.status,
        Status::Denied,
        "{:?}",
        outcome.result
    );
    assert!(!outcome.result.worker_started, "{:?}", outcome.result);
    assert!(outcome.activation.is_none());
}

#[test]
fn signed_core_wasm_and_wat_execute_in_contained_worker() {
    let mut h = Harness::new();
    let outcome = h.run();
    assert_eq!(outcome.result.status, Status::Ok, "{:?}", outcome.result);
    assert_eq!(outcome.result.value, Some(42));
    assert_eq!(outcome.result.worker_exit_code, Some(0));
    assert_eq!(
        outcome.activation.as_ref().unwrap().publisher,
        "publisher-one"
    );
    h.publish(CALC, 2, &[], false);
    let outcome = h.run();
    assert_eq!(outcome.result.value, Some(42), "{:?}", outcome.result);
    assert_eq!(outcome.activation.as_ref().unwrap().artifact_format, "wat");
}

#[test]
fn same_grant_authenticated_update_executes_without_new_approval() {
    let mut h = Harness::new();
    assert_eq!(h.run().result.value, Some(42));
    h.publish(&CALC.replace("i32.const 23", "i32.const 24"), 2, &[], true);
    let outcome = h.run();
    assert_eq!(outcome.result.value, Some(43), "{:?}", outcome.result);
    assert_eq!(outcome.activation.as_ref().unwrap().grant_generation, 1);
    assert_eq!(h.loader.checkpoint().version, 2);
}

#[test]
fn declared_capability_reaches_broker_and_undeclared_one_is_refused() {
    let mut h = Harness::new();
    h.publish(
        &call_wat(serde_json::json!({"op": "game.score.get"})),
        1,
        &["game.score.get"],
        true,
    );
    let outcome = h.run();
    assert_eq!(outcome.result.status, Status::Ok, "{:?}", outcome.result);
    assert_eq!(
        outcome.result.responses,
        vec![evx_api::Response::Score {
            ok: true,
            score: 42
        }]
    );
    h.publish(
        &call_wat(
            serde_json::json!({"op": "workspace.write", "path": "forbidden.txt", "text": "no"}),
        ),
        2,
        &["game.score.get"],
        true,
    );
    let outcome = h.run();
    assert_eq!(outcome.result.status, Status::Ok, "{:?}", outcome.result);
    assert!(!outcome.result.responses[0].is_ok());
    assert!(!h.workspace.join("forbidden.txt").exists());
}

#[test]
fn declared_authorized_write_uses_private_workspace_not_artifact_root() {
    let mut h = Harness::new();
    h.publish(
        &call_wat(
            serde_json::json!({"op": "workspace.write", "path": "state.txt", "text": "score=42"}),
        ),
        1,
        &["workspace.write"],
        true,
    );
    let outcome = h.run();
    assert_eq!(outcome.result.status, Status::Ok, "{:?}", outcome.result);
    assert!(outcome.result.responses[0].is_ok());
    assert_eq!(
        std::fs::read_to_string(h.workspace.join("state.txt")).unwrap(),
        "score=42"
    );
    assert!(!h.artifacts.join("state.txt").exists());
}

#[test]
fn signature_failure_and_revoked_grant_start_no_worker() {
    let mut h = Harness::new();
    let impostor = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    h.envelope = sign_envelope(&h.body, &impostor);
    assert_no_worker(&h.run());
    let mut h = Harness::new();
    h.broker.revoke();
    assert_no_worker(&h.run());
}

#[test]
fn xite_publisher_key_generation_and_profile_mismatches_deny() {
    let mut h = Harness::new();
    let original = h.broker.grant();
    let other_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>())
        .verifying_key()
        .to_bytes();
    type GrantMutation = Box<dyn Fn(&mut Grant)>;
    let mutations: Vec<GrantMutation> = vec![
        Box::new(|g| g.xite = "other-game".into()),
        Box::new(|g| g.publisher = Some("other-publisher".into())),
        Box::new(|g| g.generation = 2),
        Box::new(move |g| g.publisher_public_key = Some(other_key)),
        Box::new(|g| g.runtime_profiles = BTreeSet::new()),
    ];
    for mutate in mutations {
        h.broker.with_grant(|g| {
            *g = original.clone();
            mutate(g);
        });
        assert_no_worker(&h.run());
    }
    h.broker.with_grant(|g| *g = original.clone());
    assert_eq!(h.run().result.value, Some(42));
}

#[test]
fn capability_expansion_and_grant_narrowing_deny_without_advancing_floor() {
    let mut h = Harness::new();
    assert_eq!(h.run().result.value, Some(42));
    assert_eq!(h.loader.checkpoint().version, 1);
    // Beyond the loader grant: a capability that does not exist in the closed set.
    let mut body = h.body.clone();
    body["version"] = serde_json::json!(2);
    body["capabilities"] = serde_json::json!(["chain.sign"]);
    h.envelope = sign_envelope(&body, &h.key);
    assert_no_worker(&h.run());
    assert_eq!(
        h.loader.checkpoint().version,
        1,
        "denied activation advanced the floor"
    );
    // Within the loader grant but beyond the broker's current grant.
    h.publish(
        &call_wat(serde_json::json!({"op": "game.score.get"})),
        3,
        &["game.score.get"],
        true,
    );
    h.broker
        .with_grant(|g| g.capabilities = [Capability::WorkspaceRead].into_iter().collect());
    assert_no_worker(&h.run());
    assert_eq!(
        h.loader.checkpoint().version,
        1,
        "denied binding advanced the floor"
    );
    // The previous version is still runnable.
    h.broker
        .with_grant(|g| g.capabilities = Capability::all().into_iter().collect());
    h.publish(CALC, 1, &[], true);
    assert_eq!(h.run().result.value, Some(42));
}

#[test]
fn replaced_entry_is_not_reopened_by_runner() {
    let mut h = Harness::new();
    let original = std::fs::read(h.artifacts.join("main.wasm")).unwrap();
    // Verify captures the bytes; swap the file before admission and execution.
    let pending = h.loader.verify(&h.envelope, &h.artifacts).unwrap();
    std::fs::write(h.artifacts.join("main.wasm"), b"not an executable artifact").unwrap();
    drop(pending);
    // run_activation re-verifies from the (now replaced) file and must refuse,
    // because the digest no longer matches the signed manifest.
    assert_no_worker(&h.run());
    std::fs::write(h.artifacts.join("main.wasm"), &original).unwrap();
    assert_eq!(h.run().result.value, Some(42));
}

#[test]
fn runtime_revocation_blocks_signed_program_effect() {
    let mut h = Harness::new();
    h.publish(
        &call_wat(
            serde_json::json!({"op": "workspace.write", "path": "revoked.txt", "text": "no"}),
        ),
        1,
        &["workspace.write"],
        true,
    );
    let outcome = h.run_with(RunOptions {
        revoke_before_call: Some(1),
        ..Default::default()
    });
    assert!(outcome.result.worker_started);
    assert!(!outcome.result.responses[0].is_ok(), "{:?}", outcome.result);
    assert!(!h.workspace.join("revoked.txt").exists());
}

#[test]
fn rollback_to_an_older_version_is_refused() {
    let mut h = Harness::new();
    h.publish(CALC, 2, &[], true);
    assert_eq!(h.run().result.value, Some(42));
    h.publish(CALC, 1, &[], true);
    assert_no_worker(&h.run());
    assert_eq!(h.loader.checkpoint().version, 2);
}

#[test]
fn busy_workspace_does_not_advance_activation_floor() {
    let mut h = Harness::new();
    h.broker.lock().running = true;
    let outcome = h.run();
    h.broker.lock().running = false;
    assert_eq!(outcome.result.status, Status::Denied, "{outcome:?}");
    assert_eq!(
        h.loader.checkpoint().version,
        0,
        "busy denial advanced the floor"
    );
    assert!(outcome.activation.is_none(), "{outcome:?}");
}

#[test]
fn text_parsing_is_deferred_to_the_confined_compiler() {
    let mut h = Harness::new();
    h.publish("(module invalid syntax", 1, &[], false);
    h.config.worker_binary = h.workspace.join("missing-compiler");
    let outcome = h.run();
    assert_no_worker(&outcome);
    assert!(
        outcome
            .result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("worker launch failed"),
        "text was parsed in the host: {outcome:?}"
    );
    assert_eq!(h.loader.checkpoint().version, 0);
}

#[test]
fn revocation_cancels_an_active_compiler() {
    let mut h = Harness::new();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    assert!(std::process::Command::new(cargo)
        .args(["build", "-p", "evx-supervisor", "--example", "hostile_peer"])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .status()
        .unwrap()
        .success());
    let exe = std::env::current_exe().unwrap();
    h.config.worker_binary = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("examples/hostile_peer");
    h.config.worker_args = vec!["unread_init".into()];
    let changed = std::sync::Mutex::new(None);
    let outcome = std::thread::scope(|scope| {
        let broker = &h.broker;
        let config = &h.config;
        let loader = &mut h.loader;
        let envelope = &h.envelope;
        let artifacts = &h.artifacts;
        let handle = scope.spawn(move || {
            run_activation(
                config,
                loader,
                envelope,
                artifacts,
                broker,
                Default::default(),
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(200));
        *changed.lock().unwrap() = Some(std::time::Instant::now());
        h.broker.revoke();
        handle.join().unwrap()
    });
    assert!(
        changed.lock().unwrap().unwrap().elapsed() < std::time::Duration::from_millis(600),
        "compiler ignored revocation: {outcome:?}"
    );
    assert_no_worker(&outcome);
    assert_eq!(
        outcome.result.host_cancellation,
        Some(evx_api::HostCancellation::AuthorityChanged)
    );
    assert_eq!(h.loader.checkpoint().version, 0);
}

#[test]
fn host_binding_policy_changes_report_cancellation() {
    let mut outcomes = Vec::new();
    for change_generation in [false, true] {
        let mut h = Harness::new();
        if change_generation {
            h.broker.with_grant(|grant| grant.generation += 1);
        } else {
            h.broker.revoke();
        }
        let outcome = h.run();
        outcomes.push((
            outcome.result.status,
            outcome.result.host_cancellation,
            outcome.result.worker_started,
        ));
    }
    assert_eq!(
        outcomes,
        vec![
            (
                Status::Denied,
                Some(evx_api::HostCancellation::AuthorityChanged),
                false
            );
            2
        ]
    );
}

#[test]
fn compiler_cleanup_uncertainty_stops_process_admission() {
    const CHILD: &str = "EVX_COMPILER_QUARANTINE_FIXTURE";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "compiler_cleanup_uncertainty_stops_process_admission",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut h = Harness::new();
    // Capture one valid artifact before the irreversible test-process latch.
    let artifact =
        evx_supervisor::compile_module(&h.config, &evx_runtime::text_to_binary(CALC).unwrap())
            .unwrap();
    h.config.fail_compiler_cleanup = true;
    let first = h.run();
    // A missing executable proves a later refusal happens before launch.
    h.config.fail_compiler_cleanup = false;
    h.config.worker_binary = PathBuf::from("/missing-evx-quarantine-fixture");
    let second = h.run();
    let other = Harness::new();
    let guest =
        evx_supervisor::run_guest(&h.config, &artifact, &other.broker, RunOptions::default());
    assert_eq!(
        (first.result.status, second.result.status, guest.status),
        (
            Status::Quarantined,
            Status::Quarantined,
            Status::Quarantined
        ),
        "first={first:?}, second={second:?}, guest={guest:?}"
    );
    assert!(!first.result.worker_started && !second.result.worker_started && !guest.worker_started);
    assert!(second.result.error.unwrap().contains("quarantin"));
    assert_eq!(h.loader.checkpoint().version, 0);
}
