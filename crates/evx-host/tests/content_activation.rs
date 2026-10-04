#![cfg(any(target_os = "macos", target_os = "linux"))]
//! A xite's signed content.json runs one declared program through the real
//! contained supervisor: the owner key signs the manifest the way the node
//! does, `evx-declaration` parses and binds it from the stored bytes, and
//! `run_content_activation` captures, compiles, admits and executes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use evx_activation::{sha512_prefix, ActivationLoader, AuthenticationError, XiteGrant};
use evx_api::{Capability, Grant, Limits, Status};
use evx_host::{run_content_activation, ActivationOutcome};
use evx_supervisor::{Broker, Config, RunOptions};
use serde_json::{json, Value};

const CALC: &str = r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#;
const ENTRY_PATH: &str = "evx/main.wasm";
const PROGRAM_ID: &str = "calc";
const PROFILE: &str = "wasm-core-v1";
const MODIFIED: f64 = 1_700_000_000.0;

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

fn call_wat(request: Value) -> String {
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
    workspace: PathBuf,
    key: String,
    address: String,
    loader: ActivationLoader,
    broker: Broker,
    config: Config,
    /// The unsigned document; `run` signs it.
    content: Value,
    /// The xite's stored files, standing in for `XiteStorage`.
    files: BTreeMap<String, Vec<u8>>,
}

impl Harness {
    fn new() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let workspace = root.join("private-workspace");
        std::fs::create_dir(&workspace).unwrap();
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let capabilities: BTreeSet<Capability> = Capability::all().into_iter().collect();
        let profiles: BTreeSet<String> = [PROFILE.to_string()].into_iter().collect();
        let grant = XiteGrant::for_root_address(
            address.clone(),
            address.clone(),
            capabilities,
            profiles.clone(),
        )
        .unwrap();
        let loader = ActivationLoader::new(grant);
        let mut broker_grant = Grant::new(address.clone(), true).unwrap();
        broker_grant.publisher = Some(address.clone());
        broker_grant.publisher_public_key = None;
        broker_grant.runtime_profiles = profiles;
        let broker = Broker::new(&workspace, broker_grant, Limits::default()).unwrap();
        let mut harness = Harness {
            _dir: dir,
            workspace,
            key,
            address,
            loader,
            broker,
            config: Config::new(worker_binary()),
            content: Value::Null,
            files: BTreeMap::new(),
        };
        harness.publish(CALC, MODIFIED, &[]);
        harness
    }

    /// Store the compiled program and publish a content.json declaring it.
    fn publish(&mut self, wat: &str, modified: f64, capabilities: &[&str]) {
        let data = evx_runtime::text_to_binary(wat).unwrap();
        self.files.insert(ENTRY_PATH.to_string(), data.clone());
        let requested: Vec<Value> = capabilities
            .iter()
            .map(|api| json!({ "api": api }))
            .collect();
        self.content = json!({
            "address": self.address,
            "title": "Calc",
            "modified": modified,
            "files": {
                ENTRY_PATH: { "size": data.len(), "sha512": sha512_prefix(&data) },
            },
            "evx": {
                "version": 1,
                "programs": {
                    PROGRAM_ID: {
                        "runtime_profile": PROFILE,
                        "entry": ENTRY_PATH,
                        "allow_run_once": true,
                        "capabilities": requested,
                    }
                }
            }
        });
    }

    /// The stored content.json bytes, signed by the owner.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut signed = self.content.clone();
        epix_content::sign(&mut signed, &self.key).unwrap();
        epix_content::dumps_content(&signed).into_bytes()
    }

    fn run(&mut self) -> ActivationOutcome {
        self.run_with(RunOptions::default())
    }

    /// What the node does: read the bytes, verify the signer, parse and
    /// bind from the bytes, then hand the loader the decoded value.
    fn run_with(&mut self, options: RunOptions) -> ActivationOutcome {
        let raw = self.signed_bytes();
        let content: Value = serde_json::from_slice(&raw).unwrap();
        assert!(epix_content::verify_signer(&content, &self.address));
        let declaration = evx_declaration::parse_bytes(&raw).unwrap().unwrap();
        let bound = evx_declaration::bind(&declaration, PROGRAM_ID, &content).unwrap();
        let files = &self.files;
        let mut read = |path: &str| {
            files
                .get(path)
                .cloned()
                .ok_or_else(|| AuthenticationError::new("file unavailable"))
        };
        run_content_activation(
            &self.config,
            &mut self.loader,
            &content,
            &bound,
            &mut read,
            &self.broker,
            options,
        )
    }
}

fn assert_no_worker(outcome: &ActivationOutcome) {
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
fn signed_content_program_executes_in_contained_worker() {
    let mut h = Harness::new();
    let raw = h.signed_bytes();
    let outcome = h.run();
    assert_eq!(outcome.result.status, Status::Ok, "{:?}", outcome.result);
    assert_eq!(outcome.result.value, Some(42));
    assert_eq!(outcome.result.worker_exit_code, Some(0));
    let report = outcome.activation.unwrap();
    assert_eq!(report.xite, h.address);
    assert_eq!(report.publisher, h.address);
    assert_eq!(report.version, 1_700_000_000_000);
    assert_eq!(report.grant_generation, 1);
    assert_eq!(report.runtime_profile, PROFILE);
    assert_eq!(report.artifact_format, "wasm-core-v1");
    assert_eq!(report.program.as_deref(), Some(PROGRAM_ID));
    assert_eq!(
        report.declaration_digest,
        evx_declaration::declaration_digest_bytes(&raw).unwrap()
    );
    assert_eq!(h.loader.checkpoint().version, 1_700_000_000_000);
    assert_eq!(
        h.loader.checkpoint().manifest_digest.as_deref(),
        Some(report.manifest_digest.as_str())
    );
}

#[test]
fn same_grant_authenticated_update_executes_without_new_approval() {
    let mut h = Harness::new();
    assert_eq!(h.run().result.value, Some(42));
    let before = h.loader.grant().clone();
    h.publish(
        &CALC.replace("i32.const 23", "i32.const 24"),
        MODIFIED + 60.0,
        &[],
    );
    let outcome = h.run();
    assert_eq!(outcome.result.value, Some(43), "{:?}", outcome.result);
    assert_eq!(outcome.activation.as_ref().unwrap().grant_generation, 1);
    assert_eq!(h.loader.grant(), &before);
    assert_eq!(h.loader.checkpoint().version, 1_700_000_060_000);
}

#[test]
fn tampered_file_and_missing_file_start_no_worker_and_keep_the_floor() {
    let mut h = Harness::new();
    assert_eq!(h.run().result.value, Some(42));
    let floor = h.loader.checkpoint().clone();
    h.publish(CALC, MODIFIED + 1.0, &[]);
    let signed = h.files[ENTRY_PATH].clone();
    // Bytes swapped after signing.
    h.files.insert(
        ENTRY_PATH.to_string(),
        evx_runtime::text_to_binary(&CALC.replace("i32.const 23", "i32.const 0")).unwrap(),
    );
    assert_no_worker(&h.run());
    assert_eq!(h.loader.checkpoint(), &floor);
    // File gone from the store.
    h.files.remove(ENTRY_PATH);
    assert_no_worker(&h.run());
    assert_eq!(h.loader.checkpoint(), &floor);
    // Restored, the update runs.
    h.files.insert(ENTRY_PATH.to_string(), signed);
    assert_eq!(h.run().result.value, Some(42));
    assert_eq!(h.loader.checkpoint().version, floor.version + 1_000);
}

#[test]
fn rollback_to_an_older_modified_is_refused() {
    let mut h = Harness::new();
    h.publish(CALC, MODIFIED + 100.0, &[]);
    assert_eq!(h.run().result.value, Some(42));
    h.publish(CALC, MODIFIED, &[]);
    assert_no_worker(&h.run());
    assert_eq!(h.loader.checkpoint().version, 1_700_000_100_000);
}

#[test]
fn declared_capability_reaches_broker_and_undeclared_one_is_refused() {
    let mut h = Harness::new();
    h.publish(
        &call_wat(json!({"op": "game.score.get"})),
        MODIFIED + 1.0,
        &["game.score.get"],
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
        &call_wat(json!({"op": "workspace.write", "path": "forbidden.txt", "text": "no"})),
        MODIFIED + 2.0,
        &["game.score.get"],
    );
    let outcome = h.run();
    assert_eq!(outcome.result.status, Status::Ok, "{:?}", outcome.result);
    assert!(!outcome.result.responses[0].is_ok());
    assert!(!h.workspace.join("forbidden.txt").exists());
}

#[test]
fn capability_beyond_grant_stays_denied_until_a_new_grant_is_used() {
    let mut h = Harness::new();
    assert_eq!(h.run().result.value, Some(42));
    let floor = h.loader.checkpoint().clone();
    // Beyond the loader grant.
    let narrow = XiteGrant::for_root_address(
        h.address.clone(),
        h.address.clone(),
        [Capability::WorkspaceRead].into_iter().collect(),
        h.loader.grant().runtime_profiles.clone(),
    )
    .unwrap();
    h.loader = ActivationLoader::with_checkpoint(narrow, floor.clone());
    h.publish(
        &call_wat(json!({"op": "game.score.get"})),
        MODIFIED + 1.0,
        &["game.score.get"],
    );
    assert_no_worker(&h.run());
    assert_eq!(
        h.loader.checkpoint(),
        &floor,
        "denied activation advanced the floor"
    );
    assert_no_worker(&h.run());
    assert_eq!(h.loader.checkpoint(), &floor);
    // Within the loader grant but beyond the broker's current grant.
    let wide = XiteGrant::for_root_address(
        h.address.clone(),
        h.address.clone(),
        Capability::all().into_iter().collect(),
        h.loader.grant().runtime_profiles.clone(),
    )
    .unwrap();
    h.loader = ActivationLoader::with_checkpoint(wide, floor.clone());
    h.broker
        .with_grant(|g| g.capabilities = [Capability::WorkspaceRead].into_iter().collect());
    assert_no_worker(&h.run());
    assert_eq!(
        h.loader.checkpoint(),
        &floor,
        "denied binding advanced the floor"
    );
    // A grant carrying the capability admits the same publication.
    h.broker
        .with_grant(|g| g.capabilities = Capability::all().into_iter().collect());
    let outcome = h.run();
    assert_eq!(outcome.result.status, Status::Ok, "{:?}", outcome.result);
    assert_eq!(h.loader.checkpoint().version, floor.version + 1_000);
}

#[test]
fn runtime_profile_beyond_grant_denies_without_advancing_floor() {
    let mut h = Harness::new();
    assert_eq!(h.run().result.value, Some(42));
    let floor = h.loader.checkpoint().clone();
    h.publish(CALC, MODIFIED + 1.0, &[]);
    h.content["evx"]["programs"][PROGRAM_ID]["runtime_profile"] = json!("wasm-core-v2");
    // The declaration parser marks the program unsupported, so binding
    // fails before the loader; the host never sees a pending activation.
    let raw = h.signed_bytes();
    let declaration = evx_declaration::parse_bytes(&raw).unwrap().unwrap();
    assert!(!declaration.programs.contains_key(PROGRAM_ID));
    assert!(evx_declaration::bind(
        &declaration,
        PROGRAM_ID,
        &serde_json::from_slice(&raw).unwrap()
    )
    .is_err());
    // A broker whose grant lost the profile denies a usable program too.
    h.content["evx"]["programs"][PROGRAM_ID]["runtime_profile"] = json!(PROFILE);
    h.broker
        .with_grant(|g| g.runtime_profiles = BTreeSet::new());
    assert_no_worker(&h.run());
    assert_eq!(h.loader.checkpoint(), &floor);
}

#[test]
fn publisher_binding_mismatch_and_revocation_start_no_worker() {
    let mut h = Harness::new();
    let original = h.broker.grant();
    let other = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    type Mutation = Box<dyn Fn(&mut Grant)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(move |g| g.publisher = Some(other.clone())),
        Box::new(|g| g.publisher = None),
        // A root-address grant binds to no key; a broker that claims one
        // describes a different authority.
        Box::new(|g| g.publisher_public_key = Some([7; 32])),
        Box::new(|g| g.xite = "other-xite".into()),
        Box::new(|g| g.generation = 2),
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
    h.broker.revoke();
    assert_no_worker(&h.run());
}

#[test]
fn unsigned_content_is_refused_by_the_node_not_the_host() {
    // The host trusts the caller's signature check; this test shows the
    // check the node must make, so a harness never mistakes the host for it.
    let h = Harness::new();
    let unsigned: Value = h.content.clone();
    assert!(!epix_content::verify_signer(&unsigned, &h.address));
    let stranger = epix_crypt::new_seed();
    let mut foreign = h.content.clone();
    epix_content::sign(&mut foreign, &stranger).unwrap();
    assert!(!epix_content::verify_signer(&foreign, &h.address));
    let signed: Value = serde_json::from_slice(&h.signed_bytes()).unwrap();
    assert!(epix_content::verify_signer(&signed, &h.address));
}
