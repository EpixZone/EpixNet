//! Shared fixtures for supervisor integration tests. All workspaces are
//! disposable temporary directories; all guest programs are synthetic.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;

use evx_api::{Capability, Grant, Limits, RunResult};
use evx_supervisor::{compile_module, run_guest, Broker, CompiledArtifact, Config, RunOptions};

pub const PAGE: usize = 65_536;

/// Locate the worker binary, building it once if the test runner has not.
pub fn worker_binary() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target = manifest.join("../../target/debug/evx-worker");
        if !target.exists() {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
            let status = std::process::Command::new(cargo)
                .args(["build", "-p", "evx-worker"])
                .current_dir(manifest.join("../.."))
                .status()
                .expect("cargo build -p evx-worker");
            assert!(status.success(), "building evx-worker failed");
        }
        std::fs::canonicalize(target).expect("evx-worker binary")
    })
    .clone()
}

pub fn config() -> Config {
    Config::new(worker_binary())
}

pub fn calc() -> &'static str {
    r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#
}

pub fn infinite_loop() -> &'static str {
    r#"(module (memory (export "memory") 1) (func (export "run") (result i32) (loop $forever br $forever) i32.const 0))"#
}

pub fn memory_grow(delta_pages: i32) -> String {
    format!(
        r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const {delta_pages} memory.grow))"#
    )
}

fn wat_bytes(payload: &[u8]) -> String {
    payload.iter().map(|b| format!("\\{b:02x}")).collect()
}

/// One broker call with optional pointer overrides for boundary fixtures.
pub fn call_wat_raw(
    payload: &[u8],
    req_ptr: i32,
    req_len: Option<i32>,
    out_ptr: i32,
    out_cap: i32,
) -> String {
    let req_len = req_len.unwrap_or(payload.len() as i32);
    let pages = payload.len().div_ceil(PAGE).max(1);
    format!(
        r#"(module
  (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") {pages})
  (data (i32.const 0) "{}")
  (func (export "run") (result i32)
    i32.const {req_ptr} i32.const {req_len} i32.const {out_ptr} i32.const {out_cap} call $call))"#,
        wat_bytes(payload)
    )
}

pub fn call_wat(request: &serde_json::Value) -> String {
    call_wat_raw(
        serde_json::to_string(request).unwrap().as_bytes(),
        0,
        None,
        4096,
        4096,
    )
}

pub fn read_wat(path: &str) -> String {
    call_wat(&serde_json::json!({"op": "workspace.read", "path": path}))
}

pub fn write_wat(path: &str, text: &str) -> String {
    call_wat(&serde_json::json!({"op": "workspace.write", "path": path, "text": text}))
}

pub fn score_wat() -> String {
    call_wat(&serde_json::json!({"op": "game.score.get"}))
}

/// Repeat the same call `count` times and return the last result.
pub fn repeated_calls_wat(count: u32) -> String {
    let payload = br#"{"op":"game.score.get"}"#;
    format!(
        r#"(module
  (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{}")
  (func (export "run") (result i32) (local $remaining i32) (local $result i32)
    i32.const {count} local.set $remaining
    (loop $again
      i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call local.set $result
      local.get $remaining i32.const 1 i32.sub local.tee $remaining br_if $again)
    local.get $result))"#,
        wat_bytes(payload),
        payload.len()
    )
}

pub fn compile(config: &Config, wat: &str) -> Result<CompiledArtifact, String> {
    let bytes = evx_runtime::text_to_binary(wat).map_err(|e| e.to_string())?;
    compile_module(config, &bytes).map_err(|e| e.to_string())
}

pub fn compile_ok(config: &Config, wat: &str) -> CompiledArtifact {
    compile(config, wat).unwrap_or_else(|e| panic!("compile failed: {e}\n{wat}"))
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub workspace: PathBuf,
    pub outside: PathBuf,
    pub other: PathBuf,
    pub broker: Broker,
    pub config: Config,
}

impl Fixture {
    pub fn new() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let area = std::fs::canonicalize(dir.path()).unwrap();
        let outside = area.join("outside-secret.txt");
        std::fs::write(&outside, "sacrificial-secret-not-a-real-key").unwrap();
        let workspace = area.join("game-a");
        let other = area.join("game-b");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("private.txt"), "other-game-fixture").unwrap();
        let broker = Broker::new(
            &workspace,
            Grant::new("game-a", true).unwrap(),
            Limits::default(),
        )
        .unwrap();
        Fixture {
            dir,
            workspace,
            outside,
            other,
            broker,
            config: config(),
        }
    }

    pub fn run(&self, wat: &str) -> RunResult {
        let artifact = compile_ok(&self.config, wat);
        run_guest(&self.config, &artifact, &self.broker, RunOptions::default())
    }

    pub fn run_with(&self, wat: &str, options: RunOptions) -> RunResult {
        let artifact = compile_ok(&self.config, wat);
        run_guest(&self.config, &artifact, &self.broker, options)
    }

    /// The guest ran, made exactly one broker call, and the broker refused it.
    pub fn denied_call(&self, wat: &str) -> RunResult {
        let result = self.run(wat);
        assert_eq!(
            result.status,
            evx_api::Status::Ok,
            "worker did not execute: {result:?}"
        );
        assert_eq!(result.responses.len(), 1, "{result:?}");
        assert!(
            !result.responses[0].is_ok(),
            "broker accepted forbidden operation: {result:?}"
        );
        result
    }

    pub fn set_capabilities(&self, caps: &[Capability]) {
        self.broker
            .with_grant(|g| g.capabilities = caps.iter().copied().collect());
    }
}
