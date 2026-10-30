//! Shared fixtures for supervisor integration tests. All workspaces are
//! disposable temporary directories; all guest programs are synthetic.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use evx_api::{Capability, Grant, Limits, RunResult};
use evx_supervisor::{compile_module, run_guest, Broker, CompiledArtifact, Config, RunOptions};

pub const PAGE: usize = 65_536;

/// A test that re-executes itself hands the worker its parent already built
/// to the child through this variable. A second Cargo build in the child can
/// replace the executable while the parent suite is launching it, which the
/// worker then reports as an unresolvable executable.
pub const TEST_WORKER: &str = "EVX_TEST_WORKER";
/// The same hand-off for the hostile peer example.
pub const TEST_HOSTILE_PEER: &str = "EVX_TEST_HOSTILE_PEER";

/// The exit code of a child the supervisor terminated through its job on
/// Windows (`evx_windows_native::TERMINATED`).
const WINDOWS_TERMINATED: i32 = 0x45565801;

/// The exit code of a child the supervisor terminated: a negative signal
/// number on Unix, the fixed `TERMINATED` code on Windows.
pub fn terminated_by_host(code: i32) -> bool {
    if cfg!(windows) {
        code == WINDOWS_TERMINATED
    } else {
        code < 0
    }
}

/// Build and locate `evx-worker`. The target directory is derived from this
/// test binary's own location, so `CARGO_TARGET_DIR`, `--release` and
/// `--target` all resolve correctly, and the build is always requested so an
/// edit to the worker can never be tested against a stale binary (cargo makes
/// it a no-op when fresh).
pub fn worker_binary() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        handed_down(TEST_WORKER)
            .unwrap_or_else(|| pinned(build_target("evx-worker", &["-p", "evx-worker"], "")))
    })
    .clone()
}

/// Build and locate the hostile peer example of `evx-supervisor`.
pub fn hostile_peer_binary() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        handed_down(TEST_HOSTILE_PEER).unwrap_or_else(|| {
            pinned(build_target(
                "hostile_peer",
                &["-p", "evx-supervisor", "--example", "hostile_peer"],
                "examples",
            ))
        })
    })
    .clone()
}

fn handed_down(variable: &str) -> Option<PathBuf> {
    let path = std::env::var_os(variable)?;
    Some(
        std::fs::canonicalize(&path)
            .unwrap_or_else(|e| panic!("{variable} names {}: {e}", PathBuf::from(path).display())),
    )
}

/// target/<profile>/deps/<test-binary> -> target/<profile>
fn profile_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("test binary path");
    exe.parent()
        .and_then(Path::parent)
        .expect("target profile directory")
        .to_path_buf()
}

fn build_target(name: &str, args: &[&str], subdir: &str) -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut command = std::process::Command::new(cargo);
    command
        .arg("build")
        .args(args)
        .current_dir(manifest.join("../.."));
    command.arg("--locked");
    // Nested Cargo invocations do not inherit this test's feature selection.
    // Keep the compiler, guest and supervisor on the same engine backend.
    if evx_runtime::engine::backend_name().starts_with("pulley") {
        command.args(["--features", "evx-runtime/pulley"]);
    }
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    let status = command
        .status()
        .unwrap_or_else(|e| panic!("cargo build {name}: {e}"));
    assert!(status.success(), "building {name} failed");
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let profile_dir = profile_dir();
    let path = if subdir.is_empty() {
        profile_dir.join(file)
    } else {
        profile_dir.join(subdir).join(file)
    };
    std::fs::canonicalize(&path)
        .unwrap_or_else(|e| panic!("{name} not found at {}: {e}", path.display()))
}

/// The Windows backend pins a worker as a regular file with exactly one
/// link, but Cargo's uplifted `target/<profile>/<name>.exe` is a hard link
/// to the copy under `deps`. Tests therefore run a private copy under
/// `target/<profile>/evx-test-images`, refreshed whenever the build output
/// changes and kept while another test process still has it pinned.
#[cfg(windows)]
fn pinned(built: PathBuf) -> PathBuf {
    let images = profile_dir().join("evx-test-images");
    std::fs::create_dir_all(&images).expect("test image directory");
    let name = built.file_name().expect("image name");
    let bytes = std::fs::read(&built).expect("read built image");
    let shared = images.join(name);
    if std::fs::read(&shared).ok().as_deref() == Some(&bytes) {
        return shared;
    }
    if std::fs::write(&shared, &bytes).is_ok() {
        return shared;
    }
    // Another test process holds the previous image: use a private copy.
    let private = images.join(std::process::id().to_string());
    std::fs::create_dir_all(&private).expect("private image directory");
    let path = private.join(name);
    std::fs::write(&path, &bytes).expect("write private image");
    path
}

#[cfg(not(windows))]
fn pinned(built: PathBuf) -> PathBuf {
    built
}

pub fn config() -> Config {
    Config::new(worker_binary())
}

/// Delete the AppContainer profiles a disposable test workspace created.
/// Production profiles are retained forever; a test workspace is a fresh
/// temporary directory every time, so without this each test would leak
/// three permanent profiles and their package folders.
pub fn forget_workspace_profiles(workspace: &Path) {
    #[cfg(windows)]
    if let Err(error) = evx_supervisor::windows::forget_workspace_profiles(workspace) {
        eprintln!("profile cleanup for {}: {error}", workspace.display());
    }
    #[cfg(not(windows))]
    let _ = workspace;
}

/// Plant a link named `link` to `target` as the platform allows: a symbolic
/// link on Unix; on Windows a junction for a directory and, where Developer
/// Mode or the privilege allows it, a file symbolic link. Returns whether a
/// link now exists.
pub fn plant_link(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        if target.is_dir() {
            let output = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .expect("mklink");
            output.status.success()
        } else {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
    }
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

impl Drop for Fixture {
    fn drop(&mut self) {
        forget_workspace_profiles(&self.workspace);
    }
}
