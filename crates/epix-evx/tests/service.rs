//! The EVX service against a real node state: a signed fixture xite under a
//! temporary data root, the `Evx` plugin started the way the node starts it
//! (scheduler task included), and every command sent through
//! `CommandRegistry::dispatch`, where the wrapper-only gate lives. Execution
//! itself runs only on macOS, through the real worker built like the
//! `evx-host` suite builds it; everywhere else the run path must report
//! `unsupported host` and touch nothing, and the scheduler must admit
//! nothing while saying so in status.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use epix_evx::{
    EvxPlugin, EvxService, BACKGROUND_RUNS_PER_DAY, CAPABILITY_KEY, HOST_CEILING, PLUGIN_NAME,
    UNSUPPORTED_HOST,
};
use epix_plugin::{Plugin, PluginRegistry};
use epix_ui::command::WRAPPER_ID_BASE;
use epix_ui::{AppState, CommandRegistry, WsSession, XiteEntry};
use epix_xite::XiteStorage;
use evx_api::Limits;
use evx_state::DurableState;
use serde_json::{json, Value};

const CALC: &str = r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#;
/// A module with a start function: instantiating it runs code. Inspection
/// must report its hash without ever instantiating it.
const START: &str = r#"(module (memory (export "memory") 1) (func $boot) (start $boot) (func (export "run") (result i32) i32.const 7))"#;
const ENTRY_PATH: &str = "evx/main.wasm";
const PROGRAM: &str = "calc";
const MODIFIED: f64 = 1_700_000_000.0;

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn failed_activation_checkpoint_persistence_prevents_guest_execution() {
    let f = Fixture::new(Options::default()).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let blocked = f.service.root().join("checkpoints")
        .join(format!("{}.json.tmp-{}", f.address, std::process::id()));
    std::fs::create_dir(&blocked).unwrap();
    let result = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap();
    assert_ne!(result["status"], "ok", "guest ran without a durable activation floor: {result}");
    assert_eq!(result["worker_started"], false, "no guest may start after failed admission persistence: {result}");
}

/// Build and locate `evx-worker` relative to this test binary's target
/// directory, exactly as the `evx-host` suite does.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn worker_binary() -> PathBuf {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut command = std::process::Command::new(cargo);
        command.args(["build", "-p", "evx-worker", "--locked"]).current_dir(manifest.join("../.."));
        if evx_runtime::engine::backend_name().starts_with("pulley") {
            command.args(["--features", "evx-runtime/pulley"]);
        }
        if !cfg!(debug_assertions) {
            command.arg("--release");
        }
        assert!(command.status().expect("cargo build -p evx-worker").success());
        let exe = std::env::current_exe().unwrap();
        let profile_dir = exe.parent().and_then(std::path::Path::parent).unwrap();
        std::fs::canonicalize(profile_dir.join("evx-worker")).unwrap()
    })
    .clone()
}

struct Options {
    wat: &'static str,
    allow_run_once: bool,
    capabilities: Vec<&'static str>,
    /// Declared `limits`, overlaid on the defaults by the parser; `None`
    /// declares none.
    limits: Option<Value>,
    /// Declared jobs of the one program: `(job id, interval seconds)`.
    jobs: Vec<(&'static str, u64)>,
    /// Whether the manifest pins the entry file; without it the program
    /// cannot be bound and is unusable, as are its jobs.
    pin_entry: bool,
    signed: bool,
    worker: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            wat: CALC,
            allow_run_once: true,
            capabilities: Vec::new(),
            limits: None,
            jobs: Vec::new(),
            pin_entry: true,
            signed: true,
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            worker: Some(worker_binary()),
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            worker: None,
        }
    }
}

impl Options {
    /// One job `sync` every `seconds`.
    fn with_job(seconds: u64) -> Options {
        Options { jobs: vec![(JOB, seconds)], ..Options::default() }
    }
}

/// One signed fixture xite on disk: its address, its signing key, the
/// declaration digest and the content as signed, for re-signing and for
/// re-adding to a reopened node.
struct Xite {
    address: String,
    key: String,
    digest: String,
    content: Value,
}

/// Write a signed fixture xite under `data_root` and add it to `state`.
async fn write_xite(data_root: &std::path::Path, state: &AppState, options: &Options) -> Xite {
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let root = data_root.join("data").join(&address);
    std::fs::create_dir_all(root.join("evx")).unwrap();
    let storage = XiteStorage::new(&root);
    let index = b"<html>evx fixture</html>";
    storage.write("index.html", index).unwrap();
    let module = evx_runtime::text_to_binary(options.wat).unwrap();
    storage.write(ENTRY_PATH, &module).unwrap();
    let content = sign_content(&address, &key, options, index, &module);
    let raw = epix_content::dumps_content(&content).into_bytes();
    storage.write("content.json", &raw).unwrap();
    let digest = evx_declaration::declaration_digest_bytes(&raw).unwrap().unwrap();
    state
        .add_xite(&address, XiteEntry { storage, content: Some(content.clone()) })
        .await;
    Xite { address, key, digest, content }
}

/// The fixture's root `content.json`, signed with `key` unless `options`
/// say otherwise.
fn sign_content(address: &str, key: &str, options: &Options, index: &[u8], module: &[u8]) -> Value {
    let capabilities: Vec<Value> = options.capabilities.iter().map(|api| json!({ "api": api })).collect();
    let mut content = json!({
        "address": address,
        "title": "EVX fixture",
        "modified": MODIFIED,
        "files": {
            "index.html": { "size": index.len(), "sha512": XiteStorage::hash_bytes(index) },
            ENTRY_PATH: { "size": module.len(), "sha512": XiteStorage::hash_bytes(module) },
        },
        "evx": {
            "version": 1,
            "programs": {
                PROGRAM: {
                    "runtime_profile": "wasm-core-v1",
                    "entry": ENTRY_PATH,
                    "allow_run_once": options.allow_run_once,
                    "capabilities": capabilities,
                }
            }
        }
    });
    if let Some(limits) = &options.limits {
        content["evx"]["programs"][PROGRAM]["limits"] = limits.clone();
    }
    if !options.pin_entry {
        content["files"].as_object_mut().unwrap().remove(ENTRY_PATH);
    }
    if !options.jobs.is_empty() {
        let mut jobs = serde_json::Map::new();
        for (job, seconds) in &options.jobs {
            jobs.insert(
                job.to_string(),
                json!({
                    "program": PROGRAM,
                    "schedule": { "type": "interval", "seconds": seconds, "anchor": "unix_epoch", "missed": "skip" },
                    "max_concurrency": 1,
                }),
            );
        }
        content["evx"]["jobs"] = Value::Object(jobs);
    }
    if options.signed {
        epix_content::sign(&mut content, key).unwrap();
    }
    content
}

fn start_plugin(state: &Arc<AppState>, worker: Option<PathBuf>) -> (CommandRegistry, Arc<EvxService>) {
    let plugin = match worker {
        Some(worker) => EvxPlugin::with_worker(worker),
        None => EvxPlugin::default(),
    };
    let mut plugins = PluginRegistry::new();
    plugins.register(Arc::new(plugin));
    plugins.start_all(state);
    let commands = plugins.command_registry();
    let service = state.capability::<EvxService>(CAPABILITY_KEY).expect("service installed");
    (commands, service)
}

// Keep the journal alive until any admitted supervisor has reaped its child.
// Dropping only TempDir while a scheduler is finishing correctly quarantines
// the process now, so fixture teardown must follow the host shutdown contract.
struct FixtureDirectory {
    dir: tempfile::TempDir,
    service: Arc<EvxService>,
}
impl std::ops::Deref for FixtureDirectory {
    type Target = tempfile::TempDir;
    fn deref(&self) -> &Self::Target { &self.dir }
}
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        self.service.shutdown();
        let journal = self.service.root().join("lifecycle/lifecycle.json");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let active = std::fs::read(&journal).ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .and_then(|value| value["active"].as_array().map(|rows| rows.len()));
            if active == Some(0) || Instant::now() >= deadline { break; }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

struct Fixture {
    dir: FixtureDirectory,
    state: Arc<AppState>,
    address: String,
    commands: CommandRegistry,
    service: Arc<EvxService>,
    digest: String,
    xite: Xite,
    worker: Option<PathBuf>,
}

impl Fixture {
    async fn new(options: Options) -> Fixture {
        Self::build(options, true).await
    }

    /// Recovery fixtures need a live management service without automatic jobs.
    /// Shutting down a service now stops all worker admission as well.
    async fn without_scheduler(options: Options) -> Fixture {
        Self::build(options, false).await
    }

    async fn build(options: Options, scheduler: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("test", dir.path());
        let xite = write_xite(dir.path(), &state, &options).await;
        let (commands, service) = if scheduler {
            start_plugin(&state, options.worker.clone())
        } else {
            let service = Arc::new(EvxService::for_node(&state, options.worker.clone()).unwrap());
            state.install_capability(CAPABILITY_KEY, service.clone());
            let reader = service.clone();
            state.set_evx_grant_summary_source(Box::new(move |address| reader.grant_summary(address)));
            let mut plugins = PluginRegistry::new();
            plugins.register(Arc::new(EvxPlugin::default()));
            (plugins.command_registry(), service)
        };
        Fixture {
            dir: FixtureDirectory { dir, service: service.clone() },
            state,
            address: xite.address.clone(),
            commands,
            service,
            digest: xite.digest.clone(),
            xite,
            worker: options.worker,
        }
    }

    /// A second signed xite on the same node.
    async fn add_xite(&self, options: Options) -> Xite {
        write_xite(self.dir.path(), &self.state, &options).await
    }

    /// Re-sign the fixture's declaration from `options`, as a publisher's
    /// authenticated update does, leaving the files as they are. The digest
    /// changes; the old one stays in `self.digest`.
    fn resign(&self, options: Options) -> String {
        let root = self.served_root();
        let index = std::fs::read(root.join("index.html")).unwrap();
        let module = std::fs::read(root.join(ENTRY_PATH)).unwrap();
        let content = sign_content(&self.address, &self.xite.key, &options, &index, &module);
        let raw = epix_content::dumps_content(&content).into_bytes();
        XiteStorage::new(&root).write("content.json", &raw).unwrap();
        evx_declaration::declaration_digest_bytes(&raw).unwrap().unwrap()
    }

    /// The same data root under a fresh node and a fresh plugin, as a
    /// restart is: the old scheduler is stopped first, so one database has
    /// one scheduler.
    async fn reopen(mut self) -> Fixture {
        self.service.shutdown();
        tokio::task::yield_now().await;
        let state = AppState::with_data_dir("test", self.dir.path());
        let root = self.served_root();
        state
            .add_xite(&self.address, XiteEntry { storage: XiteStorage::new(&root), content: Some(self.xite.content.clone()) })
            .await;
        let (commands, service) = start_plugin(&state, self.worker.clone());
        self.dir.service = service.clone();
        Fixture { state, commands, service, ..self }
    }

    /// Sends `cmd` to the chrome with `params` and expects a refusal
    /// mentioning `word`.
    async fn refused(&self, cmd: &str, params: Value, word: &str) {
        let denied = self.chrome(cmd, params).await.unwrap_err();
        assert!(denied.contains(word), "{cmd}: {denied}");
    }

    /// The status payload straight from the service, whatever the plugin
    /// switch says (the dispatcher drops a disabled plugin's commands).
    async fn status(&self) -> Value {
        self.service.status(&self.state, &self.address).await.unwrap()
    }

    /// The status payload's entry for `job`.
    async fn job(&self, job: &str) -> Value {
        let status = self.status().await;
        status["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["job"] == job)
            .cloned()
            .unwrap_or_else(|| panic!("job {job} not in status: {status}"))
    }

    fn runs(&self) -> Vec<evx_state::RunRecord> {
        self.service.durable().runs(&self.address).unwrap()
    }

    fn page(&self) -> WsSession {
        WsSession::new(self.state.clone(), Some(self.address.clone()))
    }

    fn wrapper(&self) -> WsSession {
        WsSession::new_wrapper(self.state.clone(), Some(self.address.clone()))
    }

    fn operator(&self) -> WsSession {
        WsSession::new_trusted(self.state.clone(), None)
    }

    async fn call(&self, session: &WsSession, cmd: &str, params: Value, id: i64) -> Result<Value, String> {
        self.commands.dispatch(session, cmd, &params, id).await
    }

    /// The wrapper's own command, from its elevated id range.
    async fn chrome(&self, cmd: &str, params: Value) -> Result<Value, String> {
        self.call(&self.wrapper(), cmd, params, WRAPPER_ID_BASE + 1).await
    }

    /// The `enable` request the wrapper sends for the fixture xite: the
    /// digest it was shown and what the dialog rendered of the bound
    /// closure, from an inspection made now.
    async fn enable_params(&self) -> Value {
        self.enable_params_at(&self.address, &self.digest).await
    }

    /// The same for another xite of the node. Only the macOS execution tests
    /// use it.
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    async fn enable_params_for(&self, xite: &Xite) -> Value {
        self.enable_params_at(&xite.address, &xite.digest).await
    }

    /// The `enable` request for `xite` at `digest`, with `shown` taken from
    /// the inspect payload as the wrapper takes it.
    async fn enable_params_at(&self, xite: &str, digest: &str) -> Value {
        let inspect = self.service.inspect_json(&self.state, xite).await.unwrap();
        json!({ "xite": xite, "declaration_digest": digest, "mode": "enable", "shown": shown(&inspect) })
    }

    fn served_root(&self) -> PathBuf {
        self.dir.path().join("data").join(&self.address)
    }

    fn served_files(&self) -> Vec<PathBuf> {
        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.served_root(), &mut out);
        out.sort();
        out
    }
}

/// One job of the fixture, when it declares one.
const JOB: &str = "sync";

/// What the consent dialog rendered of the bound closure, taken from an
/// inspect payload exactly as the wrapper takes it (`ui/media/all.js`
/// `evxShown`): the usable programs and jobs and the two effective bits.
fn shown(inspect: &Value) -> Value {
    json!({
        "programs": inspect["requested"]["programs"],
        "jobs": inspect["requested"]["jobs"],
        "allow_run_once": inspect["effective"]["allow_run_once"],
        "allow_background": inspect["effective"]["allow_background"],
    })
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Poll `check` every 50 ms until it returns `Some`, or panic with
/// `what` after `timeout`. The poll is a future so it can read status.
async fn wait_for<T, F>(timeout: Duration, what: &str, mut check: impl FnMut() -> F) -> T
where
    F: std::future::Future<Output = Option<T>>,
{
    let started = Instant::now();
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(started.elapsed() < timeout, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn the_evx_plugin_registers_its_commands_under_its_name() {
    let plugin = EvxPlugin::default();
    assert_eq!(plugin.name(), "Evx");
    let names: Vec<&str> = plugin.ws_commands().iter().map(|command| command.name()).collect();
    assert_eq!(
        names,
        [
            "evxInspect",
            "evxStatus",
            "evxRequest",
            "evxGrant",
            "evxRevoke",
            "evxSetLimits",
            "evxRunOnce",
            "evxJobPause",
            "evxJobResume",
            "evxRunJob",
            "evxRecoverWorkspace",
        ]
    );
    for wrapper_only in epix_ui::command::EVX_WRAPPER_COMMANDS {
        assert!(names.contains(wrapper_only), "{wrapper_only} is gated but not registered");
    }
}

#[tokio::test]
async fn a_page_socket_can_inspect_request_and_read_status_for_its_own_xite_only() {
    let f = Fixture::new(Options::default()).await;
    let page = f.page();

    let inspect = f.call(&page, "evxInspect", json!({}), 1).await.unwrap();
    assert_eq!(inspect["xite"], f.address);
    assert_eq!(inspect["publisher"], f.address);
    assert_eq!(inspect["integrity"], "verified");
    assert_eq!(inspect["declaration_digest"], f.digest);
    let program = &inspect["declaration"]["programs"][PROGRAM];
    assert_eq!(program["usable"], true);
    assert_eq!(program["files"]["entry"]["path"], ENTRY_PATH);
    let module = evx_runtime::text_to_binary(CALC).unwrap();
    assert_eq!(program["files"]["entry"]["sha512"], XiteStorage::hash_bytes(&module));
    assert_eq!(program["files"]["entry"]["size"], module.len());
    assert_eq!(program["effective_limits"], program["limits"], "a request within the ceiling is kept");
    assert_eq!(inspect["requested"]["programs"], json!([PROGRAM]));
    assert_eq!(inspect["effective"]["runtime_profiles"], json!(["wasm-core-v1"]));
    assert_eq!(inspect["effective"]["allow_background"], false);
    assert!(inspect["grant"].is_null());
    assert_eq!(inspect["host"]["ceiling"], serde_json::to_value(&HOST_CEILING).unwrap());

    let status = f.call(&page, "evxStatus", json!({}), 2).await.unwrap();
    assert!(status["grant"].is_null());
    assert_eq!(status["runs"], json!([]));
    assert!(status["reasons"].as_array().unwrap().contains(&json!("no_grant")));
    assert!(status["asked_unix"].is_null());

    // The page asks: the payload is the inspect payload, nothing is granted.
    let asked = f.call(&page, "evxRequest", json!({ "xite": f.address }), 3).await.unwrap();
    assert_eq!(asked["declaration_digest"], f.digest);
    assert!(asked["asked_unix"].is_u64());
    assert!(asked["grant"].is_null());
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    let status = f.call(&page, "evxStatus", json!({}), 4).await.unwrap();
    assert!(status["asked_unix"].is_u64());

    // Nothing else: another xite, no xite, a foreign binding.
    for cmd in ["evxInspect", "evxStatus", "evxRequest"] {
        assert!(f.call(&page, cmd, json!({ "xite": "1Other" }), 5).await.is_err(), "{cmd}");
        let unbound = WsSession::new(f.state.clone(), None);
        assert!(f.call(&unbound, cmd, json!({}), 6).await.is_err(), "{cmd}");
        let foreign = WsSession::new(f.state.clone(), Some("1Other".into()));
        assert!(f.call(&foreign, cmd, json!({ "xite": f.address }), 7).await.is_err(), "{cmd}");
        assert!(f.call(&page, cmd, json!([f.address]), 8).await.is_err(), "{cmd}: array params");
    }
}

#[tokio::test]
async fn the_wrapper_enables_a_grant_that_status_and_the_list_panel_report() {
    let f = Fixture::new(Options { capabilities: vec!["workspace.read", "game.score.get"], ..Options::default() }).await;
    let granted = f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    assert_eq!(granted["granted"], true);
    assert_eq!(granted["mode"], "enable");
    assert_eq!(granted["grant"]["enabled"], true);
    assert_eq!(granted["grant"]["generation"], 1);
    assert_eq!(granted["grant"]["capabilities"], json!(["workspace.read", "game.score.get"]));
    assert_eq!(granted["grant"]["allow_run_once"], true);
    assert_eq!(granted["grant"]["allow_background"], false);
    assert_eq!(granted["grant"]["label"], "wrapper");
    assert_eq!(granted["grant"]["publisher"], f.address);

    let (stored, generations) = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    assert!(stored.enabled);
    assert_eq!(stored.runtime_profiles.iter().collect::<Vec<_>>(), ["wasm-core-v1"]);
    assert_eq!(generations.generation, 1);
    assert_eq!(stored.limits, Limits::default(), "the declaration asked for the defaults");

    let status = f.call(&f.page(), "evxStatus", json!({}), 1).await.unwrap();
    assert_eq!(status["grant"]["enabled"], true);
    assert_eq!(status["generations"]["generation"], 1);
    assert!(!status["reasons"].as_array().unwrap().contains(&json!("no_grant")));
    let inspect = f.call(&f.page(), "evxInspect", json!({}), 2).await.unwrap();
    assert_eq!(inspect["grant"]["covers_declaration"], true);

    // The /list panel's reader sees the same grant.
    let summary = f.state.evx_grant_summary(&f.address).unwrap();
    assert_eq!(summary["enabled"], true);
    assert_eq!(summary["generation"], 1);
    assert!(summary["expires_unix"].is_null());
    assert!(f.state.evx_grant_summary("1Unknown").is_none());

    // Re-granting the same declaration is idempotent for the generation;
    // a label is stored as given.
    let mut again = f.enable_params().await;
    again["label"] = json!("laptop");
    let granted = f.chrome("evxGrant", again).await.unwrap();
    assert_eq!(granted["grant"]["generation"], 1);
    assert_eq!(granted["grant"]["label"], "laptop");
}

#[tokio::test]
async fn a_grant_with_a_stale_declaration_digest_is_refused() {
    let f = Fixture::new(Options::default()).await;
    let mut stale = f.enable_params().await;
    stale["declaration_digest"] = json!("0".repeat(64));
    let denied = f.chrome("evxGrant", stale).await.unwrap_err();
    assert!(denied.contains("declaration_digest"), "{denied}");
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    // The same for a token.
    let denied = f
        .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": "1".repeat(64), "mode": "once", "program": PROGRAM }))
        .await
        .unwrap_err();
    assert!(denied.contains("declaration_digest"), "{denied}");
    // And for shapes the dialog never sends.
    for bad in [
        json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "always" }),
        json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "enable", "admin": true }),
        json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once" }),
        json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": "missing" }),
        json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "enable", "program": PROGRAM }),
        json!({ "xite": "1Other", "declaration_digest": f.digest, "mode": "enable" }),
    ] {
        assert!(f.chrome("evxGrant", bad.clone()).await.is_err(), "{bad}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
}

#[tokio::test]
async fn a_page_socket_cannot_grant_with_or_without_an_elevated_id() {
    let f = Fixture::new(Options::default()).await;
    let page = f.page();
    let once = json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM });
    for params in [f.enable_params().await, once] {
        let denied = f.call(&page, "evxGrant", params.clone(), 7).await.unwrap_err();
        assert!(denied.contains("prompt"), "{denied}");
        let forged = f.call(&page, "evxGrant", params.clone(), WRAPPER_ID_BASE + 3).await.unwrap_err();
        assert!(forged.contains("prompt"), "{forged}");
        let via_as = f.call(&page, "as", json!([f.address, "evxGrant", params.clone()]), 8).await;
        assert!(via_as.is_err());
        // A page command forwarded by the wrapper keeps its small id.
        assert!(f.call(&f.wrapper(), "evxGrant", params.clone(), 7).await.is_err());
    }
    for cmd in ["evxRevoke", "evxSetLimits", "evxRunOnce", "evxJobPause", "evxJobResume", "evxRunJob"] {
        let params = json!({ "xite": f.address, "limits": Limits::default(), "program": PROGRAM, "job": JOB });
        assert!(f.call(&page, cmd, params.clone(), 7).await.unwrap_err().contains("prompt"), "{cmd}");
        assert!(f.call(&page, cmd, params, WRAPPER_ID_BASE + 3).await.unwrap_err().contains("prompt"), "{cmd}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());

    // The handler itself refuses a page session even when the dispatcher
    // is bypassed: a second line behind the gate, not a replacement for it.
    let handlers = EvxPlugin::default().ws_commands();
    for cmd in epix_ui::command::EVX_WRAPPER_COMMANDS {
        let handler = handlers.iter().find(|handler| handler.name() == *cmd).unwrap();
        let denied = handler.handle(&page, &f.enable_params().await).await.unwrap_err();
        assert!(denied.contains("prompt"), "{cmd}: {denied}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    assert!(!f.state.xite_has_admin(&f.address).await, "no ADMIN was involved");
}

#[tokio::test]
async fn an_admin_xite_page_cannot_grant_through_as() {
    // On a normal node the dashboard xite holds ADMIN by default, and so
    // does any xite the user ever granted it. ADMIN grants nothing here: the
    // page is forwarded by the wrapper with its own small id, and `as` must
    // not turn that ADMIN into wrapper authority.
    let f = Fixture::new(Options::default()).await;
    f.state.add_permission(&f.address, "ADMIN").await;
    assert!(f.state.xite_has_admin(&f.address).await);
    let page = f.page();
    let once = json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM });
    for params in [f.enable_params().await, once] {
        let denied = f.call(&page, "as", json!([f.address, "evxGrant", params.clone()]), 8).await.unwrap_err();
        assert!(denied.contains("prompt"), "{denied}");
        let denied = f
            .call(&page, "as", json!({ "address": f.address, "cmd": "evxGrant", "params": params }), 9)
            .await
            .unwrap_err();
        assert!(denied.contains("prompt"), "{denied}");
    }
    for cmd in ["evxRevoke", "evxSetLimits", "evxRunOnce"] {
        let params = json!({ "xite": f.address, "limits": Limits::default(), "program": PROGRAM });
        let denied = f.call(&page, "as", json!([f.address, cmd, params]), 10).await.unwrap_err();
        assert!(denied.contains("prompt"), "{cmd}: {denied}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none(), "ADMIN stored a grant");
    assert!(f.service.durable().runs(&f.address).unwrap().is_empty());

    // Another xite that holds ADMIN gets no further on this one.
    let dashboard = "1AdminDashboard";
    let dir = tempfile::tempdir().unwrap();
    f.state
        .add_xite(dashboard, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
        .await;
    f.state.add_permission(dashboard, "ADMIN").await;
    let admin_page = WsSession::new(f.state.clone(), Some(dashboard.into()));
    let denied = f
        .call(&admin_page, "as", json!([f.address, "evxGrant", f.enable_params().await]), 11)
        .await
        .unwrap_err();
    assert!(denied.contains("prompt"), "{denied}");
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    // The inert commands still answer it for the xite it rebinds to, as
    // ADMIN's `as` always allowed.
    let inspect = f.call(&admin_page, "as", json!([f.address, "evxInspect", {}]), 12).await.unwrap();
    assert_eq!(inspect["declaration_digest"], f.digest);

    // The wrapper's own dialog answer and the operator socket are the only
    // routes, through `as` as directly.
    let granted = f
        .call(&f.wrapper(), "as", json!([f.address, "evxGrant", f.enable_params().await]), WRAPPER_ID_BASE + 1)
        .await
        .unwrap();
    assert_eq!(granted["granted"], true);
    let revoked = f.call(&f.operator(), "as", json!([f.address, "evxRevoke", {}]), 1).await.unwrap();
    assert_eq!(revoked["revoked"], true);
}

#[tokio::test]
async fn a_gateway_visitor_is_told_only_whether_execution_is_enabled() {
    // A declaration without run-once: the operator's status says the grant
    // does not allow it, which is a fact of the consent record.
    let f = Fixture::new(Options { allow_run_once: false, ..Options::default() }).await;
    let mut labelled = f.enable_params().await;
    labelled["label"] = json!("operator laptop");
    f.call(&f.operator(), "evxGrant", labelled, 1).await.unwrap();
    f.state.config_set("ui_restrict", json!(true)).await;

    // Any visitor can bind a socket to a xite the gateway serves. It learns
    // that execution is enabled and nothing of the consent behind it.
    let visitor = f.page();
    for cmd in ["evxInspect", "evxStatus"] {
        let payload = f.call(&visitor, cmd, json!({}), 1).await.unwrap();
        assert_eq!(payload["grant"], json!({ "enabled": true }), "{cmd}: {payload}");
        for gone in ["generations", "runs", "run_count", "asked_unix"] {
            assert!(payload.get(gone).is_none(), "{cmd}: {gone} survived");
        }
        let text = payload.to_string();
        assert!(!text.contains("operator laptop"), "{cmd} leaked the label: {text}");
        assert!(!text.contains("created_unix"), "{cmd} leaked the consent time: {text}");
        assert_eq!(payload["xite"], f.address, "{cmd}");
    }
    let status = f.call(&visitor, "evxStatus", json!({}), 2).await.unwrap();
    assert!(status["reasons"].is_array());
    for reason in status["reasons"].as_array().unwrap() {
        assert!(epix_evx::commands::GATEWAY_REASONS.contains(&reason.as_str().unwrap()), "{reason} survived: {status}");
    }
    assert!(!status.to_string().contains("run_once_not_allowed"), "{status}");
    assert_eq!(status["running"], false);
    // No dialog is shown on a gateway, so the ask is refused, not recorded.
    let denied = f.call(&visitor, "evxRequest", json!({}), 3).await.unwrap_err();
    assert!(denied.contains("gateway"), "{denied}");
    let status = f.call(&f.operator(), "evxStatus", json!({ "xite": f.address }), 4).await.unwrap();
    assert!(status["asked_unix"].is_null(), "the refused ask was recorded");

    // The operator socket sees everything, and a plain node tells its
    // page everything too.
    assert_eq!(status["grant"]["label"], "operator laptop");
    assert!(status["reasons"].as_array().unwrap().contains(&json!("run_once_not_allowed")), "{status}");
    assert!(status["generations"]["generation"].is_u64());
    assert_eq!(status["runs"], json!([]));
    let inspect = f.call(&f.operator(), "evxInspect", json!({ "xite": f.address }), 5).await.unwrap();
    assert_eq!(inspect["grant"]["label"], "operator laptop");
    f.state.config_set("ui_restrict", json!(false)).await;
    let status = f.call(&visitor, "evxStatus", json!({}), 6).await.unwrap();
    assert_eq!(status["grant"]["label"], "operator laptop");
    assert!(f.call(&visitor, "evxRequest", json!({}), 7).await.is_ok());
}

#[tokio::test]
async fn a_restricted_gateway_refuses_the_grant_commands_except_from_the_operator_socket() {
    let f = Fixture::new(Options::default()).await;
    f.state.config_set("ui_restrict", json!(true)).await;
    let denied = f.chrome("evxGrant", f.enable_params().await).await.unwrap_err();
    assert!(denied.contains("gateway"), "{denied}");
    for cmd in ["evxRevoke", "evxSetLimits", "evxRunOnce", "evxJobPause", "evxJobResume", "evxRunJob"] {
        let params = json!({ "xite": f.address, "limits": Limits::default(), "program": PROGRAM, "job": JOB });
        assert!(f.chrome(cmd, params).await.unwrap_err().contains("gateway"), "{cmd}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    // The operator socket is the sanctioned way to change a locked node,
    // and it may name any xite.
    let granted = f.call(&f.operator(), "evxGrant", f.enable_params().await, 1).await.unwrap();
    assert_eq!(granted["granted"], true);
    assert!(f.service.durable().xite_grant(&f.address).unwrap().unwrap().0.enabled);
    let revoked = f.call(&f.operator(), "evxRevoke", json!({ "xite": f.address }), 2).await.unwrap();
    assert_eq!(revoked["revoked"], true);
    assert!(!f.service.durable().xite_grant(&f.address).unwrap().unwrap().0.enabled);
}

#[tokio::test]
async fn revocation_disables_the_grant_and_a_later_run_once_is_refused() {
    let f = Fixture::new(Options::default()).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let revoked = f.chrome("evxRevoke", json!({})).await.unwrap();
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["had_grant"], true);
    let (stored, generations) = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    assert!(!stored.enabled);
    assert_eq!(generations.generation, 2, "revocation fences the authority generation");
    let status = f.call(&f.page(), "evxStatus", json!({}), 1).await.unwrap();
    assert_eq!(status["grant"]["enabled"], false);
    assert!(status["reasons"].as_array().unwrap().contains(&json!("revoked")));
    assert_eq!(f.state.evx_grant_summary(&f.address).unwrap()["enabled"], false);

    let denied = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap_err();
    if f.service.execution().is_ok() {
        assert!(denied.contains("no enabled EVX grant"), "{denied}");
    } else {
        assert_eq!(denied, UNSUPPORTED_HOST);
    }
    assert!(f.service.durable().runs(&f.address).unwrap().is_empty() || f.service.execution().is_err());
    // A token minted before the revocation is gone with it.
    let f = Fixture::new(Options::default()).await;
    let minted = f
        .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
        .await
        .unwrap();
    let token = minted["token"].as_str().unwrap().to_string();
    f.chrome("evxRevoke", json!({})).await.unwrap();
    assert!(!f.service.durable().consume_allow_once(&f.address, &token, &f.digest, PROGRAM).unwrap());
}

#[tokio::test]
async fn an_allow_once_token_is_bound_to_its_program_and_digest() {
    let f = Fixture::new(Options::default()).await;
    let minted = f
        .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
        .await
        .unwrap();
    assert_eq!(minted["granted"], true);
    assert_eq!(minted["mode"], "once");
    assert_eq!(minted["program"], PROGRAM);
    let token = minted["token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), 64);
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none(), "a token is not a grant");
    // Bound to the program and the digest it was minted for.
    assert!(!f.service.durable().consume_allow_once(&f.address, &token, &f.digest, "other").unwrap());
    assert!(!f.service.durable().consume_allow_once(&f.address, &token, &"0".repeat(64), PROGRAM).unwrap());
    // Spent exactly once.
    assert!(f.service.durable().consume_allow_once(&f.address, &token, &f.digest, PROGRAM).unwrap());
    assert!(!f.service.durable().consume_allow_once(&f.address, &token, &f.digest, PROGRAM).unwrap());
    // A program that does not ask for run-once gets no token.
    let f = Fixture::new(Options { allow_run_once: false, ..Options::default() }).await;
    let denied = f
        .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
        .await
        .unwrap_err();
    assert!(denied.contains("run-once"), "{denied}");
}

#[tokio::test]
async fn a_host_without_execution_reports_unsupported_host_and_spends_nothing() {
    let worker_dir = tempfile::tempdir().unwrap();
    let missing = worker_dir.path().join("no-such-worker");
    let f = Fixture::new(Options { worker: Some(missing), ..Options::default() }).await;
    assert_eq!(f.service.execution().unwrap_err(), UNSUPPORTED_HOST);
    let status = f.call(&f.page(), "evxStatus", json!({}), 1).await.unwrap();
    assert_eq!(status["host"]["execution"], false);
    assert!(status["reasons"].as_array().unwrap().contains(&json!("unsupported_host")));
    // Inspect, grant and revoke still work.
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let minted = f
        .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
        .await
        .unwrap();
    let token = minted["token"].as_str().unwrap().to_string();
    // A run refuses before touching the grant or the token.
    let denied = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap_err();
    assert_eq!(denied, UNSUPPORTED_HOST);
    let denied = f.chrome("evxRunOnce", json!({ "program": PROGRAM, "token": token })).await.unwrap_err();
    assert_eq!(denied, UNSUPPORTED_HOST);
    assert!(f.service.durable().consume_allow_once(&f.address, &token, &f.digest, PROGRAM).unwrap(), "token unspent");
    assert!(f.service.durable().runs(&f.address).unwrap().is_empty());
    assert!(!f.service.workspace_dir(&f.address).exists());
    assert!(!f.service.checkpoint_path(&f.address).exists());
    f.chrome("evxRevoke", json!({})).await.unwrap();
}

#[tokio::test]
async fn workspace_and_state_paths_are_under_private_evx_and_outside_the_served_root() {
    let f = Fixture::new(Options::default()).await;
    let private = f.dir.path().join("private").join("evx");
    assert_eq!(f.service.root(), private);
    assert_eq!(f.service.state_path(), private.join("state.sqlite"));
    assert!(f.service.state_path().is_file());
    assert!(private.join("workspaces").is_dir());
    assert_eq!(f.service.workspace_dir(&f.address), private.join("workspaces").join(&f.address));
    assert_eq!(f.service.checkpoint_path(&f.address), private.join("checkpoints").join(format!("{}.json", f.address)));
    let served = f.served_root();
    for path in [f.service.state_path(), f.service.workspace_dir(&f.address), f.service.checkpoint_path(&f.address)] {
        assert!(!path.starts_with(&served), "{} is under the served root", path.display());
        assert!(!path.starts_with(f.dir.path().join("data")), "{} is under data/", path.display());
    }
    // A grant leaves the served root untouched.
    let before = f.served_files();
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    assert_eq!(f.served_files(), before);
    // An in-memory node keeps its state in a throwaway directory, never
    // beside anything served.
    let memory = AppState::new("test");
    let service = EvxService::for_node(&memory, None).unwrap();
    assert!(service.state_path().is_file());
    assert!(service.root().starts_with(std::env::temp_dir()));
}

#[cfg(unix)]
#[tokio::test]
async fn inspecting_a_start_function_module_reports_its_hash_without_spawning_anything() {
    // A "worker" that leaves a mark if anything ever executes it.
    let dir = tempfile::tempdir().unwrap();
    let canary = dir.path().join("canary");
    let script = dir.path().join("evx-worker");
    std::fs::write(&script, format!("#!/bin/sh\ntouch {}\n", canary.display())).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let f = Fixture::new(Options { wat: START, worker: Some(script), ..Options::default() }).await;
    let module = evx_runtime::text_to_binary(START).unwrap();
    let inspect = f.call(&f.page(), "evxInspect", json!({}), 1).await.unwrap();
    let entry = &inspect["declaration"]["programs"][PROGRAM]["files"]["entry"];
    assert_eq!(entry["sha512"], XiteStorage::hash_bytes(&module));
    assert_eq!(entry["size"], module.len());
    assert_eq!(inspect["integrity"], "verified");
    f.call(&f.page(), "evxRequest", json!({}), 2).await.unwrap();
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    f.chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
        .await
        .unwrap();
    f.call(&f.page(), "evxStatus", json!({}), 3).await.unwrap();
    assert!(!canary.exists(), "inspection executed the worker");
    assert!(!f.service.workspace_dir(&f.address).exists(), "inspection created a workspace");
    assert!(f.service.durable().runs(&f.address).unwrap().is_empty());
}

#[tokio::test]
async fn set_limits_clamps_to_the_host_ceiling_and_advances_the_limits_generation() {
    let f = Fixture::new(Options::default()).await;
    assert!(f.chrome("evxSetLimits", json!({ "limits": Limits::default() })).await.is_err(), "no grant yet");
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let generous = Limits { memory_bytes: 256 * 1024 * 1024, wall_seconds: 600.0, ..Limits::default() };
    generous.validate().unwrap();
    let set = f.chrome("evxSetLimits", json!({ "limits": generous })).await.unwrap();
    assert_eq!(set["limits"]["memory_bytes"], HOST_CEILING.memory_bytes);
    assert_eq!(set["limits"]["wall_seconds"], HOST_CEILING.wall_seconds);
    assert_eq!(set["limits"]["fuel"], Limits::default().fuel);
    assert_eq!(set["generations"]["limits_generation"], 2);
    assert_eq!(set["generations"]["generation"], 1, "limits never move the authority generation");
    let (stored, generations) = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    assert_eq!(stored.limits.memory_bytes, HOST_CEILING.memory_bytes);
    assert_eq!(generations.limits_generation, 2);
    // Malformed limits are refused, not repaired; unknown fields too.
    let bad = json!({ "limits": { "memory_bytes": 1, "fuel": 1, "host_calls": 1, "storage_bytes": 0,
        "wall_seconds": 1.0, "host_call_seconds": 0.5, "process_cpu_seconds": 1.0, "process_rss_bytes": 16777216 } });
    assert!(f.chrome("evxSetLimits", bad).await.is_err());
    let mut unknown = serde_json::to_value(Limits::default()).unwrap();
    unknown["gpu"] = json!(true);
    assert!(f.chrome("evxSetLimits", json!({ "limits": unknown })).await.is_err());
    assert_eq!(f.service.durable().xite_grant(&f.address).unwrap().unwrap().1.limits_generation, 2);
    // The wrapper may also propose limits with the grant itself.
    let mut with_limits = f.enable_params().await;
    with_limits["limits"] = serde_json::to_value(Limits { fuel: 1_000_000_000_000, ..Limits::default() }).unwrap();
    let granted = f.chrome("evxGrant", with_limits).await.unwrap();
    assert_eq!(granted["grant"]["limits"]["fuel"], HOST_CEILING.fuel);
    assert_eq!(granted["grant"]["limits_generation"], 3);
}

#[tokio::test]
async fn an_unsigned_declaration_is_inspectable_but_cannot_be_granted() {
    let f = Fixture::new(Options { signed: false, ..Options::default() }).await;
    let inspect = f.call(&f.page(), "evxInspect", json!({}), 1).await.unwrap();
    assert_eq!(inspect["integrity"], "unsigned");
    assert_eq!(inspect["declaration_digest"], f.digest);
    let denied = f.chrome("evxGrant", f.enable_params().await).await.unwrap_err();
    assert!(denied.contains("unsigned"), "{denied}");
    let denied = f
        .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
        .await
        .unwrap_err();
    assert!(denied.contains("unsigned"), "{denied}");
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    // A declared file missing on disk is `incomplete`, and just as ungrantable.
    let f = Fixture::new(Options::default()).await;
    std::fs::remove_file(f.served_root().join(ENTRY_PATH)).unwrap();
    let inspect = f.call(&f.page(), "evxInspect", json!({}), 1).await.unwrap();
    assert_eq!(inspect["integrity"], "incomplete");
    let denied = f.chrome("evxGrant", f.enable_params().await).await.unwrap_err();
    assert!(denied.contains("incomplete"), "{denied}");
}

// The scheduler (docs/evx-milestone-3.md section 2), on every host: what is
// registered, claimed, refused and shown is the same everywhere, and only
// the run itself needs the macOS worker. Each test below says what it
// expects of a host that cannot execute.

#[tokio::test]
async fn enabling_a_declaration_with_a_usable_job_records_background_consent_and_registers_it() {
    let f = Fixture::new(Options::with_job(3600)).await;
    let inspect = f.call(&f.page(), "evxInspect", json!({}), 1).await.unwrap();
    assert_eq!(inspect["effective"]["allow_background"], true, "{inspect}");
    assert_eq!(inspect["requested"]["jobs"], json!([JOB]));
    assert_eq!(inspect["declaration"]["jobs"][JOB]["usable"], true);
    // Nothing is registered before consent: an inspection writes no row.
    assert!(f.service.durable().jobs(&f.address).unwrap().is_empty());
    let status = f.call(&f.page(), "evxStatus", json!({}), 2).await.unwrap();
    assert_eq!(status["jobs"], json!([]));
    assert_eq!(status["scheduler"]["enabled"], true);
    assert_eq!(status["scheduler"]["host"], if f.service.execution().is_ok() { std::env::consts::OS } else { "unsupported" });

    let granted = f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    assert_eq!(granted["grant"]["allow_background"], true, "consent and authority agree: {granted}");
    assert_eq!(granted["jobs"], json!([JOB]));
    let (stored, _) = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    assert!(stored.allow_background);
    let rows = f.service.durable().jobs(&f.address).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].job, JOB);
    assert_eq!(rows[0].program, PROGRAM);
    assert_eq!(rows[0].declaration_digest, f.digest);
    assert_eq!(rows[0].paused_reason, None);
    let slot = DurableState::slot_at(&rows[0].schedule, now_unix()).unwrap();
    assert!(rows[0].next_due_unix.is_some_and(|due| due <= slot.end_unix), "{rows:?}");
    let job = f.job(JOB).await;
    assert_eq!(job["daily_limit"], BACKGROUND_RUNS_PER_DAY);
    assert_eq!(job["schedule"]["seconds"], 3600);
    assert_eq!(job["declaration_digest"], f.digest);

    // A declaration without a job grants no background authority, as before.
    let plain = Fixture::new(Options::default()).await;
    let inspect = plain.call(&plain.page(), "evxInspect", json!({}), 1).await.unwrap();
    assert_eq!(inspect["effective"]["allow_background"], false);
    let granted = plain.chrome("evxGrant", plain.enable_params().await).await.unwrap();
    assert_eq!(granted["grant"]["allow_background"], false);
    assert_eq!(granted["jobs"], json!([]));
    assert!(plain.service.durable().jobs(&plain.address).unwrap().is_empty());
}

#[tokio::test]
async fn a_manual_job_run_claims_the_current_slot_and_a_second_request_returns_the_stored_result() {
    let f = Fixture::new(Options::with_job(3600)).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let now = now_unix();
    let row = f.service.durable().jobs(&f.address).unwrap().remove(0);
    let slot = DurableState::slot_at(&row.schedule, now).unwrap();
    let occurrence = DurableState::occurrence_id(JOB, &slot);

    // The scheduler may claim the slot first (it was woken by the grant);
    // either way exactly one execution of this occurrence happens, and the
    // manual run returns either its own result or the stored one.
    let first = f.chrome("evxRunJob", json!({ "job": JOB })).await;
    let can_run = f.service.execution().is_ok();
    match &first {
        Ok(payload) if payload["stored"] == true => {
            assert_eq!(payload["occurrence"], occurrence, "{payload}");
        }
        Ok(payload) => {
            assert!(can_run, "ran on a host without execution: {payload}");
            assert_eq!(payload["value"], 42, "{payload}");
            assert_eq!(payload["trigger"], "manual_job");
            assert_eq!(payload["authority"], "scheduled");
            assert_eq!(payload["occurrence"], occurrence);
            assert_eq!(payload["run"]["occurrence"], occurrence);
            assert_eq!(payload["run"]["trigger"], "manual_job");
        }
        Err(error) => {
            // A host without execution refuses the run, yet the reservation
            // it made is finished as refused, never left open.
            assert!((!can_run && error == UNSUPPORTED_HOST) || error.contains("already running"), "{error}");
        }
    }
    let completed = wait_for(Duration::from_secs(20), "the occurrence to complete", || async {
        let snapshot = f.service.durable().snapshot(&f.address).unwrap();
        snapshot.invocations.into_iter().find(|row| row.occurrence == occurrence && row.response.is_some())
    })
    .await;
    assert_eq!(completed.response.as_ref().unwrap()["occurrence"], occurrence);
    let stored_status = completed.response.as_ref().unwrap()["status"].clone();
    assert_eq!(stored_status, if can_run { "ok" } else { "denied" }, "{completed:?}");

    // The second request returns the stored result and runs nothing.
    let second = f.chrome("evxRunJob", json!({ "job": JOB })).await.unwrap();
    assert_eq!(second["stored"], true, "{second}");
    assert_eq!(second["occurrence"], occurrence);
    assert_eq!(second["result"]["status"], stored_status);
    assert!(second["result"]["elapsed_ms"].is_u64(), "a float-free summary: {second}");

    // One reservation for the slot, one run at most, and the schedule moved
    // past it even where the scheduler found the slot already claimed.
    let snapshot = f.service.durable().snapshot(&f.address).unwrap();
    assert_eq!(snapshot.invocations.len(), 1, "{:?}", snapshot.invocations);
    let runs = f.runs();
    assert_eq!(runs.len(), usize::from(can_run), "{runs:?}");
    if can_run {
        assert_eq!(runs[0].occurrence.as_deref(), Some(occurrence.as_str()));
        assert!(runs[0].trigger == "manual_job" || runs[0].trigger == "job", "{runs:?}");
    }
    let job = wait_for(Duration::from_secs(5), "the schedule to move on", || async {
        let row = f.service.durable().jobs(&f.address).unwrap().remove(0);
        (row.next_due_unix.is_some_and(|due| due >= slot.end_unix)).then_some(row)
    })
    .await;
    assert_eq!(job.last_slot, Some(slot.index));
    assert_eq!(job.last_occurrence.as_deref(), Some(occurrence.as_str()));
    assert_eq!(job.failures, u32::from(!can_run));
    // Unknown and unregistered jobs are refused, not invented.
    f.refused("evxRunJob", json!({ "job": "nightly" }), "not registered").await;
    assert!(f.chrome("evxRunJob", json!({ "job": "no such job!" })).await.is_err());
    assert!(f.chrome("evxRunJob", json!({})).await.is_err(), "job is required");
}

#[tokio::test]
async fn recovery_retries_an_open_occurrence_of_the_current_slot_and_abandons_a_stale_one() {
    let f = Fixture::new(Options { jobs: vec![(JOB, 3600), ("old", 60)], ..Options::default() }).await;
    // Grant with the scheduler held off, so the test owns the reservations.
    f.state.set_plugin_enabled(PLUGIN_NAME, false).await;
    f.service
        .grant(&f.state, serde_json::from_value(f.enable_params().await).unwrap())
        .await
        .unwrap();
    let now = now_unix();
    let state = f.service.durable();
    let rows = state.jobs(&f.address).unwrap();
    let current_row = rows.iter().find(|row| row.job == JOB).unwrap();
    let current_slot = DurableState::slot_at(&current_row.schedule, now).unwrap();
    let current = state
        .claim_occurrence(&f.address, current_row, &current_slot, &request(current_row, &current_slot), now)
        .unwrap();
    assert!(current.fresh);
    let old_row = rows.iter().find(|row| row.job == "old").unwrap();
    let stale_slot = DurableState::slot_at(&old_row.schedule, now - 600).unwrap();
    let stale = state
        .claim_occurrence(&f.address, old_row, &stale_slot, &request(old_row, &stale_slot), now)
        .unwrap();
    assert!(stale.fresh);
    assert_eq!(state.incomplete_occurrences(Some(&f.address)).unwrap().len(), 2);
    // The daily budget survives too; spend one unit to see it.
    state.reserve_daily_run(&f.address, now, BACKGROUND_RUNS_PER_DAY).unwrap();
    // The old scheduler is stopped before the switch goes back on, so it
    // cannot pick the reservations up itself.
    f.service.shutdown();
    tokio::task::yield_now().await;
    f.state.set_plugin_enabled(PLUGIN_NAME, true).await;

    // A restart: the new scheduler examines both reservations once.
    let f = f.reopen().await;
    let can_run = f.service.execution().is_ok();
    let (retried, abandoned) = wait_for(Duration::from_secs(30), "both reservations to be settled", || async {
        let snapshot = f.service.durable().snapshot(&f.address).unwrap();
        let find = |id: &str| snapshot.invocations.iter().find(|row| row.occurrence == id).cloned();
        match (find(&current.occurrence), find(&stale.occurrence)) {
            (Some(a), Some(b)) if a.response.is_some() && b.response.is_some() => Some((a, b)),
            _ => None,
        }
    })
    .await;
    // The current slot ran again under the same identity: a rotated token,
    // the same occurrence, one result.
    assert_ne!(retried.token, current.token, "recover rotates the fencing token");
    let retried_status = retried.response.as_ref().unwrap()["status"].clone();
    assert_eq!(retried_status, if can_run { "ok" } else { "denied" }, "{retried:?}");
    let runs = f.runs();
    let retried_runs: Vec<_> = runs.iter().filter(|run| run.occurrence.as_deref() == Some(current.occurrence.as_str())).collect();
    assert_eq!(retried_runs.len(), usize::from(can_run), "retried once: {runs:?}");
    if can_run {
        assert_eq!(retried_runs[0].trigger, "job");
        assert_eq!(retried_runs[0].status, "ok");
    }
    // The stale one is finished as abandoned and recorded as such.
    assert_eq!(abandoned.response.as_ref().unwrap()["status"], "abandoned");
    let abandoned_run = runs.iter().find(|run| run.occurrence.as_deref() == Some(stale.occurrence.as_str())).unwrap();
    assert_eq!(abandoned_run.status, "abandoned");
    assert_eq!(abandoned_run.trigger, "job");
    assert_eq!(abandoned_run.program, PROGRAM);
    let old = f.service.durable().jobs(&f.address).unwrap().into_iter().find(|row| row.job == "old").unwrap();
    assert!(old.next_due_unix.is_some_and(|due| due >= stale_slot.end_unix), "the schedule moved on: {old:?}");
    assert_eq!(old.failures, 0, "abandonment is not the program's failure");
    // The budget was not reset by the reopen.
    assert!(f.service.durable().daily_runs(&f.address, now_unix()).unwrap() >= 1);
    let status = f.call(&f.page(), "evxStatus", json!({}), 1).await.unwrap();
    assert!(status["runs"].as_array().unwrap().iter().any(|run| run["status"] == "abandoned"), "{status}");
}

/// The exact request `claim_occurrence` requires.
fn request(row: &evx_state::JobRow, slot: &evx_state::Slot) -> Value {
    json!({ "job": row.job, "slot": slot.index, "program": row.program, "declaration_digest": row.declaration_digest })
}

#[tokio::test]
async fn every_authority_refusal_is_visible_on_the_job_and_re_enabling_resumes_on_the_current_slot() {
    let f = Fixture::new(Options::with_job(3600)).await;
    let page = f.page();
    // No grant: nothing registered, the xite-level reason says why.
    let before = f.status().await;
    assert!(before["reasons"].as_array().unwrap().contains(&json!("no_grant")));
    assert_eq!(before["jobs"], json!([]));

    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let can_run = f.service.execution().is_ok();
    let slot = DurableState::slot_at(&f.service.durable().jobs(&f.address).unwrap()[0].schedule, now_unix()).unwrap();
    if can_run {
        // The grant woke the scheduler: the current slot is claimed and run.
        wait_for(Duration::from_secs(20), "the first scheduled run", || async { (!f.runs().is_empty()).then_some(()) }).await;
        assert_eq!(f.job(JOB).await["last_slot"], slot.index);
    } else {
        let job = f.job(JOB).await;
        assert_eq!(job["waiting_reason"], "unsupported_host", "{job}");
        assert!(job["last_slot"].is_null(), "nothing was claimed: {job}");
    }

    // A grant without background authority (given to a declaration that
    // had no jobs, say): the registered job waits with the reason.
    let (mut grant, _) = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    grant.allow_background = false;
    f.service.durable().set_xite_grant(&grant).unwrap();
    let job = f.job(JOB).await;
    assert_eq!(job["waiting_reason"], "background_not_allowed", "{job}");
    assert!(f.status().await["reasons"].as_array().unwrap().contains(&json!("background_not_allowed")));
    // Expired: an expiry must follow the consent, so the consent is dated
    // back with it.
    grant.allow_background = true;
    grant.created_unix = now_unix() - 10;
    grant.expires_unix = Some(now_unix() - 1);
    f.service.durable().set_xite_grant(&grant).unwrap();
    assert_eq!(f.job(JOB).await["waiting_reason"], "expired");
    grant.expires_unix = None;
    f.service.durable().set_xite_grant(&grant).unwrap();
    // Paused by the operator, then resumed on the same slot.
    let paused = f.chrome("evxJobPause", json!({ "job": JOB })).await.unwrap();
    assert_eq!(paused["paused_reason"], "user", "{paused}");
    assert_eq!(paused["waiting_reason"], "paused");
    assert_eq!(f.call(&page, "evxStatus", json!({}), 1).await.unwrap()["jobs"][0]["paused_reason"], "user");
    f.refused("evxJobPause", json!({ "job": "nightly" }), "unknown job").await;
    let resumed = f.chrome("evxJobResume", json!({ "job": JOB })).await.unwrap();
    assert!(resumed["paused_reason"].is_null(), "{resumed}");
    assert_ne!(resumed["waiting_reason"], "paused");
    // Disabled plugin: the scheduler says so and admits nothing.
    f.state.set_plugin_enabled(PLUGIN_NAME, false).await;
    let disabled = f.status().await;
    assert_eq!(disabled["scheduler"]["enabled"], false);
    assert_eq!(disabled["jobs"][0]["waiting_reason"], "plugin_disabled");
    assert!(disabled["reasons"].as_array().unwrap().contains(&json!("plugin_disabled")));
    f.state.set_plugin_enabled(PLUGIN_NAME, true).await;
    // A declaration that outgrew its grant: re-signed asking for a
    // capability the grant does not hold. The next inspection re-registers
    // the job under the new digest and pauses it until a new grant.
    let wider = f.resign(Options { capabilities: vec!["workspace.read"], ..Options::with_job(3600) });
    assert_ne!(wider, f.digest);
    let inspect = f.call(&page, "evxInspect", json!({}), 2).await.unwrap();
    assert_eq!(inspect["declaration_digest"], wider);
    assert_eq!(inspect["grant"]["covers_declaration"], false);
    let job = f.job(JOB).await;
    assert_eq!(job["paused_reason"], "declaration_outgrew_grant", "{job}");
    assert_eq!(job["declaration_digest"], wider);
    assert_eq!(job["waiting_reason"], "paused");
    f.refused("evxRunJob", json!({ "job": JOB }), "paused").await;
    // A new grant for the wider declaration lifts the pause.
    let granted = f
        .chrome("evxGrant", f.enable_params_at(&f.address, &wider).await)
        .await
        .unwrap();
    assert_eq!(granted["grant"]["capabilities"], json!(["workspace.read"]));
    assert!(f.job(JOB).await["paused_reason"].is_null());
    // Revoked, then granted again: the job resumes on the slot current then,
    // never on a missed one.
    f.chrome("evxRevoke", json!({})).await.unwrap();
    let job = f.job(JOB).await;
    assert_eq!(job["waiting_reason"], "revoked", "{job}");
    assert_eq!(f.service.durable().jobs(&f.address).unwrap().len(), 1, "registration survives a revocation");
    f.chrome("evxGrant", f.enable_params_at(&f.address, &wider).await)
        .await
        .unwrap();
    let job = f.job(JOB).await;
    assert_ne!(job["waiting_reason"], "revoked", "{job}");
    let current = DurableState::slot_at(&f.service.durable().jobs(&f.address).unwrap()[0].schedule, now_unix()).unwrap();
    assert!(job["next_due_unix"].as_u64().unwrap() <= current.end_unix, "{job}");
    if can_run {
        // The slot of the first run was this one too (an hour is long), so
        // the scheduler finds it claimed and steps to the next slot rather
        // than running it twice.
        let row = wait_for(Duration::from_secs(10), "the schedule to step past the claimed slot", || async {
            let row = f.service.durable().jobs(&f.address).unwrap().remove(0);
            (row.next_due_unix == Some(current.end_unix)).then_some(row)
        })
        .await;
        assert_eq!(row.last_slot, Some(current.index));
        assert_eq!(f.runs().iter().filter(|run| run.trigger == "job").count(), 1, "the slot ran once");
    }
}

#[tokio::test]
async fn a_xite_past_its_daily_budget_waits_with_the_reason_and_nothing_starts() {
    let f = Fixture::new(Options::with_job(1)).await;
    // Spend the whole day before the grant, so the first tick already waits.
    let now = now_unix();
    for _ in 0..BACKGROUND_RUNS_PER_DAY {
        f.service.durable().reserve_daily_run(&f.address, now, BACKGROUND_RUNS_PER_DAY).unwrap();
    }
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let job = f.job(JOB).await;
    assert_eq!(job["waiting_reason"], "daily_budget", "{job}");
    assert_eq!(job["runs_today"], BACKGROUND_RUNS_PER_DAY);
    assert_eq!(job["daily_limit"], BACKGROUND_RUNS_PER_DAY);
    assert!(job["last_slot"].is_null(), "a slot was claimed past the budget: {job}");
    assert!(f.runs().is_empty());
    assert!(f.service.durable().incomplete_occurrences(None).unwrap().is_empty());
    // The scheduler sleeps until the next UTC day, not a busy loop (a host
    // that cannot execute has nothing to wake for at all).
    let status = f.status().await;
    let next_day = (now / 86_400 + 1) * 86_400;
    if f.service.execution().is_ok() {
        assert!(status["scheduler"]["next_wake_unix"].as_u64().is_some_and(|wake| wake >= next_day), "{status}");
    } else {
        assert!(status["scheduler"]["next_wake_unix"].is_null(), "{status}");
    }
    // The budget does not stop a manual run: it bounds what the node
    // starts by itself.
    let manual = f.chrome("evxRunJob", json!({ "job": JOB })).await;
    if f.service.execution().is_ok() {
        assert_eq!(manual.unwrap()["value"], 42);
    } else {
        assert_eq!(manual.unwrap_err(), UNSUPPORTED_HOST);
    }
}

#[tokio::test]
async fn disabling_the_plugin_stops_admission_and_re_enabling_resumes_it() {
    let f = Fixture::new(Options::with_job(1)).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let can_run = f.service.execution().is_ok();
    if can_run {
        wait_for(Duration::from_secs(20), "the first scheduled run", || async { (!f.runs().is_empty()).then_some(()) }).await;
    }
    f.state.set_plugin_enabled(PLUGIN_NAME, false).await;
    // The tick in flight, if any, finishes; from the next one on nothing
    // is admitted.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let count = f.runs().len();
    let claimed = f.service.durable().jobs(&f.address).unwrap()[0].last_slot;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(f.runs().len(), count, "a run was admitted while the plugin was disabled");
    assert_eq!(f.service.durable().jobs(&f.address).unwrap()[0].last_slot, claimed, "a slot was claimed while disabled");
    let status = f.status().await;
    assert_eq!(status["scheduler"]["enabled"], false);
    assert_eq!(status["jobs"][0]["waiting_reason"], "plugin_disabled");
    // The plugin's commands are not dispatched while it is off.
    assert_eq!(f.chrome("evxStatus", json!({})).await.unwrap(), Value::Null);
    // Re-enabled: the poll notices within its interval and admission resumes.
    f.state.set_plugin_enabled(PLUGIN_NAME, true).await;
    if can_run {
        wait_for(Duration::from_secs(10), "admission to resume", || async { (f.runs().len() > count).then_some(()) }).await;
    } else {
        let status = wait_for(Duration::from_secs(10), "the scheduler to report itself enabled", || async {
            let status = f.status().await;
            (status["scheduler"]["enabled"] == true).then_some(status)
        })
        .await;
        assert_eq!(status["jobs"][0]["waiting_reason"], "unsupported_host");
    }
}

#[tokio::test]
async fn a_job_whose_program_cannot_be_bound_is_registered_paused_with_the_reason() {
    let f = Fixture::new(Options::with_job(3600)).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    assert!(f.job(JOB).await["paused_reason"].is_null());
    // Re-signed with the entry no longer pinned by the manifest: the
    // program cannot be bound, so it is unusable and so is the job, visibly.
    let unpinned = f.resign(Options { pin_entry: false, ..Options::with_job(3600) });
    let inspect = f.call(&f.page(), "evxInspect", json!({}), 1).await.unwrap();
    assert_eq!(inspect["declaration_digest"], unpinned);
    assert_eq!(inspect["declaration"]["programs"][PROGRAM]["usable"], false, "{inspect}");
    assert_eq!(inspect["declaration"]["jobs"][JOB]["usable"], false, "{inspect}");
    assert_eq!(inspect["effective"]["allow_background"], false);
    assert!(inspect["unsupported"].as_array().unwrap().iter().any(|item| item["path"] == format!("jobs.{JOB}")), "{inspect}");
    let job = f.job(JOB).await;
    assert_eq!(job["paused_reason"], "program_unsupported", "{job}");
    assert_eq!(job["waiting_reason"], "paused");
    f.refused("evxRunJob", json!({ "job": JOB }), "paused").await;
}

#[tokio::test]
async fn an_enable_grant_is_refused_when_the_bound_closure_changed_since_the_dialog_showed_it() {
    // The dialog is rendered from a manifest that does not pin the program:
    // nothing is usable, so it shows no background paragraph.
    let f = Fixture::new(Options { pin_entry: false, ..Options::with_job(3600) }).await;
    let shown_then = f.enable_params().await;
    assert_eq!(shown_then["shown"]["allow_background"], false, "{shown_then}");
    assert_eq!(shown_then["shown"]["jobs"], json!([]));
    assert_eq!(shown_then["shown"]["programs"], json!([]));
    // While the user reads it, a re-sign pins the program and leaves the
    // `evx` object alone: the digest is the same, the closure is wider.
    let digest = f.resign(Options::with_job(3600));
    assert_eq!(digest, f.digest, "the digest covers the evx object only");
    let denied = f.chrome("evxGrant", shown_then).await.unwrap_err();
    assert_eq!(denied, epix_evx::SHOWN_CHANGED);
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none(), "nothing was recorded");
    assert!(f.service.durable().jobs(&f.address).unwrap().is_empty(), "nothing was registered");
    // A request that does not say what was shown is refused too.
    let mut bare = f.enable_params().await;
    bare.as_object_mut().unwrap().remove("shown");
    let denied = f.chrome("evxGrant", bare).await.unwrap_err();
    assert!(denied.contains("shown"), "{denied}");
    // Each part counts: a dialog that said run-once is not requested, or
    // that listed no jobs, did not show what enabling would record now.
    let shown_now = f.enable_params().await;
    assert_eq!(shown_now["shown"]["allow_background"], true, "{shown_now}");
    assert_eq!(shown_now["shown"]["jobs"], json!([JOB]));
    for (field, value) in [("allow_run_once", json!(false)), ("jobs", json!([])), ("allow_background", json!(false)), ("programs", json!([]))] {
        let mut narrower = shown_now.clone();
        narrower["shown"][field] = value;
        let denied = f.chrome("evxGrant", narrower).await.unwrap_err();
        assert_eq!(denied, epix_evx::SHOWN_CHANGED, "{field}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    // `shown` is part of an enable grant only.
    let mut once = json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM });
    once["shown"] = shown_now["shown"].clone();
    assert!(f.chrome("evxGrant", once).await.is_err());
    // Shown again: the dialog names the job, and the grant records exactly
    // the background authority it named.
    f.chrome("evxGrant", shown_now).await.unwrap();
    let (grant, _) = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    assert!(grant.allow_background);
    assert!(grant.allow_run_once);
    assert_eq!(f.service.durable().jobs(&f.address).unwrap()[0].job, JOB);
}

/// Wait until the scheduler has stopped ticking (no tick for 400 ms) and
/// return how many ticks it completed.
async fn settled_ticks(f: &Fixture) -> u64 {
    let mut last = f.service.scheduler_ticks();
    loop {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let now = f.service.scheduler_ticks();
        if now == last && now > 0 {
            return now;
        }
        last = now;
    }
}

#[tokio::test]
async fn a_content_change_for_a_xite_with_jobs_re_registers_it_with_no_evx_command_and_one_for_another_xite_wakes_nothing() {
    // No worker, so nothing runs and the scheduler only ticks when woken.
    let worker_dir = tempfile::tempdir().unwrap();
    let missing = worker_dir.path().join("no-such-worker");
    let options = || Options { worker: Some(missing.clone()), ..Options::with_job(3600) };
    let f = Fixture::new(options()).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let other = f.add_xite(Options { worker: Some(missing.clone()), ..Options::default() }).await;
    let settled = settled_ticks(&f).await;
    let wake_before = f.status().await["scheduler"]["next_wake_unix"].clone();
    // A change to a xite without jobs: no tick.
    f.state.push_xite_info(&other.address).await;
    tokio::time::sleep(epix_evx::scheduler::CONTENT_WAKE_COALESCE + Duration::from_millis(800)).await;
    assert_eq!(f.service.scheduler_ticks(), settled, "an unrelated xite's change woke the scheduler");
    assert_eq!(f.status().await["scheduler"]["next_wake_unix"], wake_before);
    // The publisher re-signs asking for more, the node announces the change
    // the way it announces every content change, and nobody sends an EVX
    // command: the scheduler inspects the xite by itself, re-registers the
    // job under the new digest and pauses it, since the grant no longer
    // covers the declaration.
    let wider = f.resign(Options { capabilities: vec!["workspace.read"], ..options() });
    assert_ne!(wider, f.digest);
    f.state.push_xite_info(&f.address).await;
    let row = wait_for(
        epix_evx::scheduler::CONTENT_WAKE_COALESCE + Duration::from_secs(3),
        "the re-signed declaration to be registered",
        || async {
            let row = f.service.durable().jobs(&f.address).unwrap().remove(0);
            (row.declaration_digest == wider).then_some(row)
        },
    )
    .await;
    assert_eq!(row.paused_reason.as_deref(), Some("declaration_outgrew_grant"));
    assert!(f.service.scheduler_ticks() > settled);
    // The declaration then disappears in another re-sign: the job is held
    // with the reason, not retried every tick, and a later fix clears it,
    // again with no EVX command.
    let settled = settled_ticks(&f).await;
    let root = f.served_root();
    let mut gone = f.xite.content.clone();
    gone.as_object_mut().unwrap().remove("evx");
    epix_content::sign(&mut gone, &f.xite.key).unwrap();
    XiteStorage::new(&root).write("content.json", epix_content::dumps_content(&gone).as_bytes()).unwrap();
    f.state.push_xite_info(&f.address).await;
    wait_for(epix_evx::scheduler::CONTENT_WAKE_COALESCE + Duration::from_secs(3), "the job to be held", || async {
        let job = f.job(JOB).await;
        (job["paused_reason"] == "declaration_unavailable").then_some(())
    })
    .await;
    assert!(f.service.scheduler_ticks() > settled);
    f.resign(options());
    f.state.push_xite_info(&f.address).await;
    let row = wait_for(epix_evx::scheduler::CONTENT_WAKE_COALESCE + Duration::from_secs(3), "the hold to clear", || async {
        let row = f.service.durable().jobs(&f.address).unwrap().remove(0);
        row.paused_reason.is_none().then_some(row)
    })
    .await;
    assert_eq!(row.declaration_digest, f.digest);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod execution {
    use super::*;
    use evx_api::Status;

    /// A program that traps: every run is an `error`.
    const TRAP: &str = r#"(module (memory (export "memory") 1) (func (export "run") (result i32) unreachable))"#;

    #[tokio::test]
    async fn a_one_second_job_runs_on_its_own_with_no_page_open_and_stops_after_a_revocation() {
        let f = Fixture::new(Options::with_job(1)).await;
        // The wrapper's dialog answer is the only command sent; no page
        // socket is ever opened and no manual run requested.
        f.chrome("evxGrant", f.enable_params().await).await.unwrap();
        let runs = wait_for(Duration::from_secs(20), "two scheduled runs", || async {
            let runs = f.runs();
            (runs.len() >= 2).then_some(runs)
        })
        .await;
        for run in &runs {
            assert_eq!(run.trigger, "job", "{run:?}");
            assert_eq!(run.status, "ok", "{run:?}");
            let occurrence = run.occurrence.as_deref().expect("a scheduled run names its occurrence");
            let (job, _) = evx_state::occurrence_parts(occurrence).unwrap();
            assert_eq!(job, JOB);
        }
        let mut occurrences: Vec<_> = runs.iter().map(|run| run.occurrence.clone()).collect();
        occurrences.dedup();
        assert_eq!(occurrences.len(), runs.len(), "an occurrence ran twice: {runs:?}");
        let status = f.call(&f.operator(), "evxStatus", json!({ "xite": f.address }), 1).await.unwrap();
        assert_eq!(status["runs"][0]["trigger"], "job");
        assert!(status["runs"][0]["occurrence"].is_string());
        assert_eq!(status["jobs"][0]["failures"], 0);
        assert!(status["jobs"][0]["runs_today"].as_u64().unwrap() >= 2);
        assert!(status["jobs"][0]["waiting_reason"].is_null() || status["jobs"][0]["waiting_reason"] == "xite_busy", "{status}");

        // Revoked: nothing further starts within a period, and a run in
        // flight is stopped through its broker.
        f.chrome("evxRevoke", json!({})).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let after = f.runs().len();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(f.runs().len(), after, "a run started after the revocation");
        assert_eq!(f.job(JOB).await["waiting_reason"], "revoked");
    }

    /// The reset of the count on a success is the service unit test's
    /// business (`a_failed_or_refused_occurrence_counts_and_backs_off_and_an_unknown_effect_pauses`);
    /// a program that always traps cannot show it here.
    #[tokio::test]
    async fn a_failing_job_backs_off_with_the_persisted_next_due_and_a_manual_run_doubles_it() {
        let f = Fixture::new(Options { wat: TRAP, ..Options::with_job(1) }).await;
        f.chrome("evxGrant", f.enable_params().await).await.unwrap();
        let row = wait_for(Duration::from_secs(20), "the first failed run", || async {
            let row = f.service.durable().jobs(&f.address).unwrap().remove(0);
            (row.failures >= 1).then_some(row)
        })
        .await;
        let now = now_unix();
        assert_eq!(row.failures, 1, "{row:?}");
        // Backed off a minute, well past the one-second period, and stored.
        let next_due = row.next_due_unix.unwrap();
        assert!(next_due >= now + 55 && next_due <= now + 65, "{row:?}");
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(f.runs().len(), 1, "a run started during the backoff");
        assert_eq!(f.runs()[0].status, "error");
        let job = f.job(JOB).await;
        assert!(job["waiting_reason"].is_null(), "a backoff is a due time, not a block: {job}");
        assert_eq!(job["next_due_unix"], next_due);
        // The stored summary of the occurrence is float-free and says error.
        let snapshot = f.service.durable().snapshot(&f.address).unwrap();
        let stored = snapshot.invocations.iter().find(|row| row.response.is_some()).unwrap();
        assert_eq!(stored.response.as_ref().unwrap()["status"], "error");
        // A manual run of the next slot fails too and doubles the backoff.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let manual = f.chrome("evxRunJob", json!({ "job": JOB })).await.unwrap();
        assert_eq!(manual["status"], serde_json::to_value(Status::Error).unwrap(), "{manual}");
        let row = f.service.durable().jobs(&f.address).unwrap().remove(0);
        assert_eq!(row.failures, 2);
        assert!(row.next_due_unix.unwrap() >= now_unix() + 115, "{row:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_xites_run_within_one_tick_and_a_third_waits_for_a_worker() {
        // Each run holds a worker for its three-second wall ceiling.
        let slow = || Options {
            wat: SPIN,
            limits: Some(json!({ "fuel": HOST_CEILING.fuel, "wall_seconds": 3.0, "process_cpu_seconds": 3.0 })),
            ..Options::with_job(1)
        };
        let f = Fixture::new(slow()).await;
        let b = f.add_xite(slow()).await;
        let c = f.add_xite(slow()).await;
        // Granted with the scheduler held off (the dispatcher drops a
        // disabled plugin's commands, so the service is called directly),
        // then released: one tick sees all three due at once.
        f.state.set_plugin_enabled(PLUGIN_NAME, false).await;
        for xite in [&f.xite, &b, &c] {
            f.service
                .grant(&f.state, serde_json::from_value(f.enable_params_for(xite).await).unwrap())
                .await
                .unwrap();
        }
        f.state.set_plugin_enabled(PLUGIN_NAME, true).await;
        // Worker slots are reserved before broker registration. Observe both
        // admissions, rather than treating the earlier capacity snapshot as
        // an atomic snapshot of three separately queried xite statuses.
        wait_for(Duration::from_secs(10), "two running xites and one waiting", || async {
            let mut running = 0;
            let mut waiting = Vec::new();
            for xite in [&f.address, &b.address, &c.address] {
                let status = f.service.status(&f.state, xite).await.unwrap();
                if status["running"] == true {
                    running += 1;
                } else {
                    waiting.push(status["jobs"][0]["waiting_reason"].clone());
                }
            }
            (running == 2 && waiting == [json!("workers_busy")]
                && f.status().await["scheduler"]["busy_workers"] == 2).then_some(())
        }).await;
        // Once a worker is free the third runs.
        wait_for(Duration::from_secs(20), "every xite to have run", || async {
            [&f.address, &b.address, &c.address]
                .iter()
                .all(|xite| !f.service.durable().runs(xite).unwrap().is_empty())
                .then_some(())
        })
        .await;
    }

    #[tokio::test]
    async fn run_once_executes_the_baseline_program_through_the_real_worker() {
        let f = Fixture::new(Options::default()).await;
        assert!(f.service.execution().is_ok());
        f.chrome("evxGrant", f.enable_params().await).await.unwrap();
        let served_before = f.served_files();

        let outcome = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap();
        assert_eq!(outcome["status"], serde_json::to_value(Status::Ok).unwrap(), "{outcome}");
        assert_eq!(outcome["value"], 42);
        assert_eq!(outcome["worker_started"], true);
        assert_eq!(outcome["authority"], "grant");
        assert_eq!(outcome["activation"]["xite"], f.address);
        assert_eq!(outcome["activation"]["publisher"], f.address);
        assert_eq!(outcome["activation"]["program"], PROGRAM);
        assert_eq!(outcome["activation"]["declaration_digest"], f.digest);
        assert_eq!(outcome["activation"]["version"], 1_700_000_000_000u64);
        assert_eq!(outcome["activation"]["grant_generation"], 1);
        assert!(outcome["checkpoint_error"].is_null());
        assert_eq!(outcome["run"]["status"], "ok");

        // The floor was persisted, the run recorded, the workspace created
        // under private/evx, and the served root left alone.
        let checkpoint: Value = serde_json::from_slice(&std::fs::read(f.service.checkpoint_path(&f.address)).unwrap()).unwrap();
        assert_eq!(checkpoint["version"], 1_700_000_000_000u64);
        assert_eq!(checkpoint["manifest_digest"], outcome["activation"]["manifest_digest"]);
        let runs = f.service.durable().runs(&f.address).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "ok");
        assert_eq!(runs[0].program, PROGRAM);
        assert_eq!(runs[0].declaration_digest, f.digest);
        assert_eq!(runs[0].artifact_sha256, outcome["activation"]["artifact_sha256"]);
        assert!(f.service.workspace_dir(&f.address).is_dir());
        assert_eq!(f.served_files(), served_before);
        let status = f.call(&f.page(), "evxStatus", json!({}), 1).await.unwrap();
        assert_eq!(status["runs"][0]["status"], "ok");
        assert_eq!(status["run_count"], 1);

        // The same version runs again under the same grant (no new prompt).
        let again = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap();
        assert_eq!(again["value"], 42, "{again}");
        assert_eq!(f.service.durable().runs(&f.address).unwrap().len(), 2);

        // Revoked: refused before any worker starts, and recorded as such
        // only if it got as far as the activation (it does not).
        f.chrome("evxRevoke", json!({})).await.unwrap();
        let denied = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap_err();
        assert!(denied.contains("no enabled EVX grant"), "{denied}");
        assert_eq!(f.service.durable().runs(&f.address).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn an_allow_once_token_runs_exactly_once() {
        let f = Fixture::new(Options::default()).await;
        let minted = f
            .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
            .await
            .unwrap();
        let token = minted["token"].as_str().unwrap().to_string();
        // No persistent grant: a plain run is refused.
        let denied = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap_err();
        assert!(denied.contains("no enabled EVX grant"), "{denied}");
        let outcome = f.chrome("evxRunOnce", json!({ "program": PROGRAM, "token": token })).await.unwrap();
        assert_eq!(outcome["value"], 42, "{outcome}");
        assert_eq!(outcome["authority"], "once");
        let spent = f.chrome("evxRunOnce", json!({ "program": PROGRAM, "token": token })).await.unwrap_err();
        assert!(spent.contains("token"), "{spent}");
        assert_eq!(f.service.durable().runs(&f.address).unwrap().len(), 1);
        assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none(), "a run never created a grant");
    }

    #[tokio::test]
    async fn an_allow_once_token_survives_a_program_file_that_cannot_be_read() {
        let f = Fixture::new(Options::default()).await;
        let minted = f
            .chrome("evxGrant", json!({ "xite": f.address, "declaration_digest": f.digest, "mode": "once", "program": PROGRAM }))
            .await
            .unwrap();
        let token = minted["token"].as_str().unwrap().to_string();
        // The entry file grows past its signed size on disk (a local edit
        // after signing): the bounded read refuses it before any run, and
        // a refusal that ran nothing must spend nothing.
        {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new().append(true).open(f.served_root().join(ENTRY_PATH)).unwrap();
            file.write_all(b"\0").unwrap();
        }
        let denied = f.chrome("evxRunOnce", json!({ "program": PROGRAM, "token": token })).await.unwrap_err();
        assert!(denied.contains(ENTRY_PATH), "{denied}");
        assert!(f.service.durable().runs(&f.address).unwrap().is_empty(), "nothing ran");
        assert!(!f.service.workspace_dir(&f.address).exists(), "no workspace was created");
        assert!(
            f.service.durable().consume_allow_once(&f.address, &token, &f.digest, PROGRAM).unwrap(),
            "the token was spent although nothing ran"
        );
    }

    /// Spins until the grant is revoked: a billion units of fuel spent
    /// mostly on a dependent chain of divisions and square roots, which
    /// cost one unit each but tens of cycles, so the run outlives the
    /// test's revocation by seconds and the 30 s wall ceiling ends it
    /// otherwise.
    const SPIN: &str = r#"(module (memory (export "memory") 1)
        (func (export "run") (result i32)
            (local $x f64)
            (local.set $x (f64.const 1234567.5))
            (loop
                (local.set $x (f64.div (f64.const 98765432.25) (f64.sqrt (f64.div (f64.const 8765432.5) (f64.sqrt (f64.add (local.get $x) (f64.const 2.5)))))))
                (local.set $x (f64.div (f64.const 12345678.75) (f64.sqrt (f64.div (f64.const 7654321.5) (f64.sqrt (f64.add (local.get $x) (f64.const 3.5)))))))
                (local.set $x (f64.div (f64.const 23456789.25) (f64.sqrt (f64.div (f64.const 6543210.5) (f64.sqrt (f64.add (local.get $x) (f64.const 4.5)))))))
                (local.set $x (f64.div (f64.const 34567890.75) (f64.sqrt (f64.div (f64.const 5432109.5) (f64.sqrt (f64.add (local.get $x) (f64.const 5.5)))))))
                (br 0))
            i32.const 0))"#;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_run_queued_before_plugin_disable_cannot_start_afterward() {
        let f = Arc::new(Fixture::new(Options {
            wat: SPIN,
            limits: Some(json!({ "fuel": HOST_CEILING.fuel, "wall_seconds": 3.0, "process_cpu_seconds": 3.0 })),
            ..Options::default()
        }).await);
        f.chrome("evxGrant", f.enable_params().await).await.unwrap();
        let first = tokio::spawn({
            let f = f.clone();
            async move { f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await }
        });
        wait_for(Duration::from_secs(20), "first manual run", || async {
            (f.status().await["running"] == true).then_some(())
        }).await;
        // Poll the second command while enabled so it passes the dispatcher
        // and waits on the same xite lock. It must recheck at admission.
        let queued = f.chrome("evxRunOnce", json!({ "program": PROGRAM }));
        tokio::pin!(queued);
        tokio::select! {
            result = &mut queued => panic!("queued run finished early: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        f.state.set_plugin_enabled(PLUGIN_NAME, false).await;
        let result = tokio::time::timeout(Duration::from_secs(10), &mut queued).await.unwrap();
        first.await.unwrap().unwrap();
        assert!(result.is_err(), "a queued run started while disabled: {result:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_run_queued_behind_a_revocation_is_refused_rather_than_run_under_the_revoked_grant() {
        let f = Arc::new(
            Fixture::new(Options {
                wat: SPIN,
                limits: Some(json!({ "fuel": HOST_CEILING.fuel, "wall_seconds": 30.0, "process_cpu_seconds": 30.0 })),
                ..Options::default()
            })
            .await,
        );
        f.chrome("evxGrant", f.enable_params().await).await.unwrap();

        // Run 1 spins; run 2 queues behind it on the xite's run lock.
        let first = tokio::spawn({
            let f = Arc::clone(&f);
            async move { f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await }
        });
        let started = std::time::Instant::now();
        loop {
            let status = f.call(&f.page(), "evxStatus", json!({}), 1).await.unwrap();
            if status["running"] == true {
                break;
            }
            assert!(started.elapsed() < std::time::Duration::from_secs(20), "run 1 never started: {status}");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let second = tokio::spawn({
            let f = Arc::clone(&f);
            async move { f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await }
        });
        // Long enough for run 2 to reach the lock; run 1 is held for the
        // wall ceiling if nothing stops it.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // The revocation stops run 1 through its broker; run 2, whose turn
        // comes afterwards, must see the revoked grant, not the one it was
        // queued under.
        let revoked = f.chrome("evxRevoke", json!({})).await.unwrap();
        let first = first.await.unwrap().unwrap();
        assert_eq!(revoked["stopped_run"], true, "{revoked}; run 1: {first}");
        assert_ne!(first["status"], serde_json::to_value(Status::Ok).unwrap(), "{first}");
        // Status becomes running while compilation is active too. Cancellation
        // there carries the same typed cause as stopping an admitted guest.
        // A grant already disabled at admission reports "opt-in required".
        let error = first["error"].as_str().unwrap_or_default();
        assert!(first["host_cancellation"] == "authority_changed"
            || error.contains("revoked") || error.contains("opt-in"), "{first}");
        let second = second.await.unwrap().unwrap_err();
        assert!(second.contains("no enabled EVX grant"), "{second}");
        let runs = f.service.durable().runs(&f.address).unwrap();
        assert_eq!(runs.len(), 1, "run 2 was recorded: {runs:?}");
        let status = f.call(&f.page(), "evxStatus", json!({}), 2).await.unwrap();
        assert_eq!(status["running"], false);
    }

    #[tokio::test]
    async fn a_program_asking_beyond_the_grant_is_refused_without_a_worker() {
        // Granted with no capabilities, then re-signed asking for one: the
        // update is authenticated but broader, so it waits for a new grant.
        let f = Fixture::new(Options::default()).await;
        f.chrome("evxGrant", f.enable_params().await).await.unwrap();
        let narrow = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap();
        assert_eq!(narrow["value"], 42, "{narrow}");
        let denied = f.chrome("evxRunOnce", json!({ "program": "other" })).await.unwrap_err();
        assert!(denied.contains("not usable"), "{denied}");
        assert_eq!(f.service.durable().runs(&f.address).unwrap().len(), 1);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn uncertain_workspace_write(f: &Fixture) {
    let workspace = f.service.workspace_dir(&f.address);
    std::fs::create_dir_all(&workspace).unwrap();
    let (grant, generations) = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    let broker = evx_supervisor::Broker::new(&workspace, evx_api::Grant {
        xite: f.address.clone(), enabled: true, generation: generations.generation,
        capabilities: [evx_api::Capability::WorkspaceWrite].into_iter().collect(),
        publisher: Some(f.address.clone()), publisher_public_key: None,
        runtime_profiles: grant.runtime_profiles,
    }, grant.limits).unwrap();
    let request = serde_json::to_vec(&json!({ "op": "workspace.write", "path": "score.txt", "text": "candidate" })).unwrap();
    let escaped: String = request.iter().map(|b| format!("\\{b:02x}")).collect();
    let wat = format!(r#"(module
        (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 1) (data (i32.const 0) "{escaped}")
        (func (export "run") (result i32)
          (call $call (i32.const 0) (i32.const {}) (i32.const 4096) (i32.const 4096))))"#, request.len());
    let config = evx_supervisor::Config::new(worker_binary());
    let artifact = evx_supervisor::compile_text(&config, wat.as_bytes()).unwrap();
    let result = evx_supervisor::run_guest(&config, &artifact, &broker, evx_supervisor::RunOptions {
        file_fault: Some(evx_api::frames::HelperFault::FailAfterReplace), ..Default::default()
    });
    assert_eq!(result.status, evx_api::Status::EffectUnknown, "{result:?}");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn job_resume_refuses_unregistered_workspace_bytes_before_clearing_pause() {
    let f = Fixture::without_scheduler(Options { capabilities: vec!["workspace.write"], ..Options::with_job(3600) }).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    uncertain_workspace_write(&f);
    f.service.durable().set_job_paused(&f.address, JOB, Some("reconcile_required")).unwrap();
    std::fs::write(f.service.workspace_dir(&f.address).join("score.txt"), "unregistered").unwrap();
    let result = f.chrome("evxJobResume", json!({ "job": JOB })).await;
    assert!(result.is_err(), "resume cleared an unreconciled pause: {result:?}");
    assert_eq!(f.service.durable().jobs(&f.address).unwrap()[0].paused_reason.as_deref(), Some("reconcile_required"));
    std::fs::write(f.service.workspace_dir(&f.address).join("score.txt"), "candidate").unwrap();
    f.chrome("evxJobResume", json!({ "job": JOB })).await.unwrap();
    assert!(f.service.durable().jobs(&f.address).unwrap()[0].paused_reason.is_none());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn explicit_operator_workspace_recovery_supports_interrupted_manual_runs() {
    let f = Fixture::without_scheduler(Options { capabilities: vec!["workspace.write"], ..Options::default() }).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    uncertain_workspace_write(&f);
    f.chrome("evxRevoke", json!({})).await.unwrap();
    let before = f.service.durable().xite_grant(&f.address).unwrap().unwrap();
    let recovered = f.call(&f.operator(), "evxRecoverWorkspace", json!({ "xite": f.address }), 1).await.unwrap();
    assert_eq!(recovered["reconciled_paths"], 1, "{recovered}");
    assert_eq!(f.service.durable().xite_grant(&f.address).unwrap().unwrap(), before);
    assert!(f.runs().is_empty(), "recovery executed a program");
    assert!(f.service.durable().jobs(&f.address).unwrap().is_empty());
    let again = f.call(&f.operator(), "evxRecoverWorkspace", json!({ "xite": f.address }), 2).await.unwrap();
    assert_eq!(again["reconciled_paths"], 0);
}

#[cfg(unix)]
#[tokio::test]
async fn workspace_recovery_rejects_a_symlink_root() {
    let f = Fixture::without_scheduler(Options::default()).await;
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), f.service.workspace_dir(&f.address)).unwrap();
    let result = f.call(&f.operator(), "evxRecoverWorkspace", json!({ "xite": f.address }), 1).await;
    assert!(result.is_err(), "recovery accepted a symlink root: {result:?}");
}

#[tokio::test]
async fn workspace_recovery_requires_chrome_or_operator_authority_without_granting_admin() {
    let f = Fixture::without_scheduler(Options::default()).await;
    assert_eq!(f.chrome("evxRecoverWorkspace", json!({})).await.unwrap()["reconciled_paths"], 0);
    assert!(!f.state.xite_has_admin(&f.address).await);
    f.state.add_permission(&f.address, "ADMIN").await;
    for id in [1, WRAPPER_ID_BASE + 1] {
        assert!(f.call(&f.page(), "evxRecoverWorkspace", json!({}), id).await.is_err());
    }
    assert!(f.call(&f.wrapper(), "evxRecoverWorkspace", json!({}), 1).await.is_err());
    let recovered = f.chrome("evxRecoverWorkspace", json!({})).await.unwrap();
    assert_eq!(recovered["reconciled_paths"], 0);
    assert!(f.chrome("evxRecoverWorkspace", json!({ "xite": "1Other" })).await.is_err());
    assert!(f.chrome("evxRecoverWorkspace", json!({ "extra": true })).await.is_err());
    f.state.config_set("ui_restrict", json!(true)).await;
    assert!(f.chrome("evxRecoverWorkspace", json!({})).await.is_err());
    assert!(f.call(&f.operator(), "evxRecoverWorkspace", json!({ "xite": f.address }), 1).await.is_ok());
}

#[tokio::test]
async fn workspace_recovery_with_no_pending_paths_needs_no_worker() {
    let f = Fixture::without_scheduler(Options { worker: Some(PathBuf::from("missing-evx-worker")), ..Options::default() }).await;
    std::fs::create_dir_all(f.service.workspace_dir(&f.address)).unwrap();
    assert!(f.service.execution().is_err());
    let result = f.call(&f.operator(), "evxRecoverWorkspace", json!({ "xite": f.address }), 1).await.unwrap();
    assert_eq!(result["reconciled_paths"], 0);
    assert!(f.runs().is_empty());
}

#[tokio::test]
async fn workspace_recovery_refuses_a_stopped_service() {
    let f = Fixture::without_scheduler(Options::default()).await;
    f.service.shutdown();
    let error = f.call(&f.operator(), "evxRecoverWorkspace", json!({ "xite": f.address }), 1).await.unwrap_err();
    assert!(error.contains("cancelled by host policy"), "{error}");
    assert!(f.runs().is_empty());
}

#[tokio::test]
async fn workspace_recovery_rejects_a_regular_file_root() {
    let f = Fixture::without_scheduler(Options::default()).await;
    std::fs::write(f.service.workspace_dir(&f.address), "fixture").unwrap();
    assert!(f.call(&f.operator(), "evxRecoverWorkspace", json!({ "xite": f.address }), 1).await.is_err());
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn direct_restart_refuses_a_live_native_helper_that_released_its_lease() {
    if let Ok(root) = std::env::var("EVX_DIRECT_CRASH_ROOT") {
        let root = PathBuf::from(root);
        let address = std::env::var("EVX_DIRECT_CRASH_XITE").unwrap();
        let worker = PathBuf::from(std::env::var("EVX_DIRECT_CRASH_WORKER").unwrap());
        let app = AppState::with_data_dir("direct-crash", &root);
        let stored = root.join("data").join(&address);
        let content: Value = serde_json::from_slice(&std::fs::read(stored.join("content.json")).unwrap()).unwrap();
        app.add_xite(&address, XiteEntry { storage: XiteStorage::new(&stored), content: Some(content) }).await;
        let service = Arc::new(EvxService::for_node(&app, Some(worker)).unwrap());
        let result = service.run_once(&app, &address, PROGRAM, None).await;
        panic!("old host completed before intentional crash: {result:?}");
    }
    let request = serde_json::to_vec(&json!({"op":"workspace.write","path":"orphan-score.txt","text":"second run"})).unwrap();
    let payload: String = request.iter().map(|byte| format!("\\{byte:02x}")).collect();
    let wat: &'static str = Box::leak(format!(r#"(module
      (import "evx" "call" (func $call (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1) (data (i32.const 0) "{payload}")
      (func (export "run") (result i32)
      i32.const 0 i32.const {} i32.const 4096 i32.const 4096 call $call))"#, request.len()).into_boxed_str());
    let f = Fixture::without_scheduler(Options { wat, capabilities: vec!["workspace.write"], ..Options::default() }).await;
    f.chrome("evxGrant", f.enable_params().await).await.unwrap();
    let worker = worker_binary();
    let code = f.dir.path().join("orphan.c");
    let wrapper = f.dir.path().join("orphan-worker");
    // This native substitute deliberately drops the lease, as compromised native
    // code can. It performs no EVX file operation and self-terminates after 30s.
    std::fs::write(&code, format!(r#"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
int main(int argc, char **argv) {{
    if (argc == 2 && !strcmp(argv[1], "file")) {{
        close(3); alarm(30);
        FILE *f = fopen("peer-ready", "w"); if (!f) return 4;
        fprintf(f, "%d", getpid()); fclose(f);
        for (;;) pause();
    }}
    char *args[] = {{"{worker}", argc > 1 ? argv[1] : "", NULL}};
    execv(args[0], args); return 3;
}}
"#, worker=worker.display())).unwrap();
    assert!(std::process::Command::new("xcrun").args(["clang", "-Wall", "-Wextra", "-Werror"]).arg(&code).arg("-o").arg(&wrapper).status().unwrap().success());
    let mut old_host = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "direct_restart_refuses_a_live_native_helper_that_released_its_lease", "--nocapture"])
        .env("EVX_DIRECT_CRASH_ROOT", f.dir.path())
        .env("EVX_DIRECT_CRASH_XITE", &f.address)
        .env("EVX_DIRECT_CRASH_WORKER", &wrapper)
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::inherit()).spawn().unwrap();
    let marker = f.service.workspace_dir(&f.address).join("peer-ready");
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid: i32 = loop {
        if let Ok(text) = std::fs::read_to_string(&marker) {
            if let Ok(pid) = text.parse() { break pid; }
        }
        if Instant::now() > deadline { let _ = old_host.kill(); let _ = old_host.wait(); panic!("helper never became ready"); }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    struct KnownOrphan(i32);
    impl Drop for KnownOrphan { fn drop(&mut self) { let _ = std::process::Command::new("/bin/kill").args(["-KILL", &self.0.to_string()]).status(); } }
    let orphan = KnownOrphan(pid);
    old_host.kill().unwrap(); old_host.wait().unwrap();
    assert!(std::process::Command::new("/bin/kill").args(["-0", &pid.to_string()]).status().unwrap().success());
    let f = f.reopen().await;
    let result = f.chrome("evxRunOnce", json!({"program": PROGRAM})).await;
    let still_alive = std::process::Command::new("/bin/kill").args(["-0", &pid.to_string()]).status().unwrap().success();
    println!("orphan_pid={pid} still_alive={still_alive} restarted_result={result:?}");
    drop(orphan);
    assert!(still_alive, "reproduction requires live old helper");
    assert!(match &result { Err(_) => true, Ok(value) => value["status"] != "ok" },
        "restart admitted new manual execution while old native helper remained alive: {result:?}");
}
