//! The EVX service against a real node state: a signed fixture xite under a
//! temporary data root, the `Evx` plugin started the way the node starts it,
//! and every command sent through `CommandRegistry::dispatch`, where the
//! wrapper-only gate lives. Execution itself runs only on macOS, through the
//! real worker built like the `evx-host` suite builds it; everywhere else
//! the run path must report `unsupported host` and touch nothing.

use std::path::PathBuf;
use std::sync::Arc;

use epix_evx::{EvxPlugin, EvxService, CAPABILITY_KEY, HOST_CEILING, UNSUPPORTED_HOST};
use epix_plugin::{Plugin, PluginRegistry};
use epix_ui::command::WRAPPER_ID_BASE;
use epix_ui::{AppState, CommandRegistry, WsSession, XiteEntry};
use epix_xite::XiteStorage;
use evx_api::Limits;
use serde_json::{json, Value};

const CALC: &str = r#"(module (memory (export "memory") 1) (func (export "run") (result i32) i32.const 19 i32.const 23 i32.add))"#;
/// A module with a start function: instantiating it runs code. Inspection
/// must report its hash without ever instantiating it.
const START: &str = r#"(module (memory (export "memory") 1) (func $boot) (start $boot) (func (export "run") (result i32) i32.const 7))"#;
const ENTRY_PATH: &str = "evx/main.wasm";
const PROGRAM: &str = "calc";
const MODIFIED: f64 = 1_700_000_000.0;

/// Build and locate `evx-worker` relative to this test binary's target
/// directory, exactly as the `evx-host` suite does.
#[cfg(target_os = "macos")]
fn worker_binary() -> PathBuf {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut command = std::process::Command::new(cargo);
        command.args(["build", "-p", "evx-worker"]).current_dir(manifest.join("../.."));
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
            signed: true,
            #[cfg(target_os = "macos")]
            worker: Some(worker_binary()),
            #[cfg(not(target_os = "macos"))]
            worker: None,
        }
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    state: Arc<AppState>,
    address: String,
    commands: CommandRegistry,
    service: Arc<EvxService>,
    digest: String,
}

impl Fixture {
    async fn new(options: Options) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::with_data_dir("test", dir.path());
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let root = dir.path().join("data").join(&address);
        std::fs::create_dir_all(root.join("evx")).unwrap();
        let storage = XiteStorage::new(&root);
        let index = b"<html>evx fixture</html>";
        storage.write("index.html", index).unwrap();
        let module = evx_runtime::text_to_binary(options.wat).unwrap();
        storage.write(ENTRY_PATH, &module).unwrap();
        let capabilities: Vec<Value> = options.capabilities.iter().map(|api| json!({ "api": api })).collect();
        let mut content = json!({
            "address": address,
            "title": "EVX fixture",
            "modified": MODIFIED,
            "files": {
                "index.html": { "size": index.len(), "sha512": XiteStorage::hash_bytes(index) },
                ENTRY_PATH: { "size": module.len(), "sha512": XiteStorage::hash_bytes(&module) },
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
        if let Some(limits) = options.limits {
            content["evx"]["programs"][PROGRAM]["limits"] = limits;
        }
        if options.signed {
            epix_content::sign(&mut content, &key).unwrap();
        }
        let raw = epix_content::dumps_content(&content).into_bytes();
        storage.write("content.json", &raw).unwrap();
        let digest = evx_declaration::declaration_digest_bytes(&raw).unwrap().unwrap();
        state
            .add_xite(&address, XiteEntry { storage, content: Some(content) })
            .await;

        let plugin = match options.worker {
            Some(worker) => EvxPlugin::with_worker(worker),
            None => EvxPlugin::default(),
        };
        let mut plugins = PluginRegistry::new();
        plugins.register(Arc::new(plugin));
        plugins.start_all(&state);
        let commands = plugins.command_registry();
        let service = state.capability::<EvxService>(CAPABILITY_KEY).expect("service installed");
        Fixture { dir, state, address, commands, service, digest }
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

    fn enable_params(&self) -> Value {
        json!({ "xite": self.address, "declaration_digest": self.digest, "mode": "enable" })
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

#[tokio::test]
async fn the_evx_plugin_registers_its_commands_under_its_name() {
    let plugin = EvxPlugin::default();
    assert_eq!(plugin.name(), "Evx");
    let names: Vec<&str> = plugin.ws_commands().iter().map(|command| command.name()).collect();
    assert_eq!(
        names,
        ["evxInspect", "evxStatus", "evxRequest", "evxGrant", "evxRevoke", "evxSetLimits", "evxRunOnce"]
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
    let granted = f.chrome("evxGrant", f.enable_params()).await.unwrap();
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
    let mut again = f.enable_params();
    again["label"] = json!("laptop");
    let granted = f.chrome("evxGrant", again).await.unwrap();
    assert_eq!(granted["grant"]["generation"], 1);
    assert_eq!(granted["grant"]["label"], "laptop");
}

#[tokio::test]
async fn a_grant_with_a_stale_declaration_digest_is_refused() {
    let f = Fixture::new(Options::default()).await;
    let mut stale = f.enable_params();
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
    for params in [f.enable_params(), once] {
        let denied = f.call(&page, "evxGrant", params.clone(), 7).await.unwrap_err();
        assert!(denied.contains("prompt"), "{denied}");
        let forged = f.call(&page, "evxGrant", params.clone(), WRAPPER_ID_BASE + 3).await.unwrap_err();
        assert!(forged.contains("prompt"), "{forged}");
        let via_as = f.call(&page, "as", json!([f.address, "evxGrant", params.clone()]), 8).await;
        assert!(via_as.is_err());
        // A page command forwarded by the wrapper keeps its small id.
        assert!(f.call(&f.wrapper(), "evxGrant", params.clone(), 7).await.is_err());
    }
    for cmd in ["evxRevoke", "evxSetLimits", "evxRunOnce"] {
        let params = json!({ "xite": f.address, "limits": Limits::default(), "program": PROGRAM });
        assert!(f.call(&page, cmd, params.clone(), 7).await.unwrap_err().contains("prompt"), "{cmd}");
        assert!(f.call(&page, cmd, params, WRAPPER_ID_BASE + 3).await.unwrap_err().contains("prompt"), "{cmd}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());

    // The handler itself refuses a page session even when the dispatcher
    // is bypassed: a second line behind the gate, not a replacement for it.
    let handlers = EvxPlugin::default().ws_commands();
    for cmd in epix_ui::command::EVX_WRAPPER_COMMANDS {
        let handler = handlers.iter().find(|handler| handler.name() == *cmd).unwrap();
        let denied = handler.handle(&page, &f.enable_params()).await.unwrap_err();
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
    for params in [f.enable_params(), once] {
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
        .call(&admin_page, "as", json!([f.address, "evxGrant", f.enable_params()]), 11)
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
        .call(&f.wrapper(), "as", json!([f.address, "evxGrant", f.enable_params()]), WRAPPER_ID_BASE + 1)
        .await
        .unwrap();
    assert_eq!(granted["granted"], true);
    let revoked = f.call(&f.operator(), "as", json!([f.address, "evxRevoke", {}]), 1).await.unwrap();
    assert_eq!(revoked["revoked"], true);
}

#[tokio::test]
async fn a_gateway_visitor_is_told_only_whether_execution_is_enabled() {
    let f = Fixture::new(Options::default()).await;
    let mut labelled = f.enable_params();
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
    assert_eq!(status["running"], false);
    // No dialog is shown on a gateway, so the ask is refused, not recorded.
    let denied = f.call(&visitor, "evxRequest", json!({}), 3).await.unwrap_err();
    assert!(denied.contains("gateway"), "{denied}");
    let status = f.call(&f.operator(), "evxStatus", json!({ "xite": f.address }), 4).await.unwrap();
    assert!(status["asked_unix"].is_null(), "the refused ask was recorded");

    // The operator socket sees everything, and a plain node tells its
    // page everything too.
    assert_eq!(status["grant"]["label"], "operator laptop");
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
    let denied = f.chrome("evxGrant", f.enable_params()).await.unwrap_err();
    assert!(denied.contains("gateway"), "{denied}");
    for cmd in ["evxRevoke", "evxSetLimits", "evxRunOnce"] {
        let params = json!({ "xite": f.address, "limits": Limits::default(), "program": PROGRAM });
        assert!(f.chrome(cmd, params).await.unwrap_err().contains("gateway"), "{cmd}");
    }
    assert!(f.service.durable().xite_grant(&f.address).unwrap().is_none());
    // The operator socket is the sanctioned way to change a locked node,
    // and it may name any xite.
    let granted = f.call(&f.operator(), "evxGrant", f.enable_params(), 1).await.unwrap();
    assert_eq!(granted["granted"], true);
    assert!(f.service.durable().xite_grant(&f.address).unwrap().unwrap().0.enabled);
    let revoked = f.call(&f.operator(), "evxRevoke", json!({ "xite": f.address }), 2).await.unwrap();
    assert_eq!(revoked["revoked"], true);
    assert!(!f.service.durable().xite_grant(&f.address).unwrap().unwrap().0.enabled);
}

#[tokio::test]
async fn revocation_disables_the_grant_and_a_later_run_once_is_refused() {
    let f = Fixture::new(Options::default()).await;
    f.chrome("evxGrant", f.enable_params()).await.unwrap();
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
    let missing = std::env::temp_dir().join("epix-evx-no-such-worker");
    let f = Fixture::new(Options { worker: Some(missing), ..Options::default() }).await;
    assert_eq!(f.service.execution().unwrap_err(), UNSUPPORTED_HOST);
    let status = f.call(&f.page(), "evxStatus", json!({}), 1).await.unwrap();
    assert_eq!(status["host"]["execution"], false);
    assert!(status["reasons"].as_array().unwrap().contains(&json!("unsupported_host")));
    // Inspect, grant and revoke still work.
    f.chrome("evxGrant", f.enable_params()).await.unwrap();
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
    f.chrome("evxGrant", f.enable_params()).await.unwrap();
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
    f.chrome("evxGrant", f.enable_params()).await.unwrap();
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
    f.chrome("evxGrant", f.enable_params()).await.unwrap();
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
    let mut with_limits = f.enable_params();
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
    let denied = f.chrome("evxGrant", f.enable_params()).await.unwrap_err();
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
    let denied = f.chrome("evxGrant", f.enable_params()).await.unwrap_err();
    assert!(denied.contains("incomplete"), "{denied}");
}

#[cfg(target_os = "macos")]
mod execution {
    use super::*;
    use evx_api::Status;

    #[tokio::test]
    async fn run_once_executes_the_baseline_program_through_the_real_worker() {
        let f = Fixture::new(Options::default()).await;
        assert!(f.service.execution().is_ok());
        f.chrome("evxGrant", f.enable_params()).await.unwrap();
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
    async fn a_run_queued_behind_a_revocation_is_refused_rather_than_run_under_the_revoked_grant() {
        let f = Arc::new(
            Fixture::new(Options {
                wat: SPIN,
                limits: Some(json!({ "fuel": HOST_CEILING.fuel, "wall_seconds": 30.0, "process_cpu_seconds": 30.0 })),
                ..Options::default()
            })
            .await,
        );
        f.chrome("evxGrant", f.enable_params()).await.unwrap();

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
        // "revoked" once the run is in flight; "opt-in required" is the
        // supervisor's word for a grant already disabled at admission.
        let error = first["error"].as_str().unwrap_or_default();
        assert!(error.contains("revoked") || error.contains("opt-in"), "{first}");
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
        f.chrome("evxGrant", f.enable_params()).await.unwrap();
        let narrow = f.chrome("evxRunOnce", json!({ "program": PROGRAM })).await.unwrap();
        assert_eq!(narrow["value"], 42, "{narrow}");
        let denied = f.chrome("evxRunOnce", json!({ "program": "other" })).await.unwrap_err();
        assert!(denied.contains("not usable"), "{denied}");
        assert_eq!(f.service.durable().runs(&f.address).unwrap().len(), 1);
    }
}
