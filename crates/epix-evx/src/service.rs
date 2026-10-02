//! The EVX service: everything the management commands do, with the
//! WebSocket shapes stripped away so the tests and the plugin share one
//! implementation.
//!
//! # What is trusted here
//!
//! Every method takes the node's [`AppState`] for the xite's stored files
//! and its signature status, and this service's own [`DurableState`] for
//! consent. Nothing a xite publishes is an instruction: its `content.json`
//! is a *request* that [`EvxService::inspect`] renders and that
//! [`EvxService::grant`] compares, by digest, with what the operator saw.
//! The commands that call [`EvxService::grant`], [`EvxService::revoke`],
//! [`EvxService::set_limits`] and [`EvxService::run_once`] are reachable
//! only through the dispatcher gate in `epix_ui::command`
//! (`EVX_WRAPPER_COMMANDS`), and the handlers re-check the session shape;
//! the service itself does not know who is calling and must never be handed
//! a page's socket.
//!
//! # Reading the declaration
//!
//! The root `content.json` is read as BYTES through
//! [`AppState::read_xite_file_bounded`] and parsed with
//! `evx_declaration::parse_bytes`, never from the decoded `AppState::content`
//! value: a value has already collapsed a duplicated key, and a document
//! with two `evx` sections must be refused as malformed, not read as
//! whichever one survived. The signature is checked on the value decoded
//! from those same bytes with `epix_content::verify_signer`, and
//! `AppState::xite_core_complete` must hold, because a xite whose declared
//! files are still downloading cannot be bound to what the manifest pins.
//!
//! # Paths
//!
//! The durable state, the workspaces and the checkpoints live under
//! `<data_root>/private/evx/`, beside the node's own private files and
//! outside every served root (`<data_root>/data/<address>`), so no xite file
//! request, listing or `/raw` route can ever reach them, and so a xite's
//! workspace is not part of what the node publishes or signs for it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use epix_ui::AppState;
use evx_activation::{ActivationLoader, AuthenticationError, BoundProgram};
use evx_api::{Capability, Grant, Limits};
use evx_declaration::{Declaration, DeclarationError};
use evx_host::run_content_activation;
use evx_state::{DurableState, Generations, RunRecord, XiteGrant, ALLOW_ONCE_TTL, MAX_MESSAGE};
use evx_supervisor::{Broker, Config, RunOptions};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

use crate::checkpoint;
use crate::limits::{clamp, combine, HOST_CEILING};

/// The one runtime profile this milestone executes; the grant's profile
/// set is exactly this, so an activation declaring another profile is
/// refused by the loader as outside the grant.
pub const RUNTIME_PROFILE: &str = evx_declaration::RUNTIME_PROFILE;

/// The error every effectful path reports on a host that cannot execute:
/// a non-macOS build (no confinement yet) or a node without the worker
/// binary. Inspect, grant and revoke still work there.
pub const UNSUPPORTED_HOST: &str = "unsupported host";

/// Name of the worker binary beside the node executable.
pub const WORKER_BINARY: &str = if cfg!(windows) { "evx-worker.exe" } else { "evx-worker" };

/// The run history `evxStatus` returns: the newest of the 50 the state keeps.
pub const STATUS_RUNS: usize = 10;

/// The label a grant gets when the wrapper does not name one.
pub const DEFAULT_LABEL: &str = "wrapper";

/// What the node established about a xite's root `content.json`, in the
/// closed vocabulary the inspect payload and the `/list` panel show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    /// Signed by the xite's address and every declared file present.
    Verified,
    /// The stored root does not carry a valid signature for the address.
    Unsigned,
    /// Signed, but declared files are still missing on this node.
    Incomplete,
}

impl Integrity {
    /// The payload spelling.
    pub fn name(self) -> &'static str {
        match self {
            Integrity::Verified => "verified",
            Integrity::Unsigned => "unsigned",
            Integrity::Incomplete => "incomplete",
        }
    }
}

/// Everything `evxInspect` reports and every effectful command re-derives
/// before acting: the parsed declaration, its digest, the programs bound to
/// the signed manifest, the integrity status and the stored grant. Built
/// fresh on every call so a command always acts on what is on disk now,
/// and compared by digest with what the operator was shown.
#[derive(Debug, Clone)]
pub struct Inspection {
    /// The xite's address; also its publisher under a root-address grant.
    pub xite: String,
    /// The signature and completeness status.
    pub integrity: Integrity,
    /// The decoded root `content.json`, from the bytes the strict parser
    /// accepted; what `bind` and the activation loader take.
    pub content: Value,
    /// The parsed declaration.
    pub declaration: Declaration,
    /// SHA-256 of the canonical `evx` object: the expected-version token.
    pub digest: String,
    /// Usable programs pinned to the manifest, by id.
    pub bound: BTreeMap<String, BoundProgram>,
    /// Usable programs the manifest could not pin, with the reason. They are
    /// shown as unusable and never granted or run.
    pub unbound: BTreeMap<String, String>,
    /// The stored consent, if any, with its generations.
    pub grant: Option<(XiteGrant, Generations)>,
}

impl Inspection {
    /// Capabilities every bound program together asks for: what an `enable`
    /// grant stores, so one grant covers the whole declaration.
    pub fn requested_capabilities(&self) -> BTreeSet<Capability> {
        self.bound
            .keys()
            .filter_map(|id| self.declaration.programs.get(id))
            .flat_map(|program| program.capabilities.iter().copied())
            .collect()
    }

    /// The limits the bound programs together ask for, before the ceiling.
    pub fn requested_limits(&self) -> Option<Limits> {
        combine(
            self.bound
                .keys()
                .filter_map(|id| self.declaration.programs.get(id))
                .map(|program| &program.limits),
        )
    }

    /// Whether any bound program asks to be runnable on demand.
    pub fn requests_run_once(&self) -> bool {
        self.bound
            .keys()
            .filter_map(|id| self.declaration.programs.get(id))
            .any(|program| program.allow_run_once)
    }

    /// The stored grant, if it is enabled and unexpired at `now`.
    pub fn live_grant(&self, now: u64) -> Option<(&XiteGrant, &Generations)> {
        let (grant, generations) = self.grant.as_ref()?;
        if !grant.enabled || grant.expires_unix.is_some_and(|at| now >= at) {
            return None;
        }
        Some((grant, generations))
    }

    /// The inert inspect payload. Nothing in it is executable; the file
    /// hashes are the manifest's, re-checked by the loader only at run time.
    pub fn to_json(&self, now: u64, execution: Result<(), String>) -> Value {
        let mut summary = evx_declaration::summary(&self.declaration);
        let mut programs: Map<String, Value> = summary
            .get_mut("programs")
            .and_then(Value::as_object_mut)
            .map(std::mem::take)
            .unwrap_or_default();
        for (id, bound) in &self.bound {
            let Some(entry) = programs.get_mut(id).and_then(Value::as_object_mut) else {
                continue;
            };
            entry.insert(
                "files".into(),
                json!({
                    "entry": pinned(&bound.entry),
                    "dependencies": bound.dependencies.iter().map(pinned).collect::<Vec<_>>(),
                    "total_bytes": bound.total_bytes,
                }),
            );
            if let Some(program) = self.declaration.programs.get(id) {
                let effective = clamp(&program.limits).ok();
                entry.insert("effective_limits".into(), limits_json(effective.as_ref()));
            }
        }
        let mut unsupported = summary
            .get("unsupported")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (id, reason) in &self.unbound {
            let entry = programs
                .entry(id.clone())
                .or_insert_with(|| json!({ "usable": false, "reasons": [] }));
            if let Some(entry) = entry.as_object_mut() {
                entry.insert("usable".into(), Value::Bool(false));
                if let Some(Value::Array(reasons)) = entry.get_mut("reasons") {
                    reasons.push(Value::String(reason.clone()));
                }
            }
            unsupported.push(json!({ "path": format!("programs.{id}"), "reason": reason }));
        }
        if let Some(object) = summary.as_object_mut() {
            object.insert("programs".into(), Value::Object(programs));
            object.insert("unsupported".into(), Value::Array(unsupported.clone()));
        }
        let requested_capabilities = self.requested_capabilities();
        let requested_limits = self.requested_limits();
        let effective_limits = requested_limits.as_ref().and_then(|limits| clamp(limits).ok());
        let grant = self.grant.as_ref().map(|(grant, generations)| {
            let live = self.live_grant(now).is_some();
            let covers = live
                && requested_capabilities.is_subset(&grant.capabilities)
                && grant.runtime_profiles.contains(RUNTIME_PROFILE);
            grant_json(grant, generations, now, Some(covers))
        });
        json!({
            "xite": self.xite,
            "publisher": self.xite,
            "integrity": self.integrity.name(),
            "declaration_digest": self.digest,
            "declaration": summary,
            "requested": {
                "capabilities": capability_names(&requested_capabilities),
                "limits": limits_json(requested_limits.as_ref()),
                "allow_run_once": self.requests_run_once(),
                "programs": self.bound.keys().cloned().collect::<Vec<_>>(),
            },
            "effective": {
                "capabilities": capability_names(&requested_capabilities),
                "limits": limits_json(effective_limits.as_ref()),
                "runtime_profiles": [RUNTIME_PROFILE],
                "allow_run_once": self.requests_run_once(),
                "allow_background": false,
            },
            "unsupported": unsupported,
            "grant": grant,
            "host": host_json(execution),
        })
    }
}

/// How the wrapper asks for consent to be recorded (`evxGrant`). Decoded
/// strictly: an unknown field is refused, not ignored, because a field this
/// build does not know might have been meant to narrow the grant.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    /// The xite being granted; must be the session's or the operator's choice.
    pub xite: String,
    /// The digest the operator saw in the prompt; must still be current.
    pub declaration_digest: String,
    /// Persistent consent or a single run.
    pub mode: GrantMode,
    /// The program an `once` grant covers; refused for `enable`.
    #[serde(default)]
    pub program: Option<String>,
    /// Limits the wrapper proposes for an `enable` grant, clamped to the
    /// host ceiling; the declaration's own request when absent.
    #[serde(default)]
    pub limits: Option<Limits>,
    /// Free-text label stored with an `enable` grant.
    #[serde(default)]
    pub label: Option<String>,
}

/// The two consent shapes the dialog offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantMode {
    /// Persist a `XiteGrant` covering the declaration.
    Enable,
    /// Mint one allow-once token for one program.
    Once,
}

impl GrantMode {
    fn name(self) -> &'static str {
        match self {
            GrantMode::Enable => "enable",
            GrantMode::Once => "once",
        }
    }
}

/// The node's EVX service. One per node, created by the plugin at start and
/// shared with its commands through `AppState::install_capability`.
pub struct EvxService {
    state: DurableState,
    root: PathBuf,
    /// Keeps an in-memory node's throwaway state directory alive.
    _scratch: Option<tempfile::TempDir>,
    /// The worker binary, when one was found at start.
    worker: Option<PathBuf>,
    /// Brokers of runs in flight, by xite, so a revocation reaches the
    /// supervisor's grant check and stops the run.
    running: Mutex<HashMap<String, Arc<Broker>>>,
    /// One run at a time per xite: the loader's checkpoint is read, moved
    /// and persisted around each run, and two runs interleaving on it could
    /// persist the lower floor last.
    run_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// When each xite's page last asked (`evxRequest`), for status views.
    asked: Mutex<HashMap<String, u64>>,
}

impl EvxService {
    /// Open the service rooted at `root` (`<data_root>/private/evx`),
    /// creating the directory tree and the SQLite state. `worker` is the
    /// worker binary to use, or `None` to resolve it with
    /// [`default_worker_binary`].
    pub fn open(root: PathBuf, worker: Option<PathBuf>) -> Result<Self, String> {
        Self::build(root, worker, None)
    }

    /// Open the service for `app`: under its data root when it has one, in
    /// a temporary directory that disappears with the service otherwise.
    pub fn for_node(app: &AppState, worker: Option<PathBuf>) -> Result<Self, String> {
        match app.data_root_path() {
            Some(data_root) => Self::build(data_root.join("private").join("evx"), worker, None),
            None => {
                let scratch = tempfile::Builder::new()
                    .prefix("epix-evx-")
                    .tempdir()
                    .map_err(|error| format!("EVX scratch directory: {error}"))?;
                let root = scratch.path().to_path_buf();
                Self::build(root, worker, Some(scratch))
            }
        }
    }

    fn build(root: PathBuf, worker: Option<PathBuf>, scratch: Option<tempfile::TempDir>) -> Result<Self, String> {
        for dir in [root.clone(), root.join("workspaces"), root.join("checkpoints")] {
            std::fs::create_dir_all(&dir).map_err(|error| format!("EVX directory {}: {error}", dir.display()))?;
        }
        let state = DurableState::open(root.join("state.sqlite"))
            .map_err(|error| format!("EVX state: {error}"))?;
        // A pinned path that is not a regular file is no worker either, and
        // it never falls back to the default: the caller pinned it so that
        // nothing else would run.
        let worker = match worker {
            Some(path) => path.is_file().then_some(path),
            None => default_worker_binary(),
        };
        Ok(EvxService {
            state,
            root,
            _scratch: scratch,
            worker,
            running: Mutex::new(HashMap::new()),
            run_locks: tokio::sync::Mutex::new(HashMap::new()),
            asked: Mutex::new(HashMap::new()),
        })
    }

    /// The service's private root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The SQLite file holding grants, tokens and run history.
    pub fn state_path(&self) -> PathBuf {
        self.root.join("state.sqlite")
    }

    /// Where `xite`'s programs read and write: created on first run.
    pub fn workspace_dir(&self, xite: &str) -> PathBuf {
        self.root.join("workspaces").join(xite)
    }

    /// Where `xite`'s activation checkpoint is persisted.
    pub fn checkpoint_path(&self, xite: &str) -> PathBuf {
        checkpoint::path(&self.root.join("checkpoints"), xite)
    }

    /// The durable state, for tests and status views.
    pub fn durable(&self) -> &DurableState {
        &self.state
    }

    /// The worker binary when this host can execute, or why it cannot.
    /// Execution is macOS-only in this milestone because the worker's
    /// confinement is; the check is a runtime `cfg!` so the rest of the
    /// service compiles identically everywhere.
    pub fn execution(&self) -> Result<&Path, String> {
        if !cfg!(target_os = "macos") {
            return Err(UNSUPPORTED_HOST.into());
        }
        self.worker.as_deref().ok_or_else(|| UNSUPPORTED_HOST.to_string())
    }

    /// The stored grant as the `/list` panel reads it (`enabled`,
    /// `generation`, `expires_unix`), or `None` when the xite was never
    /// granted. Synchronous and bounded: one indexed SQLite read.
    pub fn grant_summary(&self, xite: &str) -> Option<Value> {
        let (grant, generations) = self.state.xite_grant(xite).ok()??;
        Some(grant_json(&grant, &generations, now_unix().ok()?, None))
    }

    /// Read, verify, parse, digest and bind `xite`'s declaration. Inert:
    /// nothing is compiled, instantiated or spawned, and no program file is
    /// opened; the hashes reported are the signed manifest's.
    pub async fn inspect(&self, app: &AppState, xite: &str) -> Result<Inspection, String> {
        xite_id(xite)?;
        // The root is bounded by the xite's own size limit, the guard it was
        // stored under.
        let limit = u64::try_from(app.size_limit_bytes(xite).await).unwrap_or(0);
        let raw = app.read_xite_file_bounded(xite, "content.json", limit).await?;
        let content: Value =
            serde_json::from_slice(&raw).map_err(|_| "content.json is not valid JSON".to_string())?;
        let integrity = if !epix_content::verify_signer(&content, xite) {
            Integrity::Unsigned
        } else if app.xite_core_complete(xite).await {
            Integrity::Verified
        } else {
            Integrity::Incomplete
        };
        let declaration = evx_declaration::parse_bytes(&raw)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "content.json declares no evx section".to_string())?;
        let digest = evx_declaration::declaration_digest_bytes(&raw)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "content.json declares no evx section".to_string())?;
        let mut bound = BTreeMap::new();
        let mut unbound = BTreeMap::new();
        for id in declaration.programs.keys() {
            match evx_declaration::bind(&declaration, id, &content) {
                Ok(program) => {
                    bound.insert(id.clone(), program);
                }
                Err(DeclarationError::Manifest(reason)) => {
                    unbound.insert(id.clone(), reason);
                }
                Err(error) => {
                    unbound.insert(id.clone(), error.to_string());
                }
            }
        }
        let grant = self
            .state
            .xite_grant(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        Ok(Inspection {
            xite: xite.to_string(),
            integrity,
            content,
            declaration,
            digest,
            bound,
            unbound,
            grant,
        })
    }

    /// The inspect payload for `xite`.
    pub async fn inspect_json(&self, app: &AppState, xite: &str) -> Result<Value, String> {
        let inspection = self.inspect(app, xite).await?;
        Ok(inspection.to_json(now_unix()?, self.execution().map(|_| ())))
    }

    /// Record that `xite`'s page asked for consent and return what the
    /// wrapper's prompt shows. Grants nothing: the page learns the digest
    /// it cannot use, since `evxGrant` is not reachable from a page.
    pub async fn request(&self, app: &AppState, xite: &str) -> Result<Value, String> {
        let now = now_unix()?;
        let mut payload = self.inspect_json(app, xite).await?;
        if let Ok(mut asked) = self.asked.lock() {
            asked.insert(xite.to_string(), now);
        }
        app.log("INFO", format!("EVX: {xite} asked for execution consent")).await;
        if let Some(object) = payload.as_object_mut() {
            object.insert("asked_unix".into(), json!(now));
        }
        Ok(payload)
    }

    /// Grant status, generations, recent runs and the reasons the xite
    /// cannot run right now, from the durable state alone. Works for a xite
    /// without a declaration, so a page can poll it cheaply.
    pub async fn status(&self, xite: &str) -> Result<Value, String> {
        xite_id(xite)?;
        let now = now_unix()?;
        let stored = self
            .state
            .xite_grant(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        let runs = self
            .state
            .runs(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        let mut reasons: Vec<&str> = Vec::new();
        match &stored {
            None => reasons.push("no_grant"),
            Some((grant, _)) => {
                if !grant.enabled {
                    reasons.push("revoked");
                } else if grant.expires_unix.is_some_and(|at| now >= at) {
                    reasons.push("expired");
                } else if !grant.allow_run_once {
                    reasons.push("run_once_not_allowed");
                }
            }
        }
        let execution = self.execution().map(|_| ());
        if execution.is_err() {
            reasons.push("unsupported_host");
        }
        let asked_unix = self.asked.lock().ok().and_then(|asked| asked.get(xite).copied());
        let running = self.running.lock().is_ok_and(|running| running.contains_key(xite));
        Ok(json!({
            "xite": xite,
            "grant": stored.as_ref().map(|(grant, generations)| grant_json(grant, generations, now, None)),
            "generations": stored.as_ref().map(|(_, generations)| generations_json(generations)),
            "runs": runs.iter().take(STATUS_RUNS).map(run_json).collect::<Vec<_>>(),
            "run_count": runs.len(),
            "running": running,
            "reasons": reasons,
            "asked_unix": asked_unix,
            "host": host_json(execution),
        }))
    }

    /// Record the operator's consent (`evxGrant`). Refused unless the
    /// declaration is verified and complete and `request.declaration_digest`
    /// is its current digest: the operator consented to what they were
    /// shown, and a root re-signed since then is a different request.
    pub async fn grant(&self, app: &AppState, request: GrantRequest) -> Result<Value, String> {
        let xite = request.xite.as_str();
        let inspection = self.inspect(app, xite).await?;
        if inspection.integrity != Integrity::Verified {
            return Err(format!(
                "declaration is {}; only a verified, complete xite can be granted",
                inspection.integrity.name()
            ));
        }
        if request.declaration_digest != inspection.digest {
            return Err("declaration_digest does not match the current declaration; inspect again".into());
        }
        let now = now_unix()?;
        match request.mode {
            GrantMode::Enable => {
                if request.program.is_some() {
                    return Err("program applies to mode once only".into());
                }
                if inspection.bound.is_empty() {
                    return Err("no usable program to grant".into());
                }
                let requested = inspection
                    .requested_limits()
                    .ok_or_else(|| "no usable program to grant".to_string())?;
                let limits = clamp(request.limits.as_ref().unwrap_or(&requested))?;
                let label = request.label.unwrap_or_else(|| DEFAULT_LABEL.to_string());
                let grant = XiteGrant {
                    xite: xite.to_string(),
                    publisher: xite.to_string(),
                    enabled: true,
                    capabilities: inspection.requested_capabilities(),
                    runtime_profiles: [RUNTIME_PROFILE.to_string()].into_iter().collect(),
                    limits,
                    allow_run_once: inspection.requests_run_once(),
                    // Background scheduling is Milestone 3; no dialog offers
                    // it yet, so no grant records consent to it.
                    allow_background: false,
                    created_unix: now,
                    expires_unix: None,
                    label,
                };
                let generations = self
                    .state
                    .set_xite_grant(&grant)
                    .map_err(|error| format!("EVX state: {error}"))?;
                app.log(
                    "INFO",
                    format!(
                        "EVX: enabled {xite} (declaration {}, generation {}, capabilities {:?})",
                        short(&inspection.digest),
                        generations.generation,
                        capability_names(&grant.capabilities)
                    ),
                )
                .await;
                Ok(json!({
                    "granted": true,
                    "mode": GrantMode::Enable.name(),
                    "xite": xite,
                    "declaration_digest": inspection.digest,
                    "grant": grant_json(&grant, &generations, now, Some(true)),
                }))
            }
            GrantMode::Once => {
                if request.limits.is_some() || request.label.is_some() {
                    return Err("limits and label apply to mode enable only".into());
                }
                let program = request
                    .program
                    .as_deref()
                    .ok_or_else(|| "program required for mode once".to_string())?;
                let declared = usable_program(&inspection, program)?;
                if !declared.allow_run_once {
                    return Err(format!("program {program} does not allow run-once"));
                }
                let token = self
                    .state
                    .allow_once(xite, &inspection.digest, program)
                    .map_err(|error| format!("EVX state: {error}"))?;
                app.log(
                    "INFO",
                    format!(
                        "EVX: allowed {xite} program {program} once (declaration {})",
                        short(&inspection.digest)
                    ),
                )
                .await;
                Ok(json!({
                    "granted": true,
                    "mode": GrantMode::Once.name(),
                    "xite": xite,
                    "program": program,
                    "declaration_digest": inspection.digest,
                    "token": token,
                    "expires_in": ALLOW_ONCE_TTL,
                }))
            }
        }
    }

    /// Disable `xite`'s grant (`evxRevoke`): the authority generation
    /// advances, outstanding allow-once tokens are discarded, and a run in
    /// flight is told to stop through its broker. Nothing published is
    /// recalled and the run history is kept.
    pub async fn revoke(&self, app: &AppState, xite: &str) -> Result<Value, String> {
        xite_id(xite)?;
        let had_grant = self
            .state
            .xite_grant(xite)
            .map_err(|error| format!("EVX state: {error}"))?
            .is_some();
        self.state
            .revoke_xite(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        let running = self
            .running
            .lock()
            .ok()
            .and_then(|running| running.get(xite).cloned());
        let stopped = running.is_some();
        if let Some(broker) = running {
            broker.revoke();
        }
        app.log("INFO", format!("EVX: revoked {xite} (run in flight stopped: {stopped})")).await;
        Ok(json!({ "revoked": true, "xite": xite, "had_grant": had_grant, "stopped_run": stopped }))
    }

    /// Replace the stored limits of `xite`'s grant (`evxSetLimits`) with
    /// `limits` clamped to the host ceiling. The limits generation advances
    /// when they change; usage is never reset, and a run in flight gets the
    /// new values at its next broker check.
    pub async fn set_limits(&self, app: &AppState, xite: &str, limits: &Limits) -> Result<Value, String> {
        xite_id(xite)?;
        let (mut grant, _) = self
            .state
            .xite_grant(xite)
            .map_err(|error| format!("EVX state: {error}"))?
            .ok_or_else(|| format!("no EVX grant for {xite}"))?;
        grant.limits = clamp(limits)?;
        let generations = self
            .state
            .set_xite_grant(&grant)
            .map_err(|error| format!("EVX state: {error}"))?;
        let running = self
            .running
            .lock()
            .ok()
            .and_then(|running| running.get(xite).cloned());
        if let Some(broker) = running {
            // A broker refuses limits it cannot enforce; the stored grant
            // already holds them, so the next run gets them regardless.
            let _ = broker.set_limits(grant.limits.clone());
        }
        app.log(
            "INFO",
            format!("EVX: limits of {xite} set (limits generation {})", generations.limits_generation),
        )
        .await;
        Ok(json!({
            "xite": xite,
            "limits": limits_json(Some(&grant.limits)),
            "generations": generations_json(&generations),
        }))
    }

    /// Run `program` of `xite` now (`evxRunOnce`), under the enabled grant
    /// or by spending `token`. Verifies, captures, compiles, admits and runs
    /// through `evx_host::run_content_activation`, persists the checkpoint
    /// and a run record, and returns the `RunResult` with the activation
    /// report. On a host that cannot execute it returns
    /// [`UNSUPPORTED_HOST`] before reading anything, so neither the grant
    /// nor a token is touched.
    pub async fn run_once(
        self: &Arc<Self>,
        app: &AppState,
        xite: &str,
        program: &str,
        token: Option<&str>,
    ) -> Result<Value, String> {
        let worker = self.execution()?.to_path_buf();
        xite_id(xite)?;
        evx_api::validate_identifier(program).map_err(|denied| format!("invalid program: {denied}"))?;
        let inspection = self.inspect(app, xite).await?;
        if inspection.integrity != Integrity::Verified {
            return Err(format!(
                "declaration is {}; only a verified, complete xite can run",
                inspection.integrity.name()
            ));
        }
        let declared = usable_program(&inspection, program)?.clone();
        let bound = inspection
            .bound
            .get(program)
            .cloned()
            .ok_or_else(|| format!("program {program} is not usable"))?;
        if !declared.allow_run_once {
            return Err(format!("program {program} does not allow run-once"));
        }
        let now = now_unix()?;

        // Authority: a spent token covers exactly this program at exactly
        // this digest with its own declared request; an enabled grant must
        // already cover the program's request.
        let (capabilities, limits, generation, authority) = match token {
            Some(token) => {
                let spent = self
                    .state
                    .consume_allow_once(xite, token, &inspection.digest, program)
                    .map_err(|error| format!("EVX state: {error}"))?;
                if !spent {
                    return Err("allow-once token refused: unknown, spent, expired or for another program".into());
                }
                let generation = inspection
                    .grant
                    .as_ref()
                    .map(|(_, generations)| generations.generation)
                    .unwrap_or(1);
                (declared.capabilities.clone(), clamp(&declared.limits)?, generation, "once")
            }
            None => {
                let (grant, generations) = inspection
                    .live_grant(now)
                    .ok_or_else(|| format!("no enabled EVX grant for {xite}"))?;
                if !grant.allow_run_once {
                    return Err(format!("the grant for {xite} does not allow run-once"));
                }
                if !declared.capabilities.is_subset(&grant.capabilities) {
                    return Err(format!("program {program} asks for capabilities beyond the grant"));
                }
                if !grant.runtime_profiles.contains(&declared.runtime_profile) {
                    return Err(format!("program {program} asks for a runtime profile beyond the grant"));
                }
                (grant.capabilities.clone(), grant.limits.clone(), generations.generation, "grant")
            }
        };

        // The closure's bytes, read now so the blocking run needs no node
        // state. Each read is bounded by the size the manifest signed; the
        // loader re-hashes every byte against the pin.
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for pin in std::iter::once(&bound.entry).chain(bound.dependencies.iter()) {
            let data = app.read_xite_file_bounded(xite, &pin.path, pin.size).await?;
            files.insert(pin.path.clone(), data);
        }
        let entry_sha256 = hex::encode(Sha256::digest(files.get(&bound.entry.path).map(Vec::as_slice).unwrap_or_default()));

        let lock = {
            let mut locks = self.run_locks.lock().await;
            locks.entry(xite.to_string()).or_default().clone()
        };
        let _running = lock.lock().await;

        let service = Arc::clone(self);
        let xite_owned = xite.to_string();
        let content = inspection.content.clone();
        let digest = inspection.digest.clone();
        let profiles: BTreeSet<String> = [RUNTIME_PROFILE.to_string()].into_iter().collect();
        let started = now;
        let run = tokio::task::spawn_blocking(move || {
            service.run_blocking(&xite_owned, &worker, content, bound, files, capabilities, profiles, limits, generation)
        })
        .await
        .map_err(|error| format!("EVX run task failed: {error}"))?;
        let (outcome, checkpoint_result) = run?;
        let finished = now_unix()?;

        let result_json = serde_json::to_value(&outcome.result).map_err(|error| error.to_string())?;
        let status = result_json
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| "run result without a status".to_string())?
            .to_string();
        let record = RunRecord {
            started_unix: started,
            finished_unix: finished.max(started),
            program: program.to_string(),
            declaration_digest: digest.clone(),
            artifact_sha256: outcome
                .activation
                .as_ref()
                .map(|report| report.artifact_sha256.clone())
                .unwrap_or(entry_sha256),
            input_digest: input_digest()?,
            status: status.clone(),
            message: outcome.result.error.as_deref().map(bounded_message),
            cpu_seconds: outcome
                .result
                .trusted_observations
                .as_ref()
                .map(|observations| observations.cpu_seconds)
                .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
                .unwrap_or(0.0),
            peak_rss: outcome
                .result
                .trusted_observations
                .as_ref()
                .map(|observations| observations.peak_aggregate_rss_bytes)
                .unwrap_or(0),
        };
        self.state
            .record_run(xite, &record)
            .map_err(|error| format!("EVX state: {error}"))?;
        app.log(
            "INFO",
            format!(
                "EVX: ran {xite} program {program} under {authority}: {status}{}",
                outcome.result.error.as_deref().map(|error| format!(" ({error})")).unwrap_or_default()
            ),
        )
        .await;
        // A checkpoint that could not be persisted is reported after the
        // run record so the operator sees both; the next run re-admits the
        // same version from the file that is there.
        let checkpoint_error = checkpoint_result.err();
        let mut payload = result_json;
        if let Some(object) = payload.as_object_mut() {
            object.insert("activation".into(), serde_json::to_value(&outcome.activation).unwrap_or(Value::Null));
            object.insert("run".into(), run_json(&record));
            object.insert("authority".into(), json!(authority));
            object.insert("checkpoint_error".into(), json!(checkpoint_error));
        }
        Ok(payload)
    }

    /// The blocking half of [`EvxService::run_once`]: the loader with the
    /// persisted floor, a broker on the xite's private workspace, the run,
    /// and the floor persisted again if it moved. Runs on a blocking thread
    /// because the supervisor spawns and waits on processes.
    #[allow(clippy::too_many_arguments)]
    fn run_blocking(
        &self,
        xite: &str,
        worker: &Path,
        content: Value,
        bound: BoundProgram,
        files: BTreeMap<String, Vec<u8>>,
        capabilities: BTreeSet<Capability>,
        profiles: BTreeSet<String>,
        limits: Limits,
        generation: u64,
    ) -> Result<(evx_host::ActivationOutcome, Result<(), String>), String> {
        let checkpoints = self.root.join("checkpoints");
        let floor = checkpoint::load(&checkpoints, xite)?;
        let loader_grant = evx_activation::XiteGrant::for_root_address(
            xite.to_string(),
            xite.to_string(),
            capabilities.clone(),
            profiles.clone(),
        )
        .and_then(|grant| grant.with_generation(generation))
        .map_err(|error| format!("activation grant: {error}"))?;
        let mut loader = ActivationLoader::with_checkpoint(loader_grant, floor.clone());
        let broker_grant = Grant {
            xite: xite.to_string(),
            enabled: true,
            generation,
            capabilities,
            publisher: Some(xite.to_string()),
            publisher_public_key: None,
            runtime_profiles: profiles,
        };
        let workspace = self.workspace_dir(xite);
        std::fs::create_dir_all(&workspace).map_err(|error| format!("workspace: {error}"))?;
        let broker = Arc::new(
            Broker::new(&workspace, broker_grant, limits).map_err(|denied| format!("workspace: {denied}"))?,
        );
        if let Ok(mut running) = self.running.lock() {
            running.insert(xite.to_string(), Arc::clone(&broker));
        }
        let config = Config::new(worker.to_path_buf());
        let mut read = |path: &str| -> Result<Vec<u8>, AuthenticationError> {
            files
                .get(path)
                .cloned()
                .ok_or_else(|| AuthenticationError::new("file unavailable"))
        };
        let outcome = run_content_activation(
            &config,
            &mut loader,
            &content,
            &bound,
            &mut read,
            &broker,
            RunOptions::default(),
        );
        if let Ok(mut running) = self.running.lock() {
            running.remove(xite);
        }
        let moved = loader.checkpoint() != &floor;
        let persisted = if moved {
            checkpoint::store(&checkpoints, xite, loader.checkpoint())
        } else {
            Ok(())
        };
        Ok((outcome, persisted))
    }
}

/// Resolve the worker binary the way the `evx-host` CLI does: `EVX_WORKER`
/// when set, else [`WORKER_BINARY`] beside the running executable. A path
/// that is not a regular file is `None`, which [`EvxService::execution`]
/// reports as an unsupported host rather than failing at the first run.
pub fn default_worker_binary() -> Option<PathBuf> {
    let path = match std::env::var_os("EVX_WORKER") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe().ok()?.with_file_name(WORKER_BINARY),
    };
    path.is_file().then_some(path)
}

/// Identifier check for an address used as a grant key and a path
/// component. A bech32 address passes; anything with a separator does not.
fn xite_id(xite: &str) -> Result<(), String> {
    evx_api::validate_identifier(xite).map_err(|denied| format!("invalid xite: {denied}"))
}

fn usable_program<'a>(inspection: &'a Inspection, program: &str) -> Result<&'a evx_declaration::Program, String> {
    if !inspection.bound.contains_key(program) {
        return Err(format!("program {program} is not usable in the current declaration"));
    }
    inspection
        .declaration
        .programs
        .get(program)
        .ok_or_else(|| format!("program {program} is not usable in the current declaration"))
}

/// Current Unix seconds; a clock before the epoch fails closed, as the
/// durable state's own clock does.
pub(crate) fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| "clock before the Unix epoch".to_string())
}

/// The digest of the canonical input a run-once program receives: there is
/// none, so it is the digest of canonical JSON `null`.
fn input_digest() -> Result<String, String> {
    let canonical = evx_state::canonical(&Value::Null).map_err(|error| error.to_string())?;
    Ok(evx_state::digest(&canonical))
}

/// A run message cut to what the state stores, on a character boundary.
fn bounded_message(message: &str) -> String {
    let mut out = String::new();
    for c in message.chars() {
        if out.len() + c.len_utf8() > MAX_MESSAGE {
            break;
        }
        out.push(c);
    }
    out
}

fn short(digest: &str) -> &str {
    digest.get(..16).unwrap_or(digest)
}

fn pinned(file: &evx_activation::PinnedFile) -> Value {
    json!({ "path": file.path, "size": file.size, "sha512": file.sha512 })
}

fn capability_names(capabilities: &BTreeSet<Capability>) -> Vec<&'static str> {
    capabilities.iter().map(|capability| capability.name()).collect()
}

fn limits_json(limits: Option<&Limits>) -> Value {
    limits
        .and_then(|limits| serde_json::to_value(limits).ok())
        .unwrap_or(Value::Null)
}

fn generations_json(generations: &Generations) -> Value {
    json!({
        "generation": generations.generation,
        "limits_generation": generations.limits_generation,
        "schema_generation": generations.schema_generation,
    })
}

/// The stored grant for status views. `covers` is whether it covers the
/// declaration inspected alongside it, when one was.
fn grant_json(grant: &XiteGrant, generations: &Generations, now: u64, covers: Option<bool>) -> Value {
    json!({
        "xite": grant.xite,
        "publisher": grant.publisher,
        "enabled": grant.enabled,
        "expired": grant.expires_unix.is_some_and(|at| now >= at),
        "generation": generations.generation,
        "limits_generation": generations.limits_generation,
        "capabilities": capability_names(&grant.capabilities),
        "runtime_profiles": grant.runtime_profiles,
        "limits": limits_json(Some(&grant.limits)),
        "allow_run_once": grant.allow_run_once,
        "allow_background": grant.allow_background,
        "created_unix": grant.created_unix,
        "expires_unix": grant.expires_unix,
        "label": grant.label,
        "covers_declaration": covers,
    })
}

fn run_json(run: &RunRecord) -> Value {
    serde_json::to_value(run).unwrap_or(Value::Null)
}

fn host_json(execution: Result<(), String>) -> Value {
    json!({
        "execution": execution.is_ok(),
        "reason": execution.err(),
        "ceiling": limits_json(Some(&HOST_CEILING)),
    })
}
