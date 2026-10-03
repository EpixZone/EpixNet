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
//! [`EvxService::set_limits`], [`EvxService::run_once`],
//! [`EvxService::run_job`], [`EvxService::job_pause`] and
//! [`EvxService::job_resume`] are reachable only through the dispatcher gate
//! in `epix_ui::command` (`EVX_WRAPPER_COMMANDS`), and the handlers re-check
//! the session shape; the service itself does not know who is calling and
//! must never be handed a page's socket.
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
//! # One run path
//!
//! A run-once, a scheduled occurrence and a manual job run all go through
//! [`EvxService::execute`]: the same lock, the same inspection, the same
//! file capture, the same authority re-check inside the blocking half, and
//! the same run record. What differs is the [`Run`] they are admitted as:
//! a run-once spends a token or the grant's `allow_run_once`, a job run
//! spends the grant's `allow_background` and carries the occurrence it was
//! reserved under, which `execute` finishes in the durable state whether the
//! run happened or was refused, so a reservation is never left open.
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
use evx_api::{Capability, Grant, Limits, Status};
use evx_declaration::{Declaration, DeclarationError};
use evx_host::run_content_activation;
use evx_state::{
    DurableState, Generations, Invocation, JobRow, JobSpec, RunRecord, Slot, XiteGrant,
    ALLOW_ONCE_TTL, MAX_MESSAGE,
};
use evx_supervisor::{Broker, Config, RunOptions};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

use crate::checkpoint;
use crate::limits::{clamp, combine, BACKGROUND_RUNS_PER_DAY, BACKGROUND_WORKERS, HOST_CEILING};
use crate::scheduler::{backoff, Scheduler};
use crate::PLUGIN_NAME;

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

/// The refusal of an `enable` grant whose dialog showed a different bound
/// closure than the declaration has now (see [`GrantRequest::shown`]).
pub const SHOWN_CHANGED: &str = "declaration changed since it was shown; inspect again";

/// Why a job occurrence was closed without its result: its grant changed
/// while it ran.
pub const ABANDONED_REVOKED: &str = "grant revoked while the occurrence ran";

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

/// What started a run, as the run record and the payload say it. Closed:
/// the state stores it as text and validates it as an identifier, and
/// status views and tests match on these three words only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// `evxRunOnce`: the operator's or the wrapper's one-off run.
    Once,
    /// The scheduler ran a job occurrence on its schedule.
    Job,
    /// `evxRunJob`: the operator ran the job's current occurrence by hand.
    ManualJob,
}

impl Trigger {
    /// The stored and reported spelling.
    pub fn name(self) -> &'static str {
        match self {
            Trigger::Once => "once",
            Trigger::Job => "job",
            Trigger::ManualJob => "manual_job",
        }
    }
}

/// Why a registered job is paused. Stored as text on the job row and read
/// back strictly: a reason this build did not write is left alone, neither
/// cleared nor rewritten, so a newer build's pause survives an older one.
///
/// The first two are set by people or by a run and cleared only by
/// `evxJobResume`; the others are set and cleared by registration, which
/// re-derives them from the declaration and the grant on every inspection:
/// the last two are set when the scheduler could not inspect the xite at
/// all, and the next verified inspection clears them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseReason {
    /// `evxJobPause`.
    User,
    /// A run ended `effect_unknown`: an effect may or may not have happened,
    /// and running again blindly could repeat it. A person resumes it.
    ReconcileRequired,
    /// The declaration was re-signed asking for more than the grant covers;
    /// the job waits for a new grant, as any broader authority does.
    DeclarationOutgrewGrant,
    /// The job's program can no longer be bound to the signed manifest on
    /// this node (a pinned file past the size bound, a missing entry).
    ProgramUnsupported,
    /// The scheduler could not read the declaration of a xite with due jobs:
    /// `content.json` unreadable or no longer valid, no `evx` section, or a
    /// signature that does not verify. The jobs wait for a content change
    /// (or the scheduler's own slow re-check) instead of being retried
    /// every tick.
    DeclarationUnavailable,
    /// The declaration verified but files it declares are still missing on
    /// this node; the jobs wait for them to arrive.
    ContentIncomplete,
}

impl PauseReason {
    /// The stored spelling.
    pub fn name(self) -> &'static str {
        match self {
            PauseReason::User => "user",
            PauseReason::ReconcileRequired => "reconcile_required",
            PauseReason::DeclarationOutgrewGrant => "declaration_outgrew_grant",
            PauseReason::ProgramUnsupported => "program_unsupported",
            PauseReason::DeclarationUnavailable => "declaration_unavailable",
            PauseReason::ContentIncomplete => "content_incomplete",
        }
    }

    /// The reason a stored text names, or `None` for text this build does
    /// not know.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "user" => Some(PauseReason::User),
            "reconcile_required" => Some(PauseReason::ReconcileRequired),
            "declaration_outgrew_grant" => Some(PauseReason::DeclarationOutgrewGrant),
            "program_unsupported" => Some(PauseReason::ProgramUnsupported),
            "declaration_unavailable" => Some(PauseReason::DeclarationUnavailable),
            "content_incomplete" => Some(PauseReason::ContentIncomplete),
            _ => None,
        }
    }

    /// Whether registration owns this reason: it is set and cleared from
    /// the declaration and the grant, never by a person.
    pub fn from_registration(self) -> bool {
        matches!(
            self,
            PauseReason::DeclarationOutgrewGrant
                | PauseReason::ProgramUnsupported
                | PauseReason::DeclarationUnavailable
                | PauseReason::ContentIncomplete
        )
    }

    /// Whether the scheduler set this reason because it could not inspect
    /// the xite: the pauses it re-checks by itself.
    pub fn from_inspection(self) -> bool {
        matches!(self, PauseReason::DeclarationUnavailable | PauseReason::ContentIncomplete)
    }
}

/// Why a job is not being admitted right now, as `evxStatus` shows it on
/// each job (`waiting_reason`). Derived from the current state on every
/// status call rather than remembered from the last tick, so it is never
/// stale and never says a job waits for something that already passed.
/// `None` on the payload means nothing blocks the job: it runs at
/// `next_due_unix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReason {
    /// The `Evx` plugin is switched off.
    PluginDisabled,
    /// This host cannot execute (not macOS, or no worker binary).
    UnsupportedHost,
    /// The xite was never granted.
    NoGrant,
    /// The grant is disabled.
    Revoked,
    /// The grant's expiry passed.
    Expired,
    /// The grant does not allow background work (it was given to a
    /// declaration without jobs).
    BackgroundNotAllowed,
    /// The grant no longer covers what the declaration asks for.
    DeclarationNotCovered,
    /// The job row's host switch is off.
    JobDisabled,
    /// The job is paused; `paused_reason` says why.
    Paused,
    /// The clock is before the last claimed slot's end.
    ClockRollback,
    /// The xite holds as many occurrence rows as the state retains, so no
    /// new occurrence can be reserved; the job moves to its next slot each
    /// time rather than retrying.
    OccurrenceLimit,
    /// The xite started [`BACKGROUND_RUNS_PER_DAY`] runs this UTC day.
    DailyBudget,
    /// [`BACKGROUND_WORKERS`] background runs are already in flight.
    WorkersBusy,
    /// Another run of this xite holds its run lock.
    XiteBusy,
}

impl WaitReason {
    /// The payload spelling.
    pub fn name(self) -> &'static str {
        match self {
            WaitReason::PluginDisabled => "plugin_disabled",
            WaitReason::UnsupportedHost => "unsupported_host",
            WaitReason::NoGrant => "no_grant",
            WaitReason::Revoked => "revoked",
            WaitReason::Expired => "expired",
            WaitReason::BackgroundNotAllowed => "background_not_allowed",
            WaitReason::DeclarationNotCovered => "declaration_not_covered",
            WaitReason::JobDisabled => "job_disabled",
            WaitReason::Paused => "paused",
            WaitReason::ClockRollback => "clock_rollback",
            WaitReason::OccurrenceLimit => "occurrence_limit",
            WaitReason::DailyBudget => "daily_budget",
            WaitReason::WorkersBusy => "workers_busy",
            WaitReason::XiteBusy => "xite_busy",
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

    /// The declared jobs whose program is bound: the ones that can run in
    /// the background, by id. This is the one definition of "usable job"
    /// for consent and for admission alike: the dialog's background
    /// paragraph, `effective.allow_background`, the grant's
    /// `allow_background` and the scheduler's registration all derive from
    /// it, so the user is told about exactly the jobs that enabling lets run.
    pub fn usable_jobs(&self) -> BTreeMap<&str, &evx_declaration::Job> {
        self.declaration
            .jobs
            .iter()
            .filter(|(_, job)| self.bound.contains_key(&job.program))
            .map(|(id, job)| (id.as_str(), job))
            .collect()
    }

    /// The stored grant, if it is enabled and unexpired at `now`.
    pub fn live_grant(&self, now: u64) -> Option<(&XiteGrant, &Generations)> {
        let (grant, generations) = self.grant.as_ref()?;
        if !grant.enabled || grant.expires_unix.is_some_and(|at| now >= at) {
            return None;
        }
        Some((grant, generations))
    }

    /// Whether the live grant covers what the bound programs ask for: every
    /// requested capability and the runtime profile. An authenticated update
    /// within this runs without a new prompt; one beyond it waits for one.
    pub fn covers_declaration(&self, now: u64) -> bool {
        self.live_grant(now).is_some_and(|(grant, _)| {
            self.requested_capabilities().is_subset(&grant.capabilities)
                && grant.runtime_profiles.contains(RUNTIME_PROFILE)
        })
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
        // A job whose program the manifest could not pin is shown as
        // unusable like the program itself, so the dialog never lists a job
        // that enabling would not let run.
        let usable_jobs = self.usable_jobs();
        if let Some(jobs) = summary.get_mut("jobs").and_then(Value::as_object_mut) {
            for (id, entry) in jobs.iter_mut() {
                if usable_jobs.contains_key(id.as_str()) {
                    continue;
                }
                let Some(job) = self.declaration.jobs.get(id) else { continue };
                let Some(reason) = self.unbound.get(&job.program) else { continue };
                if let Some(entry) = entry.as_object_mut() {
                    entry.insert("usable".into(), Value::Bool(false));
                    if let Some(Value::Array(reasons)) = entry.get_mut("reasons") {
                        reasons.push(Value::String(format!("program {}: {reason}", job.program)));
                    }
                }
                unsupported.push(json!({ "path": format!("jobs.{id}"), "reason": format!("program {}: {reason}", job.program) }));
            }
        }
        if let Some(object) = summary.as_object_mut() {
            object.insert("programs".into(), Value::Object(programs));
            object.insert("unsupported".into(), Value::Array(unsupported.clone()));
        }
        let requested_capabilities = self.requested_capabilities();
        let requested_limits = self.requested_limits();
        let effective_limits = requested_limits.as_ref().and_then(|limits| clamp(limits).ok());
        let grant = self
            .grant
            .as_ref()
            .map(|(grant, generations)| grant_json(grant, generations, now, Some(self.covers_declaration(now))));
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
                "jobs": usable_jobs.keys().copied().collect::<Vec<_>>(),
            },
            "effective": {
                "capabilities": capability_names(&requested_capabilities),
                "limits": limits_json(effective_limits.as_ref()),
                "runtime_profiles": [RUNTIME_PROFILE],
                "allow_run_once": self.requests_run_once(),
                // Exactly what an `enable` grant will record: consent to
                // background work is consent to these jobs, and the dialog
                // shows its background paragraph on this bit alone.
                "allow_background": !usable_jobs.is_empty(),
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
    /// What the dialog showed of the bound closure, for an `enable` grant
    /// (required there, refused for `once`): the inspect payload's
    /// `requested.programs`, `requested.jobs`, `effective.allow_run_once`
    /// and `effective.allow_background`. The digest covers the `evx` object
    /// only, and which programs bind (and so which jobs are usable, whether
    /// any run-once is requested, and whether background work is granted)
    /// also depends on the signed `files` manifest, which a re-sign can
    /// change without changing the digest. The grant compares these with
    /// what it would record and refuses on any difference, so consent is
    /// never wider than the text the user read.
    #[serde(default)]
    pub shown: Option<Shown>,
}

/// The bound closure the consent dialog rendered (see
/// [`GrantRequest::shown`]). Decoded strictly like the request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shown {
    /// The usable programs, by id (`requested.programs`).
    pub programs: Vec<String>,
    /// The usable jobs, by id (`requested.jobs`).
    pub jobs: Vec<String>,
    /// `effective.allow_run_once`.
    pub allow_run_once: bool,
    /// `effective.allow_background`.
    pub allow_background: bool,
}

impl Shown {
    /// What an `enable` grant of `inspection` records, in the same terms.
    pub fn of(inspection: &Inspection) -> Shown {
        let usable_jobs = inspection.usable_jobs();
        Shown {
            programs: inspection.bound.keys().cloned().collect(),
            jobs: usable_jobs.keys().map(|id| (*id).to_string()).collect(),
            allow_run_once: inspection.requests_run_once(),
            allow_background: !usable_jobs.is_empty(),
        }
    }

    /// The same shape with the lists in a canonical order, so the order a
    /// client happened to send them in never matters.
    fn sorted(mut self) -> Shown {
        self.programs.sort();
        self.programs.dedup();
        self.jobs.sort();
        self.jobs.dedup();
        self
    }
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

/// What a run was admitted under, as the payload reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authority {
    /// The enabled, persistent grant's `allow_run_once`.
    Grant,
    /// A spent allow-once token.
    Once,
    /// The enabled, persistent grant's `allow_background`: a job occurrence,
    /// whether the scheduler or the operator pulled the trigger. Carries
    /// the generation like [`Authority::Grant`] and is fenced the same way.
    Scheduled,
}

impl Authority {
    fn name(self) -> &'static str {
        match self {
            Authority::Grant => "grant",
            Authority::Once => "once",
            Authority::Scheduled => "scheduled",
        }
    }
}

/// A reserved job occurrence handed to [`EvxService::execute`]: the
/// invocation [`DurableState::claim_occurrence`] (or `recover`) returned,
/// the job row it was claimed from and the slot it stands for.
#[derive(Debug, Clone)]
pub(crate) struct Occurrence {
    pub invocation: Invocation,
    pub row: JobRow,
    pub slot: Slot,
}

/// How a run asks to be admitted.
pub(crate) enum Run {
    /// `evxRunOnce`: under the grant's `allow_run_once`, or by spending the
    /// token.
    Once { token: Option<String> },
    /// A job occurrence under the grant's `allow_background`. Boxed: the
    /// occurrence carries the job row and the invocation, many times the
    /// size of a token, and the enum travels into a spawned task.
    Job { occurrence: Box<Occurrence>, trigger: Trigger },
}

/// The authority [`EvxService::execute`] established for one run, handed
/// to the blocking half so it can re-derive it once the broker is in
/// `running`: the generation and the revocation count it was admitted at,
/// and the capabilities, profiles and limits the broker enforces.
struct Admitted {
    authority: Authority,
    generation: u64,
    revocations: u64,
    capabilities: BTreeSet<Capability>,
    profiles: BTreeSet<String>,
    limits: Limits,
}

/// What the run half of [`EvxService::execute`] produced: the payload the
/// command returns and the parts the occurrence commit needs.
struct Executed {
    payload: Value,
    status: Status,
    value: Option<i32>,
    error: Option<String>,
    elapsed_ms: u64,
}

/// The node's EVX service. One per node, created by the plugin at start and
/// shared with its commands through `AppState::install_capability`.
pub struct EvxService {
    pub(crate) state: DurableState,
    root: PathBuf,
    /// Keeps an in-memory node's throwaway state directory alive.
    _scratch: Option<tempfile::TempDir>,
    /// The worker binary, when one was found at start.
    worker: Option<PathBuf>,
    /// Brokers of runs in flight, by xite, so a revocation reaches the
    /// supervisor's grant check and stops the run.
    pub(crate) running: Mutex<HashMap<String, Arc<Broker>>>,
    /// One run at a time per xite: the loader's checkpoint is read, moved
    /// and persisted around each run, and two runs interleaving on it could
    /// persist the lower floor last.
    run_locks: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// How often each xite has been revoked since start. A run notes the
    /// count when its authority is checked and refuses to proceed if it
    /// moved by the time its broker is registered; the durable grant
    /// carries the same fact for a xite that has a grant row, this covers
    /// the token-only xite that has none.
    revocations: Mutex<HashMap<String, u64>>,
    /// When each xite's page last asked (`evxRequest`), for status views.
    asked: Mutex<HashMap<String, u64>>,
    /// The scheduler's wake handle and counters; the task itself is spawned
    /// by the plugin.
    pub(crate) scheduler: Scheduler,
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
            revocations: Mutex::new(HashMap::new()),
            asked: Mutex::new(HashMap::new()),
            scheduler: Scheduler::default(),
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

    /// Wake the scheduler: something that decides what is due changed.
    pub fn wake(&self) {
        self.scheduler.wake();
    }

    /// Ticks the scheduler completed since start, so a caller can tell
    /// whether an event woke it.
    pub fn scheduler_ticks(&self) -> u64 {
        self.scheduler.ticks()
    }

    /// Stop the scheduler task at its next wake. The node has no graceful
    /// shutdown hook (the design is crash-safe instead); this exists so a
    /// test can reopen the same state under a second service without two
    /// schedulers ticking on one database.
    pub fn shutdown(&self) {
        self.scheduler.stop();
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

    /// Read, verify, parse, digest and bind `xite`'s declaration. Inert for
    /// the xite: nothing is compiled, instantiated or spawned, and no
    /// program file is opened; the hashes reported are the signed
    /// manifest's. The one write is the service's own bookkeeping: when the
    /// xite holds a live grant with `allow_background`, the declaration's
    /// jobs are registered with the scheduler from what was just verified
    /// (see [`EvxService::register_jobs`]), so a re-signed declaration is
    /// picked up by whoever looks at it first, a page, the dialog or the
    /// scheduler itself.
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
        let inspection = Inspection {
            xite: xite.to_string(),
            integrity,
            content,
            declaration,
            digest,
            bound,
            unbound,
            grant,
        };
        if inspection.integrity == Integrity::Verified {
            // Bookkeeping that fails (a declaration past the state's job
            // bound, say) is the operator's to see in the log; it does not
            // hide the declaration from the dialog that would let them act.
            if let Err(error) = self.register_jobs(&inspection, now_unix()?) {
                app.log("ERROR", format!("EVX: jobs of {xite} not registered: {error}")).await;
            }
        }
        Ok(inspection)
    }

    /// Register the declaration's jobs with the scheduler from a verified
    /// inspection, when the xite holds a live grant that allows background
    /// work; without one nothing is written, since there is no consent to
    /// schedule under. Every declared job is registered under the current
    /// digest (a vanished one is removed by `set_jobs`), then paused or
    /// resumed by what registration owns: a job whose program the manifest
    /// could not pin is paused `program_unsupported`, and when the grant no
    /// longer covers the declaration every job is paused
    /// `declaration_outgrew_grant` until a new grant does. A pause a person
    /// set, or one a run set (`reconcile_required`), is left for a person
    /// to lift; text this build does not know is left alone.
    fn register_jobs(&self, inspection: &Inspection, now: u64) -> Result<(), String> {
        if !inspection.live_grant(now).is_some_and(|(grant, _)| grant.allow_background) {
            return Ok(());
        }
        let xite = inspection.xite.as_str();
        let covers = inspection.covers_declaration(now);
        let specs: Vec<JobSpec> = inspection
            .declaration
            .jobs
            .iter()
            .map(|(id, job)| JobSpec {
                job: id.clone(),
                program: job.program.clone(),
                schedule: job.schedule.clone(),
                max_concurrency: job.max_concurrency,
            })
            .collect();
        let mut rows = self
            .state
            .jobs(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        // The scheduler inspects a xite on every content change and every
        // due tick, so an unchanged registration is not written again.
        if !registered_as(&rows, &inspection.digest, &specs) {
            self.state
                .set_jobs(xite, &inspection.digest, &specs, now)
                .map_err(|error| format!("EVX state: {error}"))?;
            rows = self
                .state
                .jobs(xite)
                .map_err(|error| format!("EVX state: {error}"))?;
        }
        for row in rows {
            let Some(job) = inspection.declaration.jobs.get(&row.job) else { continue };
            let wanted = if !inspection.bound.contains_key(&job.program) {
                Some(PauseReason::ProgramUnsupported)
            } else if !covers {
                Some(PauseReason::DeclarationOutgrewGrant)
            } else {
                None
            };
            let current = row.paused_reason.as_deref();
            let owned = match current {
                None => true,
                Some(text) => PauseReason::parse(text).is_some_and(PauseReason::from_registration),
            };
            if !owned || current == wanted.map(PauseReason::name) {
                continue;
            }
            self.state
                .set_job_paused(xite, &row.job, wanted.map(PauseReason::name))
                .map_err(|error| format!("EVX state: {error}"))?;
        }
        Ok(())
    }

    /// Pause every job of `xite` with `reason`, one the scheduler sets when
    /// it cannot inspect the xite ([`PauseReason::from_inspection`]). A pause
    /// a person or a run set is left alone, as registration leaves it.
    /// Returns whether any job changed, so the caller logs a pause once
    /// rather than on every re-check.
    pub(crate) fn pause_for_inspection(&self, xite: &str, reason: PauseReason) -> Result<bool, String> {
        let rows = self
            .state
            .jobs(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        let mut changed = false;
        for row in rows {
            let current = row.paused_reason.as_deref();
            let owned = match current {
                None => true,
                Some(text) => PauseReason::parse(text).is_some_and(PauseReason::from_registration),
            };
            if !owned || current == Some(reason.name()) {
                continue;
            }
            self.state
                .set_job_paused(xite, &row.job, Some(reason.name()))
                .map_err(|error| format!("EVX state: {error}"))?;
            changed = true;
        }
        Ok(changed)
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

    /// Grant status, generations, recent runs, the registered jobs with why
    /// each is or is not being admitted, the scheduler's state and the
    /// reasons the xite cannot run right now, from the durable state and
    /// the plugin switch alone. Works for a xite without a declaration, so
    /// a page can poll it cheaply.
    pub async fn status(&self, app: &AppState, xite: &str) -> Result<Value, String> {
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
        let jobs = self
            .state
            .jobs(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        let runs_today = self
            .state
            .daily_runs(xite, now)
            .map_err(|error| format!("EVX state: {error}"))?;
        let occurrences_full = self
            .state
            .retained_occurrences(xite)
            .map_err(|error| format!("EVX state: {error}"))?
            >= evx_state::MAX_ROWS;
        let plugin_enabled = app.plugin_enabled(PLUGIN_NAME).await;
        let execution = self.execution().map(|_| ());
        let grant_wait = match &stored {
            None => Some(WaitReason::NoGrant),
            Some((grant, _)) if !grant.enabled => Some(WaitReason::Revoked),
            Some((grant, _)) if grant.expires_unix.is_some_and(|at| now >= at) => Some(WaitReason::Expired),
            Some((grant, _)) if !grant.allow_background => Some(WaitReason::BackgroundNotAllowed),
            Some(_) => None,
        };
        let mut reasons: Vec<&str> = Vec::new();
        match grant_wait {
            Some(WaitReason::NoGrant) => reasons.push("no_grant"),
            Some(WaitReason::Revoked) => reasons.push("revoked"),
            Some(WaitReason::Expired) => reasons.push("expired"),
            _ => {}
        }
        if let Some((grant, _)) = &stored {
            if grant.enabled && !grant.expires_unix.is_some_and(|at| now >= at) && !grant.allow_run_once {
                reasons.push("run_once_not_allowed");
            }
        }
        if grant_wait == Some(WaitReason::BackgroundNotAllowed) && !jobs.is_empty() {
            reasons.push("background_not_allowed");
        }
        if execution.is_err() {
            reasons.push("unsupported_host");
        }
        if !plugin_enabled {
            reasons.push("plugin_disabled");
        }
        let asked_unix = self.asked.lock().ok().and_then(|asked| asked.get(xite).copied());
        let running = self.running.lock().is_ok_and(|running| running.contains_key(xite));
        let busy_workers = self.scheduler.busy();
        let jobs_json: Vec<Value> = jobs
            .iter()
            .map(|row| {
                let slot = DurableState::slot_at(&row.schedule, now).ok();
                // The admission checks in their order, then the host: a
                // host that cannot execute admits nothing, but the reason
                // a job would wait for anyway is the more useful one to
                // show, and the host is already in `host` and `scheduler`.
                let waiting = if !plugin_enabled {
                    Some(WaitReason::PluginDisabled)
                } else if let Some(reason) = grant_wait {
                    Some(reason)
                } else if !row.enabled {
                    Some(WaitReason::JobDisabled)
                } else if row.paused_reason.is_some() {
                    Some(WaitReason::Paused)
                } else if slot.is_some_and(|slot| row.last_slot.is_some_and(|last| slot.index < last)) {
                    Some(WaitReason::ClockRollback)
                } else if occurrences_full {
                    Some(WaitReason::OccurrenceLimit)
                } else if runs_today >= BACKGROUND_RUNS_PER_DAY {
                    Some(WaitReason::DailyBudget)
                } else if busy_workers >= BACKGROUND_WORKERS {
                    Some(WaitReason::WorkersBusy)
                } else if running {
                    Some(WaitReason::XiteBusy)
                } else if execution.is_err() {
                    Some(WaitReason::UnsupportedHost)
                } else {
                    None
                };
                json!({
                    "job": row.job,
                    "program": row.program,
                    "schedule": row.schedule,
                    "enabled": row.enabled,
                    "paused_reason": row.paused_reason,
                    "next_due_unix": row.next_due_unix,
                    "last_slot": row.last_slot,
                    "last_occurrence": row.last_occurrence,
                    "failures": row.failures,
                    "runs_today": runs_today,
                    "daily_limit": BACKGROUND_RUNS_PER_DAY,
                    "declaration_digest": row.declaration_digest,
                    "current_slot": slot.map(|slot| slot.index),
                    "waiting_reason": waiting.map(WaitReason::name),
                })
            })
            .collect();
        Ok(json!({
            "xite": xite,
            "grant": stored.as_ref().map(|(grant, generations)| grant_json(grant, generations, now, None)),
            "generations": stored.as_ref().map(|(_, generations)| generations_json(generations)),
            "runs": runs.iter().take(STATUS_RUNS).map(run_json).collect::<Vec<_>>(),
            "run_count": runs.len(),
            "running": running,
            "reasons": reasons,
            "asked_unix": asked_unix,
            "host": host_json(execution.clone()),
            "jobs": jobs_json,
            "scheduler": {
                "enabled": plugin_enabled,
                "busy_workers": busy_workers,
                "next_wake_unix": self.scheduler.next_wake(),
                "host": if execution.is_ok() { "macos" } else { "unsupported" },
            },
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
                let shown = request
                    .shown
                    .clone()
                    .ok_or_else(|| "shown is required for mode enable: what the consent dialog showed".to_string())?;
                if shown.sorted() != Shown::of(&inspection) {
                    return Err(SHOWN_CHANGED.into());
                }
                if inspection.bound.is_empty() {
                    return Err("no usable program to grant".into());
                }
                let requested = inspection
                    .requested_limits()
                    .ok_or_else(|| "no usable program to grant".to_string())?;
                let limits = clamp(request.limits.as_ref().unwrap_or(&requested))?;
                let label = request.label.unwrap_or_else(|| DEFAULT_LABEL.to_string());
                let usable_jobs: Vec<&str> = inspection.usable_jobs().keys().copied().collect();
                let grant = XiteGrant {
                    xite: xite.to_string(),
                    publisher: xite.to_string(),
                    enabled: true,
                    capabilities: inspection.requested_capabilities(),
                    runtime_profiles: [RUNTIME_PROFILE.to_string()].into_iter().collect(),
                    limits,
                    allow_run_once: inspection.requests_run_once(),
                    // The same bit the inspect payload showed as
                    // `effective.allow_background`, on which the dialog said
                    // what enabling lets run in the background: consent and
                    // authority are derived from the one definition of a
                    // usable job, so neither can say more than the other.
                    allow_background: !usable_jobs.is_empty(),
                    created_unix: now,
                    expires_unix: None,
                    label,
                };
                let generations = self
                    .state
                    .set_xite_grant(&grant)
                    .map_err(|error| format!("EVX state: {error}"))?;
                // Register the jobs under the grant just stored, then wake
                // the scheduler so the first occurrence is not left to the
                // next timer.
                self.inspect(app, xite).await?;
                self.wake();
                app.log(
                    "INFO",
                    format!(
                        "EVX: enabled {xite} (declaration {}, generation {}, capabilities {:?}, jobs {:?})",
                        short(&inspection.digest),
                        generations.generation,
                        capability_names(&grant.capabilities),
                        usable_jobs
                    ),
                )
                .await;
                Ok(json!({
                    "granted": true,
                    "mode": GrantMode::Enable.name(),
                    "xite": xite,
                    "declaration_digest": inspection.digest,
                    "grant": grant_json(&grant, &generations, now, Some(true)),
                    "jobs": usable_jobs,
                }))
            }
            GrantMode::Once => {
                if request.limits.is_some() || request.label.is_some() || request.shown.is_some() {
                    return Err("limits, label and shown apply to mode enable only".into());
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
    /// recalled and the run history is kept; registered jobs stay
    /// registered and simply stop being due, so a later grant resumes them
    /// on the slot current then.
    ///
    /// The order is the mirror of the run's: the durable grant and the
    /// revocation count first, the broker lookup last, so a run that
    /// registered its broker before the lookup is stopped through it and
    /// one that registers after it sees the revocation when it re-derives
    /// its authority. A run queued behind the one in flight takes the run
    /// lock only afterwards and reads the disabled grant then; a scheduled
    /// occurrence the scheduler already reserved is finished as denied by
    /// the same re-check.
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
        if let Ok(mut revocations) = self.revocations.lock() {
            *revocations.entry(xite.to_string()).or_default() += 1;
        }
        let running = self
            .running
            .lock()
            .ok()
            .and_then(|running| running.get(xite).cloned());
        let stopped = running.is_some();
        if let Some(broker) = running {
            broker.revoke();
        }
        self.wake();
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
        self.wake();
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

    /// Pause a registered job (`evxJobPause`): it stops being due at once
    /// and an occurrence already reserved finishes as it will. The reason
    /// stored is `user`, which only [`EvxService::job_resume`] clears.
    pub async fn job_pause(&self, app: &AppState, xite: &str, job: &str) -> Result<Value, String> {
        xite_id(xite)?;
        job_id(job)?;
        self.state
            .set_job_paused(xite, job, Some(PauseReason::User.name()))
            .map_err(|error| format!("EVX state: {error}"))?;
        self.wake();
        app.log("INFO", format!("EVX: paused job {job} of {xite}")).await;
        self.job_status(app, xite, job).await
    }

    /// Resume a paused job (`evxJobResume`), whatever paused it: a person
    /// lifting `reconcile_required` is saying the reconciliation happened,
    /// and lifting a registration pause is harmless, since the next
    /// inspection puts it back while its cause stands. The job's
    /// `next_due_unix` is untouched, so it resumes on the slot it is due in
    /// now, never on one it missed.
    pub async fn job_resume(&self, app: &AppState, xite: &str, job: &str) -> Result<Value, String> {
        xite_id(xite)?;
        job_id(job)?;
        self.state
            .set_job_paused(xite, job, None)
            .map_err(|error| format!("EVX state: {error}"))?;
        self.wake();
        app.log("INFO", format!("EVX: resumed job {job} of {xite}")).await;
        self.job_status(app, xite, job).await
    }

    /// One job's entry of the status payload.
    async fn job_status(&self, app: &AppState, xite: &str, job: &str) -> Result<Value, String> {
        let status = self.status(app, xite).await?;
        status["jobs"]
            .as_array()
            .and_then(|jobs| jobs.iter().find(|entry| entry["job"] == job))
            .cloned()
            .ok_or_else(|| format!("job {job} is not registered for {xite}"))
    }

    /// Run `program` of `xite` now (`evxRunOnce`), under the enabled grant
    /// or by spending `token`. See [`EvxService::execute`] for the path
    /// and its order; a run-once has no occurrence and touches no job's
    /// slot.
    pub async fn run_once(
        self: &Arc<Self>,
        app: &AppState,
        xite: &str,
        program: &str,
        token: Option<&str>,
    ) -> Result<Value, String> {
        self.execute(app, xite, program, Run::Once { token: token.map(str::to_string) }).await
    }

    /// Run `job` of `xite` now (`evxRunJob`) as the occurrence of its
    /// current slot, so the scheduled run of that slot and this one cannot
    /// both execute: the claim is the same one the scheduler makes, and a
    /// slot already claimed comes back with its stored result (`stored:
    /// true`) or, while it is still running, as a refusal. The job must be
    /// registered, which it is for every xite with a background grant that
    /// was inspected since; a paused or disabled job is refused by the
    /// claim rather than run behind the pause. The daily budget is not
    /// spent: it bounds what the node starts by itself.
    pub async fn run_job(self: &Arc<Self>, app: &AppState, xite: &str, job: &str) -> Result<Value, String> {
        xite_id(xite)?;
        job_id(job)?;
        // Registration first, so a job of a freshly re-signed declaration
        // is claimed under its current digest.
        let inspection = self.inspect(app, xite).await?;
        if inspection.integrity != Integrity::Verified {
            return Err(format!(
                "declaration is {}; only a verified, complete xite can run",
                inspection.integrity.name()
            ));
        }
        let now = now_unix()?;
        let row = self
            .state
            .jobs(xite)
            .map_err(|error| format!("EVX state: {error}"))?
            .into_iter()
            .find(|row| row.job == job)
            .ok_or_else(|| format!("job {job} is not registered for {xite}; it needs an enabled grant that allows background runs"))?;
        let slot = DurableState::slot_at(&row.schedule, now).map_err(|error| format!("EVX state: {error}"))?;
        // Held before the claim commits, so the scheduler's recovery can
        // never see this fresh reservation unheld and run it a second time
        // as a crash's leftover; released again unless the claim is ours.
        let occurrence_id = DurableState::occurrence_id(&row.job, &slot);
        self.scheduler.hold(xite, &occurrence_id);
        let invocation = match self
            .state
            .claim_occurrence(xite, &row, &slot, &occurrence_request(&row, &slot), now)
        {
            Ok(invocation) if invocation.fresh => invocation,
            Ok(invocation) => {
                self.scheduler.release(xite, &occurrence_id);
                if invocation.completed {
                    return Ok(json!({
                        "stored": true,
                        "occurrence": invocation.occurrence,
                        "job": job,
                        "result": invocation.response,
                    }));
                }
                return Err(format!("occurrence {} is already running", invocation.occurrence));
            }
            Err(error) => {
                self.scheduler.release(xite, &occurrence_id);
                return Err(format!("EVX state: {error}"));
            }
        };
        let program = row.program.clone();
        let occurrence = Box::new(Occurrence { invocation, row, slot });
        let result = self
            .execute(app, xite, &program, Run::Job { occurrence, trigger: Trigger::ManualJob })
            .await;
        self.wake();
        let mut payload = result?;
        if let Some(object) = payload.as_object_mut() {
            object.insert("stored".into(), Value::Bool(false));
            object.insert("job".into(), json!(job));
        }
        Ok(payload)
    }

    /// The one run path. Verifies, captures, compiles, admits and runs
    /// through `evx_host::run_content_activation`, persists the checkpoint
    /// and a run record, and returns the `RunResult` with the activation
    /// report. On a host that cannot execute it returns
    /// [`UNSUPPORTED_HOST`] before reading anything, so neither the grant
    /// nor a token is touched. A job occurrence is finished in the durable
    /// state on every exit, with the result when the run happened and with
    /// the refusal when it did not, so the reservation the caller made is
    /// never left open and the schedule always moves on.
    ///
    /// The order inside matters. The xite's run lock is taken first, so a
    /// run queued behind another sees the grant as it is when its turn
    /// comes, not as it was when it was queued: a revocation that lands
    /// while it waits is seen. The program files are read before any
    /// authority is spent, so a file that cannot be read (a local edit past
    /// its signed size, a file gone missing) costs no token. The authority
    /// is checked last, and checked once more inside the blocking run after
    /// its broker is registered in `running`, where a revocation can reach
    /// it (see [`EvxService::authority_stands`]).
    pub(crate) async fn execute(
        self: &Arc<Self>,
        app: &AppState,
        xite: &str,
        program: &str,
        run: Run,
    ) -> Result<Value, String> {
        match run {
            Run::Once { token } => {
                let executed = self
                    .execute_inner(app, xite, program, Trigger::Once, token.as_deref(), None)
                    .await?;
                Ok(executed.payload)
            }
            Run::Job { occurrence, trigger } => {
                let executed = self
                    .execute_inner(app, xite, program, trigger, None, Some(&occurrence))
                    .await;
                let finished = now_unix();
                match finished {
                    Ok(now) => self.finish_job_run(app, &occurrence, &executed, now).await,
                    Err(ref error) => {
                        app.log("ERROR", format!("EVX: occurrence {} of {xite} not finished: {error}", occurrence.invocation.occurrence)).await;
                    }
                }
                self.scheduler.release(xite, &occurrence.invocation.occurrence);
                finished?;
                executed.map(|executed| executed.payload)
            }
        }
    }

    async fn execute_inner(
        self: &Arc<Self>,
        app: &AppState,
        xite: &str,
        program: &str,
        trigger: Trigger,
        token: Option<&str>,
        occurrence: Option<&Occurrence>,
    ) -> Result<Executed, String> {
        let worker = self.execution()?.to_path_buf();
        xite_id(xite)?;
        evx_api::validate_identifier(program).map_err(|denied| format!("invalid program: {denied}"))?;

        let lock = {
            let mut locks = self.run_locks.lock().await;
            locks.entry(xite.to_string()).or_default().clone()
        };
        let _running = lock.lock().await;

        let inspection = self.inspect(app, xite).await?;
        if inspection.integrity != Integrity::Verified {
            return Err(format!(
                "declaration is {}; only a verified, complete xite can run",
                inspection.integrity.name()
            ));
        }
        if let Some(occurrence) = occurrence {
            // The occurrence was reserved for a job of one declaration; a
            // root re-signed since then is a different request, and its jobs
            // were re-registered under the new digest at the inspection
            // just made. This reservation is finished as refused and the
            // scheduler claims the slot it is due in under the new digest.
            if occurrence.row.declaration_digest != inspection.digest {
                return Err("declaration changed since the occurrence was reserved".into());
            }
            if occurrence.row.program != program {
                return Err("occurrence does not belong to this program".into());
            }
            // The job as it is now, after the inspection re-registered it: a
            // job paused or disabled since the slot was reserved (by a person,
            // or by registration) does not run behind its pause, whether the
            // reservation is the scheduler's, a manual run's or a recovered
            // one.
            let current = self
                .state
                .jobs(xite)
                .map_err(|error| format!("EVX state: {error}"))?
                .into_iter()
                .find(|row| row.job == occurrence.row.job)
                .ok_or_else(|| format!("job {} is no longer registered", occurrence.row.job))?;
            if !current.enabled {
                return Err(format!("job {} is disabled", current.job));
            }
            if let Some(reason) = &current.paused_reason {
                return Err(format!("job {} is paused: {reason}", current.job));
            }
        }
        let declared = usable_program(&inspection, program)?.clone();
        let bound = inspection
            .bound
            .get(program)
            .cloned()
            .ok_or_else(|| format!("program {program} is not usable"))?;
        if trigger == Trigger::Once && !declared.allow_run_once {
            return Err(format!("program {program} does not allow run-once"));
        }

        // The closure's bytes, read now so the blocking run needs no node
        // state. Each read is bounded by the size the manifest signed; the
        // loader re-hashes every byte against the pin.
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for pin in std::iter::once(&bound.entry).chain(bound.dependencies.iter()) {
            let data = app.read_xite_file_bounded(xite, &pin.path, pin.size).await?;
            files.insert(pin.path.clone(), data);
        }
        let entry_sha256 = hex::encode(Sha256::digest(files.get(&bound.entry.path).map(Vec::as_slice).unwrap_or_default()));
        let now = now_unix()?;

        // Authority: a spent token covers exactly this program at exactly
        // this digest with its own declared request; an enabled grant must
        // already cover the program's request, through `allow_run_once` for
        // a run-once and `allow_background` for a job occurrence. The
        // revocation count is read before either is spent, so a revocation
        // from here on is seen by the re-check in the blocking run.
        let revocations = self.revocations_of(xite);
        let (capabilities, limits, generation, authority) = match (trigger, token) {
            (Trigger::Once, Some(token)) => {
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
                (declared.capabilities.clone(), clamp(&declared.limits)?, generation, Authority::Once)
            }
            (trigger, _) => {
                let (grant, generations) = inspection
                    .live_grant(now)
                    .ok_or_else(|| format!("no enabled EVX grant for {xite}"))?;
                let authority = match trigger {
                    Trigger::Once => {
                        if !grant.allow_run_once {
                            return Err(format!("the grant for {xite} does not allow run-once"));
                        }
                        Authority::Grant
                    }
                    Trigger::Job | Trigger::ManualJob => {
                        if !grant.allow_background {
                            return Err(format!("the grant for {xite} does not allow background runs"));
                        }
                        Authority::Scheduled
                    }
                };
                if !declared.capabilities.is_subset(&grant.capabilities) {
                    return Err(format!("program {program} asks for capabilities beyond the grant"));
                }
                if !grant.runtime_profiles.contains(&declared.runtime_profile) {
                    return Err(format!("program {program} asks for a runtime profile beyond the grant"));
                }
                (grant.capabilities.clone(), grant.limits.clone(), generations.generation, authority)
            }
        };

        let service = Arc::clone(self);
        let xite_owned = xite.to_string();
        let content = inspection.content.clone();
        let digest = inspection.digest.clone();
        let profiles: BTreeSet<String> = [RUNTIME_PROFILE.to_string()].into_iter().collect();
        let started = now;
        let started_instant = std::time::Instant::now();
        let run = tokio::task::spawn_blocking(move || {
            let admitted = Admitted { authority, generation, revocations, capabilities, profiles, limits };
            service.run_blocking(&xite_owned, &worker, content, bound, files, admitted)
        })
        .await
        .map_err(|error| format!("EVX run task failed: {error}"))?;
        let (outcome, checkpoint_result) = run?;
        let finished = now_unix()?;
        let elapsed_ms = u64::try_from(started_instant.elapsed().as_millis()).unwrap_or(u64::MAX);

        let result_json = serde_json::to_value(&outcome.result).map_err(|error| error.to_string())?;
        let status = result_json
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| "run result without a status".to_string())?
            .to_string();
        let occurrence_id = occurrence.map(|occurrence| occurrence.invocation.occurrence.clone());
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
            occurrence: occurrence_id.clone(),
            trigger: trigger.name().to_string(),
        };
        self.state
            .record_run(xite, &record)
            .map_err(|error| format!("EVX state: {error}"))?;
        app.log(
            "INFO",
            format!(
                "EVX: ran {xite} program {program} under {} ({}{}): {status}{}",
                authority.name(),
                trigger.name(),
                occurrence_id.as_deref().map(|id| format!(" {id}")).unwrap_or_default(),
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
            object.insert("authority".into(), json!(authority.name()));
            object.insert("trigger".into(), json!(trigger.name()));
            object.insert("occurrence".into(), json!(occurrence_id));
            object.insert("checkpoint_error".into(), json!(checkpoint_error));
        }
        Ok(Executed {
            payload,
            status: outcome.result.status,
            value: outcome.result.value,
            error: outcome.result.error,
            elapsed_ms,
        })
    }

    /// Complete a job occurrence after [`EvxService::execute_inner`]
    /// returned, with the run's result or with the refusal. The committed
    /// response is a float-free summary (status, value, error, elapsed
    /// milliseconds, occurrence) rather than the raw `RunResult`, whose
    /// float fields canonical JSON refuses; the full result is in the run
    /// record. A success moves `next_due` to the slot's end; a failure
    /// counts and backs off (`max(next slot, now + min(2^failures * 30 s,
    /// 6 h))`), and `effect_unknown` also pauses the job
    /// `reconcile_required`, since running again could repeat an effect
    /// whose outcome nobody knows. A finish the state refuses (a grant
    /// revoked mid-run fences the commit) is logged, never swallowed: the
    /// reservation stays visible to recovery and the slot stays claimed.
    async fn finish_job_run(
        &self,
        app: &AppState,
        occurrence: &Occurrence,
        executed: &Result<Executed, String>,
        now: u64,
    ) {
        let id = occurrence.invocation.occurrence.as_str();
        let (summary, failed, reconcile) = match executed {
            Ok(executed) => (
                json!({
                    "status": status_name(executed.status),
                    "value": executed.value,
                    "error": executed.error,
                    "elapsed_ms": executed.elapsed_ms,
                    "occurrence": id,
                }),
                executed.status != Status::Ok,
                executed.status == Status::EffectUnknown,
            ),
            Err(refusal) => (
                json!({
                    "status": status_name(Status::Denied),
                    "value": null,
                    "error": bounded_message(refusal),
                    "elapsed_ms": 0,
                    "occurrence": id,
                }),
                true,
                false,
            ),
        };
        let next_due = if failed {
            occurrence
                .slot
                .end_unix
                .max(now.saturating_add(backoff(occurrence.row.failures.saturating_add(1))))
        } else {
            occurrence.slot.end_unix
        };
        match self
            .state
            .finish_occurrence(&occurrence.invocation, &summary, Some(next_due), failed)
        {
            Ok(()) => {}
            // The grant was revoked (or revoked and given again) while the
            // occurrence ran: its generation fences the commit, and would
            // fence every later attempt too. The host closes its own
            // reservation without the fence instead, so it is neither left
            // open for every later start to trip over nor counted against
            // the retained rows forever.
            Err(evx_state::Error::Denied(denied)) => {
                let message = format!("{ABANDONED_REVOKED} ({denied})");
                match self.state.abandon(&occurrence.invocation, &bounded_message(&message)) {
                    Ok(()) => {
                        app.log("WARN", format!("EVX: occurrence {id} of {} abandoned: {message}", occurrence.row.xite)).await;
                    }
                    Err(error) => {
                        app.log("ERROR", format!("EVX: occurrence {id} of {} not abandoned: {error}", occurrence.row.xite)).await;
                    }
                }
            }
            Err(error) => {
                app.log("ERROR", format!("EVX: occurrence {id} of {} not finished: {error}", occurrence.row.xite)).await;
            }
        }
        if reconcile {
            if let Err(error) = self.state.set_job_paused(
                &occurrence.row.xite,
                &occurrence.row.job,
                Some(PauseReason::ReconcileRequired.name()),
            ) {
                app.log("ERROR", format!("EVX: job {} of {} not paused: {error}", occurrence.row.job, occurrence.row.xite)).await;
            } else {
                app.log(
                    "WARN",
                    format!(
                        "EVX: job {} of {} paused: occurrence {id} ended with an unknown effect; resume it once reconciled",
                        occurrence.row.job, occurrence.row.xite
                    ),
                )
                .await;
            }
        }
    }

    /// Whether `xite`'s run lock is free right now: the scheduler's
    /// admission check, advisory only, since the run takes the lock itself.
    pub(crate) async fn run_lock_free(&self, xite: &str) -> bool {
        let lock = {
            let mut locks = self.run_locks.lock().await;
            locks.entry(xite.to_string()).or_default().clone()
        };
        // Bound to a name rather than returned as the tail expression: the
        // guard `try_lock` hands back borrows `lock`, and a tail-expression
        // temporary is dropped after the locals it borrows from.
        let free = lock.try_lock().is_ok();
        free
    }

    /// How many times `xite` has been revoked since the service started.
    fn revocations_of(&self, xite: &str) -> u64 {
        self.revocations
            .lock()
            .ok()
            .and_then(|revocations| revocations.get(xite).copied())
            .unwrap_or(0)
    }

    /// Whether the authority a run was admitted under still stands. Called
    /// in the blocking run once its broker is in `running`, so that from
    /// here on a revocation reaches the run through the broker; a
    /// revocation that landed before this point is visible in two places,
    /// and either one disqualifies the run: the durable grant (disabled, or
    /// at a newer generation than the one admitted) and the service's
    /// revocation count for the xite, which also covers a token run on a
    /// xite that never had a grant row for `revoke_xite` to mark. A
    /// scheduled run is fenced exactly like a grant run: it has no token
    /// to fall back on.
    fn authority_stands(&self, xite: &str, admitted: &Admitted) -> Result<(), String> {
        if self.revocations_of(xite) != admitted.revocations {
            return Err("execution grant revoked".into());
        }
        let stored = self
            .state
            .xite_grant(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        match (admitted.authority, stored) {
            (Authority::Grant | Authority::Scheduled, Some((grant, generations))) => {
                let live = grant.enabled && !grant.expires_unix.is_some_and(|at| now_unix().is_ok_and(|now| now >= at));
                if !live || generations.generation != admitted.generation {
                    return Err("execution grant revoked".into());
                }
            }
            (Authority::Grant | Authority::Scheduled, None) => return Err("execution grant revoked".into()),
            (Authority::Once, Some((_, generations))) if generations.generation != admitted.generation => {
                return Err("execution grant revoked".into());
            }
            (Authority::Once, _) => {}
        }
        Ok(())
    }

    /// The blocking half of [`EvxService::execute`]: the loader with the
    /// persisted floor, a broker on the xite's private workspace, the run,
    /// and the floor persisted again if it moved. Runs on a blocking thread
    /// because the supervisor spawns and waits on processes.
    ///
    /// The broker is registered in `running` before anything that depends
    /// on the grant, and the authority is re-derived right after: a
    /// revocation ordered before the registration is seen by the re-check,
    /// one ordered after it finds the broker and revokes it, so no window
    /// is left in which a run proceeds under a grant that is already gone.
    fn run_blocking(
        &self,
        xite: &str,
        worker: &Path,
        content: Value,
        bound: BoundProgram,
        files: BTreeMap<String, Vec<u8>>,
        admitted: Admitted,
    ) -> Result<(evx_host::ActivationOutcome, Result<(), String>), String> {
        let checkpoints = self.root.join("checkpoints");
        let floor = checkpoint::load(&checkpoints, xite)?;
        let loader_grant = evx_activation::XiteGrant::for_root_address(
            xite.to_string(),
            xite.to_string(),
            admitted.capabilities.clone(),
            admitted.profiles.clone(),
        )
        .and_then(|grant| grant.with_generation(admitted.generation))
        .map_err(|error| format!("activation grant: {error}"))?;
        let mut loader = ActivationLoader::with_checkpoint(loader_grant, floor.clone());
        let broker_grant = Grant {
            xite: xite.to_string(),
            enabled: true,
            generation: admitted.generation,
            capabilities: admitted.capabilities.clone(),
            publisher: Some(xite.to_string()),
            publisher_public_key: None,
            runtime_profiles: admitted.profiles.clone(),
        };
        let workspace = self.workspace_dir(xite);
        std::fs::create_dir_all(&workspace).map_err(|error| format!("workspace: {error}"))?;
        let broker = Arc::new(
            Broker::new(&workspace, broker_grant, admitted.limits.clone())
                .map_err(|denied| format!("workspace: {denied}"))?,
        );
        if let Ok(mut running) = self.running.lock() {
            running.insert(xite.to_string(), Arc::clone(&broker));
        }
        // A revocation that landed between the check in `execute` and the
        // registration above disables the broker's grant here, and the
        // activation's binding check below then denies the run before any
        // worker is spawned; the denial is recorded like any other.
        if self.authority_stands(xite, &admitted).is_err() {
            broker.revoke();
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

/// The request a job occurrence is reserved with: exactly the four fields
/// [`DurableState::claim_occurrence`] requires, so the scheduler's claim and
/// a manual run's claim of the same slot digest identically.
pub(crate) fn occurrence_request(row: &JobRow, slot: &Slot) -> Value {
    json!({
        "job": row.job,
        "slot": slot.index,
        "program": row.program,
        "declaration_digest": row.declaration_digest,
    })
}

/// Whether `rows` already hold the registration `specs` under `digest`:
/// the same jobs with the same programs, schedules and concurrency.
fn registered_as(rows: &[JobRow], digest: &str, specs: &[JobSpec]) -> bool {
    rows.len() == specs.len()
        && specs.iter().all(|spec| {
            rows.iter().any(|row| {
                row.job == spec.job
                    && row.program == spec.program
                    && row.max_concurrency == spec.max_concurrency
                    && row.declaration_digest == digest
                    && serde_json::to_value(&spec.schedule).is_ok_and(|schedule| schedule == row.schedule)
            })
        })
}

/// Identifier check for an address used as a grant key and a path
/// component. A bech32 address passes; anything with a separator does not.
fn xite_id(xite: &str) -> Result<(), String> {
    evx_api::validate_identifier(xite).map_err(|denied| format!("invalid xite: {denied}"))
}

fn job_id(job: &str) -> Result<(), String> {
    evx_api::validate_identifier(job).map_err(|denied| format!("invalid job: {denied}"))
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
pub(crate) fn bounded_message(message: &str) -> String {
    let mut out = String::new();
    for c in message.chars() {
        if out.len() + c.len_utf8() > MAX_MESSAGE {
            break;
        }
        out.push(c);
    }
    out
}

/// The wire spelling of a run status (`snake_case`), as the run record
/// stores it and the occurrence summary commits it.
pub(crate) fn status_name(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok",
        Status::Error => "error",
        Status::Denied => "denied",
        Status::Timeout => "timeout",
        Status::ResourceLimit => "resource_limit",
        Status::EffectUnknown => "effect_unknown",
        Status::Quarantined => "quarantined",
    }
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

pub(crate) fn run_json(run: &RunRecord) -> Value {
    serde_json::to_value(run).unwrap_or(Value::Null)
}

fn host_json(execution: Result<(), String>) -> Value {
    json!({
        "execution": execution.is_ok(),
        "reason": execution.err(),
        "ceiling": limits_json(Some(&HOST_CEILING)),
        "background": {
            "runs_per_day": BACKGROUND_RUNS_PER_DAY,
            "workers": BACKGROUND_WORKERS,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_pause_reasons_round_trip_and_unknown_text_is_not_a_reason() {
        for reason in [
            PauseReason::User,
            PauseReason::ReconcileRequired,
            PauseReason::DeclarationOutgrewGrant,
            PauseReason::ProgramUnsupported,
            PauseReason::DeclarationUnavailable,
            PauseReason::ContentIncomplete,
        ] {
            assert_eq!(PauseReason::parse(reason.name()), Some(reason));
        }
        assert_eq!(PauseReason::parse("USER"), None);
        assert_eq!(PauseReason::parse(""), None);
        assert!(PauseReason::DeclarationOutgrewGrant.from_registration());
        assert!(PauseReason::ProgramUnsupported.from_registration());
        assert!(!PauseReason::User.from_registration());
        assert!(!PauseReason::ReconcileRequired.from_registration());
        assert!(PauseReason::DeclarationUnavailable.from_registration());
        assert!(PauseReason::ContentIncomplete.from_registration());
        assert!(PauseReason::DeclarationUnavailable.from_inspection());
        assert!(PauseReason::ContentIncomplete.from_inspection());
        assert!(!PauseReason::DeclarationOutgrewGrant.from_inspection());
        assert!(!PauseReason::User.from_inspection());
    }

    #[test]
    fn status_names_are_the_wire_spelling_of_every_status() {
        for status in [
            Status::Ok,
            Status::Error,
            Status::Denied,
            Status::Timeout,
            Status::ResourceLimit,
            Status::EffectUnknown,
            Status::Quarantined,
        ] {
            assert_eq!(json!(status_name(status)), serde_json::to_value(status).unwrap());
        }
    }

    /// A service over a throwaway root with one granted xite and one
    /// registered hourly job, for exercising the occurrence bookkeeping
    /// without a worker.
    async fn service_with_job() -> (Arc<EvxService>, Arc<AppState>, JobRow) {
        let app = AppState::new("test");
        let service = Arc::new(EvxService::for_node(&app, None).unwrap());
        let xite = "1EvxFinishTest";
        let grant = XiteGrant {
            xite: xite.into(),
            publisher: xite.into(),
            enabled: true,
            capabilities: BTreeSet::new(),
            runtime_profiles: [RUNTIME_PROFILE.to_string()].into_iter().collect(),
            limits: Limits::default(),
            allow_run_once: true,
            allow_background: true,
            created_unix: 1_700_000_000,
            expires_unix: None,
            label: "test".into(),
        };
        service.state.set_xite_grant(&grant).unwrap();
        let spec = JobSpec {
            job: "sync".into(),
            program: "calc".into(),
            schedule: evx_declaration::Schedule::Interval {
                seconds: 3600,
                anchor: evx_declaration::Anchor::UnixEpoch,
                missed: evx_declaration::Missed::Skip,
            },
            max_concurrency: 1,
        };
        service.state.set_jobs(xite, &"a".repeat(64), &[spec], 1_700_000_000).unwrap();
        let row = service.state.jobs(xite).unwrap().remove(0);
        (service, app, row)
    }

    fn claim(service: &EvxService, row: &JobRow, now: u64) -> Occurrence {
        let slot = DurableState::slot_at(&row.schedule, now).unwrap();
        let invocation = service
            .state
            .claim_occurrence(&row.xite, row, &slot, &occurrence_request(row, &slot), now)
            .unwrap();
        assert!(invocation.fresh);
        Occurrence { invocation, row: row.clone(), slot }
    }

    fn executed(status: Status) -> Executed {
        Executed {
            payload: Value::Null,
            status,
            value: (status == Status::Ok).then_some(42),
            error: (status != Status::Ok).then(|| "boom".to_string()),
            elapsed_ms: 12,
        }
    }

    #[tokio::test]
    async fn a_successful_occurrence_moves_the_job_to_the_next_slot_with_a_float_free_summary() {
        let (service, app, row) = service_with_job().await;
        let now = 1_700_000_000;
        let occurrence = claim(&service, &row, now);
        service.finish_job_run(&app, &occurrence, &Ok(executed(Status::Ok)), now + 5).await;
        let after = service.state.jobs(&row.xite).unwrap().remove(0);
        assert_eq!(after.failures, 0);
        assert_eq!(after.next_due_unix, Some(occurrence.slot.end_unix));
        assert_eq!(after.paused_reason, None);
        let stored = service.state.snapshot(&row.xite).unwrap().invocations.remove(0);
        assert_eq!(
            stored.response,
            Some(json!({ "status": "ok", "value": 42, "error": null, "elapsed_ms": 12, "occurrence": occurrence.invocation.occurrence }))
        );
    }

    #[tokio::test]
    async fn a_failed_or_refused_occurrence_counts_and_backs_off_and_an_unknown_effect_pauses() {
        let (service, app, row) = service_with_job().await;
        let now = 1_700_000_000;
        // Refused before any run: finished as denied with the refusal.
        let occurrence = claim(&service, &row, now);
        service.finish_job_run(&app, &occurrence, &Err("unsupported host".into()), now).await;
        let after = service.state.jobs(&row.xite).unwrap().remove(0);
        assert_eq!(after.failures, 1);
        assert_eq!(after.next_due_unix, Some(occurrence.slot.end_unix.max(now + backoff(1))));
        let stored = service.state.snapshot(&row.xite).unwrap().invocations.remove(0);
        assert_eq!(stored.response.as_ref().unwrap()["status"], "denied");
        assert_eq!(stored.response.as_ref().unwrap()["error"], "unsupported host");
        // The next slot fails for real: the backoff grows past the slot end
        // once it is longer than the period.
        let later = occurrence.slot.end_unix;
        let occurrence = claim(&service, &after, later);
        service.finish_job_run(&app, &occurrence, &Ok(executed(Status::Error)), later).await;
        let after = service.state.jobs(&row.xite).unwrap().remove(0);
        assert_eq!(after.failures, 2);
        assert_eq!(after.next_due_unix, Some(occurrence.slot.end_unix.max(later + backoff(2))));
        assert_eq!(after.paused_reason, None, "an error does not pause");
        // An unknown effect pauses the job until a person resumes it.
        let occurrence = claim(&service, &after, occurrence.slot.end_unix);
        service.finish_job_run(&app, &occurrence, &Ok(executed(Status::EffectUnknown)), occurrence.slot.start_unix).await;
        let after = service.state.jobs(&row.xite).unwrap().remove(0);
        assert_eq!(after.failures, 3);
        assert_eq!(after.paused_reason.as_deref(), Some(PauseReason::ReconcileRequired.name()));
        // Resuming clears it and a success resets the count.
        service.job_resume(&app, &row.xite, &row.job).await.unwrap();
        let occurrence = claim(&service, &after, occurrence.slot.end_unix);
        service.finish_job_run(&app, &occurrence, &Ok(executed(Status::Ok)), occurrence.slot.start_unix).await;
        let after = service.state.jobs(&row.xite).unwrap().remove(0);
        assert_eq!((after.failures, after.paused_reason), (0, None));
        assert_eq!(after.next_due_unix, Some(occurrence.slot.end_unix));
    }

    #[test]
    fn trigger_and_authority_names_are_identifiers() {
        for name in [
            Trigger::Once.name(),
            Trigger::Job.name(),
            Trigger::ManualJob.name(),
            Authority::Grant.name(),
            Authority::Once.name(),
            Authority::Scheduled.name(),
        ] {
            evx_api::validate_identifier(name).unwrap();
        }
    }
}
