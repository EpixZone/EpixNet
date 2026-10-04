//! `epix-evx`: the node's EVX service, management API and durable
//! scheduler (`docs/evx-milestone-2.md` section 4, `docs/evx-milestone-3.md`
//! section 2).
//!
//! The [`EvxPlugin`] is an `epix_plugin::Plugin` named `Evx`. At start it
//! opens the durable EVX state at `<data_root>/private/evx/state.sqlite`,
//! creates `<data_root>/private/evx/workspaces/`, installs the grant reader
//! the `/list` inspection panel uses, starts the scheduler task, and shares
//! its [`EvxService`] with its eleven WebSocket commands through the node's
//! capability map:
//!
//! | Command | Who | Effect |
//! | --- | --- | --- |
//! | `evxInspect` | the bound xite's page, the wrapper | registers the jobs of a granted xite |
//! | `evxStatus` | the bound xite's page, the wrapper | none |
//! | `evxRequest` | the bound xite's page | records the ask |
//! | `evxGrant` | wrapper / operator only | stores consent or mints a token |
//! | `evxRevoke` | wrapper / operator only | disables the grant |
//! | `evxSetLimits` | wrapper / operator only | adjusts limits |
//! | `evxRunOnce` | wrapper / operator only | runs one program now |
//! | `evxJobPause` | wrapper / operator only | pauses a scheduled job |
//! | `evxJobResume` | wrapper / operator only | resumes a paused job |
//! | `evxRunJob` | wrapper / operator only | runs a job's current occurrence now |
//! | `evxRecoverWorkspace` | wrapper / operator only | reconciles interrupted manual writes without executing a program |
//!
//! The last eight are gated in `epix_ui::command::CommandRegistry::dispatch`
//! through `EVX_WRAPPER_COMMANDS`, exactly as `permissionAdd` is, so no page
//! id can reach them; the handlers re-check the session shape as well.
//! `ADMIN` plays no part: an ADMIN xite cannot grant EVX, and an EVX grant
//! confers no ADMIN.
//!
//! The scheduler (`scheduler`) is one tokio task over the same service: it
//! sleeps until the earliest persisted `next_due`, wakes for grants,
//! revocations, job commands and content changes, and runs each reserved
//! occurrence through the same path `evxRunOnce` uses. Its rules, each in
//! one place: a schedule is a row, not a thread (`evx_state::JobRow`); an
//! occurrence is reserved before a worker starts and completed with its
//! result (`claim_occurrence`, `finish_occurrence`); the same occurrence
//! never runs twice (the claim is not fresh the second time); a missed
//! slot is never backfilled (only the current slot is ever claimed);
//! authority, budget and the plugin switch are rechecked at every admission
//! (`scheduler::tick`); a budget wait, a pause and an unsupported host are
//! visible in `evxStatus` (`waiting_reason`), never silent drops.
//!
//! The plan's rules this crate upholds, each in one place: publisher
//! requests never self-grant (`EvxService::grant` is the only writer and is
//! wrapper-only); unsupported requirements disable the affected work
//! (`evx_declaration` leaves them out of the usable set and the grant covers
//! only usable programs); authenticated updates within an existing grant
//! activate without a new prompt (the loader's checkpoint and the grant's
//! capability ceiling, re-derived on every run); broader authority waits for
//! a new grant (the activation refuses capabilities beyond the stored set);
//! a denied activation never advances the version floor (the checkpoint is
//! persisted only after `admit`); grants, workspaces and journals live
//! outside every served root (`private/evx`, never `data/<address>`); a
//! page cannot mint, widen or forge a grant (the dispatcher gate plus the
//! digest expected-version check).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::PathBuf;
use std::sync::Arc;

use epix_plugin::Plugin;
use epix_ui::{AppState, WsCommand};

mod checkpoint;
mod backend_binding;
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub mod apple_backend;
#[cfg(all(target_os = "macos", feature = "apple-xpc-development"))]
pub mod apple_development;
pub mod commands;
pub mod limits;
pub mod scheduler;
pub mod service;
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod service_execution_tests;

pub use limits::{clamp, BACKGROUND_RUNS_PER_DAY, BACKGROUND_WORKERS, HOST_CEILING};
pub use scheduler::Scheduler;
pub use service::{
    default_worker_binary, EvxService, GrantMode, GrantRequest, Inspection, Integrity,
    PauseReason, Shown, Trigger, WaitReason, ABANDONED_REVOKED, DEFAULT_LABEL, RUNTIME_PROFILE,
    SHOWN_CHANGED, UNSUPPORTED_HOST, WORKER_BINARY,
};

/// The plugin's stable name, as the plugin manager and the command registry
/// know it.
pub const PLUGIN_NAME: &str = "Evx";

/// Key of the [`EvxService`] in `AppState`'s capability map.
pub const CAPABILITY_KEY: &str = "evx.service";

/// The Evx plugin. [`Default`] resolves the worker binary at start from
/// `EVX_WORKER` or beside the node executable; [`EvxPlugin::with_worker`]
/// pins one, for tests that build it themselves.
#[derive(Default)]
pub struct EvxPlugin {
    worker: Option<PathBuf>,
    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    apple: Option<Arc<apple_backend::AppleBackend>>,
}

impl EvxPlugin {
    /// A plugin that executes with the worker binary at `worker`.
    pub fn with_worker(worker: PathBuf) -> Self {
        EvxPlugin {
            worker: Some(worker),
            #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
            apple: None,
        }
    }

    /// Select only the authenticated current Developer ID package. A missing
    /// or invalid policy is an error; the caller must never fall back to direct.
    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub fn from_signed_apple_package() -> Result<Self, String> {
        let package = evx_supervisor::apple_package::ApplePackage::current().map_err(|e|e.to_string())?;
        Ok(Self { worker: None, apple: Some(Arc::new(apple_backend::AppleBackend::from_package(package)?)) })
    }
    /// Exercise signed-package bootstrap with a distinct ad-hoc fixture profile.
    #[cfg(all(target_os = "macos", feature = "apple-xpc-development"))]
    pub fn from_signed_apple_fixture() -> Result<Self, String> {
        let package = evx_supervisor::apple_package::ApplePackage::current_for_fixture().map_err(|e|e.to_string())?;
        Ok(Self { worker: None, apple: Some(Arc::new(apple_backend::AppleBackend::from_package(package)?)) })
    }

    /// Select a provisioned backend for a signed development host. No page,
    /// environment variable or production App Store assembly selects it.
    #[cfg(all(target_os = "macos", feature = "apple-xpc", any(test, feature = "apple-xpc-development")))]
    pub fn with_apple_development(backend: Arc<apple_backend::AppleBackend>) -> Self {
        Self { worker: None, apple: Some(backend) }
    }
}

impl Plugin for EvxPlugin {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn ws_commands(&self) -> Vec<Arc<dyn WsCommand>> {
        commands::all()
    }

    /// Open the state, install the service and start the scheduler task. A
    /// failure is logged and leaves no service installed, so every command
    /// answers that EVX is unavailable instead of running without consent
    /// records, and nothing is scheduled.
    fn start(&self, state: &Arc<AppState>) {
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        let opened = match &self.apple {
            Some(backend) => EvxService::for_node_apple(state, backend.clone()),
            None => EvxService::for_node(state, self.worker.clone()),
        };
        #[cfg(not(all(target_os = "macos", feature = "apple-xpc")))]
        let opened = EvxService::for_node(state, self.worker.clone());
        let service = match opened {
            Ok(service) => Arc::new(service),
            Err(error) => {
                let state = Arc::clone(state);
                tokio::spawn(async move {
                    state.log("ERROR", format!("EVX service not started: {error}")).await;
                });
                return;
            }
        };
        let reader = Arc::clone(&service);
        state.set_evx_grant_summary_source(Box::new(move |address| reader.grant_summary(address)));
        state.install_capability(CAPABILITY_KEY, service.clone());
        let host = match service.execution_ready() {
            Ok(()) => "execution enabled with configured backend".to_string(),
            Err(reason) => format!("execution disabled: {reason}"),
        };
        let state = Arc::clone(state);
        tokio::spawn(async move {
            state
                .log("INFO", format!("EVX service ready at {} ({host})", service.root().display()))
                .await;
            scheduler::run(service, state).await;
        });
    }
}
