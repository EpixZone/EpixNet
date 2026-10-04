//! Explicit operator recovery of private workspace effects. This never runs a
//! guest, changes its grant, or infers authority from existing file contents.

use super::{clamp, xite_id, EvxService, RunningRegistration, PLUGIN_NAME};
use std::collections::BTreeSet;
use std::sync::Arc;
use epix_ui::AppState;
use evx_api::{Grant, Limits};
use serde_json::{json, Value};

impl EvxService {
    /// Recover interrupted manual writes without executing a program or
    /// resuming jobs. The command layer requires host management authority
    /// through the wrapper or operator. Scheduled jobs still need a resume.
    pub async fn recover_workspace(
        self: &Arc<Self>,
        app: &AppState,
        xite: &str,
    ) -> Result<Value, String> {
        xite_id(xite)?;
        let count = self.recover_workspace_inner(app, xite, None).await?;
        app.log(
            "INFO",
            format!("EVX: reconciled {count} workspace paths for {xite}"),
        )
        .await;
        Ok(json!({ "xite": xite, "reconciled_paths": count }))
    }

    pub(super) async fn recover_workspace_inner(
        self: &Arc<Self>,
        app: &AppState,
        xite: &str,
        resume_job: Option<&str>,
    ) -> Result<usize, String> {
        let plugin_changes = app.subscribe_plugin_changes();
        let revision = self
            .state
            .job_management_revision(xite)
            .map_err(|error| format!("EVX state: {error}"))?;
        let lock = {
            let mut locks = self.run_locks.lock().await;
            locks.entry(xite.to_string()).or_default().clone()
        };
        let lease = lock.lock_owned().await;
        if !app.plugin_enabled(PLUGIN_NAME).await {
            return Err("EVX plugin is disabled".into());
        }
        let service = Arc::clone(self);
        let xite = xite.to_string();
        let resume_job = resume_job.map(str::to_string);
        tokio::task::spawn_blocking(move || {
            // Keep ownership on the blocking thread even if the requesting
            // socket or async task disappears while a helper is active.
            let _lease = lease;
            service.recover_workspace_blocking(
                &xite,
                resume_job.as_deref(),
                revision,
                &plugin_changes,
            )
        })
        .await
        .map_err(|error| format!("workspace recovery task failed: {error}"))?
    }

    fn recover_workspace_blocking(
        &self,
        xite: &str,
        resume_job: Option<&str>,
        revision: u64,
        plugin_changes: &tokio::sync::watch::Receiver<()>,
    ) -> Result<usize, String> {
        let cancelled = || self.scheduler.stopped() || plugin_changes.has_changed().unwrap_or(true);
        if cancelled() {
            return Err("workspace recovery cancelled by host policy".into());
        }
        evx_supervisor::process::child_admission_status().map_err(|error| error.to_string())?;
        if let Some(job) = resume_job {
            if !self
                .state
                .jobs(xite)
                .map_err(|error| format!("EVX state: {error}"))?
                .iter()
                .any(|row| row.job == job)
            {
                return Err(format!("unknown job {job}"));
            }
        }
        let policy = self
            .policy_lock
            .lock()
            .map_err(|_| "EVX policy unavailable")?;
        let revocations = self.revocations_of(xite);
        let stored = self.state.xite_grant(xite).map_err(|error| format!("EVX state: {error}"))?;
        let (generation, limits) = match &stored {
            Some((grant, generations)) => (generations.generation, clamp(&grant.limits)?),
            None => (1, clamp(&Limits::default())?),
        };
        // Resolve the selected backend even when no direct workspace exists.
        // Apple lookup never allocates a slot and unresolved lifecycle records
        // refuse before a pause can be cleared.
        let prepared = self.prepare_backend(xite, Grant {
            xite: xite.into(), enabled: false, generation, capabilities: BTreeSet::new(),
            publisher: Some(xite.into()), publisher_public_key: None, runtime_profiles: BTreeSet::new(),
        }, limits, false)?;
        let (broker, config) = prepared.unzip();
        if let Some(broker) = &broker {
            let mut running = self.running.lock().map_err(|_| "EVX running state unavailable")?;
            if running.contains_key(xite) { return Err("workspace recovery is busy".into()); }
            running.insert(xite.into(), broker.clone());
        }
        let generation = broker.as_ref().map(|broker| broker.grant().generation);
        drop(policy);
        let _registered = RunningRegistration {
            service: self,
            xite,
            broker: broker.as_ref(),
        };
        #[cfg(test)]
        if let Some(broker) = &broker {
            if let Some(hook) = self.before_recovery.lock().unwrap().take() {
                hook(broker);
            }
        }
        if cancelled()
            || self.revocations_of(xite) != revocations
            || broker
                .as_ref()
                .is_some_and(|broker| Some(broker.grant().generation) != generation)
        {
            return Err("workspace recovery cancelled by host policy".into());
        }
        let count = if let Some(broker) = &broker {
            evx_supervisor::reconcile_workspace_cancellable(
                config.as_ref().expect("prepared broker has config"),
                broker,
                &cancelled,
            )
            .map_err(|error| format!("workspace recovery: {error}"))?
        } else {
            0
        };
        let _policy = self
            .policy_lock
            .lock()
            .map_err(|_| "EVX policy unavailable")?;
        if cancelled()
            || self.revocations_of(xite) != revocations
            || broker
                .as_ref()
                .is_some_and(|broker| Some(broker.grant().generation) != generation)
        {
            return Err("workspace recovery cancelled by host policy".into());
        }
        evx_supervisor::process::child_admission_status().map_err(|error| error.to_string())?;
        if let Some(job) = resume_job {
            self.state
                .resume_job_at_revision(xite, job, revision)
                .map_err(|error| format!("EVX state: {error}"))?;
        }
        Ok(count)
    }
}
