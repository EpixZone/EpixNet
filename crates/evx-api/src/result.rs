//! Invocation outcome reported by the supervisor.

use serde::{Deserialize, Serialize};

use crate::{Limits, Response};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The guest returned a value and every child exited cleanly.
    Ok,
    /// The guest trapped, the protocol was violated, or a child failed.
    Error,
    /// Refused before any worker started.
    Denied,
    /// Supervisor wall deadline reached; the worker was killed.
    Timeout,
    /// Kernel-observed CPU or RSS exceeded the limit; the worker was killed.
    ResourceLimit,
    /// A file commit was authorized but its outcome is unknown. Reconcile
    /// before retrying; never replay blindly.
    EffectUnknown,
    /// A child could not be reaped within budget. All new child admission
    /// stays stopped in this host process; affected workspace leases stay held.
    /// Confirm prior children stopped before restarting the host.
    Quarantined,
}

/// Why a trusted host check stopped this invocation. Guest result frames do
/// not contain this field; neither guest text nor later policy changes set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCancellation {
    AuthorityChanged,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observations {
    pub peak_aggregate_rss_bytes: u64,
    pub cpu_seconds: f64,
    pub poll_interval_seconds: f64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChildReport {
    pub role: String,
    pub pid: u32,
    pub exit_code: Option<i32>,
    pub diagnostics: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunResult {
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub worker_started: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_exit_code: Option<i32>,
    pub supervisor_elapsed_ms: f64,
    pub broker_calls: u32,
    pub responses: Vec<Response>,
    pub events: Vec<String>,
    pub diagnostics: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_limits: Option<Limits>,
    pub effect_outcome_unknown: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_cancellation: Option<HostCancellation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_observations: Option<Observations>,
    pub children: Vec<ChildReport>,
    #[serde(default)]
    pub fuel_used: u64,
    #[serde(default)]
    pub memory_bytes: u64,
}

impl RunResult {
    /// Preserve trusted cleanup and cancellation causes across refusals.
    pub fn from_denial(error: crate::Denied) -> RunResult {
        let quarantined = matches!(error, crate::Denied::Quarantined(_));
        let cancelled = matches!(error, crate::Denied::Cancelled(_));
        let mut result = Self::denied(error.to_string());
        if quarantined {
            result.status = Status::Quarantined;
        }
        if cancelled {
            result.host_cancellation = Some(HostCancellation::AuthorityChanged);
        }
        result
    }

    pub fn denied(error: impl Into<String>) -> RunResult {
        RunResult {
            status: Status::Denied,
            value: None,
            error: Some(error.into()),
            worker_started: false,
            worker_pid: None,
            worker_exit_code: None,
            supervisor_elapsed_ms: 0.0,
            broker_calls: 0,
            responses: Vec::new(),
            events: Vec::new(),
            diagnostics: String::new(),
            effective_limits: None,
            effect_outcome_unknown: false,
            host_cancellation: None,
            trusted_observations: None,
            children: Vec::new(),
            fuel_used: 0,
            memory_bytes: 0,
        }
    }
}

/// Diagnostics are text, never terminal controls or markup actions.
pub fn safe_text(value: &str, limit: usize) -> String {
    let mut out = String::new();
    for c in value.chars().take(limit) {
        if c == '\n' || c == '\t' {
            out.push(c);
        } else if c.is_control() || crate::is_format_control(c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
