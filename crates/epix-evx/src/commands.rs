//! The `evx*` WebSocket commands: thin shells over [`EvxService`] that
//! decode parameters strictly and re-check the session before acting.
//!
//! Two kinds of command exist and the difference is enforced twice. The
//! inert ones (`evxInspect`, `evxStatus`, `evxRequest`) are answerable to
//! the bound xite's page and to the wrapper, and they act on the bound xite
//! only. The effectful ones (`evxGrant`, `evxRevoke`, `evxSetLimits`,
//! `evxRunOnce`, `evxJobPause`, `evxJobResume`, `evxRunJob`) are listed in
//! `epix_ui::command::EVX_WRAPPER_COMMANDS`, so
//! the dispatcher refuses them for every request that is not the wrapper's
//! own elevated-id command or the operator socket; each handler here
//! re-checks that the session is a wrapper or operator session, so a direct
//! call on a page session (a future dispatcher regression, a test that
//! bypasses dispatch) is refused too. Neither check replaces the other: the
//! dispatcher sees the request id, the handler sees the session.
//!
//! On a public gateway (`AppState::ui_restrict`) the inert commands answer
//! a visitor with no consent detail (the grant, each job and the scheduler
//! are reduced to their `enabled` bits and the run history is left out, as
//! the `/list` panel does there), and `evxRequest` is refused: no dialog is
//! shown to a visitor and none may enable execution. The operator socket
//! sees everything.
//!
//! Parameters are JSON objects decoded with `deny_unknown_fields`; `null`
//! stands for the empty object so a page that sends no parameters still
//! works, and an array or a bare string is refused.

use std::sync::Arc;

use async_trait::async_trait;
use epix_ui::{AppState, WsCommand, WsSession};
use evx_api::Limits;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::service::{EvxService, GrantRequest};
use crate::CAPABILITY_KEY;

/// The service, installed by `EvxPlugin::start`; absent on a node whose
/// state could not be opened, which every command reports rather than
/// pretending to have no grant.
fn service(state: &AppState) -> Result<Arc<EvxService>, String> {
    state
        .capability::<EvxService>(CAPABILITY_KEY)
        .ok_or_else(|| "EVX service unavailable on this node".to_string())
}

/// Decode `params` as `T`: an object, or `null` for `{}`.
fn object_params<T: DeserializeOwned>(params: &Value) -> Result<T, String> {
    let value = match params {
        Value::Null => json!({}),
        Value::Object(_) => params.clone(),
        _ => return Err("params must be a JSON object".into()),
    };
    serde_json::from_value(value).map_err(|error| format!("invalid params: {error}"))
}

/// The xite a command acts on. A page or wrapper session acts on its bound
/// xite only: an absent `xite` means it, a different one is refused. The
/// operator socket may name any xite, and must name one when unbound.
fn target_xite(session: &WsSession, requested: Option<&str>) -> Result<String, String> {
    match (session.xite.as_deref(), requested) {
        (Some(bound), None) => Ok(bound.to_string()),
        (Some(bound), Some(requested)) if requested == bound => Ok(bound.to_string()),
        (_, Some(requested)) if session.trusted => Ok(requested.to_string()),
        (Some(_), Some(_)) => Err("this connection is bound to another xite".into()),
        (None, _) => Err("no xite bound to this connection".into()),
    }
}

/// The session shape the effectful commands require, re-checked here
/// although the dispatcher already refused everything else: a wrapper
/// socket (one that presented the xite's `wrapper_key`) or the operator's.
fn require_wrapper_or_operator(session: &WsSession, cmd: &str) -> Result<(), String> {
    if session.wrapper || session.trusted {
        Ok(())
    } else {
        Err(format!("{cmd} requires the wrapper's EVX consent prompt"))
    }
}

/// Whether the session is a visitor of a public gateway (`ui_restrict`):
/// anyone may bind a socket to any xite the gateway serves, so the inert
/// commands tell such a session no more than the `/list` panel does there.
/// The operator socket is never a visitor.
async fn gateway_visitor(session: &WsSession) -> bool {
    !session.trusted && session.state.ui_restrict().await
}

/// The consent detail a gateway visitor does not get: the operator's grant
/// (label, limits, when it was given, its generations), the run history,
/// and the schedule's state (what is due when, why a job waits, how busy
/// the node is) are the operator's own. Only the enabled bits survive: the
/// grant as a bare `{"enabled": bool}`, which is what the `/list` panel's
/// rule leaves as well, each job as `{"job", "enabled"}` and the scheduler
/// as `{"enabled"}`; the other keys are removed rather than zeroed so that
/// nothing reads as a fact.
pub fn redact_for_gateway(mut payload: Value) -> Value {
    if let Some(object) = payload.as_object_mut() {
        let enabled = object
            .get("grant")
            .and_then(|grant| grant.get("enabled"))
            .and_then(Value::as_bool);
        object.insert(
            "grant".into(),
            enabled.map(|enabled| json!({ "enabled": enabled })).unwrap_or(Value::Null),
        );
        if let Some(jobs) = object.get("jobs").and_then(Value::as_array) {
            let jobs: Vec<Value> = jobs
                .iter()
                .map(|job| json!({ "job": job.get("job").cloned().unwrap_or(Value::Null), "enabled": job.get("enabled").and_then(Value::as_bool) }))
                .collect();
            object.insert("jobs".into(), Value::Array(jobs));
        }
        if let Some(scheduler) = object.get("scheduler") {
            let enabled = scheduler.get("enabled").and_then(Value::as_bool);
            object.insert("scheduler".into(), json!({ "enabled": enabled }));
        }
        // The reasons are rebuilt from the facts that survive: whether a
        // grant exists is the `grant` key itself, and the host and the
        // plugin switch are the node's, not the consent's. Every reason
        // drawn from the grant record (revoked or expired, background or
        // run-once not allowed) is dropped, since the bare enabled bit is
        // all a visitor is told of it.
        if let Some(reasons) = object.get("reasons").and_then(Value::as_array) {
            let kept: Vec<Value> = reasons
                .iter()
                .filter(|reason| reason.as_str().is_some_and(|reason| GATEWAY_REASONS.contains(&reason)))
                .cloned()
                .collect();
            object.insert("reasons".into(), Value::Array(kept));
        }
        for key in ["generations", "runs", "run_count", "asked_unix"] {
            object.remove(key);
        }
    }
    payload
}

/// The status reasons a gateway visitor may see: none of them says
/// anything about the grant beyond whether one exists.
pub const GATEWAY_REASONS: [&str; 3] = ["no_grant", "unsupported_host", "plugin_disabled"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XiteParams {
    #[serde(default)]
    xite: Option<String>,
}

/// `evxInspect {xite?}`: the inert inspect payload for the bound xite.
pub struct EvxInspect;
#[async_trait]
impl WsCommand for EvxInspect {
    fn name(&self) -> &'static str {
        "evxInspect"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let params: XiteParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        let payload = service(&s.state)?.inspect_json(&s.state, &xite).await?;
        Ok(if gateway_visitor(s).await { redact_for_gateway(payload) } else { payload })
    }
}

/// `evxStatus {xite?}`: grant status, generations, recent runs, reasons.
pub struct EvxStatus;
#[async_trait]
impl WsCommand for EvxStatus {
    fn name(&self) -> &'static str {
        "evxStatus"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let params: XiteParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        let payload = service(&s.state)?.status(&s.state, &xite).await?;
        Ok(if gateway_visitor(s).await { redact_for_gateway(payload) } else { payload })
    }
}

/// `evxRequest {xite?}`: the page asks for consent; the wrapper shows the
/// dialog from the returned payload. Grants nothing. On a public gateway no
/// dialog is ever shown and no visitor may enable execution, so the ask is
/// refused outright rather than recorded.
pub struct EvxRequest;
#[async_trait]
impl WsCommand for EvxRequest {
    fn name(&self) -> &'static str {
        "evxRequest"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        if gateway_visitor(s).await {
            return Err(format!("{} is disabled on this gateway", self.name()));
        }
        let params: XiteParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?.request(&s.state, &xite).await
    }
}

/// `evxGrant {xite, declaration_digest, mode, program?, limits?, label?}`.
pub struct EvxGrant;
#[async_trait]
impl WsCommand for EvxGrant {
    fn name(&self) -> &'static str {
        "evxGrant"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let mut request: GrantRequest = object_params(p)?;
        request.xite = target_xite(s, Some(&request.xite))?;
        service(&s.state)?.grant(&s.state, request).await
    }
}

/// `evxRevoke {xite?}`.
pub struct EvxRevoke;
#[async_trait]
impl WsCommand for EvxRevoke {
    fn name(&self) -> &'static str {
        "evxRevoke"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let params: XiteParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?.revoke(&s.state, &xite).await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetLimitsParams {
    #[serde(default)]
    xite: Option<String>,
    limits: Limits,
}

/// `evxSetLimits {xite?, limits}`.
pub struct EvxSetLimits;
#[async_trait]
impl WsCommand for EvxSetLimits {
    fn name(&self) -> &'static str {
        "evxSetLimits"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let params: SetLimitsParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?.set_limits(&s.state, &xite, &params.limits).await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunOnceParams {
    #[serde(default)]
    xite: Option<String>,
    program: String,
    #[serde(default)]
    token: Option<String>,
}

/// `evxRunOnce {xite?, program, token?}`.
pub struct EvxRunOnce;
#[async_trait]
impl WsCommand for EvxRunOnce {
    fn name(&self) -> &'static str {
        "evxRunOnce"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let params: RunOnceParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?
            .run_once(&s.state, &xite, &params.program, params.token.as_deref())
            .await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobParams {
    #[serde(default)]
    xite: Option<String>,
    job: String,
}

/// `evxJobPause {xite?, job}`: pause a registered job until resumed.
pub struct EvxJobPause;
#[async_trait]
impl WsCommand for EvxJobPause {
    fn name(&self) -> &'static str {
        "evxJobPause"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let params: JobParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?.job_pause(&s.state, &xite, &params.job).await
    }
}

/// `evxJobResume {xite?, job}`: lift a job's pause, whoever set it.
pub struct EvxJobResume;
#[async_trait]
impl WsCommand for EvxJobResume {
    fn name(&self) -> &'static str {
        "evxJobResume"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let params: JobParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?.job_resume(&s.state, &xite, &params.job).await
    }
}

/// `evxRunJob {xite?, job}`: run the job's current occurrence now, or
/// return the stored result when that occurrence already ran.
pub struct EvxRunJob;
#[async_trait]
impl WsCommand for EvxRunJob {
    fn name(&self) -> &'static str {
        "evxRunJob"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let params: JobParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?.run_job(&s.state, &xite, &params.job).await
    }
}

/// `evxRecoverWorkspace {xite?}`: explicitly reconcile interrupted manual
/// writes. Requires the wrapper's explicit host management choice or operator
/// authority, never the publisher xite's global permissions.
pub struct EvxRecoverWorkspace;
#[async_trait]
impl WsCommand for EvxRecoverWorkspace {
    fn name(&self) -> &'static str { "evxRecoverWorkspace" }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        require_wrapper_or_operator(s, self.name())?;
        let params: XiteParams = object_params(p)?;
        let xite = target_xite(s, params.xite.as_deref())?;
        service(&s.state)?.recover_workspace(&s.state, &xite).await
    }
}

/// Every command the plugin registers.
pub fn all() -> Vec<Arc<dyn WsCommand>> {
    vec![
        Arc::new(EvxInspect),
        Arc::new(EvxStatus),
        Arc::new(EvxRequest),
        Arc::new(EvxGrant),
        Arc::new(EvxRevoke),
        Arc::new(EvxSetLimits),
        Arc::new(EvxRunOnce),
        Arc::new(EvxJobPause),
        Arc::new(EvxJobResume),
        Arc::new(EvxRunJob),
        Arc::new(EvxRecoverWorkspace),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gateway_visitor_sees_no_status_reason_drawn_from_the_grant_record() {
        let payload = json!({
            "grant": { "enabled": true, "label": "operator laptop", "allow_background": false },
            "reasons": [
                "no_grant",
                "revoked",
                "expired",
                "run_once_not_allowed",
                "background_not_allowed",
                "unsupported_host",
                "plugin_disabled",
                7,
            ],
            "runs": [],
        });
        let redacted = redact_for_gateway(payload);
        assert_eq!(redacted["grant"], json!({ "enabled": true }));
        assert_eq!(redacted["reasons"], json!(["no_grant", "unsupported_host", "plugin_disabled"]));
        assert!(redacted.get("runs").is_none());
        // A payload without reasons (the inspect payload) gets none added.
        assert!(redact_for_gateway(json!({ "grant": null })).get("reasons").is_none());
    }

    #[test]
    fn null_params_are_the_empty_object_and_other_shapes_are_refused() {
        let empty: XiteParams = object_params(&Value::Null).unwrap();
        assert!(empty.xite.is_none());
        let named: XiteParams = object_params(&json!({ "xite": "1A" })).unwrap();
        assert_eq!(named.xite.as_deref(), Some("1A"));
        assert!(object_params::<XiteParams>(&json!(["1A"])).is_err());
        assert!(object_params::<XiteParams>(&json!("1A")).is_err());
        assert!(object_params::<XiteParams>(&json!({ "xite": "1A", "extra": 1 })).is_err());
    }

    #[test]
    fn a_bound_session_acts_on_its_own_xite_and_the_operator_on_any() {
        let state = AppState::new("test");
        let page = WsSession::new(state.clone(), Some("1A".into()));
        assert_eq!(target_xite(&page, None).unwrap(), "1A");
        assert_eq!(target_xite(&page, Some("1A")).unwrap(), "1A");
        assert!(target_xite(&page, Some("1B")).is_err());
        let unbound = WsSession::new(state.clone(), None);
        assert!(target_xite(&unbound, None).is_err());
        assert!(target_xite(&unbound, Some("1A")).is_err());
        let wrapper = WsSession::new_wrapper(state.clone(), Some("1A".into()));
        assert!(target_xite(&wrapper, Some("1B")).is_err());
        let operator = WsSession::new_trusted(state.clone(), Some("1A".into()));
        assert_eq!(target_xite(&operator, Some("1B")).unwrap(), "1B");
        assert_eq!(target_xite(&operator, None).unwrap(), "1A");
        let operator_unbound = WsSession::new_trusted(state, None);
        assert_eq!(target_xite(&operator_unbound, Some("1B")).unwrap(), "1B");
        assert!(target_xite(&operator_unbound, None).is_err());
    }

    #[test]
    fn a_gateway_visitor_learns_only_whether_execution_is_enabled() {
        let status = json!({
            "xite": "1A",
            "grant": { "enabled": true, "label": "laptop", "limits": { "fuel": 1 }, "created_unix": 7, "generation": 3 },
            "generations": { "generation": 3 },
            "runs": [{ "status": "ok" }],
            "run_count": 1,
            "running": false,
            "reasons": [],
            "asked_unix": 9,
            "host": { "execution": true },
            "jobs": [{ "job": "sync", "enabled": true, "next_due_unix": 1800, "waiting_reason": "daily_budget", "failures": 2 }],
            "scheduler": { "enabled": true, "busy_workers": 1, "next_wake_unix": 1800, "host": "macos" },
        });
        let redacted = redact_for_gateway(status);
        assert_eq!(redacted["grant"], json!({ "enabled": true }));
        assert_eq!(redacted["xite"], "1A");
        assert_eq!(redacted["running"], false);
        assert_eq!(redacted["host"]["execution"], true);
        assert_eq!(redacted["jobs"], json!([{ "job": "sync", "enabled": true }]));
        assert_eq!(redacted["scheduler"], json!({ "enabled": true }));
        for gone in ["generations", "runs", "run_count", "asked_unix"] {
            assert!(redacted.get(gone).is_none(), "{gone} survived");
        }
        let text = redacted.to_string();
        for secret in ["laptop", "created_unix", "limits", "generation", "next_due", "waiting_reason", "failures", "busy_workers", "next_wake", "macos"] {
            assert!(!text.contains(secret), "{secret} survived: {text}");
        }
        // No grant stays no grant; a non-object payload is left alone.
        assert!(redact_for_gateway(json!({ "grant": null }))["grant"].is_null());
        assert_eq!(redact_for_gateway(json!("x")), json!("x"));
    }

    #[test]
    fn the_effectful_commands_refuse_a_page_session_even_when_called_directly() {
        let state = AppState::new("test");
        let page = WsSession::new(state.clone(), Some("1A".into()));
        for cmd in epix_ui::command::EVX_WRAPPER_COMMANDS {
            assert!(require_wrapper_or_operator(&page, cmd).is_err(), "{cmd}");
        }
        assert!(require_wrapper_or_operator(&page, "evxGrant").is_err());
        let wrapper = WsSession::new_wrapper(state.clone(), Some("1A".into()));
        assert!(require_wrapper_or_operator(&wrapper, "evxGrant").is_ok());
        let operator = WsSession::new_trusted(state, None);
        assert!(require_wrapper_or_operator(&operator, "evxGrant").is_ok());
    }
}
