//! The `evx*` WebSocket commands: thin shells over [`EvxService`] that
//! decode parameters strictly and re-check the session before acting.
//!
//! Two kinds of command exist and the difference is enforced twice. The
//! inert ones (`evxInspect`, `evxStatus`, `evxRequest`) are answerable to
//! the bound xite's page and to the wrapper, and they act on the bound xite
//! only. The effectful ones (`evxGrant`, `evxRevoke`, `evxSetLimits`,
//! `evxRunOnce`) are listed in `epix_ui::command::EVX_WRAPPER_COMMANDS`, so
//! the dispatcher refuses them for every request that is not the wrapper's
//! own elevated-id command or the operator socket; each handler here
//! re-checks that the session is a wrapper or operator session, so a direct
//! call on a page session (a future dispatcher regression, a test that
//! bypasses dispatch) is refused too. Neither check replaces the other: the
//! dispatcher sees the request id, the handler sees the session.
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
        service(&s.state)?.inspect_json(&s.state, &xite).await
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
        service(&s.state)?.status(&xite).await
    }
}

/// `evxRequest {xite?}`: the page asks for consent; the wrapper shows the
/// dialog from the returned payload. Grants nothing.
pub struct EvxRequest;
#[async_trait]
impl WsCommand for EvxRequest {
    fn name(&self) -> &'static str {
        "evxRequest"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
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
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_effectful_commands_refuse_a_page_session_even_when_called_directly() {
        let state = AppState::new("test");
        let page = WsSession::new(state.clone(), Some("1A".into()));
        assert!(require_wrapper_or_operator(&page, "evxGrant").is_err());
        let wrapper = WsSession::new_wrapper(state.clone(), Some("1A".into()));
        assert!(require_wrapper_or_operator(&wrapper, "evxGrant").is_ok());
        let operator = WsSession::new_trusted(state, None);
        assert!(require_wrapper_or_operator(&operator, "evxGrant").is_ok());
    }
}
