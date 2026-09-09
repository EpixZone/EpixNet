//! Per-identity channel setup.
//!
//! Every linked identity gets its own channel key material (derived from the
//! node seed and the identity's linked address) and its own published key
//! bundle in the hub's `data/users/<name>.epix/`. This module owns the job that
//! gets each identity there and keeps it there:
//!
//! - a worker that reconciles the private index against the node's linked
//!   identities (rows created for new ones, dropped for removed ones), publishes
//!   the bundle of every enabled identity that has none committed in the hub,
//!   retries with backoff while the hub is not synced or the chain is not
//!   reachable, and imports each identity's legacy mail once;
//! - the [`IdentityStatusProvider`] the Config page's Identities section shows
//!   ("channels: published / pending / failed / off") with its retry and on/off
//!   actions;
//! - the `channelIdentitySetup`, `channelIdentitySetEnabled` and
//!   `channelIdentityStatus` commands.
//!
//! Publishing is node-side: the bundle is written into the hub, the identity's
//! `content.json` is signed as that identity (not as the hub xite's effective
//! identity), and the hub is published. The multi-device slot rule is the one
//! the Mail client used to apply: the primary `data.json` when it is free or
//! already this device's, else the per-device `data-<auth>.json`.
//!
//! Linking an identity therefore implies a published channel bundle unless the
//! identity's channels are turned off first: "has a channel account" is public
//! for every linked identity by default (a deliberate change from the earlier
//! explicit-publish onboarding).

use crate::channel::{
    build_identity_bundle, deliver_channel_event, device_bundle_file, ensure_identity_row,
    import_legacy_mail, norm_xid, now_ms, own_bundle_committed, ChannelState, IdentityCtx,
};
use async_trait::async_trait;
use epix_channel::{IdentityRow, IdentitySetup};
use epix_envelope::IdentitySecret;
use epix_ui::state::{AppState, IdentityEvent, IdentityStatusProvider, UserContentSigner};
use epix_ui::{WsCommand, WsSession};
use serde_json::{json, Value};
use std::sync::Arc;

/// Setup states, as persisted in `identity.setup_state`.
pub const STATE_KEYS: &str = "keys";
pub const STATE_PENDING: &str = "pending";
pub const STATE_PUBLISHED: &str = "published";
pub const STATE_FAILED: &str = "failed";
pub const STATE_OFF: &str = "off";

/// The worker wakes at least this often; every trigger (identity events, the
/// hub landing, an explicit retry) wakes it sooner.
const TICK: std::time::Duration = std::time::Duration::from_secs(30);
/// Publish retry backoff cap.
const MAX_BACKOFF_SECS: u64 = 600;

/// How a publish attempt failed.
enum SetupError {
    /// Retry later: the hub is not synced, no peer took the update, the chain
    /// could not be reached.
    Transient(String),
    /// Retrying will not help until something changes (a key mismatch, a
    /// revoked name); the user retries explicitly.
    Definite(String),
}

fn classify(error: String) -> SetupError {
    const DEFINITE: &[&str] = &[
        "does not match",
        "failed authenticated verification",
        "revoked",
        "Invalid xID",
        "xID required",
        "unknown identity",
    ];
    if DEFINITE.iter().any(|needle| error.contains(needle)) {
        SetupError::Definite(error)
    } else {
        SetupError::Transient(error)
    }
}

fn backoff_secs(attempts: i64) -> u64 {
    (1u64 << attempts.clamp(0, 10)).min(MAX_BACKOFF_SECS)
}

/// The state a row is effectively in: `off` when channels are disabled for it,
/// else its persisted setup state.
pub(crate) fn effective_state(row: &IdentityRow) -> &str {
    if row.enabled { row.setup.state.as_str() } else { STATE_OFF }
}

/// The setup object `channelSessionInfo` and `channelIdentityStatus` report.
pub(crate) fn setup_json(row: &IdentityRow) -> Value {
    json!({
        "state": effective_state(row),
        "error": row.setup.error,
        "attempts": row.setup.attempts,
        "next_retry_ms": row.setup.next_ms,
        "published_path": row.setup.published_path,
        "published_ms": row.setup.published_ms,
        "published_peers": row.setup.published_peers,
    })
}

/// The Config page column for one identity: summary, detail, and the actions
/// (WS commands run as the node) that make sense in its state.
pub(crate) fn status_value(row: &IdentityRow) -> Value {
    let state = effective_state(row);
    let detail = match state {
        STATE_PUBLISHED => format!(
            "{}, {} peer{}",
            row.setup.published_path.as_deref().unwrap_or("published"),
            row.setup.published_peers,
            if row.setup.published_peers == 1 { "" } else { "s" }
        ),
        STATE_PENDING => row
            .setup
            .error
            .clone()
            .unwrap_or_else(|| "waiting for the hub xite to sync".to_string()),
        STATE_FAILED => row.setup.error.clone().unwrap_or_else(|| "setup failed".to_string()),
        STATE_OFF => "channels are off for this identity".to_string(),
        _ => "keys derived; publish pending".to_string(),
    };
    let mut actions = Vec::new();
    if matches!(state, STATE_FAILED | STATE_PENDING | STATE_KEYS) {
        actions.push(json!({
            "cmd": "channelIdentitySetup",
            "params": [{ "auth_address": row.auth_address }],
            "label": "Retry setup",
        }));
    }
    actions.push(json!({
        "cmd": "channelIdentitySetEnabled",
        "params": [row.auth_address, !row.enabled],
        "label": if row.enabled { "Turn channels off" } else { "Turn channels on" },
    }));
    json!({
        "provider": "channels",
        "state": state,
        "summary": format!("channels: {state}"),
        "detail": detail,
        "actions": actions,
    })
}

/// Ask the worker to (re)publish one identity now: a failed or pending row goes
/// back to `keys`, a published one is re-checked against the hub.
pub(crate) fn request_setup(ms: &ChannelState, identity_id: i64) -> Result<(), String> {
    let row = ms
        .db
        .identity_by_id(identity_id)
        .map_err(|e| e.to_string())?
        .ok_or("unknown channel identity")?;
    if row.setup.state != STATE_PUBLISHED {
        let setup = IdentitySetup {
            state: STATE_KEYS.to_string(),
            error: None,
            attempts: 0,
            next_ms: 0,
            ..row.setup
        };
        ms.db.set_identity_setup(identity_id, &setup).map_err(|e| e.to_string())?;
    }
    ms.setup_wake.notify_one();
    Ok(())
}

/// The Config page's per-identity "Channels" column.
pub struct ChannelIdentityStatusProvider {
    pub ms: Arc<ChannelState>,
}

#[async_trait]
impl IdentityStatusProvider for ChannelIdentityStatusProvider {
    fn name(&self) -> &'static str {
        "Channels"
    }
    async fn status(&self, auth_address: &str) -> Option<Value> {
        let row = self.ms.db.identity_by_auth(auth_address).ok()??;
        Some(status_value(&row))
    }
}

/// The setup worker: reconcile now, then on every trigger.
pub(crate) async fn run_setup_worker(state: Arc<AppState>, ms: Arc<ChannelState>) {
    let mut events = state.subscribe_identity_events();
    let mut legacy_imported = std::collections::HashSet::new();
    loop {
        reconcile_identities(&state, &ms, &mut legacy_imported).await;
        tokio::select! {
            _ = ms.setup_wake.notified() => {}
            _ = ms.hub_ready_notify.notified() => {}
            _ = tokio::time::sleep(TICK) => {}
            event = events.recv() => {
                if let Ok(IdentityEvent::Removed(auth)) = event {
                    forget_identity(&ms, &auth);
                }
            }
        }
    }
}

fn forget_identity(ms: &ChannelState, auth: &str) {
    if let Ok(Some(row)) = ms.db.identity_by_auth(auth) {
        let _ = ms.db.delete_identity(row.identity_id);
    }
}

/// One reconcile pass over the node's linked identities.
pub(crate) async fn reconcile_identities(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    legacy_imported: &mut std::collections::HashSet<i64>,
) {
    let linked = state.identities().await;

    // Rows for identities this node no longer holds are dropped (the removal
    // event may have been missed while the worker was busy).
    if let Ok(rows) = ms.db.identities() {
        for row in rows {
            if !linked.iter().any(|i| i.auth_address == row.auth_address) {
                let _ = ms.db.delete_identity(row.identity_id);
            }
        }
    }

    for identity in linked {
        let Ok(identity_id) = ensure_identity_row(&ms.db, &identity) else { continue };
        let Ok(Some(row)) = ms.db.identity_by_id(identity_id) else { continue };
        let now = now_ms();

        if !row.enabled {
            if row.setup.state != STATE_OFF {
                let _ = ms.db.set_identity_setup(
                    identity_id,
                    &IdentitySetup { state: STATE_OFF.to_string(), ..row.setup.clone() },
                );
            }
            continue;
        }
        match row.setup.state.as_str() {
            STATE_FAILED => continue,
            STATE_PENDING if row.setup.next_ms > now => continue,
            STATE_PUBLISHED => {
                // Re-publish only when the hub no longer carries our committed
                // bundle (a resync from a peer that never got it, a pruned
                // directory).
                let committed = own_bundle_committed(
                    state,
                    &ms.xite,
                    ms.engine.as_ref(),
                    &identity.auth_address,
                    &norm_xid(&identity.xid()),
                )
                .await;
                if committed {
                    import_legacy_once(state, ms, &identity, identity_id, legacy_imported).await;
                    continue;
                }
            }
            _ => {}
        }

        if !ms.hub_ready.load(std::sync::atomic::Ordering::Acquire) {
            let _ = ms.db.set_identity_setup(
                identity_id,
                &IdentitySetup {
                    state: STATE_PENDING.to_string(),
                    error: Some("waiting for the hub xite to sync".to_string()),
                    // The hub's arrival wakes the worker; no extra delay.
                    next_ms: now,
                    ..row.setup.clone()
                },
            );
            continue;
        }

        match publish_identity_bundle(state, ms, &identity).await {
            Ok(setup) => {
                let _ = ms.db.set_identity_setup(identity_id, &setup);
                state
                    .log(
                        "INFO",
                        format!(
                            "channels: published {}'s key bundle to the hub ({})",
                            identity.xid(),
                            setup.published_path.as_deref().unwrap_or("")
                        ),
                    )
                    .await;
                deliver_channel_event(
                    state,
                    ms,
                    json!({
                        "type": "setup",
                        "identity_id": identity_id,
                        "xid": identity.xid(),
                        "auth": identity.auth_address,
                        // No app: an identity's keys serve every client app.
                        "state": STATE_PUBLISHED,
                    }),
                )
                .await;
                import_legacy_once(state, ms, &identity, identity_id, legacy_imported).await;
            }
            Err(SetupError::Transient(error)) => {
                let attempts = row.setup.attempts + 1;
                let _ = ms.db.set_identity_setup(
                    identity_id,
                    &IdentitySetup {
                        state: STATE_PENDING.to_string(),
                        error: Some(error),
                        attempts,
                        next_ms: now + (backoff_secs(attempts) * 1000) as i64,
                        ..row.setup.clone()
                    },
                );
            }
            Err(SetupError::Definite(error)) => {
                state
                    .log(
                        "WARNING",
                        format!("channels: setup for {} failed: {error}", identity.xid()),
                    )
                    .await;
                let _ = ms.db.set_identity_setup(
                    identity_id,
                    &IdentitySetup {
                        state: STATE_FAILED.to_string(),
                        error: Some(error),
                        attempts: row.setup.attempts + 1,
                        ..row.setup.clone()
                    },
                );
            }
        }
    }
}

/// Import an identity's legacy (pre-pool) mail once per process run. Idempotent
/// on the index side too, so a second run after a restart imports nothing new.
async fn import_legacy_once(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    identity: &epix_user::Identity,
    identity_id: i64,
    legacy_imported: &mut std::collections::HashSet<i64>,
) {
    if !legacy_imported.insert(identity_id) {
        return;
    }
    let seed = state.derive_consumer_seed("channel", &identity.auth_address).await;
    let ctx = IdentityCtx {
        identity_id,
        auth: identity.auth_address.clone(),
        xid: identity.xid(),
        secret: IdentitySecret::new(seed),
    };
    match import_legacy_mail(state, ms, &ctx).await {
        Ok(report) if report.imported > 0 => {
            state
                .log(
                    "INFO",
                    format!(
                        "channels: imported {} legacy mail message(s) for {} into the private index",
                        report.imported,
                        identity.xid()
                    ),
                )
                .await;
        }
        Ok(_) => {}
        Err(error) => {
            state.log("DEBUG", format!("channels: legacy mail import: {error}")).await;
        }
    }
}

/// Publish one identity's key bundle into the hub: derive, pick the slot, write,
/// sign the identity's user content as that identity, publish, and record the
/// bundle in the private index.
async fn publish_identity_bundle(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    identity: &epix_user::Identity,
) -> Result<IdentitySetup, SetupError> {
    let auth = identity.auth_address.as_str();
    let xid = identity.xid();
    let seed = state.derive_consumer_seed("channel", auth).await;
    let bundle =
        build_identity_bundle(ms.engine.as_ref(), auth, &xid, &identity.auth_privatekey, seed)
            .map_err(SetupError::Definite)?;

    // Slot: the primary data.json when it is free or already ours, else this
    // device's own file - two devices of one name never clobber each other.
    let dir = format!("data/users/{xid}");
    let primary = format!("{dir}/data.json");
    let held_by_other = state
        .read_xite_file(&ms.xite, &primary)
        .await
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .is_some_and(|existing| existing.get("auth").and_then(Value::as_str) != Some(auth));
    let path = if held_by_other { format!("{dir}/{}", device_bundle_file(auth)) } else { primary };

    let bytes = serde_json::to_vec(&bundle).map_err(|e| SetupError::Definite(e.to_string()))?;
    state
        .write_file_unchecked(&ms.xite, &path, &bytes)
        .await
        .map_err(classify)?;
    let content_path = format!("{dir}/content.json");
    state
        .sign_user_content_as(&ms.xite, &content_path, UserContentSigner::for_identity(identity), None)
        .await
        .map_err(classify)?;
    ms.db
        .upsert_identity(&xid, auth, 0, Some(&bundle.to_string()))
        .map_err(|e| SetupError::Transient(e.to_string()))?;
    // Signing is the commitment; a publish that reaches no peer yet is retried
    // by the periodic sweep, not a setup failure.
    let peers = state.publish(&ms.xite, &content_path, None, false).await.unwrap_or(0);
    Ok(IdentitySetup {
        state: STATE_PUBLISHED.to_string(),
        error: None,
        attempts: 0,
        next_ms: 0,
        published_path: Some(path),
        published_ms: now_ms(),
        published_peers: peers as i64,
    })
}

/// `channelIdentitySetup([{auth_address?|xid?}])` - (re)run the setup job for
/// the identity in scope now; returns its setup object.
pub struct ChannelIdentitySetup;
#[async_trait]
impl WsCommand for ChannelIdentitySetup {
    fn name(&self) -> &'static str {
        "channelIdentitySetup"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = crate::channel::channel_state(s).await?;
        let ctx = crate::channel::require_identity(s, &ms, p).await?;
        request_setup(&ms, ctx.identity_id)?;
        let row = ms
            .db
            .identity_by_id(ctx.identity_id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown channel identity")?;
        Ok(setup_json(&row))
    }
}

/// `channelIdentitySetEnabled([auth_address, enabled])` - turn channels on or
/// off for one held identity. Off: not indexed, not badged, not published
/// again (a bundle already in the hub stays until overwritten).
pub struct ChannelIdentitySetEnabled;
#[async_trait]
impl WsCommand for ChannelIdentitySetEnabled {
    fn name(&self) -> &'static str {
        "channelIdentitySetEnabled"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = crate::channel::channel_state(s).await?;
        let (auth, enabled) = match p {
            Value::Array(a) => (
                a.first().and_then(Value::as_str).map(str::to_string),
                a.get(1).and_then(Value::as_bool),
            ),
            Value::Object(o) => (
                o.get("auth_address").and_then(Value::as_str).map(str::to_string),
                o.get("enabled").and_then(Value::as_bool),
            ),
            _ => (None, None),
        };
        let auth = auth.ok_or("channelIdentitySetEnabled: auth_address required")?;
        let enabled = enabled.ok_or("channelIdentitySetEnabled: enabled (bool) required")?;
        let identity = s
            .state
            .identities()
            .await
            .into_iter()
            .find(|i| i.auth_address == auth)
            .ok_or_else(|| format!("unknown identity {auth}"))?;
        let identity_id = ensure_identity_row(&ms.db, &identity)?;
        ms.db.set_identity_enabled(identity_id, enabled).map_err(|e| e.to_string())?;
        let row = ms
            .db
            .identity_by_id(identity_id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown channel identity")?;
        let state = if enabled { STATE_KEYS } else { STATE_OFF };
        ms.db
            .set_identity_setup(
                identity_id,
                &IdentitySetup { state: state.to_string(), error: None, attempts: 0, next_ms: 0, ..row.setup },
            )
            .map_err(|e| e.to_string())?;
        ms.setup_wake.notify_one();
        let row = ms
            .db
            .identity_by_id(identity_id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown channel identity")?;
        Ok(setup_json(&row))
    }
}

/// `channelIdentityStatus([{auth_address?|xid?}])` - the Config page's status
/// object for the identity in scope, or null when the xite is anonymous.
pub struct ChannelIdentityStatus;
#[async_trait]
impl WsCommand for ChannelIdentityStatus {
    fn name(&self) -> &'static str {
        "channelIdentityStatus"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = crate::channel::channel_state(s).await?;
        let Some(ctx) = crate::channel::resolve_identity(s, &ms, p).await? else {
            return Ok(Value::Null);
        };
        let row = ms
            .db
            .identity_by_id(ctx.identity_id)
            .map_err(|e| e.to_string())?
            .ok_or("unknown channel identity")?;
        Ok(status_value(&row))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(state: &str, enabled: bool) -> IdentityRow {
        IdentityRow {
            identity_id: 7,
            xid: "alice.epix".into(),
            auth_address: "epix1alice".into(),
            derive_index: 0,
            bundle_json: None,
            enabled,
            setup: IdentitySetup {
                state: state.into(),
                error: Some("boom".into()),
                attempts: 3,
                next_ms: 0,
                published_path: Some("data/users/alice.epix/data.json".into()),
                published_ms: 5,
                published_peers: 1,
            },
        }
    }

    #[test]
    fn status_reflects_state_and_offers_the_right_actions() {
        let published = status_value(&row(STATE_PUBLISHED, true));
        assert_eq!(published["state"], "published");
        assert_eq!(published["summary"], "channels: published");
        assert_eq!(published["detail"], "data/users/alice.epix/data.json, 1 peer");
        let actions = published["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 1, "a published identity only offers on/off");
        assert_eq!(actions[0]["cmd"], "channelIdentitySetEnabled");
        assert_eq!(actions[0]["params"], json!(["epix1alice", false]));

        let failed = status_value(&row(STATE_FAILED, true));
        assert_eq!(failed["detail"], "boom");
        assert_eq!(failed["actions"][0]["cmd"], "channelIdentitySetup");
        assert_eq!(failed["actions"][0]["params"], json!([{ "auth_address": "epix1alice" }]));

        let off = status_value(&row(STATE_PUBLISHED, false));
        assert_eq!(off["state"], "off");
        assert_eq!(off["actions"][0]["label"], "Turn channels on");
        assert_eq!(setup_json(&row(STATE_PENDING, false))["state"], "off");
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_secs(0), 1);
        assert_eq!(backoff_secs(3), 8);
        assert_eq!(backoff_secs(20), MAX_BACKOFF_SECS);
        assert!(matches!(classify("no peers".into()), SetupError::Transient(_)));
        assert!(matches!(
            classify("channel auth key does not match the linked address".into()),
            SetupError::Definite(_)
        ));
    }
}
