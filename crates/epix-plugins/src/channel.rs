//! The Channel plugin: metadata-private channels (mail / DMs today, forum
//! categories later), as a *consumer* of the generic anonymous-envelope-pool
//! primitive (`epix_ui::pool`).
//!
//! The core node knows nothing about channels. This plugin owns everything
//! channel-specific — the private index ([`epix_channel::ChannelDb`]), the crypto
//! engine ([`epix_envelope::Engine`]), the trial-decrypt indexer, and the
//! `channel*` WS commands — and reaches the node only through generic seams: it
//! subscribes to
//! the pool-delta bus, appends records via [`AppState::append_pool_record`],
//! derives its identity secret via [`AppState::derive_consumer_seed`] (the
//! master seed never leaves the node), and stashes its state in the generic
//! capability registry so its commands can retrieve it.
//!
//! ## Engine
//! By default this runs the real X3DH + Double Ratchet engine
//! (`epix_pairwise_engine::PairwiseEngine`). Setting `channel_allow_insecure_engine` swaps in
//! the deliberately-insecure [`epix_envelope::FakeEngine`] (NO confidentiality —
//! for pipeline testing only).

use async_trait::async_trait;
use base64::Engine as _;
use epix_channel::{ChannelDb, RevokedDevice};
use epix_envelope::{Engine, FakeEngine, IdentitySecret, PendingOutbound, ProcessOutcome};
use epix_plugin::Plugin;
use epix_ui::state::AppState;
use epix_ui::{WsCommand, WsSession};
use serde_json::{json, Value};
use std::sync::Arc;

/// Capability-registry key under which this plugin stashes [`ChannelState`].
const CHANNEL_CAP: &str = "channel";
/// Anti-entropy sweep cadence for the current-week pool shards.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// Failed durable-outbox appends are retried after this delay.
const OUTBOX_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// The channel-specific state a running node holds — installed once at startup and
/// retrieved by the `channel*` commands from the bound `AppState`.
/// The official Epix Mail xite: the default channel xite when `channel_xite`
/// is unset or blank, so metadata-private mail works out of the box. The
/// Config page default MUST equal this (a schema test pins it).
pub const DEFAULT_CHANNEL_XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";

pub struct ChannelState {
    pub db: Arc<ChannelDb>,
    pub engine: Arc<dyn Engine>,
    pub xite: String,
    pub identity_id: std::sync::atomic::AtomicI64,
    /// Serializes the send path. Detection tags and AEAD nonces are a pure
    /// deterministic function of ratchet state, so two concurrent sends that read
    /// the SAME session before either persists would seal from identical state —
    /// reusing a ChaCha20-Poly1305 (key, nonce) pair (catastrophic) and emitting
    /// two records with the same tag. Holding this across the whole seal→persist
    /// critical section makes each send read the previous send's advanced state.
    pub send_lock: tokio::sync::Mutex<()>,
    /// Serializes SQLite staging with RLN usage reconciliation/finalization.
    /// Network delivery never holds this lock.
    pub outbox_lock: tokio::sync::Mutex<()>,
    /// Coalesces immediate and background delivery attempts without blocking a
    /// new logical send from sealing and staging while a peer dial is slow.
    pub delivery_lock: tokio::sync::Mutex<()>,
    /// False while provisional RLN usage has not been durably reconciled. No
    /// queued record may become externally visible and be acknowledged then.
    pub rln_usage_ready: std::sync::atomic::AtomicBool,
    /// Coalesces failed index attempts into one persistent retained-shard scan
    /// worker. Notify keeps one wakeup while the worker is already retrying.
    pub index_retry: tokio::sync::Notify,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn active_rln_outbox_reservations(
    db: &ChannelDb,
    xite: &str,
) -> Result<Vec<(String, u64, [u8; 32])>, String> {
    db.pending_outbound(usize::MAX)
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|row| row.recovery.rln.is_some())
        .map(|row| {
            let epoch = row
                .record
                .get("epoch")
                .and_then(Value::as_i64)
                .ok_or("queued RLN record has no epoch")?;
            let ct = row
                .record
                .get("ct")
                .and_then(Value::as_str)
                .ok_or("queued RLN record has no ciphertext")
                .and_then(|value| {
                    base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .map_err(|_| "queued RLN record has invalid ciphertext")
                })?;
            Ok((
                xite.to_string(),
                epoch.max(0) as u64,
                epix_content::pool::rln_reservation_id(epoch, &ct),
            ))
        })
        .collect::<Result<Vec<_>, &str>>()
        .map_err(str::to_string)
}

fn reconcile_rln_usage(ms: &ChannelState, rln: &crate::rln::RlnAdmission) -> Result<(), String> {
    let active = active_rln_outbox_reservations(&ms.db, &ms.xite)?;
    rln.reconcile_outbox_reservations(&active)
}

#[cfg(not(test))]
fn rln_reconcile_retry_delay(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << attempt.saturating_sub(1).min(6))
}

#[cfg(test)]
fn rln_reconcile_retry_delay(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(u64::from(attempt.min(64)))
}

async fn run_rln_reconcile_retry<F, Fut>(ready: &std::sync::atomic::AtomicBool, mut reconcile: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), String>>,
{
    let mut attempt = 0u32;
    while !ready.load(std::sync::atomic::Ordering::Acquire) {
        attempt = attempt.saturating_add(1);
        match reconcile().await {
            Ok(()) => {
                ready.store(true, std::sync::atomic::Ordering::Release);
                return;
            }
            Err(_) => tokio::time::sleep(rln_reconcile_retry_delay(attempt)).await,
        }
    }
}

async fn monitor_rln_usage_reconciliation(
    state: Arc<AppState>,
    ms: Arc<ChannelState>,
    rln: Arc<crate::rln::RlnAdmission>,
) {
    loop {
        {
            // A cancelled reservation batch can poison the usage ledger if its
            // rollback cannot be persisted. Detect that state under the same
            // staging lock used by ChannelSend, then force the normal durable
            // reload and reconciliation loop before another send can stage.
            let _staging_guard = ms.outbox_lock.lock().await;
            if !rln.usage_ledger_healthy() {
                ms.rln_usage_ready
                    .store(false, std::sync::atomic::Ordering::Release);
            }
        }
        run_rln_reconcile_retry(&ms.rln_usage_ready, || {
            let state = state.clone();
            let ms = ms.clone();
            let rln = rln.clone();
            async move {
                let result = {
                    let _staging_guard = ms.outbox_lock.lock().await;
                    reconcile_rln_usage(&ms, &rln)
                };
                if let Err(error) = &result {
                    state
                        .log(
                            "ERROR",
                            &format!("could not reconcile RLN outbox reservations: {error}"),
                        )
                        .await;
                }
                result
            }
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn channel_staging_guard(
    ms: &ChannelState,
) -> Result<tokio::sync::MutexGuard<'_, ()>, String> {
    let guard = ms.outbox_lock.lock().await;
    if !ms
        .rln_usage_ready
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err("RLN usage reconciliation is incomplete; channel send was not staged".into());
    }
    Ok(guard)
}

/// Normalize a recipient id to its user directory name (`name.epix`).
fn norm_xid(x: &str) -> String {
    let x = x.trim().trim_end_matches('.');
    if x.ends_with(".epix") {
        x.to_string()
    } else {
        format!("{x}.epix")
    }
}

fn normalized_recipients(values: &[Value]) -> Vec<String> {
    let mut recipients: Vec<_> = values
        .iter()
        .filter_map(Value::as_str)
        .map(norm_xid)
        .collect();
    recipients.sort();
    recipients.dedup();
    recipients
}

fn channel_state(s: &WsSession) -> Result<Arc<ChannelState>, String> {
    s.state.capability::<ChannelState>(CHANNEL_CAP).ok_or_else(|| "channels are not enabled".to_string())
}

/// The node's single channel identity `(identity_id, secret, xid)`.
async fn channel_identity(
    state: &Arc<AppState>,
    ms: &ChannelState,
) -> Result<(i64, IdentitySecret, String, String), String> {
    let current_auth = state.user_auth_address(&ms.xite).await?;
    let row = ms
        .db
        .identities()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|row| row.auth_address == current_auth)
        .ok_or("current linked identity has no channel bundle; publish your key bundle first")?;
    let seed = state
        .derive_consumer_seed("channel", &row.auth_address)
        .await;
    Ok((
        row.identity_id,
        IdentitySecret::new(seed),
        row.xid,
        row.auth_address,
    ))
}

/// Build the one authenticated local device bundle used by both startup and
/// explicit publish. Address, signing key, channel seed, and directory name are
/// all derived from the same cert-aware linked identity.
async fn local_channel_bundle(
    state: &Arc<AppState>,
    xite: &str,
    engine: &dyn Engine,
) -> Result<(String, String, Value), String> {
    let auth = state.user_auth_address(xite).await?;
    let xid = state.user_directory(xite, &auth).await;
    let seed = state.derive_consumer_seed("channel", &auth).await;
    let mut bundle = engine.publish_bundle(&IdentitySecret::new(seed), &xid);
    if let Some(object) = bundle.as_object_mut() {
        object.insert("auth".into(), json!(auth));
    }
    if bundle.get("v").and_then(Value::as_i64) == Some(3) {
        let auth_key = state.user_cert_auth_privatekey(xite).await?;
        let signer = epix_crypt::privatekey_to_address(&auth_key).map_err(|e| e.to_string())?;
        if signer != auth {
            return Err("selected channel auth key does not match the linked address".into());
        }
        let payload = epix_pairwise_engine::keys::bundle_auth_payload(&bundle)
            .ok_or("could not canonicalize channel bundle")?;
        bundle["auth_sig"] =
            json!(epix_crypt::sign_keccak(&payload, &auth_key).map_err(|e| e.to_string())?);
        if !engine.verify_bundle(&bundle) {
            return Err("generated channel bundle failed authenticated verification".into());
        }
    }
    Ok((auth, xid, bundle))
}

fn ensure_local_sender_active(
    xid: &str,
    auth: &str,
    tombstoned: bool,
    name_active: Option<bool>,
    active_addrs: &[String],
) -> Result<(), String> {
    if tombstoned || name_active == Some(false) {
        return Err(format!("{xid}'s identity has been revoked"));
    }
    // A non-empty signer set is a positive chain result. If this device is not
    // in it, a sibling may remain active but this local signing identity cannot
    // continue an established channel session. Empty means indeterminate and
    // deliberately preserves offline messaging semantics.
    if !active_addrs.is_empty() && !active_addrs.iter().any(|a| a == auth) {
        return Err(format!("this device's identity for {xid} has been revoked"));
    }
    Ok(())
}

/// All local channel identities to trial-match inbound records against.
async fn build_identities(
    state: &Arc<AppState>,
    db: &ChannelDb,
) -> Vec<(i64, IdentitySecret, String)> {
    let Ok(rows) = db.identities() else { return Vec::new() };
    let mut out = Vec::new();
    for r in rows {
        let seed = state.derive_consumer_seed("channel", &r.auth_address).await;
        out.push((r.identity_id, IdentitySecret::new(seed), r.xid));
    }
    out
}

/// Trial-decrypt a batch of pool records into the private index; push a
/// `channelEvent` per newly-indexed message. Returns whether a NEW session formed
/// (so the caller can re-scan for out-of-order records). Does not itself re-scan.
/// Every user's published key bundle on the xite, keyed by normalized xid. The
/// map is bounded by the number of xite users; used by the first-contact
/// anti-spoof check (sender_xid → bundle.ik).
/// The per-device bundle filename for a linked-identity address. `epix1…`
/// addresses are bech32 (`[0-9a-z]` only), so this is filesystem- and
/// permission-regex-safe: `data-<auth>.json` matches `data-[0-9a-z]+\.json`.
fn device_bundle_file(auth: &str) -> String {
    let safe: String = auth.chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect();
    format!("data-{safe}.json")
}

/// Whether `path` is a channel key-bundle file (`data/users/<dir>/data.json`
/// or a per-device `.../data-<auth>.json`), returning `(dir, filename)`.
fn bundle_path_parts(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("data/users/")?;
    let (dir, file) = rest.rsplit_once('/')?;
    if dir.contains('/') {
        return None; // only the immediate user directory
    }
    let is_bundle =
        file == "data.json" || (file.starts_with("data-") && file.ends_with(".json"));
    is_bundle.then_some((dir, file))
}

fn bundle_xid_matches_directory(bundle: &Value, canonical_dir: &str) -> bool {
    bundle.get("xid").and_then(Value::as_str) == Some(canonical_dir)
}

/// Bind a secondary filename to the cryptographically authenticated `auth`
/// address carried by a v3 bundle. The engine verifies `auth_sig`; this helper
/// only prevents a signed bundle from being copied under another device path.
fn bundle_filename_matches_auth(file: &str, bundle: &Value) -> bool {
    let Some(auth) = bundle.get("auth").and_then(Value::as_str) else {
        return false;
    };
    file == "data.json" || file == device_bundle_file(auth)
}

/// Every currently-published key bundle, grouped by xID name to the name's active
/// device bundles. Revocation decisions come from one fresh, finality-bound
/// identity snapshot per name. Only an address explicitly marked revoked becomes
/// a durable tombstone. An address absent from a definite snapshot is blocked for
/// that refresh, but is not tombstoned, so a newly-linked device can become usable
/// once a later snapshot reports it active. Resolver outages remain fail-open for
/// non-tombstoned devices.
#[derive(Clone, Default)]
struct PublishedBundles {
    active: std::collections::HashMap<String, Vec<Value>>,
    revoked_names: std::collections::HashSet<String>,
    /// `(normalized xid, hex identity key)` for a definitely revoked device.
    revoked_devices: std::collections::HashSet<(String, String)>,
}

type PublishedBundleMap = std::collections::HashMap<String, Vec<Value>>;
type SessionPeerMap =
    std::collections::HashMap<String, Vec<epix_channel::SessionPeer>>;

struct PublishedBundleSources<'a> {
    state: &'a Arc<AppState>,
    engine: &'a dyn Engine,
    db: &'a ChannelDb,
    sessions_by_name: &'a SessionPeerMap,
}

async fn load_published_bundles(
    state: &Arc<AppState>,
    xite: &str,
    engine: &dyn Engine,
    db: &ChannelDb,
) -> Result<PublishedBundles, String> {
    let mut by_name = read_published_bundle_files(state, xite, engine).await;
    db.backfill_session_peer_auth(&published_auth_bindings(engine, &by_name))
        .map_err(|error| error.to_string())?;
    let sessions_by_name = session_peers_by_name(db, &mut by_name)?;
    include_local_identity_names(db, &mut by_name)?;

    let mut out = PublishedBundles::default();
    let mut newly_revoked = Vec::<RevokedDevice>::new();
    let sources = PublishedBundleSources {
        state,
        engine,
        db,
        sessions_by_name: &sessions_by_name,
    };
    for (name, devs) in by_name {
        classify_published_name(
            &sources,
            name,
            devs,
            &mut out,
            &mut newly_revoked,
        )
        .await?;
    }
    db.remember_revoked_devices(&newly_revoked, now_ms())
        .map_err(|error| error.to_string())?;
    Ok(out)
}

async fn read_published_bundle_files(
    state: &Arc<AppState>,
    xite: &str,
    engine: &dyn Engine,
) -> PublishedBundleMap {
    let mut by_name = PublishedBundleMap::new();
    for path in state.list_xite_files(xite).await {
        let Some((dir, file)) = bundle_path_parts(&path) else {
            continue;
        };
        let Some(bytes) = state.read_xite_file(xite, &path).await else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        // Attribute the bundle to the cert-gated directory it lives in. Drop a
        // bundle whose declared xID disagrees with that authenticated directory.
        let key = norm_xid(dir);
        if !bundle_xid_matches_directory(&v, &key) {
            continue;
        }
        if !engine.verify_bundle(&v) || !bundle_filename_matches_auth(file, &v) {
            continue;
        }
        by_name.entry(key).or_default().push(v);
    }
    by_name
}

fn published_auth_bindings(
    engine: &dyn Engine,
    by_name: &PublishedBundleMap,
) -> Vec<(String, String, String)> {
    let mut bindings = Vec::new();
    for (name, bundles) in by_name {
        for bundle in bundles {
            if let (Some(ik), Some(auth)) = (
                engine.sender_ik(bundle),
                bundle.get("auth").and_then(Value::as_str),
            ) {
                bindings.push((name.clone(), hex::encode(ik), auth.to_string()));
            }
        }
    }
    bindings
}

fn session_peers_by_name(
    db: &ChannelDb,
    by_name: &mut PublishedBundleMap,
) -> Result<SessionPeerMap, String> {
    let mut sessions_by_name = SessionPeerMap::new();
    for peer in db.session_peers().map_err(|e| e.to_string())? {
        let name = norm_xid(&peer.xid);
        sessions_by_name.entry(name.clone()).or_default().push(peer);
        // Query chain status even when every bundle for this established peer
        // was removed or has not synced on this node.
        by_name.entry(name).or_default();
    }
    Ok(sessions_by_name)
}

fn include_local_identity_names(
    db: &ChannelDb,
    by_name: &mut PublishedBundleMap,
) -> Result<(), String> {
    for identity in db.identities().map_err(|error| error.to_string())? {
        by_name.entry(norm_xid(&identity.xid)).or_default();
    }
    Ok(())
}

async fn published_identity_snapshot(
    state: &Arc<AppState>,
    name: &str,
) -> Option<epix_chain::XidIdentitySnapshot> {
    match state.xid_identity_snapshot(name).await {
        Ok(Some(snapshot)) if norm_xid(&snapshot.canonical_name) == name => Some(snapshot),
        Ok(Some(_)) => {
            state
                .log(
                    "WARN",
                    &format!("ignoring mismatched xID identity snapshot for {name}"),
                )
                .await;
            None
        }
        Ok(None) => None,
        Err(error) => {
            state
                .log(
                    "WARN",
                    &format!("xID identity snapshot unavailable for {name}: {error}"),
                )
                .await;
            None
        }
    }
}

fn record_snapshot_revocations(
    name: &str,
    snapshot: Option<&epix_chain::XidIdentitySnapshot>,
    out: &mut PublishedBundles,
    newly_revoked: &mut Vec<RevokedDevice>,
) {
    let Some(snapshot) = snapshot else { return };
    use epix_chain::XidIdentityStatus::{Active, Revoked};
    if !snapshot
        .identities
        .iter()
        .any(|identity| identity.status == Active)
    {
        out.revoked_names.insert(name.to_string());
    }
    for identity in snapshot
        .identities
        .iter()
        .filter(|identity| identity.status == Revoked)
    {
        newly_revoked.push(RevokedDevice {
            xid: name.to_string(),
            auth_address: identity.auth_address.clone(),
            peer_ik: String::new(),
        });
    }
}

fn classify_session_peer(
    db: &ChannelDb,
    name: &str,
    snapshot: Option<&epix_chain::XidIdentitySnapshot>,
    peer: &epix_channel::SessionPeer,
    out: &mut PublishedBundles,
    newly_revoked: &mut Vec<RevokedDevice>,
) -> Result<(), String> {
    let status_for = |auth: &str| snapshot.and_then(|value| value.status_for(auth));
    let snapshot_has_revocation = snapshot.is_some_and(|value| {
        value
            .identities
            .iter()
            .any(|identity| identity.status == epix_chain::XidIdentityStatus::Revoked)
    });
    let unbound_legacy_leg = peer.peer_auth.is_none() && snapshot_has_revocation;
    let transiently_blocked = peer.peer_auth.as_deref().is_some_and(|auth| {
        snapshot.is_some() && status_for(auth) != Some(epix_chain::XidIdentityStatus::Active)
    });
    let explicitly_revoked = peer.peer_auth.as_deref().is_some_and(|auth| {
        status_for(auth) == Some(epix_chain::XidIdentityStatus::Revoked)
    });
    if explicitly_revoked {
        newly_revoked.push(RevokedDevice {
            xid: name.to_string(),
            auth_address: peer.peer_auth.clone().unwrap_or_default(),
            peer_ik: peer.peer_ik.clone(),
        });
    }
    if unbound_legacy_leg {
        newly_revoked.push(RevokedDevice {
            xid: name.to_string(),
            auth_address: String::new(),
            peer_ik: peer.peer_ik.clone(),
        });
    }
    let should_block = if unbound_legacy_leg || transiently_blocked {
        true
    } else {
        db.is_device_revoked(name, peer.peer_auth.as_deref(), &peer.peer_ik)
            .map_err(|error| error.to_string())?
    };
    if should_block {
        out.revoked_devices
            .insert((name.to_string(), peer.peer_ik.clone()));
    }
    Ok(())
}

fn classify_session_peers(
    db: &ChannelDb,
    sessions_by_name: &SessionPeerMap,
    name: &str,
    snapshot: Option<&epix_chain::XidIdentitySnapshot>,
    out: &mut PublishedBundles,
    newly_revoked: &mut Vec<RevokedDevice>,
) -> Result<(), String> {
    for peer in sessions_by_name.get(name).into_iter().flatten() {
        classify_session_peer(db, name, snapshot, peer, out, newly_revoked)?;
    }
    Ok(())
}

fn retain_active_bundles(
    engine: &dyn Engine,
    db: &ChannelDb,
    name: &str,
    devs: Vec<Value>,
    snapshot: Option<&epix_chain::XidIdentitySnapshot>,
    out: &mut PublishedBundles,
    newly_revoked: &mut Vec<RevokedDevice>,
) -> Result<Vec<Value>, String> {
    let status_for = |auth: &str| snapshot.and_then(|value| value.status_for(auth));
    let mut retained = Vec::new();
    for bundle in refine_device_bundles(devs, &[]) {
        let Some(auth) = bundle.get("auth").and_then(Value::as_str) else {
            continue;
        };
        let Some(peer_ik) = engine.sender_ik(&bundle).map(hex::encode) else {
            continue;
        };
        let explicitly_revoked =
            status_for(auth) == Some(epix_chain::XidIdentityStatus::Revoked);
        if explicitly_revoked {
            newly_revoked.push(RevokedDevice {
                xid: name.to_string(),
                auth_address: auth.to_string(),
                peer_ik: peer_ik.clone(),
            });
            out.revoked_devices
                .insert((name.to_string(), peer_ik.clone()));
        }
        let snapshot_allows = snapshot.is_none()
            || status_for(auth) == Some(epix_chain::XidIdentityStatus::Active);
        if snapshot_allows
            && !out
                .revoked_devices
                .contains(&(name.to_string(), peer_ik.clone()))
            && !db
                .is_device_revoked(name, Some(auth), &peer_ik)
                .map_err(|error| error.to_string())?
        {
            retained.push(bundle);
        }
    }
    Ok(retained)
}

async fn classify_published_name(
    sources: &PublishedBundleSources<'_>,
    name: String,
    devs: Vec<Value>,
    out: &mut PublishedBundles,
    newly_revoked: &mut Vec<RevokedDevice>,
) -> Result<(), String> {
    let snapshot = published_identity_snapshot(sources.state, &name).await;
    record_snapshot_revocations(&name, snapshot.as_ref(), out, newly_revoked);
    classify_session_peers(
        sources.db,
        sources.sessions_by_name,
        &name,
        snapshot.as_ref(),
        out,
        newly_revoked,
    )?;
    let retained = retain_active_bundles(
        sources.engine,
        sources.db,
        &name,
        devs,
        snapshot.as_ref(),
        out,
        newly_revoked,
    )?;
    if !retained.is_empty() {
        out.active.insert(name, retained);
    }
    Ok(())
}

/// Filter one name's raw device bundles down to the usable, deduplicated set:
///   - per-device revocation: when `active` is NON-empty (a positively-known
///     active-signer set), drop a bundle whose own `auth` is absent from it; a
///     legacy bundle with no `auth`, or an empty/indeterminate `active`, is kept
///     (fail open — the name-level gate already handled full revocation);
///   - dedup by identity key, keeping the FRESHEST (highest `spk_idx`) copy so a
///     rotated prekey wins over a stale `data.json` left beside `data-<auth>.json`.
pub fn refine_device_bundles(mut devs: Vec<Value>, active: &[String]) -> Vec<Value> {
    if !active.is_empty() {
        devs.retain(|b| match b.get("auth").and_then(|a| a.as_str()) {
            Some(auth) => active.iter().any(|a| a == auth),
            None => true,
        });
    }
    devs.sort_by(|a, b| {
        let sk = |v: &Value| v.get("spk_idx").and_then(|x| x.as_u64()).unwrap_or(0);
        sk(b).cmp(&sk(a))
    });
    let mut seen = std::collections::HashSet::new();
    devs.retain(|b| match b.get("ik").and_then(|k| k.as_str()) {
        Some(ik) => seen.insert(ik.to_string()),
        None => false, // a bundle with no IK is unusable
    });
    devs
}

/// Map one process outcome to a `channelEvent` payload; a first-contact hit flags
/// that a NEW session formed (so the caller can re-scan for out-of-order records).
fn indexed_event(outcome: ProcessOutcome, new_session: &mut bool) -> Option<Value> {
    let ProcessOutcome::Indexed {
        conv_id, sender_xid, subject, snippet, unread, first_contact, pending, ..
    } = outcome
    else {
        return None;
    };
    if first_contact {
        *new_session = true;
    }
    Some(json!({
        "type": "new_message",
        "conv_id": conv_id,
        "from_xid": sender_xid,
        "subject": subject,
        "snippet": snippet,
        "unread": unread,
        // >0 means earlier messages in this conversation are still arriving
        // (received out of order) — a delivery-gap hint.
        "pending": pending,
    }))
}

/// Trial-decrypt a batch of records into the private index (the blocking core of
/// [`index_batch`]); collect a `channelEvent` per newly-indexed message and whether
/// a NEW session formed. One record can deliver to SEVERAL local identities (one
/// slot each), so `process_record` returns a Vec.
fn process_batch_blocking(
    db: &ChannelDb,
    engine: &dyn Engine,
    identities: &[(i64, IdentitySecret, String)],
    records: &[Value],
    now: i64,
    bundles: &PublishedBundles,
) -> Result<(Vec<Value>, bool), String> {
    let resolve = |xid: &str| -> Vec<Value> {
        bundles
            .active
            .get(&norm_xid(xid))
            .cloned()
            .unwrap_or_default()
    };
    let peer_active = |xid: &str, peer_ik: &str| -> Option<bool> {
        let xid = norm_xid(xid);
        if bundles.revoked_names.contains(&xid)
            || bundles
                .revoked_devices
                .contains(&(xid, peer_ik.to_string()))
        {
            Some(false)
        } else {
            None
        }
    };
    let mut events: Vec<Value> = Vec::new();
    let mut new_session = false;
    for rec in records {
        let outcomes = epix_envelope::process_record_with_peer_status(
            db,
            engine,
            identities,
            rec,
            now,
            resolve,
            peer_active,
        )
        .map_err(|error| error.to_string())?;
        for outcome in outcomes {
            if let Some(ev) = indexed_event(outcome, &mut new_session) {
                events.push(ev);
            }
        }
    }
    Ok((events, new_session))
}

async fn index_batch(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    records: Vec<Value>,
) -> Result<bool, String> {
    let identities = build_identities(state, &ms.db).await;
    if identities.is_empty() || records.is_empty() {
        return Ok(false);
    }
    let db = (*ms.db).clone();
    let engine = ms.engine.clone();
    let now = now_ms();
    // Published bundles, so the first-contact anti-spoof check can resolve a
    // sender_xid → bundle.ik synchronously inside spawn_blocking.
    let bundles = match load_published_bundles(state, &ms.xite, ms.engine.as_ref(), &ms.db).await {
        Ok(bundles) => bundles,
        Err(e) => return Err(format!("channel revocation refresh failed closed: {e}")),
    };

    // Serialize inbound ratchet advances against the SEND path: both do a
    // read-modify-write of the same opaque session-ratchet blob, so without a
    // shared lock a send could persist a ratchet computed from stale state over an
    // inbound advance (or vice versa), desyncing the ratchet and expected-tag
    // table. The send handler holds this same lock across its seal→persist section.
    let (events, new_session) = {
        let _guard = ms.send_lock.lock().await;
        tokio::task::spawn_blocking(move || {
            process_batch_blocking(&db, engine.as_ref(), &identities, &records, now, &bundles)
        })
        .await
        .map_err(|error| format!("channel index task failed: {error}"))??
    };

    for ev in events {
        state.push_site_event(&ms.xite, "channelEvent", ev);
    }
    Ok(new_session)
}

#[cfg(not(test))]
fn index_retry_delay(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << attempt.saturating_sub(1).min(6))
}

#[cfg(test)]
fn index_retry_delay(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_millis(u64::from(attempt.min(64)))
}

async fn run_persistent_retry<F, Fut>(mut operation: F)
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut attempt = 0u32;
    loop {
        attempt = attempt.saturating_add(1);
        tokio::time::sleep(index_retry_delay(attempt)).await;
        if operation(attempt).await {
            return;
        }
    }
}

async fn retry_index_records(state: Arc<AppState>, ms: Arc<ChannelState>) {
    loop {
        ms.index_retry.notified().await;
        run_persistent_retry(|attempt| {
            let state = state.clone();
            let ms = ms.clone();
            async move {
                if !state.config_bool("channel_enabled", false).await {
                    return true;
                }
                let all = state.pool_all_records(&ms.xite).await;
                let result = match index_batch(&state, &ms, all).await {
                    Ok(true) => {
                        let all = state.pool_all_records(&ms.xite).await;
                        index_batch(&state, &ms, all).await.map(|_| ())
                    }
                    Ok(false) => Ok(()),
                    Err(error) => Err(error),
                };
                match result {
                    Ok(()) => true,
                    Err(error) => {
                        state
                            .log(
                                "ERROR",
                                &format!(
                                "channel retained index retry {attempt} failed; retrying: {error}"
                            ),
                            )
                            .await;
                        false
                    }
                }
            }
        })
        .await;
        if !state.config_bool("channel_enabled", false).await {
            return;
        }
    }
}

/// Process a delta, then re-scan once if a new session formed (a record that
/// arrived before its session existed becomes matchable).
async fn index_records(state: &Arc<AppState>, ms: &Arc<ChannelState>, records: Vec<Value>) {
    match index_batch(state, ms, records).await {
        Ok(true) => {
        let all = state.pool_all_records(&ms.xite).await;
            // Idempotent: the processed-set skips already-indexed records.
            if let Err(error) = index_batch(state, ms, all).await {
                state
                    .log("ERROR", &format!("channel index rescan failed: {error}"))
                    .await;
                ms.index_retry.notify_one();
            }
        }
        Ok(false) => {}
        Err(error) => {
            state
                .log("ERROR", &format!("channel index failed: {error}"))
                .await;
            // The exact record remains in a verified local pool shard. The
            // persistent coalesced worker retries until it succeeds even if no
            // new network delta is emitted.
            ms.index_retry.notify_one();
        }
    }
}

/// Choose the channel engine: the real X3DH + Double Ratchet engine by default;
/// the INSECURE test engine only when explicitly opted into for development.
async fn build_engine(state: &Arc<AppState>) -> Option<Arc<dyn Engine>> {
    if state.config_bool("channel_allow_insecure_engine", false).await {
        state
            .log(
                "WARNING",
                "Channel messaging on the INSECURE FakeEngine (no confidentiality): dev only",
            )
            .await;
        Some(Arc::new(FakeEngine))
    } else {
        Some(Arc::new(epix_pairwise_engine::PairwiseEngine))
    }
}

async fn open_db(state: &Arc<AppState>) -> Option<Arc<ChannelDb>> {
    // Opt-in at-rest encryption: seal message content + ratchet blobs under a
    // key derived from the node master seed (recomputable across restarts /
    // restore-from-seed, never leaves the node).
    let key = if state.config_bool("channel_encrypt_at_rest", false).await {
        Some(state.derive_consumer_seed("channel-at-rest", "channels.db").await)
    } else {
        None
    };
    let db = match state.data_root_path() {
        Some(root) => {
            let path = root.join("private").join("channels.db");
            let opened = match key {
                Some(k) => ChannelDb::open_encrypted(&path, k),
                None => ChannelDb::open(&path),
            };
            match opened {
                Ok(db) => Some(db),
                Err(e) => {
                    // A memory fallback would make the ratchet and durable
                    // outbox disappear on restart while pretending channels
                    // were healthy. Refuse startup instead.
                    state
                        .log(
                            "ERROR",
                            &format!(
                                "could not open persistent channel database {}: {e}",
                                path.display()
                            ),
                        )
                        .await;
                    None
                }
            }
        }
        None => match key {
            Some(k) => ChannelDb::memory_encrypted(k).ok(),
            None => ChannelDb::memory().ok(),
        },
    };
    db.map(Arc::new)
}

/// A dashboard feed + badge source backed by the PRIVATE channel index. Nothing it
/// returns is ever shared — it is computed and rendered only on this node.
struct ChannelFeedSource {
    db: Arc<ChannelDb>,
    xite: String,
    snippets: bool,
}

#[async_trait]
impl epix_ui::local_feed::LocalFeedSource for ChannelFeedSource {
    async fn feed_rows(&self, limit: i64) -> Vec<Value> {
        let mut rows = Vec::new();
        let Ok(identities) = self.db.identities() else { return rows };
        for id in identities {
            let Ok(threads) = self.db.threads(id.identity_id, "all", 0, limit) else { continue };
            for t in threads {
                let peer = t.get("peer_xid").and_then(|v| v.as_str()).unwrap_or("someone");
                let subject = t.get("subject").and_then(|v| v.as_str()).unwrap_or("");
                let last_ms = t.get("last_ms").and_then(|v| v.as_i64()).unwrap_or(0);
                let body = if self.snippets {
                    format!("{peer}: {subject}")
                } else {
                    format!("New message from {peer}")
                };
                rows.push(json!({
                    "type": "channel",
                    "title": "Messages",
                    "body": body,
                    "date_added": last_ms as f64 / 1000.0,
                    "site": self.xite,
                    "feed_name": "channel",
                }));
            }
        }
        rows
    }

    async fn notification_entry(&self) -> Option<Value> {
        if self.xite.is_empty() {
            return None;
        }
        let mut total = 0i64;
        if let Ok(identities) = self.db.identities() {
            for id in identities {
                total += self.db.unread_count(id.identity_id).unwrap_or(0);
            }
        }
        Some(json!({
            "site": self.xite,
            "title": "Messages",
            "name": "channel",
            "count": total,
            "last_seen": 0,
        }))
    }
}

// ===========================================================================
// The plugin
// ===========================================================================

pub struct ChannelPlugin;

impl Plugin for ChannelPlugin {
    fn name(&self) -> &str {
        "Channel"
    }

    fn ws_commands(&self) -> Vec<Arc<dyn WsCommand>> {
        vec![
            Arc::new(ChannelSessionInfo),
            Arc::new(ChannelKeyBundlePublish),
            Arc::new(ChannelKeyLookup),
            Arc::new(ChannelContacts),
            Arc::new(ChannelSend),
            Arc::new(ChannelThreads),
            Arc::new(ChannelConversation),
            Arc::new(ChannelSearch),
            Arc::new(ChannelMarkRead),
            Arc::new(ChannelSetConvState),
            Arc::new(ChannelDeleteLocal),
            Arc::new(ChannelMigrateLegacy),
            Arc::new(ChannelRlnStatus),
        ]
    }

    fn start(&self, state: &Arc<AppState>) {
        tokio::spawn(run_channel_plugin(state.clone()));
    }
}

async fn initialize_local_channel_identity(
    state: &Arc<AppState>,
    xite: &str,
    engine: &dyn Engine,
    db: &ChannelDb,
) -> Option<i64> {
    let (auth, xid, bundle) = match local_channel_bundle(state, xite, engine).await {
        Ok(bundle) => bundle,
        Err(error) => {
            state
                .log(
                    "ERROR",
                    &format!("could not build authenticated channel bundle: {error}"),
                )
                .await;
            return None;
        }
    };
    match db.upsert_identity(&xid, &auth, 0, Some(&bundle.to_string())) {
        Ok(identity_id) => Some(identity_id),
        Err(error) => {
            state
                .log(
                    "ERROR",
                    &format!("could not persist channel identity: {error}"),
                )
                .await;
            None
        }
    }
}

async fn install_channel_rln(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    xite: &str,
) {
    let ledger = state
        .data_root_path()
        .map(|root| root.join("private").join("rln_usage.json"));
    let rln = crate::rln::RlnAdmission::new(ledger);
    if let Err(error) = reconcile_rln_usage(ms, &rln) {
        state
            .log(
                "ERROR",
                &format!("could not reconcile RLN outbox reservations: {error}"),
            )
            .await;
    } else {
        ms.rln_usage_ready
            .store(true, std::sync::atomic::Ordering::Release);
    }
    state.set_pool_admission(rln.clone()).await;
    rln.refresh(state, xite).await;
    state.install_capability(crate::rln::RLN_CAP, rln.clone());
    tokio::spawn(monitor_rln_usage_reconciliation(
        state.clone(),
        ms.clone(),
        rln,
    ));
}

fn spawn_channel_outbox_worker(state: Arc<AppState>, ms: Arc<ChannelState>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = deliver_due_outbox(&state, &ms).await {
                state
                    .log(
                        "WARNING",
                        &format!("channel outbox delivery failed: {error}"),
                    )
                    .await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });
}

fn spawn_channel_backfill(state: Arc<AppState>, xite: String, weeks: u64) {
    tokio::spawn(async move {
        state.backfill_pool_shards(&xite, weeks).await;
    });
}

fn spawn_channel_sweep(state: Arc<AppState>, xite: String) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            if !state.config_bool("channel_enabled", false).await {
                continue;
            }
            state.resync_pool_shards_for(&xite).await;
        }
    });
}

async fn run_channel_indexer(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    xite: &str,
    mut rx: tokio::sync::broadcast::Receiver<epix_ui::pool::PoolDelta>,
) {
    loop {
        match rx.recv().await {
            Ok(delta) if delta.address == xite => {
                index_records(state, ms, delta.records.as_ref().clone()).await;
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                let all = state.pool_all_records(xite).await;
                index_records(state, ms, all).await;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn run_channel_plugin(state: Arc<AppState>) {
            // ON by default: metadata-private mail is a core feature, not an
            // opt-in. `channel_enabled=false` remains the explicit off switch.
            if !state.config_bool("channel_enabled", true).await {
                return;
            }
            // Unset/blank falls back to the official Epix Mail xite, so mail
            // works out of the box with zero configuration.
            let xite = state
                .config_get("channel_xite")
                .await
                .and_then(|v| v.as_str().map(str::trim).map(String::from))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_CHANNEL_XITE.to_string());
            // A fresh node may not have the channel xite yet (the user has
            // never opened Epix Mail). Idle here until it appears - the moment
            // the xite is registered (first visit / clone), channels come up
            // without a restart. Costs one cheap lookup a minute meanwhile.
            while !state.has_xite(&xite).await {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
            let Some(engine) = build_engine(&state).await else { return };
            let Some(db) = open_db(&state).await else {
                state.log("ERROR", "could not open the channel index").await;
                return;
            };

            let Some(local_identity_id) = initialize_local_channel_identity(
                &state,
                &xite,
                engine.as_ref(),
                &db,
            )
            .await
            else {
                return;
            };

            let ms = Arc::new(ChannelState {
                db: db.clone(),
                engine: engine.clone(),
                xite: xite.clone(),
                identity_id: std::sync::atomic::AtomicI64::new(local_identity_id),
                send_lock: tokio::sync::Mutex::new(()),
                outbox_lock: tokio::sync::Mutex::new(()),
                delivery_lock: tokio::sync::Mutex::new(()),
                rln_usage_ready: std::sync::atomic::AtomicBool::new(false),
                index_retry: tokio::sync::Notify::new(),
            });
            state.install_capability(CHANNEL_CAP, ms.clone());
            {
                let s = state.clone();
                let m = ms.clone();
                tokio::spawn(retry_index_records(s, m));
            }

            install_channel_rln(&state, &ms, &xite).await;

            // Reconcile every provisional RLN range before any durable record
            // can publish or be acknowledged. The exact record and ratchet
            // advance already committed together, so retry remains idempotent.
            spawn_channel_outbox_worker(state.clone(), ms.clone());

            let snippets = state.config_bool("channel_feed_snippets", false).await;
            state
                .register_local_source(Arc::new(ChannelFeedSource {
                    db: db.clone(),
                    xite: xite.clone(),
                    snippets,
                }))
                .await;

            // Subscribe to the pool-delta bus BEFORE kicking off backfill, so no
            // backfilled record's delta is missed.
            let rx = state.subscribe_pool_deltas();

            // A shard can have committed durably just before a crash, after its
            // delta was emitted but before the private index consumed it. No new
            // delta is generated on restart, so scan the verified/routed local
            // pool once before waiting for network activity.
            let retained = state.pool_all_records(&xite).await;
            index_records(&state, &ms, retained).await;

            // Newest-first historical backfill.
            let weeks = state
                .config_get("channel_backfill_weeks")
                .await
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
                .unwrap_or(4);
            spawn_channel_backfill(state.clone(), xite.clone(), weeks);

            // Periodic anti-entropy sweep of the current-week shards.
            spawn_channel_sweep(state.clone(), xite.clone());
            run_channel_indexer(&state, &ms, &xite, rx).await;
}

// ===========================================================================
// WS commands
// ===========================================================================

/// Fetch the single identity id (for db reads scoped to this node's mailbox).
fn identity_id(ms: &ChannelState) -> Result<i64, String> {
    let id = ms.identity_id.load(std::sync::atomic::Ordering::Acquire);
    (id > 0)
        .then_some(id)
        .ok_or_else(|| "no channel identity".to_string())
}

struct ChannelSessionInfo;
#[async_trait]
impl WsCommand for ChannelSessionInfo {
    fn name(&self) -> &'static str {
        "channelSessionInfo"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let (has_identity, unread) = match identity_id(&ms) {
            Ok(id) => (true, ms.db.unread_count(id).unwrap_or(0)),
            Err(_) => (false, 0),
        };
        let (outbox_pending, outbox_error) = ms.db.outbox_status().map_err(|e| e.to_string())?;
        Ok(json!({
            "enabled": true,
            "xite": ms.xite,
            "key_bundle_published": has_identity,
            "unread": unread,
            "outbox_pending": outbox_pending,
            "outbox_error": outbox_error,
        }))
    }
}

/// The footprint status the site renders as a progress bar + reset countdown:
/// how much of this epoch's anonymous rate allowance the node has spent, when it
/// resets, whether the node is an enrolled member, and how long the pool retains
/// records. For a PoW-only pool it just reports retention.
struct ChannelRlnStatus;
#[async_trait]
impl WsCommand for ChannelRlnStatus {
    fn name(&self) -> &'static str {
        "channelRlnStatus"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let Some(rule) = s.state.pool_rules_for(&ms.xite).await.into_iter().next() else {
            return Ok(json!({ "rln_required": false, "retention_weeks": 0 }));
        };
        let retention_weeks = rule.retention_weeks;
        if !rule.rln_required {
            return Ok(json!({ "rln_required": false, "retention_weeks": retention_weeks }));
        }

        // Current epoch (days) and seconds until the next one, when the allowance
        // resets — the "resets at X" the UI shows on a hit limit.
        let now = now_ms();
        let day_ms = 86_400_000i64;
        let epoch = now.div_euclid(day_ms);
        let resets_in_secs = (((epoch + 1) * day_ms - now).max(0) / 1000) as u64;

        let admission = s.state.capability::<crate::rln::RlnAdmission>(crate::rln::RLN_CAP);
        let (used, limit, member) = match &admission {
            Some(a) => {
                let (used, limit) = a.usage(&ms.xite, epoch.max(0) as u64).unwrap_or((0, 0));
                let member = match s.state.user_auth_address(&ms.xite).await.ok() {
                    Some(auth) => {
                        let seed = s.state.derive_consumer_seed("rln", &auth).await;
                        a.is_member(&ms.xite, &epix_rln::RlnIdentity::from_seed(&seed))
                    }
                    None => false,
                };
                (used, limit, member)
            }
            None => (0, 0, false),
        };

        Ok(json!({
            "rln_required": true,
            "member": member,
            "unit_limit": limit,
            "units_used": used,
            "units_remaining": limit.saturating_sub(used),
            "epoch": epoch,
            "resets_in_secs": resets_in_secs,
            "retention_weeks": retention_weeks,
        }))
    }
}

struct ChannelKeyBundlePublish;
#[async_trait]
impl WsCommand for ChannelKeyBundlePublish {
    fn name(&self) -> &'static str {
        "channelKeyBundlePublish"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let (auth, xid, bundle) =
            local_channel_bundle(&s.state, &ms.xite, ms.engine.as_ref()).await?;
        let identity_id = ms
            .db
            .upsert_identity(&xid, &auth, 0, Some(&bundle.to_string()))
            .map_err(|e| e.to_string())?;
        ms.identity_id
            .store(identity_id, std::sync::atomic::Ordering::Release);
        // Cutover-safe multi-device: the site publishes to the primary
        // `data/users/<xid>/data.json` when that slot is free or already this
        // device's (so nodes that only read `data.json` keep working), and to the
        // per-device `device_path` only when a DIFFERENT device already holds the
        // primary slot — so two devices never clobber each other.
        let device_path = format!("data/users/{xid}/{}", device_bundle_file(&auth));
        Ok(json!({
            "ok": true,
            "xid": xid,
            "auth": auth,
            "primary_path": format!("data/users/{xid}/data.json"),
            "device_path": device_path,
            "bundle": bundle,
        }))
    }
}

struct ChannelKeyLookup;
#[async_trait]
impl WsCommand for ChannelKeyLookup {
    fn name(&self) -> &'static str {
        "channelKeyLookup"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let xids = p
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_array())
            .ok_or("channelKeyLookup: [xids] required")?;
        // One resolve covers every looked-up name: grouped, active-filtered,
        // deduped device bundles (the same view the send fan-out uses).
        let published =
            load_published_bundles(&s.state, &ms.xite, ms.engine.as_ref(), &ms.db).await?;
        let mut out = serde_json::Map::new();
        for x in xids {
            let Some(xid) = x.as_str() else { continue };
            let dir = norm_xid(xid);
            // A revoked identity has no usable bundle, even if a stale data.json
            // is still on disk (fail open on an indeterminate chain result).
            let revoked = published.revoked_names.contains(&dir);
            let devices = published
                .active
                .get(&dir)
                .map(|d| d.iter().filter(|b| ms.engine.verify_bundle(b)).count())
                .unwrap_or(0);
            out.insert(
                dir,
                json!({ "has_bundle": !revoked && devices > 0, "revoked": revoked, "devices": devices }),
            );
        }
        Ok(Value::Object(out))
    }
}

struct ChannelContacts;
#[async_trait]
impl WsCommand for ChannelContacts {
    fn name(&self) -> &'static str {
        "channelContacts"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let id = identity_id(&ms)?;
        let threads = ms.db.threads(id, "all", 0, 500).map_err(|e| e.to_string())?;
        let mut seen = std::collections::BTreeSet::new();
        for t in threads {
            if let Some(p) = t.get("peer_xid").and_then(|v| v.as_str()) {
                seen.insert(p.to_string());
            }
        }
        Ok(json!(seen.into_iter().map(|x| json!({ "xid": x })).collect::<Vec<_>>()))
    }
}

/// Resolve every recipient name to its active, verified device bundles, flattened
/// into one destination list (one slot per device). Errors if a recipient is
/// revoked on chain, or has published no usable channel keys. Touches no ratchet
/// state, so the caller runs it BEFORE taking the send lock.
async fn resolve_destinations(
    ms: &ChannelState,
    recipients: &[String],
    published: &PublishedBundles,
) -> Result<Vec<Value>, String> {
    let mut groups: Vec<(String, Vec<Value>)> = Vec::new();
    for recip in recipients {
        if published.revoked_names.contains(recip) {
            return Err(format!("{recip}'s identity has been revoked"));
        }
        let devices: Vec<Value> = published
            .active
            .get(recip)
            .into_iter()
            .flatten()
            .filter(|b| ms.engine.verify_bundle(b))
            .cloned()
            .collect();
        if devices.is_empty() {
            return Err(format!("{recip} has not published channel keys"));
        }
        groups.push((recip.clone(), devices));
    }
    unique_destination_devices(ms.engine.as_ref(), groups)
}

/// Flatten recipient bundles while enforcing global identity-key ownership.
/// Per-name dedup is insufficient because two cert-owned directories can carry
/// the same public device bundle. Sealing twice from one ratchet state would
/// reuse its nonce, including when the duplicate crosses a SLOTS chunk boundary.
fn unique_destination_devices(
    engine: &dyn Engine,
    groups: Vec<(String, Vec<Value>)>,
) -> Result<Vec<Value>, String> {
    let mut owners: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut out = Vec::new();
    for (xid, bundles) in groups {
        for bundle in bundles {
            let Some(ik) = engine.sender_ik(&bundle).map(hex::encode) else {
                continue;
            };
            if let Some(owner) = owners.get(&ik) {
                if owner != &xid {
                    return Err(format!(
                        "channel device key is published under both {owner} and {xid}"
                    ));
                }
                continue;
            }
            owners.insert(ik, xid.clone());
            out.push(bundle);
        }
    }
    Ok(out)
}

/// Uniform-ish `0..n` from the crypt RNG (8 bytes big-endian mod n); `n == 0` → 0.
/// Jitter is a privacy timing knob, not a cryptographic primitive, so a modulo
/// draw is fine.
fn rand_u64_below(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let bytes = hex::decode(epix_crypt::new_seed()).unwrap_or_default();
    let r = bytes.iter().take(8).fold(0u64, |acc, &b| (acc << 8) | b as u64);
    r % n
}

/// A random inter-record burst gap in `1..=max_secs`; `max_secs == 0` → 0 (the
/// caller disables jitter).
fn jitter_gap_secs(max_secs: u64) -> u64 {
    if max_secs == 0 {
        return 0;
    }
    1 + rand_u64_below(max_secs)
}

/// The max per-record burst-jitter gap (seconds); default 60, `0` disables. Only
/// spaces the SECOND-and-later records of a >SLOTS multi-record send.
async fn burst_jitter_max_secs(state: &Arc<AppState>) -> u64 {
    state
        .config_get("channel_burst_jitter_max_secs")
        .await
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
        .unwrap_or(60)
}

/// The max whole-send origin-jitter delay (seconds); default `0` (off — Tor-Always
/// is the primary send-origin mitigation). When set, the ENTIRE pool injection is
/// delayed by a random `0..=max` and fully detached from the send handler, so a
/// directly-connected clearnet peer can't bind "user pressed send" to "node
/// injected a record". Recommended on non-Tor deployments.
async fn send_jitter_max_secs(state: &Arc<AppState>) -> u64 {
    state
        .config_get("channel_send_jitter_max_secs")
        .await
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
        .unwrap_or(0)
}

async fn validate_legacy_outbound(
    state: &Arc<AppState>,
    ms: &ChannelState,
    pending: &PendingOutbound,
    record: &Value,
    rule: &epix_content::pool::PoolRule,
) -> Result<(), String> {
    let shard_path = state.pool_shard_for_record(&ms.xite, record).await?;
    let epoch = record
        .get("epoch")
        .and_then(Value::as_i64)
        .ok_or("queued channel record has no epoch")?;
    epix_content::pool::verify_pool_record(
        record,
        rule,
        epix_content::pool::week_of(epoch),
        now_ms(),
    )
    .map_err(|error| {
        format!(
            "legacy queued record needs unavailable recovery material under the current pool: {error:?}"
        )
    })?;
    if shard_path != pending.shard_path {
        return Err(
            "legacy queued record needs unavailable recovery material after a route change".into(),
        );
    }
    Ok(())
}

fn recovered_record_material(
    record: &Value,
    recovery: &epix_envelope::OutboundRecovery,
) -> Result<(i64, Vec<u8>), String> {
    let author = record
        .get("author")
        .and_then(Value::as_str)
        .ok_or("queued channel record has no author")?;
    let recovered_author = epix_crypt::privatekey_to_address(&recovery.author_private_key)
        .map_err(|error| format!("queued channel recovery key is invalid: {error}"))?;
    if recovered_author != author {
        return Err("queued channel recovery key does not match its anonymous author".into());
    }
    let epoch = record
        .get("epoch")
        .and_then(Value::as_i64)
        .ok_or("queued channel record has no epoch")?;
    let ct_b64 = record
        .get("ct")
        .and_then(Value::as_str)
        .ok_or("queued channel record has no ciphertext")?;
    let ct = base64::engine::general_purpose::STANDARD
        .decode(ct_b64)
        .map_err(|_| "queued channel record has invalid ciphertext".to_string())?;
    Ok((epoch, ct))
}

async fn refresh_recovered_rln(
    state: &Arc<AppState>,
    ms: &ChannelState,
    rule: &epix_content::pool::PoolRule,
    record: &mut Value,
    recovery: &mut epix_envelope::OutboundRecovery,
    epoch: i64,
    ct: &[u8],
) -> Result<bool, String> {
    if !rule.rln_required {
        return Ok(record
            .as_object_mut()
            .and_then(|object| object.remove("rln"))
            .is_some());
    }
    let admission = state
        .capability::<crate::rln::RlnAdmission>(crate::rln::RLN_CAP)
        .ok_or("this pool requires RLN but no admission gate is loaded")?;
    let auth = state.user_auth_address(&ms.xite).await?;
    let seed = state.derive_consumer_seed("rln", &auth).await;
    let identity = epix_rln::RlnIdentity::from_seed(&seed);
    let _transaction = admission.send_transaction(&ms.xite).await;
    let current_root = admission.current_root(&ms.xite)?;
    if let Some(reservation) = recovery.rln.as_mut() {
        let proof_is_current = reservation.root == Some(current_root) && record.get("rln").is_some();
        if proof_is_current {
            return Ok(false);
        }
        let proof = admission.reprove_reserved(&ms.xite, &identity, epoch, ct, reservation)?;
        record["rln"] = json!(base64::engine::general_purpose::STANDARD.encode(proof));
        reservation.root = Some(current_root);
        return Ok(true);
    }
    let reserved = admission.reserve_proof(&ms.xite, &identity, epoch, ct)?;
    record["rln"] = json!(base64::engine::general_purpose::STANDARD.encode(reserved.proof));
    recovery.rln = Some(reserved.reservation);
    Ok(true)
}

async fn solve_recovered_record(
    mut record: Value,
    target_work: u32,
    signing_key: String,
) -> Result<Value, String> {
    tokio::task::spawn_blocking(move || -> Result<Value, String> {
        epix_content::pool::solve_pow(&mut record, target_work);
        record["sign"] = json!(epix_crypt::sign(
            &epix_content::record_signed_data(&record),
            &signing_key,
        )?);
        Ok(record)
    })
    .await
    .map_err(|error| format!("queued channel PoW task failed: {error}"))?
}

fn persist_recovered_representation(
    ms: &ChannelState,
    pending: &PendingOutbound,
    record: &Value,
    shard_path: &str,
    recovery: &epix_envelope::OutboundRecovery,
    representation_changed: bool,
) -> Result<(), String> {
    if representation_changed
        || record != &pending.record
        || shard_path != pending.shard_path
        || pending.last_error.is_some()
    {
        ms.db
            .replace_outbound_record(pending.outbox_id, record, shard_path, recovery)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Rebuild the transport representation of one immutable queued ciphertext for
/// the current pool rule. This may move the route, increase PoW after a capacity
/// rejection, or replace an expired RLN proof while reusing the exact durable
/// unit allocation. It never reseals the pairwise payload or advances a ratchet.
async fn recover_outbound_representation(
    state: &Arc<AppState>,
    ms: &ChannelState,
    pending: &PendingOutbound,
) -> Result<PendingOutbound, String> {
    let rule = state
        .pool_rules_for(&ms.xite)
        .await
        .into_iter()
        .next()
        .ok_or("this xite has no pool configured")?;
    let mut record = pending.record.clone();
    let original_work = epix_content::pool::record_work_bits(&record);
    let mut recovery = pending.recovery.clone();
    if recovery.author_private_key.is_empty() {
        validate_legacy_outbound(state, ms, pending, &record, &rule).await?;
        return Ok(pending.clone());
    }
    let (epoch, ct) = recovered_record_material(&record, &recovery)?;
    let representation_changed =
        refresh_recovered_rln(state, ms, &rule, &mut record, &mut recovery, epoch, &ct).await?;

    let capacity_retry = pending
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("capacity") || error.contains("evicted"));
    let strengthen = capacity_retry || representation_changed;
    let target_work = rule
        .pow_bits
        .max(original_work.saturating_add(u32::from(strengthen)));
    record = solve_recovered_record(record, target_work, recovery.author_private_key.clone()).await?;

    epix_content::pool::verify_pool_record(
        &record,
        &rule,
        epix_content::pool::week_of(epoch),
        now_ms(),
    )
    .map_err(|error| {
        format!("queued channel record is incompatible with the current pool: {error:?}")
    })?;
    let shard_path = state.pool_shard_for_record(&ms.xite, &record).await?;
    persist_recovered_representation(
        ms,
        pending,
        &record,
        &shard_path,
        &recovery,
        representation_changed,
    )?;

    let mut recovered = pending.clone();
    recovered.record = record;
    recovered.shard_path = shard_path;
    recovered.recovery = recovery;
    recovered.last_error = None;
    Ok(recovered)
}

/// Append one durable-outbox record and acknowledge it only after its current
/// recoverable representation survives the local merge and a peer confirms it.
/// If acknowledgement itself fails, the row remains and a later retry safely
/// merges the same logical ciphertext again.
fn confirmation_retry_error(
    pending: &PendingOutbound,
    confirmation: &epix_ui::pool::PoolAppendConfirmation,
) -> Option<String> {
    if pending.recovery.author_private_key.is_empty() {
        return None;
    }
    match confirmation {
        epix_ui::pool::PoolAppendConfirmation::Stable { .. } => None,
        epix_ui::pool::PoolAppendConfirmation::RouteChangedAfterPeerConfirmation { .. } => Some(
            "pool route changed after peer confirmation; recoverable row will migrate on retry"
                .into(),
        ),
        epix_ui::pool::PoolAppendConfirmation::LocalPostconditionFailedAfterPeerConfirmation {
            reason,
            ..
        } => Some(reason.clone()),
    }
}

async fn append_outbound(
    state: &Arc<AppState>,
    ms: &ChannelState,
    pending: &PendingOutbound,
) -> Result<(), String> {
    if !ms
        .rln_usage_ready
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err("RLN usage reconciliation is incomplete; channel outbox remains queued".into());
    }
    let pending = recover_outbound_representation(state, ms, pending).await?;
    let cleanup_shards = ms
        .db
        .outbound_route_cleanup(pending.outbox_id)
        .map_err(|error| error.to_string())?;
    let confirmation = state
        .clone()
        .append_pool_record_confirmed_migrating_status(
            &ms.xite,
            &pending.shard_path,
            pending.record.clone(),
            &cleanup_shards,
        )
        .await?;
    if let Some(error) = confirmation_retry_error(&pending, &confirmation) {
        return Err(error);
    }
    ms.db
        .ack_outbound(pending.outbox_id)
        .map_err(|e| e.to_string())
}

/// Deliver every dependency-ready row. A failure retains and backs off that
/// exact row. Later rows sharing any conversation/device leg remain blocked by
/// the database query, while unrelated conversations continue.
async fn deliver_due_outbox(state: &Arc<AppState>, ms: &ChannelState) -> Result<(), String> {
    let _guard = ms.delivery_lock.lock().await;
    let due = {
        // Snapshot eligible rows while staging is excluded, then release this
        // lock before any disk merge or peer dial. A just-committed row cannot
        // become visible between its SQLite commit and RLN usage finalization.
        let _staging_guard = ms.outbox_lock.lock().await;
        if !ms
            .rln_usage_ready
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(
                "RLN usage reconciliation is incomplete; channel outbox remains queued".into(),
            );
        }
        ms.db
            .due_outbound_prefix(now_ms(), 128)
            .map_err(|e| e.to_string())?
    };
    let mut first_error = None;
    for pending in due {
        if let Err(e) = append_outbound(state, ms, &pending).await {
            let retry_at = now_ms() + OUTBOX_RETRY_INTERVAL.as_millis() as i64;
            ms.db
                .reschedule_outbound_error(pending.outbox_id, retry_at, Some(&e))
                .map_err(|db| format!("{e}; could not reschedule outbox row: {db}"))?;
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

async fn pending_outbound_through_ready(
    ms: &ChannelState,
    outbox_id: i64,
) -> Result<Vec<PendingOutbound>, String> {
    let _staging_guard = ms.outbox_lock.lock().await;
    if !ms
        .rln_usage_ready
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Err("RLN usage reconciliation is incomplete; channel outbox remains queued".into());
    }
    ms.db
        .pending_outbound_through(outbox_id)
        .map_err(|error| error.to_string())
}

async fn deliver_outbound_rows(
    state: &Arc<AppState>,
    ms: &ChannelState,
    rows: Vec<PendingOutbound>,
    first_error: &mut Option<String>,
) -> Result<(), String> {
    for row in rows {
        if let Err(error) = append_outbound(state, ms, &row).await {
            let retry_at = now_ms() + OUTBOX_RETRY_INTERVAL.as_millis() as i64;
            ms.db
                .reschedule_outbound_error(row.outbox_id, retry_at, Some(&error))
                .map_err(|db| format!("{error}; could not reschedule outbox row: {db}"))?;
            if first_error.is_none() {
                *first_error = Some(error);
            }
        }
    }
    Ok(())
}

fn first_delivery_result(
    ms: &ChannelState,
    pending: &PendingOutbound,
    first_error: Option<String>,
) -> Result<(), String> {
    if ms
        .db
        .outbound_pending(pending.outbox_id)
        .map_err(|error| error.to_string())?
    {
        return Err(first_error.unwrap_or_else(|| {
            format!(
                "channel send is queued behind an older dependency or future deadline for outbox row {}",
                pending.outbox_id
            )
        }));
    }
    Ok(())
}

/// Preserve the historical no-origin-jitter behavior by surfacing the first
/// append error to the command caller. The row remains durable on failure.
async fn deliver_first_now(
    state: &Arc<AppState>,
    ms: &ChannelState,
    pending: &PendingOutbound,
) -> Result<(), String> {
    let _guard = ms.delivery_lock.try_lock().map_err(|_| {
        "channel delivery worker is busy; the durably staged row remains queued".to_string()
    })?;
    let mut first_error = None;
    loop {
        let rows = pending_outbound_through_ready(ms, pending.outbox_id).await?;
        if rows.is_empty() {
            break;
        }
        deliver_outbound_rows(state, ms, rows, &mut first_error).await?;
    }
    first_delivery_result(ms, pending, first_error)
}

/// A send is already accepted once its batch committed to SQLite. Transport
/// failure after that point is reported as queued success so a client does not
/// retry the logical message and advance the ratchet twice.
async fn accepted_delivery_status(
    state: &Arc<AppState>,
    ms: &ChannelState,
    first: &PendingOutbound,
) -> &'static str {
    match deliver_first_now(state, ms, first).await {
        Ok(()) => "published",
        Err(e) => {
            state
                .log(
                    "WARN",
                    &format!("channel send accepted into durable queue: {e}"),
                )
                .await;
            "queued"
        }
    }
}

struct ChannelSendRequest {
    recipients: Vec<String>,
    subject: String,
    body: String,
    conv_hint: Option<[u8; 16]>,
}

struct LocalChannelSender {
    identity_id: i64,
    secret: IdentitySecret,
    xid: String,
}

#[derive(Clone)]
struct ChannelRlnSendContext {
    admission: Arc<crate::rln::RlnAdmission>,
    seed: Vec<u8>,
    address: String,
}

#[derive(Clone)]
struct ChannelSealContext {
    db: Arc<ChannelDb>,
    engine: Arc<dyn Engine>,
    identity_id: i64,
    secret: IdentitySecret,
    sender_xid: String,
    members: Vec<String>,
    conv: [u8; 16],
    subject: String,
    body: String,
    rule: epix_content::pool::PoolRule,
    chunk_count: usize,
    rln: Option<ChannelRlnSendContext>,
    rln_batch: Option<crate::rln::RlnReservationBatch>,
    rln_preflight_done: Arc<std::sync::atomic::AtomicBool>,
}

struct ChannelChunkSeal {
    context: ChannelSealContext,
    destinations: Vec<epix_envelope::Dest>,
    record_own: bool,
    now_ms: i64,
    scheduled_ms: i64,
}

fn parse_channel_send_request(p: &Value) -> Result<ChannelSendRequest, String> {
    let values = p
        .as_array()
        .ok_or("channelSend: [recipients, subject, body, conv_id?]")?;
    let recipients = values
        .first()
        .and_then(Value::as_array)
        .map(|items| normalized_recipients(items))
        .unwrap_or_default();
    if recipients.is_empty() {
        return Err("channelSend: at least one recipient required".into());
    }
    let conv_hint = values
        .get(3)
        .and_then(Value::as_str)
        .and_then(|value| hex::decode(value).ok())
        .and_then(|bytes| bytes.try_into().ok());
    Ok(ChannelSendRequest {
        recipients,
        subject: values.get(1).and_then(Value::as_str).unwrap_or("").to_string(),
        body: values.get(2).and_then(Value::as_str).unwrap_or("").to_string(),
        conv_hint,
    })
}

async fn local_sender_snapshot(
    state: &Arc<AppState>,
    xid: &str,
) -> Option<epix_chain::XidIdentitySnapshot> {
    match state.xid_identity_snapshot(xid).await {
        Ok(Some(snapshot)) if norm_xid(&snapshot.canonical_name) == norm_xid(xid) => Some(snapshot),
        Ok(Some(_)) | Ok(None) => None,
        Err(error) => {
            state
                .log(
                    "WARN",
                    &format!("local xID identity snapshot unavailable: {error}"),
                )
                .await;
            None
        }
    }
}

async fn validated_local_sender(
    state: &Arc<AppState>,
    ms: &ChannelState,
) -> Result<LocalChannelSender, String> {
    let (identity_id, secret, xid, auth) = channel_identity(state, ms).await?;
    let snapshot = local_sender_snapshot(state, &xid).await;
    let active_addrs: Vec<String> = snapshot
        .as_ref()
        .map(|value| {
            value
                .identities
                .iter()
                .filter(|identity| identity.status == epix_chain::XidIdentityStatus::Active)
                .map(|identity| identity.auth_address.clone())
                .collect()
        })
        .unwrap_or_default();
    let name_active = snapshot.as_ref().map(|_| !active_addrs.is_empty());
    if snapshot.as_ref().is_some_and(|value| {
        value.status_for(&auth) == Some(epix_chain::XidIdentityStatus::Revoked)
    }) {
        ms.db
            .remember_revoked_device(&norm_xid(&xid), Some(&auth), "", now_ms())
            .map_err(|error| error.to_string())?;
    }
    let tombstoned = ms
        .db
        .is_device_revoked(&norm_xid(&xid), Some(&auth), "")
        .map_err(|error| error.to_string())?;
    ensure_local_sender_active(&xid, &auth, tombstoned, name_active, &active_addrs)?;
    Ok(LocalChannelSender {
        identity_id,
        secret,
        xid,
    })
}

fn channel_conversation_members(recipients: &[String], sender_xid: &str) -> Vec<String> {
    let mut members = recipients.to_vec();
    members.push(norm_xid(sender_xid));
    members.sort();
    members.dedup();
    members
}

async fn channel_rln_send_context(
    state: &Arc<AppState>,
    ms: &ChannelState,
    rule: &epix_content::pool::PoolRule,
) -> Result<Option<ChannelRlnSendContext>, String> {
    if !rule.rln_required {
        return Ok(None);
    }
    let admission = state.capability::<crate::rln::RlnAdmission>(crate::rln::RLN_CAP);
    let auth = state.user_auth_address(&ms.xite).await.ok();
    let (Some(admission), Some(auth)) = (admission, auth) else {
        return Err("this pool requires RLN but no membership is available".into());
    };
    let seed = state.derive_consumer_seed("rln", &auth).await.to_vec();
    Ok(Some(ChannelRlnSendContext {
        admission,
        seed,
        address: ms.xite.clone(),
    }))
}

fn seal_channel_chunk_without_rln(
    input: &ChannelChunkSeal,
) -> Result<epix_envelope::PreparedSend, String> {
    let context = &input.context;
    epix_envelope::prepare_multi_scheduled(
        context.db.as_ref(),
        context.engine.as_ref(),
        context.identity_id,
        &context.secret,
        &context.sender_xid,
        &context.members,
        &input.destinations,
        context.conv,
        &context.subject,
        &context.body,
        input.now_ms,
        input.scheduled_ms,
        &context.rule,
        input.record_own,
    )
    .map_err(|error| error.to_string())
}

fn seal_channel_chunk_with_rln(
    input: &ChannelChunkSeal,
    rln: &ChannelRlnSendContext,
    batch: &crate::rln::RlnReservationBatch,
) -> Result<epix_envelope::PreparedSend, String> {
    let context = &input.context;
    let identity = epix_rln::RlnIdentity::from_seed(&rln.seed);
    let prover = |ct: &[u8], epoch: i64| {
        if !context
            .rln_preflight_done
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let smallest = context.rule.pad_buckets.first().copied().unwrap_or(1);
            let weight = epix_rln::bucket_weight(ct.len(), smallest);
            let total = weight.saturating_mul(context.chunk_count as u32);
            let (used, limit) = rln
                .admission
                .usage(&rln.address, epoch.max(0) as u64)
                .ok_or("no RLN roster loaded for this pool")?;
            if used.saturating_add(total) > limit {
                return Err(format!(
                    "epoch allowance exhausted: send needs {total} units, {used}/{limit} already spent"
                ));
            }
        }
        rln.admission
            .reserve_proof_batched(batch, &rln.address, &identity, epoch, ct)
            .map(|reserved| epix_envelope::RlnProofMaterial {
                proof: reserved.proof,
                reservation: Some(reserved.reservation),
            })
    };
    epix_envelope::prepare_multi_with_rln_reserved_scheduled(
        context.db.as_ref(),
        context.engine.as_ref(),
        context.identity_id,
        &context.secret,
        &context.sender_xid,
        &context.members,
        &input.destinations,
        context.conv,
        &context.subject,
        &context.body,
        input.now_ms,
        input.scheduled_ms,
        &context.rule,
        input.record_own,
        &prover,
    )
    .map_err(|error| error.to_string())
}

fn seal_channel_chunk_blocking(
    input: ChannelChunkSeal,
) -> Result<epix_envelope::PreparedSend, String> {
    if let Some(rln) = &input.context.rln {
        let batch = input
            .context
            .rln_batch
            .as_ref()
            .ok_or("missing RLN reservation batch")?;
        seal_channel_chunk_with_rln(&input, rln, batch)
    } else {
        seal_channel_chunk_without_rln(&input)
    }
}

async fn prepare_channel_chunk(
    context: ChannelSealContext,
    chunk: &[Value],
    record_own: bool,
    scheduled_ms: i64,
) -> Result<epix_envelope::PreparedSend, String> {
    let destinations = chunk
        .iter()
        .map(|bundle| epix_envelope::Dest {
            bundle: bundle.clone(),
        })
        .collect();
    let input = ChannelChunkSeal {
        context,
        destinations,
        record_own,
        now_ms: now_ms(),
        scheduled_ms,
    };
    tokio::task::spawn_blocking(move || seal_channel_chunk_blocking(input))
        .await
        .map_err(|error| format!("channelSend seal task failed: {error}"))?
}

fn validate_prepared_record_sizes(
    prepared: &[epix_envelope::PreparedSend],
    max_shard_bytes: usize,
) -> Result<(), String> {
    for prepared_record in prepared {
        let singleton = epix_content::pool::make_pool_container(vec![prepared_record
            .commit
            .record
            .clone()]);
        let encoded = serde_json::to_vec(&singleton)
            .map_err(|error| format!("could not size channel pool record: {error}"))?;
        if encoded.len() > max_shard_bytes {
            return Err(format!(
                "channel record cannot fit the pool shard limit ({} > {})",
                encoded.len(),
                max_shard_bytes
            ));
        }
    }
    Ok(())
}

async fn finalize_rln_send_batch(
    state: &Arc<AppState>,
    ms: &ChannelState,
    batch: Option<&crate::rln::RlnReservationBatch>,
) {
    let Some(batch) = batch else { return };
    if let Err(error) = batch.commit() {
        ms.rln_usage_ready
            .store(false, std::sync::atomic::Ordering::Release);
        state
            .log(
                "ERROR",
                &format!("could not finalize RLN usage reservation: {error}"),
            )
            .await;
    }
}

async fn stage_prepared_outbound(
    state: &Arc<AppState>,
    ms: &ChannelState,
    rule: &epix_content::pool::PoolRule,
    prepared: Vec<epix_envelope::PreparedSend>,
    rln_batch: Option<&crate::rln::RlnReservationBatch>,
) -> Result<Vec<PendingOutbound>, String> {
    validate_prepared_record_sizes(&prepared, rule.max_shard_bytes)?;
    let commits: Vec<_> = prepared.iter().map(|value| value.commit.clone()).collect();
    let staged = ms
        .db
        .commit_outbound_batch(&commits)
        .map_err(|error| error.to_string())?;
    finalize_rln_send_batch(state, ms, rln_batch).await;
    Ok(prepared
        .into_iter()
        .zip(staged)
        .map(|(prepared, (outbox_id, _msg_id))| PendingOutbound {
            outbox_id,
            record: prepared.commit.record,
            shard_path: prepared.commit.shard_path,
            created_ms: prepared.commit.created_ms,
            next_attempt_ms: prepared.commit.next_attempt_ms,
            recovery: prepared.commit.recovery,
            last_error: None,
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
async fn prepare_outbound_records(
    state: &Arc<AppState>,
    ms: &ChannelState,
    sender: LocalChannelSender,
    request: &ChannelSendRequest,
    members: Vec<String>,
    destinations: &[Value],
    conv: [u8; 16],
    rule: epix_content::pool::PoolRule,
    rln: Option<ChannelRlnSendContext>,
    burst_jitter: u64,
    mut next_attempt_ms: i64,
) -> Result<Vec<PendingOutbound>, String> {
    let _send_guard = ms.send_lock.lock().await;
    let rln_batch = match &rln {
        Some(context) => Some(context.admission.reservation_batch(&ms.xite).await),
        None => None,
    };
    let context = ChannelSealContext {
        db: ms.db.clone(),
        engine: ms.engine.clone(),
        identity_id: sender.identity_id,
        secret: sender.secret,
        sender_xid: sender.xid,
        members,
        conv,
        subject: request.subject.clone(),
        body: request.body.clone(),
        rule: rule.clone(),
        chunk_count: destinations.len().div_ceil(epix_envelope::SLOTS),
        rln,
        rln_batch: rln_batch.clone(),
        rln_preflight_done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let mut prepared = Vec::new();
    for (chunk_index, chunk) in destinations.chunks(epix_envelope::SLOTS).enumerate() {
        if chunk_index > 0 {
            next_attempt_ms += jitter_gap_secs(burst_jitter).saturating_mul(1000) as i64;
        }
        prepared.push(
            prepare_channel_chunk(
                context.clone(),
                chunk,
                chunk_index == 0,
                next_attempt_ms,
            )
            .await?,
        );
    }
    stage_prepared_outbound(state, ms, &rule, prepared, rln_batch.as_ref()).await
}

async fn immediate_channel_delivery(
    state: &Arc<AppState>,
    ms: &ChannelState,
    records: &[PendingOutbound],
    send_jitter: u64,
) -> &'static str {
    if send_jitter != 0 {
        return "queued";
    }
    match records.last() {
        Some(last) => accepted_delivery_status(state, ms, last).await,
        None => "queued",
    }
}

async fn execute_channel_send(s: &WsSession, p: &Value) -> Result<Value, String> {
    let ms = channel_state(s)?;
    let request = parse_channel_send_request(p)?;
    let sender = validated_local_sender(&s.state, &ms).await?;
    let conv = request.conv_hint.unwrap_or_else(epix_envelope::new_conv_id);
    let members = channel_conversation_members(&request.recipients, &sender.xid);
    let published =
        load_published_bundles(&s.state, &ms.xite, ms.engine.as_ref(), &ms.db).await?;
    let destinations = resolve_destinations(&ms, &request.recipients, &published).await?;

    let _staging_outbox_guard = channel_staging_guard(&ms).await?;
    let _rule_transaction = s.state.pool_rule_transaction(&ms.xite).await;
    let rule = s
        .state
        .pool_rules_for(&ms.xite)
        .await
        .into_iter()
        .next()
        .ok_or("this xite has no pool configured")?;
    let rln = channel_rln_send_context(&s.state, &ms, &rule).await?;
    let send_jitter = send_jitter_max_secs(&s.state).await;
    let burst_jitter = burst_jitter_max_secs(&s.state).await;
    let origin_delay = if send_jitter == 0 {
        0
    } else {
        rand_u64_below(send_jitter + 1)
    };
    let next_attempt_ms = now_ms() + origin_delay.saturating_mul(1000) as i64;
    let records = prepare_outbound_records(
        &s.state,
        &ms,
        sender,
        &request,
        members,
        &destinations,
        conv,
        rule,
        rln,
        burst_jitter,
        next_attempt_ms,
    )
    .await?;
    drop(_rule_transaction);
    drop(_staging_outbox_guard);

    let delivery = immediate_channel_delivery(&s.state, &ms, &records, send_jitter).await;
    Ok(json!({
        "ok": true,
        "conv_id": hex::encode(conv),
        "recipients": request.recipients.len(),
        "envelopes": records.len(),
        "delivery": delivery,
    }))
}

struct ChannelSend;
#[async_trait]
impl WsCommand for ChannelSend {
    fn name(&self) -> &'static str {
        "channelSend"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        execute_channel_send(s, p).await
    }
}

struct ChannelThreads;
#[async_trait]
impl WsCommand for ChannelThreads {
    fn name(&self) -> &'static str {
        "channelThreads"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let id = identity_id(&ms)?;
        let o = p.as_array().and_then(|a| a.first());
        let folder = o.and_then(|v| v.get("folder")).and_then(|v| v.as_str()).unwrap_or("all");
        let offset = o.and_then(|v| v.get("offset")).and_then(|v| v.as_i64()).unwrap_or(0);
        let limit = o.and_then(|v| v.get("limit")).and_then(|v| v.as_i64()).unwrap_or(50);
        let rows = ms.db.threads(id, folder, offset, limit).map_err(|e| e.to_string())?;
        Ok(json!({ "threads": rows }))
    }
}

struct ChannelConversation;
#[async_trait]
impl WsCommand for ChannelConversation {
    fn name(&self) -> &'static str {
        "channelConversation"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let id = identity_id(&ms)?;
        let conv = p
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("conv_id").or(Some(v)))
            .and_then(|v| v.as_str())
            .ok_or("channelConversation: conv_id required")?;
        let rows = ms.db.messages(id, conv).map_err(|e| e.to_string())?;
        Ok(json!({ "messages": rows }))
    }
}

struct ChannelSearch;
#[async_trait]
impl WsCommand for ChannelSearch {
    fn name(&self) -> &'static str {
        "channelSearch"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let id = identity_id(&ms)?;
        let a = p.as_array();
        let query = a.and_then(|a| a.first()).and_then(|v| v.as_str()).ok_or("channelSearch: query required")?;
        let limit = a.and_then(|a| a.get(1)).and_then(|v| v.as_i64()).unwrap_or(100);
        let rows = ms.db.search(id, query, limit).map_err(|e| e.to_string())?;
        Ok(json!({ "results": rows }))
    }
}

struct ChannelMarkRead;
#[async_trait]
impl WsCommand for ChannelMarkRead {
    fn name(&self) -> &'static str {
        "channelMarkRead"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let id = identity_id(&ms)?;
        let a = p.as_array();
        let conv = a.and_then(|a| a.first()).and_then(|v| v.as_str()).ok_or("channelMarkRead: conv_id required")?;
        let read = a.and_then(|a| a.get(1)).and_then(|v| v.as_bool()).unwrap_or(true);
        ms.db.mark_read(id, conv, read).map_err(|e| e.to_string())?;
        Ok(json!({ "ok": true }))
    }
}

struct ChannelSetConvState;
#[async_trait]
impl WsCommand for ChannelSetConvState {
    fn name(&self) -> &'static str {
        "channelSetConvState"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let id = identity_id(&ms)?;
        let a = p.as_array().ok_or("channelSetConvState: [conv_id, {starred?, archived?}]")?;
        let conv = a.first().and_then(|v| v.as_str()).ok_or("channelSetConvState: conv_id required")?;
        let opts = a.get(1);
        let starred = opts.and_then(|v| v.get("starred")).and_then(|v| v.as_bool());
        let archived = opts.and_then(|v| v.get("archived")).and_then(|v| v.as_bool());
        ms.db.set_conv_state(id, conv, starred, archived).map_err(|e| e.to_string())?;
        Ok(json!({ "ok": true }))
    }
}

struct ChannelDeleteLocal;
#[async_trait]
impl WsCommand for ChannelDeleteLocal {
    fn name(&self) -> &'static str {
        "channelDeleteLocal"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let id = identity_id(&ms)?;
        let conv = p.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()).ok_or("channelDeleteLocal: conv_id required")?;
        ms.db.delete_conversation(id, conv).map_err(|e| e.to_string())?;
        Ok(json!({ "ok": true }))
    }
}

struct ChannelMigrateLegacy;
#[async_trait]
impl WsCommand for ChannelMigrateLegacy {
    fn name(&self) -> &'static str {
        "channelMigrateLegacy"
    }
    async fn handle(&self, s: &WsSession, _p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let (identity_id, _secret, my_xid, _auth) = channel_identity(&s.state, &ms).await?;
        // The mail key (encrypt index 0) that decrypts legacy ECIES ciphertext
        // sealed to me — the same key the old site used via eciesDecrypt.
        let privkey = s.state.user_encrypt_privatekey(&ms.xite, 0).await?;

        // Gather every user's legacy messages.json currently on disk. Reading is
        // non-destructive; nothing on the shared site is modified or removed.
        let mut containers: Vec<Value> = Vec::new();
        for path in s.state.list_xite_files(&ms.xite).await {
            if path.starts_with("data/users/") && path.ends_with("/messages.json") {
                if let Some(bytes) = s.state.read_xite_file(&ms.xite, &path).await {
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        containers.push(v);
                    }
                }
            }
        }

        // Decrypt + insert off the async runtime (one ECIES open per candidate).
        let db = (*ms.db).clone();
        let report = tokio::task::spawn_blocking(move || {
            epix_channel::legacy::import_legacy_containers(&db, identity_id, &my_xid, &privkey, &containers)
        })
        .await
        .map_err(|e| format!("channelMigrateLegacy task failed: {e}"))?;

        // Refresh the badge if anything landed, and let the page reload threads.
        if report.imported > 0 {
            s.state.push_site_event(
                &ms.xite,
                "channelEvent",
                json!({ "type": "migrated", "imported": report.imported }),
            );
        }
        Ok(json!({
            "imported": report.imported,
            "skipped": report.skipped,
            "scanned": report.scanned,
        }))
    }
}

#[cfg(test)]
mod multi_device_tests {
    use super::{
        bundle_filename_matches_auth, bundle_path_parts, bundle_xid_matches_directory,
        device_bundle_file, ensure_local_sender_active, normalized_recipients,
        refine_device_bundles, unique_destination_devices,
    };
    use epix_envelope::{Engine, FakeEngine, IdentitySecret, SLOTS};
    use serde_json::{json, Value};

    #[test]
    fn device_filename_is_regex_safe() {
        // bech32 stays as-is; any stray char is stripped so it matches the
        // site's `data-[0-9a-z]+\.json` permission rule.
        // A real lowercase bech32 address passes through unchanged.
        assert_eq!(device_bundle_file("epix1abc0"), "data-epix1abc0.json");
        // Any path-traversal / non-[0-9a-z] char is stripped (defense in depth).
        assert_eq!(device_bundle_file("epix1abc/../x"), "data-epix1abcx.json");
    }

    #[tokio::test]
    async fn retained_index_retry_does_not_stop_after_five_failures() {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let observed = attempts.clone();
        super::run_persistent_retry(move |_| {
            let observed = observed.clone();
            async move { observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 6 }
        })
        .await;
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 7);
    }

    #[tokio::test]
    async fn transient_rln_reconciliation_retries_until_staging_is_ready() {
        let ready = std::sync::atomic::AtomicBool::new(false);
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let observed = attempts.clone();
        super::run_rln_reconcile_retry(&ready, move || {
            let observed = observed.clone();
            async move {
                if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                    Err("transient ledger read failure".to_string())
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(ready.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn duplicate_recipient_names_are_sealed_once() {
        let recipients = vec![json!("bob"), json!("bob.epix"), json!("alice")];
        assert_eq!(
            normalized_recipients(&recipients),
            vec!["alice.epix".to_string(), "bob.epix".to_string()]
        );
    }

    #[test]
    fn conflicting_device_key_is_rejected_across_slot_boundary() {
        let engine = FakeEngine;
        let mut alice = Vec::new();
        for i in 0..SLOTS {
            alice.push(
                engine.publish_bundle(&IdentitySecret::new([(i + 1) as u8; 32]), "alice.epix"),
            );
        }
        let mut copied = alice[0].clone();
        copied["xid"] = json!("mallory.epix");
        let err = unique_destination_devices(
            &engine,
            vec![
                ("alice.epix".into(), alice),
                ("mallory.epix".into(), vec![copied]),
            ],
        )
        .unwrap_err();
        assert!(err.contains("both alice.epix and mallory.epix"));
    }

    #[test]
    fn bundle_path_parts_matches_data_and_per_device() {
        assert_eq!(bundle_path_parts("data/users/mud.epix/data.json"), Some(("mud.epix", "data.json")));
        assert_eq!(
            bundle_path_parts("data/users/mud.epix/data-epix1x.json"),
            Some(("mud.epix", "data-epix1x.json"))
        );
        // Not a bundle file / not directly under a user dir.
        assert_eq!(bundle_path_parts("data/users/mud.epix/content.json"), None);
        assert_eq!(bundle_path_parts("data/users/mud.epix/sub/data.json"), None);
        assert_eq!(bundle_path_parts("content.json"), None);
    }

    #[test]
    fn signed_bundle_auth_is_bound_to_the_device_filename() {
        let valid = dev("epix1active", "IK-ACTIVE", 1);
        assert!(bundle_filename_matches_auth("data.json", &valid));
        assert!(bundle_filename_matches_auth(
            "data-epix1active.json",
            &valid
        ));
        assert!(!bundle_filename_matches_auth(
            "data-epix1someoneelse.json",
            &valid
        ));
    }

    #[test]
    fn valid_signature_does_not_make_a_noncanonical_bundle_name_acceptable() {
        let auth_key = epix_crypt::new_seed();
        let mut bundle = epix_pairwise_engine::keys::build_bundle(&[3u8; 32], "alice");
        bundle["auth"] = json!(epix_crypt::privatekey_to_address(&auth_key).unwrap());
        let payload = epix_pairwise_engine::keys::bundle_auth_payload(&bundle).unwrap();
        bundle["auth_sig"] = json!(epix_crypt::sign_keccak(&payload, &auth_key).unwrap());
        assert!(epix_pairwise_engine::keys::verify_bundle(&bundle));
        assert!(!bundle_xid_matches_directory(&bundle, "alice.epix"));
    }

    fn dev(auth: &str, ik: &str, spk_idx: u64) -> serde_json::Value {
        json!({ "v": 2, "xid": "mud.epix", "auth": auth, "ik": ik, "spk": "s", "spk_idx": spk_idx })
    }

    #[test]
    fn keeps_all_devices_when_active_set_indeterminate() {
        // Empty `active` = chain down / unregistered → fail open, keep both devices.
        let devs = vec![dev("epix1a", "IKA", 1), dev("epix1b", "IKB", 1)];
        let out = refine_device_bundles(devs, &[]);
        assert_eq!(out.len(), 2, "both devices kept when the active set is unknown");
    }

    #[test]
    fn drops_only_the_revoked_device() {
        // Device B's key was revoked; A stays. Per-device revocation.
        let devs = vec![dev("epix1a", "IKA", 1), dev("epix1b", "IKB", 1)];
        let out = refine_device_bundles(devs, &["epix1a".to_string()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["ik"], "IKA", "only the still-active device survives");
    }

    #[test]
    fn structural_device_filter_is_not_the_v3_authentication_gate() {
        // This helper only filters a set that load_published_bundles has already
        // authenticated through PairwiseEngine. It deliberately does not repeat
        // v3 auth checks. An unsigned legacy value survives this narrow helper
        // but is rejected before reaching it in production.
        let legacy = json!({ "v": 2, "xid": "mud.epix", "ik": "IKL", "spk": "s", "spk_idx": 3 });
        let out = refine_device_bundles(vec![legacy], &["epix1a".to_string()]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn dedups_same_ik_keeping_freshest_spk() {
        // Same device published as legacy `data.json` (spk 1) and `data-<auth>.json`
        // (spk 5). Collapse to one, keeping the newer prekey.
        let devs = vec![dev("epix1a", "IKA", 1), dev("epix1a", "IKA", 5)];
        let out = refine_device_bundles(devs, &[]);
        assert_eq!(out.len(), 1, "duplicate IK collapsed");
        assert_eq!(out[0]["spk_idx"], 5, "freshest prekey wins");
    }

    #[test]
    fn local_sender_revocation_is_definite_only() {
        let active = vec!["epix1mine".to_string()];
        assert!(
            ensure_local_sender_active("mud.epix", "epix1mine", false, Some(true), &active).is_ok()
        );
        assert!(
            ensure_local_sender_active("mud.epix", "epix1mine", false, None, &[]).is_ok(),
            "chain outage remains fail open"
        );
        assert!(
            ensure_local_sender_active("mud.epix", "epix1mine", false, Some(false), &[]).is_err()
        );
        assert!(
            ensure_local_sender_active("mud.epix", "epix1mine", true, None, &[]).is_err(),
            "a durable tombstone remains enforced during an outage"
        );
        assert!(
            ensure_local_sender_active(
                "mud.epix",
                "epix1revoked-device",
                false,
                Some(true),
                &active,
            )
            .is_err(),
            "a revoked local device cannot use a sibling's active name"
        );
    }

    #[tokio::test]
    async fn failed_or_zero_peer_publish_keeps_the_exact_outbox_row() {
        use base64::Engine as _;
        use epix_content::{pool, record_signed_data};
        use epix_ui::state::{AppState, XiteEntry};
        use epix_xite::XiteStorage;
        use std::sync::Arc;

        const XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("xite");
        std::fs::create_dir_all(&root).unwrap();
        let state = AppState::with_data_dir("channel-outbox-test", home.path());
        state
            .add_xite(
                XITE,
                XiteEntry {
                    storage: XiteStorage::new(&root),
                    content: Some(json!({
                        "address": XITE,
                        "pool": { "channels": {
                            "dir": "pool", "class": "epix-pool-1", "since_week": 0,
                            "fanout": 2, "pow_bits": 0, "pad_buckets": [64],
                            "max_record_bytes": 4096, "max_shard_bytes": 1_000_000
                        }}
                    })),
                },
            )
            .await;
        let rule = state.pool_rules_for(XITE).await.remove(0);
        let epoch = pool::epoch_now(super::now_ms());
        let tag = [7u8; 32];
        let key = epix_crypt::new_seed();
        let mut record = json!({
            "v": 1,
            "epoch": epoch,
            "tag": base64::engine::general_purpose::STANDARD.encode(tag),
            "ct": base64::engine::general_purpose::STANDARD.encode([8u8; 64]),
            "pow": 0,
            "author": epix_crypt::privatekey_to_address(&key).unwrap(),
        });
        record["sign"] = json!(epix_crypt::sign(&record_signed_data(&record), &key).unwrap());
        let shard = pool::shard_path(&rule, epoch, &tag);

        let db_path = home.path().join("private").join("channels.db");
        let db = Arc::new(epix_channel::ChannelDb::open(&db_path).unwrap());
        let (outbox_id, _) = db
            .commit_outbound(&epix_envelope::OutboundCommit {
                sessions: Vec::new(),
                record: record.clone(),
                shard_path: shard.clone(),
                created_ms: super::now_ms(),
                next_attempt_ms: super::now_ms(),
                recovery: epix_envelope::OutboundRecovery {
                    author_private_key: key,
                    rln: None,
                },
                sent: None,
            })
            .unwrap();
        let pending = db.pending_outbound(1).unwrap().remove(0);
        let channel = super::ChannelState {
            db: db.clone(),
            engine: Arc::new(FakeEngine),
            xite: XITE.into(),
            identity_id: std::sync::atomic::AtomicI64::new(0),
            send_lock: tokio::sync::Mutex::new(()),
            outbox_lock: tokio::sync::Mutex::new(()),
            delivery_lock: tokio::sync::Mutex::new(()),
            rln_usage_ready: std::sync::atomic::AtomicBool::new(true),
            index_retry: tokio::sync::Notify::new(),
        };

        let paused_delivery = channel.delivery_lock.lock().await;
        let staging = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            super::channel_staging_guard(&channel),
        )
        .await
        .expect("a paused peer push must not block staging")
        .unwrap();
        let (probe_id, _) = db
            .commit_outbound(&epix_envelope::OutboundCommit {
                sessions: Vec::new(),
                record: record.clone(),
                shard_path: shard.clone(),
                created_ms: super::now_ms(),
                next_attempt_ms: super::now_ms(),
                recovery: epix_envelope::OutboundRecovery {
                    author_private_key: epix_crypt::new_seed(),
                    rln: None,
                },
                sent: None,
            })
            .unwrap();
        assert!(db.outbound_pending(probe_id).unwrap());
        let probe = db
            .pending_outbound(usize::MAX)
            .unwrap()
            .into_iter()
            .find(|row| row.outbox_id == probe_id)
            .unwrap();
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                super::accepted_delivery_status(&state, &channel, &probe),
            )
            .await
            .expect("a second ChannelSend response must not wait for the paused peer push"),
            "queued"
        );
        assert!(
            db.outbound_pending(probe_id).unwrap(),
            "queued success keeps the exact staged row for the delivery worker"
        );
        db.ack_outbound(probe_id).unwrap();
        drop(staging);
        drop(paused_delivery);

        let original_work = pool::record_work_bits(&pending.record);
        channel
            .rln_usage_ready
            .store(false, std::sync::atomic::Ordering::Release);
        let staged_before = db.pending_outbound(usize::MAX).unwrap().len();
        assert!(super::channel_staging_guard(&channel).await.is_err());
        assert_eq!(
            db.pending_outbound(usize::MAX).unwrap().len(),
            staged_before
        );
        assert!(super::append_outbound(&state, &channel, &pending)
            .await
            .unwrap_err()
            .contains("reconciliation is incomplete"));
        assert!(
            !root.join(&shard).exists(),
            "startup cannot publish before provisional usage reconciliation"
        );
        channel
            .rln_usage_ready
            .store(true, std::sync::atomic::Ordering::Release);
        assert_eq!(
            super::accepted_delivery_status(&state, &channel, &pending).await,
            "queued"
        );
        assert!(root.join(&shard).is_file());
        let postconfirmation_eviction =
            epix_ui::pool::PoolAppendConfirmation::LocalPostconditionFailedAfterPeerConfirmation {
                staged_shard: shard.clone(),
                reason: "exact outbound record was evicted during publication".into(),
            };
        let eviction_error = super::confirmation_retry_error(&pending, &postconfirmation_eviction)
            .expect("a modern row keeps retryable recovery state");
        assert!(eviction_error.contains("evicted"));
        db.reschedule_outbound_error(outbox_id, super::now_ms(), Some(&eviction_error))
            .unwrap();
        state
            .add_xite(
                XITE,
                XiteEntry {
                    storage: XiteStorage::new(&root),
                    content: Some(json!({
                        "address": XITE,
                        "pool": { "channels": {
                            "dir": "pool", "class": "epix-pool-1", "since_week": 0,
                            "fanout": 4, "pow_bits": 0, "pad_buckets": [64],
                            "max_record_bytes": 4096, "max_shard_bytes": 1_000_000
                        }}
                    })),
                },
            )
            .await;
        state.refresh_pool_rules(XITE).await;
        let pending = db.pending_outbound(1).unwrap().remove(0);
        let recovered = super::recover_outbound_representation(&state, &channel, &pending)
            .await
            .unwrap();
        assert_ne!(recovered.shard_path, shard);
        assert!(
            pool::record_work_bits(&recovered.record) > original_work,
            "a deterministic capacity loser is re-PoWed before retry"
        );

        assert_eq!(
            super::accepted_delivery_status(&state, &channel, &recovered).await,
            "queued",
            "post-commit publication failure is accepted, never a retryable command error"
        );
        assert_eq!(db.pending_outbound(10).unwrap()[0].outbox_id, outbox_id);
        assert!(
            root.join(recovered.shard_path).is_file(),
            "the rerouted local shard is durable before retry"
        );
        let old: Value =
            serde_json::from_slice(&std::fs::read(root.join(&shard)).unwrap()).unwrap();
        assert!(
            pool::pool_records_of(&old).is_empty(),
            "the old fanout route is durably stripped after the new route lands"
        );
        assert_eq!(
            db.outbound_route_cleanup(outbox_id).unwrap(),
            vec![shard.clone()]
        );

        let reopened = Arc::new(epix_channel::ChannelDb::open(&db_path).unwrap());
        assert_eq!(
            reopened.outbound_route_cleanup(outbox_id).unwrap(),
            vec![shard.clone()],
            "unfinished cleanup state survives restart until peer confirmation"
        );
        reopened
            .reschedule_outbound(outbox_id, super::now_ms())
            .unwrap();
        let retried = reopened.pending_outbound(1).unwrap().remove(0);
        let restarted_channel = super::ChannelState {
            db: reopened,
            engine: Arc::new(FakeEngine),
            xite: XITE.into(),
            identity_id: std::sync::atomic::AtomicI64::new(0),
            send_lock: tokio::sync::Mutex::new(()),
            outbox_lock: tokio::sync::Mutex::new(()),
            delivery_lock: tokio::sync::Mutex::new(()),
            rln_usage_ready: std::sync::atomic::AtomicBool::new(true),
            index_retry: tokio::sync::Notify::new(),
        };
        let retry_error = super::append_outbound(&state, &restarted_channel, &retried)
            .await
            .unwrap_err();
        assert!(
            retry_error.contains("reached no peers")
                || retry_error.contains("publishing requires EDX")
        );
        let old: Value = serde_json::from_slice(&std::fs::read(root.join(shard)).unwrap()).unwrap();
        assert!(pool::pool_records_of(&old).is_empty());

        let (legacy_id, _) = restarted_channel
            .db
            .commit_outbound(&epix_envelope::OutboundCommit {
                sessions: Vec::new(),
                record: retried.record.clone(),
                shard_path: retried.shard_path.clone(),
                created_ms: super::now_ms(),
                next_attempt_ms: super::now_ms(),
                recovery: epix_envelope::OutboundRecovery {
                    author_private_key: String::new(),
                    rln: None,
                },
                sent: None,
            })
            .unwrap();
        let legacy = restarted_channel
            .db
            .pending_outbound(10)
            .unwrap()
            .into_iter()
            .find(|row| row.outbox_id == legacy_id)
            .unwrap();
        let unchanged = super::recover_outbound_representation(&state, &restarted_channel, &legacy)
            .await
            .unwrap();
        assert_eq!(unchanged.record, legacy.record);
        assert_eq!(unchanged.shard_path, legacy.shard_path);
        let concurrent_refresh =
            epix_ui::pool::PoolAppendConfirmation::RouteChangedAfterPeerConfirmation {
                staged_shard: legacy.shard_path.clone(),
            };
        assert!(
            super::confirmation_retry_error(&retried, &concurrent_refresh)
                .unwrap()
                .contains("route changed")
        );
        assert!(
            super::confirmation_retry_error(&legacy, &concurrent_refresh).is_none(),
            "a peer-confirmed pre-v5 exact row can clear the finite legacy barrier"
        );
        assert!(
            super::confirmation_retry_error(&legacy, &postconfirmation_eviction).is_none(),
            "a peer-confirmed keyless legacy row must not become a permanent barrier"
        );
        restarted_channel.db.ack_outbound(legacy_id).unwrap();
        assert!(!restarted_channel.db.outbound_pending(legacy_id).unwrap());
    }
}

#[cfg(test)]
mod default_config_tests {
    /// The Config page's Channels defaults must equal the plugin's code
    /// defaults, or the UI advertises a state the node does not actually use.
    #[test]
    fn config_page_channel_defaults_match_plugin_defaults() {
        let row = |key: &str| {
            epix_ui::state::CONFIG_SCHEMA
                .iter()
                .find(|(_, k, _, _, _)| *k == key)
                .unwrap_or_else(|| panic!("{key} missing from CONFIG_SCHEMA"))
        };
        let (_, _, _, enabled_default, _) = row("channel_enabled");
        assert_eq!(*enabled_default, "true", "channels are ON by default");
        let (_, _, _, xite_default, _) = row("channel_xite");
        assert_eq!(*xite_default, super::DEFAULT_CHANNEL_XITE);
    }
}
