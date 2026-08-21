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

async fn load_published_bundles(
    state: &Arc<AppState>,
    xite: &str,
    engine: &dyn Engine,
    db: &ChannelDb,
) -> Result<PublishedBundles, String> {
    let mut by_name: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
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
        // Attribute the bundle to the cert-gated directory it lives in, 
        // NOT to its self-declared `xid` field.
        // Only the owner of `data/users/<name>.epix/` can write there, so the
        // directory IS the authenticated identity (publish stamps the same value
        // into the field). Keying by the JSON field would let anyone drop a bundle
        // carrying THEIR own `ik` under a VICTIM's name, so the transcript-bound
        // `ik_a` check in the indexer would then match and the forgery would index
        // as "from victim". Drop any bundle whose declared `xid` disagrees.
        let key = norm_xid(dir);
        if !bundle_xid_matches_directory(&v, &key) {
                continue;
            }
        if !engine.verify_bundle(&v) || !bundle_filename_matches_auth(file, &v) {
            continue;
        }
        by_name.entry(key).or_default().push(v);
    }
    let mut peer_auth_bindings = Vec::new();
    for (name, bundles) in &by_name {
        for bundle in bundles {
            if let (Some(ik), Some(auth)) = (
                engine.sender_ik(bundle),
                bundle.get("auth").and_then(Value::as_str),
            ) {
                peer_auth_bindings.push((name.clone(), hex::encode(ik), auth.to_string()));
            }
        }
    }
    db.backfill_session_peer_auth(&peer_auth_bindings)
        .map_err(|e| e.to_string())?;
    let mut sessions_by_name: std::collections::HashMap<String, Vec<epix_channel::SessionPeer>> =
        std::collections::HashMap::new();
    for peer in db.session_peers().map_err(|e| e.to_string())? {
        let name = norm_xid(&peer.xid);
        sessions_by_name.entry(name.clone()).or_default().push(peer);
        // Query chain status even when every bundle for this established peer
        // was removed or has not synced on this node.
        by_name.entry(name).or_default();
    }
    let local_identities = db.identities().map_err(|e| e.to_string())?;
    for identity in &local_identities {
        by_name.entry(norm_xid(&identity.xid)).or_default();
    }

    let mut out = PublishedBundles::default();
    let mut newly_revoked = Vec::<RevokedDevice>::new();
    for (name, devs) in by_name {
        let snapshot = match state.xid_identity_snapshot(&name).await {
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
                // The documented policy is offline fail-open. A resolver or
                // finality failure must not erase an already persisted tombstone,
                // and it must not invent a new one either.
                state
                    .log(
                        "WARN",
                        &format!("xID identity snapshot unavailable for {name}: {error}"),
                    )
                    .await;
                None
            }
        };
        let status_for = |auth: &str| snapshot.as_ref().and_then(|s| s.status_for(auth));

        if let Some(snapshot) = &snapshot {
            use epix_chain::XidIdentityStatus::{Active, Revoked};
            let has_active = snapshot
                .identities
                .iter()
                .any(|identity| identity.status == Active);
            if !has_active {
                // This is a transient name-wide block for this exact snapshot,
                // not a permanent name tombstone. Future newly-linked auths work.
                out.revoked_names.insert(name.clone());
            }
            for identity in snapshot
                .identities
                .iter()
                .filter(|identity| identity.status == Revoked)
            {
                // Persist every chain-known revoked auth even if its stale bundle
                // is absent today. A later outage cannot revive that device.
                newly_revoked.push(RevokedDevice {
                    xid: name.clone(),
                    auth_address: identity.auth_address.clone(),
                    peer_ik: String::new(),
                });
        }
    }

        for peer in sessions_by_name.get(&name).into_iter().flatten() {
            let unbound_legacy_leg = peer.peer_auth.is_none()
                && snapshot.as_ref().is_some_and(|snapshot| {
                    snapshot
                        .identities
                        .iter()
                        .any(|identity| identity.status == epix_chain::XidIdentityStatus::Revoked)
                });
            let transiently_blocked = peer.peer_auth.as_deref().is_some_and(|auth| {
                snapshot.is_some()
                    && status_for(auth) != Some(epix_chain::XidIdentityStatus::Active)
            });
            let explicitly_revoked = peer.peer_auth.as_deref().is_some_and(|auth| {
                status_for(auth) == Some(epix_chain::XidIdentityStatus::Revoked)
            });
            if explicitly_revoked {
                newly_revoked.push(RevokedDevice {
                    xid: name.clone(),
                    auth_address: peer.peer_auth.clone().unwrap_or_default(),
                    peer_ik: peer.peer_ik.clone(),
                });
            }
            if unbound_legacy_leg {
                // A legacy leg without authenticated v3 ownership cannot be
                // distinguished from the revoked sibling in a mixed snapshot.
                // Close that exact old IK durably. A verified v3 re-handshake
                // with a fresh IK remains available.
                newly_revoked.push(RevokedDevice {
                    xid: name.clone(),
                    auth_address: String::new(),
                    peer_ik: peer.peer_ik.clone(),
                });
            }
            if unbound_legacy_leg
                || transiently_blocked
                || db
                    .is_device_revoked(&name, peer.peer_auth.as_deref(), &peer.peer_ik)
                    .map_err(|e| e.to_string())?
            {
                out.revoked_devices
                    .insert((name.clone(), peer.peer_ik.clone()));
            }
        }

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
                    xid: name.clone(),
                    auth_address: auth.to_string(),
                    peer_ik: peer_ik.clone(),
                });
                out.revoked_devices.insert((name.clone(), peer_ik.clone()));
            }
            let snapshot_allows = snapshot.is_none()
                || status_for(auth) == Some(epix_chain::XidIdentityStatus::Active);
            if snapshot_allows
                && !out
                    .revoked_devices
                    .contains(&(name.clone(), peer_ik.clone()))
                && !db
                    .is_device_revoked(&name, Some(auth), &peer_ik)
                    .map_err(|e| e.to_string())?
            {
                retained.push(bundle);
            }
        }
        if !retained.is_empty() {
            out.active.insert(name, retained);
        }
    }
    db.remember_revoked_devices(&newly_revoked, now_ms())
        .map_err(|e| e.to_string())?;
    Ok(out)
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
        let state = state.clone();
        tokio::spawn(async move {
            if !state.config_bool("channel_enabled", false).await {
                return;
            }
            let xite = state
                .config_get("channel_xite")
                .await
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();
            if xite.is_empty() {
                state.log("INFO", "channel_enabled but channel_xite is unset; channels off").await;
                return;
            }
            let Some(engine) = build_engine(&state).await else { return };
            let Some(db) = open_db(&state).await else {
                state.log("ERROR", "could not open the channel index").await;
                return;
            };

            // Ensure the node's channel identity row exists so inbound records can
            // be trial-matched, and stash its published bundle.
            let local_identity_id = match local_channel_bundle(&state, &xite, engine.as_ref()).await
            {
                Ok((auth, xid, bundle)) => {
                    match db.upsert_identity(&xid, &auth, 0, Some(&bundle.to_string())) {
                        Ok(identity_id) => identity_id,
                        Err(e) => {
                            state
                                .log("ERROR", &format!("could not persist channel identity: {e}"))
                                .await;
                            return;
            }
                    }
                }
                Err(e) => {
                    state
                        .log(
                            "ERROR",
                            &format!("could not build authenticated channel bundle: {e}"),
                        )
                        .await;
                    return;
                }
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

            // RLN anonymous rate-limiting: install the owner-signed admission hook
            // and load this xite's member roster. Inert unless the pool rule sets
            // rln_required and a roster is published, so it is safe to always wire.
            {
                let ledger = state.data_root_path().map(|r| r.join("private").join("rln_usage.json"));
                let rln = crate::rln::RlnAdmission::new(ledger);
                if let Err(error) = reconcile_rln_usage(&ms, &rln) {
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
                rln.refresh(&state, &xite).await;
                // Also stash it so the send path can prove with the same gates.
                state.install_capability(crate::rln::RLN_CAP, rln.clone());
                let retry_state = state.clone();
                let retry_ms = ms.clone();
                tokio::spawn(monitor_rln_usage_reconciliation(retry_state, retry_ms, rln));
            }

            // Reconcile every provisional RLN range before any durable record
            // can publish or be acknowledged. The exact record and ratchet
            // advance already committed together, so retry remains idempotent.
            {
                let s = state.clone();
                let m = ms.clone();
                tokio::spawn(async move {
                    loop {
                        if let Err(e) = deliver_due_outbox(&s, &m).await {
                            s.log("WARNING", &format!("channel outbox delivery failed: {e}"))
                                .await;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                });
            }

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
            let mut rx = state.subscribe_pool_deltas();

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
            {
                let s = state.clone();
                let x = xite.clone();
                tokio::spawn(async move {
                    s.backfill_pool_shards(&x, weeks).await;
                });
            }

            // Periodic anti-entropy sweep of the current-week shards.
            {
                let s = state.clone();
                let x = xite.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(SWEEP_INTERVAL).await;
                        if !s.config_bool("channel_enabled", false).await {
                            continue;
                        }
                        s.resync_pool_shards_for(&x).await;
                    }
                });
            }

            // The indexer loop.
            loop {
                match rx.recv().await {
                    Ok(delta) if delta.address == xite => {
                        index_records(&state, &ms, delta.records.as_ref().clone()).await;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Missed some deltas under load: rescan from disk.
                        let all = state.pool_all_records(&xite).await;
                        index_records(&state, &ms, all).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
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
        let shard_path = state.pool_shard_for_record(&ms.xite, &record).await?;
        let epoch = record
            .get("epoch")
            .and_then(Value::as_i64)
            .ok_or("queued channel record has no epoch")?;
        epix_content::pool::verify_pool_record(
            &record,
            &rule,
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
                "legacy queued record needs unavailable recovery material after a route change"
                    .into(),
            );
    }
        return Ok(pending.clone());
    }
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

    // Roster refresh and proof replacement share the same per-pool transaction
    // as multi-chunk reservation. Release it before local admission, which takes
    // the same permit. The gate retains a short grace root for a refresh in that
    // narrow handoff window, and the next retry re-proves again if necessary.
    let mut representation_changed = false;
    if rule.rln_required {
        let admission = state
            .capability::<crate::rln::RlnAdmission>(crate::rln::RLN_CAP)
            .ok_or("this pool requires RLN but no admission gate is loaded")?;
        let auth = state.user_auth_address(&ms.xite).await?;
        let seed = state.derive_consumer_seed("rln", &auth).await;
        let identity = epix_rln::RlnIdentity::from_seed(&seed);
        let _transaction = admission.send_transaction(&ms.xite).await;
        let current_root = admission.current_root(&ms.xite)?;
        if let Some(reservation) = recovery.rln.as_mut() {
            if reservation.root != Some(current_root) || record.get("rln").is_none() {
                let proof =
                    admission.reprove_reserved(&ms.xite, &identity, epoch, &ct, reservation)?;
                record["rln"] = json!(base64::engine::general_purpose::STANDARD.encode(proof));
                reservation.root = Some(current_root);
                representation_changed = true;
            }
        } else {
            // A delayed PoW-only row can outlive a descriptor change that turns
            // RLN on. Reserve by the immutable ciphertext id. A crash before the
            // SQLite representation update is safe because reserve_proof is
            // named and idempotently returns this same durable range on retry.
            let reserved = admission.reserve_proof(&ms.xite, &identity, epoch, &ct)?;
            record["rln"] = json!(base64::engine::general_purpose::STANDARD.encode(reserved.proof));
            recovery.rln = Some(reserved.reservation);
            representation_changed = true;
        }
    } else if record
        .as_object_mut()
        .and_then(|object| object.remove("rln"))
        .is_some()
    {
        // Retain the private reservation in case policy later returns to the old
        // rail. Only the public proof is invalid under a PoW-only descriptor.
        representation_changed = true;
}

    let capacity_retry = pending
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("capacity") || error.contains("evicted"));
    let strengthen = capacity_retry || representation_changed;
    let target_work = rule
        .pow_bits
        .max(original_work.saturating_add(u32::from(strengthen)));
    let signing_key = recovery.author_private_key.clone();
    record = tokio::task::spawn_blocking(move || -> Result<Value, String> {
        epix_content::pool::solve_pow(&mut record, target_work);
        record["sign"] = json!(epix_crypt::sign(
            &epix_content::record_signed_data(&record),
            &signing_key,
        )?);
        Ok(record)
    })
    .await
    .map_err(|error| format!("queued channel PoW task failed: {error}"))??;

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
    if representation_changed
        || record != pending.record
        || shard_path != pending.shard_path
        || pending.last_error.is_some()
    {
        ms.db
            .replace_outbound_record(pending.outbox_id, &record, &shard_path, &recovery)
            .map_err(|error| error.to_string())?;
    }

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
        let rows = {
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
                .pending_outbound_through(pending.outbox_id)
                .map_err(|e| e.to_string())?
        };
        if rows.is_empty() {
            break;
        }
        for row in rows {
            if let Err(e) = append_outbound(state, ms, &row).await {
                let retry_at = now_ms() + OUTBOX_RETRY_INTERVAL.as_millis() as i64;
                ms.db
                    .reschedule_outbound_error(row.outbox_id, retry_at, Some(&e))
                    .map_err(|db| format!("{e}; could not reschedule outbox row: {db}"))?;
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
    }
    if ms
        .db
        .outbound_pending(pending.outbox_id)
        .map_err(|error| error.to_string())?
    {
        Err(first_error.unwrap_or_else(|| {
            format!(
                "channel send is queued behind an older dependency or future deadline for outbox row {}",
                pending.outbox_id
            )
        }))
    } else {
        Ok(())
    }
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

struct ChannelSend;
#[async_trait]
impl WsCommand for ChannelSend {
    fn name(&self) -> &'static str {
        "channelSend"
    }
    async fn handle(&self, s: &WsSession, p: &Value) -> Result<Value, String> {
        let ms = channel_state(s)?;
        let a = p.as_array().ok_or("channelSend: [recipients, subject, body, conv_id?]")?;
        let recipients: Vec<String> = a
            .first()
            .and_then(|v| v.as_array())
            .map(|arr| normalized_recipients(arr))
            .unwrap_or_default();
        if recipients.is_empty() {
            return Err("channelSend: at least one recipient required".into());
        }
        let subject = a.get(1).and_then(|v| v.as_str()).unwrap_or("");
        let body = a.get(2).and_then(|v| v.as_str()).unwrap_or("");
        let conv_hint: Option<[u8; 16]> = a
            .get(3)
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok());

        let (identity_id, secret, my_xid, my_auth) = channel_identity(&s.state, &ms).await?;
        let snapshot = match s.state.xid_identity_snapshot(&my_xid).await {
            Ok(Some(snapshot)) if norm_xid(&snapshot.canonical_name) == norm_xid(&my_xid) => {
                Some(snapshot)
            }
            Ok(Some(_)) | Ok(None) => None,
            Err(error) => {
                s.state
                    .log(
                        "WARN",
                        &format!("local xID identity snapshot unavailable: {error}"),
                    )
                    .await;
                None
            }
        };
        let active_addrs: Vec<String> = snapshot
            .as_ref()
            .map(|snapshot| {
                snapshot
                    .identities
                    .iter()
                    .filter(|identity| identity.status == epix_chain::XidIdentityStatus::Active)
                    .map(|identity| identity.auth_address.clone())
                    .collect()
            })
            .unwrap_or_default();
        let name_active = snapshot.as_ref().map(|_| !active_addrs.is_empty());
        if snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.status_for(&my_auth) == Some(epix_chain::XidIdentityStatus::Revoked)
        }) {
            ms.db
                .remember_revoked_device(&norm_xid(&my_xid), Some(&my_auth), "", now_ms())
                .map_err(|e| e.to_string())?;
        }
        let tombstoned = ms
            .db
            .is_device_revoked(&norm_xid(&my_xid), Some(&my_auth), "")
            .map_err(|e| e.to_string())?;
        ensure_local_sender_active(&my_xid, &my_auth, tombstoned, name_active, &active_addrs)?;
        // ONE conversation id shared across the whole thread (a 1:1 or a group),
        // and the full participant list (recipients + me) so every recipient can
        // reply-all.
        let conv = conv_hint.unwrap_or_else(epix_envelope::new_conv_id);
        let mut members: Vec<String> = recipients.clone();
        members.push(norm_xid(&my_xid));
        members.sort();
        members.dedup();

        // Resolve every recipient's active device bundles, flattened to ONE list of
        // destinations. Instead of one pool record per device (which would leak the
        // recipient device+group count to a peer counting the burst), all
        // destinations are packed into fixed-width `SLOTS`-slot records — so the
        // observable record count is independent of how many devices/recipients the
        // message actually reaches. Resolving touches no ratchet state, so it runs
        // BEFORE the send lock. See `docs/channel-count-privacy.md`.
        let published =
            load_published_bundles(&s.state, &ms.xite, ms.engine.as_ref(), &ms.db).await?;
        let dests = resolve_destinations(&ms, &recipients, &published).await?;

        // Padding, routing, and RLN policy must remain the same from the rule
        // read through the atomic ratchet/outbox commit. Otherwise a descriptor
        // refresh can leave an immutable ciphertext that no current rule can
        // admit after its ratchet has already advanced.
        let _staging_outbox_guard = channel_staging_guard(&ms).await?;
        let _rule_transaction = s.state.pool_rule_transaction(&ms.xite).await;
        let rule = s
            .state
            .pool_rules_for(&ms.xite)
            .await
            .into_iter()
            .next()
            .ok_or("this xite has no pool configured")?;

        // For an rln_required pool, the node attaches an RLN membership proof to
        // every record it sends. Fetch the shared admission (the same gates the
        // ingest path uses) and this node's RLN identity seed up front, so the
        // per-chunk seal task can prove without touching async state.
        let rln_ctx: Option<(Arc<crate::rln::RlnAdmission>, Vec<u8>, String)> = if rule.rln_required
        {
            let admission = s
                .state
                .capability::<crate::rln::RlnAdmission>(crate::rln::RLN_CAP);
            let auth = s.state.user_auth_address(&ms.xite).await.ok();
            match (admission, auth) {
                (Some(a), Some(auth)) => {
                    let seed = s.state.derive_consumer_seed("rln", &auth).await.to_vec();
                    Some((a, seed, ms.xite.clone()))
                }
                _ => return Err("this pool requires RLN but no membership is available".into()),
            }
        } else {
            None
        };

        let send_jitter = send_jitter_max_secs(&s.state).await;
        let burst_jitter = burst_jitter_max_secs(&s.state).await;
        let origin_delay = if send_jitter == 0 {
            0
        } else {
            rand_u64_below(send_jitter + 1)
        };
        let mut next_attempt_ms = now_ms() + origin_delay.saturating_mul(1000) as i64;
        let chunk_count = dests.len().div_ceil(epix_envelope::SLOTS);
        let rln_preflight_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Seal each chunk of up to SLOTS destinations into one fixed-width record
        // (≤ SLOTS total devices is a single record; larger sends span the minimum
        // number of records). The sender's own copy is recorded on the first chunk
        // only. PoW runs on the blocking pool so it can't starve the runtime. The
        // send lock serializes the seal→persist section: two concurrent sends must
        // not read the same ratchet state (which would reuse an AEAD nonce and a
        // detection tag). It is held ONLY across sealing — appends touch no ratchet
        // state. Each exact signed record and its persisted jitter deadline land
        // atomically with those advances in the durable SQLite outbox.
        let records = {
            let _send_guard = ms.send_lock.lock().await;
            let rln_batch = match &rln_ctx {
                Some((admission, _, _)) => Some(admission.reservation_batch(&ms.xite).await),
                None => None,
            };
            let mut prepared: Vec<epix_envelope::PreparedSend> = Vec::new();
            for (ci, chunk) in dests.chunks(epix_envelope::SLOTS).enumerate() {
                if ci > 0 {
                    next_attempt_ms += jitter_gap_secs(burst_jitter).saturating_mul(1000) as i64;
                }
                let db = ms.db.clone();
                let engine = ms.engine.clone();
                let secret = secret.clone();
                let my_xid_c = my_xid.clone();
                let members_c = members.clone();
                let rule_c = rule.clone();
                let subject_c = subject.to_string();
                let body_c = body.to_string();
                let record_own = ci == 0;
                let now = now_ms();
                let scheduled = next_attempt_ms;
                let chunk_dests: Vec<epix_envelope::Dest> = chunk
                    .iter()
                    .map(|b| epix_envelope::Dest { bundle: b.clone() })
                    .collect();
                let rln_c = rln_ctx.clone();
                let rln_batch_c = rln_batch.clone();
                let preflight = rln_preflight_done.clone();
                let res = tokio::task::spawn_blocking(move || {
                    if let Some((admission, seed, addr)) = rln_c {
                        let ident = epix_rln::RlnIdentity::from_seed(&seed);
                        // The rail computes the record's unit cost from ct and
                        // spends a fresh unit range, refusing past the allowance.
                        let prover = |ct: &[u8], epoch: i64| {
                            if !preflight.swap(true, std::sync::atomic::Ordering::AcqRel) {
                                let smallest = rule_c.pad_buckets.first().copied().unwrap_or(1);
                                let weight = epix_rln::bucket_weight(ct.len(), smallest);
                                let total = weight.saturating_mul(chunk_count as u32);
                                let (used, limit) = admission
                                    .usage(&addr, epoch.max(0) as u64)
                                    .ok_or("no RLN roster loaded for this pool")?;
                                if used.saturating_add(total) > limit {
                                    return Err(format!(
                                        "epoch allowance exhausted: send needs {total} units, {used}/{limit} already spent"
                                    ));
                                }
                            }
                            admission
                                .reserve_proof_batched(
                                    rln_batch_c
                                        .as_ref()
                                        .ok_or("missing RLN reservation batch")?,
                                    &addr,
                                    &ident,
                                    epoch,
                                    ct,
                                )
                                .map(
                                |reserved| epix_envelope::RlnProofMaterial {
                                    proof: reserved.proof,
                                    reservation: Some(reserved.reservation),
                                },
                            )
                        };
                        epix_envelope::prepare_multi_with_rln_reserved_scheduled(
                            db.as_ref(),
                            engine.as_ref(),
                            identity_id,
                            &secret,
                            &my_xid_c,
                            &members_c,
                            &chunk_dests,
                            conv,
                            &subject_c,
                            &body_c,
                            now,
                            scheduled,
                            &rule_c,
                            record_own,
                            &prover,
                        )
                    } else {
                        epix_envelope::prepare_multi_scheduled(
                            db.as_ref(),
                            engine.as_ref(),
                            identity_id,
                            &secret,
                            &my_xid_c,
                            &members_c,
                            &chunk_dests,
                            conv,
                            &subject_c,
                            &body_c,
                            now,
                            scheduled,
                            &rule_c,
                            record_own,
                        )
                    }
                })
                .await
                .map_err(|e| format!("channelSend seal task failed: {e}"))?
                .map_err(|e| e.to_string())?;
                prepared.push(res);
            }
            for prepared_record in &prepared {
                let singleton = epix_content::pool::make_pool_container(vec![prepared_record
                    .commit
                    .record
                    .clone()]);
                let encoded = serde_json::to_vec(&singleton)
                    .map_err(|error| format!("could not size channel pool record: {error}"))?;
                if encoded.len() > rule.max_shard_bytes {
                    return Err(format!(
                        "channel record cannot fit the pool shard limit ({} > {})",
                        encoded.len(),
                        rule.max_shard_bytes
                    ));
                }
            }
            let commits: Vec<_> = prepared.iter().map(|p| p.commit.clone()).collect();
            let staged = ms
                .db
                .commit_outbound_batch(&commits)
                .map_err(|e| e.to_string())?;
            if let Some(batch) = &rln_batch {
                if let Err(error) = batch.commit() {
                    ms.rln_usage_ready
                        .store(false, std::sync::atomic::Ordering::Release);
                    // SQLite already accepted the logical send. Keep reporting
                    // queued success, while the poisoned usage ledger blocks
                    // later sends until restart reconciliation repairs it.
                    s.state
                        .log(
                            "ERROR",
                            &format!("could not finalize RLN usage reservation: {error}"),
                        )
                        .await;
                }
            }
            prepared
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
                .collect::<Vec<_>>()
        };
        drop(_rule_transaction);
        drop(_staging_outbox_guard);

        // With origin jitter disabled, preserve the synchronous first append and
        // try it immediately. Once SQLite accepted the logical send, a transport
        // failure is a queued success, not a failed command that invites the user
        // to retry and duplicate the message. Every row remains durable.
        // Delayed and tail records are picked up by the retry loop at their
        // persisted deadlines, including after a restart.
        let envelopes = records.len();
        let mut delivery = "queued";
        if send_jitter == 0 {
            if let Some(last) = records.last() {
                delivery = accepted_delivery_status(&s.state, &ms, last).await;
            }
        }

        // `envelopes` is the record count — independent of the true recipient/device
        // count (which is hidden inside each fixed-width record).
        Ok(json!({
            "ok": true,
            "conv_id": hex::encode(conv),
            "recipients": recipients.len(),
            "envelopes": envelopes,
            "delivery": delivery,
        }))
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
