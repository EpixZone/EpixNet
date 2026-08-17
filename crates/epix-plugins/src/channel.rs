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
use epix_envelope::{Engine, FakeEngine, IdentitySecret, ProcessOutcome};
use epix_channel::ChannelDb;
use epix_plugin::Plugin;
use epix_ui::state::AppState;
use epix_ui::{WsCommand, WsSession};
use serde_json::{json, Value};
use std::sync::Arc;

/// Capability-registry key under which this plugin stashes [`ChannelState`].
const CHANNEL_CAP: &str = "channel";
/// Anti-entropy sweep cadence for the current-week pool shards.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// The channel-specific state a running node holds — installed once at startup and
/// retrieved by the `channel*` commands from the bound `AppState`.
pub struct ChannelState {
    pub db: Arc<ChannelDb>,
    pub engine: Arc<dyn Engine>,
    pub xite: String,
    /// Serializes the send path. Detection tags and AEAD nonces are a pure
    /// deterministic function of ratchet state, so two concurrent sends that read
    /// the SAME session before either persists would seal from identical state —
    /// reusing a ChaCha20-Poly1305 (key, nonce) pair (catastrophic) and emitting
    /// two records with the same tag. Holding this across the whole seal→persist
    /// critical section makes each send read the previous send's advanced state.
    pub send_lock: tokio::sync::Mutex<()>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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

fn channel_state(s: &WsSession) -> Result<Arc<ChannelState>, String> {
    s.state.capability::<ChannelState>(CHANNEL_CAP).ok_or_else(|| "channels are not enabled".to_string())
}

/// The node's single channel identity `(identity_id, secret, xid)`.
async fn channel_identity(
    state: &Arc<AppState>,
    ms: &ChannelState,
) -> Result<(i64, IdentitySecret, String), String> {
    let row = ms
        .db
        .identities()
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .ok_or("no channel identity — publish your key bundle first")?;
    let seed = state.derive_consumer_seed("channel", &row.auth_address).await;
    Ok((row.identity_id, IdentitySecret::new(seed), row.xid))
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

/// Every currently-published key bundle, grouped by xID name → the name's active
/// device bundles. A name may publish MORE THAN ONE bundle (one per linked
/// identity/device); a send fans out to all of them and the anti-spoof accepts
/// any. Revocation is honored two ways, both fail-OPEN when the chain is down:
///   - name-level: drop every bundle of a name with NO active linked identity;
///   - per-device: when the chain returns a NON-empty active-address set, drop a
///     bundle whose own `auth` is positively absent from it (that one device was
///     revoked while its siblings stayed valid).
async fn load_published_bundles(
    state: &Arc<AppState>,
    xite: &str,
) -> std::collections::HashMap<String, Vec<Value>> {
    let mut by_name: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for path in state.list_xite_files(xite).await {
        let Some((dir, _file)) = bundle_path_parts(&path) else { continue };
        let Some(bytes) = state.read_xite_file(xite, &path).await else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else { continue };
        let key = norm_xid(v.get("xid").and_then(|x| x.as_str()).unwrap_or(dir));
        by_name.entry(key).or_default().push(v);
    }
    // Apply revocation per name (one chain lookup each, both cached).
    let mut out: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for (name, devs) in by_name {
        if state.xid_name_active(&name).await == Some(false) {
            continue; // whole name revoked
        }
        let active = state.xid_active_addrs(&name).await;
        let devs = refine_device_bundles(devs, &active);
        if !devs.is_empty() {
            out.insert(name, devs);
        }
    }
    out
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
    bundles: &std::collections::HashMap<String, Vec<Value>>,
) -> (Vec<Value>, bool) {
    let resolve =
        |xid: &str| -> Vec<Value> { bundles.get(&norm_xid(xid)).cloned().unwrap_or_default() };
    let mut events: Vec<Value> = Vec::new();
    let mut new_session = false;
    for rec in records {
        let outcomes = epix_envelope::process_record(db, engine, identities, rec, now, resolve)
            .unwrap_or_default();
        for outcome in outcomes {
            if let Some(ev) = indexed_event(outcome, &mut new_session) {
                events.push(ev);
            }
        }
    }
    (events, new_session)
}

async fn index_batch(state: &Arc<AppState>, ms: &Arc<ChannelState>, records: Vec<Value>) -> bool {
    let identities = build_identities(state, &ms.db).await;
    if identities.is_empty() || records.is_empty() {
        return false;
    }
    let db = (*ms.db).clone();
    let engine = ms.engine.clone();
    let now = now_ms();
    // Published bundles, so the first-contact anti-spoof check can resolve a
    // sender_xid → bundle.ik synchronously inside spawn_blocking.
    let bundles = load_published_bundles(state, &ms.xite).await;

    let (events, new_session) = tokio::task::spawn_blocking(move || {
        process_batch_blocking(&db, engine.as_ref(), &identities, &records, now, &bundles)
    })
    .await
    .unwrap_or((Vec::new(), false));

    for ev in events {
        state.push_site_event(&ms.xite, "channelEvent", ev);
    }
    new_session
}

/// Process a delta, then re-scan once if a new session formed (a record that
/// arrived before its session existed becomes matchable).
async fn index_records(state: &Arc<AppState>, ms: &Arc<ChannelState>, records: Vec<Value>) {
    if index_batch(state, ms, records).await {
        let all = state.pool_all_records(&ms.xite).await;
        // Idempotent: the processed-set skips already-indexed records. No further
        // re-scan (a second new session is caught by the next delta / sweep).
        index_batch(state, ms, all).await;
    }
}

/// Choose the channel engine: the real X3DH + Double Ratchet engine by default;
/// the INSECURE test engine only when explicitly opted into for development.
async fn build_engine(state: &Arc<AppState>) -> Option<Arc<dyn Engine>> {
    if state.config_bool("channel_allow_insecure_engine", false).await {
        state
            .log("WARNING", "Channel messaging on the INSECURE FakeEngine (no confidentiality) — dev only")
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
            match key {
                Some(k) => ChannelDb::open_encrypted(&path, k).ok(),
                None => ChannelDb::open(&path).ok(),
            }
            .or_else(|| ChannelDb::memory().ok())
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
            if let Some(auth) = state.xite_auth_address(&xite).await {
                let xid = state.user_directory(&xite, &auth).await;
                let seed = state.derive_consumer_seed("channel", &auth).await;
                let bundle = engine.publish_bundle(&IdentitySecret::new(seed), &xid);
                let _ = db.upsert_identity(&xid, &auth, 0, Some(&bundle.to_string()));
            }

            let ms = Arc::new(ChannelState {
                db: db.clone(),
                engine: engine.clone(),
                xite: xite.clone(),
                send_lock: tokio::sync::Mutex::new(()),
            });
            state.install_capability(CHANNEL_CAP, ms.clone());

            // RLN anonymous rate-limiting: install the owner-signed admission hook
            // and load this xite's member roster. Inert unless the pool rule sets
            // rln_required and a roster is published, so it is safe to always wire.
            {
                let rln = crate::rln::RlnAdmission::new();
                state.set_pool_admission(rln.clone()).await;
                rln.refresh(&state, &xite).await;
                // Also stash it so the send path can prove with the same gates.
                state.install_capability(crate::rln::RLN_CAP, rln);
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
    ms.db
        .identities()
        .map_err(|e| e.to_string())?
        .into_iter()
        .next()
        .map(|r| r.identity_id)
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
        Ok(json!({
            "enabled": true,
            "xite": ms.xite,
            "key_bundle_published": has_identity,
            "unread": unread,
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
        let auth = s.state.xite_auth_address(&ms.xite).await.ok_or("no identity for this xite")?;
        let xid = s.state.user_directory(&ms.xite, &auth).await;
        let seed = s.state.derive_consumer_seed("channel", &auth).await;
        let mut bundle = ms.engine.publish_bundle(&IdentitySecret::new(seed), &xid);
        // Stamp the device's linked-identity address so the reader can (a) fan a
        // send out to every one of a name's devices and (b) drop just the one
        // device whose linked key was revoked on chain (per-device revocation).
        if let Some(obj) = bundle.as_object_mut() {
            obj.insert("auth".into(), json!(auth));
        }
        ms.db
            .upsert_identity(&xid, &auth, 0, Some(&bundle.to_string()))
            .map_err(|e| e.to_string())?;
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
        let published = load_published_bundles(&s.state, &ms.xite).await;
        let mut out = serde_json::Map::new();
        for x in xids {
            let Some(xid) = x.as_str() else { continue };
            let dir = norm_xid(xid);
            // A revoked identity has no usable bundle, even if a stale data.json
            // is still on disk (fail open on an indeterminate chain result).
            let revoked = s.state.xid_name_active(&dir).await == Some(false);
            let devices = published
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
    state: &Arc<AppState>,
    ms: &ChannelState,
    recipients: &[String],
    published: &std::collections::HashMap<String, Vec<Value>>,
) -> Result<Vec<Value>, String> {
    let mut dests: Vec<Value> = Vec::new();
    for recip in recipients {
        // Don't seal to a recipient whose xID has been revoked on chain (fail open
        // on an indeterminate result so a chain outage doesn't block messaging).
        if state.xid_name_active(recip).await == Some(false) {
            return Err(format!("{recip}'s identity has been revoked"));
        }
        let devices: Vec<Value> = published
            .get(recip)
            .into_iter()
            .flatten()
            .filter(|b| ms.engine.verify_bundle(b))
            .cloned()
            .collect();
        if devices.is_empty() {
            return Err(format!("{recip} has not published channel keys"));
        }
        dests.extend(devices);
    }
    Ok(dests)
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

/// Append + flood the sealed records, applying two independent privacy timers:
///
/// - **send-origin jitter** (`send_jitter_max`): when non-zero the WHOLE injection
///   is delayed by a random `0..=max` and runs from a detached task, decorrelating
///   the pool write from the user's send action for a directly-connected peer. The
///   handler returns immediately; the sender's own copy is already in the private
///   index, so the UI is unaffected.
/// - **burst jitter** (`burst_jitter_max`): the second-and-later records of a
///   multi-record (over-`SLOTS`) send are spaced by a random gap so the flood
///   can't be counted as one send.
///
/// The records are already sealed with their ratchet state persisted, so any
/// deferred append is crash-safe: on an unlucky shutdown a send may simply not
/// reach some recipients, and a resend re-posts on the advanced ratchet.
async fn append_records_jittered(
    state: Arc<AppState>,
    xite: String,
    records: Vec<Value>,
    send_jitter_max: u64,
    burst_jitter_max: u64,
) -> Result<(), String> {
    // Send-origin jitter: detach the entire injection behind a random initial
    // delay. The handler has already returned, so errors are logged, not surfaced.
    if send_jitter_max > 0 {
        tokio::spawn(async move {
            let delay = rand_u64_below(send_jitter_max + 1);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            post_records(&state, &xite, records, burst_jitter_max, true).await;
        });
        return Ok(());
    }
    // No send jitter: post the first record now (surfacing an immediate error to
    // the caller), then burst-jitter the rest from a detached task.
    let mut it = records.into_iter();
    if let Some(first) = it.next() {
        state.clone().append_pool_record(&xite, first).await?;
    }
    let rest: Vec<Value> = it.collect();
    if rest.is_empty() {
        return Ok(());
    }
    let (s, x) = (state.clone(), xite.clone());
    tokio::spawn(async move {
        post_records(&s, &x, rest, burst_jitter_max, false).await;
    });
    Ok(())
}

/// Post `records` to the pool, spacing consecutive ones by `burst_jitter_max`.
/// `first_immediate` posts `records[0]` with no gap (used by the send-jitter path,
/// where the initial delay already elapsed); otherwise every record is gapped
/// (used for the tail of a no-send-jitter send). Runs detached: errors are logged.
async fn post_records(
    state: &Arc<AppState>,
    xite: &str,
    records: Vec<Value>,
    burst_jitter_max: u64,
    first_immediate: bool,
) {
    for (i, record) in records.into_iter().enumerate() {
        let gap = if i == 0 && first_immediate { 0 } else { jitter_gap_secs(burst_jitter_max) };
        if gap > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(gap)).await;
        }
        if let Err(e) = state.clone().append_pool_record(xite, record).await {
            state.log("WARNING", &format!("deferred channel record append failed: {e}")).await;
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
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(norm_xid).collect())
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

        let (identity_id, secret, my_xid) = channel_identity(&s.state, &ms).await?;
        let rule = s
            .state
            .pool_rules_for(&ms.xite)
            .await
            .into_iter()
            .next()
            .ok_or("this xite has no pool configured")?;

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
        let published = load_published_bundles(&s.state, &ms.xite).await;
        let dests = resolve_destinations(&s.state, &ms, &recipients, &published).await?;

        // For an rln_required pool, the node attaches an RLN membership proof to
        // every record it sends. Fetch the shared admission (the same gates the
        // ingest path uses) and this node's RLN identity seed up front, so the
        // per-chunk seal task can prove without touching async state.
        let rln_ctx: Option<(Arc<crate::rln::RlnAdmission>, Vec<u8>, String)> = if rule.rln_required {
            let admission = s.state.capability::<crate::rln::RlnAdmission>(crate::rln::RLN_CAP);
            let auth = s.state.xite_auth_address(&ms.xite).await;
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

        // Seal each chunk of up to SLOTS destinations into one fixed-width record
        // (≤ SLOTS total devices is a single record; larger sends span the minimum
        // number of records). The sender's own copy is recorded on the first chunk
        // only. PoW runs on the blocking pool so it can't starve the runtime. The
        // send lock serializes the seal→persist section: two concurrent sends must
        // not read the same ratchet state (which would reuse an AEAD nonce and a
        // detection tag). It is held ONLY across sealing — appends touch no ratchet
        // state — so the jittered append below never blocks another send.
        let records = {
            let _send_guard = ms.send_lock.lock().await;
            let mut records: Vec<Value> = Vec::new();
            for (ci, chunk) in dests.chunks(epix_envelope::SLOTS).enumerate() {
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
                let chunk_dests: Vec<epix_envelope::Dest> =
                    chunk.iter().map(|b| epix_envelope::Dest { bundle: b.clone() }).collect();
                let rln_c = rln_ctx.clone();
                let res = tokio::task::spawn_blocking(move || {
                    if let Some((admission, seed, addr)) = rln_c {
                        let ident = epix_rln::RlnIdentity::from_seed(&seed);
                        let prover =
                            |ct: &[u8], epoch: i64| admission.prove_for(&addr, &ident, epoch, 0, ct);
                        epix_envelope::send_multi_with_rln(
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
                            &rule_c,
                            record_own,
                            &prover,
                        )
                    } else {
                        epix_envelope::send_multi(
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
                            &rule_c,
                            record_own,
                        )
                    }
                })
                .await
                .map_err(|e| format!("channelSend seal task failed: {e}"))?
                .map_err(|e| e.to_string())?;
                records.push(res.record);
            }
            records
        };

        // Append + flood. The first record goes out now; any extra records of a
        // >SLOTS send are spaced by burst jitter so a peer watching the flood can't
        // count the simultaneous same-size records as one send.
        let envelopes = records.len();
        let send_jitter = send_jitter_max_secs(&s.state).await;
        let burst_jitter = burst_jitter_max_secs(&s.state).await;
        append_records_jittered(s.state.clone(), ms.xite.clone(), records, send_jitter, burst_jitter)
            .await?;

        // `envelopes` is the record count — independent of the true recipient/device
        // count (which is hidden inside each fixed-width record).
        Ok(json!({
            "ok": true,
            "conv_id": hex::encode(conv),
            "recipients": recipients.len(),
            "envelopes": envelopes,
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
        let (identity_id, _secret, my_xid) = channel_identity(&s.state, &ms).await?;
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
    use super::{bundle_path_parts, device_bundle_file, refine_device_bundles};
    use serde_json::json;

    #[test]
    fn device_filename_is_regex_safe() {
        // bech32 stays as-is; any stray char is stripped so it matches the
        // site's `data-[0-9a-z]+\.json` permission rule.
        // A real lowercase bech32 address passes through unchanged.
        assert_eq!(device_bundle_file("epix1abc0"), "data-epix1abc0.json");
        // Any path-traversal / non-[0-9a-z] char is stripped (defense in depth).
        assert_eq!(device_bundle_file("epix1abc/../x"), "data-epix1abcx.json");
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
    fn legacy_bundle_without_auth_is_kept() {
        // A pre-multi-device bundle (no `auth`) must not be dropped by the filter.
        let legacy = json!({ "v": 2, "xid": "mud.epix", "ik": "IKL", "spk": "s", "spk_idx": 3 });
        let out = refine_device_bundles(vec![legacy], &["epix1a".to_string()]);
        assert_eq!(out.len(), 1, "legacy no-auth bundle survives the per-device filter");
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
}
