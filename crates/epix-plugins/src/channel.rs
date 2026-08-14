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
async fn load_published_bundles(
    state: &Arc<AppState>,
    xite: &str,
) -> std::collections::HashMap<String, Value> {
    let mut bundles = std::collections::HashMap::new();
    for path in state.list_xite_files(xite).await {
        let Some(rest) = path.strip_prefix("data/users/") else { continue };
        let Some(dir) = rest.strip_suffix("/data.json") else { continue };
        let Some(bytes) = state.read_xite_file(xite, &path).await else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(&bytes) else { continue };
        let key = v.get("xid").and_then(|x| x.as_str()).unwrap_or(dir);
        bundles.insert(norm_xid(key), v);
    }
    bundles
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
        let resolve = |xid: &str| -> Option<Value> { bundles.get(&norm_xid(xid)).cloned() };
        let mut out: Vec<Value> = Vec::new();
        let mut new_session = false;
        for rec in &records {
            if let Ok(ProcessOutcome::Indexed {
                conv_id,
                sender_xid,
                subject,
                snippet,
                unread,
                first_contact,
                ..
            }) = epix_envelope::process_record(&db, engine.as_ref(), &identities, rec, now, &resolve)
            {
                if first_contact {
                    new_session = true;
                }
                out.push(json!({
                    "type": "new_message",
                    "conv_id": conv_id,
                    "from_xid": sender_xid,
                    "subject": subject,
                    "snippet": snippet,
                    "unread": unread,
                }));
            }
        }
        (out, new_session)
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
        let bundle = ms.engine.publish_bundle(&IdentitySecret::new(seed), &xid);
        ms.db
            .upsert_identity(&xid, &auth, 0, Some(&bundle.to_string()))
            .map_err(|e| e.to_string())?;
        // The site writes this to `data/users/<xid>/data.json` and signs it.
        Ok(json!({ "ok": true, "xid": xid, "bundle": bundle }))
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
        let mut out = serde_json::Map::new();
        for x in xids {
            let Some(xid) = x.as_str() else { continue };
            let dir = norm_xid(xid);
            let has = s
                .state
                .read_xite_file(&ms.xite, &format!("data/users/{dir}/data.json"))
                .await
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .map(|bundle| ms.engine.verify_bundle(&bundle))
                .unwrap_or(false);
            out.insert(dir, json!({ "has_bundle": has }));
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
        // reply-all. The message is fanned out as one pairwise-sealed envelope
        // per OTHER member — unlinkable to each other, but sharing conv + members.
        let conv = conv_hint.unwrap_or_else(epix_envelope::new_conv_id);
        let mut members: Vec<String> = recipients.clone();
        members.push(norm_xid(&my_xid));
        members.sort();
        members.dedup();

        // Serialize the whole seal→persist→append critical section: two
        // concurrent sends must not read the same ratchet state (which would
        // reuse an AEAD nonce and a detection tag). Held until this send returns.
        let _send_guard = ms.send_lock.lock().await;

        let mut records: Vec<Value> = Vec::new();
        for (i, recip) in recipients.iter().enumerate() {
            let bundle_bytes = s
                .state
                .read_xite_file(&ms.xite, &format!("data/users/{recip}/data.json"))
                .await
                .ok_or_else(|| format!("{recip} has not published channel keys"))?;
            let bundle: Value = serde_json::from_slice(&bundle_bytes).map_err(|e| e.to_string())?;
            if !ms.engine.verify_bundle(&bundle) {
                return Err(format!("{recip} has an invalid channel key bundle"));
            }
            // Sealing runs a proof-of-work that is seconds of hashing at
            // production `pow_bits`. Doing it inline would pin an async runtime
            // worker for the whole solve and starve every other connection, so
            // run the (fully synchronous) seal on the blocking pool. Record the
            // sender's own copy exactly once (on the first leg).
            let db = ms.db.clone();
            let engine = ms.engine.clone();
            let secret = secret.clone();
            let my_xid_c = my_xid.clone();
            let members_c = members.clone();
            let rule_c = rule.clone();
            let subject_c = subject.to_string();
            let body_c = body.to_string();
            let record_own = i == 0;
            let now = now_ms();
            let res = tokio::task::spawn_blocking(move || {
                epix_envelope::send_message(
                    db.as_ref(),
                    engine.as_ref(),
                    identity_id,
                    &secret,
                    &my_xid_c,
                    &members_c,
                    &bundle,
                    conv,
                    &subject_c,
                    &body_c,
                    now,
                    &rule_c,
                    record_own,
                )
            })
            .await
            .map_err(|e| format!("channelSend seal task failed: {e}"))?
            .map_err(|e| e.to_string())?;
            records.push(res.record);
        }
        // Append + flood each fan-out envelope.
        for record in records {
            s.state.clone().append_pool_record(&ms.xite, record).await?;
        }
        Ok(json!({ "ok": true, "conv_id": hex::encode(conv), "recipients": recipients.len() }))
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
