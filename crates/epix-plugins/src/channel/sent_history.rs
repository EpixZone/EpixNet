//! Re-seal locally authored Mail for another verified device of the same xID.
//! A later link or a temporarily missing bundle is discovered on the next pass.
use super::{
    channel_rln_send_context, channel_staging_guard, classify_published_name, identity_ctx_for,
    norm_xid, now_ms, prepare_outbound_records, rand_u64_below, read_device_bundle,
    send_jitter_max_secs, ChannelSendRequest, ChannelState, LocalChannelSender,
    PublishedBundleSources, PublishedBundles, SessionPeerMap,
};
use epix_channel::SentHistoryRow;
use epix_ui::state::AppState;
use serde_json::Value;
use std::{sync::Arc, time::Duration};

const INTERVAL: Duration = Duration::from_secs(30);
// Give interactive sends room in the durable outbox and use ordinary pool
// admission, scheduling and retry for every historical copy.
const PAGE_SIZE: usize = 4;
const MAX_QUEUED: i64 = 16;

pub(super) async fn run(state: Arc<AppState>, ms: Arc<ChannelState>) {
    loop {
        reconcile_sent_history(&state, &ms).await;
        tokio::time::sleep(INTERVAL).await;
    }
}

pub(crate) async fn reconcile_sent_history(state: &Arc<AppState>, ms: &Arc<ChannelState>) {
    for identity in state.identities().await {
        if let Err(error) = sync_identity(state, ms, &identity).await {
            state
                .log("WARNING", format!("channel sent history: {error}"))
                .await;
        }
    }
}

async fn sync_identity(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    identity: &epix_user::Identity,
) -> Result<(), String> {
    let row = ms
        .db
        .identity_by_auth(&identity.auth_address)
        .map_err(|e| e.to_string())?;
    let Some(row) = row.filter(|row| row.enabled) else {
        return Ok(());
    };
    let name = norm_xid(&identity.xid());
    let candidates =
        pending_siblings(state, ms, &name, &identity.auth_address, row.identity_id).await?;
    if candidates.is_empty() {
        return Ok(());
    }
    let ctx = identity_ctx_for(state, ms, identity).await?;
    let sender = LocalChannelSender {
        identity_id: ctx.identity_id,
        xid: ctx.xid,
        auth: ctx.auth,
        secret: ctx.secret,
    };
    let mut published = PublishedBundles::default();
    let mut revoked = Vec::new();
    let sessions = SessionPeerMap::new();
    let sources = PublishedBundleSources {
        state,
        engine: ms.engine.as_ref(),
        db: &ms.db,
        sessions_by_name: &sessions,
    };
    classify_published_name(&sources, name, candidates, &mut published, &mut revoked).await?;
    ms.db
        .remember_revoked_devices(&revoked, now_ms())
        .map_err(|e| e.to_string())?;
    for sibling in published.verified_siblings(&sender) {
        sync_sibling(state, ms, &sender, &sibling).await?;
    }
    Ok(())
}

// Read only this identity's bundle directory. Check the private cursor before
// consulting chain finality so idle devices make no history-related RPC calls.
async fn pending_siblings(
    state: &AppState,
    ms: &ChannelState,
    name: &str,
    auth: &str,
    identity_id: i64,
) -> Result<Vec<Value>, String> {
    let directory = format!("data/users/{name}");
    let mut candidates = Vec::new();
    for entry in state
        .list_dir(&ms.xite, &directory)
        .await
        .unwrap_or_default()
    {
        let Some(file) = entry["name"].as_str() else {
            continue;
        };
        let path = format!("{directory}/{file}");
        let Some((_, bundle)) =
            read_device_bundle(state, &ms.xite, &path, ms.engine.as_ref()).await
        else {
            continue;
        };
        let Some(ik) = ms.engine.sender_ik(&bundle) else {
            continue;
        };
        if bundle["auth"].as_str() != Some(auth)
            && ms
                .db
                .has_pending_sent_history(identity_id, &hex::encode(ik))
                .map_err(|e| e.to_string())?
        {
            candidates.push(bundle);
        }
    }
    Ok(candidates)
}

async fn sync_sibling(
    state: &Arc<AppState>,
    ms: &Arc<ChannelState>,
    sender: &LocalChannelSender,
    sibling: &Value,
) -> Result<(), String> {
    let peer_ik = hex::encode(
        ms.engine
            .sender_ik(sibling)
            .ok_or("missing sibling device key")?,
    );
    // Hold the same staging guard as a live send while selecting the page,
    // committing its outbox records and advancing this device's cursor.
    let _guard = channel_staging_guard(ms).await?;
    let (queued, _) = ms.db.outbox_status(None).map_err(|e| e.to_string())?;
    if queued >= MAX_QUEUED {
        return Ok(());
    }
    let limit = PAGE_SIZE.min((MAX_QUEUED - queued) as usize);
    let page = ms
        .db
        .next_sent_history(sender.identity_id, &peer_ik, limit)
        .map_err(|e| e.to_string())?;
    if page.is_empty() {
        return Ok(());
    }
    let _rule_guard = state.pool_rule_transaction(&ms.xite).await;
    let rule = state
        .pool_rules_for(&ms.xite)
        .await
        .into_iter()
        .next()
        .ok_or("missing channel pool")?;
    let rln = channel_rln_send_context(state, ms, &rule, &sender.auth).await?;
    let jitter = send_jitter_max_secs(state).await;
    for row in page {
        if norm_xid(&row.sender_xid) != norm_xid(&sender.xid) {
            return Err("sent row belongs to another identity".into());
        }
        let msg_id = row.msg_id;
        let conv = hex::decode(&row.conv_id)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or("invalid conversation ID in sent history")?;
        let SentHistoryRow {
            members,
            subject,
            body,
            sent_ms,
            source_id,
            ..
        } = row;
        let request = ChannelSendRequest {
            recipients: Vec::new(),
            subject,
            body,
            app: "mail".into(),
            conv_hint: Some(conv),
        };
        let delay = Duration::from_secs(rand_u64_below(jitter.saturating_add(1)));
        let scheduled =
            now_ms().saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX));
        prepare_outbound_records(
            state,
            ms,
            sender.clone(),
            &request,
            members,
            std::slice::from_ref(sibling),
            conv,
            rule.clone(),
            rln.clone(),
            0,
            scheduled,
            Some(epix_envelope::MailOrigin { source_id, sent_ms }),
            false,
        )
        .await?;
        ms.db
            .mark_sent_history_staged(sender.identity_id, &peer_ik, msg_id)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
