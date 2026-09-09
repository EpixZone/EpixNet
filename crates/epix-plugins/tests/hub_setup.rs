//! The per-identity channel setup, end to end on one node: the plugin boots
//! with no identity and answers reads with nothing; linking an identity makes
//! the node publish that identity's key bundle into the hub, signed as that
//! identity; a second identity gets its own directory; reads follow the xite's
//! selected identity; xites without a channel grant are refused; removing an
//! identity drops its private index rows.

use epix_plugin::Plugin;
use epix_plugins::channel::{ChannelPlugin, EPIX_MAIL_XITE};
use epix_ui::state::{AppState, XiteEntry};
use epix_ui::{WsCommand, WsSession};
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// A hub xite: the pool descriptor at the root, and user directories gated by
/// the xID chain cert with the bundle file rules the Mail xite used.
fn write_hub(hub_key: &str, hub: &str, storage: &XiteStorage) -> Value {
    let mut users = json!({
        "address": hub,
        "inner_path": "data/users/content.json",
        "modified": 1.0,
        "files": {},
        "user_contents": {
            "permissions": {},
            "cert_signers": { "xid.epix": ["chain"] },
            "permission_rules": {
                ".*": { "files_allowed": "data\\.json|data-[0-9a-z]+\\.json", "max_size": 8192 }
            }
        }
    });
    epix_content::sign(&mut users, hub_key).unwrap();
    storage
        .write("data/users/content.json", &serde_json::to_vec(&users).unwrap())
        .unwrap();
    let mut root = json!({
        "address": hub,
        "modified": 1.0,
        "files": {},
        "includes": { "data/users/content.json": {} },
        "pool": { "channels": {
            "dir": "pool", "class": "epix-pool-1", "since_week": 0, "fanout": 16,
            "pow_bits": 6, "pad_buckets": [8192, 32768], "max_record_bytes": 60000,
            "max_shard_bytes": 6_000_000, "sync_order": "newest_first"
        }}
    });
    epix_content::sign(&mut root, hub_key).unwrap();
    storage.write("content.json", &serde_json::to_vec(&root).unwrap()).unwrap();
    root
}

async fn wait_for<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    for _ in 0..600 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn read_json(state: &AppState, hub: &str, path: &str) -> Option<Value> {
    let bytes = state.read_xite_file(hub, path).await?;
    serde_json::from_slice(&bytes).ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linked_identities_get_their_bundles_published_to_the_hub() {
    let home = tempfile::tempdir().unwrap();
    let state = AppState::with_data_dir("test", home.path());
    let hub_key = epix_crypt::new_seed();
    let hub = epix_crypt::privatekey_to_address(&hub_key).unwrap();
    let storage = XiteStorage::new(home.path().join("data").join(&hub));
    let root = write_hub(&hub_key, &hub, &storage);
    state.add_xite(&hub, XiteEntry { storage: storage.clone(), content: Some(root) }).await;
    state.config_set("channel_xite", json!(hub)).await;
    state.config_set("channel_legacy_xites", json!("")).await;

    let commands = ChannelPlugin.ws_commands();
    let cmd = |name: &str| -> Arc<dyn WsCommand> {
        commands.iter().find(|c| c.name() == name).cloned().unwrap_or_else(|| panic!("{name}"))
    };
    let mail = WsSession::new_trusted(state.clone(), Some(EPIX_MAIL_XITE.to_string()));

    // Boot with no identity at all: the plugin comes up, the hub is found, and
    // every read answers with nothing rather than an error.
    ChannelPlugin.start(&state);
    let threads = cmd("channelThreads");
    wait_for("the channel plugin", || async {
        threads.handle(&mail, &json!([{}])).await.is_ok()
    })
    .await;
    assert_eq!(threads.handle(&mail, &json!([{}])).await.unwrap(), json!({ "threads": [] }));
    let info_cmd = cmd("channelSessionInfo");
    wait_for("the hub", || async {
        info_cmd.handle(&mail, &json!([{}])).await.unwrap()["hub_ready"] == true
    })
    .await;
    let info = info_cmd.handle(&mail, &json!([{}])).await.unwrap();
    assert!(info["identity"].is_null(), "{info}");
    assert_eq!(info["identities"], json!([]));
    assert_eq!(info["key_bundle_published"], false);
    assert_eq!(cmd("channelContacts").handle(&mail, &json!([{}])).await.unwrap(), json!([]));
    assert!(cmd("channelIdentityStatus").handle(&mail, &json!([{}])).await.unwrap().is_null());
    let err = cmd("channelSend")
        .handle(&mail, &json!([["bob"], "hi", "body"]))
        .await
        .unwrap_err();
    assert_eq!(err, epix_user::XID_REQUIRED);

    // Link an identity: the node publishes its bundle into the hub, signed as
    // that identity, and reports it published.
    let alice = state.test_support_link_identity("alice").await;
    wait_for("alice's bundle in the hub", || async {
        state
            .identity_config_rows()
            .await
            .iter()
            .any(|r| r["xid"] == "alice.epix" && r["status"]["Channels"]["state"] == "published")
    })
    .await;
    let bundle = read_json(&state, &hub, "data/users/alice.epix/data.json").await.unwrap();
    assert_eq!(bundle["auth"], alice);
    assert!(bundle["auth_sig"].is_string(), "authenticated v3 bundle: {bundle}");
    let content = read_json(&state, &hub, "data/users/alice.epix/content.json").await.unwrap();
    assert_eq!(content["cert_user_id"], "alice@xid.epix");
    assert_eq!(content["cert_auth_type"], "xid");
    assert!(content["signs"][&alice].is_string(), "signed as alice: {content}");
    assert!(content["files"]["data.json"]["sha512"].is_string());
    let info = info_cmd.handle(&mail, &json!([{}])).await.unwrap();
    assert_eq!(info["identity"]["xid"], "alice.epix");
    assert_eq!(info["identity"]["setup"]["state"], "published");
    assert_eq!(info["key_bundle_published"], true, "{info}");
    assert_eq!(info["identities"].as_array().unwrap().len(), 1);
    let status = cmd("channelIdentityStatus").handle(&mail, &json!([{}])).await.unwrap();
    assert_eq!(status["summary"], "channels: published");

    // A second identity gets its own directory; the first is untouched.
    let bob = state.test_support_link_identity("bob").await;
    wait_for("bob's bundle in the hub", || async {
        read_json(&state, &hub, "data/users/bob.epix/data.json").await.is_some()
            && state
                .identity_config_rows()
                .await
                .iter()
                .any(|r| r["xid"] == "bob.epix" && r["status"]["Channels"]["state"] == "published")
    })
    .await;
    let bob_bundle = read_json(&state, &hub, "data/users/bob.epix/data.json").await.unwrap();
    assert_eq!(bob_bundle["auth"], bob);
    let alice_again = read_json(&state, &hub, "data/users/alice.epix/data.json").await.unwrap();
    assert_eq!(alice_again["auth"], alice, "alice's slot was not clobbered");

    // Reads follow the xite's selected identity: Mail switched to bob sees bob.
    state.identity_select(EPIX_MAIL_XITE, Some(&bob)).await.unwrap();
    let info = info_cmd.handle(&mail, &json!([{}])).await.unwrap();
    assert_eq!(info["identity"]["xid"], "bob.epix");
    assert_eq!(info["identities"].as_array().unwrap().len(), 2);
    // An explicit identity parameter overrides the xite's selection.
    let info = info_cmd.handle(&mail, &json!([{ "xid": "alice.epix" }])).await.unwrap();
    assert_eq!(info["identity"]["xid"], "alice.epix");

    // A xite without a channel grant is refused; one with CHANNELS is not.
    state
        .add_xite("epix1talk", XiteEntry {
            storage: XiteStorage::new(home.path().join("data/epix1talk")),
            content: Some(json!({ "address": "epix1talk", "files": {} })),
        })
        .await;
    let talk = WsSession::new(state.clone(), Some("epix1talk".into()));
    let err = threads.handle(&talk, &json!([{}])).await.unwrap_err();
    assert!(err.contains("permission"), "{err}");
    state.add_permission("epix1talk", "CHANNELS").await;
    assert!(threads.handle(&talk, &json!([{}])).await.is_ok());

    // A scoped grant (`Channels:talk`) is confined to its own app: it cannot
    // subscribe to, list, search or send as another app.
    for (addr, grant) in [("epix1dm", "Channels:talk"), ("epix1other", "Channels:other")] {
        state
            .add_xite(addr, XiteEntry {
                storage: XiteStorage::new(home.path().join("data").join(addr)),
                content: Some(json!({ "address": addr, "files": {} })),
            })
            .await;
        state.add_permission(addr, grant).await;
    }
    let dm = WsSession::new(state.clone(), Some("epix1dm".into()));
    let other = WsSession::new(state.clone(), Some("epix1other".into()));
    let subscribe = cmd("channelSubscribe");
    assert_eq!(subscribe.handle(&dm, &json!([{}])).await.unwrap()["app"], "talk");
    let err = subscribe.handle(&dm, &json!([{ "app": "mail" }])).await.unwrap_err();
    assert!(err.contains("scoped to app talk"), "{err}");
    let err = threads.handle(&dm, &json!([{ "app": "mail" }])).await.unwrap_err();
    assert!(err.contains("scoped to app talk"), "{err}");
    assert_eq!(threads.handle(&dm, &json!([{}])).await.unwrap(), json!({ "threads": [] }));
    let send = cmd("channelSend");
    let err = send
        .handle(&dm, &json!([["bob.epix"], "hi", "body", { "app": "mail" }]))
        .await
        .unwrap_err();
    assert!(err.contains("scoped to app talk"), "{err}");
    let err = send
        .handle(&mail, &json!([["bob.epix"], "hi", "body", { "app": "Not Valid" }]))
        .await
        .unwrap_err();
    assert!(err.contains("invalid app name"), "{err}");

    // A DM sent from the scoped xite (as alice, the default identity) is a talk
    // thread. The sender's own copy is invisible to a mail-scoped view and to a
    // mail-scoped search, and the conversation cannot be opened by another app.
    state.config_set("channel_send_jitter_max_secs", json!(0)).await;
    state.config_set("channel_burst_jitter_max_secs", json!(0)).await;
    let sent = send
        .handle(&dm, &json!([["bob.epix"], "dm", "hey there ZXQ9"]))
        .await
        .unwrap();
    assert_eq!(sent["ok"], true, "{sent}");
    let conv = sent["conv_id"].as_str().unwrap().to_string();
    let mine = threads.handle(&dm, &json!([{}])).await.unwrap();
    assert_eq!(mine["threads"][0]["conv_id"], conv, "{mine}");
    assert_eq!(mine["threads"][0]["app"], "talk");
    // Mail's own view (as alice again) is mail-scoped; the full grant sees it.
    let alice_mail = WsSession::new_trusted(state.clone(), Some(EPIX_MAIL_XITE.to_string()));
    let mail_view = threads
        .handle(&alice_mail, &json!([{ "xid": "alice.epix", "app": "mail" }]))
        .await
        .unwrap();
    assert!(mail_view["threads"].as_array().unwrap().is_empty(), "{mail_view}");
    let all_view = threads.handle(&alice_mail, &json!([{ "xid": "alice.epix" }])).await.unwrap();
    assert_eq!(all_view["threads"][0]["app"], "talk", "{all_view}");
    let search = cmd("channelSearch");
    let found = search
        .handle(&alice_mail, &json!(["ZXQ9", 10, { "app": "mail", "xid": "alice.epix" }]))
        .await
        .unwrap();
    assert!(found["results"].as_array().unwrap().is_empty(), "{found}");
    let found = search.handle(&dm, &json!(["ZXQ9", 10])).await.unwrap();
    assert_eq!(found["results"].as_array().unwrap().len(), 1, "{found}");
    let err = cmd("channelConversation")
        .handle(&other, &json!([{ "conv_id": conv }]))
        .await
        .unwrap_err();
    assert!(err.contains("belongs to app talk"), "{err}");
    let opened = cmd("channelConversation").handle(&dm, &json!([{ "conv_id": conv }])).await.unwrap();
    assert_eq!(opened["messages"].as_array().unwrap().len(), 1, "{opened}");

    // Bob (Mail's current identity) receives it on this same node: the tag came
    // out of the sealed body, so his copy is a talk thread too, badged for the
    // subscribed talk xite rather than for Mail.
    wait_for("bob's inbound talk thread", || async {
        let view = threads.handle(&mail, &json!([{}])).await.unwrap();
        view["threads"].as_array().unwrap().iter().any(|t| t["conv_id"] == conv && t["app"] == "talk")
    })
    .await;
    let bob_mail = threads.handle(&mail, &json!([{ "app": "mail" }])).await.unwrap();
    assert!(bob_mail["threads"].as_array().unwrap().is_empty(), "{bob_mail}");
    let info = info_cmd.handle(&mail, &json!([{ "app": "mail" }])).await.unwrap();
    assert_eq!(info["identity"]["unread"], 0, "{info}");
    let info = info_cmd.handle(&mail, &json!([{}])).await.unwrap();
    assert_eq!(info["identity"]["unread"], 1, "{info}");
    let badges = state.local_notification_entries().await;
    let talk_badge = badges.iter().find(|b| b["name"] == "channel:talk").expect("talk badge");
    assert_eq!(talk_badge["site"], "epix1dm");
    assert_eq!(talk_badge["count"], 1, "{badges:?}");
    assert!(
        badges
            .iter()
            .filter(|b| b["site"] == EPIX_MAIL_XITE)
            .all(|b| b["count"] == 0),
        "mail badges do not count talk: {badges:?}"
    );

    // Turning channels off for an identity stops indexing it (state "off");
    // turning them back on schedules the setup again.
    let off = cmd("channelIdentitySetEnabled")
        .handle(&mail, &json!([bob, false]))
        .await
        .unwrap();
    assert_eq!(off["state"], "off");
    let on = cmd("channelIdentitySetEnabled")
        .handle(&mail, &json!([bob, true]))
        .await
        .unwrap();
    assert_eq!(on["state"], "keys");
    wait_for("bob republished", || async {
        state
            .identity_config_rows()
            .await
            .iter()
            .any(|r| r["xid"] == "bob.epix" && r["status"]["Channels"]["state"] == "published")
    })
    .await;

    // Removing an identity drops its private index rows; the hub keeps the
    // bundle it already published (nothing can sign a removal).
    assert!(state.identity_remove(&bob).await);
    wait_for("bob forgotten", || async {
        let info = info_cmd.handle(&mail, &json!([{}])).await.unwrap();
        !info["identities"].as_array().unwrap().iter().any(|i| i["xid"] == "bob.epix")
    })
    .await;
    assert!(read_json(&state, &hub, "data/users/bob.epix/data.json").await.is_some());
    // Mail's override pointed at bob and was cleared with him: it inherits
    // the default (alice) again.
    let info = info_cmd.handle(&mail, &json!([{}])).await.unwrap();
    assert_eq!(info["identity"]["xid"], "alice.epix");
}
