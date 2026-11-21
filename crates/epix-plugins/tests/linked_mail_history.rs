//! Three independent private stores connected by the public hub's signed bundles
//! and pool shard transport. Only the chain and peers are local fixtures.
#[path = "support/mail_fair_history.rs"]
mod mail_fair_history;
#[path = "support/mail_finality.rs"]
mod mail_finality;

use epix_channel::ChannelDb;
use epix_core::PeerAddr;
use epix_plugin::Plugin;
use epix_plugins::channel::{ChannelPlugin, EPIX_MAIL_XITE};
use epix_runtime::edx::{edx_hook, enable_serving, ControlHandles};
use epix_ui::command::CommandRegistry;
use epix_ui::state::{AppState, XiteEntry};
use epix_ui::WsSession;
use epix_xite::XiteStorage;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONVERSATION: &str = "034b034b034b034b034b034b034b034b";
const OLD_TIME: i64 = 1_683_000_001_234;

struct Hub {
    address: String,
    root: Value,
    users: Value,
}

impl Hub {
    fn new() -> Self {
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let mut users = json!({
            "address":address, "inner_path":"data/users/content.json", "modified":1.0, "files":{},
            "user_contents":{"permissions":{}, "cert_signers":{"xid.epix":["chain"]},
                "permission_rules":{".*":{"files_allowed":"data\\.json|data-[0-9a-z]+\\.json","max_size":8192}}}
        });
        epix_content::sign(&mut users, &key).unwrap();
        let mut root = json!({
            "address":address,"modified":1.0,"files":{},"includes":{"data/users/content.json":{}},
            "pool":{"channels":{"dir":"pool","class":"epix-pool-1","since_week":0,"fanout":16,
                "pow_bits":6,"pad_buckets":[8192,32768],"max_record_bytes":60000,"max_shard_bytes":6000000,"sync_order":"newest_first"}}
        });
        epix_content::sign(&mut root, &key).unwrap();
        Self {
            address,
            root,
            users,
        }
    }

    async fn install(&self, state: &Arc<AppState>, home: &Path) -> XiteStorage {
        let files = XiteStorage::new(home.join("data").join(&self.address));
        files
            .write("content.json", &serde_json::to_vec(&self.root).unwrap())
            .unwrap();
        files
            .write(
                "data/users/content.json",
                &serde_json::to_vec(&self.users).unwrap(),
            )
            .unwrap();
        state
            .add_xite(
                &self.address,
                XiteEntry {
                    storage: files.clone(),
                    content: Some(self.root.clone()),
                },
            )
            .await;
        files
    }

    async fn start_relay(&self, home: &Path) -> PeerAddr {
        let state = AppState::with_data_dir("public-relay", home);
        self.install(&state, home).await;
        let key = epix_crypt::new_seed();
        let store = enable_serving(&state, home, key.clone(), None)
            .await
            .unwrap();
        let server = epix_protocol::PeerServer::new(edx_hook(
            state,
            store,
            key,
            None,
            ControlHandles::detached(),
            false,
            None,
        ));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = PeerAddr::Ip(listener.local_addr().unwrap());
        tokio::spawn(server.serve(listener));
        address
    }
}

struct Device {
    registry: CommandRegistry,
    session: WsSession,
    state: Arc<AppState>,
    files: XiteStorage,
    xid: String,
    auth: String,
}

impl Device {
    async fn new(home: &Path, hub: &Hub, name: &str) -> Self {
        let state = AppState::with_data_dir("mail-test", home);
        let files = hub.install(&state, home).await;
        state.config_set("channel_xite", json!(hub.address)).await;
        state.config_set("channel_legacy_xites", json!("")).await;
        state
            .config_set("channel_send_jitter_max_secs", json!(0))
            .await;
        state
            .config_set("channel_burst_jitter_max_secs", json!(0))
            .await;
        let auth = state.test_support_link_identity(name).await;
        let mut registry = CommandRegistry::empty();
        for command in ChannelPlugin.ws_commands() {
            registry.register(command);
        }
        let session = WsSession::new(state.clone(), Some(EPIX_MAIL_XITE.into()));
        Self {
            registry,
            session,
            state,
            files,
            auth,
            xid: format!("{name}.epix"),
        }
    }

    async fn connect_relay(&self, home: &Path, hub: &Hub, relay: PeerAddr) {
        self.state
            .set_transport(Arc::new(epix_transport::TcpTransport))
            .await;
        enable_serving(&self.state, home, epix_crypt::new_seed(), None)
            .await
            .unwrap();
        self.state.add_peers(&hub.address, [relay]).await;
    }

    async fn start(&self) {
        ChannelPlugin.start(&self.state);
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if self.state.identity_config_rows().await.iter().any(|row| {
                    row["xid"] == self.xid && row["status"]["Channels"]["state"] == "published"
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("device did not publish its signed key bundle");
    }

    async fn command(&self, name: &str, args: Value) -> Value {
        self.registry
            .dispatch(&self.session, name, &args, 1)
            .await
            .unwrap()
    }

    async fn send(&self, recipient: &str, body: &str) -> Value {
        self.command(
            "channelSend",
            json!([[recipient], "Wallet Testing", body, CONVERSATION]),
        )
        .await
    }

    async fn wait_for_delivery(&self) {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let info = self.command("channelSessionInfo", json!([])).await;
            assert_eq!(info["identity"]["auth"], self.auth);
            if info["outbox_pending"] == 0 {
                return;
            }
            assert!(Instant::now() < deadline, "outbox did not deliver: {info}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn retained_ids(
        &self,
        hub: &Hub,
    ) -> std::collections::BTreeSet<epix_ui::pool::PoolRecordId> {
        self.state
            .pool_all_records(&hub.address)
            .await
            .iter()
            .map(|record| epix_ui::pool::pool_record_id(record).unwrap())
            .collect()
    }

    async fn messages(&self) -> Vec<Value> {
        self.command("channelConversation", json!([{"conv_id":CONVERSATION}]))
            .await["messages"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn deliver_bundle(&self, destination: &Self) {
        let prefix = format!("data/users/{}/", self.xid);
        for path in self
            .files
            .list_files()
            .unwrap()
            .into_iter()
            .filter(|p| p.starts_with(&prefix))
        {
            destination
                .files
                .write(&path, &self.files.read(&path).unwrap())
                .unwrap();
        }
    }

    async fn relay(&self, hub: &Hub, others: &[&Self]) {
        for path in self
            .files
            .list_files()
            .unwrap()
            .into_iter()
            .filter(|p| p.starts_with("pool/") && p.ends_with(".json"))
        {
            let bytes = self.files.read(&path).unwrap();
            for peer in others {
                peer.state
                    .apply_inbound_pool_update(&hub.address, &path, &bytes)
                    .await
                    .unwrap();
            }
        }
    }
}

async fn check_retained_recovery(
    laptop: &Device,
    phone: &Device,
    bob: &Device,
    hub: &Hub,
    attestations: &mail_finality::Attestations,
) {
    let body = "reply awaiting finalized device proof";
    laptop.wait_for_delivery().await;
    let before = phone.retained_ids(hub).await;
    assert_eq!(laptop.send(&bob.xid, body).await["recipients"], 1);
    laptop.wait_for_delivery().await;
    let sent = laptop
        .messages()
        .await
        .into_iter()
        .find(|r| r["body"] == body)
        .unwrap();
    let denied = attestations.failures();
    attestations.pause().await;
    // Deliver once while the validator attestation is unavailable. The stored
    // ciphertext must later be retried without another shard, send or restart.
    laptop.relay(hub, &[phone]).await;
    let retained = phone.retained_ids(hub).await;
    assert!(before.is_subset(&retained) && before.len() < retained.len());
    tokio::time::timeout(Duration::from_secs(15), async {
        while attestations.failures() == denied {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("receiver did not request the unavailable validator attestation");
    assert!(phone.messages().await.iter().all(|r| r["body"] != body));

    attestations.resume();
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let rows = phone.messages().await;
        let recovered: Vec<_> = rows.iter().filter(|r| r["body"] == body).collect();
        if let Some(row) = recovered.first() {
            assert_eq!(recovered.len(), 1);
            assert_eq!(row["sent_ms"], sent["sent_ms"]);
            assert_eq!(row["dir"], "out");
            assert_eq!(row["read"], 1);
            assert_eq!(phone.retained_ids(hub).await, retained);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "retained copy never recovered after finality returned"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

fn headers(rows: &[Value]) -> Vec<(&str, &str, i64)> {
    rows.iter()
        .map(|r| {
            (
                r["body"].as_str().unwrap(),
                r["dir"].as_str().unwrap(),
                r["sent_ms"].as_i64().unwrap(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn linked_devices_receive_live_and_preupgrade_sent_mail() {
    let tmp = tempfile::tempdir().unwrap();
    let hub = Hub::new();
    let laptop_home = tmp.path().join("laptop");
    let laptop = Device::new(&laptop_home, &hub, "alice").await;
    let phone = Device::new(&tmp.path().join("phone"), &hub, "alice").await;
    let bob = Device::new(&tmp.path().join("bob"), &hub, "bob").await;
    let attestations = mail_finality::serve(
        &tmp.path().join("checkpoint.json"),
        &[&laptop.auth, &phone.auth],
        &[&bob.auth],
    )
    .await;
    let active = laptop
        .state
        .xid_identity_snapshot("alice.epix")
        .await
        .unwrap()
        .unwrap();
    assert!(active.finality.is_some());
    assert_eq!(active.identities.len(), 2);

    // This is the unmarked outgoing row created by releases before sent-copy
    // support. Only the original laptop has its message or channel record.
    let members = vec![laptop.xid.clone(), bob.xid.clone()];
    {
        let db = ChannelDb::open(&laptop_home.join("private/channels.db")).unwrap();
        let id = db
            .upsert_identity(&laptop.xid, &laptop.auth, 0, None)
            .unwrap();
        db.insert_sent(
            id,
            CONVERSATION,
            Some(&bob.xid),
            &members,
            &laptop.xid,
            "Wallet Testing",
            "old reply",
            OLD_TIME,
        )
        .unwrap();
    }
    laptop.start().await;
    bob.start().await;
    laptop.deliver_bundle(&phone);
    bob.deliver_bundle(&phone);
    bob.deliver_bundle(&laptop);
    // The new phone publishes a second independently signed device bundle.
    // The laptop's initial history pass can run before this file arrives.
    phone.start().await;
    phone.deliver_bundle(&laptop);
    phone.deliver_bundle(&bob);
    // Both publishers need a genuine encrypted peer receipt before a later
    // record on the same ratchet can leave the durable outbox.
    let public_relay = hub.start_relay(&tmp.path().join("public-relay")).await;
    laptop
        .connect_relay(&laptop_home, &hub, public_relay.clone())
        .await;
    bob.connect_relay(&tmp.path().join("bob"), &hub, public_relay)
        .await;
    let sent = laptop.send(&bob.xid, "new reply").await;
    assert_eq!(sent["ok"], true);
    assert_eq!(
        sent["recipients"], 1,
        "a linked device is not another recipient"
    );
    assert_eq!(sent["conv_id"], CONVERSATION);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        laptop.relay(&hub, &[&phone, &bob]).await;
        if bob
            .messages()
            .await
            .iter()
            .any(|r| r["body"] == "new reply")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "normal recipient never received new message"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(bob.send(&laptop.xid, "confirmation").await["recipients"], 1);

    // Let the scheduled historical worker discover the late bundle and replay
    // the same shards repeatedly, as anti-entropy and a post-restart retry do.
    let deadline = Instant::now() + Duration::from_secs(75);
    let (phone_rows, laptop_rows, bob_rows) = loop {
        laptop.relay(&hub, &[&phone, &bob]).await;
        bob.relay(&hub, &[&laptop, &phone]).await;
        let rows = phone.messages().await;
        let source = laptop.messages().await;
        let recipient = bob.messages().await;
        if (rows.len() >= 3 && source.len() >= 3 && recipient.len() >= 2)
            || Instant::now() >= deadline
        {
            break (rows, source, recipient);
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    };
    let source = headers(&laptop_rows);
    let linked = headers(&phone_rows);
    assert_eq!(
        source.iter().map(|m| (m.0, m.1)).collect::<Vec<_>>(),
        [
            ("old reply", "out"),
            ("new reply", "out"),
            ("confirmation", "in")
        ]
    );
    assert_eq!(source[0].2, OLD_TIME);
    assert_eq!(
        linked, source,
        "phone must retain the original direction and timestamp"
    );
    assert_eq!(
        phone_rows
            .iter()
            .map(|m| m["read"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        [1, 1, 0]
    );
    assert_eq!(
        headers(&bob_rows)
            .iter()
            .map(|m| (m.0, m.1))
            .collect::<Vec<_>>(),
        [("new reply", "in"), ("confirmation", "out")],
        "history copies are only for linked devices"
    );
    let sent = phone.command("channelSent", json!([{"app":"mail"}])).await;
    let items = sent["messages"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for row in items {
        assert_eq!(row["peer_xid"], bob.xid);
        assert_eq!(
            serde_json::from_str::<Vec<String>>(row["members"].as_str().unwrap()).unwrap(),
            members
        );
    }
    check_retained_recovery(&laptop, &phone, &bob, &hub, &attestations).await;
    mail_fair_history::check(&laptop, &phone, &hub, &laptop_home).await;
}
