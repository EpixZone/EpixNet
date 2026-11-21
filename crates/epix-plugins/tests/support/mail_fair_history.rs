//! A source can retain mail larger than the hub's current record limits.
use super::{Device, Hub, CONVERSATION, OLD_TIME};
use epix_channel::ChannelDb;
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) async fn check(source: &Device, phone: &Device, hub: &Hub, source_home: &Path) {
    let db = ChannelDb::open(&source_home.join("private/channels.db")).unwrap();
    let identity = db.identity_by_auth(&source.auth).unwrap().unwrap();
    let members = vec![source.xid.clone(), "bob.epix".into()];
    let oversized = "x".repeat(40_000);
    let deliverable = "small reply after oversized mail";
    for body in [oversized.as_str(), deliverable] {
        db.insert_sent(
            identity.identity_id,
            CONVERSATION,
            Some("bob.epix"),
            &members,
            &source.xid,
            "Wallet Testing",
            body,
            OLD_TIME + 2,
        )
        .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(80);
    loop {
        source.relay(hub, &[phone]).await;
        let received = phone.messages().await;
        assert!(received.iter().all(|row| row["body"] != oversized));
        if let Some(reply) = received.iter().find(|row| row["body"] == deliverable) {
            assert_eq!(reply["dir"], "out");
            assert_eq!(reply["sent_ms"], OLD_TIME + 2);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "an oversized historical row blocked a later reply"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
