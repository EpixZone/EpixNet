//! Demonstration: three identities (alice, bob, carol) send encrypted mail to
//! one another through the anonymous channel pool.
//!
//! Each message is sealed with the real X3DH + Double-Ratchet engine, written to
//! a genuine on-disk pool shard that carries only ciphertext, and then
//! trial-decrypted by the intended recipient. Run with:
//!
//!   cargo test -p epix-plugins --test three_identity_mail -- --nocapture

use std::path::Path;
use std::sync::Arc;

use epix_channel::ChannelDb;
use epix_envelope::{process_record_one, send_message, Engine, IdentitySecret, ProcessOutcome};
use epix_pairwise_engine::PairwiseEngine;
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::XiteStorage;
use serde_json::{json, Value};

const XITE: &str = "epix1pvta40a8d944w3npr9ztqrfh3wec53hh2je4fa";

fn pool_descriptor() -> Value {
    json!({
        "address": XITE,
        "pool": { "channels": {
            "dir": "pool", "class": "epix-pool-1", "since_week": 0, "fanout": 16,
            "pow_bits": 6, "pad_buckets": [8192, 32768], "max_record_bytes": 60000,
            "max_shard_bytes": 6_000_000, "sync_order": "newest_first"
        }}
    })
}

async fn node(data_root: &Path, xite_root: &Path) -> Arc<AppState> {
    std::fs::create_dir_all(xite_root).unwrap();
    let state = AppState::with_data_dir("test", data_root);
    state
        .add_xite(
            XITE,
            XiteEntry { storage: XiteStorage::new(xite_root), content: Some(pool_descriptor()) },
        )
        .await;
    state
}

/// One participant: a seed-derived identity + its own private message index +
/// its published key bundle (what others seal to).
struct Identity {
    xid: String,
    seed: IdentitySecret,
    db: ChannelDb,
    id: i64,
    bundle: Value,
}

fn mk(engine: &PairwiseEngine, b: u8, xid: &str) -> Identity {
    let seed = IdentitySecret::new([b; 32]);
    let db = ChannelDb::memory().unwrap();
    let id = db.upsert_identity(xid, &format!("epix1{}", b), 0, None).unwrap();
    let bundle = engine.publish_bundle(&seed, xid);
    Identity { xid: xid.into(), seed, db, id, bundle }
}

/// Parse the on-disk shard and confirm none of its records' ciphertext contains
/// the plaintext body. `env` is the shard's array of pool records.
fn shard_is_ciphertext(shard_bytes: &[u8], plaintext: &str) -> bool {
    use base64::Engine as _;
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    let container: Value = serde_json::from_slice(shard_bytes).unwrap();
    container["env"].as_array().unwrap().iter().all(|rec| {
        let ct = base64::engine::general_purpose::STANDARD
            .decode(rec["ct"].as_str().unwrap())
            .unwrap();
        !contains(&ct, plaintext.as_bytes())
    })
}

#[tokio::test]
async fn three_identities_send_mail_to_each_other() {
    let engine = PairwiseEngine;
    let now = 1_780_000_000_000i64;

    let home = tempfile::tempdir().unwrap();
    let xite_root = home.path().join("data").join(XITE);
    let node = node(home.path(), &xite_root).await;
    let rule = node.pool_rules_for(XITE).await.into_iter().next().unwrap();

    let alice = mk(&engine, 1, "alice.epix");
    let bob = mk(&engine, 2, "bob.epix");
    let carol = mk(&engine, 3, "carol.epix");
    println!("\n=== created 3 identities: alice.epix, bob.epix, carol.epix ===");

    // Anti-spoof resolver: every xid maps to its published bundle.
    let all = [
        (alice.xid.clone(), alice.bundle.clone()),
        (bob.xid.clone(), bob.bundle.clone()),
        (carol.xid.clone(), carol.bundle.clone()),
    ];
    let resolve = |xid: &str| -> Vec<Value> {
        all.iter().filter(|(k, _)| k == xid).map(|(_, b)| b.clone()).collect()
    };

    // Every ordered pair sends a distinct message.
    let mail: [(&Identity, &Identity, &str, &str, [u8; 16]); 3] = [
        (&alice, &bob, "Lunch?", "sushi at noon", [1u8; 16]),
        (&bob, &carol, "Ship it", "PR is green", [2u8; 16]),
        (&carol, &alice, "Re: Lunch?", "count me in", [3u8; 16]),
    ];

    for (from, to, subject, body, conv) in mail {
        // 1) sender seals the message and the node writes it to the pool
        let sent = send_message(
            &from.db, &engine, from.id, &from.seed, &from.xid,
            &[from.xid.clone(), to.xid.clone()], &to.bundle,
            conv, subject, body, now, &rule, true,
        )
        .unwrap();
        let shard = node.append_pool_record(XITE, sent.record.clone()).await.unwrap();

        // 2) the on-disk shard is ciphertext only — the body is not in it
        let bytes = std::fs::read(xite_root.join(&shard)).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("epix-pool-1"));
        assert!(shard_is_ciphertext(&bytes, body), "plaintext body leaked into the pool shard");

        // 3) recipient trial-decrypts it into their private index
        let out = process_record_one(
            &to.db, &engine,
            &[(to.id, to.seed.clone(), to.xid.clone())],
            &sent.record, now + 10, resolve,
        )
        .unwrap();

        match out {
            ProcessOutcome::Indexed { subject: got_subj, sender_xid, conv_id, .. } => {
                let msgs = to.db.messages(to.id, &conv_id).unwrap();
                let got_body = msgs[0]["body"].as_str().unwrap();
                assert_eq!(got_subj, subject);
                assert_eq!(sender_xid.as_deref(), Some(from.xid.as_str()));
                assert_eq!(got_body, body);
                println!(
                    "  {} -> {}: sealed to pool shard {} (ciphertext) | {} decrypted: [{}] \"{}\" from {}",
                    from.xid, to.xid, shard, to.xid, got_subj, got_body,
                    sender_xid.as_deref().unwrap(),
                );
            }
            other => panic!("{} failed to decrypt mail from {}: {other:?}", to.xid, from.xid),
        }

        // 4) a NON-recipient cannot read it — the third party trial-decrypts and gets nothing
        let third = [&alice, &bob, &carol]
            .into_iter()
            .find(|p| p.xid != from.xid && p.xid != to.xid)
            .unwrap();
        let snoop = process_record_one(
            &third.db, &engine,
            &[(third.id, third.seed.clone(), third.xid.clone())],
            &sent.record, now + 10, resolve,
        )
        .unwrap();
        assert!(
            !matches!(snoop, ProcessOutcome::Indexed { .. }),
            "{} must NOT be able to read mail addressed to {}",
            third.xid, to.xid
        );
        println!("      (non-recipient {} could not read it — as expected)", third.xid);
    }

    println!("=== all 3 messages delivered end-to-end encrypted; pool shards leaked no plaintext ===\n");
}
