//! Moderation deletes through the feed path, with records shaped and signed
//! the way the apps produce them: `recordSign` sets `author` to the signer,
//! and Talk's `User.moderateDelete` writes a tombstone carrying the victim's
//! `post_id`, `nonce` and `date_added` (but not the app's id field) into the
//! victim's own merge file. The feed must hide exactly what the merge-file
//! fold (`epix_content::live_records`) hides: an authorized moderator's
//! tombstone hides the item, a tombstone the fold does not accept for that
//! file hides nothing.

use epix_blob::ObjId;
use epix_content::{derive_post_id, derive_post_id_keyed, make_container, record_signed_data};
use epix_feed::adapter::{records_from_container, FeedDescriptor};
use epix_feed::checkpoint::Checkpoint;
use epix_feed::rollup::Rollup;
use epix_feed::{Kind, Record};
use serde_json::{json, Value};

/// Well past every record clock below, and record clocks stay inside the
/// verify skew bound.
const NOW_MS: i64 = 1_800_000_000_000;

struct Key {
    privkey: String,
    addr: String,
}

fn key() -> Key {
    // Generated at runtime, never a literal key.
    let privkey = epix_crypt::new_seed();
    let addr = epix_crypt::privatekey_to_address(&privkey).unwrap();
    Key { privkey, addr }
}

/// What the node's `recordSign` does: set `author` to the signing key's
/// address, mint the post_id on creation, sign the canonical payload.
fn record_sign(key: &Key, mut record: Value) -> Value {
    record["author"] = json!(key.addr);
    if record.get("post_id").is_none() {
        let pid = match record.get("key").and_then(|v| v.as_str()) {
            Some(k) => derive_post_id_keyed(&key.addr, k),
            None => derive_post_id(
                &key.addr,
                record["nonce"].as_str().unwrap(),
                record["date_added"].as_i64().unwrap(),
            ),
        };
        record["post_id"] = json!(pid);
    }
    record["sign"] = json!(epix_crypt::sign(&record_signed_data(&record), &key.privkey).unwrap());
    record
}

/// Talk's `User.createRecord("comments", ...)` for a new comment.
fn talk_comment(key: &Key, comment_id: i64, topic_uri: &str, body: &str, clock: i64) -> Value {
    record_sign(
        key,
        json!({
            "nonce": epix_crypt::new_seed(),
            "clock": clock,
            "supersedes": 0,
            "deleted": false,
            "date_added": 1_737_331_200,
            "comment_id": comment_id,
            "topic_uri": topic_uri,
            "body": body,
            "added": 1_737_331_200,
        }),
    )
}

/// Talk's `User.moderateDelete`: a tombstone for `orig` signed by `key`
/// (normally a moderator). It carries the item's post_id and id origin, not
/// its `comment_id`, and `recordSign` makes `key` its author.
fn talk_moderate_delete(key: &Key, orig: &Value) -> Value {
    let clock = orig["clock"].as_i64().unwrap();
    record_sign(
        key,
        json!({
            "post_id": orig["post_id"],
            "clock": clock + 1,
            "supersedes": clock,
            "deleted": true,
            "moderated": true,
            "body": "",
            "date_added": orig["date_added"],
            "nonce": orig["nonce"],
        }),
    )
}

/// A Talk-like comments feed descriptor (millisecond `clock`).
fn comments_feed() -> FeedDescriptor {
    FeedDescriptor::parse(
        "comments",
        &json!({
            "files": "data/users/*/comments.json",
            "record_key": "post",
            "map": { "id": "comment_id", "author": "author", "clock": "clock",
                     "target": "topic_uri" },
            "kind": { "default": "comment" }
        }),
        None,
    )
    .unwrap()
}

/// What `gather_feed_records` does: each merge file is converted against the
/// signer set of its own directory, and the results are pooled.
fn gather(desc: &FeedDescriptor, files: &[(&[Value], &[String])]) -> Vec<Record> {
    let mut out = Vec::new();
    for (records, signers) in files {
        out.extend(records_from_container(desc, records, signers, NOW_MS));
    }
    out
}

fn checkpoint(records: &[Record]) -> Checkpoint {
    let boundary = records.iter().map(|r| r.clock).max().unwrap_or(0);
    Checkpoint::compute(records, boundary, ObjId([0; 32]))
}

fn live_ids(ck: &Checkpoint) -> Vec<(String, String)> {
    let mut ids: Vec<_> = ck
        .live
        .iter()
        .map(|r| (r.author.clone(), r.id.clone()))
        .collect();
    ids.sort();
    ids
}

#[test]
fn a_moderator_tombstone_hides_the_item_in_the_feed() {
    let (alice, moderator) = (key(), key());
    // Alice's directory: she and the moderator (via user_contents rules) are
    // its authorized signers.
    let alice_signers = vec![alice.addr.clone(), moderator.addr.clone()];

    let spam = talk_comment(&alice, 7, "3_topic", "spam", 1_000);
    let kept = talk_comment(&alice, 8, "3_topic", "a fine comment", 2_000);
    let tomb = talk_moderate_delete(&moderator, &spam);
    // The bug: the tombstone names the moderator, not Alice.
    assert_eq!(tomb["author"], json!(moderator.addr));
    let file = vec![spam, kept.clone(), tomb];

    // The merge-file fold (what the database shows) hides the spam.
    let db_live = epix_content::live_records(&make_container(file.clone()));
    assert_eq!(db_live, vec![kept]);

    let records = gather(&comments_feed(), &[(&file, &alice_signers)]);
    let ck = checkpoint(&records);
    assert_eq!(
        live_ids(&ck),
        vec![(alice.addr.clone(), "8".to_string())],
        "the moderated comment is gone from the feed, the other stays",
    );
    let roll = Rollup::compute(&["3_topic".to_string()], &records);
    assert_eq!(roll.get("3_topic").unwrap().comment_count, 1);
    // No version of the moderated comment is left in the feed at all.
    assert!(!records
        .iter()
        .any(|r| r.id == "7" && r.kind == Kind::Comment));
}

#[test]
fn an_unauthorized_tombstone_does_not_hide_the_item() {
    let (alice, moderator, mallory) = (key(), key(), key());
    let alice_signers = vec![alice.addr.clone(), moderator.addr.clone()];
    let mallory_signers = vec![mallory.addr.clone(), moderator.addr.clone()];
    let moderator_signers = vec![moderator.addr.clone()];

    let alice_post = talk_comment(&alice, 7, "3_topic", "alice wrote this", 1_000);
    let mod_post = talk_comment(&moderator, 9, "3_topic", "the moderator wrote this", 1_500);

    // 1. Mallory signs a moderation tombstone for Alice's comment and slips it
    //    into Alice's file. She is not a signer of Alice's directory, so the
    //    record does not verify there.
    let forged_in_alice = talk_moderate_delete(&mallory, &alice_post);
    let alice_file = vec![alice_post.clone(), forged_in_alice];

    // 2. In her OWN file Mallory tombstones Alice's post_id (and keeps the
    //    comment_id so the feed adapter maps it), and replays the moderator's
    //    signed comment next to a tombstone for it. The moderator is a signer
    //    of every user directory, so the copy verifies in Mallory's file and
    //    the fold hides it THERE, but only there.
    let mut own_tomb = talk_moderate_delete(&mallory, &alice_post);
    own_tomb["comment_id"] = json!(7);
    let own_tomb = record_sign(&mallory, own_tomb);
    let replay_tomb = talk_moderate_delete(&mallory, &mod_post);
    let mallory_file = vec![own_tomb, mod_post.clone(), replay_tomb];
    assert!(
        epix_content::live_records(&make_container(mallory_file.clone())).is_empty(),
        "the fold hides the replayed copy inside Mallory's file",
    );

    let moderator_file = vec![mod_post.clone()];
    let records = gather(
        &comments_feed(),
        &[
            (&alice_file, &alice_signers),
            (&mallory_file, &mallory_signers),
            (&moderator_file, &moderator_signers),
        ],
    );
    let ck = checkpoint(&records);
    let mut expected = vec![
        (alice.addr.clone(), "7".to_string()),
        (moderator.addr.clone(), "9".to_string()),
    ];
    expected.sort();
    assert_eq!(live_ids(&ck), expected, "neither post is hidden by Mallory");
    let roll = Rollup::compute(&["3_topic".to_string()], &records);
    assert_eq!(roll.get("3_topic").unwrap().comment_count, 2);
}

#[test]
fn a_moderator_tombstone_hides_an_epixpost_post() {
    // The EpixPost hub's real "posts" descriptor: id is the post_id itself
    // and the clock is date_added in seconds.
    let desc = FeedDescriptor::parse(
        "posts",
        &json!({
            "clock_unit": "s",
            "files": "data/users/*/posts.json",
            "kind": { "default": "post" },
            "map": { "author": "author", "clock": "date_added", "id": "post_id",
                     "target": null },
            "record_format": "epix-orset-1",
            "record_key": "post"
        }),
        None,
    )
    .unwrap();
    let (alice, moderator) = (key(), key());
    let signers = vec![alice.addr.clone(), moderator.addr.clone()];
    let post = record_sign(
        &alice,
        json!({
            "nonce": epix_crypt::new_seed(), "clock": 1_000, "supersedes": 0,
            "deleted": false, "body": "Hello Epix!", "date_added": 1_775_058_425_i64,
        }),
    );
    let other = record_sign(
        &alice,
        json!({
            "nonce": epix_crypt::new_seed(), "clock": 1_000, "supersedes": 0,
            "deleted": false, "body": "Still here", "date_added": 1_775_058_500_i64,
        }),
    );
    let tomb = talk_moderate_delete(&moderator, &post);
    let file = vec![post.clone(), other.clone(), tomb];

    let records = gather(&desc, &[(&file, &signers)]);
    let ck = checkpoint(&records);
    assert_eq!(
        live_ids(&ck),
        vec![(
            alice.addr.clone(),
            other["post_id"].as_i64().unwrap().to_string()
        )],
    );
    // The moderator's tombstone still enters the feed (it maps an id here),
    // keyed on the moderator, so it can never delete anything of Alice's by
    // itself; the post is gone because the fold dropped it.
    assert!(records
        .iter()
        .any(|r| r.kind == Kind::Tombstone && r.author == moderator.addr));
}

#[test]
fn an_epixpost_unlike_removes_the_like_from_the_count() {
    // The same fold applies to the hub's "comment_likes" reaction feed, where
    // EpixPost's toggleCommentLike writes an un-like as a `deleted: true`
    // version of the like's key. The feed used to keep counting the like.
    let desc = FeedDescriptor::parse(
        "comment_likes",
        &json!({
            "clock_unit": "s",
            "files": "data/users/*/comment_likes.json",
            "kind": { "default": "reaction", "reaction_kind_field": "reaction" },
            "map": { "author": "author", "clock": "date_added", "id": "key",
                     "target": "comment_uri" },
            "record_format": "epix-orset-1",
            "record_key": "post"
        }),
        None,
    )
    .unwrap();
    let (alice, bob) = (key(), key());
    let like = |k: &Key, clock: i64, supersedes: i64, deleted: bool, date_added: i64| {
        record_sign(
            k,
            json!({
                "key": "c1_uri", "nonce": epix_crypt::new_seed(), "clock": clock, "supersedes": supersedes,
                "deleted": deleted, "comment_uri": "c1_uri", "reaction": "like",
                "date_added": date_added,
            }),
        )
    };
    let alice_file = vec![
        like(&alice, 1_000, 0, false, 1_775_000_000),
        like(&alice, 2_000, 1_000, true, 1_775_000_100),
    ];
    let bob_file = vec![like(&bob, 1_500, 0, false, 1_775_000_050)];
    let records = gather(
        &desc,
        &[
            (&alice_file, &[alice.addr.clone()][..]),
            (&bob_file, &[bob.addr.clone()][..]),
        ],
    );
    let ck = checkpoint(&records);
    assert_eq!(
        ck.reaction_counts.get("c1_uri").and_then(|k| k.get("like")),
        Some(&1)
    );
}
