//! Phase F gate: two independent "nodes" that received the same records
//! in DIFFERENT orders (and one with duplicates, as a gossiping OR-set
//! delivers) compute byte-identical segment, index, rollup, and
//! checkpoint roots. This is the no-sealer proof: organization is a pure
//! function of the record set, so convergence needs no online authority.

use epix_feed::checkpoint::Checkpoint;
use epix_feed::index::TargetIndex;
use epix_feed::rollup::Rollup;
use epix_feed::segment::{seal, Spine};
use epix_feed::{Kind, Record};
use epix_blob::ObjId;

/// Build a realistic record set: a gallery of posts, comments, edits,
/// reactions (with un-likes), and a moderation tombstone.
fn corpus() -> Vec<Record> {
    let mut v = Vec::new();
    let mk = |id: &str, author: &str, target: &str, clock: u64, kind: Kind| {
        let canonical = format!("{id}|{author}|{target}|{clock}|{kind:?}").into_bytes();
        Record { canonical, id: id.into(), author: author.into(), target: target.into(), clock, kind }
    };
    for p in 0..5 {
        let post = format!("post{p}");
        v.push(mk(&post, "author", "", (p * 10 + 1) as u64, Kind::Post));
        for c in 0..4 {
            let cid = format!("c{p}_{c}");
            v.push(mk(&cid, &format!("u{c}"), &post, (p * 10 + 2 + c) as u64, Kind::Comment));
            // Half the comments get edited.
            if c % 2 == 0 {
                v.push(mk(&cid, &format!("u{c}"), &post, (p * 10 + 50 + c) as u64, Kind::Comment));
            }
            // Reactions with a later un-like on some.
            let lid = format!("l{p}_{c}");
            v.push(mk(&lid, &format!("u{c}"), &post, (p * 10 + 3 + c) as u64,
                Kind::Reaction { kind: "like".into(), active: true }));
            if c == 1 {
                v.push(mk(&lid, &format!("u{c}"), &post, (p * 10 + 60) as u64,
                    Kind::Reaction { kind: "like".into(), active: false }));
            }
        }
    }
    // One author authors two DISTINCT comments on post0 (plus an edit of
    // the first). The old (author, target, kind) lineage key collapsed
    // these to a single survivor and let the edit double-count; both must
    // now live and the edit must fold to one.
    v.push(mk("ac0", "author", "post0", 6, Kind::Comment));
    v.push(mk("ac1", "author", "post0", 7, Kind::Comment));
    v.push(mk("ac0", "author", "post0", 56, Kind::Comment)); // edit of ac0
    // The moderated comment's tombstone. The adapter emits it with the
    // victim id in the target and the item's own author, so one author
    // cannot tombstone another author's item.
    v.push(mk("c0_1", "u1", "c0_1", 500, Kind::Tombstone));
    v
}

/// Roots a node derives from its record set (its whole observable state).
struct Roots {
    segment: ObjId,
    spine_head: ObjId,
    index: ObjId,
    rollup: ObjId,
    checkpoint: ObjId,
    history: ObjId,
}

fn derive(records: Vec<Record>) -> Roots {
    // Seal two range-partitioned segments (early + late), chain them into
    // one monotone spine, then build index, rollup, and checkpoint — all
    // pure functions of the record set.
    let early = seal(&records, 25);
    let late = seal(&records, 1000);
    let mut spine = Spine::new();
    spine.append(&early).unwrap();
    spine.append(&late).unwrap();

    let mut index = TargetIndex::new();
    index.add_segment(&late);

    let items: Vec<String> = (0..5).map(|p| format!("post{p}")).collect();
    let rollup = Rollup::compute(&items, &records);
    let checkpoint = Checkpoint::compute(&records, 1000, ObjId([0; 32]));

    Roots {
        segment: late.root,
        spine_head: spine.head(),
        index: index.root(),
        rollup: rollup.root(),
        checkpoint: checkpoint.root,
        history: checkpoint.history_root,
    }
}

#[test]
fn two_nodes_same_records_different_order_agree() {
    let base = corpus();

    // Node A: records in arrival order.
    let a = derive(base.clone());

    // Node B: reversed arrival order + duplicate deliveries (OR-set
    // gossip delivers the same record more than once).
    let mut b_records = base.clone();
    b_records.reverse();
    b_records.extend(base.iter().step_by(3).cloned()); // duplicates

    // Dedup by content address the way a store does before folding.
    let mut seen = std::collections::HashSet::new();
    b_records.retain(|r| seen.insert(r.addr().0));
    let b = derive(b_records);

    assert_eq!(a.segment, b.segment, "segment roots diverge");
    assert_eq!(a.spine_head, b.spine_head, "spine heads diverge");
    assert_eq!(a.index, b.index, "index roots diverge");
    assert_eq!(a.rollup, b.rollup, "rollup roots diverge");
    assert_eq!(a.checkpoint, b.checkpoint, "checkpoint roots diverge");
    assert_eq!(a.history, b.history, "history roots diverge");
}

#[test]
fn absolute_state_values_exercise_the_fixes() {
    // Node-vs-node equality alone can't catch a bug both nodes share, so
    // pin the absolute checkpoint and rollup values the fixes produce.
    let base = corpus();
    let ck = Checkpoint::compute(&base, 1000, ObjId([0; 32]));

    // FIX 2 (posts): one author's five distinct posts all survive; the old
    // (author, target, kind) lineage collapsed them to a single winner.
    for p in 0..5 {
        let pid = format!("post{p}");
        assert!(
            ck.live.iter().any(|r| r.id == pid && matches!(r.kind, Kind::Post)),
            "post {pid} missing from live set",
        );
    }
    // FIX 2 (comments): the same author's two distinct comments on post0
    // both survive.
    assert!(ck.live.iter().any(|r| r.id == "ac0" && r.author == "author"));
    assert!(ck.live.iter().any(|r| r.id == "ac1" && r.author == "author"));
    // FIX 2/3 (edit): the edit of ac0 (same id) folds to a single winner.
    assert_eq!(ck.live.iter().filter(|r| r.id == "ac0").count(), 1);
    // Tombstone (victim id in target) drops the moderated comment.
    assert!(ck.tombstones.contains(&("u1".to_string(), "c0_1".to_string())));
    assert!(!ck.live.iter().any(|r| r.id == "c0_1"));

    // FIX 1+3 (rollup): post0 counts only LIVE comment winners:
    // c0_0, c0_2, c0_3, ac0, ac1 = 5. Edits fold to one and the tombstoned
    // c0_1 is excluded.
    let items: Vec<String> = (0..5).map(|p| format!("post{p}")).collect();
    let roll = Rollup::compute(&items, &base);
    assert_eq!(roll.get("post0").unwrap().comment_count, 5);
}

#[test]
fn scaling_cost_is_bounded_per_view() {
    // A large feed still yields an O(window) view: opening one post
    // touches only that post's indexed locations, independent of total
    // corpus size. We assert the index gives O(comments-on-post) not
    // O(all records).
    let mut records = Vec::new();
    let mk = |id: String, target: &str, clock: u64, kind: Kind| {
        let canonical = format!("{id}|{target}|{clock}|{kind:?}").into_bytes();
        Record { id, author: "u".into(), target: target.into(), clock, kind, canonical }
    };
    // 5000 comments spread across 1000 posts.
    for i in 0..5000u64 {
        let post = format!("post{}", i % 1000);
        records.push(mk(format!("c{i}"), &post, i, Kind::Comment));
    }
    let seg = seal(&records, u64::MAX);
    let mut index = TargetIndex::new();
    index.add_segment(&seg);
    // Opening post0 touches ~5 comments, not 5000.
    let locs = index.locations("post0");
    assert!(locs.len() <= 6, "per-post view should be O(window), got {}", locs.len());
    assert!(!locs.is_empty());
}
