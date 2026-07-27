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
    // A moderator tombstones one comment.
    v.push(mk("t0", "mod", "c0_1", 500, Kind::Tombstone));
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
