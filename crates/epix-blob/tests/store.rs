//! Store gate tests: slab round-trip + dedup, the sparse fetch/serve
//! flow (including partial-object re-serving), refcount/evict fuzz
//! against a model, slab sealing + compaction, and crash-reopen
//! revalidation.

use epix_blob::store::{Store, StoreConfig};
use epix_blob::verified::{encode_slice, OutboardBytes};
use epix_blob::{Ns, ObjId};
use std::collections::HashMap;
use std::ops::Range;

fn test_data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

fn oid(bytes: &[u8]) -> ObjId {
    ObjId(*blake3::hash(bytes).as_bytes())
}

/// Encode a verified slice the way a serving peer would.
fn slice_for(data: &[u8], ranges: &[Range<u64>]) -> (ObjId, u64, Vec<u8>) {
    let ob = OutboardBytes::from_slice(data);
    let mut out = Vec::new();
    encode_slice(data, &ob, ranges, &mut out).unwrap();
    (ob.root, ob.size, out)
}

#[test]
fn slab_insert_read_dedup() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();

    let a = test_data(1000);
    let id = oid(&a);
    assert!(store.insert_bytes(id, Ns::Plain, &a, 1).unwrap());
    // Dedup: second insert is a no-op.
    assert!(!store.insert_bytes(id, Ns::Plain, &a, 2).unwrap());
    assert!(store.contains(id).unwrap());
    assert!(store.is_complete(id).unwrap());
    assert_eq!(store.read_bytes(id, 3).unwrap(), a);

    // Poisoned insert (bytes don't hash to the claimed id) must fail.
    let poison = oid(b"claimed");
    assert!(store.insert_bytes(poison, Ns::Plain, b"actual", 4).is_err());
    assert!(!store.contains(poison).unwrap());
}

#[test]
fn ns_bytes_sums_only_the_named_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();

    let plain = test_data(1000);
    let shard_a = test_data(2000);
    let shard_b = test_data(3000);
    store.insert_bytes(oid(&plain), Ns::Plain, &plain, 1).unwrap();
    store.insert_bytes(oid(&shard_a), Ns::Shard, &shard_a, 1).unwrap();
    store.insert_bytes(oid(&shard_b), Ns::Shard, &shard_b, 1).unwrap();

    // The shard budget counts only shard-namespace bytes, not the plain
    // browse-cache object sharing the same store.
    assert_eq!(store.ns_bytes(Ns::Shard).unwrap(), 5000);
    assert_eq!(store.ns_bytes(Ns::Plain).unwrap(), 1000);
}

#[test]
fn slab_serves_verified_slices() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let data = test_data(50_000);
    let id = oid(&data);
    store.insert_bytes(id, Ns::Plain, &data, 1).unwrap();

    // A slice served from the slab decodes against the same root.
    let ranges = [1000u64..2000, 30_000..40_000];
    let mut slice = Vec::new();
    store.encode_slice(id, &ranges, &mut slice, 2).unwrap();

    let dir2 = tempfile::tempdir().unwrap();
    let store2 = Store::open(dir2.path()).unwrap();
    store2.ensure_sparse(id, Ns::Plain, data.len() as u64, 1).unwrap();
    store2.write_slice(id, &ranges, &slice[..], 2).unwrap();
    for r in &ranges {
        assert!(store2.present_bits(id).unwrap().contains_all(
            &epix_blob::bitfield::groups_for_bytes(r)
        ));
    }
}

#[test]
fn sparse_partial_reserves_only_what_it_holds() {
    // Peer A holds the whole object; peer B fetches one range and can
    // then re-serve THAT range (and only that range) verified.
    let data = test_data(200_000);
    let (id, size, _) = slice_for(&data, &[0..1]);

    let dir_b = tempfile::tempdir().unwrap();
    let b = Store::open(dir_b.path()).unwrap();
    b.ensure_sparse(id, Ns::Plain, size, 1).unwrap();

    let held = 50_000u64..80_000;
    let (_, _, slice) = slice_for(&data, &[held.clone()]);
    b.write_slice(id, &[held.clone()], &slice[..], 2).unwrap();
    assert!(!b.is_complete(id).unwrap());

    // B serves the held range to C.
    let mut reserve = Vec::new();
    b.encode_slice(id, &[held.clone()], &mut reserve, 3).unwrap();
    let dir_c = tempfile::tempdir().unwrap();
    let c = Store::open(dir_c.path()).unwrap();
    c.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    c.write_slice(id, &[held.clone()], &reserve[..], 2).unwrap();

    // B refuses to serve what it does not hold.
    let mut out = Vec::new();
    assert!(b.encode_slice(id, &[0..1000], &mut out, 4).is_err());
}

#[test]
fn sparse_completes_and_reads_back() {
    let data = test_data(100_000);
    let (id, size, slice) = slice_for(&data, &[0..100_000]);

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    assert!(store.read_bytes(id, 2).is_err(), "incomplete read must fail");
    store.write_slice(id, &[0..100_000], &slice[..], 3).unwrap();
    assert!(store.is_complete(id).unwrap());
    assert_eq!(store.read_bytes(id, 4).unwrap(), data);
}

#[test]
fn refcount_evict_fuzz_against_model() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();

    // Deterministic xorshift so failures reproduce.
    let mut rng: u64 = 0x9E3779B97F4A7C15;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };

    // Model: id -> (bytes, refcount). Objects are ~1 KiB each.
    let mut model: HashMap<ObjId, (Vec<u8>, u32)> = HashMap::new();
    let mut now = 0u64;
    for step in 0..400 {
        now += 1;
        match next() % 4 {
            0 => {
                // Insert a fresh object.
                let data = test_data(500 + (next() % 1000) as usize + step);
                let id = oid(&data);
                store.insert_bytes(id, Ns::Plain, &data, now).unwrap();
                model.entry(id).or_insert((data, 0));
            }
            1 => {
                // Bump a random existing object's refcount.
                if let Some(&id) = model.keys().nth((next() as usize) % model.len().max(1)) {
                    let rc = store.ref_delta(id, 1).unwrap();
                    let m = model.get_mut(&id).unwrap();
                    m.1 += 1;
                    assert_eq!(rc, m.1);
                }
            }
            2 => {
                // Drop a refcount.
                if let Some(&id) = model.keys().nth((next() as usize) % model.len().max(1)) {
                    let rc = store.ref_delta(id, -1).unwrap();
                    let m = model.get_mut(&id).unwrap();
                    m.1 = m.1.saturating_sub(1);
                    assert_eq!(rc, m.1);
                }
            }
            _ => {
                // Evict some bytes; only refcount-0 objects may vanish.
                store.evict_lru(2000).unwrap();
                let mut gone = Vec::new();
                for (id, (_, rc)) in &model {
                    let present = store.contains(*id).unwrap();
                    if *rc > 0 {
                        assert!(present, "refcounted object {id} was evicted");
                    } else if !present {
                        gone.push(*id);
                    }
                }
                for id in gone {
                    model.remove(&id);
                }
            }
        }
    }
    // Every surviving object still reads back correct bytes (compaction
    // and eviction never corrupted a neighbor).
    for (id, (data, _)) in &model {
        if store.contains(*id).unwrap() {
            assert_eq!(&store.read_bytes(*id, now).unwrap(), data, "object {id}");
        }
    }
}

#[test]
fn slab_sealing_and_compaction() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = StoreConfig { slab_seal_bytes: 4096, ..Default::default() };
    let store = Store::open_with(dir.path(), cfg).unwrap();

    // Fill several slabs with 1 KiB objects.
    let mut ids = Vec::new();
    for i in 0..20 {
        let data = test_data(1024 + i);
        let id = oid(&data);
        store.insert_bytes(id, Ns::Plain, &data, i as u64).unwrap();
        ids.push((id, data));
    }
    let slab_files = || {
        std::fs::read_dir(dir.path().join("slabs"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "slab"))
            .count()
    };
    assert!(slab_files() >= 4, "sealing should have opened several slabs");

    // Keep every 4th object referenced, evict the rest.
    for (i, (id, _)) in ids.iter().enumerate() {
        if i % 4 == 0 {
            store.ref_delta(*id, 1).unwrap();
        }
    }
    store.evict_lru(u64::MAX).unwrap();

    // Referenced objects survive compaction with correct bytes.
    for (i, (id, data)) in ids.iter().enumerate() {
        if i % 4 == 0 {
            assert_eq!(&store.read_bytes(*id, 100).unwrap(), data);
        } else {
            assert!(!store.contains(*id).unwrap());
        }
    }
    assert!(slab_files() <= 3, "compaction should have dropped dead slabs, have {}", slab_files());
}

#[test]
fn crash_reopen_and_revalidate_distrusts_corruption() {
    let data = test_data(100_000); // 7 groups
    let (id, size, slice) = slice_for(&data, &[0..100_000]);

    let dir = tempfile::tempdir().unwrap();
    {
        let store = Store::open(dir.path()).unwrap();
        store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
        store.write_slice(id, &[0..100_000], &slice[..], 2).unwrap();
        let small = test_data(300);
        store.insert_bytes(oid(&small), Ns::Plain, &small, 3).unwrap();
    } // drop = crash/restart

    let store = Store::open(dir.path()).unwrap();
    assert!(store.is_complete(id).unwrap(), "records survive reopen");
    assert_eq!(store.read_bytes(id, 4).unwrap(), data);

    // Corrupt one group of the sparse file on disk behind the store's back.
    let path = dir.path().join("sparse").join(id.to_string());
    let mut raw = std::fs::read(&path).unwrap();
    raw[40_000] ^= 1; // group 2 (32768..49152)
    std::fs::write(&path, &raw).unwrap();

    // Serving that region now fails (validated encode)...
    let mut out = Vec::new();
    assert!(store.encode_slice(id, &[35_000..45_000], &mut out, 5).is_err());

    // ...and revalidate() shrinks the present set to what verifies.
    let kept = store.revalidate(id).unwrap();
    assert!(!kept.contains(2), "corrupt group must be dropped");
    assert!(kept.contains(0) && kept.contains(1) && kept.contains(3));
    // The later groups, including the partial tail group 6 (98_304..100_000
    // is only part of a full 16 KiB group), must SURVIVE. The tail group's
    // chunk range has to be clamped to the object's real chunk count or the
    // pristine tail is wrongly dropped every revalidate.
    assert!(kept.contains(4) && kept.contains(5), "clean middle groups kept");
    assert!(kept.contains(6), "pristine partial tail group must survive");
    assert!(!store.is_complete(id).unwrap());

    // The clean part still serves.
    let mut out = Vec::new();
    store.encode_slice(id, &[0..16_384], &mut out, 6).unwrap();
    // The tail range still serves after revalidate.
    let mut tail = Vec::new();
    store.encode_slice(id, &[98_304..100_000], &mut tail, 7).unwrap();
}

#[test]
fn revalidate_keeps_full_set_for_uncorrupted_object() {
    // A non-16-KiB-multiple size: the tail group is partial. revalidate on
    // an untouched object must return the whole present set and stay
    // complete. Old code dropped the tail group here (its chunk range ran
    // past the object's real chunk count) and reported incomplete.
    let data = test_data(100_000);
    let (id, size, slice) = slice_for(&data, &[0..100_000]);

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    store.write_slice(id, &[0..100_000], &slice[..], 2).unwrap();
    assert!(store.is_complete(id).unwrap());

    let before = store.present_bits(id).unwrap();
    let kept = store.revalidate(id).unwrap();
    assert_eq!(kept, before, "revalidate must not shrink an untouched object");
    assert!(store.is_complete(id).unwrap(), "still complete after revalidate");
    assert_eq!(store.read_bytes(id, 3).unwrap(), data);
}

#[test]
fn revalidate_keeps_single_group_sparse_object() {
    // A sub-16-KiB object is a single (partial) group. Old code wiped the
    // whole present set on revalidate because that one group's chunk range
    // ran past the object's real chunk count.
    let data = test_data(5_000);
    let (id, size, slice) = slice_for(&data, &[0..5_000]);

    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    store.write_slice(id, &[0..5_000], &slice[..], 2).unwrap();
    assert!(store.is_complete(id).unwrap());

    let kept = store.revalidate(id).unwrap();
    assert!(kept.contains(0), "the single group must survive");
    assert!(store.is_complete(id).unwrap(), "still complete after revalidate");
    assert_eq!(store.read_bytes(id, 3).unwrap(), data);
}

#[test]
fn reopen_truncates_slab_drift() {
    // A torn append (or a crash after sync but before the index commit) can
    // leave a slab file physically longer than its tracked len. On reopen
    // the store must shrink it back, or the next O_APPEND insert lands past
    // the drift while being recorded at the tracked offset - every later
    // read is then mis-addressed.
    let dir = tempfile::tempdir().unwrap();
    let a = test_data(1000);
    let ida = oid(&a);
    {
        let store = Store::open(dir.path()).unwrap();
        store.insert_bytes(ida, Ns::Plain, &a, 1).unwrap();
    }

    // Simulate drift: append garbage to the slab behind the store's back.
    let slab_path = dir.path().join("slabs").join("0.slab");
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&slab_path).unwrap();
        f.write_all(&test_data(777)).unwrap();
        f.sync_all().unwrap();
    }

    // Reopen (should truncate the drift) and insert a new object.
    let store = Store::open(dir.path()).unwrap();
    let b = test_data(1234);
    let idb = oid(&b);
    store.insert_bytes(idb, Ns::Plain, &b, 2).unwrap();

    // Both objects read back correctly: the new one was appended at the
    // tracked offset, not past stale drift bytes.
    assert_eq!(store.read_bytes(ida, 3).unwrap(), a);
    assert_eq!(store.read_bytes(idb, 4).unwrap(), b);
}

#[test]
fn quota_evicts_unpinned_but_keeps_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();

    // Two objects: one pinned (own content), one cached (unpinned).
    let own: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let cached: Vec<u8> = (0..40_000u32).map(|i| (i / 2) as u8).collect();
    let own_id = ObjId::of(&own);
    let cached_id = ObjId::of(&cached);
    store.insert_bytes(own_id, Ns::Plain, &own, 1).unwrap();
    store.pin(own_id).unwrap();
    store.insert_bytes(cached_id, Ns::Plain, &cached, 2).unwrap();

    assert_eq!(store.total_bytes().unwrap(), 80_000);

    // Enforce a quota below the total: the unpinned object is evicted, the
    // pinned own content survives.
    let freed = store.enforce_quota(50_000).unwrap();
    assert!(freed >= 40_000, "freed {freed}");
    assert!(store.contains(own_id).unwrap(), "pinned own content survives");
    assert!(!store.contains(cached_id).unwrap(), "unpinned cache evicted");
}

// --- Extern objects: the xite tree holds the bytes ------------------------

/// A store whose extern objects resolve under `xite_root`.
fn store_rooted(store_dir: &std::path::Path, xite_root: &std::path::Path) -> Store {
    Store::open_with(
        store_dir,
        StoreConfig { xite_root: Some(xite_root.to_path_buf()), ..Default::default() },
    )
    .unwrap()
}

#[test]
fn adopting_a_file_stores_no_second_copy_and_still_serves_slices() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    let data = test_data(200_000);
    let id = oid(&data);
    let file = tree.path().join("xite1").join("big.bin");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &data).unwrap();

    assert!(store.adopt_extern(id, Ns::Plain, &file, 1).unwrap());
    assert!(store.is_extern(id).unwrap());
    assert!(store.is_complete(id).unwrap());

    // The bytes were never copied into the store: only the outboard is ours.
    assert!(!store_dir.path().join("sparse").join(id.to_string()).exists());
    assert!(store_dir.path().join("sparse").join(format!("{id}.obao")).exists());

    // It still serves a verified slice and reads ranges, straight from the
    // file the user can see.
    let mut slice = Vec::new();
    store.encode_slice(id, &[50_000..60_000], &mut slice, 2).unwrap();
    assert!(!slice.is_empty());
    assert_eq!(store.read_range(id, 1000, 500, 3).unwrap(), data[1000..1500]);

    // And it charges the cache quota nothing: it is the user's file.
    assert_eq!(store.total_bytes().unwrap(), 0);
}

#[test]
fn materialize_moves_a_completed_download_into_the_tree() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    // Fetch a whole object the way the swarm does.
    let data = test_data(120_000);
    let (id, size, slice) = slice_for(&data, &[0..120_000]);
    store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    store.write_slice(id, &[0..120_000], &slice[..], 1).unwrap();
    assert!(store.is_complete(id).unwrap());
    assert!(!store.is_extern(id).unwrap());
    assert_eq!(store.total_bytes().unwrap(), 120_000, "still cache at this point");

    // Materializing hands it to the xite tree.
    let dst = tree.path().join("xite1").join("video.mp4");
    store.materialize(id, &dst, 2).unwrap();

    assert_eq!(std::fs::read(&dst).unwrap(), data, "the user has the file");
    assert!(!store_dir.path().join("sparse").join(id.to_string()).exists(), "stored once");
    assert!(store.is_extern(id).unwrap());
    assert_eq!(store.read_bytes(id, 3).unwrap(), data, "and it still serves");
    assert_eq!(store.total_bytes().unwrap(), 0, "no longer charged as cache");

    // Idempotent: a second Range request that raced the first is a no-op.
    store.materialize(id, &dst, 4).unwrap();
    assert!(store.is_extern(id).unwrap());
}

#[test]
fn materialize_refuses_an_incomplete_object() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    let data = test_data(120_000);
    let (id, size, slice) = slice_for(&data, &[0..16_384]);
    store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    store.write_slice(id, &[0..16_384], &slice[..], 1).unwrap();

    let dst = tree.path().join("xite1").join("partial.bin");
    assert!(store.materialize(id, &dst, 2).is_err(), "half a file is not a file");
    assert!(!dst.exists());
}

#[test]
fn extern_paths_must_stay_inside_the_xite_root() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    let data = test_data(100_000);
    let id = oid(&data);
    let outside = elsewhere.path().join("passwd");
    std::fs::write(&outside, &data).unwrap();

    // The store must never be talked into reading through to an arbitrary
    // path: an object's bytes live in a xite tree or nowhere.
    assert!(store.adopt_extern(id, Ns::Plain, &outside, 1).is_err());
    assert!(!store.contains(id).unwrap());
}

#[test]
fn eviction_never_reclaims_the_users_own_downloads() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    // One extern object (a completed download) and one cached object.
    let mine = test_data(60_000);
    let mine_id = oid(&mine);
    let file = tree.path().join("xite1").join("mine.bin");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &mine).unwrap();
    store.adopt_extern(mine_id, Ns::Plain, &file, 1).unwrap();

    let cached: Vec<u8> = (0..50_000u32).map(|i| (i / 3) as u8).collect();
    let cached_id = ObjId::of(&cached);
    store.insert_bytes(cached_id, Ns::Plain, &cached, 2).unwrap();

    // Squeeze the quota to nothing. The cache goes; the download stays, and
    // the file itself is untouched.
    store.enforce_quota(0).unwrap();
    assert!(!store.contains(cached_id).unwrap(), "cache is evictable");
    assert!(store.contains(mine_id).unwrap(), "a download is not cache");
    assert!(store.is_complete(mine_id).unwrap());
    assert_eq!(std::fs::read(&file).unwrap(), mine);
}

#[test]
fn removing_an_extern_object_leaves_the_users_file_alone() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    let data = test_data(80_000);
    let id = oid(&data);
    let file = tree.path().join("xite1").join("keep.bin");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &data).unwrap();
    store.adopt_extern(id, Ns::Plain, &file, 1).unwrap();

    store.remove(id).unwrap();
    assert!(!store.contains(id).unwrap(), "the record is gone");
    assert!(
        !store_dir.path().join("sparse").join(format!("{id}.obao")).exists(),
        "and so is the outboard we owned"
    );
    assert!(file.exists(), "but the xite's file is not the store's to delete");
}

#[test]
fn an_edited_file_is_retired_rather_than_served_wrong() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    let data = test_data(70_000);
    let id = oid(&data);
    let file = tree.path().join("xite1").join("editable.bin");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &data).unwrap();
    store.adopt_extern(id, Ns::Plain, &file, 1).unwrap();
    assert!(store.revalidate(id).unwrap().is_complete(70_000));

    // The whole point of extern objects is that the user may edit their own
    // files. Doing so must retire the object, never serve altered bytes
    // under the original hash.
    let mut edited = data.clone();
    edited[40_000] ^= 0xff;
    std::fs::write(&file, &edited).unwrap();

    assert!(store.revalidate(id).unwrap().is_empty());
    assert!(!store.contains(id).unwrap(), "retired, so the next fetch refetches");
    assert!(file.exists(), "the user's edit survives");
}

#[test]
fn reclaim_converts_a_pre_extern_duplicate_and_gives_the_space_back() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    let store = store_rooted(store_dir.path(), tree.path());

    // Exactly the shape an older build left behind: the bytes in the store
    // AND the same bytes materialized in the xite tree.
    let data = test_data(90_000);
    let (id, size, slice) = slice_for(&data, &[0..90_000]);
    store.ensure_sparse(id, Ns::Plain, size, 1).unwrap();
    store.write_slice(id, &[0..90_000], &slice[..], 1).unwrap();
    let file = tree.path().join("xite1").join("dup.bin");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &data).unwrap();
    assert_eq!(store.total_bytes().unwrap(), 90_000);

    let freed = store.reclaim_duplicate(id, &file, 2).unwrap();
    assert_eq!(freed, 90_000);
    assert!(store.is_extern(id).unwrap());
    assert!(!store_dir.path().join("sparse").join(id.to_string()).exists());
    assert_eq!(store.total_bytes().unwrap(), 0);
    assert_eq!(store.read_bytes(id, 3).unwrap(), data, "still serves, from the tree");

    // A tree file that is NOT this object must never be adopted as it.
    let other = test_data(90_000).iter().map(|b| b ^ 1).collect::<Vec<u8>>();
    let (other_id, other_size, other_slice) = slice_for(&other, &[0..90_000]);
    store.ensure_sparse(other_id, Ns::Plain, other_size, 4).unwrap();
    store.write_slice(other_id, &[0..90_000], &other_slice[..], 4).unwrap();
    assert_eq!(store.reclaim_duplicate(other_id, &file, 5).unwrap(), 0, "wrong bytes, no swap");
    assert!(!store.is_extern(other_id).unwrap());
}

#[test]
fn extern_survives_a_reopen_without_a_schema_migration() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();

    let data = test_data(75_000);
    let id = oid(&data);
    let file = tree.path().join("xite1").join("persist.bin");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, &data).unwrap();
    {
        let store = store_rooted(store_dir.path(), tree.path());
        store.adopt_extern(id, Ns::Plain, &file, 1).unwrap();
    }

    // Reopening an index that now contains a Loc::Extern record must not
    // trip the schema check - the variant was appended, so old records keep
    // their meaning and no migration is owed.
    let store = store_rooted(store_dir.path(), tree.path());
    assert!(store.is_extern(id).unwrap());
    assert_eq!(store.read_range(id, 0, 100, 2).unwrap(), data[..100]);
}

#[test]
fn a_store_without_a_xite_root_simply_has_no_extern_objects() {
    let store_dir = tempfile::tempdir().unwrap();
    let tree = tempfile::tempdir().unwrap();
    // `Store::open` (tools, exports, most tests) leaves xite_root unset.
    let store = Store::open(store_dir.path()).unwrap();

    let data = test_data(50_000);
    let id = oid(&data);
    let file = tree.path().join("x.bin");
    std::fs::write(&file, &data).unwrap();

    assert!(store.adopt_extern(id, Ns::Plain, &file, 1).is_err());
    // Everything else about the store is unaffected.
    let small = test_data(900);
    assert!(store.insert_bytes(oid(&small), Ns::Plain, &small, 1).unwrap());
}
