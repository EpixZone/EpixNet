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
    let cfg = StoreConfig { slab_seal_bytes: 4096, compact_dead_num: 128 };
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
