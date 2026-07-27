//! Small-file bundles with STABLE assignment.
//!
//! A xite has hundreds of tiny files; one swarm object each would be
//! pathological. Files under [`BUNDLE_FILE_MAX`] are packed into
//! ~[`BUNDLE_TARGET`] bundles instead. The failure mode this module
//! exists to prevent: deriving membership from a path sort, where one
//! inserted CSS file shifts every bundle after it and re-mints the whole
//! xite (a 100-1000x bandwidth regression). Assignment is therefore:
//!
//! - **carried forward** from the previous manifest: an existing bundle
//!   keeps its member list and order as long as its members exist;
//! - **append-only for new files**: they fill the tail bundle, then open
//!   a new one — earlier bundles are untouched;
//! - **re-minted only on change**: editing/deleting a member re-mints
//!   only that member's bundle (same members, new bytes, new id);
//! - **lazily repacked**: only when enough bundles have decayed below
//!   half target does a full deterministic repack run, accepting the
//!   one-time refetch to restore packing efficiency.
//!
//! Given the same previous assignment and file contents, the output is
//! byte-deterministic (golden-tested).

use std::collections::BTreeMap;

use crate::ObjId;

/// Files strictly smaller than this are bundled.
pub const BUNDLE_FILE_MAX: u64 = 128 * 1024;
/// Bundles grow to roughly this size before a new tail opens.
pub const BUNDLE_TARGET: u64 = 256 * 1024;

/// One produced bundle: its content id, its bytes (member bytes
/// concatenated in member order), and the ordered member paths.
#[derive(Clone, Debug)]
pub struct Bundle {
    pub id: ObjId,
    pub bytes: Vec<u8>,
    pub members: Vec<String>,
}

/// The result of an assignment run.
#[derive(Clone, Debug, Default)]
pub struct BundleResult {
    /// Bundles in stable order (the last one is the open tail).
    pub bundles: Vec<Bundle>,
    /// path -> (index into `bundles`, byte offset, length).
    pub members: BTreeMap<String, (usize, u64, u64)>,
}

/// Whether a file of `size` bytes belongs in a bundle.
pub fn is_bundleable(size: u64) -> bool {
    size < BUNDLE_FILE_MAX
}

/// Assign `files` (path -> bytes; the caller passes only bundle-eligible
/// files — small, not user-content, not merge-files) to bundles,
/// carrying the previous manifest's membership forward.
///
/// `prev` is the previous ordered membership (each inner vec is one
/// bundle's ordered member paths); pass `&[]` for a first signing.
pub fn assign(files: &BTreeMap<String, Vec<u8>>, prev: &[Vec<String>]) -> BundleResult {
    // 1. Carry forward: previous bundles keep surviving members in order.
    let mut memberships: Vec<Vec<String>> = prev
        .iter()
        .map(|b| b.iter().filter(|p| files.contains_key(*p)).cloned().collect::<Vec<_>>())
        .filter(|b: &Vec<String>| !b.is_empty())
        .collect();

    // 2. New files append to the tail, sorted by path for determinism.
    let assigned: std::collections::BTreeSet<&String> =
        memberships.iter().flatten().collect();
    let new_files: Vec<String> =
        files.keys().filter(|p| !assigned.contains(*p)).cloned().collect();
    drop(assigned);

    let bundle_size =
        |b: &[String]| b.iter().map(|p| files[p].len() as u64).sum::<u64>();
    for path in new_files {
        let fits_tail = memberships
            .last()
            .is_some_and(|tail| bundle_size(tail) < BUNDLE_TARGET);
        if fits_tail {
            memberships.last_mut().unwrap().push(path);
        } else {
            memberships.push(vec![path]);
        }
    }

    // 3. Lazy repack: when enough non-tail bundles decayed below half
    //    target, rebuild from scratch (deterministic greedy by path).
    let n = memberships.len();
    if n > 1 {
        let fragmented = memberships[..n - 1]
            .iter()
            .filter(|b| bundle_size(b) < BUNDLE_TARGET / 2)
            .count();
        if fragmented > (n / 4).max(2) {
            memberships = repack(files);
        }
    }

    build(files, memberships)
}

/// Full deterministic repack: greedy fill in path order.
fn repack(files: &BTreeMap<String, Vec<u8>>) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut current_size = 0u64;
    for (path, bytes) in files {
        if current_size >= BUNDLE_TARGET && !current.is_empty() {
            out.push(std::mem::take(&mut current));
            current_size = 0;
        }
        current.push(path.clone());
        current_size += bytes.len() as u64;
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn build(files: &BTreeMap<String, Vec<u8>>, memberships: Vec<Vec<String>>) -> BundleResult {
    let mut result = BundleResult::default();
    for (idx, members) in memberships.into_iter().enumerate() {
        let mut bytes = Vec::new();
        for path in &members {
            let content = &files[path];
            result
                .members
                .insert(path.clone(), (idx, bytes.len() as u64, content.len() as u64));
            bytes.extend_from_slice(content);
        }
        let id = ObjId(*blake3::hash(&bytes).as_bytes());
        result.bundles.push(Bundle { id, bytes, members });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(entries: &[(&str, usize)]) -> BTreeMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(p, n)| {
                // Content depends on path so every file is distinct.
                let seed = blake3::hash(p.as_bytes());
                let bytes: Vec<u8> =
                    (0..*n).map(|i| seed.as_bytes()[i % 32] ^ (i % 251) as u8).collect();
                (p.to_string(), bytes)
            })
            .collect()
    }

    fn memberships(r: &BundleResult) -> Vec<Vec<String>> {
        r.bundles.iter().map(|b| b.members.clone()).collect()
    }

    #[test]
    fn deterministic_from_scratch() {
        let f = files(&[("a.css", 1000), ("b.js", 2000), ("c.html", 500)]);
        let r1 = assign(&f, &[]);
        let r2 = assign(&f, &[]);
        assert_eq!(r1.members, r2.members);
        assert_eq!(
            r1.bundles.iter().map(|b| b.id).collect::<Vec<_>>(),
            r2.bundles.iter().map(|b| b.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn offsets_and_bytes_line_up() {
        let f = files(&[("a", 100), ("b", 200), ("c", 300)]);
        let r = assign(&f, &[]);
        for (path, (idx, off, len)) in &r.members {
            let b = &r.bundles[*idx];
            assert_eq!(
                &b.bytes[*off as usize..(*off + *len) as usize],
                &f[path][..],
                "bytes of {path}"
            );
        }
    }

    #[test]
    fn editing_one_file_remints_only_its_bundle() {
        // Build enough files for several bundles (each 100 KiB, target 256 KiB).
        let names: Vec<String> = (0..12).map(|i| format!("f{i:02}.bin")).collect();
        let mut f = files(&names.iter().map(|n| (n.as_str(), 100_000)).collect::<Vec<_>>());
        let r1 = assign(&f, &[]);
        assert!(r1.bundles.len() >= 4, "want several bundles, got {}", r1.bundles.len());

        // Edit one file: only its bundle's id may change.
        let victim = "f05.bin";
        f.get_mut(victim).unwrap()[0] ^= 0xFF;
        let r2 = assign(&f, &memberships(&r1));
        assert_eq!(memberships(&r1), memberships(&r2), "membership must not move");
        let victim_bundle = r1.members[victim].0;
        for (i, (b1, b2)) in r1.bundles.iter().zip(&r2.bundles).enumerate() {
            if i == victim_bundle {
                assert_ne!(b1.id, b2.id, "edited bundle must re-mint");
            } else {
                assert_eq!(b1.id, b2.id, "untouched bundle {i} must keep its id");
            }
        }
    }

    #[test]
    fn new_files_append_to_tail_only() {
        let names: Vec<String> = (0..8).map(|i| format!("f{i}.bin")).collect();
        let mut f = files(&names.iter().map(|n| (n.as_str(), 100_000)).collect::<Vec<_>>());
        let r1 = assign(&f, &[]);

        // Insert a file whose path sorts FIRST — the classic re-mint bomb.
        f.insert("00-first.css".into(), vec![7u8; 5000]);
        let r2 = assign(&f, &memberships(&r1));

        let changed: Vec<usize> = r1
            .bundles
            .iter()
            .zip(&r2.bundles)
            .enumerate()
            .filter(|(_, (a, b))| a.id != b.id)
            .map(|(i, _)| i)
            .collect();
        // At most the tail changed (or a brand-new bundle appeared).
        assert!(
            changed.is_empty() || changed == vec![r1.bundles.len() - 1],
            "only the tail may change, changed: {changed:?}"
        );
    }

    #[test]
    fn deleting_a_member_remints_only_its_bundle() {
        let names: Vec<String> = (0..12).map(|i| format!("f{i:02}.bin")).collect();
        let f0 = files(&names.iter().map(|n| (n.as_str(), 100_000)).collect::<Vec<_>>());
        let r1 = assign(&f0, &[]);
        let victim = "f02.bin";
        let victim_bundle = r1.members[victim].0;
        let mut f = f0.clone();
        f.remove(victim);
        let r2 = assign(&f, &memberships(&r1));
        assert!(!r2.members.contains_key(victim));
        for (i, b1) in r1.bundles.iter().enumerate() {
            let b2 = r2.bundles.iter().find(|b| {
                b.members.iter().any(|m| b1.members.contains(m))
            });
            if i == victim_bundle {
                assert!(b2.is_none_or(|b2| b2.id != b1.id));
            } else {
                assert_eq!(b2.expect("bundle survives").id, b1.id, "bundle {i}");
            }
        }
    }

    #[test]
    fn repack_triggers_after_heavy_decay() {
        // Many bundles with single tiny survivors -> repack coalesces.
        let prev: Vec<Vec<String>> =
            (0..12).map(|i| vec![format!("f{i:02}.bin"), format!("g{i:02}.bin")]).collect();
        // Only the f-files survive, each 1 KiB -> every bundle far below half target.
        let survivors: Vec<String> = (0..12).map(|i| format!("f{i:02}.bin")).collect();
        let f = files(&survivors.iter().map(|n| (n.as_str(), 1024)).collect::<Vec<_>>());
        let r = assign(&f, &prev);
        assert!(
            r.bundles.len() <= 2,
            "12 decayed bundles should repack into 1-2, got {}",
            r.bundles.len()
        );
        // Deterministic repack.
        let r2 = assign(&f, &prev);
        assert_eq!(
            r.bundles.iter().map(|b| b.id).collect::<Vec<_>>(),
            r2.bundles.iter().map(|b| b.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_input_is_empty_output() {
        let r = assign(&BTreeMap::new(), &[]);
        assert!(r.bundles.is_empty() && r.members.is_empty());
    }
}
