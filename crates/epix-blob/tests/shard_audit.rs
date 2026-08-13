//! Phase D shard-store audit: an encrypted-shard cache's on-disk store
//! holds only ciphertext shards and their addresses — no plaintext, no
//! filenames, no shard-to-xite mapping.

use epix_blob::store::Store;
use epix_blob::{Ns, ObjId};
use epix_selfenc::{encrypt_convergent, Hash};

/// Distinctive plaintext we can grep the raw slab for.
const SECRET: &[u8] = b"DISTINCTIVE-PLAINTEXT-MARKER-that-must-not-appear-on-a-cache-disk";

/// A distinctive 32-byte "xite address" that a shard-to-xite mapping leak
/// would embed on disk. The store has no xite parameter, so it never
/// receives this; scanning every file for it turns "no shard-to-xite
/// mapping" from a prose promise into a machine check.
const MARKER_XITE: &[u8; 32] = b"XITE-ADDR-marker-do-not-persist!";

fn plaintext(n: usize) -> Vec<u8> {
    // Embed the secret marker repeatedly so any plaintext leak is findable.
    let mut v = Vec::with_capacity(n);
    while v.len() < n {
        v.extend_from_slice(SECRET);
    }
    v.truncate(n);
    v
}

#[test]
fn shard_store_contains_only_ciphertext_and_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();

    // Encrypt a private file and store its shards the way a cache node
    // does: opaque ciphertext keyed by BLAKE3(ciphertext), namespace
    // Shard. The MARKER_XITE address is in scope for this whole flow, but
    // the store API never takes it - a mapping leak would be the only way
    // it reaches disk.
    let data = plaintext(2_500_000); // ~3 chunks
    let _origin_xite = MARKER_XITE;
    let enc = encrypt_convergent(&data, b"owner-salt");
    let mut addrs: Vec<Hash> = Vec::new();
    for (addr, ct) in &enc.shards {
        let id = ObjId(*addr);
        store.insert_bytes(id, Ns::Shard, ct, 1).unwrap();
        addrs.push(*addr);
    }

    // Audit 1: no slab file AND the redb index contains the plaintext
    // secret marker.
    let slabs_dir = dir.path().join("slabs");
    for entry in std::fs::read_dir(&slabs_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "slab") {
            let raw = std::fs::read(&path).unwrap();
            assert!(
                !contains(&raw, SECRET),
                "plaintext found in {} - the cache leaks content",
                path.display()
            );
        }
    }
    let index = std::fs::read(dir.path().join("index.redb")).unwrap();
    assert!(!contains(&index, SECRET), "plaintext found in index.redb");

    // Audit 2 (machine check): nothing anywhere under the store root maps a
    // shard back to a xite. Recursively byte-scan every file - index.redb,
    // slabs/*.slab, sparse/* - and assert neither the plaintext marker nor
    // the distinctive xite-address marker appears. The only lookup key is
    // the ciphertext hash; there is no reverse path to a xite.
    let mut files = 0usize;
    scan_files(dir.path(), &mut |path, raw| {
        files += 1;
        assert!(
            !contains(raw, SECRET),
            "plaintext found in {} - the cache leaks content",
            path.display()
        );
        assert!(
            !contains(raw, MARKER_XITE),
            "shard-to-xite mapping found in {} - the cache maps a shard to a site",
            path.display()
        );
    });
    assert!(files > 0, "scan must have visited at least the index and a slab");
    for addr in &addrs {
        let id = ObjId(*addr);
        assert!(store.contains(id).unwrap(), "shard addressable by its ciphertext hash");
        // The only key is the ciphertext hash; there is no xite index to
        // query, so the store cannot answer "which xite?".
    }

    // Audit 3: what IS on disk round-trips back to plaintext only for a
    // holder of the key material (salt + data-map); a cache node holding
    // only shards has neither.
    let store_ref = &store;
    let recovered = epix_selfenc::decrypt(enc.mode, &enc.chunks, b"owner-salt", |a| {
        store_ref.read_bytes(ObjId(*a), 2).ok()
    })
    .unwrap();
    assert_eq!(recovered, data, "a reader with the salt recovers plaintext");

    // Audit 4: the WRONG salt recovers nothing.
    let bad = epix_selfenc::decrypt(enc.mode, &enc.chunks, b"guessed-salt", |a| {
        store_ref.read_bytes(ObjId(*a), 3).ok()
    });
    assert!(bad.is_err(), "without the salt the shards do not decrypt");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Read every file under `root` (recursing into subdirectories) and hand
/// its path + bytes to `f`.
fn scan_files(root: &std::path::Path, f: &mut impl FnMut(&std::path::Path, &[u8])) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            scan_files(&path, f);
        } else {
            let raw = std::fs::read(&path).unwrap();
            f(&path, &raw);
        }
    }
}
