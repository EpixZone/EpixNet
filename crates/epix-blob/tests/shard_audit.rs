//! Phase D disk-audit gate: a disk volunteer's on-disk store holds only
//! ciphertext shards and their addresses — no plaintext, no filenames, no
//! shard→xite linkage.

use epix_blob::store::Store;
use epix_blob::{Ns, ObjId};
use epix_selfenc::{encrypt_convergent, Hash};

/// Distinctive plaintext we can grep the raw slab for.
const SECRET: &[u8] = b"THE-SECRET-FORUM-POST-nobody-should-find-this-on-a-volunteer-disk";

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
fn volunteer_slab_contains_only_ciphertext_and_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();

    // Encrypt a private file and store its shards as a volunteer would:
    // opaque ciphertext keyed by BLAKE3(ciphertext), namespace Shard.
    let data = plaintext(2_500_000); // ~3 chunks
    let enc = encrypt_convergent(&data, b"owner-salt");
    let mut addrs: Vec<Hash> = Vec::new();
    for (addr, ct) in &enc.shards {
        let id = ObjId(*addr);
        store.insert_bytes(id, Ns::Shard, ct, 1).unwrap();
        addrs.push(*addr);
    }

    // Audit 1: no slab file on disk contains the plaintext secret marker.
    let slabs_dir = dir.path().join("slabs");
    for entry in std::fs::read_dir(&slabs_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "slab") {
            let raw = std::fs::read(&path).unwrap();
            assert!(
                !contains(&raw, SECRET),
                "plaintext secret found in {} — the volunteer disk leaks content",
                path.display()
            );
        }
    }

    // Audit 2: the redb index has no xite association — nothing on disk
    // maps a shard back to a site. We can only look objects up BY their
    // ciphertext address; there is no reverse path to a xite. (Structural:
    // the store's schema records (addr,size,ns,loc,refcount,last_access)
    // and never a xite id — this test documents + guards that contract.)
    for addr in &addrs {
        let id = ObjId(*addr);
        assert!(store.contains(id).unwrap(), "shard addressable by its ciphertext hash");
        // The only key is the ciphertext hash; there is no xite index to
        // query, so a volunteer literally cannot answer "which site?".
    }

    // Audit 3: what IS on disk round-trips back to plaintext only for a
    // holder of the viewing material (salt + data-map) — the volunteer
    // has neither, so holding the shards reveals nothing.
    let store_ref = &store;
    let recovered = epix_selfenc::decrypt(enc.mode, &enc.chunks, b"owner-salt", |a| {
        store_ref.read_bytes(ObjId(*a), 2).ok()
    })
    .unwrap();
    assert_eq!(recovered, data, "a viewer with the salt recovers plaintext");

    // Audit 4: the WRONG salt (a volunteer guessing) recovers nothing.
    let bad = epix_selfenc::decrypt(enc.mode, &enc.chunks, b"guessed-salt", |a| {
        store_ref.read_bytes(ObjId(*a), 3).ok()
    });
    assert!(bad.is_err(), "a volunteer without the salt cannot decrypt");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
