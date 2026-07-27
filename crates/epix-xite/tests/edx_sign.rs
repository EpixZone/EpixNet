//! Phase A gate: signing stamps the EDX manifest fields, re-signing keeps
//! bundle assignment stable, and the migration pass registers existing
//! local files into the store with no re-download.

use epix_blob::store::Store;
use epix_blob::{manifest, ObjId};
use epix_core::Address;
use epix_xite::{Xite, XiteStorage};
use serde_json::Value;

const PRIVKEY: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";

fn make_xite(dir: &std::path::Path) -> Xite {
    let address = epix_crypt::privatekey_to_address(PRIVKEY).unwrap();
    let storage = XiteStorage::new(dir);
    // Small bundleable files + one big unbundled file.
    storage.write("index.html", &vec![b'h'; 2_000]).unwrap();
    storage.write("css/all.css", &vec![b'c'; 3_000]).unwrap();
    storage.write("js/app.js", &vec![b'j'; 4_000]).unwrap();
    storage
        .write("big.bin", &(0..300_000usize).map(|i| (i % 251) as u8).collect::<Vec<u8>>())
        .unwrap();
    Xite::new(Address::parse(address).unwrap(), storage)
}

fn signed_content(xite: &Xite) -> Value {
    serde_json::from_slice(&xite.storage.read("content.json").unwrap()).unwrap()
}

#[test]
fn sign_stamps_edx_fields_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let mut xite = make_xite(dir.path());
    xite.sign(PRIVKEY, 1000.0).unwrap();
    let content = signed_content(&xite);

    // The signature itself still verifies (EDX fields are inside it).
    let addr = epix_crypt::privatekey_to_address(PRIVKEY).unwrap();
    assert!(epix_content::verify_signer(&content, &addr), "signature covers EDX fields");

    assert_eq!(manifest::edx_version(&content), Some(1));
    assert!(content.get("files_merkle_root").is_some());

    // Small files: b3 + bundle refs; entries resolve against declared bundles.
    for path in ["index.html", "css/all.css", "js/app.js"] {
        let e = manifest::edx_entry(&content, path).expect(path);
        assert!(e.bundle.is_some(), "{path} should be bundled");
        // b3 is the file's OWN hash, not the bundle's.
        let bytes = xite.storage.read(path).unwrap();
        assert_eq!(e.b3, ObjId::of(&bytes), "{path}");
    }
    // The three small files fit one 256 KiB bundle.
    assert_eq!(manifest::bundles(&content).len(), 1);

    // The big file: b3 but no bundle; legacy sha512 still present.
    let big = manifest::edx_entry(&content, "big.bin").unwrap();
    assert!(big.bundle.is_none());
    assert!(content["files"]["big.bin"]["sha512"].is_string());
}

#[test]
fn resign_keeps_untouched_bundles_stable() {
    let dir = tempfile::tempdir().unwrap();
    let mut xite = make_xite(dir.path());
    // Enough 100 KiB files for several bundles.
    for i in 0..12 {
        xite.storage
            .write(&format!("media/f{i:02}.bin"), &vec![i as u8; 100_000])
            .unwrap();
    }
    xite.sign(PRIVKEY, 1000.0).unwrap();
    let before = signed_content(&xite);
    let bundles_before = manifest::bundles(&before);
    assert!(bundles_before.len() >= 4, "want several bundles, got {}", bundles_before.len());

    // Edit ONE small file and re-sign.
    xite.storage.write("media/f03.bin", &vec![0xEE; 100_000]).unwrap();
    xite.sign(PRIVKEY, 1001.0).unwrap();
    let after = signed_content(&xite);
    let bundles_after = manifest::bundles(&after);

    // Only the edited file's bundle re-minted.
    let victim_bundle = manifest::edx_entry(&before, "media/f03.bin").unwrap().bundle.unwrap().id;
    let surviving: Vec<_> =
        bundles_before.keys().filter(|id| bundles_after.contains_key(id)).collect();
    assert_eq!(
        surviving.len(),
        bundles_before.len() - 1,
        "exactly one bundle may re-mint; before={bundles_before:?} after={bundles_after:?}"
    );
    assert!(!bundles_after.contains_key(&victim_bundle), "edited bundle must have a new id");
}

#[test]
fn edx_register_populates_the_store_without_refetch() {
    let dir = tempfile::tempdir().unwrap();
    let mut xite = make_xite(dir.path());
    xite.sign(PRIVKEY, 1000.0).unwrap();
    let content = signed_content(&xite);

    let store_dir = tempfile::tempdir().unwrap();
    let store = Store::open(store_dir.path()).unwrap();
    let (registered, skipped) = xite.edx_register(&store, 1).unwrap();
    // 4 files (content.json isn't in files) + 1 bundle.
    assert_eq!((registered, skipped), (5, 0));

    // Every declared object is now present and complete.
    for path in ["index.html", "css/all.css", "js/app.js", "big.bin"] {
        let e = manifest::edx_entry(&content, path).unwrap();
        assert!(store.is_complete(e.b3).unwrap(), "{path} in store");
    }
    for id in manifest::bundles(&content).keys() {
        assert!(store.is_complete(*id).unwrap(), "bundle {id} in store");
    }

    // The adopted big file serves a verified slice (the store really can
    // serve without ever having 'downloaded' anything).
    let big = manifest::edx_entry(&content, "big.bin").unwrap();
    let mut slice = Vec::new();
    store.encode_slice(big.b3, &[100_000..150_000], &mut slice, 2).unwrap();
    assert!(!slice.is_empty());

    // Idempotent: a second pass dedups everything.
    let (again, skipped2) = xite.edx_register(&store, 3).unwrap();
    assert_eq!((again, skipped2), (5, 0), "second pass is all dedup hits, no errors");
}
