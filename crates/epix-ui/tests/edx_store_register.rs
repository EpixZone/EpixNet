//! Phase C stage 2: when an EDX object store is installed on the node,
//! loading a xite from disk registers its files into that store
//! (content-addressed, no re-download), and when no store is installed the
//! node behaves exactly as before.

use std::sync::Arc;

use epix_blob::store::Store;
use epix_core::Address;
use epix_ui::state::{AppState, XiteEntry};
use epix_xite::{Xite, XiteStorage};

/// Sign a small EDX xite on disk (stamps b3/bundle fields) and return its
/// address, its on-disk dir, and the signed content.json.
fn sign_edx_xite() -> (String, tempfile::TempDir, serde_json::Value) {
    let privkey = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", &vec![b'h'; 2_000]).unwrap();
    storage.write("css/all.css", &vec![b'c'; 3_000]).unwrap();
    storage
        .write("big.bin", &(0..300_000usize).map(|i| (i % 251) as u8).collect::<Vec<u8>>())
        .unwrap();
    let mut xite = Xite::new(Address::parse(address.clone()).unwrap(), storage);
    xite.sign(&privkey, 1000.0).unwrap();
    let content = xite.content.clone().unwrap();
    (address, dir, content)
}

#[tokio::test]
async fn loading_a_xite_registers_its_files_into_the_edx_store() {
    let (address, dir, content) = sign_edx_xite();

    // A node with an EDX store installed. Big files are adopted where they
    // lie rather than copied in, so the store is told which tree that is.
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::open_with(
            store_dir.path(),
            epix_blob::store::StoreConfig {
                xite_root: Some(dir.path().to_path_buf()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let state = AppState::new("test");
    state.set_edx_store(store.clone()).await.unwrap();

    // Register the xite pointing at the on-disk dir with no loaded content,
    // so load_content_from_disk actually reads + verifies it.
    state
        .add_xite(&address, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
        .await;
    assert!(state.load_content_from_disk(&address).await, "verified load from disk");

    // Every declared file's own BLAKE3 object is now in the store, so EDX
    // can serve and dedup it without a re-download.
    for path in ["index.html", "css/all.css", "big.bin"] {
        let e = epix_blob::manifest::edx_entry(&content, path).expect(path);
        assert!(
            store.contains(e.b3).unwrap(),
            "{path} (b3 {}) should be registered in the EDX store",
            e.b3
        );
    }

    // The declared bundle object is present too (the small files packed).
    for id in epix_blob::manifest::bundles(&content).keys() {
        assert!(store.contains(*id).unwrap(), "declared bundle {id} should be registered");
    }
}

#[tokio::test]
async fn no_edx_store_installed_is_a_no_op() {
    let (address, dir, _content) = sign_edx_xite();

    // Same flow, but no store installed: load still succeeds and nothing
    // reaches for a store (the legacy path is untouched).
    let state = AppState::new("test");
    state
        .add_xite(&address, XiteEntry { storage: XiteStorage::new(dir.path()), content: None })
        .await;
    assert!(state.load_content_from_disk(&address).await, "load works with no EDX store");
    assert!(state.edx_store().await.is_none(), "no store is installed by default");
    assert!(
        state.edx_register_xite(&address).await.is_none(),
        "register is a no-op without a store"
    );
}
