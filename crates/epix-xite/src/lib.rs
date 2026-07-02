//! `epix-xite` - xite lifecycle: storage, content.json, and peer announcing.

pub mod announcer;
pub mod settings;
pub mod piecefield;
pub mod piecemap;
pub mod xite;
pub mod storage;

pub use announcer::announce;
pub use settings::{content_stats, Cache, ContentStats, XiteSettings};
pub use piecefield::Piecefield;
pub use piecemap::parse_piecemap;
pub use xite::{FileEntry, Xite};
pub use storage::XiteStorage;

#[cfg(test)]
mod tests {
    use super::*;
    use epix_core::Address;
    use serde_json::json;

    fn signed_content(priv_hex: &str, files: serde_json::Value) -> (String, Vec<u8>) {
        let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();
        let mut content = json!({
            "address": address,
            "inner_path": "content.json",
            "modified": 1777992697,
            "files": files,
        });
        epix_content::sign(&mut content, priv_hex).unwrap();
        (address, serde_json::to_vec(&content).unwrap())
    }

    #[test]
    fn set_content_verifies_and_lists_needed_files() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let a = XiteStorage::hash_bytes(b"hello");
        let (address, content_bytes) = signed_content(
            priv_hex,
            json!({ "a.txt": { "size": 5, "sha512": a } }),
        );

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(
            Address::parse(address).unwrap(),
            XiteStorage::new(dir.path()),
        );
        xite.set_content(&content_bytes).unwrap();

        // a.txt is declared but not present -> needed.
        let needed = xite.files_needed();
        assert_eq!(needed.len(), 1);
        assert_eq!(needed[0].inner_path, "a.txt");

        // Write it -> no longer needed.
        xite.storage.write("a.txt", b"hello").unwrap();
        assert!(xite.files_needed().is_empty());
    }

    #[test]
    fn sign_rebuilds_files_and_produces_a_valid_content_json() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(Address::parse(address.clone()).unwrap(), XiteStorage::new(dir.path()));
        // Some files on disk, plus a stale content.json we'll overwrite.
        xite.storage.write("index.html", b"<h1>hi</h1>").unwrap();
        xite.storage.write("js/app.js", b"console.log(1)").unwrap();

        xite.sign(priv_hex, 1777992698.0).unwrap();

        // The signed content.json verifies, lists the real files with correct
        // hashes, and needs nothing (everything is on disk).
        let content = xite.content.clone().unwrap();
        assert!(epix_content::verify_signer(&content, &address));
        assert_eq!(content["files"]["index.html"]["size"], 11);
        assert_eq!(
            content["files"]["index.html"]["sha512"],
            XiteStorage::hash_bytes(b"<h1>hi</h1>")
        );
        assert_eq!(content["modified"], 1777992698.0);
        assert!(content["files"].get("content.json").is_none(), "content.json isn't listed in files");
        assert!(xite.files_needed().is_empty());

        // Reloading the written file re-verifies (round-trips on disk).
        let mut reloaded = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
        assert!(reloaded.load_content().unwrap());
    }

    #[test]
    fn sign_rejects_non_owner_key() {
        let owner = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let owner_addr = epix_crypt::privatekey_to_address(owner).unwrap();
        let other = "22c824485fe256587c3809b5f7c99864d7339e9fba061a016834cecc454e01f8";

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(Address::parse(owner_addr).unwrap(), XiteStorage::new(dir.path()));
        xite.storage.write("a.txt", b"x").unwrap();
        // A key that doesn't own this xite must be refused.
        assert!(xite.sign(other, 1.0).is_err());
    }

    #[test]
    fn set_content_rejects_bad_signature() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let (address, mut content_bytes) = signed_content(priv_hex, json!({}));
        // Corrupt the signed body.
        content_bytes = serde_json::to_vec(&{
            let mut v: serde_json::Value = serde_json::from_slice(&content_bytes).unwrap();
            v["modified"] = json!(0); // invalidates the signature
            v
        })
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(
            Address::parse(address).unwrap(),
            XiteStorage::new(dir.path()),
        );
        assert!(xite.set_content(&content_bytes).is_err());
    }
}
