//! `epix-xite` - xite lifecycle: storage, content.json, and peer announcing.

pub mod announcer;
pub mod hashfield;
pub mod settings;
pub mod piecefield;
pub mod piecemap;
pub mod xite;
pub mod storage;

pub use announcer::{announce, SelfAdvert, Tracker};
pub use epix_discovery::OnionSigner;
pub use hashfield::Hashfield;
pub use settings::{content_stats, Cache, ContentStats, OptionalFileStat, XiteSettings};
pub use piecefield::Piecefield;
pub use piecemap::{build_piecemap, hash_bigfile, parse_piecemap, BigfileHash};
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
    fn stage_content_adopts_in_memory_without_touching_disk() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let a = XiteStorage::hash_bytes(b"hello");
        let (address, content_bytes) =
            signed_content(priv_hex, json!({ "a.txt": { "size": 5, "sha512": a } }));

        let dir = tempfile::tempdir().unwrap();
        let mut xite =
            Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));

        // Staging verifies + adopts in memory: the sync workers can read the
        // declared files, but the stored content.json (the completeness
        // marker) is untouched.
        xite.stage_content(&content_bytes).unwrap();
        assert!(xite.content.is_some());
        assert_eq!(xite.files_needed().len(), 1);
        assert!(!xite.storage.exists("content.json"), "staging must not write to disk");

        // The commit lands the exact staged bytes.
        xite.commit_content(&content_bytes).unwrap();
        assert_eq!(xite.storage.read("content.json").unwrap(), content_bytes);

        // A bad signature still fails at stage time.
        let mut tampered: serde_json::Value = serde_json::from_slice(&content_bytes).unwrap();
        tampered["title"] = json!("evil");
        assert!(xite.stage_content(&serde_json::to_vec(&tampered).unwrap()).is_err());
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
        // Whole-second timestamps sign as integers (EpixNet writes int(time.time())).
        assert_eq!(content["modified"], 1777992698);
        assert!(content["files"].get("content.json").is_none(), "content.json isn't listed in files");
        assert!(xite.files_needed().is_empty());

        // Reloading the written file re-verifies (round-trips on disk).
        let mut reloaded = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
        assert!(reloaded.load_content().unwrap());
    }

    #[test]
    fn sign_applies_ignore_and_skips_nested_content_units() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
        xite.storage.write("index.html", b"<h1>hi</h1>").unwrap();
        xite.storage.write("css/all.css", b"body{}").unwrap();
        xite.storage.write("css/extra.css", b"p{}").unwrap();
        xite.storage.write("build.py", b"print(1)").unwrap();
        // A nested content unit (like data/users/content.json): its files are
        // separately signed user content, never the root's.
        xite.storage.write("data/users/content.json", b"{}").unwrap();
        xite.storage.write("data/users/alice/data.json", b"{}").unwrap();
        // An EpixNet-style ignore with a lookahead: css/ except all.css, and
        // anything .py.
        let content = serde_json::to_vec(&json!({
            "ignore": "(css/(?!all\\.css)|.*\\.py)",
        }))
        .unwrap();
        xite.storage.write("content.json", &content).unwrap();
        xite.content = Some(serde_json::from_slice(&content).unwrap());

        xite.sign(priv_hex, 1777992698.0).unwrap();

        let files = xite.content.as_ref().unwrap()["files"].as_object().unwrap();
        let mut keys: Vec<&str> = files.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["css/all.css", "index.html"]);
    }

    #[test]
    fn sign_splits_files_by_the_optional_pattern() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
        xite.storage.write("avatar.jpg", b"AV").unwrap();
        xite.storage.write("1775.jpg", b"PHOTO").unwrap();
        xite.storage.write("data.json", b"{}").unwrap();
        // An EpixPost-style optional lookahead: every jpg except the avatar.
        let content = serde_json::to_vec(&json!({ "optional": "(?!avatar).*jpg" })).unwrap();
        xite.storage.write("content.json", &content).unwrap();
        xite.content = Some(serde_json::from_slice(&content).unwrap());

        xite.sign(priv_hex, 1777992698.0).unwrap();

        // Matches hash into files_optional (size + sha512, they don't count
        // against the required size limit); everything else stays required.
        let content = xite.content.clone().unwrap();
        let mut required: Vec<&str> =
            content["files"].as_object().unwrap().keys().map(|s| s.as_str()).collect();
        required.sort();
        assert_eq!(required, ["avatar.jpg", "data.json"]);
        assert_eq!(content["files_optional"]["1775.jpg"]["size"], 5);
        assert_eq!(
            content["files_optional"]["1775.jpg"]["sha512"],
            XiteStorage::hash_bytes(b"PHOTO")
        );
        assert_eq!(content["files_optional"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn sign_without_an_optional_pattern_declares_no_optional_files() {
        // EpixTalk regression guard: a content.json with no `optional` key
        // signs everything as required and gains no files_optional node, even
        // for names another site's pattern would match.
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
        xite.storage.write("index.html", b"<h1>hi</h1>").unwrap();
        xite.storage.write("1775.jpg", b"PHOTO").unwrap();

        xite.sign(priv_hex, 1777992698.0).unwrap();

        let content = xite.content.clone().unwrap();
        let mut keys: Vec<&str> =
            content["files"].as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["1775.jpg", "index.html"]);
        assert!(content.get("files_optional").is_none());
    }

    #[test]
    fn sign_keeps_declared_optional_entries_for_absent_files() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
        // gone.jpg is declared optional but was never downloaded; new.jpg is a
        // fresh match on disk.
        xite.storage.write("new.jpg", b"NEW").unwrap();
        let content = serde_json::to_vec(&json!({
            "optional": ".*jpg",
            "files_optional": { "gone.jpg": { "size": 3, "sha512": "aa" } },
        }))
        .unwrap();
        xite.storage.write("content.json", &content).unwrap();
        xite.content = Some(serde_json::from_slice(&content).unwrap());

        xite.sign(priv_hex, 1777992698.0).unwrap();

        let content = xite.content.clone().unwrap();
        let optional = content["files_optional"].as_object().unwrap();
        assert_eq!(optional["gone.jpg"], json!({ "size": 3, "sha512": "aa" }));
        assert_eq!(optional["new.jpg"]["sha512"], XiteStorage::hash_bytes(b"NEW"));
        assert!(content["files"].as_object().unwrap().is_empty());
    }

    #[test]
    fn sign_skips_declared_merge_files() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let address = epix_crypt::privatekey_to_address(priv_hex).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut xite = Xite::new(Address::parse(address).unwrap(), XiteStorage::new(dir.path()));
        xite.storage.write("posts.json", br#"{"record_format":"epix-orset-1","post":[]}"#).unwrap();
        xite.storage.write("index.html", b"<h1>hi</h1>").unwrap();
        let content = serde_json::to_vec(&json!({
            "files_merged": { "posts.json": { "class": "epix-orset-1" } },
        }))
        .unwrap();
        xite.storage.write("content.json", &content).unwrap();
        xite.content = Some(serde_json::from_slice(&content).unwrap());

        xite.sign(priv_hex, 1777992698.0).unwrap();

        let content = xite.content.clone().unwrap();
        // posts.json is NEVER hashed into files/files_optional (would re-arm LWW).
        assert!(content["files"].get("posts.json").is_none());
        assert!(content.get("files_optional").and_then(|o| o.get("posts.json")).is_none());
        // A normal file still hashes, and the merge-file declaration is preserved.
        assert!(content["files"].get("index.html").is_some());
        assert_eq!(content["files_merged"]["posts.json"]["class"], "epix-orset-1");
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

    #[test]
    fn load_content_local_serves_unverified_on_disk() {
        // A content.json signed for one address, stored under a DIFFERENT one
        // (e.g. files copied into a new site's dir but not re-signed yet). The
        // verifying load rejects it; the local load parses it so the on-disk
        // copy still serves - a signature is only required from peers.
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let (signed_for, content_bytes) = signed_content(priv_hex, json!({}));
        let other = "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g";
        assert_ne!(signed_for, other);

        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage.write("content.json", &content_bytes).unwrap();

        let mut xite = Xite::new(Address::parse(other.to_string()).unwrap(), storage);
        // Verifying load fails against the wrong address, leaving content unset.
        assert!(xite.load_content().is_err());
        assert!(xite.content.is_none());
        // Lenient local load parses it so the files can be served (and signed).
        assert!(xite.load_content_local());
        assert!(xite.content.is_some());
        assert_eq!(xite.content.as_ref().unwrap()["address"], signed_for);
    }
}
