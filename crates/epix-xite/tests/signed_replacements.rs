use epix_content::verify::VerifyContext;
use epix_core::Address;
use epix_xite::{Xite, XiteStorage};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const OWNER: &str = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
const CHILD: &str = "data/admin/content.json";
const DATA: &str = "data/admin/data.json";

struct Context {
    address: String,
    root: Value,
    storage: XiteStorage,
}

impl VerifyContext for Context {
    fn xite_address(&self) -> &str {
        &self.address
    }
    fn loaded_content(&self, path: &str) -> Option<Value> {
        (path == "content.json").then(|| self.root.clone())
    }
    fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        self.storage.read(path).ok()
    }
}

fn fixture(child: Value) -> (tempfile::TempDir, Xite, Context) {
    let directory = tempfile::tempdir().unwrap();
    let address = epix_crypt::privatekey_to_address(OWNER).unwrap();
    let storage = XiteStorage::new(directory.path());
    let mut root = json!({
        "address": address,
        "files": {},
        "includes": {
            (CHILD): {"signers": [], "signers_required": 1, "max_items": {"comment": 1}}
        }
    });
    epix_content::sign(&mut root, OWNER).unwrap();
    storage
        .write("content.json", &serde_json::to_vec(&root).unwrap())
        .unwrap();
    storage
        .write(CHILD, &serde_json::to_vec(&child).unwrap())
        .unwrap();
    storage
        .write(DATA, br#"{"comment":[{"body":"old"}]}"#)
        .unwrap();
    let xite = Xite::new(Address::parse(address.clone()).unwrap(), storage.clone());
    let context = Context {
        address,
        root,
        storage,
    };
    (directory, xite, context)
}

fn snapshot(storage: &XiteStorage) -> BTreeMap<String, Vec<u8>> {
    storage
        .list_files()
        .unwrap()
        .into_iter()
        .map(|path| {
            let bytes = storage.read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

#[test]
fn replacement_hashes_use_new_bytes_and_preparation_does_not_write_them() {
    let (_directory, xite, context) = fixture(json!({"files": {}}));
    let before = snapshot(&context.storage);
    let edited = br#"{"comment":[{"body":"a substantially longer replacement"}]}"#.to_vec();
    let replacements = BTreeMap::from([(DATA.to_string(), edited.clone())]);
    let prepared = xite
        .prepare_child_sign_with_replacements(
            CHILD,
            OWNER,
            1000.0,
            &Default::default(),
            &context,
            &replacements,
        )
        .unwrap();
    let entry = &prepared.content()["files"]["data.json"];
    assert_eq!(entry["size"], edited.len());
    assert_eq!(entry["sha512"], XiteStorage::hash_bytes(&edited));
    assert_eq!(entry["b3"], epix_blob::ObjId::of(&edited).to_string());
    assert_eq!(prepared.pruned_files().get(DATA), Some(&edited));
    assert_eq!(snapshot(&context.storage), before);
}

#[test]
fn replacement_item_limit_checks_edited_bytes_instead_of_old_disk_bytes() {
    let (_directory, xite, context) = fixture(json!({"files": {}}));
    let before = snapshot(&context.storage);
    let replacements = BTreeMap::from([(
        DATA.to_string(),
        br#"{"comment":[{"body":"one"},{"body":"two"}]}"#.to_vec(),
    )]);
    let error = xite
        .prepare_child_sign_with_replacements(
            CHILD,
            OWNER,
            1000.0,
            &Default::default(),
            &context,
            &replacements,
        )
        .err()
        .expect("edited file exceeds max_items");
    assert!(error.to_string().contains("Too many items"), "{error}");
    assert_eq!(snapshot(&context.storage), before);
}

#[test]
fn a_rejected_replacement_signature_preserves_every_stored_byte() {
    let (_directory, xite, context) = fixture(json!({"files": {}}));
    let before = snapshot(&context.storage);
    let replacements = BTreeMap::from([(
        DATA.to_string(),
        br#"{"comment":[{"body":"unauthorized"}]}"#.to_vec(),
    )]);
    let key = epix_crypt::new_seed();
    let error = xite
        .prepare_child_sign_with_replacements(
            CHILD,
            &key,
            1000.0,
            &Default::default(),
            &context,
            &replacements,
        )
        .err()
        .expect("unrelated signer must be rejected");
    assert!(error.to_string().contains("Valid signs: 0/1"), "{error}");
    assert_eq!(snapshot(&context.storage), before);
}

#[test]
fn pruning_never_stages_ignored_nested_or_unhashed_optional_files() {
    let unchanged = br#"{"comment":[{"body":"one"},{"body":"two"}]}"#;
    let (_directory, xite, context) = fixture(json!({
        "files": {},
        "ignore": "ignored-data\\.json",
        "files_optional": {
            "preserved-data.json": {
                "size": unchanged.len(), "sha512": XiteStorage::hash_bytes(unchanged),
                "b3": epix_blob::ObjId::of(unchanged).to_string()
            }
        }
    }));
    context.storage.write(DATA, unchanged).unwrap();
    context
        .storage
        .write("data/admin/settings.json", br#"{"title":"Old"}"#)
        .unwrap();
    context
        .storage
        .write("data/admin/ignored-data.json", unchanged)
        .unwrap();
    context
        .storage
        .write("data/admin/preserved-data.json", unchanged)
        .unwrap();
    context
        .storage
        .write("data/admin/nested/content.json", br#"{"files":{}}"#)
        .unwrap();
    context
        .storage
        .write("data/admin/nested/data.json", unchanged)
        .unwrap();
    let before = snapshot(&context.storage);
    let replacements = BTreeMap::from([(
        "data/admin/settings.json".to_string(),
        br#"{"title":"New"}"#.to_vec(),
    )]);
    let prepared = xite
        .prepare_child_sign_with_replacements(
            CHILD,
            OWNER,
            1000.0,
            &Default::default(),
            &context,
            &replacements,
        )
        .unwrap();
    assert_eq!(
        prepared.pruned_files().keys().cloned().collect::<Vec<_>>(),
        [DATA.to_string(), "data/admin/settings.json".to_string(),]
    );
    let pruned: Value = serde_json::from_slice(&prepared.pruned_files()[DATA]).unwrap();
    assert_eq!(pruned["comment"], json!([{"body": "two"}]));
    assert_eq!(
        prepared.content()["files_optional"]["preserved-data.json"]["sha512"],
        XiteStorage::hash_bytes(unchanged)
    );
    assert_eq!(snapshot(&context.storage), before);
}
