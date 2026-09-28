//! Root authoring defaults are signed, preserve edits, and never alter received manifests.
use epix_core::Address;
use epix_xite::{Xite, XiteStorage};
use serde_json::{json, Value};

const FIELDS: &[&str] = &[
    "title",
    "description",
    "domain",
    "favicon",
    "background-color",
    "background-color-light",
    "background-color-dark",
    "viewport",
    "ignore",
    "optional",
    "shard",
];

fn fixture() -> (tempfile::TempDir, String, Xite) {
    let dir = tempfile::tempdir().unwrap();
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let storage = XiteStorage::new(dir.path());
    storage.write("index.html", b"<h1>My xite</h1>").unwrap();
    (
        dir,
        key,
        Xite::new(Address::parse(address).unwrap(), storage),
    )
}

#[test]
fn signing_root_adds_empty_authoring_fields_without_changing_file_classification() {
    let (_dir, key, mut xite) = fixture();
    xite.sign(&key, 1.0).unwrap();
    let content: Value =
        serde_json::from_slice(&xite.storage.read("content.json").unwrap()).unwrap();
    for field in FIELDS {
        assert_eq!(
            content.get(*field),
            Some(&json!("")),
            "missing editable field {field}"
        );
    }
    assert!(content["files"]["index.html"].is_object());
    assert!(content.get("files_optional").is_none());
    assert!(content.get("files_shard").is_none());
    assert!(epix_content::verify_signer(&content, xite.address.as_str()));
    assert!(xite.load_content().unwrap());
}

#[test]
fn signing_preserves_existing_metadata_and_fills_missing_fields() {
    let (_dir, key, mut xite) = fixture();
    let edited = json!({
        "title": "My title", "description": "My description", "domain": "my-xite.epix",
        "favicon": "img/icon.png", "background-color": "#112233",
        "background-color-dark": "#101010", "viewport": "width=device-width",
        "ignore": "drafts/", "optional": "media/", "shard": "private/",
        "custom_metadata": "keep me"
    });
    xite.storage.write("drafts/note.txt", b"draft").unwrap();
    xite.storage.write("media/photo.jpg", b"image").unwrap();
    xite.content = Some(edited.clone());
    xite.sign(&key, 1.0).unwrap();
    let content = xite.content.as_ref().unwrap();
    for (field, value) in edited.as_object().unwrap() {
        assert_eq!(&content[field], value, "overwrote {field}");
    }
    assert_eq!(content.get("background-color-light"), Some(&json!("")));
    assert!(content["files"].get("drafts/note.txt").is_none());
    assert!(content["files_optional"]["media/photo.jpg"].is_object());
    assert!(epix_content::verify_signer(content, xite.address.as_str()));
}

#[test]
fn loading_a_signed_manifest_does_not_backfill_or_invalidate_it() {
    let (_dir, key, mut xite) = fixture();
    let mut content = json!({"address": xite.address.as_str(), "modified": 1, "files": {}});
    epix_content::sign(&mut content, &key).unwrap();
    let bytes = epix_content::dumps_content(&content).into_bytes();
    xite.set_content(&bytes).unwrap();
    assert_eq!(xite.content.as_ref(), Some(&content));
    assert_eq!(xite.storage.read("content.json").unwrap(), bytes);
    assert!(epix_content::verify_signer(
        xite.content.as_ref().unwrap(),
        xite.address.as_str()
    ));
}
