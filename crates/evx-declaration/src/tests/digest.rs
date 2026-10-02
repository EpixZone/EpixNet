//! The declaration digest covers the `evx` object, canonically, and nothing
//! else.

use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::{content, evx, set, without};
use crate::{declaration_digest, DeclarationError};

#[test]
fn digest_is_sha256_of_the_sorted_compact_evx_object() {
    let section = json!({ "version": 1, "programs": { "b": { "entry": "b.wasm" }, "a": { "z": [1, 2.5, "é\n"], "y": null } } });
    let canonical =
        r#"{"programs":{"a":{"y":null,"z":[1,2.5,"é\n"]},"b":{"entry":"b.wasm"}},"version":1}"#;
    let expected = hex::encode(Sha256::digest(canonical.as_bytes()));
    assert_eq!(declaration_digest(&content(section)).unwrap(), expected);
    assert_eq!(expected.len(), 64);
}

#[test]
fn digest_ignores_key_order_and_the_rest_of_content_json() {
    let reference = declaration_digest(&content(evx())).unwrap();
    let reordered = serde_json::from_str(
        r#"{"programs":{"score":{"capabilities":[{"api":"game.score.get"}],"entry":"evx/score.wasm","runtime_profile":"wasm-core-v1"},"presence":{"limits":{"fuel":500000,"memory_bytes":2097152},"capabilities":[{"api":"workspace.read"},{"api":"workspace.write"}],"allow_run_once":true,"dependencies":["evx/lib.wasm"],"entry":"evx/presence.wasm","runtime_profile":"wasm-core-v1"}},"jobs":{"presence-every-30m":{"max_concurrency":1,"schedule":{"missed":"skip","anchor":"unix_epoch","seconds":1800,"type":"interval"},"program":"presence"}},"version":1}"#,
    )
    .unwrap();
    assert_eq!(declaration_digest(&content(reordered)).unwrap(), reference);
    let elsewhere = set(
        set(content(evx()), "/modified", json!(1_800_000_000_000_i64)),
        "/title",
        json!("Renamed"),
    );
    assert_eq!(declaration_digest(&elsewhere).unwrap(), reference);
    let elsewhere = set(content(evx()), "/signs", json!({ "epix1test": "sig" }));
    assert_eq!(declaration_digest(&elsewhere).unwrap(), reference);
}

#[test]
fn any_change_inside_the_section_changes_the_digest() {
    let reference = declaration_digest(&content(evx())).unwrap();
    for changed in [
        set(evx(), "/programs/presence/allow_run_once", json!(false)),
        set(
            evx(),
            "/programs/presence/capabilities/1",
            json!({ "api": "game.score.get" }),
        ),
        set(evx(), "/programs/presence/limits/fuel", json!(500_001)),
        set(
            evx(),
            "/jobs/presence-every-30m/schedule/seconds",
            json!(1801),
        ),
        without(evx(), "/jobs"),
        set(evx(), "/streams", json!({})),
    ] {
        assert_ne!(declaration_digest(&content(changed)).unwrap(), reference);
    }
}

#[test]
fn digest_does_not_require_a_parseable_declaration() {
    let malformed = json!({ "version": 2, "network": true });
    let digest = declaration_digest(&content(malformed)).unwrap();
    let canonical = r#"{"network":true,"version":2}"#;
    assert_eq!(digest, hex::encode(Sha256::digest(canonical.as_bytes())));
}

#[test]
fn digest_fails_without_an_evx_object() {
    assert_eq!(
        declaration_digest(&json!({ "files": {} })),
        Err(DeclarationError::Missing)
    );
    assert_eq!(
        declaration_digest(&json!([])),
        Err(DeclarationError::malformed("content.json is not an object"))
    );
    for section in [json!(null), json!([]), json!("x"), json!(1)] {
        assert_eq!(
            declaration_digest(&content(section)),
            Err(DeclarationError::malformed("evx: must be an object"))
        );
    }
    let overflow = content(json!({ "version": 1, "programs": {}, "big": u64::MAX }));
    assert!(matches!(
        declaration_digest(&overflow),
        Err(DeclarationError::Malformed(_))
    ));
}

#[test]
fn digest_is_not_the_python_signed_data_digest() {
    let root = content(evx());
    let digest = declaration_digest(&root).unwrap();
    let signed_data = epix_content::signed_data(&root);
    assert_ne!(digest, hex::encode(Sha256::digest(signed_data.as_bytes())));
    let evx_signed = epix_content::dumps_sorted(&root["evx"]);
    assert!(
        evx_signed.contains("\": "),
        "Python separators are not canonical here"
    );
    assert_ne!(digest, hex::encode(Sha256::digest(evx_signed.as_bytes())));
}
