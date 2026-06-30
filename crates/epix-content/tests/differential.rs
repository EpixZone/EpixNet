//! Differential test: epix-content canonicalization + verification must match
//! EpixNet's Python `ContentManager` (vectors generated from it).

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Vectors {
    canonical: Vec<CanonCase>,
    real: RealCase,
}

#[derive(Deserialize)]
struct CanonCase {
    value: Value,
    expected: String,
}

#[derive(Deserialize)]
struct RealCase {
    content: Value,
    signer: String,
    sig: String,
    signed_data: String,
    verify: bool,
}

fn load() -> Vectors {
    serde_json::from_str(include_str!("content_vectors.json")).expect("parse vectors")
}

#[test]
fn canonicalization_matches_python_json_dumps() {
    let v = load();
    for (i, c) in v.canonical.iter().enumerate() {
        assert_eq!(
            epix_content::dumps_sorted(&c.value),
            c.expected,
            "canonical mismatch #{i}"
        );
    }
}

#[test]
fn real_content_signed_data_is_byte_exact() {
    let v = load();
    // The canonical payload of a real 8 KB content.json must match Python's
    // json.dumps(content_without_signs, sort_keys=True) exactly.
    assert_eq!(epix_content::signed_data(&v.real.content), v.real.signed_data);
}

#[test]
fn real_network_signature_verifies() {
    let v = load();
    assert!(v.real.verify, "python self-consistency");
    // The real signature from the live network verifies in Rust.
    assert!(
        epix_content::verify_signer(&v.real.content, &v.real.signer),
        "real signature failed to verify"
    );
    // And via verify_all.
    let all = epix_content::verify_all(&v.real.content);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, v.real.signer);
    assert!(all[0].1);
    // Sanity: the captured signature is the one in the content.
    assert_eq!(
        v.real.content["signs"][&v.real.signer].as_str().unwrap(),
        v.real.sig
    );
}
