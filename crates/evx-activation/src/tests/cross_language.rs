//! Envelopes and canonicalization vectors minted by the Python reference
//! implementation (`authenticated_artifacts.py`) with a disposable key.
//!
//! `fixtures/python_signed.json` is written by the harness script, never by
//! hand: every byte in it came out of the reference module. If the Rust
//! canonicalization or verifier drifted from the reference, these tests fail.

use std::collections::BTreeSet;

use evx_api::Capability;
use serde_json::Value;
use tempfile::TempDir;

use super::{generate_key, public, PROGRAM};
use crate::envelope::{to_serde, verify_envelope};
use crate::{canonical_bytes, digest, ActivationLoader, XiteGrant};

const FIXTURES: &str = include_str!("fixtures/python_signed.json");

struct Fixtures {
    public_key: [u8; 32],
    program_digest: String,
    activation_manifest_digest: String,
    activation_envelope: Vec<u8>,
    unicode_envelope: Vec<u8>,
    unicode_body_digest: String,
    vectors: Vec<(String, String)>,
}

fn fixtures() -> Fixtures {
    let value: Value = serde_json::from_str(FIXTURES).unwrap();
    let text = |name: &str| value[name].as_str().unwrap().to_string();
    let public_key: [u8; 32] = hex::decode(text("public_key_hex"))
        .unwrap()
        .try_into()
        .unwrap();
    let vectors = value["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_string(),
                pair[1].as_str().unwrap().to_string(),
            )
        })
        .collect();
    Fixtures {
        public_key,
        program_digest: text("program_digest"),
        activation_manifest_digest: text("activation_manifest_digest"),
        activation_envelope: text("activation_envelope").into_bytes(),
        unicode_envelope: text("unicode_envelope").into_bytes(),
        unicode_body_digest: text("unicode_body_digest"),
        vectors,
    }
}

fn grant(public_key: [u8; 32]) -> XiteGrant {
    XiteGrant::new(
        "game-one",
        "publisher-one",
        public_key,
        [Capability::GameScoreGet, Capability::WorkspaceRead]
            .into_iter()
            .collect(),
        ["fixture.wasm.v1".to_string()].into_iter().collect(),
    )
    .unwrap()
}

#[test]
fn python_signed_activation_envelope_admits_in_rust() {
    let fx = fixtures();
    assert_eq!(digest(PROGRAM), fx.program_digest);
    let temp = TempDir::new().unwrap();
    std::fs::write(temp.path().join("main.wat"), PROGRAM).unwrap();

    let mut loader = ActivationLoader::new(grant(fx.public_key));
    let pending = loader.verify(&fx.activation_envelope, temp.path()).unwrap();
    assert_eq!(pending.manifest_digest(), fx.activation_manifest_digest);
    assert_eq!(pending.version(), 1);
    assert_eq!(
        pending.capabilities(),
        &BTreeSet::from([Capability::GameScoreGet])
    );
    let activation = loader.admit(pending).unwrap();
    assert_eq!(activation.entry_bytes(), PROGRAM);
    assert_eq!(loader.checkpoint().version, 1);
    assert_eq!(
        loader.checkpoint().manifest_digest.as_deref(),
        Some(fx.activation_manifest_digest.as_str())
    );

    // The same envelope under a different trusted key is refused.
    let other = ActivationLoader::new(grant(public(&generate_key())));
    assert!(other.verify(&fx.activation_envelope, temp.path()).is_err());
    // A single flipped byte inside the signed body is refused.
    let mut tampered = fx.activation_envelope.clone();
    let position = tampered
        .windows(9)
        .position(|w| w == b"\"version\"")
        .unwrap()
        + 10;
    tampered[position] = b'2';
    assert!(loader.verify(&tampered, temp.path()).is_err());
}

#[test]
fn python_signed_unicode_envelope_verifies_and_recanonicalizes() {
    let fx = fixtures();
    let signed = verify_envelope(&fx.unicode_envelope, &fx.public_key).unwrap();
    assert_eq!(digest(&signed.bytes), fx.unicode_body_digest);
    // Re-canonicalizing the decoded body reproduces the signed bytes exactly.
    let body = Value::Object(signed.body.clone());
    assert_eq!(canonical_bytes(&body).unwrap(), signed.bytes);
    // The escapes decoded to the characters the reference started from.
    assert_eq!(
        body["text"].as_str().unwrap(),
        "h\u{e9}llo w\u{f6}rld \u{2014} \u{1F600} \u{0}\u{1f}\u{7f} \"quoted\" back\\slash \n\t\u{8}\u{c}\r end"
    );
    assert_eq!(body["cjk"].as_str().unwrap(), "\u{65e5}\u{672c}\u{8a9e}");
    assert_eq!(
        body["emoji"].as_str().unwrap(),
        "\u{1F3AE}\u{1F579}\u{fe0f}"
    );
    assert_eq!(body["nested"]["z"][3], Value::from(1e16));
    assert_eq!(
        body["nested"]["z"][6],
        Value::from(123_456_789_012_345_678_i64)
    );
}

#[test]
fn python_canonical_vectors_match() {
    let fx = fixtures();
    assert!(fx.vectors.len() >= 30);
    for (input, expected) in &fx.vectors {
        assert!(!expected.starts_with("ERROR"), "reference refused {input}");
        // Through serde_json, as the fixture signer sees values.
        let parsed: Value = serde_json::from_str(input).unwrap();
        let actual = String::from_utf8(canonical_bytes(&parsed).unwrap()).unwrap();
        assert_eq!(&actual, expected, "serde path for {input}");
        // Through the strict parser, as the verifier sees envelope bodies.
        let strict = evx_api::strict::parse(input.as_bytes())
            .unwrap_or_else(|err| panic!("strict parse of {input}: {err}"));
        let converted = to_serde(&strict).unwrap();
        let actual = String::from_utf8(canonical_bytes(&converted).unwrap()).unwrap();
        assert_eq!(&actual, expected, "strict path for {input}");
    }
}
