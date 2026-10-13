use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use evx_api::Capability;
use serde_json::{json, Value};

use super::{generate_key, public, PROGRAM};
use crate::{digest, sign_envelope, ActivationLoader, XiteGrant, MAX_ARTIFACT};

fn fixture() -> (SigningKey, ActivationLoader, Value) {
    let key = generate_key();
    let grant = XiteGrant::new(
        "game",
        "publisher",
        public(&key),
        BTreeSet::from([Capability::GameScoreGet]),
        BTreeSet::from(["fixture.wasm.v1".to_owned()]),
    )
    .unwrap();
    let body = json!({
        "kind": "evx.activation.v1", "xite": "game", "publisher": "publisher",
        "version": 1, "runtime_profile": "fixture.wasm.v1", "entry": "main.wat",
        "artifact_format": "wat", "files": {"main.wat": digest(PROGRAM)},
        "capabilities": ["game.score.get"],
    });
    (key, ActivationLoader::new(grant), body)
}

#[test]
fn reader_retains_authenticated_bytes_and_admission_remains_separate() {
    let (key, mut loader, body) = fixture();
    let envelope = sign_envelope(&body, &key);
    let mut source = PROGRAM.to_vec();
    let mut calls = 0;
    let pending = loader
        .verify_reader(&envelope, &mut |name, limit| {
            assert_eq!(name, "main.wat");
            assert_eq!(limit, MAX_ARTIFACT);
            calls += 1;
            Ok(source.clone())
        })
        .unwrap();
    source.fill(b'x');
    assert_eq!(calls, 1);
    assert_eq!(pending.entry_bytes(), PROGRAM);
    assert_eq!(loader.checkpoint().version, 0);
    assert_eq!(loader.admit(pending).unwrap().entry_bytes(), PROGRAM);
    assert_eq!(loader.checkpoint().version, 1);
}

#[test]
fn invalid_authority_never_invokes_reader() {
    let (key, loader, body) = fixture();
    let mut cases = vec![sign_envelope(&body, &generate_key())];
    for (field, value) in [
        ("xite", json!("other-game")),
        ("capabilities", json!(["workspace.write"])),
        ("entry", json!("../main.wat")),
    ] {
        let mut changed = body.clone();
        changed[field] = value;
        cases.push(sign_envelope(&changed, &key));
    }
    let mut calls = 0;
    for envelope in cases {
        assert!(loader
            .verify_reader(&envelope, &mut |_, _| {
                calls += 1;
                Ok(PROGRAM.to_vec())
            })
            .is_err());
    }
    assert_eq!(calls, 0);
    assert_eq!(loader.checkpoint().version, 0);
}

#[test]
fn reader_cannot_bypass_per_file_or_total_byte_limits() {
    let (key, loader, mut body) = fixture();
    let oversized = vec![b' '; MAX_ARTIFACT + 1];
    body["files"] = json!({"main.wat": digest(&oversized)});
    let error = loader
        .verify_reader(&sign_envelope(&body, &key), &mut |_, limit| {
            assert_eq!(limit, MAX_ARTIFACT);
            Ok(oversized.clone())
        })
        .unwrap_err();
    assert_eq!(error.message(), "artifact size limit");

    let mut program = PROGRAM.to_vec();
    program.resize(MAX_ARTIFACT, b' ');
    let mut files = serde_json::Map::new();
    for name in ["a.wat", "b.wat", "c.wat", "d.wat", "main.wat"] {
        files.insert(name.into(), json!(digest(&program)));
    }
    body["files"] = Value::Object(files);
    let mut limits = Vec::new();
    assert!(loader
        .verify_reader(&sign_envelope(&body, &key), &mut |_, limit| {
            limits.push(limit);
            Ok(program.clone())
        })
        .is_err());
    assert_eq!(
        limits,
        [MAX_ARTIFACT, MAX_ARTIFACT, MAX_ARTIFACT, MAX_ARTIFACT, 0]
    );
    assert_eq!(loader.checkpoint().version, 0);
}

#[test]
fn changed_bytes_or_stale_version_are_refused_without_advancing_state() {
    let (key, mut loader, mut body) = fixture();
    assert!(loader
        .verify_reader(&sign_envelope(&body, &key), &mut |_, _| {
            Ok(b"(module)".to_vec())
        })
        .is_err());
    assert_eq!(loader.checkpoint().version, 0);
    body["version"] = json!(2);
    let pending = loader
        .verify_reader(
            &sign_envelope(&body, &key),
            &mut |_, _| Ok(PROGRAM.to_vec()),
        )
        .unwrap();
    loader.admit(pending).unwrap();
    body["version"] = json!(1);
    assert!(loader
        .verify_reader(&sign_envelope(&body, &key), &mut |_, _| {
            panic!("stale version must be refused before reading")
        })
        .is_err());
    assert_eq!(loader.checkpoint().version, 2);
}
