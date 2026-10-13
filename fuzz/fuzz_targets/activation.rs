#![no_main]

use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use evx_activation::{ActivationLoader, XiteGrant};
use evx_api::Capability;
use libfuzzer_sys::fuzz_target;

const PROGRAM: &[u8] =
    b"(module (memory (export \"memory\") 1) (func (export \"run\") (result i32) i32.const 42))";

fn fixture_root() -> &'static tempfile::TempDir {
    static ROOT: OnceLock<tempfile::TempDir> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("main.wat"), PROGRAM).unwrap();
        root
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    // Public sacrificial signing material, used only to reach authenticated
    // parsing and capture. No real publisher identity or filesystem is used.
    let key = SigningKey::from_bytes(&[7; 32]);
    let grant = XiteGrant::new(
        "game-one",
        "publisher-one",
        key.verifying_key().to_bytes(),
        [Capability::GameScoreGet].into(),
        ["fixture.wasm.v1".to_owned()].into(),
    )
    .unwrap();
    let mut loader = ActivationLoader::new(grant.clone());
    let root = fixture_root().path();
    let _ = loader.verify(data, root);
    // Strict parsing bounds nesting and rejects duplicate keys before the
    // fixture signer canonicalizes a mutated body.
    if evx_api::strict::parse(data).is_err() {
        return;
    }
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let signed = evx_activation::sign_envelope(&body, &key);
    if let Ok(pending) = loader.verify(&signed, root) {
        assert_eq!(pending.xite(), "game-one");
        assert_eq!(pending.publisher(), "publisher-one");
        assert!(pending.capabilities().is_subset(&grant.capabilities));
        let second_pending = loader.verify(&signed, root).unwrap();
        let mut other_grant = grant.clone();
        other_grant.capabilities.clear();
        let mut other = ActivationLoader::new(other_grant);
        assert!(other.admit(second_pending).is_err());
        let activation = loader.admit(pending).unwrap();
        assert_eq!(activation.entry_bytes(), PROGRAM);
        assert_eq!(activation.files().count(), 1);
        assert_eq!(loader.checkpoint().version, activation.version());
    }
});
