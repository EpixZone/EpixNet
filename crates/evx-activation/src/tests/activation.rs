use std::collections::BTreeSet;
use std::os::fd::BorrowedFd;
use std::path::Path;

use ed25519_dalek::SigningKey;
use evx_api::{Capability, Grant};
use serde_json::{json, Value};
use tempfile::TempDir;

use super::{generate_key, invalid_public_key, public, updated, with, PROGRAM};
use crate::capture;
use crate::{
    canonical_bytes, digest, sign_envelope, ActivationCheckpoint, ActivationLoader, ArtifactFormat,
    AuthenticationError, FrozenActivation, XiteGrant, MAX_ARTIFACT, MAX_ENVELOPE,
};

struct Fixture {
    temp: TempDir,
    publisher: SigningKey,
    impostor: SigningKey,
    grant: XiteGrant,
    loader: ActivationLoader,
    body: Value,
}

impl Fixture {
    fn new() -> Fixture {
        let temp = tempfile::Builder::new()
            .prefix("evx-auth-fixture-")
            .tempdir()
            .unwrap();
        let publisher = generate_key();
        let impostor = generate_key();
        let grant = XiteGrant::new(
            "game-one",
            "publisher-one",
            public(&publisher),
            [Capability::GameScoreGet, Capability::WorkspaceRead]
                .into_iter()
                .collect(),
            ["fixture.wasm.v1".to_string()].into_iter().collect(),
        )
        .unwrap();
        let loader = ActivationLoader::new(grant.clone());
        let body = json!({
            "kind": "evx.activation.v1", "xite": "game-one", "publisher": "publisher-one",
            "version": 1, "runtime_profile": "fixture.wasm.v1", "entry": "main.wat",
            "artifact_format": "wat", "files": {"main.wat": digest(PROGRAM)},
            "capabilities": ["game.score.get"],
        });
        std::fs::write(temp.path().join("main.wat"), PROGRAM).unwrap();
        Fixture {
            temp,
            publisher,
            impostor,
            grant,
            loader,
            body,
        }
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }

    fn write(&self, name: &str, data: &[u8]) {
        std::fs::write(self.root().join(name), data).unwrap();
    }

    fn signed(&self, body: &Value) -> Vec<u8> {
        sign_envelope(body, &self.publisher)
    }

    /// Two-phase activation with no binding check in between.
    fn activate(&mut self) -> Result<FrozenActivation, AuthenticationError> {
        let envelope = self.signed(&self.body);
        self.activate_raw(&envelope)
    }

    fn activate_body(&mut self, body: &Value) -> Result<FrozenActivation, AuthenticationError> {
        let envelope = self.signed(body);
        self.activate_raw(&envelope)
    }

    fn activate_signed(
        &mut self,
        body: &Value,
        key: &SigningKey,
    ) -> Result<FrozenActivation, AuthenticationError> {
        let envelope = sign_envelope(body, key);
        self.activate_raw(&envelope)
    }

    fn activate_raw(&mut self, envelope: &[u8]) -> Result<FrozenActivation, AuthenticationError> {
        let pending = self.loader.verify(envelope, self.temp.path())?;
        self.loader.admit(pending)
    }
}

#[test]
fn verified_entry_and_grant_context() {
    let mut fx = Fixture::new();
    let activation = fx.activate().unwrap();
    assert_eq!(activation.entry_bytes(), PROGRAM);
    assert_eq!(activation.xite(), fx.grant.xite);
    assert_eq!(activation.grant_generation(), fx.grant.generation);
    assert_eq!(
        activation.capabilities(),
        &BTreeSet::from([Capability::GameScoreGet])
    );
    assert_eq!(
        activation.manifest_digest(),
        digest(&canonical_bytes(&fx.body).unwrap())
    );
    assert_eq!(activation.artifact_format(), ArtifactFormat::Wat);
    assert_eq!(activation.entry(), "main.wat");
    assert_eq!(activation.files().collect::<Vec<_>>(), ["main.wat"]);
    // No key material travels with the activation.
    assert!(!format!("{activation:?}").contains(&hex::encode(fx.grant.public_key)));
    let context = activation.context(fx.grant.generation, fx.grant.public_key);
    assert_eq!(context.xite, "game-one");
    assert_eq!(context.publisher, "publisher-one");
    assert_eq!(context.generation, 1);
    assert_eq!(context.public_key, Some(fx.grant.public_key));
    assert_eq!(context.runtime_profile, "fixture.wasm.v1");
    assert_eq!(
        context.capabilities,
        BTreeSet::from([Capability::GameScoreGet])
    );
}

#[test]
fn authenticated_update_reuses_existing_grant_without_code_approval() {
    let mut fx = Fixture::new();
    let first = fx.activate().unwrap();
    fx.write("main.wat", &updated());
    let update = with(
        &fx.body,
        &[
            ("version", json!(2)),
            ("files", json!({"main.wat": digest(&updated())})),
        ],
    );
    let second = fx.activate_body(&update).unwrap();
    assert_eq!(fx.loader.grant(), &fx.grant);
    assert_eq!(first.entry_bytes(), PROGRAM);
    assert_eq!(second.entry_bytes(), updated());
    assert_eq!(first.grant_generation(), second.grant_generation());
}

#[test]
fn capability_expansion_denied_without_advancing_checkpoint() {
    let mut fx = Fixture::new();
    fx.activate().unwrap();
    let expanded = with(
        &fx.body,
        &[
            ("version", json!(2)),
            ("capabilities", json!(["game.score.get", "workspace.write"])),
        ],
    );
    assert!(fx.activate_body(&expanded).is_err());
    assert_eq!(fx.loader.checkpoint().version, 1);
}

#[test]
fn capability_already_in_grant_can_be_used_by_update() {
    let mut fx = Fixture::new();
    fx.activate().unwrap();
    let update = with(
        &fx.body,
        &[
            ("version", json!(2)),
            ("capabilities", json!(["workspace.read"])),
        ],
    );
    assert_eq!(
        fx.activate_body(&update).unwrap().capabilities(),
        &BTreeSet::from([Capability::WorkspaceRead])
    );
}

#[test]
fn disabled_grant_blocks_signed_program() {
    let mut fx = Fixture::new();
    fx.loader = ActivationLoader::new(fx.grant.clone().with_enabled(false));
    assert!(fx.activate().is_err());
}

#[test]
fn unknown_publisher_and_substituted_signing_key_fail() {
    let mut fx = Fixture::new();
    let impostor = fx.impostor.clone();
    let body = fx.body.clone();
    assert!(fx.activate_signed(&body, &impostor).is_err());
    assert!(fx
        .activate_body(&with(&body, &[("publisher", json!("attacker"))]))
        .is_err());
    let substituted = with(
        &body,
        &[("public_key", json!(hex::encode(public(&impostor))))],
    );
    assert!(fx.activate_body(&substituted).is_err());
}

#[test]
fn caller_claimed_xite_cannot_replace_grant_identity() {
    let mut fx = Fixture::new();
    let body = with(&fx.body, &[("xite", json!("other-game"))]);
    assert!(fx.activate_body(&body).is_err());
}

#[test]
fn tampered_signed_body_fails() {
    let mut fx = Fixture::new();
    let mut signed: Value = serde_json::from_slice(&fx.signed(&fx.body)).unwrap();
    signed["body"]["capabilities"] = json!(["workspace.read"]);
    assert!(fx.activate_raw(&canonical_bytes(&signed).unwrap()).is_err());
}

#[test]
fn unsigned_draft_and_duplicate_json_fields_fail() {
    let mut fx = Fixture::new();
    let draft = canonical_bytes(&fx.body).unwrap();
    assert!(fx.activate_raw(&draft).is_err());
    let envelope = fx.signed(&fx.body);
    let mut duplicated = envelope[..envelope.len() - 1].to_vec();
    duplicated.extend_from_slice(b",\"signature\":\"\"}");
    assert!(fx.activate_raw(&duplicated).is_err());
}

#[test]
fn malformed_envelopes_fail_without_unexpected_exceptions() {
    let mut fx = Fixture::new();
    let deep = [b"[".repeat(2000), b"]".repeat(2000)].concat();
    let cases: Vec<Vec<u8>> = vec![
        b"\xff".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        b"{\"body\":".to_vec(),
        deep,
        b"{\"body\":{},\"signature\":5}".to_vec(),
        b"{\"body\":{},\"signature\":\"%%%%\"}".to_vec(),
        Vec::new(),
    ];
    for raw in cases {
        assert!(
            fx.activate_raw(&raw).is_err(),
            "accepted {:?}",
            String::from_utf8_lossy(&raw[..raw.len().min(40)])
        );
    }
}

#[test]
fn trusted_signature_does_not_excuse_malformed_declarations() {
    let mut fx = Fixture::new();
    let keys: Vec<String> = fx.body.as_object().unwrap().keys().cloned().collect();
    for key in keys {
        let body = with(&fx.body, &[(key.as_str(), Value::Null)]);
        assert!(fx.activate_body(&body).is_err(), "accepted null {key}");
    }
    assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());
}

#[test]
fn artifact_and_dependency_tampering_fail() {
    let mut fx = Fixture::new();
    fx.write("main.wat", &updated());
    assert!(fx.activate().is_err());
    fx.write("main.wat", PROGRAM);
    fx.write("helper.wat", &updated());
    let closure = with(
        &fx.body,
        &[(
            "files",
            json!({"main.wat": digest(PROGRAM), "helper.wat": digest(PROGRAM)}),
        )],
    );
    assert!(fx.activate_body(&closure).is_err());
}

#[test]
fn dependency_closure_captured_and_unknown_dependency_denied() {
    let mut fx = Fixture::new();
    fx.write("helper.wat", &updated());
    let closure = with(
        &fx.body,
        &[(
            "files",
            json!({"main.wat": digest(PROGRAM), "helper.wat": digest(&updated())}),
        )],
    );
    let snapshot = fx.activate_body(&closure).unwrap();
    std::fs::remove_file(fx.root().join("helper.wat")).unwrap();
    assert_eq!(snapshot.artifact_bytes("helper.wat").unwrap(), updated());
    assert!(snapshot.artifact_bytes("unsigned.wat").is_err());
    assert_eq!(
        snapshot.files().collect::<Vec<_>>(),
        ["helper.wat", "main.wat"]
    );
}

#[test]
fn capture_never_reopens_replaced_path() {
    let mut fx = Fixture::new();
    let snapshot = fx.activate().unwrap();
    fx.write("new.wat", &updated());
    std::fs::rename(fx.root().join("new.wat"), fx.root().join("main.wat")).unwrap();
    assert_eq!(snapshot.entry_bytes(), PROGRAM);
    // The reference asserts FrozenInstanceError on `snapshot.entry = ...`;
    // here FrozenActivation has no public mutators, so the type enforces it.
}

#[test]
fn swap_after_capture_keeps_authenticated_bytes() {
    let mut fx = Fixture::new();
    let root = fx.root().to_path_buf();
    let envelope = fx.signed(&fx.body);
    let mut capture_and_swap =
        |fd: BorrowedFd<'_>, path: &str| -> Result<Vec<u8>, AuthenticationError> {
            let data = capture::capture_file(fd, path)?;
            std::fs::write(root.join(path), updated()).unwrap();
            Ok(data)
        };
    let pending = fx
        .loader
        .verify_with(&envelope, &root, &mut capture_and_swap)
        .unwrap();
    assert_eq!(fx.loader.admit(pending).unwrap().entry_bytes(), PROGRAM);
}

#[test]
fn swap_before_capture_is_detected() {
    let fx = Fixture::new();
    let root = fx.root().to_path_buf();
    let envelope = fx.signed(&fx.body);
    let mut swap_and_capture =
        |fd: BorrowedFd<'_>, path: &str| -> Result<Vec<u8>, AuthenticationError> {
            std::fs::write(root.join(path), updated()).unwrap();
            capture::capture_file(fd, path)
        };
    assert!(fx
        .loader
        .verify_with(&envelope, &root, &mut swap_and_capture)
        .is_err());
}

#[test]
fn symlink_and_hardlink_artifacts_fail() {
    let mut fx = Fixture::new();
    let original = fx.root().join("main.wat");
    let target = fx.root().join("target.wat");
    std::fs::write(&target, PROGRAM).unwrap();
    std::fs::remove_file(&original).unwrap();
    std::os::unix::fs::symlink(&target, &original).unwrap();
    assert!(fx.activate().is_err());
    std::fs::remove_file(&original).unwrap();
    std::fs::hard_link(&target, &original).unwrap();
    assert!(fx.activate().is_err());
}

#[test]
fn symlink_parent_and_root_fail() {
    let mut fx = Fixture::new();
    std::fs::create_dir(fx.root().join("real")).unwrap();
    std::fs::write(fx.root().join("real").join("main.wat"), PROGRAM).unwrap();
    std::os::unix::fs::symlink(fx.root().join("real"), fx.root().join("alias")).unwrap();
    let body = with(
        &fx.body,
        &[
            ("entry", json!("alias/main.wat")),
            ("files", json!({"alias/main.wat": digest(PROGRAM)})),
        ],
    );
    assert!(fx.activate_body(&body).is_err());
    let envelope = fx.signed(&fx.body);
    assert!(fx
        .loader
        .verify(&envelope, &fx.root().join("alias"))
        .is_err());
    // A real nested directory is fine.
    let nested = with(
        &fx.body,
        &[
            ("entry", json!("real/main.wat")),
            ("files", json!({"real/main.wat": digest(PROGRAM)})),
        ],
    );
    assert_eq!(fx.activate_body(&nested).unwrap().entry_bytes(), PROGRAM);
}

#[test]
fn path_escapes_are_rejected_even_if_signed() {
    let mut fx = Fixture::new();
    let long = format!("a/{}", "x".repeat(256));
    for path in [
        "../main.wat",
        "/main.wat",
        "a//main.wat",
        "a\\main.wat",
        "a/./main.wat",
        long.as_str(),
    ] {
        let body = with(
            &fx.body,
            &[
                ("entry", json!(path)),
                ("files", json!({path: digest(PROGRAM)})),
            ],
        );
        assert!(fx.activate_body(&body).is_err(), "accepted {path:?}");
    }
}

#[test]
fn rollback_and_same_version_conflict_fail() {
    let mut fx = Fixture::new();
    let v2 = with(&fx.body, &[("version", json!(2))]);
    fx.activate_body(&v2).unwrap();
    assert!(fx.activate().is_err());
    let conflicting = with(&v2, &[("capabilities", json!(["workspace.read"]))]);
    assert!(fx.activate_body(&conflicting).is_err());
    assert_eq!(fx.activate_body(&v2).unwrap().version(), 2);
}

#[test]
fn restored_host_checkpoint_preserves_version_floor() {
    let mut fx = Fixture::new();
    let v2 = with(&fx.body, &[("version", json!(2))]);
    fx.activate_body(&v2).unwrap();
    let checkpoint = fx.loader.checkpoint().clone();
    assert_eq!(checkpoint.version, 2);
    fx.loader = ActivationLoader::with_checkpoint(fx.grant.clone(), checkpoint);
    assert!(fx.activate().is_err());
}

#[test]
fn unsupported_runtime_and_native_cache_formats_fail() {
    let mut fx = Fixture::new();
    let body = with(
        &fx.body,
        &[("runtime_profile", json!("native.unrestricted"))],
    );
    assert!(fx.activate_body(&body).is_err());
    let body = with(
        &fx.body,
        &[("artifact_format", json!("wasmtime.serialized"))],
    );
    assert!(fx.activate_body(&body).is_err());
    let body = with(&fx.body, &[("artifact_format", json!("wasm-core-v1"))]);
    assert!(fx.activate_body(&body).is_err());
    assert!(ArtifactFormat::parse("wasmtime.serialized").is_none());
    assert!(ArtifactFormat::parse("cwasm").is_none());
}

#[test]
fn core_wasm_bytes_are_captured_without_native_deserialization() {
    let mut fx = Fixture::new();
    let core = b"\0asm\x01\0\0\0";
    fx.write("main.wat", core);
    let body = with(
        &fx.body,
        &[
            ("artifact_format", json!("wasm-core-v1")),
            ("files", json!({"main.wat": digest(core)})),
        ],
    );
    let activation = fx.activate_body(&body).unwrap();
    assert_eq!(activation.entry_bytes(), core);
    assert_eq!(activation.artifact_format(), ArtifactFormat::WasmCoreV1);
}

#[test]
fn size_limits_and_missing_entry_fail() {
    let mut fx = Fixture::new();
    assert!(fx.activate_raw(&vec![b' '; MAX_ENVELOPE + 1]).is_err());
    let body = with(&fx.body, &[("entry", json!("unsigned.wat"))]);
    assert!(fx.activate_body(&body).is_err());
    let mut large = PROGRAM.to_vec();
    large.extend(std::iter::repeat_n(b' ', MAX_ARTIFACT));
    fx.write("main.wat", &large);
    let body = with(&fx.body, &[("files", json!({"main.wat": digest(&large)}))]);
    assert!(fx.activate_body(&body).is_err());
}

#[test]
fn grant_constructor_validates_identifiers_keys_and_generation() {
    let key = generate_key();
    let make = |xite: &str, publisher: &str, public_key: [u8; 32]| {
        XiteGrant::new(
            xite,
            publisher,
            public_key,
            BTreeSet::new(),
            BTreeSet::new(),
        )
    };
    assert!(make("game-one", "publisher-one", public(&key)).is_ok());
    assert!(make("-bad", "publisher-one", public(&key)).is_err());
    assert!(make("game-one", "bad publisher", public(&key)).is_err());
    assert!(make("game-one", "publisher-one", invalid_public_key()).is_err());
    let grant = make("game-one", "publisher-one", public(&key)).unwrap();
    assert!(grant.clone().with_generation(0).is_err());
    assert!(grant.clone().with_generation(u64::MAX).is_err());
    assert_eq!(grant.with_generation(7).unwrap().generation, 7);
}

// Two-phase admission: the deliberate change from the reference design.

#[test]
fn verify_without_admit_leaves_checkpoint_unchanged() {
    let mut fx = Fixture::new();
    let v2 = with(&fx.body, &[("version", json!(2))]);
    let envelope = fx.signed(&v2);
    let pending = fx.loader.verify(&envelope, fx.root()).unwrap();
    assert_eq!(pending.version(), 2);
    assert_eq!(pending.xite(), "game-one");
    assert_eq!(pending.publisher(), "publisher-one");
    assert_eq!(pending.runtime_profile(), "fixture.wasm.v1");
    assert_eq!(
        pending.capabilities(),
        &BTreeSet::from([Capability::GameScoreGet])
    );
    assert_eq!(
        pending.manifest_digest(),
        digest(&canonical_bytes(&v2).unwrap())
    );
    assert_eq!(pending.artifact_format(), ArtifactFormat::Wat);
    assert_eq!(pending.grant_generation(), 1);
    assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());
    drop(pending);
    assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());

    // Nothing moved the floor, so version 1 is still admissible.
    assert_eq!(fx.activate().unwrap().version(), 1);
    assert_eq!(fx.loader.checkpoint().version, 1);

    // After an admission, verify of a lower version is refused.
    let v3 = with(&fx.body, &[("version", json!(3))]);
    let envelope = fx.signed(&v3);
    let pending = fx.loader.verify(&envelope, fx.root()).unwrap();
    fx.loader.admit(pending).unwrap();
    assert_eq!(fx.loader.checkpoint().version, 3);
    let envelope = fx.signed(&fx.body);
    assert!(fx.loader.verify(&envelope, fx.root()).is_err());
    let envelope = fx.signed(&v2);
    assert!(fx.loader.verify(&envelope, fx.root()).is_err());
    assert_eq!(fx.loader.checkpoint().version, 3);
}

#[test]
fn admit_rechecks_checkpoint_moved_by_a_concurrent_admit() {
    let mut fx = Fixture::new();
    let v2 = with(&fx.body, &[("version", json!(2))]);
    let v2_alt = with(&v2, &[("capabilities", json!(["workspace.read"]))]);
    // Three verifications from the same floor.
    let pending_v2 = fx.loader.verify(&fx.signed(&v2), fx.root()).unwrap();
    let pending_v1 = fx.loader.verify(&fx.signed(&fx.body), fx.root()).unwrap();
    let pending_v2_alt = fx.loader.verify(&fx.signed(&v2_alt), fx.root()).unwrap();
    fx.loader.admit(pending_v2).unwrap();
    assert_eq!(fx.loader.checkpoint().version, 2);
    // A lower version verified earlier is refused at admission.
    assert!(fx.loader.admit(pending_v1).is_err());
    // A different manifest at the same version is refused at admission.
    assert!(fx.loader.admit(pending_v2_alt).is_err());
    assert_eq!(fx.loader.checkpoint().version, 2);
    assert_eq!(
        fx.loader.checkpoint().manifest_digest.as_deref(),
        Some(digest(&canonical_bytes(&v2).unwrap()).as_str())
    );
    // Re-admitting the identical manifest is idempotent.
    let again = fx.loader.verify(&fx.signed(&v2), fx.root()).unwrap();
    assert_eq!(fx.loader.admit(again).unwrap().version(), 2);
}

#[test]
fn denied_binding_between_verify_and_admit_keeps_previous_version_runnable() {
    let mut fx = Fixture::new();
    fx.activate().unwrap();
    // The host's current grant covers fewer capabilities than the loader's.
    let mut host_grant = Grant::new("game-one", true).unwrap();
    host_grant.publisher = Some("publisher-one".to_string());
    host_grant.publisher_public_key = Some(fx.grant.public_key);
    host_grant.capabilities = BTreeSet::from([Capability::GameScoreGet]);
    host_grant.runtime_profiles = BTreeSet::from(["fixture.wasm.v1".to_string()]);

    let update = with(
        &fx.body,
        &[
            ("version", json!(2)),
            ("capabilities", json!(["workspace.read"])),
        ],
    );
    let pending = fx.loader.verify(&fx.signed(&update), fx.root()).unwrap();
    let context = pending.context(host_grant.generation, fx.grant.public_key);
    assert!(!context.matches(&host_grant), "binding check must deny");
    drop(pending);
    // The refused update did not raise the floor: version 1 still runs.
    assert_eq!(fx.loader.checkpoint().version, 1);
    assert_eq!(fx.activate().unwrap().version(), 1);

    // A declaration within the current grant is admitted normally.
    let covered = with(&fx.body, &[("version", json!(2))]);
    let pending = fx.loader.verify(&fx.signed(&covered), fx.root()).unwrap();
    assert!(pending
        .context(host_grant.generation, fx.grant.public_key)
        .matches(&host_grant));
    assert_eq!(fx.loader.admit(pending).unwrap().version(), 2);
    assert_eq!(fx.loader.checkpoint().version, 2);
}

#[test]
fn admit_refuses_pending_verified_under_another_grant() {
    let mut fx = Fixture::new();
    let other = ActivationLoader::new(fx.grant.clone().with_generation(2).unwrap());
    let pending = other.verify(&fx.signed(&fx.body), fx.root()).unwrap();
    assert!(fx.loader.admit(pending).is_err());
    assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());
    let disabled = ActivationLoader::new(fx.grant.clone().with_enabled(false));
    let pending = fx.loader.verify(&fx.signed(&fx.body), fx.root()).unwrap();
    let mut disabled = disabled;
    assert!(disabled.admit(pending).is_err());
}
