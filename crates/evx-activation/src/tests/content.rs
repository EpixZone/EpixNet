//! The content path: a root content.json signed with a real owner key the
//! way the node writes it, a program bound to its manifest, and an
//! in-memory file store standing in for `XiteStorage`. Every denial asserts
//! the checkpoint afterwards, because "a denied activation never advances
//! the floor" is the property the two-phase split exists for.

use std::collections::{BTreeMap, BTreeSet};

use evx_api::{strict, Capability};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

#[cfg(not(unix))]
use super::FixtureFileVerify;
use super::{generate_key, public, with};
use crate::{
    digest, sha512_prefix, ActivationCheckpoint, ActivationLoader, ArtifactFormat,
    AuthenticationError, BoundProgram, FrozenActivation, PendingActivation, PinnedFile,
    PublisherAuthority, XiteGrant, MAX_ARTIFACT, MAX_FILES, MAX_TOTAL,
};

const ENTRY: &[u8] = b"\0asm\x01\0\0\0main";
const LIB: &[u8] = b"\0asm\x01\0\0\0lib";
const ENTRY_PATH: &str = "evx/main.wasm";
const LIB_PATH: &str = "evx/lib.wasm";
const PROGRAM_ID: &str = "main";
const PROFILE: &str = "wasm-core-v1";
/// `modified` of the baseline, in Unix seconds with a fractional part, as
/// EpixNet writes it.
const MODIFIED: f64 = 1_700_000_000.5;
const MODIFIED_MILLIS: u64 = 1_700_000_000_500;

fn file_entry(data: &[u8]) -> Value {
    json!({ "size": data.len(), "sha512": sha512_prefix(data) })
}

/// Split a JSON pointer into its parent pointer and unescaped last key.
fn parent_and_key(pointer: &str) -> (&str, String) {
    let (parent, key) = pointer.rsplit_once('/').expect("pointer has a parent");
    (parent, key.replace("~1", "/").replace("~0", "~"))
}

/// The JSON pointer of a manifest entry; file paths contain `/`.
fn file_pointer(path: &str) -> String {
    format!("/files/{}", path.replace('~', "~0").replace('/', "~1"))
}

/// Set the value at a JSON pointer whose parent exists, creating the leaf.
fn set(mut root: Value, pointer: &str, value: Value) -> Value {
    let (parent, key) = parent_and_key(pointer);
    match root.pointer_mut(parent).expect("pointer parent exists") {
        Value::Object(map) => {
            map.insert(key, value);
        }
        other => panic!("pointer parent is not an object: {other}"),
    }
    root
}

/// Remove the key at a JSON pointer.
fn without(root: &Value, pointer: &str) -> Value {
    let mut root = root.clone();
    let (parent, key) = parent_and_key(pointer);
    root.pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .expect("pointer parent is an object")
        .remove(&key);
    root
}

/// What `evx_declaration::declaration_digest` computes for the section.
fn expected_declaration_digest(content: &Value) -> String {
    let raw = serde_json::to_vec(&content["evx"]).unwrap();
    let value = strict::parse(&raw).unwrap();
    hex::encode(Sha256::digest(strict::to_json(&value).as_bytes()))
}

/// A manual `evx_declaration::bind`: pin the program's entry and
/// dependencies to `content["files"]`.
fn bind(content: &Value, program: &str) -> BoundProgram {
    let declared = &content["evx"]["programs"][program];
    let pin = |path: &str| PinnedFile {
        path: path.to_string(),
        size: content["files"][path]["size"].as_u64().unwrap(),
        sha512: content["files"][path]["sha512"]
            .as_str()
            .unwrap()
            .to_string(),
    };
    let entry = pin(declared["entry"].as_str().unwrap());
    let dependencies: Vec<PinnedFile> = declared["dependencies"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|item| pin(item.as_str().unwrap()))
                .collect()
        })
        .unwrap_or_default();
    let total_bytes = entry.size + dependencies.iter().map(|pin| pin.size).sum::<u64>();
    BoundProgram {
        program: program.to_string(),
        entry,
        dependencies,
        total_bytes,
    }
}

struct Fixture {
    key: String,
    address: String,
    grant: XiteGrant,
    loader: ActivationLoader,
    /// The unsigned baseline; `signed` produces the on-disk form.
    content: Value,
    files: BTreeMap<String, Vec<u8>>,
}

impl Fixture {
    fn new() -> Fixture {
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let grant = XiteGrant::for_root_address(
            address.clone(),
            address.clone(),
            [Capability::GameScoreGet, Capability::WorkspaceRead]
                .into_iter()
                .collect(),
            [PROFILE.to_string()].into_iter().collect(),
        )
        .unwrap();
        let loader = ActivationLoader::new(grant.clone());
        let index = b"<html>main</html>";
        let content = json!({
            "address": address,
            "title": "Main",
            "modified": MODIFIED,
            "files": {
                "index.html": file_entry(index),
                ENTRY_PATH: file_entry(ENTRY),
                LIB_PATH: file_entry(LIB),
            },
            "evx": {
                "version": 1,
                "programs": {
                    PROGRAM_ID: {
                        "runtime_profile": PROFILE,
                        "entry": ENTRY_PATH,
                        "dependencies": [LIB_PATH],
                        "capabilities": [{ "api": "game.score.get" }],
                    }
                }
            }
        });
        let files = [
            ("index.html", index.to_vec()),
            (ENTRY_PATH, ENTRY.to_vec()),
            (LIB_PATH, LIB.to_vec()),
        ]
        .into_iter()
        .map(|(path, data)| (path.to_string(), data))
        .collect();
        Fixture {
            key,
            address,
            grant,
            loader,
            content,
            files,
        }
    }

    /// Sign `content` with the owner key and round-trip it through the
    /// serialised form the node stores, so the value under test is the one
    /// `serde_json` yields from the bytes on disk.
    fn signed(&self, content: &Value) -> Value {
        let mut signed = content.clone();
        epix_content::sign(&mut signed, &self.key).unwrap();
        assert!(epix_content::verify_signer(&signed, &self.address));
        serde_json::from_str(&epix_content::dumps_content(&signed)).unwrap()
    }

    fn store(&mut self, path: &str, data: &[u8]) {
        self.files.insert(path.to_string(), data.to_vec());
    }

    fn verify_bound(
        &self,
        signed: &Value,
        bound: &BoundProgram,
    ) -> Result<PendingActivation, AuthenticationError> {
        let files = &self.files;
        let mut read = |path: &str| {
            files
                .get(path)
                .cloned()
                .ok_or_else(|| AuthenticationError::new("file unavailable"))
        };
        self.loader.verify_content(signed, bound, &mut read)
    }

    fn verify(&self, content: &Value) -> Result<PendingActivation, AuthenticationError> {
        let signed = self.signed(content);
        self.verify_bound(&signed, &bind(&signed, PROGRAM_ID))
    }

    fn activate(&mut self, content: &Value) -> Result<FrozenActivation, AuthenticationError> {
        let pending = self.verify(content)?;
        self.loader.admit(pending)
    }

    fn activate_bound(
        &mut self,
        content: &Value,
        bound: &BoundProgram,
    ) -> Result<FrozenActivation, AuthenticationError> {
        let signed = self.signed(content);
        let pending = self.verify_bound(&signed, bound)?;
        self.loader.admit(pending)
    }

    /// Admit the baseline so later denials have a floor to leave alone.
    fn admitted_baseline(&mut self) -> ActivationCheckpoint {
        self.activate(&self.content.clone()).unwrap();
        let checkpoint = self.loader.checkpoint().clone();
        assert_eq!(checkpoint.version, MODIFIED_MILLIS);
        checkpoint
    }

    #[track_caller]
    fn assert_denied(&mut self, content: &Value, floor: &ActivationCheckpoint) {
        let outcome = self.activate(content);
        assert!(outcome.is_err(), "admitted {content}");
        assert_eq!(self.loader.checkpoint(), floor, "denial moved the floor");
    }
}

#[test]
fn signed_content_activation_admits_with_the_bound_closure() {
    let mut fx = Fixture::new();
    let signed = fx.signed(&fx.content);
    let activation = fx.activate(&fx.content.clone()).unwrap();
    assert_eq!(activation.xite(), fx.address);
    assert_eq!(activation.publisher(), fx.address);
    assert_eq!(activation.grant_generation(), 1);
    assert_eq!(activation.version(), MODIFIED_MILLIS);
    assert_eq!(activation.runtime_profile(), PROFILE);
    assert_eq!(activation.artifact_format(), ArtifactFormat::WasmCoreV1);
    assert_eq!(
        activation.capabilities(),
        &BTreeSet::from([Capability::GameScoreGet])
    );
    let signed_data = epix_content::signed_data(&signed);
    assert_eq!(activation.manifest_bytes(), signed_data.as_bytes());
    assert_eq!(activation.manifest_digest(), digest(signed_data.as_bytes()));
    assert_eq!(
        activation.declaration_digest(),
        Some(expected_declaration_digest(&signed).as_str())
    );
    assert_eq!(activation.program(), Some(PROGRAM_ID));
    assert_eq!(activation.entry(), ENTRY_PATH);
    assert_eq!(activation.entry_bytes(), ENTRY);
    assert_eq!(activation.artifact_bytes(LIB_PATH).unwrap(), LIB);
    assert_eq!(
        activation.files().collect::<Vec<_>>(),
        [LIB_PATH, ENTRY_PATH]
    );
    assert!(activation.artifact_bytes("index.html").is_err());
    assert_eq!(
        fx.loader.checkpoint(),
        &ActivationCheckpoint::new(MODIFIED_MILLIS, Some(activation.manifest_digest().into()))
    );
    let context = activation.grant_context(fx.loader.grant());
    assert_eq!(context.xite, fx.address);
    assert_eq!(context.publisher, fx.address);
    assert_eq!(context.generation, 1);
    assert_eq!(context.public_key, None);
    assert_eq!(context.runtime_profile, PROFILE);
    assert_eq!(
        context.capabilities,
        BTreeSet::from([Capability::GameScoreGet])
    );
}

#[test]
fn verify_without_admit_leaves_the_floor_unchanged_for_content() {
    let fx = Fixture::new();
    let pending = fx.verify(&fx.content).unwrap();
    assert_eq!(pending.version(), MODIFIED_MILLIS);
    assert_eq!(pending.program(), Some(PROGRAM_ID));
    assert!(pending.declaration_digest().is_some());
    assert_eq!(pending.grant_context(fx.loader.grant()).public_key, None);
    assert_eq!(pending.entry_bytes(), ENTRY);
    assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());
    drop(pending);
    assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());
}

#[test]
fn the_signature_is_the_callers_contract_not_the_loaders_check() {
    // The node verifies `signs` before calling; the loader must neither
    // re-verify nor require the field, or a caller could mistake it for the
    // authority check. An unsigned document and one signed by a stranger
    // both pass this layer; the node would never hand either over.
    let fx = Fixture::new();
    let unsigned = fx.content.clone();
    let bound = bind(&unsigned, PROGRAM_ID);
    assert!(fx.verify_bound(&unsigned, &bound).is_ok());
    let stranger = epix_crypt::new_seed();
    let mut foreign = fx.content.clone();
    epix_content::sign(&mut foreign, &stranger).unwrap();
    assert!(!epix_content::verify_signer(&foreign, &fx.address));
    assert!(fx.verify_bound(&foreign, &bound).is_ok());
}

#[test]
fn modified_becomes_whole_milliseconds_for_integer_and_float_forms() {
    let fx = Fixture::new();
    for (modified, version) in [
        (json!(1_700_000_000_u64), 1_700_000_000_000_u64),
        (json!(1_700_000_000.123_f64), 1_700_000_000_123),
        (json!(1.0), 1_000),
        (json!(0.001), 1),
        (json!(1), 1_000),
    ] {
        let content = with(&fx.content, &[("modified", modified.clone())]);
        let pending = fx.verify(&content).unwrap();
        assert_eq!(pending.version(), version, "modified {modified}");
    }
}

#[test]
fn malformed_modified_values_are_rejected_without_touching_the_checkpoint() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let cases = [
        json!("1700000000"),
        Value::Null,
        json!(true),
        json!(-1),
        json!(-0.5),
        json!(0),
        json!(0.0),
        json!(0.0004),
        json!(1e300),
        json!(9_223_372_036_854_775.808_f64),
        json!(9_223_372_036_854_776_u64),
        json!(u64::MAX),
        json!(i64::MAX),
    ];
    for modified in cases {
        let content = with(&fx.content, &[("modified", modified.clone())]);
        let outcome = fx.activate(&content);
        assert_eq!(
            outcome.err().map(|e| e.message().to_string()),
            Some("invalid modified timestamp".into()),
            "modified {modified}"
        );
        assert_eq!(fx.loader.checkpoint(), &floor);
    }
    let missing = without(&fx.content, "/modified");
    fx.assert_denied(&missing, &floor);
}

#[test]
fn tampered_entry_bytes_are_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    fx.store(ENTRY_PATH, b"\0asm\x01\0\0\0evil");
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    fx.assert_denied(&update, &floor);
}

#[test]
fn tampered_dependency_bytes_are_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    fx.store(LIB_PATH, b"\0asm\x01\0\0\0lib2");
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    fx.assert_denied(&update, &floor);
}

#[test]
fn a_missing_dependency_is_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    fx.files.remove(LIB_PATH);
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    let outcome = fx.activate(&update);
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("file unavailable".into())
    );
    assert_eq!(fx.loader.checkpoint(), &floor);
}

#[test]
fn a_file_whose_size_differs_from_the_signed_manifest_is_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    // The owner signed one byte more than the store holds.
    let longer = set(
        update.clone(),
        &format!("{}/size", file_pointer(ENTRY_PATH)),
        json!(ENTRY.len() + 1),
    );
    fx.assert_denied(&longer, &floor);
    // The store holds one byte more than the owner signed; the digest also
    // differs, and the loader refuses before any format check.
    let mut padded = ENTRY.to_vec();
    padded.push(0);
    fx.store(ENTRY_PATH, &padded);
    fx.assert_denied(&update, &floor);
}

#[test]
fn a_bound_program_that_differs_from_the_signed_manifest_is_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let evil = b"\0asm\x01\0\0\0evil";
    fx.store(ENTRY_PATH, evil);
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    let honest = bind(&fx.signed(&update), PROGRAM_ID);
    // The first pin matches the stored bytes but not the signed manifest:
    // the signature covers `files`, not the BoundProgram.
    type Mutation = Box<dyn Fn(&mut BoundProgram)>;
    let mutations: Vec<(&str, Mutation)> = vec![
        ("digest", Box::new(|b| b.entry.sha512 = sha512_prefix(evil))),
        ("size", Box::new(|b| b.entry.size += 1)),
        ("total", Box::new(|b| b.total_bytes += 1)),
        ("program", Box::new(|b| b.program = "other".into())),
        ("entry path", Box::new(|b| b.entry.path = LIB_PATH.into())),
        ("dependencies", Box::new(|b| b.dependencies.clear())),
        (
            "dependency order",
            Box::new(|b| {
                let lib = b.dependencies[0].clone();
                b.dependencies = vec![lib.clone(), lib];
            }),
        ),
    ];
    for (name, mutate) in mutations {
        let mut bound = honest.clone();
        mutate(&mut bound);
        assert!(
            fx.activate_bound(&update, &bound).is_err(),
            "admitted mutated {name}"
        );
        assert_eq!(fx.loader.checkpoint(), &floor, "{name} moved the floor");
    }
    fx.store(ENTRY_PATH, ENTRY);
    assert_eq!(
        fx.activate_bound(&update, &honest).unwrap().entry_bytes(),
        ENTRY
    );
}

#[test]
fn rollback_to_a_lower_modified_is_denied_and_the_floor_stays() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let older = with(&fx.content, &[("modified", json!(MODIFIED - 1.0))]);
    let outcome = fx.activate(&older);
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("activation rollback or version conflict".into())
    );
    assert_eq!(fx.loader.checkpoint(), &floor);
    // One millisecond below is still a rollback.
    let older = with(&fx.content, &[("modified", json!(MODIFIED - 0.001))]);
    fx.assert_denied(&older, &floor);
}

#[test]
fn the_same_modified_with_a_different_manifest_is_a_conflict() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let retitled = with(&fx.content, &[("title", json!("Renamed"))]);
    fx.assert_denied(&retitled, &floor);
    // The identical publication is idempotent.
    assert_eq!(
        fx.activate(&fx.content.clone()).unwrap().version(),
        MODIFIED_MILLIS
    );
    assert_eq!(fx.loader.checkpoint(), &floor);
}

#[test]
fn restored_checkpoint_keeps_the_content_floor() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    fx.loader = ActivationLoader::with_checkpoint(fx.grant.clone(), floor.clone());
    let older = with(&fx.content, &[("modified", json!(MODIFIED - 1.0))]);
    fx.assert_denied(&older, &floor);
}

#[test]
fn a_runtime_profile_outside_the_grant_is_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let pointer = format!("/evx/programs/{PROGRAM_ID}/runtime_profile");
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    let future = set(update.clone(), &pointer, json!("wasm-core-v2"));
    let outcome = fx.activate(&future);
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("runtime profile outside grant".into())
    );
    assert_eq!(fx.loader.checkpoint(), &floor);
    for bad in [json!("not an identifier"), json!(1), Value::Null] {
        fx.assert_denied(&set(update.clone(), &pointer, bad), &floor);
    }
    fx.assert_denied(&without(&update, &pointer), &floor);
}

#[test]
fn a_capability_outside_the_grant_stays_denied_until_a_grant_carrying_it_is_used() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let pointer = format!("/evx/programs/{PROGRAM_ID}/capabilities");
    let wider = set(
        with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]),
        &pointer,
        json!([{ "api": "game.score.get" }, { "api": "workspace.write" }]),
    );
    let outcome = fx.activate(&wider);
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("capability declaration exceeds grant".into())
    );
    assert_eq!(fx.loader.checkpoint(), &floor);
    // Asking again changes nothing: the request cannot self-grant.
    fx.assert_denied(&wider, &floor);
    assert_eq!(fx.loader.grant(), &fx.grant);
    // A new grant carrying the capability, restored onto the same floor.
    let mut capabilities = fx.grant.capabilities.clone();
    capabilities.insert(Capability::WorkspaceWrite);
    let wider_grant = XiteGrant::for_root_address(
        fx.address.clone(),
        fx.address.clone(),
        capabilities,
        fx.grant.runtime_profiles.clone(),
    )
    .unwrap()
    .with_generation(2)
    .unwrap();
    fx.loader = ActivationLoader::with_checkpoint(wider_grant, floor);
    let activation = fx.activate(&wider).unwrap();
    assert_eq!(
        activation.capabilities(),
        &BTreeSet::from([Capability::GameScoreGet, Capability::WorkspaceWrite])
    );
    assert_eq!(activation.grant_generation(), 2);
    assert_eq!(fx.loader.checkpoint().version, MODIFIED_MILLIS + 1_000);
}

#[test]
fn a_capability_already_in_the_grant_can_be_used_by_an_update() {
    let mut fx = Fixture::new();
    fx.admitted_baseline();
    let update = set(
        with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]),
        &format!("/evx/programs/{PROGRAM_ID}/capabilities"),
        json!([{ "api": "workspace.read" }]),
    );
    assert_eq!(
        fx.activate(&update).unwrap().capabilities(),
        &BTreeSet::from([Capability::WorkspaceRead])
    );
}

#[test]
fn malformed_capability_declarations_are_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let pointer = format!("/evx/programs/{PROGRAM_ID}/capabilities");
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    let many: Vec<Value> = (0..65)
        .map(|_| json!({ "api": "game.score.get" }))
        .collect();
    let cases = [
        json!({ "api": "game.score.get" }),
        json!(["game.score.get"]),
        json!([{ "api": "chain.sign" }]),
        json!([{ "api": "game.score.get" }, { "api": "game.score.get" }]),
        json!([{ "api": "game.score.get", "scope": "all" }]),
        json!([{ "name": "game.score.get" }]),
        json!([{}]),
        json!([null]),
        Value::Null,
        Value::Array(many),
    ];
    for capabilities in cases {
        fx.assert_denied(&set(update.clone(), &pointer, capabilities), &floor);
    }
    fx.assert_denied(&without(&update, &pointer), &floor);
    // An empty request is well-formed and asks for nothing.
    let none = set(update, &pointer, json!([]));
    assert!(fx.activate(&none).unwrap().capabilities().is_empty());
}

#[test]
fn an_authenticated_update_inside_the_grant_admits_without_a_new_grant() {
    let mut fx = Fixture::new();
    let first = fx.activate(&fx.content.clone()).unwrap();
    let updated_entry = b"\0asm\x01\0\0\0main2";
    fx.store(ENTRY_PATH, updated_entry);
    let update = set(
        with(&fx.content, &[("modified", json!(MODIFIED + 60.0))]),
        &file_pointer(ENTRY_PATH),
        file_entry(updated_entry),
    );
    let second = fx.activate(&update).unwrap();
    assert_eq!(fx.loader.grant(), &fx.grant, "the grant was not touched");
    assert_eq!(first.entry_bytes(), ENTRY);
    assert_eq!(second.entry_bytes(), updated_entry);
    assert_eq!(first.grant_generation(), second.grant_generation());
    assert_eq!(second.version(), MODIFIED_MILLIS + 60_000);
    assert_eq!(fx.loader.checkpoint().version, MODIFIED_MILLIS + 60_000);
    assert_ne!(first.manifest_digest(), second.manifest_digest());
    assert_eq!(
        first.declaration_digest(),
        second.declaration_digest(),
        "the declaration did not change"
    );
}

#[test]
fn every_denial_leaves_the_checkpoint_unchanged() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    let program = format!("/evx/programs/{PROGRAM_ID}");
    let denials = [
        (
            "other xite",
            with(&update, &[("address", json!("epix1other"))]),
        ),
        ("no address", without(&update, "/address")),
        ("no files", without(&update, "/files")),
        ("no evx", without(&update, "/evx")),
        ("evx not an object", with(&update, &[("evx", json!([]))])),
        ("no programs", without(&update, "/evx/programs")),
        ("no program", without(&update, &program)),
        (
            "program not an object",
            set(update.clone(), &program, json!(1)),
        ),
        (
            "entry not in files",
            without(&update, &file_pointer(ENTRY_PATH)),
        ),
        (
            "dependency not in files",
            without(&update, &file_pointer(LIB_PATH)),
        ),
        (
            "foreign profile",
            set(
                update.clone(),
                &format!("{program}/runtime_profile"),
                json!("native"),
            ),
        ),
        (
            "foreign capability",
            set(
                update.clone(),
                &format!("{program}/capabilities"),
                json!([{ "api": "workspace.write" }]),
            ),
        ),
        ("rollback", with(&fx.content, &[("modified", json!(1.0))])),
    ];
    for (name, content) in denials {
        let bound = bind_or_baseline(&content);
        assert!(
            fx.activate_bound(&content, &bound).is_err(),
            "admitted {name}"
        );
        assert_eq!(fx.loader.checkpoint(), &floor, "{name} moved the floor");
    }
    assert_eq!(
        fx.activate(&update).unwrap().version(),
        MODIFIED_MILLIS + 1_000
    );
}

/// Bind from `content` when its manifest still allows it, otherwise the
/// baseline's honest pins, so a denial is attributable to the content and
/// not to a panic in the test's own binder.
fn bind_or_baseline(content: &Value) -> BoundProgram {
    let complete = [ENTRY_PATH, LIB_PATH]
        .iter()
        .all(|path| content["files"][path].is_object())
        && content["evx"]["programs"][PROGRAM_ID]["entry"].is_string();
    if complete {
        bind(content, PROGRAM_ID)
    } else {
        bind(&Fixture::new().content, PROGRAM_ID)
    }
}

#[test]
fn a_disabled_grant_denies_content() {
    let mut fx = Fixture::new();
    fx.loader = ActivationLoader::new(fx.grant.clone().with_enabled(false));
    let outcome = fx.activate(&fx.content.clone());
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("xite execution is not enabled".into())
    );
}

#[test]
fn each_grant_kind_admits_only_its_own_path() {
    let fx = Fixture::new();
    let key = generate_key();
    let ed25519 = XiteGrant::new(
        fx.address.clone(),
        "publisher-one",
        public(&key),
        fx.grant.capabilities.clone(),
        fx.grant.runtime_profiles.clone(),
    )
    .unwrap();
    let signed = fx.signed(&fx.content);
    let bound = bind(&signed, PROGRAM_ID);
    let files = fx.files.clone();
    let mut read = |path: &str| {
        files
            .get(path)
            .cloned()
            .ok_or_else(|| AuthenticationError::new("file unavailable"))
    };
    let outcome = ActivationLoader::new(ed25519).verify_content(&signed, &bound, &mut read);
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("content activation requires a root-address grant".into())
    );
    let envelope = crate::sign_envelope(
        &json!({
            "kind": "evx.activation.v1", "xite": fx.address, "publisher": fx.address,
            "version": 1, "runtime_profile": PROFILE, "entry": "main.wat",
            "artifact_format": "wat", "files": {"main.wat": digest(super::PROGRAM)},
            "capabilities": [],
        }),
        &key,
    );
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("main.wat"), super::PROGRAM).unwrap();
    let outcome = fx.loader.verify(&envelope, temp.path());
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("envelope activation requires an Ed25519 grant".into())
    );
}

#[test]
fn an_envelope_activation_carries_no_declaration() {
    let key = generate_key();
    let grant = XiteGrant::new(
        "game-one",
        "publisher-one",
        public(&key),
        BTreeSet::new(),
        [PROFILE.to_string()].into_iter().collect(),
    )
    .unwrap();
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("main.wat"), super::PROGRAM).unwrap();
    let envelope = crate::sign_envelope(
        &json!({
            "kind": "evx.activation.v1", "xite": "game-one", "publisher": "publisher-one",
            "version": 1, "runtime_profile": PROFILE, "entry": "main.wat",
            "artifact_format": "wat", "files": {"main.wat": digest(super::PROGRAM)},
            "capabilities": [],
        }),
        &key,
    );
    let mut loader = ActivationLoader::new(grant.clone());
    let pending = loader.verify(&envelope, temp.path()).unwrap();
    assert_eq!(pending.declaration_digest(), None);
    assert_eq!(pending.program(), None);
    assert_eq!(pending.grant_context(&grant).public_key, Some(public(&key)));
    let activation = loader.admit(pending).unwrap();
    assert_eq!(activation.declaration_digest(), None);
    assert_eq!(activation.program(), None);
}

#[test]
fn content_naming_another_xite_is_denied() {
    let mut fx = Fixture::new();
    let other = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    let foreign = with(&fx.content, &[("address", json!(other))]);
    let outcome = fx.activate(&foreign);
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("activation identity mismatch".into())
    );
    assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());
}

#[test]
fn content_whose_address_is_not_the_grants_root_address_is_denied() {
    let mut fx = Fixture::new();
    let other = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    // The grant names the document's address as its xite but vouches for a
    // different owner: the signature the node checked was `other`'s, so
    // nothing has verified this document, whatever its `address` says.
    let foreign_owner = XiteGrant::for_root_address(
        fx.address.clone(),
        other.clone(),
        fx.grant.capabilities.clone(),
        fx.grant.runtime_profiles.clone(),
    )
    .unwrap();
    // The same through the public field, which a host could set directly.
    let mut edited = fx.grant.clone();
    edited.authority = PublisherAuthority::RootAddress(other);
    for grant in [foreign_owner, edited] {
        fx.loader = ActivationLoader::new(grant);
        let outcome = fx.activate(&fx.content.clone());
        assert_eq!(
            outcome.err().map(|e| e.message().to_string()),
            Some("content address is not the grant's root address".into())
        );
        assert_eq!(fx.loader.checkpoint(), &ActivationCheckpoint::default());
    }
    // The grant as issued, naming the owner, admits the same document.
    fx.loader = ActivationLoader::new(fx.grant.clone());
    assert!(fx.activate(&fx.content.clone()).is_ok());
}

#[test]
fn a_bound_entry_that_is_not_the_declared_entry_is_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    // The owner declared `lib` as a dependency; a binder that swapped the
    // two would run the wrong module under the entry's name.
    let swapped = set(
        set(
            update.clone(),
            &format!("/evx/programs/{PROGRAM_ID}/entry"),
            json!(LIB_PATH),
        ),
        &format!("/evx/programs/{PROGRAM_ID}/dependencies"),
        json!([ENTRY_PATH]),
    );
    let bound = bind(&fx.signed(&update), PROGRAM_ID);
    let outcome = fx.activate_bound(&swapped, &bound);
    assert_eq!(
        outcome.err().map(|e| e.message().to_string()),
        Some("bound closure does not match signed declaration".into())
    );
    assert_eq!(fx.loader.checkpoint(), &floor);
    // A declaration without `dependencies` means none, so a bound program
    // carrying one is not the declared closure.
    let bare = without(&update, &format!("/evx/programs/{PROGRAM_ID}/dependencies"));
    assert!(fx.activate_bound(&bare, &bound).is_err());
    assert_eq!(fx.loader.checkpoint(), &floor);
}

#[test]
fn closure_bounds_are_enforced_before_any_file_is_read() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    let honest = bind(&fx.signed(&update), PROGRAM_ID);
    let fake = |path: &str, size: u64| PinnedFile {
        path: path.to_string(),
        size,
        sha512: sha512_prefix(path.as_bytes()),
    };
    let mut reads = 0usize;
    let mut counting = |_: &str| -> Result<Vec<u8>, AuthenticationError> {
        reads += 1;
        Err(AuthenticationError::new("file unavailable"))
    };

    // MAX_FILES + 1 pins.
    let mut too_many = honest.clone();
    too_many.dependencies = (0..MAX_FILES)
        .map(|i| fake(&format!("evx/d{i}.wasm"), 1))
        .collect();
    too_many.total_bytes = honest.entry.size + MAX_FILES as u64;
    // One pin beyond MAX_ARTIFACT.
    let mut too_large = honest.clone();
    too_large.entry.size = MAX_ARTIFACT as u64 + 1;
    too_large.total_bytes = too_large.entry.size + honest.dependencies[0].size;
    // Five pins of MAX_ARTIFACT bytes each, beyond MAX_TOTAL together.
    let mut too_much = honest.clone();
    too_much.entry.size = MAX_ARTIFACT as u64;
    too_much.dependencies = (0..4)
        .map(|i| fake(&format!("evx/d{i}.wasm"), MAX_ARTIFACT as u64))
        .collect();
    too_much.total_bytes = 5 * MAX_ARTIFACT as u64;
    assert!(too_much.total_bytes > MAX_TOTAL as u64);
    // A path escape, a duplicate, a malformed digest.
    let mut escape = honest.clone();
    escape.entry.path = "../main.wasm".into();
    let mut duplicate = honest.clone();
    duplicate.dependencies.push(honest.entry.clone());
    duplicate.total_bytes += honest.entry.size;
    let mut bad_digest = honest.clone();
    bad_digest.entry.sha512 = bad_digest.entry.sha512.to_uppercase();

    let signed = fx.signed(&update);
    for (name, bound) in [
        ("too many files", too_many),
        ("artifact too large", too_large),
        ("closure too large", too_much),
        ("path escape", escape),
        ("duplicate", duplicate),
        ("uppercase digest", bad_digest),
    ] {
        let outcome = fx.loader.verify_content(&signed, &bound, &mut counting);
        assert!(outcome.is_err(), "admitted {name}");
    }
    assert_eq!(reads, 0, "a refused closure was read");
    assert_eq!(fx.loader.checkpoint(), &floor);
}

#[test]
fn a_read_that_returns_other_bytes_than_the_manifest_pins_is_denied() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    let update = with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]);
    let signed = fx.signed(&update);
    let bound = bind(&signed, PROGRAM_ID);
    let mut failing = |_: &str| Err(AuthenticationError::new("storage offline"));
    assert_eq!(
        fx.loader
            .verify_content(&signed, &bound, &mut failing)
            .err()
            .map(|e| e.message().to_string()),
        Some("storage offline".into())
    );
    // More bytes than pinned, with the pinned bytes as a prefix.
    let mut padded = |path: &str| -> Result<Vec<u8>, AuthenticationError> {
        let mut data = fx.files[path].clone();
        data.extend_from_slice(&[0; 8]);
        Ok(data)
    };
    assert!(fx
        .loader
        .verify_content(&signed, &bound, &mut padded)
        .is_err());
    assert_eq!(fx.loader.checkpoint(), &floor);
}

#[test]
fn bytes_that_are_not_a_core_wasm_module_are_denied_even_when_signed() {
    let mut fx = Fixture::new();
    let floor = fx.admitted_baseline();
    for (name, bytes) in [
        ("wat", &b"(module)"[..]),
        ("cwasm", &b"\0cwasm\x01\0"[..]),
        ("wasm v2", &b"\0asm\x02\0\0\0"[..]),
        ("empty", &b""[..]),
    ] {
        fx.store(ENTRY_PATH, bytes);
        let update = set(
            with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]),
            &file_pointer(ENTRY_PATH),
            file_entry(bytes),
        );
        let outcome = fx.activate(&update);
        assert!(outcome.is_err(), "admitted {name}");
        assert_eq!(fx.loader.checkpoint(), &floor, "{name} moved the floor");
    }
    // A dependency is held to the same rule.
    fx.store(ENTRY_PATH, ENTRY);
    fx.store(LIB_PATH, b"(module)");
    let update = set(
        with(&fx.content, &[("modified", json!(MODIFIED + 1.0))]),
        &file_pointer(LIB_PATH),
        file_entry(b"(module)"),
    );
    fx.assert_denied(&update, &floor);
}

#[test]
fn captured_bytes_outlive_changes_to_the_store() {
    let mut fx = Fixture::new();
    let activation = fx.activate(&fx.content.clone()).unwrap();
    fx.store(ENTRY_PATH, b"\0asm\x01\0\0\0later");
    fx.files.remove(LIB_PATH);
    assert_eq!(activation.entry_bytes(), ENTRY);
    assert_eq!(activation.artifact_bytes(LIB_PATH).unwrap(), LIB);
}

#[test]
fn the_declaration_digest_follows_the_section_and_the_manifest_digest_the_document() {
    let mut fx = Fixture::new();
    let first = fx.activate(&fx.content.clone()).unwrap();
    let edited = with(
        &fx.content,
        &[
            ("modified", json!(MODIFIED + 1.0)),
            ("title", json!("Renamed")),
        ],
    );
    let second = fx.activate(&edited).unwrap();
    assert_eq!(first.declaration_digest(), second.declaration_digest());
    assert_ne!(first.manifest_digest(), second.manifest_digest());
    let redeclared = set(
        with(&fx.content, &[("modified", json!(MODIFIED + 2.0))]),
        &format!("/evx/programs/{PROGRAM_ID}/allow_run_once"),
        json!(true),
    );
    let third = fx.activate(&redeclared).unwrap();
    assert_ne!(third.declaration_digest(), first.declaration_digest());
    assert_eq!(
        third.declaration_digest(),
        Some(expected_declaration_digest(&redeclared).as_str())
    );
    // The digest form is the canonical compact object, so key order in the
    // document is irrelevant.
    let reordered: Value = serde_json::from_str(
        r#"{"programs":{"main":{"capabilities":[{"api":"game.score.get"}],"dependencies":["evx/lib.wasm"],"entry":"evx/main.wasm","runtime_profile":"wasm-core-v1"}},"version":1}"#,
    )
    .unwrap();
    let same = with(
        &fx.content,
        &[("modified", json!(MODIFIED + 3.0)), ("evx", reordered)],
    );
    assert_eq!(
        fx.activate(&same).unwrap().declaration_digest(),
        first.declaration_digest()
    );
}

#[test]
fn root_address_grant_constructor_validates_its_inputs() {
    let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
    let make = |xite: &str, publisher: &str| {
        XiteGrant::for_root_address(xite, publisher, BTreeSet::new(), BTreeSet::new())
    };
    let grant = make("game-one", &address).unwrap();
    assert_eq!(
        grant.authority,
        PublisherAuthority::RootAddress(address.clone())
    );
    assert_eq!(grant.publisher, address);
    assert_eq!(grant.public_key, [0; 32]);
    assert_eq!(grant.ed25519_public_key(), None);
    assert_eq!(grant.generation, 1);
    assert!(grant.enabled);
    assert!(make("-bad", &address).is_err());
    assert!(make("game-one", "publisher-one").is_err());
    assert!(make("game-one", "epix1notanaddress").is_err());
    assert!(make("game-one", "").is_err());
    let key = generate_key();
    let ed25519 = XiteGrant::new(
        "game-one",
        "publisher-one",
        public(&key),
        BTreeSet::new(),
        BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(ed25519.authority, PublisherAuthority::Ed25519(public(&key)));
    assert_eq!(ed25519.ed25519_public_key(), Some(public(&key)));
    assert_eq!(ed25519.public_key, public(&key));
}

#[test]
fn a_frozen_content_activation_carries_no_key_material() {
    let mut fx = Fixture::new();
    let activation = fx.activate(&fx.content.clone()).unwrap();
    let printed = format!("{activation:?}");
    assert!(!printed.contains(&fx.key));
    assert!(!printed.contains("signs"));
}
