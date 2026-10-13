//! Binding to the manifest: only required, well-formed, bounded entries pin.

use std::collections::{BTreeMap, BTreeSet};

use evx_activation::{MAX_ARTIFACT, MAX_FILES, MAX_TOTAL};
use evx_api::Limits;
use serde_json::{json, Value};

use super::{content, evx, file_entry, parse_evx, set, sha512_prefix, without, ENTRY, LIB, SCORE};
use crate::{bind, BoundProgram, Declaration, DeclarationError, PinnedFile, Program};

fn manifest_error(decl: &Declaration, program: &str, content: &Value) -> String {
    match bind(decl, program, content) {
        Err(DeclarationError::Manifest(reason)) => reason,
        other => panic!("expected a manifest error, got {other:?}"),
    }
}

/// Manifest paths contain `/`, so they are set by key rather than by pointer.
fn with_file(mut root: Value, path: &str, entry: Value) -> Value {
    root["files"][path] = entry;
    root
}

#[test]
fn bind_pins_entry_and_dependencies_to_the_signed_files_map() {
    let root = content(evx());
    let decl = parse_evx(evx()).unwrap();
    let bound = bind(&decl, "presence", &root).unwrap();
    assert_eq!(
        bound,
        BoundProgram {
            program: "presence".to_string(),
            entry: PinnedFile {
                path: "evx/presence.wasm".to_string(),
                size: ENTRY.len() as u64,
                sha512: sha512_prefix(ENTRY),
            },
            dependencies: vec![PinnedFile {
                path: "evx/lib.wasm".to_string(),
                size: LIB.len() as u64,
                sha512: sha512_prefix(LIB),
            }],
            total_bytes: (ENTRY.len() + LIB.len()) as u64,
        }
    );
    let bound = bind(&decl, "score", &root).unwrap();
    assert!(bound.dependencies.is_empty());
    assert_eq!(bound.total_bytes, SCORE.len() as u64);
    assert_eq!(bound.entry.sha512, sha512_prefix(SCORE));
}

#[test]
fn bind_refuses_programs_that_are_undeclared_or_unsupported() {
    let root = content(evx());
    let decl = parse_evx(evx()).unwrap();
    assert_eq!(
        bind(&decl, "ghost", &root),
        Err(DeclarationError::UnknownProgram("ghost".to_string()))
    );
    let decl = parse_evx(set(
        evx(),
        "/programs/score/runtime_profile",
        json!("wasm-gc-v1"),
    ))
    .unwrap();
    assert_eq!(
        bind(&decl, "score", &root),
        Err(DeclarationError::UnknownProgram("score".to_string()))
    );
    assert!(bind(&decl, "presence", &root).is_ok());
}

#[test]
fn bind_refuses_files_declared_only_as_optional() {
    let mut root = content(evx());
    let lib = root["files"]
        .as_object_mut()
        .unwrap()
        .remove("evx/lib.wasm")
        .unwrap();
    root["files_optional"] = json!({ "evx/lib.wasm": lib });
    let decl = parse_evx(evx()).unwrap();
    assert_eq!(
        manifest_error(&decl, "presence", &root),
        "evx/lib.wasm: declared in files_optional; only required files can be bound"
    );
    assert!(
        bind(&decl, "score", &root).is_ok(),
        "the other program is unaffected"
    );
}

#[test]
fn bind_refuses_a_missing_file_or_files_map() {
    let decl = parse_evx(evx()).unwrap();
    let mut root = content(evx());
    root["files"]
        .as_object_mut()
        .unwrap()
        .remove("evx/presence.wasm")
        .unwrap();
    assert_eq!(
        manifest_error(&decl, "presence", &root),
        "evx/presence.wasm: not in the signed files map"
    );
    let root = without(content(evx()), "/files");
    assert_eq!(
        manifest_error(&decl, "presence", &root),
        "content.json has no files object"
    );
    let root = set(content(evx()), "/files", json!([]));
    assert_eq!(
        manifest_error(&decl, "presence", &root),
        "content.json has no files object"
    );
}

#[test]
fn bind_requires_an_exact_path_match() {
    let decl = parse_evx(evx()).unwrap();
    let mut root = content(evx());
    let entry = root["files"]
        .as_object_mut()
        .unwrap()
        .remove("evx/presence.wasm")
        .unwrap();
    root["files"]["evx/Presence.wasm"] = entry.clone();
    root["files"]["./evx/presence.wasm"] = entry;
    assert_eq!(
        manifest_error(&decl, "presence", &root),
        "evx/presence.wasm: not in the signed files map"
    );
}

#[test]
fn bind_refuses_malformed_size_and_digest_fields() {
    let decl = parse_evx(evx()).unwrap();
    let digest = sha512_prefix(SCORE);
    for (name, entry, expected) in [
        (
            "string size",
            json!({ "size": "12", "sha512": digest }),
            "size must be a non-negative integer",
        ),
        (
            "negative size",
            json!({ "size": -1, "sha512": digest }),
            "size must be a non-negative integer",
        ),
        (
            "float size",
            json!({ "size": 12.0, "sha512": digest }),
            "size must be a non-negative integer",
        ),
        (
            "missing size",
            json!({ "sha512": digest }),
            "size must be a non-negative integer",
        ),
        (
            "missing digest",
            json!({ "size": 12 }),
            "sha512 must be 64 lowercase hexadecimal characters",
        ),
        (
            "short digest",
            json!({ "size": 12, "sha512": "abc" }),
            "sha512 must be 64 lowercase",
        ),
        (
            "uppercase digest",
            json!({ "size": 12, "sha512": digest.to_uppercase() }),
            "sha512 must be 64 lowercase",
        ),
        (
            "non-hex digest",
            json!({ "size": 12, "sha512": "z".repeat(64) }),
            "sha512 must be 64 lowercase",
        ),
        (
            "full sha512",
            json!({ "size": 12, "sha512": "a".repeat(128) }),
            "sha512 must be 64 lowercase",
        ),
        (
            "entry not object",
            json!("abc"),
            "manifest entry is not an object",
        ),
    ] {
        let root = with_file(content(evx()), "evx/score.wasm", entry);
        let reason = manifest_error(&decl, "score", &root);
        assert!(reason.starts_with("evx/score.wasm: "), "{name}: {reason}");
        assert!(reason.contains(expected), "{name}: {reason}");
    }
}

#[test]
fn bind_refuses_artifacts_over_max_artifact() {
    let decl = parse_evx(evx()).unwrap();
    let too_big = json!({ "size": MAX_ARTIFACT + 1, "sha512": sha512_prefix(SCORE) });
    let root = with_file(content(evx()), "evx/score.wasm", too_big);
    assert_eq!(
        manifest_error(&decl, "score", &root),
        format!(
            "evx/score.wasm: size {} exceeds {MAX_ARTIFACT} bytes",
            MAX_ARTIFACT + 1
        )
    );
    let at_limit = json!({ "size": MAX_ARTIFACT, "sha512": sha512_prefix(SCORE) });
    let root = with_file(content(evx()), "evx/score.wasm", at_limit);
    assert_eq!(
        bind(&decl, "score", &root).unwrap().total_bytes,
        MAX_ARTIFACT as u64
    );
}

#[test]
fn bind_refuses_closures_over_max_total() {
    let per_file = MAX_ARTIFACT;
    let count = MAX_TOTAL / per_file + 1; // enough full-size files to cross the aggregate limit
    assert!(
        count <= MAX_FILES,
        "fixture must stay inside the file-count limit"
    );
    let deps: Vec<String> = (1..count).map(|i| format!("evx/dep{i}.wasm")).collect();
    let section = set(evx(), "/programs/presence/dependencies", json!(deps));
    let mut root = content(section.clone());
    for path in std::iter::once("evx/presence.wasm").chain(deps.iter().map(String::as_str)) {
        root["files"][path] = json!({ "size": per_file, "sha512": sha512_prefix(path.as_bytes()) });
    }
    let decl = parse_evx(section).unwrap();
    assert_eq!(
        manifest_error(&decl, "presence", &root),
        format!("closure of {} bytes exceeds {MAX_TOTAL}", count * per_file)
    );
    // Exactly the aggregate limit binds.
    root["files"]["evx/presence.wasm"]["size"] = json!(per_file - (count * per_file - MAX_TOTAL));
    assert_eq!(
        bind(&decl, "presence", &root).unwrap().total_bytes,
        MAX_TOTAL as u64
    );
}

/// A program constructed by hand, bypassing the parser: `bind` re-checks the
/// rules the parser enforces because `Declaration`'s fields are public.
fn hand_built(entry: &str, dependencies: &[&str]) -> Declaration {
    let program = Program {
        runtime_profile: "wasm-core-v1".to_string(),
        entry: entry.to_string(),
        dependencies: dependencies.iter().map(ToString::to_string).collect(),
        allow_run_once: false,
        capabilities: BTreeSet::new(),
        limits: Limits::default(),
    };
    Declaration {
        version: 1,
        programs: BTreeMap::from([("hand".to_string(), program)]),
        jobs: BTreeMap::new(),
        unsupported: Vec::new(),
    }
}

#[test]
fn bind_refuses_hand_built_duplicates_and_self_dependencies() {
    let root = content(evx());
    let decl = hand_built("evx/presence.wasm", &["evx/lib.wasm", "evx/lib.wasm"]);
    assert_eq!(
        manifest_error(&decl, "hand", &root),
        "evx/lib.wasm: listed twice in the closure"
    );
    let decl = hand_built("evx/presence.wasm", &["evx/presence.wasm"]);
    assert_eq!(
        manifest_error(&decl, "hand", &root),
        "evx/presence.wasm: listed twice in the closure"
    );
}

#[test]
fn bind_refuses_hand_built_path_escapes_and_oversized_closures() {
    let mut root = content(evx());
    root["files"]["../outside.wasm"] = file_entry(LIB);
    let decl = hand_built("../outside.wasm", &[]);
    assert_eq!(
        manifest_error(&decl, "hand", &root),
        "../outside.wasm: path outside workspace"
    );
    let decl = hand_built("evx/presence.wasm", &["evx/lib.wasm", "evx\\lib.wasm"]);
    assert_eq!(
        manifest_error(&decl, "hand", &root),
        "evx\\lib.wasm: path outside workspace"
    );
    let deps: Vec<String> = (0..MAX_FILES).map(|i| format!("evx/dep{i}.wasm")).collect();
    let refs: Vec<&str> = deps.iter().map(String::as_str).collect();
    let decl = hand_built("evx/presence.wasm", &refs);
    assert_eq!(
        manifest_error(&decl, "hand", &root),
        format!("closure of {} files exceeds {MAX_FILES}", MAX_FILES + 1)
    );
}

#[test]
fn bound_program_serialises_for_the_inspect_payload() {
    let decl = parse_evx(evx()).unwrap();
    let bound = bind(&decl, "presence", &content(evx())).unwrap();
    let json = serde_json::to_value(&bound).unwrap();
    assert_eq!(json["entry"]["path"], "evx/presence.wasm");
    assert_eq!(json["entry"]["size"], ENTRY.len());
    assert_eq!(json["dependencies"][0]["sha512"], sha512_prefix(LIB));
    let back: BoundProgram = serde_json::from_value(json).unwrap();
    assert_eq!(back, bound);
}
