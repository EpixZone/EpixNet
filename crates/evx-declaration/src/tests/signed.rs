//! Round trips on a content.json signed and serialised the way the node
//! does it (the shape `crates/epix-ui/tests/integration.rs` builds), so the
//! parser, binder and digest are proven against the real on-disk form.

use std::collections::BTreeMap;

use evx_activation::{ActivationLoader, AuthenticationError, XiteGrant};
use evx_api::Capability;
use serde_json::{json, Value};

use super::{evx, file_entry, parse_evx, set, sha512_prefix, ENTRY, LIB, SCORE};
use crate::{bind, declaration_digest, parse, parse_bytes};

/// A signed root content.json with the baseline declaration.
fn signed_root() -> (Value, String, String) {
    let key = epix_crypt::new_seed();
    let address = epix_crypt::privatekey_to_address(&key).unwrap();
    let index = b"<html>presence</html>";
    let mut root = json!({
        "address": address,
        "title": "Presence",
        "modified": 1_700_000_000.123_f64,
        "files": {
            "index.html": file_entry(index),
            "evx/presence.wasm": file_entry(ENTRY),
            "evx/lib.wasm": file_entry(LIB),
            "evx/score.wasm": file_entry(SCORE)
        },
        "files_optional": {
            "media/intro.webm": file_entry(b"webm")
        },
        "evx": evx()
    });
    epix_content::sign(&mut root, &key).unwrap();
    assert!(epix_content::verify_signer(&root, &address));
    (root, address, key)
}

#[test]
fn signed_content_json_parses_binds_and_digests() {
    let (root, _, _) = signed_root();
    let decl = parse(&root).unwrap();
    assert_eq!(
        decl,
        parse_evx(evx()).unwrap(),
        "the signature fields change nothing"
    );
    let bound = bind(&decl, "presence", &root).unwrap();
    assert_eq!(bound.entry.sha512, sha512_prefix(ENTRY));
    assert_eq!(bound.entry.size, ENTRY.len() as u64);
    assert_eq!(bound.dependencies[0].sha512, sha512_prefix(LIB));
    assert_eq!(bound.total_bytes, (ENTRY.len() + LIB.len()) as u64);
    assert_eq!(declaration_digest(&root).unwrap().len(), 64);
}

#[test]
fn the_on_disk_form_parses_identically_through_bytes_and_through_a_value() {
    let (root, address, _) = signed_root();
    let disk = epix_content::dumps_content(&root);
    let reread: Value = serde_json::from_str(&disk).unwrap();
    assert!(
        epix_content::verify_signer(&reread, &address),
        "disk form keeps the signature"
    );
    assert_eq!(
        parse_bytes(disk.as_bytes()).unwrap().unwrap(),
        parse(&root).unwrap()
    );
    assert_eq!(parse(&reread).unwrap(), parse(&root).unwrap());
    assert_eq!(
        declaration_digest(&reread).unwrap(),
        declaration_digest(&root).unwrap()
    );
    assert_eq!(
        bind(&parse(&reread).unwrap(), "presence", &reread),
        bind(&parse(&root).unwrap(), "presence", &root)
    );
}

#[test]
fn re_signing_without_changing_the_declaration_keeps_the_digest() {
    let (mut root, address, key) = signed_root();
    let before = declaration_digest(&root).unwrap();
    root["modified"] = json!(1_700_000_100.0_f64);
    root["files"]["index.html"] = file_entry(b"<html>presence v2</html>");
    epix_content::sign(&mut root, &key).unwrap();
    assert!(epix_content::verify_signer(&root, &address));
    assert_eq!(declaration_digest(&root).unwrap(), before);
}

#[test]
fn tampering_with_the_declaration_breaks_the_signature_and_changes_the_digest() {
    let (root, address, _) = signed_root();
    let before = declaration_digest(&root).unwrap();
    let tampered = set(
        root,
        "/evx/programs/score/capabilities/1",
        json!({ "api": "workspace.write" }),
    );
    assert!(!epix_content::verify_signer(&tampered, &address));
    assert_ne!(declaration_digest(&tampered).unwrap(), before);
    assert!(
        parse(&tampered).is_ok(),
        "the parser does not verify signatures; the caller does"
    );
}

#[test]
fn optional_files_in_a_signed_manifest_cannot_be_bound() {
    let (root, _, _) = signed_root();
    let section = set(
        evx(),
        "/programs/presence/dependencies",
        json!(["evx/lib.wasm", "media/intro.webm"]),
    );
    let root = set(root, "/evx", section);
    let decl = parse(&root).unwrap();
    let error = bind(&decl, "presence", &root).unwrap_err();
    assert_eq!(
        error.to_string(),
        "manifest binding failed: media/intro.webm: declared in files_optional; only required files can be bound"
    );
}

#[test]
fn a_bound_program_is_what_the_activation_loader_takes_without_conversion() {
    // What the node does after `verify_signer`: bind from the signed
    // document and hand the result straight to the loader. `bind` returns
    // `evx_activation::BoundProgram` itself, so no serde round trip or
    // field-by-field copy stands between the binder and the loader.
    let (root, address, _) = signed_root();
    let decl = parse(&root).unwrap();
    let bound = bind(&decl, "presence", &root).unwrap();
    let grant = XiteGrant::for_root_address(
        address.clone(),
        address.clone(),
        [Capability::WorkspaceRead, Capability::WorkspaceWrite]
            .into_iter()
            .collect(),
        ["wasm-core-v1".to_string()].into_iter().collect(),
    )
    .unwrap();
    let files: BTreeMap<&str, &[u8]> = [("evx/presence.wasm", ENTRY), ("evx/lib.wasm", LIB)]
        .into_iter()
        .collect();
    let mut read = |path: &str| {
        files
            .get(path)
            .map(|data| data.to_vec())
            .ok_or_else(|| AuthenticationError::new("file unavailable"))
    };
    let pending = ActivationLoader::new(grant)
        .verify_content(&root, &bound, &mut read)
        .unwrap();
    assert_eq!(pending.xite(), address);
    assert_eq!(pending.program(), Some("presence"));
    assert_eq!(pending.version(), 1_700_000_000_123);
    assert_eq!(
        pending.declaration_digest(),
        Some(declaration_digest(&root).unwrap().as_str())
    );
}
