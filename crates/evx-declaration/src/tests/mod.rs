//! Shared fixtures. The baseline declaration is the plan's illustrative
//! fragment brought onto the closed capability set; every test mutates it
//! through JSON pointers so the thing under test is the one change.

use serde_json::{json, Value};
use sha2::{Digest as _, Sha512};

use crate::{parse, Declaration, DeclarationError};

mod bind;
mod digest;
mod parser;
mod signed;
mod summary;

pub(crate) const ENTRY: &[u8] = b"\0asm\x01\0\0\0presence";
pub(crate) const LIB: &[u8] = b"\0asm\x01\0\0\0lib";
pub(crate) const SCORE: &[u8] = b"\0asm\x01\0\0\0score";

/// A usable two-program, one-job declaration.
pub(crate) fn evx() -> Value {
    json!({
        "version": 1,
        "programs": {
            "presence": {
                "runtime_profile": "wasm-core-v1",
                "entry": "evx/presence.wasm",
                "dependencies": ["evx/lib.wasm"],
                "allow_run_once": true,
                "capabilities": [{ "api": "workspace.read" }, { "api": "workspace.write" }],
                "limits": { "memory_bytes": 2_097_152, "fuel": 500_000 }
            },
            "score": {
                "runtime_profile": "wasm-core-v1",
                "entry": "evx/score.wasm",
                "capabilities": [{ "api": "game.score.get" }]
            }
        },
        "jobs": {
            "presence-every-30m": {
                "program": "presence",
                "schedule": { "type": "interval", "seconds": 1800, "anchor": "unix_epoch", "missed": "skip" },
                "max_concurrency": 1
            }
        }
    })
}

/// The truncated SHA-512 EpixNet manifests carry (`XiteStorage::hash_bytes`).
pub(crate) fn sha512_prefix(data: &[u8]) -> String {
    hex::encode(&Sha512::digest(data)[..32])
}

pub(crate) fn file_entry(data: &[u8]) -> Value {
    json!({ "size": data.len(), "sha512": sha512_prefix(data) })
}

/// An unsigned root content.json carrying `evx` and a manifest for the
/// baseline's three files.
pub(crate) fn content(evx: Value) -> Value {
    json!({
        "address": "epix1test",
        "title": "Presence",
        "modified": 1_700_000_000_000_i64,
        "files": {
            "index.html": file_entry(b"<html></html>"),
            "evx/presence.wasm": file_entry(ENTRY),
            "evx/lib.wasm": file_entry(LIB),
            "evx/score.wasm": file_entry(SCORE)
        },
        "evx": evx
    })
}

pub(crate) fn parse_evx(evx: Value) -> Result<Declaration, DeclarationError> {
    parse(&content(evx))
}

/// Parse and return the `Malformed` message, failing on any other outcome.
#[track_caller]
pub(crate) fn malformed(evx: Value) -> String {
    match parse_evx(evx) {
        Err(DeclarationError::Malformed(reason)) => reason,
        other => panic!("expected a malformed section, got {other:?}"),
    }
}

/// `(path, reason)` pairs from `unsupported`.
pub(crate) fn reasons(decl: &Declaration) -> Vec<(String, String)> {
    decl.unsupported
        .iter()
        .map(|item| (item.path.clone(), item.reason.clone()))
        .collect()
}

/// Set the value at a JSON pointer whose parent exists, creating the leaf.
pub(crate) fn set(mut root: Value, pointer: &str, value: Value) -> Value {
    let (parent, key) = pointer.rsplit_once('/').expect("pointer has a parent");
    match root.pointer_mut(parent).expect("pointer parent exists") {
        Value::Object(map) => {
            map.insert(key.to_string(), value);
        }
        Value::Array(items) => {
            let index: usize = key.parse().expect("array index");
            if index == items.len() {
                items.push(value);
            } else {
                items[index] = value;
            }
        }
        _ => panic!("pointer parent is not a container"),
    }
    root
}

/// Remove the key at a JSON pointer.
pub(crate) fn without(mut root: Value, pointer: &str) -> Value {
    let (parent, key) = pointer.rsplit_once('/').expect("pointer has a parent");
    match root.pointer_mut(parent).expect("pointer parent exists") {
        Value::Object(map) => {
            map.remove(key);
        }
        _ => panic!("pointer parent is not an object"),
    }
    root
}
