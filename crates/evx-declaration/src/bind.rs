//! Pinning a program's closure to the signed manifest.
//!
//! The owner's content signature covers `files`, so `size` and `sha512` there
//! are the only authenticated statement of what the entry and dependencies
//! should contain. Binding copies those two values out; the activation loader
//! later reads the real bytes and compares. Nothing is read here.

use std::collections::BTreeSet;

use evx_activation::{MAX_ARTIFACT, MAX_FILES, MAX_TOTAL};
use evx_api::validate_relative_path;
use serde::{Deserialize, Serialize};

use crate::{Declaration, DeclarationError};

/// One program whose files are pinned to the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundProgram {
    /// The program id in the declaration.
    pub program: String,
    /// The module exporting `run`.
    pub entry: PinnedFile,
    /// Dependencies in declared order.
    pub dependencies: Vec<PinnedFile>,
    /// Sum of all pinned sizes, at most [`MAX_TOTAL`].
    pub total_bytes: u64,
}

/// A manifest entry: path plus the signed size and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedFile {
    /// Manifest-relative path, exactly as it appears in `files`.
    pub path: String,
    /// Signed size in bytes, at most [`MAX_ARTIFACT`].
    pub size: u64,
    /// Signed digest: 64 lowercase hex characters, the truncated SHA-512
    /// EpixNet manifests use.
    pub sha512: String,
}

/// Pin `program`'s entry and dependencies to `content["files"]`.
///
/// Refuses: a program that is not usable in `decl`; a manifest without a
/// `files` object; a path missing from `files` (being in `files_optional`
/// does not count: optional files are not guaranteed present and are not part
/// of what every node downloads); a `size` that is not a non-negative integer
/// or exceeds [`MAX_ARTIFACT`]; a `sha512` that is not 64 lowercase hex
/// characters; a closure of more than [`MAX_FILES`] files or more than
/// [`MAX_TOTAL`] bytes in all.
///
/// Duplicate paths, a dependency equal to the entry and path escapes are
/// refused again here although [`crate::parse`] already refuses them: the
/// fields of [`Declaration`] are public, so a bound program must not depend
/// on how the declaration was built.
pub fn bind(
    decl: &Declaration,
    program: &str,
    content: &serde_json::Value,
) -> Result<BoundProgram, DeclarationError> {
    let declared = decl
        .programs
        .get(program)
        .ok_or_else(|| DeclarationError::UnknownProgram(program.to_string()))?;
    let files = content
        .get("files")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| DeclarationError::manifest("content.json has no files object"))?;
    let optional = content
        .get("files_optional")
        .and_then(serde_json::Value::as_object);

    if declared.dependencies.len() + 1 > MAX_FILES {
        return Err(DeclarationError::manifest(format!(
            "closure of {} files exceeds {MAX_FILES}",
            declared.dependencies.len() + 1
        )));
    }

    let mut seen = BTreeSet::new();
    let mut pin = |path: &str| -> Result<PinnedFile, DeclarationError> {
        validate_relative_path(path)
            .map_err(|denied| DeclarationError::manifest(format!("{path}: {denied}")))?;
        if !seen.insert(path.to_string()) {
            return Err(DeclarationError::manifest(format!(
                "{path}: listed twice in the closure"
            )));
        }
        let Some(meta) = files.get(path) else {
            let reason = if optional.is_some_and(|optional| optional.contains_key(path)) {
                "declared in files_optional; only required files can be bound"
            } else {
                "not in the signed files map"
            };
            return Err(DeclarationError::manifest(format!("{path}: {reason}")));
        };
        let meta = meta.as_object().ok_or_else(|| {
            DeclarationError::manifest(format!("{path}: manifest entry is not an object"))
        })?;
        let size = meta
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                DeclarationError::manifest(format!("{path}: size must be a non-negative integer"))
            })?;
        if size > MAX_ARTIFACT as u64 {
            return Err(DeclarationError::manifest(format!(
                "{path}: size {size} exceeds {MAX_ARTIFACT} bytes"
            )));
        }
        let sha512 = meta
            .get("sha512")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| is_lower_hash_hex(digest))
            .ok_or_else(|| {
                DeclarationError::manifest(format!(
                    "{path}: sha512 must be 64 lowercase hexadecimal characters"
                ))
            })?;
        Ok(PinnedFile {
            path: path.to_string(),
            size,
            sha512: sha512.to_string(),
        })
    };

    let entry = pin(&declared.entry)?;
    let mut dependencies = Vec::with_capacity(declared.dependencies.len());
    for dependency in &declared.dependencies {
        dependencies.push(pin(dependency)?);
    }

    let mut total_bytes = entry.size;
    for dependency in &dependencies {
        total_bytes = total_bytes
            .checked_add(dependency.size)
            .ok_or_else(|| DeclarationError::manifest("closure size overflows"))?;
    }
    if total_bytes > MAX_TOTAL as u64 {
        return Err(DeclarationError::manifest(format!(
            "closure of {total_bytes} bytes exceeds {MAX_TOTAL}"
        )));
    }

    Ok(BoundProgram {
        program: program.to_string(),
        entry,
        dependencies,
        total_bytes,
    })
}

/// The manifest digest form `epix-content` enforces: 64 lowercase hex digits.
fn is_lower_hash_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
