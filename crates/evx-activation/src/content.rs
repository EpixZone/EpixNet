//! Content-based activation: the real authority chain.
//!
//! A xite's root `content.json` is signed by its owner's secp256k1 key and
//! carries, in `files`, the size and truncated SHA-512 of every required
//! file, and in `evx`, the programs the owner asks to run. The node verifies
//! that signature, parses and binds the declaration (`evx-declaration`), and
//! hands this module the decoded document, one [`BoundProgram`] and a reader
//! for the xite's stored files. [`ActivationLoader::verify_content`] then
//! produces the same [`PendingActivation`] the envelope path does, so
//! [`ActivationLoader::admit`], the checkpoint and every host binding check
//! are shared: a denied content activation never advances the version floor
//! for the same reason a denied envelope never does.
//!
//! # Caller contract
//!
//! The loader never verifies the content signature. It cannot: the trusted
//! input for a root-address grant is the address the node already checked
//! `content.json` against (`epix_content::verify_signer`), and repeating that
//! check here would only pretend the loader can decide who signed. So
//! `verify_content` requires the caller to have established that `content`
//! is the root `content.json` signed by the owner of the grant's root
//! address, and it re-checks what *it* can check: the document names the
//! granted xite and that root address, the bound closure is exactly what the
//! signed manifest pins, every captured byte matches, and the program's
//! request lies within the grant. Tests pass unsigned documents on purpose
//! to make the division visible.
//!
//! # Why the request is read from the signed section again
//!
//! A [`BoundProgram`] carries only the closure. The capabilities and runtime
//! profile the activation runs with are read from
//! `content["evx"]["programs"][program]` here, not taken from a caller
//! argument, so the authority an activation holds is always the one the
//! owner signed and a host cannot be handed a wider set by mistake. The
//! declaration parser has already accepted the section once; the decoding
//! here is strict in the same way and refuses anything it does not expect.

use std::collections::{BTreeMap, BTreeSet};

use evx_api::{strict, Capability};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256, Sha512};

use crate::activation::{rollback_error, ArtifactFormat, PublisherAuthority, VerifiedContent};
use crate::{
    digest, ActivationLoader, AuthenticationError, PendingActivation, MAX_ARTIFACT, MAX_FILES,
    MAX_TOTAL,
};

/// Most capability objects one program may list, the parser's bound.
const MAX_CAPABILITIES: usize = 64;
/// Largest version (`2**63 - 1`), the same bound the envelope path uses.
const MAX_VERSION: u64 = i64::MAX as u64;

/// One program whose files are pinned to the signed manifest.
///
/// Produced by `evx_declaration::bind` from the parsed declaration and the
/// manifest's required `files` map. It lives in this crate because the
/// declaration crate depends on this one for the closure bounds, and the
/// loader must name the type in [`ActivationLoader::verify_content`];
/// `evx_declaration` re-exports it, so the binder's output is this type and
/// not a lookalike.
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
    /// EpixNet manifests use (`XiteStorage::hash_bytes`).
    pub sha512: String,
}

/// The reader a host supplies for the xite's stored files: given a
/// manifest-relative path, the file's bytes, or why they are unavailable.
pub type ContentReadFn<'a> = dyn FnMut(&str) -> Result<Vec<u8>, AuthenticationError> + 'a;

impl ActivationLoader {
    /// Phase one of a content activation.
    ///
    /// `content` must already be verified by the caller as the root
    /// `content.json` signed by the owner of the grant's root address
    /// (`epix_content::verify_signer(content, address)` is true, where
    /// `address` is the [`PublisherAuthority::RootAddress`] in the grant);
    /// this function does not check the signature, only that the document
    /// names that address. It captures the entry and dependencies through
    /// `read`, checks each against the size and truncated SHA-512 the
    /// manifest signed, and yields the same [`PendingActivation`] the
    /// envelope path does. Nothing is mutated.
    ///
    /// The activation's version is `content["modified"]` in whole
    /// milliseconds; its manifest digest is the SHA-256 of
    /// `epix_content::signed_data(content)`, the exact bytes the owner
    /// signed; its declaration digest is the SHA-256 of the canonical `evx`
    /// object, as `evx_declaration::declaration_digest` computes it.
    ///
    /// Refuses, in this order and each without touching the checkpoint: a
    /// disabled grant; a grant that is not a root-address grant; a document
    /// that is not an object or whose `address` is not the granted xite or
    /// not the grant's root address; a `modified` that is missing, not a
    /// number, non-finite, negative, zero or beyond `2**63 - 1`
    /// milliseconds; a version the checkpoint does not admit; a missing or
    /// malformed `evx` section or program entry; a runtime profile outside
    /// the grant; a capability list that is not
    /// exactly `[{"api": name}, ...]` of distinct known names within the
    /// grant; a bound entry or dependency list that differs from the signed
    /// program; a closure beyond [`MAX_FILES`], [`MAX_ARTIFACT`] or
    /// [`MAX_TOTAL`], with a path escape, a duplicate, or a pin that differs
    /// from the signed `files` entry; a read failure; captured bytes whose
    /// length or digest differ from the pin; a file that is not a core Wasm
    /// module.
    pub fn verify_content(
        &self,
        content: &Value,
        bound: &BoundProgram,
        read: &mut ContentReadFn<'_>,
    ) -> Result<PendingActivation, AuthenticationError> {
        let grant = self.grant();
        if !grant.enabled {
            return Err(AuthenticationError::new("xite execution is not enabled"));
        }
        let PublisherAuthority::RootAddress(owner) = &grant.authority else {
            return Err(AuthenticationError::new(
                "content activation requires a root-address grant",
            ));
        };
        let document = content
            .as_object()
            .ok_or_else(|| AuthenticationError::new("content.json is not an object"))?;
        let address = document.get("address").and_then(Value::as_str);
        if address != Some(grant.xite.as_str()) {
            return Err(AuthenticationError::new("activation identity mismatch"));
        }
        // The caller verified the signature against the address the grant
        // names; a document naming any other address was not vouched for
        // by that check, whatever its `address` field says.
        if address != Some(owner.as_str()) {
            return Err(AuthenticationError::new(
                "content address is not the grant's root address",
            ));
        }
        let version = modified_version(document.get("modified"))?;
        let manifest_bytes = epix_content::signed_data(content).into_bytes();
        let manifest_digest = digest(&manifest_bytes);
        if !self.admits(version, &manifest_digest) {
            return Err(rollback_error());
        }

        let section = document
            .get("evx")
            .and_then(Value::as_object)
            .ok_or_else(|| AuthenticationError::new("content.json has no evx section"))?;
        let program = section
            .get("programs")
            .and_then(Value::as_object)
            .and_then(|programs| programs.get(&bound.program))
            .and_then(Value::as_object)
            .ok_or_else(|| AuthenticationError::new("program absent from signed declaration"))?;
        let runtime_profile = program
            .get("runtime_profile")
            .and_then(Value::as_str)
            .filter(|profile| evx_api::validate_identifier(profile).is_ok())
            .ok_or_else(|| AuthenticationError::new("invalid runtime profile declaration"))?;
        if !grant.runtime_profiles.contains(runtime_profile) {
            return Err(AuthenticationError::new("runtime profile outside grant"));
        }
        let capabilities = declared_capabilities(program.get("capabilities"), &grant.capabilities)?;
        check_bound_matches_program(bound, program)?;
        let declaration_digest = declaration_digest(section)?;

        let files_map = document
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| AuthenticationError::new("content.json has no files object"))?;
        let pins = pinned_closure(bound, files_map)?;

        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for pin in pins {
            let data = read(&pin.path)?;
            total = total.saturating_add(data.len());
            if total > MAX_TOTAL
                || u64::try_from(data.len()) != Ok(pin.size)
                || sha512_prefix(&data) != pin.sha512
            {
                return Err(AuthenticationError::new(
                    "artifact digest or aggregate size mismatch",
                ));
            }
            ArtifactFormat::WasmCoreV1.check_bytes(&data)?;
            files.insert(pin.path.clone(), data);
        }

        Ok(self.pending_content(VerifiedContent {
            version,
            runtime_profile: runtime_profile.to_string(),
            capabilities,
            manifest_digest,
            manifest_bytes,
            declaration_digest,
            program: bound.program.clone(),
            entry: bound.entry.path.clone(),
            files,
        }))
    }
}

/// `content["modified"]` as whole milliseconds.
///
/// EpixNet writes `modified` as Unix seconds, usually a float with a
/// fractional part, sometimes an integer. Both forms become a millisecond
/// count so the version floor is monotonic across the two spellings; a float
/// is rounded to the nearest millisecond because a value such as
/// `1700000000.123` has no exact binary form and truncation could land one
/// below the millisecond the owner wrote. Non-finite, negative and zero
/// values and anything beyond `2**63 - 1` milliseconds are refused: the
/// checkpoint stores an `i64`-range version and a zero would compare equal
/// to "nothing admitted".
fn modified_version(value: Option<&Value>) -> Result<u64, AuthenticationError> {
    let invalid = || AuthenticationError::new("invalid modified timestamp");
    let number = value.and_then(Value::as_number).ok_or_else(invalid)?;
    let millis = if let Some(seconds) = number.as_u64() {
        seconds.checked_mul(1000).ok_or_else(invalid)?
    } else {
        // A negative integer also lands here, as a negative float.
        let seconds = number.as_f64().ok_or_else(invalid)?;
        if !seconds.is_finite() || seconds < 0.0 {
            return Err(invalid());
        }
        let millis = (seconds * 1000.0).round();
        // `i64::MAX as f64` rounds up to 2**63, which is itself out of range.
        if millis >= MAX_VERSION as f64 {
            return Err(invalid());
        }
        millis as u64
    };
    if millis == 0 || millis > MAX_VERSION {
        return Err(invalid());
    }
    Ok(millis)
}

/// The program's capability request: at most [`MAX_CAPABILITIES`] objects of
/// exactly `{"api": name}`, distinct, each a member of the closed set and of
/// the grant. Anything else refuses the activation rather than running with
/// a reinterpreted request.
fn declared_capabilities(
    value: Option<&Value>,
    granted: &BTreeSet<Capability>,
) -> Result<BTreeSet<Capability>, AuthenticationError> {
    let invalid = || AuthenticationError::new("invalid capability declaration");
    let exceeds = || AuthenticationError::new("capability declaration exceeds grant");
    let declared = value
        .and_then(Value::as_array)
        .filter(|list| list.len() <= MAX_CAPABILITIES)
        .ok_or_else(invalid)?;
    let mut capabilities = BTreeSet::new();
    for item in declared {
        let object = item.as_object().ok_or_else(invalid)?;
        if object.len() != 1 {
            return Err(invalid());
        }
        let name = object
            .get("api")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        let capability = Capability::parse(name).ok_or_else(exceeds)?;
        if !capabilities.insert(capability) {
            return Err(exceeds());
        }
    }
    if !capabilities.is_subset(granted) {
        return Err(exceeds());
    }
    Ok(capabilities)
}

/// The bound closure must be the one the owner declared for this program:
/// the same entry and the same dependencies in the same order. A
/// [`BoundProgram`] has public fields, so this cannot be assumed from how
/// it was built.
fn check_bound_matches_program(
    bound: &BoundProgram,
    program: &Map<String, Value>,
) -> Result<(), AuthenticationError> {
    let mismatch = || AuthenticationError::new("bound closure does not match signed declaration");
    if program.get("entry").and_then(Value::as_str) != Some(bound.entry.path.as_str()) {
        return Err(mismatch());
    }
    let declared: Vec<&str> = match program.get("dependencies") {
        None => Vec::new(),
        Some(list) => list
            .as_array()
            .ok_or_else(mismatch)?
            .iter()
            .map(|item| item.as_str().ok_or_else(mismatch))
            .collect::<Result<_, _>>()?,
    };
    let bound_paths: Vec<&str> = bound
        .dependencies
        .iter()
        .map(|pin| pin.path.as_str())
        .collect();
    if declared != bound_paths {
        return Err(mismatch());
    }
    Ok(())
}

/// The closure in capture order (entry first), each pin re-validated and
/// compared with the signed `files` entry for its path.
///
/// Sizes, digests and paths are checked again although `bind` checked them:
/// the pins are what the captured bytes are compared with, so they must be
/// provably the signed values and not whatever a caller put in the public
/// fields. The signature covers `files`; it does not cover a `BoundProgram`.
fn pinned_closure<'a>(
    bound: &'a BoundProgram,
    files: &Map<String, Value>,
) -> Result<Vec<&'a PinnedFile>, AuthenticationError> {
    let pins: Vec<&PinnedFile> = std::iter::once(&bound.entry)
        .chain(bound.dependencies.iter())
        .collect();
    if pins.len() > MAX_FILES {
        return Err(AuthenticationError::new("invalid artifact closure"));
    }
    let mut seen = BTreeSet::new();
    let mut total: u64 = 0;
    for pin in &pins {
        evx_api::validate_relative_path(&pin.path)
            .map_err(|_| AuthenticationError::new("artifact path outside allowed namespace"))?;
        if !seen.insert(pin.path.as_str()) {
            return Err(AuthenticationError::new("invalid artifact closure"));
        }
        if pin.size > MAX_ARTIFACT as u64 || !is_lower_hash_hex(&pin.sha512) {
            return Err(AuthenticationError::new("invalid artifact closure"));
        }
        total = total
            .checked_add(pin.size)
            .filter(|total| *total <= MAX_TOTAL as u64)
            .ok_or_else(|| AuthenticationError::new("invalid artifact closure"))?;
        let signed = files
            .get(&pin.path)
            .and_then(Value::as_object)
            .ok_or_else(|| AuthenticationError::new("artifact absent from signed manifest"))?;
        let signed_size = signed.get("size").and_then(Value::as_u64);
        let signed_digest = signed.get("sha512").and_then(Value::as_str);
        if signed_size != Some(pin.size) || signed_digest != Some(pin.sha512.as_str()) {
            return Err(AuthenticationError::new(
                "bound closure does not match signed manifest",
            ));
        }
    }
    if total != bound.total_bytes {
        return Err(AuthenticationError::new("invalid artifact closure"));
    }
    Ok(pins)
}

/// SHA-256 of the canonical (sorted-key, compact) `evx` object, computed the
/// way `evx_declaration::declaration_digest` computes it: through the strict
/// decoder's own encoder, so the two can never disagree on a section the
/// strict decoder accepts.
fn declaration_digest(section: &Map<String, Value>) -> Result<String, AuthenticationError> {
    let raw = serde_json::to_vec(section)
        .map_err(|_| AuthenticationError::new("evx section cannot be serialised"))?;
    let value = strict::parse(&raw)
        .map_err(|denied| AuthenticationError::new(format!("evx section: {denied}")))?;
    Ok(hex::encode(Sha256::digest(
        strict::to_json(&value).as_bytes(),
    )))
}

/// The truncated SHA-512 EpixNet manifests carry: the first 32 bytes of the
/// digest, lowercase hex.
pub fn sha512_prefix(data: &[u8]) -> String {
    hex::encode(&Sha512::digest(data)[..32])
}

fn is_lower_hash_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
