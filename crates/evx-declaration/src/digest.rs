//! The declaration digest: what a grant is pinned to.
//!
//! `evxGrant` carries the digest the wrapper saw in the inspect payload, and
//! the node refuses the grant unless it matches the declaration it currently
//! holds. That makes the digest an expected-version check: the user consents
//! to exactly the declaration they were shown, and a publication that changes
//! any requested capability, file, limit or schedule changes the digest.

use evx_api::strict::{self, Value};
use sha2::{Digest as _, Sha256};

use crate::parse::strict_document;
use crate::DeclarationError;

/// Lowercase hex SHA-256 of the canonical form of the `evx` object, from a
/// root `content.json` held as bytes.
///
/// Canonical means the object re-encoded with keys sorted by code point and
/// compact separators (`{"a":1,"b":[1,2]}`), produced by
/// [`evx_api::strict::to_json`] after a strict decode. It covers the `evx`
/// object only, so the digest is stable across edits elsewhere in
/// `content.json` (a re-sign, a changed `modified`, a new file) and changes
/// whenever the declaration does.
///
/// This is the primary form, and the one the node should call on the stored
/// bytes of `content.json`: the whole document is decoded through
/// [`evx_api::strict`], so a duplicated key anywhere in it is refused, the
/// same way [`crate::parse_bytes`] refuses it. A `serde_json::Value` has
/// already kept the last of two equal keys and dropped the other, so
/// [`declaration_digest`] cannot tell and would digest the collapsed object
/// while a first-wins reader sees the other value.
///
/// Like `parse_bytes`, a document without an `evx` key is `Ok(None)`.
///
/// This is **not** `epix_content::signed_data`: that is Python-style
/// (`", "` and `": "` separators, `ensure_ascii` escapes) over the whole
/// content minus `sign`/`signs`, and it is what the content signature covers.
/// The two serve different purposes; the manifest digest the activation
/// loader records is the signed-data one.
///
/// The digest does not require the declaration to parse: the inspection view
/// shows what the owner published even when it is malformed, and a grant for
/// a malformed declaration is refused on the parse, not on the digest.
pub fn declaration_digest_bytes(raw: &[u8]) -> Result<Option<String>, DeclarationError> {
    let document = strict_document(raw)?;
    match document.get("evx") {
        None => Ok(None),
        Some(section) => section_digest(section).map(Some),
    }
}

/// [`declaration_digest_bytes`] for an already-decoded `content.json`.
///
/// Only safe on a value whose bytes are known to be free of duplicate keys,
/// such as one re-read from a document that [`crate::parse_bytes`] accepted:
/// a `serde_json::Value` cannot carry a duplicate, so this function cannot
/// refuse one. A caller holding the bytes uses `declaration_digest_bytes`.
///
/// A missing section is [`DeclarationError::Missing`], as for [`crate::parse`].
pub fn declaration_digest(content: &serde_json::Value) -> Result<String, DeclarationError> {
    let object = content
        .as_object()
        .ok_or_else(|| DeclarationError::malformed("content.json is not an object"))?;
    let section = object.get("evx").ok_or(DeclarationError::Missing)?;
    if !section.is_object() {
        return Err(DeclarationError::malformed("evx: must be an object"));
    }
    let raw = serde_json::to_vec(section)
        .map_err(|_| DeclarationError::malformed("evx section cannot be serialised"))?;
    let value =
        strict::parse(&raw).map_err(|denied| DeclarationError::malformed(denied.to_string()))?;
    section_digest(&value)
}

fn section_digest(section: &Value) -> Result<String, DeclarationError> {
    if section.as_object().is_none() {
        return Err(DeclarationError::malformed("evx: must be an object"));
    }
    Ok(hex::encode(Sha256::digest(
        strict::to_json(section).as_bytes(),
    )))
}
