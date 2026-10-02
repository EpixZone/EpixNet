//! The declaration digest: what a grant is pinned to.
//!
//! `evxGrant` carries the digest the wrapper saw in the inspect payload, and
//! the node refuses the grant unless it matches the declaration it currently
//! holds. That makes the digest an expected-version check: the user consents
//! to exactly the declaration they were shown, and a publication that changes
//! any requested capability, file, limit or schedule changes the digest.

use evx_api::strict;
use sha2::{Digest as _, Sha256};

use crate::DeclarationError;

/// Lowercase hex SHA-256 of the canonical form of the `evx` object.
///
/// Canonical means the object re-encoded with keys sorted by code point and
/// compact separators (`{"a":1,"b":[1,2]}`), produced by
/// [`evx_api::strict::to_json`] after a strict decode. It covers the `evx`
/// object only, so the digest is stable across edits elsewhere in
/// `content.json` (a re-sign, a changed `modified`, a new file) and changes
/// whenever the declaration does.
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
    Ok(hex::encode(Sha256::digest(
        strict::to_json(&value).as_bytes(),
    )))
}
