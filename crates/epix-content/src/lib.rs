//! `epix-content` - content.json canonicalization, signing, and verification.
//!
//! The signed payload is `content` minus its `sign`/`signs` fields, serialized
//! via [`canonical::dumps_sorted`] (Python-compatible), then signed/recovered
//! with `epix-crypt`'s `dbl`-format recoverable ECDSA.

pub mod canonical;
pub mod diff;
pub mod merge;
pub mod record;
pub mod verify;

pub use canonical::{dumps_content, dumps_sorted};
pub use diff::{patch, DiffAction};
pub use merge::{live_records, make_container, merge_orset, records_of, RECORD_FORMAT};
pub use record::{derive_post_id, record_signed_data, verify_record, RecordError, CLOCK_SKEW_BOUND_MS};
pub use verify::{verify_content_file, VerifyContext, VerifyError};
use epix_core::{Error, Result};
use serde_json::Value;

/// The canonical signed payload: `content` with `sign` and `signs` removed,
/// dumped exactly as `json.dumps(content, sort_keys=True)`.
pub fn signed_data(content: &Value) -> String {
    let mut c = content.clone();
    if let Value::Object(map) = &mut c {
        map.remove("sign");
        map.remove("signs");
    }
    dumps_sorted(&c)
}

/// Verify the signature `signs[address]` against the canonical payload.
/// Returns false if the address has no entry in `signs` or the signature is bad.
pub fn verify_signer(content: &Value, address: &str) -> bool {
    match content.get("signs").and_then(|s| s.get(address)).and_then(|v| v.as_str()) {
        Some(sig) => epix_crypt::verify(&signed_data(content), address, sig),
        None => false,
    }
}

/// Verify every entry in `signs`, returning `(address, is_valid)` for each.
pub fn verify_all(content: &Value) -> Vec<(String, bool)> {
    let data = signed_data(content);
    content
        .get("signs")
        .and_then(|s| s.as_object())
        .map(|signs| {
            signs
                .iter()
                .map(|(addr, sig)| {
                    let ok = sig
                        .as_str()
                        .map(|s| epix_crypt::verify(&data, addr, s))
                        .unwrap_or(false);
                    (addr.clone(), ok)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Sign `content` with a single private key: strips any prior `sign`/`signs`,
/// signs the canonical payload, and sets `signs = {address: signature}`.
/// Returns the base64 signature. (Multisig / `signers_sign` live a layer up.)
pub fn sign(content: &mut Value, privatekey: &str) -> Result<String> {
    let data = signed_data(content);
    let address = epix_crypt::privatekey_to_address(privatekey).map_err(Error::Crypt)?;
    let sig = epix_crypt::sign(&data, privatekey).map_err(Error::Crypt)?;
    if let Value::Object(map) = content {
        map.remove("sign");
        let mut signs = serde_json::Map::new();
        signs.insert(address, Value::String(sig.clone()));
        map.insert("signs".to_string(), Value::Object(signs));
    } else {
        return Err(Error::Protocol("content is not a JSON object".into()));
    }
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn separators_and_sorting_match_python() {
        assert_eq!(dumps_sorted(&json!({"b": 1, "a": 2})), r#"{"a": 2, "b": 1}"#);
        assert_eq!(dumps_sorted(&json!([1, 2, 3])), "[1, 2, 3]");
        assert_eq!(dumps_sorted(&json!({})), "{}");
    }

    /// The on-disk format matches Python EpixNet's `helper.jsonDumps` exactly.
    /// The expected string below is that function's verbatim output for this
    /// value (`json.dumps(indent=1, sort_keys=True)` + its compaction passes):
    /// multi-line file entries, the one-entry `signs` dict on a single line, a
    /// flat signers list on a single line.
    #[test]
    fn dumps_content_matches_python_json_dumps() {
        let content = json!({
            "address": "epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g",
            "title": "Dashboard",
            "modified": 1783901827,
            "inner_path": "content.json",
            "postmessage_nonce_security": true,
            "signs_required": 1,
            "ignore": "(js/all\\.js|\\.git)",
            "files": {
                "index.html": {"sha512": "5b6a2c352af0e4a85a55fffa42fa1e2463", "size": 3919},
                "css/all.css": {"sha512": "aabbccddee0011223344556677889900aa", "size": 83622},
            },
            "includes": {
                "data/users/content.json": {"signers": ["epix1abc", "epix1def"], "signers_required": 1}
            },
            "optional": "(data/.*|.*\\.zip)",
            "signers_sign": "GzDAK33cGtqcui0MibSu9pX",
            "signs": {"epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g": "HMPzO44Ztew"},
        });
        let expected = "{\n \"address\": \"epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g\",\n \"files\": {\n  \"css/all.css\": {\n   \"sha512\": \"aabbccddee0011223344556677889900aa\",\n   \"size\": 83622\n  },\n  \"index.html\": {\n   \"sha512\": \"5b6a2c352af0e4a85a55fffa42fa1e2463\",\n   \"size\": 3919\n  }\n },\n \"ignore\": \"(js/all\\\\.js|\\\\.git)\",\n \"includes\": {\n  \"data/users/content.json\": {\n   \"signers\": [\"epix1abc\",\"epix1def\"],\n   \"signers_required\": 1\n  }\n },\n \"inner_path\": \"content.json\",\n \"modified\": 1783901827,\n \"optional\": \"(data/.*|.*\\\\.zip)\",\n \"postmessage_nonce_security\": true,\n \"signers_sign\": \"GzDAK33cGtqcui0MibSu9pX\",\n \"signs\": {\"epix1dashanwfts3qcflekhmkvcz66ss4kxz2tr2k6g\": \"HMPzO44Ztew\"},\n \"signs_required\": 1,\n \"title\": \"Dashboard\"\n}";
        assert_eq!(dumps_content(&content), expected);
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let priv_hex = "11b913374fe145476b2798a4f6b88753c6228d8ea950f905723bcdbb343df0e7";
        let addr = epix_crypt::privatekey_to_address(priv_hex).unwrap();
        let mut content = json!({
            "address": "epix1xite",
            "files": {"index.html": {"size": 10, "sha512": "ab"}},
            "modified": 1777992697,
            "sign": "stale",
            "signs": {"old": "stale"},
        });
        let sig = sign(&mut content, priv_hex).unwrap();
        // signs replaced with our single signer; stale `sign` removed.
        assert!(content.get("sign").is_none());
        assert_eq!(content["signs"][&addr], json!(sig));
        assert!(verify_signer(&content, &addr));
        assert!(!verify_signer(&content, "epix1someoneelse"));
        // Tamper -> verification fails.
        content["modified"] = json!(0);
        assert!(!verify_signer(&content, &addr));
    }
}
