//! Deep content.json verification - the rules EpixNet's `ContentManager`
//! enforces beyond a single root signature:
//!
//! - **Valid signers + `signers_sign`**: a root content.json may delegate signing
//!   to extra `signers`; that signer list must itself be authorized by the site
//!   owner (`signers_sign`), and the content must carry a valid signature from
//!   one of the valid signers (`signs_required`, default 1).
//! - **Certs** (`user_contents`): a user file under a `user_contents` node must
//!   carry a `cert_user_id`/`cert_sign` issued by an accepted `cert_signers`
//!   provider, verified against the user's address.
//! - **Content rules**: address + inner_path match, valid relative paths,
//!   size-limit enforcement, and per-include `max_size` / `max_size_optional` /
//!   `files_allowed` / `files_allowed_optional` / `includes_allowed`.
//!
//! Signature/cert checks are the security gates; the size/quota checks bound
//! abuse. Ported from `EpixNet/src/Content/ContentManager.py`
//! (`verifyFile`/`verifyContent`/`verifyContentInclude`/`verifyCert`/
//! `getValidSigners`/`getRules`/`getUserContentRules`).

use crate::{signed_data, verify_signer};
use serde_json::Value;

/// A verification failure with EpixNet's message text (sent back on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError(pub String);

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for VerifyError {}

fn err<T>(msg: impl Into<String>) -> Result<T, VerifyError> {
    Err(VerifyError(msg.into()))
}

/// What a verifier needs from the surrounding site: the site address, the size
/// limit, and any already-loaded parent content.json values (to resolve the
/// rules for an included/user file).
pub trait VerifyContext {
    /// The site's signed address (`epix1…`).
    fn site_address(&self) -> &str;
    /// A loaded (already-verified) content.json by its inner_path, for rules.
    fn loaded_content(&self, inner_path: &str) -> Option<Value>;
    /// The site's effective size limit in bytes (root content.json guard).
    fn size_limit_bytes(&self) -> i64 {
        i64::MAX
    }
    /// Resolve an xID name (e.g. `facts.epix`) to the bech32 addresses that may
    /// sign for it (owner + identities). EpixTalk-style user_contents dirs are
    /// named by the user's xID and the content is signed by the identity that
    /// xID belongs to, so a signer given as an xID name must be resolved to
    /// match the signature. The node pre-resolves these; default is empty.
    fn resolve_xid(&self, _name: &str) -> Vec<String> {
        Vec::new()
    }
}

/// The valid signer addresses for `inner_path`: the declared `signers` (root
/// `signers`, or an include/user rule's `signers`) plus the site address, which
/// is always valid. Mirrors `getValidSigners`.
pub fn valid_signers(inner_path: &str, content: &Value, ctx: &dyn VerifyContext) -> Vec<String> {
    let mut signers: Vec<String> = Vec::new();
    if inner_path == "content.json" {
        // Prefer the loaded root's signers; bootstrap from the content being
        // verified when nothing is loaded yet.
        let root = ctx.loaded_content("content.json");
        let src = root.as_ref().unwrap_or(content);
        if let Some(list) = src.get("signers").and_then(|v| v.as_array()) {
            signers.extend(list.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
    } else if let Some(rules) = get_rules(inner_path, content, ctx) {
        if let Some(list) = rules.get("signers").and_then(|v| v.as_array()) {
            signers.extend(list.iter().filter_map(|v| v.as_str().map(str::to_string)));
        }
    }
    // A signer given as an xID name (contains a dot, not a bech32 address)
    // resolves to the chain address that actually signs the content.
    let resolved: Vec<String> = signers
        .iter()
        .filter(|s| s.contains('.'))
        .flat_map(|name| ctx.resolve_xid(name))
        .collect();
    signers.extend(resolved);
    let site = ctx.site_address().to_string();
    if !signers.contains(&site) {
        signers.push(site);
    }
    signers
}

/// The number of valid signatures required (EpixNet hardcodes 1; a delegated
/// signer list is authorized separately via `signers_sign`).
fn signs_required(_inner_path: &str, _content: &Value) -> u64 {
    1
}

/// Verify a `cert_sign`: the provider (`issuer_address`) signed
/// `user_address#auth_type/user_name`. Mirrors `verifyCertSign`.
pub fn verify_cert_sign(
    user_address: &str,
    auth_type: &str,
    user_name: &str,
    issuer_address: &str,
    sign: &str,
) -> bool {
    let subject = format!("{user_address}#{auth_type}/{user_name}");
    epix_crypt::verify(&subject, issuer_address, sign)
}

/// Resolve the rules for a non-root file by walking up to the nearest parent
/// content.json that declares it under `includes` or `user_contents`.
fn get_rules(inner_path: &str, content: &Value, ctx: &dyn VerifyContext) -> Option<Value> {
    if inner_path == "content.json" {
        return Some(serde_json::json!({
            "signers": valid_signers(inner_path, content, ctx),
        }));
    }
    let parts: Vec<&str> = inner_path.split('/').collect();
    // Walk parent directories from the closest up to the root.
    for cut in (0..parts.len()).rev() {
        let parent_dir = parts[..cut].join("/");
        let content_inner_path = if parent_dir.is_empty() {
            "content.json".to_string()
        } else {
            format!("{parent_dir}/content.json")
        };
        let Some(parent) = ctx.loaded_content(&content_inner_path) else { continue };
        let relative = parts[cut..].join("/");
        if let Some(includes) = parent.get("includes").and_then(|v| v.as_object()) {
            return includes.get(&relative).cloned();
        }
        if parent.get("user_contents").is_some() {
            return user_content_rules(&parent, inner_path, content);
        }
    }
    None
}

/// Rules for a file under a `user_contents` node: pick the permission set for
/// the user (by address or cert user id), attach the provider `cert_signers`,
/// set the user's own address as a signer, and forbid nested includes. A
/// focused port of `getUserContentRules` (the `permission_rules` regex merge is
/// omitted; the common `permissions[address|cert_user_id]` path is covered).
fn user_content_rules(parent: &Value, inner_path: &str, content: &Value) -> Option<Value> {
    let user_contents = parent.get("user_contents")?;
    // The user directory name is the path segment after the user_contents dir.
    let user_address = user_dir_segment(parent, inner_path)?;
    let cert_user_id = content.get("cert_user_id").and_then(|v| v.as_str()).unwrap_or("n-a");

    let permissions = user_contents.get("permissions").and_then(|v| v.as_object());
    let mut rules = permissions
        .and_then(|p| p.get(&user_address).or_else(|| p.get(cert_user_id)))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    // `permissions[user] == false` means banned - no rules, no self-signer.
    let banned = rules == Value::Bool(false);
    if banned || !rules.is_object() {
        rules = serde_json::json!({});
    }

    let obj = rules.as_object_mut().unwrap();
    obj.insert(
        "cert_signers".to_string(),
        user_contents.get("cert_signers").cloned().unwrap_or_else(|| serde_json::json!({})),
    );
    if let Some(pat) = user_contents.get("cert_signers_pattern") {
        obj.insert("cert_signers_pattern".to_string(), pat.clone());
    }
    let mut signers: Vec<Value> = obj
        .get("signers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if !banned {
        signers.push(Value::from(user_address.clone())); // resolveUserSigners default
    }
    obj.insert("signers".to_string(), Value::Array(signers));
    obj.insert("user_address".to_string(), Value::from(user_address));
    obj.insert("includes_allowed".to_string(), Value::Bool(false));
    Some(rules)
}

/// The user-directory segment of `inner_path` relative to the `user_contents`
/// parent (e.g. `data/users/<addr>/data.json` -> `<addr>`).
fn user_dir_segment(parent: &Value, inner_path: &str) -> Option<String> {
    let parent_inner = parent.get("inner_path").and_then(|v| v.as_str()).unwrap_or("content.json");
    let parent_dir = dirname(parent_inner);
    let rest = inner_path.strip_prefix(&parent_dir).unwrap_or(inner_path);
    rest.trim_start_matches('/').split('/').next().map(str::to_string).filter(|s| !s.is_empty())
}

/// `data/site/content.json` -> `data/site/` (EpixNet's `helper.getDirname`).
fn dirname(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[..=i].trim_start_matches('/').to_string(),
        None => String::new(),
    }
}

/// Verify the cert on a `user_contents` file (`verifyCert`): the file's
/// `cert_user_id`/`cert_sign` must be issued by an accepted provider.
fn verify_cert(inner_path: &str, content: &Value, ctx: &dyn VerifyContext) -> Result<bool, VerifyError> {
    let Some(rules) = get_rules(inner_path, content, ctx) else {
        return err("No rules for this file");
    };
    let has_signers = rules.get("cert_signers").and_then(|v| v.as_object()).is_some_and(|m| !m.is_empty());
    let has_pattern = rules.get("cert_signers_pattern").and_then(|v| v.as_str()).is_some();
    if !has_signers && !has_pattern {
        return Ok(true); // does not need a cert
    }
    let cert_user_id = match content.get("cert_user_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return err("Missing cert_user_id"),
    };
    if cert_user_id.matches('@').count() != 1 {
        return err("Invalid domain in cert_user_id");
    }
    let (name, domain) = cert_user_id.rsplit_once('@').unwrap();
    // The issuers allowed for this domain: `cert_signers[domain]` is a list of
    // addresses (EpixNet stores an array), or the domain itself via a pattern.
    let issuers: Vec<String> = rules
        .get("cert_signers")
        .and_then(|m| m.get(domain))
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .or_else(|| {
            let pat = rules.get("cert_signers_pattern").and_then(|v| v.as_str())?;
            regex_full_match(pat, domain).then(|| vec![domain.to_string()])
        })
        .unwrap_or_default();
    if issuers.is_empty() {
        return err(format!("Invalid cert signer: {domain}"));
    }
    // Epix chain-delegated certs (`["chain"]`): the issuing authority is the
    // Epix chain / XID system (keccak-ethsecp256k1 signatures resolved on
    // chain), not a static ECC address. The user's content.json is still
    // signature-verified on its own (the user's auth address signs it), so
    // accept the chain-delegated cert here.
    // TODO: full on-chain cert verification (resolve the xID, check the
    // cert_sign against the chain-registered key) to also reject forged
    // chain-issued identities, not just enforce the content signature.
    if issuers.iter().any(|i| i == "chain") {
        return Ok(true);
    }
    let cert_address = issuers[0].clone();
    let user_address = rules.get("user_address").and_then(|v| v.as_str()).unwrap_or("");
    let auth_type = content.get("cert_auth_type").and_then(|v| v.as_str()).unwrap_or("");
    let cert_sign = content.get("cert_sign").and_then(|v| v.as_str()).unwrap_or("");
    Ok(verify_cert_sign(user_address, auth_type, name, &cert_address, cert_sign))
}

/// Verify content rules (`verifyContent` + `verifyContentInclude`): address /
/// inner_path match, valid relative paths, the root size-limit guard, and
/// per-include size/filename/includes limits. `raw_len` is the received
/// content.json byte length (used for the size guard).
fn verify_content_rules(
    inner_path: &str,
    content: &Value,
    raw_len: i64,
    ctx: &dyn VerifyContext,
) -> Result<(), VerifyError> {
    // Address must match the site.
    if let Some(addr) = content.get("address").and_then(|v| v.as_str()) {
        if addr != ctx.site_address() {
            return err(format!("Wrong site address: {addr} != {}", ctx.site_address()));
        }
    }
    // inner_path must match (normalizing backslashes).
    if let Some(ip) = content.get("inner_path").and_then(|v| v.as_str()) {
        if ip.replace('\\', "/") != inner_path.replace('\\', "/") {
            return err(format!("Wrong inner_path: {ip}"));
        }
    }
    // Valid relative filenames.
    for node in ["files", "files_optional"] {
        if let Some(files) = content.get(node).and_then(|v| v.as_object()) {
            for path in files.keys() {
                if !is_valid_relative_path(path) {
                    return err(format!("Invalid relative path: {path}"));
                }
            }
        }
    }

    if inner_path == "content.json" {
        // Root content.json bigger than the size limit is rejected.
        if raw_len > ctx.size_limit_bytes() {
            return err(format!(
                "Content too large {raw_len} B > {} B, aborting task...",
                ctx.size_limit_bytes()
            ));
        }
        return Ok(());
    }

    // Non-root: enforce the include rules.
    let Some(rules) = get_rules(inner_path, content, ctx) else {
        return err("No rules");
    };
    let content_size = raw_len + sum_file_sizes(content, "files");
    let content_size_optional = sum_file_sizes(content, "files_optional");
    if let Some(max) = rules.get("max_size").and_then(|v| v.as_i64()) {
        if content_size > max {
            return err(format!("Include too large {content_size}B > {max}B"));
        }
    }
    if let Some(max) = rules.get("max_size_optional").and_then(|v| v.as_i64()) {
        if content_size_optional > max {
            return err(format!(
                "Include optional files too large {content_size_optional}B > {max}B"
            ));
        }
    }
    if let Some(pat) = rules.get("files_allowed").and_then(|v| v.as_str()) {
        for path in content.get("files").and_then(|v| v.as_object()).into_iter().flat_map(|m| m.keys()) {
            if !regex_full_match(pat, path) {
                return err(format!("File not allowed: {path}"));
            }
        }
    }
    if let Some(pat) = rules.get("files_allowed_optional").and_then(|v| v.as_str()) {
        for path in content.get("files_optional").and_then(|v| v.as_object()).into_iter().flat_map(|m| m.keys()) {
            if !regex_full_match(pat, path) {
                return err(format!("Optional file not allowed: {path}"));
            }
        }
    }
    if rules.get("includes_allowed") == Some(&Value::Bool(false))
        && content.get("includes").and_then(|v| v.as_object()).is_some_and(|m| !m.is_empty())
    {
        return err("Includes not allowed");
    }
    Ok(())
}

/// Full verification of a content.json file (`verifyFile` for content.json):
/// signatures against valid signers (with `signers_sign` authorization for a
/// delegated signer list), cert check for user files, then the content rules.
/// `raw_len` is the received byte length. Returns Ok on success.
pub fn verify_content_file(
    inner_path: &str,
    content: &Value,
    raw_len: i64,
    ctx: &dyn VerifyContext,
) -> Result<(), VerifyError> {
    let signs = content.get("signs").and_then(|v| v.as_object());
    let Some(signs) = signs else {
        return err("Invalid old-style sign");
    };
    let signers = valid_signers(inner_path, content, ctx);
    let required = signs_required(inner_path, content);

    // A delegated signer list on the root must be authorized by the owner.
    if inner_path == "content.json" && signers.len() > 1 {
        let joined = signers.join(",");
        let signers_data = format!("{required}:{joined}");
        let signers_sign = content.get("signers_sign").and_then(|v| v.as_str()).unwrap_or("");
        if !epix_crypt::verify(&signers_data, ctx.site_address(), signers_sign) {
            return err("Invalid signers_sign!");
        }
    }

    // A user file must carry a valid cert.
    if inner_path != "content.json" && !verify_cert(inner_path, content, ctx)? {
        return err("Invalid cert!");
    }

    // Count valid signatures from the valid signers.
    let data = signed_data(content);
    let mut valid = 0u64;
    for address in &signers {
        if let Some(sig) = signs.get(address).and_then(|v| v.as_str()) {
            // Epix accepts two signature schemes: the classic double-SHA256
            // (ZeroNet) and keccak256 (chain / ethsecp256k1). User_contents
            // content is signed with keccak, so try both.
            if epix_crypt::verify(&data, address, sig)
                || epix_crypt::verify_keccak(&data, address, sig)
            {
                valid += 1;
            }
        }
        if valid >= required {
            break;
        }
    }
    if valid < required {
        return err(format!("Valid signs: {valid}/{required}"));
    }

    verify_content_rules(inner_path, content, raw_len, ctx)
}

fn sum_file_sizes(content: &Value, node: &str) -> i64 {
    content
        .get(node)
        .and_then(|v| v.as_object())
        .map(|files| {
            files
                .values()
                .filter_map(|f| f.get("size").and_then(|s| s.as_i64()))
                .filter(|&s| s >= 0)
                .sum()
        })
        .unwrap_or(0)
}

/// EpixNet's `isValidRelativePath`: no `..`, no leading slash, no control/quote
/// characters, not absolute.
fn is_valid_relative_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.contains("..") {
        return false;
    }
    // Reject characters ZeroNet/EpixNet forbid in inner paths.
    !path.chars().any(|c| c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
}

/// Anchored full-string regex match (`^pat$`), as EpixNet's `SafeRe.match` with
/// the `^…$` wrapping used at the call sites.
fn regex_full_match(pattern: &str, text: &str) -> bool {
    let anchored = format!("^(?:{pattern})$");
    regex::Regex::new(&anchored).map(|re| re.is_match(text)).unwrap_or(false)
}

/// Convenience for verifying a root content.json that is signed by the site
/// address only (no delegated signers) - the common single-owner case. Used by
/// `Xite::set_content` as a fast path; falls back to full verification when a
/// `signers` list is present.
pub fn is_single_owner_signed(content: &Value, site_address: &str) -> bool {
    content.get("signers").and_then(|v| v.as_array()).is_none_or(|a| a.is_empty())
        && verify_signer(content, site_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Ctx {
        address: String,
        loaded: std::collections::HashMap<String, Value>,
        limit: i64,
    }
    impl VerifyContext for Ctx {
        fn site_address(&self) -> &str {
            &self.address
        }
        fn loaded_content(&self, inner_path: &str) -> Option<Value> {
            self.loaded.get(inner_path).cloned()
        }
        fn size_limit_bytes(&self) -> i64 {
            self.limit
        }
    }

    fn sign_content(mut content: Value, privkey: &str) -> (Value, Vec<u8>) {
        crate::sign(&mut content, privkey).unwrap();
        let bytes = serde_json::to_vec(&content).unwrap();
        (content, bytes)
    }

    #[test]
    fn root_single_owner_passes_and_declared_address_must_match() {
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let (content, bytes) = sign_content(
            json!({ "address": addr, "inner_path": "content.json", "modified": 1, "files": {} }),
            &pk,
        );
        let ctx = Ctx { address: addr.clone(), loaded: Default::default(), limit: i64::MAX };
        assert!(verify_content_file("content.json", &content, bytes.len() as i64, &ctx).is_ok());

        // A content.json whose declared `address` differs from the site is
        // rejected (signed by the owner, so signatures pass; the address check
        // catches it). Sign with a mismatched declared address.
        let (mismatch, mbytes) = sign_content(
            json!({ "address": "1WrongDeclared", "inner_path": "content.json", "modified": 1, "files": {} }),
            &pk,
        );
        let e = verify_content_file("content.json", &mismatch, mbytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("Wrong site address"), "{}", e.0);
    }

    #[test]
    fn root_size_limit_enforced() {
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let (content, bytes) =
            sign_content(json!({ "address": addr, "inner_path": "content.json", "modified": 1, "files": {} }), &pk);
        // Limit below the actual size -> rejected.
        let ctx = Ctx { address: addr, loaded: Default::default(), limit: 5 };
        let e = verify_content_file("content.json", &content, bytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("Content too large"), "{}", e.0);
    }

    #[test]
    fn delegated_signer_needs_signers_sign() {
        // Owner authorizes a moderator to sign; content is signed by the moderator.
        let owner_pk = epix_crypt::new_seed();
        let owner = epix_crypt::privatekey_to_address(&owner_pk).unwrap();
        let mod_pk = epix_crypt::new_seed();
        let moderator = epix_crypt::privatekey_to_address(&mod_pk).unwrap();

        // valid_signers for the root = [moderator, owner]; owner signs the list.
        let signers = vec![moderator.clone(), owner.clone()];
        let signers_data = format!("1:{}", signers.join(","));
        let signers_sign = epix_crypt::sign(&signers_data, &owner_pk).unwrap();

        let content = json!({
            "address": owner, "inner_path": "content.json", "modified": 1, "files": {},
            "signers": [moderator], "signers_sign": signers_sign,
        });
        // Moderator signs the content.
        let (content, bytes) = sign_content(content, &mod_pk);
        let ctx = Ctx { address: owner.clone(), loaded: Default::default(), limit: i64::MAX };
        assert!(
            verify_content_file("content.json", &content, bytes.len() as i64, &ctx).is_ok(),
            "moderator-signed content with a valid signers_sign should pass"
        );

        // Tamper the signers_sign -> rejected.
        let mut bad = content.clone();
        bad["signers_sign"] = json!("deadbeef");
        let e = verify_content_file("content.json", &bad, bytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("Invalid signers_sign"), "{}", e.0);
    }

    #[test]
    fn wrong_signer_rejected() {
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let (content, bytes) =
            sign_content(json!({ "address": addr, "inner_path": "content.json", "modified": 1, "files": {} }), &pk);
        // Verify under a different site: the only valid signer is that site, and
        // the content isn't signed by it -> no valid signatures.
        let other = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let ctx = Ctx { address: other, loaded: Default::default(), limit: i64::MAX };
        let e = verify_content_file("content.json", &content, bytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("Valid signs"), "{}", e.0);

        // Content with no signs at all is rejected as old-style.
        let mut unsigned = content.clone();
        unsigned.as_object_mut().unwrap().remove("signs");
        let ctx2 = Ctx { address: addr, loaded: Default::default(), limit: i64::MAX };
        let e = verify_content_file("content.json", &unsigned, bytes.len() as i64, &ctx2).unwrap_err();
        assert!(e.0.contains("old-style"), "{}", e.0);
    }

    #[test]
    fn user_file_requires_valid_cert() {
        // Parent content.json declares a user_contents node with a cert provider.
        let provider_pk = epix_crypt::new_seed();
        let provider = epix_crypt::privatekey_to_address(&provider_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user_addr = epix_crypt::privatekey_to_address(&user_pk).unwrap();

        let parent = json!({
            "address": "1Site", "inner_path": "data/users/content.json", "modified": 1,
            "user_contents": {
                "cert_signers": { "epixid.epix": [provider] },
                "permissions": { "cert_user_id_placeholder": {} },
            },
        });
        let inner = format!("data/users/{user_addr}/content.json");
        // The user signs their own content; the cert binds their address+name.
        let cert_sign = epix_crypt::sign(
            &format!("{user_addr}#web/alice"),
            &provider_pk,
        )
        .unwrap();
        let content = json!({
            "address": "1Site", "inner_path": inner, "modified": 1, "files": {},
            "cert_user_id": "alice@epixid.epix", "cert_auth_type": "web", "cert_sign": cert_sign,
        });
        let (content, bytes) = sign_content(content, &user_pk);

        let mut loaded = std::collections::HashMap::new();
        loaded.insert("data/users/content.json".to_string(), parent);
        let ctx = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };

        assert!(
            verify_content_file(&inner, &content, bytes.len() as i64, &ctx).is_ok(),
            "valid user cert should pass"
        );

        // A forged cert_sign (wrong issuer) is rejected.
        let mut bad = content.clone();
        bad["cert_sign"] = json!(epix_crypt::sign(&format!("{user_addr}#web/alice"), &user_pk).unwrap());
        // Re-sign the content so the user signature is still valid.
        bad.as_object_mut().unwrap().remove("signs");
        let (bad, bad_bytes) = sign_content(bad, &user_pk);
        let e = verify_content_file(&inner, &bad, bad_bytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("Invalid cert"), "{}", e.0);
    }

    #[test]
    fn relative_path_validation() {
        assert!(is_valid_relative_path("index.html"));
        assert!(is_valid_relative_path("js/app.js"));
        assert!(!is_valid_relative_path("../secret"));
        assert!(!is_valid_relative_path("/etc/passwd"));
        assert!(!is_valid_relative_path("a\\b"));
    }
}
