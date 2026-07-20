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
    /// Resolve an xID name (e.g. `user.epix`) to the bech32 addresses that may
    /// sign for it (owner + identities). EpixTalk-style user_contents dirs are
    /// named by the user's xID and the content is signed by the identity that
    /// xID belongs to, so a signer given as an xID name must be resolved to
    /// match the signature. The node pre-resolves these; default is empty.
    fn resolve_xid(&self, _name: &str) -> Vec<String> {
        Vec::new()
    }
    /// Read a stored (data) file by inner_path - used by the `max_items` rule,
    /// which counts entries in the data.json files a content.json declares.
    /// Contexts without storage return None, which skips that check.
    fn read_file(&self, _inner_path: &str) -> Option<Vec<u8>> {
        None
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
pub fn get_rules(inner_path: &str, content: &Value, ctx: &dyn VerifyContext) -> Option<Value> {
    if inner_path == "content.json" {
        return Some(serde_json::json!({
            "signers": valid_signers(inner_path, content, ctx),
        }));
    }
    let parts: Vec<&str> = inner_path.split('/').collect();
    // Walk parent directories from the file's OWN directory up to the root -
    // but never the file's own content.json (EpixNet's "Dont check in self
    // dir"): rules for X/content.json come from its parent, else re-verifying
    // a stored include (e.g. data/users/content.json) would match its own
    // user_contents and wrongly demand a cert.
    for cut in (0..parts.len().saturating_sub(1)).rev() {
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
/// the user (by address or cert user id), merge in the regex-keyed
/// `permission_rules`, attach the provider `cert_signers`, set the user's own
/// address as a signer, and forbid nested includes. A port of
/// `getUserContentRules`.
fn user_content_rules(parent: &Value, inner_path: &str, content: &Value) -> Option<Value> {
    let user_contents = parent.get("user_contents")?;
    // The user directory name is the path segment after the user_contents dir.
    let user_address = user_dir_segment(parent, inner_path)?;
    let cert_user_id = content.get("cert_user_id").and_then(|v| v.as_str()).unwrap_or("n-a");
    let cert_auth_type = content.get("cert_auth_type").and_then(|v| v.as_str()).unwrap_or("n-a");
    // The urn permission_rules patterns match against, e.g. `xid/user@xid.epix`.
    let user_urn = format!("{cert_auth_type}/{cert_user_id}");

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

    // permission_rules: regex-keyed defaults merged into the user's rules
    // (larger numbers and longer strings win, lists append). This is how a
    // site grants extra rights across all users - EpixTalk lists its admins
    // as additional `signers` on every user dir so moderation can re-sign
    // any user's content.json.
    let zeroed = serde_json::json!({ "max_size": 0, "max_size_optional": 0 });
    if let Some(prules) = user_contents.get("permission_rules").and_then(|v| v.as_object()) {
        for (pattern, extra) in prules {
            if !regex_prefix_match(pattern, &user_urn) {
                continue;
            }
            // A null rule means "may write nothing" (sizes zeroed).
            let extra = if extra.is_null() { &zeroed } else { extra };
            let Some(extra) = extra.as_object() else { continue };
            for (key, val) in extra {
                match obj.get_mut(key) {
                    None => {
                        obj.insert(key.clone(), val.clone());
                    }
                    Some(cur) => merge_rule_value(cur, val),
                }
            }
        }
    }

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

/// Merge one `permission_rules` value into an already-present rule, with
/// EpixNet's semantics: a larger number wins, a longer string wins, dicts
/// merge per key taking larger values, lists append.
fn merge_rule_value(cur: &mut Value, val: &Value) {
    match (cur, val) {
        (Value::Number(c), Value::Number(v)) => {
            if v.as_f64().unwrap_or(0.0) > c.as_f64().unwrap_or(0.0) {
                *c = v.clone();
            }
        }
        (Value::String(c), Value::String(v)) => {
            if v.len() > c.len() {
                *c = v.clone();
            }
        }
        (Value::Object(c), Value::Object(v)) => {
            for (k, vv) in v {
                match c.get_mut(k) {
                    Some(cv) => merge_rule_value(cv, vv),
                    None => {
                        c.insert(k.clone(), vv.clone());
                    }
                }
            }
        }
        (Value::Array(c), Value::Array(v)) => c.extend(v.iter().cloned()),
        _ => {}
    }
}

/// The xID names whose chain-linked addresses a
/// verifier must resolve before checking a user content.json: the user
/// directory's own name plus any name-form signers the parent's
/// `user_contents` rules grant (site admins for moderation). Callers resolve
/// each and pass the map into verification / signing.
pub fn user_content_xid_names(parent: &Value, inner_path: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let looks_like_name = |s: &str| s.contains('.') && !s.contains('@') && !s.contains('/');
    if let Some(dir) = user_dir_segment(parent, inner_path) {
        if looks_like_name(&dir) {
            names.push(dir);
        }
    }
    if let Some(uc) = parent.get("user_contents") {
        for node in ["permissions", "permission_rules"] {
            let Some(map) = uc.get(node).and_then(|v| v.as_object()) else { continue };
            for entry in map.values() {
                let Some(signers) = entry.get("signers").and_then(|v| v.as_array()) else {
                    continue;
                };
                for s in signers.iter().filter_map(|v| v.as_str()) {
                    if looks_like_name(s) {
                        names.push(s.to_string());
                    }
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// The user-directory segment of `inner_path` relative to the `user_contents`
/// parent (e.g. `data/users/<addr>/data.json` -> `<addr>`).
fn user_dir_segment(parent: &Value, inner_path: &str) -> Option<String> {
    let parent_inner = parent.get("inner_path").and_then(|v| v.as_str()).unwrap_or("content.json");
    let parent_dir = dirname(parent_inner);
    let rest = inner_path.strip_prefix(&parent_dir).unwrap_or(inner_path);
    rest.trim_start_matches('/').split('/').next().map(str::to_string).filter(|s| !s.is_empty())
}

/// The inner_path of the parent content.json governing a child content.json:
/// one directory level up (`data/users/user.epix/content.json` ->
/// `data/users/content.json`), falling back to the root.
pub fn parent_content_path(inner_path: &str) -> String {
    let dir = dirname(inner_path);
    match dir.trim_end_matches('/').rsplit_once('/') {
        Some((up, _)) => format!("{up}/content.json"),
        None => "content.json".to_string(),
    }
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
    for node in ["files", "files_optional", "files_merged"] {
        if let Some(files) = content.get(node).and_then(|v| v.as_object()) {
            for path in files.keys() {
                if !is_valid_relative_path(path) {
                    return err(format!("Invalid relative path: {path}"));
                }
            }
        }
    }
    // A merge file (`files_merged`, verified per-record, no whole-file hash) may
    // NEVER also appear as a hashed file - that would re-arm the last-writer-
    // wins overwrite this class exists to prevent. Universal invariant.
    if let Some(merged) = content.get("files_merged").and_then(|v| v.as_object()) {
        for path in merged.keys() {
            let hashed = ["files", "files_optional"].iter().any(|n| {
                content.get(n).and_then(|v| v.as_object()).is_some_and(|m| m.contains_key(path))
            });
            if hashed {
                return err(format!("Merge file also declared as a hashed file: {path}"));
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
    // A merge file must be allow-listed by the owner's include (`merge_files`),
    // so a user cannot turn an arbitrary file into an unhashed merge file. The
    // owner-signed include is the root of trust; a user-signed `files_merged`
    // entry with no matching owner `merge_files` key is rejected.
    if let Some(merged) = content.get("files_merged").and_then(|v| v.as_object()) {
        let allowed = rules.get("merge_files").and_then(|v| v.as_object());
        for path in merged.keys() {
            if !allowed.is_some_and(|a| a.contains_key(path)) {
                return err(format!("Merge file not allowed: {path}"));
            }
        }
    }
    // `max_items`: cap the entry count of arrays in the declared data.json
    // files (a spam guard for user content: {"comment": 100} allows at most
    // 100 comments). Only checkable when the context can read storage.
    if let Some(max_items) = rules.get("max_items").and_then(|v| v.as_object()) {
        let dir = inner_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
        for rel in content.get("files").and_then(|v| v.as_object()).into_iter().flat_map(|m| m.keys())
        {
            if !rel.ends_with("data.json") {
                continue;
            }
            let Some(bytes) = ctx.read_file(&format!("{dir}{rel}")) else { continue };
            let Ok(data) = serde_json::from_slice::<Value>(&bytes) else { continue };
            for (key, limit) in max_items {
                let Some(limit) = limit.as_i64() else { continue };
                let count =
                    data.get(key).and_then(|v| v.as_array()).map(|a| a.len() as i64).unwrap_or(0);
                if count > limit {
                    return err(format!("Too many items in {rel}.{key}: {count} > {limit}"));
                }
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

    // EpixNet's `isArchived`: a parent may archive a user directory (or
    // everything before a timestamp); content at or before that time is
    // revoked and can no longer be pushed.
    if inner_path != "content.json" && is_archived(inner_path, content, ctx) {
        return err("This file is archived!");
    }

    // Count valid signatures from the valid signers.
    let data = signed_data(content);
    let mut valid = 0u64;
    for address in &signers {
        if let Some(sig) = signs.get(address).and_then(|v| v.as_str()) {
            // Epix accepts two signature schemes: the classic
            // double-SHA256 and keccak256 (chain / ethsecp256k1). User_contents
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

/// EpixNet's `isArchived`: whether the parent's `user_contents` marks this
/// file's directory as archived (`archived[dirname] >= modified`) or the whole
/// tree as archived before a time (`archived_before >= modified`).
fn is_archived(inner_path: &str, content: &Value, ctx: &dyn VerifyContext) -> bool {
    let parent_path = parent_content_path(inner_path);
    let Some(dirname) = inner_path
        .strip_suffix("/content.json")
        .and_then(|d| d.rsplit_once('/').map(|(_, name)| name))
    else {
        return false;
    };
    let Some(parent) = ctx.loaded_content(&parent_path) else { return false };
    let Some(uc) = parent.get("user_contents") else { return false };
    let modified = content.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let before = uc.get("archived_before").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let dir_archived = uc
        .get("archived")
        .and_then(|a| a.get(dirname))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    modified <= before || modified <= dir_archived
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

/// EpixNet's `isValidRelativePath`: no `..` traversal, no leading slash, no
/// control/quote characters, not absolute, and no Windows-reserved device names
/// (a xite carrying `CON/x.txt` would be undownloadable on Windows peers).
fn is_valid_relative_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') {
        return false;
    }
    // Traversal is a whole path SEGMENT equal to `..` (or `.`), not any `..`
    // substring. A dotted filename is fine and common - e.g. a Vite/Nuxt
    // catch-all bundle `assets/_...all_-53e78351.js` from a `[...all]` route.
    // The old `path.contains("..")` rejected those, so a validly-signed content
    // .json failed verification: the clone never finalized and the xite was
    // dropped on restart.
    if path.split('/').any(|segment| segment == ".." || segment == ".") {
        return false;
    }
    // Reject characters EpixNet forbids in inner paths.
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return false;
    }
    // Reserved on Windows, as a directory segment or a file's base name
    // (`CON`, `CON.txt`, and `a/PRN/b` are all invalid there). Uppercase only,
    // exactly like EpixNet's regex - being stricter would reject content that
    // Python nodes accept and split the network.
    !path.split('/').any(|segment| {
        let base = segment.split('.').next().unwrap_or(segment);
        matches!(base, "CON" | "PRN" | "AUX" | "NUL" | "CONOUT$" | "CONIN$")
            || (base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && base.as_bytes()[3].is_ascii_digit()
                && base.as_bytes()[3] != b'0')
    })
}

/// Anchored full-string regex match (`^pat$`), as EpixNet's `SafeRe.match` with
/// the `^…$` wrapping used at the call sites.
fn regex_full_match(pattern: &str, text: &str) -> bool {
    let anchored = format!("^(?:{pattern})$");
    regex::Regex::new(&anchored).map(|re| re.is_match(text)).unwrap_or(false)
}

/// Regex match anchored at the start only - Python `re.match` semantics, which
/// is what `getUserContentRules` uses for `permission_rules` patterns.
fn regex_prefix_match(pattern: &str, text: &str) -> bool {
    let anchored = format!("^(?:{pattern})");
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
    struct DiskCtx {
        files: std::collections::HashMap<String, Value>,
    }
    impl VerifyContext for DiskCtx {
        fn site_address(&self) -> &str { "epix1site" }
        fn loaded_content(&self, inner_path: &str) -> Option<Value> {
            self.files.get(inner_path).cloned()
        }
    }

    #[test]
    fn get_rules_skips_the_files_own_content_json() {
        // Root includes data/users/content.json (which itself has
        // user_contents). Rules for data/users/content.json must come from the
        // ROOT include entry, not from its own user_contents.
        let root = json!({
            "address": "epix1site",
            "includes": { "data/users/content.json": { "signers": ["mud.epix"] } },
        });
        let uc = json!({ "user_contents": { "cert_signers": { "xid.epix": ["chain"] } } });
        let mut files = std::collections::HashMap::new();
        files.insert("content.json".to_string(), root);
        files.insert("data/users/content.json".to_string(), uc.clone());
        let ctx = DiskCtx { files };
        let rules = super::get_rules("data/users/content.json", &uc, &ctx).expect("rules");
        // The include entry (has signers, no cert_signers), not user_contents.
        assert!(rules.get("signers").is_some());
        assert!(rules.get("cert_signers").is_none());
    }

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
    fn permission_rules_grant_moderator_signing_over_user_dirs() {
        // EpixTalk's moderation model: data/users/content.json lists the site
        // admins as extra `signers` under a permission_rules catch-all, so an
        // admin may re-sign any user's content.json (deleting their post).
        let user_pk = epix_crypt::new_seed();
        let user = epix_crypt::privatekey_to_address(&user_pk).unwrap();
        let mod_pk = epix_crypt::new_seed();
        let moderator = epix_crypt::privatekey_to_address(&mod_pk).unwrap();
        let stranger_pk = epix_crypt::new_seed();

        let parent = json!({
            "inner_path": "data/users/content.json",
            "user_contents": {
                "cert_signers": {},
                "permissions": {},
                "permission_rules": {
                    ".*": { "signers": [moderator], "max_size": 100000 },
                },
            }
        });
        let inner = format!("data/users/{user}/content.json");
        let mut loaded = std::collections::HashMap::new();
        loaded.insert("data/users/content.json".to_string(), parent);
        let ctx = Ctx { address: "epix1site".to_string(), loaded, limit: i64::MAX };
        let make = |pk: &str| {
            sign_content(
                json!({
                    "address": "epix1site", "inner_path": inner, "modified": 2,
                    "files": { "data.json": { "size": 10, "sha512": "ab" } },
                }),
                pk,
            )
        };

        // The rule-granted moderator may sign the user's file.
        let (c, b) = make(&mod_pk);
        assert!(verify_content_file(&inner, &c, b.len() as i64, &ctx).is_ok());
        // The user's own key (the dir name) still signs.
        let (c, b) = make(&user_pk);
        assert!(verify_content_file(&inner, &c, b.len() as i64, &ctx).is_ok());
        // Anyone else is rejected.
        let (c, b) = make(&stranger_pk);
        assert!(verify_content_file(&inner, &c, b.len() as i64, &ctx).is_err());

        // The merged max_size is enforced: a parent allowing only 10 bytes
        // rejects this content.json.
        let tiny = json!({
            "inner_path": "data/users/content.json",
            "user_contents": {
                "cert_signers": {},
                "permissions": {},
                "permission_rules": { ".*": { "max_size": 10 } },
            }
        });
        let mut loaded = std::collections::HashMap::new();
        loaded.insert("data/users/content.json".to_string(), tiny);
        let ctx = Ctx { address: "epix1site".to_string(), loaded, limit: i64::MAX };
        let (c, b) = make(&user_pk);
        assert!(verify_content_file(&inner, &c, b.len() as i64, &ctx).is_err());
    }

    #[test]
    fn merge_file_declaration_rules() {
        let user_pk = epix_crypt::new_seed();
        let user = epix_crypt::privatekey_to_address(&user_pk).unwrap();
        let inner = format!("data/users/{user}/content.json");

        // Owner include allows `posts.json` as a merge file.
        let parent = json!({
            "inner_path": "data/users/content.json",
            "user_contents": {
                "cert_signers": {}, "permissions": {},
                "permission_rules": {
                    ".*": { "merge_files": { "posts.json": { "class": "epix-orset-1", "max_size": 3000000 } } },
                },
            }
        });
        let mut loaded = std::collections::HashMap::new();
        loaded.insert("data/users/content.json".to_string(), parent);
        let ctx = Ctx { address: "epix1site".to_string(), loaded, limit: i64::MAX };
        let make = |files_merged: Value, extra_files: Value| {
            sign_content(
                json!({
                    "address": "epix1site", "inner_path": inner, "modified": 2,
                    "files": extra_files,
                    "files_merged": files_merged,
                }),
                &user_pk,
            )
        };

        // Declaring the allowed merge file (no sha512) verifies.
        let (c, b) = make(json!({ "posts.json": { "class": "epix-orset-1" } }), json!({}));
        assert!(verify_content_file(&inner, &c, b.len() as i64, &ctx).is_ok());

        // A merge file the owner did not allow is rejected.
        let (c, b) = make(json!({ "secret.json": { "class": "epix-orset-1" } }), json!({}));
        let e = verify_content_file(&inner, &c, b.len() as i64, &ctx).unwrap_err();
        assert!(format!("{e:?}").contains("Merge file not allowed"), "{e:?}");

        // Declaring the same path as BOTH a merge file and a hashed file is
        // rejected (would re-arm last-writer-wins).
        let (c, b) = make(
            json!({ "posts.json": { "class": "epix-orset-1" } }),
            json!({ "posts.json": { "size": 2, "sha512": "ab" } }),
        );
        let e = verify_content_file(&inner, &c, b.len() as i64, &ctx).unwrap_err();
        assert!(format!("{e:?}").contains("also declared as a hashed file"), "{e:?}");
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
        // Only a `..`/`.` path SEGMENT is traversal, not a `..` substring: a
        // Vite/Nuxt catch-all bundle for a `[...all]` route is legitimate.
        assert!(is_valid_relative_path("assets/_...all_-53e78351.js"));
        assert!(is_valid_relative_path("a..b/c...d.js"));
        assert!(!is_valid_relative_path("../secret"));
        assert!(!is_valid_relative_path("a/../b"));
        assert!(!is_valid_relative_path("a/.."));
        assert!(!is_valid_relative_path("a/./b"));
        assert!(!is_valid_relative_path("/etc/passwd"));
        assert!(!is_valid_relative_path("a\\b"));
        // Windows-reserved device names, matching EpixNet's (uppercase-only)
        // regex: as a segment or a base name, at any depth.
        assert!(!is_valid_relative_path("CON"));
        assert!(!is_valid_relative_path("CON.txt"));
        assert!(!is_valid_relative_path("data/PRN/file.txt"));
        assert!(!is_valid_relative_path("COM1.log"));
        assert!(!is_valid_relative_path("js/LPT9"));
        assert!(is_valid_relative_path("CONFIG.txt")); // prefix only, allowed
        assert!(is_valid_relative_path("COM0.txt")); // COM0 is not reserved
        assert!(is_valid_relative_path("con.txt")); // lowercase, like EpixNet
    }

    /// A user content.json signed by its own dir keypair, with a permissive
    /// user_contents parent - the shared fixture for the rules tests below.
    fn user_content_fixture(
        parent_extra: Value,
        content_extra: Value,
    ) -> (String, Value, Vec<u8>, std::collections::HashMap<String, Value>) {
        let user_pk = epix_crypt::new_seed();
        let user_addr = epix_crypt::privatekey_to_address(&user_pk).unwrap();
        let mut parent = json!({
            "address": "1Site", "inner_path": "data/users/content.json", "modified": 1,
            "user_contents": { "cert_signers": {}, "permissions": {} },
        });
        merge(&mut parent["user_contents"], parent_extra);
        let inner = format!("data/users/{user_addr}/content.json");
        let mut content = json!({
            "address": "1Site", "inner_path": inner, "modified": 100, "files": {},
        });
        merge(&mut content, content_extra);
        let (content, bytes) = sign_content(content, &user_pk);
        let mut loaded = std::collections::HashMap::new();
        loaded.insert("data/users/content.json".to_string(), parent);
        (inner, content, bytes, loaded)
    }

    fn merge(into: &mut Value, from: Value) {
        if let (Some(a), Some(b)) = (into.as_object_mut(), from.as_object()) {
            for (k, v) in b {
                a.insert(k.clone(), v.clone());
            }
        }
    }

    #[test]
    fn archived_user_directory_is_revoked() {
        // The parent archives this user dir at t=500: content modified at or
        // before that is rejected; newer content is accepted again.
        let (inner, content, bytes, loaded) = user_content_fixture(json!({}), json!({}));
        let dirname = inner.split('/').nth(2).unwrap().to_string();

        // archived[dirname] = 500 >= modified 100 -> revoked.
        let mut loaded_archived = loaded.clone();
        loaded_archived.get_mut("data/users/content.json").unwrap()["user_contents"]["archived"] =
            json!({ dirname.clone(): 500 });
        let ctx = Ctx { address: "1Site".into(), loaded: loaded_archived, limit: i64::MAX };
        let e = verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("archived"), "{}", e.0);

        // archived_before = 500 >= modified 100 -> also revoked.
        let mut loaded_before = loaded.clone();
        loaded_before.get_mut("data/users/content.json").unwrap()["user_contents"]
            ["archived_before"] = json!(500);
        let ctx = Ctx { address: "1Site".into(), loaded: loaded_before, limit: i64::MAX };
        let e = verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("archived"), "{}", e.0);

        // No archive rules -> passes.
        let ctx = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };
        assert!(verify_content_file(&inner, &content, bytes.len() as i64, &ctx).is_ok());
    }

    /// Ctx variant whose read_file serves an in-memory data.json, for the
    /// max_items check.
    struct DataCtx {
        inner: Ctx,
        data: std::collections::HashMap<String, Vec<u8>>,
    }
    impl VerifyContext for DataCtx {
        fn site_address(&self) -> &str {
            self.inner.site_address()
        }
        fn loaded_content(&self, inner_path: &str) -> Option<Value> {
            self.inner.loaded_content(inner_path)
        }
        fn read_file(&self, inner_path: &str) -> Option<Vec<u8>> {
            self.data.get(inner_path).cloned()
        }
    }

    #[test]
    fn max_items_rule_caps_data_json_arrays() {
        // permission_rules grant max_items {comment: 2}; a data.json with 3
        // comments is rejected, 2 pass.
        let (inner, content, bytes, loaded) = user_content_fixture(
            json!({ "permission_rules": { ".*": { "max_items": { "comment": 2 } } } }),
            json!({ "files": { "data.json": { "size": 1, "sha512": "00" } } }),
        );
        let dir = inner.rsplit_once('/').unwrap().0;
        let base = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };

        let mut data = std::collections::HashMap::new();
        data.insert(
            format!("{dir}/data.json"),
            serde_json::to_vec(&json!({ "comment": [1, 2, 3] })).unwrap(),
        );
        let ctx = DataCtx { inner: base, data };
        let e = verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("Too many items"), "{}", e.0);

        let mut data = std::collections::HashMap::new();
        data.insert(
            format!("{dir}/data.json"),
            serde_json::to_vec(&json!({ "comment": [1, 2] })).unwrap(),
        );
        let ctx = DataCtx {
            inner: Ctx { address: "1Site".into(), loaded: ctx.inner.loaded, limit: i64::MAX },
            data,
        };
        assert!(verify_content_file(&inner, &content, bytes.len() as i64, &ctx).is_ok());
    }
}
