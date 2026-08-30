//! Deep content.json verification - the rules EpixNet's `ContentManager`
//! enforces beyond a single root signature:
//!
//! - **Valid signers + `signers_sign`**: a root content.json may delegate signing
//!   to extra `signers`; that signer list must itself be authorized by the xite
//!   owner (`signers_sign`), and the content must carry a valid signature from
//!   one of the valid signers (`signs_required`, default 1).
//! - **Certs** (`user_contents`): a user file under a `user_contents` node must
//!   carry a `cert_user_id`/`cert_sign` issued by an accepted `cert_signers`
//!   provider, verified against the user's address.
//! - **Content rules**: address + inner_path match, valid relative paths and
//!   file metadata, size-limit enforcement, and per-include `max_size` /
//!   `max_size_optional` / `files_allowed` / `files_allowed_optional` /
//!   `includes_allowed`.
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

/// Decode a manifest byte size without changing the signed JSON value.
/// Integer-form JSON may use the full nonnegative i64 range. Legacy and
/// foreign signers may encode the same value as an integral float (`10.0`),
/// which is accepted only inside IEEE-754's exact integer range. This keeps
/// every consumer on one representation without accepting rounded magnitudes.
pub fn exact_nonnegative_size(value: &Value) -> Option<i64> {
    if let Some(size) = value.as_i64() {
        return (size >= 0).then_some(size);
    }
    // Keep the boundary strictly below 2^53. serde_json stores float-form
    // numbers as f64, so the signed lexeme `9007199254740993.0` has already
    // rounded to 2^53 by the time it reaches this function. Rejecting 2^53
    // prevents that imprecise magnitude from being accepted as a different
    // declared size.
    const MAX_EXACT_FLOAT_INTEGER: f64 = 9_007_199_254_740_991.0;
    let size = value.as_f64()?;
    if !size.is_finite()
        || size.is_sign_negative()
        || size.fract() != 0.0
        || size > MAX_EXACT_FLOAT_INTEGER
    {
        return None;
    }
    let integer = size as i64;
    ((integer as f64) == size).then_some(integer)
}

/// Two conservative, platform-independent case keys for signed filesystem
/// destinations. Using both catches ordinary Unicode case pairs (`Ä`/`ä`)
/// and one-to-many uppercase expansions (`straße`/`STRASSE`) without making
/// the protocol reject otherwise valid non-ASCII filenames.
pub fn portable_path_case_keys(path: &str) -> (String, String) {
    (path.to_lowercase(), path.to_uppercase())
}

/// One chain-linked identity of an xID name, as the chain's domain record
/// carries it: the identity address plus its revocation state. The node
/// pre-resolves names into a [`XidMap`] and verification consumes it through
/// [`VerifyContext::resolve_xid_identities`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XidIdentity {
    pub address: String,
    pub active: bool,
    /// Unix time the identity was revoked at (0 = not revoked).
    pub revoked_at_time: u64,
}

/// Pre-resolved xID names -> their linked identity records.
pub type XidMap = std::collections::HashMap<String, Vec<XidIdentity>>;

/// The signer addresses an identity list yields: every linked identity,
/// active or revoked (revoked identities' already-signed content stays
/// valid; the cert check bounds what a revoked identity may still push).
pub fn xid_identity_addresses(identities: &[XidIdentity]) -> Vec<String> {
    identities.iter().map(|identity| identity.address.clone()).collect()
}

/// What a verifier needs from the surrounding xite: the xite address, the size
/// limit, and any already-loaded parent content.json values (to resolve the
/// rules for an included/user file).
pub trait VerifyContext {
    /// The xite's signed address (`epix1…`).
    fn xite_address(&self) -> &str;
    /// A loaded (already-verified) content.json by its inner_path, for rules.
    fn loaded_content(&self, inner_path: &str) -> Option<Value>;
    /// The xite's effective size limit in bytes (root content.json guard).
    fn size_limit_bytes(&self) -> i64 {
        i64::MAX
    }
    /// Resolve an xID name (e.g. `user.epix`) to the bech32 addresses that may
    /// sign for it (owner + identities). EpixTalk-style user_contents dirs are
    /// named by the user's xID and the content is signed by the identity that
    /// xID belongs to, so a signer given as an xID name must be resolved to
    /// match the signature. The node pre-resolves these.
    ///
    /// Derived from [`resolve_xid_identities`](Self::resolve_xid_identities),
    /// so a context that serves identity records gets this for free and an
    /// unresolved name stays empty. Override only to answer with addresses a
    /// context holds without the surrounding identity records.
    fn resolve_xid(&self, name: &str) -> Vec<String> {
        self.resolve_xid_identities(name)
            .map(|identities| xid_identity_addresses(&identities))
            .unwrap_or_default()
    }
    /// Full identity records for an xID name (chain-cert verification needs
    /// each linked address with its active flag and revocation time, not just
    /// the address list). `None` means the name is not resolved - the chain
    /// cert check fails closed, exactly like a dot-form dir signer whose
    /// [`resolve_xid`](Self::resolve_xid) came back empty.
    fn resolve_xid_identities(&self, _name: &str) -> Option<Vec<XidIdentity>> {
        None
    }
    /// Read a stored (data) file by inner_path - used by the `max_items` rule,
    /// which counts entries in the data.json files a content.json declares.
    /// Contexts without storage return None, which skips that check.
    fn read_file(&self, _inner_path: &str) -> Option<Vec<u8>> {
        None
    }
}

/// The valid signer addresses for `inner_path`: the declared `signers` (root
/// `signers`, or an include/user rule's `signers`) plus the xite address, which
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
    let xite = ctx.xite_address().to_string();
    if !signers.contains(&xite) {
        signers.push(xite);
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

/// The stored content.json whose current rules govern `inner_path`. Includes
/// may skip directory levels, so this cannot be derived by removing one path
/// segment. Archive replay uses the exact governing path to require a verified
/// trust chain before executing a child's destructive directives.
pub fn governing_content_path(inner_path: &str, ctx: &dyn VerifyContext) -> Option<String> {
    if inner_path == "content.json" {
        return Some("content.json".to_string());
    }
    let parts: Vec<&str> = inner_path.split('/').collect();
    for cut in (0..parts.len().saturating_sub(1)).rev() {
        let parent_dir = parts[..cut].join("/");
        let candidate = if parent_dir.is_empty() {
            "content.json".to_string()
        } else {
            format!("{parent_dir}/content.json")
        };
        let Some(parent) = ctx.loaded_content(&candidate) else {
            continue;
        };
        let relative = parts[cut..].join("/");
        let declared_include = parent
            .get("includes")
            .and_then(Value::as_object)
            .is_some_and(|includes| includes.contains_key(&relative));
        if declared_include || parent.get("user_contents").is_some() {
            return Some(candidate);
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
    // xite grants extra rights across all users - EpixTalk lists its admins
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
/// `user_contents` rules grant (xite admins for moderation). Callers resolve
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

/// Every xID name whose current signer addresses may authorize one child
/// content.json through this exact parent. This includes ordinary `includes`
/// signer rules as well as the user-content names handled by
/// [`user_content_xid_names`].
pub fn content_xid_names(parent: &Value, inner_path: &str) -> Vec<String> {
    let mut names = user_content_xid_names(parent, inner_path);
    let looks_like_name = |value: &str| {
        value.contains('.') && !value.contains('@') && !value.contains('/')
    };
    let parent_inner = parent
        .get("inner_path")
        .and_then(Value::as_str)
        .unwrap_or("content.json");
    let parent_dir = dirname(parent_inner);
    let relative = inner_path
        .strip_prefix(&parent_dir)
        .unwrap_or(inner_path)
        .trim_start_matches('/');
    if let Some(signers) = parent
        .get("includes")
        .and_then(Value::as_object)
        .and_then(|includes| includes.get(relative))
        .and_then(|rules| rules.get("signers"))
        .and_then(Value::as_array)
    {
        for signer in signers.iter().filter_map(Value::as_str) {
            if looks_like_name(signer) {
                names.push(signer.to_string());
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

/// `data/xite/content.json` -> `data/xite/` (EpixNet's `helper.getDirname`).
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
    // chain), not a static ECC address.
    if issuers.iter().any(|i| i == "chain") {
        return verify_chain_cert(name, content, &rules, ctx);
    }
    let cert_address = issuers[0].clone();
    let user_address = rules.get("user_address").and_then(|v| v.as_str()).unwrap_or("");
    let auth_type = content.get("cert_auth_type").and_then(|v| v.as_str()).unwrap_or("");
    let cert_sign = content.get("cert_sign").and_then(|v| v.as_str()).unwrap_or("");
    Ok(verify_cert_sign(user_address, auth_type, name, &cert_address, cert_sign))
}

/// Grace period for clock drift between the chain's block time and a user's
/// content `modified` stamp: content modified within this window after a
/// revocation is still accepted (the archived Python XidResolver's
/// `REVOCATION_GRACE_PERIOD`).
const REVOCATION_GRACE_PERIOD_SECS: f64 = 60.0;

/// The chain resolution key for an xID cert name (`alice` -> `alice.epix`).
fn xid_fqdn(name: &str) -> String {
    if name.contains('.') {
        name.to_string()
    } else {
        format!("{name}.epix")
    }
}

/// The xID name a chain-delegated cert needs pre-resolved before its child
/// verifies: the `cert_user_id` name part as an fqdn, when the governing
/// parent's `cert_signers` delegates that domain to the chain. Callers add it
/// to the names they resolve into the xid map alongside the dir/signer names
/// from [`content_xid_names`].
pub fn chain_cert_xid_name(parent: &Value, content: &Value) -> Option<String> {
    let cert_user_id = content.get("cert_user_id")?.as_str()?;
    let (name, domain) = cert_user_id.rsplit_once('@')?;
    parent
        .get("user_contents")?
        .get("cert_signers")?
        .get(domain)?
        .as_array()?
        .iter()
        .any(|issuer| issuer.as_str() == Some("chain"))
        .then(|| xid_fqdn(name))
}

/// Verify a chain-delegated cert: `cert_sign` is the user's auth key over
/// `{auth_address}#xid/{name}` (keccak/ethsecp256k1, self-signed at acquire
/// time), so the recovered signer must be an identity the chain links to the
/// xID name - active, or revoked with the content modified before the
/// revocation plus grace. A port of the archived Python
/// `XidResolverPlugin._verifyXidCert`.
fn verify_chain_cert(
    name: &str,
    content: &Value,
    rules: &Value,
    ctx: &dyn VerifyContext,
) -> Result<bool, VerifyError> {
    let Some(cert_sign) = content.get("cert_sign").and_then(|v| v.as_str()) else {
        return err("Missing cert_sign for xID cert");
    };
    let Some(user_address) = rules.get("user_address").and_then(|v| v.as_str()) else {
        return err("Cannot determine user address from rules");
    };
    let Some(identities) = ctx.resolve_xid_identities(&xid_fqdn(name)) else {
        return err(format!("xID name '{name}' not found on chain"));
    };
    // The identity the cert_sign recovers to. A dir named by the xID itself
    // has no single auth address, so every linked identity is a candidate; a
    // raw-address dir must recover to exactly that address.
    let signer_address = if user_address.contains('.') {
        let matched = identities.iter().find(|identity| {
            let subject = format!("{}#xid/{name}", identity.address);
            epix_crypt::get_sign_address_keccak(&subject, cert_sign)
                .is_ok_and(|recovered| recovered == identity.address)
        });
        match matched {
            Some(identity) => identity.address.clone(),
            None => return err("No linked identity matches xID cert signature"),
        }
    } else {
        let subject = format!("{user_address}#xid/{name}");
        match epix_crypt::get_sign_address_keccak(&subject, cert_sign) {
            Ok(recovered) if recovered == user_address => recovered,
            Ok(recovered) => {
                return err(format!(
                    "xID cert signature mismatch: recovered {recovered}, expected {user_address}"
                ))
            }
            Err(_) => return err("Could not recover address from xID cert signature"),
        }
    };
    let Some(identity) = identities.iter().find(|i| i.address == signer_address) else {
        return err(format!(
            "Identity address {signer_address} not linked to xID '{name}'"
        ));
    };
    if identity.active {
        return Ok(true);
    }
    // Revoked: content signed before the revocation stays valid; anything
    // stamped at or after `revoked_at_time` + grace is rejected. Without a
    // usable timestamp on either side, reject.
    let modified = content.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
    if identity.revoked_at_time == 0 || modified <= 0.0 {
        return err(format!(
            "Identity address {signer_address} has been revoked from xID '{name}'"
        ));
    }
    let cutoff = identity.revoked_at_time as f64 + REVOCATION_GRACE_PERIOD_SECS;
    if modified >= cutoff {
        return err(format!(
            "Identity {signer_address} was revoked at {} but content was modified at {modified}",
            identity.revoked_at_time
        ));
    }
    Ok(true)
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
    // Address must match the xite.
    if let Some(addr) = content.get("address").and_then(|v| v.as_str()) {
        if addr != ctx.xite_address() {
            return err(format!("Wrong xite address: {addr} != {}", ctx.xite_address()));
        }
    }
    // inner_path must match (normalizing backslashes).
    if let Some(ip) = content.get("inner_path").and_then(|v| v.as_str()) {
        if ip.replace('\\', "/") != inner_path.replace('\\', "/") {
            return err(format!("Wrong inner_path: {ip}"));
        }
    }
    verify_file_metadata(content)?;
    // A merge file (`files_merged`, verified per-record, no whole-file hash)
    // may NEVER also appear as a hashed file - that would re-arm the
    // last-writer-wins overwrite this class exists to prevent. Universal
    // invariant, checked before the generic destination-collision loop so
    // the specific error is the one reported.
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
    // Valid relative filenames.
    let destination_prefix = dirname(inner_path);
    let mut lower_destinations = std::collections::HashMap::new();
    let mut upper_destinations = std::collections::HashMap::new();
    for node in ["files", "files_optional", "files_merged", "includes"] {
        if let Some(files) = content.get(node).and_then(|v| v.as_object()) {
            for path in files.keys() {
                if !is_valid_relative_path(path) {
                    return err(format!("Invalid relative path: {path}"));
                }
                if node == "files_merged" && is_merge_manifest_alias(path) {
                    return err(format!("Merge file aliases content.json: {path}"));
                }
                let full = format!("{destination_prefix}{path}");
                let (lower, upper) = portable_path_case_keys(&full);
                let previous = lower_destinations
                    .get(&lower)
                    .or_else(|| upper_destinations.get(&upper));
                if let Some(previous) = previous {
                    return err(format!(
                        "Case-insensitive content destination collision: {previous} and {node}:{path}"
                    ));
                }
                let declaration = format!("{node}:{path}");
                lower_destinations.insert(lower, declaration.clone());
                upper_destinations.insert(upper, declaration);
            }
        }
    }
    // A declared `pool` directory holds anonymous, union-merged envelope shards
    // (class epix-pool-1). No hashed / optional / merge file may live under it:
    // such a file would make an envelope attributable (defeating the whole point)
    // and would collide with the pool's own union-write path. Universal invariant.
    let pool_dirs: Vec<String> =
        crate::pool::pool_rules_of(content).into_iter().map(|r| r.dir).collect();
    if !pool_dirs.is_empty() {
        for node in ["files", "files_optional", "files_merged"] {
            if let Some(files) = content.get(node).and_then(|v| v.as_object()) {
                for path in files.keys() {
                    if pool_dirs
                        .iter()
                        .any(|d| path == d || path.starts_with(&format!("{d}/")))
                    {
                        return err(format!("File under a pool directory: {path}"));
                    }
                }
            }
        }
    }
    // Validate each aggregate even for a root manifest. Root files are not
    // constrained by include max_size rules, but clone progress and settings
    // store their totals in i64 and must never receive a signed overflowing
    // set.
    let files_size = sum_file_sizes(content, "files")?;
    let files_size_optional = sum_file_sizes(content, "files_optional")?;

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
    let content_size = raw_len
        .checked_add(files_size)
        .ok_or_else(|| VerifyError("files size total overflow".to_string()))?;
    let content_size_optional = files_size_optional;
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

/// Validate hashed file declarations before any caller enumerates them.
/// Epix hashes are the first 32 bytes of SHA-512, encoded as 64 hex
/// characters. BLAKE3 object IDs use the same encoded length. File consumers
/// use signed `i64` sizes, so values outside that range are not valid metadata.
fn verify_file_metadata(content: &Value) -> Result<(), VerifyError> {
    for node in ["files", "files_optional"] {
        let Some(value) = content.get(node) else { continue };
        let Some(files) = value.as_object() else {
            return err(format!("Invalid {node}: expected an object"));
        };
        for (path, value) in files {
            let Some(metadata) = value.as_object() else {
                return err(format!("Invalid {node} entry {path}: expected an object"));
            };
            // Every consumer uses the same exact decoder. Integral floats from
            // legacy signers remain valid without bypassing availability or
            // aggregate-size checks.
            let size_ok = metadata
                .get("size")
                .and_then(exact_nonnegative_size)
                .is_some();
            if !size_ok {
                return err(format!(
                    "Invalid {node} entry {path}: size must be a nonnegative integer"
                ));
            }
            if !metadata.get("sha512").is_some_and(is_lower_hash_hex) {
                return err(format!(
                    "Invalid {node} entry {path}: sha512 must be 64 lowercase hexadecimal characters"
                ));
            }
            if metadata.get("b3").is_some_and(|value| !is_hash_hex(value)) {
                return err(format!(
                    "Invalid {node} entry {path}: b3 must be 64 hexadecimal characters"
                ));
            }
        }
    }
    Ok(())
}

fn is_hash_hex(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn is_lower_hash_hex(value: &Value) -> bool {
    value.as_str().is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
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
        if !epix_crypt::verify(&signers_data, ctx.xite_address(), signers_sign) {
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

/// The structural manifest rules alone (path validity, case-insensitive
/// destination collisions, merge/hashed exclusivity, size aggregation) with
/// no signature or signer-authorization checks. [`verify_content_file`]
/// enforces these same rules on every load, so a signer must run this on a
/// freshly built manifest BEFORE committing it: a manifest failing them
/// would sign fine and then be rejected by this very node on restart,
/// bricking the xite at sign time.
pub fn verify_content_structure(
    inner_path: &str,
    content: &Value,
    raw_len: i64,
    ctx: &dyn VerifyContext,
) -> Result<(), VerifyError> {
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

fn sum_file_sizes(content: &Value, node: &str) -> Result<i64, VerifyError> {
    let Some(files) = content.get(node).and_then(Value::as_object) else {
        return Ok(0);
    };
    let mut total = 0i64;
    for size in files
        .values()
        .filter_map(|file| file.get("size").and_then(exact_nonnegative_size))
    {
        total = total
            .checked_add(size)
            .ok_or_else(|| VerifyError(format!("{node} size total overflow")))?;
    }
    Ok(total)
}

/// EpixNet's `isValidRelativePath`: no `..` traversal, no leading slash, no
/// control/quote characters, not absolute, and no Windows-reserved device names
/// (a xite carrying `CON/x.txt` would be undownloadable on Windows peers).
/// Whether a protocol inner path has one canonical, portable filesystem form.
/// Recovery uses this same gate before trusting journal paths.
pub fn is_valid_relative_path(path: &str) -> bool {
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return false;
    }
    // Traversal is a whole path SEGMENT equal to `..` (or `.`), not any `..`
    // substring. A dotted filename is fine and common - e.g. a Vite/Nuxt
    // catch-all bundle `assets/_...all_-53e78351.js` from a `[...all]` route.
    // The old `path.contains("..")` rejected those, so a validly-signed content
    // .json failed verification: the clone never finalized and the xite was
    // dropped on restart.
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == ".." || segment == ".")
    {
        return false;
    }
    // Reject characters EpixNet forbids in inner paths.
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return false;
    }
    // Windows ignores trailing spaces/dots and treats device names
    // case-insensitively. Reject those aliases on every platform so two peers
    // cannot map one signed path to different files.
    !path.split('/').any(|segment| {
        let trimmed = segment.trim_end_matches([' ', '.']);
        if trimmed.is_empty() || trimmed != segment {
            return true;
        }
        let base = trimmed.split('.').next().unwrap_or(trimmed).to_ascii_uppercase();
        matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONOUT$" | "CONIN$")
            || (base.len() == 4
                && (base.starts_with("COM") || base.starts_with("LPT"))
                && base.as_bytes()[3].is_ascii_digit()
                && base.as_bytes()[3] != b'0')
    })
}

/// Whether a merge-file path's Windows-normalized terminal component aliases
/// a content manifest. State uses the same predicate before taking path locks.
pub fn is_merge_manifest_alias(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let terminal = normalized.rsplit('/').next().unwrap_or(&normalized);
    terminal
        .trim_end_matches([' ', '.'])
        .eq_ignore_ascii_case("content.json")
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

/// Convenience for verifying a root content.json that is signed by the xite
/// address only (no delegated signers) - the common single-owner case. Used by
/// `Xite::set_content` as a fast path; falls back to full verification when a
/// `signers` list is present.
pub fn is_single_owner_signed(content: &Value, xite_address: &str) -> bool {
    content.get("signers").and_then(|v| v.as_array()).is_none_or(|a| a.is_empty())
        && verify_signer(content, xite_address)
}

#[cfg(test)]
mod tests {
    struct DiskCtx {
        files: std::collections::HashMap<String, Value>,
    }
    impl VerifyContext for DiskCtx {
        fn xite_address(&self) -> &str { "epix1site" }
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

    #[test]
    fn exact_size_accepts_legacy_integral_floats_without_rounded_magnitudes() {
        assert_eq!(exact_nonnegative_size(&json!(0)), Some(0));
        assert_eq!(exact_nonnegative_size(&json!(i64::MAX)), Some(i64::MAX));
        assert_eq!(exact_nonnegative_size(&json!(1.0)), Some(1));
        assert_eq!(
            exact_nonnegative_size(&json!(9_007_199_254_740_991.0)),
            Some(9_007_199_254_740_991)
        );

        for invalid in [
            json!(-1),
            json!(-0.0),
            json!(1.5),
            json!(u64::MAX),
            json!("1"),
            serde_json::from_str("9007199254740993.0").unwrap(),
        ] {
            assert_eq!(exact_nonnegative_size(&invalid), None, "{invalid}");
        }
        assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
        assert!(serde_json::Number::from_f64(f64::NAN).is_none());
    }

    struct Ctx {
        address: String,
        loaded: std::collections::HashMap<String, Value>,
        limit: i64,
    }
    impl VerifyContext for Ctx {
        fn xite_address(&self) -> &str {
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

        // A content.json whose declared `address` differs from the xite is
        // rejected (signed by the owner, so signatures pass; the address check
        // catches it). Sign with a mismatched declared address.
        let (mismatch, mbytes) = sign_content(
            json!({ "address": "1WrongDeclared", "inner_path": "content.json", "modified": 1, "files": {} }),
            &pk,
        );
        let e = verify_content_file("content.json", &mismatch, mbytes.len() as i64, &ctx).unwrap_err();
        assert!(e.0.contains("Wrong xite address"), "{}", e.0);
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
    fn root_required_and_optional_size_totals_reject_overflow() {
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let ctx = Ctx {
            address: addr.clone(),
            loaded: Default::default(),
            limit: i64::MAX,
        };

        for node in ["files", "files_optional"] {
            let mut content = json!({
                "address": addr.clone(),
                "inner_path": "content.json",
                "modified": 1,
                "files": {},
                "files_optional": {},
            });
            content[node] = json!({
                "first.bin": { "size": i64::MAX, "sha512": "a".repeat(64) },
                "second.bin": { "size": 1, "sha512": "b".repeat(64) },
            });
            let (content, bytes) = sign_content(content, &pk);
            let error = verify_content_file("content.json", &content, bytes.len() as i64, &ctx)
                .unwrap_err();
            assert!(
                error.0.contains(&format!("{node} size total overflow")),
                "{node}: {}",
                error.0
            );
        }
    }

    #[test]
    fn root_file_metadata_requires_sizes_and_64_character_hashes() {
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let ctx = Ctx { address: addr.clone(), loaded: Default::default(), limit: i64::MAX };

        let (valid, bytes) = sign_content(
            json!({
                "address": addr,
                "inner_path": "content.json",
                "modified": 1,
                "files": {
                    "required.bin": {
                        "size": 1.0,
                        "sha512": "a".repeat(64),
                        "b3": "B".repeat(64),
                    },
                },
                "files_optional": {
                    "optional.bin": { "size": 1, "sha512": "0".repeat(64) },
                },
            }),
            &pk,
        );
        assert!(
            verify_content_file("content.json", &valid, bytes.len() as i64, &ctx).is_ok()
        );

        for node in ["files", "files_optional"] {
            let mut content = json!({
                "address": ctx.address,
                "inner_path": "content.json",
                "modified": 1,
                "files": {},
                "files_optional": {},
            });
            content[node] = json!([]);
            let (content, bytes) = sign_content(content, &pk);
            let error =
                verify_content_file("content.json", &content, bytes.len() as i64, &ctx).unwrap_err();
            assert!(error.0.contains("expected an object"), "{node}: {}", error.0);
        }

        let malformed = [
            ("non-object entry", json!(null), "expected an object"),
            ("empty entry", json!({}), "size must be a nonnegative integer"),
            (
                "string size",
                json!({ "size": "1", "sha512": "a".repeat(64) }),
                "size must be a nonnegative integer",
            ),
            (
                "negative size",
                json!({ "size": -1, "sha512": "a".repeat(64) }),
                "size must be a nonnegative integer",
            ),
            (
                "fractional size",
                json!({ "size": 1.5, "sha512": "a".repeat(64) }),
                "size must be a nonnegative integer",
            ),
            ("missing sha512", json!({ "size": 1 }), "sha512 must be 64"),
            (
                "short sha512",
                json!({ "size": 1, "sha512": "ab" }),
                "sha512 must be 64",
            ),
            (
                "non-hex sha512",
                json!({ "size": 1, "sha512": "z".repeat(64) }),
                "sha512 must be 64",
            ),
            (
                "uppercase sha512",
                json!({ "size": 1, "sha512": "A".repeat(64) }),
                "sha512 must be 64 lowercase",
            ),
            (
                "non-string b3",
                json!({ "size": 1, "sha512": "a".repeat(64), "b3": 1 }),
                "b3 must be 64",
            ),
            (
                "short b3",
                json!({ "size": 1, "sha512": "a".repeat(64), "b3": "ab" }),
                "b3 must be 64",
            ),
            (
                "non-hex b3",
                json!({ "size": 1, "sha512": "a".repeat(64), "b3": "z".repeat(64) }),
                "b3 must be 64",
            ),
        ];
        for node in ["files", "files_optional"] {
            for (case, metadata, expected) in &malformed {
                let mut content = json!({
                    "address": ctx.address,
                    "inner_path": "content.json",
                    "modified": 1,
                    "files": {},
                    "files_optional": {},
                });
                content[node]["gate.bin"] = metadata.clone();
                let (content, bytes) = sign_content(content, &pk);
                let error = verify_content_file(
                    "content.json",
                    &content,
                    bytes.len() as i64,
                    &ctx,
                )
                .unwrap_err();
                assert!(
                    error.0.contains(expected),
                    "{node} {case}: {}",
                    error.0
                );
            }
        }
    }

    #[test]
    fn permission_rules_grant_moderator_signing_over_user_dirs() {
        // EpixTalk's moderation model: data/users/content.json lists the xite
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
                    "files": { "data.json": { "size": 10, "sha512": "a".repeat(64) } },
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
            json!({ "posts.json": { "size": 2, "sha512": "a".repeat(64) } }),
        );
        let e = verify_content_file(&inner, &c, b.len() as i64, &ctx).unwrap_err();
        assert!(format!("{e:?}").contains("also declared as a hashed file"), "{e:?}");

        let merge_value = |path: &str| {
            let mut merged = serde_json::Map::new();
            merged.insert(path.to_string(), json!({ "class": "epix-orset-1" }));
            Value::Object(merged)
        };
        for alias in ["content.json", "nested/content.json", "nested/Content.Json"] {
            let (c, b) = make(merge_value(alias), json!({}));
            let e = verify_content_file(&inner, &c, b.len() as i64, &ctx).unwrap_err();
            assert!(e.0.contains("aliases content.json"), "{alias}: {}", e.0);
        }
        for alias in ["content.json.", "nested/CONTENT.JSON "] {
            assert!(is_merge_manifest_alias(alias), "{alias}");
            let (c, b) = make(merge_value(alias), json!({}));
            let e = verify_content_file(&inner, &c, b.len() as i64, &ctx).unwrap_err();
            assert!(e.0.contains("Invalid relative path"), "{alias}: {}", e.0);
        }
        assert!(is_merge_manifest_alias(r"nested\Content.Json. "));
        assert!(!is_merge_manifest_alias("nested/not-content.json"));
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
        // Verify under a different xite: the only valid signer is that xite, and
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
        assert!(!is_valid_relative_path("a//b"));
        assert!(!is_valid_relative_path("a/"));
        assert!(!is_valid_relative_path("/etc/passwd"));
        assert!(!is_valid_relative_path("a\\b"));
        assert!(!is_valid_relative_path("file.txt:stream"));
        assert!(!is_valid_relative_path("name."));
        assert!(!is_valid_relative_path("name "));
        assert!(!is_valid_relative_path("dir./file"));
        // Windows-reserved device names are case-insensitive, as a segment or
        // a file's base name, at any depth.
        assert!(!is_valid_relative_path("CON"));
        assert!(!is_valid_relative_path("CON.txt"));
        assert!(!is_valid_relative_path("con.txt"));
        assert!(!is_valid_relative_path("data/PRN/file.txt"));
        assert!(!is_valid_relative_path("data/prn/file.txt"));
        assert!(!is_valid_relative_path("aux"));
        assert!(!is_valid_relative_path("nul.bin"));
        assert!(!is_valid_relative_path("ConIn$"));
        assert!(!is_valid_relative_path("conout$.log"));
        assert!(!is_valid_relative_path("COM1.log"));
        assert!(!is_valid_relative_path("com9.log"));
        assert!(!is_valid_relative_path("js/LPT9"));
        assert!(!is_valid_relative_path("js/lpt1.txt"));
        assert!(is_valid_relative_path("CONFIG.txt")); // prefix only, allowed
        assert!(is_valid_relative_path("COM0.txt")); // COM0 is not reserved
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
    fn child_file_metadata_is_verified_before_commit_enumeration() {
        let (inner, content, bytes, loaded) = user_content_fixture(
            json!({}),
            json!({ "files": { "gate.bin": {} } }),
        );
        let ctx = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };

        let error = verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
        assert!(error.0.contains("size must be a nonnegative integer"), "{}", error.0);
    }

    #[test]
    fn signed_manifest_rejects_case_folded_paths_in_one_section() {
        for extra in [
            json!({
                "files": {
                    "Media/Foo.bin": { "size": 1, "sha512": "a".repeat(64) },
                    "media/foo.BIN": { "size": 1, "sha512": "b".repeat(64) },
                },
            }),
            json!({
                "includes": {
                    "Users/A/content.json": {},
                    "users/a/CONTENT.JSON": {},
                },
            }),
            json!({
                "files": {
                    "Media/Ä.bin": { "size": 1, "sha512": "a".repeat(64) },
                    "media/ä.BIN": { "size": 1, "sha512": "b".repeat(64) },
                },
            }),
            json!({
                "files": {
                    "straße.bin": { "size": 1, "sha512": "a".repeat(64) },
                    "STRASSE.BIN": { "size": 1, "sha512": "b".repeat(64) },
                },
            }),
        ] {
            let (inner, content, bytes, loaded) =
                user_content_fixture(json!({}), extra);
            let ctx = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };

            let error =
                verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
            assert!(
                error.0.contains("Case-insensitive content destination collision"),
                "{}",
                error.0
            );
        }
    }

    #[test]
    fn signed_manifest_rejects_case_folded_paths_across_sections() {
        for extra in [
            json!({
                "files": {
                    "Media/Foo.bin": { "size": 1, "sha512": "a".repeat(64) },
                },
                "files_optional": {
                    "media/foo.BIN": { "size": 1, "sha512": "b".repeat(64) },
                },
            }),
            json!({
                "files": {
                    "Media/Foo.bin": { "size": 1, "sha512": "a".repeat(64) },
                },
                "files_merged": {
                    "media/foo.BIN": { "class": "epix-orset-1" },
                },
            }),
            json!({
                "files": {
                    "Users/A/content.json": { "size": 1, "sha512": "a".repeat(64) },
                },
                "includes": {
                    "users/a/CONTENT.JSON": {},
                },
            }),
        ] {
            let (inner, content, bytes, loaded) =
                user_content_fixture(json!({}), extra);
            let ctx = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };

            let error =
                verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
            assert!(
                error.0.contains("Case-insensitive content destination collision"),
                "{}",
                error.0
            );
        }
    }

    #[test]
    fn child_file_size_totals_reject_integer_overflow() {
        for node in ["files", "files_optional"] {
            let mut extra = json!({ "files": {}, "files_optional": {} });
            extra[node] = json!({
                "one.bin": { "size": i64::MAX, "sha512": "a".repeat(64) },
                "two.bin": { "size": i64::MAX, "sha512": "b".repeat(64) },
            });
            let (inner, content, bytes, loaded) = user_content_fixture(json!({}), extra);
            let ctx = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };

            let error =
                verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
            assert!(
                error.0.contains(&format!("{node} size total overflow")),
                "{node}: {}",
                error.0
            );
        }

        // The required-file sum itself can fit while adding content.json's
        // signed byte length still exceeds the supported total.
        let (inner, content, bytes, loaded) = user_content_fixture(
            json!({}),
            json!({
                "files": {
                    "one.bin": { "size": i64::MAX, "sha512": "a".repeat(64) },
                },
            }),
        );
        let ctx = Ctx { address: "1Site".into(), loaded, limit: i64::MAX };
        let error = verify_content_file(&inner, &content, bytes.len() as i64, &ctx).unwrap_err();
        assert!(error.0.contains("files size total overflow"), "{}", error.0);
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
        fn xite_address(&self) -> &str {
            self.inner.xite_address()
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
            json!({ "files": { "data.json": { "size": 1, "sha512": "0".repeat(64) } } }),
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

    #[test]
    fn content_xid_names_include_skipped_level_include_signers() {
        let parent = json!({
            "inner_path": "content.json",
            "includes": {
                "deep/path/content.json": {
                    "signers": ["admin.epix", "epix1address", "admin.epix"]
                }
            }
        });
        assert_eq!(
            content_xid_names(&parent, "deep/path/content.json"),
            vec!["admin.epix".to_string()]
        );
    }

    /// Ctx variant serving pre-resolved xID identity records, mirroring how
    /// the node hands the chain snapshot to verification.
    struct ChainCtx {
        inner: Ctx,
        identities: XidMap,
    }
    impl VerifyContext for ChainCtx {
        fn xite_address(&self) -> &str {
            self.inner.xite_address()
        }
        fn loaded_content(&self, inner_path: &str) -> Option<Value> {
            self.inner.loaded_content(inner_path)
        }
        fn resolve_xid_identities(&self, name: &str) -> Option<Vec<XidIdentity>> {
            self.identities.get(name).cloned()
        }
    }

    /// A fresh keypair as (private key, address).
    fn new_identity() -> (String, String) {
        let secret = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&secret).unwrap();
        (secret, address)
    }

    /// The `data/users/content.json` -> parent map every user-content fixture
    /// loads.
    fn loaded_parent(parent: Value) -> std::collections::HashMap<String, Value> {
        let mut loaded = std::collections::HashMap::new();
        loaded.insert("data/users/content.json".to_string(), parent);
        loaded
    }

    /// The single-parent Ctx these tests verify against.
    fn user_ctx(loaded: std::collections::HashMap<String, Value>) -> Ctx {
        Ctx { address: "1Site".into(), loaded, limit: i64::MAX }
    }

    /// Assert a rejection and the reason for it. The reason is matched, never
    /// formatted into the panic message: these fixtures are built from signing
    /// keys, so echoing values derived from them into test output is what the
    /// cleartext-logging scanners flag.
    fn assert_rejected(result: Result<(), VerifyError>, expected: &str) {
        let error = result.expect_err("expected verification to reject this content");
        assert!(error.0.contains(expected), "rejected, but not for {expected:?}");
    }

    /// A signed user content.json in a chain-cert xite (`cert_signers`
    /// `["chain"]`), in a dir named `dir` (the user's auth address, or the
    /// xID name), with the cert made by `cert_signer` over `subject_addr` and
    /// the content itself signed by `dir_signer`.
    fn chain_cert_fixture(
        dir: &str,
        cert_signer: &str,
        subject_addr: &str,
        dir_signer: &str,
        modified: f64,
    ) -> (String, Value, Vec<u8>, std::collections::HashMap<String, Value>) {
        let parent = json!({
            "address": "1Site", "inner_path": "data/users/content.json", "modified": 1,
            "user_contents": {
                "cert_signers": { "xid.epix": ["chain"] },
                "permissions": {},
            },
        });
        let inner = format!("data/users/{dir}/content.json");
        let cert_sign =
            epix_crypt::sign_keccak(&format!("{subject_addr}#xid/alice"), cert_signer).unwrap();
        let content = json!({
            "address": "1Site", "inner_path": inner, "modified": modified, "files": {},
            "cert_user_id": "alice@xid.epix", "cert_auth_type": "xid", "cert_sign": cert_sign,
        });
        let (content, bytes) = sign_content(content, dir_signer);
        (inner, content, bytes, loaded_parent(parent))
    }

    /// Build a chain-cert fixture and verify it against `identities`.
    fn verify_chain_cert(
        dir: &str,
        cert_signer: &str,
        subject_addr: &str,
        dir_signer: &str,
        modified: f64,
        identities: XidMap,
    ) -> Result<(), VerifyError> {
        let (inner, content, bytes, loaded) =
            chain_cert_fixture(dir, cert_signer, subject_addr, dir_signer, modified);
        let ctx = ChainCtx { inner: user_ctx(loaded), identities };
        verify_content_file(&inner, &content, bytes.len() as i64, &ctx)
    }

    fn active_identity(address: &str) -> XidIdentity {
        XidIdentity { address: address.to_string(), active: true, revoked_at_time: 0 }
    }

    /// `name` resolving to a single active identity, the common chain answer.
    fn linked_to(address: &str) -> XidMap {
        XidMap::from([("alice.epix".to_string(), vec![active_identity(address)])])
    }

    #[test]
    fn chain_cert_verified_against_linked_identity() {
        let (user_key, user) = new_identity();
        assert!(
            verify_chain_cert(&user, &user_key, &user, &user_key, 100.0, linked_to(&user)).is_ok()
        );
    }

    #[test]
    fn chain_cert_forged_identity_rejected() {
        // An attacker in their own raw-address dir self-signs a cert claiming
        // alice@xid.epix. The signature is internally consistent (it recovers
        // to the attacker), but the attacker is not a linked identity of the
        // name, so the cert is rejected.
        let (user_key, user) = new_identity();
        let (attacker_key, attacker) = new_identity();
        assert_rejected(
            verify_chain_cert(
                &attacker,
                &attacker_key,
                &attacker,
                &attacker_key,
                100.0,
                linked_to(&user),
            ),
            "not linked to xID",
        );

        // A cert_sign over the dir's own address but made by a different key
        // recovers to a third address and is rejected as a mismatch.
        assert_rejected(
            verify_chain_cert(&user, &attacker_key, &user, &user_key, 100.0, linked_to(&user)),
            "signature mismatch",
        );
    }

    #[test]
    fn chain_cert_revoked_identity_temporal_check() {
        let (user_key, user) = new_identity();
        let revoked = |revoked_at_time: u64| {
            XidMap::from([(
                "alice.epix".to_string(),
                vec![XidIdentity {
                    address: user.clone(),
                    active: false,
                    revoked_at_time,
                }],
            )])
        };

        // Modified before revoked_at_time + grace (60s): still accepted.
        assert!(
            verify_chain_cert(&user, &user_key, &user, &user_key, 1059.0, revoked(1000)).is_ok()
        );
        // Modified at the cutoff: rejected.
        assert_rejected(
            verify_chain_cert(&user, &user_key, &user, &user_key, 1060.0, revoked(1000)),
            "was revoked at",
        );
        // Revoked with no usable timestamp: rejected outright.
        assert_rejected(
            verify_chain_cert(&user, &user_key, &user, &user_key, 100.0, revoked(0)),
            "has been revoked",
        );
    }

    #[test]
    fn chain_cert_unresolvable_name_fails_closed() {
        let (user_key, user) = new_identity();
        assert_rejected(
            verify_chain_cert(&user, &user_key, &user, &user_key, 100.0, XidMap::new()),
            "not found on chain",
        );
    }

    #[test]
    fn chain_cert_missing_cert_sign_rejected() {
        let (user_key, user) = new_identity();
        let (inner, mut content, _, loaded) =
            chain_cert_fixture(&user, &user_key, &user, &user_key, 100.0);
        content.as_object_mut().unwrap().remove("cert_sign");
        content.as_object_mut().unwrap().remove("signs");
        let (content, bytes) = sign_content(content, &user_key);
        let ctx = ChainCtx { inner: user_ctx(loaded), identities: linked_to(&user) };
        assert_rejected(
            verify_content_file(&inner, &content, bytes.len() as i64, &ctx),
            "Missing cert_sign",
        );
    }

    #[test]
    fn chain_cert_in_xid_named_dir_matches_a_linked_identity() {
        // The dir is named by the xID itself; any linked identity whose key
        // made the cert_sign satisfies the cert (Python's candidate loop).
        let (user_key, user) = new_identity();
        assert!(
            verify_chain_cert("alice.epix", &user_key, &user, &user_key, 100.0, linked_to(&user))
                .is_ok()
        );

        // A cert_sign from a key that is not any linked identity fails.
        let (stranger_key, stranger) = new_identity();
        assert_rejected(
            verify_chain_cert(
                "alice.epix",
                &stranger_key,
                &stranger,
                &user_key,
                100.0,
                linked_to(&user),
            ),
            "No linked identity matches",
        );
    }

    #[test]
    fn chain_cert_xid_name_extraction() {
        let parent = json!({
            "user_contents": { "cert_signers": { "xid.epix": ["chain"] } }
        });
        let legacy_parent = json!({
            "user_contents": { "cert_signers": { "xid.epix": ["1LegacyIssuer"] } }
        });
        let chain_cert = json!({ "cert_user_id": "alice@xid.epix" });
        let dotted = json!({ "cert_user_id": "alice.foo@xid.epix" });
        let other_domain = json!({ "cert_user_id": "alice@other.bit" });
        assert_eq!(chain_cert_xid_name(&parent, &chain_cert).as_deref(), Some("alice.epix"));
        assert_eq!(chain_cert_xid_name(&parent, &dotted).as_deref(), Some("alice.foo"));
        assert_eq!(chain_cert_xid_name(&parent, &other_domain), None);
        assert_eq!(chain_cert_xid_name(&legacy_parent, &chain_cert), None);
        assert_eq!(chain_cert_xid_name(&parent, &json!({})), None);
    }

    /// A parent whose `user_contents` carries exactly `permissions`, plus any
    /// extra `user_contents` keys.
    fn ban_parent(permissions: Value, extra: Value) -> std::collections::HashMap<String, Value> {
        let mut user_contents = json!({ "cert_signers": {}, "permissions": permissions });
        if let Some(extra) = extra.as_object() {
            let target = user_contents.as_object_mut().unwrap();
            for (key, value) in extra {
                target.insert(key.clone(), value.clone());
            }
        }
        loaded_parent(json!({
            "address": "1Site", "inner_path": "data/users/content.json", "modified": 1,
            "user_contents": user_contents,
        }))
    }

    /// Content in `inner`, signed by `signer`, optionally carrying a cert id.
    fn user_content(inner: &str, signer: &str, cert_user_id: Option<&str>) -> (Value, Vec<u8>) {
        let mut content =
            json!({ "address": "1Site", "inner_path": inner, "modified": 100, "files": {} });
        if let Some(id) = cert_user_id {
            let object = content.as_object_mut().unwrap();
            object.insert("cert_user_id".into(), json!(id));
            object.insert("cert_auth_type".into(), json!("xid"));
        }
        sign_content(content, signer)
    }

    #[test]
    fn banned_user_loses_the_self_signer() {
        // permissions[user] == false: the user's own signature no longer
        // verifies anywhere (the ban is part of the owner-signed parent, so
        // every node enforces it).
        let (user_key, user) = new_identity();
        let inner = format!("data/users/{user}/content.json");
        let (content, bytes) = user_content(&inner, &user_key, None);

        // Banned by raw auth address.
        let ctx = user_ctx(ban_parent(json!({ user.clone(): false }), json!({})));
        assert_rejected(
            verify_content_file(&inner, &content, bytes.len() as i64, &ctx),
            "Valid signs: 0/1",
        );

        // The same user without the ban entry verifies.
        let ctx = user_ctx(ban_parent(json!({}), json!({})));
        assert!(verify_content_file(&inner, &content, bytes.len() as i64, &ctx).is_ok());
    }

    #[test]
    fn banned_by_cert_user_id() {
        let (user_key, user) = new_identity();
        let inner = format!("data/users/{user}/content.json");
        let banned = || ban_parent(json!({ "alice@xid.epix": false }), json!({}));

        // The banned cert id cannot push, even from a raw-address dir.
        let (content, bytes) = user_content(&inner, &user_key, Some("alice@xid.epix"));
        let ctx = user_ctx(banned());
        assert_rejected(
            verify_content_file(&inner, &content, bytes.len() as i64, &ctx),
            "Valid signs: 0/1",
        );

        // A different cert id in the same dir layout is unaffected.
        let (content, bytes) = user_content(&inner, &user_key, Some("bob@xid.epix"));
        let ctx = user_ctx(banned());
        assert!(verify_content_file(&inner, &content, bytes.len() as i64, &ctx).is_ok());
    }

    #[test]
    fn null_permission_rule_zeroes_the_write_quota() {
        let (inner, content, bytes, loaded) =
            user_content_fixture(json!({ "permission_rules": { ".*": null } }), json!({}));
        assert_rejected(
            verify_content_file(&inner, &content, bytes.len() as i64, &user_ctx(loaded)),
            "Include too large",
        );

        // The same content under a real quota verifies.
        let (inner, content, bytes, loaded) = user_content_fixture(
            json!({ "permission_rules": { ".*": { "max_size": 100000 } } }),
            json!({}),
        );
        let ctx = user_ctx(loaded);
        assert!(verify_content_file(&inner, &content, bytes.len() as i64, &ctx).is_ok());
    }

    #[test]
    fn admin_signer_still_works_in_a_banned_user_dir() {
        // Moderation tombstones: the ban removes the user's self-signer, but
        // an admin granted through permission_rules signers can still re-sign
        // the dir's content.json (e.g. to blank a spammer's posts).
        let (user_key, user) = new_identity();
        let (admin_key, admin) = new_identity();
        let inner = format!("data/users/{user}/content.json");
        let parent = || {
            ban_parent(
                json!({ user.clone(): false }),
                json!({ "permission_rules": { ".*": { "signers": [admin], "max_size": 100000 } } }),
            )
        };

        let (content, bytes) = user_content(&inner, &admin_key, None);
        let ctx = user_ctx(parent());
        assert!(verify_content_file(&inner, &content, bytes.len() as i64, &ctx).is_ok());

        // The banned user still cannot sign despite the merged rule quota.
        let (content, bytes) = user_content(&inner, &user_key, None);
        let ctx = user_ctx(parent());
        assert_rejected(
            verify_content_file(&inner, &content, bytes.len() as i64, &ctx),
            "Valid signs: 0/1",
        );
    }
}
