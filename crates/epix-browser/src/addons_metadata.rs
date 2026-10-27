//! Read-only startup checks for Firefox ESR 153's extension DB and cache.
//!
//! Pinned schema: FIREFOX_153_4_0esr_RELEASE, XPIProvider (DB_SCHEMA=37,
//! XPIState/Location.toJSON), XPIDatabase.toJSON, and AddonManagerStartup's
//! mozLz40 decoder. These checks complement archive/consent verification;
//! cached signedState is never independent evidence of a Mozilla signature.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

const METADATA_LIMIT: usize = 16 * 1024 * 1024;
const ARCHIVE_LIMIT: u64 = 32 * 1024 * 1024;
const ENTRY_LIMIT: usize = 4096;
const NODE_LIMIT: usize = 131072;
const DB_SCHEMA: u64 = 37;

fn invalid(message: &str) -> String {
    format!(
        "Firefox extension state is unsupported or inconsistent: {message}. Close Firefox and repair this profile before reopening it."
    )
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(key))
}
fn id_valid(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"@._-{}".contains(&b))
}
fn hash_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// A duplicate-key and node-bounded parser. A cache key cannot mean one value
// to this verifier and another value to Firefox's JSON parser.
struct Seed<'a>(&'a mut usize);
struct JsonVisitor<'a>(&'a mut usize);
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        *self.0 += 1;
        if *self.0 > NODE_LIMIT {
            return Err(de::Error::custom("Metadata node limit"));
        }
        d.deserialize_any(JsonVisitor(self.0))
    }
}
impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded unique JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("Invalid number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = a.next_element_seed(Seed(&mut *self.0))? {
            if values.len() >= ENTRY_LIMIT {
                return Err(de::Error::custom("Metadata entry limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = a.next_key::<String>()? {
            if values.len() >= ENTRY_LIMIT || key.len() > 4096 || values.contains_key(&key) {
                return Err(de::Error::custom("Duplicate or excessive metadata key"));
            }
            values.insert(key, a.next_value_seed(Seed(&mut *self.0))?);
        }
        Ok(Value::Object(values))
    }
}
fn json(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > METADATA_LIMIT {
        return Err(invalid("metadata size limit"));
    }
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let value = Seed(&mut 0)
        .deserialize(&mut parser)
        .map_err(|_| invalid("invalid or duplicate JSON metadata"))?;
    parser.end().map_err(|_| invalid("trailing metadata"))?;
    Ok(value)
}

/// Mozilla's envelope is eight bytes `mozLz40\0`, LE output length, then one
/// raw LZ4 block (not an LZ4 frame). Output allocation and every copy are bound
/// to the checked declared length. No dictionary or external decompressor.
fn startup_json(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() < 12 || bytes.len() > METADATA_LIMIT || &bytes[..8] != b"mozLz40\0" {
        return Err(invalid("unknown startup-cache format"));
    }
    let expected = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if expected == 0 || expected > METADATA_LIMIT {
        return Err(invalid("startup-cache expansion limit"));
    }
    let input = &bytes[12..];
    let mut at = 0usize;
    let mut output = Vec::with_capacity(expected);
    fn length(input: &[u8], at: &mut usize, initial: usize, limit: usize) -> Result<usize, String> {
        let mut n = initial;
        if initial == 15 {
            loop {
                let next = *input
                    .get(*at)
                    .ok_or_else(|| invalid("truncated LZ4 length"))?
                    as usize;
                *at += 1;
                n = n
                    .checked_add(next)
                    .filter(|n| *n <= limit)
                    .ok_or_else(|| invalid("LZ4 expansion limit"))?;
                if next != 255 {
                    break;
                }
            }
        }
        Ok(n)
    }
    while at < input.len() {
        let token = input[at];
        at += 1;
        let literals = length(input, &mut at, (token >> 4) as usize, expected)?;
        let end = at
            .checked_add(literals)
            .filter(|end| *end <= input.len())
            .ok_or_else(|| invalid("truncated LZ4 literals"))?;
        if output
            .len()
            .checked_add(literals)
            .is_none_or(|n| n > expected)
        {
            return Err(invalid("LZ4 expansion limit"));
        }
        output.extend_from_slice(&input[at..end]);
        at = end;
        if at == input.len() {
            break;
        }
        let offset_bytes = input
            .get(at..at + 2)
            .ok_or_else(|| invalid("truncated LZ4 offset"))?;
        let offset = u16::from_le_bytes(offset_bytes.try_into().unwrap()) as usize;
        at += 2;
        if offset == 0 || offset > output.len() {
            return Err(invalid("invalid LZ4 back-reference"));
        }
        let matched = length(input, &mut at, (token & 15) as usize, expected)?
            .checked_add(4)
            .filter(|n| {
                output
                    .len()
                    .checked_add(*n)
                    .is_some_and(|end| end <= expected)
            })
            .ok_or_else(|| invalid("LZ4 expansion limit"))?;
        for _ in 0..matched {
            output.push(output[output.len() - offset]);
        }
    }
    if output.len() != expected {
        return Err(invalid("startup-cache length mismatch"));
    }
    json(&output)
}

fn read_optional(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => crate::addons::read_regular(path, limit).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(invalid("unreadable metadata or archive")),
    }
}
#[derive(Clone)]
struct Version {
    version: String,
    hash: String,
}
struct Expected {
    versions: Vec<Version>,
    staged: Option<Version>,
}
fn version(value: &Value) -> Result<Version, String> {
    let version = field(value, "version")?;
    let hash = field(value, "archive_sha256")?;
    if version.is_empty() || version.len() > 128 || !hash_valid(hash) {
        return Err(invalid("invalid ownership version"));
    }
    Ok(Version {
        version: version.into(),
        hash: hash.into(),
    })
}
fn expected(mirror: &Value, approved: Option<&Value>) -> Result<HashMap<String, Expected>, String> {
    let owners = mirror
        .get("managed")
        .and_then(Value::as_array)
        .filter(|a| a.len() <= 256)
        .ok_or_else(|| invalid("managed receipt list"))?;
    let mut result = HashMap::new();
    for owner in owners {
        let id = field(owner, "addon_id")?;
        if !id_valid(id) || result.contains_key(id) {
            return Err(invalid("duplicate managed identity"));
        }
        result.insert(
            id.into(),
            Expected {
                versions: vec![version(owner)?],
                staged: None,
            },
        );
    }
    let pending = mirror.get("pending").filter(|v| !v.is_null());
    let candidate = pending
        .and_then(|p| p.get("candidate"))
        .filter(|v| !v.is_null());
    if let Some(candidate) = candidate {
        let id = field(candidate, "addon_id")?;
        if !id_valid(id) {
            return Err(invalid("pending addon identity"));
        }
        // Protection is wider than approval. A handed-off candidate alone is
        // never permission to activate its archive after a crash.
        result.entry(id.into()).or_insert(Expected {
            versions: Vec::new(),
            staged: None,
        });
    }
    if let Some(approved) = approved {
        let candidate =
            candidate.ok_or_else(|| invalid("native consent has no pending candidate"))?;
        let pending = pending.unwrap();
        if !matches!(
            pending.get("phase").and_then(Value::as_str),
            Some("HandedOff" | "Staged" | "NeedsReconciliation" | "Installed")
        ) || ["operation_id", "addon_id", "version", "archive_sha256"]
            .iter()
            .any(|key| {
                approved.get(key).and_then(Value::as_str).is_none()
                    || approved.get(key) != candidate.get(key)
            })
            || pending.get("operation_id") != candidate.get("operation_id")
        {
            return Err(invalid("native consent does not match pending operation"));
        }
        let item = result.get_mut(field(candidate, "addon_id")?).unwrap();
        let approved = version(candidate)?;
        item.versions.push(approved.clone());
        item.staged = Some(approved);
    }
    Ok(result)
}
fn archive_version(path: &Path, versions: &[Version]) -> Result<Option<String>, String> {
    let Some(bytes) = read_optional(path, ARCHIVE_LIMIT)? else {
        return Ok(None);
    };
    let actual = sha256(&bytes);
    versions
        .iter()
        .find(|v| v.hash == actual)
        .map(|v| Some(v.version.clone()))
        .ok_or_else(|| invalid("archive has no exact approved version"))
}
#[cfg(test)]
fn root_uri(path: &Path) -> Result<String, String> {
    let uri = url::Url::from_file_path(path).map_err(|_| invalid("profile archive path"))?;
    Ok(format!("jar:{uri}!/"))
}
// ESR 153 serializes a verbatim Windows disk path using its literal device
// prefix in the file URL. Admit only this observed disk spelling; UNC and
// device namespaces have no equivalent enrollment contract here.
#[cfg(any(windows, test))]
fn windows_verbatim_disk_uri(uri: &str) -> Option<String> {
    let tail = uri
        .strip_prefix("file://///%3F/")
        .or_else(|| uri.strip_prefix("file://///%3f/"))?;
    let bytes = tail.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1..3] != *b":/" {
        return None;
    }
    Some(format!("file:///{tail}"))
}
fn packed_file_uri_matches(uri: &str, path: &Path) -> bool {
    let Some(file_uri) = uri.strip_prefix("jar:").and_then(|s| s.strip_suffix("!/")) else {
        return false;
    };
    if !file_uri.starts_with("file:///")
        || file_uri.len() > 65536
        || file_uri.contains(['\\', '?', '#'])
    {
        return false;
    }
    #[cfg(windows)]
    let normalized;
    #[cfg(windows)]
    let file_uri = if file_uri.starts_with("file:////") {
        let Some(value) = windows_verbatim_disk_uri(file_uri) else {
            return false;
        };
        normalized = value;
        normalized.as_str()
    } else {
        file_uri
    };
    // Allow equivalent percent spelling (Gecko escapes ';' as `%3b`), but
    // never let URL normalization hide a dot segment or encoded separator.
    for part in file_uri.split('/') {
        let mut decoded = Vec::with_capacity(part.len());
        let mut bytes = part.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let Some(hi) = bytes.next().and_then(|b| (b as char).to_digit(16)) else {
                    return false;
                };
                let Some(lo) = bytes.next().and_then(|b| (b as char).to_digit(16)) else {
                    return false;
                };
                let byte = ((hi << 4) | lo) as u8;
                if byte == 0 || byte == b'/' || (cfg!(windows) && byte == b'\\') {
                    return false;
                }
                decoded.push(byte);
            } else {
                decoded.push(byte);
            }
        }
        if decoded == b"." || decoded == b".." {
            return false;
        }
    }
    let Ok(url) = url::Url::parse(file_uri) else {
        return false;
    };
    if url.scheme() != "file"
        || url.host_str().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let Ok(actual) = url.to_file_path() else {
        return false;
    };
    same_archive_path(&actual, path)
}
#[cfg(not(windows))]
fn same_archive_path(actual: &Path, expected: &Path) -> bool {
    actual == expected
}
#[cfg(windows)]
fn same_archive_path(actual: &Path, expected: &Path) -> bool {
    use std::path::{Component, Prefix};
    // Canonical Rust roots use the verbatim prefix; file URLs use the ordinary
    // drive/UNC spelling. Normalize only that prefix, never filesystem aliases.
    fn ordinary(path: &Path) -> Option<std::path::PathBuf> {
        let mut parts = path.components();
        let prefix = match parts.next()? {
            Component::Prefix(p) => p.kind(),
            _ => return None,
        };
        let mut result = match prefix {
            Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                std::path::PathBuf::from(format!("{}:", d as char))
            }
            Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                let mut value = std::path::PathBuf::from(r"\\");
                value.push(server);
                value.push(share);
                value
            }
            _ => return None,
        };
        result.extend(parts);
        Some(result)
    }
    ordinary(actual)
        .zip(ordinary(expected))
        .is_some_and(|(a, b)| a == b)
}
fn ordinary(value: &Value, id: &str, version: &str, path: &Path, kind: u8) -> Result<(), String> {
    // kind:0 installed DB,1 startup addon,2 staged AddonInternal metadata.
    if (kind != 1 && field(value, "id")? != id)
        || field(value, "version")? != version
        || value.get("signedState").and_then(Value::as_i64) != Some(2)
        || value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or(if kind == 1 { "extension" } else { "" })
            != "extension"
        || value.get("loader").is_some_and(|v| !v.is_null())
        || !packed_file_uri_matches(field(value, "rootURI")?, path)
    {
        return Err(invalid(
            "managed addon identity, signature cache or archive URI",
        ));
    }
    if kind != 1 {
        if field(value, "location")? != "app-profile" {
            return Err(invalid("managed addon moved outside profile"));
        }
        let algorithms = value
            .get("signedTypes")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("missing cached signature algorithms"))?;
        // nsIAppSignatureInfo in ESR153: SHA1=0, PKCS7_SHA256=1, COSE_SHA256=2.
        if algorithms.is_empty()
            || algorithms.len() > 3
            || algorithms
                .iter()
                .any(|v| !matches!(v.as_u64(), Some(0..=2)))
            || !algorithms.iter().any(|v| matches!(v.as_u64(), Some(1 | 2)))
        {
            return Err(invalid("unsupported cached signature algorithms"));
        }
    }
    match value.get("path").and_then(Value::as_str) {
        Some(actual) => {
            let actual = Path::new(actual);
            let expected_relative = Path::new(
                path.file_name()
                    .ok_or_else(|| invalid("archive filename"))?,
            );
            if actual != path && !(kind == 1 && actual == expected_relative) {
                return Err(invalid("managed addon archive path redirect"));
            }
        }
        None if kind == 2 => {} // AddonInternal.path is assigned by addToDatabase only.
        None => return Err(invalid("missing managed addon path")),
    }
    Ok(())
}

// A native uninstall may remove the archive before Gecko flushes its caches.
// Only the exact durable uninstall can explain that absence. This permits no
// package to activate and never edits Firefox's database or startup cache.
fn interrupted_uninstall(
    profile: &Path,
    mirror: &Value,
    expected: &HashMap<String, Expected>,
    installed: &HashMap<String, String>,
) -> Result<Option<(String, String)>, String> {
    let Some(pending) = mirror.get("pending").filter(|p| {
        matches!(
            p.get("phase").and_then(Value::as_str),
            Some("Uninstalling" | "NeedsReconciliation")
        ) && p.get("uninstall_id").is_some_and(|v| !v.is_null())
    }) else {
        return Ok(None);
    };
    if pending.get("candidate") != Some(&Value::Null)
        || !hash_valid(field(pending, "operation_id")?)
    {
        return Err(invalid("ambiguous pending uninstall"));
    }
    let id = field(pending, "uninstall_id")?;
    let owner = expected
        .get(id)
        .filter(|v| v.versions.len() == 1 && v.staged.is_none())
        .ok_or_else(|| invalid("pending uninstall has no exact owner"))?;
    if installed.contains_key(id) {
        return Ok(None);
    }
    for path in [
        profile.join("extensions").join(format!("{id}.xpi")),
        profile.join("extensions/staged").join(format!("{id}.xpi")),
        profile.join("extensions").join(id),
        profile.join("extensions/staged").join(id),
    ] {
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(invalid(
                    "pending uninstall still has an archive or alternate entry",
                ));
            }
        }
    }
    Ok(Some((id.into(), owner.versions[0].version.clone())))
}

fn check_database(
    profile: &Path,
    base: &Path,
    expected: &HashMap<String, Expected>,
    installed: &HashMap<String, String>,
    removed: Option<&(String, String)>,
) -> Result<(), String> {
    let Some(bytes) = read_optional(&profile.join("extensions.json"), METADATA_LIMIT as u64)?
    else {
        return Ok(());
    };
    let db = json(&bytes)?;
    if db.get("schemaVersion").and_then(Value::as_u64) != Some(DB_SCHEMA) {
        return Err(invalid("unknown extensions database schema"));
    }
    let addons = db
        .get("addons")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("invalid extensions database"))?;
    let mut seen = HashSet::new();
    for addon in addons {
        let id = field(addon, "id")?;
        if !expected.contains_key(id) {
            continue;
        }
        if !seen.insert(id) {
            return Err(invalid("duplicate managed database identity"));
        }
        let version = installed
            .get(id)
            .or_else(|| {
                removed
                    .filter(|(removed_id, _)| removed_id == id)
                    .map(|(_, version)| version)
            })
            .ok_or_else(|| invalid("database references missing or unapproved managed archive"))?;
        ordinary(addon, id, version, &base.join(format!("{id}.xpi")), 0)?;
    }
    Ok(())
}

fn check_startup_cache(
    profile: &Path,
    base: &Path,
    expected: &HashMap<String, Expected>,
    installed: &HashMap<String, String>,
    staged: &HashMap<String, String>,
    removed: Option<&(String, String)>,
) -> Result<(), String> {
    let Some(bytes) = read_optional(
        &profile.join("addonStartup.json.lz4"),
        METADATA_LIMIT as u64,
    )?
    else {
        return Ok(());
    };
    let data = startup_json(&bytes)?;
    let locations = data
        .as_object()
        .filter(|v| v.len() <= 32)
        .ok_or_else(|| invalid("invalid startup locations"))?;
    let mut seen_installed = HashSet::new();
    let mut seen_staged = HashSet::new();
    for (location, state) in locations {
        for (section, seen, versions, kind) in [
            ("addons", &mut seen_installed, installed, 1),
            ("staged", &mut seen_staged, staged, 2),
        ] {
            let Some(entries) = state.get(section) else {
                continue;
            };
            let entries = entries
                .as_object()
                .ok_or_else(|| invalid("invalid startup addon table"))?;
            for (id, addon) in entries {
                if !expected.contains_key(id) {
                    continue;
                }
                if location != "app-profile"
                    || field(state, "path")?
                        != base
                            .to_str()
                            .ok_or_else(|| invalid("non-UTF8 profile path"))?
                    || !seen.insert(id)
                {
                    return Err(invalid("duplicate or redirected startup location"));
                }
                let version = versions
                    .get(id)
                    .or_else(|| {
                        removed
                            .filter(|(removed_id, _)| kind == 1 && removed_id == id)
                            .map(|(_, version)| version)
                    })
                    .ok_or_else(|| {
                        invalid("startup references missing or unapproved managed archive")
                    })?;
                let path = if kind == 1 {
                    base.join(format!("{id}.xpi"))
                } else {
                    base.join("staged").join(format!("{id}.xpi"))
                };
                ordinary(addon, id, version, &path, kind)?;
            }
        }
    }
    Ok(())
}

/// `approved_candidate` is supplied only after the launcher validates the
/// profile's native Allow marker against this exact pending operation.
pub(super) fn check(
    profile: &Path,
    mirror: &Value,
    approved_candidate: Option<&Value>,
) -> Result<(), String> {
    let expected = expected(mirror, approved_candidate)?;
    if expected.is_empty() {
        return Ok(());
    }
    let base = profile.join("extensions");
    let mut installed = HashMap::new();
    let mut staged = HashMap::new();
    for (id, item) in &expected {
        if let Some(v) = archive_version(&base.join(format!("{id}.xpi")), &item.versions)? {
            installed.insert(id.clone(), v);
        }
        let approved = item
            .staged
            .as_ref()
            .map(std::slice::from_ref)
            .unwrap_or(&[]);
        if let Some(v) = archive_version(&base.join("staged").join(format!("{id}.xpi")), approved)?
        {
            staged.insert(id.clone(), v);
        }
    }
    let removed = interrupted_uninstall(profile, mirror, &expected, &installed)?;
    check_database(profile, &base, &expected, &installed, removed.as_ref())?;
    check_startup_cache(
        profile,
        &base,
        &expected,
        &installed,
        &staged,
        removed.as_ref(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const ID: &str = "ordinary@example.invalid";
    const OLD: &[u8] = b"already approved ordinary extension";
    const NEW: &[u8] = b"new native-approved ordinary extension";
    fn compressed(bytes: &[u8]) -> Vec<u8> {
        // Valid raw LZ4 literal sequence, wrapped in Mozilla's exact envelope.
        let mut data = b"mozLz40\0".to_vec();
        data.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        data.push((bytes.len().min(15) as u8) << 4);
        if bytes.len() >= 15 {
            let mut rest = bytes.len() - 15;
            while rest >= 255 {
                data.push(255);
                rest -= 255;
            }
            data.push(rest as u8);
        }
        data.extend_from_slice(bytes);
        data
    }
    fn owner(version: &str, bytes: &[u8]) -> Value {
        json!({"addon_id":ID,"version":version,"archive_sha256":sha256(bytes)})
    }
    fn record(profile: &Path, version: &str, staged: bool, startup: bool) -> Value {
        let base = if staged {
            profile.join("extensions/staged")
        } else {
            profile.join("extensions")
        };
        let path = base.join(format!("{ID}.xpi"));
        let mut result = json!({"id":ID,"version":version,"location":"app-profile","type":"extension","loader":null,"signedState":2,"signedTypes":[2,1],"path":path,"rootURI":root_uri(&path).unwrap()});
        if startup {
            result["path"] = json!(format!("{ID}.xpi"));
            result["enabled"] = json!(true);
            result.as_object_mut().unwrap().remove("id");
            result.as_object_mut().unwrap().remove("signedTypes");
            result.as_object_mut().unwrap().remove("type");
        } else if staged {
            result.as_object_mut().unwrap().remove("path");
        }
        result
    }
    struct Fixture {
        _temp: tempfile::TempDir,
        profile: std::path::PathBuf,
        mirror: Value,
        db: Value,
        cache: Value,
    }
    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let profile = temp.path().canonicalize().unwrap();
            std::fs::create_dir_all(profile.join("extensions/staged")).unwrap();
            std::fs::write(profile.join(format!("extensions/{ID}.xpi")), OLD).unwrap();
            let db = json!({"schemaVersion":37,"addons":[record(&profile,"1.0",false,false)]});
            let cache = json!({"app-profile":{"path":profile.join("extensions"),"addons":{ID:record(&profile,"1.0",false,true)},"staged":{}}});
            let mirror = json!({"managed":[owner("1.0",OLD)],"pending":null});
            Self {
                _temp: temp,
                profile,
                mirror,
                db,
                cache,
            }
        }
        fn save(&self) {
            std::fs::write(
                self.profile.join("extensions.json"),
                serde_json::to_vec(&self.db).unwrap(),
            )
            .unwrap();
            std::fs::write(
                self.profile.join("addonStartup.json.lz4"),
                compressed(&serde_json::to_vec(&self.cache).unwrap()),
            )
            .unwrap();
        }
        fn approved_update(&mut self) -> Value {
            let mut candidate = owner("2.0", NEW);
            candidate["operation_id"] = json!("a".repeat(64));
            self.mirror["pending"] =
                json!({"operation_id":"a".repeat(64),"phase":"HandedOff","candidate":candidate});
            std::fs::write(
                self.profile.join(format!("extensions/staged/{ID}.xpi")),
                NEW,
            )
            .unwrap();
            self.cache["app-profile"]["staged"][ID] = record(&self.profile, "2.0", true, false);
            candidate
        }
    }
    #[test]
    fn addons_metadata_accepts_pinned_db_cache_and_is_read_only() {
        let f = Fixture::new();
        f.save();
        let paths = [
            f.profile.join("extensions.json"),
            f.profile.join("addonStartup.json.lz4"),
        ];
        let before: Vec<_> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
        check(&f.profile, &f.mirror, None).unwrap();
        assert_eq!(
            before,
            paths
                .iter()
                .map(|p| std::fs::read(p).unwrap())
                .collect::<Vec<_>>()
        );
        // A missing cache is rebuilt by Gecko from the separately hash-verified
        // profile archives. It is distinct from a present malformed cache.
        std::fs::remove_file(&paths[1]).unwrap();
        check(&f.profile, &f.mirror, None).unwrap();
    }
    #[test]
    fn addons_metadata_requires_native_consent_before_staged_or_installed_replacement() {
        let mut f = Fixture::new();
        let approved = f.approved_update();
        f.save();
        assert!(check(&f.profile, &f.mirror, None).is_err());
        check(&f.profile, &f.mirror, Some(&approved)).unwrap();
        let mut wrong = approved.clone();
        wrong["operation_id"] = json!("b".repeat(64));
        assert!(check(&f.profile, &f.mirror, Some(&wrong)).is_err());
        std::fs::rename(
            f.profile.join(format!("extensions/staged/{ID}.xpi")),
            f.profile.join(format!("extensions/{ID}.xpi")),
        )
        .unwrap();
        f.db["addons"][0] = record(&f.profile, "2.0", false, false);
        f.cache["app-profile"]["addons"][ID] = record(&f.profile, "2.0", false, true);
        f.cache["app-profile"]["staged"] = json!({});
        f.save();
        assert!(check(&f.profile, &f.mirror, None).is_err());
        check(&f.profile, &f.mirror, Some(&approved)).unwrap();
        // Matching an old allowed version is insufficient when the bytes are
        // the new version. The cache must match that exact digest/version pair.
        f.db["addons"][0]["version"] = json!("1.0");
        f.save();
        assert!(check(&f.profile, &f.mirror, Some(&approved)).is_err());
    }
    #[test]
    fn addons_metadata_rejects_redirected_unpacked_duplicate_and_unsigned_managed_records() {
        for patch in [
            json!({"path":"/outside.xpi"}),
            json!({"rootURI":"jar:file:///outside.xpi!/"}),
            json!({"location":"app-system-profile"}),
            json!({"loader":"bootstrap"}),
            json!({"type":"theme"}),
            json!({"signedState":3}),
            json!({"signedTypes":[0]}),
            json!({"signedTypes":[2,999]}),
        ] {
            let mut f = Fixture::new();
            for (key, value) in patch.as_object().unwrap() {
                f.db["addons"][0][key] = value.clone()
            }
            f.save();
            assert!(check(&f.profile, &f.mirror, None).is_err(), "{patch}");
        }
        let mut f = Fixture::new();
        let duplicate = f.db["addons"][0].clone();
        f.db["addons"].as_array_mut().unwrap().push(duplicate);
        f.save();
        assert!(check(&f.profile, &f.mirror, None).is_err());
        let f = Fixture::new();
        f.save();
        let path = f.profile.join(format!("extensions/{ID}.xpi"));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(check(&f.profile, &f.mirror, None).is_err());
    }
    #[test]
    fn addons_metadata_rejects_startup_path_aliases_and_unapproved_staged_cache() {
        for patch in [
            json!({"path":"../ordinary@example.invalid.xpi"}),
            json!({"rootURI":"file:///outside/"}),
            json!({"signedState":0}),
            json!({"version":"99.0"}),
        ] {
            let mut f = Fixture::new();
            for (k, v) in patch.as_object().unwrap() {
                f.cache["app-profile"]["addons"][ID][k] = v.clone()
            }
            f.save();
            assert!(check(&f.profile, &f.mirror, None).is_err());
        }
        let mut f = Fixture::new();
        f.cache["app-profile"]["path"] = json!("/elsewhere/extensions");
        f.save();
        assert!(check(&f.profile, &f.mirror, None).is_err());
        let mut f = Fixture::new();
        f.cache["app-system-local"] = f.cache["app-profile"].clone();
        f.save();
        assert!(check(&f.profile, &f.mirror, None).is_err());
        let mut f = Fixture::new();
        f.cache["app-profile"]["staged"][ID] = record(&f.profile, "1.0", true, false);
        f.save();
        assert!(check(&f.profile, &f.mirror, None).is_err());
    }
    #[test]
    fn addons_metadata_recovers_only_exact_interrupted_uninstall_without_cache_writes() {
        for phase in ["Uninstalling", "NeedsReconciliation"] {
            let mut f = Fixture::new();
            f.mirror["pending"] = json!({"operation_id":"a".repeat(64),"phase":phase,"candidate":null,"uninstall_id":ID});
            std::fs::remove_file(f.profile.join(format!("extensions/{ID}.xpi"))).unwrap();
            f.save();
            let db = std::fs::read(f.profile.join("extensions.json")).unwrap();
            let cache = std::fs::read(f.profile.join("addonStartup.json.lz4")).unwrap();
            check(&f.profile, &f.mirror, None).unwrap();
            assert_eq!(
                std::fs::read(f.profile.join("extensions.json")).unwrap(),
                db
            );
            assert_eq!(
                std::fs::read(f.profile.join("addonStartup.json.lz4")).unwrap(),
                cache
            );
        }
    }
    #[test]
    fn addons_metadata_interrupted_uninstall_never_admits_replacement_or_redirect() {
        for mutation in 0..12 {
            let mut f = Fixture::new();
            f.mirror["pending"] = json!({"operation_id":"a".repeat(64),"phase":"NeedsReconciliation","candidate":null,"uninstall_id":ID});
            let archive = f.profile.join(format!("extensions/{ID}.xpi"));
            std::fs::remove_file(&archive).unwrap();
            match mutation {
                0 => f.mirror["pending"] = Value::Null,
                1 => f.mirror["pending"]["phase"] = json!("Cancelled"),
                2 => f.mirror["pending"]["operation_id"] = json!("bad"),
                3 => f.mirror["pending"]["uninstall_id"] = json!("other@example.invalid"),
                4 => f.mirror["pending"]["candidate"] = owner("2.0", NEW),
                5 => f.db["addons"][0]["version"] = json!("2.0"),
                6 => f.db["addons"][0]["rootURI"] = json!("jar:file:///outside.xpi!/"),
                7 => f.cache["app-profile"]["addons"][ID]["signedState"] = json!(0),
                8 => {
                    std::fs::write(&archive, NEW).unwrap();
                }
                9 => {
                    std::fs::write(f.profile.join(format!("extensions/staged/{ID}.xpi")), OLD)
                        .unwrap();
                }
                10 => {
                    std::fs::create_dir(f.profile.join("extensions").join(ID)).unwrap();
                }
                11 => f.cache["app-profile"]["staged"][ID] = record(&f.profile, "1.0", true, false),
                _ => unreachable!(),
            }
            f.save();
            assert!(
                check(&f.profile, &f.mirror, None).is_err(),
                "mutation {mutation}"
            );
        }
    }
    #[test]
    fn addons_metadata_bounds_lz4_json_and_schema() {
        assert_eq!(startup_json(&compressed(b"{}")).unwrap(), json!({}));
        // A valid overlapping match: the JSON string "abcabcabc012345".
        let literal = b"\"abc";
        let tail = b"012345\"";
        let mut raw = vec![0x42];
        raw.extend_from_slice(literal);
        raw.extend_from_slice(&[3, 0]);
        raw.push((tail.len() as u8) << 4);
        raw.extend_from_slice(tail);
        let expected = b"\"abcabcabc012345\"";
        let mut envelope = b"mozLz40\0".to_vec();
        envelope.extend_from_slice(&(expected.len() as u32).to_le_bytes());
        envelope.extend_from_slice(&raw);
        assert_eq!(startup_json(&envelope).unwrap(), json!("abcabcabc012345"));
        for value in [b"{}garbage".as_slice(), b"{\"x\":1,\"x\":2}".as_slice()] {
            assert!(startup_json(&compressed(value)).is_err())
        }
        let mut too_big = compressed(b"{}");
        too_big[8..12].copy_from_slice(&((METADATA_LIMIT + 1) as u32).to_le_bytes());
        assert!(startup_json(&too_big).is_err());
        for bytes in [
            b"mozLz40\0\x02\0\0\0\x10".as_slice(),
            b"mozLz40\0\x06\0\0\0\x10a\0\0".as_slice(),
        ] {
            assert!(startup_json(bytes).is_err())
        }
        assert!(json(format!("[{}]", vec!["0"; ENTRY_LIMIT + 1].join(",")).as_bytes()).is_err());
        let mut f = Fixture::new();
        f.db["schemaVersion"] = json!(38);
        f.save();
        assert!(check(&f.profile, &f.mirror, None).is_err());
        let f = Fixture::new();
        f.save();
        std::fs::write(
            f.profile.join("addonStartup.json.lz4"),
            b"unknown compression",
        )
        .unwrap();
        assert!(check(&f.profile, &f.mirror, None).is_err());
    }
    #[test]
    fn addons_metadata_accepts_gecko_uri_escaping_without_path_aliases() {
        let f = Fixture::new();
        let path = f.profile.join("space ;#%20 ü.xpi");
        let uri = root_uri(&path).unwrap();
        assert!(packed_file_uri_matches(&uri, &path));
        assert!(packed_file_uri_matches(&uri.replace(';', "%3b"), &path));
        for bad in [
            uri.replace("space", "../space"),
            uri.replace("space", "%2e%2e/space"),
            uri.replace("space", "%2fspace"),
            uri.replace("space", "%xxspace"),
            uri.replace("!/", "?ignored!/"),
            uri.replace("!/", "#ignored!/"),
            uri.replace("file:", "https:"),
            uri.replace("file:///", "file://localhost/"),
            uri.replace("file:///", "file://remote.invalid/"),
        ] {
            assert!(!packed_file_uri_matches(&bad, &path), "{bad}");
        }
        assert!(!packed_file_uri_matches(&uri, &f.profile.join("other.xpi")));
    }
    #[test]
    fn addons_metadata_handles_only_observed_windows_verbatim_disk_uri() {
        // Retained actual Firefox 153.4 Windows metadata after native Allow.
        let actual = "file://///%3F/D:/a/_temp/epix646-update-g70p78gh/profile%20space%20%C3%A9%20%E9%9B%AA%20%3b%23literal%2520/extensions/uBlock0@raymondhill.net.xpi";
        let ordinary = actual.replacen("file://///%3F/", "file:///", 1);
        assert_eq!(windows_verbatim_disk_uri(actual), Some(ordinary.clone()));
        assert_eq!(
            windows_verbatim_disk_uri(&actual.replace("%3F", "%3f")),
            Some(ordinary)
        );
        for bad in [
            actual.replace("%3F/D:/", "%3F/UNC/server/share/"),
            actual.replace("%3F/D:/", "%3F/GLOBALROOT/Device/"),
            actual.replace("%3F/D:/", "%3F/D:"),
            actual.replace("%3F/D:/", "%3F//D:/"),
            actual.replace("%3F/D:/", "%3F/%44:/"),
            actual.replace("%3F", "%253F"),
            actual.replace("file://///", "file://localhost///"),
        ] {
            assert!(windows_verbatim_disk_uri(&bad).is_none(), "{bad}");
        }
        #[cfg(windows)]
        {
            let path = Path::new(
                r"\\?\D:\a\_temp\epix646-update-g70p78gh\profile space é 雪 ;#literal%20\extensions\uBlock0@raymondhill.net.xpi",
            );
            let uri = format!("jar:{actual}!/");
            assert!(packed_file_uri_matches(&uri, path));
            for bad in [
                uri.replace("/D:/", "/C:/"),
                uri.replace("/extensions/", "/outside/"),
                uri.replace("/extensions/", "/%2e%2e/extensions/"),
                uri.replace("/extensions/", "/%2fextensions/"),
                uri.replace("/extensions/", "/%5cextensions/"),
                uri.replace("!/", "?ignored!/"),
                uri.replace("!/", "#ignored!/"),
            ] {
                assert!(!packed_file_uri_matches(&bad, path), "{bad}");
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn addons_metadata_linked_inputs_do_not_read_outside_profile() {
        let f = Fixture::new();
        f.save();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"sentinel").unwrap();
        let cache = f.profile.join("addonStartup.json.lz4");
        std::fs::remove_file(&cache).unwrap();
        std::os::unix::fs::symlink(outside.path(), cache).unwrap();
        assert!(check(&f.profile, &f.mirror, None).is_err());
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"sentinel");
    }
}
