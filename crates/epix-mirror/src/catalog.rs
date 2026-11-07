use crate::{safe_path, MAX_BYTES, MAX_CATALOG, MAX_FILE, MAX_FILES};
use anyhow::{bail, ensure, Result};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileInfo {
    pub size: u64,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub version: u64,
    pub manager: String,
    pub expires: String,
    pub files: BTreeMap<String, FileInfo>,
    pub routes: BTreeMap<String, String>,
    pub snapshot: String,
}
impl Catalog {
    pub fn new(
        manager: String,
        expires: String,
        files: BTreeMap<String, FileInfo>,
        routes: BTreeMap<String, String>,
    ) -> Result<Self> {
        let mut catalog = Self {
            version: 1,
            manager,
            expires,
            files,
            routes,
            snapshot: String::new(),
        };
        catalog.snapshot = catalog.digest()?;
        catalog.check()?;
        Ok(catalog)
    }
    pub fn digest(&self) -> Result<String> {
        let mut unsigned = serde_json::to_value(self)?;
        unsigned
            .as_object_mut()
            .expect("catalog object")
            .remove("snapshot");
        Ok(hex::encode(Sha256::digest(encode(&unsigned)?)))
    }
    pub fn summary(&self) -> Value {
        json!({"snapshot":self.snapshot,"manager":self.manager,"expires":self.expires})
    }
    pub fn check(&self) -> Result<()> {
        ensure!(self.version == 1, "Unsupported snapshot catalog");
        ensure!(
            ["apt", "dnf", "homebrew", "chocolatey"].contains(&self.manager.as_str()),
            "Unsupported package manager"
        );
        ensure!(
            !self.files.is_empty() && self.files.len() <= MAX_FILES,
            "Snapshot must contain 1 to 60,000 files"
        );
        let mut folded = HashSet::new();
        let mut total = 0u64;
        for (path, info) in &self.files {
            safe_path(path)?;
            ensure!(
                folded.insert(collision_key(path)),
                "Case-insensitive path collision"
            );
            ensure!(
                info.size <= MAX_FILE && valid_digest(&info.sha256),
                "Invalid file metadata"
            );
            total = total
                .checked_add(info.size)
                .ok_or_else(|| anyhow::anyhow!("Snapshot byte count overflow"))?;
            ensure!(total <= MAX_BYTES, "Snapshot exceeds 15 GiB");
        }
        self.check_routes()?;
        ensure!(
            self.snapshot == self.digest()?,
            "Catalog snapshot digest mismatch"
        );
        fresh(self)
    }
    fn check_routes(&self) -> Result<()> {
        ensure!(self.routes.len() <= MAX_FILES, "Too many artifact routes");
        ensure!(
            self.manager == "homebrew" || self.routes.is_empty(),
            "Artifact routes are only for Homebrew"
        );
        for (route, path) in &self.routes {
            ensure!(
                self.files.contains_key(path) && route.len() <= 4096,
                "Invalid artifact route"
            );
            ensure!(
                route.starts_with("/https://")
                    || route.starts_with("/http://")
                    || route.starts_with("/v2/"),
                "Invalid artifact route prefix"
            );
            ensure!(
                !route
                    .chars()
                    .any(|c| c.is_control() || matches!(c, '#' | '\\')),
                "Invalid artifact route characters"
            );
        }
        Ok(())
    }
}
/// Conservatively reject case aliases, including multi-character folds such as ß.
pub(crate) fn collision_key(path: &str) -> String {
    path.to_uppercase().to_lowercase()
}
pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn timestamp(value: &str) -> Result<i64> {
    Ok(chrono::DateTime::parse_from_rfc3339(value)?.timestamp())
}
pub fn fresh(catalog: &Catalog) -> Result<()> {
    ensure!(
        timestamp(&catalog.expires)? > chrono::Utc::now().timestamp(),
        "Snapshot expired; obtain a fresh signed snapshot"
    );
    Ok(())
}

/// Stable sorted, ASCII-escaped JSON with a final newline. Version 1 catalogs
/// remain portable across tools, including Unicode repository path names.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    fn canonical(value: &Value, out: &mut String) -> Result<()> {
        match value {
            Value::Object(map) => {
                out.push('{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key)?);
                    out.push(':');
                    canonical(&map[key], out)?;
                }
                out.push('}');
            }
            Value::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    canonical(value, out)?;
                }
                out.push(']');
            }
            _ => out.push_str(&serde_json::to_string(value)?),
        }
        Ok(())
    }
    let mut text = String::new();
    canonical(value, &mut text)?;
    let mut ascii = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii() {
            ascii.push(character);
        } else {
            let mut encoded = [0; 2];
            for unit in character.encode_utf16(&mut encoded) {
                use std::fmt::Write;
                write!(ascii, "\\u{unit:04x}")?;
            }
        }
    }
    ascii.push('\n');
    ensure!(ascii.len() as u64 <= MAX_CATALOG, "Metadata exceeds 8 MiB");
    Ok(ascii.into_bytes())
}

struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("JSON without duplicate keys")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> std::result::Result<Unique, E> {
        Ok(Unique(json!(v)))
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(Unique(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(Unique(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Unique, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
            if values.insert(key.clone(), value).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "Duplicate JSON key: {key}"
                )));
            }
        }
        Ok(Unique(Value::Object(values)))
    }
}
pub fn decode(data: &[u8]) -> Result<Value> {
    if data.len() as u64 > MAX_CATALOG {
        bail!("Metadata exceeds 8 MiB");
    }
    Ok(serde_json::from_slice::<Unique>(data)?.0)
}
