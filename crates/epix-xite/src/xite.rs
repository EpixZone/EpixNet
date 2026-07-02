//! A xite: its address, storage, and (once loaded) verified content.json.

use crate::storage::XiteStorage;
use epix_core::{Address, Error, Result};
use serde_json::{json, Value};

/// One entry from content.json `files`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub inner_path: String,
    pub size: i64,
    pub sha512: String,
}

pub struct Xite {
    pub address: Address,
    pub storage: XiteStorage,
    /// The verified content.json (root), once loaded.
    pub content: Option<Value>,
}

impl Xite {
    pub fn new(address: Address, storage: XiteStorage) -> Self {
        Self { address, storage, content: None }
    }

    /// Load `content.json` from storage (if present) and verify it. Returns
    /// `false` if there is no stored content.json yet.
    pub fn load_content(&mut self) -> Result<bool> {
        if !self.storage.exists("content.json") {
            return Ok(false);
        }
        let bytes = self.storage.read("content.json")?;
        self.set_content(&bytes)?;
        Ok(true)
    }

    /// Verify `content.json` is signed by the xite address, then store + parse it.
    pub fn set_content(&mut self, bytes: &[u8]) -> Result<()> {
        let json: Value = serde_json::from_slice(bytes)?;
        if !epix_content::verify_signer(&json, self.address.as_str()) {
            return Err(Error::Crypt(
                "content.json is not validly signed by the xite address".into(),
            ));
        }
        self.storage.write("content.json", bytes)?;
        self.content = Some(json);
        Ok(())
    }

    /// Files declared under a content.json node (`files` or `files_optional`).
    fn files_under(&self, node: &str) -> Vec<FileEntry> {
        self.content
            .as_ref()
            .and_then(|c| c.get(node))
            .and_then(|f| f.as_object())
            .map(|files| {
                files
                    .iter()
                    .filter_map(|(path, info)| {
                        Some(FileEntry {
                            inner_path: path.clone(),
                            size: info.get("size")?.as_i64()?,
                            sha512: info.get("sha512")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All required files declared in content.json (`files`).
    pub fn files(&self) -> Vec<FileEntry> {
        self.files_under("files")
    }

    /// Optional files (`files_optional`) — declared but not auto-downloaded.
    pub fn optional_files(&self) -> Vec<FileEntry> {
        self.files_under("files_optional")
    }

    /// Info for one file by inner path (required or optional).
    pub fn file_info(&self, inner_path: &str) -> Option<FileEntry> {
        self.files()
            .into_iter()
            .chain(self.optional_files())
            .find(|f| f.inner_path == inner_path)
    }

    /// Required files that are missing on disk or fail their hash.
    pub fn files_needed(&self) -> Vec<FileEntry> {
        self.files()
            .into_iter()
            .filter(|f| !self.storage.verify(&f.inner_path, &f.sha512))
            .collect()
    }

    /// Sign the root content.json with `privatekey`: rebuild the `files` map by
    /// hashing every file under the root (except content.json files, which are
    /// their own signed units), set `modified` (must exceed the previous value),
    /// stamp the address, sign, and write.
    ///
    /// The key must own the xite (its address must equal the xite address),
    /// otherwise the resulting signature wouldn't verify.
    pub fn sign(&mut self, privatekey: &str, modified: f64) -> Result<()> {
        let signer =
            epix_crypt::privatekey_to_address(privatekey).map_err(Error::Crypt)?;
        if signer != self.address.as_str() {
            return Err(Error::Crypt(format!(
                "private key address {signer} does not own xite {}",
                self.address.as_str()
            )));
        }

        let mut content = self.content.clone().unwrap_or_else(|| json!({}));

        // Files already declared optional stay optional; everything else on disk
        // (minus content.json units) becomes a required file with size + hash.
        let optional: std::collections::HashSet<String> = content
            .get("files_optional")
            .and_then(|v| v.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();

        let mut files = serde_json::Map::new();
        for inner in self.storage.list_files() {
            if inner == "content.json" || inner.ends_with("/content.json") || optional.contains(&inner) {
                continue;
            }
            let bytes = self.storage.read(&inner)?;
            files.insert(
                inner,
                json!({ "size": bytes.len(), "sha512": XiteStorage::hash_bytes(&bytes) }),
            );
        }

        let map = content.as_object_mut().ok_or_else(|| {
            Error::Protocol("content.json is not a JSON object".into())
        })?;
        map.insert("files".into(), Value::Object(files));
        map.insert("modified".into(), json!(modified));
        map.insert("address".into(), json!(self.address.as_str()));

        epix_content::sign(&mut content, privatekey)?;
        let bytes = serde_json::to_vec(&content).map_err(Error::from)?;
        self.storage.write("content.json", &bytes)?;
        self.content = Some(content);
        Ok(())
    }
}
