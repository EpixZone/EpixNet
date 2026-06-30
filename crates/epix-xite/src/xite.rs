//! A xite: its address, storage, and (once loaded) verified content.json.

use crate::storage::XiteStorage;
use epix_core::{Address, Error, Result};
use serde_json::Value;

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

    /// All files declared in content.json.
    pub fn files(&self) -> Vec<FileEntry> {
        self.content
            .as_ref()
            .and_then(|c| c.get("files"))
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

    /// Declared files that are missing on disk or fail their hash.
    pub fn files_needed(&self) -> Vec<FileEntry> {
        self.files()
            .into_iter()
            .filter(|f| !self.storage.verify(&f.inner_path, &f.sha512))
            .collect()
    }
}
