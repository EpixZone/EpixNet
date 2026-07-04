//! A xite: its address, storage, and (once loaded) verified content.json.

use crate::storage::XiteStorage;
use epix_content::VerifyContext;
use epix_core::{Address, Error, Result};
use serde_json::{json, Value};

/// Verification context for a root content.json: only the site address and the
/// size limit are needed (the root's rules bootstrap from itself).
struct RootCtx {
    address: String,
    size_limit: i64,
}
impl VerifyContext for RootCtx {
    fn site_address(&self) -> &str {
        &self.address
    }
    fn loaded_content(&self, _inner_path: &str) -> Option<Value> {
        None
    }
    fn size_limit_bytes(&self) -> i64 {
        self.size_limit
    }
}

/// Verification context for a non-root content.json (an include or a user
/// content.json): resolves parent content.json files from storage so the
/// signer/cert rules can be checked.
struct ChildCtx<'a> {
    address: String,
    storage: &'a XiteStorage,
    xid_map: &'a std::collections::HashMap<String, Vec<String>>,
}
impl VerifyContext for ChildCtx<'_> {
    fn site_address(&self) -> &str {
        &self.address
    }
    fn loaded_content(&self, inner_path: &str) -> Option<Value> {
        let bytes = self.storage.read(inner_path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }
    fn resolve_xid(&self, name: &str) -> Vec<String> {
        self.xid_map.get(name).cloned().unwrap_or_default()
    }
}

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

    /// Verify + store the root `content.json` with no size limit. See
    /// [`Self::set_content_limited`].
    pub fn set_content(&mut self, bytes: &[u8]) -> Result<()> {
        self.set_content_limited(bytes, i64::MAX)
    }

    /// Verify the root `content.json` - signatures against the valid signers
    /// (including a delegated `signers` list authorized by `signers_sign`),
    /// address/inner_path/relative-path rules, and the `size_limit` (bytes) -
    /// then store + parse it. This is the full EpixNet `verifyFile` path, not
    /// just a single-owner signature.
    pub fn set_content_limited(&mut self, bytes: &[u8], size_limit: i64) -> Result<()> {
        let json: Value = serde_json::from_slice(bytes)?;
        let ctx = RootCtx { address: self.address.as_str().to_string(), size_limit };
        epix_content::verify_content_file("content.json", &json, bytes.len() as i64, &ctx)
            .map_err(|e| Error::Crypt(e.to_string()))?;
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

    /// This xite's storage handle.
    pub fn storage(&self) -> &XiteStorage {
        &self.storage
    }

    /// The `includes` inner_paths declared in a content.json value.
    pub fn includes_in(content: &Value) -> Vec<String> {
        content
            .get("includes")
            .and_then(|v| v.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// The `includes` declared in the root content.json.
    pub fn includes(&self) -> Vec<String> {
        self.content.as_ref().map(Self::includes_in).unwrap_or_default()
    }

    /// Verify + store a non-root content.json (an include or a user
    /// content.json) whose PARENT content.json is already on disk, then return
    /// the files it declares (`files` + `files_optional`). `inner_path` is the
    /// child's path, e.g. `data/users/1abc/content.json`.
    pub fn add_content(
        &self,
        inner_path: &str,
        bytes: &[u8],
        xid_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<Vec<FileEntry>> {
        let json: Value = serde_json::from_slice(bytes)?;
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            xid_map,
        };
        epix_content::verify_content_file(inner_path, &json, bytes.len() as i64, &ctx)
            .map_err(|e| Error::Crypt(e.to_string()))?;
        self.storage.write(inner_path, bytes)?;
        // The child's declared files are relative to its own directory.
        let dir = match inner_path.rsplit_once('/') {
            Some((d, _)) => d.to_string(),
            None => String::new(),
        };
        let join = |rel: &str| if dir.is_empty() { rel.to_string() } else { format!("{dir}/{rel}") };
        let mut out = Vec::new();
        for node in ["files", "files_optional"] {
            if let Some(files) = json.get(node).and_then(|f| f.as_object()) {
                for (path, info) in files {
                    if let (Some(size), Some(sha512)) = (
                        info.get("size").and_then(|v| v.as_i64()),
                        info.get("sha512").and_then(|v| v.as_str()),
                    ) {
                        out.push(FileEntry {
                            inner_path: join(path),
                            size,
                            sha512: sha512.to_string(),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    /// The `includes` a stored child content.json declares, as inner_paths
    /// relative to the site root (for recursing into nested includes).
    pub fn child_includes(&self, inner_path: &str) -> Vec<String> {
        let Ok(bytes) = self.storage.read(inner_path) else { return Vec::new() };
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else { return Vec::new() };
        let dir = inner_path.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default();
        Self::includes_in(&json)
            .into_iter()
            .map(|rel| if dir.is_empty() { rel } else { format!("{dir}/{rel}") })
            .collect()
    }

    /// All required files declared in content.json (`files`).
    pub fn files(&self) -> Vec<FileEntry> {
        self.files_under("files")
    }

    /// Optional files (`files_optional`) - declared but not auto-downloaded.
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
        // EpixNet signs an integer `modified` (int(time.time())); keep whole
        // seconds as an integer so our output matches, but allow a fractional
        // bump (prev + 1.0 collisions never produce one in practice).
        if modified.fract() == 0.0 {
            map.insert("modified".into(), json!(modified as i64));
        } else {
            map.insert("modified".into(), json!(modified));
        }
        map.insert("address".into(), json!(self.address.as_str()));
        map.insert("inner_path".into(), json!("content.json"));
        if !map.contains_key("signs_required") {
            map.insert("signs_required".into(), json!(1));
        }

        epix_content::sign(&mut content, privatekey)?;
        let bytes = serde_json::to_vec(&content).map_err(Error::from)?;
        self.storage.write("content.json", &bytes)?;
        self.content = Some(content);
        Ok(())
    }
}
