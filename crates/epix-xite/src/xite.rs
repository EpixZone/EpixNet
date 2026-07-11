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
    fn read_file(&self, inner_path: &str) -> Option<Vec<u8>> {
        self.storage.read(inner_path).ok()
    }
}

/// Files signing never hashes into a content.json (EpixNet's `hashFiles`):
/// hidden dot-files and the `-old`/`-new` publish-diff snapshots.
fn skip_hashing(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base.starts_with('.') || rel.ends_with("-old") || rel.ends_with("-new")
}

/// The content's `ignore` pattern compiled with EpixNet's `re.match`
/// semantics (anchored at the start of the relative path). An invalid or
/// missing pattern ignores nothing.
fn ignore_regex(pat: Option<&Value>) -> Option<fancy_regex::Regex> {
    let pat = pat?.as_str()?;
    if pat.is_empty() {
        return None;
    }
    fancy_regex::Regex::new(&format!("^(?:{pat})")).ok()
}

fn is_ignored(re: &Option<fancy_regex::Regex>, rel: &str) -> bool {
    re.as_ref().is_some_and(|re| re.is_match(rel).unwrap_or(false))
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
        // A user_contents parent (e.g. data/users/content.json) may archive
        // user directories; compare with the copy being replaced and delete
        // newly archived children (EpixNet's revocation path).
        let old: Option<Value> = self
            .storage
            .read(inner_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        self.storage.write(inner_path, bytes)?;
        self.apply_archived(inner_path, old.as_ref(), &json);
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

    /// EpixNet's archive semantics: when a user_contents parent (e.g.
    /// `data/users/content.json`) is replaced, a user directory named in
    /// `user_contents.archived` (or older than `user_contents.archived_before`)
    /// has its stored content removed - the moderation/revocation path. Only
    /// entries that changed against `old` are acted on, so re-applying the
    /// same parent is a no-op.
    fn apply_archived(&self, inner_path: &str, old: Option<&Value>, new: &Value) {
        let Some(uc) = new.get("user_contents") else { return };
        let dir = inner_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
        let old_uc = old.and_then(|o| o.get("user_contents"));

        if let Some(archived) = uc.get("archived").and_then(|v| v.as_object()) {
            let old_archived = old_uc.and_then(|u| u.get("archived")).and_then(|v| v.as_object());
            for (dirname, date) in archived {
                let date = date.as_f64().unwrap_or(0.0);
                let unchanged = old_archived
                    .and_then(|m| m.get(dirname))
                    .and_then(|v| v.as_f64())
                    .is_some_and(|old_date| old_date == date);
                if !unchanged {
                    self.remove_child_if_older(&format!("{dir}{dirname}/content.json"), date);
                }
            }
        }

        let before = uc.get("archived_before").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let old_before =
            old_uc.and_then(|u| u.get("archived_before")).and_then(|v| v.as_f64()).unwrap_or(0.0);
        if before > 0.0 && before != old_before {
            for child in self.child_contents_under(&dir) {
                if child != inner_path {
                    self.remove_child_if_older(&child, before);
                }
            }
        }
    }

    /// Delete a stored child content.json and its declared files when its
    /// `modified` predates `cutoff` (strictly older, like EpixNet's
    /// `removeContent` guard), pruning the emptied directory.
    fn remove_child_if_older(&self, inner_path: &str, cutoff: f64) {
        let Ok(bytes) = self.storage.read(inner_path) else { return };
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else { return };
        let modified = json.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if modified >= cutoff {
            return;
        }
        let dir = inner_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
        for node in ["files", "files_optional"] {
            if let Some(files) = json.get(node).and_then(|f| f.as_object()) {
                for rel in files.keys() {
                    let _ = self.storage.delete(&format!("{dir}{rel}"));
                }
            }
        }
        let _ = self.storage.delete(inner_path);
        // Best-effort prune of the now-empty user directory.
        if !dir.is_empty() {
            if let Ok(path) = self.storage.path(dir.trim_end_matches('/')) {
                let _ = std::fs::remove_dir(path);
            }
        }
    }

    /// Every stored `*/content.json` under `dir` (inner paths), any depth.
    fn child_contents_under(&self, dir: &str) -> Vec<String> {
        let root = self.storage.root().join(dir);
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().is_some_and(|n| n == "content.json") {
                    if let Ok(rel) = path.strip_prefix(self.storage.root()) {
                        out.push(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        out
    }

    /// EpixNet's `_pruneDataFiles`: trim arrays in the `data.json` files under
    /// `dir` per the governing rules. `max_items` `{key: N}` is a hard cap
    /// (keep the newest N); `max_items_age` `{key: seconds}` drops entries
    /// whose `timestamp` fell out of the window, but never below
    /// `max_items_min` (default 100) entries. Runs at sign time, before
    /// hashing, so the signed hashes reflect the pruned data.
    fn prune_data_files(&self, dir: &str, rules: &Value, now: f64) {
        let Some(max_items) = rules.get("max_items").and_then(|v| v.as_object()) else { return };
        let age_rules = rules.get("max_items_age").and_then(|v| v.as_object());
        let min_rules = rules.get("max_items_min").and_then(|v| v.as_object());
        let ts = |e: &Value| e.get("timestamp").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let prefix = format!("{dir}/");
        for inner in self.storage.list_files() {
            if !inner.starts_with(&prefix) || !inner.ends_with("data.json") {
                continue;
            }
            let Ok(bytes) = self.storage.read(&inner) else { continue };
            let Ok(mut data) = serde_json::from_slice::<Value>(&bytes) else { continue };
            let Some(map) = data.as_object_mut() else { continue };
            let mut changed = false;

            if let Some(age_rules) = age_rules {
                for (key, max_age) in age_rules {
                    let Some(max_age) = max_age.as_f64() else { continue };
                    let min_keep = min_rules
                        .and_then(|m| m.get(key))
                        .and_then(|v| v.as_i64())
                        .unwrap_or(100)
                        .max(0) as usize;
                    let Some(list) = map.get_mut(key).and_then(|v| v.as_array_mut()) else {
                        continue;
                    };
                    if list.len() <= min_keep {
                        continue;
                    }
                    // Oldest first, so the tail is the newest min_keep entries.
                    list.sort_by(|a, b| {
                        ts(a).partial_cmp(&ts(b)).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    let cutoff = now - max_age;
                    let keep_from = list.len() - min_keep;
                    let pruned: Vec<Value> = list
                        .iter()
                        .enumerate()
                        .filter(|(i, e)| *i >= keep_from || ts(e) >= cutoff)
                        .map(|(_, e)| e.clone())
                        .collect();
                    if pruned.len() < list.len() {
                        *list = pruned;
                        changed = true;
                    }
                }
            }

            for (key, limit) in max_items {
                let Some(limit) = limit.as_i64() else { continue };
                let limit = limit.max(0) as usize;
                let Some(list) = map.get_mut(key).and_then(|v| v.as_array_mut()) else { continue };
                if list.len() > limit {
                    *list = list[list.len() - limit..].to_vec();
                    changed = true;
                }
            }

            if changed {
                if let Ok(bytes) = serde_json::to_vec(&data) {
                    let _ = self.storage.write(&inner, &bytes);
                }
            }
        }
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

    /// Build the `files` map for the content.json unit rooted at `dir` (empty
    /// for the root): hash every file under `dir`, keyed by path relative to
    /// `dir`. Skips the unit's own content.json and nested content.json subtrees
    /// (their own signed units), entries already declared optional,
    /// hidden/transient files, and paths matching the `ignore` pattern. Shared
    /// by the root [`sign`](Self::sign) and [`sign_child`](Self::sign_child).
    fn hash_unit_files(
        &self,
        dir: &str,
        optional: &std::collections::HashSet<String>,
        ignore: &Option<fancy_regex::Regex>,
    ) -> Result<serde_json::Map<String, Value>> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        let listing = self.storage.list_files();
        // Directories governed by their own content.json own their subtrees.
        let nested_dirs: Vec<String> = listing
            .iter()
            .filter_map(|f| f.strip_prefix(prefix.as_str()))
            .filter(|rel| rel.ends_with("/content.json"))
            .map(|rel| rel[..rel.len() - "content.json".len()].to_string())
            .collect();
        let mut files = serde_json::Map::new();
        for inner in listing {
            let Some(rel) = inner.strip_prefix(prefix.as_str()).map(str::to_string) else {
                continue;
            };
            if rel == "content.json" || rel.ends_with("/content.json") || optional.contains(&rel) {
                continue;
            }
            if skip_hashing(&rel) || is_ignored(ignore, &rel) {
                continue;
            }
            if nested_dirs.iter().any(|d| rel.starts_with(d.as_str())) {
                continue;
            }
            let bytes = self.storage.read(&inner)?;
            files.insert(
                rel,
                json!({ "size": bytes.len(), "sha512": XiteStorage::hash_bytes(&bytes) }),
            );
        }
        Ok(files)
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

        let ignore = ignore_regex(content.get("ignore"));
        let files = self.hash_unit_files("", &optional, &ignore)?;

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

    /// Sign a non-root content.json - a user content.json or include - with
    /// `privatekey`, mirroring EpixNet's `ContentManager.sign`: rebuild the
    /// `files` map by hashing the files in its own directory, fill in the
    /// `extend` fields (cert data; only keys not already present), stamp
    /// `modified`/`address`/`inner_path`, sign, then verify against the
    /// parent's rules (signers, cert) and store - so anything the network
    /// would reject fails here instead of after publishing.
    pub fn sign_child(
        &self,
        inner_path: &str,
        privatekey: &str,
        modified: f64,
        extend: &serde_json::Map<String, Value>,
        xid_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<Value> {
        let Some((dir, name)) = inner_path.rsplit_once('/') else {
            return Err(Error::Protocol(format!("not a child content.json: {inner_path}")));
        };
        if name != "content.json" {
            return Err(Error::Protocol(format!("can only sign content.json files: {inner_path}")));
        }

        let mut content: Value = match self.storage.read(inner_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(_) => json!({}),
        };
        let map = content
            .as_object_mut()
            .ok_or_else(|| Error::Protocol("content.json is not a JSON object".into()))?;
        for (key, val) in extend {
            let missing = map.get(key).map(|v| v.is_null()).unwrap_or(true);
            if missing {
                map.insert(key.clone(), val.clone());
            }
        }

        // EpixNet's sign-time auto-prune: the parent's rules may cap arrays in
        // this directory's data.json files (`max_items`, with age/min
        // variants). Trim before hashing so the signed hashes reflect the
        // pruned data and the result passes the receiver's max_items check.
        {
            let ctx = ChildCtx {
                address: self.address.as_str().to_string(),
                storage: &self.storage,
                xid_map,
            };
            if let Some(rules) = epix_content::verify::get_rules(inner_path, &content, &ctx) {
                self.prune_data_files(dir, &rules, modified);
            }
        }
        let map = content
            .as_object_mut()
            .ok_or_else(|| Error::Protocol("content.json is not a JSON object".into()))?;

        // Hash this directory's files. Nested content.json files are their own
        // signed units; entries already declared optional keep their metadata
        // (they may not be on disk).
        let optional: std::collections::HashSet<String> = map
            .get("files_optional")
            .and_then(|v| v.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let ignore = ignore_regex(map.get("ignore"));
        let files = self.hash_unit_files(dir, &optional, &ignore)?;
        map.insert("files".into(), Value::Object(files));
        if modified.fract() == 0.0 {
            map.insert("modified".into(), json!(modified as i64));
        } else {
            map.insert("modified".into(), json!(modified));
        }
        map.insert("address".into(), json!(self.address.as_str()));
        map.insert("inner_path".into(), json!(inner_path));

        epix_content::sign(&mut content, privatekey)?;
        let bytes = serde_json::to_vec(&content).map_err(Error::from)?;
        // add_content verifies (signer allowed, cert valid, sizes) and stores.
        self.add_content(inner_path, &bytes, xid_map)?;
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epix_core::Address;

    /// Sign `content` with `privkey` and return its bytes.
    fn signed(mut content: Value, privkey: &str) -> Vec<u8> {
        epix_content::sign(&mut content, privkey).unwrap();
        serde_json::to_vec(&content).unwrap()
    }

    #[test]
    fn archiving_a_user_directory_deletes_its_content() {
        // A user_contents parent update that archives a user dir removes that
        // user's stored content.json and files (EpixNet's revocation path);
        // re-applying the same parent is a no-op for others.
        let site_pk = epix_crypt::new_seed();
        let site = epix_crypt::privatekey_to_address(&site_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user = epix_crypt::privatekey_to_address(&user_pk).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(site.clone()).unwrap(), storage.clone());
        let none = std::collections::HashMap::new();

        // Root delegates data/users/content.json to the site owner.
        storage
            .write(
                "content.json",
                &signed(
                    serde_json::json!({
                        "address": site, "modified": 1, "files": {},
                        "includes": { "data/users/content.json": {} },
                    }),
                    &site_pk,
                ),
            )
            .unwrap();

        // Parent v1: permissive user_contents, nothing archived.
        let parent_v1 = signed(
            serde_json::json!({
                "address": site, "inner_path": "data/users/content.json",
                "modified": 10, "files": {},
                "user_contents": { "permissions": {}, "cert_signers": {} },
            }),
            &site_pk,
        );
        xite.add_content("data/users/content.json", &parent_v1, &none).unwrap();

        // A user posts: their content.json + a data file.
        let user_inner = format!("data/users/{user}/content.json");
        let data_inner = format!("data/users/{user}/data.json");
        let data = br#"{"topic":[]}"#;
        storage.write(&data_inner, data).unwrap();
        let child = signed(
            serde_json::json!({
                "address": site, "inner_path": user_inner, "modified": 100,
                "files": { "data.json": {
                    "size": data.len(),
                    "sha512": XiteStorage::hash_bytes(data),
                } },
            }),
            &user_pk,
        );
        xite.add_content(&user_inner, &child, &none).unwrap();
        assert!(storage.exists(&user_inner) && storage.exists(&data_inner));

        // Parent v2 archives the user dir at t=500 (> the child's 100).
        let parent_v2 = signed(
            serde_json::json!({
                "address": site, "inner_path": "data/users/content.json",
                "modified": 20, "files": {},
                "user_contents": {
                    "permissions": {}, "cert_signers": {},
                    "archived": { user.clone(): 500 },
                },
            }),
            &site_pk,
        );
        xite.add_content("data/users/content.json", &parent_v2, &none).unwrap();
        assert!(!storage.exists(&user_inner), "archived child content removed");
        assert!(!storage.exists(&data_inner), "archived child files removed");

        // And the revoked user can no longer push old content back.
        let err = xite.add_content(&user_inner, &child, &none).unwrap_err();
        assert!(err.to_string().contains("archived"), "{err}");
    }
}
