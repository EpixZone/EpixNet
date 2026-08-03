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

/// A content path pattern (`ignore` or `optional`) compiled with EpixNet's
/// `re.match` semantics (anchored at the start of the relative path). An
/// invalid or missing pattern matches nothing - `hashFiles` never fails a
/// sign over a bad regex.
fn path_pattern(pat: Option<&Value>) -> Option<fancy_regex::Regex> {
    let pat = pat?.as_str()?;
    if pat.is_empty() {
        return None;
    }
    fancy_regex::Regex::new(&format!("^(?:{pat})")).ok()
}

fn pattern_matches(re: &Option<fancy_regex::Regex>, rel: &str) -> bool {
    re.as_ref().is_some_and(|re| re.is_match(rel).unwrap_or(false))
}

/// How `hash_unit_files` treats one dir-relative path: `None` skips it
/// (content.json units, transient files, ignored paths, nested units, and
/// declared-optional entries whose stored metadata must survive), otherwise
/// whether it hashes into `files_optional` instead of `files`.
fn unit_file_class(
    rel: &str,
    nested_dirs: &[String],
    declared_optional: &serde_json::Map<String, Value>,
    declared_merged: &serde_json::Map<String, Value>,
    ignore: &Option<fancy_regex::Regex>,
    optional: &Option<fancy_regex::Regex>,
) -> Option<bool> {
    if rel == "content.json" || rel.ends_with("/content.json") {
        return None;
    }
    if skip_hashing(rel) || pattern_matches(ignore, rel) {
        return None;
    }
    // A declared merge file (posts.json) is verified per-record, NEVER hashed
    // into `files`/`files_optional` - hashing it would re-arm last-writer-wins.
    if declared_merged.contains_key(rel) {
        return None;
    }
    if nested_dirs.iter().any(|d| rel.starts_with(d.as_str())) {
        return None;
    }
    let is_optional = pattern_matches(optional, rel);
    if !is_optional && declared_optional.contains_key(rel) {
        return None;
    }
    Some(is_optional)
}

/// Apply a `sign` `extend` map onto a content.json object: every key is added
/// only when missing (cert fields), EXCEPT `files_merged`, which is UNIONED -
/// an app that declares a SECOND merge file later must get it added, not
/// skipped (a skipped declaration would be signed as a hashed last-writer-wins
/// file, the exact bug the merge class prevents).
fn apply_extend(map: &mut serde_json::Map<String, Value>, extend: &serde_json::Map<String, Value>) {
    for (key, val) in extend {
        if key == "files_merged" {
            let dst =
                map.entry("files_merged").or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let (Some(dst), Some(src)) = (dst.as_object_mut(), val.as_object()) {
                for (k, v) in src {
                    dst.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
            continue;
        }
        if map.get(key).map(|v| v.is_null()).unwrap_or(true) {
            map.insert(key.clone(), val.clone());
        }
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
        // Already on disk - verify + parse into memory, don't re-write it.
        self.stage_content(&bytes)?;
        Ok(true)
    }

    /// Parse a stored `content.json` for serving the LOCAL copy, WITHOUT
    /// signature verification. Returns `false` if none is stored or it is not
    /// valid JSON. A signature is only required when fetching content from peers
    /// (see [`Self::set_content`]); content already on disk - a site the
    /// operator authored, edited, or has not signed yet - is served as-is, so
    /// its files can be opened and then signed. Never call this on bytes
    /// received from a peer.
    pub fn load_content_local(&mut self) -> bool {
        let Ok(bytes) = self.storage.read("content.json") else { return false };
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else { return false };
        self.content = Some(json);
        true
    }

    /// Verify + store the root `content.json` with no size limit. See
    /// [`Self::set_content_limited`].
    pub fn set_content(&mut self, bytes: &[u8]) -> Result<()> {
        self.set_content_limited(bytes, i64::MAX)
    }

    /// [`Self::stage_content_limited`] with no size limit.
    pub fn stage_content(&mut self, bytes: &[u8]) -> Result<()> {
        self.stage_content_limited(bytes, i64::MAX)
    }

    /// Verify the root `content.json` - signatures against the valid signers
    /// (including a delegated `signers` list authorized by `signers_sign`),
    /// address/inner_path/relative-path rules, and the `size_limit` (bytes) -
    /// and adopt it IN MEMORY ONLY. Sync workers read `self.content`, so this
    /// is enough to start fetching the files it declares; nothing touches the
    /// stored content.json until [`Self::commit_content`], keeping the old
    /// on-disk version authoritative (and the site serving) through the sync.
    /// This is the full EpixNet `verifyFile` path, not just a single-owner
    /// signature.
    pub fn stage_content_limited(&mut self, bytes: &[u8], size_limit: i64) -> Result<()> {
        let json: Value = serde_json::from_slice(bytes)?;
        let ctx = RootCtx { address: self.address.as_str().to_string(), size_limit };
        epix_content::verify_content_file("content.json", &json, bytes.len() as i64, &ctx)
            .map_err(|e| Error::Crypt(e.to_string()))?;
        self.content = Some(json);
        Ok(())
    }

    /// Commit staged root content.json bytes to disk atomically. Call once the
    /// files the staged content declares are present, so the on-disk
    /// content.json (the completeness marker) never gets ahead of its files.
    pub fn commit_content(&self, bytes: &[u8]) -> Result<()> {
        self.storage.write_atomic("content.json", bytes)
    }

    /// Verify + adopt + commit the root `content.json` in one step: stage
    /// ([`Self::stage_content_limited`]) then commit ([`Self::commit_content`]).
    /// For paths where the declared files are already known-present (owner
    /// signing, local edits); sync paths should stage first and commit after
    /// the files arrive.
    pub fn set_content_limited(&mut self, bytes: &[u8], size_limit: i64) -> Result<()> {
        self.stage_content_limited(bytes, size_limit)?;
        self.commit_content(bytes)
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

    pub fn content_rules(
        &self,
        inner_path: &str,
        content: &Value,
        xid_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Option<Value> {
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            xid_map,
        };
        epix_content::verify::get_rules(inner_path, content, &ctx)
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

    /// The authorized signer set for the content.json unit at
    /// `content_inner_path` (root or a user content.json), resolving xID-name
    /// signers via `xid_map`. Used by the merge path to decide which addresses
    /// may author records in a directory. Empty if the content.json is absent
    /// or unparseable.
    pub fn valid_signers_for(
        &self,
        content_inner_path: &str,
        xid_map: &std::collections::HashMap<String, Vec<String>>,
    ) -> Vec<String> {
        let Ok(bytes) = self.storage.read(content_inner_path) else {
            return Vec::new();
        };
        let Ok(content) = serde_json::from_slice::<Value>(&bytes) else {
            return Vec::new();
        };
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            xid_map,
        };
        epix_content::verify::valid_signers(content_inner_path, &content, &ctx)
    }

    /// Build the `files` and `files_optional` maps for the content.json unit
    /// rooted at `dir` (empty for the root): hash every file under `dir`,
    /// keyed by path relative to `dir`. Skips the unit's own content.json and
    /// nested content.json subtrees (their own signed units), hidden/transient
    /// files, and paths matching the `ignore` pattern. A file matching the
    /// unit's `optional` pattern hashes into the second map (EpixNet's
    /// `hashFiles` matches it against the same dir-relative path as `ignore`);
    /// a file only in `declared_optional` is skipped so its stored entry
    /// survives (it may not be on disk). Shared by the root
    /// [`sign`](Self::sign) and [`sign_child`](Self::sign_child).
    ///
    /// The third return value is the bytes of every bundle-eligible required
    /// file (the only ones that bundle), so
    /// [`stamp_edx_manifest`](Self::stamp_edx_manifest) can build the bundles
    /// from exactly what was hashed. Re-reading there instead would sign a
    /// manifest whose bundle bytes disagree with the b3/size it declares when
    /// an app rewrites a file mid-sign.
    fn hash_unit_files(
        &self,
        dir: &str,
        declared_optional: &serde_json::Map<String, Value>,
        declared_merged: &serde_json::Map<String, Value>,
        ignore: &Option<fancy_regex::Regex>,
        optional: &Option<fancy_regex::Regex>,
    ) -> Result<(
        serde_json::Map<String, Value>,
        serde_json::Map<String, Value>,
        std::collections::BTreeMap<String, Vec<u8>>,
    )> {
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
        let mut files_optional = serde_json::Map::new();
        let mut hashed_bytes = std::collections::BTreeMap::new();
        for inner in listing {
            let Some(rel) = inner.strip_prefix(prefix.as_str()).map(str::to_string) else {
                continue;
            };
            let Some(is_optional) = unit_file_class(
                &rel,
                &nested_dirs,
                declared_optional,
                declared_merged,
                ignore,
                optional,
            ) else {
                continue;
            };
            let bytes = self.storage.read(&inner)?;
            // `b3` is the EDX per-file BLAKE3 root (docs/edx-manifest.md);
            // `sha512` stays alongside it for the migration window.
            let entry = json!({
                "size": bytes.len(),
                "sha512": XiteStorage::hash_bytes(&bytes),
                "b3": epix_blob::ObjId::of(&bytes).to_string(),
            });
            if is_optional {
                files_optional.insert(rel, entry);
            } else {
                // Only required files bundle, so only they are worth keeping:
                // an optional-heavy xite must not pay for a cache nothing reads.
                if epix_blob::bundle::is_bundleable(bytes.len() as u64) {
                    hashed_bytes.insert(rel.clone(), bytes);
                }
                files.insert(rel, entry);
            }
        }
        Ok((files, files_optional, hashed_bytes))
    }

    /// Merge `files_optional` rebuilt by [`hash_unit_files`](Self::hash_unit_files)
    /// with the entries already declared in the unit and store the result on
    /// `map`: declared entries whose file was not re-hashed keep their metadata
    /// (EpixNet's sign with `remove_missing_optional=False`). The key is only
    /// written when there is something to declare, so a unit that never had
    /// optional files signs byte-identically to before.
    fn merge_files_optional(
        map: &mut serde_json::Map<String, Value>,
        mut files_optional: serde_json::Map<String, Value>,
        declared_optional: serde_json::Map<String, Value>,
    ) {
        for (rel, entry) in declared_optional {
            files_optional.entry(rel).or_insert(entry);
        }
        if !files_optional.is_empty() {
            map.insert("files_optional".into(), Value::Object(files_optional));
        }
    }

    /// Sign the root content.json with `privatekey`: rebuild the `files` map by
    /// hashing every file under the root (except content.json files, which are
    /// their own signed units), set `modified` (must exceed the previous value),
    /// stamp the address, sign, and write.
    ///
    /// The key must own the xite (its address must equal the xite address),
    /// otherwise the resulting signature wouldn't verify.
    pub fn sign(&mut self, privatekey: &str, modified: f64) -> Result<()> {
        // The underlying failure is a base58check/curve detail (checksum byte
        // arrays and the like). This message reaches the user as a notification,
        // and there is nothing actionable in the detail: the key is unusable.
        let signer = epix_crypt::privatekey_to_address(privatekey)
            .map_err(|_| Error::Crypt("that is not a valid private key".into()))?;
        if signer != self.address.as_str() {
            return Err(Error::Crypt(format!(
                "private key address {signer} does not own xite {}",
                self.address.as_str()
            )));
        }

        let mut content = self.content.clone().unwrap_or_else(|| json!({}));

        // Files already declared optional stay optional; new files matching the
        // content's `optional` pattern sign as optional; everything else on
        // disk (minus content.json units) becomes a required file.
        let declared_optional: serde_json::Map<String, Value> = content
            .get("files_optional")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        // Declared merge files (posts.json) are re-emitted untouched (`sign`
        // only overwrites `files`/`files_optional`) and skipped by the hasher.
        let declared_merged: serde_json::Map<String, Value> = content
            .get("files_merged")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        let ignore = path_pattern(content.get("ignore"));
        let optional = path_pattern(content.get("optional"));
        // Files matching the `shard` pattern are self-encrypted (private).
        let shard = path_pattern(content.get("shard"));
        let (files, files_optional, hashed_bytes) =
            self.hash_unit_files("", &declared_optional, &declared_merged, &ignore, &optional)?;

        let map = content.as_object_mut().ok_or_else(|| {
            Error::Protocol("content.json is not a JSON object".into())
        })?;
        map.insert("files".into(), Value::Object(files));
        Self::merge_files_optional(map, files_optional, declared_optional);
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

        self.encrypt_shard_files(&mut content, &shard)?;
        self.stamp_edx_manifest(&mut content, hashed_bytes)?;

        epix_content::sign(&mut content, privatekey)?;
        // Python-EpixNet's on-disk format (helper.jsonDumps): human-readable
        // and diff-friendly; the signature covers the canonical form, not this.
        let bytes = epix_content::dumps_content(&content).into_bytes();
        self.storage.write_atomic("content.json", &bytes)?;
        self.content = Some(content);
        Ok(())
    }

    /// EDX shards: files matching the `shard` pattern are self-encrypted
    /// into content-addressed ciphertext shards. Their data-map (chunk
    /// list + the xite salt) lives in the signed content.json, so a reader
    /// who resolves the xite can decrypt, while a volunteer that only holds
    /// ciphertext shards by hash cannot. They leave `files` and
    /// `files_optional` entirely, so they are never served or hashed as
    /// plaintext.
    ///
    /// A content with no `shard` pattern is left untouched - no salt is
    /// stamped and any stored `files_shard` stays as it is.
    fn encrypt_shard_files(
        &self,
        content: &mut Value,
        shard: &Option<fancy_regex::Regex>,
    ) -> Result<()> {
        if shard.is_none() {
            return Ok(());
        }
        let salt = self.ensure_edx_salt(content);
        content.as_object_mut().and_then(|o| o.remove("files_shard"));
        // `files_optional` is scanned too: a path can match the `optional`
        // pattern as well (or be a declared-optional entry carried over), and
        // the shard pattern has to win - the owner marked it private.
        let shard_paths: Vec<(&'static str, String)> = ["files", "files_optional"]
            .into_iter()
            .flat_map(|key| {
                content
                    .get(key)
                    .and_then(Value::as_object)
                    .map(|f| {
                        f.keys()
                            .filter(|p| pattern_matches(shard, p))
                            .map(|p| (key, p.clone()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();
        for (key, path) in shard_paths {
            // A declared-optional entry may have no local copy. Fail the sign
            // rather than re-publish its plaintext hash under a shard pattern.
            let Ok(bytes) = self.storage.read(&path) else {
                return Err(Error::Protocol(format!(
                    "{path} matches the shard pattern but is not on disk, so it cannot be \
                     encrypted; fetch it or drop it from files_optional before signing"
                )));
            };
            let enc = epix_selfenc::encrypt_convergent(&bytes, &salt);
            let chunks: Vec<epix_blob::manifest::ShardChunk> = enc
                .chunks
                .iter()
                .zip(&enc.shards)
                .map(|(c, (_addr, ct))| epix_blob::manifest::ShardChunk {
                    plain_hash: c.plain_hash,
                    cipher_addr: epix_blob::ObjId(c.cipher_addr),
                    len: c.len,
                    csize: ct.len() as u32,
                })
                .collect();
            epix_blob::manifest::set_shard_entry(
                content,
                &path,
                &epix_blob::manifest::ShardEntry { size: bytes.len() as u64, mode: 0, chunks },
            );
            if let Some(f) = content.get_mut(key).and_then(Value::as_object_mut) {
                f.remove(&path);
            }
        }
        // A unit whose only optional entries became shards must sign as one
        // that never had any (`merge_files_optional` omits the empty key).
        if content.get("files_optional").and_then(Value::as_object).is_some_and(|f| f.is_empty()) {
            content.as_object_mut().and_then(|o| o.remove("files_optional"));
        }
        Ok(())
    }

    /// EDX (docs/edx-manifest.md): bundle small required files with
    /// STABLE assignment against the previous manifest, then stamp
    /// b3/bundle/off, the bundles section, files_merkle_root and edx:1.
    ///
    /// The stability comes from `self.content`, the manifest as it was BEFORE
    /// this sign, so the bundles it already published keep their members.
    ///
    /// `hashed_bytes` is what [`hash_unit_files`](Self::hash_unit_files) read
    /// to compute the declared b3/size; bundles must be built from those exact
    /// bytes, never a second read.
    fn stamp_edx_manifest(
        &self,
        content: &mut Value,
        hashed_bytes: std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        let prev_bundles = self
            .content
            .as_ref()
            .map(epix_blob::manifest::prev_memberships)
            .unwrap_or_default();
        let roots = Self::edx_file_roots(content);
        let bundleable = self.edx_bundle_inputs(content, hashed_bytes)?;
        let assignment = epix_blob::bundle::assign(&bundleable, &prev_bundles);
        epix_blob::manifest::apply_edx(content, &roots, &assignment);
        Ok(())
    }

    /// The declared b3 root of every entry in `files` and `files_optional`,
    /// keyed by path. An entry without a usable `b3` is left out (pre-EDX or
    /// malformed), which is what `apply_edx` treats as "leave untouched".
    fn edx_file_roots(content: &Value) -> std::collections::BTreeMap<String, epix_blob::ObjId> {
        let mut roots = std::collections::BTreeMap::new();
        for key in ["files", "files_optional"] {
            let Some(entries) = content.get(key).and_then(Value::as_object) else { continue };
            for (path, e) in entries {
                if let Some(id) =
                    e.get("b3").and_then(Value::as_str).and_then(epix_blob::ObjId::from_hex)
                {
                    roots.insert(path.clone(), id);
                }
            }
        }
        roots
    }

    /// The bytes the bundle packer works from: the small required files, in
    /// path order. Only `files` is scanned - optional files must stay
    /// individually fetchable on demand, so they never bundle.
    ///
    /// Bytes come from `hashed_bytes` (what this sign already read and declared
    /// a b3 for), so a file rewritten between the hash pass and here cannot
    /// make the bundle disagree with the manifest. Falling back to a read is
    /// for entries carried in from a previous manifest, which this sign did not
    /// re-hash.
    fn edx_bundle_inputs(
        &self,
        content: &Value,
        mut hashed_bytes: std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        let mut bundleable = std::collections::BTreeMap::new();
        let Some(entries) = content.get("files").and_then(Value::as_object) else {
            return Ok(bundleable);
        };
        for (path, e) in entries {
            let size = e.get("size").and_then(Value::as_u64).unwrap_or(0);
            if !epix_blob::bundle::is_bundleable(size) {
                continue;
            }
            let bytes = match hashed_bytes.remove(path) {
                Some(bytes) => bytes,
                None => self.storage.read(path)?,
            };
            bundleable.insert(path.clone(), bytes);
        }
        Ok(bundleable)
    }

    /// The owner salt for salted-convergent shards, read from `edx_salt` or
    /// freshly generated and stamped (stable across re-signs for dedup).
    fn ensure_edx_salt(&self, content: &mut Value) -> Vec<u8> {
        if let Some(salt) = epix_blob::manifest::edx_salt(content) {
            return salt;
        }
        let hex = epix_crypt::new_seed(); // 32 random bytes, hex
        if let Some(o) = content.as_object_mut() {
            o.insert("edx_salt".into(), json!(hex));
        }
        (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect()
    }

    /// The EDX migration pass: register this xite's local files (and the
    /// bundles its manifest declares) as content-addressed objects in the
    /// store - no re-download, no second copy (large files are adopted by
    /// hard link where possible).
    ///
    /// Small files insert into slabs; files >= the bundle cutoff adopt in
    /// place. Declared bundles are rebuilt from their member files and
    /// verified against their declared id before insertion. Returns
    /// `(registered, skipped)` - a skip is a missing/mismatched local
    /// file, which simply stays fetchable from the swarm instead.
    pub fn edx_register(
        &self,
        store: &epix_blob::store::Store,
        now: u64,
    ) -> Result<(usize, usize)> {
        let Some(content) = &self.content else { return Ok((0, 0)) };
        // Four independent passes whose store writes and pins must happen in
        // this order. Sequential bindings, not an array of calls: with an array
        // the ordering would rest on left-to-right element evaluation, and
        // reshuffling the lines for readability would silently reorder the
        // writes.
        let (mut registered, mut skipped) = self.register_file_entries(store, content, "", now);
        // Declared bundles: rebuild from member files, verify, insert.
        let (r, s) = self.register_bundles(store, content, now);
        registered += r;
        skipped += s;
        // The encrypted shards this content.json records.
        let (r, s) = self.register_shards(store, content, now);
        registered += r;
        skipped += s;
        // The child / per-user content.json units stored below the root.
        let (r, s) = self.register_child_units(store, now);
        registered += r;
        skipped += s;
        Ok((registered, skipped))
    }

    /// Every `(object id, inner_path)` pair this xite's manifests declare
    /// with a `b3` (root + child units), plus its declared bundles mapped
    /// to an empty inner_path — a bundle spans many files, so serving one
    /// credits the xite without a per-file counter. The reverse map upload
    /// accounting resolves a served object through.
    pub fn edx_object_paths(&self) -> Vec<(epix_blob::ObjId, String)> {
        let mut out = Vec::new();
        let Some(content) = &self.content else { return out };
        collect_object_paths(content, "", &mut out);
        for id in epix_blob::manifest::bundles(content).keys() {
            out.push((*id, String::new()));
        }
        for cj in self.storage.list_files() {
            if cj == "content.json" || !cj.ends_with("/content.json") {
                continue;
            }
            let dir = &cj[..cj.len() - "content.json".len()]; // trailing '/'
            let Ok(bytes) = self.storage.read(&cj) else { continue };
            let Ok(child) = serde_json::from_slice::<Value>(&bytes) else { continue };
            collect_object_paths(&child, dir, &mut out);
        }
        out
    }

    /// Register the per-file objects one content.json unit declares (`files`
    /// and `files_optional`), each declared path prefixed with `dir_prefix`
    /// (empty for the root unit, the child unit's dir - trailing '/' included -
    /// for a child unit). Returns `(registered, skipped)`; an entry with no
    /// `b3` is pre-EDX and counts as neither.
    fn register_file_entries(
        &self,
        store: &epix_blob::store::Store,
        content: &Value,
        dir_prefix: &str,
        now: u64,
    ) -> (usize, usize) {
        let mut registered = 0usize;
        let mut skipped = 0usize;
        for key in ["files", "files_optional"] {
            let Some(entries) = content.get(key).and_then(Value::as_object) else { continue };
            for (rel, e) in entries {
                let Some(id) =
                    e.get("b3").and_then(Value::as_str).and_then(epix_blob::ObjId::from_hex)
                else {
                    continue; // pre-EDX entry: nothing to register
                };
                let size = e.get("size").and_then(Value::as_u64).unwrap_or(0);
                let path = format!("{dir_prefix}{rel}");
                if self.register_entry(store, id, &path, size, now) {
                    registered += 1;
                } else {
                    skipped += 1;
                }
            }
        }
        (registered, skipped)
    }

    /// Register one local file as the object `id` and pin it: small files
    /// insert into slabs, files >= the bundle cutoff are adopted where they
    /// lie (the file in the xite tree IS the object's bytes - nothing is
    /// copied or linked). Returns whether it was registered - a `false` is a
    /// missing/mismatched local file, which simply stays fetchable from the
    /// swarm instead.
    fn register_entry(
        &self,
        store: &epix_blob::store::Store,
        id: epix_blob::ObjId,
        path: &str,
        size: u64,
        now: u64,
    ) -> bool {
        if !self.storage.exists(path) {
            return false;
        }
        let res = if epix_blob::bundle::is_bundleable(size) {
            self.storage
                .read(path)
                .and_then(|bytes| {
                    store.insert_bytes(id, epix_blob::Ns::Plain, &bytes, now).map_err(Error::Io)
                })
                .map(|_| ())
        } else {
            self.storage.path(path).and_then(|p| {
                let fresh = store.adopt_extern(id, epix_blob::Ns::Plain, &p, now).map_err(Error::Io)?;
                if !fresh {
                    // A record already existed. If it is a store-side copy of
                    // this same file - what every materialized download used
                    // to leave behind - hand the space back and read through
                    // to the tree instead. No-op for anything else.
                    let _ = store.reclaim_duplicate(id, &p, now);
                }
                Ok(())
            })
        };
        match res {
            Ok(()) => {
                // Our own content: pin it so eviction never reclaims it.
                let _ = store.pin(id);
                true
            }
            Err(_) => false, // corrupt/changed local copy: refetch later
        }
    }

    /// Rebuild every bundle the manifest declares from its member files and
    /// insert it under its declared id. A member whose `off` does not continue
    /// the bytes collected so far, an unreadable member, or a rebuild that
    /// hashes to something else fails the whole bundle - it is counted skipped
    /// and never inserted under an id it does not match. Returns
    /// `(registered, skipped)`.
    fn register_bundles(
        &self,
        store: &epix_blob::store::Store,
        content: &Value,
        now: u64,
    ) -> (usize, usize) {
        let mut registered = 0usize;
        let mut skipped = 0usize;
        let declared = epix_blob::manifest::bundles(content);
        if declared.is_empty() {
            return (registered, skipped);
        }
        for (hex, paths) in Self::collect_bundle_members(content) {
            let Some(id) = epix_blob::ObjId::from_hex(&hex) else { continue };
            if !declared.contains_key(&id) {
                continue;
            }
            if self.register_bundle(store, id, paths, now) {
                registered += 1;
            } else {
                skipped += 1;
            }
        }
        (registered, skipped)
    }

    /// The members every bundle in `files` / `files_optional` claims, keyed by
    /// the bundle id hex the entries name. The `(off, path)` pairs come out in
    /// manifest order, not offset order - the caller sorts them.
    fn collect_bundle_members(
        content: &Value,
    ) -> std::collections::BTreeMap<String, Vec<(u64, String)>> {
        // bundle id -> ordered (off, member path).
        let mut members: std::collections::BTreeMap<String, Vec<(u64, String)>> =
            std::collections::BTreeMap::new();
        for key in ["files", "files_optional"] {
            let Some(entries) = content.get(key).and_then(Value::as_object) else { continue };
            for (path, e) in entries {
                if let (Some(bundle), Some(off)) = (
                    e.get("bundle").and_then(Value::as_str),
                    e.get("off").and_then(Value::as_u64),
                ) {
                    members.entry(bundle.into()).or_default().push((off, path.clone()));
                }
            }
        }
        members
    }

    /// Rebuild one declared bundle from its members and insert it under `id`.
    /// Returns whether it was registered - a gap in the members, an unreadable
    /// member, or a rebuild that hashes to something else fails the bundle, so
    /// it is never inserted under an id it does not match.
    fn register_bundle(
        &self,
        store: &epix_blob::store::Store,
        id: epix_blob::ObjId,
        mut paths: Vec<(u64, String)>,
        now: u64,
    ) -> bool {
        paths.sort();
        let Some(bytes) = self.read_bundle_members(&paths) else { return false };
        if epix_blob::ObjId::of(&bytes) != id {
            return false;
        }
        if store.insert_bytes(id, epix_blob::Ns::Plain, &bytes, now).is_err() {
            return false;
        }
        let _ = store.pin(id); // own content: never evict
        true
    }

    /// Concatenate a bundle's members, `paths` already in offset order. `None`
    /// if a member's `off` does not continue the bytes collected so far or a
    /// member cannot be read.
    fn read_bundle_members(&self, paths: &[(u64, String)]) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        for (off, path) in paths {
            let data = self.storage.read(path).ok()?;
            // A zero-byte member shares its `off` with the member that follows
            // it, so the (off, path) sort can put it after that member. It
            // contributes nothing either way; only its position is odd.
            if data.is_empty() {
                if *off > bytes.len() as u64 {
                    return None;
                }
            } else if *off != bytes.len() as u64 {
                return None;
            }
            bytes.extend_from_slice(&data);
        }
        Some(bytes)
    }

    /// Encrypted shards: re-derive the ciphertext (deterministic from the
    /// plaintext + xite salt) and store each shard object by its address as
    /// Ns::Shard, so this node can serve them to peers. The addresses match
    /// the ones the signed content.json already recorded. Returns
    /// `(registered, skipped)`, counted per shard object (an unreadable
    /// plaintext is one skip).
    fn register_shards(
        &self,
        store: &epix_blob::store::Store,
        content: &Value,
        now: u64,
    ) -> (usize, usize) {
        let mut registered = 0usize;
        let mut skipped = 0usize;
        let Some(salt) = epix_blob::manifest::edx_salt(content) else {
            return (registered, skipped);
        };
        let Some(fs) = content.get("files_shard").and_then(Value::as_object) else {
            return (registered, skipped);
        };
        for path in fs.keys() {
            let Ok(bytes) = self.storage.read(path) else {
                skipped += 1;
                continue;
            };
            let enc = epix_selfenc::encrypt_convergent(&bytes, &salt);
            for (addr, ct) in &enc.shards {
                let id = epix_blob::ObjId(*addr);
                match store.insert_bytes(id, epix_blob::Ns::Shard, ct, now) {
                    Ok(_) => {
                        let _ = store.pin(id);
                        registered += 1;
                    }
                    Err(_) => skipped += 1,
                }
            }
        }
        (registered, skipped)
    }

    /// Child / per-user content.json units: their files carry a b3 too, so
    /// register them (full path = the unit's dir + the relative path) so
    /// this node can serve forum and per-user content over EDX. A unit that
    /// cannot be read or parsed is passed over, counting as neither. Returns
    /// `(registered, skipped)`.
    fn register_child_units(
        &self,
        store: &epix_blob::store::Store,
        now: u64,
    ) -> (usize, usize) {
        let mut registered = 0usize;
        let mut skipped = 0usize;
        for cj in self.storage.list_files() {
            if cj == "content.json" || !cj.ends_with("/content.json") {
                continue;
            }
            let dir = &cj[..cj.len() - "content.json".len()]; // trailing '/'
            let Ok(bytes) = self.storage.read(&cj) else { continue };
            let Ok(child) = serde_json::from_slice::<Value>(&bytes) else { continue };
            let (r, s) = self.register_file_entries(store, &child, dir, now);
            registered += r;
            skipped += s;
        }
        (registered, skipped)
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
        apply_extend(map, extend);

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
        // (they may not be on disk); new files matching this content's
        // `optional` pattern sign as optional.
        let declared_optional: serde_json::Map<String, Value> = map
            .get("files_optional")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        // Declared merge files (a user's posts.json) are re-emitted untouched
        // and never hashed - integrity is per-record, not whole-file.
        let declared_merged: serde_json::Map<String, Value> = map
            .get("files_merged")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let ignore = path_pattern(map.get("ignore"));
        let optional = path_pattern(map.get("optional"));
        // Child units are not EDX-bundled, so the hashed bytes are dropped.
        let (files, files_optional, _) =
            self.hash_unit_files(dir, &declared_optional, &declared_merged, &ignore, &optional)?;
        map.insert("files".into(), Value::Object(files));
        Self::merge_files_optional(map, files_optional, declared_optional);
        if modified.fract() == 0.0 {
            map.insert("modified".into(), json!(modified as i64));
        } else {
            map.insert("modified".into(), json!(modified));
        }
        map.insert("address".into(), json!(self.address.as_str()));
        map.insert("inner_path".into(), json!(inner_path));

        epix_content::sign(&mut content, privatekey)?;
        // Python-EpixNet's on-disk format (helper.jsonDumps), like the root.
        let bytes = epix_content::dumps_content(&content).into_bytes();
        // add_content verifies (signer allowed, cert valid, sizes) and stores.
        self.add_content(inner_path, &bytes, xid_map)?;
        Ok(content)
    }
}

/// Collect one content.json unit's `(b3 object id, inner_path)` pairs from
/// `files` + `files_optional`, each path prefixed with `dir_prefix` (empty
/// for the root, the child's dir — trailing '/' included — for a child).
fn collect_object_paths(
    content: &Value,
    dir_prefix: &str,
    out: &mut Vec<(epix_blob::ObjId, String)>,
) {
    for key in ["files", "files_optional"] {
        let Some(entries) = content.get(key).and_then(Value::as_object) else { continue };
        for (rel, e) in entries {
            let Some(id) = e.get("b3").and_then(Value::as_str).and_then(epix_blob::ObjId::from_hex)
            else {
                continue; // pre-EDX entry: never served by object id
            };
            out.push((id, format!("{dir_prefix}{rel}")));
        }
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

    /// The upload-accounting reverse map covers everything served by object
    /// id: root + child unit files (child paths dir-prefixed), bundles with
    /// an empty inner_path; a pre-EDX entry (no b3) has no object to map.
    #[test]
    fn edx_object_paths_maps_declared_objects() {
        let site = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "data/users/alice/content.json",
                &serde_json::to_vec(&json!({
                    "files": { "avatar.png": { "size": 3, "b3": epix_blob::ObjId::of(b"png").to_string() } }
                }))
                .unwrap(),
            )
            .unwrap();
        let mut xite = Xite::new(Address::parse(site).unwrap(), storage);
        let bundle_hex = epix_blob::ObjId::of(b"bundle").to_string();
        xite.content = Some(json!({
            "files": {
                "index.html": { "size": 4, "b3": epix_blob::ObjId::of(b"html").to_string() },
                "legacy.bin": { "size": 2 }, // pre-EDX: no b3, not mapped
            },
            "files_optional": {
                "movie.bin": { "size": 5, "b3": epix_blob::ObjId::of(b"movie").to_string() },
            },
            "bundles": { &bundle_hex: { "size": 9 } },
        }));

        let paths: std::collections::HashMap<_, _> =
            xite.edx_object_paths().into_iter().collect();
        assert_eq!(paths.len(), 4);
        assert_eq!(paths[&epix_blob::ObjId::of(b"html")], "index.html");
        assert_eq!(paths[&epix_blob::ObjId::of(b"movie")], "movie.bin");
        assert_eq!(
            paths[&epix_blob::ObjId::of(b"png")],
            "data/users/alice/avatar.png",
            "child unit paths carry their directory prefix"
        );
        assert_eq!(paths[&epix_blob::ObjId::of(b"bundle")], "", "bundles credit the xite only");
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

    #[test]
    fn sign_child_splits_files_by_the_optional_pattern() {
        // The EpixPost flow: a user content.json declares an `optional`
        // pattern, so a newly written photo signs as optional instead of
        // counting against the user's required size limit.
        let site_pk = epix_crypt::new_seed();
        let site = epix_crypt::privatekey_to_address(&site_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user = epix_crypt::privatekey_to_address(&user_pk).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(site.clone()).unwrap(), storage.clone());
        let none = std::collections::HashMap::new();

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
        let parent = signed(
            serde_json::json!({
                "address": site, "inner_path": "data/users/content.json",
                "modified": 10, "files": {},
                "user_contents": { "permissions": {}, "cert_signers": {} },
            }),
            &site_pk,
        );
        xite.add_content("data/users/content.json", &parent, &none).unwrap();

        // The user's unsigned content.json (as the app fileWrites it) plus
        // their files: an avatar, a photo, and a data.json.
        let user_dir = format!("data/users/{user}");
        let user_inner = format!("{user_dir}/content.json");
        storage
            .write(&user_inner, br#"{ "optional": "(?!avatar).*jpg" }"#)
            .unwrap();
        storage.write(&format!("{user_dir}/avatar.jpg"), b"AV").unwrap();
        storage.write(&format!("{user_dir}/1775.jpg"), b"PHOTO").unwrap();
        storage.write(&format!("{user_dir}/data.json"), b"{}").unwrap();

        let content = xite
            .sign_child(&user_inner, &user_pk, 100.0, &serde_json::Map::new(), &none)
            .unwrap();

        let mut required: Vec<&str> =
            content["files"].as_object().unwrap().keys().map(|s| s.as_str()).collect();
        required.sort();
        assert_eq!(required, ["avatar.jpg", "data.json"]);
        assert_eq!(content["files_optional"]["1775.jpg"]["size"], 5);
        assert_eq!(
            content["files_optional"]["1775.jpg"]["sha512"],
            XiteStorage::hash_bytes(b"PHOTO")
        );
        assert_eq!(content["files_optional"].as_object().unwrap().len(), 1);
        // add_content verified and stored the signed result.
        let stored: Value =
            serde_json::from_slice(&storage.read(&user_inner).unwrap()).unwrap();
        assert!(stored["files_optional"]["1775.jpg"].is_object());
    }

    #[test]
    fn a_shard_file_never_signs_as_optional_plaintext() {
        // Overlapping patterns: the file matches `optional` (so the hasher
        // routes it to files_optional) AND `shard`. The shard pattern wins;
        // publishing its plaintext hash would serve a file the owner marked
        // private in the clear.
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let mut xite = Xite::new(Address::parse(addr).unwrap(), storage.clone());

        let secret = b"the home video";
        storage.write("private/home-video.mp4", secret).unwrap();
        storage.write("index.html", b"<h1>public</h1>").unwrap();
        xite.content = Some(serde_json::json!({
            "shard": "private/.*",
            "optional": ".*\\.mp4",
        }));
        xite.sign(&pk, 1000.0).unwrap();
        let content = xite.content.clone().unwrap();

        assert!(
            epix_blob::manifest::edx_shard_entry(&content, "private/home-video.mp4").is_some(),
            "the shard-matched file must be encrypted"
        );
        assert!(content.get("files").and_then(|f| f.get("private/home-video.mp4")).is_none());
        assert!(
            content.get("files_optional").and_then(|f| f.get("private/home-video.mp4")).is_none(),
            "must not be published as an optional plaintext file"
        );
        // files_optional held only that file, so it is gone entirely.
        assert!(content.get("files_optional").is_none());
        // And the plaintext hash is nowhere in the signed manifest on disk.
        let on_disk = String::from_utf8(storage.read("content.json").unwrap()).unwrap();
        assert!(!on_disk.contains(&XiteStorage::hash_bytes(secret)), "plaintext hash published");
        assert!(content["files"]["index.html"].is_object(), "public files still sign");
    }

    #[test]
    fn a_declared_optional_shard_file_that_is_gone_fails_the_sign() {
        // A declared-optional entry the hasher never re-reads is carried
        // forward by merge_files_optional. If it matches `shard` and has no
        // local copy it cannot be encrypted, so the sign fails rather than
        // re-publishing its plaintext hash.
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let mut xite = Xite::new(Address::parse(addr).unwrap(), storage.clone());

        storage.write("index.html", b"<h1>public</h1>").unwrap();
        xite.content = Some(serde_json::json!({
            "shard": "private/.*",
            "files_optional": {
                "private/gone.dat": { "size": 4, "sha512": XiteStorage::hash_bytes(b"gone") },
            },
        }));
        let err = xite.sign(&pk, 1000.0).unwrap_err();
        assert!(err.to_string().contains("private/gone.dat"), "{err}");
    }

    #[test]
    fn a_zero_byte_bundle_member_does_not_fail_the_bundle() {
        // bundle::build stamps a zero-byte member with the same `off` as the
        // member that follows it, so register_bundle's (off, path) sort can
        // place it after that member. It contributes no bytes either way.
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(addr).unwrap(), storage.clone());

        storage.write("m.bin", b"MMMM").unwrap();
        storage.write("z.keep", b"").unwrap();
        storage.write("a.bin", b"AAA").unwrap();

        // As signed: [m.bin@0, z.keep@4, a.bin@4]; register_bundle sorts to
        // [m.bin, a.bin, z.keep].
        let mut paths = vec![
            (0u64, "m.bin".to_string()),
            (4u64, "z.keep".to_string()),
            (4u64, "a.bin".to_string()),
        ];
        paths.sort();
        let bytes = xite.read_bundle_members(&paths).expect("zero-byte member must not fail");
        assert_eq!(bytes, b"MMMMAAA".to_vec());

        // A real gap still fails the bundle.
        let gap = vec![(0u64, "m.bin".to_string()), (9u64, "a.bin".to_string())];
        assert!(xite.read_bundle_members(&gap).is_none());
    }

    #[test]
    fn hashing_hands_back_the_bytes_bundles_are_built_from() {
        // hash_unit_files hands back the bytes it hashed, and only for the
        // files that bundle: a file over the cutoff is never cached, so an
        // optional-heavy or large xite does not hold its whole tree in RAM.
        // That stamp_edx_manifest actually uses these bytes is covered by
        // a_file_rewritten_mid_sign_does_not_change_the_bundle.
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(addr).unwrap(), storage.clone());

        storage.write("small.txt", b"small").unwrap();
        storage.write("big.bin", &vec![7u8; 200_000]).unwrap();
        let none = serde_json::Map::new();
        let (files, _optional, hashed) =
            xite.hash_unit_files("", &none, &none, &None, &None).unwrap();

        assert_eq!(hashed.get("small.txt").map(|b| b.as_slice()), Some(&b"small"[..]));
        assert!(!hashed.contains_key("big.bin"), "over the bundle cutoff: never bundled");
        assert_eq!(files["small.txt"]["size"], 5);
    }

    #[test]
    fn a_file_rewritten_mid_sign_does_not_change_the_bundle() {
        // The interleaving the cache exists for: hash_unit_files reads and
        // declares b3/size, then an app rewrites the file (same length, so
        // nothing downstream notices), then stamp_edx_manifest builds the
        // bundle. Bundling must use the hashed bytes, or the signed bundle
        // disagrees with the b3 the same manifest declares.
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(addr).unwrap(), storage.clone());

        storage.write("a.txt", b"AAA").unwrap();
        storage.write("small.txt", b"small").unwrap();
        let none = serde_json::Map::new();
        let (files, _optional, hashed) =
            xite.hash_unit_files("", &none, &none, &None, &None).unwrap();

        // Rewrite between the two passes, keeping the length identical.
        storage.write("small.txt", b"DIRTY").unwrap();

        let mut content = json!({ "files": files });
        xite.stamp_edx_manifest(&mut content, hashed).unwrap();

        // One bundle, members in path order: "AAA" then "small".
        let clean = epix_blob::ObjId::of(b"AAAsmall").to_string();
        let dirty = epix_blob::ObjId::of(b"AAADIRTY").to_string();
        assert_ne!(clean, dirty, "the rewrite must change the bundle id");
        assert_eq!(
            content["files"]["small.txt"]["bundle"],
            json!(clean),
            "the bundle must be built from the hashed bytes, not a second read"
        );
        assert_eq!(content["files"]["small.txt"]["off"], json!(3));
        assert!(content["bundles"].get(clean.as_str()).is_some(), "{}", content["bundles"]);
        assert!(content["bundles"].get(dirty.as_str()).is_none(), "signed the rewritten bytes");
    }
}
