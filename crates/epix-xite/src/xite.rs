//! A xite: its address, storage, and (once loaded) verified content.json.

use crate::storage::XiteStorage;
use epix_content::VerifyContext;
use epix_core::{Address, Error, Result};
use serde_json::{json, Value};

/// Verification context for a root content.json: only the xite address and the
/// size limit are needed (the root's rules bootstrap from itself).
struct RootCtx {
    address: String,
    size_limit: i64,
}
impl VerifyContext for RootCtx {
    fn xite_address(&self) -> &str {
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
    /// The in-memory root content.json, consulted when the on-disk copy is
    /// absent. During a clone the root is STAGED (committed to disk only once
    /// the core set completes) while includes are already arriving; without
    /// this fallback every one of them failed rules resolution ("No rules
    /// for this file") and the user-content pass could not run concurrently
    /// with the core download. Disk still wins when present.
    root: Option<&'a Value>,
    xid_map: &'a epix_content::verify::XidMap,
}
impl VerifyContext for ChildCtx<'_> {
    fn xite_address(&self) -> &str {
        &self.address
    }
    fn loaded_content(&self, inner_path: &str) -> Option<Value> {
        if let Ok(bytes) = self.storage.read(inner_path) {
            return serde_json::from_slice(&bytes).ok();
        }
        if inner_path == "content.json" {
            return self.root.cloned();
        }
        None
    }
    fn resolve_xid_identities(&self, name: &str) -> Option<Vec<epix_content::XidIdentity>> {
        self.xid_map.get(name).cloned()
    }
    fn read_file(&self, inner_path: &str) -> Option<Vec<u8>> {
        self.storage.read(inner_path).ok()
    }
}

struct FileOverlayCtx<'a> {
    base: &'a dyn VerifyContext,
    files: &'a std::collections::BTreeMap<String, Vec<u8>>,
}

impl VerifyContext for FileOverlayCtx<'_> {
    fn xite_address(&self) -> &str {
        self.base.xite_address()
    }

    fn loaded_content(&self, inner_path: &str) -> Option<Value> {
        self.base.loaded_content(inner_path)
    }

    fn size_limit_bytes(&self) -> i64 {
        self.base.size_limit_bytes()
    }

    fn resolve_xid(&self, name: &str) -> Vec<String> {
        self.base.resolve_xid(name)
    }

    fn resolve_xid_identities(&self, name: &str) -> Option<Vec<epix_content::XidIdentity>> {
        self.base.resolve_xid_identities(name)
    }

    fn read_file(&self, inner_path: &str) -> Option<Vec<u8>> {
        self.files
            .get(inner_path)
            .cloned()
            .or_else(|| self.base.read_file(inner_path))
    }
}

/// Read-only verification context whose parent lookup is restricted to the
/// manifests already accepted by a [`VerifiedManifestWalk`]. A stale or
/// corrupt closer content.json may remain on disk after revocation, but it
/// cannot shadow a direct include from a verified ancestor.
struct VerifiedWalkCtx<'a> {
    address: &'a str,
    storage: &'a XiteStorage,
    verified: &'a std::collections::HashMap<String, Value>,
    xid_map: &'a epix_content::verify::XidMap,
}

impl VerifyContext for VerifiedWalkCtx<'_> {
    fn xite_address(&self) -> &str {
        self.address
    }

    fn loaded_content(&self, inner_path: &str) -> Option<Value> {
        self.verified.get(inner_path).cloned()
    }

    fn resolve_xid_identities(&self, name: &str) -> Option<Vec<epix_content::XidIdentity>> {
        self.xid_map.get(name).cloned()
    }

    fn read_file(&self, inner_path: &str) -> Option<Vec<u8>> {
        self.storage.read(inner_path).ok()
    }
}

/// Files signing never hashes into a content.json (EpixNet's `hashFiles`):
/// hidden dot-files and the `-old`/`-new` publish-diff snapshots.
/// The local sign cache at the xite root. A dotfile, so [`skip_hashing`]
/// keeps it out of every signed manifest; it never syncs to peers.
const SIGN_CACHE: &str = ".sign-cache.json";
const MAX_STORED_MANIFEST_WALK_ENTRIES: usize = 100_000;

/// One file's cached hashes, trusted only while its (size, mtime_ns) is
/// unchanged - the same stat contract git's index uses. The cache exists
/// because a sign otherwise re-reads and double-hashes every declared byte:
/// on a media xite that is hundreds of gigabytes and the better part of an
/// hour per sign, for files that have not moved since the last one.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct CachedHash {
    size: u64,
    mtime_ns: i64,
    sha512: String,
    b3: String,
}

type SignCache = std::collections::HashMap<String, CachedHash>;

/// Per-invocation sign options (`siteSign --full`, `--keep-missing`).
#[derive(Clone, Copy, Default)]
pub struct SignOpts {
    /// Re-read every file instead of trusting the stat cache.
    pub full: bool,
    /// Keep declared optional entries whose file is gone from disk instead
    /// of pruning them (the default). For signers that deliberately do not
    /// hold every optional file, e.g. a node whose eviction wiped some.
    pub keep_missing_optional: bool,
}

/// A fully signed root candidate that has not replaced `content.json` yet.
/// The state layer uses this to bind the bytes to its manifest transaction
/// before any authoritative path changes.
pub struct PreparedRootSign {
    content: Value,
    bytes: Vec<u8>,
    sign_cache: Option<Vec<u8>>,
}

impl PreparedRootSign {
    pub fn content(&self) -> &Value {
        &self.content
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A performance-only cache rebuilt from the exact files hashed for this
    /// candidate. It must not be installed before the governing manifest
    /// commits because a legacy manifest may still declare this reserved
    /// path as an authoritative Store object.
    pub fn sign_cache(&self) -> Option<&[u8]> {
        self.sign_cache.as_deref()
    }
}

/// A fully verified child candidate plus data-file edits required by its
/// `max_items` rules. None of these bytes have been written yet.
pub struct PreparedChildSign {
    content: Value,
    bytes: Vec<u8>,
    pruned_files: std::collections::BTreeMap<String, Vec<u8>>,
    archive: PreparedArchiveUpdate,
}

impl PreparedChildSign {
    pub fn content(&self) -> &Value {
        &self.content
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn pruned_files(&self) -> &std::collections::BTreeMap<String, Vec<u8>> {
        &self.pruned_files
    }
}

/// A file's (size, mtime_ns), or `None` when it cannot be stat'd. Taken
/// BEFORE the read on the hashing path, so a write racing the sign leaves a
/// stale mtime with fresh hashes and the NEXT sign re-reads - never the
/// reverse, which would freeze a wrong hash into the manifest.
fn stat_size_mtime(storage: &XiteStorage, inner: &str) -> Option<(u64, i64)> {
    let meta = storage.path(inner).ok().and_then(|p| std::fs::metadata(p).ok())?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    Some((meta.len(), mtime))
}

/// The cached hashes for `rel`, when they may be trusted: the stat matches
/// the cache and the file's bytes are not needed anyway (bundle-eligible
/// required files always read - the bundle builder wants them, and they are
/// the cheap kilobytes of a sign).
fn reuse_cached(
    rel: &str,
    stat: Option<(u64, i64)>,
    is_optional: bool,
    cache: Option<&SignCache>,
) -> Option<CachedHash> {
    let (size, mtime_ns) = stat?;
    if !is_optional && epix_blob::bundle::is_bundleable(size) {
        return None;
    }
    let c = cache?.get(rel)?;
    (c.size == size && c.mtime_ns == mtime_ns).then(|| c.clone())
}

/// Hash `bytes` into a manifest entry (`b3` is the EDX per-file BLAKE3 root,
/// docs/edx-manifest.md; `sha512` stays alongside for the migration window),
/// recording the result in `fresh` when the pre-read stat still describes
/// these bytes.
fn hash_entry(
    rel: &str,
    bytes: &[u8],
    stat: Option<(u64, i64)>,
    fresh: &mut SignCache,
) -> Value {
    let sha512 = XiteStorage::hash_bytes(bytes);
    let b3 = epix_blob::ObjId::of(bytes).to_string();
    if let Some((size, mtime_ns)) = stat {
        if size == bytes.len() as u64 {
            fresh.insert(
                rel.to_string(),
                CachedHash { size, mtime_ns, sha512: sha512.clone(), b3: b3.clone() },
            );
        }
    }
    json!({ "size": bytes.len(), "sha512": sha512, "b3": b3 })
}

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

/// Parent-first archive replay state. The verified set is private so callers
/// cannot authorize a descendant whose governing manifest failed verification.
pub struct ArchiveReplay {
    pending: std::collections::VecDeque<String>,
    verified_chains: std::collections::HashMap<String, Vec<String>>,
    verified_contents: std::collections::HashMap<String, Value>,
}

impl ArchiveReplay {
    /// The next child manifest whose signer map the caller should resolve.
    pub fn next_path(&self) -> Option<&str> {
        self.pending.front().map(String::as_str)
    }
}

/// Parent-first, read-only verification state for stored child manifests.
/// The verified authority chains stay private so a caller cannot authorize a
/// descendant whose actual governing manifest failed verification.
pub struct VerifiedManifestWalk {
    pending: std::collections::VecDeque<String>,
    verified_chains: std::collections::HashMap<String, Vec<String>>,
    verified_contents: std::collections::HashMap<String, Value>,
    seen: std::collections::HashSet<String>,
    max_manifests: usize,
}

impl VerifiedManifestWalk {
    /// The next child manifest whose current xID signer map should be
    /// resolved by the caller.
    pub fn next_path(&self) -> Option<&str> {
        self.pending.front().map(String::as_str)
    }
}

/// One stored child manifest accepted by a [`VerifiedManifestWalk`].
pub struct VerifiedManifest {
    inner_path: String,
    governing_path: String,
    authority_chain: Vec<String>,
    content: Value,
}

impl VerifiedManifest {
    pub fn inner_path(&self) -> &str {
        &self.inner_path
    }

    pub fn governing_path(&self) -> &str {
        &self.governing_path
    }

    /// Required hashed files declared by this verified unit, with paths
    /// prefixed by the unit's own directory.
    pub fn files(&self) -> Vec<FileEntry> {
        Xite::child_file_entries(&self.inner_path, &self.content)
    }

    /// Included manifest paths declared by this verified unit, prefixed by
    /// the unit's own directory so callers can enqueue exact storage paths.
    pub fn includes(&self) -> Vec<String> {
        let prefix = self.inner_path.strip_suffix("content.json").unwrap_or_default();
        Xite::includes_in(&self.content)
            .into_iter()
            .map(|path| format!("{prefix}{path}"))
            .collect()
    }

    /// Verified child paths from the root to this manifest, inclusive.
    pub fn authority_chain(&self) -> &[String] {
        &self.authority_chain
    }

    pub fn content(&self) -> &Value {
        &self.content
    }
}

/// One exact stored file selected by a verified archive directive. The path is
/// relative to this xite's storage root and has already passed storage's path
/// safety checks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArchiveTarget {
    inner_path: String,
}

impl ArchiveTarget {
    pub fn inner_path(&self) -> &str {
        &self.inner_path
    }
}

/// A verified manifest update and its side-effect-free archive plan. Fields
/// stay private so callers cannot change the bytes after verification or add
/// filesystem targets that were not derived from the signed content.
#[derive(Debug)]
pub struct PreparedArchiveUpdate {
    address: String,
    storage_root: std::path::PathBuf,
    inner_path: String,
    bytes: Vec<u8>,
    content: Value,
    files: Vec<FileEntry>,
    archive_targets: Vec<ArchiveTarget>,
    archive_prune_dirs: Vec<String>,
}

impl PreparedArchiveUpdate {
    pub fn archive_targets(&self) -> &[ArchiveTarget] {
        &self.archive_targets
    }

    /// Directories formerly containing archived child manifests. Callers may
    /// remove them after moving targets; removal must remain best effort and
    /// only succeeds when no unrelated files remain.
    pub fn archive_prune_dirs(&self) -> &[String] {
        &self.archive_prune_dirs
    }
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
    /// (see [`Self::set_content`]); content already on disk - a xite the
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
    /// on-disk version authoritative (and the xite serving) through the sync.
    /// This is the full EpixNet `verifyFile` path, not just a single-owner
    /// signature.
    pub fn stage_content_limited(&mut self, bytes: &[u8], size_limit: i64) -> Result<()> {
        let json = self.verify_root_content(bytes, size_limit)?;
        self.content = Some(json);
        Ok(())
    }

    fn verify_root_content(&self, bytes: &[u8], size_limit: i64) -> Result<Value> {
        let json: Value = serde_json::from_slice(bytes)?;
        let ctx = RootCtx { address: self.address.as_str().to_string(), size_limit };
        epix_content::verify_content_file("content.json", &json, bytes.len() as i64, &ctx)
            .map_err(|e| Error::Crypt(e.to_string()))?;
        Ok(json)
    }

    /// Verify a root candidate and derive its exact archive targets without
    /// changing served state or storage.
    pub fn prepare_root_archive_update(
        &self,
        bytes: &[u8],
        size_limit: i64,
    ) -> Result<PreparedArchiveUpdate> {
        let content = self.verify_root_content(bytes, size_limit)?;
        let old = self.stored_json("content.json");
        let (archive_targets, archive_prune_dirs) =
            self.archive_targets_between("content.json", old.as_ref(), &content)?;
        let files = Self::child_file_entries("content.json", &content);
        Ok(PreparedArchiveUpdate {
            address: self.address.as_str().to_string(),
            storage_root: self.storage.root().to_path_buf(),
            inner_path: "content.json".to_string(),
            bytes: bytes.to_vec(),
            content,
            files,
            archive_targets,
            archive_prune_dirs,
        })
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
        let prepared = self.prepare_root_archive_update(bytes, size_limit)?;
        let targets = prepared.archive_targets.clone();
        let prune_dirs = prepared.archive_prune_dirs.clone();
        self.commit_prepared_archive_update(prepared)?;
        self.apply_archive_plan(&targets, &prune_dirs);
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
                            size: info
                                .get("size")
                                .and_then(epix_content::verify::exact_nonnegative_size)?,
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
        xid_map: &epix_content::verify::XidMap,
    ) -> Option<Value> {
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            root: self.content.as_ref(),
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

    /// Verify a non-root content.json without writing it or applying archive
    /// directives. Update receivers use this to stage a child until every
    /// required file is present, so an incomplete manifest has no destructive
    /// or externally visible side effects.
    pub fn verify_child_content(
        &self,
        inner_path: &str,
        bytes: &[u8],
        xid_map: &epix_content::verify::XidMap,
    ) -> Result<Vec<FileEntry>> {
        let json: Value = serde_json::from_slice(bytes)?;
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            root: self.content.as_ref(),
            xid_map,
        };
        epix_content::verify_content_file(inner_path, &json, bytes.len() as i64, &ctx)
            .map_err(|e| Error::Crypt(e.to_string()))?;
        Ok(Self::child_file_entries(inner_path, &json))
    }

    /// Verify a child candidate against the current parent and signer map,
    /// then derive its exact archive targets without writing or deleting.
    pub fn prepare_child_archive_update(
        &self,
        inner_path: &str,
        bytes: &[u8],
        xid_map: &epix_content::verify::XidMap,
    ) -> Result<PreparedArchiveUpdate> {
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            root: self.content.as_ref(),
            xid_map,
        };
        self.prepare_child_archive_update_with_context(inner_path, bytes, &ctx)
    }

    /// Verify and prepare a child update through a caller-supplied authority
    /// context. State transactions use this with a root-to-parent snapshot so
    /// a revoked but still-readable closer manifest cannot shadow the accepted
    /// governing chain.
    pub fn prepare_child_archive_update_with_context(
        &self,
        inner_path: &str,
        bytes: &[u8],
        context: &dyn VerifyContext,
    ) -> Result<PreparedArchiveUpdate> {
        self.storage.path(inner_path)?;
        let content: Value = serde_json::from_slice(bytes)?;
        epix_content::verify_content_file(inner_path, &content, bytes.len() as i64, context)
            .map_err(|error| Error::Crypt(error.to_string()))?;
        let files = Self::child_file_entries(inner_path, &content);
        let old = self.stored_json(inner_path);
        let (archive_targets, archive_prune_dirs) =
            self.archive_targets_between(inner_path, old.as_ref(), &content)?;
        Ok(PreparedArchiveUpdate {
            address: self.address.as_str().to_string(),
            storage_root: self.storage.root().to_path_buf(),
            inner_path: inner_path.to_string(),
            bytes: bytes.to_vec(),
            content,
            files,
            archive_targets,
            archive_prune_dirs,
        })
    }

    /// Write an opaque verified update. Archive targets are deliberately not
    /// applied here so the caller can move them to rollback-safe backups first.
    pub fn commit_prepared_archive_update(
        &mut self,
        prepared: PreparedArchiveUpdate,
    ) -> Result<Vec<FileEntry>> {
        self.write_prepared_archive_update(&prepared)?;
        if prepared.inner_path == "content.json" {
            self.content = Some(prepared.content);
        }
        Ok(prepared.files)
    }

    fn write_prepared_archive_update(&self, prepared: &PreparedArchiveUpdate) -> Result<()> {
        if prepared.address != self.address.as_str() {
            return Err(Error::Other(
                "prepared update belongs to another xite".to_string(),
            ));
        }
        if prepared.storage_root != self.storage.root() {
            return Err(Error::Other(
                "prepared update belongs to another storage root".to_string(),
            ));
        }
        self.storage
            .write_atomic_durable(&prepared.inner_path, &prepared.bytes)
    }

    /// Verify + store a non-root content.json (an include or a user
    /// content.json) whose PARENT content.json is already on disk, then return
    /// the files it declares (`files` + `files_optional`). `inner_path` is the
    /// child's path, e.g. `data/users/1abc/content.json`.
    pub fn add_content(
        &self,
        inner_path: &str,
        bytes: &[u8],
        xid_map: &epix_content::verify::XidMap,
    ) -> Result<Vec<FileEntry>> {
        let prepared = self.prepare_child_archive_update(inner_path, bytes, xid_map)?;
        let targets = prepared.archive_targets.clone();
        let prune_dirs = prepared.archive_prune_dirs.clone();
        self.write_prepared_archive_update(&prepared)?;
        let files = prepared.files;
        self.apply_archive_plan(&targets, &prune_dirs);
        Ok(files)
    }

    fn child_file_entries(inner_path: &str, json: &Value) -> Vec<FileEntry> {
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
                        info.get("size")
                            .and_then(epix_content::verify::exact_nonnegative_size),
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
        out
    }

    fn stored_json(&self, inner_path: &str) -> Option<Value> {
        self.storage
            .read(inner_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    /// Derive EpixNet's moderation/revocation targets without changing disk.
    /// Only the selected child manifest and files declared by that manifest
    /// are returned. Every path is validated even when the file is absent.
    fn archive_targets_between(
        &self,
        inner_path: &str,
        old: Option<&Value>,
        new: &Value,
    ) -> Result<(Vec<ArchiveTarget>, Vec<String>)> {
        use std::collections::BTreeSet;

        self.storage.path(inner_path)?;
        let governing_path = self.normalized_inner_path(inner_path)?;
        let Some(uc) = new.get("user_contents") else {
            return Ok((Vec::new(), Vec::new()));
        };
        let dir = inner_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
        let old_uc = old.and_then(|o| o.get("user_contents"));
        let mut targets = BTreeSet::new();
        let mut prune_dirs = BTreeSet::new();

        if let Some(archived) = uc.get("archived").and_then(|v| v.as_object()) {
            let old_archived = old_uc.and_then(|u| u.get("archived")).and_then(|v| v.as_object());
            for (dirname, date) in archived {
                if !Self::valid_archive_dirname(dirname) {
                    return Err(Error::Other(format!(
                        "unsafe archived directory name: {dirname}"
                    )));
                }
                let date = date.as_f64().unwrap_or(0.0);
                let unchanged = old_archived
                    .and_then(|m| m.get(dirname))
                    .and_then(|v| v.as_f64())
                    .is_some_and(|old_date| old_date == date);
                if !unchanged {
                    self.collect_child_archive_targets(
                        &format!("{dir}{dirname}/content.json"),
                        date,
                        &mut targets,
                        &mut prune_dirs,
                        &governing_path,
                    )?;
                }
            }
        }

        let before = uc.get("archived_before").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let old_before =
            old_uc.and_then(|u| u.get("archived_before")).and_then(|v| v.as_f64()).unwrap_or(0.0);
        if before > 0.0 && before != old_before {
            for child in self.child_contents_under(&dir)? {
                if child != inner_path {
                    self.collect_child_archive_targets(
                        &child,
                        before,
                        &mut targets,
                        &mut prune_dirs,
                        &governing_path,
                    )?;
                }
            }
        }
        let targets = targets
            .into_iter()
            .map(|inner_path| ArchiveTarget { inner_path })
            .collect();
        let mut prune_dirs = prune_dirs.into_iter().collect::<Vec<_>>();
        prune_dirs.sort_by(|left, right| {
            right
                .matches('/')
                .count()
                .cmp(&left.matches('/').count())
                .then_with(|| left.cmp(right))
        });
        Ok((targets, prune_dirs))
    }

    fn valid_archive_dirname(dirname: &str) -> bool {
        use std::path::Component;

        let mut components = std::path::Path::new(dirname).components();
        matches!(
            (components.next(), components.next()),
            (Some(Component::Normal(name)), None) if name == std::ffi::OsStr::new(dirname)
        )
    }

    fn normalized_inner_path(&self, inner_path: &str) -> Result<std::path::PathBuf> {
        use std::path::Component;

        self.storage.path(inner_path)?;
        let mut normalized = std::path::PathBuf::new();
        for component in std::path::Path::new(inner_path).components() {
            match component {
                Component::Normal(name) => normalized.push(name),
                Component::CurDir => {}
                _ => return Err(Error::Other(format!("unsafe inner_path: {inner_path}"))),
            }
        }
        Ok(normalized)
    }

    fn collect_child_archive_targets(
        &self,
        inner_path: &str,
        cutoff: f64,
        targets: &mut std::collections::BTreeSet<String>,
        prune_dirs: &mut std::collections::BTreeSet<String>,
        governing_path: &std::path::Path,
    ) -> Result<()> {
        if self.normalized_inner_path(inner_path)? == governing_path {
            return Err(Error::Other(format!(
                "archive target aliases governing manifest: {inner_path}"
            )));
        }
        let Ok(bytes) = self.storage.read(inner_path) else { return Ok(()) };
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else { return Ok(()) };
        let modified = json.get("modified").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if modified > cutoff {
            return Ok(());
        }
        let dir = inner_path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
        if !dir.is_empty() {
            let prune_dir = dir.trim_end_matches('/').to_string();
            self.storage.path(&prune_dir)?;
            prune_dirs.insert(prune_dir);
        }
        for node in ["files", "files_optional"] {
            if let Some(files) = json.get(node).and_then(|f| f.as_object()) {
                for rel in files.keys() {
                    let target = format!("{dir}{rel}");
                    if self.normalized_inner_path(&target)? == governing_path {
                        return Err(Error::Other(format!(
                            "archive target aliases governing manifest: {target}"
                        )));
                    }
                    if self.storage.exists(&target) {
                        targets.insert(target);
                    }
                }
            }
        }
        targets.insert(inner_path.to_string());
        Ok(())
    }

    fn apply_archive_plan(&self, targets: &[ArchiveTarget], prune_dirs: &[String]) {
        for target in targets {
            let _ = self.storage.delete(target.inner_path());
        }
        for dir in prune_dirs {
            if let Ok(path) = self.storage.path(dir) {
                let _ = std::fs::remove_dir(path);
            }
        }
    }

    fn apply_archived(
        &self,
        inner_path: &str,
        old: Option<&Value>,
        new: &Value,
    ) -> Result<()> {
        let (targets, prune_dirs) = self.archive_targets_between(inner_path, old, new)?;
        self.apply_archive_plan(&targets, &prune_dirs);
        Ok(())
    }

    /// Verify and adopt the committed root, then apply its root-level archive
    /// directives. This is safe after a live root commit and at startup. A
    /// corrupt or locally edited unsigned root cannot trigger deletion.
    pub fn apply_committed_root_archived_directives(&mut self) -> Result<bool> {
        if !self.load_content()? {
            return Ok(false);
        }
        let content = self
            .content
            .clone()
            .ok_or_else(|| Error::Other("verified root was not adopted".to_string()))?;
        self.apply_archived("content.json", None, &content)?;
        Ok(true)
    }

    /// Resolve the exact stored content.json whose current rules govern a
    /// child path. Includes may skip directories, so callers must not derive
    /// this by stripping one path component.
    pub fn governing_content_path(&self, inner_path: &str) -> Option<String> {
        let xid_map = std::collections::HashMap::new();
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            root: self.content.as_ref(),
            xid_map: &xid_map,
        };
        epix_content::verify::governing_content_path(inner_path, &ctx)
    }

    /// Begin a read-only parent-first verification walk over a bounded list
    /// of stored child content.json paths. No archive directive is applied.
    pub fn begin_verified_manifest_walk(
        &mut self,
        parent_first_paths: Vec<String>,
        max_manifests: usize,
    ) -> Result<Option<VerifiedManifestWalk>> {
        if !self.load_content()? {
            return Ok(None);
        }
        self.verified_manifest_walk_from_loaded(parent_first_paths, max_manifests)
            .map(Some)
    }

    /// Verify a signed root candidate in memory, then begin the same bounded
    /// read-only child walk against that candidate. The stored root is not
    /// read or changed, so a caller can finish all fallible authority work
    /// before atomically committing the candidate.
    pub fn begin_verified_manifest_walk_from_root(
        &mut self,
        signed_root: &[u8],
        parent_first_paths: Vec<String>,
        max_manifests: usize,
    ) -> Result<VerifiedManifestWalk> {
        self.stage_content(signed_root)?;
        self.verified_manifest_walk_from_loaded(parent_first_paths, max_manifests)
    }

    fn verified_manifest_walk_from_loaded(
        &self,
        parent_first_paths: Vec<String>,
        max_manifests: usize,
    ) -> Result<VerifiedManifestWalk> {
        if max_manifests == 0
            || parent_first_paths.len().saturating_add(1) > max_manifests
        {
            return Err(Error::Other(format!(
                "stored manifest walk exceeds limit {max_manifests}"
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for path in &parent_first_paths {
            self.storage.path(path)?;
            if path == "content.json"
                || !path.ends_with("/content.json")
                || !seen.insert(path.clone())
            {
                return Err(Error::Other(format!(
                    "invalid stored manifest walk path: {path}"
                )));
            }
        }
        Ok(VerifiedManifestWalk {
            pending: parent_first_paths.into(),
            verified_chains: std::iter::once(("content.json".to_string(), Vec::new())).collect(),
            verified_contents: std::iter::once((
                "content.json".to_string(),
                self.content.clone().ok_or_else(|| {
                    Error::Other("verified root disappeared".to_string())
                })?,
            ))
            .collect(),
            seen,
            max_manifests,
        })
    }

    /// Append newly discovered child manifests to an existing verified walk.
    /// Every path ever enqueued remains in `seen`, including missing or
    /// rejected units, so cycles and repeated discovery cannot bypass the
    /// original manifest cap.
    pub fn enqueue_verified_manifest_paths(
        &self,
        walk: &mut VerifiedManifestWalk,
        mut paths: Vec<String>,
    ) -> Result<()> {
        paths.sort_by(|left, right| {
            left.matches('/')
                .count()
                .cmp(&right.matches('/').count())
                .then_with(|| left.cmp(right))
        });
        let mut fresh = Vec::new();
        let mut batch_seen = std::collections::HashSet::new();
        for path in paths {
            self.storage.path(&path)?;
            if path == "content.json" || !path.ends_with("/content.json") {
                return Err(Error::Other(format!(
                    "invalid stored manifest walk path: {path}"
                )));
            }
            if walk.seen.contains(&path) || !batch_seen.insert(path.clone()) {
                continue;
            }
            fresh.push(path);
        }
        if walk
            .seen
            .len()
            .saturating_add(fresh.len())
            .saturating_add(1)
            > walk.max_manifests
        {
            return Err(Error::Other(format!(
                "stored manifest walk exceeds limit {}",
                walk.max_manifests
            )));
        }
        for path in fresh {
            walk.seen.insert(path.clone());
            walk.pending.push_back(path);
        }
        Ok(())
    }

    /// Verify the next stored manifest without writing or applying archives.
    /// The actual governing manifest must have passed earlier in this walk.
    pub fn verify_next_stored_manifest(
        &self,
        walk: &mut VerifiedManifestWalk,
        expected_path: &str,
        xid_map: &epix_content::verify::XidMap,
    ) -> Result<Option<VerifiedManifest>> {
        let Some(inner_path) = walk.pending.pop_front() else { return Ok(None) };
        if inner_path != expected_path {
            return Err(Error::Other(format!(
                "manifest walk expected {inner_path}, got {expected_path}"
            )));
        }
        if !self.storage.exists(&inner_path) {
            return Ok(None);
        }
        let governing_path = {
            let ctx = VerifiedWalkCtx {
                address: self.address.as_str(),
                storage: &self.storage,
                verified: &walk.verified_contents,
                xid_map,
            };
            epix_content::verify::governing_content_path(&inner_path, &ctx)
                .ok_or_else(|| Error::Crypt(format!("manifest walk has no parent: {inner_path}")))?
        };
        let parent_chain = walk.verified_chains.get(&governing_path).cloned().ok_or_else(|| {
            Error::Crypt(format!(
                "manifest walk parent was not verified: {governing_path}"
            ))
        })?;
        let bytes = self.storage.read(&inner_path)?;
        let content: Value = serde_json::from_slice(&bytes)?;
        let ctx = VerifiedWalkCtx {
            address: self.address.as_str(),
            storage: &self.storage,
            verified: &walk.verified_contents,
            xid_map,
        };
        epix_content::verify_content_file(&inner_path, &content, bytes.len() as i64, &ctx)
            .map_err(|error| Error::Crypt(error.to_string()))?;
        let mut authority_chain = parent_chain;
        authority_chain.push(inner_path.clone());
        walk.verified_chains
            .insert(inner_path.clone(), authority_chain.clone());
        walk.verified_contents
            .insert(inner_path.clone(), content.clone());
        Ok(Some(VerifiedManifest {
            inner_path,
            governing_path,
            authority_chain,
            content,
        }))
    }

    /// Return the exact already-verified parent for the next walk item so the
    /// caller can resolve only the xID names declared by that parent.
    pub fn next_stored_manifest_governing_path(
        &self,
        walk: &VerifiedManifestWalk,
        expected_path: &str,
    ) -> Result<Option<String>> {
        let Some(inner_path) = walk.pending.front() else { return Ok(None) };
        if inner_path != expected_path {
            return Err(Error::Other(format!(
                "manifest walk expected {inner_path}, got {expected_path}"
            )));
        }
        if !self.storage.exists(inner_path) {
            return Ok(None);
        }
        let xid_map = std::collections::HashMap::new();
        let ctx = VerifiedWalkCtx {
            address: self.address.as_str(),
            storage: &self.storage,
            verified: &walk.verified_contents,
            xid_map: &xid_map,
        };
        let governing_path = epix_content::verify::governing_content_path(inner_path, &ctx)
            .ok_or_else(|| Error::Crypt(format!("manifest walk has no parent: {inner_path}")))?;
        if !walk.verified_chains.contains_key(&governing_path) {
            return Err(Error::Crypt(format!(
                "manifest walk parent was not verified: {governing_path}"
            )));
        }
        Ok(Some(governing_path))
    }

    /// Refuse the next pending unit without adding it to the verified set.
    /// Callers use this when the exact governing manifest could not be read or
    /// its xID names could not be resolved safely.
    pub fn skip_next_stored_manifest(
        &self,
        walk: &mut VerifiedManifestWalk,
        expected_path: &str,
    ) -> Result<()> {
        let Some(inner_path) = walk.pending.front() else {
            return Err(Error::Other("manifest walk has no pending item".to_string()));
        };
        if inner_path != expected_path {
            return Err(Error::Other(format!(
                "manifest walk expected {inner_path}, got {expected_path}"
            )));
        }
        walk.pending.pop_front();
        Ok(())
    }

    /// Start a parent-first replay after a restart. The committed root is
    /// verified before any directive runs. Each child must then pass through
    /// [`Self::replay_next_archived_directives`], which preserves that trust
    /// chain one manifest at a time.
    pub fn begin_archive_replay(&mut self) -> Result<Option<ArchiveReplay>> {
        let mut manifests = self.child_contents_under("")?;
        manifests.retain(|path| path != "content.json");
        manifests.sort_by(|left, right| {
            left.matches('/')
                .count()
                .cmp(&right.matches('/').count())
                .then_with(|| left.cmp(right))
        });
        self.begin_archive_replay_from_paths(
            manifests,
            MAX_STORED_MANIFEST_WALK_ENTRIES,
        )
    }

    /// Start archive replay from the same bounded, parent-first manifest list
    /// used by a caller's read-only verification walk. The list is validated
    /// before the root can execute a destructive directive.
    pub fn begin_archive_replay_from_paths(
        &mut self,
        parent_first_paths: Vec<String>,
        max_manifests: usize,
    ) -> Result<Option<ArchiveReplay>> {
        if max_manifests == 0
            || parent_first_paths.len().saturating_add(1) > max_manifests
        {
            return Err(Error::Other(format!(
                "archive replay exceeds limit {max_manifests}"
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for path in &parent_first_paths {
            self.storage.path(path)?;
            if path == "content.json"
                || !path.ends_with("/content.json")
                || !seen.insert(path.clone())
            {
                return Err(Error::Other(format!(
                    "invalid archive replay manifest path: {path}"
                )));
            }
        }
        if !self.apply_committed_root_archived_directives()? {
            return Ok(None);
        }
        Ok(Some(ArchiveReplay {
            pending: parent_first_paths.into(),
            verified_chains: std::iter::once(("content.json".to_string(), Vec::new())).collect(),
            verified_contents: std::iter::once((
                "content.json".to_string(),
                self.content.clone().ok_or_else(|| {
                    Error::Other("verified root disappeared".to_string())
                })?,
            ))
            .collect(),
        }))
    }

    /// Return the exact already-verified parent for the next archive replay
    /// item. Callers use this parent to resolve only its current xID names.
    pub fn next_archive_replay_governing_path(
        &self,
        replay: &ArchiveReplay,
        expected_path: &str,
    ) -> Result<Option<String>> {
        let Some(inner_path) = replay.pending.front() else { return Ok(None) };
        if inner_path != expected_path {
            return Err(Error::Other(format!(
                "archive replay expected {inner_path}, got {expected_path}"
            )));
        }
        if !self.storage.exists(inner_path) {
            return Ok(None);
        }
        let xid_map = std::collections::HashMap::new();
        let ctx = VerifiedWalkCtx {
            address: self.address.as_str(),
            storage: &self.storage,
            verified: &replay.verified_contents,
            xid_map: &xid_map,
        };
        let governing = epix_content::verify::governing_content_path(inner_path, &ctx)
            .ok_or_else(|| Error::Crypt(format!("archive replay has no parent: {inner_path}")))?;
        if !replay.verified_chains.contains_key(&governing) {
            return Err(Error::Crypt(format!(
                "archive replay parent was not verified: {governing}"
            )));
        }
        Ok(Some(governing))
    }

    /// Verify and replay the next child in an [`ArchiveReplay`]. A child is
    /// trusted only when its current governing parent was already verified.
    /// Missing paths are benign because an earlier parent directive may have
    /// removed them from the replay snapshot.
    pub fn replay_next_archived_directives(
        &self,
        replay: &mut ArchiveReplay,
        expected_path: &str,
        xid_map: &epix_content::verify::XidMap,
    ) -> Result<bool> {
        let Some(inner_path) = replay.pending.pop_front() else {
            return Ok(false);
        };
        if inner_path != expected_path {
            return Err(Error::Other(format!(
                "archive replay expected {inner_path}, got {expected_path}"
            )));
        }
        if !self.storage.exists(&inner_path) {
            return Ok(false);
        }
        let ctx = VerifiedWalkCtx {
            address: self.address.as_str(),
            storage: &self.storage,
            verified: &replay.verified_contents,
            xid_map,
        };
        let parent = epix_content::verify::governing_content_path(&inner_path, &ctx)
            .ok_or_else(|| Error::Crypt(format!("archive replay has no parent: {inner_path}")))?;
        let parent_chain = replay
            .verified_chains
            .get(&parent)
            .cloned()
            .ok_or_else(|| {
                Error::Crypt(format!("archive replay parent was not verified: {parent}"))
            })?;
        let bytes = self.storage.read(&inner_path)?;
        let content: Value = serde_json::from_slice(&bytes)?;
        epix_content::verify_content_file(&inner_path, &content, bytes.len() as i64, &ctx)
            .map_err(|error| Error::Crypt(error.to_string()))?;
        self.apply_archived(&inner_path, None, &content)?;
        let mut authority_chain = parent_chain;
        authority_chain.push(inner_path.clone());
        replay
            .verified_contents
            .insert(inner_path.clone(), content);
        replay.verified_chains.insert(inner_path, authority_chain);
        Ok(true)
    }

    /// Every stored `*/content.json` under `dir` (inner paths), any depth.
    fn child_contents_under(&self, dir: &str) -> Result<Vec<String>> {
        let root = self.storage.path(dir.trim_end_matches('/'))?;
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        let mut visited = 0usize;
        while let Some(d) = stack.pop() {
            let entries = std::fs::read_dir(&d)?;
            for entry in entries {
                let entry = entry?;
                visited = visited.saturating_add(1);
                if visited > MAX_STORED_MANIFEST_WALK_ENTRIES {
                    return Err(Error::Other(format!(
                        "stored manifest walk exceeds {MAX_STORED_MANIFEST_WALK_ENTRIES} entries"
                    )));
                }
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                let path = entry.path();
                if file_type.is_dir() {
                    stack.push(path);
                } else if file_type.is_file()
                    && path.file_name().is_some_and(|n| n == "content.json")
                {
                    if let Ok(rel) = path.strip_prefix(self.storage.root()) {
                        out.push(rel.to_string_lossy().replace('\\', "/"));
                    }
                }
            }
        }
        Ok(out)
    }

    /// EpixNet's `_pruneDataFiles`: trim arrays in the `data.json` files under
    /// `dir` per the governing rules. `max_items` `{key: N}` is a hard cap
    /// (keep the newest N); `max_items_age` `{key: seconds}` drops entries
    /// whose `timestamp` fell out of the window, but never below
    /// `max_items_min` (default 100) entries. Runs at sign time, before
    /// hashing, so the signed hashes reflect the pruned data.
    fn pruned_data_files(
        &self,
        dir: &str,
        rules: &Value,
        now: f64,
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        let Some(max_items) = rules.get("max_items").and_then(|v| v.as_object()) else {
            return Ok(std::collections::BTreeMap::new());
        };
        let age_rules = rules.get("max_items_age").and_then(|v| v.as_object());
        let min_rules = rules.get("max_items_min").and_then(|v| v.as_object());
        let ts = |e: &Value| e.get("timestamp").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let prefix = format!("{dir}/");
        let mut pruned = std::collections::BTreeMap::new();
        for inner in self
            .storage
            .list_files_checked(MAX_STORED_MANIFEST_WALK_ENTRIES)?
        {
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
                pruned.insert(inner, serde_json::to_vec(&data)?);
            }
        }
        Ok(pruned)
    }

    /// The `includes` a stored child content.json declares, as inner_paths
    /// relative to the xite root (for recursing into nested includes).
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
        xid_map: &epix_content::verify::XidMap,
    ) -> Vec<String> {
        let Ok(bytes) = self.storage.read(content_inner_path) else {
            return Vec::new();
        };
        let Ok(content) = serde_json::from_slice::<Value>(&bytes) else {
            return Vec::new();
        };
        self.valid_signers_for_content(content_inner_path, &content, xid_map)
    }

    /// The authorized signer set for an already verified, possibly staged,
    /// content.json value. Unlike [`Self::valid_signers_for`], this does not
    /// read storage, so callers do not need to publish a child manifest merely
    /// to derive the merge-record signer set it authorizes.
    pub fn valid_signers_for_content(
        &self,
        content_inner_path: &str,
        content: &Value,
        xid_map: &epix_content::verify::XidMap,
    ) -> Vec<String> {
        let ctx = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            root: self.content.as_ref(),
            xid_map,
        };
        epix_content::verify::valid_signers(content_inner_path, content, &ctx)
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
        cache: Option<&SignCache>,
        overrides: Option<&std::collections::BTreeMap<String, Vec<u8>>>,
    ) -> Result<(
        serde_json::Map<String, Value>,
        serde_json::Map<String, Value>,
        std::collections::BTreeMap<String, Vec<u8>>,
        SignCache,
    )> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        let listing = self
            .storage
            .list_files_checked(MAX_STORED_MANIFEST_WALK_ENTRIES)?;
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
        let mut fresh_cache: SignCache = std::collections::HashMap::new();
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
            // Stat BEFORE any read (see stat_size_mtime for why).
            let override_bytes = overrides.and_then(|files| files.get(&inner));
            let stat = override_bytes
                .is_none()
                .then(|| stat_size_mtime(&self.storage, &inner))
                .flatten();
            let entry = match reuse_cached(&rel, stat, is_optional, cache) {
                Some(hit) => {
                    let entry = json!({ "size": hit.size, "sha512": hit.sha512, "b3": hit.b3 });
                    fresh_cache.insert(rel.clone(), hit);
                    entry
                }
                None => {
                    let bytes = match override_bytes {
                        Some(bytes) => bytes.clone(),
                        None => self.storage.read(&inner)?,
                    };
                    let entry = hash_entry(&rel, &bytes, stat, &mut fresh_cache);
                    // Only bundle-eligible required files are worth keeping:
                    // the bundle builder needs their bytes, and an
                    // optional-heavy xite must not pay for a cache nothing
                    // reads.
                    if !is_optional && epix_blob::bundle::is_bundleable(bytes.len() as u64) {
                        hashed_bytes.insert(rel.clone(), bytes);
                    }
                    entry
                }
            };
            if is_optional {
                files_optional.insert(rel, entry);
            } else {
                files.insert(rel, entry);
            }
        }
        Ok((files, files_optional, hashed_bytes, fresh_cache))
    }

    /// The sign cache from the xite root, or empty when `full` asks for an
    /// honest full re-hash (the escape hatch when a deploy is suspected of
    /// preserving mtimes over changed bytes). Either way the sign REBUILDS
    /// the cache, so one --full pass also repairs a stale cache for good.
    fn load_sign_cache(&self, full: bool) -> SignCache {
        if full {
            return SignCache::new();
        }
        self.storage
            .read(SIGN_CACHE)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
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
        self.sign_opts(privatekey, modified, SignOpts::default())
    }

    /// [`Self::sign`] with `full` forcing a re-read of every file instead of
    /// trusting the stat cache - a per-invocation choice (siteSign --full),
    /// not process state.
    pub fn sign_with(&mut self, privatekey: &str, modified: f64, full: bool) -> Result<()> {
        self.sign_opts(privatekey, modified, SignOpts { full, ..Default::default() })
    }

    /// [`Self::sign`] with explicit options.
    pub fn sign_opts(&mut self, privatekey: &str, modified: f64, opts: SignOpts) -> Result<()> {
        let prepared = self.prepare_sign_opts(privatekey, modified, opts)?;
        self.storage
            .write_atomic_durable("content.json", prepared.bytes())?;
        if let Some(cache) = prepared.sign_cache() {
            let _ = self.storage.write_atomic_durable(SIGN_CACHE, cache);
        }
        self.content = Some(prepared.content);
        Ok(())
    }

    /// Build and sign a root candidate without replacing the authoritative
    /// manifest. The caller can bind the returned bytes to a journaled commit.
    pub fn prepare_sign_opts(
        &self,
        privatekey: &str,
        modified: f64,
        opts: SignOpts,
    ) -> Result<PreparedRootSign> {
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
        // disk (minus content.json units) becomes a required file. A declared
        // optional entry whose file is gone from disk is pruned by default,
        // so a deletion actually leaves the manifest - carrying it forward
        // meant every peer that once held the file re-queued a download
        // nobody could serve (the media xite purged 13 films and its own
        // seeder sat at "updating: 13 left" forever). A signer that
        // deliberately does not hold every optional file (e.g. eviction wiped
        // some) opts out with `keep_missing_optional` (siteSign
        // --keep-missing).
        let mut declared_optional: serde_json::Map<String, Value> = content
            .get("files_optional")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if !opts.keep_missing_optional {
            declared_optional.retain(|rel, _| self.storage.exists(rel));
        }
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
        let sign_cache = self.load_sign_cache(opts.full);
        let (files, files_optional, hashed_bytes, fresh_cache) =
            self.hash_unit_files(
                "",
                &declared_optional,
                &declared_merged,
                &ignore,
                &optional,
                Some(&sign_cache),
                None,
            )?;
        // The cache is returned with the candidate and installed only after
        // the governing manifest commits. A failed cache write merely makes
        // the next sign re-read the files.
        let sign_cache = serde_json::to_vec(&fresh_cache).ok();

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
        // A manifest this node's own loader would reject (an invalid relative
        // path, a case-insensitive destination collision) must fail NOW, at
        // sign time - committing it would brick the xite on the next restart
        // when verify_content_file enforces the same rules. The size gate is
        // skipped (i64::MAX): the effective limit is a load-time setting.
        let ctx = RootCtx {
            address: self.address.as_str().to_string(),
            size_limit: i64::MAX,
        };
        epix_content::verify_content_structure("content.json", &content, bytes.len() as i64, &ctx)
            .map_err(|e| {
                Error::Crypt(format!("refusing to sign an unloadable manifest: {e}"))
            })?;
        Ok(PreparedRootSign { content, bytes, sign_cache })
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
            let Some(size) = e
                .get("size")
                .and_then(epix_content::verify::exact_nonnegative_size)
                .and_then(|size| u64::try_from(size).ok())
            else {
                continue;
            };
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
        let (mut registered, mut skipped) =
            self.register_file_entries(store, content, "", now)?;
        // Declared bundles: rebuild from member files, verify, insert.
        let (r, s) = self.register_bundles(store, content, "", now)?;
        registered += r;
        skipped += s;
        // The encrypted shards this content.json records.
        let (r, s) = self.register_shards(store, content, "", now)?;
        registered += r;
        skipped += s;
        // The child / per-user content.json units stored below the root.
        let (r, s) = self.register_child_units(store, now)?;
        registered += r;
        skipped += s;
        Ok((registered, skipped))
    }

    /// Register one content unit whose signature and exact governing chain
    /// were already verified by [`Self::begin_verified_manifest_walk`]. This
    /// deliberately does not enumerate sibling `content.json` files: startup
    /// callers must pass only units accepted by the verified walk, so a
    /// parseable but corrupt child can never create a Store row.
    pub fn edx_register_verified_manifest(
        &self,
        store: &epix_blob::store::Store,
        inner_path: &str,
        content: &Value,
        now: u64,
    ) -> Result<(usize, usize)> {
        self.storage.path(inner_path)?;
        let dir_prefix = inner_path
            .strip_suffix("content.json")
            .ok_or_else(|| Error::Protocol(format!("not a content manifest: {inner_path}")))?;
        // Backslashes normalize like verify_content_rules does: manifests
        // signed on Windows declare `data\users\...\content.json`, and the
        // verify path (matching Python EpixNet) accepts them - registration
        // must not reject what verification accepted.
        if inner_path != "content.json"
            && content
                .get("inner_path")
                .and_then(Value::as_str)
                .map(|declared| declared.replace('\\', "/"))
                .as_deref()
                != Some(inner_path)
        {
            return Err(Error::Protocol(format!(
                "verified manifest path mismatch: {inner_path}"
            )));
        }
        let (mut registered, mut skipped) =
            self.register_file_entries(store, content, dir_prefix, now)?;
        let (bundles, bundle_skips) =
            self.register_bundles(store, content, dir_prefix, now)?;
        registered += bundles;
        skipped += bundle_skips;
        let (shards, shard_skips) =
            self.register_shards(store, content, dir_prefix, now)?;
        registered += shards;
        skipped += shard_skips;
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
        for cj in self.storage.list_files().unwrap_or_else(|e| {
            eprintln!("edx_object_paths: xite file walk failed: {e}");
            Vec::new()
        }) {
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
    ) -> Result<(usize, usize)> {
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
                let Some(size) = e
                    .get("size")
                    .and_then(epix_content::verify::exact_nonnegative_size)
                    .and_then(|size| u64::try_from(size).ok())
                else {
                    skipped += 1;
                    continue;
                };
                let path = format!("{dir_prefix}{rel}");
                if self.register_entry(store, id, &path, size, now)? {
                    registered += 1;
                } else {
                    skipped += 1;
                }
            }
        }
        Ok((registered, skipped))
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
    ) -> Result<bool> {
        if !self.storage.exists(path) {
            return Ok(false);
        }
        if epix_blob::bundle::is_bundleable(size) {
            let Ok(bytes) = self.storage.read(path) else {
                return Ok(false);
            };
            if bytes.len() as u64 != size || epix_blob::ObjId::of(&bytes) != id {
                return Ok(false);
            }
            store
                .insert_bytes(id, epix_blob::Ns::Plain, &bytes, now)
                .map_err(Error::Io)?;
        } else {
            let Ok(path) = self.storage.path(path) else {
                return Ok(false);
            };
            let Ok((actual, actual_size)) = epix_blob::ObjId::of_file(&path) else {
                return Ok(false);
            };
            if actual != id || actual_size != size {
                return Ok(false);
            }
            let fresh = store
                .adopt_extern(id, epix_blob::Ns::Plain, &path, now)
                .map_err(Error::Io)?;
            if !fresh {
                // A record already existed. If it is a store-side copy of
                // this same file, hand the space back and read through to the
                // tree instead. No-op for anything else.
                store.reclaim_duplicate(id, &path, now).map_err(Error::Io)?;
            }
        }
        store.claim_manifest(id).map_err(Error::Io)?;
        Ok(true)
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
        dir_prefix: &str,
        now: u64,
    ) -> Result<(usize, usize)> {
        let mut registered = 0usize;
        let mut skipped = 0usize;
        let declared = epix_blob::manifest::bundles(content);
        if declared.is_empty() {
            return Ok((registered, skipped));
        }
        for (hex, paths) in Self::collect_bundle_members(content) {
            let Some(id) = epix_blob::ObjId::from_hex(&hex) else { continue };
            if !declared.contains_key(&id) {
                continue;
            }
            let paths = paths
                .into_iter()
                .map(|(off, path)| (off, format!("{dir_prefix}{path}")))
                .collect();
            if self.register_bundle(store, id, paths, now)? {
                registered += 1;
            } else {
                skipped += 1;
            }
        }
        Ok((registered, skipped))
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
    ) -> Result<bool> {
        paths.sort();
        let Some(bytes) = self.read_bundle_members(&paths) else { return Ok(false) };
        if epix_blob::ObjId::of(&bytes) != id {
            return Ok(false);
        }
        store
            .insert_bytes(id, epix_blob::Ns::Plain, &bytes, now)
            .map_err(Error::Io)?;
        store.claim_manifest(id).map_err(Error::Io)?;
        Ok(true)
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
        dir_prefix: &str,
        now: u64,
    ) -> Result<(usize, usize)> {
        let mut registered = 0usize;
        let mut skipped = 0usize;
        let Some(salt) = epix_blob::manifest::edx_salt(content) else {
            return Ok((registered, skipped));
        };
        let Some(fs) = content.get("files_shard").and_then(Value::as_object) else {
            return Ok((registered, skipped));
        };
        for path in fs.keys() {
            let Ok(bytes) = self.storage.read(&format!("{dir_prefix}{path}")) else {
                skipped += 1;
                continue;
            };
            let Some(declared) = epix_blob::manifest::edx_shard_entry(content, path) else {
                skipped += 1;
                continue;
            };
            if declared.mode != 0 {
                skipped += declared.chunks.len().max(1);
                continue;
            }
            let enc = epix_selfenc::encrypt_convergent(&bytes, &salt);
            let exact = declared.chunks.len() == enc.chunks.len()
                && declared.chunks.iter().zip(&enc.chunks).zip(&enc.shards).all(
                    |((signed, plain), (cipher_addr, ciphertext))| {
                        signed.plain_hash == plain.plain_hash
                            && signed.cipher_addr.0 == *cipher_addr
                            && signed.len == plain.len
                            && signed.csize == ciphertext.len() as u32
                    },
                );
            if !exact {
                skipped += declared.chunks.len().max(enc.shards.len()).max(1);
                continue;
            }
            for (addr, ct) in &enc.shards {
                let id = epix_blob::ObjId(*addr);
                store
                    .insert_bytes(id, epix_blob::Ns::Shard, ct, now)
                    .map_err(Error::Io)?;
                store.claim_manifest(id).map_err(Error::Io)?;
                registered += 1;
            }
        }
        Ok((registered, skipped))
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
    ) -> Result<(usize, usize)> {
        let mut registered = 0usize;
        let mut skipped = 0usize;
        for cj in self
            .storage
            .list_files_checked(MAX_STORED_MANIFEST_WALK_ENTRIES)?
        {
            if cj == "content.json" || !cj.ends_with("/content.json") {
                continue;
            }
            let dir = &cj[..cj.len() - "content.json".len()]; // trailing '/'
            let Ok(bytes) = self.storage.read(&cj) else { continue };
            let Ok(child) = serde_json::from_slice::<Value>(&bytes) else { continue };
            let (r, s) = self.register_file_entries(store, &child, dir, now)?;
            registered += r;
            skipped += s;
        }
        Ok((registered, skipped))
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
        xid_map: &epix_content::verify::XidMap,
    ) -> Result<Value> {
        let context = ChildCtx {
            address: self.address.as_str().to_string(),
            storage: &self.storage,
            root: self.content.as_ref(),
            xid_map,
        };
        self.sign_child_with_context(inner_path, privatekey, modified, extend, &context)
    }

    /// Sign a child against a caller-supplied, already verified parent chain.
    /// This prevents an unverified closer content.json left on disk from
    /// changing the rules used for a local signature.
    pub fn sign_child_with_context(
        &self,
        inner_path: &str,
        privatekey: &str,
        modified: f64,
        extend: &serde_json::Map<String, Value>,
        context: &dyn VerifyContext,
    ) -> Result<Value> {
        let prepared = self.prepare_child_sign_with_context(
            inner_path,
            privatekey,
            modified,
            extend,
            context,
        )?;
        if !prepared.pruned_files.is_empty()
            || !prepared.archive.archive_targets.is_empty()
            || !prepared.archive.archive_prune_dirs.is_empty()
        {
            return Err(Error::Other(
                "child signing has data side effects and requires a staged transaction"
                    .to_string(),
            ));
        }
        let PreparedChildSign { content, archive, .. } = prepared;
        self.write_prepared_archive_update(&archive)?;
        Ok(content)
    }

    /// Build and verify a child signature without mutating its data files or
    /// governing manifest. Sign-time pruning is returned as staged file bytes.
    pub fn prepare_child_sign_with_context(
        &self,
        inner_path: &str,
        privatekey: &str,
        modified: f64,
        extend: &serde_json::Map<String, Value>,
        context: &dyn VerifyContext,
    ) -> Result<PreparedChildSign> {
        let Some((dir, name)) = inner_path.rsplit_once('/') else {
            return Err(Error::Protocol(format!("not a child content.json: {inner_path}")));
        };
        if name != "content.json" {
            return Err(Error::Protocol(format!("can only sign content.json files: {inner_path}")));
        }

        let mut content: Value = match self.storage.read(inner_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => json!({}),
            Err(error) => return Err(error),
        };
        let map = content
            .as_object_mut()
            .ok_or_else(|| Error::Protocol("content.json is not a JSON object".into()))?;
        apply_extend(map, extend);

        // EpixNet's sign-time auto-prune: the parent's rules may cap arrays in
        // this directory's data.json files (`max_items`, with age/min
        // variants). Trim before hashing so the signed hashes reflect the
        // pruned data and the result passes the receiver's max_items check.
        let pruned_files = match epix_content::verify::get_rules(inner_path, &content, context) {
            Some(rules) => self.pruned_data_files(dir, &rules, modified)?,
            None => std::collections::BTreeMap::new(),
        };
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
        let (files, files_optional, _, _) = self.hash_unit_files(
            dir,
            &declared_optional,
            &declared_merged,
            &ignore,
            &optional,
            None,
            Some(&pruned_files),
        )?;
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
        let overlay = FileOverlayCtx {
            base: context,
            files: &pruned_files,
        };
        let prepared = self.prepare_child_archive_update_with_context(
            inner_path,
            &bytes,
            &overlay,
        )?;
        Ok(PreparedChildSign {
            content,
            bytes,
            pruned_files,
            archive: prepared,
        })
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

    /// During a clone the root content.json is staged in memory and only
    /// committed to disk once the core set completes - but the user-content
    /// pass runs concurrently and its includes must verify against the root's
    /// rules. Rules resolution has to fall back to the in-memory root when no
    /// disk copy exists, or every include fails with "No rules for this file"
    /// and comments/likes cannot arrive until after the whole core set.
    #[test]
    fn add_content_verifies_includes_against_a_staged_root() {
        let privkey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privkey).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let mut xite = Xite::new(Address::parse(address.clone()).unwrap(), storage);

        // The include, signed by the xite key.
        let include = signed(
            json!({
                "address": address,
                "inner_path": "data/users/content.json",
                "files": {},
                "modified": 1000,
                "user_contents": { "permission_rules": {}, "permissions": {} },
            }),
            &privkey,
        );

        // Root staged in memory only - nothing on disk, exactly mid-clone.
        xite.content = Some(json!({
            "address": address,
            "files": {},
            "includes": { "data/users/content.json": { "signers": [], "signers_required": 1 } },
        }));
        let xid_map = std::collections::HashMap::new();
        xite.add_content("data/users/content.json", &include, &xid_map)
            .expect("include verifies against the staged in-memory root");

        // And a root on disk still wins over the memory copy: stage a root
        // WITHOUT the include declared and the same file must now fail.
        let bare = Xite {
            address: xite.address.clone(),
            storage: xite.storage.clone(),
            content: Some(json!({ "address": address, "files": {}, "includes": {} })),
        };
        assert!(
            bare.add_content("data/users/content.json", &include, &xid_map).is_err(),
            "an undeclared include must not verify"
        );
    }

    /// A re-sign must not re-read what has not changed: the sign cache
    /// carries (size, mtime, hashes) per file, and a second sign of an
    /// untouched xite produces the identical manifest from stats alone.
    /// Touching a file (new mtime) re-hashes it; the cache itself is a
    /// dotfile and never appears in the signed manifest.
    #[test]
    fn resign_reuses_cached_hashes_and_rehashes_touched_files() {
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let mut xite = Xite::new(Address::parse(addr).unwrap(), storage.clone());

        // One optional file over the bundle cutoff (the cacheable class) and
        // one small required file (always read, it feeds the bundles).
        let movie = vec![9u8; 200_000];
        storage.write("video/movie.bin", &movie).unwrap();
        storage.write("index.html", b"<h1>hi</h1>").unwrap();
        xite.content = Some(serde_json::json!({ "optional": "video/.*" }));
        xite.sign(&pk, 1000.0).unwrap();
        let first = xite.content.clone().unwrap();
        assert!(storage.exists(SIGN_CACHE), "sign leaves its cache behind");
        assert!(
            first.get("files").and_then(|f| f.get(SIGN_CACHE)).is_none()
                && first.get("files_optional").and_then(|f| f.get(SIGN_CACHE)).is_none(),
            "the cache never enters the manifest"
        );

        // Corrupt the on-disk movie WITHOUT changing size or mtime: a second
        // sign must trust the cache (prove it reused rather than re-read).
        let mtime = std::fs::metadata(storage.path("video/movie.bin").unwrap())
            .unwrap()
            .modified()
            .unwrap();
        let mut swapped = movie.clone();
        swapped[0] = 1;
        storage.write("video/movie.bin", &swapped).unwrap();
        let f = std::fs::File::options()
            .append(true)
            .open(storage.path("video/movie.bin").unwrap())
            .unwrap();
        f.set_modified(mtime).unwrap();
        xite.sign(&pk, 1001.0).unwrap();
        let second = xite.content.clone().unwrap();
        assert_eq!(
            first["files_optional"]["video/movie.bin"]["b3"],
            second["files_optional"]["video/movie.bin"]["b3"],
            "unchanged (size, mtime) reuses the cached hash without reading"
        );

        // A --full sign ignores the cache and reads the truth even though the
        // stat still matches - the per-invocation escape hatch.
        xite.sign_with(&pk, 1002.0, true).unwrap();
        let full = xite.content.clone().unwrap();
        assert_eq!(
            full["files_optional"]["video/movie.bin"]["b3"],
            serde_json::json!(epix_blob::ObjId::of(&swapped).to_string()),
            "--full re-reads regardless of the stat"
        );

        // Now touch the mtime: a normal sign re-reads changed files by itself.
        f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)).unwrap();
        xite.sign(&pk, 1003.0).unwrap();
        let third = xite.content.clone().unwrap();
        assert_ne!(
            first["files_optional"]["video/movie.bin"]["b3"],
            third["files_optional"]["video/movie.bin"]["b3"],
            "a touched file is re-hashed"
        );
        assert_eq!(
            third["files_optional"]["video/movie.bin"]["b3"],
            serde_json::json!(epix_blob::ObjId::of(&swapped).to_string()),
            "and the manifest now carries the real bytes' hash"
        );
    }

    /// A deleted optional file leaves the manifest on the next sign by
    /// default - carrying it forward meant peers that once held it re-queued
    /// a download nobody could serve. --keep-missing is the opt-out for a
    /// signer that deliberately does not hold every optional file.
    #[test]
    fn a_sign_prunes_deleted_optional_files_unless_kept() {
        let pk = epix_crypt::new_seed();
        let addr = epix_crypt::privatekey_to_address(&pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let mut xite = Xite::new(Address::parse(addr).unwrap(), storage.clone());

        storage.write("video/keep.bin", &vec![1u8; 4096]).unwrap();
        storage.write("video/purged.bin", &vec![2u8; 4096]).unwrap();
        storage.write("index.html", b"<h1>hi</h1>").unwrap();
        xite.content = Some(serde_json::json!({ "optional": "video/.*" }));
        xite.sign(&pk, 1000.0).unwrap();

        // Delete one film. A keep-missing sign carries its entry forward.
        std::fs::remove_file(storage.path("video/purged.bin").unwrap()).unwrap();
        xite.sign_opts(&pk, 1001.0, SignOpts { keep_missing_optional: true, ..Default::default() })
            .unwrap();
        let carried = xite.content.clone().unwrap();
        assert!(
            carried["files_optional"].get("video/purged.bin").is_some(),
            "--keep-missing keeps the declared entry (a signer need not hold it)"
        );

        // A plain sign drops it, and keeps what is still on disk.
        xite.sign(&pk, 1002.0).unwrap();
        let pruned = xite.content.clone().unwrap();
        assert!(pruned["files_optional"].get("video/purged.bin").is_none(), "pruned");
        assert!(pruned["files_optional"].get("video/keep.bin").is_some(), "kept");
    }

    #[cfg(unix)]
    #[test]
    fn signing_rejects_symlinked_files_outside_the_xite() {
        use std::os::unix::fs::symlink;

        let privatekey = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&privatekey).unwrap();
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), b"outside secret").unwrap();
        symlink(outside.path(), root.path().join("leak")).unwrap();
        let storage = XiteStorage::new(root.path());
        let xite = Xite::new(Address::parse(address).unwrap(), storage);

        assert!(xite
            .prepare_sign_opts(&privatekey, 1000.0, SignOpts::default())
            .is_err());
        assert_eq!(std::fs::read(outside.path().join("secret.txt")).unwrap(), b"outside secret");
    }

    /// The upload-accounting reverse map covers everything served by object
    /// id: root + child unit files (child paths dir-prefixed), bundles with
    /// an empty inner_path; a pre-EDX entry (no b3) has no object to map.
    #[test]
    fn edx_object_paths_maps_declared_objects() {
        let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
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
        let mut xite = Xite::new(Address::parse(address).unwrap(), storage);
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
    fn verified_child_registration_prefixes_bundle_members_and_shard_plaintext() {
        let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path().join("xite"));
        storage.write("child/one.bin", b"one").unwrap();
        storage.write("child/two.bin", b"two").unwrap();
        let secret = b"child secret bytes";
        storage.write("child/secret.bin", secret).unwrap();
        let xite = Xite::new(Address::parse(address.clone()).unwrap(), storage);

        let bundle_bytes = b"onetwo";
        let bundle_id = epix_blob::ObjId::of(bundle_bytes);
        // Randomized: a literal salt trips CodeQL's hard-coded-crypto-value
        // taint tracking, and the value is arbitrary for this test.
        let salt: Vec<u8> =
            epix_crypt::new_seed().into_bytes().into_iter().take(32).collect();
        let salt_hex = salt.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let encrypted = epix_selfenc::encrypt_convergent(secret, &salt);
        let mut child = json!({
            "address": address,
            "inner_path": "child/content.json",
            "modified": 1.0,
            "edx_salt": salt_hex,
            "files": {
                "one.bin": {
                    "size": 3,
                    "sha512": XiteStorage::hash_bytes(b"one"),
                    "b3": epix_blob::ObjId::of(b"one").to_string(),
                    "bundle": bundle_id.to_string(),
                    "off": 0,
                },
                "two.bin": {
                    "size": 3,
                    "sha512": XiteStorage::hash_bytes(b"two"),
                    "b3": epix_blob::ObjId::of(b"two").to_string(),
                    "bundle": bundle_id.to_string(),
                    "off": 3,
                },
            },
            "bundles": {
                (bundle_id.to_string()): { "size": bundle_bytes.len() },
            },
        });
        let chunks = encrypted
            .chunks
            .iter()
            .zip(&encrypted.shards)
            .map(|(chunk, (_, ciphertext))| epix_blob::manifest::ShardChunk {
                plain_hash: chunk.plain_hash,
                cipher_addr: epix_blob::ObjId(chunk.cipher_addr),
                len: chunk.len,
                csize: ciphertext.len() as u32,
            })
            .collect();
        epix_blob::manifest::set_shard_entry(
            &mut child,
            "secret.bin",
            &epix_blob::manifest::ShardEntry {
                size: secret.len() as u64,
                mode: 0,
                chunks,
            },
        );

        let store_dir = tempfile::tempdir().unwrap();
        let store = epix_blob::store::Store::open(store_dir.path()).unwrap();
        let (registered, skipped) = xite
            .edx_register_verified_manifest(&store, "child/content.json", &child, 1)
            .unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(registered, 3 + encrypted.shards.len());
        assert!(store.is_complete(bundle_id).unwrap());
        assert_eq!(store.read_bytes(bundle_id, 2).unwrap(), bundle_bytes);
        for (cipher_addr, ciphertext) in encrypted.shards {
            let id = epix_blob::ObjId(cipher_addr);
            assert!(store.is_complete(id).unwrap());
            assert_eq!(store.read_bytes(id, 2).unwrap(), ciphertext);
        }
    }

    #[test]
    fn integral_float_sizes_feed_edx_bundling_and_registration() {
        let address = epix_crypt::privatekey_to_address(&epix_crypt::new_seed()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage.write("one.bin", b"x").unwrap();
        let xite = Xite::new(Address::parse(address).unwrap(), storage);
        let id = epix_blob::ObjId::of(b"x");
        let content = json!({
            "files": {
                "one.bin": {
                    "size": 1.0,
                    "sha512": XiteStorage::hash_bytes(b"x"),
                    "b3": id.to_string(),
                }
            }
        });

        let bundleable = xite
            .edx_bundle_inputs(&content, Default::default())
            .unwrap();
        assert_eq!(
            bundleable.get("one.bin").map(Vec::as_slice),
            Some(b"x".as_slice())
        );

        let store_dir = tempfile::tempdir().unwrap();
        let store = epix_blob::store::Store::open_with(
            store_dir.path(),
            epix_blob::store::StoreConfig {
                xite_root: Some(dir.path().to_path_buf()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            xite.register_file_entries(&store, &content, "", 1).unwrap(),
            (1, 0)
        );
        assert!(store.is_complete(id).unwrap());
    }

    #[test]
    fn verified_manifest_walk_preserves_real_parent_chains() {
        let xite_key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&xite_key).unwrap();
        let user_key = epix_crypt::new_seed();
        let user = epix_crypt::privatekey_to_address(&user_key).unwrap();
        let wrong_key = epix_crypt::new_seed();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 1,
                        "files": {},
                        "includes": {
                            "skipped/deep/content.json": {},
                            "plugins/content.json": {},
                            "data/users/content.json": {},
                            "corrupt/content.json": {},
                        },
                    }),
                    &xite_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "skipped/deep/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "skipped/deep/content.json",
                        "modified": 2,
                        "files": {},
                    }),
                    &xite_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "plugins/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "plugins/content.json",
                        "modified": 2,
                        "files": {},
                        "includes": { "nested/content.json": {} },
                    }),
                    &xite_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "plugins/nested/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "plugins/nested/content.json",
                        "modified": 3,
                        "files": {},
                    }),
                    &xite_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "data/users/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "data/users/content.json",
                        "modified": 2,
                        "files": {},
                        "user_contents": { "permissions": {}, "cert_signers": {} },
                    }),
                    &xite_key,
                ),
            )
            .unwrap();
        let user_path = format!("data/users/{user}/content.json");
        storage
            .write(
                &user_path,
                &signed(
                    json!({
                        "address": address,
                        "inner_path": user_path,
                        "modified": 3,
                        "files": {},
                    }),
                    &user_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "corrupt/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "corrupt/content.json",
                        "modified": 2,
                        "files": {},
                        "includes": { "child/content.json": {} },
                    }),
                    &wrong_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "corrupt/child/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "corrupt/child/content.json",
                        "modified": 3,
                        "files": {},
                    }),
                    &xite_key,
                ),
            )
            .unwrap();

        let paths = vec![
            "corrupt/content.json".to_string(),
            "plugins/content.json".to_string(),
            "data/users/content.json".to_string(),
            "skipped/deep/content.json".to_string(),
            "corrupt/child/content.json".to_string(),
            "plugins/nested/content.json".to_string(),
            user_path.clone(),
        ];
        let mut xite = Xite::new(Address::parse(address).unwrap(), storage);
        let mut walk = xite
            .begin_verified_manifest_walk(paths, 8)
            .unwrap()
            .unwrap();
        let mut verified = std::collections::HashMap::new();
        let none = std::collections::HashMap::new();
        while let Some(path) = walk.next_path().map(str::to_string) {
            if let Ok(Some(item)) = xite.verify_next_stored_manifest(&mut walk, &path, &none) {
                verified.insert(
                    path,
                    (item.governing_path().to_string(), item.authority_chain().to_vec()),
                );
            }
        }
        assert_eq!(
            verified["skipped/deep/content.json"].0,
            "content.json",
            "a skipped directory level remains governed by the root"
        );
        assert_eq!(
            verified["plugins/nested/content.json"].1,
            vec!["plugins/content.json", "plugins/nested/content.json"],
            "nested include keys are relative to their declaring manifest"
        );
        assert_eq!(
            verified[&user_path].1,
            vec!["data/users/content.json".to_string(), user_path],
            "a dynamic user manifest follows its verified user_contents parent"
        );
        assert!(!verified.contains_key("corrupt/content.json"));
        assert!(!verified.contains_key("corrupt/child/content.json"));
    }

    #[test]
    fn verified_manifest_walk_refuses_oversize_or_duplicate_sources() {
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 1,
                        "files": {},
                        "user_contents": { "archived": { "victim": 500 } },
                    }),
                    &key,
                ),
            )
            .unwrap();
        storage
            .write("victim/content.json", br#"{"modified":1,"files":{}}"#)
            .unwrap();
        let mut xite = Xite::new(Address::parse(address).unwrap(), storage);
        assert!(xite
            .begin_verified_manifest_walk(vec!["a/content.json".into()], 1)
            .is_err());
        assert!(xite
            .begin_verified_manifest_walk(
                vec!["a/content.json".into(), "a/content.json".into()],
                3,
            )
            .is_err());
        assert!(xite
            .begin_archive_replay_from_paths(vec!["a/content.json".into()], 1)
            .is_err());
        assert!(
            xite.storage.exists("victim/content.json"),
            "an oversize replay source executed a root archive directive"
        );
    }

    #[test]
    fn verified_manifest_walk_ignores_an_unverified_shadow_parent() {
        let owner_key = epix_crypt::new_seed();
        let wrong_key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&owner_key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 2,
                        "files": {},
                        "includes": { "a/deep/content.json": {} },
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "a/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "a/content.json",
                        "modified": 1,
                        "files": {},
                        "includes": { "deep/content.json": {} },
                    }),
                    &wrong_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "a/deep/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "a/deep/content.json",
                        "modified": 3,
                        "files": {},
                    }),
                    &owner_key,
                ),
            )
            .unwrap();

        let mut xite = Xite::new(Address::parse(address).unwrap(), storage);
        let mut walk = xite
            .begin_verified_manifest_walk(
                vec!["a/content.json".into(), "a/deep/content.json".into()],
                3,
            )
            .unwrap()
            .unwrap();
        let none = std::collections::HashMap::new();
        assert!(xite
            .verify_next_stored_manifest(&mut walk, "a/content.json", &none)
            .is_err());
        assert_eq!(
            xite
                .next_stored_manifest_governing_path(&walk, "a/deep/content.json")
                .unwrap()
                .as_deref(),
            Some("content.json")
        );
        let deep = xite
            .verify_next_stored_manifest(&mut walk, "a/deep/content.json", &none)
            .unwrap()
            .unwrap();
        assert_eq!(deep.governing_path(), "content.json");
    }

    #[test]
    fn verified_manifest_walk_uses_the_accepted_parent_snapshot() {
        let owner_key = epix_crypt::new_seed();
        let owner = epix_crypt::privatekey_to_address(&owner_key).unwrap();
        let attacker_key = epix_crypt::new_seed();
        let attacker = epix_crypt::privatekey_to_address(&attacker_key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": owner,
                        "modified": 1,
                        "files": {},
                        "includes": { "parent/content.json": {} },
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "parent/content.json",
                &signed(
                    json!({
                        "address": owner,
                        "inner_path": "parent/content.json",
                        "modified": 2,
                        "files": {},
                        "includes": {
                            "child/content.json": {
                                "signers": [owner],
                                "signers_required": 1,
                            }
                        },
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "parent/child/content.json",
                &signed(
                    json!({
                        "address": owner,
                        "inner_path": "parent/child/content.json",
                        "modified": 3,
                        "files": {},
                    }),
                    &attacker_key,
                ),
            )
            .unwrap();

        let mut xite = Xite::new(Address::parse(owner.clone()).unwrap(), storage.clone());
        let mut walk = xite
            .begin_verified_manifest_walk(
                vec![
                    "parent/content.json".into(),
                    "parent/child/content.json".into(),
                ],
                3,
            )
            .unwrap()
            .unwrap();
        let none = std::collections::HashMap::new();
        xite.verify_next_stored_manifest(&mut walk, "parent/content.json", &none)
            .unwrap()
            .unwrap();

        // A local edit after parent acceptance must not change the authority
        // used for the pending child.
        storage
            .write(
                "parent/content.json",
                &signed(
                    json!({
                        "address": owner,
                        "inner_path": "parent/content.json",
                        "modified": 4,
                        "files": {},
                        "includes": {
                            "child/content.json": {
                                "signers": [attacker],
                                "signers_required": 1,
                            }
                        },
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        assert!(xite
            .verify_next_stored_manifest(
                &mut walk,
                "parent/child/content.json",
                &none,
            )
            .is_err());
    }

    #[test]
    fn verified_manifest_walk_accepts_name_signed_skipped_level_include() {
        let owner_key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&owner_key).unwrap();
        let admin_key = epix_crypt::new_seed();
        let admin = epix_crypt::privatekey_to_address(&admin_key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 1,
                        "files": {},
                        "includes": {
                            "deep/path/content.json": {
                                "signers": ["admin.epix"],
                                "signers_required": 1,
                            }
                        },
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "deep/path/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "deep/path/content.json",
                        "modified": 2,
                        "files": {},
                    }),
                    &admin_key,
                ),
            )
            .unwrap();
        let mut xite = Xite::new(Address::parse(address).unwrap(), storage);
        let mut walk = xite
            .begin_verified_manifest_walk(vec!["deep/path/content.json".into()], 2)
            .unwrap()
            .unwrap();
        let xid_map = std::collections::HashMap::from([(
            "admin.epix".to_string(),
            vec![epix_content::XidIdentity { address: admin, active: true, revoked_at_time: 0 }],
        )]);
        let verified = xite
            .verify_next_stored_manifest(
                &mut walk,
                "deep/path/content.json",
                &xid_map,
            )
            .unwrap()
            .unwrap();
        assert_eq!(verified.governing_path(), "content.json");
    }

    #[test]
    fn archiving_a_user_directory_deletes_its_content() {
        // A user_contents parent update that archives a user dir removes that
        // user's stored content.json and files (EpixNet's revocation path);
        // re-applying the same parent is a no-op for others.
        let xite_pk = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&xite_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user = epix_crypt::privatekey_to_address(&user_pk).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(address.clone()).unwrap(), storage.clone());
        let none = std::collections::HashMap::new();

        // Root delegates data/users/content.json to the xite owner.
        storage
            .write(
                "content.json",
                &signed(
                    serde_json::json!({
                        "address": address, "modified": 1, "files": {},
                        "includes": { "data/users/content.json": {} },
                    }),
                    &xite_pk,
                ),
            )
            .unwrap();

        // Parent v1: permissive user_contents, nothing archived.
        let parent_v1 = signed(
            serde_json::json!({
                "address": address, "inner_path": "data/users/content.json",
                "modified": 10, "files": {},
                "user_contents": { "permissions": {}, "cert_signers": {} },
            }),
            &xite_pk,
        );
        xite.add_content("data/users/content.json", &parent_v1, &none).unwrap();

        // A user posts: their content.json + a data file.
        let user_inner = format!("data/users/{user}/content.json");
        let data_inner = format!("data/users/{user}/data.json");
        let data = br#"{"topic":[]}"#;
        storage.write(&data_inner, data).unwrap();
        let child = signed(
            serde_json::json!({
                "address": address, "inner_path": user_inner, "modified": 100,
                "files": { "data.json": {
                    "size": data.len(),
                    "sha512": XiteStorage::hash_bytes(data),
                } },
            }),
            &user_pk,
        );
        xite.add_content(&user_inner, &child, &none).unwrap();
        assert!(storage.exists(&user_inner) && storage.exists(&data_inner));
        let unrelated_inner = format!("data/users/{user}/keep.txt");
        storage.write(&unrelated_inner, b"keep").unwrap();

        // Parent v2 archives the user dir exactly at the child's timestamp.
        let parent_v2 = signed(
            serde_json::json!({
                "address": address, "inner_path": "data/users/content.json",
                "modified": 20, "files": {},
                "user_contents": {
                    "permissions": {}, "cert_signers": {},
                    "archived": { user.clone(): 100 },
                },
            }),
            &xite_pk,
        );
        let prepared = xite
            .prepare_child_archive_update("data/users/content.json", &parent_v2, &none)
            .unwrap();
        let planned = prepared
            .archive_targets()
            .iter()
            .map(|target| target.inner_path().to_string())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            planned,
            [user_inner.clone(), data_inner.clone()].into_iter().collect(),
            "the plan contains only the child manifest and its declared file"
        );
        assert_eq!(
            prepared.archive_prune_dirs(),
            &[format!("data/users/{user}")],
            "the plan carries only the archived child's safe prune directory"
        );
        assert!(
            storage.exists(&user_inner)
                && storage.exists(&data_inner)
                && storage.exists(&unrelated_inner),
            "planning must not change storage"
        );
        xite.add_content("data/users/content.json", &parent_v2, &none).unwrap();
        for target in planned {
            assert!(!storage.exists(&target), "apply removed every planned target");
        }
        assert!(storage.exists(&unrelated_inner), "archive kept unrelated content");

        // Model a crash after the parent rename but before cleanup, then a
        // restart. Replaying the already-committed directive removes the
        // lingering revoked subtree without requiring another parent update.
        storage.delete(&unrelated_inner).unwrap();
        storage.write(&data_inner, data).unwrap();
        storage.write(&user_inner, &child).unwrap();
        let mut reloaded = Xite::new(Address::parse(address.clone()).unwrap(), storage.clone());
        let mut replay = reloaded.begin_archive_replay().unwrap().unwrap();
        while let Some(path) = replay.next_path().map(str::to_string) {
            reloaded
                .replay_next_archived_directives(&mut replay, &path, &none)
                .unwrap();
        }
        assert!(
            !storage.exists(&user_inner),
            "restart replay kept revoked content"
        );
        assert!(
            !storage.exists(&data_inner),
            "restart replay kept revoked data"
        );
        assert!(
            !storage.path(&format!("data/users/{user}")).unwrap().exists(),
            "applying the plan did not prune the empty archived directory"
        );

        // And the revoked user can no longer push old content back.
        let err = xite.add_content(&user_inner, &child, &none).unwrap_err();
        assert!(err.to_string().contains("archived"), "{err}");
    }

    #[test]
    fn archive_replay_rejects_corrupt_root_and_child_directives() {
        let xite_pk = epix_crypt::new_seed();
        let wrong_pk = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&xite_pk).unwrap();
        let none = std::collections::HashMap::new();

        // A bad root signature must not authorize a root-level deletion.
        let root_dir = tempfile::tempdir().unwrap();
        let root_storage = XiteStorage::new(root_dir.path());
        root_storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 2,
                        "files": {},
                        "user_contents": { "archived": { "victim": 500 } },
                    }),
                    &wrong_pk,
                ),
            )
            .unwrap();
        root_storage
            .write("victim/content.json", br#"{"modified":1,"files":{}}"#)
            .unwrap();
        let mut corrupt_root = Xite::new(
            Address::parse(address.clone()).unwrap(),
            root_storage.clone(),
        );
        assert!(corrupt_root.begin_archive_replay().is_err());
        assert!(
            root_storage.exists("victim/content.json"),
            "an unverified root executed archive directives"
        );

        // A verified root does not make arbitrary descendants trusted. The
        // corrupt include must fail before its archive map can remove a child,
        // and that failure must also keep its descendants outside the trust
        // chain.
        let child_dir = tempfile::tempdir().unwrap();
        let child_storage = XiteStorage::new(child_dir.path());
        child_storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 1,
                        "files": {},
                        "includes": { "data/mods/content.json": {} },
                    }),
                    &xite_pk,
                ),
            )
            .unwrap();
        child_storage
            .write(
                "data/mods/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "data/mods/content.json",
                        "modified": 2,
                        "files": {},
                        "user_contents": { "archived": { "victim": 500 } },
                    }),
                    &wrong_pk,
                ),
            )
            .unwrap();
        child_storage
            .write(
                "data/mods/victim/content.json",
                br#"{"modified":1,"files":{}}"#,
            )
            .unwrap();
        let mut corrupt_child = Xite::new(Address::parse(address).unwrap(), child_storage.clone());
        let mut replay = corrupt_child.begin_archive_replay().unwrap().unwrap();
        let first = replay.next_path().unwrap().to_string();
        assert_eq!(first, "data/mods/content.json");
        assert!(corrupt_child
            .replay_next_archived_directives(&mut replay, &first, &none)
            .is_err());
        let second = replay.next_path().unwrap().to_string();
        assert_eq!(second, "data/mods/victim/content.json");
        assert!(
            corrupt_child
                .replay_next_archived_directives(&mut replay, &second, &none)
                .is_err(),
            "a descendant inherited trust from an unverified parent"
        );
        assert!(
            child_storage.exists("data/mods/victim/content.json"),
            "an unverified child executed archive directives"
        );
    }

    #[test]
    fn archive_replay_ignores_an_unverified_shadow_parent() {
        let owner_key = epix_crypt::new_seed();
        let wrong_key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&owner_key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 2,
                        "files": {},
                        "includes": { "a/deep/content.json": {} },
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "a/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "a/content.json",
                        "modified": 1,
                        "files": {},
                        "includes": { "deep/content.json": {} },
                    }),
                    &wrong_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "a/deep/content.json",
                &signed(
                    json!({
                        "address": address,
                        "inner_path": "a/deep/content.json",
                        "modified": 3,
                        "files": {},
                        "user_contents": {
                            "permissions": {},
                            "cert_signers": {},
                            "archived": { "victim": 50 },
                        },
                    }),
                    &owner_key,
                ),
            )
            .unwrap();
        storage
            .write(
                "a/deep/victim/content.json",
                br#"{"address":"ignored","inner_path":"a/deep/victim/content.json","modified":1,"files":{}}"#,
            )
            .unwrap();

        let mut xite = Xite::new(Address::parse(address).unwrap(), storage.clone());
        let mut replay = xite
            .begin_archive_replay_from_paths(
                vec![
                    "a/content.json".into(),
                    "a/deep/content.json".into(),
                    "a/deep/victim/content.json".into(),
                ],
                4,
            )
            .unwrap()
            .unwrap();
        let none = std::collections::HashMap::new();
        assert!(xite
            .replay_next_archived_directives(&mut replay, "a/content.json", &none)
            .is_err());
        assert_eq!(
            xite
                .next_archive_replay_governing_path(&replay, "a/deep/content.json")
                .unwrap()
                .as_deref(),
            Some("content.json")
        );
        assert!(xite
            .replay_next_archived_directives(
                &mut replay,
                "a/deep/content.json",
                &none,
            )
            .unwrap());
        assert!(
            !storage.exists("a/deep/victim/content.json"),
            "verified deep archive cleanup was shadowed by a corrupt closer parent"
        );
    }

    #[test]
    fn a_prepared_archive_update_is_bound_to_its_storage_tree() {
        let private_key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&private_key).unwrap();
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        let first = Xite::new(
            Address::parse(address.clone()).unwrap(),
            XiteStorage::new(first_dir.path()),
        );
        let mut second = Xite::new(
            Address::parse(address.clone()).unwrap(),
            XiteStorage::new(second_dir.path()),
        );
        let root = signed(
            json!({ "address": address, "modified": 1, "files": {} }),
            &private_key,
        );

        let prepared = first.prepare_root_archive_update(&root, i64::MAX).unwrap();
        let error = second.commit_prepared_archive_update(prepared).unwrap_err();
        assert!(
            error.to_string().contains("another storage root"),
            "{error}"
        );
        assert!(!second.storage.exists("content.json"));
        assert!(second.content.is_none());
    }

    #[test]
    fn archive_planning_rejects_unsafe_declared_targets_without_side_effects() {
        let private_key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&private_key).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(address.clone()).unwrap(), storage.clone());
        let none = std::collections::HashMap::new();
        storage
            .write(
                "content.json",
                &signed(
                    json!({
                        "address": address,
                        "modified": 1,
                        "files": {},
                        "includes": { "data/users/content.json": {} },
                    }),
                    &private_key,
                ),
            )
            .unwrap();
        let old_parent = signed(
            json!({
                "address": address,
                "inner_path": "data/users/content.json",
                "modified": 2,
                "files": {},
                "user_contents": { "permissions": {}, "cert_signers": {} },
            }),
            &private_key,
        );
        xite.add_content("data/users/content.json", &old_parent, &none)
            .unwrap();
        storage
            .write(
                "data/users/victim/content.json",
                &serde_json::to_vec(&json!({
                    "modified": 3,
                    "files": { "../../escape.txt": {} },
                }))
                .unwrap(),
            )
            .unwrap();
        let new_parent = signed(
            json!({
                "address": address,
                "inner_path": "data/users/content.json",
                "modified": 4,
                "files": {},
                "user_contents": {
                    "permissions": {},
                    "cert_signers": {},
                    "archived": { "victim": 5 },
                },
            }),
            &private_key,
        );

        let error = xite
            .prepare_child_archive_update("data/users/content.json", &new_parent, &none)
            .unwrap_err();
        assert!(error.to_string().contains("unsafe inner_path"), "{error}");
        assert!(storage.exists("data/users/victim/content.json"));
        assert_eq!(storage.read("data/users/content.json").unwrap(), old_parent);

        let alias_parent = signed(
            json!({
                "address": address,
                "inner_path": "data/users/content.json",
                "modified": 5,
                "files": {},
                "user_contents": {
                    "permissions": {},
                    "cert_signers": {},
                    "archived": { ".": 6 },
                },
            }),
            &private_key,
        );
        let error = xite
            .prepare_child_archive_update("data/users/content.json", &alias_parent, &none)
            .unwrap_err();
        assert!(
            error.to_string().contains("unsafe archived directory name"),
            "{error}"
        );
        assert_eq!(storage.read("data/users/content.json").unwrap(), old_parent);
    }

    #[test]
    fn committed_root_archive_directives_apply_without_a_restart() {
        let xite_pk = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&xite_pk).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage
            .write("victim/content.json", br#"{"modified":1,"files":{}}"#)
            .unwrap();
        let root = signed(
            json!({
                "address": address,
                "modified": 2,
                "files": {},
                "user_contents": { "archived": { "victim": 500 } },
            }),
            &xite_pk,
        );
        storage.write("content.json", &root).unwrap();

        let mut xite = Xite::new(Address::parse(address).unwrap(), storage.clone());
        assert!(xite.apply_committed_root_archived_directives().unwrap());
        assert!(
            !storage.exists("victim/content.json"),
            "a live root commit left its archive directive pending until restart"
        );
    }

    #[test]
    fn sign_child_splits_files_by_the_optional_pattern() {
        // The EpixPost flow: a user content.json declares an `optional`
        // pattern, so a newly written photo signs as optional instead of
        // counting against the user's required size limit.
        let xite_pk = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&xite_pk).unwrap();
        let user_pk = epix_crypt::new_seed();
        let user = epix_crypt::privatekey_to_address(&user_pk).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        let xite = Xite::new(Address::parse(address.clone()).unwrap(), storage.clone());
        let none = std::collections::HashMap::new();

        storage
            .write(
                "content.json",
                &signed(
                    serde_json::json!({
                        "address": address, "modified": 1, "files": {},
                        "includes": { "data/users/content.json": {} },
                    }),
                    &xite_pk,
                ),
            )
            .unwrap();
        let parent = signed(
            serde_json::json!({
                "address": address, "inner_path": "data/users/content.json",
                "modified": 10, "files": {},
                "user_contents": { "permissions": {}, "cert_signers": {} },
            }),
            &xite_pk,
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
        let (files, _optional, hashed, _cache) =
            xite.hash_unit_files("", &none, &none, &None, &None, None, None).unwrap();

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
        let (files, _optional, hashed, _cache) =
            xite.hash_unit_files("", &none, &none, &None, &None, None, None).unwrap();

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
