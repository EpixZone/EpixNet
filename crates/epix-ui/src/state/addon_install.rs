//! Native addon operations bound to the accepted, live signed manifest chain.
use super::{
    AppState, EdxObjectRef, VerifiedAuthorityContext, VerifiedDeclarationSection,
    VerifiedFileDeclaration, canonical_address,
};
use crate::addons::{
    AddonAction, AddonCandidate, AddonEngine, AddonEngineOutcome, AddonError, AddonErrorCode,
    AddonInstalled, AddonInventory, AddonOwnership, AddonPhase, AddonPrepareRequest, AddonSession,
    AddonSnapshot, CANDIDATE_LIFETIME_MS, Ledger, MAX_ARCHIVE_BYTES, MAX_AUTHORITY_BYTES,
    MAX_LEDGER_BYTES, MAX_MANAGED_ADDONS, MAX_MANIFEST_BYTES, Profile, Result, StagedAddon,
    check_cancel, check_managed_count, fail, now_ms, random_id, valid_id,
};
use crate::data_relocation::{NativeReadDirectory, ProtectedDirectory};
use epix_core::Address;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone)]
pub(crate) struct AuthorityStamp {
    canonical: String,
    inner: String,
    storage_root: PathBuf,
    root: Arc<NativeReadDirectory>,
    declaration: VerifiedFileDeclaration,
    accepted: HashMap<String, Value>,
    verified_epoch: u64,
    source_epoch: u64,
    raw_hashes: Vec<(String, String)>,
}
fn authority_error(e: impl ToString) -> AddonError {
    AddonError::new(AddonErrorCode::UnverifiedAuthority, e.to_string())
}
fn changed(e: impl ToString) -> AddonError {
    AddonError::new(AddonErrorCode::ChangedAuthority, e.to_string())
}
async fn cancelled(cancel: &AtomicBool) {
    while !cancel.load(Ordering::Acquire) {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}
async fn bounded_preparation<T>(
    cancel: &AtomicBool,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    check_cancel(cancel)?;
    tokio::select! {
        result = tokio::time::timeout(std::time::Duration::from_secs(120), future) =>
            result.map_err(|_| AddonError::new(AddonErrorCode::Expired, "Addon preparation timed out"))?,
        _ = cancelled(cancel) => fail(AddonErrorCode::Cancelled, "Addon preparation cancelled"),
    }
}
fn bounded_value_len(value: &Value) -> Result<usize> {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(b.len())
                .filter(|n| *n <= MAX_MANIFEST_BYTES as usize)
                .ok_or_else(|| std::io::Error::other("Manifest size limit"))?;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Counter(0);
    serde_json::to_writer(&mut c, value).map_err(|_| {
        AddonError::new(
            AddonErrorCode::LimitExceeded,
            "Accepted manifest exceeds limit",
        )
    })?;
    Ok(c.0)
}
fn archive_hashes(bytes: &[u8], entry: &Value) -> Result<()> {
    if entry.get("piecemap").is_some() {
        return fail(
            AddonErrorCode::UnsupportedSource,
            "Addon packages require a flat signed file",
        );
    }
    let size = entry
        .get("size")
        .and_then(epix_content::verify::exact_nonnegative_size)
        .ok_or_else(|| authority_error("Invalid declared package size"))? as u64;
    if size > MAX_ARCHIVE_BYTES {
        return fail(
            AddonErrorCode::LimitExceeded,
            "Declared package exceeds archive limit",
        );
    }
    if size != bytes.len() as u64 {
        return fail(
            AddonErrorCode::UnverifiedAuthority,
            "Package length differs from signed declaration",
        );
    }
    let mut present = false;
    for key in ["b3", "sha512"] {
        if let Some(value) = entry.get(key) {
            present = true;
            let hash = value
                .as_str()
                .filter(|s| valid_id(s))
                .ok_or_else(|| authority_error("Invalid declared package hash"))?;
            let actual = if key == "b3" {
                blake3::hash(bytes).to_hex().to_string()
            } else {
                hex::encode(&sha2::Sha512::digest(bytes)[..32])
            };
            if hash != actual {
                return fail(
                    AddonErrorCode::UnverifiedAuthority,
                    "Package bytes differ from signed hash",
                );
            }
        }
    }
    if !present {
        return fail(
            AddonErrorCode::UnverifiedAuthority,
            "Package requires a flat signed file hash",
        );
    }
    Ok(())
}
fn verify_live_authority(
    stamp: &AuthorityStamp,
    cancel: &AtomicBool,
    xid_map: &epix_content::XidMap,
) -> Result<Vec<(String, String)>> {
    let mut live = HashMap::new();
    let mut hashes = Vec::new();
    let mut total = 0;
    for (index, path) in std::iter::once("content.json")
        .chain(stamp.declaration.authority_chain.iter().map(String::as_str))
        .enumerate()
    {
        check_cancel(cancel)?;
        let bytes = stamp
            .root
            .read(path, MAX_MANIFEST_BYTES)
            .map_err(authority_error)?;
        total += bytes.len();
        if total > MAX_AUTHORITY_BYTES {
            return fail(
                AddonErrorCode::LimitExceeded,
                "Live authority exceeds limit",
            );
        }
        let value = crate::addons::unique_json(&bytes).map_err(authority_error)?;
        if value
            .get("signs")
            .and_then(Value::as_object)
            .is_some_and(|s| s.len() > 64)
            || value
                .get("signers")
                .and_then(Value::as_array)
                .is_some_and(|s| s.len() > 64)
        {
            return fail(
                AddonErrorCode::LimitExceeded,
                "Authority signer count limit",
            );
        }
        let context = VerifiedAuthorityContext {
            canonical: &stamp.canonical,
            contents: &live,
            xid_map,
            storage: None,
            staged: None,
        };
        if index > 0 {
            let parent = if index == 1 {
                "content.json"
            } else {
                &stamp.declaration.authority_chain[index - 2]
            };
            if epix_content::verify::governing_content_path(path, &context).as_deref()
                != Some(parent)
            {
                return Err(authority_error("Delegation parent changed"));
            }
        }
        epix_content::verify_content_file(path, &value, bytes.len() as i64, &context)
            .map_err(authority_error)?;
        if stamp.accepted.get(path) != Some(&value) {
            return Err(changed("Stored manifest differs from accepted authority"));
        }
        hashes.push((path.into(), hex::encode(Sha256::digest(&bytes))));
        live.insert(path.into(), value);
    }
    Ok(hashes)
}
impl AppState {
    #[cfg(test)]
    pub(crate) async fn addon_hold_authority_for_test(
        &self,
        address: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.merge_path_lock(address, "content.json")
            .lock_owned()
            .await
    }

    async fn addon_publisher(&self, source: &str) -> Result<(String, String)> {
        let (host, inner) = crate::addons::parse_source(source)?;
        let address = host.strip_suffix(".epix").unwrap();
        match epix_core::classify_label(address) {
            epix_core::LabelClass::Address => return Ok((address.into(), inner)),
            epix_core::LabelClass::AddressShaped => {
                return Err(authority_error("Invalid publisher address checksum"));
            }
            epix_core::LabelClass::Name => {}
        }
        let resolver =
            self.on_demand.read().await.clone().ok_or_else(|| {
                authority_error("Publisher name has no configured verified resolver")
            })?;
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            resolver.resolve_verified_name(&host),
        )
        .await
        .map_err(|_| authority_error("Publisher resolution timed out"))?
        .filter(|r| r.verified)
        .ok_or_else(|| authority_error("Publisher name has no verified chain resolution"))?;
        Address::parse(answer.address.clone()).map_err(authority_error)?;
        Ok((answer.address, inner))
    }
    async fn addon_snapshot(&self, canonical: &str, inner: &str) -> Result<AuthorityStamp> {
        let _activation = self.xite_activation_gate.clone().read_owned().await;
        let _tree = self.tree_mutation_lock(canonical).lock_owned().await;
        let xites = self.xites.read().await;
        let xite = xites.get(canonical).ok_or_else(|| {
            AddonError::new(
                AddonErrorCode::MissingLocalFile,
                "Publisher xite is not available locally",
            )
        })?;
        if canonical_address(xite.content.as_ref(), canonical) != canonical {
            return fail(
                AddonErrorCode::UnverifiedAuthority,
                "Publisher identity mismatch",
            );
        }
        // Bound every potential governing manifest before the declaration
        // accessor clones an entry/authority chain from the accepted index.
        {
            let contents = self
                .verified_manifest_contents
                .read()
                .expect("verified_manifest_contents");
            let contents = contents
                .get(canonical)
                .ok_or_else(|| authority_error("Missing accepted authority"))?;
            let mut parent = String::new();
            let mut depth = 0;
            for part in std::iter::once("").chain(
                inner
                    .split('/')
                    .take(inner.split('/').count().saturating_sub(1)),
            ) {
                if !part.is_empty() {
                    if !parent.is_empty() {
                        parent.push('/');
                    }
                    parent.push_str(part);
                }
                let path = if parent.is_empty() {
                    "content.json".into()
                } else {
                    format!("{parent}/content.json")
                };
                if let Some(value) = contents.get(&path) {
                    bounded_value_len(value)?;
                    depth += 1;
                    if depth > 32 {
                        return fail(AddonErrorCode::LimitExceeded, "Authority depth limit");
                    }
                }
            }
        }
        let declaration = self
            .verified_file_declaration(canonical, inner, VerifiedDeclarationSection::File)
            .ok_or_else(|| authority_error("Package is not in the verified file index"))?;
        let entry = &declaration.entry;
        if entry.get("piecemap").is_some() {
            return fail(
                AddonErrorCode::UnsupportedSource,
                "Addon packages require a flat signed file",
            );
        }
        let size = entry
            .get("size")
            .and_then(epix_content::verify::exact_nonnegative_size)
            .ok_or_else(|| authority_error("Invalid package size"))?;
        if size == 0 || size as u64 > MAX_ARCHIVE_BYTES {
            return fail(
                AddonErrorCode::LimitExceeded,
                "Package size exceeds allowed range",
            );
        }
        if declaration.authority_chain.len() > 32 {
            return fail(
                AddonErrorCode::LimitExceeded,
                "Authority chain exceeds depth limit",
            );
        }
        let indexed = self
            .verified_manifest_contents
            .read()
            .expect("verified_manifest_contents");
        let indexed = indexed
            .get(canonical)
            .ok_or_else(|| authority_error("Missing accepted authority"))?;
        let mut accepted = HashMap::new();
        let mut total = 0;
        for path in std::iter::once("content.json")
            .chain(declaration.authority_chain.iter().map(String::as_str))
        {
            if path.len() > 1024 || !epix_content::verify::is_valid_relative_path(path) {
                return fail(
                    AddonErrorCode::UnverifiedAuthority,
                    "Invalid indexed authority path",
                );
            }
            let value = indexed
                .get(path)
                .ok_or_else(|| authority_error("Incomplete accepted authority"))?;
            total += bounded_value_len(value)?;
            if total > MAX_AUTHORITY_BYTES {
                return fail(
                    AddonErrorCode::LimitExceeded,
                    "Authority metadata exceeds limit",
                );
            }
            accepted.insert(path.into(), value.clone());
        }
        let governing = &accepted[&declaration.governing];
        let required = governing
            .get("files")
            .and_then(|files| files.get(&declaration.relative_path));
        let optional = governing
            .get("files_optional")
            .and_then(|files| files.get(&declaration.relative_path));
        if required.is_some() && optional.is_some() {
            return Err(authority_error(
                "Package is ambiguously declared as required and optional",
            ));
        }
        if accepted.get("content.json") != xite.content.as_ref() {
            return fail(
                AddonErrorCode::UnverifiedAuthority,
                "Accepted and managed roots differ",
            );
        }
        let root =
            Arc::new(NativeReadDirectory::open(xite.storage.root()).map_err(authority_error)?);
        Ok(AuthorityStamp {
            canonical: canonical.into(),
            inner: inner.into(),
            storage_root: xite.storage.root().to_owned(),
            root,
            declaration,
            accepted,
            verified_epoch: self.verified_index_epoch(canonical),
            source_epoch: self.db_source_epoch(canonical),
            raw_hashes: Vec::new(),
        })
    }
    async fn addon_verify(
        &self,
        stamp: &mut AuthorityStamp,
        cancel: &AtomicBool,
        read_archive: bool,
    ) -> Result<Option<Vec<u8>>> {
        check_cancel(cancel)?;
        let names =
            Self::authority_chain_xid_names(&stamp.declaration.authority_chain, &stamp.accepted)
                .map_err(authority_error)?;
        if names.len() > 64 || names.iter().any(|n| n.len() > 255) {
            return fail(
                AddonErrorCode::LimitExceeded,
                "Too many authority identities",
            );
        }
        let xid_map = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            Self::resolve_xid_names_checked(names),
        )
        .await
        .map_err(|_| authority_error("Authority identity resolution timed out"))?
        .map_err(authority_error)?;
        check_cancel(cancel)?;
        let _guard = self
            .acquire_manifest_guard(&stamp.canonical, &stamp.declaration.governing)
            .await
            .map_err(authority_error)?;
        let _tree = self.tree_mutation_lock(&stamp.canonical).lock_owned().await;
        {
            let xites = self.xites.read().await;
            let xite = xites
                .get(&stamp.canonical)
                .ok_or_else(|| changed("Publisher removed"))?;
            if xite.storage.root() != stamp.storage_root
                || xite.content.as_ref() != stamp.accepted.get("content.json")
                || self.verified_index_epoch(&stamp.canonical) != stamp.verified_epoch
                || self.db_source_epoch(&stamp.canonical) != stamp.source_epoch
            {
                return Err(changed("Publisher changed during preparation"));
            }
        }
        let current = self
            .verified_file_declaration(
                &stamp.canonical,
                &stamp.inner,
                VerifiedDeclarationSection::File,
            )
            .ok_or_else(|| changed("Package declaration removed"))?;
        if current.governing != stamp.declaration.governing
            || current.authority_chain != stamp.declaration.authority_chain
            || current.entry != stamp.declaration.entry
            || current.optional != stamp.declaration.optional
        {
            return Err(changed("Package declaration changed"));
        }
        // Borrow each accepted value for equality, avoiding a second unbounded clone.
        {
            let indexed = self
                .verified_manifest_contents
                .read()
                .expect("verified_manifest_contents");
            let indexed = indexed
                .get(&stamp.canonical)
                .ok_or_else(|| changed("Accepted authority removed"))?;
            if stamp
                .accepted
                .iter()
                .any(|(p, v)| indexed.get(p) != Some(v))
            {
                return Err(changed("Accepted authority changed"));
            }
        }
        stamp.root.assert_bound().map_err(changed)?;
        let hashes = verify_live_authority(stamp, cancel, &xid_map)?;
        if !stamp.raw_hashes.is_empty() && stamp.raw_hashes != hashes {
            return Err(changed("Raw authority bytes changed since consent"));
        }
        stamp.raw_hashes = hashes;
        let bytes = if read_archive {
            let size = stamp
                .declaration
                .entry
                .get("size")
                .and_then(epix_content::verify::exact_nonnegative_size)
                .ok_or_else(|| authority_error("Invalid package size"))?;
            if size as u64 > MAX_ARCHIVE_BYTES {
                return fail(AddonErrorCode::LimitExceeded, "Package exceeds limit");
            }
            let bytes = stamp
                .root
                .read(&stamp.inner, MAX_ARCHIVE_BYTES)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        AddonError::new(
                            AddonErrorCode::MissingLocalFile,
                            "Package is not available in local xite storage",
                        )
                    } else {
                        authority_error(e)
                    }
                })?;
            archive_hashes(&bytes, &stamp.declaration.entry)?;
            Some(bytes)
        } else {
            None
        };
        stamp.root.assert_bound().map_err(changed)?;
        check_cancel(cancel)?;
        Ok(bytes)
    }

    async fn addon_archive(
        &self,
        stamp: &mut AuthorityStamp,
        cancel: &AtomicBool,
    ) -> Result<Vec<u8>> {
        match self.addon_verify(stamp, cancel, true).await {
            Ok(Some(bytes)) => return Ok(bytes),
            Err(error) if error.code == AddonErrorCode::MissingLocalFile => {}
            Err(error) => return Err(error),
            Ok(None) => unreachable!("archive read requested"),
        }
        // addon_verify already froze and verified the entire live authority
        // chain before reporting the missing file. No mutable path is sent to
        // the downloader, and it never writes into the publisher's tree.
        let entry = &stamp.declaration.entry;
        if entry.get("bundle").is_some() || entry.get("off").is_some() {
            return fail(
                AddonErrorCode::UnsupportedSource,
                "Bundled addon package must already be downloaded in its xite",
            );
        }
        let id = entry
            .get("b3")
            .and_then(Value::as_str)
            .filter(|h| valid_id(h))
            .and_then(epix_blob::ObjId::from_hex)
            .ok_or_else(|| {
                AddonError::new(
                    AddonErrorCode::MissingLocalFile,
                    "Missing package has no signed EDX object hash",
                )
            })?;
        let size = entry
            .get("size")
            .and_then(epix_content::verify::exact_nonnegative_size)
            .ok_or_else(|| authority_error("Invalid package size"))? as u64;
        let fetcher = self.edx_fetcher.read().await.clone().ok_or_else(|| {
            AddonError::new(
                AddonErrorCode::MissingLocalFile,
                "Addon download is unavailable",
            )
        })?;
        let fetch = fetcher.fetch_addon_object(&stamp.canonical, EdxObjectRef { id, size });
        let bytes = tokio::select! {
            result = tokio::time::timeout(std::time::Duration::from_secs(60), fetch) => {
                result.map_err(|_| AddonError::new(AddonErrorCode::MissingLocalFile, "Addon download timed out"))?
                    .map_err(|e| AddonError::new(AddonErrorCode::MissingLocalFile, e))?
            },
            _ = cancelled(cancel) => return fail(AddonErrorCode::Cancelled, "Addon preparation cancelled"),
        };
        check_cancel(cancel)?;
        archive_hashes(&bytes, &stamp.declaration.entry)?;
        self.addon_verify(stamp, cancel, false).await?;
        Ok(bytes)
    }
}

fn stage_name(operation: &str) -> String {
    format!("{operation}.xpi")
}
fn store_ledger(profile: &mut Profile, ledger: Ledger) -> Result<()> {
    check_managed_count(ledger.managed.len())?;
    let bytes = serde_json::to_vec(&ledger)
        .map_err(|e| AddonError::new(AddonErrorCode::Io, e.to_string()))?;
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return fail(AddonErrorCode::LimitExceeded, "Addon receipt limit");
    }
    profile.directory.write("receipts.json", &bytes)?;
    profile.ledger = ledger;
    Ok(())
}
fn clear_pending(
    profile: &mut Profile,
    phase: AddonPhase,
    message: Option<String>,
) -> Result<AddonSnapshot> {
    let mut operation = profile
        .operation
        .clone()
        .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidRequest, "No addon operation"))?;
    operation.phase = phase;
    operation.message = message;
    let mut ledger = profile.ledger.clone();
    ledger.pending = None;
    ledger.uninstall_id = None;
    ledger.completed = Some(operation.clone());
    store_ledger(profile, ledger)?;
    profile.stamp = None;
    profile.operation = Some(operation.clone());
    // Persist cancellation first. A leftover owned spool after an IO failure
    // cannot be interpreted as an authorized engine handoff.
    profile
        .directory
        .remove(&stage_name(&operation.operation_id))?;
    Ok(operation)
}
fn ensure_operation<'a>(p: &'a mut Profile, id: &str) -> Result<&'a mut AddonSnapshot> {
    if !valid_id(id) {
        return fail(AddonErrorCode::InvalidRequest, "Invalid operation ID");
    }
    p.operation
        .as_mut()
        .filter(|o| o.operation_id == id)
        .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidRequest, "Stale operation"))
}
fn validate_ledger(ledger: &Ledger, profile: &str, engine: AddonEngine) -> Result<()> {
    if ledger.schema != 1
        || ledger.profile_id != profile
        || ledger.engine != engine
        || ledger.managed.len() > MAX_MANAGED_ADDONS
    {
        return fail(
            AddonErrorCode::NeedsReconciliation,
            "Incompatible profile receipt",
        );
    }
    let mut ids = std::collections::HashSet::new();
    for owner in &ledger.managed {
        if owner.addon_id.is_empty()
            || owner.addon_id.len() > 255
            || !ids.insert(&owner.addon_id)
            || !valid_id(&owner.archive_sha256)
            || owner.engine != engine
            || Address::parse(owner.publisher.clone()).is_err()
            || crate::addons::parse_source(&owner.source_url).is_err()
        {
            return fail(
                AddonErrorCode::NeedsReconciliation,
                "Invalid ownership receipt",
            );
        }
    }
    if let Some(pending) = &ledger.pending {
        if !valid_id(&pending.operation_id)
            || pending.candidate.as_ref().is_some_and(|c| {
                c.operation_id != pending.operation_id
                    || !valid_id(&c.archive_sha256)
                    || c.engine != engine
                    || c.byte_length > MAX_ARCHIVE_BYTES
            })
        {
            return fail(
                AddonErrorCode::NeedsReconciliation,
                "Invalid pending receipt",
            );
        }
    }
    if let Some(completed) = &ledger.completed {
        fn text(s: &str, max: usize) -> bool {
            !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
        }
        fn addon_id(s: &str) -> bool {
            text(s, 255)
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@._-{}".contains(&b))
        }
        let candidate_valid = completed.candidate.as_ref().is_none_or(|c| {
            let lists = [
                &c.required_permissions,
                &c.optional_permissions,
                &c.host_permissions,
                &c.optional_host_permissions,
            ];
            c.operation_id == completed.operation_id
                && valid_id(&c.archive_sha256)
                && c.engine == engine
                && c.byte_length > 0
                && c.byte_length <= MAX_ARCHIVE_BYTES
                && addon_id(&c.addon_id)
                && text(&c.version, 128)
                && text(&c.name, 256)
                && text(&c.publisher, 128)
                && Address::parse(c.publisher.clone()).is_ok()
                && text(&c.source_url, 4096)
                && crate::addons::parse_source(&c.source_url).is_ok_and(|(host, inner)| {
                    host == format!("{}.epix", c.publisher) && inner == c.inner_path
                })
                && text(&c.governing_manifest, 1024)
                && epix_content::verify::is_valid_relative_path(&c.governing_manifest)
                && matches!(c.manifest_version, 2 | 3)
                && c.expires_at_ms > 0
                && lists
                    .iter()
                    .all(|list| list.len() <= 256 && list.iter().all(|p| text(p, 2048)))
                && lists
                    .iter()
                    .flat_map(|list| list.iter())
                    .map(String::len)
                    .sum::<usize>()
                    <= 65536
        });
        if ledger.pending.is_some()
            || ledger.uninstall_id.is_some()
            || !valid_id(&completed.operation_id)
            || !matches!(
                completed.phase,
                AddonPhase::Installed
                    | AddonPhase::Cancelled
                    | AddonPhase::Failed
                    | AddonPhase::Uninstalled
            )
            || !candidate_valid
            || completed.message.as_ref().is_some_and(|m| m.len() > 2048)
            || completed
                .uninstall_id
                .as_ref()
                .is_some_and(|id| !addon_id(id))
            || (completed.candidate.is_some() && completed.uninstall_id.is_some())
            || (completed.phase == AddonPhase::Installed && completed.candidate.is_none())
            || (completed.phase == AddonPhase::Uninstalled && completed.uninstall_id.is_none())
        {
            return fail(
                AddonErrorCode::NeedsReconciliation,
                "Invalid completed operation receipt",
            );
        }
    }
    Ok(())
}
fn reconcile_pending_install(
    managed: &mut Vec<AddonOwnership>,
    candidate: &AddonCandidate,
    inventory: &AddonInventory,
) -> Option<AddonPhase> {
    let actual = inventory
        .addons
        .iter()
        .find(|a| a.addon_id == candidate.addon_id);
    if actual.is_some_and(|a| {
        a.version == candidate.version
            && a.archive_sha256.as_deref() == Some(candidate.archive_sha256.as_str())
    }) {
        managed.retain(|a| a.addon_id != candidate.addon_id);
        managed.push(candidate.into());
        return Some(AddonPhase::Installed);
    }
    let old = managed.iter().find(|a| a.addon_id == candidate.addon_id);
    let unchanged = match (actual, old) {
        (None, None) => true,
        (Some(actual), Some(old)) => {
            actual.version == old.version
                && actual.archive_sha256.as_deref() == Some(old.archive_sha256.as_str())
        }
        _ => false,
    };
    unchanged.then_some(AddonPhase::Cancelled)
}
fn reconcile_pending_uninstall(
    managed: &mut Vec<AddonOwnership>,
    id: &str,
    inventory: &AddonInventory,
) -> Option<AddonPhase> {
    let Some(actual) = inventory.addons.iter().find(|a| a.addon_id == id) else {
        managed.retain(|a| a.addon_id != id);
        return Some(AddonPhase::Uninstalled);
    };
    let unchanged = managed
        .iter()
        .find(|o| o.addon_id == id)
        .is_some_and(|owner| {
            actual.version == owner.version
                && actual.archive_sha256.as_deref() == Some(owner.archive_sha256.as_str())
        });
    unchanged.then_some(AddonPhase::Cancelled)
}
fn reconcile_pending(ledger: &mut Ledger, inventory: &AddonInventory) -> Option<AddonPhase> {
    // An unfinished engine operation is not evidence for a terminal receipt.
    if inventory.has_pending_installs {
        return None;
    }
    let pending = ledger.pending.as_ref()?;
    if let Some(candidate) = &pending.candidate {
        return reconcile_pending_install(&mut ledger.managed, candidate, inventory);
    }
    let id = ledger.uninstall_id.as_deref()?;
    reconcile_pending_uninstall(&mut ledger.managed, id, inventory)
}
impl AppState {
    pub async fn addon_open_session(
        &self,
        profile_id: &str,
        engine: AddonEngine,
    ) -> Result<AddonSession> {
        if !valid_id(profile_id) {
            return fail(
                AddonErrorCode::InvalidRequest,
                "Native profile ID must be 32 random bytes encoded as lowercase hex",
            );
        }
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        if let Some(previous) = profiles.0.get_mut(profile_id) {
            previous.cancel.store(true, Ordering::Release);
            if previous
                .operation
                .as_ref()
                .is_some_and(|o| matches!(o.phase, AddonPhase::Preparing | AddonPhase::Ready))
            {
                clear_pending(
                    previous,
                    AddonPhase::Cancelled,
                    Some("Native session replaced".into()),
                )?;
            }
        }
        if profiles.0.len() >= 16 && !profiles.0.contains_key(profile_id) {
            return fail(
                AddonErrorCode::LimitExceeded,
                "Native profile session limit",
            );
        }
        let root = self.data_root_path().ok_or_else(|| {
            AddonError::new(
                AddonErrorCode::Io,
                "Addon installation requires persistent private storage",
            )
        })?;
        let directory = ProtectedDirectory::open_child(&root.join("private"), "addons")?
            .addon_profile(profile_id)?;
        let mut ledger = if let Some(raw) = directory.read("receipts.json", MAX_LEDGER_BYTES)? {
            let value = crate::addons::unique_json(&raw)?;
            serde_json::from_value::<Ledger>(value)
                .map_err(|e| AddonError::new(AddonErrorCode::NeedsReconciliation, e.to_string()))?
        } else {
            Ledger {
                schema: 1,
                profile_id: profile_id.into(),
                engine,
                managed: Vec::new(),
                pending: None,
                uninstall_id: None,
                completed: None,
            }
        };
        validate_ledger(&ledger, profile_id, engine)?;
        if let Some(pending) = &ledger.pending {
            if matches!(pending.phase, AddonPhase::Ready | AddonPhase::Preparing) {
                let mut completed = pending.clone();
                completed.phase = AddonPhase::Cancelled;
                completed.message = Some("Preparation interrupted before engine handoff".into());
                directory.remove(&stage_name(&pending.operation_id))?;
                ledger.pending = None;
                ledger.uninstall_id = None;
                ledger.completed = Some(completed);
            } else {
                ledger.pending.as_mut().unwrap().phase = AddonPhase::NeedsReconciliation;
            }
        }
        directory.discard_addon_spools_except(
            ledger
                .pending
                .as_ref()
                .map(|p| stage_name(&p.operation_id))
                .as_deref(),
        )?;
        let profile = Profile {
            session_id: random_id()?,
            operation: ledger.pending.clone().or_else(|| ledger.completed.clone()),
            ledger,
            reconciled: false,
            inventory: AddonInventory {
                addons: Vec::new(),
                has_pending_installs: false,
            },
            cancel: Arc::new(AtomicBool::new(false)),
            stamp: None,
            directory,
        };
        profile.save()?;
        let result = profile.snapshot();
        profiles.0.insert(profile_id.into(), profile);
        Ok(result)
    }
    pub async fn addon_status(&self, session_id: &str) -> Result<AddonSession> {
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        let p = profiles.session_mut(session_id)?;
        if p.operation.as_ref().is_some_and(|o| {
            o.phase == AddonPhase::Ready
                && o.candidate
                    .as_ref()
                    .is_some_and(|c| now_ms() > c.expires_at_ms)
        }) {
            p.cancel.store(true, Ordering::Release);
            clear_pending(p, AddonPhase::Cancelled, Some("Candidate expired".into()))?;
        }
        Ok(p.snapshot())
    }
    pub async fn addon_reconcile(
        &self,
        session_id: &str,
        inventory: AddonInventory,
    ) -> Result<AddonSession> {
        if inventory.addons.len() > 2048 {
            return fail(AddonErrorCode::LimitExceeded, "Engine inventory limit");
        }
        let mut seen = std::collections::HashSet::new();
        for item in &inventory.addons {
            if item.addon_id.is_empty()
                || item.addon_id.len() > 255
                || item.version.len() > 128
                || !seen.insert(&item.addon_id)
                || item.archive_sha256.as_ref().is_some_and(|h| !valid_id(h))
            {
                return fail(AddonErrorCode::InvalidRequest, "Invalid engine inventory");
            }
        }
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        let p = profiles.session_mut(session_id)?;
        if p.operation
            .as_ref()
            .is_some_and(|o| matches!(o.phase, AddonPhase::Preparing | AddonPhase::Ready))
        {
            return fail(
                AddonErrorCode::Busy,
                "Complete or cancel preparation before reconciliation",
            );
        }
        p.reconciled = false;
        let mut ledger = p.ledger.clone();
        let result_phase = reconcile_pending(&mut ledger, &inventory);
        if let Some(phase) = result_phase {
            let mut completed = ledger.pending.as_ref().unwrap().clone();
            completed.phase = phase;
            completed.message = None;
            ledger.pending = None;
            ledger.uninstall_id = None;
            ledger.completed = Some(completed.clone());
            store_ledger(p, ledger.clone())?;
            p.operation = Some(completed.clone());
            p.stamp = None;
            p.directory.remove(&stage_name(&completed.operation_id))?;
        }
        // An authoritative absence is sufficient to forget a removed addon;
        // it never authorizes adoption of a replacement with the same ID.
        if !inventory.has_pending_installs && ledger.pending.is_none() {
            ledger.managed.retain(|owner| {
                inventory
                    .addons
                    .iter()
                    .any(|a| a.addon_id == owner.addon_id)
            });
            if ledger.managed != p.ledger.managed {
                store_ledger(p, ledger.clone())?;
            }
        }
        // Unknown removals or replaced versions are not silently adopted. The
        // native host must make their provenance/recovery explicit.
        let matched = ledger.managed.iter().all(|owner| {
            inventory.addons.iter().any(|a| {
                a.addon_id == owner.addon_id
                    && a.version == owner.version
                    && a.archive_sha256.as_deref() == Some(owner.archive_sha256.as_str())
            })
        });
        p.inventory = inventory;
        p.reconciled = matched && !p.inventory.has_pending_installs && p.ledger.pending.is_none();
        Ok(p.snapshot())
    }
    pub async fn addon_prepare(&self, request: AddonPrepareRequest) -> Result<AddonCandidate> {
        crate::addons::parse_source(&request.source_url)?;
        let (operation_id, cancel, engine) = {
            let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
            if profiles
                .0
                .values()
                .filter(|p| {
                    p.operation
                        .as_ref()
                        .is_some_and(|o| o.phase == AddonPhase::Preparing)
                })
                .count()
                >= 2
            {
                return fail(AddonErrorCode::Busy, "Another package is being verified");
            }
            let p = profiles.session_mut(&request.session_id)?;
            if p.ledger.engine == AddonEngine::WebKit {
                return fail(
                    AddonErrorCode::UnsupportedSource,
                    "WebKit-compatible package format is not enabled",
                );
            }
            if !p.reconciled {
                return fail(
                    AddonErrorCode::NeedsReconciliation,
                    "Reconcile the actual browser profile before installing",
                );
            }
            if p.pending() {
                return fail(
                    AddonErrorCode::Busy,
                    "Profile already has a pending operation",
                );
            }
            if matches!(&request.action, AddonAction::Install) {
                // Refuse before fetching or asking the engine for approval.
                // Replacing an existing owner does not consume another slot.
                check_managed_count(p.ledger.managed.len().saturating_add(1))?;
            }
            let operation_id = random_id()?;
            p.cancel = Arc::new(AtomicBool::new(false));
            p.stamp = None;
            p.operation = Some(AddonSnapshot {
                uninstall_id: None,
                operation_id: operation_id.clone(),
                phase: AddonPhase::Preparing,
                candidate: None,
                message: None,
            });
            (operation_id, p.cancel.clone(), p.ledger.engine)
        };
        let prepared: Result<(AddonCandidate, AuthorityStamp, Vec<u8>)> =
            bounded_preparation(&cancel, async {
                let (canonical, inner) = self.addon_publisher(&request.source_url).await?;
                check_cancel(&cancel)?;
                let mut stamp = self.addon_snapshot(&canonical, &inner).await?;
                let bytes = self.addon_archive(&mut stamp, &cancel).await?;
                let inspection = crate::addons::inspect_package(&bytes, &cancel)?;
                let candidate = AddonCandidate {
                    operation_id: operation_id.clone(),
                    source_url: format!("https://{canonical}.epix/{inner}"),
                    publisher: canonical,
                    inner_path: inner,
                    governing_manifest: stamp.declaration.governing.clone(),
                    archive_sha256: hex::encode(Sha256::digest(&bytes)),
                    byte_length: bytes.len() as u64,
                    addon_id: inspection.id,
                    version: inspection.version,
                    name: inspection.name,
                    manifest_version: inspection.manifest_version,
                    required_permissions: inspection.required,
                    optional_permissions: inspection.optional,
                    host_permissions: inspection.hosts,
                    optional_host_permissions: inspection.optional_hosts,
                    expires_at_ms: now_ms().saturating_add(CANDIDATE_LIFETIME_MS),
                    engine,
                };
                Ok((candidate, stamp, bytes))
            })
            .await;
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        let p = profiles.session_mut(&request.session_id)?;
        ensure_operation(p, &operation_id)?;
        let finish = |p: &mut Profile| -> Result<AddonCandidate> {
            let (candidate, stamp, bytes) = prepared?;
            check_cancel(&cancel)?;
            let existing = p
                .ledger
                .managed
                .iter()
                .find(|a| a.addon_id == candidate.addon_id);
            match &request.action {
                AddonAction::Install => {
                    check_managed_count(p.ledger.managed.len().saturating_add(1))?;
                    if existing.is_some()
                        || p.inventory
                            .addons
                            .iter()
                            .any(|a| a.addon_id == candidate.addon_id)
                    {
                        return fail(
                            AddonErrorCode::InvalidRequest,
                            "Existing addon ID cannot be enrolled",
                        );
                    }
                }
                AddonAction::Update { addon_id } => {
                    let owner = existing
                        .filter(|o| &o.addon_id == addon_id)
                        .ok_or_else(|| {
                            AddonError::new(
                                AddonErrorCode::InvalidRequest,
                                "Update requires an owned addon",
                            )
                        })?;
                    if owner.publisher != candidate.publisher
                        || owner.inner_path != candidate.inner_path
                        || owner.archive_sha256 == candidate.archive_sha256
                    {
                        return fail(
                            AddonErrorCode::InvalidRequest,
                            "Update publisher/path changed or package is unchanged",
                        );
                    }
                }
            }
            let root = self
                .data_root_path()
                .ok_or_else(|| AddonError::new(AddonErrorCode::Io, "Missing addon data root"))?;
            let used = ProtectedDirectory::open_child(&root.join("private"), "addons")?
                .addon_spool_bytes()?;
            if used.saturating_add(candidate.byte_length) > 2 * MAX_ARCHIVE_BYTES {
                return fail(AddonErrorCode::LimitExceeded, "Pending addon disk quota");
            }
            p.directory.create_new(&stage_name(&operation_id), &bytes)?;
            let operation = AddonSnapshot {
                uninstall_id: None,
                operation_id: operation_id.clone(),
                phase: AddonPhase::Ready,
                candidate: Some(candidate.clone()),
                message: None,
            };
            let mut ledger = p.ledger.clone();
            ledger.pending = Some(operation.clone());
            ledger.completed = None;
            if let Err(e) = store_ledger(p, ledger) {
                let _ = p.directory.remove(&stage_name(&operation_id));
                return Err(e);
            }
            p.operation = Some(operation);
            p.stamp = Some(stamp);
            Ok(candidate)
        };
        match finish(p) {
            Ok(candidate) => Ok(candidate),
            Err(error) => {
                p.operation = Some(AddonSnapshot {
                    uninstall_id: None,
                    operation_id,
                    phase: if error.code == AddonErrorCode::Cancelled {
                        AddonPhase::Cancelled
                    } else {
                        AddonPhase::Failed
                    },
                    candidate: None,
                    message: Some(error.to_string()),
                });
                Err(error)
            }
        }
    }
    pub async fn addon_cancel(
        &self,
        session_id: &str,
        operation_id: Option<&str>,
    ) -> Result<AddonSnapshot> {
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        let p = profiles.session_mut(session_id)?;
        if let Some(id) = operation_id {
            ensure_operation(p, id)?;
        }
        p.cancel.store(true, Ordering::Release);
        let operation = p
            .operation
            .as_ref()
            .ok_or_else(|| AddonError::new(AddonErrorCode::InvalidRequest, "No addon operation"))?;
        if matches!(operation.phase, AddonPhase::Preparing | AddonPhase::Ready) {
            return clear_pending(p, AddonPhase::Cancelled, None);
        }
        if matches!(
            operation.phase,
            AddonPhase::HandedOff
                | AddonPhase::Staged
                | AddonPhase::Uninstalling
                | AddonPhase::NeedsReconciliation
        ) {
            let mut operation = operation.clone();
            operation.phase = AddonPhase::NeedsReconciliation;
            operation.message =
                Some("Confirm actual engine cancellation before starting another operation".into());
            let mut ledger = p.ledger.clone();
            ledger.pending = Some(operation.clone());
            store_ledger(p, ledger)?;
            p.operation = Some(operation.clone());
            p.reconciled = false;
            return Ok(operation);
        }
        Ok(operation.clone())
    }
    pub async fn addon_stage(
        &self,
        session_id: &str,
        operation_id: &str,
        archive_sha256: &str,
    ) -> Result<StagedAddon> {
        let (mut stamp, cancel, candidate) = {
            let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
            let p = profiles.session_mut(session_id)?;
            let operation = ensure_operation(p, operation_id)?.clone();
            if operation.phase != AddonPhase::Ready {
                return fail(
                    AddonErrorCode::InvalidRequest,
                    "Candidate is not ready for handoff",
                );
            }
            let candidate = operation.candidate.unwrap();
            if candidate.archive_sha256 != archive_sha256 {
                return fail(AddonErrorCode::InvalidRequest, "Candidate digest mismatch");
            }
            if now_ms() > candidate.expires_at_ms {
                return fail(
                    AddonErrorCode::Expired,
                    "Prepare and review the package again",
                );
            }
            (
                p.stamp
                    .clone()
                    .ok_or_else(|| changed("Preparation stamp missing"))?,
                p.cancel.clone(),
                candidate,
            )
        };
        bounded_preparation(&cancel, self.addon_verify(&mut stamp, &cancel, false)).await?;
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        let p = profiles.session_mut(session_id)?;
        if ensure_operation(p, operation_id)?.phase != AddonPhase::Ready {
            return fail(
                AddonErrorCode::Cancelled,
                "Operation changed during handoff",
            );
        }
        check_cancel(&cancel)?;
        if now_ms() > candidate.expires_at_ms {
            return fail(AddonErrorCode::Expired, "Candidate expired during handoff");
        }
        if !p
            .ledger
            .managed
            .iter()
            .any(|owner| owner.addon_id == candidate.addon_id)
        {
            check_managed_count(p.ledger.managed.len().saturating_add(1))?;
        }
        let bytes = p
            .directory
            .read(&stage_name(operation_id), MAX_ARCHIVE_BYTES)?
            .ok_or_else(|| changed("Staged package missing"))?;
        if bytes.len() as u64 != candidate.byte_length
            || hex::encode(Sha256::digest(&bytes)) != candidate.archive_sha256
        {
            return Err(changed("Private staged bytes changed"));
        }
        let path = p.directory.path(&stage_name(operation_id))?;
        let mut operation = p.operation.clone().unwrap();
        operation.phase = AddonPhase::HandedOff;
        let mut ledger = p.ledger.clone();
        ledger.pending = Some(operation.clone());
        store_ledger(p, ledger)?;
        p.operation = Some(operation);
        p.reconciled = false;
        p.stamp = None;
        Ok(StagedAddon { candidate, path })
    }
    pub async fn addon_report(
        &self,
        session_id: &str,
        operation_id: &str,
        outcome: AddonEngineOutcome,
    ) -> Result<AddonSnapshot> {
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        let p = profiles.session_mut(session_id)?;
        let mut operation = ensure_operation(p, operation_id)?.clone();
        if !matches!(
            operation.phase,
            AddonPhase::HandedOff
                | AddonPhase::Staged
                | AddonPhase::NeedsReconciliation
                | AddonPhase::Uninstalling
        ) {
            return fail(AddonErrorCode::InvalidRequest, "No matching engine handoff");
        }
        let staged = matches!(&outcome, AddonEngineOutcome::Staged { .. });
        match outcome {
            AddonEngineOutcome::Installed {
                addon_id,
                version,
                archive_sha256,
            }
            | AddonEngineOutcome::Staged {
                addon_id,
                version,
                archive_sha256,
            } => {
                let candidate = operation.candidate.as_ref().ok_or_else(|| {
                    AddonError::new(AddonErrorCode::InvalidRequest, "Install candidate missing")
                })?;
                if candidate.addon_id != addon_id
                    || candidate.version != version
                    || candidate.archive_sha256 != archive_sha256
                {
                    return fail(
                        AddonErrorCode::InvalidRequest,
                        "Engine result differs from approved package",
                    );
                }
                if staged {
                    operation.phase = AddonPhase::Staged;
                    let mut ledger = p.ledger.clone();
                    ledger.pending = Some(operation.clone());
                    store_ledger(p, ledger)?;
                    p.operation = Some(operation.clone());
                    Ok(operation)
                } else {
                    let mut ledger = p.ledger.clone();
                    ledger.managed.retain(|o| o.addon_id != addon_id);
                    ledger.managed.push(candidate.into());
                    ledger.pending = None;
                    ledger.uninstall_id = None;
                    operation.phase = AddonPhase::Installed;
                    operation.message = None;
                    ledger.completed = Some(operation.clone());
                    store_ledger(p, ledger)?;
                    p.operation = Some(operation.clone());
                    p.directory.remove(&stage_name(operation_id))?;
                    p.inventory.addons.retain(|o| o.addon_id != addon_id);
                    p.inventory.addons.push(AddonInstalled {
                        addon_id,
                        version,
                        archive_sha256: Some(archive_sha256),
                        enabled: true,
                    });
                    p.reconciled = true;
                    Ok(operation)
                }
            }
            AddonEngineOutcome::Uninstalled { addon_id } => {
                if p.ledger.uninstall_id.as_deref() != Some(addon_id.as_str()) {
                    return fail(AddonErrorCode::InvalidRequest, "Uninstall result mismatch");
                }
                let mut ledger = p.ledger.clone();
                ledger.managed.retain(|o| o.addon_id != addon_id);
                ledger.pending = None;
                ledger.uninstall_id = None;
                operation.phase = AddonPhase::Uninstalled;
                operation.message = None;
                ledger.completed = Some(operation.clone());
                store_ledger(p, ledger)?;
                p.operation = Some(operation.clone());
                p.inventory.addons.retain(|o| o.addon_id != addon_id);
                p.reconciled = true;
                Ok(operation)
            }
            other => {
                let reason = match other {
                    AddonEngineOutcome::Cancelled => {
                        "Engine cancellation requires reconciliation".into()
                    }
                    AddonEngineOutcome::Failed { reason }
                    | AddonEngineOutcome::Unknown { reason } => reason,
                    _ => unreachable!(),
                };
                operation.phase = AddonPhase::NeedsReconciliation;
                operation.message = Some(reason.chars().take(512).collect());
                let mut ledger = p.ledger.clone();
                ledger.pending = Some(operation.clone());
                store_ledger(p, ledger)?;
                p.operation = Some(operation.clone());
                p.reconciled = false;
                Ok(operation)
            }
        }
    }
    pub async fn addon_begin_uninstall(
        &self,
        session_id: &str,
        addon_id: &str,
    ) -> Result<AddonSnapshot> {
        let mut profiles = self.addon_profiles.lock().expect("addon_profiles");
        let p = profiles.session_mut(session_id)?;
        if !p.reconciled {
            return fail(
                AddonErrorCode::NeedsReconciliation,
                "Reconcile before uninstalling",
            );
        }
        if p.pending() {
            return fail(AddonErrorCode::Busy, "An addon operation is pending");
        }
        if !p.ledger.managed.iter().any(|o| o.addon_id == addon_id) {
            return fail(
                AddonErrorCode::InvalidRequest,
                "Addon is not managed by this profile",
            );
        }
        let operation = AddonSnapshot {
            uninstall_id: Some(addon_id.into()),
            operation_id: random_id()?,
            phase: AddonPhase::Uninstalling,
            candidate: None,
            message: None,
        };
        let mut ledger = p.ledger.clone();
        ledger.pending = Some(operation.clone());
        ledger.uninstall_id = Some(addon_id.into());
        ledger.completed = None;
        store_ledger(p, ledger)?;
        p.operation = Some(operation.clone());
        p.reconciled = false;
        Ok(operation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{
        EdxBatch, EdxBatchProgress, EdxFetcher, EdxPushError, EdxPushProgress, EdxSignedProgress,
        EdxWant, OnDemandResolver, ResolvedHost, UpdatePayload, XiteEntry,
    };
    use epix_core::PeerAddr;
    use epix_xite::XiteStorage;
    use serde_json::json;
    use std::io::{Cursor, Write};
    struct Fixture {
        root: tempfile::TempDir,
        state: Arc<AppState>,
        storage: XiteStorage,
        address: String,
        key: String,
        child_key: String,
        delegated: bool,
    }
    fn package(version: &str) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file(
            "manifest.json",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(&serde_json::to_vec(&json!({"manifest_version":2,"name":"Local public fixture","version":version,"browser_specific_settings":{"gecko":{"id":"addon@example.test"}},"permissions":["storage"]})).unwrap()).unwrap();
        zip.finish().unwrap().into_inner()
    }
    impl Fixture {
        async fn new(delegated: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            let root_path = root.path().canonicalize().unwrap();
            let state = AppState::with_data_dir("addon-test", &root_path);
            let key = epix_crypt::new_private_key();
            let child_key = epix_crypt::new_private_key();
            let address = epix_crypt::privatekey_to_address(&key).unwrap();
            let storage = XiteStorage::new(root_path.join("data").join(&address));
            let fixture = Self {
                root,
                state,
                storage,
                address,
                key,
                child_key,
                delegated,
            };
            fixture.publish("1.0").await;
            fixture
        }
        async fn publish(&self, version: &str) {
            let bytes = package(version);
            self.storage.write("addons/extension.xpi", &bytes).unwrap();
            let entry = json!({"size":bytes.len(),"b3":blake3::hash(&bytes).to_hex().to_string(),"sha512":XiteStorage::hash_bytes(&bytes)});
            let mut root =
                json!({"address":self.address,"inner_path":"content.json","modified":1,"files":{}});
            if self.delegated {
                root["includes"] = json!({"addons/content.json":{"signers":[epix_crypt::privatekey_to_address(&self.child_key).unwrap()],"signers_required":1,"max_size":8388608,"files_allowed":"extension\\.xpi","includes_allowed":false}});
                let mut child = json!({"address":self.address,"inner_path":"addons/content.json","modified":1,"files":{"extension.xpi":entry}});
                epix_content::sign(&mut child, &self.child_key).unwrap();
                self.storage
                    .write(
                        "addons/content.json",
                        epix_content::dumps_content(&child).as_bytes(),
                    )
                    .unwrap();
            } else {
                root["files"]["addons/extension.xpi"] = entry;
            }
            epix_content::sign(&mut root, &self.key).unwrap();
            self.storage
                .write(
                    "content.json",
                    epix_content::dumps_content(&root).as_bytes(),
                )
                .unwrap();
            self.state
                .add_xite(
                    &self.address,
                    XiteEntry {
                        storage: self.storage.clone(),
                        content: Some(root),
                    },
                )
                .await;
        }
        async fn session(&self, profile: &str) -> AddonSession {
            let s = self
                .state
                .addon_open_session(profile, AddonEngine::Gecko)
                .await
                .unwrap();
            self.state
                .addon_reconcile(
                    &s.session_id,
                    AddonInventory {
                        addons: vec![],
                        has_pending_installs: false,
                    },
                )
                .await
                .unwrap()
        }
        fn request(&self, session: &str, action: AddonAction) -> AddonPrepareRequest {
            AddonPrepareRequest {
                session_id: session.into(),
                source_url: format!("https://{}.epix/addons/extension.xpi", self.address),
                action,
            }
        }
    }
    fn inventory(c: &AddonCandidate, pending: bool) -> AddonInventory {
        AddonInventory {
            addons: vec![AddonInstalled {
                addon_id: c.addon_id.clone(),
                version: c.version.clone(),
                archive_sha256: Some(c.archive_sha256.clone()),
                enabled: true,
            }],
            has_pending_installs: pending,
        }
    }
    fn installed(c: &AddonCandidate) -> AddonEngineOutcome {
        AddonEngineOutcome::Installed {
            addon_id: c.addon_id.clone(),
            version: c.version.clone(),
            archive_sha256: c.archive_sha256.clone(),
        }
    }
    fn reloaded(f: &Fixture) -> Arc<AppState> {
        AppState::with_data_dir("addon-reloaded", f.root.path().canonicalize().unwrap())
    }
    // Seed valid prior receipts instead of manufacturing hundreds of signed
    // packages. The extension being installed/updated still uses the complete
    // signed fixture, preparation, handoff and engine-result path.
    fn seed_managed(f: &Fixture, session: &str, count: usize) -> Vec<AddonInstalled> {
        let mut profiles = f.state.addon_profiles.lock().unwrap();
        let profile = profiles.session_mut(session).unwrap();
        let mut ledger = profile.ledger.clone();
        ledger.managed = (0..count)
            .map(|index| AddonOwnership {
                addon_id: format!("previous-{index}@example.test"),
                version: "1.0".into(),
                archive_sha256: "a".repeat(64),
                publisher: f.address.clone(),
                inner_path: format!("addons/previous-{index}.xpi"),
                source_url: format!("https://{}.epix/addons/previous-{index}.xpi", f.address),
                engine: AddonEngine::Gecko,
            })
            .collect();
        let inventory: Vec<_> = ledger
            .managed
            .iter()
            .map(|owner| AddonInstalled {
                addon_id: owner.addon_id.clone(),
                version: owner.version.clone(),
                archive_sha256: Some(owner.archive_sha256.clone()),
                enabled: true,
            })
            .collect();
        store_ledger(profile, ledger).unwrap();
        profile.inventory.addons = inventory.clone();
        inventory
    }
    #[tokio::test]
    async fn addon_managed_limit_allows_last_slot_and_update_but_rejects_new_enrollment() {
        let f = Fixture::new(false).await;
        let s = f.session(&"a".repeat(64)).await;
        seed_managed(&f, &s.session_id, MAX_MANAGED_ADDONS - 1);
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        f.state
            .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
            .await
            .unwrap();
        f.state
            .addon_report(&s.session_id, &c.operation_id, installed(&c))
            .await
            .unwrap();
        assert_eq!(
            f.state
                .addon_status(&s.session_id)
                .await
                .unwrap()
                .managed
                .len(),
            MAX_MANAGED_ADDONS
        );
        let receipts = f
            .root
            .path()
            .join("private/addons")
            .join(&s.profile_id)
            .join("receipts.json");
        let before = std::fs::read(&receipts).unwrap();
        let mut another = f.request(&s.session_id, AddonAction::Install);
        // No declared file exists here. The capacity refusal must precede
        // source verification or any native handoff, leaving receipts intact.
        another.source_url = format!("https://{}.epix/addons/another.xpi", f.address);
        assert_eq!(
            f.state.addon_prepare(another).await.unwrap_err().code,
            AddonErrorCode::LimitExceeded
        );
        assert_eq!(std::fs::read(&receipts).unwrap(), before);
        f.publish("2.0").await;
        let updated = f
            .state
            .addon_prepare(f.request(
                &s.session_id,
                AddonAction::Update {
                    addon_id: c.addon_id.clone(),
                },
            ))
            .await
            .unwrap();
        f.state
            .addon_stage(
                &s.session_id,
                &updated.operation_id,
                &updated.archive_sha256,
            )
            .await
            .unwrap();
        f.state
            .addon_report(&s.session_id, &updated.operation_id, installed(&updated))
            .await
            .unwrap();
        let reopened = reloaded(&f)
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert_eq!(reopened.managed.len(), MAX_MANAGED_ADDONS);
        assert_eq!(
            reopened
                .managed
                .iter()
                .find(|owner| owner.addon_id == c.addon_id)
                .unwrap()
                .version,
            "2.0"
        );
    }
    #[tokio::test]
    async fn addon_managed_limit_is_rechecked_before_engine_handoff() {
        let f = Fixture::new(false).await;
        let s = f.session(&"b".repeat(64)).await;
        seed_managed(&f, &s.session_id, MAX_MANAGED_ADDONS - 1);
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        // Simulate an unexpected capacity change after review. The final
        // native handoff must still refuse, without changing the Ready receipt.
        seed_managed(&f, &s.session_id, MAX_MANAGED_ADDONS);
        let receipts = f
            .root
            .path()
            .join("private/addons")
            .join(&s.profile_id)
            .join("receipts.json");
        let before = std::fs::read(&receipts).unwrap();
        assert_eq!(
            f.state
                .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::LimitExceeded
        );
        assert_eq!(std::fs::read(&receipts).unwrap(), before);
        assert_eq!(
            f.state
                .addon_status(&s.session_id)
                .await
                .unwrap()
                .operation
                .unwrap()
                .phase,
            AddonPhase::Ready
        );
    }
    #[tokio::test]
    async fn addon_managed_limit_guards_report_and_reconciliation_receipt_commits() {
        let f = Fixture::new(false).await;
        let s = f.session(&"c".repeat(64)).await;
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        f.state
            .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
            .await
            .unwrap();
        // Defense in depth for a capacity change after handoff: neither a
        // direct engine report nor reconciliation may persist a 257th owner.
        let mut actual = seed_managed(&f, &s.session_id, MAX_MANAGED_ADDONS);
        let receipts = f
            .root
            .path()
            .join("private/addons")
            .join(&s.profile_id)
            .join("receipts.json");
        let before = std::fs::read(&receipts).unwrap();
        assert_eq!(
            f.state
                .addon_report(&s.session_id, &c.operation_id, installed(&c))
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::LimitExceeded
        );
        assert_eq!(std::fs::read(&receipts).unwrap(), before);
        actual.extend(inventory(&c, false).addons);
        assert_eq!(
            f.state
                .addon_reconcile(
                    &s.session_id,
                    AddonInventory {
                        addons: actual,
                        has_pending_installs: false
                    }
                )
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::LimitExceeded
        );
        assert_eq!(std::fs::read(&receipts).unwrap(), before);
        let reopened = reloaded(&f)
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert_eq!(reopened.managed.len(), MAX_MANAGED_ADDONS);
        assert_eq!(reopened.operation.unwrap().operation_id, c.operation_id);
    }
    #[tokio::test]
    async fn addon_terminal_cancelled_receipts_survive_reload_without_authorizing_bytes() {
        for update in [false, true] {
            let f = Fixture::new(false).await;
            let s = f.session(&"d".repeat(64)).await;
            let first = f
                .state
                .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                .await
                .unwrap();
            f.state
                .addon_stage(&s.session_id, &first.operation_id, &first.archive_sha256)
                .await
                .unwrap();
            let (candidate, unchanged) = if update {
                f.state
                    .addon_report(&s.session_id, &first.operation_id, installed(&first))
                    .await
                    .unwrap();
                f.publish("2.0").await;
                let next = f
                    .state
                    .addon_prepare(f.request(
                        &s.session_id,
                        AddonAction::Update {
                            addon_id: first.addon_id.clone(),
                        },
                    ))
                    .await
                    .unwrap();
                f.state
                    .addon_stage(&s.session_id, &next.operation_id, &next.archive_sha256)
                    .await
                    .unwrap();
                (next, inventory(&first, false))
            } else {
                (
                    first,
                    AddonInventory {
                        addons: vec![],
                        has_pending_installs: false,
                    },
                )
            };
            f.state
                .addon_cancel(&s.session_id, Some(&candidate.operation_id))
                .await
                .unwrap();
            let settled = f
                .state
                .addon_reconcile(&s.session_id, unchanged.clone())
                .await
                .unwrap();
            assert_eq!(
                settled.operation.as_ref().unwrap().phase,
                AddonPhase::Cancelled
            );
            // Recreate AppState so this result comes only from the synced ledger,
            // as when the browser mirror write or response was interrupted.
            let restarted = reloaded(&f);
            let opened = restarted
                .addon_open_session(&s.profile_id, AddonEngine::Gecko)
                .await
                .unwrap();
            let completed = opened.operation.as_ref().unwrap();
            assert_eq!(completed.phase, AddonPhase::Cancelled);
            assert_eq!(completed.operation_id, candidate.operation_id);
            assert_eq!(completed.candidate.as_ref(), Some(&candidate));
            assert!(completed.uninstall_id.is_none());
            assert_eq!(opened.managed, settled.managed);
            assert!(
                restarted
                    .addon_stage(
                        &opened.session_id,
                        &candidate.operation_id,
                        &candidate.archive_sha256
                    )
                    .await
                    .is_err()
            );
            assert!(
                restarted
                    .addon_report(
                        &opened.session_id,
                        &candidate.operation_id,
                        installed(&candidate)
                    )
                    .await
                    .is_err()
            );
            assert!(
                !restarted
                    .addon_reconcile(&opened.session_id, unchanged)
                    .await
                    .unwrap()
                    .needs_reconciliation
            );
        }
    }
    #[tokio::test]
    async fn addon_terminal_install_and_uninstall_results_survive_reload() {
        let f = Fixture::new(false).await;
        let s = f.session(&"e".repeat(64)).await;
        let candidate = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        f.state
            .addon_stage(
                &s.session_id,
                &candidate.operation_id,
                &candidate.archive_sha256,
            )
            .await
            .unwrap();
        f.state
            .addon_report(
                &s.session_id,
                &candidate.operation_id,
                installed(&candidate),
            )
            .await
            .unwrap();
        let restart = reloaded(&f);
        let opened = restart
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert_eq!(
            opened.operation.as_ref().unwrap().phase,
            AddonPhase::Installed
        );
        assert_eq!(
            opened.operation.as_ref().unwrap().candidate.as_ref(),
            Some(&candidate)
        );
        restart
            .addon_reconcile(&opened.session_id, inventory(&candidate, false))
            .await
            .unwrap();
        let uninstall = restart
            .addon_begin_uninstall(&opened.session_id, &candidate.addon_id)
            .await
            .unwrap();
        // Neither a still-pending engine install nor unproven replacement bytes
        // can turn an uncertain removal into a completed cancellation.
        assert!(
            restart
                .addon_reconcile(&opened.session_id, inventory(&candidate, true))
                .await
                .unwrap()
                .needs_reconciliation
        );
        let mut unknown = inventory(&candidate, false);
        unknown.addons[0].archive_sha256 = None;
        assert!(
            restart
                .addon_reconcile(&opened.session_id, unknown)
                .await
                .unwrap()
                .needs_reconciliation
        );
        let kept = restart
            .addon_reconcile(&opened.session_id, inventory(&candidate, false))
            .await
            .unwrap();
        assert_eq!(
            kept.operation.as_ref().unwrap().phase,
            AddonPhase::Cancelled
        );
        let retry = reloaded(&f);
        let opened = retry
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert_eq!(
            opened.operation.as_ref().unwrap().operation_id,
            uninstall.operation_id
        );
        assert_eq!(
            opened.operation.as_ref().unwrap().uninstall_id.as_deref(),
            Some(candidate.addon_id.as_str())
        );
        assert!(opened.operation.as_ref().unwrap().candidate.is_none());
        retry
            .addon_reconcile(&opened.session_id, inventory(&candidate, false))
            .await
            .unwrap();
        let uninstall = retry
            .addon_begin_uninstall(&opened.session_id, &candidate.addon_id)
            .await
            .unwrap();
        retry
            .addon_report(
                &opened.session_id,
                &uninstall.operation_id,
                AddonEngineOutcome::Uninstalled {
                    addon_id: candidate.addon_id.clone(),
                },
            )
            .await
            .unwrap();
        let final_state = reloaded(&f)
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert!(final_state.managed.is_empty());
        let completed = final_state.operation.unwrap();
        assert_eq!(completed.phase, AddonPhase::Uninstalled);
        assert_eq!(completed.operation_id, uninstall.operation_id);
        assert_eq!(completed.uninstall_id, Some(candidate.addon_id));
    }
    #[tokio::test]
    async fn addon_completed_receipt_bounds_legacy_and_interrupted_ready() {
        let f = Fixture::new(false).await;
        let s = f.session(&"f".repeat(64)).await;
        let candidate = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        let opened = reloaded(&f)
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert_eq!(
            opened.operation.as_ref().unwrap().phase,
            AddonPhase::Cancelled
        );
        assert_eq!(
            opened.operation.as_ref().unwrap().candidate.as_ref(),
            Some(&candidate)
        );
        let path = f
            .root
            .path()
            .join("private/addons")
            .join(&s.profile_id)
            .join("receipts.json");
        let ledger: Ledger = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(ledger.pending.is_none());
        for variant in 0..7 {
            let mut bad = ledger.clone();
            let completed = bad.completed.as_mut().unwrap();
            match variant {
                0 => completed.phase = AddonPhase::HandedOff,
                1 => completed.candidate.as_mut().unwrap().operation_id = "0".repeat(64),
                2 => completed.candidate.as_mut().unwrap().version = "x".repeat(129),
                3 => completed.message = Some("x".repeat(2049)),
                4 => completed.uninstall_id = Some(candidate.addon_id.clone()),
                5 => bad.pending = Some(completed.clone()),
                _ => {
                    completed.candidate.as_mut().unwrap().required_permissions =
                        vec!["storage".into(); 257]
                }
            }
            assert_eq!(
                validate_ledger(&bad, &s.profile_id, AddonEngine::Gecko)
                    .unwrap_err()
                    .code,
                AddonErrorCode::NeedsReconciliation
            );
        }
        // Pre-change schema1 ledgers remain readable with no completion field.
        let mut legacy = serde_json::to_value(&ledger).unwrap();
        legacy.as_object_mut().unwrap().remove("completed");
        std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let opened = reloaded(&f)
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert!(opened.operation.is_none());
        assert!(opened.managed.is_empty());
    }

    #[tokio::test]
    async fn addon_optional_and_local_bundled_packages_preserve_exact_signed_bytes() {
        for kind in ["optional", "bundle", "ambiguous"] {
            for local in [true, false] {
                let f = Fixture::new(false).await;
                let bytes = package("1.0");
                let mut root: Value =
                    serde_json::from_slice(&f.storage.read("content.json").unwrap()).unwrap();
                let entry = root["files"]["addons/extension.xpi"].clone();
                match kind {
                    "optional" | "ambiguous" => {
                        root["files_optional"] = json!({"addons/extension.xpi":entry});
                        if kind == "optional" {
                            root["files"]
                                .as_object_mut()
                                .unwrap()
                                .remove("addons/extension.xpi");
                        }
                    }
                    "bundle" => {
                        let mut bundle = b"prefix".to_vec();
                        bundle.extend_from_slice(&bytes);
                        let id = blake3::hash(&bundle).to_hex().to_string();
                        root["files"]["addons/extension.xpi"]["bundle"] = json!(id);
                        root["files"]["addons/extension.xpi"]["off"] = json!(6);
                        root["bundles"] = json!({id:{"size":bundle.len(),"seq":0}});
                    }
                    _ => unreachable!(),
                }
                epix_content::sign(&mut root, &f.key).unwrap();
                f.storage
                    .write(
                        "content.json",
                        epix_content::dumps_content(&root).as_bytes(),
                    )
                    .unwrap();
                if !local {
                    std::fs::remove_file(f.storage.root().join("addons/extension.xpi")).unwrap();
                }
                f.state
                    .add_xite(
                        &f.address,
                        XiteEntry {
                            storage: f.storage.clone(),
                            content: Some(root),
                        },
                    )
                    .await;
                let mock = AddonFetchFixture::new(bytes.clone(), false);
                f.state.set_edx_fetcher(mock.clone()).await;
                let s = f.session(&"a".repeat(64)).await;
                let result = f
                    .state
                    .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                    .await;
                if kind == "ambiguous" {
                    assert_eq!(
                        result.unwrap_err().code,
                        AddonErrorCode::UnverifiedAuthority
                    );
                } else if kind == "bundle" && !local {
                    assert_eq!(result.unwrap_err().code, AddonErrorCode::UnsupportedSource);
                } else {
                    let c = result.unwrap();
                    let stage = f
                        .state
                        .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                        .await
                        .unwrap();
                    assert_eq!(std::fs::read(stage.path).unwrap(), bytes);
                }
                assert_eq!(
                    mock.seen.lock().unwrap().len(),
                    usize::from(kind == "optional" && !local)
                );
            }
        }
    }
    #[tokio::test]
    async fn addon_name_resolution_never_clones_or_accepts_stale_mapping() {
        struct NameOnly {
            address: String,
            verified: bool,
        }
        #[async_trait::async_trait]
        impl OnDemandResolver for NameOnly {
            async fn ensure(&self, _: &str) -> Result<(), String> {
                panic!("No addon clone")
            }
            async fn resolve(&self, _: &str) -> Option<ResolvedHost> {
                panic!("No stale resolver fallback")
            }
            async fn resolve_verified_name(&self, host: &str) -> Option<ResolvedHost> {
                assert_eq!(host, "addons.epix");
                Some(ResolvedHost {
                    address: self.address.clone(),
                    verified: self.verified,
                })
            }
        }
        for verified in [true, false] {
            let f = Fixture::new(false).await;
            f.state
                .set_on_demand(Arc::new(NameOnly {
                    address: f.address.clone(),
                    verified,
                }))
                .await;
            let s = f.session(&"a".repeat(64)).await;
            let mut request = f.request(&s.session_id, AddonAction::Install);
            request.source_url = "https://addons.epix/addons/extension.xpi".into();
            let result = f.state.addon_prepare(request).await;
            if verified {
                assert_eq!(result.unwrap().publisher, f.address);
            } else {
                assert_eq!(
                    result.unwrap_err().code,
                    AddonErrorCode::UnverifiedAuthority
                );
            }
            let mut invalid_address = f.address.clone();
            let last = invalid_address.pop().unwrap();
            invalid_address.push(if last == 'q' { 'p' } else { 'q' });
            assert_eq!(
                f.state
                    .addon_publisher(&format!("https://{invalid_address}.epix/test.xpi"))
                    .await
                    .unwrap_err()
                    .code,
                AddonErrorCode::UnverifiedAuthority
            );
        }
    }
    struct AddonFetchFixture {
        bytes: Vec<u8>,
        seen: std::sync::Mutex<Vec<(String, EdxObjectRef)>>,
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
        dropped: Arc<AtomicBool>,
        wait: bool,
    }
    impl AddonFetchFixture {
        fn new(bytes: Vec<u8>, wait: bool) -> Arc<Self> {
            Arc::new(Self {
                bytes,
                seen: Default::default(),
                started: Default::default(),
                release: Default::default(),
                dropped: Arc::new(AtomicBool::new(false)),
                wait,
            })
        }
    }
    #[async_trait::async_trait]
    impl EdxFetcher for AddonFetchFixture {
        async fn fetch_addon_object(
            &self,
            address: &str,
            object: EdxObjectRef,
        ) -> Result<Vec<u8>, String> {
            struct DropFlag(Arc<AtomicBool>);
            impl Drop for DropFlag {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _guard = DropFlag(self.dropped.clone());
            self.seen.lock().unwrap().push((address.into(), object));
            self.started.notify_one();
            if self.wait {
                self.release.notified().await;
            }
            Ok(self.bytes.clone())
        }
        async fn fetch_file(&self, _: &str, _: &str) -> Result<bool, String> {
            unreachable!()
        }
        async fn fetch_signed(
            &self,
            _: PeerAddr,
            _: &str,
            _: &str,
        ) -> Result<Option<Vec<u8>>, String> {
            unreachable!()
        }
        async fn fetch_signed_many(
            &self,
            _: &str,
            _: Vec<String>,
            _: Vec<PeerAddr>,
            _: Option<EdxSignedProgress>,
        ) -> HashMap<String, Vec<u8>> {
            unreachable!()
        }
        async fn fetch_range(
            &self,
            _: &str,
            _: &str,
            _: u64,
            _: u64,
        ) -> Result<Option<Vec<u8>>, String> {
            unreachable!()
        }
        async fn push_update(
            &self,
            _peer: PeerAddr,
            _address: &str,
            _inner_path: &str,
            _signed: Arc<Vec<u8>>,
            _modified: f64,
            _payload: Arc<UpdatePayload>,
            _sender_peers: Arc<Vec<String>>,
            _progress: Arc<EdxPushProgress>,
        ) -> Result<bool, EdxPushError> {
            unreachable!()
        }
        async fn fetch_files(
            &self,
            _: &str,
            _: Vec<EdxWant>,
            _: Vec<PeerAddr>,
            _: Option<Value>,
            _: Option<EdxBatchProgress>,
        ) -> EdxBatch {
            unreachable!()
        }
        async fn list_signed(
            &self,
            _: PeerAddr,
            _: &str,
            _: u64,
        ) -> Result<Option<Vec<(String, u64, u64)>>, String> {
            unreachable!()
        }
        async fn pex(
            &self,
            _: PeerAddr,
            _: &str,
            _: u32,
            _: Vec<PeerAddr>,
        ) -> Result<Vec<PeerAddr>, String> {
            unreachable!()
        }
        async fn get_trackers(&self, _: PeerAddr) -> Result<Vec<String>, String> {
            unreachable!()
        }
        async fn kad(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
            unreachable!()
        }
        async fn announce(&self, _: PeerAddr, _: Vec<u8>) -> Result<Vec<u8>, String> {
            unreachable!()
        }
        async fn updates_since(
            &self,
            _: PeerAddr,
            _: u64,
        ) -> Result<(Vec<(String, i64)>, u64), String> {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn addon_download_freezes_object_and_stages_without_site_write() {
        for valid in [true, false] {
            let f = Fixture::new(true).await;
            let bytes = package("1.0");
            std::fs::remove_file(f.storage.root().join("addons/extension.xpi")).unwrap();
            let mock =
                AddonFetchFixture::new(if valid { bytes.clone() } else { package("9.9") }, false);
            f.state.set_edx_fetcher(mock.clone()).await;
            let s = f.session(&"a".repeat(64)).await;
            let result = f
                .state
                .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                .await;
            assert_eq!(
                *mock.seen.lock().unwrap(),
                vec![(
                    f.address.clone(),
                    EdxObjectRef {
                        id: epix_blob::ObjId::of(&bytes),
                        size: bytes.len() as u64
                    }
                )]
            );
            assert!(!f.storage.root().join("addons/extension.xpi").exists());
            if valid {
                let c = result.unwrap();
                let stage = f
                    .state
                    .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                    .await
                    .unwrap();
                assert_eq!(std::fs::read(stage.path).unwrap(), bytes);
            } else {
                assert_eq!(
                    result.unwrap_err().code,
                    AddonErrorCode::UnverifiedAuthority
                );
            }
        }
    }
    #[tokio::test]
    async fn addon_download_rechecks_authority_after_await() {
        let f = Fixture::new(false).await;
        std::fs::remove_file(f.storage.root().join("addons/extension.xpi")).unwrap();
        let mock = AddonFetchFixture::new(package("1.0"), true);
        f.state.set_edx_fetcher(mock.clone()).await;
        let s = f.session(&"a".repeat(64)).await;
        let state = f.state.clone();
        let request = f.request(&s.session_id, AddonAction::Install);
        let task = tokio::spawn(async move { state.addon_prepare(request).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), mock.started.notified())
            .await
            .unwrap();
        f.publish("1.1").await;
        mock.release.notify_one();
        assert_eq!(
            task.await.unwrap().unwrap_err().code,
            AddonErrorCode::ChangedAuthority
        );
        assert_eq!(
            f.storage.read("addons/extension.xpi").unwrap(),
            package("1.1")
        );
    }
    #[tokio::test]
    async fn addon_download_cancellation_and_deadline_drop_owned_future() {
        for cancel in [true, false] {
            let f = Fixture::new(false).await;
            std::fs::remove_file(f.storage.root().join("addons/extension.xpi")).unwrap();
            let mock = AddonFetchFixture::new(package("1.0"), true);
            f.state.set_edx_fetcher(mock.clone()).await;
            let s = f.session(&"a".repeat(64)).await;
            let state = f.state.clone();
            let request = f.request(&s.session_id, AddonAction::Install);
            let task = tokio::spawn(async move { state.addon_prepare(request).await });
            tokio::time::timeout(std::time::Duration::from_secs(2), mock.started.notified())
                .await
                .unwrap();
            if cancel {
                f.state.addon_cancel(&s.session_id, None).await.unwrap();
            } else {
                tokio::time::pause();
                tokio::time::advance(std::time::Duration::from_secs(61)).await;
            }
            let result = tokio::time::timeout(std::time::Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap();
            if !cancel {
                tokio::time::resume();
            }
            assert_eq!(
                result.unwrap_err().code,
                if cancel {
                    AddonErrorCode::Cancelled
                } else {
                    AddonErrorCode::MissingLocalFile
                }
            );
            assert!(mock.dropped.load(Ordering::Acquire));
            assert!(
                f.state
                    .addon_status(&s.session_id)
                    .await
                    .unwrap()
                    .operation
                    .unwrap()
                    .candidate
                    .is_none()
            );
        }
    }
    #[tokio::test]
    async fn addon_quota_counts_unopened_profile_spools_and_cleans_only_owned_temps() {
        let f = Fixture::new(false).await;
        let root =
            ProtectedDirectory::open_child(&f.root.path().join("private"), "addons").unwrap();
        let old = root.addon_profile(&"b".repeat(64)).unwrap();
        // Sparse files keep this boundary test small on disk.
        for id in ["c", "d"] {
            old.create_new(&stage_name(&id.repeat(64)), b"").unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .open(old.path(&stage_name(&id.repeat(64))).unwrap())
                .unwrap()
                .set_len(MAX_ARCHIVE_BYTES)
                .unwrap();
        }
        let s = f.session(&"a".repeat(64)).await;
        assert_eq!(
            f.state
                .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::LimitExceeded
        );
        let current = root.addon_profile(&s.profile_id).unwrap();
        let temporary = format!(".epix-write-{}", "e".repeat(32));
        current
            .create_new(&temporary, b"interrupted receipt")
            .unwrap();
        current
            .create_new(".epix-write-user-notes", b"sentinel")
            .unwrap();
        f.state
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert!(current.read(&temporary, 1024).unwrap().is_none());
        assert_eq!(
            current
                .read(".epix-write-user-notes", 1024)
                .unwrap()
                .unwrap(),
            b"sentinel"
        );
        assert_eq!(root.addon_spool_bytes().unwrap(), 2 * MAX_ARCHIVE_BYTES);
    }
    #[tokio::test]
    async fn addon_real_root_and_delegation_stage_exact_bytes() {
        for delegated in [false, true] {
            let f = Fixture::new(delegated).await;
            let s = f.session(&"a".repeat(64)).await;
            let c = f
                .state
                .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                .await
                .unwrap();
            let stage = f
                .state
                .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                .await
                .unwrap();
            assert_eq!(std::fs::read(stage.path).unwrap(), package("1.0"));
            assert_eq!(
                c.governing_manifest,
                if delegated {
                    "addons/content.json"
                } else {
                    "content.json"
                }
            );
            let done = f
                .state
                .addon_report(&s.session_id, &c.operation_id, installed(&c))
                .await
                .unwrap();
            assert_eq!(done.phase, AddonPhase::Installed);
            assert_eq!(
                f.state
                    .addon_status(&s.session_id)
                    .await
                    .unwrap()
                    .managed
                    .len(),
                1
            );
        }
    }
    #[tokio::test]
    async fn addon_live_manifest_and_bytes_are_reverified() {
        for delegated in [false, true] {
            let f = Fixture::new(delegated).await;
            let s = f.session(&"b".repeat(64)).await;
            let path = if delegated {
                "addons/content.json"
            } else {
                "content.json"
            };
            let raw = f.storage.read(path).unwrap();
            let mut value: Value = serde_json::from_slice(&raw).unwrap();
            value["title"] = "unsigned edit".into();
            f.storage
                .write(path, &serde_json::to_vec(&value).unwrap())
                .unwrap();
            assert!(
                f.state
                    .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                    .await
                    .is_err()
            );
            f.storage.write(path, &raw).unwrap();
            f.storage
                .write("addons/extension.xpi", b"changed bytes")
                .unwrap();
            assert!(
                f.state
                    .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                    .await
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn addon_changed_raw_authority_and_staged_file_reject_handoff() {
        let f = Fixture::new(false).await;
        let s = f.session(&"c".repeat(64)).await;
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        let raw = f.storage.read("content.json").unwrap();
        f.storage
            .write("content.json", &[raw.as_slice(), b"\n"].concat())
            .unwrap();
        assert_eq!(
            f.state
                .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::ChangedAuthority
        );
        f.storage.write("content.json", &raw).unwrap();
        let path = f
            .root
            .path()
            .join("private/addons")
            .join(&s.profile_id)
            .join(stage_name(&c.operation_id));
        std::fs::write(path, b"changed").unwrap();
        assert_eq!(
            f.state
                .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::ChangedAuthority
        );
    }
    #[tokio::test]
    async fn addon_requires_clean_inventory_and_preserves_pending_receipt() {
        let f = Fixture::new(false).await;
        let s = f
            .state
            .addon_open_session(&"d".repeat(64), AddonEngine::Gecko)
            .await
            .unwrap();
        assert_eq!(
            f.state
                .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::NeedsReconciliation
        );
        f.state
            .addon_reconcile(
                &s.session_id,
                AddonInventory {
                    addons: vec![],
                    has_pending_installs: false,
                },
            )
            .await
            .unwrap();
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        f.state
            .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
            .await
            .unwrap();
        let reopened = f
            .state
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        assert!(reopened.needs_reconciliation);
        assert!(
            f.state
                .addon_report(&s.session_id, &c.operation_id, installed(&c))
                .await
                .is_err()
        );
        let pending = f
            .state
            .addon_reconcile(
                &reopened.session_id,
                AddonInventory {
                    addons: vec![],
                    has_pending_installs: true,
                },
            )
            .await
            .unwrap();
        assert!(pending.needs_reconciliation);
        let recovered = f
            .state
            .addon_reconcile(&reopened.session_id, inventory(&c, false))
            .await
            .unwrap();
        assert!(!recovered.needs_reconciliation);
        assert_eq!(recovered.managed[0].archive_sha256, c.archive_sha256);
    }
    #[tokio::test]
    async fn addon_cancel_and_expiry_never_release_path() {
        let f = Fixture::new(false).await;
        let s = f.session(&"e".repeat(64)).await;
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        f.state
            .addon_cancel(&s.session_id, Some(&c.operation_id))
            .await
            .unwrap();
        assert!(
            f.state
                .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                .await
                .is_err()
        );
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        {
            let mut profiles = f.state.addon_profiles.lock().unwrap();
            let p = profiles.session_mut(&s.session_id).unwrap();
            p.operation
                .as_mut()
                .unwrap()
                .candidate
                .as_mut()
                .unwrap()
                .expires_at_ms = 0;
        }
        assert_eq!(
            f.state
                .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::Expired
        );
    }
    #[tokio::test]
    async fn addon_cancel_while_waiting_on_authority_is_terminal() {
        let f = Fixture::new(false).await;
        let s = f.session(&"f".repeat(64)).await;
        let guard = f
            .state
            .merge_path_lock(&f.address, "content.json")
            .lock_owned()
            .await;
        let state = f.state.clone();
        let request = f.request(&s.session_id, AddonAction::Install);
        let task = tokio::spawn(async move { state.addon_prepare(request).await });
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if f.state
                    .addon_status(&s.session_id)
                    .await
                    .unwrap()
                    .operation
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        f.state.addon_cancel(&s.session_id, None).await.unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .code,
            AddonErrorCode::Cancelled
        );
        drop(guard);
    }
    #[tokio::test]
    async fn addon_update_uninstall_and_wrong_result_bind_exact_identity() {
        let f = Fixture::new(false).await;
        let s = f.session(&"1".repeat(64)).await;
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        f.state
            .addon_stage(&s.session_id, &c.operation_id, &c.archive_sha256)
            .await
            .unwrap();
        assert!(
            f.state
                .addon_report(
                    &s.session_id,
                    &c.operation_id,
                    AddonEngineOutcome::Installed {
                        addon_id: "other".into(),
                        version: c.version.clone(),
                        archive_sha256: c.archive_sha256.clone()
                    }
                )
                .await
                .is_err()
        );
        f.state
            .addon_report(&s.session_id, &c.operation_id, installed(&c))
            .await
            .unwrap();
        f.publish("2.0").await;
        let updated = f
            .state
            .addon_prepare(f.request(
                &s.session_id,
                AddonAction::Update {
                    addon_id: c.addon_id.clone(),
                },
            ))
            .await
            .unwrap();
        f.state
            .addon_stage(
                &s.session_id,
                &updated.operation_id,
                &updated.archive_sha256,
            )
            .await
            .unwrap();
        f.state
            .addon_report(
                &s.session_id,
                &updated.operation_id,
                AddonEngineOutcome::Staged {
                    addon_id: updated.addon_id.clone(),
                    version: updated.version.clone(),
                    archive_sha256: updated.archive_sha256.clone(),
                },
            )
            .await
            .unwrap();
        assert!(
            f.state
                .addon_reconcile(&s.session_id, inventory(&c, true))
                .await
                .unwrap()
                .needs_reconciliation
        );
        assert!(
            !f.state
                .addon_reconcile(&s.session_id, inventory(&updated, false))
                .await
                .unwrap()
                .needs_reconciliation
        );
        let u = f
            .state
            .addon_begin_uninstall(&s.session_id, &c.addon_id)
            .await
            .unwrap();
        assert_eq!(u.uninstall_id.as_deref(), Some(c.addon_id.as_str()));
        let reopened = f
            .state
            .addon_open_session(&s.profile_id, AddonEngine::Gecko)
            .await
            .unwrap();
        let final_state = f
            .state
            .addon_reconcile(
                &reopened.session_id,
                AddonInventory {
                    addons: vec![],
                    has_pending_installs: false,
                },
            )
            .await
            .unwrap();
        assert!(final_state.managed.is_empty());
        assert!(!final_state.needs_reconciliation);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn addon_linked_package_cannot_read_outside_xite() {
        let f = Fixture::new(false).await;
        let s = f.session(&"2".repeat(64)).await;
        let outside = f.root.path().join("sentinel");
        std::fs::write(&outside, b"unchanged").unwrap();
        let path = f.storage.path("addons/extension.xpi").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(
            f.state
                .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(outside).unwrap(), b"unchanged");
    }
    #[tokio::test]
    #[ignore = "requires public signed fixture directory in EPIX_ADDON_FIXTURES"]
    async fn addon_public_signed_fixture_matrix() {
        let public = PathBuf::from(
            std::env::var_os("EPIX_ADDON_FIXTURES").expect("public fixture directory"),
        );
        for (name, expected) in [
            ("owner-v174", true),
            ("owner-v175", true),
            ("delegated-v175", true),
            ("owner-unsigned-archive", true),
            ("owner-tampered-archive", true),
            ("negative-byte-mismatch", false),
            ("negative-unsigned-manifest", false),
            ("negative-mutated-manifest", false),
            ("negative-unauthorized-delegate", false),
            ("negative-missing-delegation", false),
        ] {
            let source = public.join(name);
            let raw = std::fs::read(source.join("content.json")).unwrap();
            let root: Value = serde_json::from_slice(&raw).unwrap();
            let address = root["address"].as_str().unwrap();
            let output = tempfile::tempdir().unwrap();
            let path = output.path().canonicalize().unwrap();
            let state = AppState::with_data_dir("public-addon-fixture", &path);
            let storage = XiteStorage::new(path.join("data").join(address));
            for inner in [
                "content.json",
                "index.html",
                "addons/content.json",
                "addons/extension.xpi",
            ] {
                if let Ok(bytes) = std::fs::read(source.join(inner)) {
                    storage.write(inner, &bytes).unwrap();
                }
            }
            state
                .add_xite(
                    address,
                    XiteEntry {
                        storage,
                        content: Some(root.clone()),
                    },
                )
                .await;
            let session = state
                .addon_open_session(&"3".repeat(64), AddonEngine::Gecko)
                .await
                .unwrap();
            state
                .addon_reconcile(
                    &session.session_id,
                    AddonInventory {
                        addons: vec![],
                        has_pending_installs: false,
                    },
                )
                .await
                .unwrap();
            let result = state
                .addon_prepare(AddonPrepareRequest {
                    session_id: session.session_id.clone(),
                    source_url: format!("https://{address}.epix/addons/extension.xpi"),
                    action: AddonAction::Install,
                })
                .await;
            assert_eq!(result.is_ok(), expected, "{name}: {result:?}");
            if let Ok(candidate) = result {
                let staged = state
                    .addon_stage(
                        &session.session_id,
                        &candidate.operation_id,
                        &candidate.archive_sha256,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    std::fs::read(staged.path).unwrap(),
                    std::fs::read(source.join("addons/extension.xpi")).unwrap()
                );
            }
        }
    }
    #[tokio::test]
    async fn addon_private_orphans_and_foreign_ids_fail_closed() {
        let f = Fixture::new(false).await;
        let profile = "4".repeat(64);
        let s = f.session(&profile).await;
        let c = f
            .state
            .addon_prepare(f.request(&s.session_id, AddonAction::Install))
            .await
            .unwrap();
        let folder = f.root.path().join("private/addons").join(&profile);
        let orphan = folder.join(format!("{}.xpi", "9".repeat(64)));
        std::fs::write(&orphan, b"interrupted stage").unwrap();
        let unrelated = folder.join("keep.txt");
        std::fs::write(&unrelated, b"keep").unwrap();
        let reopened = f
            .state
            .addon_open_session(&profile, AddonEngine::Gecko)
            .await
            .unwrap();
        assert!(!orphan.exists());
        assert!(!folder.join(stage_name(&c.operation_id)).exists());
        assert_eq!(std::fs::read(unrelated).unwrap(), b"keep");
        f.state
            .addon_reconcile(&reopened.session_id, inventory(&c, false))
            .await
            .unwrap();
        assert!(
            f.state
                .addon_prepare(f.request(&reopened.session_id, AddonAction::Install))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn addon_profile_binding_and_webkit_policy_are_explicit() {
        let f = Fixture::new(false).await;
        let s = f
            .state
            .addon_open_session(&"5".repeat(64), AddonEngine::WebKit)
            .await
            .unwrap();
        f.state
            .addon_reconcile(
                &s.session_id,
                AddonInventory {
                    addons: vec![],
                    has_pending_installs: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            f.state
                .addon_prepare(f.request(&s.session_id, AddonAction::Install))
                .await
                .unwrap_err()
                .code,
            AddonErrorCode::UnsupportedSource
        );
        assert!(
            f.state
                .addon_open_session("../profile", AddonEngine::Gecko)
                .await
                .is_err()
        );
        let first = f.session(&"6".repeat(64)).await;
        let second = f.session(&"7".repeat(64)).await;
        let c = f
            .state
            .addon_prepare(f.request(&first.session_id, AddonAction::Install))
            .await
            .unwrap();
        assert!(
            f.state
                .addon_stage(&second.session_id, &c.operation_id, &c.archive_sha256)
                .await
                .is_err()
        );
    }
}
