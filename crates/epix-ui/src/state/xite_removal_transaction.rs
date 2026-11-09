use super::{
    canonical_address, remove_xite_directories_with_progress, sync_parent_directory, AppState,
    ManagedXite, XiteRemovalIntent, XiteRemovalOutcome, XiteRemovalProgress,
};
use epix_blob::store::{ExternInternalization, ExternPathEntry, Store};
use epix_blob::ObjId;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

struct RemovalTarget {
    canonical: String,
    keys: Vec<String>,
    cache_keys: Vec<String>,
    roots: Vec<PathBuf>,
}

struct RemovalStore {
    active: Option<Arc<Store>>,
    dormant: bool,
}

enum IntentCommit {
    Untracked,
    Durable,
    Pending,
}

struct StoreCleanup {
    internalized: usize,
    retired: Vec<ObjId>,
    complete: bool,
    warnings: Vec<String>,
}

impl StoreCleanup {
    fn ready() -> Self {
        Self {
            internalized: 0,
            retired: Vec::new(),
            complete: true,
            warnings: Vec::new(),
        }
    }

    fn pending(warning: String) -> Self {
        Self {
            complete: false,
            warnings: vec![warning],
            ..Self::ready()
        }
    }
}

impl AppState {
    pub(super) async fn remove_xite_owned(
        &self,
        address: &str,
        progress: &XiteRemovalProgress,
    ) -> Result<XiteRemovalOutcome, String> {
        // Cancel before waiting for the activation and manifest guards. An
        // old download must not recreate progress after cleanup.
        let canonical = self.canonical_key(address).await;
        if let Some(resolver) = self.on_demand.read().await.clone() {
            resolver.cancel(&canonical).await;
        }
        let activation = self.acquire_activation_write().await;
        let registry = self.xite_registry_lock.lock().await;
        let Some(target) = self.removal_target(address).await else {
            let pending = self.pending_removal_canonical(address)?;
            drop(registry);
            drop(activation);
            return Ok(self.resume_pending_removal(pending).await);
        };
        self.validate_removal_target(&target).await?;
        let manifest = self.lock_removal_manifest(&target.canonical).await?;
        let tree = self
            .tree_mutation_lock(&target.canonical)
            .lock_owned()
            .await;
        let active = self.edx_store().await;
        let store = RemovalStore {
            dormant: active.is_none() && self.dormant_edx_store_may_exist(),
            active,
        };
        // Derived-feed ownership is released while the xite is still
        // intact. Its cache can rebuild if the intent cannot be committed.
        let feed_cleanup_complete = self.clear_removal_feed_caches(&target.cache_keys).await;
        let intent_persisted = match self.commit_removal_intent(&target, &store).await {
            Ok(IntentCommit::Durable) => true,
            Ok(IntentCommit::Untracked) => false,
            Ok(IntentCommit::Pending) => {
                // An installed intent whose parent cannot be synced blocks
                // re-adds, but must not retain mutation authority while waiting.
                drop(tree);
                drop(manifest);
                drop(registry);
                drop(activation);
                self.schedule_xite_removal_retry(&target.canonical);
                return Ok(XiteRemovalOutcome::Pending);
            }
            Err(error) => {
                drop(tree);
                drop(manifest);
                self.log("ERROR", error.clone()).await;
                return Err(error);
            }
        };

        // The durable intent precedes every destructive membership or tree
        // mutation. Keep both outer guards through final receipt retirement.
        self.invalidate_removal_sessions(&target);
        let registry_persisted = self.persist_removal_registry(&target.canonical).await;
        let ownership_warnings = self
            .release_removal_membership(&target, &store, feed_cleanup_complete)
            .await;
        let mut store_cleanup = self.preserve_removal_store(&target, &store, progress).await;
        self.persist_removal_store_phase(&target, &store, intent_persisted, &mut store_cleanup);
        let roots_removed = self
            .remove_committed_roots(&target.roots, store_cleanup.complete, progress)
            .await;
        progress.report("Finishing site cleanup...", 95);
        drop(tree);
        drop(manifest);

        // Rehome and merger rebuild acquire their own tree/manifest locks.
        // The activation and registry guards still protect this transaction.
        let ownership_complete = self
            .finish_removal_ownership(
                &target,
                &store,
                intent_persisted,
                store_cleanup,
                ownership_warnings,
            )
            .await;
        let metadata_complete = self.finish_removal_metadata(&target).await;
        let cleanup_complete =
            registry_persisted && roots_removed && ownership_complete && metadata_complete;
        let intent_remaining = self
            .finish_removal_intent(&target.canonical, intent_persisted, cleanup_complete)
            .await;
        drop(registry);
        drop(activation);
        if intent_remaining {
            self.schedule_xite_removal_retry(&target.canonical);
        }
        Ok(if cleanup_complete && !intent_remaining {
            XiteRemovalOutcome::Complete
        } else {
            XiteRemovalOutcome::Pending
        })
    }

    async fn removal_target(&self, address: &str) -> Option<RemovalTarget> {
        let xites = self.xites.read().await;
        let xite = self.resolve_xite(&xites, address)?;
        let canonical = canonical_address(xite.content.as_ref(), address);
        let keys: Vec<_> = xites
            .iter()
            .filter(|(key, xite)| canonical_address(xite.content.as_ref(), key) == canonical)
            .map(|(key, _)| key.clone())
            .collect();
        Some(RemovalTarget {
            cache_keys: removal_cache_keys(&xites, &canonical, &keys),
            roots: removal_storage_roots(&xites, &keys),
            canonical,
            keys,
        })
    }

    fn pending_removal_canonical(&self, address: &str) -> Result<Option<String>, String> {
        Ok(self
            .read_xite_removal_intents()
            .map_err(|error| format!("Could not inspect pending xite removal: {error}"))?
            .into_iter()
            .find_map(|(canonical, intent)| {
                (canonical == address || intent.keys.iter().any(|key| key == address))
                    .then_some(canonical)
            }))
    }

    async fn resume_pending_removal(&self, pending: Option<String>) -> XiteRemovalOutcome {
        let Some(canonical) = pending else {
            return XiteRemovalOutcome::Unknown;
        };
        self.schedule_xite_removal_retry(&canonical);
        if self.retry_pending_xite_removal_once(&canonical).await {
            XiteRemovalOutcome::Complete
        } else {
            XiteRemovalOutcome::Pending
        }
    }

    async fn validate_removal_target(&self, target: &RemovalTarget) -> Result<(), String> {
        if self
            .removal_root_is_reused(&target.canonical, &target.roots)
            .await
        {
            let error = format!(
                "Refusing to remove {}: its storage root is shared by another served xite",
                target.canonical
            );
            self.log("ERROR", error.clone()).await;
            return Err(error);
        }
        Ok(())
    }

    async fn lock_removal_manifest(
        &self,
        canonical: &str,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, String> {
        match self.acquire_manifest_mutex(canonical, "content.json").await {
            Ok(guard) => Ok(guard),
            Err(error) => {
                let error = format!("Could not lock {canonical} for deletion: {error}");
                self.log("ERROR", error.clone()).await;
                Err(error)
            }
        }
    }

    async fn clear_removal_feed_caches(&self, keys: &[String]) -> bool {
        let mut complete = true;
        for key in keys {
            complete &= self.clear_feed_cache(key).await;
        }
        complete
    }

    async fn removal_store_root(&self, store: &RemovalStore) -> Result<Option<PathBuf>, String> {
        if let Some(store) = store.active.as_deref() {
            return Self::store_receipt_root(store)
                .map(Some)
                .map_err(|error| format!("Could not start xite removal: {error}"));
        }
        if !store.dormant {
            return Ok(None);
        }
        let data_root = self
            .data_root
            .as_ref()
            .ok_or_else(|| "Could not bind dormant Store removal: no data root".to_string())?;
        tokio::fs::canonicalize(data_root.join("edx-store"))
            .await
            .map(Some)
            .map_err(|error| format!("Could not bind dormant Store removal: {error}"))
    }

    async fn commit_removal_intent(
        &self,
        target: &RemovalTarget,
        store: &RemovalStore,
    ) -> Result<IntentCommit, String> {
        if self.xites_path.is_none() {
            return Ok(IntentCommit::Untracked);
        }
        let mut intents = self
            .read_xite_removal_intents()
            .map_err(|error| format!("Could not start xite removal: {error}"))?;
        let store_root = self.removal_store_root(store).await?;
        let intent = XiteRemovalIntent {
            keys: target.cache_keys.clone(),
            roots: target.roots.clone(),
            owner_cleanup_required: store_root.is_some(),
            store_root,
            store_cleanup_required: store.active.is_some() || store.dormant,
            rehome_ids: Vec::new(),
        };
        self.validated_removal_roots(&target.canonical, &intent)
            .map_err(|error| format!("Could not start xite removal: {error}"))?;
        intents.insert(target.canonical.clone(), intent);
        if let Err(error) = self.write_xite_removal_intents(&intents) {
            // Atomic rename can install the exact generation before parent
            // sync fails. Confirm that generation, then retry its durability
            // barrier before permitting any destructive mutation.
            let installed = self
                .read_xite_removal_intents()
                .is_ok_and(|actual| actual == intents);
            if !installed {
                return Err(format!("Could not start xite removal: {error}"));
            }
            self.log(
                "WARN",
                format!(
                    "Xite removal intent was installed but its durability check failed; retrying before removal: {error}"
                ),
            )
            .await;
            let path = self.xite_removals_path().ok_or_else(|| {
                "Could not confirm xite removal: journal path disappeared".to_string()
            })?;
            if sync_parent_directory(&path).is_err() {
                return Ok(IntentCommit::Pending);
            }
        }
        Ok(IntentCommit::Durable)
    }

    fn invalidate_removal_sessions(&self, target: &RemovalTarget) {
        // These capabilities and prompt decisions belong to this exact
        // served membership, even if the same address is later re-added.
        self.bigfile_uploads
            .lock()
            .unwrap()
            .retain(|_, upload| upload.canonical != target.canonical);
        let remove: HashSet<_> = target.cache_keys.iter().collect();
        self.retention_consents
            .lock()
            .unwrap()
            .retain(|key| !remove.contains(key));
        self.optional_prompts
            .lock()
            .unwrap()
            .retain(|key| !remove.contains(key));
        self.clone_statuses
            .lock()
            .unwrap()
            .retain(|key, _| !remove.contains(key));
        self.clone_retry_wakes
            .lock()
            .unwrap()
            .retain(|key, _| !remove.contains(key));
        self.clone_retry_dirty
            .lock()
            .unwrap()
            .retain(|key| !remove.contains(key));
        self.xite_update_requests
            .lock()
            .unwrap()
            .retain(|key, _| !remove.contains(key));
        self.clones_in_flight
            .lock()
            .unwrap()
            .retain(|key| !remove.contains(key));
    }

    async fn persist_removal_registry(&self, canonical: &str) -> bool {
        if self.xites_path.is_none() {
            return true;
        }
        let excluded = HashSet::from([canonical.to_string()]);
        let bytes = {
            let xites = self.xites.read().await;
            Self::xite_registry_bytes(&xites, &excluded)
        };
        if let Err(error) = bytes.and_then(|bytes| self.write_xite_registry_bytes(&bytes)) {
            self.log(
                "WARN",
                format!(
                    "Could not compact xites.json while deleting {canonical}; the durable removal intent remains: {error}"
                ),
            )
            .await;
            return false;
        }
        true
    }

    async fn release_removal_membership(
        &self,
        target: &RemovalTarget,
        store: &RemovalStore,
        feed_cleanup_complete: bool,
    ) -> Vec<String> {
        // Release accepted declarations before preserving Extern rows so
        // objects with no surviving owner need no object-sized copy.
        {
            let mut xites = self.xites.write().await;
            for key in &target.keys {
                xites.remove(key);
            }
        }
        self.replace_verified_object_paths(&target.canonical, Vec::new());
        self.replace_verified_manifest_chains(&target.canonical, HashMap::new());
        self.replace_verified_manifest_contents(&target.canonical, &[]);
        let mut warnings = Vec::new();
        if !feed_cleanup_complete {
            warnings.push(format!(
                "could not release all feed ownership for removed xite {}",
                target.canonical
            ));
        }
        warnings.extend(
            store
                .active
                .as_deref()
                .map(|store| self.reconcile_manifest_object_owners(store))
                .unwrap_or_default(),
        );
        warnings
    }

    async fn preserve_removal_store(
        &self,
        target: &RemovalTarget,
        store: &RemovalStore,
        progress: &XiteRemovalProgress,
    ) -> StoreCleanup {
        let Some(store) = store.active.clone() else {
            return if store.dormant {
                StoreCleanup::pending(format!(
                    "persistent Store is not active; retaining {} until Store activation",
                    target.canonical
                ))
            } else {
                StoreCleanup::ready()
            };
        };
        progress.report("Preserving shared files...", 10);
        let roots = target.roots.clone();
        let canonical = target.canonical.clone();
        let state = self.owned_state();
        let progress = progress.clone();
        // Copying and syncing shared objects must not block delivery of
        // progress on the asynchronous worker.
        tokio::task::spawn_blocking(move || {
            state.preserve_removal_store_blocking(&canonical, &roots, &store, &progress)
        })
        .await
        .unwrap_or_else(|error| {
            StoreCleanup::pending(format!("shared-file preservation worker failed: {error}"))
        })
    }

    fn preserve_removal_store_blocking(
        &self,
        canonical: &str,
        roots: &[PathBuf],
        store: &Store,
        progress: &XiteRemovalProgress,
    ) -> StoreCleanup {
        // Only Store's authenticated extern index supplies deletion inputs.
        // Rejected manifests cannot name unrelated objects for removal.
        let mut entries = match store.extern_entries() {
            Ok(entries) => entries,
            Err(error) => {
                return StoreCleanup::pending(format!(
                    "could not enumerate Store rows for {canonical}: {error}"
                ));
            }
        };
        entries.retain(|entry| Self::removal_entry_is_under_roots(&entry.path, roots));
        let mut cleanup = StoreCleanup::ready();
        let total = entries.len();
        let mut last_report = std::time::Instant::now();
        for (index, entry) in entries.into_iter().enumerate() {
            if last_report.elapsed() >= std::time::Duration::from_millis(100) {
                progress.report(&format!("Preserving shared file {}/{total}", index + 1), 10);
                last_report = std::time::Instant::now();
            }
            self.preserve_removal_store_entry(canonical, store, entry, &mut cleanup);
        }
        cleanup
    }

    fn preserve_removal_store_entry(
        &self,
        canonical: &str,
        store: &Store,
        entry: ExternPathEntry,
        cleanup: &mut StoreCleanup,
    ) {
        match store.internalize_extern_at(entry.id, &entry.path) {
            Ok(ExternInternalization::Internalized) => {
                cleanup.internalized = cleanup.internalized.saturating_add(1);
                self.collect_removal_rehome_candidate(canonical, entry.id, cleanup);
            }
            Ok(ExternInternalization::CanonicalElsewhere) => {}
            Err(error) => {
                // Retire an invalid old mapping only if revalidation proves
                // Store no longer contains it. A copy/sync failure alone is
                // not evidence that another owner's only source is corrupt.
                let invalid_owner_retired =
                    store.revalidate(entry.id).is_ok() && !store.contains(entry.id).unwrap_or(true);
                if invalid_owner_retired {
                    self.collect_removal_rehome_candidate(canonical, entry.id, cleanup);
                    return;
                }
                cleanup.complete = false;
                cleanup.warnings.push(format!(
                    "could not preserve {} while deleting {canonical}: {error}",
                    entry.id,
                ));
            }
        }
    }

    fn collect_removal_rehome_candidate(
        &self,
        canonical: &str,
        id: ObjId,
        cleanup: &mut StoreCleanup,
    ) {
        let shared = self
            .edx_paths
            .read()
            .expect("edx_paths")
            .get(&id)
            .is_some_and(|entries| {
                entries.iter().any(|candidate| {
                    candidate.canonical != canonical && Self::declaration_is_rehomeable(candidate)
                })
            });
        if shared {
            cleanup.retired.push(id);
        }
    }

    fn persist_removal_store_phase(
        &self,
        target: &RemovalTarget,
        store: &RemovalStore,
        intent_persisted: bool,
        cleanup: &mut StoreCleanup,
    ) {
        if !cleanup.complete || !intent_persisted || store.active.is_none() {
            return;
        }
        // Record preservation and rehome IDs before roots can disappear so
        // restart can finish this phase even without an active Store.
        let phase = self.read_xite_removal_intents().and_then(|mut intents| {
            if let Some(intent) = intents.get_mut(&target.canonical) {
                intent.store_cleanup_required = false;
                intent.owner_cleanup_required = true;
                intent.rehome_ids = cleanup.retired.iter().map(ToString::to_string).collect();
            }
            self.write_xite_removal_intents(&intents)
        });
        if let Err(error) = phase {
            cleanup.complete = false;
            cleanup.warnings.push(format!(
                "could not persist Store cleanup for {}: {error}",
                target.canonical
            ));
        }
    }

    async fn remove_committed_roots(
        &self,
        roots: &[PathBuf],
        store_cleanup_complete: bool,
        progress: &XiteRemovalProgress,
    ) -> bool {
        if !store_cleanup_complete {
            return false;
        }
        let roots = roots.to_vec();
        let progress = progress.clone();
        let errors = tokio::task::spawn_blocking(move || {
            remove_xite_directories_with_progress(&roots, &mut |update| progress.files(update))
        })
        .await
        .unwrap_or_else(|error| vec![format!("file removal worker failed: {error}")]);
        for error in &errors {
            self.log("WARN", format!("Pending xite removal: {error}"))
                .await;
        }
        errors.is_empty()
    }

    async fn finish_removal_ownership(
        &self,
        target: &RemovalTarget,
        store: &RemovalStore,
        intent_persisted: bool,
        cleanup: StoreCleanup,
        mut ownership_warnings: Vec<String>,
    ) -> bool {
        for warning in &cleanup.warnings {
            self.log("WARN", format!("Xite deletion Store retry: {warning}"))
                .await;
        }
        let rehome_warnings = self
            .rehome_retired_objects(store.active.clone(), cleanup.retired, None)
            .await;
        if intent_persisted
            && store.active.is_some()
            && ownership_warnings.is_empty()
            && rehome_warnings.is_empty()
        {
            if let Err(error) = self.persist_xite_removal_owner_phase(&target.canonical, false, &[])
            {
                ownership_warnings.push(format!(
                    "could not persist owner cleanup for {}: {error}",
                    target.canonical
                ));
            }
        }
        for warning in &ownership_warnings {
            self.log("WARN", format!("Xite deletion ownership retry: {warning}"))
                .await;
        }
        for warning in &rehome_warnings {
            self.log("WARN", format!("Xite deletion rehome retry: {warning}"))
                .await;
        }
        if cleanup.internalized > 0 {
            self.log(
                "INFO",
                format!(
                    "Preserved {} Store object(s) before deleting {}",
                    cleanup.internalized, target.canonical
                ),
            )
            .await;
        }
        cleanup.warnings.is_empty() && ownership_warnings.is_empty() && rehome_warnings.is_empty()
    }

    async fn finish_removal_metadata(&self, target: &RemovalTarget) -> bool {
        // Revoke contributed merger rows before returning. Keep the receipt
        // until user and metadata files accept removal durably as well.
        self.rebuild_merger_dbs().await;
        let user_cleanup = self.delete_user_xite_data(&target.cache_keys).await;
        if let Err(error) = &user_cleanup {
            self.log(
                "WARN",
                format!(
                    "Could not persist user cleanup for {}: {error}",
                    target.canonical
                ),
            )
            .await;
        }
        let metadata_cleanup = self
            .delete_xite_persisted_metadata(&target.canonical, &target.cache_keys)
            .await;
        if let Err(error) = &metadata_cleanup {
            self.log(
                "WARN",
                format!(
                    "Could not persist metadata cleanup for {}: {error}",
                    target.canonical
                ),
            )
            .await;
        }
        user_cleanup.is_ok() && metadata_cleanup.is_ok()
    }

    async fn finish_removal_intent(
        &self,
        canonical: &str,
        intent_persisted: bool,
        cleanup_complete: bool,
    ) -> bool {
        if !intent_persisted {
            return false;
        }
        // Any unsettled phase keeps the receipt for retry even though this
        // process no longer serves the removed membership.
        if cleanup_complete {
            let retired = self.read_xite_removal_intents().and_then(|mut intents| {
                intents.remove(canonical);
                self.write_xite_removal_intents(&intents)
            });
            if let Err(error) = retired {
                self.log(
                    "WARN",
                    format!("Could not retire xite-removal intent: {error}"),
                )
                .await;
            }
        }
        self.read_xite_removal_intents()
            .map_or(true, |intents| intents.contains_key(canonical))
    }
}

fn removal_cache_keys(
    xites: &HashMap<String, ManagedXite>,
    canonical: &str,
    keys: &[String],
) -> Vec<String> {
    let mut cache_keys = vec![canonical.to_string()];
    for key in keys {
        if !cache_keys.contains(key) {
            cache_keys.push(key.clone());
        }
        if let Some(display) = xites.get(key).and_then(|xite| xite.display.clone()) {
            if !cache_keys.contains(&display) {
                cache_keys.push(display);
            }
        }
    }
    cache_keys
}

fn removal_storage_roots(xites: &HashMap<String, ManagedXite>, keys: &[String]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for key in keys {
        let Some(xite) = xites.get(key) else { continue };
        let root = xite.storage.root();
        let absolute = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|current| current.join(root))
                .unwrap_or_else(|_| root.to_path_buf())
        };
        if !roots.contains(&absolute) {
            roots.push(absolute);
        }
    }
    roots
}
