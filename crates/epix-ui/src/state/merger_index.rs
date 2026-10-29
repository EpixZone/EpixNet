//! Persistent derived merger databases. The source tree remains authoritative.
//! A cache is never exposed until reconciliation and receipt validation finish.

use super::*;
use epix_db::derived::{DeltaMetrics, DerivedIndex, SourceVersion};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq)]
struct SourceReceipt {
    storage_root: PathBuf,
    verified_epoch: u64,
    source_epoch: u64,
    merged_type: String,
}

#[derive(Clone)]
pub(super) struct CachedIndex {
    index: DerivedIndex,
    fingerprint: String,
    sources: BTreeMap<String, SourceReceipt>,
    filter_epoch: u64,
    publication: Arc<IndexPublication>,
    // Ephemeral AppState instances must not write caches into served trees.
    _temporary: Option<Arc<tempfile::TempDir>>,
}

struct IndexPublication {
    index: DerivedIndex,
    published: AtomicBool,
}

impl Drop for IndexPublication {
    fn drop(&mut self) {
        // Failed or superseded preparations never become permanent orphan
        // generations. The lease defers deletion until workers/readers close.
        if !self.published.load(Ordering::Acquire) {
            let _ = self.index.retire();
        }
    }
}

#[derive(Default, serde::Serialize)]
pub(super) struct IndexCounters {
    reconciliations: u64,
    cache_recoveries: u64,
    explicit_resets: u64,
    verified_input_files: u64,
    reused_hubs: u64,
    changed_sources: u64,
    skipped_sources: u64,
    replayed_sources: u64,
    replayed_bytes: u64,
}

struct Target {
    key: String,
    canonical: String,
    storage: XiteStorage,
    schema: DbSchema,
    types: Vec<String>,
    verified_epoch: u64,
    source_epoch: u64,
    cache: Option<CachedIndex>,
    db: Option<Database>,
}

fn digest(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
        .map_err(|error| error.to_string())
}

fn authority_digest(authority: &VerifiedDbAuthority) -> Result<String, String> {
    // Sort maps explicitly; HashMap serialization order is not a checkpoint.
    let manifests = authority
        .manifests
        .iter()
        .map(|manifest| (&manifest.inner_path, &manifest.content))
        .collect::<BTreeMap<_, _>>();
    let chains = authority.manifest_chains.iter().collect::<BTreeMap<_, _>>();
    digest(&(manifests, chains))
}

impl AppState {
    /// Cumulative work performed by merger indexing in this process. Used by
    /// the benchmark to distinguish reuse from a deceptively fast rebuild.
    pub fn merger_index_stats(&self) -> Value {
        serde_json::to_value(&*self.merger_index_counters.lock().unwrap()).unwrap_or(Value::Null)
    }

    fn count_index_delta(&self, delta: &DeltaMetrics) {
        let mut counters = self.merger_index_counters.lock().unwrap();
        counters.changed_sources += delta.changed_sources;
        counters.skipped_sources += delta.skipped_sources;
        counters.replayed_sources += delta.replayed_sources;
        counters.replayed_bytes += delta.replayed_bytes;
    }

    async fn open_merger_index(
        &self,
        key: &str,
        canonical: &str,
        storage: &XiteStorage,
        schema: &DbSchema,
        types: &[String],
        filter_epoch: u64,
    ) -> Result<CachedIndex, String> {
        let context = digest(&(canonical, storage.root(), types))?;
        let fingerprint = digest(&(&context, schema))?;
        let cached = {
            let caches = self.merger_indexes.lock().unwrap();
            caches
                .get(key)
                .filter(|cache| cache.fingerprint == fingerprint)
                .or_else(|| {
                    caches
                        .values()
                        .find(|cache| cache.fingerprint == fingerprint)
                })
                .cloned()
        };
        if let Some(mut cached) = cached {
            if cached.filter_epoch != filter_epoch {
                cached.sources.clear();
                cached.filter_epoch = filter_epoch;
            }
            return Ok(cached);
        }
        let (root, temporary) = match self.data_dir() {
            Some(root) => (root.join("cache/merger-index-v1"), None),
            None => {
                let mut temporary = self.merger_temporary_root.lock().unwrap();
                if temporary.is_none() {
                    *temporary = Some(Arc::new(
                        tempfile::tempdir().map_err(|error| error.to_string())?,
                    ));
                }
                let temporary = temporary.as_ref().unwrap().clone();
                (temporary.path().to_path_buf(), Some(temporary))
            }
        };
        let schema = schema.clone();
        let file_name = format!("{fingerprint}.sqlite");
        let (index, recovered) = tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
            // Retry durable retirement markers left by an interrupted shutdown.
            for entry in std::fs::read_dir(&root).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let Some(hash) = name.strip_suffix(".sqlite.retired") else {
                    continue;
                };
                if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    let _ = DerivedIndex::discard_cache(root.join(format!("{hash}.sqlite")));
                }
            }
            let path = root.join(file_name);
            match DerivedIndex::open(&path, &schema, &context) {
                Ok(index) => Ok((index, false)),
                Err(error) if DerivedIndex::is_recoverable_cache_error(&error) => {
                    // Only this node-private, disposable cache is removed.
                    // Signed source data is never changed by cache recovery.
                    if !DerivedIndex::discard_cache(&path).map_err(|error| error.to_string())? {
                        return Err("invalid merger cache still has active readers".to_string());
                    }
                    DerivedIndex::open(&path, &schema, &context)
                        .map(|index| (index, true))
                        .map_err(|error| error.to_string())
                }
                Err(error) => Err(error.to_string()),
            }
        })
        .await
        .map_err(|error| error.to_string())??;
        if recovered {
            self.merger_index_counters.lock().unwrap().cache_recoveries += 1;
            self.log(
                "WARN",
                format!("rebuilding invalid private merger cache for {key}"),
            )
            .await;
        }
        Ok(CachedIndex {
            publication: Arc::new(IndexPublication {
                index: index.clone(),
                published: AtomicBool::new(false),
            }),
            index,
            fingerprint,
            sources: BTreeMap::new(),
            filter_epoch,
            _temporary: temporary,
        })
    }

    /// Reconcile persistent projections from current verified source inputs.
    /// Unchanged hubs are skipped within a process; after restart the normal
    /// authority checks run again, while identical projections remain on disk.
    pub async fn rebuild_merger_dbs(&self) {
        // SQL workers cannot be cancelled after they start. Keep their writer
        // and authority guards owned by a completion task even if the request
        // waiting for this refresh is dropped.
        let state = self.owned_state();
        if let Err(error) = tokio::spawn(async move {
            state.rebuild_merger_dbs_inner().await;
        })
        .await
        {
            self.log("WARN", format!("merger refresh completion failed: {error}"))
                .await;
        }
    }

    async fn rebuild_merger_dbs_inner(&self) {
        // A partial restore is not a removal of the hubs still waiting to load.
        if self.boot_restore_pending() {
            return;
        }
        let _writer = self.merger_index_refresh.lock().await;
        self.merger_index_counters.lock().unwrap().reconciliations += 1;
        loop {
            if self.boot_restore_pending() {
                return;
            }
            let filter_epoch = self.db_filter_epoch();
            let merger_epoch = self.db_merger_epoch();
            let muted = self.muted_authors().await;
            let registry = {
                let xites = self.xites.read().await;
                xites
                    .iter()
                    .map(|(key, xite)| {
                        (
                            key.clone(),
                            canonical_address(xite.content.as_ref(), key),
                            xite.storage.clone(),
                            xite.content.clone(),
                            xite.db_schema.clone(),
                            xite.settings
                                .permissions
                                .iter()
                                .filter_map(|permission| {
                                    permission.strip_prefix("Merger:").map(String::from)
                                })
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            // Registering many source hubs before a frontend must not repeatedly
            // materialize every source when there is no database to populate.
            if !registry
                .iter()
                .any(|entry| entry.4.as_ref().is_some_and(|schema| schema.version == 3))
            {
                let retired = {
                    let mut caches = self.merger_indexes.lock().unwrap();
                    let retired = caches
                        .values()
                        .map(|cache| cache.index.clone())
                        .collect::<Vec<_>>();
                    caches.clear();
                    retired
                };
                self.retire_merger_indexes(retired).await;
                return;
            }
            if self.db_filter_epoch() != filter_epoch || self.db_merger_epoch() != merger_epoch {
                continue;
            }
            // Withdraw handles before touching a persistent projection. Old
            // detached reads fail their receipt recheck, including on errors.
            {
                let mut xites = self.xites.write().await;
                for (key, _, _, _, schema, _) in &registry {
                    if schema.as_ref().is_some_and(|schema| schema.version == 3) {
                        if let Some(xite) = xites.get_mut(key) {
                            xite.db = None;
                            xite.db_generation = self.next_db_generation();
                        }
                    }
                }
            }
            let mut roots = BTreeMap::new();
            for (_, canonical, storage, _, _, _) in &registry {
                if roots
                    .insert(canonical, storage.root())
                    .is_some_and(|root| root != storage.root())
                {
                    self.log(
                        "WARN",
                        format!("merger index: conflicting storage roots for {canonical}"),
                    )
                    .await;
                    return;
                }
            }
            let mut targets = Vec::new();
            for (key, canonical, storage, content, current_schema, types) in &registry {
                let Some(current_schema) =
                    current_schema.as_ref().filter(|schema| schema.version == 3)
                else {
                    continue;
                };
                let before = self.verified_index_epoch(canonical);
                let source_before = self.db_source_epoch(canonical);
                let accepted_schema =
                    match self.accepted_db_authority_for_root_locked(canonical, content.as_ref()) {
                        Ok(authority) => Self::db_snapshot_from_authority_selected(
                            canonical,
                            storage,
                            &authority,
                            None,
                            Some("dbschema.json"),
                        )
                        .await
                        .ok()
                        .and_then(|snapshot| {
                            snapshot
                                .values
                                .into_iter()
                                .find(|(path, _)| path == "dbschema.json")
                        })
                        .and_then(|(_, value)| serde_json::from_value::<DbSchema>(value).ok())
                        .filter(|schema| {
                            schema.version == 3
                                && epix_content::verify::is_valid_relative_path(&schema.db_file)
                        }),
                        Err(_) => None,
                    };
                let schema = accepted_schema
                    .clone()
                    .unwrap_or_else(|| current_schema.clone());
                let cache = if accepted_schema.is_some() {
                    match self
                        .open_merger_index(key, canonical, storage, &schema, types, filter_epoch)
                        .await
                    {
                        Ok(cache) => Some(cache),
                        Err(error) => {
                            self.log("WARN", format!("merger index {key}: {error}"))
                                .await;
                            None
                        }
                    }
                } else {
                    None
                };
                // Failed authority must not expose any persisted rows. Keep a
                // fresh empty handle only for the existing fail-closed contract.
                let db = if accepted_schema.is_none() {
                    Database::open_in_memory().ok().and_then(|db| {
                        db.apply_schema(&schema).ok()?;
                        Some(db)
                    })
                } else {
                    cache.as_ref().map(|cache| cache.index.database())
                };
                targets.push(Target {
                    key: key.clone(),
                    canonical: canonical.clone(),
                    storage: storage.clone(),
                    schema,
                    types: types.clone(),
                    verified_epoch: before,
                    source_epoch: source_before,
                    cache,
                    db,
                });
            }
            let mut observed = BTreeMap::new();
            let mut retry = false;
            let mut failed = false;
            for (_, canonical, storage, content, _, _) in &registry {
                if observed.contains_key(canonical) {
                    continue;
                }
                let _tree = self.tree_mutation_lock(canonical).lock_owned().await;
                let authority =
                    match self.accepted_db_authority_for_root_locked(canonical, content.as_ref()) {
                        Ok(authority) => authority,
                        Err(_) => continue,
                    };
                let Some(merged_type) = authority
                    .manifests
                    .iter()
                    .find(|manifest| manifest.inner_path == "content.json")
                    .and_then(|manifest| manifest.content.get("merged_type"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                let receipt = SourceReceipt {
                    storage_root: storage.root().to_path_buf(),
                    verified_epoch: self.verified_index_epoch(canonical),
                    source_epoch: self.db_source_epoch(canonical),
                    merged_type: merged_type.to_string(),
                };
                let needing = targets
                    .iter()
                    .enumerate()
                    .filter_map(|(index, target)| {
                        let cache = target.cache.as_ref()?;
                        (target.types.iter().any(|kind| kind == merged_type)
                            && cache.sources.get(canonical) != Some(&receipt))
                        .then_some(index)
                    })
                    .collect::<Vec<_>>();
                if needing.is_empty() {
                    observed.insert(canonical.clone(), receipt);
                    self.merger_index_counters.lock().unwrap().reused_hubs += 1;
                    continue;
                }
                if self.db_merger_epoch() != merger_epoch || self.db_filter_epoch() != filter_epoch
                {
                    retry = true;
                    break;
                }
                let snapshot =
                    match Self::db_snapshot_from_authority(canonical, storage, &authority).await {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            self.log(
                                "WARN",
                                format!("merger source {canonical} unavailable: {error}"),
                            )
                            .await;
                            continue;
                        }
                    };
                self.merger_index_counters
                    .lock()
                    .unwrap()
                    .verified_input_files += snapshot.values.len() as u64;
                let authority_hash = match authority_digest(&authority) {
                    Ok(hash) => hash,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                };
                let indices = needing
                    .iter()
                    .map(|index| targets[*index].cache.as_ref().unwrap().index.clone())
                    .collect::<Vec<_>>();
                let hub = canonical.clone();
                let excluded = muted.clone();
                let result = tokio::task::spawn_blocking(move || {
                    reconcile_hub(&indices, &hub, snapshot.values, &authority_hash, &excluded)
                })
                .await
                .map_err(|error| error.to_string())
                .and_then(|result| result);
                match result {
                    Ok(metrics) => {
                        for metric in metrics {
                            self.count_index_delta(&metric);
                        }
                    }
                    Err(error) => {
                        self.log("WARN", format!("merger source {canonical}: {error}"))
                            .await;
                        failed = true;
                        break;
                    }
                }
                for index in needing {
                    targets[index]
                        .cache
                        .as_mut()
                        .unwrap()
                        .sources
                        .insert(canonical.clone(), receipt.clone());
                }
                observed.insert(canonical.clone(), receipt);
            }
            if failed {
                return;
            }
            if retry {
                tokio::task::yield_now().await;
                continue;
            }
            for target in &mut targets {
                let Some(cache) = &mut target.cache else {
                    continue;
                };
                let keep = observed
                    .iter()
                    .filter(|(_, receipt)| target.types.contains(&receipt.merged_type))
                    .map(|(hub, _)| hub.clone())
                    .collect::<BTreeSet<_>>();
                cache.sources.retain(|hub, _| keep.contains(hub));
                let index = cache.index.clone();
                let result =
                    tokio::task::spawn_blocking(move || -> Result<Vec<DeltaMetrics>, String> {
                        let mut metrics = Vec::new();
                        for source in index.sources_all().map_err(|error| error.to_string())? {
                            if !keep.contains(&source.hub) {
                                metrics.push(
                                    index
                                        .remove_source(&source.hub, &source.path, &source.version)
                                        .map_err(|error| error.to_string())?,
                                );
                            }
                        }
                        Ok(metrics)
                    })
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|result| result);
                match result {
                    Ok(metrics) => {
                        for metric in metrics {
                            self.count_index_delta(&metric);
                        }
                    }
                    Err(error) => {
                        self.log("WARN", format!("merger prune {}: {error}", target.key))
                            .await;
                        failed = true;
                    }
                }
            }
            if failed {
                return;
            }
            #[cfg(test)]
            let pause = self.merger_db_before_install_pause.lock().unwrap().clone();
            #[cfg(test)]
            if let Some((started, release)) = pause {
                started.notify_one();
                let _permit = release.acquire().await;
            }
            let mut canonicals = observed
                .keys()
                .cloned()
                .chain(targets.iter().map(|target| target.canonical.clone()))
                .collect::<Vec<_>>();
            canonicals.sort();
            canonicals.dedup();
            let mut guards = Vec::new();
            for canonical in &canonicals {
                match self.tree_mutation_lock(canonical).try_lock_owned() {
                    Ok(guard) => guards.push(guard),
                    Err(_) => {
                        retry = true;
                        break;
                    }
                }
            }
            if retry {
                drop(guards);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            let mut xites = self.xites.write().await;
            let current = self.db_merger_epoch() == merger_epoch
                && self.db_filter_epoch() == filter_epoch
                && observed.iter().all(|(canonical, receipt)| {
                    self.verified_index_epoch(canonical) == receipt.verified_epoch
                        && self.db_source_epoch(canonical) == receipt.source_epoch
                        && xites.values().any(|xite| {
                            xite.storage.root() == receipt.storage_root
                                && canonical_address(xite.content.as_ref(), canonical) == *canonical
                        })
                })
                && targets.iter().all(|target| {
                    self.verified_index_epoch(&target.canonical) == target.verified_epoch
                        && self.db_source_epoch(&target.canonical) == target.source_epoch
                        && xites.get(&target.key).is_some_and(|xite| {
                            xite.storage.root() == target.storage.root()
                                && canonical_address(xite.content.as_ref(), &target.key)
                                    == target.canonical
                                && xite
                                    .settings
                                    .permissions
                                    .iter()
                                    .filter_map(|p| p.strip_prefix("Merger:").map(String::from))
                                    .collect::<Vec<_>>()
                                    == target.types
                        })
                });
            if !current {
                drop(xites);
                drop(guards);
                tokio::task::yield_now().await;
                continue;
            }
            let retired = {
                let keep = targets
                    .iter()
                    .filter_map(|target| {
                        target.cache.as_ref().map(|cache| cache.fingerprint.clone())
                    })
                    .collect::<BTreeSet<_>>();
                let mut caches = self.merger_indexes.lock().unwrap();
                let retired = caches
                    .values()
                    .filter(|cache| !keep.contains(&cache.fingerprint))
                    .map(|cache| cache.index.clone())
                    .collect::<Vec<_>>();
                caches.retain(|key, _| targets.iter().any(|target| &target.key == key));
                for target in targets {
                    let Some(xite) = xites.get_mut(&target.key) else {
                        continue;
                    };
                    xite.db = target.db;
                    xite.db_schema = Some(target.schema);
                    xite.db_verified_epoch = target.verified_epoch;
                    xite.db_source_epoch = target.source_epoch;
                    xite.db_merger_epoch = merger_epoch;
                    xite.db_generation = self.next_db_generation();
                    xite.db_filter_epoch = filter_epoch;
                    if let Some(cache) = target.cache {
                        cache.publication.published.store(true, Ordering::Release);
                        caches.insert(target.key, cache);
                    } else {
                        caches.remove(&target.key);
                    }
                }
                retired
            };
            drop(xites);
            drop(guards);
            self.retire_merger_indexes(retired).await;
            return;
        }
    }

    async fn retire_merger_indexes(&self, retired: Vec<DerivedIndex>) {
        let errors = tokio::task::spawn_blocking(move || {
            retired
                .into_iter()
                .filter_map(|index| index.retire().err().map(|error| error.to_string()))
                .collect::<Vec<_>>()
        })
        .await;
        if let Ok(errors) = errors {
            for error in errors {
                self.log("WARN", format!("merger cache retirement: {error}"))
                    .await;
            }
        }
    }
}

fn reconcile_hub(
    indices: &[DerivedIndex],
    hub: &str,
    values: Vec<(String, Value)>,
    authority: &str,
    muted: &[String],
) -> Result<Vec<DeltaMetrics>, String> {
    let mut retained = BTreeSet::new();
    let mut metrics = Vec::new();
    for (path, value) in values {
        if muted
            .iter()
            .any(|entry| format!("{hub}/{path}").contains(entry))
        {
            continue;
        }
        retained.insert(path.clone());
        let version = SourceVersion {
            digest: digest(&value)?,
            authority: authority.to_string(),
        };
        for index in indices {
            let previous = index
                .source(hub, &path)
                .map_err(|error| error.to_string())?;
            metrics.push(
                index
                    .apply_source(hub, &path, &version, &value, previous.as_ref())
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    for index in indices {
        for source in index.sources(hub).map_err(|error| error.to_string())? {
            if !retained.contains(&source.path) {
                metrics.push(
                    index
                        .remove_source(hub, &source.path, &source.version)
                        .map_err(|error| error.to_string())?,
                );
            }
        }
    }
    Ok(metrics)
}

pub(super) struct VerifiedInputDelta {
    pub canonical: String,
    pub storage: XiteStorage,
    pub content: Option<Value>,
    pub verified_epoch: u64,
    pub source_epoch: u64,
    pub previous_merger_epoch: u64,
    pub merger_epoch: u64,
    pub filter_epoch: u64,
    pub path: String,
    pub value: Value,
    pub authority: String,
    pub merged_type: String,
}

impl AppState {
    /// The fast path applies one verified input only when every installed
    /// projection covered the immediately preceding global source generation.
    /// Any concurrent or already pending change falls back to reconciliation.
    pub(super) async fn update_merger_input(&self, delta: VerifiedInputDelta) -> bool {
        let state = self.owned_state();
        match tokio::spawn(async move { state.update_merger_input_inner(delta).await }).await {
            Ok(updated) => updated,
            Err(error) => {
                self.log("WARN", format!("merger update completion failed: {error}"))
                    .await;
                false
            }
        }
    }

    async fn update_merger_input_inner(&self, delta: VerifiedInputDelta) -> bool {
        let _writer = self.merger_index_refresh.lock().await;
        let _tree = self.tree_mutation_lock(&delta.canonical).lock_owned().await;
        if delta.merger_epoch != delta.previous_merger_epoch.saturating_add(1)
            || self.db_merger_epoch() != delta.merger_epoch
            || self.db_filter_epoch() != delta.filter_epoch
            || self.db_source_epoch(&delta.canonical) != delta.source_epoch
            || self.verified_index_epoch(&delta.canonical) != delta.verified_epoch
        {
            return false;
        }
        let muted = self.muted_authors().await;
        if muted
            .iter()
            .any(|entry| format!("{}/{}", delta.canonical, delta.path).contains(entry))
        {
            // Reconciliation retires the input and advances the receipt without
            // ever inserting a muted hub through the single-file path.
            return false;
        }
        let mut targets = Vec::new();
        {
            let mut xites = self.xites.write().await;
            if !xites.values().any(|xite| {
                xite.storage.root() == delta.storage.root()
                    && canonical_address(xite.content.as_ref(), &delta.canonical) == delta.canonical
                    && xite.content == delta.content
            }) {
                return false;
            }
            let caches = self.merger_indexes.lock().unwrap();
            for (key, xite) in xites.iter() {
                if !xite
                    .db_schema
                    .as_ref()
                    .is_some_and(|schema| schema.version == 3)
                {
                    continue;
                }
                let Some(cache) = caches.get(key) else {
                    return false;
                };
                if xite.db.is_none()
                    || xite.db_merger_epoch != delta.previous_merger_epoch
                    || xite.db_filter_epoch != delta.filter_epoch
                {
                    return false;
                }
                let interested = xite
                    .settings
                    .permissions
                    .iter()
                    .any(|permission| permission == &format!("Merger:{}", delta.merged_type));
                if interested
                    && !cache.sources.get(&delta.canonical).is_some_and(|receipt| {
                        receipt.verified_epoch == delta.verified_epoch
                            && receipt.storage_root == delta.storage.root()
                            && receipt.source_epoch.saturating_add(1) == delta.source_epoch
                            && receipt.merged_type == delta.merged_type
                    })
                {
                    return false;
                }
                targets.push((
                    key.clone(),
                    canonical_address(xite.content.as_ref(), key),
                    xite.storage.root().to_path_buf(),
                    xite.db_source_epoch,
                    xite.db_verified_epoch,
                    interested,
                    cache.clone(),
                    0,
                ));
            }
            for (key, _, _, _, _, _, _, generation) in &mut targets {
                let xite = xites.get_mut(key).unwrap();
                xite.db = None;
                xite.db_generation = self.next_db_generation();
                *generation = xite.db_generation;
            }
        }
        if targets.is_empty() {
            return true;
        }
        let indices = targets
            .iter()
            .filter(|target| target.5)
            .map(|target| target.6.index.clone())
            .collect::<Vec<_>>();
        let hub = delta.canonical.clone();
        let path = delta.path.clone();
        let version = match digest(&delta.value) {
            Ok(hash) => SourceVersion {
                digest: hash,
                authority: delta.authority.clone(),
            },
            Err(_) => return false,
        };
        let value = delta.value;
        self.merger_index_counters
            .lock()
            .unwrap()
            .verified_input_files += 1;
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<DeltaMetrics>, String> {
            let mut metrics = Vec::new();
            for index in indices {
                let old = index
                    .source(&hub, &path)
                    .map_err(|error| error.to_string())?;
                metrics.push(
                    index
                        .apply_source(&hub, &path, &version, &value, old.as_ref())
                        .map_err(|error| error.to_string())?,
                );
            }
            Ok(metrics)
        })
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result);
        match result {
            Ok(metrics) => {
                for metric in metrics {
                    self.count_index_delta(&metric);
                }
            }
            Err(error) => {
                self.log("WARN", format!("merger incremental update: {error}"))
                    .await;
                return false;
            }
        }
        let mut other_trees = targets
            .iter()
            .map(|target| target.1.clone())
            .filter(|canonical| canonical != &delta.canonical)
            .collect::<Vec<_>>();
        other_trees.sort();
        other_trees.dedup();
        let mut guards = Vec::new();
        for canonical in other_trees {
            match self.tree_mutation_lock(&canonical).try_lock_owned() {
                Ok(guard) => guards.push(guard),
                Err(_) => return false,
            }
        }
        let mut xites = self.xites.write().await;
        if self.db_merger_epoch() != delta.merger_epoch
            || self.db_filter_epoch() != delta.filter_epoch
            || targets.iter().any(
                |(key, canonical, storage, source, verified, _, _, generation)| {
                    self.db_source_epoch(canonical) != *source
                        || self.verified_index_epoch(canonical) != *verified
                        || !xites.get(key).is_some_and(|xite| {
                            xite.storage.root() == storage
                                && canonical_address(xite.content.as_ref(), key) == *canonical
                                && xite.db_generation == *generation
                        })
                },
            )
        {
            return false;
        }
        let mut caches = self.merger_indexes.lock().unwrap();
        for (key, _, _, _, _, interested, mut cache, _) in targets {
            if interested {
                cache.sources.insert(
                    delta.canonical.clone(),
                    SourceReceipt {
                        storage_root: delta.storage.root().to_path_buf(),
                        verified_epoch: delta.verified_epoch,
                        source_epoch: delta.source_epoch,
                        merged_type: delta.merged_type.clone(),
                    },
                );
            }
            let xite = xites.get_mut(&key).unwrap();
            xite.db = Some(cache.index.database());
            xite.db_merger_epoch = delta.merger_epoch;
            xite.db_generation = self.next_db_generation();
            caches.insert(key, cache);
        }
        true
    }

    pub(super) fn merger_authority_digest(
        authority: &VerifiedDbAuthority,
    ) -> Result<String, String> {
        authority_digest(authority)
    }
}

impl AppState {
    pub(super) async fn reset_merger_index(&self, address: &str) -> bool {
        let state = self.owned_state();
        let key = address.to_string();
        tokio::spawn(async move {
            let _writer = state.merger_index_refresh.lock().await;
            let cached = state.merger_indexes.lock().unwrap().get(&key).cloned();
            let Some(cached) = cached else {
                return true;
            };
            {
                let mut xites = state.xites.write().await;
                let caches = state.merger_indexes.lock().unwrap();
                for (other, cache) in caches
                    .iter()
                    .filter(|(_, cache)| cache.fingerprint == cached.fingerprint)
                {
                    let _ = cache;
                    if let Some(xite) = xites.get_mut(other) {
                        xite.db = None;
                        xite.db_generation = state.next_db_generation();
                    }
                }
            }
            let index = cached.index.clone();
            let result = tokio::task::spawn_blocking(move || index.reset()).await;
            match result {
                Ok(Ok(metrics)) => {
                    state.count_index_delta(&metrics);
                    state.merger_index_counters.lock().unwrap().explicit_resets += 1;
                    for cache in state.merger_indexes.lock().unwrap().values_mut() {
                        if cache.fingerprint == cached.fingerprint {
                            cache.sources.clear();
                        }
                    }
                    true
                }
                other => {
                    state
                        .log("WARN", format!("merger index reset failed: {other:?}"))
                        .await;
                    false
                }
            }
        })
        .await
        .unwrap_or(false)
    }
}
