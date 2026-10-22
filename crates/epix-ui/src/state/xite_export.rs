//! Bind an export to the currently accepted public manifest tree.
use super::*;
use crate::xite_zip::{ExportInput, MergeRule};
use std::collections::HashSet;

struct MergeUnit {
    declaration: VerifiedFileDeclaration,
    paths: Vec<(String, String)>,
}

#[derive(Default)]
struct StringBudget {
    count: usize,
    bytes: usize,
}

impl StringBudget {
    fn charge(&mut self, signers: &[String], label: &str) -> Result<(), String> {
        self.count = self
            .count
            .checked_add(signers.len())
            .filter(|n| *n <= 65_536)
            .ok_or_else(|| format!("Xite export exceeds the {label} count limit"))?;
        for signer in signers {
            self.bytes = self
                .bytes
                .checked_add(signer.len())
                .filter(|n| *n <= 8 * 1024 * 1024)
                .ok_or_else(|| format!("Xite export exceeds the {label} size limit"))?;
        }
        Ok(())
    }
}

pub(crate) struct ExportStamp {
    address: String,
    storage_root: PathBuf,
    managed_root: Option<Value>,
    verified_epoch: u64,
    source_epoch: u64,
}

impl AppState {
    pub(crate) async fn xite_export_snapshot(
        &self,
        address: &str,
    ) -> Result<(ExportInput, ExportStamp), String> {
        let activation = self.xite_activation_gate.clone().read_owned().await;
        let (storage, managed_root) = {
            let xites = self.xites.read().await;
            let xite = xites.get(address).ok_or("Xite is no longer available")?;
            if canonical_address(xite.content.as_ref(), address) != address {
                return Err("Xite address changed before export".into());
            }
            if let Some(root) = &xite.content {
                crate::xite_zip::validate_manifest_values(std::iter::once(root))?;
            }
            (xite.storage.clone(), xite.content.clone())
        };
        let tree = self.tree_mutation_lock(address).lock_owned().await;
        {
            let indexed = self
                .verified_manifest_contents
                .read()
                .expect("verified_manifest_contents");
            let values = indexed
                .get(address)
                .ok_or("Verified manifest tree is unavailable")?;
            // Check the borrowed index before cloning it. A count-only limit
            // still allows large chunk maps to exhaust a mobile node's memory.
            crate::xite_zip::validate_manifest_values(values.values())?;
        }
        {
            let indexed = self
                .verified_manifest_chains
                .read()
                .expect("verified_manifest_chains");
            let chains = indexed
                .get(address)
                .ok_or("Verified manifest chains are unavailable")?;
            let mut budget = StringBudget::default();
            for chain in chains.values() {
                budget.charge(chain, "authority chain")?;
            }
        }
        let authority =
            self.accepted_db_authority_for_root_locked(address, managed_root.as_ref())?;
        // Bound snapshot metadata and identity resolution before allocating
        // archive entries. The writer applies its own byte and entry limits.
        if authority.manifests.len() > 8192 {
            return Err("Xite export exceeds the manifest count limit".into());
        }
        let stamp = ExportStamp {
            address: address.to_owned(),
            storage_root: storage.root().to_path_buf(),
            managed_root,
            verified_epoch: self.verified_index_epoch(address),
            source_epoch: self.db_source_epoch(address),
        };
        if !self.xite_export_matches_locked(&stamp).await {
            return Err("Xite changed before export".into());
        }
        let contents: HashMap<_, _> = authority
            .manifests
            .iter()
            .map(|unit| (unit.inner_path.clone(), unit.content.clone()))
            .collect();
        let mut merged_units: HashMap<String, MergeUnit> = HashMap::new();
        let mut merged_count = 0;
        let mut names = HashSet::new();
        for unit in &authority.manifests {
            let directory = unit.inner_path.strip_suffix("/content.json").unwrap_or("");
            for relative in epix_content::declared_merge_files(&unit.content) {
                merged_count += 1;
                if merged_count > 8192 {
                    return Err("Xite export exceeds the merge file count limit".into());
                }
                let path = if directory.is_empty() {
                    relative.clone()
                } else {
                    format!("{directory}/{relative}")
                };
                if path.len() > 1024 || !epix_content::verify::is_valid_relative_path(&path) {
                    return Err("Unsafe merge file path".into());
                }
                // A governing manifest has one signer policy. Keep its chain
                // and resolve its names once, rather than once per file.
                if !merged_units.contains_key(&unit.inner_path) {
                    let declaration = self
                        .verified_file_declaration(
                            address,
                            &path,
                            VerifiedDeclarationSection::Merged,
                        )
                        .ok_or_else(|| format!("Unverified merge file: {path}"))?;
                    if declaration.governing != unit.inner_path {
                        return Err(format!("Ambiguous merge file declaration: {path}"));
                    }
                    for name in Self::merge_authority_xid_names(&declaration, &contents)? {
                        names.insert(name);
                        if names.len() > 8192 {
                            return Err("Xite export exceeds the identity count limit".into());
                        }
                    }
                    merged_units.insert(
                        unit.inner_path.clone(),
                        MergeUnit {
                            declaration,
                            paths: Vec::new(),
                        },
                    );
                }
                merged_units
                    .get_mut(&unit.inner_path)
                    .expect("inserted merge unit")
                    .paths
                    .push((path, relative));
            }
        }
        let store = self.edx_store().await;
        drop(tree);
        drop(activation);
        // Only merge signer identities may need chain proofs. No xite content
        // is cloned, downloaded, or requested from peers by an export.
        let xid_map = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Self::resolve_xid_names_checked(names.into_iter().collect()),
        )
        .await
        .map_err(|_| "Merge signer verification is unavailable".to_string())??;
        let mut merged = HashMap::new();
        let mut signer_budget = StringBudget::default();
        let context = VerifiedAuthorityContext {
            canonical: address,
            contents: &contents,
            xid_map: &xid_map,
            storage: None,
            staged: None,
        };
        for (governing, unit) in merged_units {
            let content = contents
                .get(&governing)
                .ok_or("Verified merge manifest disappeared")?;
            let signers = epix_content::verify::valid_signers(&governing, content, &context);
            signer_budget.charge(&signers, "signer")?;
            let signers = Arc::new(signers);
            let rules =
                epix_content::verify::get_rules(&unit.declaration.governing, content, &context);
            for (path, relative) in unit.paths {
                let max_size = rules
                    .as_ref()
                    .and_then(|rules| rules.get("merge_files"))
                    .and_then(Value::as_object)
                    .and_then(|files| files.get(&relative))
                    .and_then(|rule| rule.get("max_size"))
                    .and_then(Value::as_u64)
                    .unwrap_or(MAX_MERGE_DELTA_OBJECT_BYTES)
                    .min(MAX_MERGE_DELTA_OBJECT_BYTES);
                if merged
                    .insert(
                        path.clone(),
                        MergeRule {
                            signers: signers.clone(),
                            max_size,
                        },
                    )
                    .is_some()
                {
                    return Err(format!("Duplicate merge file declaration: {path}"));
                }
            }
        }
        if !self.xite_export_is_current(&stamp).await {
            return Err("Xite changed during export preparation".into());
        }
        Ok((
            ExportInput {
                spool_directory: self.data_root_path(),
                storage,
                manifests: authority
                    .manifests
                    .into_iter()
                    .map(|unit| (unit.inner_path, unit.content))
                    .collect(),
                store,
                merged,
            },
            stamp,
        ))
    }

    async fn xite_export_matches_locked(&self, stamp: &ExportStamp) -> bool {
        let xites = self.xites.read().await;
        xites.get(&stamp.address).is_some_and(|xite| {
            xite.storage.root() == stamp.storage_root
                && xite.content == stamp.managed_root
                && canonical_address(xite.content.as_ref(), &stamp.address) == stamp.address
                && self.verified_index_epoch(&stamp.address) == stamp.verified_epoch
                && self.db_source_epoch(&stamp.address) == stamp.source_epoch
        })
    }

    pub(crate) async fn xite_export_is_current(&self, stamp: &ExportStamp) -> bool {
        let _activation = self.xite_activation_gate.clone().read_owned().await;
        let _tree = self.tree_mutation_lock(&stamp.address).lock_owned().await;
        self.xite_export_matches_locked(stamp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_signer_policies_cannot_exceed_the_aggregate_metadata_budget() {
        let mut budget = StringBudget {
            count: 65_535,
            bytes: 0,
        };
        assert!(budget.charge(&["a".into(), "b".into()], "signer").is_err());
        let mut budget = StringBudget {
            count: 0,
            bytes: 8 * 1024 * 1024 - 1,
        };
        assert!(budget.charge(&["ab".into()], "signer").is_err());
    }

    #[tokio::test]
    async fn finished_export_rejects_content_merge_and_storage_changes() {
        let directory = tempfile::tempdir().unwrap();
        let key = epix_crypt::new_seed();
        let address = epix_crypt::privatekey_to_address(&key).unwrap();
        let storage = XiteStorage::new(directory.path().join("xite"));
        let mut root = json!({"address": address, "modified": 1, "files": {}, "files_merged": {
            "first.json": {"class": "epix-orset-1"},
            "second.json": {"class": "epix-orset-1"}
        }});
        epix_content::sign(&mut root, &key).unwrap();
        storage
            .write(
                "content.json",
                epix_content::dumps_content(&root).as_bytes(),
            )
            .unwrap();
        let state = AppState::new("export-test");
        state
            .add_xite(
                &address,
                XiteEntry {
                    storage,
                    content: Some(root),
                },
            )
            .await;
        let (input, stamp) = state.xite_export_snapshot(&address).await.unwrap();
        assert!(Arc::ptr_eq(
            &input.merged["first.json"].signers,
            &input.merged["second.json"].signers
        ));
        assert!(state.xite_export_is_current(&stamp).await);
        state.bump_db_source_epoch(&address);
        assert!(!state.xite_export_is_current(&stamp).await);
        let (_, stamp) = state.xite_export_snapshot(&address).await.unwrap();
        state.bump_verified_index_epoch(&address);
        assert!(!state.xite_export_is_current(&stamp).await);
        let (_, stamp) = state.xite_export_snapshot(&address).await.unwrap();
        state.xites.write().await.get_mut(&address).unwrap().storage =
            XiteStorage::new(directory.path().join("replacement"));
        assert!(!state.xite_export_is_current(&stamp).await);
        state.xites.write().await.remove(&address);
        assert!(!state.xite_export_is_current(&stamp).await);
    }
}
