use super::protocol::{self, Keys};
use crate::state::{
    read_regular_xite_file_bounded, AppState, ManifestGuard, UpdatePayload, VerifiedDbAuthority,
};
use epix_core::Address;
use epix_xite::{Xite, XiteStorage};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;

pub(super) const MAX_DOCUMENT: u64 = 512 * 1024;
const MAX_DOCUMENTS: usize = 64;
const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Document {
    pub format: String,
    pub revision: u64,
    pub profile: Option<Value>,
    pub public_messages: Vec<Value>,
    pub private_messages: Vec<Value>,
}
impl Default for Document {
    fn default() -> Self {
        Self {
            format: protocol::PROTOCOL.into(),
            revision: 0,
            profile: None,
            public_messages: Vec::new(),
            private_messages: Vec::new(),
        }
    }
}
impl Document {
    fn parse(value: Value) -> Result<Self, String> {
        let doc: Self =
            serde_json::from_value(value).map_err(|_| "Invalid local profile document")?;
        if doc.format != protocol::PROTOCOL
            || doc.public_messages.len() > 128
            || doc.private_messages.len() > 32
        {
            return Err("Local profile document exceeds limits".into());
        }
        Ok(doc)
    }
    pub fn append(&mut self, record: Value) -> Result<(), String> {
        match record["kind"].as_str() {
            Some("profile") => self.profile = Some(record),
            Some("public") => self.public_messages.push(record),
            Some("private") => self.private_messages.push(record),
            _ => return Err("Invalid mutation record".into()),
        }
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or("Local profile revision exhausted")?;
        while self.public_messages.len() > 128 {
            self.public_messages.remove(0);
        }
        while self.private_messages.len() > 32 {
            self.private_messages.remove(0);
        }
        while serde_json::to_vec(self).map_err(|e| e.to_string())?.len() as u64 > MAX_DOCUMENT {
            let public_time = self
                .public_messages
                .first()
                .and_then(|v| v["sent_at"].as_u64())
                .unwrap_or(u64::MAX);
            let private_time = self
                .private_messages
                .first()
                .and_then(|v| v["sent_at"].as_u64())
                .unwrap_or(u64::MAX);
            if public_time == u64::MAX && private_time == u64::MAX {
                return Err("Profile exceeds document limit".into());
            }
            if public_time <= private_time {
                self.public_messages.remove(0);
            } else {
                self.private_messages.remove(0);
            }
        }
        Ok(())
    }
}

pub(super) struct Documents {
    pub docs: Vec<(String, Document)>,
    pub truncated: bool,
    pub rejected: usize,
}

fn read_manifest(storage: &XiteStorage, path: &str, budget: &mut u64) -> Result<Value, String> {
    let limit = MAX_DOCUMENT.min(*budget);
    let bytes = read_regular_xite_file_bounded(storage, path, limit).map_err(|_| {
        if limit < MAX_DOCUMENT {
            *budget = 0;
            "Local profile read budget exhausted"
        } else {
            "Signed authority unavailable"
        }
    })?;
    *budget -= bytes.len() as u64;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid signed authority".into())
}

fn matching_authority(
    storage: &XiteStorage,
    authority: &VerifiedDbAuthority,
    path: &str,
    checked: &mut HashSet<String>,
    budget: &mut u64,
) -> Result<(), String> {
    let chain = authority
        .manifest_chains
        .get(path)
        .ok_or("Missing accepted authority chain")?;
    for parent in std::iter::once("content.json").chain(chain.iter().map(String::as_str)) {
        if !checked.contains(parent) {
            let expected = authority
                .manifests
                .iter()
                .find(|unit| unit.inner_path == parent)
                .ok_or("Missing accepted authority")?;
            if read_manifest(storage, parent, budget)? != expected.content {
                return Err("Signed authority changed on disk".into());
            }
            checked.insert(parent.to_string());
        }
    }
    Ok(())
}

fn read_document(
    storage: &XiteStorage,
    manifest: &Value,
    author: &str,
) -> Result<Document, String> {
    let path = format!("data/users/{author}/data.json");
    let entry = &manifest["files"]["data.json"];
    let size = entry["size"]
        .as_u64()
        .ok_or("Missing signed profile data")?;
    if size > MAX_DOCUMENT {
        return Err("Local profile document exceeds limit".into());
    }
    let bytes = read_regular_xite_file_bounded(storage, &path, size)
        .map_err(|_| "Signed profile data unavailable or changed")?;
    if bytes.len() as u64 != size {
        return Err("Signed profile data size mismatch".into());
    }
    let sha = entry["sha512"]
        .as_str()
        .ok_or("Missing signed profile digest")?;
    if XiteStorage::hash_bytes(&bytes) != sha {
        return Err("Signed profile data digest mismatch".into());
    }
    if let Some(b3) = entry.get("b3") {
        if b3.as_str() != Some(epix_blob::ObjId::of(&bytes).to_string().as_str()) {
            return Err("Signed profile object digest mismatch".into());
        }
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| "Invalid profile document JSON")?;
    Document::parse(value)
}

fn profile_author(path: &str) -> Option<&str> {
    path.strip_prefix("data/users/")?
        .strip_suffix("/content.json")
        .filter(|author| epix_crypt::is_valid_address(author))
}

impl AppState {
    /// Validate the current accepted root before deriving any local identity.
    /// The scope was captured at registration, not read from an editable draft.
    pub(super) async fn local_profile_canonical(&self, address: &str) -> Result<String, String> {
        let _activation = self.activation_read_fresh().await;
        let (storage, canonical, root) = {
            let xites = self.xites.read().await;
            let entry = xites.get(address).ok_or("Unknown xite")?;
            (
                entry.storage.clone(),
                entry
                    .local_profile_address
                    .clone()
                    .ok_or("No registered local profile scope")?,
                entry.content.clone(),
            )
        };
        let _tree = self.tree_mutation_lock(&canonical).lock_owned().await;
        let authority = self.accepted_db_authority_for_root_locked(&canonical, root.as_ref())?;
        let accepted = authority
            .manifests
            .iter()
            .find(|unit| unit.inner_path == "content.json")
            .ok_or("Missing accepted root")?;
        let mut budget = MAX_DOCUMENT;
        if accepted.content["address"].as_str() != Some(canonical.as_str())
            || read_manifest(&storage, "content.json", &mut budget)? != accepted.content
        {
            return Err("Local profile root authority changed".into());
        }
        Ok(canonical)
    }

    pub(super) async fn local_documents(
        &self,
        address: &str,
        preferred: &str,
    ) -> Result<Documents, String> {
        let _activation = self.activation_read_fresh().await;
        let (storage, canonical, root) = {
            let xites = self.xites.read().await;
            let entry = xites.get(address).ok_or("Unknown xite")?;
            (
                entry.storage.clone(),
                entry
                    .local_profile_address
                    .clone()
                    .ok_or("No registered local profile scope")?,
                entry.content.clone(),
            )
        };
        let _tree = self.tree_mutation_lock(&canonical).lock_owned().await;
        let mut authority =
            self.accepted_db_authority_for_root_locked(&canonical, root.as_ref())?;
        let preferred_path = format!("data/users/{preferred}/content.json");
        authority
            .manifests
            .sort_by_key(|unit| unit.inner_path != preferred_path);
        let mut checked = HashSet::new();
        let mut result = Documents {
            docs: Vec::new(),
            truncated: false,
            rejected: 0,
        };
        let mut remaining = MAX_READ_BYTES;
        let candidates = authority
            .manifests
            .iter()
            .filter_map(|unit| profile_author(&unit.inner_path).map(|author| (unit, author)));
        for (scanned, (unit, author)) in candidates.enumerate() {
            if scanned >= MAX_DOCUMENTS * 2 || result.docs.len() >= MAX_DOCUMENTS {
                result.truncated = true;
                break;
            }
            let size = unit.content["files"]["data.json"]["size"]
                .as_u64()
                .unwrap_or(MAX_DOCUMENT + 1);
            if size > MAX_DOCUMENT {
                result.rejected += 1;
                continue;
            }
            if size > remaining {
                result.truncated = true;
                break;
            }
            remaining -= size;
            let doc = matching_authority(
                &storage,
                &authority,
                &unit.inner_path,
                &mut checked,
                &mut remaining,
            )
            .and_then(|()| read_document(&storage, &unit.content, author));
            match doc {
                Ok(doc) => result.docs.push((author.to_string(), doc)),
                Err(_) => {
                    result.rejected += 1;
                    if remaining == 0 {
                        result.truncated = true;
                        break;
                    }
                }
            }
        }
        Ok(result)
    }

    /// Commit only the native identity's fixed data file. The existing child
    /// transaction validates current parent rules and promotes data+manifest
    /// together, including Store receipts and rollback. No unsigned live write.
    pub(super) async fn local_commit(
        &self,
        address: &str,
        keys: &Keys,
        expected: u64,
        record: Value,
        origin: u64,
    ) -> Result<(), String> {
        let activation = self.activation_read_fresh().await;
        let (storage, canonical, root) = {
            let xites = self.xites.read().await;
            let entry = xites.get(address).ok_or("Unknown xite")?;
            (
                entry.storage.clone(),
                entry
                    .local_profile_address
                    .clone()
                    .ok_or("No registered local profile scope")?,
                entry.content.clone(),
            )
        };
        if canonical != keys.xite {
            return Err("Local profile xite changed".into());
        }
        let path = format!("data/users/{}/content.json", keys.author);
        let data_path = format!("data/users/{}/data.json", keys.author);
        let manifest = self.acquire_manifest_mutex(&canonical, &path).await?;
        let tree = self.tree_mutation_lock(&canonical).lock_owned().await;
        let authority = self.accepted_db_authority_for_root_locked(&canonical, root.as_ref())?;
        let existing = authority
            .manifests
            .iter()
            .find(|unit| unit.inner_path == path);
        let mut doc = if let Some(unit) = existing {
            let mut budget = MAX_READ_BYTES;
            matching_authority(
                &storage,
                &authority,
                &path,
                &mut HashSet::new(),
                &mut budget,
            )?;
            read_document(&storage, &unit.content, &keys.author)?
        } else {
            if storage.exists(&path) || storage.exists(&data_path) {
                return Err("Unverified profile files must be repaired before writing".into());
            }
            Document::default()
        };
        if doc.revision != expected {
            return Err("Profile changed; reload before sending".into());
        }
        doc.append(record)?;
        let bytes = serde_json::to_vec(&doc).map_err(|e| e.to_string())?;
        let previous = existing
            .and_then(|u| u.content["modified"].as_f64())
            .unwrap_or(0.0);
        let mut signed = json!({"address":canonical,"inner_path":path,"modified":(epix_core::now_secs() as f64).max(previous+1.0),
            "files":{"data.json":{"size":bytes.len(),"sha512":XiteStorage::hash_bytes(&bytes),"b3":epix_blob::ObjId::of(&bytes).to_string()}}});
        keys.manifest_sign(&mut signed)?;
        let signed_bytes = epix_content::dumps_content(&signed).into_bytes();
        let files = Self::signed_child_required_files(&path, &signed)?;
        let transaction = Self::bind_manifest_transaction(
            &storage,
            &canonical,
            &path,
            &signed_bytes,
            ManifestGuard {
                _activation: Some(activation),
                _manifest: Some(manifest),
            },
        )?;
        let staged = transaction
            .lease
            .register_staged(&storage, &data_path, None)?;
        XiteStorage::new(transaction.lease.stage_root.clone())
            .write_atomic_durable(&staged, &bytes)
            .map_err(|e| e.to_string())?;
        drop(tree);
        let xite = Xite::new(
            Address::parse(canonical.clone()).map_err(|e| e.to_string())?,
            storage.clone(),
        );
        self.commit_child_candidate(
            address,
            &xite,
            &path,
            &signed_bytes,
            &files,
            &transaction,
            &mut UpdatePayload::default(),
        )
        .await?;
        self.verify_current_store_xite_activated(address, &canonical, &storage)
            .await?;
        transaction.lease.release_activation();
        self.ingest_file_from(address, &path, Some(origin)).await;
        Ok(())
    }
}
