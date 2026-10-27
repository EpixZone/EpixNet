//! Native-only xite addon verification and durable profile receipts.
//!
//! Xite provenance is separate from engine signature/compatibility checks.
//! Gecko adapters must additionally verify Mozilla signatures. Nothing here
//! exposes an installer command to a page or grants native messaging access.
mod package;
pub(crate) use package::{inspect_package, parse_source, unique_json};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub const MAX_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024;
pub const CANDIDATE_LIFETIME_MS: u64 = 300_000;
pub(crate) const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_AUTHORITY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_LEDGER_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_MANAGED_ADDONS: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddonEngine {
    Gecko,
    WebKit,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddonAction {
    Install,
    Update { addon_id: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonPrepareRequest {
    pub session_id: String,
    pub source_url: String,
    pub action: AddonAction,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddonCandidate {
    pub operation_id: String,
    pub source_url: String,
    pub publisher: String,
    pub inner_path: String,
    pub governing_manifest: String,
    pub archive_sha256: String,
    pub byte_length: u64,
    pub addon_id: String,
    pub version: String,
    pub name: String,
    pub manifest_version: u32,
    pub required_permissions: Vec<String>,
    pub optional_permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub optional_host_permissions: Vec<String>,
    pub expires_at_ms: u64,
    pub engine: AddonEngine,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddonPhase {
    Preparing,
    Ready,
    HandedOff,
    Staged,
    Installed,
    Cancelled,
    Failed,
    NeedsReconciliation,
    Uninstalling,
    Uninstalled,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonSnapshot {
    pub uninstall_id: Option<String>,
    pub operation_id: String,
    pub phase: AddonPhase,
    pub candidate: Option<AddonCandidate>,
    pub message: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddonOwnership {
    pub addon_id: String,
    pub version: String,
    pub archive_sha256: String,
    pub publisher: String,
    pub inner_path: String,
    pub source_url: String,
    pub engine: AddonEngine,
}
impl From<&AddonCandidate> for AddonOwnership {
    fn from(c: &AddonCandidate) -> Self {
        Self {
            addon_id: c.addon_id.clone(),
            version: c.version.clone(),
            archive_sha256: c.archive_sha256.clone(),
            publisher: c.publisher.clone(),
            inner_path: c.inner_path.clone(),
            source_url: c.source_url.clone(),
            engine: c.engine,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonSession {
    pub session_id: String,
    pub profile_id: String,
    pub engine: AddonEngine,
    pub needs_reconciliation: bool,
    pub managed: Vec<AddonOwnership>,
    pub operation: Option<AddonSnapshot>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonInstalled {
    pub addon_id: String,
    pub version: String,
    pub archive_sha256: Option<String>,
    pub enabled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddonInventory {
    pub addons: Vec<AddonInstalled>,
    pub has_pending_installs: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagedAddon {
    pub candidate: AddonCandidate,
    pub path: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AddonEngineOutcome {
    Installed {
        addon_id: String,
        version: String,
        archive_sha256: String,
    },
    Staged {
        addon_id: String,
        version: String,
        archive_sha256: String,
    },
    Uninstalled {
        addon_id: String,
    },
    Cancelled,
    Failed {
        reason: String,
    },
    Unknown {
        reason: String,
    },
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddonErrorCode {
    InvalidRequest,
    UnsupportedSource,
    MissingLocalFile,
    UnverifiedAuthority,
    ChangedAuthority,
    InvalidPackage,
    LimitExceeded,
    Cancelled,
    Expired,
    Busy,
    NeedsReconciliation,
    Io,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddonError {
    pub code: AddonErrorCode,
    pub message: String,
}
impl AddonError {
    pub(crate) fn new(code: AddonErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            code,
            message: message.chars().take(512).collect(),
        }
    }
}
impl std::fmt::Display for AddonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for AddonError {}
impl From<std::io::Error> for AddonError {
    fn from(e: std::io::Error) -> Self {
        Self::new(AddonErrorCode::Io, e.to_string())
    }
}
pub(crate) type Result<T, E = AddonError> = std::result::Result<T, E>;
pub(crate) fn fail<T>(code: AddonErrorCode, message: impl Into<String>) -> Result<T> {
    Err(AddonError::new(code, message))
}
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
pub(crate) fn random_id() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| AddonError::new(AddonErrorCode::Io, e.to_string()))?;
    Ok(hex::encode(bytes))
}
pub(crate) fn valid_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Acquire) {
        fail(AddonErrorCode::Cancelled, "Operation cancelled")
    } else {
        Ok(())
    }
}

pub(crate) fn check_managed_count(count: usize) -> Result<()> {
    if count > MAX_MANAGED_ADDONS {
        fail(
            AddonErrorCode::LimitExceeded,
            "Managed extension limit reached",
        )
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ledger {
    pub schema: u32,
    pub profile_id: String,
    pub engine: AddonEngine,
    pub managed: Vec<AddonOwnership>,
    pub pending: Option<AddonSnapshot>,
    pub uninstall_id: Option<String>,
    // Retain the exact terminal operation across a lost native mirror/reply.
    // This is recovery evidence, never permission to hand off another archive.
    #[serde(default)]
    pub completed: Option<AddonSnapshot>,
}
pub(crate) struct Profile {
    pub session_id: String,
    pub ledger: Ledger,
    pub reconciled: bool,
    pub inventory: AddonInventory,
    pub operation: Option<AddonSnapshot>,
    pub cancel: Arc<AtomicBool>,
    pub stamp: Option<crate::state::addon_install::AuthorityStamp>,
    pub directory: crate::data_relocation::ProtectedDirectory,
}
impl Profile {
    pub fn snapshot(&self) -> AddonSession {
        AddonSession {
            session_id: self.session_id.clone(),
            profile_id: self.ledger.profile_id.clone(),
            engine: self.ledger.engine,
            needs_reconciliation: !self.reconciled,
            managed: self.ledger.managed.clone(),
            operation: self.operation.clone(),
        }
    }
    pub fn save(&self) -> Result<()> {
        check_managed_count(self.ledger.managed.len())?;
        let bytes = serde_json::to_vec(&self.ledger)
            .map_err(|e| AddonError::new(AddonErrorCode::Io, e.to_string()))?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return fail(AddonErrorCode::LimitExceeded, "Too many addon receipts");
        }
        self.directory.write("receipts.json", &bytes)?;
        Ok(())
    }
    pub fn pending(&self) -> bool {
        self.operation.as_ref().is_some_and(|o| {
            matches!(
                o.phase,
                AddonPhase::Preparing
                    | AddonPhase::Ready
                    | AddonPhase::HandedOff
                    | AddonPhase::Staged
                    | AddonPhase::NeedsReconciliation
                    | AddonPhase::Uninstalling
            )
        })
    }
}
#[derive(Default)]
pub(crate) struct Profiles(pub HashMap<String, Profile>);
impl Profiles {
    pub fn session_mut(&mut self, session: &str) -> Result<&mut Profile> {
        if !valid_id(session) {
            return fail(AddonErrorCode::InvalidRequest, "Invalid session");
        }
        self.0
            .values_mut()
            .find(|p| p.session_id == session)
            .ok_or_else(|| {
                AddonError::new(
                    AddonErrorCode::InvalidRequest,
                    "Stale or unknown native session",
                )
            })
    }
}
