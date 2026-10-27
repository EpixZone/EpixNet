//! Native-only addon API. No web-view bridge forwards these methods.
use crate::{EpixNode, NodeState};
use epix_ui::addons as core;

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddonEngine {
    Gecko,
    WebKit,
}
impl From<AddonEngine> for core::AddonEngine {
    fn from(value: AddonEngine) -> Self {
        match value {
            AddonEngine::Gecko => Self::Gecko,
            AddonEngine::WebKit => Self::WebKit,
        }
    }
}
impl From<core::AddonEngine> for AddonEngine {
    fn from(value: core::AddonEngine) -> Self {
        match value {
            core::AddonEngine::Gecko => Self::Gecko,
            core::AddonEngine::WebKit => Self::WebKit,
        }
    }
}
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
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
impl From<AddonPhase> for core::AddonPhase {
    fn from(value: AddonPhase) -> Self {
        match value {
            AddonPhase::Preparing => Self::Preparing,
            AddonPhase::Ready => Self::Ready,
            AddonPhase::HandedOff => Self::HandedOff,
            AddonPhase::Staged => Self::Staged,
            AddonPhase::Installed => Self::Installed,
            AddonPhase::Cancelled => Self::Cancelled,
            AddonPhase::Failed => Self::Failed,
            AddonPhase::NeedsReconciliation => Self::NeedsReconciliation,
            AddonPhase::Uninstalling => Self::Uninstalling,
            AddonPhase::Uninstalled => Self::Uninstalled,
        }
    }
}
impl From<core::AddonPhase> for AddonPhase {
    fn from(value: core::AddonPhase) -> Self {
        match value {
            core::AddonPhase::Preparing => Self::Preparing,
            core::AddonPhase::Ready => Self::Ready,
            core::AddonPhase::HandedOff => Self::HandedOff,
            core::AddonPhase::Staged => Self::Staged,
            core::AddonPhase::Installed => Self::Installed,
            core::AddonPhase::Cancelled => Self::Cancelled,
            core::AddonPhase::Failed => Self::Failed,
            core::AddonPhase::NeedsReconciliation => Self::NeedsReconciliation,
            core::AddonPhase::Uninstalling => Self::Uninstalling,
            core::AddonPhase::Uninstalled => Self::Uninstalled,
        }
    }
}
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
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
impl From<AddonErrorCode> for core::AddonErrorCode {
    fn from(value: AddonErrorCode) -> Self {
        match value {
            AddonErrorCode::InvalidRequest => Self::InvalidRequest,
            AddonErrorCode::UnsupportedSource => Self::UnsupportedSource,
            AddonErrorCode::MissingLocalFile => Self::MissingLocalFile,
            AddonErrorCode::UnverifiedAuthority => Self::UnverifiedAuthority,
            AddonErrorCode::ChangedAuthority => Self::ChangedAuthority,
            AddonErrorCode::InvalidPackage => Self::InvalidPackage,
            AddonErrorCode::LimitExceeded => Self::LimitExceeded,
            AddonErrorCode::Cancelled => Self::Cancelled,
            AddonErrorCode::Expired => Self::Expired,
            AddonErrorCode::Busy => Self::Busy,
            AddonErrorCode::NeedsReconciliation => Self::NeedsReconciliation,
            AddonErrorCode::Io => Self::Io,
        }
    }
}
impl From<core::AddonErrorCode> for AddonErrorCode {
    fn from(value: core::AddonErrorCode) -> Self {
        match value {
            core::AddonErrorCode::InvalidRequest => Self::InvalidRequest,
            core::AddonErrorCode::UnsupportedSource => Self::UnsupportedSource,
            core::AddonErrorCode::MissingLocalFile => Self::MissingLocalFile,
            core::AddonErrorCode::UnverifiedAuthority => Self::UnverifiedAuthority,
            core::AddonErrorCode::ChangedAuthority => Self::ChangedAuthority,
            core::AddonErrorCode::InvalidPackage => Self::InvalidPackage,
            core::AddonErrorCode::LimitExceeded => Self::LimitExceeded,
            core::AddonErrorCode::Cancelled => Self::Cancelled,
            core::AddonErrorCode::Expired => Self::Expired,
            core::AddonErrorCode::Busy => Self::Busy,
            core::AddonErrorCode::NeedsReconciliation => Self::NeedsReconciliation,
            core::AddonErrorCode::Io => Self::Io,
        }
    }
}

#[derive(uniffi::Error, Debug, thiserror::Error)]
pub enum AddonFailure {
    #[error("{code:?}: {detail}")]
    Rejected {
        code: AddonErrorCode,
        detail: String,
    },
}
impl From<core::AddonError> for AddonFailure {
    fn from(error: core::AddonError) -> Self {
        Self::Rejected {
            code: error.code.into(),
            detail: error.message,
        }
    }
}
#[derive(uniffi::Enum, Clone)]
pub enum AddonAction {
    Install,
    Update { addon_id: String },
}
impl From<AddonAction> for core::AddonAction {
    fn from(value: AddonAction) -> Self {
        match value {
            AddonAction::Install => Self::Install,
            AddonAction::Update { addon_id } => Self::Update { addon_id },
        }
    }
}
#[derive(uniffi::Enum, Clone)]
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
impl From<AddonEngineOutcome> for core::AddonEngineOutcome {
    fn from(value: AddonEngineOutcome) -> Self {
        match value {
            AddonEngineOutcome::Installed {
                addon_id,
                version,
                archive_sha256,
            } => Self::Installed {
                addon_id,
                version,
                archive_sha256,
            },
            AddonEngineOutcome::Staged {
                addon_id,
                version,
                archive_sha256,
            } => Self::Staged {
                addon_id,
                version,
                archive_sha256,
            },
            AddonEngineOutcome::Uninstalled { addon_id } => Self::Uninstalled { addon_id },
            AddonEngineOutcome::Cancelled => Self::Cancelled,
            AddonEngineOutcome::Failed { reason } => Self::Failed { reason },
            AddonEngineOutcome::Unknown { reason } => Self::Unknown { reason },
        }
    }
}

#[derive(uniffi::Record, Clone)]
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
impl From<core::AddonCandidate> for AddonCandidate {
    fn from(value: core::AddonCandidate) -> Self {
        Self {
            operation_id: value.operation_id,
            source_url: value.source_url,
            publisher: value.publisher,
            inner_path: value.inner_path,
            governing_manifest: value.governing_manifest,
            archive_sha256: value.archive_sha256,
            byte_length: value.byte_length,
            addon_id: value.addon_id,
            version: value.version,
            name: value.name,
            manifest_version: value.manifest_version,
            required_permissions: value.required_permissions,
            optional_permissions: value.optional_permissions,
            host_permissions: value.host_permissions,
            optional_host_permissions: value.optional_host_permissions,
            expires_at_ms: value.expires_at_ms,
            engine: value.engine.into(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct AddonSnapshot {
    pub operation_id: String,
    pub phase: AddonPhase,
    pub candidate: Option<AddonCandidate>,
    pub message: Option<String>,
    pub uninstall_id: Option<String>,
}
impl From<core::AddonSnapshot> for AddonSnapshot {
    fn from(value: core::AddonSnapshot) -> Self {
        Self {
            operation_id: value.operation_id,
            phase: value.phase.into(),
            candidate: value.candidate.map(Into::into),
            message: value.message,
            uninstall_id: value.uninstall_id,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct AddonOwnership {
    pub addon_id: String,
    pub version: String,
    pub archive_sha256: String,
    pub publisher: String,
    pub inner_path: String,
    pub source_url: String,
    pub engine: AddonEngine,
}
impl From<core::AddonOwnership> for AddonOwnership {
    fn from(value: core::AddonOwnership) -> Self {
        Self {
            addon_id: value.addon_id,
            version: value.version,
            archive_sha256: value.archive_sha256,
            publisher: value.publisher,
            inner_path: value.inner_path,
            source_url: value.source_url,
            engine: value.engine.into(),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct AddonSession {
    pub session_id: String,
    pub profile_id: String,
    pub engine: AddonEngine,
    pub needs_reconciliation: bool,
    pub managed: Vec<AddonOwnership>,
    pub operation: Option<AddonSnapshot>,
}
impl From<core::AddonSession> for AddonSession {
    fn from(value: core::AddonSession) -> Self {
        Self {
            session_id: value.session_id,
            profile_id: value.profile_id,
            engine: value.engine.into(),
            needs_reconciliation: value.needs_reconciliation,
            managed: value.managed.into_iter().map(Into::into).collect(),
            operation: value.operation.map(Into::into),
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct AddonInstalled {
    pub addon_id: String,
    pub version: String,
    pub archive_sha256: Option<String>,
    pub enabled: bool,
}
impl From<AddonInstalled> for core::AddonInstalled {
    fn from(value: AddonInstalled) -> Self {
        Self {
            addon_id: value.addon_id,
            version: value.version,
            archive_sha256: value.archive_sha256,
            enabled: value.enabled,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct AddonInventory {
    pub addons: Vec<AddonInstalled>,
    pub has_pending_installs: bool,
}
impl From<AddonInventory> for core::AddonInventory {
    fn from(value: AddonInventory) -> Self {
        Self {
            addons: value.addons.into_iter().map(Into::into).collect(),
            has_pending_installs: value.has_pending_installs,
        }
    }
}

#[derive(uniffi::Record, Clone)]
pub struct StagedAddon {
    pub candidate: AddonCandidate,
    pub path: String,
}
impl TryFrom<core::StagedAddon> for StagedAddon {
    type Error = AddonFailure;
    fn try_from(value: core::StagedAddon) -> Result<Self, Self::Error> {
        let path = value
            .path
            .to_str()
            .ok_or_else(|| AddonFailure::Rejected {
                code: AddonErrorCode::Io,
                detail: "Addon stage path cannot be represented by this platform".into(),
            })?
            .to_owned();
        Ok(Self {
            candidate: value.candidate.into(),
            path,
        })
    }
}
impl EpixNode {
    fn addon_node(&self) -> Result<std::sync::Arc<epix_ui::AppState>, AddonFailure> {
        let inner = self.inner.lock().map_err(|_| AddonFailure::Rejected {
            code: AddonErrorCode::Io,
            detail: "Node state is unavailable".into(),
        })?;
        if inner.state != NodeState::Serving {
            return Err(AddonFailure::Rejected {
                code: AddonErrorCode::InvalidRequest,
                detail: "Start the node before managing extensions".into(),
            });
        }
        inner.node.clone().ok_or_else(|| AddonFailure::Rejected {
            code: AddonErrorCode::InvalidRequest,
            detail: "Node is not running".into(),
        })
    }
}
#[uniffi::export]
impl EpixNode {
    pub fn addon_open_session(
        &self,
        profile_id: String,
        engine: AddonEngine,
    ) -> Result<AddonSession, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_open_session(&profile_id, engine.into()))
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn addon_reconcile(
        &self,
        session_id: String,
        inventory: AddonInventory,
    ) -> Result<AddonSession, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_reconcile(&session_id, inventory.into()))
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn addon_prepare(
        &self,
        session_id: String,
        source_url: String,
        action: AddonAction,
    ) -> Result<AddonCandidate, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_prepare(core::AddonPrepareRequest {
                session_id,
                source_url,
                action: action.into(),
            }))
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn addon_status(&self, session_id: String) -> Result<AddonSession, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_status(&session_id))
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn addon_cancel(
        &self,
        session_id: String,
        operation_id: Option<String>,
    ) -> Result<AddonSnapshot, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_cancel(&session_id, operation_id.as_deref()))
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn addon_stage(
        &self,
        session_id: String,
        operation_id: String,
        archive_sha256: String,
    ) -> Result<StagedAddon, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_stage(&session_id, &operation_id, &archive_sha256))?
            .try_into()
    }
    pub fn addon_report(
        &self,
        session_id: String,
        operation_id: String,
        outcome: AddonEngineOutcome,
    ) -> Result<AddonSnapshot, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_report(&session_id, &operation_id, outcome.into()))
            .map(Into::into)
            .map_err(Into::into)
    }
    pub fn addon_begin_uninstall(
        &self,
        session_id: String,
        addon_id: String,
    ) -> Result<AddonSnapshot, AddonFailure> {
        let node = self.addon_node()?;
        self.rt
            .block_on(node.addon_begin_uninstall(&session_id, &addon_id))
            .map(Into::into)
            .map_err(Into::into)
    }
}
