//! Retained, permanently bound Apple service-pool sessions.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use evx_supervisor::apple_slots::AppleSlotRegistry;
use evx_supervisor::apple_workspace::AppleWorkspace;
use evx_supervisor::{Broker, Config};

/// A permanently bound Apple service pool retained by the node.
///
/// Trusted packaging must verify the signed inventory and independently
/// establish fresh containers before provisioning the supplied registry.
/// This constructor never provisions, resets, migrates or verifies a package.
pub struct AppleBackend {
    registry: AppleSlotRegistry,
    authority: PathBuf,
    binding: String,
    state_root: Option<PathBuf>,
    workspaces: Mutex<HashMap<String, Arc<AppleWorkspace>>>,
}

impl AppleBackend {
    /// Use an existing permanent registry and the signed host identifier.
    /// Neither argument may originate in a xite, page or management command.
    #[cfg(any(test, feature = "apple-xpc-development"))]
    pub fn from_provisioned_registry(registry: AppleSlotRegistry, host_identifier: &str) -> Result<Self, String> {
        Self::from_registry(registry, host_identifier)
    }

    fn from_registry(registry: AppleSlotRegistry, host_identifier: &str) -> Result<Self, String> {
        let identity = registry.identity().map_err(|error| error.to_string())?;
        let authority = evx_supervisor::apple::authority_directory(host_identifier).map_err(|error| error.to_string())?;
        let binding = serde_json::json!({"version":1,"profile":"apple-xpc-development",
            "host_identifier":host_identifier,"registry":identity}).to_string();
        Ok(Self { registry, authority, binding, state_root: None, workspaces: Mutex::new(HashMap::new()) })
    }

    pub(crate) fn from_package(package: evx_supervisor::apple_package::ApplePackage) -> Result<Self, String> {
        let mut backend = Self::from_registry(package.registry, &package.host_identifier)?;
        backend.binding = serde_json::json!({"version":1,"profile":package.profile,
            "host_identifier":package.host_identifier,"registry":backend.registry.identity().map_err(|e|e.to_string())?}).to_string();
        backend.state_root = Some(package.state_root);
        Ok(backend)
    }
    pub(crate) fn state_root(&self) -> Option<&std::path::Path> { self.state_root.as_deref() }

    pub(crate) fn binding(&self) -> &str { &self.binding }

    pub(crate) fn prepare(&self, xite: &str, grant: evx_api::Grant, limits: evx_api::Limits,
        allocate: bool) -> Result<Option<(Arc<Broker>, Config)>, String> {
        let mut workspaces = self.workspaces.lock().map_err(|_| "Apple workspace sessions unavailable")?;
        let workspace = if let Some(workspace) = workspaces.get(xite) {
            workspace.clone()
        } else {
            let assignment = match self.registry.lookup(xite).map_err(|error| error.to_string())? {
                Some(assignment) => assignment,
                None if allocate => self.registry.allocate(xite).map_err(|error| error.to_string())?,
                None => return Ok(None),
            };
            let workspace = AppleWorkspace::open(assignment).map_err(|error| error.to_string())?;
            workspaces.insert(xite.into(), workspace.clone());
            workspace
        };
        drop(workspaces);
        let config = workspace.config(self.authority.clone());
        let broker = Arc::new(Broker::new_apple(workspace, grant, limits).map_err(|error| error.to_string())?);
        broker.check_backend(&config).map_err(|error| error.to_string())?;
        Ok(Some((broker, config)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evx_supervisor::apple_slots::{AppleServiceIdentity, AppleServiceSlot, AppleSlotInventory};
    use std::os::unix::fs::PermissionsExt;

    fn backend(root: &std::path::Path) -> Arc<AppleBackend> {
        std::fs::create_dir_all(root).unwrap();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = |role| AppleServiceIdentity { service: format!("org.example.node.{role}"), requirement: "fixture".into() };
        let registry = AppleSlotRegistry::provision_fresh(&root.join("registry"), [4;32],
            AppleSlotInventory::new(vec![AppleServiceSlot { slot: "first".into(), guest: identity("guest"),
                compiler: identity("compiler"), file: identity("file") }]).unwrap()).unwrap();
        Arc::new(AppleBackend::from_provisioned_registry(registry, "org.example.node-host").unwrap())
    }

    #[test]
    fn retained_session_is_shared_and_recovery_never_allocates() {
        let temp = tempfile::tempdir().unwrap();
        let backend = backend(temp.path());
        let grant = evx_api::Grant::new("game", true).unwrap();
        assert!(backend.prepare("game", grant.clone(), evx_api::Limits::default(), false).unwrap().is_none());
        assert!(backend.registry.lookup("game").unwrap().is_none());
        let (broker, config) = backend.prepare("game", grant.clone(), evx_api::Limits::default(), true).unwrap().unwrap();
        let session = backend.workspaces.lock().unwrap()["game"].clone();
        drop((broker, config));
        backend.prepare("game", grant, evx_api::Limits::default(), false).unwrap().unwrap();
        assert!(Arc::ptr_eq(&session, &backend.workspaces.lock().unwrap()["game"]));
        assert!(backend.prepare("another", evx_api::Grant::new("another", true).unwrap(), evx_api::Limits::default(), true).is_err());
    }

    #[test]
    fn cached_workspace_still_refuses_unresolved_or_missing_lifecycle() {
        let temp = tempfile::tempdir().unwrap();
        let backend = backend(temp.path());
        let grant = evx_api::Grant::new("game", true).unwrap();
        backend.prepare("game", grant.clone(), evx_api::Limits::default(), true).unwrap().unwrap();
        let journal = temp.path().join("registry/workspaces/first/lifecycle.json");
        std::fs::write(&journal, b"{\"version\":1,\"session\":1,\"next\":1,\"active\":{\"compiler\":1}}").unwrap();
        assert!(backend.prepare("game", grant.clone(), evx_api::Limits::default(), false).is_err());
        std::fs::remove_file(&journal).unwrap();
        assert!(backend.prepare("game", grant, evx_api::Limits::default(), true).is_err());
        assert!(!journal.exists());
    }

    #[test]
    fn node_state_pins_registry_identity_and_rejects_direct_or_legacy_adoption() {
        let temp = tempfile::tempdir().unwrap();
        let one = backend(&temp.path().join("one"));
        let app = epix_ui::AppState::with_data_dir("fixture", temp.path().join("node"));
        let service = crate::EvxService::for_node_apple_development(&app, one.clone()).unwrap();
        assert!(service.execution_ready().is_ok());
        assert!(service.execution().is_err());
        assert!(one.workspaces.lock().unwrap().is_empty());
        assert!(crate::EvxService::open(service.root().to_path_buf(), None).is_err());
        crate::EvxService::for_node_apple_development(&app, one).unwrap();
        let other = backend(&temp.path().join("other"));
        assert!(crate::EvxService::for_node_apple_development(&app, other).is_err());
        std::fs::remove_file(service.root().join(crate::backend_binding::MARKER)).unwrap();
        assert!(crate::EvxService::open(service.root().to_path_buf(), None).is_err());
        let legacy_app = epix_ui::AppState::with_data_dir("fixture", temp.path().join("legacy"));
        let legacy = temp.path().join("legacy/private/evx-apple-development");
        std::fs::create_dir_all(&legacy).unwrap();
        let new_backend = backend(&temp.path().join("new"));
        assert!(crate::EvxService::for_node_apple_development(&legacy_app, new_backend).is_err());
    }
}
