//! One host-created broker per workspace: grant, limits, lease and request
//! authorization. No guest-selected caller exists anywhere in this type.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};

use evx_api::{Capability, Denied, Grant, Limits, Request, Response};

pub struct Inner {
    pub grant: Grant,
    pub limits: Limits,
    /// Advances on every limits change. Paired with each limits snapshot a
    /// helper receives, so a change during a helper's lifetime denies its
    /// commit rather than applying stale quota values.
    pub limits_generation: u64,
    /// One invocation at a time per broker, in addition to the OS lease.
    pub running: bool,
    /// Set when a child could not be reaped. The lease is never released.
    pub quarantined: bool,
    /// Capabilities declared by the current activation, if any.
    pub active_capabilities: Option<BTreeSet<Capability>>,
    pub calls: u32,
    pub responses: Vec<Response>,
}

pub struct Broker {
    workspace: PathBuf,
    root_fd: OwnedFd,
    inner: Mutex<Inner>,
    pub(crate) provenance: crate::provenance::Provenance,
    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    apple_workspace: Option<std::sync::Arc<crate::apple_workspace::AppleWorkspace>>,
}

impl Broker {
    /// Open a workspace and bind a grant to it. The workspace must be a
    /// host-created directory, never a symlink. Its parent is host-owned and
    /// trusted; only that parent is resolved before the final NOFOLLOW open.
    pub fn new(workspace: &Path, grant: Grant, limits: Limits) -> Result<Broker, Denied> {
        limits.validate()?;
        let name = workspace
            .file_name()
            .ok_or_else(|| Denied::new("workspace unavailable"))?;
        let parent = workspace
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let workspace = std::fs::canonicalize(parent)
            .map_err(|_| Denied::new("workspace unavailable"))?
            .join(name);
        let root_fd = evx_workspace::open_root(&workspace)?;
        let provenance =
            crate::provenance::Provenance::new(&workspace, root_fd.as_fd(), &grant.xite)?;
        Ok(Broker {
            #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
            apple_workspace: None,
            provenance,
            workspace,
            root_fd,
            inner: Mutex::new(Inner {
                grant,
                limits,
                limits_generation: 1,
                running: false,
                quarantined: false,
                active_capabilities: None,
                calls: 0,
                responses: Vec::new(),
            }),
        })
    }

    /// Bind only host control/provenance state. Guest data remains in the
    /// assigned file service's private container and is never opened here.
    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    pub fn new_apple(
        workspace: std::sync::Arc<crate::apple_workspace::AppleWorkspace>,
        grant: Grant,
        limits: Limits,
    ) -> Result<Self, Denied> {
        if grant.xite != workspace.xite() {
            return Err(Denied::new("Apple workspace xite mismatch"));
        }
        workspace.validate()?;
        let mut broker = Self::new(workspace.control_path(), grant, limits)?;
        broker.apple_workspace = Some(workspace);
        Ok(broker)
    }

    /// Check the trusted backend/workspace binding before compilation or
    /// execution. This does not launch a process or allocate a service slot.
    pub fn check_backend(&self, config: &crate::Config) -> Result<(), Denied> {
        if let Some(scope) = &config.direct_lifecycle {
            #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
            if config.apple_xpc.is_some() {
                return Err(Denied::new("conflicting execution backends"));
            }
            if scope.xite() != self.grant().xite {
                return Err(Denied::new("direct lifecycle xite mismatch"));
            }
            scope.validate()?;
        }
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        match &self.apple_workspace {
            Some(workspace) => return workspace.check_config(config),
            None if config.apple_xpc.is_some() => {
                return Err(Denied::new("Apple workspace binding required"));
            }
            None => {}
        }
        let _ = config;
        Ok(())
    }

    pub(crate) fn helper_lease_fd(&self) -> Option<std::os::fd::RawFd> {
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        if self.apple_workspace.is_some() {
            return None;
        }
        Some(std::os::fd::AsRawFd::as_raw_fd(&self.root_fd))
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn root_fd(&self) -> BorrowedFd<'_> {
        self.root_fd.as_fd()
    }

    pub fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn grant(&self) -> Grant {
        self.lock().grant.clone()
    }

    /// Trusted harness access to the grant, for tests and the host.
    pub fn with_grant<T>(&self, f: impl FnOnce(&mut Grant) -> T) -> T {
        f(&mut self.lock().grant)
    }

    pub fn limits(&self) -> Limits {
        self.lock().limits.clone()
    }

    pub fn quarantined(&self) -> bool {
        self.lock().quarantined
    }

    /// Disable the grant and advance its authority generation.
    pub fn revoke(&self) {
        self.lock().grant.revoke();
    }

    /// Trusted limits adjustment; advances the limits generation.
    pub fn set_limits(&self, limits: Limits) -> Result<(), Denied> {
        limits.validate()?;
        let mut inner = self.lock();
        inner.limits = limits;
        inner.limits_generation += 1;
        Ok(())
    }

    pub fn set_storage_limit(&self, bytes: u64) -> Result<(), Denied> {
        let mut limits = self.limits();
        limits.storage_bytes = bytes;
        self.set_limits(limits)
    }

    /// Bytes and entries currently used in the workspace.
    pub fn usage(&self) -> Result<(u64, usize), Denied> {
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        if self.apple_workspace.is_some() {
            return Err(Denied::new(
                "Apple workspace usage requires the scoped file service",
            ));
        }
        evx_workspace::usage(self.root_fd())
    }

    /// Validate one raw guest request against the locked state without any
    /// filesystem I/O.
    pub fn authorize(
        inner: &Inner,
        raw: &[u8],
        expected_generation: u64,
    ) -> Result<Request, Denied> {
        if !inner.grant.enabled || inner.grant.generation != expected_generation {
            return Err(Denied::Cancelled("execution grant revoked".into()));
        }
        let request = Request::decode(raw)?;
        let capability = request.capability();
        if !inner.grant.capabilities.contains(&capability) {
            return Err(Denied::new("capability denied"));
        }
        if let Some(active) = &inner.active_capabilities {
            if !active.contains(&capability) {
                return Err(Denied::new("undeclared capability"));
            }
        }
        Ok(request)
    }
}
