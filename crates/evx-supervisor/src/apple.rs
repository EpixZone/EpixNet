//! Apple App Sandbox profile. The signed XPC service owns and reaps workers;
//! the node owns admission, the broker, bounded pipe I/O and durable state.
//! Observations come from that trusted service's kernel calls, not the guest.

use std::cell::{Cell, RefCell};
use std::ffi::{c_char, c_void, CString};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use evx_api::Denied;

use crate::process::Role;

/// Supplied by trusted host packaging and durable slot assignment. None of
/// these values may come from an execution declaration or guest request.
#[derive(Debug, Clone)]
pub struct AppleXpcConfig {
    pub guest_service: String,
    pub guest_requirement: String,
    pub compiler_service: String,
    pub compiler_requirement: String,
    pub file_service: String,
    pub file_requirement: String,
    /// Host-private 0700 directory returned by [`authority_directory`].
    pub authority_directory: PathBuf,
    pub(crate) workspace: Option<std::sync::Arc<crate::apple_workspace::AppleWorkspace>>,
}

impl AppleXpcConfig {
    /// Unbound transport configuration for trusted development fixtures. The
    /// node activation path must use AppleWorkspace::config instead.
    pub fn unbound_for_development(
        slot: &crate::apple_slots::AppleServiceSlot,
        authority_directory: PathBuf,
    ) -> Result<Self, Denied> {
        crate::apple_slots::AppleSlotInventory::new(vec![slot.clone()])?;
        Ok(Self {
            guest_service: slot.guest.service.clone(),
            guest_requirement: slot.guest.requirement.clone(),
            compiler_service: slot.compiler.service.clone(),
            compiler_requirement: slot.compiler.requirement.clone(),
            file_service: slot.file.service.clone(),
            file_requirement: slot.file.requirement.clone(),
            authority_directory,
            workspace: None,
        })
    }
}

#[derive(Default, Clone, Copy)]
#[repr(C)]
struct Observation {
    state: i32,
    pid: i32,
    exit_code: i32,
    rss: u64,
    peak_rss: u64,
    cpu: f64,
}

unsafe extern "C" {
    fn evx_xpc_authority_directory(
        identifier: *const c_char,
        output: *mut c_char,
        capacity: usize,
    ) -> i32;
    fn evx_xpc_open(
        name: *const c_char,
        requirement: *const c_char,
        authority_root: *const c_char,
        access: u32,
        input: i32,
        output: i32,
        error: i32,
    ) -> *mut c_void;
    fn evx_xpc_snapshot(client: *mut c_void, observation: *mut Observation);
    fn evx_xpc_stop(client: *mut c_void);
    fn evx_xpc_release(client: *mut c_void);
    fn evx_xpc_service_main();
}

/// Resolve the fixed per-user host container location from the account record.
/// `host_identifier` is trusted signed package policy, never a xite value.
/// This does not create directories, issue consent or enable execution.
pub fn authority_directory(host_identifier: &str) -> Result<PathBuf, Denied> {
    let identifier = CString::new(host_identifier)
        .map_err(|_| Denied::new("invalid Apple authority host identifier"))?;
    let mut output = [0u8; libc::PATH_MAX as usize];
    // SAFETY: the identifier is terminated; output is writable for capacity.
    let resolved = unsafe {
        evx_xpc_authority_directory(
            identifier.as_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    };
    if resolved != 0 {
        return Err(Denied::new("Apple authority location unavailable"));
    }
    let length = output
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| Denied::new("invalid Apple authority location"))?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(
        output[..length].to_vec(),
    )))
}

fn pipe() -> Result<(File, File), Denied> {
    let mut descriptors = [-1; 2];
    // SAFETY: valid two-element output buffer; each successful descriptor is
    // transferred to exactly one owned File below.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(Denied::new("Apple worker pipe unavailable"));
    }
    let (read, write) = unsafe {
        (
            File::from(OwnedFd::from_raw_fd(descriptors[0])),
            File::from(OwnedFd::from_raw_fd(descriptors[1])),
        )
    };
    for descriptor in [&read, &write] {
        // No descriptor may leak to another concurrently spawned child.
        if unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(Denied::new("Apple worker descriptor configuration"));
        }
    }
    Ok((read, write))
}

pub(crate) struct Spawned {
    pub peer: ApplePeer,
    pub stdin: File,
    pub stdout: File,
    pub stderr: File,
}

pub(crate) struct ApplePeer {
    native: *mut c_void,
    invocation: RefCell<Option<crate::apple_workspace::AppleInvocation>>,
    journal_failed: Cell<bool>,
}

// The C transport serializes callbacks and protects its fixed-size snapshot
// with a mutex. Drop only cancels/releases the owned connection; its finalizer
// frees callback state after the connection and queued callbacks release it.
unsafe impl Send for ApplePeer {}

impl ApplePeer {
    pub fn spawn(config: &AppleXpcConfig, role: Role, mode: &str) -> Result<Spawned, Denied> {
        let (service, requirement) = match role {
            Role::Guest => (&config.guest_service, &config.guest_requirement),
            Role::Compiler => (&config.compiler_service, &config.compiler_requirement),
            Role::File => (&config.file_service, &config.file_requirement),
        };
        let access = match (role, mode) {
            (Role::Guest, "run") | (Role::Compiler, "compile") => 0,
            (Role::File, "file-read") => 1,
            (Role::File, "file") => 2,
            _ => return Err(Denied::new("invalid Apple worker operation")),
        };
        if service.is_empty()
            || service.len() > 255
            || requirement.is_empty()
            || requirement.len() > 2048
        {
            return Err(Denied::new("invalid Apple service identity"));
        }
        let service = CString::new(service.as_str())
            .map_err(|_| Denied::new("invalid Apple service identity"))?;
        let requirement = CString::new(requirement.as_str())
            .map_err(|_| Denied::new("invalid Apple service requirement"))?;
        let authority = CString::new(config.authority_directory.as_os_str().as_bytes())
            .map_err(|_| Denied::new("invalid Apple authority directory"))?;
        let (input, stdin) = pipe()?;
        let (stdout, output) = pipe()?;
        let (stderr, error) = pipe()?;
        let flags = unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(stdin.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(Denied::new("Apple worker input configuration"));
        }
        if config
            .workspace
            .as_ref()
            .is_some_and(|workspace| !workspace.matches(config))
        {
            return Err(Denied::new("Apple workspace service binding mismatch"));
        }
        // The durable possible-invocation record precedes any native open.
        // Dropping the token on failure intentionally leaves the slot blocked.
        let invocation = config
            .workspace
            .as_ref()
            .map(|workspace| workspace.begin(role))
            .transpose()?;
        // SAFETY: strings and owned pipe descriptors remain valid for the
        // synchronous start handshake. XPC duplicates the transferred ends.
        let native = unsafe {
            evx_xpc_open(
                service.as_ptr(),
                requirement.as_ptr(),
                authority.as_ptr(),
                access,
                input.as_raw_fd(),
                output.as_raw_fd(),
                error.as_raw_fd(),
            )
        };
        if native.is_null() {
            // A service may have started a worker before communication failed.
            // Never interpret handshake failure as evidence of no execution.
            return Err(Denied::Quarantined(
                "Apple worker admission or termination unconfirmed".into(),
            ));
        }
        Ok(Spawned {
            peer: Self {
                native,
                invocation: RefCell::new(invocation),
                journal_failed: Cell::new(false),
            },
            stdin,
            stdout,
            stderr,
        })
    }

    fn observation(&self) -> Observation {
        let mut sample = Observation::default();
        // SAFETY: native owns a live client; snapshot locks and copies fields.
        unsafe { evx_xpc_snapshot(self.native, &mut sample) };
        sample
    }

    pub fn pid(&self) -> i32 {
        self.observation().pid
    }

    pub fn measure(&self) -> Result<(f64, u64), Denied> {
        let sample = self.observation();
        if sample.state <= 0 || !sample.cpu.is_finite() || sample.cpu < 0.0 {
            return Err(Denied::new("Apple worker observation unavailable"));
        }
        Ok((sample.cpu, sample.rss.max(sample.peak_rss)))
    }

    /// Physical reap evidence only; journal completion is checked by poll.
    pub fn observed_exit_code(&self) -> Option<i32> {
        let sample = self.observation();
        (sample.state == 2).then_some(sample.exit_code)
    }

    pub fn poll(&self) -> Option<i32> {
        let sample = self.observation();
        if sample.state != 2 || self.journal_failed.get() {
            return None;
        }
        if let Some(mut invocation) = self.invocation.borrow_mut().take() {
            if invocation.complete().is_err() {
                self.journal_failed.set(true);
                crate::process::quarantine_child_admission();
                return None;
            }
        }
        Some(sample.exit_code)
    }

    pub fn close(&self, timeout: Duration) -> Result<i32, crate::process::CleanupTimeout> {
        if let Some(code) = self.poll() {
            return Ok(code);
        }
        // SAFETY: the connection is owned and valid; stop is an exact bounded
        // control message to the trusted child owner, not a raw PID signal.
        unsafe { evx_xpc_stop(self.native) };
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(code) = self.poll() {
                return Ok(code);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        crate::process::quarantine_child_admission();
        Err(crate::process::CleanupTimeout { pid: self.pid() })
    }
}

impl Drop for ApplePeer {
    fn drop(&mut self) {
        if self.poll().is_none() {
            let _ = self.close(Duration::from_secs(2));
        }
        // SAFETY: release consumes our native ownership. The C connection's
        // finalizer, not this call, disposes callback state after invalidation.
        unsafe { evx_xpc_release(self.native) };
    }
}

/// Entry point used only by the signed, role-specific embedded service.
pub fn service_main() -> ! {
    // SAFETY: initializes a process-global listener and never returns.
    unsafe { evx_xpc_service_main() };
    std::process::exit(1)
}
