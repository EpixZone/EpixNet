//! Windows children: a less-privileged AppContainer inside a Job Object.
//!
//! `spawn` stages nothing itself: the backend (`crate::windows`) owns the
//! pinned worker image and the profiles. Here the role picks a profile, the
//! three pipes and the job are created, the child is launched suspended
//! with an explicit handle list, verified (token, zero capabilities, job
//! membership) and only then resumed. Measurement comes from the process
//! and job objects, death from the process object plus an empty job, and
//! termination from `TerminateJobObject`. The journal order is the Unix
//! one: `begin` before the launch, an unconfirmed launch quarantines the
//! process-wide admission latch, `complete` only after the exact child's
//! terminal evidence.
//!
//! A file helper's workspace lease is not inherited: the lease handle is
//! never marked inheritable, because any concurrent `CreateProcessW` by
//! another thread of the host (a `std::process::Command` inherits every
//! inheritable handle) could copy it into an unrelated, long-lived process
//! and hold the workspace busy. Instead the suspended child receives a
//! duplicate through `DuplicateHandle`, and the duplicate's value in the
//! child is the first eight bytes (little endian) on the child's stdin,
//! ahead of the first frame. The duplicate keeps the lease alive exactly
//! as an inherited handle would: the sharing reservation belongs to the
//! file object, not to any one handle's access mask. The duplicate is
//! therefore cut down to what the helper needs: list, traverse, attributes
//! and security for both helpers, plus add-file and add-subdirectory for
//! the writing helper (its commit flushes the directory handle, which
//! needs write access), and never `DELETE`, which the host's own lease
//! handle carries and which would let a compromised helper remove an
//! empty workspace. The worker refuses a handle that carries more
//! (`evx-worker/src/confine_windows.rs`).
//!
//! The job carries fixed backstop limits (2 GiB committed per process and
//! per job, 600 s of user time per process and per job, one active process,
//! kill on close, die on unhandled exception). The supervisor enforces the
//! real budgets by observation, exactly as on Unix; the job limits only
//! bound a host that stopped observing.

use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use evx_api::{Denied, MAX_FRAME};
use evx_windows_native::{
    blocking_pipe_pair, create_job, is_app_container, launch_suspended, os_version, pipe_pair,
    process_dead, process_usage, resume_thread, terminate_job, verify_process, worker_environment,
    Handle, JobLimits, LaunchSpec, Launched, OsVersion, TERMINATED,
};
use evx_workspace::sys::RawLease;
use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::common::{
    quarantine_child_admission, quarantine_error, read_frames, read_stderr, record_diagnostics,
    CleanupTimeout, Event, Input, Role, CHILD_ADMISSION_STOPPED,
};
use crate::windows::{Container, PipeWriter, WindowsBackend};

/// Backstop job limits; see the module documentation.
const BACKSTOP: JobLimits = JobLimits {
    process_memory: 2 << 30,
    job_memory: 2 << 30,
    per_process_user_100ns: 600 * 10_000_000,
    per_job_user_100ns: 600 * 10_000_000,
    cpu_rate_hard_cap_percent_x100: None,
};
/// Length of the workspace handle preamble a file helper reads from its
/// stdin before the first frame: the handle value as a little-endian u64.
pub const WORKSPACE_PREAMBLE: usize = 8;
// Access rights (winnt.h) of the lease duplicate a file helper receives.
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_ADD_FILE: u32 = 0x0002;
const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
const FILE_TRAVERSE: u32 = 0x0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const READ_CONTROL: u32 = 0x0002_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
/// What the file-read helper's lease duplicate grants: list, traverse,
/// attributes, security. No write bit, no `DELETE`.
pub const READ_LEASE_ACCESS: u32 =
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
/// What the writing file helper's lease duplicate grants: the read set plus
/// creating entries, so its commit can flush the directory. Never `DELETE`.
pub const WRITE_LEASE_ACCESS: u32 = READ_LEASE_ACCESS | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;
const MINIMUM_VERSION: OsVersion = OsVersion {
    major: 10,
    minor: 0,
    build: 15063,
};

pub struct Peer {
    pub role: Role,
    pub id: u64,
    pub pid: i32,
    pub started: Instant,
    process: OwnedHandle,
    job: OwnedHandle,
    direct_invocation: Option<crate::direct_lifecycle::DirectInvocation>,
    /// Death was observed (or could not be observed). No process or job
    /// call may be made on this identity again, as after a Unix reap.
    ownership_lost: bool,
    _backend: Arc<WindowsBackend>,
    _container: Arc<Container>,
    input: Input,
    pub exit_code: Option<i32>,
    // Physical death evidence is separate from successful durable completion.
    observed_exit_code: Option<i32>,
    pub readers: u8,
    pub output_bytes: usize,
    pub frames: u32,
    pub diagnostics: Vec<u8>,
    pub max_cpu: f64,
    /// The process's peak working set so far: monotonic, so it is the
    /// conservative figure for a budget that must not miss a short peak.
    pub last_rss: Option<u64>,
    // Role-specific state the supervisor tracks per peer.
    pub terminal: bool,
    pub prepared: bool,
    pub commit_sent: bool,
    pub limits_generation: u64,
}

/// The name of pipe `number` (0 stdin, 1 stdout, 2 stderr) of peer `id` in
/// this host process. Exposed so tests can prove a connected pipe cannot
/// be opened by name.
pub fn pipe_name(id: u64, number: u32) -> String {
    evx_windows_native::pipe_name(&pipe_suffix(id), number)
}

fn pipe_suffix(id: u64) -> String {
    format!("sup-{}-{id}", std::process::id())
}

/// Convert a native handle into an owned std handle.
fn owned(handle: Handle) -> OwnedHandle {
    // SAFETY: `into_raw` transfers ownership of an open handle.
    unsafe { OwnedHandle::from_raw_handle(handle.into_raw()) }
}

/// The child's command line: the staged image, the trusted extra
/// arguments and the mode.
fn command_line(executable: &Path, args: &[String], mode: &str) -> String {
    let mut line = format!("\"{}\"", executable.display());
    for arg in args.iter().map(String::as_str).chain(std::iter::once(mode)) {
        line.push_str(&format!(" \"{arg}\""));
    }
    line
}

/// The lease duplicate's access mask for a file helper in `mode`.
pub fn helper_lease_access(mode: &str) -> u32 {
    if mode == "file-read" {
        READ_LEASE_ACCESS
    } else {
        WRITE_LEASE_ACCESS
    }
}

/// Copy the workspace lease into the suspended child with exactly `access`
/// and return the handle value the child sees. The host keeps its own
/// handle untouched; the copy holds the same file object, so the lease's
/// sharing reservation lives as long as either handle.
fn duplicate_lease(child: RawHandle, lease: RawLease, access: u32) -> std::io::Result<RawHandle> {
    let mut duplicate = null_mut();
    // SAFETY: the lease is an open handle of this process and `child` an
    // open process handle with full access; the kernel writes the value.
    let copied = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            lease,
            child,
            &mut duplicate,
            access,
            0,
            0,
        )
    };
    if copied == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(duplicate)
}

/// Everything prepared before the journal entry: nothing here can start a
/// process.
struct Prepared {
    backend: Arc<WindowsBackend>,
    container: Arc<Container>,
    cwd: PathBuf,
    command_line: String,
    environment: Vec<u16>,
    job: Handle,
    stdin: (Handle, Handle),
    stdout: (Handle, Handle),
    stderr: (Handle, Handle),
    lease: Option<RawLease>,
}

impl Prepared {
    fn new(
        config: &crate::supervisor::Config,
        id: u64,
        mode: &str,
        cwd: &Path,
        role: Role,
        lease: Option<RawLease>,
    ) -> Result<Self, Denied> {
        let backend = match &config.windows {
            Some(backend) => backend.clone(),
            None => WindowsBackend::default_for(&config.worker_binary)?,
        };
        let container = crate::windows::containers().select(role, mode, cwd)?;
        let environment =
            worker_environment().map_err(|_| Denied::new("worker environment unavailable"))?;
        // A guest or compiler never sees the workspace; its working
        // directory is the staged image's, which an LPAC token can open.
        let cwd = if role == Role::File {
            cwd.to_path_buf()
        } else {
            backend.stage_dir().to_path_buf()
        };
        let suffix = pipe_suffix(id);
        let pipes = || -> std::io::Result<_> {
            Ok((
                pipe_pair(true, 0, &suffix)?,
                blocking_pipe_pair(false, 1, &suffix)?,
                blocking_pipe_pair(false, 2, &suffix)?,
                create_job(&BACKSTOP)?,
            ))
        };
        let (stdin, stdout, stderr, job) =
            pipes().map_err(|e| Denied::new(format!("worker pipes unavailable: {e}")))?;
        Ok(Prepared {
            command_line: command_line(backend.staged_worker(), &config.worker_args, mode),
            backend,
            container,
            cwd,
            environment,
            job,
            stdin,
            stdout,
            stderr,
            lease,
        })
    }

    fn launch(&mut self) -> std::io::Result<Launched> {
        let inherited = vec![self.stdin.1.raw(), self.stdout.1.raw(), self.stderr.1.raw()];
        let mut spec = LaunchSpec {
            executable: self.backend.staged_worker(),
            command_line: self.command_line.clone(),
            current_directory: &self.cwd,
            environment: std::mem::take(&mut self.environment),
            container_sid: self.container.sid(),
            job: &self.job,
            inherited_handles: inherited,
            stdin: self.stdin.1.raw(),
            stdout: self.stdout.1.raw(),
            stderr: self.stderr.1.raw(),
        };
        launch_suspended(&mut spec)
    }
}

impl Peer {
    /// Spawn `worker <mode>` under the role's AppContainer, with an empty
    /// environment and only the three pipe ends plus, for a file role, a
    /// duplicate of the workspace lease handle, whose value the child reads
    /// as the first eight bytes of its stdin.
    pub fn spawn(
        config: &crate::supervisor::Config,
        mode: &str,
        cwd: &Path,
        role: Role,
        events: SyncSender<Event>,
        lease: Option<RawLease>,
    ) -> Result<Peer, Denied> {
        // Hold through spawn so quarantine and admission have one order.
        // No broker callbacks occur while holding this lock.
        let mut stopped = CHILD_ADMISSION_STOPPED
            .lock()
            .map_err(|_| quarantine_error())?;
        if *stopped {
            return Err(quarantine_error());
        }
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| Denied::new("worker instance limit"))?;
        let mut prepared = Prepared::new(config, id, mode, cwd, role, lease)?;
        let direct_invocation = config
            .direct_lifecycle
            .as_ref()
            .map(|scope| scope.begin(role))
            .transpose()?;
        let launched = match prepared.launch() {
            Ok(launched) => launched,
            Err(_) if direct_invocation.is_some() => {
                *stopped = true;
                return Err(Denied::Quarantined(
                    "direct worker launch outcome unconfirmed".into(),
                ));
            }
            Err(error) => return Err(Denied::new(format!("worker launch failed: {error}"))),
        };
        let Launched {
            process,
            thread,
            pid,
        } = launched;
        let lease = prepared.lease;
        let (mut peer, stdout, stderr) =
            Peer::suspended(role, id, pid, process, prepared, direct_invocation);
        drop(stopped);
        if verify_process(
            peer.process.as_raw_handle(),
            peer.job.as_raw_handle(),
            peer._container.sid(),
        )
        .is_err()
        {
            peer.close(Duration::from_millis(50), Duration::from_secs(2))
                .map_err(|_| quarantine_error())?;
            return Err(Denied::new("worker confinement verification failed"));
        }
        if let Err(error) = peer.hand_over_lease(lease, helper_lease_access(mode)) {
            peer.close(Duration::from_millis(50), Duration::from_secs(2))
                .map_err(|_| quarantine_error())?;
            return Err(error);
        }
        let tx = events.clone();
        std::thread::spawn(move || read_frames(role, id, stdout, tx));
        std::thread::spawn(move || read_stderr(role, id, stderr, events));
        if resume_thread(thread.raw()).is_err() {
            peer.close(Duration::from_millis(50), Duration::from_secs(2))
                .map_err(|_| quarantine_error())?;
            return Err(Denied::new("worker resume failed"));
        }
        Ok(peer)
    }

    /// The peer for a child that exists but has not run yet, with the
    /// host's stdout and stderr ends. The child's pipe ends and the lease
    /// inherit flag are released here: the child alone holds its ends from
    /// now on, so EOF propagates when it dies.
    fn suspended(
        role: Role,
        id: u64,
        pid: u32,
        process: Handle,
        prepared: Prepared,
        direct_invocation: Option<crate::direct_lifecycle::DirectInvocation>,
    ) -> (Peer, File, File) {
        let Prepared {
            backend,
            container,
            job,
            stdin: (stdin, _),
            stdout: (stdout, _),
            stderr: (stderr, _),
            ..
        } = prepared;
        let peer = Peer {
            role,
            id,
            pid: pid as i32,
            started: Instant::now(),
            process: owned(process),
            job: owned(job),
            direct_invocation,
            ownership_lost: false,
            _backend: backend,
            _container: container,
            input: Input::new(Some(PipeWriter::new(owned(stdin)))),
            exit_code: None,
            observed_exit_code: None,
            readers: 2,
            output_bytes: 0,
            frames: 0,
            diagnostics: Vec::new(),
            max_cpu: 0.0,
            last_rss: None,
            terminal: false,
            prepared: false,
            commit_sent: false,
            limits_generation: 0,
        };
        (peer, File::from(owned(stdout)), File::from(owned(stderr)))
    }

    /// Give a suspended file helper its copy of the workspace lease, cut
    /// down to `access`, and queue the handle value as the stdin preamble.
    fn hand_over_lease(&mut self, lease: Option<RawLease>, access: u32) -> Result<(), Denied> {
        let Some(lease) = lease else {
            return Ok(());
        };
        let value = duplicate_lease(self.process.as_raw_handle(), lease, access)
            .map_err(|_| Denied::new("workspace lease hand-over failed"))?;
        self.input.preload(&(value as usize as u64).to_le_bytes())
    }

    /// Queue one bounded frame, flushing only while the pipe is writable.
    /// The event loop calls `flush_input` on every watchdog tick.
    pub fn send(&mut self, encoded: &[u8]) -> Result<(), Denied> {
        self.input.send(encoded, MAX_FRAME)
    }

    /// Only a guest's first input may carry the larger serialized artifact.
    pub(crate) fn send_artifact_init(&mut self, encoded: &[u8]) -> Result<(), Denied> {
        self.input.send_artifact_init(self.role, encoded)
    }

    pub fn flush_input(&mut self) -> Result<(), Denied> {
        self.input.flush()
    }

    pub fn record_stderr(&mut self, chunk: &[u8]) {
        record_diagnostics(&mut self.diagnostics, chunk);
    }

    fn record_usage(&mut self) -> Option<u32> {
        let usage = process_usage(self.process.as_raw_handle(), self.job.as_raw_handle()).ok()?;
        if usage.cpu_seconds > self.max_cpu {
            self.max_cpu = usage.cpu_seconds;
        }
        self.last_rss = Some(self.last_rss.unwrap_or(0).max(usage.peak_resident_bytes));
        Some(usage.exit_code)
    }

    /// Kernel-owned usage for a live child: user plus kernel time and the
    /// peak working set, from the process object.
    pub fn measure(&mut self) -> Result<(), Denied> {
        if self.exit_code.is_some() {
            return Ok(());
        }
        if self.ownership_lost {
            return Err(quarantine_error());
        }
        self.record_usage()
            .map(|_| ())
            .ok_or_else(|| Denied::new("process measurement unavailable"))
    }

    /// Non-blocking death check: the process object signaled and the job
    /// reports no active process. Terminal usage and the exit code are
    /// taken then; a child the host terminated reports `TERMINATED`.
    pub fn poll(&mut self) -> Option<i32> {
        if self.exit_code.is_some() {
            return self.exit_code;
        }
        if self.ownership_lost {
            return None;
        }
        match process_dead(self.process.as_raw_handle(), self.job.as_raw_handle()) {
            Ok(false) => return None,
            Ok(true) => {}
            Err(_) => {
                // The handles are ours; a failed wait proves nothing about
                // the child. Preserve durable uncertainty.
                self.ownership_lost = true;
                quarantine_child_admission();
                return None;
            }
        }
        self.ownership_lost = true;
        let code = self.record_usage().map_or(-1, |code| code as i32);
        self.observed_exit_code = Some(code);
        if let Some(mut invocation) = self.direct_invocation.take() {
            if invocation.complete().is_err() {
                quarantine_child_admission();
                return None;
            }
        }
        self.exit_code = Some(code);
        self.exit_code
    }

    /// Close the child's input, terminate its job and confirm death within
    /// `cleanup`. Windows has no cooperative termination signal, so
    /// `grace` is not observed. A `CleanupTimeout` is a quarantine signal.
    pub fn close(&mut self, _grace: Duration, cleanup: Duration) -> Result<i32, CleanupTimeout> {
        self.input.close();
        if let Some(code) = self.poll() {
            return Ok(code);
        }
        if self.ownership_lost {
            return Err(CleanupTimeout { pid: self.pid });
        }
        let deadline = Instant::now() + cleanup;
        let _ = terminate_job(self.job.as_raw_handle(), TERMINATED);
        while Instant::now() < deadline {
            if let Some(code) = self.poll() {
                return Ok(code);
            }
            if self.ownership_lost {
                return Err(CleanupTimeout { pid: self.pid });
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        quarantine_child_admission();
        Err(CleanupTimeout { pid: self.pid })
    }

    /// Result evidence only. This does not authorize reuse or release a lease.
    pub fn observed_exit_code(&self) -> Option<i32> {
        self.observed_exit_code.or(self.exit_code)
    }

    pub fn is_alive(&self) -> bool {
        self.exit_code.is_none()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        // Never leave a confined child running after its supervisor state is
        // gone; the normal path has already confirmed its death.
        if self.exit_code.is_none() {
            let _ = self.close(Duration::from_millis(50), Duration::from_millis(500));
        }
    }
}

/// Read-only platform capability check for the Windows backend: Windows 10
/// 1703 or newer, a host that is not itself an AppContainer, and a working
/// AppContainer profile API. Never a fallback; the first answer is kept.
pub(crate) fn confinement_available() -> Result<(), Denied> {
    static ANSWER: OnceLock<Result<(), String>> = OnceLock::new();
    ANSWER
        .get_or_init(|| probe_confinement().map_err(|e| e.to_string()))
        .clone()
        .map_err(Denied::new)
}

fn probe_confinement() -> Result<(), Denied> {
    let version = os_version().map_err(|_| Denied::new("Windows version unavailable"))?;
    if version < MINIMUM_VERSION {
        return Err(Denied::new("Windows 10 version 1703 or newer is required"));
    }
    // SAFETY: the pseudo handle for the current process is always valid.
    if is_app_container(unsafe { GetCurrentProcess() })
        .map_err(|_| Denied::new("host token unavailable"))?
    {
        return Err(Denied::new("the host must not run inside an AppContainer"));
    }
    crate::windows::probe_profiles()
        .map_err(|e| Denied::new(format!("AppContainer profiles unavailable: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confinement_is_available_on_this_host() {
        confinement_available().unwrap();
    }

    #[test]
    fn command_line_quotes_every_argument_after_the_image() {
        let line = command_line(Path::new(r"C:\s\evx-worker.exe"), &["a b".into()], "run");
        assert_eq!(line, r#""C:\s\evx-worker.exe" "a b" "run""#);
    }

    /// Duplicate `lease` into this process with `access` and own the copy.
    fn local_duplicate(lease: &evx_workspace::Lease, access: u32) -> OwnedHandle {
        // SAFETY: the pseudo handle for the current process is always valid.
        let copy = duplicate_lease(unsafe { GetCurrentProcess() }, lease.raw(), access).unwrap();
        assert_ne!(copy, lease.raw());
        // SAFETY: the duplicate is a handle this process owns.
        unsafe { OwnedHandle::from_raw_handle(copy) }
    }

    #[test]
    fn a_reduced_lease_duplicate_keeps_the_workspace_busy_without_delete() {
        const DELETE: u32 = 0x0001_0000;
        const WRITE_BITS: u32 = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;
        let dir = tempfile::tempdir().unwrap();
        let root = evx_workspace::Dir::open_root(dir.path()).unwrap();
        let lease = root.lease().unwrap();
        assert_ne!(
            evx_windows_native::granted_access(lease.raw()).unwrap() & DELETE,
            0
        );
        let read = local_duplicate(&lease, READ_LEASE_ACCESS);
        let write = local_duplicate(&lease, WRITE_LEASE_ACCESS);
        let granted = |handle: &OwnedHandle| {
            evx_windows_native::granted_access(handle.as_raw_handle()).unwrap()
        };
        assert_eq!(granted(&read) & (DELETE | WRITE_BITS), 0);
        assert_eq!(granted(&write) & DELETE, 0);
        assert_eq!(granted(&write) & WRITE_BITS, WRITE_BITS);
        // The host's handle is gone; the reduced copies alone hold the lease.
        lease.release();
        assert!(
            root.lease().is_err(),
            "workspace not busy through the duplicates"
        );
        drop(write);
        assert!(
            root.lease().is_err(),
            "workspace not busy through the read duplicate"
        );
        // A reduced copy still serves the helper's directory operations.
        let through = evx_workspace::Dir::from(read);
        assert!(through.entries().unwrap().is_empty());
        assert!(through.stat_self().unwrap().kind == evx_workspace::Kind::Directory);
        drop(through);
        root.lease().unwrap().release();
    }

    #[test]
    fn helper_lease_access_never_includes_delete() {
        const DELETE: u32 = 0x0001_0000;
        assert_eq!(helper_lease_access("file-read"), READ_LEASE_ACCESS);
        assert_eq!(helper_lease_access("file"), WRITE_LEASE_ACCESS);
        assert_eq!(READ_LEASE_ACCESS & DELETE, 0);
        assert_eq!(WRITE_LEASE_ACCESS & DELETE, 0);
        assert_eq!(
            READ_LEASE_ACCESS & (FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY),
            0
        );
    }

    #[test]
    fn a_missing_image_is_refused_before_the_journal_entry() {
        use crate::direct_lifecycle::DirectLifecycle;
        let parent = tempfile::tempdir().unwrap();
        let path = parent.path().join("lifecycle");
        let context = DirectLifecycle::provision_fresh(&path).unwrap();
        let mut config = crate::Config::new(parent.path().join("missing-worker.exe"));
        config.direct_lifecycle = Some(context.scope("game-a").unwrap());
        let (tx, _) = std::sync::mpsc::sync_channel(8);
        // No process could have started, so this is a plain denial and the
        // journal stays clean.
        assert!(matches!(
            Peer::spawn(&config, "compile", parent.path(), Role::Compiler, tx, None),
            Err(Denied::Reason(_))
        ));
        assert!(super::super::child_admission_status().is_ok());
        drop(context);
        DirectLifecycle::open(&path).unwrap();
    }
}
