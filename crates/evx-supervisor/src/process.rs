//! Confined child processes: spawning, framed I/O, kernel observations and
//! bounded termination.
//!
//! Every child has its own process group, starts with an empty
//! environment and closed descriptors, and confines itself before reading
//! input. The supervisor is the only reaper of its children and uses `wait4`
//! so a helper shorter than one poll interval still has its CPU time counted.
//! Resource observations come from the kernel, never from the child.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use evx_api::{Denied, MAX_ARTIFACT_FRAME, MAX_FRAME};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Guest,
    File,
    Compiler,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Guest => "guest",
            Role::File => "file",
            Role::Compiler => "compiler",
        }
    }
}

#[derive(Debug)]
pub enum Event {
    /// One complete frame body from the child's stdout.
    Frame(Role, u64, Vec<u8>),
    /// A chunk of stderr.
    Stderr(Role, u64, Vec<u8>),
    /// A stream closed. `protocol_error` is set when it closed mid-frame or
    /// after an oversized length prefix.
    Closed(Role, u64, Stream, Option<&'static str>),
}

impl Event {
    pub fn origin(&self) -> (Role, u64) {
        match self {
            Self::Frame(role, id, _) | Self::Stderr(role, id, _) | Self::Closed(role, id, _, _) => {
                (*role, *id)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Child termination or durable cleanup was not confirmed. Quarantine its slot.
#[derive(Debug, thiserror::Error)]
#[error("child {pid} cleanup unconfirmed; quarantine its slot")]
pub struct CleanupTimeout {
    pub pid: i32,
}

#[derive(Debug, thiserror::Error)]
#[error("process measurement unavailable")]
pub struct ObservationUnavailable;

#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub rss_bytes: u64,
    pub cpu_seconds: f64,
}

pub struct Peer {
    pub role: Role,
    pub id: u64,
    pub pid: i32,
    pub started: Instant,
    child: Option<Child>,
    direct_invocation: Option<crate::direct_lifecycle::DirectInvocation>,
    ownership_lost: bool,
    #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
    apple: Option<crate::apple::ApplePeer>,
    stdin: Option<File>,
    pending_input: Vec<u8>,
    input_offset: usize,
    input_started: bool,
    pub exit_code: Option<i32>,
    // Physical reap evidence is separate from successful durable completion.
    observed_exit_code: Option<i32>,
    pub readers: u8,
    pub output_bytes: usize,
    pub frames: u32,
    pub diagnostics: Vec<u8>,
    pub max_cpu: f64,
    // Most recent post-exec sample. On Darwin, includes attributable terminal
    // high-water usage; the Apple service also includes its trusted overhead.
    pub last_rss: Option<u64>,
    // Role-specific state the supervisor tracks per peer.
    pub terminal: bool,
    pub prepared: bool,
    pub commit_sent: bool,
    pub limits_generation: u64,
}

const STDERR_RETAINED: usize = 4096;
pub(crate) const OUTPUT_QUOTA: usize = 256 * 1024;
pub(crate) const MAX_FRAMES: u32 = 130;
pub(crate) const EVENT_CAPACITY: usize = 8;

/// Mark all ambient descriptors close-on-exec. This also covers descriptors
/// a different host thread opened immediately before fork. The exec error
/// pipe stays open until exec, so Rust can still report launch failures.
#[cfg(target_os = "macos")]
unsafe fn seal_descriptors(keep_lease: bool) -> std::io::Result<()> {
    // A fixed buffer avoids allocation after fork. Refuse unusually large FD
    // tables instead of truncating enumeration and leaking unlisted handles.
    let mut entries: [libc::proc_fdinfo; 4096] = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&entries);
    let used = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            size as i32,
        )
    };
    if used <= 0
        || used as usize >= size
        || !(used as usize).is_multiple_of(std::mem::size_of::<libc::proc_fdinfo>())
    {
        return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
    }
    for entry in &entries[..used as usize / std::mem::size_of::<libc::proc_fdinfo>()] {
        let fd = entry.proc_fd;
        if fd <= 2 || (fd == 3 && keep_lease) {
            continue;
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn seal_descriptors(keep_lease: bool) -> std::io::Result<()> {
    let first = if keep_lease { 4u32 } else { 3u32 };
    if unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 4u32) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
unsafe fn seal_descriptors(_keep_lease: bool) -> std::io::Result<()> {
    Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
}

// Every spawn and every cleanup-uncertainty latch use the same lock. This
// prevents another xite from consuming a released scheduler slot to launch
// more processes after an old child could not be confirmed stopped.
static CHILD_ADMISSION_STOPPED: Mutex<bool> = Mutex::new(false);

fn quarantine_error() -> Denied {
    Denied::Quarantined(
        "child admission quarantined; confirm prior children stopped before restarting the host"
            .into(),
    )
}

pub fn child_admission_status() -> Result<(), Denied> {
    let stopped = CHILD_ADMISSION_STOPPED
        .lock()
        .map_err(|_| quarantine_error())?;
    if *stopped {
        Err(quarantine_error())
    } else {
        Ok(())
    }
}

/// Irreversible within this host process. No guest or operator API clears it.
pub(crate) fn quarantine_child_admission() {
    *CHILD_ADMISSION_STOPPED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
}

impl Peer {
    /// Spawn `worker <mode>` with `cwd`, an empty environment, and optionally
    /// the workspace lease descriptor duplicated onto descriptor 3 so the
    /// child inherits the `flock`.
    pub fn spawn(
        config: &crate::supervisor::Config,
        mode: &str,
        cwd: &Path,
        role: Role,
        events: SyncSender<Event>,
        lease_fd: Option<i32>,
    ) -> Result<Peer, Denied> {
        // Hold through spawn so quarantine and admission have one order.
        // No broker callbacks occur while holding this lock.
        #[allow(unused_mut)]
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
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        if let Some(apple) = &config.apple_xpc {
            if config.direct_lifecycle.is_some()
                || !config.worker_args.is_empty()
                || lease_fd.is_some()
                || !matches!(
                    (role, mode),
                    (Role::Guest, "run")
                        | (Role::Compiler, "compile")
                        | (Role::File, "file" | "file-read")
                )
            {
                return Err(Denied::new("unsupported Apple worker operation"));
            }
            let spawned = match crate::apple::ApplePeer::spawn(apple, role, mode) {
                Ok(spawned) => spawned,
                Err(error) => {
                    if matches!(error, Denied::Quarantined(_)) {
                        *stopped = true;
                    }
                    return Err(error);
                }
            };
            drop(stopped);
            let pid = spawned.peer.pid();
            let tx = events.clone();
            std::thread::spawn(move || read_frames(role, id, spawned.stdout, tx));
            std::thread::spawn(move || read_stderr(role, id, spawned.stderr, events));
            return Ok(Peer {
                role,
                id,
                pid,
                started: Instant::now(),
                child: None,
                direct_invocation: None,
                ownership_lost: false,
                apple: Some(spawned.peer),
                stdin: Some(spawned.stdin),
                pending_input: Vec::new(),
                input_offset: 0,
                input_started: false,
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
            });
        }
        let mut command = Command::new(&config.worker_binary);
        command
            .args(&config.worker_args)
            .arg(mode)
            .current_dir(cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        // SAFETY: the child uses only descriptor and process syscalls before
        // exec. No allocation, locks, or guest input are involved. The lease
        // is the only non-stdio descriptor deliberately kept across exec.
        unsafe {
            command.pre_exec(move || {
                if let Some(fd) = lease_fd {
                    if fd != 3 && libc::dup2(fd, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                seal_descriptors(lease_fd.is_some())
            });
        }
        let direct_invocation = config
            .direct_lifecycle
            .as_ref()
            .map(|scope| scope.begin(role))
            .transpose()?;
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) if direct_invocation.is_some() => {
                *stopped = true;
                return Err(Denied::Quarantined(
                    "direct worker launch outcome unconfirmed".into(),
                ));
            }
            Err(_) => return Err(Denied::new("worker launch failed")),
        };
        let pid = child.id() as i32;
        let stdin = child
            .stdin
            .take()
            .map(|input| File::from(std::os::fd::OwnedFd::from(input)));
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let mut peer = Peer {
            role,
            id,
            pid,
            started: Instant::now(),
            child: Some(child),
            direct_invocation,
            ownership_lost: false,
            #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
            apple: None,
            stdin,
            pending_input: Vec::new(),
            input_offset: 0,
            input_started: false,
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
        drop(stopped);
        let configured = peer.stdin.as_ref().is_some_and(|input| {
            let fd = input.as_raw_fd();
            // SAFETY: owned pipe; nonblocking writes preserve watchdog progress.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0
        });
        let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
            peer.close(Duration::from_millis(50), Duration::from_secs(2))
                .map_err(|_| quarantine_error())?;
            return Err(Denied::new("worker output pipes unavailable"));
        };
        if !configured {
            peer.close(Duration::from_millis(50), Duration::from_secs(2))
                .map_err(|_| quarantine_error())?;
            return Err(Denied::new("worker pipe configuration failed"));
        }
        let tx = events.clone();
        std::thread::spawn(move || read_frames(role, id, stdout, tx));
        std::thread::spawn(move || read_stderr(role, id, stderr, events));
        Ok(peer)
    }

    /// Queue one bounded frame, flushing only while the pipe is writable.
    /// The event loop calls `flush_input` on every watchdog tick. A second
    /// frame cannot overtake an incomplete frame or grow the input queue.
    pub fn send(&mut self, encoded: &[u8]) -> Result<(), Denied> {
        self.send_bounded(encoded, MAX_FRAME)
    }

    /// Only a guest's first input may carry the larger serialized artifact.
    /// Compiler input, file helpers and subsequent broker replies stay small.
    pub(crate) fn send_artifact_init(&mut self, encoded: &[u8]) -> Result<(), Denied> {
        if self.role != Role::Guest || self.input_started {
            return Err(Denied::new("unexpected artifact initialization"));
        }
        self.send_bounded(encoded, MAX_ARTIFACT_FRAME)
    }

    fn send_bounded(&mut self, encoded: &[u8], limit: usize) -> Result<(), Denied> {
        if encoded.len() > limit + 4 {
            return Err(Denied::new("outgoing frame limit"));
        }
        self.flush_input()?;
        if !self.pending_input.is_empty() {
            return Err(Denied::new("worker input backpressure"));
        }
        self.input_started = true;
        self.pending_input.extend_from_slice(encoded);
        self.flush_input()
    }

    pub fn flush_input(&mut self) -> Result<(), Denied> {
        while self.input_offset < self.pending_input.len() {
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| Denied::new("worker input closed"))?;
            match stdin.write(&self.pending_input[self.input_offset..]) {
                Ok(0) => return Err(Denied::new("worker input closed")),
                Ok(n) => self.input_offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Denied::new("worker input closed")),
            }
        }
        self.pending_input.clear();
        self.input_offset = 0;
        Ok(())
    }

    pub fn record_stderr(&mut self, chunk: &[u8]) {
        let room = STDERR_RETAINED.saturating_sub(self.diagnostics.len());
        self.diagnostics
            .extend_from_slice(&chunk[..chunk.len().min(room)]);
    }

    /// Kernel-owned usage for a live child.
    pub fn measure(&mut self) -> Result<(), Denied> {
        if self.exit_code.is_some() {
            return Ok(());
        }
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        if let Some(peer) = &self.apple {
            let (cpu, rss) = peer.measure()?;
            self.max_cpu = self.max_cpu.max(cpu);
            self.last_rss = Some(rss);
            return Ok(());
        }
        if self.ownership_lost {
            return Err(quarantine_error());
        }
        match sample_process(self.pid) {
            Ok(sample) => {
                self.last_rss = Some(sample.rss_bytes);
                if sample.cpu_seconds > self.max_cpu {
                    self.max_cpu = sample.cpu_seconds;
                }
                Ok(())
            }
            Err(SampleError::Gone) => {
                if self.poll().is_none() {
                    return Err(Denied::new("process measurement unavailable"));
                }
                Ok(())
            }
            Err(SampleError::Unavailable) => Err(Denied::new("process measurement unavailable")),
        }
    }

    /// Non-blocking reap through `wait4`, recording final CPU usage.
    pub fn poll(&mut self) -> Option<i32> {
        if self.exit_code.is_some() {
            return self.exit_code;
        }
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        if let Some(peer) = &self.apple {
            if let Ok((cpu, rss)) = peer.measure() {
                self.max_cpu = self.max_cpu.max(cpu);
                self.last_rss = Some(rss);
            }
            self.exit_code = peer.poll();
            self.observed_exit_code = peer.observed_exit_code();
            return self.exit_code;
        }
        self.poll_direct_with(|pid, status, usage| {
            // SAFETY: owned child identity and valid out-pointers.
            let reaped = unsafe { libc::wait4(pid, status, libc::WNOHANG, usage) };
            (
                reaped,
                if reaped < 0 {
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                } else {
                    0
                },
            )
        })
    }

    fn poll_direct_with(
        &mut self,
        wait: impl FnOnce(i32, &mut i32, &mut libc::rusage) -> (i32, i32),
    ) -> Option<i32> {
        if self.ownership_lost {
            return None;
        }
        let mut status = 0;
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        let (reaped, error) = wait(self.pid, &mut status, &mut usage);
        if reaped == self.pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            // A traced child can report a stopped status without being reaped.
            // Only terminal status completes the invocation.
            // The PID is no longer reserved after reap. Never signal it again.
            self.ownership_lost = true;
            self.child.take();
            let cpu = usage.ru_utime.tv_sec as f64
                + usage.ru_utime.tv_usec as f64 / 1e6
                + usage.ru_stime.tv_sec as f64
                + usage.ru_stime.tv_usec as f64 / 1e6;
            if cpu > self.max_cpu {
                self.max_cpu = cpu;
            }
            // Darwin's byte count is attributable to this executable. Linux
            // wait4 also retains the parent's inherited pre-exec high-water
            // mark, so it cannot establish this worker's memory consumption.
            // Keep only post-exec procfs samples there, including after reap.
            #[cfg(target_os = "macos")]
            {
                let terminal_rss = u64::try_from(usage.ru_maxrss).unwrap_or(0);
                self.last_rss = Some(self.last_rss.unwrap_or(0).max(terminal_rss));
            }
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                -libc::WTERMSIG(status)
            } else {
                -1
            };
            self.observed_exit_code = Some(code);
            if let Some(mut invocation) = self.direct_invocation.take() {
                if invocation.complete().is_err() {
                    quarantine_child_admission();
                    return None;
                }
            }
            self.exit_code = Some(code);
        } else if reaped < 0 && error != libc::EINTR {
            // ECHILD and unexpected errors do not prove whose process now
            // owns this PID. Preserve durable uncertainty and never signal it.
            self.ownership_lost = true;
            self.child.take();
            quarantine_child_admission();
        }
        self.exit_code
    }

    /// Terminate then kill the child's process group and reap it within the
    /// cleanup budget. A `CleanupTimeout` is a quarantine signal.
    pub fn close(&mut self, grace: Duration, cleanup: Duration) -> Result<i32, CleanupTimeout> {
        self.stdin.take();
        if let Some(code) = self.poll() {
            return Ok(code);
        }
        #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
        if let Some(peer) = &self.apple {
            let code = peer.close(cleanup)?;
            if let Ok((cpu, rss)) = peer.measure() {
                self.max_cpu = self.max_cpu.max(cpu);
                self.last_rss = Some(rss);
            }
            self.exit_code = Some(code);
            return Ok(code);
        }
        if self.ownership_lost {
            return Err(CleanupTimeout { pid: self.pid });
        }
        let deadline = Instant::now() + cleanup;
        // SAFETY: target our child's group and the unreaped child itself.
        // A compromised child changing groups must not evade termination.
        // Its PID cannot be reused until this supervisor reaps it.
        unsafe {
            libc::killpg(self.pid, libc::SIGTERM);
            libc::kill(self.pid, libc::SIGTERM);
        }
        let grace_deadline = Instant::now() + grace;
        while Instant::now() < grace_deadline {
            if let Some(code) = self.poll() {
                return Ok(code);
            }
            if self.ownership_lost {
                return Err(CleanupTimeout { pid: self.pid });
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.ownership_lost {
            return Err(CleanupTimeout { pid: self.pid });
        }
        unsafe {
            libc::killpg(self.pid, libc::SIGKILL);
            libc::kill(self.pid, libc::SIGKILL);
        }
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
        // gone; the normal path has already reaped it.
        if self.exit_code.is_none() {
            let _ = self.close(Duration::from_millis(50), Duration::from_millis(500));
        }
        // Child::try_wait cannot supply this journal's trusted wait4 evidence.
        // Cleanup above owns all reaping; uncertainty must remain durable.
    }
}

fn read_frames(role: Role, id: u64, mut stdout: impl Read, tx: SyncSender<Event>) {
    let frame_limit = if role == Role::Compiler {
        MAX_ARTIFACT_FRAME
    } else {
        MAX_FRAME
    };
    let mut bytes = 0usize;
    let mut frames = 0u32;
    loop {
        let mut len = [0u8; 4];
        // Distinguish a clean boundary EOF from a truncated length prefix.
        match stdout.read(&mut len[..1]) {
            Ok(0) => {
                let _ = tx.send(Event::Closed(role, id, Stream::Stdout, None));
                return;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = tx.send(Event::Closed(
                    role,
                    id,
                    Stream::Stdout,
                    Some("worker output read failed"),
                ));
                return;
            }
        }
        if stdout.read_exact(&mut len[1..]).is_err() {
            let _ = tx.send(Event::Closed(
                role,
                id,
                Stream::Stdout,
                Some("truncated worker frame"),
            ));
            return;
        }
        let len = u32::from_be_bytes(len) as usize;
        frames += 1;
        if len == 0
            || len > frame_limit
            || frames > MAX_FRAMES
            || len > OUTPUT_QUOTA.saturating_sub(bytes)
        {
            let _ = tx.send(Event::Closed(
                role,
                id,
                Stream::Stdout,
                Some("worker frame quota"),
            ));
            return;
        }
        bytes += len;
        let mut body = vec![0u8; len];
        if stdout.read_exact(&mut body).is_err() {
            let _ = tx.send(Event::Closed(
                role,
                id,
                Stream::Stdout,
                Some("truncated worker frame"),
            ));
            return;
        }
        if tx.send(Event::Frame(role, id, body)).is_err() {
            return;
        }
    }
}

fn read_stderr(role: Role, id: u64, mut stderr: impl Read, tx: SyncSender<Event>) {
    let mut buffer = [0u8; 4096];
    let mut bytes = 0usize;
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => {
                let _ = tx.send(Event::Closed(role, id, Stream::Stderr, None));
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = tx.send(Event::Closed(
                    role,
                    id,
                    Stream::Stderr,
                    Some("worker diagnostics read failed"),
                ));
                return;
            }
            Ok(n) => {
                bytes += n;
                if bytes > OUTPUT_QUOTA {
                    let _ = tx.send(Event::Closed(
                        role,
                        id,
                        Stream::Stderr,
                        Some("worker output quota"),
                    ));
                    return;
                }
                if tx
                    .send(Event::Stderr(role, id, buffer[..n].to_vec()))
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

enum SampleError {
    /// Only the macOS sampler can tell a vanished process from an
    /// unavailable measurement; other platforms fail closed as unavailable.
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    Gone,
    Unavailable,
}

#[cfg(target_os = "macos")]
#[allow(deprecated)] // libc's mach_timebase_info binding is stable ABI; mach2 is not a direct dependency
fn sample_process(pid: i32) -> Result<Sample, SampleError> {
    use std::sync::OnceLock;
    static TIMEBASE: OnceLock<Option<(u64, u64)>> = OnceLock::new();
    let timebase = TIMEBASE.get_or_init(|| {
        let mut info = libc::mach_timebase_info { numer: 0, denom: 0 };
        // SAFETY: plain FFI with a valid out-pointer.
        if unsafe { libc::mach_timebase_info(&mut info) } != 0 || info.numer == 0 || info.denom == 0
        {
            None
        } else {
            Some((u64::from(info.numer), u64::from(info.denom)))
        }
    });
    let (numer, denom) = (*timebase).ok_or(SampleError::Unavailable)?;
    let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
    // SAFETY: RUSAGE_INFO_V2 matches the struct passed; the kernel fills it.
    let rc = unsafe {
        libc::proc_pid_rusage(
            pid,
            libc::RUSAGE_INFO_V2,
            &mut info as *mut libc::rusage_info_v2 as *mut libc::rusage_info_t,
        )
    };
    if rc != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(if errno == libc::ESRCH {
            SampleError::Gone
        } else {
            SampleError::Unavailable
        });
    }
    let user_ns = info.ri_user_time.saturating_mul(numer) / denom;
    let system_ns = info.ri_system_time.saturating_mul(numer) / denom;
    Ok(Sample {
        rss_bytes: info.ri_resident_size,
        cpu_seconds: (user_ns + system_ns) as f64 / 1e9,
    })
}

#[cfg(target_os = "linux")]
fn sample_process(pid: i32) -> Result<Sample, SampleError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SampleError::Gone
        } else {
            SampleError::Unavailable
        }
    })?;
    // comm is parenthesized and can contain spaces or parentheses. Fields
    // following its last ')' begin at process state (field 3).
    let end = stat.rfind(')').ok_or(SampleError::Unavailable)?;
    let fields: Vec<_> = stat[end + 1..].split_whitespace().collect();
    let value = |index: usize| -> Result<u64, SampleError> {
        fields
            .get(index)
            .ok_or(SampleError::Unavailable)?
            .parse()
            .map_err(|_| SampleError::Unavailable)
    };
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ticks <= 0 || page_size <= 0 {
        return Err(SampleError::Unavailable);
    }
    Ok(Sample {
        rss_bytes: value(21)?
            .checked_mul(page_size as u64)
            .ok_or(SampleError::Unavailable)?,
        cpu_seconds: (value(11)? as f64 + value(12)? as f64) / ticks as f64,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sample_process(_pid: i32) -> Result<Sample, SampleError> {
    // No kernel accounting implemented for this platform yet. Fail closed.
    Err(SampleError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inert_peer(invocation: Option<crate::direct_lifecycle::DirectInvocation>) -> Peer {
        Peer {
            role: Role::Compiler,
            id: 1,
            pid: i32::MAX,
            started: Instant::now(),
            child: None,
            direct_invocation: invocation,
            ownership_lost: false,
            #[cfg(all(target_os = "macos", feature = "apple-xpc"))]
            apple: None,
            stdin: None,
            pending_input: Vec::new(),
            input_offset: 0,
            input_started: false,
            exit_code: None,
            observed_exit_code: None,
            readers: 0,
            output_bytes: 0,
            frames: 0,
            diagnostics: Vec::new(),
            max_cpu: 0.0,
            last_rss: None,
            terminal: false,
            prepared: false,
            commit_sent: false,
            limits_generation: 0,
        }
    }

    #[test]
    fn wait_errors_and_journal_failures_preserve_process_uncertainty() {
        use crate::direct_lifecycle::DirectLifecycle;
        let parent = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.path().join("lifecycle");
        let context = DirectLifecycle::provision_fresh(&path).unwrap();
        let scope = context.scope("game-a").unwrap();
        let mut peer = inert_peer(Some(scope.begin(Role::Compiler).unwrap()));
        assert_eq!(
            peer.poll_direct_with(|pid, status, _| {
                *status = (libc::SIGSTOP << 8) | 0x7f;
                (pid, 0)
            }),
            None
        );
        assert!(!peer.ownership_lost);
        assert_eq!(peer.poll_direct_with(|_, _, _| (-1, libc::EINTR)), None);
        assert!(!peer.ownership_lost);
        assert!(DirectLifecycle::open(&path).is_err());
        assert_eq!(
            peer.poll_direct_with(|pid, status, usage| {
                *status = 0;
                usage.ru_utime.tv_sec = 1;
                (pid, 0)
            }),
            Some(0)
        );
        assert_eq!(peer.max_cpu, 1.0);
        let reopened = DirectLifecycle::open(&path).unwrap();
        let mut peer = inert_peer(Some(
            reopened.scope("game-a").unwrap().begin(Role::File).unwrap(),
        ));
        assert_eq!(peer.poll_direct_with(|_, _, _| (-1, libc::ECHILD)), None);
        assert!(peer.ownership_lost);
        assert!(peer.close(Duration::ZERO, Duration::ZERO).is_err());
        assert!(child_admission_status().is_err());
        assert!(DirectLifecycle::open(&path).is_err());
        // No syscall may use this lost identity again, including Drop.
        assert_eq!(
            peer.poll_direct_with(|_, _, _| panic!("lost child was waited again")),
            None
        );
        drop(peer);
        *CHILD_ADMISSION_STOPPED.lock().unwrap() = false;

        let other = parent.path().join("other");
        let context = DirectLifecycle::provision_fresh(&other).unwrap();
        let mut peer = inert_peer(Some(
            context.scope("game-a").unwrap().begin(Role::Guest).unwrap(),
        ));
        std::fs::remove_file(other.join("lifecycle.json")).unwrap();
        assert_eq!(
            peer.poll_direct_with(|pid, status, usage| {
                *status = 0;
                usage.ru_utime.tv_sec = 2;
                (pid, 0)
            }),
            None
        );
        assert_eq!(peer.max_cpu, 2.0);
        assert_eq!(peer.observed_exit_code(), Some(0));
        assert_eq!(peer.exit_code, None);
        assert!(peer.ownership_lost);
        assert!(peer.close(Duration::ZERO, Duration::ZERO).is_err());
        assert!(child_admission_status().is_err());
        drop(peer);
        *CHILD_ADMISSION_STOPPED.lock().unwrap() = false;

        let third = parent.path().join("launch");
        let context = DirectLifecycle::provision_fresh(&third).unwrap();
        let mut config = crate::Config::new(parent.path().join("missing-worker"));
        config.direct_lifecycle = Some(context.scope("game-a").unwrap());
        let (tx, _) = std::sync::mpsc::sync_channel(8);
        assert!(matches!(
            Peer::spawn(&config, "compile", parent.path(), Role::Compiler, tx, None),
            Err(Denied::Quarantined(_))
        ));
        assert!(child_admission_status().is_err());
        assert!(DirectLifecycle::open(&third).is_err());
        *CHILD_ADMISSION_STOPPED.lock().unwrap() = false;
    }

    #[test]
    fn compiler_artifact_envelope_does_not_expand_guest_or_helper_output() {
        let len = MAX_FRAME + 1;
        let mut bytes = (len as u32).to_be_bytes().to_vec();
        bytes.resize(len + 4, b' ');
        for role in [Role::Guest, Role::File, Role::Compiler] {
            let (tx, rx) = std::sync::mpsc::sync_channel(8);
            read_frames(role, 0, std::io::Cursor::new(&bytes), tx);
            let events: Vec<_> = rx.try_iter().collect();
            assert_eq!(
                matches!(events.first(), Some(Event::Frame(..))),
                role == Role::Compiler
            );
        }
        // The compiler's aggregate output budget remains 256 KiB. A second
        // otherwise valid large frame is rejected before allocating its body.
        let mut twice = bytes.clone();
        twice.extend_from_slice(&bytes);
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        read_frames(Role::Compiler, 0, std::io::Cursor::new(twice), tx);
        let events: Vec<_> = rx.try_iter().collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::Frame(..)))
                .count(),
            1
        );
        assert!(matches!(
            events.last(),
            Some(Event::Closed(_, _, _, Some("worker frame quota")))
        ));
    }

    #[test]
    fn compiler_artifact_prefix_above_cap_is_rejected_before_body() {
        let bytes = ((MAX_ARTIFACT_FRAME + 1) as u32).to_be_bytes();
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        read_frames(Role::Compiler, 0, std::io::Cursor::new(bytes), tx);
        assert!(matches!(
            rx.recv().unwrap(),
            Event::Closed(_, _, _, Some("worker frame quota"))
        ));
    }

    #[test]
    fn reader_bounds_flood_before_supervisor_dequeues_it() {
        let mut bytes = Vec::new();
        for _ in 0..1000 {
            bytes.extend_from_slice(&2u32.to_be_bytes());
            bytes.extend_from_slice(b"{}");
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1024);
        read_frames(Role::Guest, 0, std::io::Cursor::new(bytes), tx);
        let events: Vec<_> = rx.try_iter().collect();
        assert!(
            events.len() <= 131,
            "queued {} events before applying quota",
            events.len()
        );
        assert!(matches!(
            events.last(),
            Some(Event::Closed(_, _, _, Some(_)))
        ));
    }
}
