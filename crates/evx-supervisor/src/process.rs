//! Confined child processes: spawning, framed I/O, kernel observations and
//! bounded termination.
//!
//! Every child is its own session and process group, starts with an empty
//! environment and closed descriptors, and confines itself before reading
//! input. The supervisor is the only reaper of its children and uses `wait4`
//! so a helper shorter than one poll interval still has its CPU time counted.
//! Resource observations come from the kernel, never from the child.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use evx_api::{Denied, MAX_FRAME};

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
    Frame(Role, Vec<u8>),
    /// A chunk of stderr.
    Stderr(Role, Vec<u8>),
    /// A stream closed. `protocol_error` is set when it closed mid-frame or
    /// after an oversized length prefix.
    Closed(Role, Stream, Option<&'static str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// The child was not reaped within the cleanup budget. Quarantine its slot.
#[derive(Debug, thiserror::Error)]
#[error("child {pid} was not reaped; quarantine its slot")]
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
    pub pid: i32,
    pub started: Instant,
    child: Child,
    stdin: Option<ChildStdin>,
    pub exit_code: Option<i32>,
    pub readers: u8,
    pub output_bytes: usize,
    pub frames: u32,
    pub diagnostics: Vec<u8>,
    pub max_cpu: f64,
    pub last_rss: Option<u64>,
    // Role-specific state the supervisor tracks per peer.
    pub terminal: bool,
    pub prepared: bool,
    pub commit_sent: bool,
    pub limits_generation: u64,
}

const STDERR_RETAINED: usize = 4096;

impl Peer {
    /// Spawn `worker <mode>` with `cwd`, an empty environment, and optionally
    /// the workspace lease descriptor duplicated onto descriptor 3 so the
    /// child inherits the `flock`.
    pub fn spawn(
        config: &crate::supervisor::Config,
        mode: &str,
        cwd: &Path,
        role: Role,
        events: Sender<Event>,
        lease_fd: Option<i32>,
    ) -> Result<Peer, Denied> {
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
        if let Some(fd) = lease_fd {
            // SAFETY: dup2 and fcntl are async-signal-safe and the descriptor
            // stays open in the parent for the child's whole lifetime. dup2 to
            // a different number clears close-on-exec; when the lease already
            // is descriptor 3, dup2 is a no-op and the flag must be cleared
            // explicitly or the lease would close at exec.
            unsafe {
                command.pre_exec(move || {
                    if fd != 3 && libc::dup2(fd, 3) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command
            .spawn()
            .map_err(|_| Denied::new("worker launch failed"))?;
        let pid = child.id() as i32;
        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Denied::new("worker stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Denied::new("worker stderr"))?;
        let tx = events.clone();
        std::thread::spawn(move || read_frames(role, stdout, tx));
        let tx = events;
        std::thread::spawn(move || read_stderr(role, stderr, tx));
        Ok(Peer {
            role,
            pid,
            started: Instant::now(),
            child,
            stdin,
            exit_code: None,
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
        })
    }

    /// Write one encoded frame. Frames are small and the child reads promptly;
    /// a child that stops reading is killed by the deadlines, not by a stuck
    /// write, because the pipe buffer exceeds any frame the supervisor sends.
    pub fn send(&mut self, encoded: &[u8]) -> Result<(), Denied> {
        if encoded.len() > MAX_FRAME + 4 {
            return Err(Denied::new("outgoing frame limit"));
        }
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| Denied::new("worker input closed"))?;
        stdin
            .write_all(encoded)
            .map_err(|_| Denied::new("worker input closed"))?;
        stdin
            .flush()
            .map_err(|_| Denied::new("worker input closed"))
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
        let mut status: libc::c_int = 0;
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: plain FFI with valid out-pointers; this supervisor is the
        // only reaper of its own children.
        let reaped = unsafe { libc::wait4(self.pid, &mut status, libc::WNOHANG, &mut usage) };
        if reaped == self.pid {
            let cpu = usage.ru_utime.tv_sec as f64
                + usage.ru_utime.tv_usec as f64 / 1e6
                + usage.ru_stime.tv_sec as f64
                + usage.ru_stime.tv_usec as f64 / 1e6;
            if cpu > self.max_cpu {
                self.max_cpu = cpu;
            }
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                -libc::WTERMSIG(status)
            } else {
                -1
            };
            self.exit_code = Some(code);
        } else if reaped < 0 {
            // ECHILD: already reaped elsewhere. Treat as an abnormal exit.
            self.exit_code = Some(-1);
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
        let deadline = Instant::now() + cleanup;
        // SAFETY: signalling our own child's dedicated process group.
        unsafe {
            libc::killpg(self.pid, libc::SIGTERM);
        }
        let grace_deadline = Instant::now() + grace;
        while Instant::now() < grace_deadline {
            if let Some(code) = self.poll() {
                return Ok(code);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        unsafe {
            libc::killpg(self.pid, libc::SIGKILL);
        }
        while Instant::now() < deadline {
            if let Some(code) = self.poll() {
                return Ok(code);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Err(CleanupTimeout { pid: self.pid })
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
        let _ = self.child.try_wait();
    }
}

fn read_frames(role: Role, mut stdout: impl Read, tx: Sender<Event>) {
    loop {
        let mut len = [0u8; 4];
        if stdout.read_exact(&mut len).is_err() {
            let _ = tx.send(Event::Closed(role, Stream::Stdout, None));
            return;
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_FRAME {
            let _ = tx.send(Event::Closed(
                role,
                Stream::Stdout,
                Some("worker frame quota"),
            ));
            return;
        }
        let mut body = vec![0u8; len];
        if stdout.read_exact(&mut body).is_err() {
            let _ = tx.send(Event::Closed(
                role,
                Stream::Stdout,
                Some("truncated worker frame"),
            ));
            return;
        }
        if tx.send(Event::Frame(role, body)).is_err() {
            return;
        }
    }
}

fn read_stderr(role: Role, mut stderr: impl Read, tx: Sender<Event>) {
    let mut buffer = [0u8; 4096];
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) | Err(_) => {
                let _ = tx.send(Event::Closed(role, Stream::Stderr, None));
                return;
            }
            Ok(n) => {
                if tx.send(Event::Stderr(role, buffer[..n].to_vec())).is_err() {
                    return;
                }
            }
        }
    }
}

enum SampleError {
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

#[cfg(not(target_os = "macos"))]
fn sample_process(_pid: i32) -> Result<Sample, SampleError> {
    // No kernel accounting implemented for this platform yet. Fail closed.
    Err(SampleError::Unavailable)
}
