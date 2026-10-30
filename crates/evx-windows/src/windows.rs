use crate::denial::{denied, descendant_denied, winsock_startup_denied};
use evx_windows_native::{
    create_job, current_user_sid_text, fail, inherited_object, launch_suspended, ok, protect,
    resume, terminate_job, validate_token, verify_launched, wide, worker_environment, Handle,
    JobLimits, LaunchSpec, Profile, TERMINATED,
};
use std::{
    io,
    mem::{size_of, zeroed},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Cryptography::*, SECURITY_ATTRIBUTES},
    Storage::FileSystem::*,
    System::{JobObjects::*, Memory::*, Pipes::*, Threading::*},
};

const MEMORY: usize = 64 * 1024 * 1024;
const CPU_100NS: i64 = 5_000_000;
const FRAME: [u8; 8] = *b"EVX042\r\n";
/// The fixed fixture job: 64 MiB, 500 ms of user time and half a processor.
pub(crate) const FIXTURE_LIMITS: JobLimits = JobLimits {
    process_memory: MEMORY,
    job_memory: MEMORY,
    per_process_user_100ns: CPU_100NS,
    per_job_user_100ns: CPU_100NS,
    cpu_rate_hard_cap_percent_x100: Some(5000),
};

fn random_id() -> io::Result<String> {
    let mut random = [0u8; 16];
    if unsafe {
        BCryptGenRandom(
            null_mut(),
            random.as_mut_ptr(),
            random.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return Err(fail("fixture randomness unavailable"));
    }
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

fn inheritable() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    }
}

/// An anonymous pipe whose write end is inheritable and whose read end is not.
fn reply_pipe() -> io::Result<(Handle, Handle)> {
    let mut read = null_mut();
    let mut write = null_mut();
    unsafe {
        ok(CreatePipe(&mut read, &mut write, &inheritable(), 4096))?;
    }
    let reader = Handle::checked(read)?;
    let writer = Handle::checked(write)?;
    unsafe {
        ok(SetHandleInformation(reader.raw(), HANDLE_FLAG_INHERIT, 0))?;
    }
    Ok((reader, writer))
}

struct Stage {
    root: PathBuf,
    directory: Option<tempfile::TempDir>,
    executable: PathBuf,
    profile: Option<Profile>,
    active: bool,
}
impl Stage {
    fn new() -> io::Result<Self> {
        Self::with_executable(&std::env::current_exe()?)
    }
    fn with_executable(source: &Path) -> io::Result<Self> {
        Self::with_image(|target| std::fs::copy(source, target).map(|_| ()))
    }
    fn with_bytes(bytes: &[u8]) -> io::Result<Self> {
        Self::with_image(|target| std::fs::write(target, bytes))
    }
    fn with_image(write_executable: impl FnOnce(&Path) -> io::Result<()>) -> io::Result<Self> {
        let profile = Profile::create(&format!("Epix.EvxFixture.{}", random_id()?))?;
        if !profile.created() {
            return Err(fail(
                "fresh AppContainer profile failed: name already exists",
            ));
        }
        let owner = current_user_sid_text()?;
        let package = profile.sid_text()?;
        let private = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})");
        let readable = format!("{private}(A;OICI;GRGX;;;{package})");
        let directory = tempfile::Builder::new().prefix("evx-windows-").tempdir()?;
        let root = directory.path().to_path_buf();
        // Apply the protected DACL before staging any executable or host data.
        protect(&root, &readable)?;
        let stage = Self {
            directory: Some(directory),
            executable: root.join("game.exe"),
            root,
            profile: Some(profile),
            active: false,
        };
        write_executable(&stage.executable)?;
        protect(&stage.executable, &readable)?;
        let canary = stage.root.join("private-game-save");
        std::fs::write(&canary, b"disposable host game data")?;
        protect(&canary, &private)?;
        Ok(stage)
    }
    fn launch(&mut self, mode: Mode, port: u16) -> io::Result<Child> {
        if self.active {
            return Err(fail("fixture stage already active or quarantined"));
        }
        let profile = self
            .profile
            .as_ref()
            .ok_or_else(|| fail("missing profile"))?;
        let job = create_job(&FIXTURE_LIMITS)?;
        let (reader, writer) = reply_pipe()?;
        // Deliberately inheritable, but excluded from the explicit handle list.
        let excluded = Handle::checked(unsafe { CreateEventW(&inheritable(), 1, 0, null()) })?;
        // Only our fixed enum and decimal handles/loopback port enter argv. The
        // executable is also supplied separately, never searched through PATH.
        // The same explicitly inherited private pipe also captures bounded
        // startup diagnostics; no host console handles are inherited, and no
        // parent environment is inherited.
        let mut spec = LaunchSpec {
            executable: &self.executable,
            command_line: format!(
                "\"{}\" --evx-fixed-child {} {} {}",
                self.executable.display(),
                mode as u32,
                writer.raw() as usize,
                port
            ),
            current_directory: &self.root,
            environment: worker_environment()?,
            container_sid: profile.sid(),
            job: &job,
            inherited_handles: vec![writer.raw()],
            stdin: INVALID_HANDLE_VALUE,
            stdout: writer.raw(),
            stderr: writer.raw(),
        };
        let launched = launch_suspended(&mut spec)
            .map_err(|error| fail(&format!("CreateProcessW LPAC fixture: {error}")))?;
        self.active = true;
        // An error from here leaves the stage quarantined; closing the job kills
        // the process but is not treated as confirmation that it has died.
        verify_launched(&launched, &job, profile.sid())?;
        // Inspect the suspended child's handle table from the host. Calling
        // SetEvent on an excluded value inside LPAC triggers strict-handle
        // termination, preventing the remaining denial probes from running.
        if !inherited_object(launched.process.raw(), &writer)? {
            return Err(fail("explicit reply handle was not inherited"));
        }
        if inherited_object(launched.process.raw(), &excluded)? {
            return Err(fail("excluded event was inherited"));
        }
        drop(writer);
        resume(&launched)?;
        Ok(Child {
            process: launched.process,
            job: Some(job),
            reader,
            excluded,
            started: Instant::now(),
        })
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if self.active {
            execution::quarantine();
            // Do not delete/reassign a profile after an unconfirmed child lifetime.
            if let Some(profile) = self.profile.as_mut() {
                // Retain the OS profile but release the local SID allocation.
                profile.retain();
            }
            if let Some(directory) = self.directory.take() {
                let _ = directory.keep();
            }
            eprintln!(
                "retained unconfirmed fixture directory: {}",
                self.root.display()
            );
        } else if let Some(directory) = self.directory.take() {
            if let Err(error) = directory.close() {
                eprintln!("fixture cleanup failed at {}: {error}", self.root.display());
            }
        }
    }
}

struct Child {
    process: Handle,
    job: Option<Handle>,
    reader: Handle,
    excluded: Handle,
    started: Instant,
}
struct Outcome {
    code: u32,
    deadline: bool,
    user_100ns: i64,
    peak_bytes: usize,
}
impl Child {
    fn confirm_ready(&self, wall: Duration) -> io::Result<()> {
        loop {
            if unsafe { WaitForSingleObject(self.process.raw(), 0) } != WAIT_TIMEOUT {
                return Err(fail("sleep fixture exited before job-close probe"));
            }
            let mut bytes = 0;
            unsafe {
                ok(PeekNamedPipe(
                    self.reader.raw(),
                    null_mut(),
                    0,
                    null_mut(),
                    &mut bytes,
                    null_mut(),
                ))?;
            }
            if bytes != 0 {
                verify_fixture_reply(&self.reader, 0)?;
                if unsafe { WaitForSingleObject(self.process.raw(), 0) } != WAIT_TIMEOUT {
                    return Err(fail("sleep fixture died before closing the job"));
                }
                return Ok(());
            }
            if self.started.elapsed() >= wall {
                return Err(fail("sleep fixture did not confirm readiness"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(
        mut self,
        stage: &mut Stage,
        wall: Duration,
        close_job: bool,
        expect_reply: bool,
    ) -> io::Result<Outcome> {
        // KILL_ON_JOB_CLOSE test retains the process handle as independent death
        // evidence. ActiveProcessLimit=1 plus child restriction prevents descendants.
        if close_job {
            self.confirm_ready(wall)?;
            drop(self.job.take());
        }
        let deadline;
        loop {
            match unsafe { WaitForSingleObject(self.process.raw(), 10) } {
                WAIT_OBJECT_0 => {
                    deadline = self.started.elapsed() >= wall;
                    break;
                }
                WAIT_TIMEOUT => {}
                _ => return Err(fail("wait did not confirm child death")),
            }
            if self.started.elapsed() >= wall {
                deadline = true;
                if let Some(job) = &self.job {
                    terminate_job(job.raw(), TERMINATED)?;
                }
                if unsafe { WaitForSingleObject(self.process.raw(), 3000) } != WAIT_OBJECT_0 {
                    return Err(fail("termination unconfirmed; fixture retained"));
                }
                break;
            }
        }
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        if let Some(job) = &self.job {
            // Signaled process is necessary but does not by itself prove an empty job.
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                unsafe {
                    ok(QueryInformationJobObject(
                        job.raw(),
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut(),
                    ))?;
                }
                if accounting.ActiveProcesses == 0 {
                    break;
                }
                if Instant::now() >= until {
                    return Err(fail("job still contains an active process"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            unsafe {
                ok(QueryInformationJobObject(
                    job.raw(),
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    null_mut(),
                ))?;
            }
        }
        let mut code = 0;
        unsafe {
            ok(GetExitCodeProcess(self.process.raw(), &mut code))?;
        }
        // Only native wait and empty-job evidence clear quarantine, even if later
        // reply checks fail. Exit code alone, including STILL_ACTIVE, never clears it.
        stage.active = false;
        if unsafe { WaitForSingleObject(self.excluded.raw(), 0) } != WAIT_TIMEOUT {
            return Err(fail("excluded event was inherited or signaled"));
        }
        if expect_reply {
            verify_fixture_reply(&self.reader, code)?;
        }
        Ok(Outcome {
            code,
            deadline,
            user_100ns: accounting.TotalUserTime,
            peak_bytes: limits.PeakJobMemoryUsed,
        })
    }
}
fn verify_fixture_reply(reader: &Handle, code: u32) -> io::Result<()> {
    let mut bytes = 0;
    unsafe {
        ok(PeekNamedPipe(
            reader.raw(),
            null_mut(),
            0,
            null_mut(),
            &mut bytes,
            null_mut(),
        ))
        .map_err(|error| fail(&format!("child exit 0x{code:08x} without a reply: {error}")))?;
    }
    if bytes == 0 || bytes > 4096 {
        return Err(fail(&format!(
            "child exit 0x{code:08x}: invalid reply size {bytes}"
        )));
    }
    let mut reply = vec![0u8; bytes as usize];
    let mut read = 0;
    unsafe {
        ok(ReadFile(
            reader.raw(),
            reply.as_mut_ptr(),
            bytes,
            &mut read,
            null_mut(),
        ))?;
    }
    if read != bytes || code != 0 || reply != FRAME {
        return Err(fail(&format!(
            "child exit 0x{code:08x}: invalid reply: {}",
            String::from_utf8_lossy(&reply)
        )));
    }
    Ok(())
}

struct Winsock;
impl Winsock {
    fn start() -> io::Result<Self> {
        use windows_sys::Win32::Networking::WinSock::{WSAStartup, WSADATA};
        let mut data: WSADATA = unsafe { zeroed() };
        let status = unsafe { WSAStartup(0x0202, &mut data) };
        if status == 0 {
            Ok(Self)
        } else {
            Err(io::Error::from_raw_os_error(status))
        }
    }
}
impl Drop for Winsock {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Networking::WinSock::WSACleanup() };
    }
}

fn winsock_catalog_access() -> io::Result<()> {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
    };
    let path = wide(r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9")?;
    let mut key = null_mut();
    let status = unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_QUERY_VALUE, &mut key)
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let status = unsafe { RegCloseKey(key) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

fn network_denials(port: u16) -> io::Result<()> {
    // Rust's networking initialization asserts that WSAStartup succeeds. A
    // zero-capability LPAC can deny the catalog access needed even to start it.
    // Check the native status first and require a separate permission denial;
    // unavailable networking or another startup error cannot pass this test.
    let _winsock = match Winsock::start() {
        Ok(winsock) => winsock,
        Err(error) => {
            return winsock_startup_denied(
                error.raw_os_error().unwrap_or(0),
                winsock_catalog_access(),
            );
        }
    };
    denied(
        TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(500),
        ),
        "loopback connection",
    )?;
    denied(TcpListener::bind("127.0.0.1:0"), "network listen")
}

impl Drop for Child {
    fn drop(&mut self) {
        drop(self.job.take());
    }
}

#[derive(Clone, Copy)]
#[repr(u32)]
enum Mode {
    Game = 1,
    NativeDenials = 2,
    Memory = 3,
    Cpu = 4,
    Sleep = 5,
}
impl Mode {
    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "1" => Ok(Self::Game),
            "2" => Ok(Self::NativeDenials),
            "3" => Ok(Self::Memory),
            "4" => Ok(Self::Cpu),
            "5" => Ok(Self::Sleep),
            _ => Err(fail("invalid fixed fixture mode")),
        }
    }
}
fn child(args: &[String]) -> io::Result<()> {
    if args.len() != 5 {
        return Err(fail("invalid child frame"));
    }
    let mode = Mode::parse(&args[2])?;
    let writer = args[3]
        .parse::<usize>()
        .map_err(|_| fail("bad reply handle"))? as HANDLE;
    let port = args[4]
        .parse::<u16>()
        .map_err(|_| fail("bad loopback port"))?;
    validate_token(unsafe { GetCurrentProcess() }, None)?;
    match mode {
        Mode::Game => {}
        Mode::NativeDenials => {
            let exe = std::env::current_exe()?;
            let root = exe.parent().ok_or_else(|| fail("missing stage root"))?;
            denied(
                std::fs::read(root.join("private-game-save")),
                "host-private fixture read",
            )?;
            denied(
                std::fs::write(root.join("unexpected-save"), b"42"),
                "package write",
            )?;
            descendant_denied(
                std::process::Command::new(exe)
                    .arg("--unexpected-child")
                    .spawn(),
            )?;
            network_denials(port)?;
        }
        Mode::Memory => {
            let small =
                unsafe { VirtualAlloc(null(), 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
            if small.is_null() {
                return Err(fail("baseline memory allocation failed"));
            }
            unsafe {
                ok(VirtualFree(small, 0, MEM_RELEASE))?;
            }
            let allocation = unsafe {
                VirtualAlloc(null(), MEMORY * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
            };
            if !allocation.is_null() {
                unsafe {
                    VirtualFree(allocation, 0, MEM_RELEASE);
                }
                return Err(fail("allocation above memory budget succeeded"));
            }
        }
        Mode::Cpu => loop {
            std::hint::black_box(42u64.wrapping_mul(12345));
        },
        Mode::Sleep => {
            write_fixture_reply(writer)?;
            std::thread::sleep(Duration::from_secs(60));
            return Err(fail("sleep fixture survived without termination"));
        }
    }
    write_fixture_reply(writer)
}

fn write_fixture_reply(writer: HANDLE) -> io::Result<()> {
    let mut written = 0;
    unsafe {
        ok(WriteFile(
            writer,
            FRAME.as_ptr(),
            FRAME.len() as u32,
            &mut written,
            null_mut(),
        ))?;
    }
    if written != FRAME.len() as u32 {
        return Err(fail("short game response"));
    }
    Ok(())
}

pub fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "--evx-fixed-child") {
        return child(&args);
    }
    if args.len() != 1 {
        return Err(fail("the fixture accepts no caller-selected command"));
    }
    let _winsock = Winsock::start()?;
    winsock_catalog_access()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    for (mode, label) in [
        (Mode::Game, "game"),
        (Mode::NativeDenials, "native-denials"),
        (Mode::Memory, "memory"),
    ] {
        let mut stage = Stage::new()?;
        let child = stage.launch(mode, port)?;
        let result = child.finish(&mut stage, Duration::from_secs(10), false, true)?;
        if result.code != 0 || result.deadline || result.peak_bytes > MEMORY {
            return Err(fail(&format!(
                "{label} failed: exit={}, deadline={}, peak={}",
                result.code, result.deadline, result.peak_bytes
            )));
        }
        println!(
            "PASS {label}: confirmed death, empty job, user_100ns={}, peak_bytes={}",
            result.user_100ns, result.peak_bytes
        );
    }
    if listener.accept().is_ok() {
        return Err(fail("isolated fixture connected to loopback"));
    }
    let mut stage = Stage::new()?;
    let child = stage.launch(Mode::Cpu, port)?;
    let result = child.finish(&mut stage, Duration::from_secs(10), false, false)?;
    if result.deadline || result.code == 0 || result.user_100ns < CPU_100NS {
        return Err(fail(
            "CPU limit was not independently observed before wall deadline",
        ));
    }
    println!("PASS CPU termination: user_100ns={}", result.user_100ns);
    let mut stage = Stage::new()?;
    let child = stage.launch(Mode::Sleep, port)?;
    let result = child.finish(&mut stage, Duration::from_millis(200), false, false)?;
    if !result.deadline || result.code != TERMINATED {
        return Err(fail("wall timeout was not confirmed"));
    }
    println!("PASS wall timeout: confirmed death and empty job");
    let mut stage = Stage::new()?;
    let child = stage.launch(Mode::Sleep, port)?;
    let result = child.finish(&mut stage, Duration::from_secs(3), true, false)?;
    // Closing the last job handle may produce exit code zero. Readiness and
    // an independently signaled process before the deadline prove the kill;
    // a loader failure or a naturally completed child cannot satisfy the probe.
    if result.deadline {
        return Err(fail("kill-on-job-close did not terminate fixture"));
    }
    println!("PASS job close: process death confirmed independently");
    println!("PASS 6 native Windows fixture cases; production EVX remains disabled");
    Ok(())
}

#[path = "execution.rs"]
pub mod execution;
