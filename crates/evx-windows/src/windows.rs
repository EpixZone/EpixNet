use crate::denial::{denied, descendant_denied};
use std::{
    ffi::OsStr,
    io,
    mem::{size_of, zeroed},
    net::{TcpListener, TcpStream},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Cryptography::*, Isolation::*, *},
    Storage::FileSystem::*,
    System::{JobObjects::*, Memory::*, Pipes::*, Threading::*, WindowsProgramming::*},
};

const MEMORY: usize = 64 * 1024 * 1024;
const CPU_100NS: i64 = 5_000_000;
const TERMINATED: u32 = 0x45565801;
const FRAME: [u8; 8] = *b"EVX042\r\n";

fn fail(message: &str) -> io::Error {
    io::Error::other(message)
}
fn ok(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn wide(value: impl AsRef<OsStr>) -> io::Result<Vec<u16>> {
    let mut result: Vec<_> = value.as_ref().encode_wide().collect();
    if result.contains(&0) {
        return Err(fail("NUL in trusted fixture path"));
    }
    result.push(0);
    Ok(result)
}
struct Handle(HANDLE);
impl Handle {
    fn checked(raw: HANDLE) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn token(process: HANDLE) -> io::Result<Handle> {
    let mut raw = null_mut();
    unsafe {
        ok(OpenProcessToken(process, TOKEN_QUERY, &mut raw))?;
    }
    Handle::checked(raw)
}
fn token_info(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token.0, class, null_mut(), 0, &mut bytes);
    }
    if bytes == 0 || bytes > 65536 {
        return Err(fail("invalid token metadata size"));
    }
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    unsafe {
        ok(GetTokenInformation(
            token.0,
            class,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        ))?;
    }
    Ok(buffer)
}
fn sid_text(sid: PSID) -> io::Result<String> {
    let mut raw = null_mut();
    unsafe {
        ok(ConvertSidToStringSidW(sid, &mut raw))?;
    }
    let allocated = Local(raw.cast());
    let mut len = 0;
    unsafe {
        while len < 256 && *raw.add(len) != 0 {
            len += 1;
        }
        if len == 256 {
            return Err(fail("oversized SID text"));
        }
        let text = String::from_utf16(std::slice::from_raw_parts(raw, len))
            .map_err(|_| fail("invalid SID text"))?;
        drop(allocated);
        Ok(text)
    }
}
fn descriptor(sddl: &str) -> io::Result<Local> {
    let text = wide(sddl)?;
    let mut raw = null_mut();
    unsafe {
        ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut raw,
            null_mut(),
        ))?;
    }
    Ok(Local(raw))
}
fn protect(path: &Path, sddl: &str) -> io::Result<()> {
    let sd = descriptor(sddl)?;
    let mut dacl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    unsafe {
        ok(GetSecurityDescriptorDacl(
            sd.0,
            &mut present,
            &mut dacl,
            &mut defaulted,
        ))?;
    }
    if present == 0 || dacl.is_null() {
        return Err(fail("missing fixture ACL"));
    }
    let path = wide(path)?;
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

struct Profile {
    name: Vec<u16>,
    sid: PSID,
}
impl Drop for Profile {
    fn drop(&mut self) {
        unsafe {
            DeleteAppContainerProfile(self.name.as_ptr());
            FreeSid(self.sid);
        }
    }
}
struct Stage {
    root: PathBuf,
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
        let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let name = wide(format!("Epix.EvxFixture.{id}"))?;
        let mut sid = null_mut();
        let status = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                name.as_ptr(),
                name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        if status < 0 {
            return Err(fail(&format!(
                "fresh AppContainer profile failed: 0x{:08x}",
                status as u32
            )));
        }
        let profile = Profile { name, sid };
        let parent = token(unsafe { GetCurrentProcess() })?;
        let user = token_info(&parent, TokenUser)?;
        let owner = sid_text(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
        let package = sid_text(profile.sid)?;
        let private = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})");
        let readable = format!("{private}(A;OICI;GRGX;;;{package})");
        let root = std::env::temp_dir().join(format!("evx-windows-{id}"));
        let root_wide = wide(&root)?;
        let sd = descriptor(&readable)?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        unsafe {
            ok(CreateDirectoryW(root_wide.as_ptr(), &attrs))?;
        }
        let stage = Self {
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
        let job = job()?;
        let inherit = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let mut read = null_mut();
        let mut write = null_mut();
        unsafe {
            ok(CreatePipe(&mut read, &mut write, &inherit, 4096))?;
        }
        let reader = Handle::checked(read)?;
        let writer = Handle::checked(write)?;
        unsafe {
            ok(SetHandleInformation(reader.0, HANDLE_FLAG_INHERIT, 0))?;
        }
        // Deliberately inheritable, but excluded from the explicit handle list.
        let excluded = Handle::checked(unsafe { CreateEventW(&inherit, 1, 0, null()) })?;
        let mut security = SECURITY_CAPABILITIES {
            AppContainerSid: profile.sid,
            Capabilities: null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut lpac = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        let mut restricted = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        let mut jobs = [job.0];
        let mut handles = [writer.0];
        // Backing values outlive Attributes: UpdateProcThreadAttribute retains pointers.
        let mut attrs = Attributes::new(5)?;
        attrs.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &mut security)?;
        attrs.set(
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            &mut lpac,
        )?;
        attrs.set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &mut restricted)?;
        attrs.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &mut jobs)?;
        attrs.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &mut handles)?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attrs.raw();
        let exe = wide(&self.executable)?;
        // Only our fixed enum and decimal handles/loopback port enter argv. The
        // executable is also supplied separately, never searched through PATH.
        let mut command = wide(format!(
            "\"{}\" --evx-fixed-child {} {} {} {}",
            self.executable.display(),
            mode as u32,
            writer.0 as usize,
            excluded.0 as usize,
            port
        ))?;
        let cwd = wide(&self.root)?;
        // No parent environment, including credentials or configuration, is inherited.
        let mut environment = [0u16, 0];
        let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
        unsafe {
            ok(CreateProcessW(
                exe.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT,
                environment.as_mut_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut process,
            ))?;
        }
        self.active = true;
        let process_handle = Handle::checked(process.hProcess)?;
        let thread = Handle::checked(process.hThread)?;
        drop(writer);
        // An error from here leaves the stage quarantined; closing the job kills
        // the process but is not treated as confirmation that it has died.
        validate_token(process_handle.0, Some(profile.sid))?;
        let mut in_job = 0;
        unsafe {
            ok(IsProcessInJob(process_handle.0, job.0, &mut in_job))?;
        }
        if in_job == 0 {
            return Err(fail("child not atomically placed in job"));
        }
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(Child {
            process: process_handle,
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
            if let Some(profile) = self.profile.take() {
                std::mem::forget(profile);
            }
            eprintln!(
                "retained unconfirmed fixture directory: {}",
                self.root.display()
            );
        } else if let Err(error) = std::fs::remove_dir_all(&self.root) {
            eprintln!("fixture cleanup failed at {}: {error}", self.root.display());
        }
    }
}

struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 65536 {
            return Err(fail("invalid startup attribute size"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        unsafe {
            ok(InitializeProcThreadAttributeList(
                storage.as_mut_ptr().cast(),
                count,
                0,
                &mut bytes,
            ))?;
        }
        // DeleteProcThreadAttributeList requires successful initialization.
        Ok(Self { storage })
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn set<T>(&mut self, key: u32, value: &mut T) -> io::Result<()> {
        unsafe {
            ok(UpdateProcThreadAttribute(
                self.raw(),
                0,
                key as usize,
                std::ptr::from_mut(value).cast(),
                size_of::<T>(),
                null_mut(),
                null(),
            ))
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.raw());
        }
    }
}

fn job() -> io::Result<Handle> {
    let job = Handle::checked(unsafe { CreateJobObjectW(null(), null()) })?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_JOB_TIME
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.BasicLimitInformation.PerProcessUserTimeLimit = CPU_100NS;
    limits.BasicLimitInformation.PerJobUserTimeLimit = CPU_100NS;
    limits.ProcessMemoryLimit = MEMORY;
    limits.JobMemoryLimit = MEMORY;
    unsafe {
        ok(SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ))?;
    }
    let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { zeroed() };
    cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu.Anonymous.CpuRate = 5000;
    unsafe {
        ok(SetInformationJobObject(
            job.0,
            JobObjectCpuRateControlInformation,
            (&cpu as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
            size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        ))?;
    }
    Ok(job)
}
fn validate_token(process: HANDLE, expected: Option<PSID>) -> io::Result<()> {
    let token = token(process)?;
    for class in [TokenIsAppContainer, TokenIsLessPrivilegedAppContainer] {
        let buffer = token_info(&token, class)?;
        if unsafe { *buffer.as_ptr().cast::<u32>() } != 1 {
            return Err(fail("child token is not an LPAC"));
        }
    }
    let caps = token_info(&token, TokenCapabilities)?;
    if unsafe { (*caps.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount } != 0 {
        return Err(fail("unexpected AppContainer capabilities"));
    }
    if let Some(expected) = expected {
        let sid = token_info(&token, TokenAppContainerSid)?;
        let actual =
            unsafe { (*sid.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer };
        if unsafe { EqualSid(actual, expected) } == 0 {
            return Err(fail("wrong AppContainer identity"));
        }
    }
    Ok(())
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
            drop(self.job.take());
        }
        let deadline;
        loop {
            match unsafe { WaitForSingleObject(self.process.0, 10) } {
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
                    unsafe {
                        ok(TerminateJobObject(job.0, TERMINATED))?;
                    }
                }
                if unsafe { WaitForSingleObject(self.process.0, 3000) } != WAIT_OBJECT_0 {
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
                        job.0,
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
                    job.0,
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    null_mut(),
                ))?;
            }
        }
        let mut code = 0;
        unsafe {
            ok(GetExitCodeProcess(self.process.0, &mut code))?;
        }
        // Only native wait and empty-job evidence clear quarantine, even if later
        // reply checks fail. Exit code alone, including STILL_ACTIVE, never clears it.
        stage.active = false;
        if unsafe { WaitForSingleObject(self.excluded.0, 0) } != WAIT_TIMEOUT {
            return Err(fail("excluded event was inherited or signaled"));
        }
        if expect_reply {
            let mut bytes = 0;
            unsafe {
                ok(PeekNamedPipe(
                    self.reader.0,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut bytes,
                    null_mut(),
                ))?;
            }
            if bytes != FRAME.len() as u32 {
                return Err(fail("wrong bounded reply size"));
            }
            let mut reply = [0u8; 8];
            let mut read = 0;
            unsafe {
                ok(ReadFile(
                    self.reader.0,
                    reply.as_mut_ptr(),
                    reply.len() as u32,
                    &mut read,
                    null_mut(),
                ))?;
            }
            if read != 8 || reply != FRAME {
                return Err(fail("invalid game reply"));
            }
        }
        Ok(Outcome {
            code,
            deadline,
            user_100ns: accounting.TotalUserTime,
            peak_bytes: limits.PeakJobMemoryUsed,
        })
    }
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
    if args.len() != 6 {
        return Err(fail("invalid child frame"));
    }
    let mode = Mode::parse(&args[2])?;
    let writer = args[3]
        .parse::<usize>()
        .map_err(|_| fail("bad reply handle"))? as HANDLE;
    let excluded = args[4]
        .parse::<usize>()
        .map_err(|_| fail("bad excluded handle"))? as HANDLE;
    let port = args[5]
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
            // The numeric value may name an unrelated child-local event. Only
            // the host's observation of its original object proves inheritance.
            unsafe {
                SetEvent(excluded);
            }
            descendant_denied(
                std::process::Command::new(exe)
                    .arg("--unexpected-child")
                    .spawn(),
            )?;
            denied(
                TcpStream::connect_timeout(
                    &format!("127.0.0.1:{port}")
                        .parse()
                        .map_err(|_| fail("invalid fixture address"))?,
                    Duration::from_millis(500),
                ),
                "loopback connection",
            )?;
            denied(TcpListener::bind("127.0.0.1:0"), "network listen")?;
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
        Mode::Sleep => std::thread::sleep(Duration::from_secs(60)),
    }
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
    if result.deadline || result.code == 0 {
        return Err(fail("kill-on-job-close did not terminate fixture"));
    }
    println!("PASS job close: process death confirmed independently");
    println!("PASS 6 native Windows fixture cases; production EVX remains disabled");
    Ok(())
}

#[path = "execution.rs"]
pub mod execution;
