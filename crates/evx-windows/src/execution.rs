//! Windows transport for real EVX compiler and Pulley worker roles.
//! This trusted embedding API does not grant consent or enable node admission.
use super::*;
use evx_api::frames::{self, FromCompiler, FromWorker, ToCompiler, ToWorker, WorkerResult};
use evx_api::{Limits, MAX_ARTIFACT_FRAME, MAX_FRAME};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::windows::io::FromRawHandle;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
#[path = "../../evx-worker/src/ipc.rs"]
mod ipc;

/// Bytes pinned by trusted installation policy, never by a xite request.
/// The held Windows handle denies writes and deletion while the source is used.
pub struct TrustedWorker {
    _file: std::fs::File,
    bytes: Vec<u8>,
    sha256: String,
}
impl TrustedWorker {
    pub fn open(path: &Path, expected_sha256: &str) -> io::Result<Self> {
        if expected_sha256.len() != 64
            || !expected_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !path.is_absolute()
        {
            return Err(fail("invalid trusted worker identity"));
        }
        // Local disks only. Every existing component must be an ordinary path,
        // including the final executable; never silently resolve a reparse point.
        let mut current = PathBuf::new();
        for component in path.components() {
            if let std::path::Component::Prefix(prefix) = component {
                if !matches!(prefix.kind(), std::path::Prefix::Disk(_)) {
                    return Err(fail("local disk worker required"));
                }
            }
            current.push(component);
            if current.parent().is_some() {
                let name = wide(&current)?;
                let attributes = unsafe { GetFileAttributesW(name.as_ptr()) };
                if attributes == INVALID_FILE_ATTRIBUTES
                    || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                {
                    return Err(fail("worker path unavailable or redirected"));
                }
            }
        }
        let name = wide(path)?;
        let handle = Handle::checked(unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        unsafe {
            ok(GetFileInformationByHandle(handle.0, &mut info))?;
        }
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || info.nNumberOfLinks != 1
        {
            return Err(fail("worker must be a non-linked regular file"));
        }
        let file = unsafe { std::fs::File::from_raw_handle(handle.0) };
        std::mem::forget(handle);
        if file.metadata()?.len() > 512 * 1024 * 1024 {
            return Err(fail("worker exceeds installation limit"));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(512 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if hex::encode(Sha256::digest(&bytes)) != expected_sha256 {
            return Err(fail("worker hash differs from trusted installation"));
        }
        Ok(Self {
            _file: file,
            bytes,
            sha256: expected_sha256.into(),
        })
    }
}
/// Native evidence. Job commitment and resident working set remain distinct.
#[derive(Clone, Debug)]
pub struct NativeUsage {
    pub cpu_seconds: f64,
    pub peak_resident_bytes: u64,
    pub peak_committed_bytes: u64,
    pub exit_code: u32,
}
/// Only unchanged output of this host's confined compiler can construct this.
pub struct CompiledModule {
    bytes: Vec<u8>,
    sha256: String,
    engine: String,
}
/// Host-owned cancellation/deadline-aware execution. No filesystem broker is
/// enabled here; the embedding host supplies only explicitly authorized calls.
pub struct WindowsExecutor {
    worker: TrustedWorker,
}
static QUARANTINED: AtomicBool = AtomicBool::new(false);
pub(super) fn quarantine() {
    QUARANTINED.store(true, Ordering::Release);
}
impl WindowsExecutor {
    pub fn new(worker: TrustedWorker) -> Self {
        Self { worker }
    }
    pub fn compile(
        &self,
        module: &[u8],
        limits: &Limits,
        cancel: &Arc<AtomicBool>,
    ) -> io::Result<(CompiledModule, NativeUsage)> {
        if module.len() > evx_api::MAX_MODULE {
            return Err(fail("module size limit"));
        }
        let initial = frames::encode(&ToCompiler::Compile {
            module: module.into(),
        })
        .map_err(|e| fail(&e.to_string()))?;
        let mut invocation = Invocation::spawn(&self.worker, "compile", limits, cancel)?;
        let result = (|| {
            invocation.write(&initial, cancel)?;
            let frame = invocation.read(MAX_ARTIFACT_FRAME, cancel)?;
            let response =
                frames::decode_compiler_reply(&frame).map_err(|e| fail(&e.to_string()))?;
            match response {
                FromCompiler::Artifact {
                    artifact,
                    artifact_sha256,
                    engine_key,
                } => {
                    if engine_key != evx_runtime::engine_key()
                        || hex::encode(Sha256::digest(&artifact)) != artifact_sha256
                    {
                        return Err(fail("compiler artifact identity mismatch"));
                    }
                    Ok(CompiledModule {
                        bytes: artifact,
                        sha256: artifact_sha256,
                        engine: engine_key,
                    })
                }
                FromCompiler::Rejected { error } => {
                    Err(fail(&format!("compiler rejected module: {error}")))
                }
            }
        })();
        let usage = invocation.finish(result.is_err(), cancel)?;
        if usage.exit_code != 0 {
            return Err(fail("compiler process failed"));
        }
        result.map(|artifact| (artifact, usage))
    }
    pub fn run(
        &self,
        artifact: &CompiledModule,
        limits: &Limits,
        cancel: &Arc<AtomicBool>,
        mut host_call: impl FnMut(&[u8]) -> io::Result<Vec<u8>>,
    ) -> io::Result<(WorkerResult, NativeUsage)> {
        if artifact.engine != evx_runtime::engine_key() {
            return Err(fail("artifact engine mismatch"));
        }
        let initial = frames::encode_worker_init(&ToWorker::Init {
            artifact: artifact.bytes.clone(),
            artifact_sha256: artifact.sha256.clone(),
            limits: limits.clone(),
        })
        .map_err(|e| fail(&e.to_string()))?;
        let mut invocation = Invocation::spawn(&self.worker, "run", limits, cancel)?;
        let result = (|| {
            invocation.write(&initial, cancel)?;
            let mut calls = 0;
            loop {
                let frame = invocation.read(MAX_FRAME, cancel)?;
                let response: FromWorker =
                    evx_api::strict::parse_typed(&frame).map_err(|e| fail(&e.to_string()))?;
                match response {
                    FromWorker::Result(result) => return Ok(result),
                    FromWorker::Call { request } => {
                        calls += 1;
                        if calls > limits.host_calls {
                            return Err(fail("host call limit"));
                        }
                        evx_api::Request::decode(&request)
                            .map_err(|_| fail("invalid broker operation"))?;
                        let before = Instant::now();
                        let response = host_call(&request)?;
                        if response.len() > evx_api::MAX_RESPONSE {
                            return Err(fail("broker response limit"));
                        }
                        if before.elapsed().as_secs_f64() > limits.host_call_seconds {
                            return Err(fail("host call deadline"));
                        }
                        invocation.write(
                            &frames::encode(&ToWorker::Response { response })
                                .map_err(|e| fail(&e.to_string()))?,
                            cancel,
                        )?;
                    }
                }
            }
        })();
        let usage = invocation.finish(result.is_err(), cancel)?;
        if usage.exit_code != 0 {
            return Err(fail("guest process failed"));
        }
        result.map(|result| (result, usage))
    }
}

/// Confine verification happens before framing, module parsing or deserialization.
pub fn worker_main() -> io::Result<()> {
    validate_token(unsafe { GetCurrentProcess() }, None)?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    unsafe {
        ok(QueryInformationJobObject(
            null_mut(),
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            null_mut(),
        ))?;
    }
    let required = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME;
    if limits.BasicLimitInformation.LimitFlags & required != required
        || limits.BasicLimitInformation.ActiveProcessLimit != 1
        || limits.ProcessMemoryLimit == 0
    {
        return Err(fail("required native job restrictions unavailable"));
    }
    match std::env::args().nth(1).as_deref() {
        Some("compile") => {
            let request: ToCompiler =
                ipc::read_frame(&mut io::stdin().lock()).map_err(|e| fail(&e))?;
            let module = match request {
                ToCompiler::Compile { module } => Ok(module),
                ToCompiler::CompileText { source } => std::str::from_utf8(&source)
                    .map_err(|_| evx_runtime::ValidationError::new("invalid WAT encoding"))
                    .and_then(evx_runtime::text_to_binary),
            };
            let response = match module.and_then(|module| evx_runtime::precompile(&module)) {
                Ok(artifact) => FromCompiler::Artifact {
                    artifact: artifact.bytes,
                    artifact_sha256: artifact.sha256,
                    engine_key: artifact.engine_key,
                },
                Err(error) => FromCompiler::Rejected {
                    error: error.to_string(),
                },
            };
            ipc::write_compiler_reply(&mut io::stdout().lock(), &response).map_err(|e| fail(&e))
        }
        Some("run") => {
            let (artifact, artifact_sha256, limits) =
                match ipc::read_worker_init(&mut io::stdin().lock()).map_err(|e| fail(&e))? {
                    ToWorker::Init {
                        artifact,
                        artifact_sha256,
                        limits,
                    } => (artifact, artifact_sha256, limits),
                    _ => return Err(fail("artifact initialization required")),
                };
            limits.validate().map_err(|e| fail(&e.to_string()))?;
            // SAFETY: this private inherited channel carries only the unchanged
            // output of the host's confined compiler. Publisher artifacts are never accepted.
            let report = unsafe {
                evx_runtime::run(
                    &artifact,
                    &evx_runtime::RunOptions {
                        limits,
                        artifact_sha256,
                        engine_key: evx_runtime::engine_key(),
                    },
                    Box::new(StdioBroker),
                )
            };
            ipc::write_frame(&mut io::stdout().lock(), &FromWorker::Result(report.result))
                .map_err(|e| fail(&e))
        }
        _ => Err(fail("fixed compile or run role required")),
    }
}
struct StdioBroker;
impl evx_runtime::HostCalls for StdioBroker {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, evx_runtime::HostError> {
        let error = |message: String| evx_runtime::HostError::Fatal(message);
        ipc::write_frame(
            &mut io::stdout().lock(),
            &FromWorker::Call {
                request: request.into(),
            },
        )
        .map_err(error)?;
        match ipc::read_frame(&mut io::stdin().lock()).map_err(error)? {
            ToWorker::Response { response } => Ok(response),
            _ => Err(error("unexpected initialization".into())),
        }
    }
}

fn pipe_pair(host_writes: bool, number: u32, suffix: &str) -> io::Result<(Handle, Handle)> {
    let parent = token(unsafe { GetCurrentProcess() })?;
    let owner = token_info(&parent, TokenUser)?;
    let sid = sid_text(unsafe { (*owner.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
    let sd = descriptor(&format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid})"))?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let name = wide(format!("\\\\.\\pipe\\LOCAL\\EpixEVX-{suffix}-{number}"))?;
    let access = if host_writes {
        PIPE_ACCESS_OUTBOUND
    } else {
        PIPE_ACCESS_INBOUND
    };
    let server = Handle::checked(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            access | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            &attrs,
        )
    })?;
    let inherited = SECURITY_ATTRIBUTES {
        bInheritHandle: 1,
        ..attrs
    };
    let client = Handle::checked(unsafe {
        CreateFileW(
            name.as_ptr(),
            if host_writes {
                GENERIC_READ
            } else {
                GENERIC_WRITE
            },
            0,
            &inherited,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    })?;
    if unsafe { ConnectNamedPipe(server.0, null_mut()) } == 0
        && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED
    {
        return Err(io::Error::last_os_error());
    }
    Ok((server, client))
}
struct Native {
    process: Handle,
    job: Handle,
}
// Windows process/job handles support concurrent queries and termination. The
// Arc owns their lifetime and neither handle is inherited by the child.
unsafe impl Send for Native {}
unsafe impl Sync for Native {}
impl Native {
    fn usage(&self) -> io::Result<NativeUsage> {
        let mut created: FILETIME = unsafe { zeroed() };
        let mut exited = created;
        let mut user = created;
        let mut kernel = created;
        unsafe {
            ok(GetProcessTimes(
                self.process.0,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            ))?;
        }
        let ticks =
            |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        let mut memory: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
        memory.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        unsafe {
            ok(GetProcessMemoryInfo(
                self.process.0,
                &mut memory,
                size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ))?;
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        unsafe {
            ok(QueryInformationJobObject(
                self.job.0,
                JobObjectExtendedLimitInformation,
                (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            ))?;
        }
        let mut code = 0;
        unsafe {
            ok(GetExitCodeProcess(self.process.0, &mut code))?;
        }
        Ok(NativeUsage {
            cpu_seconds: (ticks(user) + ticks(kernel)) as f64 / 10_000_000.0,
            peak_resident_bytes: memory.PeakWorkingSetSize as u64,
            peak_committed_bytes: limits.PeakJobMemoryUsed as u64,
            exit_code: code,
        })
    }
    fn dead(&self) -> io::Result<bool> {
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(false),
            WAIT_OBJECT_0 => {
                let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
                unsafe {
                    ok(QueryInformationJobObject(
                        self.job.0,
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut(),
                    ))?;
                }
                Ok(accounting.ActiveProcesses == 0)
            }
            _ => Err(fail("native process wait unavailable")),
        }
    }
    fn terminate(&self) -> io::Result<()> {
        unsafe { ok(TerminateJobObject(self.job.0, TERMINATED)) }
    }
}
struct Invocation {
    native: Arc<Native>,
    input: Handle,
    output: Handle,
    error: Handle,
    _executable: Option<TrustedWorker>,
    policy: Limits,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    monitor: Option<std::thread::JoinHandle<()>>,
    output_count: usize,
    // Drop native/image handles before attempting directory/profile cleanup.
    stage: Stage,
}
impl Invocation {
    fn spawn(
        worker: &TrustedWorker,
        role: &str,
        limits: &Limits,
        cancel: &Arc<AtomicBool>,
    ) -> io::Result<Self> {
        limits.validate().map_err(|e| fail(&e.to_string()))?;
        if QUARANTINED.load(Ordering::Acquire) {
            return Err(fail("Windows process admission is quarantined"));
        }
        if !matches!(role, "compile" | "run") {
            return Err(fail("unknown worker role"));
        }
        // Keep the pinned source guard alive throughout staging, then pin the
        // destination before any process loader opens it.
        let mut stage = Stage::with_bytes(&worker.bytes)?;
        let executable = TrustedWorker::open(&stage.executable, &worker.sha256)?;
        let profile = stage
            .profile
            .as_ref()
            .ok_or_else(|| fail("missing fresh LPAC"))?;
        let suffix = stage
            .root
            .file_name()
            .ok_or_else(|| fail("missing stage name"))?
            .to_string_lossy();
        let (input, child_input) = pipe_pair(true, 0, &suffix)?;
        let (output, child_output) = pipe_pair(false, 1, &suffix)?;
        let (error, child_error) = pipe_pair(false, 2, &suffix)?;
        let job = job()?;
        let mut native_limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        native_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_PROCESS_TIME
            | JOB_OBJECT_LIMIT_JOB_TIME
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        native_limits.BasicLimitInformation.ActiveProcessLimit = 1;
        native_limits.BasicLimitInformation.PerProcessUserTimeLimit =
            (limits.process_cpu_seconds * 10_000_000.0).ceil() as i64;
        native_limits.BasicLimitInformation.PerJobUserTimeLimit =
            native_limits.BasicLimitInformation.PerProcessUserTimeLimit;
        native_limits.ProcessMemoryLimit = usize::try_from(limits.process_rss_bytes)
            .map_err(|_| fail("unsupported process memory cap"))?;
        native_limits.JobMemoryLimit = native_limits.ProcessMemoryLimit;
        unsafe {
            ok(SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&native_limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ))?;
        }
        let mut security = SECURITY_CAPABILITIES {
            AppContainerSid: profile.sid,
            Capabilities: null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut lpac = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        let mut restricted = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        let mut jobs = [job.0];
        let mut handles = [child_input.0, child_output.0, child_error.0];
        let mut attributes = Attributes::new(5)?;
        attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &mut security)?;
        attributes.set(
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            &mut lpac,
        )?;
        attributes.set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &mut restricted)?;
        attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &mut jobs)?;
        attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &mut handles)?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_input.0;
        startup.StartupInfo.hStdOutput = child_output.0;
        startup.StartupInfo.hStdError = child_error.0;
        startup.lpAttributeList = attributes.raw();
        let exe = wide(&stage.executable)?;
        let cwd = wide(&stage.root)?;
        let mut command = wide(format!("\"{}\" {role}", stage.executable.display()))?;
        let mut environment = [0u16, 0];
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
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
                &mut info,
            ))?;
        }
        stage.active = true;
        let native = Arc::new(Native {
            process: Handle::checked(info.hProcess)?,
            job,
        });
        let thread = Handle::checked(info.hThread)?;
        drop((child_input, child_output, child_error));
        validate_token(native.process.0, Some(profile.sid))?;
        let mut member = 0;
        unsafe {
            ok(IsProcessInJob(native.process.0, native.job.0, &mut member))?;
        }
        if member != 1 {
            return Err(fail("worker outside required job"));
        }
        let started = Instant::now();
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let observed = native.clone();
        let done = stop.clone();
        let fault = failed.clone();
        let policy = limits.clone();
        let cancelled = cancel.clone();
        let monitor = std::thread::Builder::new()
            .name("evx-windows-limits".into())
            .spawn(move || {
                while !done.load(Ordering::Acquire) {
                    if observed.dead().unwrap_or(false) {
                        break;
                    }
                    let refused = cancelled.load(Ordering::Acquire)
                        || started.elapsed().as_secs_f64() > policy.wall_seconds
                        || observed.usage().map_or(true, |usage| {
                            usage.cpu_seconds > policy.process_cpu_seconds
                                || usage.peak_resident_bytes > policy.process_rss_bytes
                        });
                    if refused {
                        fault.store(true, Ordering::Release);
                        let _ = observed.terminate();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            })?;
        let mut invocation = Self {
            stage,
            native,
            input,
            output,
            error,
            _executable: Some(executable),
            policy: limits.clone(),
            stop,
            failed,
            monitor: Some(monitor),
            output_count: 0,
        };
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let error = io::Error::last_os_error();
            invocation.finish(true, cancel)?;
            return Err(error);
        }
        Ok(invocation)
    }
    fn check(&mut self, cancel: &AtomicBool) -> io::Result<()> {
        if cancel.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            return Err(fail(
                "execution cancelled or native budget unavailable/exceeded",
            ));
        }
        let mut bytes = [0u8; 4096];
        loop {
            let count = available(self.error.0)?;
            if count == 0 {
                break;
            }
            let count = read_available(self.error.0, &mut bytes[..(count as usize).min(4096)])?;
            self.account_output(count)?;
        }
        Ok(())
    }
    fn account_output(&mut self, count: usize) -> io::Result<()> {
        self.output_count = self
            .output_count
            .checked_add(count)
            .ok_or_else(|| fail("output overflow"))?;
        if self.output_count > 256 * 1024 {
            return Err(fail("combined output limit"));
        }
        Ok(())
    }
    fn write(&mut self, mut bytes: &[u8], cancel: &AtomicBool) -> io::Result<()> {
        while !bytes.is_empty() {
            self.check(cancel)?;
            if self.native.dead()? {
                return Err(fail("worker exited before request"));
            }
            let mut count = 0;
            unsafe {
                ok(WriteFile(
                    self.input.0,
                    bytes.as_ptr(),
                    bytes.len().min(4096) as u32,
                    &mut count,
                    null_mut(),
                ))?;
            }
            bytes = &bytes[count as usize..];
            if count == 0 {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        Ok(())
    }
    fn exact(&mut self, bytes: &mut [u8], cancel: &AtomicBool) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            self.check(cancel)?;
            let available = available(self.output.0)? as usize;
            if available == 0 {
                if self.native.dead()? {
                    return Err(fail("truncated worker output"));
                }
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            let end = bytes.len().min(offset + available);
            let count = read_available(self.output.0, &mut bytes[offset..end])?;
            self.account_output(count)?;
            offset += count;
        }
        Ok(())
    }
    fn read(&mut self, maximum: usize, cancel: &AtomicBool) -> io::Result<Vec<u8>> {
        let mut length = [0u8; 4];
        self.exact(&mut length, cancel)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > maximum {
            return Err(fail("worker frame limit"));
        }
        let mut body = vec![0u8; length];
        self.exact(&mut body, cancel)?;
        Ok(body)
    }
    fn finish(&mut self, terminate: bool, cancel: &AtomicBool) -> io::Result<NativeUsage> {
        if terminate || cancel.load(Ordering::Acquire) {
            self.native.terminate()?;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.native.dead()? {
            if Instant::now() >= deadline {
                self.native.terminate()?;
                return Err(fail("child death unconfirmed; stage quarantined"));
            }
            // Terminal protocol is final. Trailing output cannot hide in pipes.
            self.check(cancel).ok();
            if available(self.output.0)? != 0 {
                self.native.terminate()?;
                return Err(fail("unexpected trailing output"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        self.stage.active = false;
        self.stop.store(true, Ordering::Release);
        if let Some(monitor) = self.monitor.take() {
            monitor.join().map_err(|_| fail("native monitor failed"))?;
        }
        let usage = self.native.usage()?;
        if usage.cpu_seconds > self.policy.process_cpu_seconds
            || usage.peak_resident_bytes > self.policy.process_rss_bytes
        {
            return Err(fail("terminal native resource limit"));
        }
        if available(self.output.0)? != 0 {
            return Err(fail("unexpected trailing output"));
        }
        self.check(cancel)?;
        Ok(usage)
    }
}
impl Drop for Invocation {
    fn drop(&mut self) {
        if self.stage.active {
            let _ = self.native.terminate();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if self.native.dead().unwrap_or(false) {
                    self.stage.active = false;
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        self.stop.store(true, Ordering::Release);
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.join();
        }
        if self.stage.active {
            quarantine();
        }
        // Release the no-delete identity handle before Stage attempts cleanup.
        self._executable.take();
    }
}
fn available(pipe: HANDLE) -> io::Result<u32> {
    let mut bytes = 0;
    if unsafe { PeekNamedPipe(pipe, null_mut(), 0, null_mut(), &mut bytes, null_mut()) } == 0 {
        if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
            return Ok(0);
        }
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}
fn read_available(pipe: HANDLE, bytes: &mut [u8]) -> io::Result<usize> {
    let mut count = 0;
    unsafe {
        ok(ReadFile(
            pipe,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut count,
            null_mut(),
        ))?;
    }
    if count == 0 {
        return Err(fail("worker pipe closed"));
    }
    Ok(count as usize)
}
