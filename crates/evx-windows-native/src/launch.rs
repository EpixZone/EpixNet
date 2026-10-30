//! Suspended LPAC launch into a job, with host-side verification before resume.
use crate::handle::{fail, ok, wide, Handle};
use crate::security::validate_token;
use std::{
    io,
    mem::{size_of, size_of_val, zeroed},
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        CompareObjectHandles, DuplicateHandle, GetHandleInformation, SetHandleInformation,
        DUPLICATE_SAME_ACCESS, ERROR_INVALID_HANDLE, HANDLE, HANDLE_FLAG_INHERIT,
    },
    Security::{PSID, SECURITY_CAPABILITIES},
    System::{
        JobObjects::IsProcessInJob,
        Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
            InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS,
            EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            STARTF_USESTDHANDLES, STARTUPINFOEXW,
        },
        WindowsProgramming::{
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
            PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
        },
    },
};

/// A proc-thread attribute list. Values passed to `set` are retained by
/// pointer and must outlive the list.
pub struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    /// Allocate a list for up to `count` attributes.
    pub fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: a null list asks for the required size.
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 65536 {
            return Err(fail("invalid startup attribute size"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: the storage holds at least `bytes` bytes.
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
    /// The list pointer for `STARTUPINFOEXW::lpAttributeList`.
    pub fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    /// Set attribute `key` to `value`. The backing value must outlive the
    /// list: UpdateProcThreadAttribute retains the pointer.
    pub fn set<T>(&mut self, key: u32, value: &mut T) -> io::Result<()> {
        self.set_list(key, std::slice::from_mut(value))
    }
    /// Set a list-valued attribute such as the handle or job list. The
    /// backing slice must outlive the list.
    pub fn set_list<T>(&mut self, key: u32, values: &mut [T]) -> io::Result<()> {
        // SAFETY: the list is initialized; the pointer and length describe `values`.
        unsafe {
            ok(UpdateProcThreadAttribute(
                self.raw(),
                0,
                key as usize,
                values.as_mut_ptr().cast(),
                size_of_val(values),
                null_mut(),
                null(),
            ))
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the list was initialized successfully in `new`.
        unsafe {
            DeleteProcThreadAttributeList(self.raw());
        }
    }
}

/// Everything a confined launch needs. The executable is supplied separately
/// from the command line and never searched through PATH.
pub struct LaunchSpec<'a> {
    /// The image to run.
    pub executable: &'a Path,
    /// The full command line, including the quoted executable.
    pub command_line: String,
    /// The child's working directory.
    pub current_directory: &'a Path,
    /// A double NUL terminated UTF-16 environment block, see `worker_environment`.
    pub environment: Vec<u16>,
    /// The AppContainer package SID; the child gets zero capabilities.
    pub container_sid: PSID,
    /// The job the child is placed in at creation.
    pub job: &'a Handle,
    /// The only handles the child inherits. Must not be empty.
    pub inherited_handles: Vec<HANDLE>,
    /// Standard input handle, or `INVALID_HANDLE_VALUE`.
    pub stdin: HANDLE,
    /// Standard output handle.
    pub stdout: HANDLE,
    /// Standard error handle.
    pub stderr: HANDLE,
}

/// A suspended child. Its process and thread handles close on drop; the
/// job's kill-on-close decides whether that ends the process.
pub struct Launched {
    /// The process handle.
    pub process: Handle,
    /// The initial thread, suspended until `resume`.
    pub thread: Handle,
    /// The process identifier.
    pub pid: u32,
}

/// Create the child suspended, detached from any console, as a zero-capability
/// LPAC with the ALL APPLICATION PACKAGES opt-out and child-process
/// restriction, inside `spec.job`, inheriting only `spec.inherited_handles`.
/// The listed handles need not be inheritable beforehand: they are marked
/// inheritable for the `CreateProcessW` call alone and cleared again before
/// this returns, whether or not the launch succeeded.
pub fn launch_suspended(spec: &mut LaunchSpec) -> io::Result<Launched> {
    if spec.inherited_handles.is_empty() {
        return Err(fail("explicit inherited handle list required"));
    }
    let mut security = SECURITY_CAPABILITIES {
        AppContainerSid: spec.container_sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut lpac = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let mut restricted = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    let mut jobs = [spec.job.raw()];
    // Backing values outlive Attributes: UpdateProcThreadAttribute retains pointers.
    let mut attrs = Attributes::new(5)?;
    attrs.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &mut security)?;
    attrs.set(
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        &mut lpac,
    )?;
    attrs.set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &mut restricted)?;
    attrs.set_list(PROC_THREAD_ATTRIBUTE_JOB_LIST, &mut jobs)?;
    attrs.set_list(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        &mut spec.inherited_handles,
    )?;
    // SAFETY: STARTUPINFOEXW is plain data; the used fields are set below.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = spec.stdin;
    startup.StartupInfo.hStdOutput = spec.stdout;
    startup.StartupInfo.hStdError = spec.stderr;
    startup.lpAttributeList = attrs.raw();
    // The listed handles are inheritable only across this one call: a
    // concurrent CreateProcess elsewhere in the host that inherits handles
    // without an explicit list (`std::process::Command`) would otherwise
    // copy them into an unrelated process and hold the child's pipes open.
    set_inheritable(&spec.inherited_handles, true)?;
    let created = create_process(spec, &startup);
    let cleared = set_inheritable(&spec.inherited_handles, false);
    let info = created?;
    let launched = Launched {
        process: Handle::checked(info.hProcess)?,
        thread: Handle::checked(info.hThread)?,
        pid: info.dwProcessId,
    };
    cleared?;
    Ok(launched)
}

/// Set or clear `HANDLE_FLAG_INHERIT` on every handle in `handles`.
fn set_inheritable(handles: &[HANDLE], inheritable: bool) -> io::Result<()> {
    let flags = if inheritable { HANDLE_FLAG_INHERIT } else { 0 };
    for &handle in handles {
        // SAFETY: the caller owns every listed handle; only the inherit flag
        // is touched.
        unsafe {
            ok(SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags))?;
        }
    }
    Ok(())
}

/// Whether `handle` carries `HANDLE_FLAG_INHERIT`.
pub fn is_inheritable(handle: HANDLE) -> io::Result<bool> {
    let mut flags = 0;
    // SAFETY: `flags` receives the handle's flags.
    unsafe {
        ok(GetHandleInformation(handle, &mut flags))?;
    }
    Ok(flags & HANDLE_FLAG_INHERIT != 0)
}

fn create_process(
    spec: &mut LaunchSpec,
    startup: &STARTUPINFOEXW,
) -> io::Result<PROCESS_INFORMATION> {
    let exe = wide(spec.executable)?;
    let mut command = wide(&spec.command_line)?;
    let cwd = wide(spec.current_directory)?;
    // SAFETY: PROCESS_INFORMATION is plain data filled by the API.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    // Pipe-only workers need no console infrastructure inside the
    // zero-capability LPAC and its single-process job.
    // SAFETY: every string is NUL-terminated, the environment block is double
    // NUL terminated, and the attribute list and its backing values are alive.
    unsafe {
        ok(CreateProcessW(
            exe.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                | DETACHED_PROCESS
                | CREATE_UNICODE_ENVIRONMENT,
            spec.environment.as_mut_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        ))?;
    }
    Ok(info)
}

/// Require that the suspended child is a zero-capability LPAC under `sid`
/// and was placed in `job` atomically at creation.
pub fn verify_launched(launched: &Launched, job: &Handle, sid: PSID) -> io::Result<()> {
    verify_process(launched.process.raw(), job.raw(), sid)
}

/// `verify_launched` for raw process and job handles the caller owns.
pub fn verify_process(process: HANDLE, job: HANDLE, sid: PSID) -> io::Result<()> {
    validate_token(process, Some(sid))?;
    let mut in_job = 0;
    // SAFETY: both handles are open; `in_job` receives the answer.
    unsafe {
        ok(IsProcessInJob(process, job, &mut in_job))?;
    }
    if in_job != 1 {
        return Err(fail("child not atomically placed in job"));
    }
    Ok(())
}

/// Resume the child's initial thread.
pub fn resume(launched: &Launched) -> io::Result<()> {
    resume_thread(launched.thread.raw())
}

/// Resume a suspended thread the caller owns a handle to.
pub fn resume_thread(thread: HANDLE) -> io::Result<()> {
    // SAFETY: the thread handle is open.
    if unsafe { ResumeThread(thread) } == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether `process` holds `original` at the same handle value, inspected
/// from the host. Inheritance preserves handle values, so a recycled number
/// referring to a different child-local object is not evidence of a leak.
pub fn inherited_object(process: HANDLE, original: &Handle) -> io::Result<bool> {
    let mut duplicate = null_mut();
    // SAFETY: the source handle value is probed in `process`; on success the
    // duplicate is owned by this process and closed below.
    let copied = unsafe {
        DuplicateHandle(
            process,
            original.raw(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if copied == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let duplicate = Handle::checked(duplicate)?;
    // SAFETY: both handles are open in this process.
    Ok(unsafe { CompareObjectHandles(original.raw(), duplicate.raw()) } != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_list_accepts_scalar_and_list_values() {
        let mut attrs = Attributes::new(2).unwrap();
        let mut restricted = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        attrs
            .set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &mut restricted)
            .unwrap();
        // SAFETY: the pseudo handle is a valid handle value for the list.
        let mut handles = [unsafe { GetCurrentProcess() }];
        attrs
            .set_list(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &mut handles)
            .unwrap();
    }

    /// Launch this test executable suspended (never resumed) as an LPAC
    /// child of a throwaway profile, with `handles` as the explicit list.
    fn launch_fixture(handles: Vec<HANDLE>) -> (Launched, Handle, crate::Profile) {
        let profile =
            crate::Profile::create(&format!("Epix.EvxNativeLaunch.{}", std::process::id()))
                .unwrap();
        let job = crate::create_job(&crate::JobLimits {
            process_memory: 1 << 30,
            job_memory: 1 << 30,
            per_process_user_100ns: 10_000_000,
            per_job_user_100ns: 10_000_000,
            cpu_rate_hard_cap_percent_x100: None,
        })
        .unwrap();
        let exe = std::env::current_exe().unwrap();
        // A directory every LPAC token can open.
        let cwd = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        let mut spec = LaunchSpec {
            executable: &exe,
            command_line: format!("\"{}\"", exe.display()),
            current_directory: &cwd,
            environment: crate::worker_environment().unwrap(),
            container_sid: profile.sid(),
            job: &job,
            stdin: handles[0],
            stdout: handles[1],
            stderr: handles[2],
            inherited_handles: handles,
        };
        let launched = launch_suspended(&mut spec).unwrap();
        (launched, job, profile)
    }

    #[test]
    fn listed_handles_are_inheritable_only_during_the_launch() {
        let suffix = format!("native-launch-{}", std::process::id());
        let (host_in, child_in) = crate::pipe_pair(true, 0, &suffix).unwrap();
        let (host_out, child_out) = crate::blocking_pipe_pair(false, 1, &suffix).unwrap();
        let (host_err, child_err) = crate::blocking_pipe_pair(false, 2, &suffix).unwrap();
        for handle in [
            &host_in, &child_in, &host_out, &child_out, &host_err, &child_err,
        ] {
            assert!(!is_inheritable(handle.raw()).unwrap());
        }
        let (launched, job, profile) =
            launch_fixture(vec![child_in.raw(), child_out.raw(), child_err.raw()]);
        // The child received exactly the listed ends, and the flag is gone.
        for handle in [&child_in, &child_out, &child_err] {
            assert!(!is_inheritable(handle.raw()).unwrap());
            assert!(inherited_object(launched.process.raw(), handle).unwrap());
        }
        for handle in [&host_in, &host_out, &host_err] {
            assert!(!is_inheritable(handle.raw()).unwrap());
            assert!(!inherited_object(launched.process.raw(), handle).unwrap());
        }
        verify_launched(&launched, &job, profile.sid()).unwrap();
        drop(launched);
        drop(job);
    }

    #[test]
    fn inherited_object_distinguishes_live_and_invalid_values() {
        let job = crate::create_job(&crate::JobLimits {
            process_memory: 1 << 20,
            job_memory: 1 << 20,
            per_process_user_100ns: 1,
            per_job_user_100ns: 1,
            cpu_rate_hard_cap_percent_x100: None,
        })
        .unwrap();
        // SAFETY: the pseudo handle for the current process is always valid.
        let me = unsafe { GetCurrentProcess() };
        assert!(inherited_object(me, &job).unwrap());
        // A value no handle table can hold: never closed, so released with into_raw.
        let bogus = Handle::checked(0x7FFF_FFF4usize as HANDLE).unwrap();
        assert!(!inherited_object(me, &bogus).unwrap());
        bogus.into_raw();
    }
}
