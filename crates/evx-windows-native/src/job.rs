//! Job objects with EVX's limit set, and process accounting through a job.
use crate::handle::{fail, ok, Handle};
use std::{
    io,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        JobObjects::{
            CreateJobObjectW, JobObjectBasicAccountingInformation,
            JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
            JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
            JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
        },
        ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
        Threading::{GetExitCodeProcess, GetProcessTimes, WaitForSingleObject},
    },
};

/// Exit code of a child terminated by the host through its job.
pub const TERMINATED: u32 = 0x45565801;

/// Limits applied to a job created by `create_job`. Memory is in bytes and
/// user time in 100 ns units; the CPU rate cap is in hundredths of a percent
/// of one processor, applied only when set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobLimits {
    /// Committed memory limit per process.
    pub process_memory: usize,
    /// Committed memory limit for the whole job.
    pub job_memory: usize,
    /// User-mode time limit per process.
    pub per_process_user_100ns: i64,
    /// User-mode time limit for the whole job.
    pub per_job_user_100ns: i64,
    /// Hard CPU rate cap, such as `Some(5000)` for half of one processor.
    pub cpu_rate_hard_cap_percent_x100: Option<u32>,
}

fn extended_limits(limits: &JobLimits) -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    // SAFETY: the structure is plain data; every used field is set below.
    let mut extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    extended.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY
        | JOB_OBJECT_LIMIT_PROCESS_TIME
        | JOB_OBJECT_LIMIT_JOB_TIME
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    extended.BasicLimitInformation.ActiveProcessLimit = 1;
    extended.BasicLimitInformation.PerProcessUserTimeLimit = limits.per_process_user_100ns;
    extended.BasicLimitInformation.PerJobUserTimeLimit = limits.per_job_user_100ns;
    extended.ProcessMemoryLimit = limits.process_memory;
    extended.JobMemoryLimit = limits.job_memory;
    extended
}

fn set_cpu_rate(job: &Handle, rate: u32) -> io::Result<()> {
    // SAFETY: the structure is plain data; the used fields are set below.
    let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { zeroed() };
    cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpu.Anonymous.CpuRate = rate;
    // SAFETY: the pointer and length describe `cpu`.
    unsafe {
        ok(SetInformationJobObject(
            job.raw(),
            JobObjectCpuRateControlInformation,
            (&cpu as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
            size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        ))
    }
}

/// Create an anonymous job with kill-on-close, one active process, the
/// given memory and user-time limits, die-on-unhandled-exception and an
/// optional hard CPU rate cap.
pub fn create_job(limits: &JobLimits) -> io::Result<Handle> {
    // SAFETY: an anonymous job needs no attributes or name.
    let job = Handle::checked(unsafe { CreateJobObjectW(null(), null()) })?;
    let extended = extended_limits(limits);
    // SAFETY: the pointer and length describe `extended`.
    unsafe {
        ok(SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&extended as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ))?;
    }
    if let Some(rate) = limits.cpu_rate_hard_cap_percent_x100 {
        set_cpu_rate(&job, rate)?;
    }
    Ok(job)
}

/// Terminate every process in `job` with exit code `code`.
pub fn terminate_job(job: HANDLE, code: u32) -> io::Result<()> {
    // SAFETY: `job` is an open job handle.
    unsafe { ok(TerminateJobObject(job, code)) }
}

/// Native evidence about a process in a job. Job commitment and resident
/// working set remain distinct.
#[derive(Clone, Debug)]
pub struct ProcessUsage {
    /// User plus kernel time of the process in seconds.
    pub cpu_seconds: f64,
    /// Peak working set of the process in bytes.
    pub peak_resident_bytes: u64,
    /// Peak committed memory of the whole job in bytes.
    pub peak_committed_bytes: u64,
    /// The process exit code, `STILL_ACTIVE` while it runs.
    pub exit_code: u32,
}

fn query_job<T>(job: HANDLE, class: i32) -> io::Result<T> {
    // SAFETY: job information structures are plain data that the API fills;
    // the pointer and length describe `value`.
    unsafe {
        let mut value: T = zeroed();
        ok(QueryInformationJobObject(
            job,
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
            null_mut(),
        ))?;
        Ok(value)
    }
}

fn ticks(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

/// CPU time, peak memory and exit code of `process`, with the job's peak
/// commitment.
pub fn process_usage(process: HANDLE, job: HANDLE) -> io::Result<ProcessUsage> {
    // SAFETY: FILETIME is plain data filled by the API.
    let mut created: FILETIME = unsafe { zeroed() };
    let mut exited = created;
    let mut user = created;
    let mut kernel = created;
    // SAFETY: every out-parameter targets a live local.
    unsafe {
        ok(GetProcessTimes(
            process,
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        ))?;
    }
    // SAFETY: the counters structure is plain data; `cb` is set before the call.
    let mut memory: PROCESS_MEMORY_COUNTERS = unsafe { zeroed() };
    memory.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    unsafe {
        ok(GetProcessMemoryInfo(
            process,
            &mut memory,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ))?;
    }
    let limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
        query_job(job, JobObjectExtendedLimitInformation)?;
    let mut code = 0;
    // SAFETY: `code` receives the exit code.
    unsafe {
        ok(GetExitCodeProcess(process, &mut code))?;
    }
    Ok(ProcessUsage {
        cpu_seconds: (ticks(user) + ticks(kernel)) as f64 / 10_000_000.0,
        peak_resident_bytes: memory.PeakWorkingSetSize as u64,
        peak_committed_bytes: limits.PeakJobMemoryUsed as u64,
        exit_code: code,
    })
}

/// Whether `process` has signaled and `job` reports no active process. A
/// signaled process alone does not prove an empty job.
pub fn process_dead(process: HANDLE, job: HANDLE) -> io::Result<bool> {
    // SAFETY: a zero timeout polls the process object.
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_TIMEOUT => Ok(false),
        WAIT_OBJECT_0 => {
            let accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
                query_job(job, JobObjectBasicAccountingInformation)?;
            Ok(accounting.ActiveProcesses == 0)
        }
        _ => Err(fail("native process wait unavailable")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_job_applies_limits() {
        let limits = JobLimits {
            process_memory: 64 * 1024 * 1024,
            job_memory: 32 * 1024 * 1024,
            per_process_user_100ns: 5_000_000,
            per_job_user_100ns: 7_000_000,
            cpu_rate_hard_cap_percent_x100: Some(5000),
        };
        let job = create_job(&limits).unwrap();
        let extended: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            query_job(job.raw(), JobObjectExtendedLimitInformation).unwrap();
        let flags = extended.BasicLimitInformation.LimitFlags;
        assert_eq!(
            flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        );
        assert_eq!(extended.BasicLimitInformation.ActiveProcessLimit, 1);
        assert_eq!(
            extended.BasicLimitInformation.PerProcessUserTimeLimit,
            5_000_000
        );
        assert_eq!(
            extended.BasicLimitInformation.PerJobUserTimeLimit,
            7_000_000
        );
        assert_eq!(extended.ProcessMemoryLimit, 64 * 1024 * 1024);
        assert_eq!(extended.JobMemoryLimit, 32 * 1024 * 1024);
        let cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION =
            query_job(job.raw(), JobObjectCpuRateControlInformation).unwrap();
        assert_eq!(
            cpu.ControlFlags,
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        );
        // SAFETY: CpuRate is the member written by `set_cpu_rate`.
        assert_eq!(unsafe { cpu.Anonymous.CpuRate }, 5000);
        let uncapped = create_job(&JobLimits {
            cpu_rate_hard_cap_percent_x100: None,
            ..limits
        })
        .unwrap();
        let cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION =
            query_job(uncapped.raw(), JobObjectCpuRateControlInformation).unwrap();
        assert_eq!(cpu.ControlFlags, 0);
    }
}
