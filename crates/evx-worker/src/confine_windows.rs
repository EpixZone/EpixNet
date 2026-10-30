//! Windows self-verification: the worker proves to itself, before reading a
//! byte, that the host placed it in a zero-capability less-privileged
//! AppContainer inside a job with the required limits. The host verified
//! the same facts before resuming the child; neither side trusts the
//! other's word for the boundary (`docs/evx-windows-backend.md`).

use std::io::Read;
use std::mem::{size_of, zeroed};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::null_mut;

use evx_windows_native::{granted_access, validate_token};
use evx_workspace::{Dir, Kind};
use windows_sys::Win32::Foundation::{GetHandleInformation, GENERIC_ALL, GENERIC_WRITE};
use windows_sys::Win32::System::JobObjects::{
    JobObjectExtendedLimitInformation, QueryInformationJobObject,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    JOB_OBJECT_LIMIT_PROCESS_TIME,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject, INFINITE};

/// The supervisor duplicates the workspace lease into this process and
/// sends the handle value as the first eight bytes of stdin, little endian,
/// ahead of the first frame.
const WORKSPACE_PREAMBLE: usize = 8;
const REQUIRED_LIMITS: u32 = JOB_OBJECT_LIMIT_PROCESS_MEMORY
    | JOB_OBJECT_LIMIT_JOB_MEMORY
    | JOB_OBJECT_LIMIT_PROCESS_TIME
    | JOB_OBJECT_LIMIT_JOB_TIME
    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;

/// Require the LPAC token and the job limits. Fails closed.
pub fn verify() -> Result<(), String> {
    // SAFETY: the pseudo handle for the current process is always valid.
    validate_token(unsafe { GetCurrentProcess() }, None)
        .map_err(|e| format!("confinement verification failed: {e}"))?;
    // SAFETY: the structure is plain data the API fills.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    // SAFETY: a null job handle queries the job of the calling process; the
    // pointer and length describe `limits`.
    let queried = unsafe {
        QueryInformationJobObject(
            null_mut(),
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            null_mut(),
        )
    };
    if queried == 0 {
        return Err("not inside a job".into());
    }
    let basic = &limits.BasicLimitInformation;
    if basic.LimitFlags & REQUIRED_LIMITS != REQUIRED_LIMITS
        || basic.ActiveProcessLimit != 1
        || limits.ProcessMemoryLimit == 0
        || limits.JobMemoryLimit == 0
        || basic.PerProcessUserTimeLimit <= 0
        || basic.PerJobUserTimeLimit <= 0
    {
        return Err("required job restrictions unavailable".into());
    }
    Ok(())
}

/// The workspace directory from the lease handle the supervisor duplicated
/// into this process. The working directory plays no part: the handle is
/// the only authority. A handle granting more than the role needs is
/// refused: `DELETE` always (a helper must not be able to remove an empty
/// workspace), and any write bit for a read-only helper.
pub fn workspace(writable: bool) -> Result<Dir, String> {
    workspace_from(std::io::stdin().lock(), writable)
}

/// `workspace` with the preamble read from `input` instead of stdin.
fn workspace_from(mut input: impl Read, writable: bool) -> Result<Dir, String> {
    let mut preamble = [0u8; WORKSPACE_PREAMBLE];
    input
        .read_exact(&mut preamble)
        .map_err(|_| "workspace handle not provided".to_string())?;
    let value = usize::try_from(u64::from_le_bytes(preamble))
        .map_err(|_| "invalid workspace handle".to_string())?;
    let raw = value as RawHandle;
    let mut flags = 0;
    // The pseudo handles for the current process and thread (-1 and -2)
    // are "valid" to every query and must never be adopted as a workspace.
    let pseudo = value >= usize::MAX - 1;
    // SAFETY: a handle value is validated before it is adopted; an invalid
    // value is refused here, never closed.
    if raw.is_null() || pseudo || unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
        return Err("workspace handle unavailable".into());
    }
    // SAFETY: the value names an open handle this process inherited and
    // nothing else owns it.
    adopt_workspace(unsafe { OwnedHandle::from_raw_handle(raw) }, writable)
}

// Access rights (winnt.h), spelled out so the masks read as policy.
const FILE_WRITE_DATA: u32 = 0x0002; // FILE_ADD_FILE on a directory
const FILE_APPEND_DATA: u32 = 0x0004; // FILE_ADD_SUBDIRECTORY on a directory
const FILE_WRITE_EA: u32 = 0x0010;
const FILE_DELETE_CHILD: u32 = 0x0040;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const DELETE: u32 = 0x0001_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

/// Access bits a read-only helper's handle must not carry: every write,
/// delete and security-change right, generic or specific.
const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// Accept an inherited workspace handle only if it is a directory and its
/// granted access fits the role.
fn adopt_workspace(handle: OwnedHandle, writable: bool) -> Result<Dir, String> {
    let granted = granted_access(handle.as_raw_handle())
        .map_err(|_| "workspace handle access unavailable".to_string())?;
    if granted & DELETE != 0 {
        return Err("workspace handle grants delete".into());
    }
    if !writable && granted & WRITE_RIGHTS != 0 {
        return Err("read-only workspace handle grants write".into());
    }
    let root = Dir::from(handle);
    match root.stat_self() {
        Ok(stat) if stat.kind == Kind::Directory => Ok(root),
        _ => Err("workspace handle is not a directory".into()),
    }
}

/// Block in a native wait that never completes, for the test fault that
/// proves the supervisor can terminate a stuck helper.
pub fn block_forever() -> ! {
    // SAFETY: a process never signals its own handle while it runs.
    unsafe {
        WaitForSingleObject(GetCurrentProcess(), INFINITE);
    }
    std::process::exit(3);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_test_process_is_not_confined() {
        assert!(verify().is_err());
    }

    #[test]
    fn workspace_handle_must_be_present_and_valid() {
        // No preamble, a short preamble, a null handle and a handle value
        // no process could hold are all refused; stdin is never consulted,
        // so the test cannot block on an inherited pipe.
        assert_eq!(
            workspace_from(std::io::empty(), true).unwrap_err(),
            "workspace handle not provided"
        );
        assert_eq!(
            workspace_from(&[1u8, 2, 3][..], true).unwrap_err(),
            "workspace handle not provided"
        );
        assert_eq!(
            workspace_from(&[0u8; WORKSPACE_PREAMBLE][..], true).unwrap_err(),
            "workspace handle unavailable"
        );
        for pseudo in [u64::MAX, u64::MAX - 1] {
            assert_eq!(
                workspace_from(&pseudo.to_le_bytes()[..], false).unwrap_err(),
                "workspace handle unavailable"
            );
        }
        // A handle value this process never opened.
        assert_eq!(
            workspace_from(&0x7FFF_FFF0u64.to_le_bytes()[..], true).unwrap_err(),
            "workspace handle unavailable"
        );
    }

    /// A handle on `dir` with exactly `access`.
    fn directory_handle(dir: &std::path::Path, access: u32) -> OwnedHandle {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)
            .unwrap()
            .into()
    }

    #[test]
    fn adopted_handles_are_bounded_by_role() {
        const FILE_LIST_DIRECTORY: u32 = 0x0001;
        const FILE_TRAVERSE: u32 = 0x0020;
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const READ_CONTROL: u32 = 0x0002_0000;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const READ: u32 =
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        const WRITE: u32 = READ | FILE_WRITE_DATA | FILE_APPEND_DATA;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
        // The supervisor's own masks are accepted by their roles.
        assert!(adopt_workspace(directory_handle(dir.path(), READ), false).is_ok());
        assert!(adopt_workspace(directory_handle(dir.path(), WRITE), true).is_ok());
        // Write bits are refused by the read-only helper.
        assert_eq!(
            adopt_workspace(directory_handle(dir.path(), WRITE), false).unwrap_err(),
            "read-only workspace handle grants write"
        );
        assert!(adopt_workspace(directory_handle(dir.path(), READ | WRITE_DAC), false).is_err());
        // DELETE is refused by both, as is the host's full lease mask.
        for writable in [false, true] {
            assert_eq!(
                adopt_workspace(directory_handle(dir.path(), READ | DELETE), writable).unwrap_err(),
                "workspace handle grants delete"
            );
            let root = Dir::open_root(dir.path()).unwrap();
            let lease = root.lease().unwrap();
            let mut copy = std::ptr::null_mut();
            // SAFETY: duplicating our own lease handle into our own process.
            let copied = unsafe {
                windows_sys::Win32::Foundation::DuplicateHandle(
                    GetCurrentProcess(),
                    lease.raw(),
                    GetCurrentProcess(),
                    &mut copy,
                    0,
                    0,
                    windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
                )
            };
            assert_ne!(copied, 0);
            // SAFETY: the duplicate is a handle this process owns.
            let copy = unsafe { OwnedHandle::from_raw_handle(copy) };
            assert!(adopt_workspace(copy, writable).is_err());
        }
        // A file is not a workspace.
        let file: OwnedHandle = std::fs::File::open(dir.path().join("file.txt"))
            .unwrap()
            .into();
        assert_eq!(
            adopt_workspace(file, true).unwrap_err(),
            "workspace handle is not a directory"
        );
    }
}
