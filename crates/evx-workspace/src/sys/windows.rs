//! Windows implementation: handle-relative NT opens.
//!
//! `NtCreateFile` with `RootDirectory` set to an open directory handle is
//! the Windows equivalent of `openat`: the name is a single component
//! resolved inside that directory, and `FILE_OPEN_REPARSE_POINT` opens a
//! symbolic link, junction or other reparse point itself instead of
//! following it, so the attributes read back through the handle say what
//! was really opened. Identity is the volume serial number and the file
//! index; link counts come from the same query. Privacy is the owner SID
//! plus the DACL. Renames and deletes use the POSIX-semantics information
//! classes relative to the directory handle, so an open target does not
//! block them and no path string is resolved against the host namespace.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::File;
use std::mem::{offset_of, size_of, zeroed};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::ptr::{null, null_mut, NonNull};

use evx_api::Denied;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{NtCreateFile, NtSetInformationFile, FILE_RENAME_INFORMATION};
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, LocalFree, DUPLICATE_SAME_ACCESS,
    ERROR_LOCK_VIOLATION, ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
    UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetAce, GetSecurityDescriptorDacl, GetTokenInformation,
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, GetFileInformationByHandle, GetFileInformationByHandleEx,
    LockFileEx, SetFileInformationByHandle, UnlockFileEx, BY_HANDLE_FILE_INFORMATION,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_FULL_DIR_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::IO::{IO_STATUS_BLOCK, OVERLAPPED};

use super::{component, Entry, Identity, Kind, Privacy, Stat};

// Access rights (winnt.h). Spelled out here so the masks read as policy.
const FILE_READ_DATA: u32 = 0x0001; // FILE_LIST_DIRECTORY on a directory
const FILE_WRITE_DATA: u32 = 0x0002; // FILE_ADD_FILE on a directory
const FILE_APPEND_DATA: u32 = 0x0004; // FILE_ADD_SUBDIRECTORY on a directory
const FILE_TRAVERSE: u32 = 0x0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
/// What the host holds on a directory it operates in: list, traverse,
/// create, flush. Shares everything, so leases and other readers coexist.
const DIRECTORY_ACCESS: u32 = FILE_READ_DATA
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_TRAVERSE
    | FILE_READ_ATTRIBUTES
    | READ_CONTROL
    | SYNCHRONIZE;
/// What a read-only helper can get on a child directory: list, traverse and
/// attributes. `open_dir` falls back to this when the write bits of
/// `DIRECTORY_ACCESS` are refused, so a `.r` container (read and list only,
/// `docs/evx-windows-backend.md`) can still walk the workspace it reads.
const READ_DIRECTORY_ACCESS: u32 =
    FILE_READ_DATA | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
/// The lease additionally asks for `DELETE` and refuses to share it. Only
/// read, write and delete take part in sharing checks, so this is the one
/// bit a second lease conflicts on while ordinary handles stay unaffected.
const LEASE_ACCESS: u32 = DIRECTORY_ACCESS | DELETE;
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const SHARE_READ_WRITE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;

// NtCreateFile dispositions and options (wdm.h).
const FILE_OPEN: u32 = 0x0000_0001;
const FILE_CREATE: u32 = 0x0000_0002;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC000_0034_u32 as NTSTATUS;
const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS = 0xC000_003A_u32 as NTSTATUS;
const STATUS_OBJECT_NAME_COLLISION: NTSTATUS = 0xC000_0035_u32 as NTSTATUS;
const STATUS_SHARING_VIOLATION: NTSTATUS = 0xC000_0043_u32 as NTSTATUS;
const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;

// Information classes and flags for the information APIs.
/// `FileRenameInformationEx` for `NtSetInformationFile`. The Win32 wrapper
/// refuses a `RootDirectory`, and without one a relative name is resolved
/// against the process working directory, so the NT call is the only one
/// that renames relative to the directory handle.
const FILE_RENAME_INFORMATION_EX: i32 = 65;
const FILE_DISPOSITION_INFO_EX_CLASS: i32 = 21;
const FILE_FULL_DIRECTORY_INFO: i32 = 14;
const FILE_FULL_DIRECTORY_RESTART_INFO: i32 = 15;
const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;
const FILE_DISPOSITION_FLAG_DELETE: u32 = 0x1;
const FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: u32 = 0x2;
const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x1;
const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x2;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const TOKEN_USER_CLASS: i32 = 1;
const TOKEN_OWNER_CLASS: i32 = 4;
const LISTING_BUFFER: usize = 64 * 1024;

/// An open directory handle.
#[derive(Debug)]
pub struct Dir(OwnedHandle);

/// The workspace lease: a second handle on the directory that owns
/// `DELETE` access and shares only read and write.
#[derive(Debug)]
pub struct Lease {
    handle: Option<OwnedHandle>,
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the pointer came from an API that documents LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn denied(reason: &'static str) -> Denied {
    Denied::new(reason)
}

fn wide(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}

fn nul_terminated(path: &Path) -> Result<Vec<u16>, Denied> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(denied("invalid path"));
    }
    wide.push(0);
    Ok(wide)
}

/// Open `name` inside `root` without following a reparse point.
fn open_relative(
    root: HANDLE,
    name: &str,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    security: *const c_void,
) -> Result<OwnedHandle, NTSTATUS> {
    let mut buffer = wide(name);
    let length = u16::try_from(buffer.len() * 2).map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
    let unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: buffer.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.cast(),
        SecurityQualityOfService: null(),
    };
    let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
    let mut handle: HANDLE = null_mut();
    // SAFETY: every pointer refers to a live local; the name buffer outlives
    // the call; the kernel writes only the handle and the status block.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            null(),
            0,
        )
    };
    if status < 0 {
        return Err(status);
    }
    // SAFETY: a successful NtCreateFile returned a handle this process owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, Denied> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: valid handle and output struct.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(denied("workspace stat"));
    }
    Ok(info)
}

fn convert(info: &BY_HANDLE_FILE_INFORMATION) -> Stat {
    let kind = if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        Kind::Other
    } else if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        Kind::Directory
    } else {
        Kind::Regular
    };
    Stat {
        kind,
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        links: u64::from(info.nNumberOfLinks),
        identity: Identity([
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ]),
    }
}

fn stat_handle(handle: HANDLE) -> Result<Stat, Denied> {
    information(handle).map(|info| convert(&info))
}

fn absent(status: NTSTATUS) -> bool {
    status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND
}

/// The directory handle must be a real directory, not a reparse point.
fn require_directory(handle: &OwnedHandle) -> Result<(), Denied> {
    match stat_handle(handle.as_raw_handle())?.kind {
        Kind::Directory => Ok(()),
        _ => Err(denied("workspace directory")),
    }
}

impl Dir {
    /// Open a directory by path. The final component is not followed.
    pub fn open_root(path: &Path) -> Result<Dir, Denied> {
        let name = nul_terminated(path)?;
        // SAFETY: NUL-terminated path; no security attributes or template.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                DIRECTORY_ACCESS,
                SHARE_ALL,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(denied("workspace root unavailable"));
        }
        // SAFETY: CreateFileW returned a handle this process owns.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        require_directory(&handle).map_err(|_| denied("workspace root unavailable"))?;
        Ok(Dir(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }

    /// Open a child directory without following links. A caller whose token
    /// is granted only read and list rights gets a read-only handle.
    pub fn open_dir(&self, name: &str) -> Result<Dir, Denied> {
        let name = component(name)?;
        let handle = match self.open_child_dir(name, DIRECTORY_ACCESS) {
            Err(STATUS_ACCESS_DENIED) => self.open_child_dir(name, READ_DIRECTORY_ACCESS),
            other => other,
        }
        .map_err(|_| denied("workspace directory"))?;
        require_directory(&handle)?;
        Ok(Dir(handle))
    }

    fn open_child_dir(&self, name: &str, access: u32) -> Result<OwnedHandle, NTSTATUS> {
        open_relative(
            self.raw(),
            name,
            access,
            SHARE_ALL,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
            null(),
        )
    }

    /// A second handle for the same directory.
    pub fn try_clone(&self) -> Result<Dir, Denied> {
        let mut duplicate: HANDLE = null_mut();
        // SAFETY: duplicating our own handle into our own process.
        let copied = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.raw(),
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if copied == 0 {
            return Err(denied("workspace descriptor"));
        }
        // SAFETY: DuplicateHandle returned a handle this process owns.
        Ok(Dir(unsafe { OwnedHandle::from_raw_handle(duplicate) }))
    }

    fn make_dir(&self, name: &str, security: *const c_void) -> Result<bool, Denied> {
        match open_relative(
            self.raw(),
            component(name)?,
            DIRECTORY_ACCESS,
            SHARE_ALL,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            security,
        ) {
            Ok(_) => Ok(true),
            Err(STATUS_OBJECT_NAME_COLLISION) => Ok(false),
            Err(_) => Err(denied("workspace directory")),
        }
    }

    /// Create a child directory that inherits this directory's ACL.
    /// `Ok(false)` when it exists.
    pub fn create_dir(&self, name: &str) -> Result<bool, Denied> {
        self.make_dir(name, null())
    }

    /// Create a host-private child directory: a protected DACL naming only
    /// the owner and SYSTEM, so nothing inherited from a profile directory
    /// reaches it. `Ok(false)` when it exists.
    pub fn create_private_dir(&self, name: &str) -> Result<bool, Denied> {
        let descriptor = private_descriptor()?;
        self.make_dir(name, descriptor.0)
    }

    /// Metadata of a child without following it; `None` when absent.
    pub fn stat(&self, name: &str) -> Result<Option<Stat>, Denied> {
        match open_relative(
            self.raw(),
            component(name)?,
            FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            FILE_OPEN,
            FILE_OPEN_FOR_BACKUP_INTENT,
            null(),
        ) {
            Ok(handle) => stat_handle(handle.as_raw_handle()).map(Some),
            Err(status) if absent(status) => Ok(None),
            Err(_) => Err(denied("workspace stat")),
        }
    }

    /// Metadata of this directory.
    pub fn stat_self(&self) -> Result<Stat, Denied> {
        stat_handle(self.raw())
    }

    /// Open a child for reading without following it; `None` when absent.
    pub fn open_read(&self, name: &str) -> Result<Option<(File, Stat)>, Denied> {
        self.open_file(name, FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL)
    }

    /// Open an existing child for reading and writing; `None` when absent.
    pub fn open_write(&self, name: &str) -> Result<Option<(File, Stat)>, Denied> {
        self.open_file(
            name,
            FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        )
    }

    fn open_file(&self, name: &str, access: u32) -> Result<Option<(File, Stat)>, Denied> {
        let handle = match open_relative(
            self.raw(),
            component(name)?,
            access,
            SHARE_ALL,
            FILE_OPEN,
            0,
            null(),
        ) {
            Ok(handle) => handle,
            Err(status) if absent(status) => return Ok(None),
            Err(_) => return Err(denied("workspace operation denied")),
        };
        let stat = stat_handle(handle.as_raw_handle())?;
        Ok(Some((File::from(handle), stat)))
    }

    /// Create a child that must not exist yet, for writing. It inherits
    /// this directory's ACL and shares read and delete, so an abort can
    /// remove it while it is still open.
    pub fn create_new(&self, name: &str) -> Result<File, Denied> {
        open_relative(
            self.raw(),
            component(name)?,
            FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            null(),
        )
        .map(File::from)
        .map_err(|_| denied("workspace operation denied"))
    }

    fn open_for_delete(&self, name: &str) -> Result<OwnedHandle, Denied> {
        let handle = open_relative(
            self.raw(),
            component(name)?,
            DELETE | FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            null(),
        )
        .map_err(|_| denied("workspace operation denied"))?;
        if stat_handle(handle.as_raw_handle())?.kind != Kind::Regular {
            return Err(denied("workspace operation denied"));
        }
        Ok(handle)
    }

    /// Rename one child over another within this directory, replacing an
    /// existing target atomically. The target name is resolved relative to
    /// this directory handle, never against a path.
    pub fn rename(&self, from: &str, to: &str) -> Result<(), Denied> {
        let source = self.open_for_delete(from)?;
        let target = wide(component(to)?);
        let name_bytes = target.len() * 2;
        let header = size_of::<FILE_RENAME_INFORMATION>();
        let mut buffer = vec![0u8; header + name_bytes];
        let mut status_block: IO_STATUS_BLOCK = unsafe { zeroed() };
        // SAFETY: the buffer is at least one FILE_RENAME_INFORMATION long
        // and the name is copied after the fixed fields, as the API lays it
        // out; every pointer refers to a live local.
        let status = unsafe {
            let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
            (*info).Anonymous.Flags =
                FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
            (*info).RootDirectory = self.raw();
            (*info).FileNameLength = name_bytes as u32;
            std::ptr::copy_nonoverlapping(
                target.as_ptr().cast::<u8>(),
                buffer
                    .as_mut_ptr()
                    .add(std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName)),
                name_bytes,
            );
            NtSetInformationFile(
                source.as_raw_handle(),
                &mut status_block,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                FILE_RENAME_INFORMATION_EX,
            )
        };
        if status < 0 {
            return Err(denied("workspace operation denied"));
        }
        Ok(())
    }

    /// Remove a child that is not a directory, even while it is open by a
    /// handle that shares delete.
    pub fn unlink(&self, name: &str) -> Result<(), Denied> {
        let handle = self.open_for_delete(name)?;
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        // SAFETY: valid handle and a fully initialised information struct.
        let set = unsafe {
            SetFileInformationByHandle(
                handle.as_raw_handle(),
                FILE_DISPOSITION_INFO_EX_CLASS,
                (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        };
        if set == 0 {
            return Err(denied("workspace operation denied"));
        }
        Ok(())
    }

    /// List the entries without following any of them.
    pub fn entries(&self) -> Result<Vec<Entry>, Denied> {
        let mut buffer = vec![0u64; LISTING_BUFFER / 8];
        let mut entries = Vec::new();
        let mut class = FILE_FULL_DIRECTORY_RESTART_INFO;
        loop {
            // SAFETY: the buffer is 8-byte aligned and its length is passed.
            let filled = unsafe {
                GetFileInformationByHandleEx(
                    self.raw(),
                    class,
                    buffer.as_mut_ptr().cast(),
                    LISTING_BUFFER as u32,
                )
            };
            if filled == 0 {
                // SAFETY: plain thread-local error query.
                if unsafe { GetLastError() } == ERROR_NO_MORE_FILES {
                    return Ok(entries);
                }
                return Err(denied("workspace listing"));
            }
            class = FILE_FULL_DIRECTORY_INFO;
            collect_entries(buffer.as_ptr().cast::<u8>(), &mut entries)?;
        }
    }

    /// Flush this directory's metadata, so a completed rename is durable.
    pub fn sync(&self) -> Result<(), Denied> {
        // SAFETY: valid handle opened with write access.
        if unsafe { FlushFileBuffers(self.raw()) } == 0 {
            return Err(denied("workspace operation denied"));
        }
        Ok(())
    }

    /// Durable identity of this directory.
    pub fn identity(&self) -> Result<Identity, Denied> {
        Ok(self.stat_self()?.identity)
    }

    /// Who can reach this directory.
    pub fn privacy(&self) -> Result<Privacy, Denied> {
        privacy_of(self.raw())
    }

    /// Restrict this directory to its owner and SYSTEM with a protected
    /// DACL that children inherit.
    pub fn make_private(&self) -> Result<(), Denied> {
        let descriptor = private_descriptor()?;
        let mut present: i32 = 0;
        let mut defaulted: i32 = 0;
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: a valid self-relative descriptor from the converter.
        let found = unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
        };
        if found == 0 || present == 0 || dacl.is_null() {
            return Err(denied("workspace operation denied"));
        }
        // Writing the DACL needs WRITE_DAC, which the ordinary handle does
        // not carry: reopen this very directory through its handle.
        let writable = open_relative(
            self.raw(),
            "",
            WRITE_DAC | READ_CONTROL,
            SHARE_ALL,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
            null(),
        )
        .map_err(|_| denied("workspace operation denied"))?;
        // SAFETY: valid handle and DACL; owner and SACL are left untouched.
        let status = unsafe {
            SetSecurityInfo(
                writable.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if status != 0 {
            return Err(denied("workspace operation denied"));
        }
        Ok(())
    }

    /// Reopen this directory (`None`) or one child (`Some(name)`), without
    /// following a link, with the access needed to read and replace its
    /// DACL. The host uses it to prepare a workspace's ACL; nothing else
    /// needs `WRITE_DAC`.
    pub fn open_security(&self, name: Option<&str>) -> Result<OwnedHandle, Denied> {
        let name = match name {
            Some(name) => component(name)?,
            None => "",
        };
        open_relative(
            self.raw(),
            name,
            WRITE_DAC | READ_CONTROL | FILE_READ_ATTRIBUTES,
            SHARE_ALL,
            FILE_OPEN,
            FILE_OPEN_FOR_BACKUP_INTENT,
            null(),
        )
        .map_err(|_| denied("workspace operation denied"))
    }

    /// Take the exclusive workspace lease, or report that another holder
    /// has it. The lease is a reopen of this very directory through its
    /// handle, never through a path.
    pub fn lease(&self) -> Result<Lease, Denied> {
        match open_relative(
            self.raw(),
            "",
            LEASE_ACCESS,
            SHARE_READ_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT,
            null(),
        ) {
            Ok(handle) => Ok(Lease {
                handle: Some(handle),
            }),
            Err(STATUS_SHARING_VIOLATION) => Err(denied("workspace busy")),
            Err(_) => Err(denied("workspace lease")),
        }
    }

    /// The raw handle, for inheritance into a confined child.
    pub fn as_raw_handle(&self) -> RawHandle {
        self.0.as_raw_handle()
    }

}

impl From<OwnedHandle> for Dir {
    /// Adopt an inherited directory handle the caller already owns.
    fn from(handle: OwnedHandle) -> Dir {
        Dir(handle)
    }
}

/// Decode one buffer of `FILE_FULL_DIR_INFO` records.
fn collect_entries(mut cursor: *const u8, entries: &mut Vec<Entry>) -> Result<(), Denied> {
    loop {
        // SAFETY: the kernel wrote valid, chained records into this buffer.
        let record = unsafe { &*cursor.cast::<FILE_FULL_DIR_INFO>() };
        let name_len = record.FileNameLength as usize / 2;
        let name_ptr = std::ptr::addr_of!(record.FileName).cast::<u16>();
        // SAFETY: FileName is an inline array of FileNameLength bytes.
        let units = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
        let name = String::from_utf16(units).map_err(|_| denied("workspace name encoding"))?;
        if name != "." && name != ".." {
            let kind = if record.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                Kind::Other
            } else if record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                Kind::Directory
            } else {
                Kind::Regular
            };
            entries.push(Entry {
                name,
                kind,
                size: record.EndOfFile.max(0) as u64,
            });
        }
        if record.NextEntryOffset == 0 {
            return Ok(());
        }
        // SAFETY: NextEntryOffset stays inside the buffer the kernel filled.
        cursor = unsafe { cursor.add(record.NextEntryOffset as usize) };
    }
}

impl Lease {
    /// The handle a helper inherits to keep the lease alive.
    pub fn raw(&self) -> RawHandle {
        self.handle
            .as_ref()
            .map_or(INVALID_HANDLE_VALUE, |handle| handle.as_raw_handle())
    }

    /// Release the lease.
    pub fn release(self) {
        drop(self);
    }

    /// Keep the lease forever: a quarantined workspace is never released.
    /// The handle is leaked on purpose.
    pub fn forget(mut self) {
        if let Some(handle) = self.handle.take() {
            std::mem::forget(handle);
        }
    }
}

/// Metadata of an open file.
pub fn file_stat(file: &File) -> Result<Stat, Denied> {
    stat_handle(file.as_raw_handle())
}

/// Who can reach an open file.
pub fn file_privacy(file: &File) -> Result<Privacy, Denied> {
    privacy_of(file.as_raw_handle())
}

/// Try an exclusive non-blocking lock on an open file. `Ok(false)` when
/// another holder has it.
pub fn try_lock_file(file: &File) -> Result<bool, Denied> {
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    // SAFETY: valid handle; one byte at offset zero, which may lie past EOF.
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if locked != 0 {
        return Ok(true);
    }
    // SAFETY: plain thread-local error query.
    if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
        return Ok(false);
    }
    Err(denied("workspace lock"))
}

/// Release a lock taken with [`try_lock_file`].
pub fn unlock_file(file: &File) -> Result<(), Denied> {
    let mut overlapped: OVERLAPPED = unsafe { zeroed() };
    // SAFETY: the same byte range the lock covered.
    if unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut overlapped) } == 0 {
        return Err(denied("workspace lock"));
    }
    Ok(())
}

struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by OpenProcessToken below.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

fn current_token() -> Result<Token, Denied> {
    let mut raw: HANDLE = null_mut();
    // SAFETY: querying our own process token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(denied("workspace owner"));
    }
    Ok(Token(raw))
}

fn token_information(token: &Token, class: i32) -> Result<Vec<u64>, Denied> {
    let mut bytes = 0u32;
    // SAFETY: a size query with a null buffer.
    unsafe {
        GetTokenInformation(token.0, class, null_mut(), 0, &mut bytes);
    }
    if bytes == 0 || bytes > 65536 {
        return Err(denied("workspace owner"));
    }
    let mut buffer = vec![0u64; (bytes as usize).div_ceil(8)];
    // SAFETY: the buffer is at least `bytes` long and 8-byte aligned.
    let ok = unsafe {
        GetTokenInformation(token.0, class, buffer.as_mut_ptr().cast(), bytes, &mut bytes)
    };
    if ok == 0 {
        return Err(denied("workspace owner"));
    }
    Ok(buffer)
}

/// The SIDs that may appear on a private object: the token's user and its
/// default owner (Administrators for an elevated process), SYSTEM and the
/// Administrators group.
struct Principals {
    user: Vec<u64>,
    owner: Vec<u64>,
    system: Vec<u8>,
    administrators: Vec<u8>,
}

fn well_known(kind: i32) -> Result<Vec<u8>, Denied> {
    let mut sid = vec![0u8; 68];
    let mut size = sid.len() as u32;
    // SAFETY: the buffer is the documented maximum SID size.
    if unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(denied("workspace owner"));
    }
    Ok(sid)
}

impl Principals {
    fn current() -> Result<Self, Denied> {
        let token = current_token()?;
        Ok(Self {
            user: token_information(&token, TOKEN_USER_CLASS)?,
            owner: token_information(&token, TOKEN_OWNER_CLASS)?,
            system: well_known(WinLocalSystemSid)?,
            administrators: well_known(WinBuiltinAdministratorsSid)?,
        })
    }

    fn user_sid(&self) -> PSID {
        // SAFETY: the buffer holds a TOKEN_USER whose SID pointer targets
        // the same allocation.
        unsafe { (*self.user.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }

    fn owner_sid(&self) -> PSID {
        // SAFETY: as above for TOKEN_OWNER.
        unsafe { (*self.owner.as_ptr().cast::<TOKEN_OWNER>()).Owner }
    }

    fn is_caller(&self, sid: PSID) -> bool {
        // SAFETY: both arguments are valid SIDs.
        unsafe { EqualSid(sid, self.user_sid()) != 0 || EqualSid(sid, self.owner_sid()) != 0 }
    }

    fn is_system_or_administrators(&self, sid: PSID) -> bool {
        // SAFETY: both arguments are valid SIDs.
        unsafe {
            EqualSid(sid, self.system.as_ptr().cast_mut().cast()) != 0
                || EqualSid(sid, self.administrators.as_ptr().cast_mut().cast()) != 0
        }
    }
}

fn privacy_of(handle: HANDLE) -> Result<Privacy, Denied> {
    let principals = Principals::current()?;
    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: valid handle; the descriptor is freed by `Local`.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() || owner.is_null() {
        return Err(denied("workspace owner"));
    }
    let _descriptor = Local(descriptor);
    let owned = principals.is_caller(owner);
    // A missing DACL grants everyone everything.
    let shared = match NonNull::new(dacl) {
        None => true,
        Some(dacl) => dacl_shared(dacl, &principals)?,
    };
    Ok(Privacy {
        owned,
        shared,
        mode: None,
    })
}

/// Whether any allow entry names a principal other than the caller, SYSTEM
/// or Administrators. Unknown entry types count as shared.
fn dacl_shared(dacl: NonNull<ACL>, principals: &Principals) -> Result<bool, Denied> {
    // SAFETY: GetSecurityInfo returned this non-null ACL inside the
    // descriptor, which outlives the walk.
    let count = unsafe { dacl.as_ref() }.AceCount;
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: index is below AceCount.
        if unsafe { GetAce(dacl.as_ptr(), index, &mut ace) } == 0 {
            return Err(denied("workspace owner"));
        }
        let ace = NonNull::new(ace).ok_or_else(|| denied("workspace owner"))?;
        // SAFETY: every ACE starts with an ACE_HEADER, inside the descriptor.
        let header = unsafe { ace.cast::<ACE_HEADER>().as_ref() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            return Ok(true);
        }
        // SAFETY: an access-allowed ACE carries its SID inline at SidStart,
        // within the entry `header.AceSize` describes; this is address
        // arithmetic inside that entry, not a read.
        let sid: PSID = unsafe {
            ace.as_ptr()
                .cast::<u8>()
                .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
        }
        .cast::<c_void>();
        if !principals.is_caller(sid) && !principals.is_system_or_administrators(sid) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn sid_text(sid: PSID) -> Result<String, Denied> {
    let mut raw: *mut u16 = null_mut();
    // SAFETY: valid SID; the string is freed by `Local`.
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 {
        return Err(denied("workspace owner"));
    }
    let allocated = Local(raw.cast());
    let mut len = 0;
    // SAFETY: the converter returned a NUL-terminated string.
    unsafe {
        while len < 256 && *raw.add(len) != 0 {
            len += 1;
        }
    }
    if len == 256 {
        return Err(denied("workspace owner"));
    }
    // SAFETY: `len` characters were found before the terminator.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
        .map_err(|_| denied("workspace owner"))?;
    drop(allocated);
    Ok(text)
}

/// A self-relative security descriptor whose protected DACL names only the
/// caller's default owner and SYSTEM, with inheritance to children.
fn private_descriptor() -> Result<Local, Denied> {
    let principals = Principals::current()?;
    let owner = sid_text(principals.owner_sid())?;
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})");
    let mut text: Vec<u16> = sddl.encode_utf16().collect();
    text.push(0);
    let mut raw: *mut c_void = null_mut();
    // SAFETY: NUL-terminated SDDL; the descriptor is freed by `Local`.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), 1, &mut raw, null_mut())
    };
    if converted == 0 || raw.is_null() {
        return Err(denied("workspace operation denied"));
    }
    Ok(Local(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn relative_opens_refuse_links_and_report_identity() {
        let dir = tempfile::tempdir().unwrap();
        let root = Dir::open_root(dir.path()).unwrap();
        assert!(root.create_dir("sub").unwrap());
        assert!(!root.create_dir("sub").unwrap());
        let mut file = root.create_new("a.txt").unwrap();
        file.write_all(b"hello").unwrap();
        file.sync_all().unwrap();
        drop(file);
        let stat = root.stat("a.txt").unwrap().unwrap();
        assert_eq!(stat.kind, Kind::Regular);
        assert_eq!(stat.size, 5);
        assert_eq!(stat.links, 1);
        assert!(root.stat("missing").unwrap().is_none());
        std::fs::hard_link(dir.path().join("a.txt"), dir.path().join("b.txt")).unwrap();
        assert_eq!(root.stat("a.txt").unwrap().unwrap().links, 2);
        let (_, opened) = root.open_read("a.txt").unwrap().unwrap();
        assert_eq!(opened.identity, stat.identity);
        assert_ne!(root.identity().unwrap(), stat.identity);
        let names: Vec<_> = root.entries().unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["a.txt", "b.txt", "sub"]);
        // A junction is a reparse point and is never followed.
        let outside = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(dir.path().join("jump"))
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(status.status.success(), "{status:?}");
        assert_eq!(root.stat("jump").unwrap().unwrap().kind, Kind::Other);
        assert!(root.open_dir("jump").is_err());
        assert_eq!(
            root.entries().unwrap().iter().find(|e| e.name == "jump").unwrap().kind,
            Kind::Other
        );
    }

    #[test]
    fn rename_replaces_and_unlink_removes_open_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = Dir::open_root(dir.path()).unwrap();
        root.create_new("old").unwrap().write_all(b"1").unwrap();
        root.create_new("new").unwrap().write_all(b"22").unwrap();
        let (held, _) = root.open_read("new").unwrap().unwrap();
        root.rename("old", "new").unwrap();
        drop(held);
        assert_eq!(std::fs::read(dir.path().join("new")).unwrap(), b"1");
        assert!(root.stat("old").unwrap().is_none());
        let staged = root.create_new("staged").unwrap();
        root.unlink("staged").unwrap();
        drop(staged);
        assert!(root.stat("staged").unwrap().is_none());
        root.sync().unwrap();
        assert!(root.create_dir("d").unwrap());
        assert!(root.unlink("d").is_err());
    }

    #[test]
    fn a_second_lease_fails_while_ordinary_handles_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let root = Dir::open_root(dir.path()).unwrap();
        let other = Dir::open_root(dir.path()).unwrap();
        let lease = root.lease().unwrap();
        assert_eq!(other.lease().unwrap_err().to_string(), "workspace busy");
        assert_eq!(root.lease().unwrap_err().to_string(), "workspace busy");
        // Files can still be created and listed by anyone.
        std::fs::write(dir.path().join("inside"), b"x").unwrap();
        assert_eq!(other.entries().unwrap().len(), 1);
        assert!(std::fs::read_dir(dir.path()).is_ok());
        lease.release();
        other.lease().unwrap().release();
        let forgotten = root.lease().unwrap();
        forgotten.forget();
        assert!(other.lease().is_err());
    }

    #[test]
    fn file_locks_are_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let root = Dir::open_root(dir.path()).unwrap();
        root.create_new("lock").unwrap();
        let (first, _) = root.open_write("lock").unwrap().unwrap();
        let (second, _) = root.open_write("lock").unwrap().unwrap();
        assert!(try_lock_file(&first).unwrap());
        assert!(!try_lock_file(&second).unwrap());
        unlock_file(&first).unwrap();
        assert!(try_lock_file(&second).unwrap());
    }

    #[test]
    fn privacy_follows_owner_and_dacl() {
        let dir = tempfile::tempdir().unwrap();
        let root = Dir::open_root(dir.path()).unwrap();
        assert!(root.create_private_dir("private").unwrap());
        let private = root.open_dir("private").unwrap();
        let privacy = private.privacy().unwrap();
        assert!(privacy.owned && !privacy.shared, "{privacy:?}");
        private.create_new("inner").unwrap();
        let (inner, _) = private.open_read("inner").unwrap().unwrap();
        assert!(file_privacy(&inner).unwrap().is_private());
        // Everyone read access makes it shared.
        let status = std::process::Command::new("icacls")
            .arg(dir.path().join("private"))
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .unwrap();
        assert!(status.status.success(), "{status:?}");
        assert!(private.privacy().unwrap().shared);
        private.make_private().unwrap();
        assert!(private.privacy().unwrap().is_private());
    }
}
