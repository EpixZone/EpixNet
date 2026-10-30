//! Create relocation directories with private permissions before any bytes exist.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null_mut, NonNull};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAclInformation, GetSecurityDescriptorControl, GetTokenInformation,
    IsValidAcl, IsValidSecurityDescriptor, TokenUser, ACL, ACL_SIZE_INFORMATION,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERITED_ACE, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetVolumeInformationByHandleW, FILE_ALL_ACCESS, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS, SID_MAX_SUB_AUTHORITIES, SID_REVISION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: these buffers are allocated by the documented LocalFree APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    // SAFETY: SID pointers come from a live token/security-descriptor buffer.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(text.cast());
    let mut length = 0;
    // SAFETY: the successful API returns a terminated UTF-16 string.
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(text, length))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

fn current_user_sid() -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: the pseudo process handle is valid; token is an output handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken transferred this handle to us.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    // SAFETY: a null buffer and zero length query the required allocation size.
    let result =
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
    if result != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || size < std::mem::size_of::<TOKEN_USER>() as u32
        || size > 64 * 1024
    {
        return Err(denied(
            "Cannot determine the current Windows user for private storage",
        ));
    }
    // usize storage preserves the alignment of TOKEN_USER and its embedded SID.
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: buffer is aligned and has at least size writable bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful TokenUser output begins with TOKEN_USER.
    sid_string(unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid })
}

fn create_with_descriptor(path: &Path, descriptor: &str) -> io::Result<()> {
    let descriptor: Vec<u16> = descriptor.encode_utf16().chain(Some(0)).collect();
    let mut security: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the input is a terminated UTF-16 descriptor; output is owned below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor.as_ptr(),
            SDDL_REVISION_1,
            &mut security,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let _security = LocalAllocation(security);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security,
        bInheritHandle: 0,
    };
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both buffers live through CreateDirectoryW. Existing paths fail.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn open_directory(path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

// Parse only bounded bytes. In an ACCESS_ALLOWED_ACE the header and access mask
// occupy eight bytes, followed by a variable-length SID. Checking the complete
// SID extent here makes the subsequent Windows SID conversion safe.
fn private_ace_sid(ace: &[u8], flags: u8, mask: u32) -> io::Result<&[u8]> {
    if ace.len() < 16
        || ace[0] != ACCESS_ALLOWED_ACE_TYPE as u8
        || ace[1] != flags
        || usize::from(u16::from_le_bytes([ace[2], ace[3]])) != ace.len()
        || u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]) != mask
    {
        return Err(denied("Private storage has an unexpected access entry"));
    }
    let sid = &ace[8..];
    if sid[0] != SID_REVISION as u8
        || u32::from(sid[1]) > SID_MAX_SUB_AUTHORITIES
        || sid.len() != 8 + usize::from(sid[1]) * 4
    {
        return Err(denied("Private storage has an invalid access-entry SID"));
    }
    Ok(sid)
}

fn verify_private_acl(file: &File, expected_sid: &str, directory: bool) -> io::Result<()> {
    let mut owner = null_mut();
    let mut acl: *mut ACL = null_mut();
    let mut security: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: handle is live and output pointers are writable. Only the returned
    // descriptor owns memory; owner and ACL point inside it.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut security,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let security = NonNull::new(security)
        .ok_or_else(|| denied("Private storage has no security descriptor"))?;
    let _security = LocalAllocation(security.as_ptr());
    let owner = NonNull::new(owner).ok_or_else(|| denied("Private storage has no owner"))?;
    let acl = NonNull::new(acl).ok_or_else(|| denied("Private storage has no restrictive DACL"))?;
    // SAFETY: these non-null pointers refer to the live GetSecurityInfo buffer.
    if unsafe { IsValidSecurityDescriptor(security.as_ptr()) } == 0
        || unsafe { IsValidAcl(acl.as_ptr()) } == 0
    {
        return Err(denied("Private storage has an invalid security descriptor"));
    }
    if directory && sid_string(owner.as_ptr())? != expected_sid {
        return Err(denied(
            "Private storage did not retain the current user's owner and DACL",
        ));
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: security is the live descriptor returned above.
    if unsafe { GetSecurityDescriptorControl(security.as_ptr(), &mut control, &mut revision) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: the ACL is validated above and information is a writable struct.
    if unsafe {
        GetAclInformation(
            acl.as_ptr(),
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // A single current-user allow ACE excludes inherited Everyone/Users access.
    // Directories must also block future broad ACL propagation from the target.
    if information.AceCount != 1 || (directory && control & SE_DACL_PROTECTED == 0) {
        return Err(denied(
            "Private storage inherited permissions from its destination",
        ));
    }
    let used = information.AclBytesInUse as usize;
    if !(std::mem::size_of::<ACL>()..=u16::MAX as usize).contains(&used) {
        return Err(denied("Private storage has an invalid ACL extent"));
    }
    // SAFETY: GetAclInformation reports the bytes occupied by the validated ACL
    // and its ACEs. The descriptor allocation remains owned until this function
    // returns. Only this bounded slice is inspected, with no typed pointer reads.
    let bytes = unsafe { std::slice::from_raw_parts(acl.as_ptr().cast::<u8>(), used) };
    let flags = if directory {
        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
    } else {
        INHERITED_ACE as u8
    };
    let sid = private_ace_sid(&bytes[std::mem::size_of::<ACL>()..], flags, FILE_ALL_ACCESS)?;
    if sid_string(sid.as_ptr().cast_mut().cast())? != expected_sid {
        return Err(denied(
            "Private storage grants access beyond the current Windows user",
        ));
    }
    Ok(())
}

/// Return the verified handle without delete sharing so the caller can retain
/// it without a path-reopen gap. Existing paths and unsupported ACL storage fail.
pub(super) fn verify_private_directory(file: &File) -> io::Result<()> {
    verify_private_acl(file, &current_user_sid()?, true)
}

pub(super) fn create_private_directory(path: &Path, parent: &File) -> io::Result<File> {
    let mut flags = 0;
    // SAFETY: parent is a pinned directory handle; optional outputs are null.
    if unsafe {
        GetVolumeInformationByHandleW(
            parent.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "Cannot verify destination ACL support: {}",
                io::Error::last_os_error()
            ),
        ));
    }
    if flags & FILE_PERSISTENT_ACLS == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "The destination filesystem cannot enforce private Windows permissions",
        ));
    }
    let sid = current_user_sid()?;
    create_with_descriptor(path, &format!("O:{sid}D:P(A;OICI;FA;;;{sid})"))?;
    let directory = open_directory(path)?;
    super::regular_metadata(&directory.metadata()?, true)?;
    verify_private_acl(&directory, &sid, true)?;
    Ok(directory)
}

#[cfg(test)]
mod ace_bounds_tests {
    use super::*;

    fn fixture(flags: u8) -> Vec<u8> {
        // A single allow ACE for S-1-5-21-42, in the Windows wire layout.
        let mut bytes = vec![0, flags, 24, 0];
        bytes.extend(FILE_ALL_ACCESS.to_le_bytes());
        bytes.extend([1, 2, 0, 0, 0, 0, 0, 5]);
        bytes.extend(21u32.to_le_bytes());
        bytes.extend(42u32.to_le_bytes());
        bytes
    }

    #[test]
    fn accepts_only_the_complete_bounded_sid() {
        for flags in [3, 16] {
            let bytes = fixture(flags);
            assert_eq!(
                private_ace_sid(&bytes, flags, FILE_ALL_ACCESS).unwrap(),
                &bytes[8..]
            );
            for length in 0..bytes.len() {
                assert!(private_ace_sid(&bytes[..length], flags, FILE_ALL_ACCESS).is_err());
            }
        }
    }

    #[test]
    fn rejects_mismatched_ace_and_sid_lengths() {
        for size in [0u16, 8, 16, 23, 25, u16::MAX] {
            let mut bytes = fixture(3);
            bytes[2..4].copy_from_slice(&size.to_le_bytes());
            assert!(private_ace_sid(&bytes, 3, FILE_ALL_ACCESS).is_err());
        }
        for count in [0u8, 1, 3, 15, 16, 255] {
            let mut bytes = fixture(3);
            bytes[9] = count;
            assert!(private_ace_sid(&bytes, 3, FILE_ALL_ACCESS).is_err());
        }
        let mut trailing = fixture(3);
        trailing.extend([0; 4]);
        trailing[2] = 28;
        assert!(private_ace_sid(&trailing, 3, FILE_ALL_ACCESS).is_err());
    }

    #[test]
    fn rejects_other_entry_types_flags_masks_and_sid_revisions() {
        for kind in 1..=u8::MAX {
            let mut bytes = fixture(3);
            bytes[0] = kind;
            assert!(private_ace_sid(&bytes, 3, FILE_ALL_ACCESS).is_err());
        }
        for flags in [0, 1, 2, 7, 16, 255] {
            let bytes = fixture(flags);
            assert!(private_ace_sid(&bytes, 3, FILE_ALL_ACCESS).is_err());
        }
        for mask in [0, FILE_ALL_ACCESS ^ 1, u32::MAX] {
            let mut bytes = fixture(3);
            bytes[4..8].copy_from_slice(&mask.to_le_bytes());
            assert!(private_ace_sid(&bytes, 3, FILE_ALL_ACCESS).is_err());
        }
        let mut revision = fixture(3);
        revision[8] = 2;
        assert!(private_ace_sid(&revision, 3, FILE_ALL_ACCESS).is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_parent_cannot_grant_other_users_access_to_staged_or_promoted_private_files() {
        let temp = tempfile::tempdir().unwrap();
        let shared = temp.path().canonicalize().unwrap().join("shared");
        create_with_descriptor(&shared, "D:P(A;OICI;FA;;;WD)").unwrap();
        let parent = open_directory(&shared).unwrap();
        let stage_path = shared.join("stage");
        let stage = create_private_directory(&stage_path, &parent).unwrap();
        let private_path = stage_path.join("private");
        let private = create_private_directory(&private_path, &stage).unwrap();
        let sid = current_user_sid().unwrap();
        std::fs::write(private_path.join("users.json"), b"public fixture identity").unwrap();
        verify_private_acl(&stage, &sid, true).unwrap();
        verify_private_acl(&private, &sid, true).unwrap();
        verify_private_acl(
            &File::open(private_path.join("users.json")).unwrap(),
            &sid,
            false,
        )
        .unwrap();
        assert!(
            create_private_directory(&private_path, &stage).is_err(),
            "existing directories cannot have their ACL rewritten"
        );
        drop(private);
        let promoted = shared.join("private");
        epix_fs::install_file_write_through(&private_path, &promoted).unwrap();
        verify_private_acl(&open_directory(&promoted).unwrap(), &sid, true).unwrap();
        verify_private_acl(
            &File::open(promoted.join("users.json")).unwrap(),
            &sid,
            false,
        )
        .unwrap();
        drop(stage);
        drop(parent);
    }
}
