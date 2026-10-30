//! Tokens, SIDs, SDDL descriptors, protected DACLs and LPAC token validation.
use crate::handle::{fail, ok, wide, Handle, Local};
use std::{
    io,
    mem::{size_of, zeroed},
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SetSecurityInfo, SE_FILE_OBJECT,
    },
    Security::{
        AccessCheck, DuplicateToken, EqualSid, GetSecurityDescriptorDacl, GetTokenInformation,
        SecurityIdentification, TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
        TokenUser, ACL, DACL_SECURITY_INFORMATION, GENERIC_MAPPING, PRIVILEGE_SET,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_APPCONTAINER_INFORMATION, TOKEN_DUPLICATE,
        TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Open the primary token of `process` for query and duplication.
pub fn open_process_token(process: HANDLE) -> io::Result<Handle> {
    let mut raw = null_mut();
    // SAFETY: `raw` receives the token handle on success.
    unsafe {
        ok(OpenProcessToken(
            process,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut raw,
        ))?;
    }
    Handle::checked(raw)
}

/// Query one token information class into a pointer-aligned buffer. The
/// caller casts the buffer start to the class's structure.
pub fn token_info(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut bytes = 0;
    // SAFETY: a null buffer with length zero asks for the required size.
    unsafe {
        GetTokenInformation(token.raw(), class, null_mut(), 0, &mut bytes);
    }
    if bytes == 0 || bytes > 65536 {
        return Err(fail("invalid token metadata size"));
    }
    let mut buffer = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    // SAFETY: the buffer holds at least `bytes` bytes and is pointer aligned.
    unsafe {
        ok(GetTokenInformation(
            token.raw(),
            class,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        ))?;
    }
    Ok(buffer)
}

/// The SDDL text form of a SID, such as `S-1-5-21-...`.
pub fn sid_text(sid: PSID) -> io::Result<String> {
    let mut raw = null_mut();
    // SAFETY: `raw` receives a LocalAlloc string owned by `allocated` below.
    unsafe {
        ok(ConvertSidToStringSidW(sid, &mut raw))?;
    }
    let allocated = Local::new(raw.cast());
    let mut len = 0;
    // SAFETY: the string is NUL-terminated and stays allocated until
    // `allocated` drops after the copy.
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

/// The SID text of the current process token's user.
pub fn current_user_sid_text() -> io::Result<String> {
    // SAFETY: the pseudo handle needs no closing; OpenProcessToken duplicates it.
    let token = open_process_token(unsafe { GetCurrentProcess() })?;
    let user = token_info(&token, TokenUser)?;
    // SAFETY: `token_info` returned a TokenUser buffer whose SID pointer
    // targets the same allocation, which lives through the conversion.
    sid_text(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

/// A self-relative security descriptor parsed from SDDL text.
pub fn descriptor(sddl: &str) -> io::Result<Local> {
    let text = wide(sddl)?;
    let mut raw = null_mut();
    // SAFETY: `text` is NUL-terminated; `raw` receives a LocalAlloc descriptor.
    unsafe {
        ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut raw,
            null_mut(),
        ))?;
    }
    Ok(Local::new(raw))
}

fn dacl(sd: &Local) -> io::Result<*mut ACL> {
    let mut dacl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: `sd` is a valid descriptor; the DACL pointer targets inside it.
    unsafe {
        ok(GetSecurityDescriptorDacl(
            sd.raw(),
            &mut present,
            &mut dacl,
            &mut defaulted,
        ))?;
    }
    if present == 0 || dacl.is_null() {
        return Err(fail("missing fixture ACL"));
    }
    Ok(dacl)
}

fn status_result(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

/// Replace the DACL of a file or directory with the one in `sddl` and mark
/// it protected, so nothing is inherited from the parent.
pub fn protect(path: &Path, sddl: &str) -> io::Result<()> {
    let sd = descriptor(sddl)?;
    let dacl = dacl(&sd)?;
    let path = wide(path)?;
    // SAFETY: `path` is NUL-terminated and `dacl` lives inside `sd`.
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
    status_result(status)
}

/// `protect` for a file or directory the caller holds open. The handle needs
/// `WRITE_DAC` access.
pub fn protect_handle(handle: HANDLE, sddl: &str) -> io::Result<()> {
    let sd = descriptor(sddl)?;
    let dacl = dacl(&sd)?;
    // SAFETY: `handle` is open and `dacl` lives inside `sd`.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    status_result(status)
}

/// Replace the DACL of an open file or directory with one that holds only
/// what its parent passes down: an empty unprotected DACL, which the
/// system fills from the parent's inheritable entries. This is what
/// `icacls /reset` does. The handle needs `WRITE_DAC` access.
pub fn inherit_dacl(handle: HANDLE) -> io::Result<()> {
    let sd = descriptor("D:")?;
    let dacl = dacl(&sd)?;
    // SAFETY: `handle` is open and `dacl` lives inside `sd`.
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    status_result(status)
}

/// The access mask the kernel granted when `handle` was opened or
/// duplicated: what the holder can do with it regardless of what the
/// object's DACL would grant the holder's token now.
pub fn granted_access(handle: HANDLE) -> io::Result<u32> {
    // SAFETY: plain data the API fills.
    let mut info: PUBLIC_OBJECT_BASIC_INFORMATION = unsafe { zeroed() };
    let mut returned = 0;
    // SAFETY: the pointer and length describe `info`; the kernel validates
    // the handle and writes only inside the buffer.
    let status = unsafe {
        NtQueryObject(
            handle,
            ObjectBasicInformation,
            (&mut info as *mut PUBLIC_OBJECT_BASIC_INFORMATION).cast(),
            size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32,
            &mut returned,
        )
    };
    if status < 0 {
        return Err(fail(&format!(
            "object query failed: 0x{:08x}",
            status as u32
        )));
    }
    Ok(info.GrantedAccess)
}

/// Whether an impersonation token passes an access check against an object
/// that grants read to Everyone and to `package`. Everyone satisfies the
/// ordinary user check, so the second grant tests the AppContainer package
/// restriction independently of host file ACLs.
pub fn grants_read(token: &Handle, package: &str) -> io::Result<bool> {
    let sd = descriptor(&format!("O:SYG:SYD:(A;;0x1;;;WD)(A;;0x1;;;{package})"))?;
    let mapping = GENERIC_MAPPING {
        GenericRead: 1,
        GenericWrite: 1,
        GenericExecute: 1,
        GenericAll: 1,
    };
    // SAFETY: PRIVILEGE_SET is plain data for the API to fill.
    let mut privileges: PRIVILEGE_SET = unsafe { zeroed() };
    let mut bytes = size_of::<PRIVILEGE_SET>() as u32;
    let mut granted = 0;
    let mut allowed = 0;
    // SAFETY: every out-parameter targets a live local; `sd` outlives the call.
    unsafe {
        ok(AccessCheck(
            sd.raw(),
            token.raw(),
            1,
            &mapping,
            &mut privileges,
            &mut bytes,
            &mut granted,
            &mut allowed,
        ))?;
    }
    Ok(allowed != 0 && granted & 1 != 0)
}

/// Require that `token` is a less-privileged AppContainer for `package`.
/// Class 46 (TokenIsLessPrivilegedAppContainer) is not queryable through
/// GetTokenInformation on current Windows, so this checks LPAC's defining
/// access restriction: the package's own grant works, ALL_APPLICATION_PACKAGES
/// does not. The positive control prevents an unrelated denial from passing.
pub fn validate_lpac(token: &Handle, package: PSID) -> io::Result<()> {
    let mut raw = null_mut();
    // SAFETY: `raw` receives the impersonation token on success.
    unsafe {
        ok(DuplicateToken(
            token.raw(),
            SecurityIdentification,
            &mut raw,
        ))?;
    }
    let impersonation = Handle::checked(raw)?;
    if !grants_read(&impersonation, &sid_text(package)?)? {
        return Err(fail(
            "AppContainer token failed its own package access check",
        ));
    }
    if grants_read(&impersonation, "S-1-15-2-1")? {
        return Err(fail(
            "child token accepts ALL_APPLICATION_PACKAGES; LPAC required",
        ));
    }
    Ok(())
}

/// Whether `process` runs inside any AppContainer.
pub fn is_app_container(process: HANDLE) -> io::Result<bool> {
    let token = open_process_token(process)?;
    let buffer = token_info(&token, TokenIsAppContainer)?;
    // SAFETY: TokenIsAppContainer returns a DWORD at the buffer start.
    Ok(unsafe { *buffer.as_ptr().cast::<u32>() } != 0)
}

/// Require that `process` runs as a zero-capability LPAC, optionally under
/// the exact AppContainer SID `expected`.
pub fn validate_token(process: HANDLE, expected: Option<PSID>) -> io::Result<()> {
    if !is_app_container(process)? {
        return Err(fail("child token is not an AppContainer"));
    }
    let token = open_process_token(process)?;
    let caps = token_info(&token, TokenCapabilities)?;
    // SAFETY: TokenCapabilities returns a TOKEN_GROUPS at the buffer start.
    if unsafe { (*caps.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount } != 0 {
        return Err(fail("unexpected AppContainer capabilities"));
    }
    let sid = token_info(&token, TokenAppContainerSid)?;
    // SAFETY: TokenAppContainerSid returns a TOKEN_APPCONTAINER_INFORMATION
    // whose SID pointer targets the same buffer, which lives through the checks.
    let actual =
        unsafe { (*sid.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer };
    if actual.is_null() {
        return Err(fail("missing AppContainer identity"));
    }
    if let Some(expected) = expected {
        // SAFETY: both SIDs are valid for the comparison.
        if unsafe { EqualSid(actual, expected) } == 0 {
            return Err(fail("wrong AppContainer identity"));
        }
    }
    validate_lpac(&token, actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;

    #[test]
    fn current_user_sid_is_a_user_sid() {
        let sid = current_user_sid_text().unwrap();
        assert!(sid.starts_with("S-1-5-"), "{sid}");
    }

    #[test]
    fn granted_access_reports_the_mask_a_handle_was_opened_with() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_READ_ATTRIBUTES};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("granted");
        std::fs::write(&path, b"x").unwrap();
        let file = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | DELETE)
            .open(&path)
            .unwrap();
        let granted = granted_access(file.as_raw_handle()).unwrap();
        assert_eq!(granted & DELETE, DELETE);
        assert_eq!(granted & FILE_READ_ATTRIBUTES, FILE_READ_ATTRIBUTES);
        drop(file);
        let read = std::fs::File::open(&path).unwrap();
        assert_eq!(granted_access(read.as_raw_handle()).unwrap() & DELETE, 0);
        drop(read);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn descriptor_parses_and_rejects_sddl() {
        assert!(descriptor("D:P(A;;FA;;;SY)").is_ok());
        assert!(descriptor("not sddl").is_err());
    }

    #[test]
    fn host_process_is_not_an_app_container() {
        // SAFETY: the pseudo handle for the current process is always valid.
        assert!(validate_token(unsafe { GetCurrentProcess() }, None).is_err());
        // SAFETY: as above.
        assert!(!is_app_container(unsafe { GetCurrentProcess() }).unwrap());
    }

    #[test]
    fn protect_handle_applies_a_protected_dacl() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, READ_CONTROL, WRITE_DAC,
        };
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("protect");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("marker"), b"x").unwrap();
        let owner = current_user_sid_text().unwrap();
        let open = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&directory)
            .unwrap();
        // SYSTEM only: the owner keeps WRITE_DAC implicitly but loses listing.
        protect_handle(open.as_raw_handle(), "D:P(A;OICI;FA;;;SY)").unwrap();
        assert_eq!(
            std::fs::read_dir(&directory)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::PermissionDenied)
        );
        protect(
            &directory,
            &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{owner})"),
        )
        .unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        // A child reset to inheritance carries exactly the parent's entries.
        let marker_path = directory.join("marker");
        protect(&marker_path, &format!("D:P(A;;FA;;;{owner})")).unwrap();
        let listing = |path: &Path| {
            let output = std::process::Command::new("icacls")
                .arg(path)
                .output()
                .unwrap();
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        assert!(!listing(&marker_path).contains("SYSTEM:(I)(F)"));
        let marker = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | WRITE_DAC)
            .open(&marker_path)
            .unwrap();
        inherit_dacl(marker.as_raw_handle()).unwrap();
        drop(marker);
        assert!(
            listing(&marker_path).contains("SYSTEM:(I)(F)"),
            "{}",
            listing(&marker_path)
        );
        assert_eq!(std::fs::read(&marker_path).unwrap(), b"x");
        drop(open);
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
