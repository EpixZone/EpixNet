//! The minimal environment a confined child needs, derived from the OS and
//! never from the caller's environment variables.
use crate::handle::{fail, SystemLibrary};
use std::{io, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::HANDLE, System::SystemInformation::GetWindowsDirectoryW,
    UI::Shell::FOLDERID_LocalAppData,
};

type KnownFolderPath =
    unsafe extern "system" fn(*const windows_sys::core::GUID, u32, HANDLE, *mut *mut u16) -> i32;
type FreePath = unsafe extern "system" fn(*const std::ffi::c_void);

/// The current user's registered local application data folder as UTF-16
/// without a terminator. Resolved through shell32 and ole32 loaded on demand,
/// without trusting or inheriting caller-controlled environment variables.
pub fn local_app_data() -> io::Result<Vec<u16>> {
    // Resolve host-only shell/COM entry points on demand. Static imports would
    // also initialize these DLLs in the confined child before its entrypoint.
    let shell = SystemLibrary::open("shell32.dll")?;
    let com = SystemLibrary::open("ole32.dll")?;
    // SAFETY: fixed system DLL exports and their documented Win32 signatures;
    // both libraries remain loaded through the call and allocation release.
    let known_folder: KnownFolderPath =
        unsafe { std::mem::transmute(shell.symbol(c"SHGetKnownFolderPath")?) };
    let free_path: FreePath = unsafe { std::mem::transmute(com.symbol(c"CoTaskMemFree")?) };
    let mut path = null_mut();
    let status = unsafe { known_folder(&FOLDERID_LocalAppData, 0, null_mut(), &mut path) };
    let result = if status < 0 || path.is_null() {
        Err(fail(&format!(
            "local app data lookup failed: 0x{:08x}",
            status as u32
        )))
    } else {
        copy_path(path)
    };
    // The API requires freeing this allocation even on a failed lookup.
    unsafe { free_path(path.cast()) };
    result
}

fn copy_path(path: *const u16) -> io::Result<Vec<u16>> {
    let mut len = 0;
    // SAFETY: `path` is a NUL-terminated string owned by the shell allocation
    // that the caller releases after this copy; the scan is bounded.
    unsafe {
        while len < 32768 && *path.add(len) != 0 {
            len += 1;
        }
        if len == 0 || len == 32768 {
            Err(fail("invalid local app data path"))
        } else {
            Ok(std::slice::from_raw_parts(path, len).to_vec())
        }
    }
}

/// The environment block for a confined worker: `LOCALAPPDATA` and
/// `SystemRoot` only, double NUL terminated, in the case-insensitive
/// environment sort order. AppContainer startup resolves and redirects
/// LOCALAPPDATA for its profile; SystemRoot is required for activation contexts.
pub fn worker_environment() -> io::Result<Vec<u16>> {
    let mut windows = vec![0u16; 32768];
    // SAFETY: the buffer and its length are passed together.
    let size = unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) } as usize;
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    if size >= windows.len() {
        return Err(fail("Windows directory exceeds environment limit"));
    }
    let mut environment: Vec<u16> = "LOCALAPPDATA=".encode_utf16().collect();
    environment.extend(local_app_data()?);
    environment.push(0);
    environment.extend("SystemRoot=".encode_utf16());
    environment.extend_from_slice(&windows[..size]);
    environment.extend([0, 0]);
    Ok(environment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_environment_holds_only_two_variables() {
        let block = worker_environment().unwrap();
        let text = String::from_utf16(&block).unwrap();
        let entries: Vec<_> = text.split('\0').filter(|entry| !entry.is_empty()).collect();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].starts_with("LOCALAPPDATA="));
        assert!(entries[1].starts_with("SystemRoot="));
        assert!(block.ends_with(&[0, 0]));
    }
}
