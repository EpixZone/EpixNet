//! Error helpers, UTF-16 conversion and RAII wrappers for kernel objects,
//! LocalAlloc memory and dynamically loaded system libraries.
use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FreeLibrary, LocalFree, HANDLE, HMODULE, INVALID_HANDLE_VALUE},
    System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32},
};

/// An `io::Error` of kind `Other` carrying a fixed message.
pub fn fail(message: &str) -> io::Error {
    io::Error::other(message)
}

/// Map a Win32 BOOL result to `io::Result`, reading the last OS error on zero.
pub fn ok(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// NUL-terminated UTF-16 for a Win32 call. Refuses embedded NUL.
pub fn wide(value: impl AsRef<OsStr>) -> io::Result<Vec<u16>> {
    let mut result: Vec<_> = value.as_ref().encode_wide().collect();
    if result.contains(&0) {
        return Err(fail("NUL in trusted fixture path"));
    }
    result.push(0);
    Ok(result)
}

/// An owned kernel handle, closed on drop.
pub struct Handle(HANDLE);
impl Handle {
    /// Take ownership of `raw`, rejecting null and `INVALID_HANDLE_VALUE`
    /// with the last OS error.
    pub fn checked(raw: HANDLE) -> io::Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(raw))
        }
    }
    /// The raw handle value; ownership stays with this object.
    pub fn raw(&self) -> HANDLE {
        self.0
    }
    /// Give up ownership without closing the handle.
    pub fn into_raw(self) -> HANDLE {
        let raw = self.0;
        std::mem::forget(self);
        raw
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this object and closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Memory returned by a Win32 call that must be released with `LocalFree`.
pub struct Local(*mut std::ffi::c_void);
impl Local {
    pub(crate) fn new(raw: *mut std::ffi::c_void) -> Self {
        Self(raw)
    }
    /// The raw allocation; ownership stays with this object.
    pub fn raw(&self) -> *mut std::ffi::c_void {
        self.0
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: the allocation came from a Win32 API that documents LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}

/// A system DLL loaded on demand from System32. Used for userenv, shell32
/// and ole32 so that confined images never import them statically.
pub struct SystemLibrary(HMODULE);
impl SystemLibrary {
    /// Load `name` from the System32 search path only.
    pub fn open(name: &str) -> io::Result<Self> {
        let name = wide(name)?;
        // SAFETY: `name` is NUL-terminated and the search is restricted to System32.
        let module =
            unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(module))
    }
    /// Resolve an export. The caller transmutes it to the documented signature
    /// and must keep this library alive while the pointer is used.
    pub fn symbol(
        &self,
        name: &std::ffi::CStr,
    ) -> io::Result<unsafe extern "system" fn() -> isize> {
        // SAFETY: the module is loaded and `name` is a NUL-terminated C string.
        unsafe { GetProcAddress(self.0, name.as_ptr().cast()) }.ok_or_else(io::Error::last_os_error)
    }
}
impl Drop for SystemLibrary {
    fn drop(&mut self) {
        // SAFETY: balances the LoadLibraryExW in `open`.
        unsafe { FreeLibrary(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_refuses_embedded_nul() {
        assert!(wide("a\0b").is_err());
        assert_eq!(wide("ab").unwrap(), vec![b'a' as u16, b'b' as u16, 0]);
    }

    #[test]
    fn checked_rejects_null_and_invalid() {
        assert!(Handle::checked(null_mut()).is_err());
        assert!(Handle::checked(INVALID_HANDLE_VALUE).is_err());
    }

    #[test]
    fn system_library_resolves_exports() {
        let shell = SystemLibrary::open("shell32.dll").unwrap();
        assert!(shell.symbol(c"SHGetKnownFolderPath").is_ok());
        assert!(shell.symbol(c"NoSuchExport").is_err());
    }
}
