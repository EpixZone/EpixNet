//! The running kernel's version, from ntdll rather than the manifest-filtered
//! Win32 query.
use std::{
    io,
    mem::{size_of, zeroed},
};
use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(info: *mut OSVERSIONINFOW) -> i32;
}

/// Major, minor and build of the running Windows kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OsVersion {
    /// Major version, 10 for Windows 10 and 11.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Build number, such as 15063 for the 1703 release.
    pub build: u32,
}

/// The kernel version as `RtlGetVersion` reports it. Unlike `GetVersionExW`
/// this is not filtered by the application manifest.
pub fn os_version() -> io::Result<OsVersion> {
    // SAFETY: the structure is plain data; its size field is set before the call.
    let mut info: OSVERSIONINFOW = unsafe { zeroed() };
    info.dwOSVersionInfoSize = size_of::<OSVERSIONINFOW>() as u32;
    // SAFETY: `info` is a live, correctly sized version structure.
    if unsafe { RtlGetVersion(&mut info) } < 0 {
        return Err(io::Error::other("kernel version unavailable"));
    }
    Ok(OsVersion {
        major: info.dwMajorVersion,
        minor: info.dwMinorVersion,
        build: info.dwBuildNumber,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_host_is_windows_10_or_newer() {
        let version = os_version().unwrap();
        assert!(version.major >= 10, "{version:?}");
        assert!(version.build >= 15063, "{version:?}");
    }
}
