//! Kernel boot identity, never caller input, wall time, PID or an environment value.

use evx_api::Denied;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BootSession([u8; 16]);

fn unavailable() -> Denied {
    Denied::new("kernel boot identity unavailable; process recovery disabled")
}

impl BootSession {
    pub(crate) fn current() -> Result<Self, Denied> {
        #[cfg(target_os = "macos")]
        {
            let mut bytes = [0u8; 37];
            let mut len = bytes.len();
            // SAFETY: fixed NUL-terminated name, writable bounded output, no new value.
            let result = unsafe {
                libc::sysctlbyname(
                    c"kern.bootsessionuuid".as_ptr(),
                    bytes.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if result != 0 || len != bytes.len() || bytes[36] != 0 {
                return Err(unavailable());
            }
            Self::parse(&bytes[..36])
        }
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open("/proc/sys/kernel/random/boot_id")
                .map_err(|_| unavailable())?;
            let mut bytes = [0u8; 38];
            let len = file.read(&mut bytes).map_err(|_| unavailable())?;
            if len != 37 || bytes[36] != b'\n' {
                return Err(unavailable());
            }
            Self::parse(&bytes[..36])
        }
        #[cfg(target_os = "windows")]
        {
            windows::current()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err(unavailable())
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", test))]
    fn parse(bytes: &[u8]) -> Result<Self, Denied> {
        if bytes.len() != 36 {
            return Err(unavailable());
        }
        let mut hex_bytes = [0u8; 32];
        let mut offset = 0;
        for (i, byte) in bytes.iter().copied().enumerate() {
            if [8, 13, 18, 23].contains(&i) {
                if byte != b'-' {
                    return Err(unavailable());
                }
            } else {
                if !byte.is_ascii_hexdigit() {
                    return Err(unavailable());
                }
                hex_bytes[offset] = byte;
                offset += 1;
            }
        }
        let mut value = [0u8; 16];
        hex::decode_to_slice(hex_bytes, &mut value).map_err(|_| unavailable())?;
        let session = Self(value);
        session.validate()?;
        Ok(session)
    }

    pub(crate) fn validate(&self) -> Result<(), Denied> {
        if self.0 == [0; 16] {
            Err(unavailable())
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(value: u8) -> Self {
        Self([value; 16])
    }
}

/// Windows has no documented boot UUID. The identity is a digest of the
/// machine GUID and the kernel's boot counter, which it increments on every
/// boot. Both are machine-wide registry values under `HKLM` that no caller,
/// page or environment variable can influence, and neither depends on wall
/// time.
#[cfg(target_os = "windows")]
mod windows {
    use super::{unavailable, BootSession};
    use evx_api::Denied;
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};

    const MACHINE_KEY: &str = r"SOFTWARE\Microsoft\Cryptography";
    const MACHINE_VALUE: &str = "MachineGuid";
    const BOOT_KEY: &str =
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";
    const BOOT_VALUE: &str = "BootId";

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn machine_guid() -> Result<String, Denied> {
        let key = wide(MACHINE_KEY);
        let value = wide(MACHINE_VALUE);
        let mut buffer = [0u16; 128];
        let mut bytes = (buffer.len() * 2) as u32;
        // SAFETY: NUL-terminated names and a bounded output buffer.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut bytes,
            )
        };
        if status != 0 || bytes < 2 {
            return Err(unavailable());
        }
        let units = &buffer[..(bytes as usize / 2).saturating_sub(1)];
        let text = String::from_utf16(units).map_err(|_| unavailable())?;
        if text.len() != 36 {
            return Err(unavailable());
        }
        Ok(text)
    }

    fn boot_counter() -> Result<u32, Denied> {
        let key = wide(BOOT_KEY);
        let value = wide(BOOT_VALUE);
        let mut data = 0u32;
        let mut bytes = 4u32;
        // SAFETY: NUL-terminated names and a 4-byte output for a DWORD.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut data as *mut u32).cast(),
                &mut bytes,
            )
        };
        if status != 0 || bytes != 4 || data == 0 {
            return Err(unavailable());
        }
        Ok(data)
    }

    pub(super) fn current() -> Result<BootSession, Denied> {
        let mut hasher = Sha256::new();
        hasher.update(machine_guid()?.as_bytes());
        hasher.update(boot_counter()?.to_le_bytes());
        let digest = hasher.finalize();
        let mut value = [0u8; 16];
        value.copy_from_slice(&digest[..16]);
        let session = BootSession(value);
        session.validate()?;
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_kernel_identity_is_stable() {
        assert_eq!(
            BootSession::current().unwrap(),
            BootSession::current().unwrap()
        );
    }

    #[test]
    fn only_exact_nonzero_uuid_is_accepted() {
        assert!(BootSession::parse(b"12345678-1234-1234-1234-123456789abc").is_ok());
        assert!(BootSession::parse(b"00000000-0000-0000-0000-000000000000").is_err());
        assert!(BootSession::parse(b"1234567811234-1234-1234-123456789abc").is_err());
        assert!(BootSession::parse(b"12345678-1234-1234-1234-123456789abz").is_err());
        assert!(BootSession::parse(b"12345678-1234-1234-1234-123456789abc\n").is_err());
    }
}
