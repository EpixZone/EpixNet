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
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(unavailable())
        }
    }

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
