//! Typed reads of machine-wide registry values.
use crate::handle::{fail, wide};
use std::{io, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::ERROR_SUCCESS,
    System::Registry::{RegGetValueW, HKEY, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_SZ},
};

fn read_value(key: HKEY, subkey: &str, value: &str, flags: u32) -> io::Result<Vec<u8>> {
    let subkey = wide(subkey)?;
    let value = wide(value)?;
    let mut bytes = 0u32;
    // SAFETY: both names are NUL-terminated; a null buffer asks for the size.
    let status = unsafe {
        RegGetValueW(
            key,
            subkey.as_ptr(),
            value.as_ptr(),
            flags,
            null_mut(),
            null_mut(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if bytes == 0 || bytes > 65536 {
        return Err(fail("invalid registry value size"));
    }
    let mut buffer = vec![0u8; bytes as usize];
    // SAFETY: the buffer length is passed with the buffer.
    let status = unsafe {
        RegGetValueW(
            key,
            subkey.as_ptr(),
            value.as_ptr(),
            flags,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    buffer.truncate(bytes as usize);
    Ok(buffer)
}

/// Read a `REG_DWORD` value. Any other type is an error.
pub fn registry_dword(key: HKEY, subkey: &str, value: &str) -> io::Result<u32> {
    let bytes = read_value(key, subkey, value, RRF_RT_REG_DWORD)?;
    let bytes: [u8; 4] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| fail("registry DWORD has an unexpected size"))?;
    Ok(u32::from_ne_bytes(bytes))
}

/// Read a `REG_SZ` value without environment expansion. Any other type,
/// including `REG_EXPAND_SZ`, is an error.
pub fn registry_string(key: HKEY, subkey: &str, value: &str) -> io::Result<String> {
    let bytes = read_value(key, subkey, value, RRF_RT_REG_SZ | RRF_NOEXPAND)?;
    let (pairs, _odd_tail) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|pair| u16::from_ne_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16(&units).map_err(|_| fail("registry string is not UTF-16"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;

    #[test]
    fn boot_identity_sources_are_readable() {
        let machine = registry_string(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            "MachineGuid",
        )
        .unwrap();
        assert!(!machine.is_empty());
        let boot = registry_dword(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            "BootId",
        )
        .unwrap();
        assert_ne!(boot, 0);
    }

    #[test]
    fn wrong_type_and_missing_values_fail() {
        assert!(registry_dword(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            "MachineGuid"
        )
        .is_err());
        assert!(registry_string(
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            "NoSuchEvxValue"
        )
        .is_err());
    }
}
