//! Private named-pipe pairs between the host and a confined child.
use crate::handle::{fail, ok, wide, Handle};
use crate::security::{current_user_sid_text, descriptor};
use std::{io, mem::size_of, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_INBOUND,
        PIPE_ACCESS_OUTBOUND,
    },
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PeekNamedPipe, PIPE_NOWAIT, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    },
};

/// The name of the pipe `pipe_pair` creates for `suffix` and `number`.
pub fn pipe_name(suffix: &str, number: u32) -> String {
    format!(r"\\.\pipe\LOCAL\EpixEVX-{suffix}-{number}")
}

/// A one-way byte pipe named `\\.\pipe\LOCAL\EpixEVX-<suffix>-<number>`,
/// readable only by the owner and SYSTEM. Returns the host's server end
/// (non-blocking) and the child's client end. Neither is inheritable:
/// `launch_suspended` marks the listed client ends inheritable for the
/// duration of its `CreateProcessW` call only, so a concurrent launch
/// elsewhere in the host cannot copy them. `host_writes` selects the
/// direction.
pub fn pipe_pair(host_writes: bool, number: u32, suffix: &str) -> io::Result<(Handle, Handle)> {
    create_pair(host_writes, false, number, suffix)
}

/// As `pipe_pair`, but the host's server end blocks: a reader thread can
/// park in `ReadFile` until the child writes or closes its end.
pub fn blocking_pipe_pair(
    host_writes: bool,
    number: u32,
    suffix: &str,
) -> io::Result<(Handle, Handle)> {
    create_pair(host_writes, true, number, suffix)
}

fn create_pair(
    host_writes: bool,
    blocking: bool,
    number: u32,
    suffix: &str,
) -> io::Result<(Handle, Handle)> {
    let sid = current_user_sid_text()?;
    let sd = descriptor(&format!("D:P(A;;FA;;;SY)(A;;FA;;;{sid})"))?;
    let attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.raw(),
        bInheritHandle: 0,
    };
    let name = wide(pipe_name(suffix, number))?;
    let access = if host_writes {
        PIPE_ACCESS_OUTBOUND
    } else {
        PIPE_ACCESS_INBOUND
    };
    let wait = if blocking { PIPE_WAIT } else { PIPE_NOWAIT };
    // SAFETY: `name` is NUL-terminated and `attrs` references `sd`, which
    // outlives both creation calls.
    let server = Handle::checked(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            access | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | wait | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            &attrs,
        )
    })?;
    let client = Handle::checked(unsafe {
        CreateFileW(
            name.as_ptr(),
            if host_writes {
                GENERIC_READ
            } else {
                GENERIC_WRITE
            },
            0,
            &attrs,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    })?;
    // SAFETY: the server handle is open; a null OVERLAPPED is a synchronous call.
    if unsafe { ConnectNamedPipe(server.raw(), null_mut()) } == 0
        && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED
    {
        return Err(io::Error::last_os_error());
    }
    Ok((server, client))
}

/// Bytes waiting in `pipe`. A broken pipe reports zero.
pub fn available(pipe: HANDLE) -> io::Result<u32> {
    let mut bytes = 0;
    // SAFETY: a null buffer with length zero only queries the byte count.
    if unsafe { PeekNamedPipe(pipe, null_mut(), 0, null_mut(), &mut bytes, null_mut()) } == 0 {
        // SAFETY: reads the thread's last error after the failed call above.
        if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
            return Ok(0);
        }
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}

/// Read up to `bytes.len()` bytes that `available` reported. A zero-byte
/// read means the pipe closed and is an error.
pub fn read_available(pipe: HANDLE, bytes: &mut [u8]) -> io::Result<usize> {
    let mut count = 0;
    // SAFETY: the buffer and its length are passed together.
    unsafe {
        ok(ReadFile(
            pipe,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            &mut count,
            null_mut(),
        ))?;
    }
    if count == 0 {
        return Err(fail("worker pipe closed"));
    }
    Ok(count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;

    #[test]
    fn child_to_host_pipe_carries_bytes() {
        let suffix = format!("native-test-{}", std::process::id());
        let (server, client) = pipe_pair(false, 1, &suffix).unwrap();
        assert_eq!(available(server.raw()).unwrap(), 0);
        let payload = b"EVX042";
        let mut written = 0;
        // SAFETY: the buffer and its length are passed together.
        unsafe {
            ok(WriteFile(
                client.raw(),
                payload.as_ptr(),
                payload.len() as u32,
                &mut written,
                null_mut(),
            ))
            .unwrap();
        }
        assert_eq!(written as usize, payload.len());
        assert_eq!(available(server.raw()).unwrap() as usize, payload.len());
        let mut buffer = [0u8; 16];
        let count = read_available(server.raw(), &mut buffer[..payload.len()]).unwrap();
        assert_eq!(&buffer[..count], payload);
        drop(client);
        assert_eq!(available(server.raw()).unwrap(), 0);
        assert!(read_available(server.raw(), &mut buffer).is_err());
    }

    #[test]
    fn blocking_pair_reads_to_eof_through_a_file() {
        use std::io::Read;
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        let suffix = format!("native-block-{}", std::process::id());
        let (server, client) = blocking_pipe_pair(false, 1, &suffix).unwrap();
        // A connected single-instance pipe cannot be opened again by name.
        let name = wide(pipe_name(&suffix, 1)).unwrap();
        // SAFETY: `name` is NUL-terminated; no attributes or template.
        let again = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        assert!(Handle::checked(again).is_err());
        // SAFETY: the client handle is owned here and released into the File.
        let mut client =
            std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(client.into_raw()) });
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            client.write_all(b"EVX").unwrap();
            drop(client);
        });
        // SAFETY: the server handle is owned here and released into the File.
        let mut file =
            std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(server.into_raw()) });
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"EVX");
        writer.join().unwrap();
    }

    #[test]
    fn both_ends_are_created_non_inheritable() {
        let suffix = format!("native-inherit-{}", std::process::id());
        let (server, client) = pipe_pair(false, 1, &suffix).unwrap();
        assert!(!crate::is_inheritable(server.raw()).unwrap());
        assert!(!crate::is_inheritable(client.raw()).unwrap());
    }

    #[test]
    fn second_instance_of_a_pipe_is_refused() {
        let suffix = format!("native-dup-{}", std::process::id());
        let _first = pipe_pair(true, 0, &suffix).unwrap();
        assert!(pipe_pair(true, 0, &suffix).is_err());
    }
}
