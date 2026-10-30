//! The host's end of a child's stdin pipe.

use std::fs::File;
use std::io::{self, Write};
use std::os::windows::io::OwnedHandle;

/// The host's non-blocking end of the child's stdin pipe. A `PIPE_NOWAIT`
/// byte pipe reports a full buffer as a successful zero-byte write; the
/// input queue treats zero bytes as a closed pipe, so this writer turns
/// that into `WouldBlock` and lets the next watchdog tick retry.
pub(crate) struct PipeWriter(File);

impl PipeWriter {
    pub(crate) fn new(handle: OwnedHandle) -> Self {
        PipeWriter(File::from(handle))
    }
}

impl Write for PipeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.0.write(bytes) {
            Ok(0) if !bytes.is_empty() => Err(io::ErrorKind::WouldBlock.into()),
            other => other,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_pipe_reports_would_block_not_closure() {
        use std::os::windows::io::FromRawHandle;
        let suffix = format!("sup-io-test-{}", std::process::id());
        let (server, client) = evx_windows_native::pipe_pair(true, 0, &suffix).unwrap();
        // SAFETY: the server handle is owned here and released into the writer.
        let mut writer =
            PipeWriter::new(unsafe { OwnedHandle::from_raw_handle(server.into_raw()) });
        let chunk = vec![0u8; 16 * 1024];
        let mut accepted = 0;
        let error = loop {
            match writer.write(&chunk) {
                Ok(n) => accepted += n,
                Err(error) => break error,
            }
            assert!(accepted <= 1 << 20, "pipe never filled");
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(accepted > 0);
        drop(client);
        assert!(writer.write(&chunk).is_err());
    }
}
