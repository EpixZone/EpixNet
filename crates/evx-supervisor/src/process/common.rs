//! The parts of child management that do not touch the operating system:
//! roles, reader events, the process-wide admission latch, the bounded
//! input queue and the framed output readers.

use std::io::{Read, Write};
use std::sync::mpsc::SyncSender;
use std::sync::Mutex;

use evx_api::{Denied, MAX_ARTIFACT_FRAME, MAX_FRAME};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Guest,
    File,
    Compiler,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::Guest => "guest",
            Role::File => "file",
            Role::Compiler => "compiler",
        }
    }
}

#[derive(Debug)]
pub enum Event {
    /// One complete frame body from the child's stdout.
    Frame(Role, u64, Vec<u8>),
    /// A chunk of stderr.
    Stderr(Role, u64, Vec<u8>),
    /// A stream closed. `protocol_error` is set when it closed mid-frame or
    /// after an oversized length prefix.
    Closed(Role, u64, Stream, Option<&'static str>),
}

impl Event {
    pub fn origin(&self) -> (Role, u64) {
        match self {
            Self::Frame(role, id, _) | Self::Stderr(role, id, _) | Self::Closed(role, id, _, _) => {
                (*role, *id)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Child termination or durable cleanup was not confirmed. Quarantine its slot.
#[derive(Debug, thiserror::Error)]
#[error("child {pid} cleanup unconfirmed; quarantine its slot")]
pub struct CleanupTimeout {
    pub pid: i32,
}

#[derive(Debug, thiserror::Error)]
#[error("process measurement unavailable")]
pub struct ObservationUnavailable;

pub(crate) const STDERR_RETAINED: usize = 4096;
pub(crate) const OUTPUT_QUOTA: usize = 256 * 1024;
pub(crate) const MAX_FRAMES: u32 = 130;
pub(crate) const EVENT_CAPACITY: usize = 8;

pub(crate) static CHILD_ADMISSION_STOPPED: Mutex<bool> = Mutex::new(false);

pub(crate) fn quarantine_error() -> Denied {
    Denied::Quarantined(
        "child admission quarantined; confirm prior children stopped before restarting the host"
            .into(),
    )
}

pub fn child_admission_status() -> Result<(), Denied> {
    let stopped = CHILD_ADMISSION_STOPPED
        .lock()
        .map_err(|_| quarantine_error())?;
    if *stopped {
        Err(quarantine_error())
    } else {
        Ok(())
    }
}

/// Irreversible within this host process. No guest or operator API clears it.
pub(crate) fn quarantine_child_admission() {
    *CHILD_ADMISSION_STOPPED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
}

/// Keep at most the first `STDERR_RETAINED` bytes of a child's diagnostics.
pub(crate) fn record_diagnostics(diagnostics: &mut Vec<u8>, chunk: &[u8]) {
    let room = STDERR_RETAINED.saturating_sub(diagnostics.len());
    diagnostics.extend_from_slice(&chunk[..chunk.len().min(room)]);
}

/// The bounded, non-blocking input queue to a child: one frame at a time,
/// flushed only while the pipe is writable. A second frame cannot overtake
/// an incomplete frame or grow the queue. The writer must report a full
/// pipe as `WouldBlock`, never as a zero-byte write (which means closed):
/// a non-blocking Unix pipe does; the Windows pipe writer translates.
#[derive(Default)]
pub(crate) struct Input {
    stdin: Option<Box<dyn Write + Send>>,
    pending: Vec<u8>,
    offset: usize,
    started: bool,
}

impl Input {
    pub(crate) fn new<W: Write + Send + 'static>(stdin: Option<W>) -> Self {
        Input {
            stdin: stdin.map(|writer| Box::new(writer) as Box<dyn Write + Send>),
            pending: Vec::new(),
            offset: 0,
            started: false,
        }
    }

    /// Whether any frame has been queued yet.
    #[cfg(test)]
    pub(crate) fn started(&self) -> bool {
        self.started
    }

    /// Close the child's input.
    pub(crate) fn close(&mut self) {
        self.stdin.take();
    }

    /// Queue raw bytes ahead of the first frame: the Windows file helper's
    /// workspace handle preamble. Not a frame, so it does not count as the
    /// first input and does not pass through the frame limit.
    #[cfg(windows)]
    pub(crate) fn preload(&mut self, bytes: &[u8]) -> Result<(), Denied> {
        if self.started || !self.pending.is_empty() {
            return Err(Denied::new("worker input preamble after frames"));
        }
        self.pending.extend_from_slice(bytes);
        self.flush()
    }

    /// Queue one bounded frame, flushing only while the pipe is writable.
    pub(crate) fn send(&mut self, encoded: &[u8], limit: usize) -> Result<(), Denied> {
        if encoded.len() > limit + 4 {
            return Err(Denied::new("outgoing frame limit"));
        }
        self.flush()?;
        if !self.pending.is_empty() {
            return Err(Denied::new("worker input backpressure"));
        }
        self.started = true;
        self.pending.extend_from_slice(encoded);
        self.flush()
    }

    /// Only a guest's first input may carry the larger serialized artifact.
    pub(crate) fn send_artifact_init(&mut self, role: Role, encoded: &[u8]) -> Result<(), Denied> {
        if role != Role::Guest || self.started {
            return Err(Denied::new("unexpected artifact initialization"));
        }
        self.send(encoded, MAX_ARTIFACT_FRAME)
    }

    /// Write as much of the queued frame as the pipe accepts right now.
    pub(crate) fn flush(&mut self) -> Result<(), Denied> {
        while self.offset < self.pending.len() {
            let stdin = self
                .stdin
                .as_mut()
                .ok_or_else(|| Denied::new("worker input closed"))?;
            match stdin.write(&self.pending[self.offset..]) {
                Ok(0) => return Err(Denied::new("worker input closed")),
                Ok(n) => self.offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(Denied::new("worker input closed")),
            }
        }
        self.pending.clear();
        self.offset = 0;
        Ok(())
    }
}

/// The ordinary frame limit for a role's output.
pub(crate) fn frame_limit(role: Role) -> usize {
    if role == Role::Compiler {
        MAX_ARTIFACT_FRAME
    } else {
        MAX_FRAME
    }
}

pub(crate) fn read_frames(role: Role, id: u64, mut stdout: impl Read, tx: SyncSender<Event>) {
    let frame_limit = frame_limit(role);
    let mut bytes = 0usize;
    let mut frames = 0u32;
    loop {
        let mut len = [0u8; 4];
        // Distinguish a clean boundary EOF from a truncated length prefix.
        match stdout.read(&mut len[..1]) {
            Ok(0) => {
                let _ = tx.send(Event::Closed(role, id, Stream::Stdout, None));
                return;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = tx.send(Event::Closed(
                    role,
                    id,
                    Stream::Stdout,
                    Some("worker output read failed"),
                ));
                return;
            }
        }
        if stdout.read_exact(&mut len[1..]).is_err() {
            let _ = tx.send(Event::Closed(
                role,
                id,
                Stream::Stdout,
                Some("truncated worker frame"),
            ));
            return;
        }
        let len = u32::from_be_bytes(len) as usize;
        frames += 1;
        if len == 0
            || len > frame_limit
            || frames > MAX_FRAMES
            || len > OUTPUT_QUOTA.saturating_sub(bytes)
        {
            let _ = tx.send(Event::Closed(
                role,
                id,
                Stream::Stdout,
                Some("worker frame quota"),
            ));
            return;
        }
        bytes += len;
        let mut body = vec![0u8; len];
        if stdout.read_exact(&mut body).is_err() {
            let _ = tx.send(Event::Closed(
                role,
                id,
                Stream::Stdout,
                Some("truncated worker frame"),
            ));
            return;
        }
        if tx.send(Event::Frame(role, id, body)).is_err() {
            return;
        }
    }
}

pub(crate) fn read_stderr(role: Role, id: u64, mut stderr: impl Read, tx: SyncSender<Event>) {
    let mut buffer = [0u8; 4096];
    let mut bytes = 0usize;
    loop {
        match stderr.read(&mut buffer) {
            Ok(0) => {
                let _ = tx.send(Event::Closed(role, id, Stream::Stderr, None));
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = tx.send(Event::Closed(
                    role,
                    id,
                    Stream::Stderr,
                    Some("worker diagnostics read failed"),
                ));
                return;
            }
            Ok(n) => {
                bytes += n;
                if bytes > OUTPUT_QUOTA {
                    let _ = tx.send(Event::Closed(
                        role,
                        id,
                        Stream::Stderr,
                        Some("worker output quota"),
                    ));
                    return;
                }
                if tx
                    .send(Event::Stderr(role, id, buffer[..n].to_vec()))
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiler_artifact_envelope_does_not_expand_guest_or_helper_output() {
        let len = MAX_FRAME + 1;
        let mut bytes = (len as u32).to_be_bytes().to_vec();
        bytes.resize(len + 4, b' ');
        for role in [Role::Guest, Role::File, Role::Compiler] {
            let (tx, rx) = std::sync::mpsc::sync_channel(8);
            read_frames(role, 0, std::io::Cursor::new(&bytes), tx);
            let events: Vec<_> = rx.try_iter().collect();
            assert_eq!(
                matches!(events.first(), Some(Event::Frame(..))),
                role == Role::Compiler
            );
        }
        // The compiler's aggregate output budget remains 256 KiB. A second
        // otherwise valid large frame is rejected before allocating its body.
        let mut twice = bytes.clone();
        twice.extend_from_slice(&bytes);
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        read_frames(Role::Compiler, 0, std::io::Cursor::new(twice), tx);
        let events: Vec<_> = rx.try_iter().collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::Frame(..)))
                .count(),
            1
        );
        assert!(matches!(
            events.last(),
            Some(Event::Closed(_, _, _, Some("worker frame quota")))
        ));
    }

    #[test]
    fn compiler_artifact_prefix_above_cap_is_rejected_before_body() {
        let bytes = ((MAX_ARTIFACT_FRAME + 1) as u32).to_be_bytes();
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        read_frames(Role::Compiler, 0, std::io::Cursor::new(bytes), tx);
        assert!(matches!(
            rx.recv().unwrap(),
            Event::Closed(_, _, _, Some("worker frame quota"))
        ));
    }

    #[test]
    fn reader_bounds_flood_before_supervisor_dequeues_it() {
        let mut bytes = Vec::new();
        for _ in 0..1000 {
            bytes.extend_from_slice(&2u32.to_be_bytes());
            bytes.extend_from_slice(b"{}");
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1024);
        read_frames(Role::Guest, 0, std::io::Cursor::new(bytes), tx);
        let events: Vec<_> = rx.try_iter().collect();
        assert!(
            events.len() <= 131,
            "queued {} events before applying quota",
            events.len()
        );
        assert!(matches!(
            events.last(),
            Some(Event::Closed(_, _, _, Some(_)))
        ));
    }

    #[test]
    fn input_queue_refuses_a_second_frame_before_the_first_drains() {
        let mut input = Input::new(None::<std::io::Sink>);
        assert!(!input.started());
        assert!(input.send(&[0, 0, 0, 1, b'x'], 1).is_err());
        assert!(input.send_artifact_init(Role::File, &[]).is_err());
        assert_eq!(
            input.send(&[0, 0, 0, 1, b'x'], 4).unwrap_err().to_string(),
            "worker input closed"
        );
    }

    /// A writer that accepts nothing while full and everything afterwards.
    struct Throttled(std::sync::Arc<std::sync::atomic::AtomicBool>, Vec<u8>);
    impl Write for Throttled {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.1.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_full_pipe_keeps_the_frame_queued_until_the_next_flush() {
        use std::sync::atomic::Ordering;
        let full = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut input = Input::new(Some(Throttled(full.clone(), Vec::new())));
        input.send(&[0, 0, 0, 1, b'x'], 4).unwrap();
        assert_eq!(
            input.send(&[0, 0, 0, 1, b'y'], 4).unwrap_err().to_string(),
            "worker input backpressure"
        );
        full.store(false, Ordering::Relaxed);
        input.flush().unwrap();
        input.send(&[0, 0, 0, 1, b'y'], 4).unwrap();
    }
}
