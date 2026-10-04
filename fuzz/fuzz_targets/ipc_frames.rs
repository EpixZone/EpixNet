#![no_main]

//! Exercise the actual worker framing code and both directions of every IPC
//! message type. This target never creates a process or runs guest code.

use std::fmt::Debug;
use std::io::{Cursor, Read};

use evx_api::frames::{
    decode_compiler_reply, encode_compiler_reply, encode_worker_init, FromCompiler,
    FromHelper, FromWorker, ToCompiler, ToHelper, ToWorker,
};
use evx_api::{strict, MAX_ARTIFACT_FRAME, MAX_FRAME};
use libfuzzer_sys::fuzz_target;
use serde::{de::DeserializeOwned, Serialize};

// Include the production source instead of copying its framing implementation.
#[path = "../../crates/evx-worker/src/ipc.rs"]
mod worker_ipc;

/// Force read_exact to handle partial reads and a bounded interruption.
struct Fragmented<'a> {
    input: Cursor<&'a [u8]>,
    chunk: usize,
    interrupt: bool,
}

impl Read for Fragmented<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        let len = out.len().min(self.chunk);
        self.input.read(&mut out[..len])
    }
}

fn round_trip<T: DeserializeOwned + Serialize + PartialEq + Debug>(value: T) {
    // A decoded message can exceed the wire limit when re-encoded. The
    // production encoder must reject that case without sending a frame.
    let Ok(encoded) = evx_api::frames::encode(&value) else {
        return;
    };
    assert!(encoded.len() <= MAX_FRAME + 4);
    let mut cursor = Cursor::new(encoded.as_slice());
    assert_eq!(worker_ipc::read_frame::<T>(&mut cursor).unwrap(), value);
    assert_eq!(cursor.position() as usize, encoded.len());
    let mut written = Vec::new();
    worker_ipc::write_frame(&mut written, &value).unwrap();
    assert_eq!(written, encoded);
}

fn exercise<T: DeserializeOwned + Serialize + PartialEq + Debug>(data: &[u8], chunk: usize) {
    // Fuzz the exact strict typed decode used for supervisor receive frames.
    if let Ok(value) = strict::parse_typed::<T>(data) {
        round_trip(value);
    }

    // Fuzz arbitrary length prefixes, bodies, partial reads and trailing
    // frames through the production worker reader. One call consumes exactly
    // one frame; trailing bytes belong to the next call, not the first one.
    let mut reader = Fragmented {
        input: Cursor::new(data),
        chunk,
        interrupt: true,
    };
    for _ in 0..2 {
        let start = reader.input.position() as usize;
        let Ok(value) = worker_ipc::read_frame::<T>(&mut reader) else {
            break;
        };
        let end = reader.input.position() as usize;
        let declared = u32::from_be_bytes(data[start..start + 4].try_into().unwrap()) as usize;
        assert!((1..=MAX_FRAME).contains(&declared));
        assert_eq!(end, start + 4 + declared);
        assert_eq!(
            strict::parse_typed::<T>(&data[start + 4..end]).unwrap(),
            value
        );
        round_trip(value);
    }
}

fn exercise_artifacts(data: &[u8], chunk: usize) {
    if let Ok(value) = decode_compiler_reply(data) {
        if data.len() > MAX_FRAME { assert!(matches!(value, FromCompiler::Artifact { .. })); }
        if let Ok(encoded) = encode_compiler_reply(&value) {
            assert!(encoded.len() <= MAX_ARTIFACT_FRAME + 4);
            assert_eq!(decode_compiler_reply(&encoded[4..]).unwrap(), value);
            let mut written = Vec::new();
            worker_ipc::write_compiler_reply(&mut written, &value).unwrap();
            assert_eq!(written, encoded);
        }
    }
    let mut reader = Fragmented { input: Cursor::new(data), chunk, interrupt: true };
    if let Ok(value) = worker_ipc::read_worker_init(&mut reader) {
        assert!(matches!(value, ToWorker::Init { .. }));
        let declared = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
        assert!((1..=MAX_ARTIFACT_FRAME).contains(&declared));
        assert_eq!(reader.input.position() as usize, declared + 4);
        if declared > MAX_FRAME {
            assert!(worker_ipc::read_frame::<ToWorker>(&mut Cursor::new(data)).is_err());
        }
        if let Ok(encoded) = encode_worker_init(&value) {
            assert!(encoded.len() <= MAX_ARTIFACT_FRAME + 4);
            assert_eq!(worker_ipc::read_worker_init(&mut Cursor::new(&encoded)).unwrap(), value);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_ARTIFACT_FRAME + 4 {
        return;
    }
    let chunk = 1 + data.last().copied().unwrap_or(0) as usize;
    exercise::<ToWorker>(data, chunk);
    exercise::<FromWorker>(data, chunk);
    exercise::<ToCompiler>(data, chunk);
    exercise::<FromCompiler>(data, chunk);
    exercise::<ToHelper>(data, chunk);
    exercise::<FromHelper>(data, chunk);
    exercise_artifacts(data, chunk);
});
