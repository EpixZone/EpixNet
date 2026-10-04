//! Length-prefixed frames over stdin and stdout.

use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::Serialize;

use evx_api::frames::{encode, encode_compiler_reply, FromCompiler, ToWorker};
use evx_api::{strict, MAX_ARTIFACT_FRAME, MAX_FRAME};

/// Read one frame from the supervisor. The supervisor is trusted, but the
/// decode still goes through the strict parser so a malformed frame fails
/// closed rather than being interpreted loosely.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, String> {
    read_bounded(reader, MAX_FRAME)
}

/// Only the first guest frame can carry the larger host-produced artifact.
/// Broker responses continue through read_frame with the ordinary limit.
pub fn read_worker_init(reader: &mut impl Read) -> Result<ToWorker, String> {
    let frame = read_bounded(reader, MAX_ARTIFACT_FRAME)?;
    if !matches!(frame, ToWorker::Init { .. }) {
        return Err("expected artifact initialization".to_string());
    }
    Ok(frame)
}

fn read_bounded<T: DeserializeOwned>(reader: &mut impl Read, limit: usize) -> Result<T, String> {
    let mut len = [0u8; 4];
    reader
        .read_exact(&mut len)
        .map_err(|_| "input closed".to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > limit {
        return Err("input frame limit".to_string());
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|_| "truncated input frame".to_string())?;
    strict::parse_typed(&body).map_err(|e| format!("invalid input frame: {e}"))
}

/// Write one frame to the supervisor.
pub fn write_frame<T: Serialize>(writer: &mut impl Write, frame: &T) -> Result<(), String> {
    let bytes = encode(frame).map_err(|e| e.to_string())?;
    write_encoded(writer, &bytes)
}

/// Compiler output has a larger envelope only for its terminal artifact.
pub fn write_compiler_reply(writer: &mut impl Write, frame: &FromCompiler) -> Result<(), String> {
    let bytes = encode_compiler_reply(frame).map_err(|e| e.to_string())?;
    write_encoded(writer, &bytes)
}

fn write_encoded(writer: &mut impl Write, bytes: &[u8]) -> Result<(), String> {
    writer
        .write_all(bytes)
        .map_err(|_| "output closed".to_string())?;
    writer.flush().map_err(|_| "output closed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use evx_api::frames::{encode_worker_init, FromWorker, ToHelper};
    use std::io::Cursor;

    #[test]
    fn artifact_initialization_is_separate_from_ordinary_frames() {
        let init = ToWorker::Init {
            artifact: vec![0; 132_880],
            artifact_sha256: "0".repeat(64),
            limits: evx_api::Limits::default(),
        };
        let encoded = encode_worker_init(&init).unwrap();
        assert_eq!(read_worker_init(&mut Cursor::new(&encoded)).unwrap(), init);
        assert!(read_frame::<ToWorker>(&mut Cursor::new(&encoded)).is_err());
        assert!(read_frame::<ToHelper>(&mut Cursor::new(&encoded)).is_err());
        let response = encode(&ToWorker::Response { response: vec![] }).unwrap();
        assert!(read_worker_init(&mut Cursor::new(response)).is_err());
    }

    #[test]
    fn frame_limits_are_checked_before_reading_body() {
        let artifact = ((MAX_ARTIFACT_FRAME + 1) as u32).to_be_bytes();
        assert_eq!(
            read_worker_init(&mut Cursor::new(artifact)).unwrap_err(),
            "input frame limit"
        );
        let ordinary = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame::<ToWorker>(&mut Cursor::new(ordinary)).unwrap_err(),
            "input frame limit"
        );
    }

    #[test]
    fn compiler_artifact_output_keeps_guest_output_small() {
        let artifact = FromCompiler::Artifact {
            artifact: vec![0; 132_880],
            artifact_sha256: "0".repeat(64),
            engine_key: "fixture".into(),
        };
        let mut output = Vec::new();
        write_compiler_reply(&mut output, &artifact).unwrap();
        assert_eq!(output, encode_compiler_reply(&artifact).unwrap());
        assert!(write_frame(&mut Vec::new(), &artifact).is_err());
        assert!(write_frame(
            &mut Vec::new(),
            &FromWorker::Call {
                request: vec![0; MAX_FRAME]
            }
        )
        .is_err());
        assert!(write_compiler_reply(
            &mut Vec::new(),
            &FromCompiler::Rejected {
                error: "x".repeat(MAX_FRAME)
            }
        )
        .is_err());
    }
}
