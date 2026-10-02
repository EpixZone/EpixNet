//! Length-prefixed frames over stdin and stdout.

use std::io::{Read, Write};

use serde::de::DeserializeOwned;
use serde::Serialize;

use evx_api::frames::encode;
use evx_api::{strict, MAX_FRAME};

/// Read one frame from the supervisor. The supervisor is trusted, but the
/// decode still goes through the strict parser so a malformed frame fails
/// closed rather than being interpreted loosely.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, String> {
    let mut len = [0u8; 4];
    reader
        .read_exact(&mut len)
        .map_err(|_| "input closed".to_string())?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
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
    writer
        .write_all(&bytes)
        .map_err(|_| "output closed".to_string())?;
    writer.flush().map_err(|_| "output closed".to_string())
}
