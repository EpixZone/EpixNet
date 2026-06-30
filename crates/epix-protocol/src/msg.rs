//! msgpack message framing for the EpixNet wire protocol.
//!
//! Messages are bare, self-delimiting msgpack maps streamed back-to-back (no
//! length prefix). We drive `rmpv` directly rather than a typed serde decoder
//! whose `#[serde(untagged)]` + `flatten` message enum fails to parse EpixNet's
//! handshake response under rmp (proven in the wire spike).

use epix_core::{Error, Result};
use epix_transport::PeerStream;
use rmpv::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build a msgpack map from `(key, value)` pairs.
pub fn vmap(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

/// Look up a string key in a msgpack map value.
pub fn vget<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, val)| val)
}

/// Encode and write one message, then flush.
pub async fn send_msg(stream: &mut PeerStream, msg: &Value) -> Result<()> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, msg)
        .map_err(|e| Error::Protocol(format!("msgpack encode: {e}")))?;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// Read exactly one msgpack value, buffering across reads. `buf` carries any
/// bytes already received past the previous message.
pub async fn read_msg(stream: &mut PeerStream, buf: &mut Vec<u8>) -> Result<Value> {
    loop {
        let mut cursor = std::io::Cursor::new(&buf[..]);
        match rmpv::decode::read_value(&mut cursor) {
            Ok(value) => {
                let consumed = cursor.position() as usize;
                buf.drain(..consumed);
                return Ok(value);
            }
            // Truncated mid-value — read more and retry.
            Err(e) if is_truncation(&e) => {}
            Err(e) => return Err(Error::Protocol(format!("msgpack decode: {e}"))),
        }

        let mut tmp = [0u8; 64 * 1024];
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::Protocol("connection closed by peer".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn is_truncation(e: &rmpv::decode::Error) -> bool {
    use rmpv::decode::Error::{InvalidDataRead, InvalidMarkerRead};
    match e {
        InvalidMarkerRead(io) | InvalidDataRead(io) => {
            io.kind() == std::io::ErrorKind::UnexpectedEof
        }
        _ => false,
    }
}
