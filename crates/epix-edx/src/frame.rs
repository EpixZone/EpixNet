//! Frame codec: `u32-LE length ‖ postcard(Frame)` over any byte stream,
//! plus the accept-time protocol sniff for the migration window.
//!
//! Payload chunks are capped at [`crate::MAX_FRAME_LEN`]; a whole frame
//! (header + payload) may never exceed [`FRAME_HARD_CAP`]. The cap is
//! enforced on BOTH sides: writers split, readers reject — a peer
//! claiming a larger frame is cut off before any allocation happens.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::msg::Frame;
use crate::{MAGIC, MAX_FRAME_LEN};

/// Absolute cap on an encoded frame: payload cap + header slack.
pub const FRAME_HARD_CAP: usize = MAX_FRAME_LEN + 4096;

/// Which protocol an incoming connection speaks (first-byte sniff).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sniff {
    /// `E` of `EDX1`.
    Edx,
    /// A msgpack map header (fixmap 0x80-0x8f, map16 0xde, map32 0xdf):
    /// every legacy EpixNet message starts with one.
    Legacy,
    Unknown,
}

pub fn sniff(first_byte: u8) -> Sniff {
    match first_byte {
        b'E' => Sniff::Edx,
        0x80..=0x8f | 0xde | 0xdf => Sniff::Legacy,
        _ => Sniff::Unknown,
    }
}

/// Send the 4-byte magic (each side sends it once, before anything else).
pub async fn write_magic<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    w.write_all(&MAGIC).await
}

/// Read and check the peer's magic.
pub async fn read_magic<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<()> {
    let mut got = [0u8; 4];
    r.read_exact(&mut got).await?;
    if got != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not an EDX peer (got {got:02x?})"),
        ));
    }
    Ok(())
}

/// Encode a frame to bytes (length prefix included), enforcing the cap.
pub fn encode(frame: &Frame) -> io::Result<Vec<u8>> {
    let body = postcard::to_stdvec(frame)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if body.len() > FRAME_HARD_CAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("frame of {} bytes exceeds cap {FRAME_HARD_CAP}", body.len()),
        ));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Write one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let bytes = encode(frame)?;
    w.write_all(&bytes).await
}

/// Read one frame, rejecting oversize claims BEFORE allocating.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > FRAME_HARD_CAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer claimed a {len}-byte frame (cap {FRAME_HARD_CAP})"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    postcard::from_bytes(&body).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("frame decode: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{FrameBody, Req, Resp};
    use epix_blob::ObjId;

    #[tokio::test]
    async fn frames_round_trip_over_a_stream() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let sent = vec![
            Frame { stream: 1, body: FrameBody::Req(Req::GetBitfield { obj: ObjId([9; 32]) }) },
            Frame { stream: 1, body: FrameBody::Resp { last: true, resp: Resp::Ok } },
            Frame { stream: 7, body: FrameBody::Data { last: true, bytes: vec![3; 60_000] } },
        ];
        for f in &sent {
            write_frame(&mut a, f).await.unwrap();
        }
        for f in &sent {
            assert_eq!(&read_frame(&mut b).await.unwrap(), f);
        }
    }

    #[tokio::test]
    async fn oversize_claim_is_rejected_without_allocation() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Hand-write a length prefix claiming 1 GiB.
        a.write_all(&(1u32 << 30).to_le_bytes()).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("claimed"));
    }

    #[test]
    fn oversize_payload_refuses_to_encode() {
        let f = Frame {
            stream: 1,
            body: FrameBody::Data { last: false, bytes: vec![0; FRAME_HARD_CAP + 1] },
        };
        assert!(encode(&f).is_err());
    }

    #[test]
    fn payload_at_cap_encodes() {
        let f = Frame {
            stream: 1,
            body: FrameBody::Data { last: true, bytes: vec![0; MAX_FRAME_LEN] },
        };
        assert!(encode(&f).is_ok());
    }

    #[tokio::test]
    async fn truncated_stream_errors_cleanly() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&100u32.to_le_bytes()).await.unwrap();
        a.write_all(&[1, 2, 3]).await.unwrap();
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }

    #[test]
    fn sniff_separates_protocols() {
        assert_eq!(sniff(b'E'), Sniff::Edx);
        for legacy in [0x80u8, 0x8f, 0xde, 0xdf] {
            assert_eq!(sniff(legacy), Sniff::Legacy, "{legacy:#x}");
        }
        assert_eq!(sniff(0x00), Sniff::Unknown);
    }

    #[tokio::test]
    async fn magic_exchange() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_magic(&mut a).await.unwrap();
        read_magic(&mut b).await.unwrap();
        // Wrong magic rejected.
        b.write_all(b"HTTP").await.unwrap();
        assert!(read_magic(&mut a).await.is_err());
    }
}
