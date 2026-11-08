use std::io;

use reticulum::buffer::{InputBuffer, OutputBuffer};
use reticulum::iface::hdlc::Hdlc;
use reticulum::packet::Packet;
use reticulum::serde::Serialize;

// Existing RNS TCP uses this same fixed Packet-derived serialization bound.
const MAX_PACKET: usize = std::mem::size_of::<Packet>();
const MAX_FRAME: usize = MAX_PACKET * 2 + 2;

#[derive(Default)]
pub(super) struct Decoder {
    bytes: Vec<u8>,
    started: bool,
    escaped: bool,
}

impl Decoder {
    pub fn push(&mut self, byte: u8) -> io::Result<Option<Packet>> {
        if byte == 0x7e {
            if self.escaped {
                return Err(invalid_frame());
            }
            self.started = true;
            if self.bytes.is_empty() {
                return Ok(None);
            }
            let packet = Packet::deserialize(&mut InputBuffer::new(&self.bytes))
                .map_err(|_| invalid_frame())?;
            self.bytes.clear();
            return Ok(Some(packet));
        }
        if !self.started {
            return Ok(None);
        }
        if !self.escaped && byte == 0x7d {
            self.escaped = true;
            return Ok(None);
        }
        if self.bytes.len() == MAX_PACKET {
            return Err(invalid_frame());
        }
        self.bytes
            .push(if self.escaped { byte ^ 0x20 } else { byte });
        self.escaped = false;
        Ok(None)
    }
}

pub(super) fn encode(packet: &Packet) -> io::Result<Vec<u8>> {
    let mut raw = [0; MAX_PACKET];
    let mut output = OutputBuffer::new(&mut raw);
    packet.serialize(&mut output).map_err(|_| invalid_frame())?;
    let mut framed = [0; MAX_FRAME];
    let mut frame = OutputBuffer::new(&mut framed);
    Hdlc::encode(output.as_slice(), &mut frame).map_err(|_| invalid_frame())?;
    Ok(frame.as_slice().to_vec())
}

fn invalid_frame() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or oversized native radio frame",
    )
}
