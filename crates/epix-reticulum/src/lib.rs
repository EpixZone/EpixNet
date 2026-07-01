//! Reticulum mesh transport for EpixNet.
//!
//! Reticulum moves data as discrete, encrypted packets over a [`Link`] (LoRa,
//! BLE, packet radio, TCP, serial…). The EpixNet wire protocol, on the other
//! hand, is a byte stream: msgpack messages framed over a [`PeerStream`]
//! (`AsyncRead` + `AsyncWrite`). [`ReticulumStream`] is the adapter between the
//! two — it presents a Reticulum `Link` as a byte stream, so the *entire*
//! FileRequest command set (handshake, getFile, the DHT `kad` RPCs, …) runs
//! over mesh with no protocol changes.
//!
//! Direction of travel:
//! - **write** — bytes are chunked to the link MTU, turned into encrypted data
//!   packets ([`Link::data_packet`]), and sent on the transport.
//! - **read** — the link's inbound `Data` events are concatenated back into a
//!   byte stream. Because a `Link` delivers packets reliably and in order, the
//!   reassembled stream is faithful; the reader neither knows nor cares that it
//!   arrived as packets.
//!
//! [`PeerStream`]: epix_transport::PeerStream

mod server;
mod transport;
pub use server::ReticulumServer;
pub use transport::ReticulumTransport;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use reticulum::destination::link::{Link, LinkEvent, LinkEventData, LinkId};
use reticulum::transport::Transport;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{broadcast, mpsc, Mutex};

/// Bytes per data packet. Well under the Reticulum MDU (2048) once link
/// encryption overhead is accounted for; larger writes are split across packets
/// and the reader reassembles them transparently.
const CHUNK: usize = 1024;

/// A Reticulum [`Link`] presented as a byte stream.
///
/// Construct one per link — the client side wraps its out-link
/// ([`Transport::find_out_link`]), the server side wraps the matching in-link
/// ([`Transport::find_in_link`]). Both are full duplex.
pub struct ReticulumStream {
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,
    outgoing: mpsc::UnboundedSender<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl ReticulumStream {
    /// Wrap `link` (identified by `link_id`) as a byte stream. `events` is the
    /// link-event stream this link's data arrives on — `in_link_events()` for a
    /// server-side in-link, `out_link_events()` for a client-side out-link.
    pub fn wrap(
        transport: Arc<Transport>,
        link: Arc<Mutex<Link>>,
        link_id: LinkId,
        mut events: broadcast::Receiver<LinkEventData>,
    ) -> Self {
        let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Reader: forward this link's Data payloads into the byte stream.
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(ev) if ev.id == link_id => match ev.event {
                        LinkEvent::Data(payload) => {
                            if in_tx.send(payload.as_slice().to_vec()).is_err() {
                                break; // reader dropped
                            }
                        }
                        LinkEvent::Closed => break,
                        _ => {}
                    },
                    Ok(_) => {}
                    // A slow consumer can lag the broadcast; keep going rather
                    // than tearing down the stream.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        // Writer: chunk to the MTU, encrypt into data packets, send.
        tokio::spawn(async move {
            while let Some(bytes) = out_rx.recv().await {
                for chunk in bytes.chunks(CHUNK) {
                    let packet = { link.lock().await.data_packet(chunk) };
                    match packet {
                        Ok(p) => transport.send_packet(p).await,
                        Err(_) => return, // link closed
                    }
                }
            }
        });

        Self { incoming: in_rx, outgoing: out_tx, read_buf: Vec::new(), read_pos: 0 }
    }
}

impl AsyncRead for ReticulumStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Refill from the next payload when the current one is drained.
        if this.read_pos >= this.read_buf.len() {
            match this.incoming.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    this.read_buf = data;
                    this.read_pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())), // link closed -> EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = buf.remaining().min(this.read_buf.len() - this.read_pos);
        buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
        this.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReticulumStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Hand the bytes to the writer task; it chunks and sends. Unbounded, so
        // this never blocks the protocol layer.
        match self.get_mut().outgoing.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "reticulum link closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
