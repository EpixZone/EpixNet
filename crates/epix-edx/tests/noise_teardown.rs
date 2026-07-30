//! The Noise tunnel must not outlive the stream it was handed.
//!
//! `secure()` splits the caller's stream into two detached pump tasks and
//! returns a plaintext duplex, so the caller keeps NO reference to the stream it
//! passed in. On the node that stream is the registry's counting stream, which
//! owns both the socket and the connection's row on the /Stats page. If the
//! pumps do not end when the tunnel above them does, the socket and the row
//! leak for the life of the process even after the server's idle reaper fired -
//! which is exactly what a gateway showed: rows stuck at `last recv = Hello`,
//! zero activity, still listed after two and a half hours.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// Stands in for `epix_protocol::registry::CountingStream`: its drop is the
/// event that delists a connection from /Stats and closes the fd.
struct Tracked {
    inner: DuplexStream,
    dropped: Arc<AtomicUsize>,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl AsyncRead for Tracked {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tracked {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn settle() {
    for _ in 0..500 {
        tokio::task::yield_now().await;
    }
}

/// Dropping the tunnel's user end must free the caller's stream, WITHOUT the
/// peer having to close first. The peer here stays connected and silent, which
/// is the case that leaked: the inbound pump had no wakeup source at all.
#[tokio::test]
async fn dropping_the_tunnel_frees_the_stream_while_the_peer_stays_connected() {
    let (srv_io, cli_io) = tokio::io::duplex(64 * 1024);
    let dropped = Arc::new(AtomicUsize::new(0));
    let tracked = Tracked { inner: srv_io, dropped: dropped.clone() };

    let (srv, cli) = tokio::join!(
        epix_edx::noise::secure_responder(Box::pin(tracked)),
        epix_edx::noise::secure_initiator(Box::pin(cli_io)),
    );
    let srv = srv.unwrap();
    let cli = cli.unwrap();

    // What the EDX layer above does when the idle reaper fires: serve() returns,
    // the Conn drops, its reader/writer end. All of that only ever held the
    // tunnel's USER end.
    drop(srv.stream);
    settle().await;

    // `cli` is deliberately still alive: the peer is connected and silent.
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        1,
        "dropping the tunnel must free the caller's stream: the outbound pump ends when the \
         user duplex closes, and dropping its teardown sender unblocks the inbound pump so \
         neither half stays parked on the socket"
    );
    drop(cli);
}

/// The tunnel still carries traffic both ways. A teardown signal that fired
/// early, or a read deadline that cut a live link, would break this.
#[tokio::test]
async fn the_tunnel_still_round_trips_after_the_teardown_change() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (srv_io, cli_io) = tokio::io::duplex(64 * 1024);
    let (srv, cli) = tokio::join!(
        epix_edx::noise::secure_responder(Box::pin(srv_io)),
        epix_edx::noise::secure_initiator(Box::pin(cli_io)),
    );
    let mut srv = srv.unwrap().stream;
    let mut cli = cli.unwrap().stream;

    cli.write_all(b"ping over noise").await.unwrap();
    cli.flush().await.unwrap();
    let mut got = [0u8; 15];
    srv.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping over noise");

    srv.write_all(b"pong").await.unwrap();
    srv.flush().await.unwrap();
    let mut back = [0u8; 4];
    cli.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"pong");
}
