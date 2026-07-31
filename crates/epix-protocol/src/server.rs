//! Inbound accept loop: take TCP connections and hand the ones that speak
//! EDX to the EDX serve hook. EDX is the only peer protocol now, so this is
//! purely a doorman - it owns the fd budget and the two timeouts that keep a
//! public fileserver port from being held open by things that never talk.

use epix_core::PeerAddr;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// How long an accepted connection may sit before its first byte. The
/// fileserver address gets announced to public BitTorrent trackers, so random
/// BT clients and scanners connect and never speak our protocol - without this
/// bound each one holds a socket (and an fd) forever.
pub const FIRST_MSG_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum concurrent inbound connections. A guard against fd exhaustion: on
/// the public gateway, leaked BT-crawler connections once ate the process fd
/// limit, which killed the accept loop AND all outbound dials.
pub const MAX_INBOUND: usize = 400;

/// First byte of `epix_edx::MAGIC` ("EDX1"). Checked here rather than
/// depending on `epix-edx` for one byte; `epix_edx::magic_starts_with_e` pins
/// the two together.
const EDX_FIRST_BYTE: u8 = b'E';

/// Called once per inbound connection that completes the EDX handshake, with
/// the connection's source address. Only the clearnet TCP path wires this (a
/// real inbound peer proves our fileserver port is reachable); onion/I2P/mesh
/// inbound do not imply clearnet reachability, so they leave it unset.
pub type InboundHook = Arc<dyn Fn(&PeerAddr) + Send + Sync>;

/// Takes over an accepted stream: runs the EDX handshake and serve loop over
/// it. The runtime installs this; there are two variants, one that runs Noise
/// (clearnet) and one that does not (overlays, whose transport already
/// encrypts).
pub type EdxHook = Arc<
    dyn Fn(PeerAddr, epix_transport::PeerStream) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// A TCP peer server. Overlay listeners (Tor/I2P/Reticulum) call their
/// [`EdxHook`] directly - their streams cannot be peeked and their transport
/// already filters who reaches us.
pub struct PeerServer {
    edx: EdxHook,
    max_inbound: usize,
    first_msg_timeout: Duration,
}

impl PeerServer {
    pub fn new(edx: EdxHook) -> Self {
        Self { edx, max_inbound: MAX_INBOUND, first_msg_timeout: FIRST_MSG_TIMEOUT }
    }

    /// A smaller connection cap, so the shedding test does not need 400 real
    /// sockets (which would outrun the default fd limit on macOS).
    #[cfg(test)]
    fn with_max_inbound(mut self, max: usize) -> Self {
        self.max_inbound = max;
        self
    }

    /// A shorter first-byte deadline, so the reaper test finishes in
    /// milliseconds. Paused time is no help here: a registered socket keeps
    /// tokio's IO driver parked, so the clock never auto-advances.
    #[cfg(test)]
    fn with_first_msg_timeout(mut self, timeout: Duration) -> Self {
        self.first_msg_timeout = timeout;
        self
    }

    /// Serve inbound TCP connections until the future is dropped.
    ///
    /// Accept errors (EMFILE under fd pressure, ECONNABORTED, …) are transient:
    /// retry after a short pause instead of returning, or one error would kill
    /// the accept loop and leave the node running but permanently deaf.
    pub async fn serve(self, listener: TcpListener) -> std::io::Result<()> {
        let inbound = Arc::new(tokio::sync::Semaphore::new(self.max_inbound));
        let first_msg_timeout = self.first_msg_timeout;
        loop {
            let (sock, addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            };
            // At capacity: shed the new connection instead of leaking toward
            // the process fd limit (which would also break outbound dials).
            let Ok(permit) = inbound.clone().try_acquire_owned() else {
                drop(sock);
                continue;
            };
            let _ = sock.set_nodelay(true);
            let edx = self.edx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let stream: epix_transport::PeerStream = Box::pin(sock);
                // Read one byte under the reaper timeout, then replay it: a
                // scanner that connects and says nothing is dropped instead of
                // holding the socket, and a first byte that is not the EDX
                // magic is dropped immediately (nothing else speaks here).
                let peek = tokio::time::timeout(
                    first_msg_timeout,
                    epix_transport::peek_first_byte(stream),
                );
                let Ok(Ok((first, stream))) = peek.await else { return };
                if first != EDX_FIRST_BYTE {
                    return;
                }
                edx(PeerAddr::Ip(addr), stream).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// A hook that counts takeovers and echoes the bytes it was handed, so a
    /// test can prove the peeked byte was replayed.
    fn echo_hook(hits: Arc<AtomicUsize>) -> EdxHook {
        Arc::new(move |_peer, mut stream| {
            let hits = hits.clone();
            Box::pin(async move {
                hits.fetch_add(1, Ordering::Relaxed);
                let mut buf = [0u8; 4];
                if stream.read_exact(&mut buf).await.is_ok() {
                    let _ = stream.write_all(&buf).await;
                    let _ = stream.flush().await;
                }
            })
        })
    }

    /// An EDX peer reaches the hook, and the sniffed first byte is replayed -
    /// the hook must see the whole magic, not three quarters of it.
    #[tokio::test]
    async fn an_edx_first_byte_reaches_the_hook_with_the_byte_intact() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        tokio::spawn(PeerServer::new(echo_hook(hits.clone())).serve(listener));

        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"EDX1").await.unwrap();
        let mut back = [0u8; 4];
        sock.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"EDX1");
        assert_eq!(hits.load(Ordering::Relaxed), 1);
    }

    /// Wait for the server to hang up. Dropping a socket with unread data
    /// sends an RST, so a reset counts as "hung up" just like a clean EOF.
    async fn wait_for_hangup(sock: &mut TcpStream) -> Vec<u8> {
        let mut back = Vec::new();
        match sock.read_to_end(&mut back).await {
            Ok(_) => back,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => back,
            Err(e) => panic!("expected a hangup, got {e}"),
        }
    }

    /// A connection whose first byte is not the EDX magic is dropped at once:
    /// BT crawlers hit the announced fileserver port constantly and there is
    /// no other protocol left for them to be speaking.
    #[tokio::test]
    async fn a_non_edx_first_byte_is_dropped_without_reaching_the_hook() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        tokio::spawn(PeerServer::new(echo_hook(hits.clone())).serve(listener));

        let mut sock = TcpStream::connect(addr).await.unwrap();
        // A msgpack fixmap header, i.e. an old EpixNet/ZeroNet peer.
        sock.write_all(&[0x83, 0x01, 0x02, 0x03]).await.unwrap();
        let back = wait_for_hangup(&mut sock).await;
        assert!(back.is_empty(), "nothing was written back, got {back:?}");
        assert_eq!(hits.load(Ordering::Relaxed), 0, "the hook never ran");
    }

    /// A client that connects and never sends a byte (BT crawlers, port
    /// scanners) must be dropped after the first-byte deadline instead of
    /// holding a socket forever - the leak that exhausted the gateway's fd
    /// limit and killed its accept loop.
    #[tokio::test]
    async fn a_silent_inbound_connection_is_reaped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server = PeerServer::new(echo_hook(hits.clone()))
            .with_first_msg_timeout(Duration::from_millis(100));
        tokio::spawn(server.serve(listener));

        let mut sock = TcpStream::connect(addr).await.unwrap();
        // The client never sends a byte. The outer bound only trips if the
        // doorman waits on the first byte forever.
        let back = tokio::time::timeout(Duration::from_secs(5), wait_for_hangup(&mut sock))
            .await
            .expect("the silent connection should have been dropped");
        assert!(back.is_empty());
        assert_eq!(hits.load(Ordering::Relaxed), 0);
    }

    /// Past the inbound cap the accept loop sheds new connections rather than
    /// climbing toward the process fd limit - the guard that keeps a crawler
    /// flood from killing the accept loop and every outbound dial with it.
    #[tokio::test]
    async fn past_the_inbound_cap_new_connections_are_shed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        // A hook that parks forever, so every admitted connection holds its
        // permit for the whole test.
        let held_hits = hits.clone();
        let hook: EdxHook = Arc::new(move |_peer, stream| {
            let held_hits = held_hits.clone();
            Box::pin(async move {
                held_hits.fetch_add(1, Ordering::Relaxed);
                let _held = stream;
                std::future::pending::<()>().await;
            })
        });
        tokio::spawn(PeerServer::new(hook).with_max_inbound(2).serve(listener));

        let mut held = Vec::new();
        for _ in 0..2 {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(b"E").await.unwrap();
            held.push(s);
        }
        // Both permits must be taken before the third connect, or the shed is
        // not what we measured.
        while hits.load(Ordering::Relaxed) < 2 {
            tokio::task::yield_now().await;
        }

        let mut extra = TcpStream::connect(addr).await.unwrap();
        let _ = extra.write_all(b"E").await;
        let back = tokio::time::timeout(Duration::from_secs(5), wait_for_hangup(&mut extra))
            .await
            .expect("the shed connection should have been hung up");
        assert!(back.is_empty());
        assert_eq!(hits.load(Ordering::Relaxed), 2, "the third never reached the hook");
    }
}
