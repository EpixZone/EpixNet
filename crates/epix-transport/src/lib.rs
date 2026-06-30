//! `epix-transport` — the byte-stream abstraction beneath the wire protocol.
//!
//! `epix-protocol`'s connection runs over a [`PeerStream`], so the same
//! msgpack/FileRequest logic works over TCP today and Tor / Reticulum mesh
//! later — each is just another [`Transport`] that yields a `PeerStream`.

use async_trait::async_trait;
use epix_core::{Error, PeerAddr, Result};
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Anything that is an async, bidirectional, owned byte stream.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// An established, transport-agnostic stream to a peer.
///
/// `Pin<Box<dyn …>>` so it implements `AsyncRead`/`AsyncWrite` directly (via
/// tokio's `Pin<P>` blankets) and `AsyncReadExt`/`AsyncWriteExt` just work.
pub type PeerStream = Pin<Box<dyn AsyncReadWrite>>;

/// A way to reach peers. One impl per physical/overlay transport.
#[async_trait]
pub trait Transport: Send + Sync {
    fn scheme(&self) -> &'static str;
    async fn dial(&self, addr: &PeerAddr) -> Result<PeerStream>;
}

/// Clearnet TCP.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpTransport;

#[async_trait]
impl Transport for TcpTransport {
    fn scheme(&self) -> &'static str {
        "tcp"
    }

    async fn dial(&self, addr: &PeerAddr) -> Result<PeerStream> {
        match addr {
            PeerAddr::Ip(sa) => {
                let stream = TcpStream::connect(sa)
                    .await
                    .map_err(|e| Error::Protocol(format!("tcp connect {sa}: {e}")))?;
                let _ = stream.set_nodelay(true);
                Ok(Box::pin(stream))
            }
            other => Err(Error::Protocol(format!(
                "TcpTransport cannot dial a `{}` peer",
                other.scheme()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_transport_dials_and_streams_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Echo server.
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            sock.read_exact(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
        });

        let mut stream = TcpTransport.dial(&PeerAddr::Ip(addr)).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"hello");
    }

    #[tokio::test]
    async fn tcp_transport_rejects_non_ip() {
        let result = TcpTransport.dial(&PeerAddr::Rns([0; 16])).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(format!("{err}").contains("cannot dial"));
    }
}
