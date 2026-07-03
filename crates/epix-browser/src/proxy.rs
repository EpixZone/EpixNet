//! The browser proxy Firefox points at.
//!
//! Firefox's PAC sends every `*.epix` request here. Two shapes arrive:
//!
//! - **`CONNECT dashboard.epix:443`** (https): we answer `200`, do a TLS
//!   handshake with an on-the-fly leaf cert for the SNI host (signed by the
//!   local CA Firefox trusts), then serve the node's UI app over TLS - so the
//!   page is `https://dashboard.epix/`, a real secure context.
//! - **`GET http://dashboard.epix/…`** (plain http): we serve the app directly.
//!
//! Either way the app is the same axum router the node serves on loopback, so
//! host routing, the wrapper, inner files, and the WebSocket all work
//! unchanged. We peek the first bytes to tell CONNECT from a plain request
//! without consuming them.

use crate::ca::{EpixCertResolver, LocalCa};
use axum::extract::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use rustls::ServerConfig;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

/// Serve the browser proxy on `listener`: TLS-terminate `CONNECT` (https) and
/// serve plain http, both feeding `app` (the node's UI router, already wrapped
/// with the transparent-proxy host rewrite). Runs until the listener errors.
pub async fn serve<S>(listener: TcpListener, app: S, ca: Arc<LocalCa>) -> std::io::Result<()>
where
    S: Service<Request, Response = axum::response::Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    let resolver = Arc::new(EpixCertResolver::new(ca));
    // Use the ring provider explicitly so we don't depend on a process-global
    // default being installed.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::other(format!("tls versions: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = TlsAcceptor::from(Arc::new(tls_config));

    loop {
        let (sock, _peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let app = app.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(sock, app, tls).await {
                tracing_debug(&format!("proxy conn ended: {e}"));
            }
        });
    }
}

fn tracing_debug(_m: &str) {}

async fn handle_conn<S>(
    mut sock: tokio::net::TcpStream,
    app: S,
    tls: TlsAcceptor,
) -> Result<(), String>
where
    S: Service<Request, Response = axum::response::Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    // Peek the request line to classify without consuming it.
    let mut peek = [0u8; 8];
    let n = sock.peek(&mut peek).await.map_err(|e| e.to_string())?;
    let is_connect = n >= 7 && &peek[..7] == b"CONNECT";

    if is_connect {
        // Read + discard the CONNECT request head (up to the blank line).
        consume_headers(&mut sock).await?;
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        // TLS handshake with a per-SNI leaf cert, then serve the app over it.
        let tls_stream = tls.accept(sock).await.map_err(|e| format!("tls: {e}"))?;
        serve_app(TokioIo::new(tls_stream), app).await
    } else {
        // Plain http proxying (absolute-form request); serve the app directly.
        serve_app(TokioIo::new(sock), app).await
    }
}

/// Read and discard bytes until the end of the HTTP request head (`\r\n\r\n`).
async fn consume_headers(sock: &mut tokio::net::TcpStream) -> Result<(), String> {
    let mut seen = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let r = sock.read(&mut byte).await.map_err(|e| e.to_string())?;
        if r == 0 {
            break;
        }
        seen.push(byte[0]);
        if seen.ends_with(b"\r\n\r\n") || seen.len() > 16 * 1024 {
            break;
        }
    }
    Ok(())
}

/// Serve the axum app over one connection (with WebSocket upgrades).
async fn serve_app<I, S>(io: I, app: S) -> Result<(), String>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: Service<Request, Response = axum::response::Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
    // Bridge the tower service (axum router) to hyper, mapping the body type.
    let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
        let mut app = app.clone();
        async move {
            let req = req.map(axum::body::Body::new);
            let resp = app.call(req).await?;
            Ok::<_, Infallible>(resp)
        }
    });
    ConnBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, svc)
        .await
        .map_err(|e| format!("serve: {e}"))
}
