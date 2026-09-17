//! The browser proxy Firefox points at.
//!
//! Firefox's PAC sends every `*.epix` request here. Two shapes arrive:
//!
//! - **`CONNECT dashboard.epix:443`** (https): we answer `200`, do a TLS
//!   handshake with an on-the-fly leaf cert for the SNI host (signed by the
//!   local CA Firefox trusts), then serve the node's UI app over TLS - so the
//!   page is `https://dashboard.epix/`, a real secure context.
//! - **`GET http://dashboard.epix/…`** (plain http): in secure mode we send the
//!   browser to `https://` instead (the CA makes `https://*.epix` a real secure
//!   context, so a xite must never load as an insecure http page); otherwise we
//!   serve the app directly.
//!
//! Either way the app is the same axum router the node serves on loopback, so
//! host routing, the wrapper, inner files, and the WebSocket all work
//! unchanged. We peek the first bytes to tell CONNECT from a plain request
//! without consuming them.

use crate::ca::{EpixCertResolver, LocalCa};
use axum::extract::Request;
use axum::response::IntoResponse;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use rustls::ServerConfig;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::Service;

/// Serve the browser proxy on `listener`: TLS-terminate `CONNECT` (https) and
/// serve plain http, both feeding `app` (the node's UI router, already wrapped
/// with the transparent-proxy host rewrite). Runs until the listener errors.
/// `secure` is shared with the launcher: it flips to `true` once the local CA is
/// confirmed trusted (so `https://*.epix` validates). While it is `false` we
/// must serve plain http, because the browser cannot complete the TLS handshake
/// yet; once true, plain-http xite loads are upgraded to https.
pub async fn serve<S>(
    listener: TcpListener,
    app: S,
    ca: Arc<LocalCa>,
    secure: Arc<AtomicBool>,
) -> std::io::Result<()>
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
        let secure = secure.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(sock, app, tls, secure).await {
                tracing_debug(&format!("proxy conn ended: {e}"));
            }
        });
    }
}

fn tracing_debug(_m: &str) {}

/// Per-connection proxy diagnostics, printed only when `EPIX_PROXY_LOG` is set
/// (any non-empty value except `0`). Off by default: these fire on every
/// connection, including routine client aborts, so they are debug aids, not
/// operational logging. Proved essential for diagnosing browser-side proxy
/// behaviour (which hosts CONNECT, SNI presence, TLS handshake fate).
fn proxy_debug(msg: &str) {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let on = *ON.get_or_init(|| {
        std::env::var("EPIX_PROXY_LOG").map_or(false, |v| !v.is_empty() && v != "0")
    });
    if on {
        eprintln!("[epix-proxy] {msg}");
    }
}

async fn handle_conn<S>(
    mut sock: tokio::net::TcpStream,
    app: S,
    tls: TlsAcceptor,
    secure: Arc<AtomicBool>,
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
        let head = consume_headers(&mut sock).await?;
        let target = String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        proxy_debug(&target);
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        // TLS handshake with a per-SNI leaf cert, then serve the app over it.
        let tls_stream = match tls.accept(sock).await {
            Ok(s) => {
                proxy_debug(&format!("TLS ok for: {target}"));
                s
            }
            Err(e) => {
                proxy_debug(&format!("TLS failed for {target}: {e}"));
                return Err(format!("tls: {e}"));
            }
        };
        let r = serve_app(TokioIo::new(tls_stream), app).await;
        if let Err(e) = &r {
            proxy_debug(&format!("serve error for {target}: {e}"));
        }
        r
    } else {
        // Plain http. In secure mode, redirect a xite's top-level GET to https
        // (so a typed `talk.epix`, or a redirect that resolved to http, never
        // leaves the user on an insecure page). Everything else - and every
        // request before the CA is trusted - is served directly.
        // 307 (temporary), never 301: browsers cache permanent redirects hard,
        // and a profile that later falls back to http mode (CA install failed)
        // must not be stuck with a cached forced-https redirect. The upgrade
        // itself costs one loopback round trip on the rare plain-http hit.
        if secure.load(Ordering::Relaxed) {
            if let Some(location) = https_upgrade_target(&sock).await {
                proxy_debug(&format!("plain-http upgrade -> {location}"));
                // Drain the request head before responding: the target was
                // only peeked, and closing a socket that still holds unread
                // received data sends a TCP RST instead of FIN - the RST can
                // destroy the in-flight 307 before the browser reads it,
                // surfacing as an intermittent "The connection was reset" on
                // plain-http xite loads. (GET/HEAD only, so the head is the
                // whole request.) The graceful shutdown then puts the FIN
                // after the response bytes.
                let _ = consume_headers(&mut sock).await;
                let resp = format!(
                    "HTTP/1.1 307 Temporary Redirect\r\n\
                     Location: {location}\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\r\n"
                );
                sock.write_all(resp.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                let _ = sock.shutdown().await;
                return Ok(());
            }
        }
        proxy_debug("plain-http serve");
        serve_app(TokioIo::new(sock), app).await
    }
}

/// For a plain-http proxy request, the `https://…` URL to redirect it to, or
/// `None` to serve it as-is. Peeks the request line (never consuming it, so a
/// non-match still serves normally) and upgrades only a top-level `GET`/`HEAD`
/// for a xite host - a `.epix` name or a bare bech32 `epix1…` address. A bare
/// address is upgraded to its dotted alias `<addr>.epix` (browsers
/// special-case single-label hosts, so the dotted form is the canonical
/// origin). Other methods (POST, WebSocket upgrades) and non-xite hosts are
/// left untouched.
async fn https_upgrade_target(sock: &tokio::net::TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = sock.peek(&mut buf).await.ok()?;
    let head = &buf[..n];
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    if method != "GET" && method != "HEAD" {
        return None;
    }
    // Proxy plain-http requests are absolute-form: `GET http://talk.epix/p?q ...`.
    let rest = parts.next()?.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = authority.split(':').next().unwrap_or(authority);
    if host.starts_with("epix1") && host.len() > 20 && !host.contains('.') {
        return Some(format!("https://{host}.epix{path}"));
    }
    if host.ends_with(".epix") && host.len() > 5 {
        return Some(format!("https://{host}{path}"));
    }
    None
}

/// Read bytes until the end of the HTTP request head (`\r\n\r\n`), returning
/// the consumed head (for logging the CONNECT target).
async fn consume_headers(sock: &mut tokio::net::TcpStream) -> Result<Vec<u8>, String> {
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
    Ok(seen)
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
            if let Some(location) = canonical_xite_location(&req) {
                return Ok(axum::response::Redirect::temporary(&location).into_response());
            }
            let resp = app.call(req).await?;
            Ok::<_, Infallible>(resp)
        }
    });
    ConnBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, svc)
        .await
        .map_err(|e| format!("serve: {e}"))
}

/// Path-form links must change origin even for iframe/file requests. Serving
/// another xite's HTML under a trusted host would inherit that host's wallet
/// permissions. The loopback UI keeps its existing path routing.
fn canonical_xite_location(req: &Request) -> Option<String> {
    let host = req
        .headers()
        .get("host")?
        .to_str()
        .ok()?
        .split(':')
        .next()?;
    if !crate::ca::is_epix_host(host) {
        return None;
    }
    let path = req.uri().path().trim_start_matches('/');
    let (target, rest) = path.split_once('/').unwrap_or((path, ""));
    if !crate::ca::is_epix_host(target) {
        return None;
    }
    let origin = if target.ends_with(".epix") {
        target.to_string()
    } else {
        format!("{target}.epix")
    };
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    Some(format!("//{origin}/{rest}{query}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tls_proxy_serves_only_private_origins_with_its_own_anchor() {
        use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
        use tokio::net::TcpStream;
        use tokio_rustls::TlsConnector;
        let dir = tempfile::tempdir().unwrap();
        let ca = Arc::new(LocalCa::load_or_create(dir.path()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/", axum::routing::get(|| async { "private xite" }));
        let server = tokio::spawn(serve(
            listener,
            app,
            ca.clone(),
            Arc::new(AtomicBool::new(true)),
        ));
        let mut roots = RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                ca.cert_der().to_vec(),
            ))
            .unwrap();
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            for host in [
                "dashboard.epix",
                "example.com",
                "epix1abcdefghijklmnopqrstuv.example",
            ] {
                let mut socket = TcpStream::connect(address).await.unwrap();
                socket
                    .write_all(
                        format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .unwrap();
                let response = consume_headers(&mut socket).await.unwrap();
                assert!(response.starts_with(b"HTTP/1.1 200"));
                let result = connector
                    .connect(ServerName::try_from(host.to_string()).unwrap(), socket)
                    .await;
                if host != "dashboard.epix" {
                    assert!(result.is_err(), "must not issue certificates for {host}");
                    continue;
                }
                let mut tls =
                    result.expect("private origin must validate against the installation CA");
                tls.write_all(
                    b"GET / HTTP/1.1\r\nHost: dashboard.epix\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
                let mut response = Vec::new();
                tls.read_to_end(&mut response).await.unwrap();
                let text = String::from_utf8(response).unwrap();
                assert!(text.starts_with("HTTP/1.1 200"));
                assert!(text.contains("private xite"));
            }
        })
        .await
        .expect("TLS regression timed out");
        server.abort();
    }

    #[test]
    fn nested_xite_files_cannot_inherit_host_permissions() {
        let request = |host, path| {
            Request::builder()
                .uri(path)
                .header("host", host)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        for path in [
            "/evil.epix/",
            "/evil.epix/index.html",
            "/evil.epix/a%20b?q=a%2Fb",
        ] {
            assert_eq!(
                canonical_xite_location(&request("xid.epix", path)),
                Some(format!("/{}", path))
            );
        }
        assert_eq!(
            canonical_xite_location(&request("xid.epix", "//evil.epix/index.html")),
            Some("//evil.epix/index.html".into())
        );
        assert_eq!(
            canonical_xite_location(&request("dashboard.epix", "/dashboard.epix/")),
            Some("//dashboard.epix/".into())
        );
        for (host, path) in [
            ("127.0.0.1:43110", "/talk.epix/index.html"),
            ("talk.epix", "/index.html"),
            ("talk.epix", "/uimedia/all.js"),
            ("talk.epix", "/evil.example/index.html"),
        ] {
            assert_eq!(canonical_xite_location(&request(host, path)), None);
        }
    }
}
