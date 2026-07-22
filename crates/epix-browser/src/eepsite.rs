//! The `.i2p` HTTP proxy (eepsite browsing). Firefox's PAC sends every `*.i2p`
//! host here; requests are carried over SAM streams through the node's I2P
//! router (embedded emissary, or an external one).
//!
//! Two shapes arrive, like the `.epix` proxy:
//!
//! - **`GET http://site.i2p/…`** (absolute-form, the norm - eepsites are
//!   plain http): resolve the host to a destination, open a SAM stream, and
//!   forward the request in origin-form.
//! - **`CONNECT site.i2p:443`** (the rare TLS eepsite, or an HTTPS-First
//!   probe): tunnel raw bytes over the SAM stream.
//!
//! Host resolution order: an `?i2paddresshelper=` jump-link destination
//! (persisted, so the site works bare afterwards) > the local addressbook >
//! the router's naming service (`.b32.i2p` always resolves there; plain
//! hostnames only if the router knows them). Unknown hosts get an explanatory
//! page instead of a dead socket, as do requests while I2P is disabled or
//! still starting.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Read cap for one request head; anything larger is hostile or broken.
const MAX_HEAD: usize = 32 * 1024;
/// Resolve + connect budget. Tunnel building through a fresh router is slow;
/// beyond this the user gets an error page instead of a hung tab.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Serve the eepsite proxy on `listener` until it errors. `state` supplies the
/// live I2P status (mode / phase / SAM port); `book_path` is the persisted
/// jump-link addressbook.
pub async fn serve(
    listener: TcpListener,
    state: Arc<epix_ui::AppState>,
    book_path: PathBuf,
) -> std::io::Result<()> {
    let dialer = epix_i2p::EepsiteDialer::new();
    let book = Arc::new(Addressbook::load(book_path).await);
    loop {
        let (sock, _peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let state = state.clone();
        let dialer = dialer.clone();
        let book = book.clone();
        tokio::spawn(async move {
            let _ = handle_conn(sock, state, dialer, book).await;
        });
    }
}

async fn handle_conn(
    mut sock: TcpStream,
    state: Arc<epix_ui::AppState>,
    dialer: epix_i2p::EepsiteDialer,
    book: Arc<Addressbook>,
) -> Result<(), String> {
    let (head, leftover) = read_head(&mut sock).await?;
    let head_text = String::from_utf8_lossy(&head).to_string();
    let request_line = head_text.lines().next().unwrap_or("").to_string();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    // I2P must be on and its SAM bridge up before anything can be dialed.
    let sam_port = match i2p_gate(&state).await {
        Ok(port) => port,
        Err(page) => return respond_html(&mut sock, &page.0, &page.1, &page.2).await,
    };

    if method == "CONNECT" {
        let host = target.split(':').next().unwrap_or("").to_ascii_lowercase();
        let dest = match resolve(&book, sam_port, &host).await {
            Ok(d) => d,
            Err(page) => return respond_html(&mut sock, &page.0, &page.1, &page.2).await,
        };
        let mut upstream = tokio::time::timeout(CONNECT_TIMEOUT, dialer.connect(sam_port, &dest))
            .await
            .map_err(|_| "connect timeout".to_string())?
            .map_err(|e| e.to_string())?;
        sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .map_err(|e| e.to_string())?;
        if !leftover.is_empty() {
            upstream.write_all(&leftover).await.map_err(|e| e.to_string())?;
        }
        let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
        return Ok(());
    }

    // Absolute-form plain http.
    let Some((host, port, path_query)) = parse_absolute(&target) else {
        return respond_html(
            &mut sock,
            "502 Bad Gateway",
            "Unsupported request",
            "This proxy only serves .i2p sites.",
        )
        .await;
    };
    if !host.ends_with(".i2p") {
        return respond_html(
            &mut sock,
            "502 Bad Gateway",
            "Not an eepsite",
            &format!("{host} is not a .i2p host."),
        )
        .await;
    }

    // A jump link: persist the supplied destination for this host, then
    // redirect to the clean URL - from now on the bare hostname works.
    if let Some((dest, clean)) = split_addresshelper(&path_query) {
        book.put(&host, &dest).await;
        let location = format!("http://{host}{clean}");
        let resp = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        return sock.write_all(resp.as_bytes()).await.map_err(|e| e.to_string());
    }

    let dest = match resolve(&book, sam_port, &host).await {
        Ok(d) => d,
        Err(page) => return respond_html(&mut sock, &page.0, &page.1, &page.2).await,
    };
    // A failed dial renders a page, not a dropped socket: the difference
    // between "site down / stale saved address" and a browser network error.
    let mut upstream = match tokio::time::timeout(CONNECT_TIMEOUT, dialer.connect(sam_port, &dest))
        .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return respond_html(
                &mut sock,
                "502 Bad Gateway",
                "Eepsite unreachable",
                &format!(
                    "{host} could not be reached over I2P: {e}. The site may be offline, or its \
                     saved address may be stale - opening a fresh ?i2paddresshelper= link \
                     replaces it."
                ),
            )
            .await;
        }
        Err(_) => {
            return respond_html(
                &mut sock,
                "504 Gateway Timeout",
                "Eepsite timed out",
                &format!(
                    "{host} did not answer within {}s. I2P tunnels may still be building - \
                     retry in a minute.",
                    CONNECT_TIMEOUT.as_secs()
                ),
            )
            .await;
        }
    };

    // Forward in origin-form with hop-by-hop headers stripped and the
    // connection forced closed (one request per SAM stream keeps this simple).
    let out_head = origin_head(&method, &path_query, &host, port, &head_text);
    upstream.write_all(out_head.as_bytes()).await.map_err(|e| e.to_string())?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await.map_err(|e| e.to_string())?;
    }
    let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
    Ok(())
}

/// The SAM port when I2P can serve requests, else the error page to show:
/// `(status line, title, body)`.
async fn i2p_gate(state: &epix_ui::AppState) -> Result<u16, (String, String, String)> {
    let s = state.i2p_status().await;
    let get = |k: &str| s.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mode = get("mode");
    if mode.is_empty() || mode == "disable" {
        return Err((
            "503 Service Unavailable".into(),
            "I2P is disabled".into(),
            "Enable I2P on the Config page (dashboard.epix → Config), then try again.".into(),
        ));
    }
    let sam_port = s.get("sam_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    if sam_port == 0 {
        let phase = get("phase");
        return Err((
            "503 Service Unavailable".into(),
            "I2P is starting".into(),
            format!("The I2P router is not ready yet ({phase}). Retry in a moment."),
        ));
    }
    Ok(sam_port)
}

/// Resolve `host` to something `STREAM CONNECT` accepts: local addressbook
/// first (jump-link destinations), then the host itself for `.b32.i2p`
/// (self-certifying - the router does the leaseset lookup during the connect;
/// its `NAMING LOOKUP` only serves the local hosts file and refuses b32
/// instantly, which is also how peer dials work), then the naming service for
/// plain hostnames. An unknown plain hostname explains jump links.
async fn resolve(
    book: &Addressbook,
    sam_port: u16,
    host: &str,
) -> Result<String, (String, String, String)> {
    if let Some(dest) = book.get(host).await {
        return Ok(dest);
    }
    if host.ends_with(".b32.i2p") {
        return Ok(host.to_string());
    }
    match epix_i2p::EepsiteDialer::lookup(sam_port, host).await {
        Ok(dest) => Ok(dest),
        Err(_) => Err((
            "404 Not Found".into(),
            "Unknown eepsite name".into(),
            format!(
                "No I2P destination is known for {host}. Open it once through an address-helper \
                 link (a URL with ?i2paddresshelper=…, offered by I2P jump services) or use its \
                 .b32.i2p address - after that, the plain name works here."
            ),
        )),
    }
}

/// Read one HTTP request head; returns `(head bytes incl. blank line, any
/// body/pipeline bytes read past it)`.
async fn read_head(sock: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = find_head_end(&buf) {
            let leftover = buf.split_off(end);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large".into());
        }
        let n = sock.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before request head".into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse an absolute-form target `http://host[:port]/path?query` into
/// `(host lowercased, port, path?query)`.
fn parse_absolute(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 80),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_ascii_lowercase(), port, path_query))
}

/// Extract an `i2paddresshelper` destination from `path?query`; returns the
/// (percent-decoded) destination and the URL with that one parameter removed.
fn split_addresshelper(path_query: &str) -> Option<(String, String)> {
    let (path, query) = path_query.split_once('?')?;
    let mut dest = None;
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| match pair.split_once('=') {
            Some(("i2paddresshelper", v)) if !v.is_empty() => {
                dest.get_or_insert_with(|| percent_decode(v));
                false
            }
            _ => true,
        })
        .collect();
    let dest = dest?;
    let clean = if kept.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", kept.join("&"))
    };
    Some((dest, clean))
}

/// Minimal percent-decoding (I2P destinations are base64 over `A-Za-z0-9-~`,
/// with `=` padding sometimes encoded as `%3D`). Invalid escapes pass through.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Rebuild the request head in origin-form: hop-by-hop headers stripped, Host
/// pinned, the connection forced closed.
fn origin_head(method: &str, path_query: &str, host: &str, port: u16, head_text: &str) -> String {
    const HOP: [&str; 7] = [
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-authenticate",
    ];
    let mut out = format!("{method} {path_query} HTTP/1.1\r\n");
    let host_header =
        if port == 80 { format!("Host: {host}\r\n") } else { format!("Host: {host}:{port}\r\n") };
    out.push_str(&host_header);
    for line in head_text.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if name == "host" || HOP.contains(&name.as_str()) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

async fn respond_html(
    sock: &mut TcpStream,
    status: &str,
    title: &str,
    body: &str,
) -> Result<(), String> {
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>\
         <style>body{{font-family:system-ui,sans-serif;background:#16171d;color:#e8e8ea;\
         display:grid;place-items:center;min-height:90vh;margin:0}}\
         main{{max-width:34rem;padding:2rem}}h1{{font-size:1.3rem}}\
         p{{color:#b9bac1;line-height:1.5;word-break:break-word}}</style></head>\
         <body><main><h1>{title}</h1><p>{body}</p></main></body></html>"
    );
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nRetry-After: 5\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    sock.write_all(resp.as_bytes()).await.map_err(|e| e.to_string())
}

/// The persisted jump-link addressbook: `{host: destination}` JSON, written
/// atomically on every addition. Local convenience state, not key material.
struct Addressbook {
    path: PathBuf,
    map: tokio::sync::Mutex<HashMap<String, String>>,
}

impl Addressbook {
    async fn load(path: PathBuf) -> Self {
        let map = tokio::fs::read(&path)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        Self { path, map: tokio::sync::Mutex::new(map) }
    }

    async fn get(&self, host: &str) -> Option<String> {
        self.map.lock().await.get(host).cloned()
    }

    async fn put(&self, host: &str, dest: &str) {
        let mut map = self.map.lock().await;
        map.insert(host.to_string(), dest.to_string());
        let json = serde_json::to_vec_pretty(&*map).unwrap_or_default();
        drop(map);
        if let Some(parent) = self.path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let tmp = self.path.with_extension("json.tmp");
        if tokio::fs::write(&tmp, &json).await.is_ok() {
            let _ = tokio::fs::rename(&tmp, &self.path).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_form_parses_host_port_path() {
        assert_eq!(
            parse_absolute("http://web.telegram.i2p/a/b?x=1"),
            Some(("web.telegram.i2p".into(), 80, "/a/b?x=1".into()))
        );
        assert_eq!(
            parse_absolute("http://Site.I2P:8080"),
            Some(("site.i2p".into(), 8080, "/".into()))
        );
        assert_eq!(parse_absolute("https://site.i2p/"), None);
        assert_eq!(parse_absolute("/origin-form"), None);
    }

    #[test]
    fn addresshelper_is_extracted_and_stripped() {
        // The helper parameter is removed; other params survive.
        let (dest, clean) = split_addresshelper("/?i2paddresshelper=AAAA~-x%3D&q=1").unwrap();
        assert_eq!(dest, "AAAA~-x=");
        assert_eq!(clean, "/?q=1");
        // Alone, the query is dropped entirely.
        let (_, clean) = split_addresshelper("/page?i2paddresshelper=AAAA").unwrap();
        assert_eq!(clean, "/page");
        // No helper, no match.
        assert!(split_addresshelper("/page?q=1").is_none());
        assert!(split_addresshelper("/page").is_none());
    }

    #[test]
    fn origin_head_strips_hop_headers_and_pins_host() {
        let head = "GET http://site.i2p/x HTTP/1.1\r\nHost: proxyhost\r\n\
                    Proxy-Connection: keep-alive\r\nAccept: text/html\r\n\r\n";
        let out = origin_head("GET", "/x", "site.i2p", 80, head);
        assert!(out.starts_with("GET /x HTTP/1.1\r\nHost: site.i2p\r\n"));
        assert!(out.contains("Accept: text/html\r\n"));
        assert!(!out.to_lowercase().contains("proxy-connection"));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
        // A non-default port rides in the Host header.
        let out = origin_head("GET", "/", "site.i2p", 8080, head);
        assert!(out.contains("Host: site.i2p:8080\r\n"));
    }

    #[test]
    fn head_end_detection_and_leftover_split() {
        let buf = b"GET / HTTP/1.1\r\n\r\nBODY";
        let end = find_head_end(buf).unwrap();
        assert_eq!(&buf[end..], b"BODY");
        assert_eq!(find_head_end(b"partial\r\n"), None);
    }

    #[tokio::test]
    async fn addressbook_persists_across_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eepsite-hosts.json");
        let book = Addressbook::load(path.clone()).await;
        assert_eq!(book.get("web.telegram.i2p").await, None);
        book.put("web.telegram.i2p", "XeeEcrjZ...").await;
        let reloaded = Addressbook::load(path).await;
        assert_eq!(reloaded.get("web.telegram.i2p").await.as_deref(), Some("XeeEcrjZ..."));
    }
}
