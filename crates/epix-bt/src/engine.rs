//! The streaming engine: magnet in, verified video bytes out.
//!
//! A xite's `<video>` points at the node's local Range endpoint; the node hands
//! the magnet here. The engine, once per info-hash, fetches the `.torrent` from
//! an `xs=` source (so it has the piece hashes and file layout), picks the
//! largest file to stream, and opens a sparse [`PieceStore`] for it. Each Range
//! request then pulls exactly the pieces covering the requested window from the
//! [`WebSeed`], verifies each against its SHA-1, writes it, and returns the
//! bytes - sequential fetch, so playback order is the fetch order (what a video
//! player needs, unlike a downloader's rarest-first).
//!
//! Everything the engine fetches goes through [`crate::http`], i.e. the node's
//! Tor SOCKS proxy when Tor is on - the node streams, the xite page never
//! touches BitTorrent.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::http::{self, HttpError};
use crate::magnet::{self, MagnetError};
use crate::metainfo::{self, MetaError, MetaInfo};
use crate::store::{PieceStore, StoreError};
use crate::swarm::{Swarm, SwarmError};
use crate::webseed::{WebSeed, WebSeedError};

/// Max bytes returned for one Range request. Streaming means fetching only the
/// playback window on demand; without a cap, an open-ended `bytes=0-` would
/// pull the whole (multi-hundred-MB) file up front. The player re-requests as
/// it plays.
const MAX_CHUNK: u64 = 4 * 1024 * 1024;
/// Sharded per-piece fetch locks: two requests wanting the same piece collapse
/// to one fetch; different pieces rarely collide. Small and fixed.
const FETCH_SHARDS: usize = 16;
const TORRENT_TIMEOUT: Duration = Duration::from_secs(60);
const PIECE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Magnet(#[from] MagnetError),
    #[error(transparent)]
    Meta(#[from] MetaError),
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error(transparent)]
    WebSeed(#[from] WebSeedError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Swarm(#[from] SwarmError),
    #[error("this magnet needs peer discovery (mainline DHT over UDP), which Tor cannot carry; set Tor to enable or disable to stream it")]
    SwarmDisabled,
    #[error("could not fetch a usable .torrent from any source")]
    MetaFetchFailed,
    #[error("unsupported source: expected a magnet: link or an http(s) .torrent URL")]
    UnsupportedSource,
    #[error("internal: info-hash did not yield a valid cache key")]
    BadInfoHash,
    #[error("no reachable web seed (`ws=`/url-list) to stream from over the current transport")]
    NoWebSeed,
    #[error("requested range is not satisfiable")]
    Unsatisfiable,
}

/// One served window: the bytes plus what the node needs to build a 206.
pub struct Served {
    /// Total length of the streamed file (the `Content-Range` denominator).
    pub total: u64,
    /// First byte offset returned (inclusive).
    pub start: u64,
    /// Last byte offset returned (inclusive).
    pub end: u64,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// Holds live streaming sessions keyed by the source URI (a magnet or a
/// `.torrent` URL). One per node.
pub struct Engine {
    cache_dir: PathBuf,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

impl Engine {
    /// `cache_dir` is where streamed files are stored (e.g. `<data>/bt`).
    pub fn new(cache_dir: impl Into<PathBuf>) -> Engine {
        Engine { cache_dir: cache_dir.into(), sessions: Mutex::new(HashMap::new()) }
    }

    /// Stream the window named by `range_header` (an HTTP `Range` value like
    /// `bytes=0-`, or `None` for the start of the file) from `source_uri`, which
    /// is either a `magnet:?…` link or a direct `http(s)://…​.torrent` URL.
    pub async fn stream(
        &self,
        source_uri: &str,
        range_header: Option<&str>,
    ) -> Result<Served, EngineError> {
        let session = self.session_for(source_uri).await?;
        session.serve(range_header).await
    }

    /// Get the existing session for this source, or build one. Building fetches
    /// the `.torrent`; we don't hold the map lock across that await. Keyed by
    /// the source string so both a magnet and a `.torrent` URL work.
    async fn session_for(&self, source_uri: &str) -> Result<Arc<Session>, EngineError> {
        if let Some(s) = self.sessions.lock().unwrap().get(source_uri).cloned() {
            return Ok(s);
        }
        let session = Arc::new(Session::start(source_uri, &self.cache_dir).await?);
        let mut map = self.sessions.lock().unwrap();
        // Another request may have built it while we fetched; prefer theirs.
        Ok(map.entry(source_uri.to_string()).or_insert(session).clone())
    }
}

/// Where a session's verified bytes come from: an HTTP web seed, or the peer
/// swarm (mainline DHT discovery + peer wire). Both expose the same
/// `read_range(global_off, len)` over the torrent's data, so [`Session`] is
/// source-agnostic.
enum Source {
    Web(WebSeed),
    Swarm(Swarm),
}

impl Source {
    async fn read_range(&self, global_off: u64, len: u64) -> Result<Vec<u8>, EngineError> {
        match self {
            Source::Web(w) => Ok(w.read_range(global_off, len).await?),
            Source::Swarm(s) => Ok(s.read_range(global_off, len).await?),
        }
    }
}

/// A single torrent being streamed: its metainfo, the file we serve, the store
/// holding verified bytes, and the source (web seed or swarm) feeding them.
struct Session {
    meta: Arc<MetaInfo>,
    source: Source,
    store: PieceStore,
    /// Global offset of the streamed file within the torrent's data.
    file_start: u64,
    /// Length of the streamed file.
    file_len: u64,
    content_type: String,
    fetch_locks: Vec<tokio::sync::Mutex<()>>,
}

impl Session {
    async fn start(source_uri: &str, cache_dir: &Path) -> Result<Session, EngineError> {
        match resolve_source(source_uri)? {
            Resolved::Http { torrent_urls, web_seeds, expected_hash } => {
                Session::start_web(torrent_urls, web_seeds, expected_hash, cache_dir).await
            }
            Resolved::Bare { info_hash } => Session::start_swarm(info_hash, cache_dir).await,
        }
    }

    /// Web-seed path: fetch the `.torrent`, derive HTTP seeds, stream via BEP19.
    async fn start_web(
        torrent_urls: Vec<String>,
        web_seeds: Vec<String>,
        expected_hash: Option<[u8; 20]>,
        cache_dir: &Path,
    ) -> Result<Session, EngineError> {
        // Fetch the .torrent (from a magnet `xs=` or the direct URL), recording
        // which URL delivered it so we can derive an implicit web seed from it.
        let (meta, seeds_from_torrent, from_url) =
            fetch_metainfo(&torrent_urls, expected_hash).await?;
        let meta = Arc::new(meta);

        // Web seeds, in priority order: explicit `ws=`, then the torrent's own
        // `url-list`, then - crucially for a bare `.torrent` with neither - the
        // directory the `.torrent` itself came from. A file hosted next to its
        // `.torrent` (…/ToS/x.torrent ↔ …/ToS/x.webm) is then streamable with no
        // magnet and no declared seed.
        let mut bases = web_seeds;
        for s in seeds_from_torrent {
            push_unique(&mut bases, s);
        }
        if let Some(dir) = url_dir(&from_url) {
            push_unique(&mut bases, dir);
        }
        if bases.is_empty() {
            return Err(EngineError::NoWebSeed);
        }

        let (store, file_start, file_len, content_type, fetch_locks) =
            open_store(&meta, cache_dir).await?;
        let client = http::client(PIECE_TIMEOUT)?;
        let webseed = WebSeed::new(client, bases, meta.clone());
        Ok(Session {
            meta,
            source: Source::Web(webseed),
            store,
            file_start,
            file_len,
            content_type,
            fetch_locks,
        })
    }

    /// Swarm path (bare magnet): find peers on the mainline DHT, pull the
    /// metainfo over BEP9, then stream pieces from the peer wire. Refused in
    /// Tor-`always` mode, where UDP (and thus DHT discovery) is unavailable.
    async fn start_swarm(info_hash: [u8; 20], cache_dir: &Path) -> Result<Session, EngineError> {
        if !http::swarm_allowed() {
            return Err(EngineError::SwarmDisabled);
        }
        let socks = http::peer_socks().and_then(|s| s.parse::<SocketAddr>().ok());
        let swarm = Swarm::connect(info_hash, socks).await?;
        let meta = swarm.metainfo();

        let (store, file_start, file_len, content_type, fetch_locks) =
            open_store(&meta, cache_dir).await?;
        Ok(Session {
            meta,
            source: Source::Swarm(swarm),
            store,
            file_start,
            file_len,
            content_type,
            fetch_locks,
        })
    }

    async fn serve(&self, range_header: Option<&str>) -> Result<Served, EngineError> {
        let total = self.file_len;
        let (start, req_end) = match range_header.and_then(|h| parse_range(h, total)) {
            Some(pair) => (pair.0, Some(pair.1)),
            None => {
                // An explicit but unsatisfiable Range (past EOF) is an error;
                // a missing/blank Range just means "from the start".
                if range_header.map(str::trim).is_some_and(|h| h.starts_with("bytes=")) {
                    return Err(EngineError::Unsatisfiable);
                }
                (0, None)
            }
        };
        let hard_end = total - 1;
        // Cap the window so one request never pulls the whole file.
        let end = req_end.unwrap_or(hard_end).min(hard_end).min(start + MAX_CHUNK - 1);

        // Fetch+verify every piece covering the (global) window.
        let g0 = self.file_start + start;
        let g1 = self.file_start + end;
        let plen = self.meta.piece_length;
        let p0 = (g0 / plen) as usize;
        let p1 = (g1 / plen) as usize;
        for p in p0..=p1 {
            self.ensure_piece(p).await?;
        }

        let bytes = self.store.read_at(start, (end - start + 1) as usize).await?;
        Ok(Served {
            total,
            start,
            end,
            content_type: self.content_type.clone(),
            bytes,
        })
    }

    /// Ensure piece `p` is fetched, verified, and its file-overlapping bytes are
    /// written to the store. Idempotent; deduped across concurrent callers.
    async fn ensure_piece(&self, p: usize) -> Result<(), EngineError> {
        if self.store.has(p) {
            return Ok(());
        }
        let _guard = self.fetch_locks[p % FETCH_SHARDS].lock().await;
        if self.store.has(p) {
            return Ok(());
        }

        let piece_start = p as u64 * self.meta.piece_length;
        let piece_size = self.meta.piece_size(p);
        let data = self.source.read_range(piece_start, piece_size).await?;
        if !self.meta.verify_piece(p, &data) {
            // The source served bytes that don't match the torrent's hash - do
            // not store them; the caller surfaces the error.
            return Err(WebSeedError::NoSource.into());
        }

        // Write only the portion of the piece that lies in the streamed file.
        let piece_end = piece_start + piece_size;
        let ov_start = piece_start.max(self.file_start);
        let ov_end = piece_end.min(self.file_start + self.file_len);
        if ov_start < ov_end {
            let src = (ov_start - piece_start) as usize..(ov_end - piece_start) as usize;
            let dst = ov_start - self.file_start;
            self.store.write_at(dst, &data[src]).await?;
        }
        self.store.mark(p);
        Ok(())
    }
}

/// A source resolved to how the engine will stream it.
enum Resolved {
    /// An HTTP path: a `.torrent` to fetch (a magnet `xs=` or a direct URL)
    /// plus any declared web seeds, and the info-hash to check when known.
    Http { torrent_urls: Vec<String>, web_seeds: Vec<String>, expected_hash: Option<[u8; 20]> },
    /// A bare magnet with no `.torrent` source: discover peers on the DHT and
    /// pull the metainfo + pieces over the peer wire (the swarm path).
    Bare { info_hash: [u8; 20] },
}

/// Resolve a user-supplied source string. A `magnet:?…` with an `xs=`/`as=`
/// `.torrent` source takes the HTTP path; a bare magnet (info-hash only) takes
/// the swarm path; a direct `http(s)://…​.torrent` URL is its own authority.
fn resolve_source(uri: &str) -> Result<Resolved, EngineError> {
    let uri = uri.trim();
    if uri.starts_with("magnet:?") {
        let m = magnet::parse(uri)?;
        // Without a `.torrent` source there are no piece hashes to fetch over
        // HTTP, so even a `ws=`-only magnet must get its metainfo from peers.
        if m.sources.is_empty() {
            Ok(Resolved::Bare { info_hash: m.info_hash })
        } else {
            Ok(Resolved::Http {
                torrent_urls: m.sources,
                web_seeds: m.web_seeds,
                expected_hash: Some(m.info_hash),
            })
        }
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        Ok(Resolved::Http {
            torrent_urls: vec![uri.to_string()],
            web_seeds: Vec::new(),
            expected_hash: None,
        })
    } else {
        Err(EngineError::UnsupportedSource)
    }
}

/// Open the sparse [`PieceStore`] for the metainfo's primary (largest) file and
/// return everything a [`Session`] needs alongside its source. Shared by the
/// web-seed and swarm paths.
async fn open_store(
    meta: &Arc<MetaInfo>,
    cache_dir: &Path,
) -> Result<(PieceStore, u64, u64, String, Vec<tokio::sync::Mutex<()>>), EngineError> {
    let (primary_index, primary) = meta.primary_file();
    let (file_start, file_len) = meta.file_span(primary_index);
    // The torrent-supplied file name is used ONLY to choose the Content-Type -
    // never to build a filesystem path.
    let content_type = content_type_for(&primary.display_path()).to_string();

    // The cache path is built only from the info-hash and a constant file name,
    // so no torrent-controlled string can steer it out of the cache dir.
    // `cache_dir_name` encodes the fixed `[u8; 20]` info-hash through a constant
    // hex table, yielding exactly 40 chars of `[0-9a-f]` - no separators, no `..`.
    let key = meta.cache_dir_name();
    if key.len() != 40 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(EngineError::BadInfoHash);
    }
    // Reject any parent-dir escape in the assembled path before it reaches the
    // filesystem, and rebuild the path from the checked string so the guard
    // covers every downstream use. Nothing here can produce a `..`, but this is
    // the explicit no-traversal barrier - for a reader and for the lint.
    let dir_str = cache_dir.join(&key).to_string_lossy().into_owned();
    if dir_str.contains("..") {
        return Err(EngineError::BadInfoHash);
    }
    let dir = PathBuf::from(dir_str);
    tokio::fs::create_dir_all(&dir).await.map_err(StoreError::from)?;
    let store = PieceStore::open(&dir.join("media"), file_len, meta.piece_count()).await?;

    let fetch_locks = (0..FETCH_SHARDS).map(|_| tokio::sync::Mutex::new(())).collect();
    Ok((store, file_start, file_len, content_type, fetch_locks))
}

/// Fetch and parse the metainfo from the given `.torrent` URLs (trying each in
/// order), returning it plus any `url-list` web seeds and the URL that
/// delivered it. `expected` (a magnet's `xt`) is checked when present.
async fn fetch_metainfo(
    urls: &[String],
    expected: Option<[u8; 20]>,
) -> Result<(MetaInfo, Vec<String>, String), EngineError> {
    http::egress_ok()?;
    let client = http::client(TORRENT_TIMEOUT)?;
    let mut last: Option<EngineError> = None;
    for url in urls {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(body) => match MetaInfo::parse(&body, expected) {
                    Ok(meta) => {
                        let seeds = metainfo::webseeds_from_torrent(&body);
                        return Ok((meta, seeds, url.clone()));
                    }
                    Err(e) => last = Some(e.into()),
                },
                Err(e) => last = Some(HttpError::Request(e.to_string()).into()),
            },
            Ok(resp) => last = Some(HttpError::Status(resp.status().as_u16()).into()),
            Err(e) => last = Some(HttpError::Request(e.to_string()).into()),
        }
    }
    Err(last.unwrap_or(EngineError::MetaFetchFailed))
}

/// Push `s` onto `v` if not already present (small lists, order-preserving).
fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

/// The directory portion of an `http(s)` URL, with the trailing slash - i.e. a
/// web-seed base. `http://h/ToS/x.torrent` → `http://h/ToS/`. `None` when the
/// URL has no path segment (nothing to strip a filename from).
fn url_dir(url: &str) -> Option<String> {
    let scheme_end = url.find("://")? + 3;
    let path_slash = url[scheme_end..].rfind('/')?;
    Some(url[..scheme_end + path_slash + 1].to_string())
}

/// Parse an HTTP `Range` header (single range only) against `total`, returning
/// an inclusive `[start, end]`. `None` if malformed or unsatisfiable.
fn parse_range(header: &str, total: u64) -> Option<(u64, u64)> {
    let spec = header.trim().strip_prefix("bytes=")?.trim();
    // We serve one range; ignore any after the first.
    let spec = spec.split(',').next()?.trim();
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if a.is_empty() {
        // Suffix range: last N bytes.
        let n: u64 = b.parse().ok()?;
        if n == 0 || total == 0 {
            return None;
        }
        let start = total.saturating_sub(n);
        return Some((start, total - 1));
    }
    let start: u64 = a.parse().ok()?;
    if start >= total {
        return None; // unsatisfiable
    }
    let end = if b.is_empty() { total - 1 } else { b.parse::<u64>().ok()?.min(total - 1) };
    if end < start {
        return None;
    }
    Some((start, end))
}

/// A conservative MIME type from the streamed file's extension. Unknown types
/// fall back to `application/octet-stream`; the player still tries.
fn content_type_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "mov" => "video/quicktime",
        "ogv" => "video/ogg",
        "m4a" => "audio/mp4",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" => "audio/ogg",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges() {
        assert_eq!(parse_range("bytes=0-", 100), Some((0, 99)));
        assert_eq!(parse_range("bytes=10-19", 100), Some((10, 19)));
        assert_eq!(parse_range("bytes=90-1000", 100), Some((90, 99))); // clamp end
        assert_eq!(parse_range("bytes=-20", 100), Some((80, 99))); // suffix
        assert_eq!(parse_range("bytes=100-", 100), None); // start past EOF
        assert_eq!(parse_range("bytes=50-40", 100), None); // end<start
        assert_eq!(parse_range("nonsense", 100), None);
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type_for("Tears of Steel.mp4"), "video/mp4");
        assert_eq!(content_type_for("clip.WEBM"), "video/webm");
        assert_eq!(content_type_for("noext"), "application/octet-stream");
    }

    #[test]
    fn url_dir_strips_the_filename() {
        assert_eq!(
            url_dir("http://h/ToS/x.torrent").as_deref(),
            Some("http://h/ToS/")
        );
        assert_eq!(url_dir("https://h/x.torrent").as_deref(), Some("https://h/"));
        // No path segment to strip a filename from.
        assert_eq!(url_dir("http://h"), None);
    }

    #[test]
    fn resolve_source_routes_http_and_swarm() {
        // A magnet with an xs takes the HTTP path with the info-hash to check.
        let m = resolve_source(
            "magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec\
             &xs=https%3A%2F%2Fh%2Fx.torrent",
        )
        .unwrap();
        match m {
            Resolved::Http { torrent_urls, expected_hash, .. } => {
                assert_eq!(torrent_urls, vec!["https://h/x.torrent"]);
                assert!(expected_hash.is_some());
            }
            _ => panic!("expected Http"),
        }

        // A bare .torrent URL: HTTP path, no expected hash, no web seed.
        match resolve_source("http://h/ToS/x.torrent").unwrap() {
            Resolved::Http { torrent_urls, web_seeds, expected_hash } => {
                assert_eq!(torrent_urls, vec!["http://h/ToS/x.torrent"]);
                assert!(expected_hash.is_none());
                assert!(web_seeds.is_empty());
            }
            _ => panic!("expected Http"),
        }

        // A bare magnet (no xs) takes the swarm path, carrying its info-hash.
        match resolve_source("magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec")
            .unwrap()
        {
            Resolved::Bare { info_hash } => {
                assert_eq!(hex::encode(info_hash), "209c8226b299b308beaf2b9cd3fb49212dbd13ec");
            }
            _ => panic!("expected Bare"),
        }
        // Neither a magnet nor an http URL.
        assert!(matches!(resolve_source("ftp://nope"), Err(EngineError::UnsupportedSource)));
    }
}
