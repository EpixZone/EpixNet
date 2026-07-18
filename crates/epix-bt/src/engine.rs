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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::http::{self, HttpError};
use crate::magnet::{self, MagnetError};
use crate::metainfo::{self, MetaError, MetaInfo};
use crate::store::{PieceStore, StoreError};
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
    #[error("magnet has no `xs=` .torrent source (peer metadata not yet supported)")]
    NoMetaSource,
    #[error("unsupported source: expected a magnet: link or an http(s) .torrent URL")]
    UnsupportedSource,
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

/// A single torrent being streamed: its metainfo, the file we serve, the store
/// holding verified bytes, and the web-seed source feeding them.
struct Session {
    meta: Arc<MetaInfo>,
    webseed: WebSeed,
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
        let resolved = resolve_source(source_uri)?;
        // Fetch the .torrent (from a magnet `xs=` or the direct URL), recording
        // which URL delivered it so we can derive an implicit web seed from it.
        let (meta, seeds_from_torrent, from_url) =
            fetch_metainfo(&resolved.torrent_urls, resolved.expected_hash).await?;
        let meta = Arc::new(meta);

        // Web seeds, in priority order: explicit `ws=`, then the torrent's own
        // `url-list`, then - crucially for a bare `.torrent` with neither - the
        // directory the `.torrent` itself came from. A file hosted next to its
        // `.torrent` (…/ToS/x.torrent ↔ …/ToS/x.webm) is then streamable with no
        // magnet and no declared seed.
        let mut bases = resolved.web_seeds.clone();
        for s in seeds_from_torrent {
            push_unique(&mut bases, s);
        }
        if let Some(dir) = url_dir(&from_url) {
            push_unique(&mut bases, dir);
        }
        if bases.is_empty() {
            return Err(EngineError::NoWebSeed);
        }

        let (primary_index, primary) = meta.primary_file();
        let (file_start, file_len) = meta.file_span(primary_index);
        let content_type = content_type_for(&primary.display_path()).to_string();

        // Store under <cache>/<info-hash>/<sanitized file name>.
        let dir = cache_dir.join(meta.info_hash_hex());
        tokio::fs::create_dir_all(&dir).await.map_err(StoreError::from)?;
        let fname = primary.path.last().cloned().unwrap_or_else(|| "video".to_string());
        let store = PieceStore::open(&dir.join(fname), file_len, meta.piece_count()).await?;

        let client = http::client(PIECE_TIMEOUT)?;
        let webseed = WebSeed::new(client, bases, meta.clone());

        let fetch_locks = (0..FETCH_SHARDS).map(|_| tokio::sync::Mutex::new(())).collect();

        Ok(Session { meta, webseed, store, file_start, file_len, content_type, fetch_locks })
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
        let data = self.webseed.read_range(piece_start, piece_size).await?;
        if !self.meta.verify_piece(p, &data) {
            // A web seed served bytes that don't match the torrent's hash - do
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

/// A source resolved to what the engine needs: where to fetch the `.torrent`,
/// any explicit web seeds, and (for a magnet) the info-hash to check the fetched
/// metainfo against.
struct ResolvedSource {
    torrent_urls: Vec<String>,
    web_seeds: Vec<String>,
    expected_hash: Option<[u8; 20]>,
}

/// Resolve a user-supplied source string to a [`ResolvedSource`]. Accepts a
/// `magnet:?…` link (needs an `xs=` to fetch metainfo, since there's no peer
/// wire yet) or a direct `http(s)://…​.torrent` URL (the torrent is its own
/// authority, so no info-hash to check).
fn resolve_source(uri: &str) -> Result<ResolvedSource, EngineError> {
    let uri = uri.trim();
    if uri.starts_with("magnet:?") {
        let m = magnet::parse(uri)?;
        if m.sources.is_empty() {
            return Err(EngineError::NoMetaSource);
        }
        Ok(ResolvedSource {
            torrent_urls: m.sources,
            web_seeds: m.web_seeds,
            expected_hash: Some(m.info_hash),
        })
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        Ok(ResolvedSource {
            torrent_urls: vec![uri.to_string()],
            web_seeds: Vec::new(),
            expected_hash: None,
        })
    } else {
        Err(EngineError::UnsupportedSource)
    }
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
    Err(last.unwrap_or(EngineError::NoMetaSource))
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
    fn resolve_source_accepts_magnet_and_torrent_url() {
        // A magnet with an xs resolves with the info-hash to check against.
        let m = resolve_source(
            "magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec\
             &xs=https%3A%2F%2Fh%2Fx.torrent",
        )
        .unwrap();
        assert_eq!(m.torrent_urls, vec!["https://h/x.torrent"]);
        assert!(m.expected_hash.is_some());

        // A bare .torrent URL resolves with no expected hash (it's its own
        // authority) and no explicit web seed.
        let t = resolve_source("http://h/ToS/x.torrent").unwrap();
        assert_eq!(t.torrent_urls, vec!["http://h/ToS/x.torrent"]);
        assert!(t.expected_hash.is_none());
        assert!(t.web_seeds.is_empty());

        // A magnet with no xs can't fetch metadata yet.
        assert!(matches!(
            resolve_source("magnet:?xt=urn:btih:209c8226b299b308beaf2b9cd3fb49212dbd13ec"),
            Err(EngineError::NoMetaSource)
        ));
        // Neither a magnet nor an http URL.
        assert!(matches!(
            resolve_source("ftp://nope"),
            Err(EngineError::UnsupportedSource)
        ));
    }
}
