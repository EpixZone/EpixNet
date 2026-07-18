//! HTTP/S web-seed source (BEP19, GetRight style).
//!
//! A web seed is a plain HTTP host that serves the torrent's files by URL, so a
//! client with no peers can still fetch data with ordinary Range requests. Over
//! Tor - where UDP trackers and the DHT are unreachable - this is the data path
//! that actually works, which is why it is the engine's first source.
//!
//! URL construction (BEP19):
//! - multi-file: `<base>/<name>/<path components...>`
//! - single-file: `<base><name>` when the base ends in `/`, else the base is
//!   the file URL itself.
//!
//! A piece can straddle file boundaries, so [`WebSeed::read_range`] splits a
//! global byte range across the files it covers, issues one Range request per
//! file (trying each base until one answers with the bytes), and concatenates.

use std::sync::Arc;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use reqwest::header::{CONTENT_RANGE, RANGE};

use crate::http::{self, HttpError};
use crate::metainfo::MetaInfo;

/// Encode a single path segment: keep the URL-unreserved set (alphanumerics and
/// `- . _ ~`) and percent-encode everything else, including spaces and the
/// delimiters that would otherwise break out of the segment.
const SEG: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\')
    .add(b'^')
    .add(b'[')
    .add(b']')
    .add(b'|')
    .add(b'+')
    .add(b';')
    .add(b'=')
    .add(b'@')
    .add(b':');

fn enc(seg: &str) -> String {
    utf8_percent_encode(seg, SEG).to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum WebSeedError {
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error("no web seed returned the requested bytes")]
    NoSource,
    #[error("web seed returned {got} bytes, expected {want}")]
    ShortRead { got: usize, want: usize },
}

pub struct WebSeed {
    client: reqwest::Client,
    /// Web-seed base URLs, tried in order.
    bases: Vec<String>,
    meta: Arc<MetaInfo>,
}

impl WebSeed {
    pub fn new(client: reqwest::Client, bases: Vec<String>, meta: Arc<MetaInfo>) -> WebSeed {
        WebSeed { client, bases, meta }
    }

    pub fn has_bases(&self) -> bool {
        !self.bases.is_empty()
    }

    /// The full URL of file `i` under `base`, per the BEP19 rules.
    fn file_url(&self, base: &str, i: usize) -> String {
        let file = &self.meta.files[i];
        if self.meta.multi_file {
            let mut url = base.to_string();
            if !url.ends_with('/') {
                url.push('/');
            }
            url.push_str(&enc(&self.meta.name));
            for comp in &file.path {
                url.push('/');
                url.push_str(&enc(comp));
            }
            url
        } else if base.ends_with('/') {
            format!("{base}{}", enc(&self.meta.name))
        } else {
            base.to_string()
        }
    }

    /// Fetch `[global_off, global_off + len)` of the torrent's concatenated
    /// data, splitting across the files it covers.
    pub async fn read_range(&self, global_off: u64, len: u64) -> Result<Vec<u8>, WebSeedError> {
        let end = global_off + len;
        let mut out = Vec::with_capacity(len as usize);
        for i in 0..self.meta.files.len() {
            let (f_start, f_len) = self.meta.file_span(i);
            let f_end = f_start + f_len;
            // Overlap of the requested range with this file's span.
            let seg_start = global_off.max(f_start);
            let seg_end = end.min(f_end);
            if seg_start >= seg_end {
                continue;
            }
            let in_file_off = seg_start - f_start;
            let seg_len = (seg_end - seg_start) as usize;
            let bytes = self.fetch_file_range(i, in_file_off, seg_len).await?;
            out.extend_from_slice(&bytes);
        }
        if out.len() != len as usize {
            return Err(WebSeedError::ShortRead { got: out.len(), want: len as usize });
        }
        Ok(out)
    }

    /// Fetch `[off, off + len)` of file `i`, trying each base until one delivers.
    async fn fetch_file_range(
        &self,
        i: usize,
        off: u64,
        len: usize,
    ) -> Result<Vec<u8>, WebSeedError> {
        http::egress_ok()?;
        let mut last_err: Option<WebSeedError> = None;
        for base in &self.bases {
            let url = self.file_url(base, i);
            match self.range_get(&url, off, len).await {
                Ok(bytes) if bytes.len() == len => return Ok(bytes),
                Ok(bytes) => last_err = Some(WebSeedError::ShortRead { got: bytes.len(), want: len }),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(WebSeedError::NoSource))
    }

    /// A single HTTP Range GET, returning exactly the requested window. Handles
    /// a server that honors Range (206) and one that ignores it (200 - slice
    /// the window out of the full body).
    async fn range_get(&self, url: &str, off: u64, len: usize) -> Result<Vec<u8>, WebSeedError> {
        let end_inclusive = off + len as u64 - 1;
        let resp = self
            .client
            .get(url)
            .header(RANGE, format!("bytes={off}-{end_inclusive}"))
            .send()
            .await
            .map_err(|e| HttpError::Request(e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::PARTIAL_CONTENT {
            // Trust the 206 body is the requested window. (A misbehaving server
            // that returns a different range fails the caller's length check,
            // then the piece SHA-1 - so bad bytes never reach the player.)
            let _ = resp.headers().get(CONTENT_RANGE);
            let body = resp.bytes().await.map_err(|e| HttpError::Request(e.to_string()))?;
            Ok(body.to_vec())
        } else if status == reqwest::StatusCode::OK {
            // Range ignored: we got the whole file. Slice the window.
            let body = resp.bytes().await.map_err(|e| HttpError::Request(e.to_string()))?;
            let start = off as usize;
            let stop = (start + len).min(body.len());
            if start >= body.len() {
                return Ok(Vec::new());
            }
            Ok(body[start..stop].to_vec())
        } else {
            Err(HttpError::Status(status.as_u16()).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::FileEntry;

    fn meta(multi: bool, name: &str, files: Vec<FileEntry>) -> Arc<MetaInfo> {
        let total = files.iter().map(|f| f.length).sum();
        Arc::new(MetaInfo {
            info_hash: [0; 20],
            name: name.to_string(),
            piece_length: 16,
            piece_hashes: vec![[0; 20]],
            files,
            total_length: total,
            multi_file: multi,
        })
    }

    fn seed(bases: &[&str], meta: Arc<MetaInfo>) -> WebSeed {
        WebSeed::new(
            reqwest::Client::new(),
            bases.iter().map(|s| s.to_string()).collect(),
            meta,
        )
    }

    #[test]
    fn single_file_url_appends_name_when_base_ends_in_slash() {
        let m = meta(false, "Tears of Steel.mp4", vec![FileEntry {
            path: vec!["Tears of Steel.mp4".into()],
            length: 100,
        }]);
        let ws = seed(&["https://host/torrents/"], m);
        assert_eq!(ws.file_url("https://host/torrents/", 0), "https://host/torrents/Tears%20of%20Steel.mp4");
    }

    #[test]
    fn single_file_url_is_base_itself_without_trailing_slash() {
        let m = meta(false, "clip.mp4", vec![FileEntry { path: vec!["clip.mp4".into()], length: 100 }]);
        let ws = seed(&["https://host/clip.mp4"], m);
        assert_eq!(ws.file_url("https://host/clip.mp4", 0), "https://host/clip.mp4");
    }

    #[test]
    fn multi_file_url_appends_name_and_path() {
        let m = meta(true, "Tears of Steel", vec![
            FileEntry { path: vec!["poster.jpg".into()], length: 10 },
            FileEntry { path: vec!["Tears of Steel.mp4".into()], length: 100 },
        ]);
        let ws = seed(&["https://host/torrents/"], m);
        assert_eq!(
            ws.file_url("https://host/torrents/", 1),
            "https://host/torrents/Tears%20of%20Steel/Tears%20of%20Steel.mp4"
        );
        // Base without a trailing slash still gets one inserted.
        assert_eq!(
            ws.file_url("https://host/torrents", 0),
            "https://host/torrents/Tears%20of%20Steel/poster.jpg"
        );
    }
}
