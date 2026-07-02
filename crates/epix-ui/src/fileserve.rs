//! Inbound file server - the seeding counterpart to the download path.
//!
//! Implements [`epix_protocol::RequestHandler`] so other peers can pull our
//! files over the wire protocol (`getFile`/`streamFile`), plus `ping` and a
//! minimal `pex`. Without this the node could download from peers but never
//! serve, so it could not seed content, Bigfile pieces, or optional files.
//!
//! Feature-gated behind `inbound-seeding` (off for mobile, which should not
//! accept inbound connections).

use crate::AppState;
use async_trait::async_trait;
use epix_core::PeerAddr;
use epix_protocol::RequestHandler;
use rmpv::Value;
use std::sync::Arc;

/// The largest chunk a single `getFile` response returns (EpixNet's FILE_BUFF).
const FILE_BUFF: usize = 1024 * 512;

/// Serves our local xite files to peers.
pub struct FileService {
    state: Arc<AppState>,
}

impl FileService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    /// `getPiecefields {site}` - report which pieces of each big file we hold,
    /// keyed by the file's sha512, so a downloader only asks us for pieces we
    /// actually have.
    async fn get_piecefields(&self, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        let packed = self.state.our_piecefields(&site).await;
        let map: Vec<(Value, Value)> = packed
            .into_iter()
            .map(|(sha512, bytes)| (Value::from(sha512), Value::Binary(bytes)))
            .collect();
        vmap(vec![("piecefields_packed", Value::Map(map))])
    }

    async fn get_file(&self, params: &Value) -> Value {
        let site = vget_str(params, "site").unwrap_or_default();
        let inner_path = vget_str(params, "inner_path").unwrap_or_default();
        let location = vget_i64(params, "location").unwrap_or(0).max(0) as u64;
        let read_bytes = vget_i64(params, "read_bytes")
            .map(|n| (n.max(0) as usize).min(FILE_BUFF))
            .unwrap_or(FILE_BUFF);

        match self.state.serve_file_chunk(&site, &inner_path, location, read_bytes).await {
            Some((chunk, total)) => {
                let next = location + chunk.len() as u64;
                vmap(vec![
                    ("body", Value::Binary(chunk)),
                    ("size", Value::from(total as i64)),
                    ("location", Value::from(next as i64)),
                ])
            }
            None => vmap(vec![("error", Value::from("File not found"))]),
        }
    }
}

#[async_trait]
impl RequestHandler for FileService {
    async fn handle(&self, _peer: &PeerAddr, cmd: &str, params: &Value) -> Value {
        match cmd {
            "ping" => vmap(vec![("body", Value::Binary(b"Pong!".to_vec()))]),
            "getFile" | "streamFile" => self.get_file(params).await,
            "getPiecefields" => self.get_piecefields(params).await,
            // A peer pushing us its piecefields: acknowledge (our downloader
            // re-queries piecefields when it needs them, so we don't retain).
            "setPiecefields" => vmap(vec![("ok", Value::from("Updated"))]),
            // Unknown/unsupported request: empty body (the server still wraps it
            // as a response so the peer isn't left hanging).
            _ => Value::Map(vec![]),
        }
    }
}

/// Build a msgpack map from string-keyed pairs.
fn vmap(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (Value::from(k), v)).collect())
}

/// Read a string field from a msgpack map param.
fn vget_str(params: &Value, key: &str) -> Option<String> {
    vget(params, key).and_then(|v| match v {
        Value::String(s) => s.as_str().map(str::to_string),
        Value::Binary(b) => Some(String::from_utf8_lossy(b).into_owned()),
        _ => None,
    })
}

/// Read an integer field from a msgpack map param.
fn vget_i64(params: &Value, key: &str) -> Option<i64> {
    vget(params, key).and_then(Value::as_i64)
}

fn vget<'a>(params: &'a Value, key: &str) -> Option<&'a Value> {
    match params {
        Value::Map(fields) => fields
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::XiteEntry;
    use epix_xite::XiteStorage;
    use serde_json::json;

    #[tokio::test]
    async fn serves_a_file_chunk_over_the_handler() {
        let dir = tempfile::tempdir().unwrap();
        let storage = XiteStorage::new(dir.path());
        storage.write("index.html", b"hello seeding world").unwrap();
        let state = AppState::new("test");
        state
            .add_xite("1Seed", XiteEntry { storage, content: Some(json!({ "address": "1Seed" })) })
            .await;
        let svc = FileService::new(state);
        let peer = PeerAddr::parse("1.2.3.4:1").unwrap();

        // ping
        let pong = svc.handle(&peer, "ping", &Value::Map(vec![])).await;
        assert_eq!(vget(&pong, "body"), Some(&Value::Binary(b"Pong!".to_vec())));

        // getFile whole file
        let params = vmap(vec![
            ("site", Value::from("1Seed")),
            ("inner_path", Value::from("index.html")),
            ("location", Value::from(0i64)),
        ]);
        let resp = svc.handle(&peer, "getFile", &params).await;
        assert_eq!(vget(&resp, "body"), Some(&Value::Binary(b"hello seeding world".to_vec())));
        assert_eq!(vget_i64(&resp, "size"), Some(19));
        assert_eq!(vget_i64(&resp, "location"), Some(19));

        // getFile ranged
        let params = vmap(vec![
            ("site", Value::from("1Seed")),
            ("inner_path", Value::from("index.html")),
            ("location", Value::from(6i64)),
            ("read_bytes", Value::from(7i64)),
        ]);
        let resp = svc.handle(&peer, "getFile", &params).await;
        assert_eq!(vget(&resp, "body"), Some(&Value::Binary(b"seeding".to_vec())));

        // Missing file -> error body.
        let params = vmap(vec![
            ("site", Value::from("1Seed")),
            ("inner_path", Value::from("nope.txt")),
        ]);
        let resp = svc.handle(&peer, "getFile", &params).await;
        assert!(vget(&resp, "error").is_some());
    }
}
