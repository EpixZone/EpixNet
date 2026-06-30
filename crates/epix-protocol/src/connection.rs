//! A client connection to a peer: handshake + the FileRequest command set.

use crate::msg::{read_msg, send_msg, vget, vmap};
use epix_core::{Error, PeerAddr, Result};
use epix_transport::{PeerStream, Transport};
use rmpv::Value;

/// The handshake info exchanged with a peer.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    pub version: String,
    pub rev: i64,
    pub protocol: String,
    pub peer_id: String,
    pub fileserver_port: u16,
    pub crypt_supported: Vec<String>,
}

fn parse_handshake(v: &Value) -> HandshakeInfo {
    let s = |k: &str| vget(v, k).and_then(|x| x.as_str()).unwrap_or("").to_string();
    let i = |k: &str| vget(v, k).and_then(|x| x.as_i64()).unwrap_or(0);
    HandshakeInfo {
        version: s("version"),
        rev: i("rev"),
        protocol: s("protocol"),
        peer_id: s("peer_id"),
        fileserver_port: i("fileserver_port") as u16,
        crypt_supported: vget(v, "crypt_supported")
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    }
}

fn random_peer_id() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::getrandom(&mut b);
    format!("-EpixRS-{}", hex::encode(b))
}

/// A live connection to one peer. Request/response is matched by `req_id`.
pub struct Connection {
    stream: PeerStream,
    buf: Vec<u8>,
    next_req_id: i64,
    pub peer: Option<HandshakeInfo>,
}

impl Connection {
    /// Dial `addr` over `transport` and wrap the resulting stream.
    pub async fn connect(transport: &dyn Transport, addr: &PeerAddr) -> Result<Self> {
        let stream = transport.dial(addr).await?;
        Ok(Self { stream, buf: Vec::new(), next_req_id: 0, peer: None })
    }

    fn next_id(&mut self) -> i64 {
        let id = self.next_req_id;
        self.next_req_id += 1;
        id
    }

    /// Send `{cmd, req_id, params}` and return the matching `response` map.
    /// Inbound requests and unrelated responses are skipped.
    pub async fn request(&mut self, cmd: &str, params: Value) -> Result<Value> {
        let req_id = self.next_id();
        let msg = vmap(vec![
            ("cmd", Value::from(cmd)),
            ("req_id", Value::from(req_id)),
            ("params", params),
        ]);
        send_msg(&mut self.stream, &msg).await?;

        loop {
            let resp = read_msg(&mut self.stream, &mut self.buf).await?;
            let is_response = vget(&resp, "cmd").and_then(|v| v.as_str()) == Some("response");
            let to = vget(&resp, "to").and_then(|v| v.as_i64());
            if is_response && to == Some(req_id) {
                if let Some(err) = vget(&resp, "error") {
                    return Err(Error::Protocol(format!("peer error on `{cmd}`: {err}")));
                }
                return Ok(resp);
            }
            // Not ours — keep reading (a well-behaved peer answers our req_id).
        }
    }

    /// Perform the protocol handshake (plaintext, no crypt negotiation yet).
    pub async fn handshake(&mut self) -> Result<HandshakeInfo> {
        let params = vmap(vec![
            ("version", Value::from(env!("CARGO_PKG_VERSION"))),
            ("rev", Value::from(8192i64)),
            ("peer_id", Value::from(random_peer_id())),
            ("protocol", Value::from("v2")),
            ("use_bin_type", Value::from(true)),
            ("fileserver_port", Value::from(0i64)),
            ("crypt_supported", Value::Array(vec![])),
            ("port_opened", Value::from(false)),
        ]);
        let resp = self.request("handshake", params).await?;
        let hs = parse_handshake(&resp);
        self.peer = Some(hs.clone());
        Ok(hs)
    }

    /// `ping` → `true` if the peer answers `Pong!`.
    pub async fn ping(&mut self) -> Result<bool> {
        let resp = self.request("ping", Value::Map(vec![])).await?;
        Ok(vget(&resp, "body").and_then(|v| v.as_str()) == Some("Pong!"))
    }

    /// Download a whole file, following `location`/`size` across chunks.
    pub async fn get_file(&mut self, site: &str, inner_path: &str) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut location = 0i64;
        loop {
            let params = vmap(vec![
                ("site", Value::from(site)),
                ("inner_path", Value::from(inner_path)),
                ("location", Value::from(location)),
            ]);
            let resp = self.request("getFile", params).await?;
            let body = vget(&resp, "body")
                .ok_or_else(|| Error::Protocol("getFile response has no body".into()))?;
            let chunk: &[u8] = match body {
                Value::Binary(b) => b.as_slice(),
                Value::String(s) => s.as_bytes(),
                other => {
                    return Err(Error::Protocol(format!("getFile body has type {other:?}")))
                }
            };
            out.extend_from_slice(chunk);

            let size = vget(&resp, "size").and_then(|v| v.as_i64()).unwrap_or(out.len() as i64);
            let next = vget(&resp, "location").and_then(|v| v.as_i64()).unwrap_or(size);
            if out.len() as i64 >= size || next <= location {
                break;
            }
            location = next;
        }
        Ok(out)
    }
}
