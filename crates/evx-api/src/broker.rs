//! Closed broker operation set.
//!
//! A guest submits a JSON object naming one operation and exactly the fields
//! that operation takes. Unknown operations, extra fields, caller identities,
//! privilege flags and host paths are all rejected at this layer. The
//! fixture operation `game.score.get` stands in for an EpixNet capability so
//! the conformance suite can prove the boundary without an integration.

use serde::{Deserialize, Serialize};

use crate::strict;
use crate::{validate_relative_path, Denied, MAX_FILE, MAX_REQUEST};

/// Capability names a grant can hold. One capability authorizes one request
/// kind; the set is closed so a grant cannot name an operation that does not
/// exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    #[serde(rename = "workspace.read")]
    WorkspaceRead,
    #[serde(rename = "workspace.write")]
    WorkspaceWrite,
    #[serde(rename = "game.score.get")]
    GameScoreGet,
}

impl Capability {
    pub fn all() -> [Capability; 3] {
        [
            Capability::WorkspaceRead,
            Capability::WorkspaceWrite,
            Capability::GameScoreGet,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Capability::WorkspaceRead => "workspace.read",
            Capability::WorkspaceWrite => "workspace.write",
            Capability::GameScoreGet => "game.score.get",
        }
    }

    pub fn parse(name: &str) -> Option<Capability> {
        Capability::all().into_iter().find(|c| c.name() == name)
    }
}

/// One authorized broker request. Field sets are exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "workspace.read")]
    WorkspaceRead { path: String },
    #[serde(rename = "workspace.write")]
    WorkspaceWrite { path: String, text: String },
    #[serde(rename = "game.score.get")]
    GameScoreGet,
}

impl Request {
    pub fn capability(&self) -> Capability {
        match self {
            Request::WorkspaceRead { .. } => Capability::WorkspaceRead,
            Request::WorkspaceWrite { .. } => Capability::WorkspaceWrite,
            Request::GameScoreGet => Capability::GameScoreGet,
        }
    }

    /// Decode and validate one raw guest request without performing I/O.
    pub fn decode(raw: &[u8]) -> Result<Request, Denied> {
        if raw.len() > MAX_REQUEST {
            return Err(Denied::new("request limit"));
        }
        let value = strict::parse(raw)?;
        let object = value
            .as_object()
            .ok_or_else(|| Denied::new("request must be object"))?;
        let op = object
            .get("op")
            .and_then(strict::Value::as_str)
            .ok_or_else(|| Denied::new("capability denied"))?;
        let capability = Capability::parse(op).ok_or_else(|| Denied::new("capability denied"))?;
        // Exact field sets. serde's deny_unknown_fields does not cover unit
        // variants of internally tagged enums, so the shape is checked here.
        let expected: &[&str] = match capability {
            Capability::WorkspaceRead => &["op", "path"],
            Capability::WorkspaceWrite => &["op", "path", "text"],
            Capability::GameScoreGet => &["op"],
        };
        let keys: Vec<&str> = object.keys().map(String::as_str).collect();
        let mut expected_sorted = expected.to_vec();
        expected_sorted.sort_unstable();
        if keys != expected_sorted {
            return Err(Denied::new("unknown operation or fields"));
        }
        let request: Request =
            strict::parse_typed(raw).map_err(|_| Denied::new("unknown operation or fields"))?;
        match &request {
            Request::WorkspaceRead { path } => {
                validate_relative_path(path)?;
            }
            Request::WorkspaceWrite { path, text } => {
                validate_relative_path(path)?;
                if text.len() > MAX_FILE {
                    return Err(Denied::new("file write limit"));
                }
            }
            Request::GameScoreGet => {}
        }
        Ok(request)
    }
}

/// Broker response returned to the guest. Error strings never contain host
/// paths or secrets; the supervisor maps OS errors to a fixed message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Read {
        ok: bool,
        data_b64: String,
        bytes: usize,
    },
    Write {
        ok: bool,
        bytes: usize,
    },
    Score {
        ok: bool,
        score: i64,
    },
    Error {
        ok: bool,
        error: String,
    },
}

impl Response {
    pub fn error(message: impl Into<String>) -> Response {
        let mut text: String = message.into();
        text.truncate(160);
        Response::Error {
            ok: false,
            error: text,
        }
    }

    pub fn is_ok(&self) -> bool {
        match self {
            Response::Read { ok, .. }
            | Response::Write { ok, .. }
            | Response::Score { ok, .. }
            | Response::Error { ok, .. } => *ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_exact_shapes_only() {
        assert_eq!(
            Request::decode(br#"{"op":"game.score.get"}"#).unwrap(),
            Request::GameScoreGet
        );
        assert_eq!(
            Request::decode(br#"{"op":"workspace.read","path":"a/b"}"#).unwrap(),
            Request::WorkspaceRead { path: "a/b".into() }
        );
        for bad in [
            &br#"{"op":"game.score.get","xite":"game-b"}"#[..],
            br#"{"op":"permissionAdd","permission":"ADMIN"}"#,
            br#"{"op":"exec","command":"true"}"#,
            br#"{"op":"http.get","url":"https://example.invalid/"}"#,
            br#"{"op":"workspace.read"}"#,
            br#"{"op":"workspace.read","path":1}"#,
            br#"{"op":"workspace.read","path":"../x"}"#,
            br#"{"op":"workspace.write","path":"x"}"#,
            br#"{"op":"Game.Score.Get"}"#,
            br#"{"op":"game.score.get","op":"workspace.read"}"#,
            br#"["workspace.read"]"#,
            b"",
            b"\xff",
        ] {
            assert!(
                Request::decode(bad).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let long = format!(
            r#"{{"op":"workspace.write","path":"x","text":"{}"}}"#,
            "x".repeat(MAX_FILE + 1)
        );
        assert!(Request::decode(long.as_bytes()).is_err());
    }
}
