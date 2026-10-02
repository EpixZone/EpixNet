//! IPC frames between the supervisor and its child processes.
//!
//! Wire format: a 4-byte big-endian length followed by that many bytes of
//! UTF-8 JSON. Frames from an untrusted peer are decoded through
//! [`crate::strict`]. Length is bounded by [`crate::MAX_FRAME`].
//!
//! Three peers speak these frames: the guest worker (untrusted), the compiler
//! process (trusted code on hostile input) and the file helper (trusted code
//! with write access to one workspace).

use serde::{Deserialize, Serialize};

use crate::{Limits, Request, Response, MAX_FRAME};

/// Byte payloads are carried as base64 so frames stay valid UTF-8 JSON.
pub mod b64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

/// Supervisor to guest worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ToWorker {
    /// First frame. The artifact is a host-produced serialized module whose
    /// digest the supervisor recorded; the worker deserializes nothing else.
    #[serde(rename = "init")]
    Init {
        #[serde(with = "b64")]
        artifact: Vec<u8>,
        artifact_sha256: String,
        limits: Limits,
    },
    /// Reply to one broker call.
    #[serde(rename = "response")]
    Response {
        #[serde(with = "b64")]
        response: Vec<u8>,
    },
}

/// Guest worker to supervisor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum FromWorker {
    #[serde(rename = "call")]
    Call {
        #[serde(with = "b64")]
        request: Vec<u8>,
    },
    #[serde(rename = "result")]
    Result(WorkerResult),
}

/// Terminal frame from the worker. Measurements here are diagnostic only; the
/// supervisor never uses them for budget decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResult {
    pub status: WorkerStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub elapsed_ms: f64,
    #[serde(default)]
    pub fuel_used: u64,
    #[serde(default)]
    pub memory_bytes: u64,
    #[serde(default)]
    pub host_calls: u32,
    #[serde(default)]
    pub invalid_calls: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    Ok,
    Error,
}

/// Supervisor to compiler process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ToCompiler {
    #[serde(rename = "compile")]
    Compile {
        #[serde(with = "b64")]
        module: Vec<u8>,
    },
}

/// Compiler process to supervisor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum FromCompiler {
    #[serde(rename = "artifact")]
    Artifact {
        #[serde(with = "b64")]
        artifact: Vec<u8>,
        artifact_sha256: String,
        /// Engine identity the artifact is bound to; the worker refuses a
        /// mismatch.
        engine_key: String,
    },
    #[serde(rename = "rejected")]
    Rejected { error: String },
}

/// Supervisor to file helper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ToHelper {
    #[serde(rename = "init")]
    Init {
        xite: String,
        generation: u64,
        capabilities: Vec<crate::Capability>,
        limits: Limits,
        request: Request,
        /// Trusted test-only fault injection. Never populated from guest input.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        test_fault: Option<HelperFault>,
    },
    #[serde(rename = "commit")]
    Commit,
}

/// File helper to supervisor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum FromHelper {
    /// Staging is durable; the helper is waiting for commit authorization.
    #[serde(rename = "prepared")]
    Prepared,
    #[serde(rename = "file_result")]
    FileResult { response: Response },
    #[serde(rename = "fault_entered")]
    FaultEntered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperFault {
    BlockBeforeOperation,
    BlockAfterAuthorization,
    FailAfterReplace,
}

/// Encode one frame with its length prefix.
pub fn encode<T: Serialize>(frame: &T) -> Result<Vec<u8>, crate::Denied> {
    let body = serde_json::to_vec(frame).map_err(|_| crate::Denied::new("frame encoding"))?;
    if body.len() > MAX_FRAME {
        return Err(crate::Denied::new("outgoing frame limit"));
    }
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strict;

    #[test]
    fn frames_round_trip_and_reject_extra_authority() {
        let frame = FromWorker::Call {
            request: b"{}".to_vec(),
        };
        let json = serde_json::to_vec(&frame).unwrap();
        let back: FromWorker = strict::parse_typed(&json).unwrap();
        assert_eq!(back, frame);
        let forged = br#"{"type":"call","request":"e30=","xite":"game-b"}"#;
        assert!(strict::parse_typed::<FromWorker>(forged).is_err());
        let bad_value = br#"{"type":"result","status":"ok","value":true}"#;
        assert!(strict::parse_typed::<FromWorker>(bad_value).is_err());
        let nonfinite = br#"{"type":"result","status":"ok","value":1,"elapsed_ms":1e999}"#;
        assert!(strict::parse_typed::<FromWorker>(nonfinite).is_err());
    }
}
