//! IPC frames between the supervisor and its child processes.
//!
//! Wire format: a 4-byte big-endian length followed by that many bytes of
//! UTF-8 JSON. Frames from an untrusted peer are decoded through
//! [`crate::strict`]. Ordinary frames are bounded by [`crate::MAX_FRAME`].
//! Only compiler artifacts and the initial guest artifact use the larger
//! [`crate::MAX_ARTIFACT_FRAME`] envelope.
//!
//! Three peers speak these frames: the guest worker (untrusted), the compiler
//! process (trusted code on hostile input) and the file helper (trusted code
//! with write access to one workspace).

use serde::{Deserialize, Serialize};

use crate::{Limits, Request, Response, MAX_ARTIFACT_FRAME, MAX_FRAME};

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
    /// Fixture text is parsed only after compiler-process confinement.
    #[serde(rename = "compile_text")]
    CompileText {
        #[serde(with = "b64")]
        source: Vec<u8>,
    },
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
    /// Native authority probe for a read-only helper, selected only by tests.
    ReadOnlyWriteProbe,
    BlockBeforeOperation,
    BlockAfterAuthorization,
    FailAfterReplace,
}

/// Encode one frame with its length prefix.
pub fn encode<T: Serialize>(frame: &T) -> Result<Vec<u8>, crate::Denied> {
    encode_bounded(frame, MAX_FRAME)
}

/// Encode the one initial artifact sent by the trusted supervisor. Ordinary
/// guest responses cannot use this larger envelope.
pub fn encode_worker_init(frame: &ToWorker) -> Result<Vec<u8>, crate::Denied> {
    if !matches!(frame, ToWorker::Init { .. }) {
        return Err(crate::Denied::new("expected artifact initialization"));
    }
    encode_bounded(frame, MAX_ARTIFACT_FRAME)
}

/// The compiler may return one larger artifact, never a larger error.
pub fn encode_compiler_reply(frame: &FromCompiler) -> Result<Vec<u8>, crate::Denied> {
    let limit = if matches!(frame, FromCompiler::Artifact { .. }) {
        MAX_ARTIFACT_FRAME
    } else {
        MAX_FRAME
    };
    encode_bounded(frame, limit)
}

/// Decode compiler output with the same variant-specific envelope as the
/// encoder. The pipe reader bounds allocation before this parser runs.
pub fn decode_compiler_reply(body: &[u8]) -> Result<FromCompiler, crate::Denied> {
    if body.len() > MAX_ARTIFACT_FRAME {
        return Err(crate::Denied::new("compiler frame limit"));
    }
    let frame = crate::strict::parse_typed(body)?;
    if body.len() > MAX_FRAME && !matches!(frame, FromCompiler::Artifact { .. }) {
        return Err(crate::Denied::new("compiler error frame limit"));
    }
    Ok(frame)
}

fn encode_bounded<T: Serialize>(frame: &T, limit: usize) -> Result<Vec<u8>, crate::Denied> {
    let body = serde_json::to_vec(frame).map_err(|_| crate::Denied::new("frame encoding"))?;
    if body.len() > limit {
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

    #[test]
    fn large_artifacts_have_narrow_directional_envelopes() {
        let artifact = FromCompiler::Artifact {
            artifact: vec![0; 132_880],
            artifact_sha256: "0".repeat(64),
            engine_key: "fixture".into(),
        };
        assert!(encode(&artifact).is_err());
        let encoded = encode_compiler_reply(&artifact).unwrap();
        assert!(encoded.len() > MAX_FRAME + 4);
        assert_eq!(decode_compiler_reply(&encoded[4..]).unwrap(), artifact);

        let init = ToWorker::Init {
            artifact: vec![0; 132_880],
            artifact_sha256: "0".repeat(64),
            limits: Limits::default(),
        };
        assert!(encode(&init).is_err());
        assert!(encode_worker_init(&init).is_ok());
        let response = ToWorker::Response {
            response: vec![0; MAX_FRAME],
        };
        assert!(encode(&response).is_err());
        assert!(encode_worker_init(&response).is_err());
        assert!(encode(&FromWorker::Call {
            request: vec![0; MAX_FRAME]
        })
        .is_err());

        let rejected = FromCompiler::Rejected {
            error: "x".repeat(MAX_FRAME),
        };
        assert!(encode_compiler_reply(&rejected).is_err());
        assert!(decode_compiler_reply(&serde_json::to_vec(&rejected).unwrap()).is_err());
    }

    #[test]
    fn artifact_envelope_exact_limit_and_one_byte_over() {
        let mut artifact = FromCompiler::Artifact {
            artifact: vec![0; 132_880],
            artifact_sha256: "0".repeat(64),
            engine_key: String::new(),
        };
        let padding = MAX_ARTIFACT_FRAME - serde_json::to_vec(&artifact).unwrap().len();
        if let FromCompiler::Artifact { engine_key, .. } = &mut artifact {
            *engine_key = "x".repeat(padding);
        }
        let encoded = encode_compiler_reply(&artifact).unwrap();
        assert_eq!(encoded.len(), MAX_ARTIFACT_FRAME + 4);
        assert_eq!(decode_compiler_reply(&encoded[4..]).unwrap(), artifact);
        if let FromCompiler::Artifact { engine_key, .. } = &mut artifact {
            engine_key.push('x');
        }
        assert!(encode_compiler_reply(&artifact).is_err());
        assert!(decode_compiler_reply(&serde_json::to_vec(&artifact).unwrap()).is_err());
    }
}
