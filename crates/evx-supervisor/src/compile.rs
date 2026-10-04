//! Compilation in a confined child with a watchdog.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use evx_api::frames::{decode_compiler_reply, encode, FromCompiler, ToCompiler};
use evx_api::{Denied, MAX_MODULE};

use crate::process::{Event, Peer, Role, EVENT_CAPACITY, OUTPUT_QUOTA};
use crate::supervisor::Config;

/// A serialized module this host produced, bound to its engine key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledArtifact {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub engine_key: String,
}

/// The child closed its output without an artifact: say how it ended and
/// what it wrote to stderr (sanitised, bounded), which is the only evidence.
fn exited_without_result(peer: &mut Peer) -> Denied {
    let code = peer.poll();
    let diagnostics = evx_api::result::safe_text(&String::from_utf8_lossy(&peer.diagnostics), 512);
    Denied::new(format!(
        "compiler exited without a result (exit {code:?}; stderr: {diagnostics:?})"
    ))
}

/// Validate and precompile `module` in a confined compiler process. The
/// child has no workspace access; a hang or crash is reported, never retried
/// unconfined.
pub fn compile_module(config: &Config, module: &[u8]) -> Result<CompiledArtifact, Denied> {
    compile_module_cancellable(config, module, &|| false)
}

/// Compiler cancellation is trusted host state, never guest telemetry.
pub fn compile_module_cancellable(
    config: &Config,
    module: &[u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<CompiledArtifact, Denied> {
    if module.len() > MAX_MODULE {
        return Err(Denied::new("module size limit"));
    }
    compile_input(
        config,
        ToCompiler::Compile {
            module: module.to_vec(),
        },
        cancelled,
    )
}

/// Compile fixture text without parsing guest-controlled syntax in the host.
pub fn compile_text(config: &Config, source: &[u8]) -> Result<CompiledArtifact, Denied> {
    compile_text_cancellable(config, source, &|| false)
}

pub fn compile_text_cancellable(
    config: &Config,
    source: &[u8],
    cancelled: &dyn Fn() -> bool,
) -> Result<CompiledArtifact, Denied> {
    if source.len() > MAX_MODULE {
        return Err(Denied::new("module size limit"));
    }
    compile_input(
        config,
        ToCompiler::CompileText {
            source: source.to_vec(),
        },
        cancelled,
    )
}

fn compile_input(
    config: &Config,
    input: ToCompiler,
    cancelled: &dyn Fn() -> bool,
) -> Result<CompiledArtifact, Denied> {
    if cancelled() {
        return Err(Denied::Cancelled("compilation cancelled".into()));
    }
    if !config.compile_cpu_seconds.is_finite()
        || config.compile_cpu_seconds <= 0.0
        || config.compile_rss_bytes == 0
    {
        return Err(Denied::new("invalid compiler limits"));
    }
    let frame = encode(&input)?;
    let (tx, rx) = mpsc::sync_channel(EVENT_CAPACITY);
    let scratch = std::env::temp_dir();
    let mut peer = Peer::spawn(config, "compile", &scratch, Role::Compiler, tx, None)?;
    let send_failure = peer.send(&frame).err();
    let deadline = Instant::now() + config.compile_timeout;
    let mut reply: Option<FromCompiler> = None;
    let mut failure: Option<Denied> = send_failure;
    while failure.is_none() {
        if cancelled() {
            failure = Some(Denied::Cancelled("compilation cancelled".into()));
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            failure = Some(Denied::new("compilation deadline"));
            break;
        }
        if let Err(error) = peer.flush_input().and_then(|_| peer.measure()) {
            failure = Some(error);
            break;
        }
        peer.poll();
        if peer.max_cpu > config.compile_cpu_seconds {
            failure = Some(Denied::new("compiler CPU limit"));
            break;
        }
        if peer.last_rss.unwrap_or(0) > config.compile_rss_bytes {
            failure = Some(Denied::new("compiler RSS limit"));
            break;
        }
        if peer.exit_code.is_some() && peer.readers == 0 {
            if reply.is_none() {
                failure = Some(exited_without_result(&mut peer));
            }
            break;
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(20))) {
            Ok(Event::Frame(_, _, body)) => {
                peer.output_bytes = peer.output_bytes.saturating_add(body.len());
                if peer.output_bytes > OUTPUT_QUOTA {
                    failure = Some(Denied::new("compiler output quota"));
                } else if reply.is_some() {
                    failure = Some(Denied::new("compiler message after terminal result"));
                } else {
                    match decode_compiler_reply(&body) {
                        Ok(frame) => reply = Some(frame),
                        Err(_) => failure = Some(Denied::new("compiler protocol")),
                    }
                }
            }
            Ok(Event::Stderr(_, _, chunk)) => {
                peer.output_bytes = peer.output_bytes.saturating_add(chunk.len());
                if peer.output_bytes > OUTPUT_QUOTA {
                    failure = Some(Denied::new("compiler output quota"));
                }
                peer.record_stderr(&chunk);
            }
            Ok(Event::Closed(_, _, _, error)) => {
                peer.readers = peer.readers.saturating_sub(1);
                if let Some(error) = error {
                    failure = Some(Denied::new(error));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Both readers send their Closed event before disconnecting.
                if peer.readers != 0 {
                    failure = Some(Denied::new("compiler channel closed"));
                } else {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
    let closed = if config.fail_compiler_cleanup {
        Err(crate::process::CleanupTimeout { pid: peer.pid })
    } else {
        peer.close(Duration::from_millis(50), Duration::from_secs(2))
    };
    let code = closed.map_err(|_| {
        crate::process::quarantine_child_admission();
        Denied::Quarantined(
            "compiler termination unconfirmed; child admission quarantined; confirm prior children stopped before restarting the host"
                .into(),
        )
    })?;
    if let Some(error) = failure {
        return Err(error);
    }
    match reply {
        Some(FromCompiler::Artifact {
            artifact,
            artifact_sha256,
            engine_key,
        }) => {
            if code != 0 {
                return Err(Denied::new("compiler failed after producing output"));
            }
            if engine_key != evx_runtime::engine_key() {
                return Err(Denied::new("artifact engine mismatch"));
            }
            if hex::encode(Sha256::digest(&artifact)) != artifact_sha256 {
                return Err(Denied::new("artifact digest mismatch"));
            }
            Ok(CompiledArtifact {
                bytes: artifact,
                sha256: artifact_sha256,
                engine_key,
            })
        }
        Some(FromCompiler::Rejected { error }) => {
            Err(Denied::new(evx_api::result::safe_text(&error, 512)))
        }
        None => Err(Denied::new("compiler produced no result")),
    }
}
