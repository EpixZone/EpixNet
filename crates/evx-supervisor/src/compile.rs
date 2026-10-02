//! Compilation in a confined child with a watchdog.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use evx_api::frames::{encode, FromCompiler, ToCompiler};
use evx_api::{strict, Denied, MAX_MODULE};

use crate::process::{Event, Peer, Role, Stream};
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
    if module.len() > MAX_MODULE {
        return Err(Denied::new("module size limit"));
    }
    let (tx, rx) = mpsc::channel();
    let scratch = std::env::temp_dir();
    let mut peer = Peer::spawn(config, "compile", &scratch, Role::Compiler, tx, None)?;
    let frame = encode(&ToCompiler::Compile {
        module: module.to_vec(),
    })?;
    peer.send(&frame)?;
    let deadline = Instant::now() + config.compile_timeout;
    let mut reply: Option<FromCompiler> = None;
    let mut failure: Option<Denied> = None;
    // The reader thread delivers the child's frames and then, at EOF, the
    // stdout `Closed` event, in that order. A child that has already exited
    // may still have its artifact in flight on that thread, so the exit alone
    // is never the verdict: the stream's end is, with a bounded drain after
    // the exit so a reader that never reaches EOF cannot hang us.
    let mut exited_at: Option<Instant> = None;
    while reply.is_none() && failure.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            failure = Some(Denied::new("compilation deadline"));
            break;
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(50))) {
            Ok(Event::Frame(_, body)) => match strict::parse_typed::<FromCompiler>(&body) {
                Ok(frame) => reply = Some(frame),
                Err(_) => failure = Some(Denied::new("compiler protocol")),
            },
            Ok(Event::Stderr(_, chunk)) => peer.record_stderr(&chunk),
            Ok(Event::Closed(_, Stream::Stdout, _)) => {
                if reply.is_none() {
                    failure = Some(exited_without_result(&mut peer));
                }
            }
            Ok(Event::Closed(_, Stream::Stderr, _)) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if peer.poll().is_some() {
                    let since = *exited_at.get_or_insert_with(Instant::now);
                    if since.elapsed() > Duration::from_secs(5) {
                        failure = Some(Denied::new("compiler output not drained after exit"));
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                failure = Some(Denied::new("compiler channel closed"))
            }
        }
    }
    // The compiler exits on its own right after replying. Give it the rest of
    // its deadline (bounded) to do so before `close` signals it: on a slow
    // host the reply arrives while the child is still tearing down its
    // engine, and our own SIGTERM would otherwise read as a crash after
    // output. A child that lingers past this is still killed and refused.
    if reply.is_some() && failure.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let exit_deadline = Instant::now() + remaining.clamp(Duration::from_millis(250), Duration::from_secs(3));
        while Instant::now() < exit_deadline && peer.poll().is_none() {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let code = peer
        .close(Duration::from_millis(50), Duration::from_secs(2))
        .map_err(|_| Denied::new("compiler termination unconfirmed"))?;
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
