//! The three worker modes.

use std::io::{self, Read, Write};

use evx_api::frames::{
    FromCompiler, FromHelper, FromWorker, HelperFault, ToCompiler, ToHelper, ToWorker,
};
use evx_api::{Request, Response};
use evx_runtime::{HostCalls, HostError, RunOptions};

use crate::confine::{self, Spec};
use crate::ipc::{read_frame, write_frame};

/// Broker channel: each call is one frame out and one frame back.
struct StdioBroker {
    stdin: io::Stdin,
    stdout: io::Stdout,
}

impl HostCalls for StdioBroker {
    fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, HostError> {
        let mut out = self.stdout.lock();
        write_frame(
            &mut out,
            &FromWorker::Call {
                request: request.to_vec(),
            },
        )
        .map_err(|e| HostError::Fatal(format!("broker channel: {e}")))?;
        drop(out);
        let mut input = self.stdin.lock();
        match read_frame::<ToWorker>(&mut input) {
            Ok(ToWorker::Response { response }) => Ok(response),
            Ok(ToWorker::Init { .. }) => Err(HostError::Fatal("unexpected init frame".into())),
            Err(e) => Err(HostError::Fatal(format!("broker channel: {e}"))),
        }
    }
}

/// Execute one precompiled artifact.
pub fn run() -> Result<(), String> {
    confine::apply_rlimits(3, 64)?;
    confine::apply(&Spec {
        workspace: None,
        writable: false,
    })?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let init = read_frame::<ToWorker>(&mut stdin.lock())?;
    let (artifact, artifact_sha256, limits) = match init {
        ToWorker::Init {
            artifact,
            artifact_sha256,
            limits,
        } => (artifact, artifact_sha256, limits),
        ToWorker::Response { .. } => return Err("expected init frame".into()),
    };
    limits.validate().map_err(|e| e.to_string())?;
    let options = RunOptions {
        limits,
        artifact_sha256,
        engine_key: evx_runtime::engine_key(),
    };
    let report = evx_runtime::run(
        &artifact,
        &options,
        Box::new(StdioBroker {
            stdin: io::stdin(),
            stdout: io::stdout(),
        }),
    );
    if report.unclassified_trap {
        eprintln!("evx-worker: unclassified trap variant observed");
    }
    write_frame(&mut stdout.lock(), &FromWorker::Result(report.result))
}

/// Validate and precompile one module.
pub fn compile() -> Result<(), String> {
    confine::apply_rlimits(10, 64)?;
    confine::apply(&Spec {
        workspace: None,
        writable: false,
    })?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let ToCompiler::Compile { module } = read_frame::<ToCompiler>(&mut stdin.lock())?;
    let reply = match evx_runtime::precompile(&module) {
        Ok(artifact) => FromCompiler::Artifact {
            artifact: artifact.bytes,
            artifact_sha256: artifact.sha256,
            engine_key: artifact.engine_key,
        },
        Err(error) => FromCompiler::Rejected {
            error: error.to_string(),
        },
    };
    write_frame(&mut stdout.lock(), &reply)
}

/// Perform one workspace operation in the current directory, which the
/// supervisor set to the workspace. Writes need a commit acknowledgement.
pub fn file() -> Result<(), String> {
    confine::apply_rlimits(3, 64)?;
    let workspace = std::env::current_dir().map_err(|_| "no working directory")?;
    confine::apply(&Spec {
        workspace: Some(&workspace),
        writable: true,
    })?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let init = read_frame::<ToHelper>(&mut stdin.lock())?;
    let (capabilities, limits, request, fault) = match init {
        ToHelper::Init {
            capabilities,
            limits,
            request,
            test_fault,
            ..
        } => (capabilities, limits, request, test_fault),
        ToHelper::Commit => return Err("expected init frame".into()),
    };
    limits.validate().map_err(|e| e.to_string())?;
    let root = evx_workspace::open_root(&workspace).map_err(|e| e.to_string())?;
    let root = rustix::fd::AsFd::as_fd(&root);

    if fault == Some(HelperFault::BlockBeforeOperation) {
        write_frame(&mut stdout.lock(), &FromHelper::FaultEntered)?;
        block_forever();
    }

    let response = (|| -> Result<Response, evx_api::Denied> {
        if !capabilities.contains(&request.capability()) {
            return Err(evx_api::Denied::new("capability denied"));
        }
        evx_workspace::cleanup_staging(root)?;
        match &request {
            Request::WorkspaceRead { path } => evx_workspace::read(root, path),
            Request::WorkspaceWrite { path, text } => {
                let staged = evx_workspace::stage_write(root, path, text, limits.storage_bytes)?;
                // Staging is durable. Ask the supervisor whether the commit is
                // still authorized under the current grant and limits.
                write_frame(&mut stdout.lock(), &FromHelper::Prepared)
                    .map_err(evx_api::Denied::new)?;
                match read_frame::<ToHelper>(&mut stdin.lock()) {
                    Ok(ToHelper::Commit) => {}
                    _ => {
                        staged.abort();
                        return Err(evx_api::Denied::new("commit denied"));
                    }
                }
                if fault == Some(HelperFault::BlockAfterAuthorization) {
                    write_frame(&mut stdout.lock(), &FromHelper::FaultEntered)
                        .map_err(evx_api::Denied::new)?;
                    block_forever();
                }
                let after: Option<&dyn Fn() -> Result<(), evx_api::Denied>> =
                    if fault == Some(HelperFault::FailAfterReplace) {
                        Some(&|| Err(evx_api::Denied::new("injected directory sync failure")))
                    } else {
                        None
                    };
                staged.commit(after)
            }
            Request::GameScoreGet => Err(evx_api::Denied::new("not a file operation")),
        }
    })();
    let response = match response {
        Ok(response) => response,
        Err(error) => Response::error(error.to_string()),
    };
    write_frame(&mut stdout.lock(), &FromHelper::FileResult { response })
}

/// Real blocking native I/O with no writer, used only by test fault injection
/// to prove the supervisor can terminate a stuck helper.
fn block_forever() -> ! {
    let (reader, _writer) = rustix::pipe::pipe().expect("pipe");
    let mut file = std::fs::File::from(reader);
    let mut byte = [0u8; 1];
    let _ = file.read(&mut byte);
    std::process::exit(3);
}

#[allow(dead_code)]
fn _assert_write_is_used(w: &mut dyn Write) {
    let _ = w.flush();
}
