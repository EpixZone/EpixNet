//! The confined worker modes.

use std::io::{self, Read, Write};

use evx_api::frames::{
    FromCompiler, FromHelper, FromWorker, HelperFault, ToCompiler, ToHelper, ToWorker,
};
use evx_api::{Request, Response};
use evx_runtime::{HostCalls, HostError, RunOptions};

use crate::confine::{self, Spec};
use crate::ipc::{read_frame, read_worker_init, write_compiler_reply, write_frame};

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
    // The supervisor enforces the current grant (at most 300 CPU seconds)
    // and can apply live changes. This non-raisable backstop covers its loss.
    confine::apply_rlimits(301, 64)?;
    confine::apply(&Spec {
        workspace: None,
        writable: false,
    })?;
    run_confined()
}

/// The signed worker inherits the trusted service's App Sandbox. This profile
/// permits that service's private container; it never installs another sandbox.
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub fn apple_run() -> Result<(), String> {
    confine::apply_rlimits(301, 64)?;
    confine::verify_apple_inheritance()?;
    run_confined()
}

fn run_confined() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let init = read_worker_init(&mut stdin.lock())?;
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
    // SAFETY: this private inherited IPC channel is owned by the supervisor.
    // It forwards unchanged output from its confined EVX compiler, never a
    // publisher-provided serialized artifact. The worker has already applied
    // the process sandbox, and the supervisor enforces native resource limits.
    let report = unsafe {
        evx_runtime::run(
            &artifact,
            &options,
            Box::new(StdioBroker {
                stdin: io::stdin(),
                stdout: io::stdout(),
            }),
        )
    };
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
    compile_confined()
}

#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub fn apple_compile() -> Result<(), String> {
    confine::apply_rlimits(10, 64)?;
    confine::verify_apple_inheritance()?;
    compile_confined()
}

fn compile_confined() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let module = match read_frame::<ToCompiler>(&mut stdin.lock())? {
        ToCompiler::Compile { module } => Ok(module),
        ToCompiler::CompileText { source } => std::str::from_utf8(&source)
            .map_err(|_| evx_runtime::ValidationError::new("invalid WAT encoding"))
            .and_then(evx_runtime::text_to_binary),
    };
    let reply = match module.and_then(|module| evx_runtime::precompile(&module)) {
        Ok(artifact) => FromCompiler::Artifact {
            artifact: artifact.bytes,
            artifact_sha256: artifact.sha256,
            engine_key: artifact.engine_key,
        },
        Err(error) => FromCompiler::Rejected {
            error: error.to_string(),
        },
    };
    write_compiler_reply(&mut stdout.lock(), &reply)
}

/// Perform one workspace operation in the current directory, which the
/// supervisor set to the workspace. Writes need a commit acknowledgement.
pub fn file(writable: bool) -> Result<(), String> {
    // The supervisor enforces the current grant (at most 300 CPU seconds)
    // and can apply live changes. This non-raisable backstop covers its loss.
    confine::apply_rlimits(301, 64)?;
    let workspace = std::env::current_dir().map_err(|_| "no working directory")?;
    confine::apply(&Spec {
        workspace: Some(&workspace),
        writable,
    })?;
    file_confined(workspace, writable, None)
}

/// The trusted file service owns this private workspace and passes its lease.
/// App Sandbox permits native access within this role container. Read/write
/// request restrictions here are protocol checks, not separate OS profiles.
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub fn apple_file(writable: bool) -> Result<(), String> {
    use std::os::fd::FromRawFd;
    confine::apply_rlimits(301, 64)?;
    confine::verify_apple_inheritance()?;
    let workspace = std::env::current_dir().map_err(|_| "no working directory")?;
    let mut lease: libc::stat = unsafe { std::mem::zeroed() };
    let mut cwd: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fixed inherited descriptor and valid output pointers. FD3 is
    // owned below only after checking it names the current workspace directory.
    if unsafe { libc::fstat(3, &mut lease) } != 0
        || unsafe {
            libc::fstatat(
                libc::AT_FDCWD,
                c".".as_ptr(),
                &mut cwd,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        || lease.st_mode & libc::S_IFMT != libc::S_IFDIR
        || lease.st_dev != cwd.st_dev
        || lease.st_ino != cwd.st_ino
        || lease.st_uid != unsafe { libc::geteuid() }
    {
        return Err("Apple file workspace descriptor unavailable".into());
    }
    let root = unsafe { rustix::fd::OwnedFd::from_raw_fd(3) };
    file_confined(workspace, writable, Some(root))
}

fn file_confined(
    workspace: std::path::PathBuf,
    writable: bool,
    root: Option<rustix::fd::OwnedFd>,
) -> Result<(), String> {
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
    if fault == Some(HelperFault::ReadOnlyWriteProbe) {
        let allowed =
            std::fs::write(workspace.join("read-only-native-probe.txt"), b"fixture").is_ok();
        return write_frame(
            &mut stdout.lock(),
            &FromHelper::FileResult {
                response: Response::error(if allowed {
                    "native write allowed"
                } else {
                    "native write denied"
                }),
            },
        );
    }
    let root = match root {
        Some(root) => root,
        None => evx_workspace::open_root(&workspace).map_err(|e| e.to_string())?,
    };
    let root = rustix::fd::AsFd::as_fd(&root);

    if fault == Some(HelperFault::BlockBeforeOperation) {
        write_frame(&mut stdout.lock(), &FromHelper::FaultEntered)?;
        block_forever();
    }

    let response = (|| -> Result<Response, evx_api::Denied> {
        if !capabilities.contains(&request.capability()) {
            return Err(evx_api::Denied::new("capability denied"));
        }
        if writable {
            evx_workspace::cleanup_staging(root)?;
        }
        if !writable && !matches!(request, Request::WorkspaceRead { .. }) {
            return Err(evx_api::Denied::new("read-only helper operation"));
        }
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
    // Linux confinement permits pipe2 on both native architectures.
    #[cfg(target_os = "linux")]
    let (reader, _writer) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).expect("pipe");
    #[cfg(not(target_os = "linux"))]
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
