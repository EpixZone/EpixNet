//! EVX worker binary.
//!
//! One binary, three modes, selected by the trusted supervisor on the command
//! line. Each mode installs hard process limits and the OS confinement for its
//! role before reading a single byte from the supervisor, so no untrusted
//! input is ever parsed outside the sandbox.
//!
//! * `run`     executes one precompiled artifact. No filesystem access at all.
//! * `compile` validates and precompiles one module. No filesystem access.
//! * `file`    performs one workspace read or staged write with a commit
//!             handshake. Read and write access to one workspace directory.
//!
//! All frames travel over stdin and stdout with a 4-byte length prefix;
//! stderr carries bounded diagnostics only.

mod confine;
mod ipc;
mod modes;
mod probe;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let outcome = match mode.as_str() {
        "run" => modes::run(),
        "compile" => modes::compile(),
        "file" => modes::file(),
        // Harness-only containment probe; the supervisor never selects it.
        "probe" => probe::probe(),
        _ => Err("usage: evx-worker run|compile|file|probe".to_string()),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("evx-worker: {message}");
            ExitCode::from(1)
        }
    }
}
