//! `evx-host` CLI for external harnesses.
//!
//! Reads one JSON command on stdin and writes one JSON result on stdout. It is
//! a thin, trusted harness entry point: all authority decisions happen in the
//! supervisor and activation crates. Commands:
//!
//! ```json
//! {"command":"compile","source":"(module ...)"}                       -> {"artifact":{...}} | {"error":"..."}
//! {"command":"run","workspace":"/abs","grant":{...},"limits":{...},
//!  "artifact":{"bytes_b64":"...","sha256":"...","engine_key":"..."},
//!  "options":{"revoke_before_call":2,"file_fault":"block_before_operation"}} -> RunResult JSON
//! {"command":"probe","workspace":"/abs","outside_file":"...","outside_write":"...","port":1234}
//! ```

use std::io::{Read, Write};
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use evx_api::frames::HelperFault;
use evx_api::{Grant, Limits};
use evx_supervisor::{compile_text, run_guest, Broker, CompiledArtifact, Config, RunOptions};

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
enum Command {
    Compile {
        source: String,
    },
    Run {
        workspace: PathBuf,
        grant: Grant,
        #[serde(default)]
        limits: Limits,
        artifact: ArtifactJson,
        #[serde(default)]
        options: OptionsJson,
    },
}

#[derive(Serialize, Deserialize)]
struct ArtifactJson {
    bytes_b64: String,
    sha256: String,
    engine_key: String,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct OptionsJson {
    #[serde(default)]
    revoke_before_call: Option<u32>,
    #[serde(default)]
    stall_broker: bool,
    #[serde(default)]
    revoke_at_file_commit: bool,
    #[serde(default)]
    file_fault: Option<HelperFault>,
}

fn worker_binary() -> PathBuf {
    if let Ok(path) = std::env::var("EVX_WORKER") {
        return PathBuf::from(path);
    }
    let exe = std::env::current_exe().expect("current executable");
    exe.with_file_name("evx-worker")
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let command: Command = match serde_json::from_str(&input) {
        Ok(command) => command,
        Err(e) => {
            println!(
                "{}",
                serde_json::json!({"error": format!("invalid command: {e}")})
            );
            std::process::exit(2);
        }
    };
    let config = Config::new(worker_binary());
    let output = match command {
        Command::Compile { source } => {
            match compile_text(&config, source.as_bytes()).map_err(|e| e.to_string()) {
                Ok(artifact) => serde_json::json!({"artifact": ArtifactJson {
                    bytes_b64: B64.encode(&artifact.bytes),
                    sha256: artifact.sha256,
                    engine_key: artifact.engine_key,
                }}),
                Err(error) => serde_json::json!({"error": error}),
            }
        }
        Command::Run {
            workspace,
            grant,
            limits,
            artifact,
            options,
        } => {
            let bytes = match B64.decode(&artifact.bytes_b64) {
                Ok(bytes) => bytes,
                Err(_) => {
                    println!(
                        "{}",
                        serde_json::json!({"error": "invalid artifact encoding"})
                    );
                    std::process::exit(2);
                }
            };
            let artifact = CompiledArtifact {
                bytes,
                sha256: artifact.sha256,
                engine_key: artifact.engine_key,
            };
            let broker = match Broker::new(&workspace, grant, limits) {
                Ok(broker) => broker,
                Err(e) => {
                    println!("{}", serde_json::json!({"error": e.to_string()}));
                    std::process::exit(2);
                }
            };
            let result = run_guest(
                &config,
                &artifact,
                &broker,
                RunOptions {
                    revoke_before_call: options.revoke_before_call,
                    stall_broker: options.stall_broker,
                    revoke_at_file_commit: options.revoke_at_file_commit,
                    file_fault: options.file_fault,
                    ..Default::default()
                },
            );
            serde_json::to_value(result).expect("result serializes")
        }
    };
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{output}").expect("stdout");
}
