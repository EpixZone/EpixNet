//! Native containment probe: harmless attempts to escape, run under the same
//! confinement as `run` mode, reporting what the OS allowed.
//!
//! This exists for the conformance suite's "simulated compromised worker"
//! case. The supervisor never selects it; only a trusted harness does. Every
//! file target is a sacrificial fixture passed on the command line.

use std::io::Write;
use std::net::TcpStream;
use std::process::Command;

use crate::confine::{self, Spec};

fn attempt(label: &str, out: &mut Vec<String>, operation: impl FnOnce() -> Result<String, String>) {
    match operation() {
        Ok(detail) => out.push(format!(
            "{{\"op\":\"{label}\",\"allowed\":true,\"detail\":{}}}",
            json_str(&detail)
        )),
        Err(error) => out.push(format!(
            "{{\"op\":\"{label}\",\"allowed\":false,\"detail\":{}}}",
            json_str(&error)
        )),
    }
}

fn json_str(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

/// `evx-worker probe <outside-file> <outside-write> <loopback-port> [workspace]`
pub fn probe() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        return Err(
            "usage: evx-worker probe <outside-file> <outside-write> <loopback-port> [workspace]"
                .into(),
        );
    }
    let outside_file = args[2].clone();
    let outside_write = args[3].clone();
    let port: u16 = args[4].parse().map_err(|_| "port")?;
    let workspace = args.get(5).map(std::path::PathBuf::from);
    confine::apply_rlimits(3, 64)?;
    confine::apply(&Spec {
        workspace: workspace.as_deref(),
        writable: false,
    })?;

    let mut results = Vec::new();
    attempt("outside_read", &mut results, || {
        std::fs::read_to_string(&outside_file)
            .map(|s| format!("{} bytes", s.len()))
            .map_err(|e| e.to_string())
    });
    attempt("outside_write", &mut results, || {
        std::fs::write(&outside_write, b"fixture")
            .map(|_| "written".into())
            .map_err(|e| e.to_string())
    });
    if let Some(ws) = &workspace {
        attempt("workspace_read", &mut results, || {
            std::fs::read_to_string(ws.join("native-fixture.txt"))
                .map(|s| format!("{} bytes", s.len()))
                .map_err(|e| e.to_string())
        });
        attempt("workspace_write", &mut results, || {
            std::fs::write(ws.join("native-probe.txt"), b"fixture")
                .map(|_| "written".into())
                .map_err(|e| e.to_string())
        });
        attempt("symlink_read", &mut results, || {
            std::fs::read_to_string(ws.join("outside-link"))
                .map(|s| format!("{} bytes", s.len()))
                .map_err(|e| e.to_string())
        });
    }
    attempt("etc_hosts_read", &mut results, || {
        std::fs::read_to_string("/etc/hosts")
            .map(|s| format!("{} bytes", s.len()))
            .map_err(|e| e.to_string())
    });
    attempt("home_listing", &mut results, || {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users".into());
        std::fs::read_dir(home)
            .map(|d| format!("{} entries", d.count()))
            .map_err(|e| e.to_string())
    });
    attempt("loopback_connection", &mut results, || {
        TcpStream::connect(("127.0.0.1", port))
            .map(|_| "connected".into())
            .map_err(|e| e.to_string())
    });
    attempt("network_bind", &mut results, || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .map(|_| "bound".into())
            .map_err(|e| e.to_string())
    });
    attempt("subprocess_true", &mut results, || {
        Command::new("/usr/bin/true")
            .status()
            .map(|s| s.to_string())
            .map_err(|e| e.to_string())
    });
    attempt("fork", &mut results, || {
        // SAFETY: fork is attempted purely to observe the sandbox verdict; the
        // child exits immediately without running any Rust runtime code.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        Ok("forked".into())
    });
    attempt("wasmtime_engine", &mut results, || {
        evx_runtime::new_engine()
            .map(|_| "engine created".into())
            .map_err(|e| e.to_string())
    });
    let mut out = std::io::stdout().lock();
    writeln!(out, "[{}]", results.join(",")).map_err(|_| "output closed")?;
    Ok(())
}
