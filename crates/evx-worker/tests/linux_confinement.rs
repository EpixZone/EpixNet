#![cfg(target_os = "linux")]
//! Runs only sacrificial native probes. A kernel without Landlock must refuse
//! before reading stdin. Supported-kernel CI additionally exercises the real
//! sandbox and the full supervisor integration suites.

use std::process::{Command, Stdio};

fn abi() -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    }
}

#[test]
fn unavailable_landlock_refuses_before_input() {
    if abi() >= 3 {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_evx-worker"))
        .arg("run")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Landlock ABI 3 or newer required"));
}

#[test]
fn supported_kernel_contains_native_probe() {
    if abi() < 3 {
        // The refusal test is still mandatory. Native CI sets this to make a
        // missing security module a failure rather than a skipped success.
        assert!(
            std::env::var_os("EVX_REQUIRE_LINUX_CONFINEMENT").is_none(),
            "Landlock unavailable on required conformance host"
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let workspace = root.join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let outside = root.join("outside.txt");
    std::fs::write(&outside, "sacrificial fixture").unwrap();
    std::fs::write(workspace.join("native-fixture.txt"), "fixture").unwrap();
    std::os::unix::fs::symlink(&outside, workspace.join("outside-link")).unwrap();
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_evx-worker"))
        .arg("probe")
        .arg(&outside)
        .arg(root.join("must-not-exist"))
        .arg(socket.local_addr().unwrap().port().to_string())
        .arg(&workspace)
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "sacrificial fixture"
    );
    assert_eq!(
        std::fs::read_to_string(workspace.join("native-fixture.txt")).unwrap(),
        "fixture"
    );
    assert!(!root.join("must-not-exist").exists());
    assert!(!workspace.join("native-probe.txt").exists());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let observed: std::collections::BTreeSet<_> =
        rows.iter().map(|row| row["op"].as_str().unwrap()).collect();
    let expected = [
        "outside_read",
        "outside_write",
        "workspace_read",
        "workspace_write",
        "workspace_truncate_readonly",
        "symlink_read",
        "etc_hosts_read",
        "home_listing",
        "loopback_connection",
        "network_bind",
        "subprocess_true",
        "fork",
        "raise_cpu_limit",
        "wasmtime_engine",
    ]
    .into_iter()
    .collect();
    assert_eq!(observed, expected, "every containment probe must execute");
    assert_eq!(rows.len(), observed.len(), "duplicate probe result");
    // HOME is cleared, so this must probe the real Linux home directory,
    // not a missing directory that would fail without any confinement.
    assert!(std::path::Path::new("/home").is_dir());
    let home = rows.iter().find(|row| row["op"] == "home_listing").unwrap();
    assert!(
        home["detail"]
            .as_str()
            .unwrap()
            .contains("Permission denied"),
        "home listing must be rejected by the policy: {home}"
    );
    for row in rows {
        let expected = matches!(
            row["op"].as_str(),
            Some("workspace_read" | "wasmtime_engine")
        );
        assert_eq!(row["allowed"].as_bool(), Some(expected), "{row}");
    }
}
