#![allow(clippy::field_reassign_with_default)]
#![cfg(target_os = "macos")]
//! Port of the proof-of-concept baseline suite (`run_tests.py`): containment,
//! capability boundary, guest-memory boundary, malformed input, resource
//! limits, revocation, quotas and native escape simulation.

mod common;

use std::os::unix::fs::symlink;

use evx_api::{Capability, Limits, Response, Status};
use evx_supervisor::{run_guest, RunOptions};

use common::*;

fn decode_read(response: &Response) -> Vec<u8> {
    match response {
        Response::Read { data_b64, .. } => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(data_b64)
                .unwrap()
        }
        other => panic!("not a read response: {other:?}"),
    }
}

#[test]
fn no_execution_before_opt_in_and_allowed_computation() {
    let f = Fixture::new();
    f.broker.with_grant(|g| g.enabled = false);
    let artifact = compile_ok(&f.config, calc());
    let denied = run_guest(&f.config, &artifact, &f.broker, RunOptions::default());
    assert_eq!(denied.status, Status::Denied);
    assert!(!denied.worker_started);
    f.broker.with_grant(|g| g.enabled = true);
    let result = f.run(calc());
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert_eq!(result.value, Some(42));
    assert_eq!(result.worker_exit_code, Some(0));
    assert!(result.fuel_used > 0);
}

#[test]
fn narrow_capability_and_private_file_round_trip() {
    let f = Fixture::new();
    let score = f.run(&score_wat());
    assert_eq!(score.status, Status::Ok, "{score:?}");
    assert_eq!(
        score.responses,
        vec![Response::Score {
            ok: true,
            score: 42
        }]
    );
    let write = f.run(&write_wat("state/presence.txt", "game fixture"));
    assert_eq!(write.status, Status::Ok, "{write:?}");
    assert_eq!(
        write.responses,
        vec![Response::Write {
            ok: true,
            bytes: 12
        }]
    );
    assert!(write.events.contains(&"file_commit_authorized".to_string()));
    let read = f.run(&read_wat("state/presence.txt"));
    assert_eq!(decode_read(&read.responses[0]), b"game fixture");
    assert_eq!(
        std::fs::read_to_string(f.workspace.join("state/presence.txt")).unwrap(),
        "game fixture"
    );
}

#[test]
fn guest_cannot_select_other_xite_or_privileged_operations() {
    let f = Fixture::new();
    for request in [
        serde_json::json!({"op": "game.score.get", "xite": "other-game"}),
        serde_json::json!({"op": "permissionAdd", "permission": "ADMIN"}),
        serde_json::json!({"op": "http.get", "url": "https://example.invalid/"}),
        serde_json::json!({"op": "exec", "command": "true"}),
    ] {
        f.denied_call(&call_wat(&request));
    }
}

#[test]
fn traversal_absolute_cross_xite_links_and_special_files_denied() {
    let f = Fixture::new();
    f.denied_call(&read_wat("../outside-secret.txt"));
    f.denied_call(&read_wat(f.outside.to_str().unwrap()));
    f.denied_call(&read_wat("../game-b/private.txt"));
    symlink(&f.outside, f.workspace.join("outside-link")).unwrap();
    symlink(&f.other, f.workspace.join("dir-link")).unwrap();
    f.denied_call(&read_wat("outside-link"));
    f.denied_call(&read_wat("dir-link/private.txt"));
    f.denied_call(&write_wat("outside-link", "changed"));
    std::fs::hard_link(&f.outside, f.workspace.join("hard-link")).unwrap();
    f.denied_call(&read_wat("hard-link"));
    std::fs::remove_file(f.workspace.join("hard-link")).unwrap();
    let fifo = f.workspace.join("pipe-fixture");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    f.denied_call(&read_wat("pipe-fixture"));
    std::fs::remove_file(&fifo).unwrap();
    assert_eq!(
        std::fs::read_to_string(&f.outside).unwrap(),
        "sacrificial-secret-not-a-real-key"
    );
}

#[test]
fn guest_memory_boundaries_and_tiny_output_never_reach_broker() {
    let f = Fixture::new();
    let payload = br#"{"op":"game.score.get"}"#;
    let cases: [(i32, Option<i32>, i32, i32); 7] = [
        (PAGE as i32 - 1, None, 4096, 4096),
        (0, Some(PAGE as i32 + 1), 4096, 4096),
        (-1, None, 4096, 4096),
        (0, Some(-1), 4096, 4096),
        (0, None, PAGE as i32 - 1, 4096),
        (0, None, 4096, -1),
        (0, None, 4096, 1),
    ];
    for (rp, rl, op, oc) in cases {
        let result = f.run(&call_wat_raw(payload, rp, rl, op, oc));
        assert_eq!(result.status, Status::Ok, "{result:?}");
        assert_eq!(result.value, Some(-1), "{rp} {rl:?} {op} {oc}: {result:?}");
        assert_eq!(result.broker_calls, 0);
    }
    let write = serde_json::to_vec(
        &serde_json::json!({"op": "workspace.write", "path": "must-not-exist.txt", "text": "no"}),
    )
    .unwrap();
    let result = f.run(&call_wat_raw(&write, 0, None, 4096, 1));
    assert_eq!(result.value, Some(-1));
    assert!(
        !f.workspace.join("must-not-exist.txt").exists(),
        "effect happened without result capacity"
    );
    let overlap = f.run(&call_wat_raw(payload, 0, None, 0, 4096));
    assert_eq!(
        overlap.responses,
        vec![Response::Score {
            ok: true,
            score: 42
        }],
        "{overlap:?}"
    );
}

#[test]
fn malformed_requests_and_oversized_input() {
    let f = Fixture::new();
    for raw in [
        &b""[..],
        br#"{"op":"#,
        b"\xff",
        br#"{"op":"workspace.read","op":"game.score.get"}"#,
    ] {
        f.denied_call(&call_wat_raw(raw, 0, None, 4096, 4096));
    }
    let big = serde_json::to_vec(&serde_json::json!({"op": "workspace.write", "path": "oversized.txt", "text": "x".repeat(9000)})).unwrap();
    let result = f.run(&call_wat_raw(&big, 0, None, 4096, 4096));
    assert_eq!(result.value, Some(-1), "{result:?}");
    assert_eq!(result.broker_calls, 0);
}

#[test]
fn unsupported_imports_malformed_modules_and_start_functions_fail_before_effects() {
    let f = Fixture::new();
    let wasi = r#"(module (import "wasi_snapshot_preview1" "path_open" (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32))) (memory (export "memory") 1) (func (export "run") (result i32) i32.const 0))"#;
    let net = r#"(module (import "wasi_snapshot_preview1" "sock_open" (func (param i32 i32 i32) (result i32))) (memory (export "memory") 1) (func (export "run") (result i32) i32.const 0))"#;
    for source in [wasi, net] {
        let error = compile(&f.config, source).unwrap_err();
        assert!(error.contains("unsupported import"), "{error}");
    }
    assert!(compile(&f.config, "(module (func").is_err());
    let start = write_wat("bad-abi-effect.txt", "must not write").replace(
        "(func (export \"run\") (result i32)",
        "(func $effect (result i32)",
    );
    let start = format!("{}(func $start call $effect drop) (start $start) (func (export \"run\") (result i32) i32.const 0))", &start[..start.len() - 1]);
    assert!(compile(&f.config, &start).is_err());
    assert!(!f.workspace.join("bad-abi-effect.txt").exists());
    let long = f.denied_call(&write_wat(
        &format!("must-not-create/{}", "x".repeat(300)),
        "no",
    ));
    assert!(!f.workspace.join("must-not-create").exists(), "{long:?}");
}

#[test]
fn memory_growth_fuel_and_wall_deadlines() {
    let f = Fixture::new();
    let mut limits = Limits::default();
    limits.memory_bytes = 65536;
    f.broker.set_limits(limits.clone()).unwrap();
    let low = f.run(&memory_grow(1));
    assert_eq!(low.value, Some(-1), "{low:?}");
    assert_eq!(low.memory_bytes, 65536);
    limits.memory_bytes = 131072;
    f.broker.set_limits(limits).unwrap();
    let high = f.run(&memory_grow(1));
    assert_eq!(high.value, Some(1));
    assert_eq!(high.memory_bytes, 131072);
    f.broker.set_limits(Limits::default()).unwrap();

    let fuel = f.run(infinite_loop());
    assert_eq!(fuel.status, Status::Error, "{fuel:?}");
    assert!(fuel.error.as_deref().unwrap().contains("fuel"), "{fuel:?}");
    assert_eq!(fuel.fuel_used, Limits::default().fuel);

    let mut limits = Limits::default();
    limits.fuel = 1_000_000_000_000;
    limits.wall_seconds = 0.4;
    limits.host_call_seconds = 0.3;
    f.broker.set_limits(limits).unwrap();
    let timeout = f.run(infinite_loop());
    assert_eq!(timeout.status, Status::Timeout, "{timeout:?}");
    assert_ne!(timeout.worker_exit_code, Some(0));
    assert!(timeout.supervisor_elapsed_ms < 1500.0, "{timeout:?}");
    let stalled = f.run_with(
        &score_wat(),
        RunOptions {
            stall_broker: true,
            ..Default::default()
        },
    );
    assert_eq!(stalled.status, Status::Timeout, "{stalled:?}");
    assert_ne!(stalled.worker_exit_code, Some(0));
}

#[test]
fn host_call_budget_capability_denial_and_live_revocation() {
    let f = Fixture::new();
    let budget = f.run(&repeated_calls_wat(17));
    assert_eq!(budget.status, Status::Error, "{budget:?}");
    assert!(
        budget
            .error
            .as_deref()
            .unwrap()
            .contains("host call budget"),
        "{budget:?}"
    );
    assert_eq!(budget.broker_calls, 16);

    f.set_capabilities(&[Capability::GameScoreGet]);
    f.denied_call(&write_wat("denied.txt", "no"));
    assert!(!f.workspace.join("denied.txt").exists());
    f.set_capabilities(&Capability::all());

    let revoked = f.run_with(
        &repeated_calls_wat(2),
        RunOptions {
            revoke_before_call: Some(2),
            ..Default::default()
        },
    );
    assert!(
        revoked.responses[0].is_ok() && !revoked.responses[1].is_ok(),
        "{revoked:?}"
    );
    let next = f.run(calc());
    assert!(
        !next.worker_started,
        "revoked grant launched another worker: {next:?}"
    );
    f.broker.with_grant(|g| g.enabled = true);
    let healthy = f.run(calc());
    assert_eq!(healthy.value, Some(42));
}

#[test]
fn storage_quota_rejects_growth_and_preserves_data_after_reduction() {
    let f = Fixture::new();
    let mut limits = Limits::default();
    limits.storage_bytes = 1024;
    f.broker.set_limits(limits).unwrap();
    let first = f.run(&write_wat("saved.txt", &"x".repeat(768)));
    assert!(first.responses[0].is_ok(), "{first:?}");
    f.denied_call(&write_wat("extra.txt", &"x".repeat(512)));
    f.broker.set_storage_limit(32).unwrap();
    f.denied_call(&write_wat("small.txt", "x"));
    let readable = f.run(&read_wat("saved.txt"));
    assert_eq!(
        decode_read(&readable.responses[0]).len(),
        768,
        "lowering destroyed data"
    );
    f.broker.set_storage_limit(2048).unwrap();
    let raised = f.run(&write_wat("extra.txt", &"x".repeat(512)));
    assert!(raised.responses[0].is_ok(), "{raised:?}");
    assert_eq!(f.broker.usage().unwrap().0, 768 + 512);
}

#[test]
fn native_escape_simulation_denies_files_network_and_children() {
    let f = Fixture::new();
    std::fs::write(f.workspace.join("native-fixture.txt"), "readable fixture").unwrap();
    symlink(&f.outside, f.workspace.join("outside-link")).unwrap();
    let destination = f.dir.path().join("outside-write.txt");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Controls: the fixture and listener are reachable by the trusted parent.
    assert_eq!(
        std::fs::read_to_string(&f.outside).unwrap(),
        "sacrificial-secret-not-a-real-key"
    );
    std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    listener.accept().unwrap();
    let output = std::process::Command::new(worker_binary())
        .args([
            "probe",
            f.outside.to_str().unwrap(),
            destination.to_str().unwrap(),
            &port.to_string(),
            f.workspace.to_str().unwrap(),
        ])
        .current_dir(&f.workspace)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let allowed = |op: &str| {
        findings
            .iter()
            .find(|v| v["op"] == op)
            .unwrap_or_else(|| panic!("missing {op}"))["allowed"]
            .as_bool()
            .unwrap()
    };
    assert!(allowed("workspace_read"));
    assert!(allowed("wasmtime_engine"));
    for op in [
        "workspace_write",
        "outside_read",
        "outside_write",
        "symlink_read",
        "etc_hosts_read",
        "home_listing",
        "loopback_connection",
        "network_bind",
        "subprocess_true",
        "fork",
    ] {
        assert!(!allowed(op), "{op} was allowed: {findings:?}");
    }
    assert!(!destination.exists() && !f.workspace.join("native-probe.txt").exists());
    listener.set_nonblocking(true).unwrap();
    assert!(listener.accept().is_err(), "native worker reached listener");
    assert_eq!(
        std::fs::read_to_string(&f.outside).unwrap(),
        "sacrificial-secret-not-a-real-key"
    );
}

#[test]
fn healthy_worker_after_failures_and_outside_secret_unchanged() {
    let f = Fixture::new();
    let _ = f.run(infinite_loop());
    let _ = f.denied_call(&read_wat("../outside-secret.txt"));
    let result = f.run(calc());
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert_eq!(result.value, Some(42));
    assert_eq!(
        std::fs::read_to_string(&f.outside).unwrap(),
        "sacrificial-secret-not-a-real-key"
    );
}
