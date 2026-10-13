#![allow(clippy::field_reassign_with_default)]
#![cfg(any(target_os = "macos", target_os = "linux"))]
//! Cancellation, commit authorization and workspace leases. Port of
//! `test_supervisor_lifecycle.py`, including the supervisor-death fixture,
//! which re-invokes this test binary as a controlled crashing supervisor.

mod common;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use evx_api::frames::{encode, HelperFault, ToHelper};
use evx_api::{Capability, Grant, Limits, Request, Status};
use evx_supervisor::process::{Event, Peer, Role};
use evx_supervisor::{run_guest, Broker, RunOptions};

use common::*;

fn lifecycle_limits() -> Limits {
    let mut limits = Limits::default();
    limits.wall_seconds = 5.0;
    limits.host_call_seconds = 1.5;
    limits.process_cpu_seconds = 2.5;
    limits.process_rss_bytes = 256 * 1024 * 1024;
    limits
}

fn fixture() -> Fixture {
    let f = Fixture::new();
    f.broker.set_limits(lifecycle_limits()).unwrap();
    f
}

fn assert_clean_children(f: &Fixture, result: &evx_api::RunResult) {
    assert!(result.worker_started, "{result:?}");
    assert!(!result.children.is_empty(), "{result:?}");
    for child in &result.children {
        assert!(child.exit_code.is_some(), "{result:?}");
    }
    assert!(!f.broker.quarantined(), "{result:?}");
}

/// Run an uncancellable loop on a scoped thread, invoke `during` once the
/// workspace lease is held, and return the invocation's result.
fn run_cancellable(f: &Fixture, options: RunOptions, during: impl FnOnce()) -> evx_api::RunResult {
    let mut limits = lifecycle_limits();
    limits.fuel = 1_000_000_000_000;
    f.broker.set_limits(limits).unwrap();
    let artifact = compile_ok(&f.config, infinite_loop());
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| run_guest(&f.config, &artifact, &f.broker, options));
        await_lease(f);
        during();
        handle.join().unwrap()
    })
}

fn await_lease(f: &Fixture) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if f.broker.lock().running {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("fixture did not acquire workspace lease");
}

#[test]
fn blocked_native_helper_is_killed_and_next_operation_recovers() {
    let f = fixture();
    let mut limits = lifecycle_limits();
    limits.host_call_seconds = 0.8;
    f.broker.set_limits(limits).unwrap();
    let result = f.run_with(
        &write_wat("blocked.txt", "not committed"),
        RunOptions {
            file_fault: Some(HelperFault::BlockBeforeOperation),
            ..Default::default()
        },
    );
    assert!(
        result.events.contains(&"native_fault_entered".to_string()),
        "{result:?}"
    );
    assert!(
        result.events.contains(&"native_call_deadline".to_string()),
        "{result:?}"
    );
    assert!(!f.workspace.join("blocked.txt").exists());
    assert!(!result.effect_outcome_unknown, "{result:?}");
    let files: Vec<_> = result
        .children
        .iter()
        .filter(|c| c.role == "file")
        .collect();
    assert_eq!(files.len(), 1, "{result:?}");
    assert!(files[0].exit_code.unwrap() < 0, "{result:?}");
    assert_clean_children(&f, &result);
    let recovery = f.run(&write_wat("recovered.txt", "ready"));
    assert_eq!(recovery.status, Status::Ok, "{recovery:?}");
    assert!(recovery.responses[0].is_ok());
    assert_eq!(
        std::fs::read_to_string(f.workspace.join("recovered.txt")).unwrap(),
        "ready"
    );
}

#[test]
fn direct_revocation_stops_pure_computation() {
    let f = fixture();
    let revoked_at = std::sync::Mutex::new(None);
    let result = run_cancellable(&f, RunOptions::default(), || {
        std::thread::sleep(Duration::from_millis(700));
        *revoked_at.lock().unwrap() = Some(Instant::now());
        f.broker.revoke();
    });
    assert!(
        revoked_at.lock().unwrap().unwrap().elapsed() < Duration::from_secs(1),
        "{result:?}"
    );
    assert!(
        result.error.as_deref().unwrap_or("").contains("revoked"),
        "{result:?}"
    );
    assert_eq!(result.broker_calls, 0);
    assert_eq!(
        result.host_cancellation,
        Some(evx_api::HostCancellation::AuthorityChanged),
        "{result:?}"
    );
    assert_clean_children(&f, &result);
}

#[test]
fn terminal_worker_memory_follows_platform_attribution() {
    use evx_api::frames::{decode_compiler_reply, FromCompiler, ToCompiler};

    let f = fixture();
    let (tx, rx) = mpsc::sync_channel(8);
    let mut peer = Peer::spawn(&f.config, "compile", &f.workspace, Role::Compiler, tx, None).unwrap();
    peer.send(&encode(&ToCompiler::CompileText {
        source: calc().as_bytes().to_vec(),
    }).unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < deadline, "compiler did not return its artifact");
        peer.flush_input().unwrap();
        if let Ok(Event::Frame(_, _, frame)) = rx.recv_timeout(Duration::from_millis(10)) {
            assert!(matches!(decode_compiler_reply(&frame).unwrap(), FromCompiler::Artifact { .. }));
            break;
        }
    }
    // No live measurement was taken. Only the kernel's terminal usage can
    // supply this result, as when cancellation wins the first sample race.
    assert_eq!(peer.last_rss, None);
    peer.close(Duration::from_millis(50), Duration::from_secs(1)).unwrap();
    assert!(peer.max_cpu > 0.0);
    #[cfg(target_os = "macos")]
    assert!(peer.last_rss.is_some_and(|rss| rss > 0), "terminal RSS was lost");
    // Linux wait4 can include inherited parent memory. Without a live
    // post-exec sample, memory must remain unobserved instead of misattributed.
    #[cfg(target_os = "linux")]
    assert_eq!(peer.last_rss, None, "inherited RSS was attributed to the worker");
}

#[test]
fn lowering_active_cpu_budget_stops_pure_computation() {
    let f = fixture();
    let changed_at = std::sync::Mutex::new(None);
    let result = run_cancellable(&f, RunOptions::default(), || {
        std::thread::sleep(Duration::from_millis(300));
        let mut limits = f.broker.limits();
        limits.process_cpu_seconds = 0.05;
        *changed_at.lock().unwrap() = Some(Instant::now());
        f.broker.set_limits(limits).unwrap();
    });
    assert!(
        changed_at.lock().unwrap().unwrap().elapsed() < Duration::from_millis(600),
        "stale active limits: {result:?}"
    );
    assert_eq!(result.status, Status::ResourceLimit, "{result:?}");
    assert_clean_children(&f, &result);
}

#[test]
fn event_revocation_stops_pure_computation() {
    let f = fixture();
    let revoke = Arc::new(AtomicBool::new(false));
    let revoked_at = std::sync::Mutex::new(None);
    let flag = revoke.clone();
    let result = run_cancellable(
        &f,
        RunOptions {
            revoke_event: Some(revoke),
            ..Default::default()
        },
        || {
            std::thread::sleep(Duration::from_millis(700));
            *revoked_at.lock().unwrap() = Some(Instant::now());
            flag.store(true, Ordering::Relaxed);
        },
    );
    assert!(
        revoked_at.lock().unwrap().unwrap().elapsed() < Duration::from_secs(1),
        "{result:?}"
    );
    assert!(
        result.error.as_deref().unwrap_or("").contains("revoked"),
        "{result:?}"
    );
    assert_clean_children(&f, &result);
}

#[test]
fn quota_lowered_before_commit_preserves_existing_file() {
    let f = fixture();
    let target = f.workspace.join("state.txt");
    std::fs::write(&target, "old").unwrap();
    let result = f.run_with(
        &write_wat("state.txt", "new value"),
        RunOptions {
            before_file_commit: Some(Box::new(|broker: &Broker| {
                broker.set_storage_limit(3).unwrap()
            })),
            ..Default::default()
        },
    );
    assert!(
        result
            .error
            .as_deref()
            .unwrap_or("")
            .contains("limits changed before commit"),
        "{result:?}"
    );
    assert!(!result
        .events
        .contains(&"file_commit_authorized".to_string()));
    assert!(!result.effect_outcome_unknown);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
    assert_clean_children(&f, &result);
    f.broker.set_storage_limit(4096).unwrap();
    let recovery = f.run(&write_wat("state.txt", "recovered"));
    assert_eq!(recovery.status, Status::Ok, "{recovery:?}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "recovered");
    assert!(std::fs::read_dir(&f.workspace).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".pending-")));
}

#[test]
fn revocation_at_commit_preserves_existing_file() {
    let f = fixture();
    let target = f.workspace.join("state.txt");
    std::fs::write(&target, "old").unwrap();
    let result = f.run_with(
        &write_wat("state.txt", "new"),
        RunOptions {
            revoke_at_file_commit: true,
            ..Default::default()
        },
    );
    assert!(
        result.error.as_deref().unwrap_or("").contains("revoked"),
        "{result:?}"
    );
    assert!(!result
        .events
        .contains(&"file_commit_authorized".to_string()));
    assert!(!result.effect_outcome_unknown);
    assert_eq!(
        result.host_cancellation,
        Some(evx_api::HostCancellation::AuthorityChanged),
        "{result:?}"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
    assert_clean_children(&f, &result);
    f.broker.with_grant(|g| {
        g.enabled = true;
        g.generation += 1;
    });
    assert_eq!(f.run(calc()).value, Some(42));
}

#[test]
fn concurrent_admission_cannot_release_a_held_lease() {
    let f = fixture();
    let other = Broker::new(
        &f.workspace,
        Grant::new("game-a", true).unwrap(),
        lifecycle_limits(),
    )
    .unwrap();
    let artifact = compile_ok(&f.config, calc());
    run_cancellable(&f, RunOptions::default(), || {
        for contender in [&f.broker, &other] {
            let denied = run_guest(&f.config, &artifact, contender, RunOptions::default());
            assert_eq!(denied.status, Status::Denied, "{denied:?}");
            assert_eq!(denied.error.as_deref(), Some("workspace busy"));
            assert!(!denied.worker_started);
        }
        f.broker.revoke();
    });
    let recovered = run_guest(&f.config, &artifact, &other, RunOptions::default());
    assert_eq!(recovered.value, Some(42), "{recovered:?}");
}

/// Controlled crashing supervisor: holds the lease, starts a real blocked
/// helper that inherits it, prints the helper's pid, then exits abruptly.
fn lease_supervisor(workspace: &Path) {
    let broker = Broker::new(
        workspace,
        Grant::new("game-fixture", true).unwrap(),
        lifecycle_limits(),
    )
    .unwrap();
    rustix::fs::flock(
        broker.root_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .expect("lease");
    let (tx, rx) = mpsc::sync_channel(8);
    let lease_fd = rustix::fd::AsRawFd::as_raw_fd(&broker.root_fd());
    let config = config();
    let mut helper =
        Peer::spawn(&config, "file", workspace, Role::File, tx, Some(lease_fd)).expect("helper");
    let init = encode(&ToHelper::Init {
        xite: "game-fixture".into(),
        generation: 1,
        capabilities: Capability::all().to_vec(),
        limits: lifecycle_limits(),
        request: Request::WorkspaceWrite {
            path: "never-committed.txt".into(),
            text: "fixture".into(),
        },
        test_fault: Some(HelperFault::BlockBeforeOperation),
    })
    .unwrap();
    helper.send(&init).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(Event::Frame(_, _, body)) = rx.recv_timeout(Duration::from_millis(20)) {
            if String::from_utf8_lossy(&body).contains("fault_entered") {
                println!("{}", helper.pid);
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line).unwrap();
                assert_eq!(line.trim(), "exit");
                // Intentional controlled crash: no cleanup runs, the helper keeps
                // the inherited lease.
                std::mem::forget(helper);
                std::mem::forget(broker);
                std::process::exit(0);
            }
        }
        if helper.poll().is_some() {
            panic!("lease helper exited before blocking");
        }
    }
    panic!("lease helper startup deadline");
}

#[test]
fn inherited_lease_survives_supervisor_death() {
    if std::env::var("EVX_LEASE_SUPERVISOR").is_ok() {
        lease_supervisor(&PathBuf::from(
            std::env::var("EVX_LEASE_SUPERVISOR").unwrap(),
        ));
        return;
    }
    let f = fixture();
    let exe = std::env::current_exe().unwrap();
    let mut supervisor = std::process::Command::new(exe)
        .args([
            "--exact",
            "inherited_lease_survives_supervisor_death",
            "--nocapture",
        ])
        .env("EVX_LEASE_SUPERVISOR", &f.workspace)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = supervisor.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    let helper_pid: i32 = loop {
        line.clear();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "controlled supervisor exited without a helper pid"
        );
        if let Ok(pid) = line.trim().parse::<i32>() {
            break pid;
        }
    };
    let mut stdin = supervisor.stdin.take().unwrap();
    stdin.write_all(b"exit\n").unwrap();
    stdin.flush().unwrap();
    let status = supervisor.wait().unwrap();
    assert!(status.success(), "controlled supervisor failed");
    // The lease now lives only in the orphaned helper.
    let artifact = compile_ok(&f.config, calc());
    let denied = run_guest(&f.config, &artifact, &f.broker, RunOptions::default());
    assert_eq!(denied.status, Status::Denied, "{denied:?}");
    assert_eq!(denied.error.as_deref(), Some("workspace busy"));
    assert!(!denied.worker_started);
    // Stop the known orphan and recover.
    unsafe {
        libc::killpg(helper_pid, libc::SIGKILL);
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && unsafe { libc::kill(helper_pid, 0) } == 0 {
        std::thread::sleep(Duration::from_millis(10));
    }
    let recovered = run_guest(&f.config, &artifact, &f.broker, RunOptions::default());
    assert_eq!(recovered.value, Some(42), "{recovered:?}");
    assert!(!f.workspace.join("never-committed.txt").exists());
}

#[test]
fn cpu_budget_above_three_seconds_is_honored() {
    let f = fixture();
    let mut limits = lifecycle_limits();
    limits.fuel = 1_000_000_000_000;
    limits.process_cpu_seconds = 3.2;
    limits.wall_seconds = 8.0;
    f.broker.set_limits(limits).unwrap();
    let artifact = compile_ok(&f.config, infinite_loop());
    let result = run_guest(&f.config, &artifact, &f.broker, Default::default());
    assert_eq!(
        result.status,
        Status::ResourceLimit,
        "premature fixed CPU cap: {result:?}"
    );
    assert!(
        result.trusted_observations.as_ref().unwrap().cpu_seconds >= 3.2,
        "{result:?}"
    );
    assert_clean_children(&f, &result);
}

#[test]
fn lowering_active_guest_memory_or_fuel_cancels_computation() {
    for memory in [false, true] {
        let f = fixture();
        let changed_at = std::sync::Mutex::new(None);
        let result = run_cancellable(&f, Default::default(), || {
            std::thread::sleep(Duration::from_millis(300));
            let mut limits = f.broker.limits();
            if memory {
                limits.memory_bytes = 65_536;
            } else {
                limits.fuel = 1;
            }
            *changed_at.lock().unwrap() = Some(Instant::now());
            f.broker.set_limits(limits).unwrap();
        });
        assert!(
            changed_at.lock().unwrap().unwrap().elapsed() < Duration::from_millis(600),
            "stale guest limits (memory={memory}): {result:?}"
        );
        assert_eq!(result.status, Status::ResourceLimit, "{result:?}");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("guest limits lowered"),
            "{result:?}"
        );
        assert_clean_children(&f, &result);
    }
}

#[test]
fn read_helper_has_no_native_write_authority() {
    let f = fixture();
    std::fs::write(f.workspace.join("read.txt"), "fixture").unwrap();
    let result = f.run_with(
        &read_wat("read.txt"),
        RunOptions {
            file_fault: Some(HelperFault::ReadOnlyWriteProbe),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert!(
        !f.workspace.join("read-only-native-probe.txt").exists(),
        "read helper could write directly: {result:?}"
    );
    assert_eq!(
        result.responses,
        vec![evx_api::Response::error("native write denied")]
    );
    assert_clean_children(&f, &result);
}

fn two_reads_wat(path: &str) -> String {
    let request = serde_json::json!({"op":"workspace.read", "path":path});
    let len = serde_json::to_vec(&request).unwrap().len();
    call_wat(&request).replace("call $call))", &format!("call $call drop i32.const 0 i32.const {len} i32.const 4096 i32.const 4096 call $call))"))
}

fn late_helper_event(kind: u8) {
    use evx_api::frames::FromHelper;
    use evx_supervisor::process::Stream;
    use std::sync::atomic::AtomicU64;
    let f = fixture();
    let mut limits = lifecycle_limits();
    limits.host_call_seconds = 0.2;
    f.broker.set_limits(limits).unwrap();
    let write = f.run(&write_wat("state.txt", "current"));
    assert_eq!(write.status, Status::Ok, "{write:?}");
    let previous = Arc::new(AtomicU64::new(0));
    let saved = previous.clone();
    let result = f.run_with(
        &two_reads_wat("state.txt"),
        RunOptions {
            file_fault: Some(HelperFault::BlockBeforeOperation),
            file_fault_once: true,
            after_helper_spawn: Some(Box::new(move |call, id, tx| {
                if call == 1 {
                    saved.store(id, Ordering::SeqCst);
                }
                if call == 2 {
                    let old = saved.load(Ordering::SeqCst);
                    assert_ne!(old, id);
                    let event = match kind {
                        0 => Event::Frame(
                            Role::File,
                            old,
                            serde_json::to_vec(&FromHelper::FileResult {
                                response: evx_api::Response::error("retired response"),
                            })
                            .unwrap(),
                        ),
                        1 => Event::Frame(
                            Role::File,
                            old,
                            serde_json::to_vec(&FromHelper::Prepared).unwrap(),
                        ),
                        _ => Event::Closed(
                            Role::File,
                            old,
                            Stream::Stdout,
                            Some("retired protocol error"),
                        ),
                    };
                    tx.send(event).unwrap();
                }
            })),
            ..Default::default()
        },
    );
    assert_eq!(
        result.status,
        Status::Ok,
        "retired event changed current invocation: {result:?}"
    );
    assert_eq!(result.responses.len(), 2, "{result:?}");
    assert!(!result.responses[0].is_ok());
    assert_eq!(
        result.responses[1],
        evx_api::Response::Read {
            ok: true,
            bytes: 7,
            data_b64: "Y3VycmVudA==".into()
        },
        "{result:?}"
    );
    assert!(
        !result
            .events
            .contains(&"file_commit_authorized".to_string()),
        "retired Prepared authorized a commit: {result:?}"
    );
    assert_clean_children(&f, &result);
}

#[test]
fn late_helper_result_cannot_replace_current_response() {
    late_helper_event(0);
}
#[test]
fn late_helper_prepared_cannot_authorize_current_commit() {
    late_helper_event(1);
}
#[test]
fn late_helper_protocol_error_cannot_abort_replacement() {
    late_helper_event(2);
}

fn unconfirmed_cleanup(commit: bool) {
    const CHILD: &str = "EVX_HELPER_QUARANTINE_FIXTURE";
    if std::env::var_os(CHILD).is_none() {
        let test = if commit {
            "unconfirmed_commit_cleanup_preserves_effect_uncertainty"
        } else {
            "unconfirmed_helper_cleanup_quarantines_the_workspace"
        };
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let f = fixture();
    let artifact = compile_ok(&f.config, calc());
    let mut limits = lifecycle_limits();
    limits.host_call_seconds = 0.2;
    f.broker.set_limits(limits).unwrap();
    let result = f.run_with(
        &write_wat("pending.txt", "fixture"),
        RunOptions {
            file_fault: Some(if commit {
                HelperFault::BlockAfterAuthorization
            } else {
                HelperFault::BlockBeforeOperation
            }),
            // Inject an unconfirmed first reap. Final cleanup still kills the
            // sacrificial child; no real unkillable OS task is created.
            fail_file_cleanup: true,
            ..Default::default()
        },
    );
    assert_eq!(
        result.status,
        Status::Quarantined,
        "cleanup uncertainty escaped bookkeeping: {result:?}"
    );
    assert!(f.broker.quarantined());
    assert_eq!(result.effect_outcome_unknown, commit, "{result:?}");
    assert!(
        result.children.iter().any(|child| child.role == "file"),
        "untracked helper: {result:?}"
    );
    let mut config = f.config.clone();
    config.worker_binary = std::path::PathBuf::from("/missing-evx-quarantine-fixture");
    let other = fixture();
    let denied = run_guest(&config, &artifact, &other.broker, RunOptions::default());
    assert_eq!(
        denied.status,
        Status::Quarantined,
        "other workspace admitted: {denied:?}"
    );
    assert!(!denied.worker_started);
    let compiler = evx_supervisor::compile_module(&config, &[0]);
    assert!(compiler.unwrap_err().to_string().contains("quarantin"));
}
#[test]
fn unconfirmed_helper_cleanup_quarantines_the_workspace() {
    unconfirmed_cleanup(false);
}
#[test]
fn unconfirmed_commit_cleanup_preserves_effect_uncertainty() {
    unconfirmed_cleanup(true);
}

#[test]
fn read_helper_cannot_request_commit_authority() {
    let f = fixture();
    std::fs::write(f.workspace.join("state.txt"), "current").unwrap();
    let result = f.run_with(
        &read_wat("state.txt"),
        RunOptions {
            after_helper_spawn: Some(Box::new(|_, id, tx| {
                tx.send(Event::Frame(
                    Role::File,
                    id,
                    serde_json::to_vec(&evx_api::frames::FromHelper::Prepared).unwrap(),
                ))
                .unwrap();
            })),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::Error, "{result:?}");
    assert!(
        !result
            .events
            .contains(&"file_commit_authorized".to_string()),
        "{result:?}"
    );
    assert!(
        !result.effect_outcome_unknown,
        "read has no effect: {result:?}"
    );
}
