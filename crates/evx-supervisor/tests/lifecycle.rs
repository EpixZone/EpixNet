#![allow(clippy::field_reassign_with_default)]
#![cfg(target_os = "macos")]
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
    let (tx, rx) = mpsc::channel();
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
        if let Ok(Event::Frame(_, body)) = rx.recv_timeout(Duration::from_millis(20)) {
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
