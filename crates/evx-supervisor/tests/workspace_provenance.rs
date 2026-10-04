#![cfg(any(target_os = "macos", target_os = "linux"))]
//! Production broker regressions for bytes whose path does not prove origin.
mod common;
use common::*;
use evx_api::{Response, Status};

#[test]
fn unregistered_workspace_bytes_never_reach_the_guest() {
    let f = Fixture::new();
    let target = f.workspace.join("score.txt");
    std::fs::write(&target, "outside fixture bytes").unwrap();
    let result = f.run(&read_wat("score.txt"));
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert_eq!(result.responses.len(), 1, "{result:?}");
    assert!(
        matches!(&result.responses[0], Response::Error { ok: false, .. }),
        "unregistered bytes escaped broker: {result:?}"
    );
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("outside fixture bytes"));
    assert_eq!(
        std::fs::read_to_string(target).unwrap(),
        "outside fixture bytes"
    );
}

fn read_bytes(response: &Response) -> Vec<u8> {
    use base64::Engine;
    let Response::Read { data_b64, .. } = response else {
        panic!("not a read: {response:?}")
    };
    base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .unwrap()
}

#[test]
fn provenance_survives_broker_restart_and_rejects_changed_bytes_and_paths() {
    use evx_api::{Grant, Limits};
    use evx_supervisor::{run_guest, Broker, RunOptions};
    let f = Fixture::new();
    let write = f.run(&write_wat("score.txt", "inside"));
    assert_eq!(write.status, Status::Ok, "{write:?}");
    let broker = Broker::new(
        &f.workspace,
        Grant::new("game-a", true).unwrap(),
        Limits::default(),
    )
    .unwrap();
    let program = compile_ok(&f.config, &read_wat("score.txt"));
    let read = run_guest(&f.config, &program, &broker, RunOptions::default());
    assert_eq!(read_bytes(&read.responses[0]), b"inside");
    std::fs::copy(f.workspace.join("score.txt"), f.workspace.join("other.txt")).unwrap();
    f.denied_call(&read_wat("other.txt"));
    std::fs::write(f.workspace.join("score.txt"), "substituted outside bytes").unwrap();
    f.denied_call(&read_wat("score.txt"));
}

#[test]
fn concurrent_link_replacement_never_releases_outside_bytes() {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicBool, Ordering};
    let f = Fixture::new();
    let write = f.run(&write_wat("score.txt", "inside"));
    assert_eq!(write.status, Status::Ok, "{write:?}");
    let source = read_wat("score.txt");
    let artifact = compile_ok(&f.config, &source);
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            let next = f.workspace.join("replacement");
            let target = f.workspace.join("score.txt");
            let mut n = 0;
            while !stop.load(Ordering::Acquire) {
                match n % 3 {
                    0 => symlink(&f.outside, &next).unwrap(),
                    1 => std::fs::hard_link(&f.outside, &next).unwrap(),
                    _ => std::fs::write(&next, "inside").unwrap(),
                }
                std::fs::rename(&next, &target).unwrap();
                n += 1;
            }
        });
        let results: Vec<_> = (0..24)
            .map(|_| evx_supervisor::run_guest(&f.config, &artifact, &f.broker, Default::default()))
            .collect();
        stop.store(true, Ordering::Release);
        writer.join().unwrap();
        for result in results {
            assert_eq!(result.status, Status::Ok, "{result:?}");
            for response in &result.responses {
                if response.is_ok() {
                    assert_eq!(read_bytes(response), b"inside");
                }
            }
        }
    });
    assert_eq!(
        std::fs::read_to_string(&f.outside).unwrap(),
        "sacrificial-secret-not-a-real-key"
    );
}

#[test]
fn substituted_staged_source_cannot_be_read_as_authorized_content() {
    let f = Fixture::new();
    let result = f.run_with(
        &write_wat("score.txt", "authorized"),
        evx_supervisor::RunOptions {
            before_file_commit: Some(Box::new(|broker| {
                let pending = std::fs::read_dir(broker.workspace())
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".pending-")
                    })
                    .unwrap();
                std::fs::write(pending, "outside source bytes").unwrap();
            })),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert_eq!(
        std::fs::read_to_string(f.workspace.join("score.txt")).unwrap(),
        "outside source bytes"
    );
    f.denied_call(&read_wat("score.txt"));
}

#[test]
fn uncertain_write_requires_explicit_reconciliation_before_different_content() {
    use evx_api::frames::HelperFault;
    for after_replace in [false, true] {
        let f = Fixture::new();
        assert_eq!(f.run(&write_wat("score.txt", "old")).status, Status::Ok);
        let mut limits = f.broker.limits();
        limits.host_call_seconds = 0.25;
        f.broker.set_limits(limits).unwrap();
        let result = f.run_with(
            &write_wat("score.txt", "candidate"),
            evx_supervisor::RunOptions {
                file_fault: Some(if after_replace {
                    HelperFault::FailAfterReplace
                } else {
                    HelperFault::BlockAfterAuthorization
                }),
                ..Default::default()
            },
        );
        assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
        let read = f.run(&read_wat("score.txt"));
        assert_eq!(
            read_bytes(&read.responses[0]),
            if after_replace {
                b"candidate" as &[u8]
            } else {
                b"old"
            }
        );
        let blocked = f.run(&write_wat("score.txt", "later"));
        assert_ne!(blocked.status, Status::Ok, "{blocked:?}");
        assert!(!blocked.events.iter().any(|e| e == "file_commit_authorized"));
        assert_eq!(
            evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
            1
        );
        assert_eq!(f.run(&write_wat("score.txt", "later")).status, Status::Ok);
    }
}

#[test]
fn host_reconciliation_of_write_only_disabled_grant_does_not_enroll_changed_bytes() {
    let f = Fixture::new();
    assert_eq!(f.run(&write_wat("score.txt", "old")).status, Status::Ok);
    let result = f.run_with(
        &write_wat("score.txt", "candidate"),
        evx_supervisor::RunOptions {
            file_fault: Some(evx_api::frames::HelperFault::FailAfterReplace),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
    f.set_capabilities(&[evx_api::Capability::WorkspaceWrite]);
    f.broker.revoke();
    std::fs::write(f.workspace.join("score.txt"), "unregistered").unwrap();
    assert!(evx_supervisor::reconcile_workspace(&f.config, &f.broker).is_err());
    std::fs::write(f.workspace.join("score.txt"), "candidate").unwrap();
    assert_eq!(
        evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
        1
    );
    assert!(!f.broker.grant().enabled);
    assert!(!f
        .broker
        .grant()
        .capabilities
        .contains(&evx_api::Capability::WorkspaceRead));
}

#[test]
fn no_pending_writes_reconcile_without_a_worker() {
    let f = Fixture::new();
    f.broker.revoke();
    let config = evx_supervisor::Config::new(f.workspace.join("missing-worker"));
    assert_eq!(
        evx_supervisor::reconcile_workspace(&config, &f.broker).unwrap(),
        0
    );
}

#[test]
fn failed_provenance_persistence_prevents_the_native_commit() {
    let f = Fixture::new();
    assert_eq!(f.run(&write_wat("score.txt", "old")).status, Status::Ok);
    let registry = f.workspace.parent().unwrap().join(".evx-provenance");
    let file = std::fs::read_dir(registry)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|path| path.extension().is_some_and(|x| x == "json"))
        .unwrap();
    // The authority store is outside the attacker's workspace. This is a
    // host-storage corruption fixture, not a guest permission bypass.
    std::fs::write(&file, "broken trusted metadata").unwrap();
    let result = f.run(&write_wat("score.txt", "new"));
    assert_ne!(result.status, Status::Ok, "{result:?}");
    assert!(!result.events.iter().any(|e| e == "file_commit_authorized"));
    assert_eq!(
        std::fs::read_to_string(f.workspace.join("score.txt")).unwrap(),
        "old"
    );
}

#[test]
fn first_write_interrupted_before_replace_can_reconcile_absence() {
    let f = Fixture::new();
    let mut limits = f.broker.limits();
    limits.host_call_seconds = 0.2;
    f.broker.set_limits(limits).unwrap();
    let interrupted = f.run_with(
        &write_wat("state/score.txt", "candidate"),
        evx_supervisor::RunOptions {
            file_fault: Some(evx_api::frames::HelperFault::BlockAfterAuthorization),
            ..Default::default()
        },
    );
    assert_eq!(interrupted.status, Status::EffectUnknown, "{interrupted:?}");
    assert!(!f.workspace.join("state/score.txt").exists());
    assert_eq!(
        evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
        1
    );
    let write = f.run(&write_wat("state/score.txt", "later"));
    assert_eq!(write.status, Status::Ok, "{write:?}");
}

#[test]
fn invalid_write_acknowledgement_preserves_effect_uncertainty() {
    use evx_supervisor::process::{Event, Role};
    use std::sync::{Arc, Mutex};
    let f = Fixture::new();
    let saved = Arc::new(Mutex::new(
        None::<(u64, std::sync::mpsc::SyncSender<Event>)>,
    ));
    let spawn = saved.clone();
    let result = f.run_with(
        &write_wat("score.txt", "authorized"),
        evx_supervisor::RunOptions {
            after_helper_spawn: Some(Box::new(move |_, id, tx| {
                *spawn.lock().unwrap() = Some((id, tx.clone()));
            })),
            before_file_commit: Some(Box::new(move |_| {
                let guard = saved.lock().unwrap();
                let (id, tx) = guard.as_ref().unwrap();
                tx.send(Event::Frame(
                    Role::File,
                    *id,
                    serde_json::to_vec(&evx_api::frames::FromHelper::FileResult {
                        response: Response::Write {
                            ok: true,
                            bytes: 999,
                        },
                    })
                    .unwrap(),
                ))
                .unwrap();
            })),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
    assert!(result.effect_outcome_unknown, "{result:?}");
}

#[test]
fn hostile_reconciliation_helpers_preserve_pending_authority_and_release_lease() {
    let f = Fixture::new();
    let interrupted = f.run_with(
        &write_wat("score.txt", "candidate"),
        evx_supervisor::RunOptions {
            file_fault: Some(evx_api::frames::HelperFault::FailAfterReplace),
            ..Default::default()
        },
    );
    assert_eq!(interrupted.status, Status::EffectUnknown, "{interrupted:?}");
    let binary = hostile_peer_binary();
    for mode in [
        "unread_init",
        "bad_json",
        "oversize",
        "compiler_cpu",
        "compiler_rss",
    ] {
        let limits = evx_api::Limits {
            host_call_seconds: 0.3,
            process_cpu_seconds: 0.1,
            process_rss_bytes: 24 * 1024 * 1024,
            ..Default::default()
        };
        f.broker.set_limits(limits).unwrap();
        let mut config = evx_supervisor::Config::new(binary.clone());
        config.worker_args = vec![mode.into()];
        let started = std::time::Instant::now();
        assert!(
            evx_supervisor::reconcile_workspace(&config, &f.broker).is_err(),
            "{mode}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{mode}"
        );
        assert!(
            !f.broker.quarantined(),
            "ordinary helper failure leaked cleanup: {mode}"
        );
    }
    f.broker.set_limits(evx_api::Limits::default()).unwrap();
    assert_eq!(
        evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
        1
    );
}

#[test]
fn reconciliation_waits_for_clean_exit_after_both_streams_close() {
    let f = Fixture::new();
    let interrupted = f.run_with(
        &write_wat("score.txt", "candidate"),
        evx_supervisor::RunOptions {
            file_fault: Some(evx_api::frames::HelperFault::FailAfterReplace),
            ..Default::default()
        },
    );
    assert_eq!(interrupted.status, Status::EffectUnknown, "{interrupted:?}");
    let mut config = evx_supervisor::Config::new(hostile_peer_binary());
    config.worker_args = vec!["reconcile_close_before_exit".into()];
    assert_eq!(
        evx_supervisor::reconcile_workspace(&config, &f.broker).unwrap(),
        1
    );
}

#[test]
fn cancellation_after_write_acknowledgement_retains_reconciliation() {
    let f = Fixture::new();
    let result = f.run_with(
        &write_wat("score.txt", "candidate"),
        evx_supervisor::RunOptions {
            after_file_result: Some(Box::new(|broker| broker.revoke())),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
    assert!(result.effect_outcome_unknown, "{result:?}");
    assert_eq!(
        evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
        1
    );
}

#[test]
fn failed_commit_delivery_retains_reconciliation() {
    let f = Fixture::new();
    assert_eq!(f.run(&write_wat("score.txt", "old")).status, Status::Ok);
    let artifact = evx_supervisor::compile_text(&f.config, calc().as_bytes()).unwrap();
    let mut config = evx_supervisor::Config::new(hostile_peer_binary());
    config.worker_args = vec!["commit_input_closed".into()];
    let result = evx_supervisor::run_guest(&config, &artifact, &f.broker, Default::default());
    assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
    assert!(result.effect_outcome_unknown, "{result:?}");
    assert_eq!(
        evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
        1
    );
    assert_eq!(f.run(&write_wat("score.txt", "later")).status, Status::Ok);
}

#[test]
fn broker_refuses_a_symlink_workspace_root() {
    let f = Fixture::new();
    let alias = f.workspace.parent().unwrap().join("workspace-alias");
    std::os::unix::fs::symlink(&f.workspace, &alias).unwrap();
    assert!(
        evx_supervisor::Broker::new(&alias, f.broker.grant(), f.broker.limits()).is_err(),
        "a final-component symlink bypassed the root NOFOLLOW check"
    );
}

#[test]
fn host_cancellation_of_reconciliation_preserves_pending_authority() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let f = Fixture::new();
    let interrupted = f.run_with(
        &write_wat("score.txt", "candidate"),
        evx_supervisor::RunOptions {
            file_fault: Some(evx_api::frames::HelperFault::FailAfterReplace),
            ..Default::default()
        },
    );
    assert_eq!(interrupted.status, Status::EffectUnknown);
    let checks = AtomicUsize::new(0);
    let result = evx_supervisor::reconcile_workspace_cancellable(&f.config, &f.broker, &|| {
        checks.fetch_add(1, Ordering::SeqCst) >= 2
    });
    assert!(
        matches!(result, Err(evx_api::Denied::Cancelled(_))),
        "{result:?}"
    );
    assert!(!f.broker.quarantined());
    assert_eq!(
        evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
        1
    );
}
