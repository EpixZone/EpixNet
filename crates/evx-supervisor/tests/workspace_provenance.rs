#![cfg(any(target_os = "macos", target_os = "linux", windows))]
//! Production broker regressions for bytes whose path does not prove origin.
mod common;
use common::*;
use evx_api::{Response, Status};
use evx_supervisor::process::{Event, Role, Stream};

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
                    // A file symbolic link may be unavailable on Windows;
                    // a hard link to the outside file stands in then.
                    0 if !plant_link(&f.outside, &next) => {
                        std::fs::hard_link(&f.outside, &next).unwrap()
                    }
                    0 => {}
                    1 => std::fs::hard_link(&f.outside, &next).unwrap(),
                    _ => std::fs::write(&next, "inside").unwrap(),
                }
                // Windows refuses to replace a file a helper has open
                // without delete sharing; a refused replacement is retried.
                if std::fs::rename(&next, &target).is_err() {
                    let _ = std::fs::remove_file(&next);
                }
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
                let pending = staged_file(broker.workspace());
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

fn staged_file(parent: &std::path::Path) -> std::path::PathBuf {
    let mut entries = std::fs::read_dir(parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".pending-")
        });
    let path = entries.next().expect("expected a staged write");
    assert!(entries.next().is_none(), "expected only one staged write");
    path
}

// A one-write fixture. Queue an event while the supervisor handles Prepared.
// It finishes recording and sending Commit before it can consume the event.
fn inject_at_commit(
    make_event: impl Fn(u64) -> Event + Send + 'static,
) -> evx_supervisor::RunOptions {
    let (helper, prepared) = std::sync::mpsc::sync_channel(1);
    evx_supervisor::RunOptions {
        after_helper_spawn: Some(Box::new(move |_, id, events| {
            helper.try_send((id, events.clone())).unwrap();
        })),
        before_file_commit: Some(Box::new(move |_| {
            let (id, events) = prepared.try_recv().expect("file helper already spawned");
            events.try_send(make_event(id)).expect("room for test event");
        })),
        ..Default::default()
    }
}

fn interrupt_before_replace() -> evx_supervisor::RunOptions {
    evx_supervisor::RunOptions {
        // Keep the real helper from renaming the staged file or acknowledging.
        file_fault: Some(evx_api::frames::HelperFault::BlockAfterAuthorization),
        ..inject_at_commit(|id| {
            Event::Closed(
                Role::File,
                id,
                Stream::Stdout,
                Some("truncated worker frame"),
            )
        })
    }
}

fn assert_authorized_write_is_uncertain(result: &evx_api::RunResult) {
    assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
    assert!(result.effect_outcome_unknown, "{result:?}");
    assert!(
        result.events.iter().any(|e| e == "file_commit_authorized"),
        "{result:?}"
    );
    assert!(
        !result.events.iter().any(|e| e == "native_call_deadline"),
        "{result:?}"
    );
}

#[test]
fn uncertain_write_requires_explicit_reconciliation_before_different_content() {
    use evx_api::frames::HelperFault;
    for after_replace in [false, true] {
        let f = Fixture::new();
        assert_eq!(f.run(&write_wat("score.txt", "old")).status, Status::Ok);
        let options = if after_replace {
            evx_supervisor::RunOptions {
                file_fault: Some(HelperFault::FailAfterReplace),
                ..Default::default()
            }
        } else {
            interrupt_before_replace()
        };
        let result = f.run_with(&write_wat("score.txt", "candidate"), options);
        assert_authorized_write_is_uncertain(&result);
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
    let result = f.run_with(
        &write_wat("state/score.txt", "candidate"),
        interrupt_before_replace(),
    );
    assert_authorized_write_is_uncertain(&result);
    assert!(
        result.responses.is_empty(),
        "the helper never acknowledged: {result:?}"
    );
    let staged = staged_file(&f.workspace.join("state"));
    assert_eq!(std::fs::read(&staged).unwrap(), b"candidate");
    assert!(!f.workspace.join("state/score.txt").exists());
    assert_eq!(
        evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
        1
    );
    let write = f.run(&write_wat("state/score.txt", "later"));
    assert_eq!(write.status, Status::Ok, "{write:?}");
    assert!(
        !staged.exists(),
        "the next write cleans up the orphaned stage"
    );
    assert_eq!(
        std::fs::read(f.workspace.join("state/score.txt")).unwrap(),
        b"later"
    );
}

#[test]
fn invalid_write_acknowledgement_preserves_effect_uncertainty() {
    let f = Fixture::new();
    let result = f.run_with(
        &write_wat("score.txt", "authorized"),
        inject_at_commit(|id| {
            Event::Frame(
                Role::File,
                id,
                serde_json::to_vec(&evx_api::frames::FromHelper::FileResult {
                    response: Response::Write {
                        ok: true,
                        bytes: 999,
                    },
                })
                .unwrap(),
            )
        }),
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
    assert!(plant_link(&f.workspace, &alias));
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
