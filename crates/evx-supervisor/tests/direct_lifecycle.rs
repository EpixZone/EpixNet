#![cfg(any(target_os = "macos", target_os = "linux"))]
//! Durable admission through the actual confined compiler, guest and helper.
mod common;
use common::*;
use evx_api::frames::HelperFault;
use evx_api::{Response, Status};
use evx_supervisor::direct_lifecycle::DirectLifecycle;
use evx_supervisor::{reconcile_workspace, run_guest, RunOptions};
use std::os::unix::fs::PermissionsExt;

#[test]
fn direct_journal_covers_compile_guest_helper_and_reconciliation() {
    if evx_supervisor::confinement_available().is_err() {
        return;
    }
    let mut fixture = Fixture::new();
    let control = tempfile::tempdir().unwrap();
    std::fs::set_permissions(control.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = control.path().join("lifecycle");
    let journal = DirectLifecycle::provision_fresh(&path).unwrap();
    fixture.config.direct_lifecycle = Some(journal.scope("game-a").unwrap());
    let artifact = compile_ok(&fixture.config, &write_wat("score.txt", "level=7"));
    let result = run_guest(
        &fixture.config,
        &artifact,
        &fixture.broker,
        RunOptions {
            before_file_commit: Some(Box::new({
                let path = path.clone();
                move |_| {
                    let state: serde_json::Value = serde_json::from_slice(
                        &std::fs::read(path.join("lifecycle.json")).unwrap(),
                    )
                    .unwrap();
                    let roles: std::collections::BTreeSet<_> = state["active"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|entry| entry["role"].as_str().unwrap())
                        .collect();
                    assert_eq!(roles, std::collections::BTreeSet::from(["guest", "file"]));
                    assert!(DirectLifecycle::open(&path).is_err());
                }
            })),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert!(result
        .children
        .iter()
        .all(|child| child.exit_code == Some(0)));
    let uncertain = run_guest(
        &fixture.config,
        &artifact,
        &fixture.broker,
        RunOptions {
            file_fault: Some(HelperFault::FailAfterReplace),
            ..Default::default()
        },
    );
    assert_eq!(uncertain.status, Status::EffectUnknown, "{uncertain:?}");
    assert_eq!(
        reconcile_workspace(&fixture.config, &fixture.broker).unwrap(),
        1
    );
    let read = fixture.run(&read_wat("score.txt"));
    assert!(matches!(
        read.responses.first(),
        Some(Response::Read { ok: true, .. })
    ));
    let reopened = DirectLifecycle::open(&path).unwrap();
    assert!(journal.validate().is_err());
    fixture.config.direct_lifecycle = Some(reopened.scope("game-a").unwrap());
    assert_eq!(fixture.run(calc()).value, Some(42));
}

#[test]
fn direct_scope_cannot_be_substituted_for_another_broker_xite() {
    if evx_supervisor::confinement_available().is_err() {
        return;
    }
    let mut fixture = Fixture::new();
    let control = tempfile::tempdir().unwrap();
    std::fs::set_permissions(control.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let journal = DirectLifecycle::provision_fresh(&control.path().join("lifecycle")).unwrap();
    let artifact = compile_ok(&fixture.config, calc());
    fixture.config.direct_lifecycle = Some(journal.scope("game-b").unwrap());
    let result = run_guest(
        &fixture.config,
        &artifact,
        &fixture.broker,
        Default::default(),
    );
    assert_eq!(result.status, Status::Denied, "{result:?}");
    assert!(!result.worker_started);
}
