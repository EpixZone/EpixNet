#![allow(clippy::field_reassign_with_default)]
#![cfg(target_os = "macos")]
//! Adversarial supervisor integration: a hostile peer (`examples/hostile_peer.rs`)
//! that violates the frame protocol, forges measurements, floods output and
//! leaks control characters. Port of `test_supervisor_ipc.py`.

mod common;

use std::path::PathBuf;
use std::sync::OnceLock;

use evx_api::frames::HelperFault;
use evx_api::{Limits, RunResult, Status};
use evx_supervisor::{run_guest, Config, RunOptions};

use common::*;

/// Locate the hostile peer example, building it once if the test runner has
/// not. `cargo test` builds examples by default, so this is normally a no-op.
fn hostile_peer_binary() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target = manifest.join("../../target/debug/examples/hostile_peer");
        if !target.exists() {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
            let status = std::process::Command::new(cargo)
                .args(["build", "-p", "evx-supervisor", "--example", "hostile_peer"])
                .current_dir(manifest.join("../.."))
                .status()
                .expect("cargo build --example hostile_peer");
            assert!(status.success(), "building hostile_peer failed");
        }
        std::fs::canonicalize(target).expect("hostile_peer binary")
    })
    .clone()
}

fn hostile_config(mode: &str) -> Config {
    let mut config = Config::new(hostile_peer_binary());
    config.worker_args = vec![mode.to_string()];
    config
}

fn hostile(f: &Fixture, mode: &str) -> RunResult {
    // The artifact is compiled by the real worker; the hostile peer ignores it.
    let artifact = compile_ok(&f.config, calc());
    let result = run_guest(
        &hostile_config(mode),
        &artifact,
        &f.broker,
        RunOptions::default(),
    );
    assert!(result.worker_started, "{mode}: {result:?}");
    assert!(
        result.children.iter().all(|c| c.exit_code.is_some()),
        "{mode}: {result:?}"
    );
    result
}

#[test]
fn malformed_envelopes_fail_closed_and_healthy_worker_recovers() {
    let f = Fixture::new();
    for mode in [
        "bad_json",
        "duplicate_field",
        "nonfinite",
        "truncated",
        "oversize",
        "stderr_flood",
        "bad_type",
        "bad_value",
        "missing_value",
        "extra_authority",
        "invalid_base64",
        "after_result",
        "duplicate_result",
        "failed_exit",
        "frame_flood",
    ] {
        let result = hostile(&f, mode);
        assert_ne!(result.status, Status::Ok, "{mode}: {result:?}");
        assert!(!f.workspace.join("must-not-exist").exists(), "{mode}");
        assert!(!f.broker.quarantined(), "{mode}: {result:?}");
    }
    assert_eq!(f.run(calc()).value, Some(42));
}

#[test]
fn forged_cpu_telemetry_cannot_disable_budget() {
    let f = Fixture::new();
    let mut limits = Limits::default();
    limits.process_cpu_seconds = 0.25;
    f.broker.set_limits(limits).unwrap();
    let result = hostile(&f, "false_cpu");
    assert_eq!(result.status, Status::ResourceLimit, "{result:?}");
    assert!(result.error.as_deref().unwrap().contains("CPU"));
    assert!(
        result.trusted_observations.as_ref().unwrap().cpu_seconds >= 0.25,
        "{result:?}"
    );
}

#[test]
fn forged_rss_telemetry_cannot_disable_budget() {
    let f = Fixture::new();
    let mut limits = Limits::default();
    limits.process_rss_bytes = 32 * 1024 * 1024;
    f.broker.set_limits(limits).unwrap();
    let result = hostile(&f, "false_rss");
    assert_eq!(result.status, Status::ResourceLimit, "{result:?}");
    assert!(result.error.as_deref().unwrap().contains("RSS"));
    assert!(
        result
            .trusted_observations
            .as_ref()
            .unwrap()
            .peak_aggregate_rss_bytes
            > 32 * 1024 * 1024,
        "{result:?}"
    );
}

#[test]
fn control_characters_are_inert_text() {
    let f = Fixture::new();
    let result = hostile(&f, "diagnostics");
    assert_eq!(result.status, Status::Ok, "{result:?}");
    for control in ["\x1b", "\0", "\u{202e}"] {
        assert!(!result.diagnostics.contains(control), "{result:?}");
    }
    assert!(result.diagnostics.contains("\\u001b"), "{result:?}");
}

#[test]
fn parent_environment_is_not_inherited() {
    let f = Fixture::new();
    std::env::set_var("EVX_TEST_SECRET", "sacrificial-value");
    let result = hostile(&f, "environment");
    std::env::remove_var("EVX_TEST_SECRET");
    assert_eq!(result.value, Some(0), "{result:?}");
}

#[test]
fn oversized_module_is_rejected_before_any_child_starts() {
    let f = Fixture::new();
    let error =
        evx_supervisor::compile_module(&f.config, &vec![0u8; evx_api::MAX_MODULE + 1]).unwrap_err();
    assert!(error.to_string().contains("module size"), "{error}");
}

#[test]
fn timeout_after_commit_authorization_is_uncertain_not_success() {
    let f = Fixture::new();
    let mut limits = Limits::default();
    limits.host_call_seconds = 0.4;
    f.broker.set_limits(limits).unwrap();
    let result = f.run_with(
        &write_wat("state.txt", "new"),
        RunOptions {
            file_fault: Some(HelperFault::BlockAfterAuthorization),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
    assert!(result.effect_outcome_unknown);
    assert!(
        result.events.contains(&"native_fault_entered".to_string()),
        "{result:?}"
    );
    assert!(result.children.iter().all(|c| c.exit_code.is_some()));
    // Observation only: the helper blocked before the rename in this fixture.
    assert!(!f.workspace.join("state.txt").exists());
}

#[test]
fn failure_after_rename_reports_possible_effect() {
    let f = Fixture::new();
    let result = f.run_with(
        &write_wat("state.txt", "committed"),
        RunOptions {
            file_fault: Some(HelperFault::FailAfterReplace),
            ..Default::default()
        },
    );
    assert_eq!(result.status, Status::EffectUnknown, "{result:?}");
    assert!(result.effect_outcome_unknown);
    assert!(!result.responses[0].is_ok(), "{result:?}");
    assert_eq!(
        std::fs::read_to_string(f.workspace.join("state.txt")).unwrap(),
        "committed"
    );
}
