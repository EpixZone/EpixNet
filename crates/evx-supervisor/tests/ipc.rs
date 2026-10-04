#![allow(clippy::field_reassign_with_default)]
#![cfg(any(target_os = "macos", target_os = "linux"))]
//! Adversarial supervisor integration: a hostile peer (`examples/hostile_peer.rs`)
//! that violates the frame protocol, forges measurements, floods output and
//! leaks control characters. Port of `test_supervisor_ipc.py`.

mod common;

use evx_api::frames::HelperFault;
use evx_api::{Limits, RunResult, Status};
use evx_supervisor::{run_guest, Config, RunOptions};

use common::*;

#[test]
fn unread_initial_frame_cannot_block_the_supervisor_deadline() {
    let f = Fixture::new();
    let mut limits = Limits::default();
    limits.wall_seconds = 0.1;
    limits.host_call_seconds = 0.05;
    f.broker.set_limits(limits).unwrap();
    // The synthetic peer never deserializes this bounded frame.
    let artifact = evx_supervisor::CompiledArtifact {
        bytes: vec![0; 80 * 1024],
        sha256: String::new(),
        engine_key: evx_runtime::engine_key(),
    };
    let config = hostile_config("unread_init");
    let started = std::time::Instant::now();
    let result = run_guest(&config, &artifact, &f.broker, RunOptions::default());
    assert!(
        started.elapsed() < std::time::Duration::from_millis(600),
        "blocked past deadline: {result:?}"
    );
    assert_eq!(result.status, Status::Timeout, "{result:?}");
    assert!(result
        .children
        .iter()
        .all(|child| child.exit_code.is_some()));
}

#[test]
fn unread_compiler_input_cannot_block_its_deadline() {
    let mut config = hostile_config("unread_init");
    config.compile_timeout = std::time::Duration::from_millis(100);
    let started = std::time::Instant::now();
    let result = evx_supervisor::compile_module(&config, &vec![0; 80 * 1024]);
    assert!(
        started.elapsed() < std::time::Duration::from_millis(600),
        "blocked past compile deadline: {result:?}"
    );
    assert!(result.is_err());
}

#[test]
fn compiler_artifact_and_diagnostics_share_one_output_budget() {
    let config = hostile_config("compiler_combined_output");
    let result = evx_supervisor::compile_module(&config, b"fixture");
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("compiler output quota")),
        "combined streams must be bounded; accepted={}",
        result.is_ok()
    );
}

#[test]
fn partial_prefix_after_result_is_a_protocol_error() {
    let f = Fixture::new();
    let result = hostile(&f, "partial_prefix_after_result");
    assert_eq!(result.status, Status::Error, "{result:?}");
    assert!(result
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("truncated"));
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

#[test]
fn compiler_kernel_resource_limits_apply_before_output() {
    use std::time::Duration;
    for (mode, expected) in [
        ("compiler_rss", "compiler RSS limit"),
        ("compiler_cpu", "compiler CPU limit"),
    ] {
        let mut config = hostile_config(mode);
        config.compile_timeout = Duration::from_secs(2);
        config.compile_cpu_seconds = 0.05;
        config.compile_rss_bytes = 24 * 1024 * 1024;
        let error = evx_supervisor::compile_module(&config, b"fixture").unwrap_err();
        // A resource-specific error proves the host enforced the native cap
        // before its distinct compilation deadline. Total wall time also
        // includes process creation and confirmed cleanup under CI load.
        assert_eq!(error.to_string(), expected, "{mode}");
    }
}

#[test]
fn ambient_non_cloexec_descriptor_is_not_inherited() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let f = Fixture::new();
    let fixture = std::fs::File::open(&f.outside).unwrap();
    let fd = unsafe { libc::fcntl(fixture.as_raw_fd(), libc::F_DUPFD, 100) };
    assert!(fd >= 100);
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut config = hostile_config("inherited_fd");
    config.worker_args.push(owned.as_raw_fd().to_string());
    let artifact = compile_ok(&f.config, calc());
    let result = run_guest(&config, &artifact, &f.broker, Default::default());
    assert_eq!(result.status, Status::Ok, "{result:?}");
    assert_eq!(
        result.value,
        Some(0),
        "ambient fixture descriptor leaked: {result:?}"
    );
}

#[test]
fn cleanup_reaps_a_child_that_changed_its_process_group() {
    let f = Fixture::new();
    let mut limits = Limits::default();
    limits.wall_seconds = 0.3;
    limits.host_call_seconds = 0.05;
    f.broker.set_limits(limits).unwrap();
    let artifact = compile_ok(&f.config, calc());
    let config = hostile_config("change_group");
    let result = run_guest(&config, &artifact, &f.broker, RunOptions::default());
    assert!(
        result.diagnostics.contains("group changed"),
        "fixture did not change group: {result:?}"
    );
    assert_eq!(result.status, Status::Timeout, "{result:?}");
    assert!(!f.broker.quarantined(), "{result:?}");
    assert!(
        result.children.iter().all(|c| c.exit_code.is_some()),
        "{result:?}"
    );
}

#[test]
fn encoded_transport_limits_reject_before_launch() {
    let config = Config::new(std::path::PathBuf::from("/missing-evx-test-worker"));
    // 96 KiB becomes 128 KiB in base64 before adding any JSON fields.
    // The 1 MiB structural validator ceiling does not promise transport.
    let input = vec![0; 96 * 1024];
    assert!(input.len() < evx_api::MAX_MODULE);
    for rejected in [
        evx_supervisor::compile_module(&config, &input),
        evx_supervisor::compile_text(&config, &input),
    ] {
        assert!(rejected
            .unwrap_err()
            .to_string()
            .contains("outgoing frame limit"));
    }
    let f = Fixture::new();
    let artifact = evx_supervisor::CompiledArtifact {
        // Compiled artifacts alone have a 256 KiB encoded envelope. Source
        // compilation requests above retain the ordinary 128 KiB envelope.
        bytes: vec![0; evx_api::MAX_ARTIFACT_FRAME / 4 * 3],
        sha256: "fixture".into(),
        engine_key: evx_runtime::engine_key(),
    };
    let result = run_guest(&config, &artifact, &f.broker, RunOptions::default());
    assert_eq!(result.status, Status::Denied, "{result:?}");
    assert!(!result.worker_started);
    assert!(result.error.unwrap().contains("outgoing frame limit"));
}

#[test]
fn guest_errors_cannot_claim_host_cancellation() {
    let f = Fixture::new();
    for mode in ["forged_cancellation", "forged_cancellation_field"] {
        let result = hostile(&f, mode);
        assert_eq!(result.status, Status::Error, "{result:?}");
        assert_eq!(result.host_cancellation, None, "{result:?}");
    }
    let result = hostile(&f, "bad_json");
    f.broker.revoke();
    assert_eq!(
        result.host_cancellation, None,
        "a later revoke reclassified an earlier failure: {result:?}"
    );
}
