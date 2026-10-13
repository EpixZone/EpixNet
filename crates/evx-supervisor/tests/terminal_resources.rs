#![cfg(target_os = "macos")]
//! Native IPC accounting fixtures, not a proof of guest confinement.

mod common;
use common::*;
use evx_api::{Grant, Limits, Status};
use evx_supervisor::{run_guest, Broker, CompiledArtifact, Config, RunOptions};

const RSS_LIMIT: u64 = 16 * 1024 * 1024;

fn transient_config() -> Config {
    let mut config = Config::new(hostile_peer_binary());
    config.worker_args.push("terminal_rss".into());
    config
}

#[test]
fn a_known_terminal_memory_violation_cannot_report_success() {
    let config = transient_config();
    // Only our substituted test peer sees this artifact. No native engine
    // deserializes it, and it cannot reach a production worker.
    let artifact = CompiledArtifact {
        bytes: Vec::new(),
        sha256: evx_runtime::compile::sha256_hex(&[]),
        engine_key: evx_runtime::engine_key(),
    };
    for _ in 0..8 {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("game");
        std::fs::create_dir(&workspace).unwrap();
        let limits = Limits {
            process_rss_bytes: RSS_LIMIT,
            ..Limits::default()
        };
        let broker = Broker::new(&workspace, Grant::new("game", true).unwrap(), limits).unwrap();
        let result = run_guest(&config, &artifact, &broker, RunOptions::default());
        assert!(
            result
                .trusted_observations
                .as_ref()
                .unwrap()
                .peak_aggregate_rss_bytes
                > RSS_LIMIT,
            "{result:?}"
        );
        assert_eq!(
            result.status,
            Status::ResourceLimit,
            "known terminal RSS violation: {result:?}"
        );
        assert_eq!(result.value, None);
        assert!(
            result
                .children
                .iter()
                .all(|child| child.exit_code.is_some()),
            "{result:?}"
        );
    }
}

#[test]
fn compiler_terminal_memory_is_checked_before_accepting_an_artifact() {
    let mut config = transient_config();
    config.compile_rss_bytes = RSS_LIMIT;
    let result = evx_supervisor::compile_text(&config, calc().as_bytes());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("compiler RSS limit"));
}

#[test]
fn reconciliation_terminal_memory_failure_preserves_pending_provenance() {
    let config = transient_config();
    for _ in 0..8 {
        let f = Fixture::new();
        let interrupted = f.run_with(
            &write_wat("score.txt", "candidate"),
            RunOptions {
                file_fault: Some(evx_api::frames::HelperFault::FailAfterReplace),
                ..Default::default()
            },
        );
        assert_eq!(interrupted.status, Status::EffectUnknown, "{interrupted:?}");
        let original = f.broker.limits();
        let mut limits = original.clone();
        limits.process_rss_bytes = RSS_LIMIT;
        f.broker.set_limits(limits).unwrap();
        let result = evx_supervisor::reconcile_workspace(&config, &f.broker);
        assert!(
            result.is_err(),
            "over-budget reconciliation accepted: {result:?}"
        );
        assert!(result.unwrap_err().to_string().contains("resource limit"));
        // A failed recovery must not clear the authorized pending candidate.
        f.broker.set_limits(original).unwrap();
        assert_eq!(
            evx_supervisor::reconcile_workspace(&f.config, &f.broker).unwrap(),
            1
        );
    }
}
