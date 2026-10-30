//! Tests for the Milestone 2 xite grants, allow-once tokens, run history and
//! the additive schema migration. No live xites, keys or destinations.

use std::collections::BTreeSet;

use evx_api::{Capability, Limits};
use serde_json::json;

use crate::xite::check_xite_grant;
use crate::{
    connect, DeliveryStatus, DurableState, Effect, Error, GrantPolicy, MockDestination, RunRecord,
    XiteGrant, ALLOW_ONCE_TTL, MAX_ALLOW_ONCE, MAX_MESSAGE, MAX_RUNS, MAX_RUNTIME_PROFILES, SCHEMA,
    SCHEMA_VERSION, XITE_BUDGET_LIMIT,
};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ISSUED: u64 = 1_700_000_000;

struct Fixture {
    _temp: tempfile::TempDir,
    db_path: std::path::PathBuf,
    state: DurableState,
}

fn fixture() -> Fixture {
    let temp = tempfile::Builder::new()
        .prefix("evx-xite-test-")
        .tempdir()
        .unwrap();
    let db_path = temp.path().join("host.sqlite");
    let state = DurableState::open(&db_path).unwrap();
    Fixture {
        _temp: temp,
        db_path,
        state,
    }
}

fn grant(xite: &str) -> XiteGrant {
    XiteGrant {
        xite: xite.to_owned(),
        publisher: "1PublisherAddressXXXXXXXXXXXXXXXXX".to_owned(),
        enabled: true,
        capabilities: BTreeSet::from([Capability::WorkspaceRead, Capability::WorkspaceWrite]),
        runtime_profiles: BTreeSet::from(["wasm-core-v1".to_owned()]),
        limits: Limits::default(),
        allow_run_once: true,
        allow_background: false,
        created_unix: ISSUED,
        expires_unix: None,
        label: "bradley@laptop".to_owned(),
    }
}

fn run(program: &str, started: u64) -> RunRecord {
    RunRecord {
        started_unix: started,
        finished_unix: started + 1,
        program: program.to_owned(),
        declaration_digest: DIGEST_A.to_owned(),
        artifact_sha256: DIGEST_B.to_owned(),
        input_digest: DIGEST_A.to_owned(),
        status: "ok".to_owned(),
        message: None,
        cpu_seconds: 0.25,
        peak_rss: 4096,
        occurrence: None,
        trigger: "once".to_owned(),
    }
}

fn generations(state: &DurableState, xite: &str) -> (u64, u64) {
    let (_, generations) = state.xite_grant(xite).unwrap().unwrap();
    (generations.generation, generations.limits_generation)
}

macro_rules! assert_err {
    ($result:expr, $pattern:pat) => {{
        let result = $result;
        assert!(
            matches!(result, Err($pattern)),
            "expected {}, got {:?}",
            stringify!($pattern),
            result
        );
    }};
}

#[test]
fn xite_grant_round_trips_every_field_and_derives_a_policy_row() {
    let f = fixture();
    let mut wanted = grant("game-a");
    wanted.expires_unix = Some(ISSUED + 86_400);
    wanted.allow_background = true;
    let generations = f.state.set_xite_grant(&wanted).unwrap();
    assert_eq!(
        (
            generations.generation,
            generations.limits_generation,
            generations.schema_generation
        ),
        (1, 1, 1)
    );
    let (stored, read_back) = f.state.xite_grant("game-a").unwrap().unwrap();
    assert_eq!(stored, wanted);
    assert_eq!(read_back, generations);
    let policy = f.state.snapshot("game-a").unwrap().grant.unwrap();
    assert!(policy.enabled);
    assert_eq!(policy.budget_limit, XITE_BUDGET_LIMIT);
    assert_eq!(policy.publication_prefix, None);
    assert_eq!(f.state.xite_grant("game-b").unwrap(), None);
}

#[test]
fn identical_regrant_moves_no_generation() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (1, 1));
}

#[test]
fn limits_only_update_preserves_revocation_and_replacement_authority() {
    let f = fixture();
    let original = grant("game-a");
    f.state.set_xite_grant(&original).unwrap();
    f.state.begin("game-a", "reserved", None, 3).unwrap();
    let mut requested = original.limits.clone();
    requested.storage_bytes /= 2;
    f.state.revoke_xite("game-a").unwrap();
    let changed = f.state.set_xite_limits("game-a", &requested).unwrap();
    let (revoked, current) = f.state.xite_grant("game-a").unwrap().unwrap();
    assert!(!revoked.enabled);
    assert_eq!(revoked.limits, requested);
    assert_eq!(changed, current);
    assert_eq!(current.generation, 2);
    assert_eq!(current.limits_generation, 2);
    assert_eq!(f.state.snapshot("game-a").unwrap().grant.unwrap().used, 3);

    let mut replacement = original;
    replacement.capabilities.clear();
    replacement.allow_background = false;
    replacement.publisher = "new-publisher".to_owned();
    f.state.set_xite_grant(&replacement).unwrap();
    let generation = f.state.xite_grant("game-a").unwrap().unwrap().1.generation;
    f.state.set_xite_limits("game-a", &requested).unwrap();
    let (current, generations) = f.state.xite_grant("game-a").unwrap().unwrap();
    replacement.limits = requested.clone();
    assert_eq!(current, replacement);
    assert_eq!(generations.generation, generation);
    assert_eq!(
        f.state.set_xite_limits("game-a", &requested).unwrap(),
        generations
    );
    assert!(f.state.set_xite_limits("unknown", &requested).is_err());
}

#[test]
fn enabled_change_bumps_authority_only() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut disabled = grant("game-a");
    disabled.enabled = false;
    f.state.set_xite_grant(&disabled).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (2, 1));
    assert_err!(f.state.begin("game-a", "one", None, 1), Error::Denied(_));
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (3, 1));
}

#[test]
fn capability_change_bumps_authority_only() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut narrower = grant("game-a");
    narrower.capabilities = BTreeSet::from([Capability::WorkspaceRead]);
    f.state.set_xite_grant(&narrower).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (2, 1));
    let mut wider = grant("game-a");
    wider.capabilities.insert(Capability::GameScoreGet);
    f.state.set_xite_grant(&wider).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (3, 1));
}

#[test]
fn runtime_profile_change_bumps_authority_only() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut changed = grant("game-a");
    changed.runtime_profiles.insert("wasm-core-v2".to_owned());
    f.state.set_xite_grant(&changed).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (2, 1));
}

#[test]
fn publisher_change_bumps_authority_only() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut changed = grant("game-a");
    changed.publisher = "1OtherPublisherXXXXXXXXXXXXXXXXXXX".to_owned();
    f.state.set_xite_grant(&changed).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (2, 1));
}

#[test]
fn limits_change_bumps_limits_generation_only() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut changed = grant("game-a");
    changed.limits.fuel *= 2;
    f.state.set_xite_grant(&changed).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (1, 2));
    changed.limits.wall_seconds = 3.5;
    f.state.set_xite_grant(&changed).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (1, 3));
    f.state.set_xite_grant(&changed).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (1, 3));
}

#[test]
fn consent_flags_label_and_expiry_move_no_generation() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut changed = grant("game-a");
    changed.allow_run_once = false;
    changed.allow_background = true;
    changed.label = "someone else".to_owned();
    changed.created_unix += 10;
    changed.expires_unix = Some(ISSUED + 100_000);
    f.state.set_xite_grant(&changed).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (1, 1));
    assert_eq!(f.state.xite_grant("game-a").unwrap().unwrap().0, changed);
}

#[test]
fn xite_grant_over_existing_policy_keeps_usage_and_schema_generation() {
    let f = fixture();
    f.state
        .set_grant(
            "game-a",
            GrantPolicy {
                budget_limit: 10,
                schema_generation: 3,
                publication_prefix: Some("users/a".to_owned()),
                ..GrantPolicy::default()
            },
        )
        .unwrap();
    f.state.begin("game-a", "one", None, 4).unwrap();
    let generations = f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(
        (
            generations.generation,
            generations.limits_generation,
            generations.schema_generation
        ),
        (2, 2, 3)
    );
    let policy = f.state.snapshot("game-a").unwrap().grant.unwrap();
    assert_eq!(policy.used, 4);
    assert_eq!(policy.budget_limit, 10);
    assert_eq!(policy.publication_prefix, None);
}

#[test]
fn derived_policy_runs_the_checkpoint_and_outbox_model_without_publication() {
    let f = fixture();
    let mut destination = MockDestination::open(f._temp.path().join("destination.sqlite")).unwrap();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    assert!(call.fresh);
    assert_err!(
        f.state.commit(
            &call,
            &json!({}),
            &[Effect::publish(
                "pub",
                json!({"writes": {"a.txt": "x"}, "deletes": []})
            )],
            None,
        ),
        Error::Denied(_)
    );
    f.state
        .commit(
            &call,
            &json!({"done": true}),
            &[Effect::record("round-1", json!({"score": 1}))],
            Some(crate::StateUpdate {
                expected_version: 0,
                value: json!({"round": 1}),
            }),
        )
        .unwrap();
    assert_eq!(f.state.read_state("game-a").unwrap().version, 1);
    let outcomes = f.state.dispatch(&mut destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Delivered);
}

#[test]
fn revoke_xite_blocks_a_later_begin_until_regranted() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    f.state.begin("game-a", "one", None, 1).unwrap();
    f.state.revoke_xite("game-a").unwrap();
    assert_err!(f.state.begin("game-a", "two", None, 1), Error::Denied(_));
    let (stored, after_revoke) = f.state.xite_grant("game-a").unwrap().unwrap();
    assert!(!stored.enabled);
    assert_eq!(after_revoke.generation, 2);
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (3, 1));
    assert!(f.state.begin("game-a", "two", None, 1).unwrap().fresh);
    f.state.revoke_xite("never-granted").unwrap();
}

#[test]
fn revoke_xite_fences_running_invocation_and_cancels_queued_effect() {
    let f = fixture();
    let mut destination = MockDestination::open(f._temp.path().join("destination.sqlite")).unwrap();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let queued = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(
            &queued,
            &json!({}),
            &[Effect::record("round-1", json!({"score": 1}))],
            None,
        )
        .unwrap();
    let running = f.state.begin("game-a", "two", None, 1).unwrap();
    f.state.revoke_xite("game-a").unwrap();
    assert_err!(
        f.state.commit(&running, &json!({}), &[], None),
        Error::Denied(_)
    );
    let outcomes = f.state.dispatch(&mut destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Cancelled);
}

#[test]
fn expired_xite_grant_denies_begin_without_revocation() {
    let f = fixture();
    let mut expiring = grant("game-a");
    expiring.created_unix = 1;
    expiring.expires_unix = Some(2);
    f.state.set_xite_grant(&expiring).unwrap();
    let error = f.state.begin("game-a", "one", None, 1).unwrap_err();
    assert!(matches!(error, Error::Denied(_)), "{error:?}");
    assert!(error.to_string().contains("expired"), "{error}");
    let (stored, _) = f.state.xite_grant("game-a").unwrap().unwrap();
    assert!(stored.enabled, "expiry is reported, not rewritten");
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert!(f.state.begin("game-a", "one", None, 1).unwrap().fresh);
}

#[test]
fn malformed_xite_grants_are_rejected_before_any_write() {
    let f = fixture();
    let mut bad_xite = grant("game-a");
    bad_xite.xite = "../game".to_owned();
    let mut bad_publisher = grant("game-a");
    bad_publisher.publisher = String::new();
    let mut bad_profile = grant("game-a");
    bad_profile.runtime_profiles = BTreeSet::from(["wasm core".to_owned()]);
    let mut bad_limits = grant("game-a");
    bad_limits.limits.memory_bytes = 1;
    let mut bad_expiry = grant("game-a");
    bad_expiry.expires_unix = Some(ISSUED);
    let mut bad_label = grant("game-a");
    bad_label.label = "line\nbreak".to_owned();
    let mut bad_created = grant("game-a");
    bad_created.created_unix = u64::MAX;
    for bad in [
        bad_xite,
        bad_publisher,
        bad_profile,
        bad_limits,
        bad_expiry,
        bad_label,
        bad_created,
    ] {
        assert_err!(f.state.set_xite_grant(&bad), Error::Invalid(_));
    }
    assert_eq!(f.state.xite_grant("game-a").unwrap(), None);
    assert!(f.state.snapshot("game-a").unwrap().grant.is_none());
}

#[test]
fn allow_once_token_is_single_use() {
    let f = fixture();
    let token = f.state.allow_once("game-a", DIGEST_A, "main").unwrap();
    assert_eq!(token.len(), 64);
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert!(f
        .state
        .consume_allow_once("game-a", &token, DIGEST_A, "main")
        .unwrap());
    assert!(!f
        .state
        .consume_allow_once("game-a", &token, DIGEST_A, "main")
        .unwrap());
    let other = f.state.allow_once("game-a", DIGEST_A, "main").unwrap();
    assert_ne!(token, other, "tokens are random, not derived");
}

#[test]
fn allow_once_is_bound_to_xite_digest_and_program() {
    let f = fixture();
    let token = f.state.allow_once("game-a", DIGEST_A, "main").unwrap();
    assert!(!f
        .state
        .consume_allow_once("game-a", &token, DIGEST_B, "main")
        .unwrap());
    assert!(!f
        .state
        .consume_allow_once("game-a", &token, DIGEST_A, "other")
        .unwrap());
    assert!(!f
        .state
        .consume_allow_once("game-b", &token, DIGEST_A, "main")
        .unwrap());
    assert!(
        f.state
            .consume_allow_once("game-a", &token, DIGEST_A, "main")
            .unwrap(),
        "a mismatched attempt does not spend the token"
    );
}

#[test]
fn allow_once_expires_after_ten_minutes() {
    let f = fixture();
    let token = f
        .state
        .allow_once_at("game-a", DIGEST_A, "main", ISSUED)
        .unwrap();
    assert!(!f
        .state
        .consume_allow_once_at("game-a", &token, DIGEST_A, "main", ISSUED + ALLOW_ONCE_TTL)
        .unwrap());
    assert!(
        !f.state
            .consume_allow_once_at("game-a", &token, DIGEST_A, "main", ISSUED + 1)
            .unwrap(),
        "an expired token is deleted, not revived by a clock step backwards"
    );
    let token = f
        .state
        .allow_once_at("game-a", DIGEST_A, "main", ISSUED)
        .unwrap();
    assert!(
        !f.state
            .consume_allow_once_at("game-a", &token, DIGEST_A, "main", ISSUED - 1)
            .unwrap(),
        "a clock before the issue time is a bad clock, not a valid token"
    );
    let token = f
        .state
        .allow_once_at("game-a", DIGEST_A, "main", ISSUED)
        .unwrap();
    assert!(f
        .state
        .consume_allow_once_at(
            "game-a",
            &token,
            DIGEST_A,
            "main",
            ISSUED + ALLOW_ONCE_TTL - 1
        )
        .unwrap());
}

#[test]
fn unknown_tokens_are_false_and_malformed_ones_are_invalid() {
    let f = fixture();
    assert!(!f
        .state
        .consume_allow_once("game-a", DIGEST_B, DIGEST_A, "main")
        .unwrap());
    assert_err!(
        f.state
            .consume_allow_once("game-a", "short", DIGEST_A, "main"),
        Error::Invalid(_)
    );
    assert_err!(
        f.state
            .consume_allow_once("game-a", &DIGEST_A.to_uppercase(), DIGEST_A, "main"),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.allow_once("game-a", "not-a-digest", "main"),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.allow_once("game-a", DIGEST_A, "bad program"),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.allow_once("../game", DIGEST_A, "main"),
        Error::Invalid(_)
    );
}

#[test]
fn revoke_discards_outstanding_allow_once_tokens() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let token = f.state.allow_once("game-a", DIGEST_A, "main").unwrap();
    let unrelated = f.state.allow_once("game-b", DIGEST_A, "main").unwrap();
    f.state.revoke_xite("game-a").unwrap();
    assert!(!f
        .state
        .consume_allow_once("game-a", &token, DIGEST_A, "main")
        .unwrap());
    assert!(f
        .state
        .consume_allow_once("game-b", &unrelated, DIGEST_A, "main")
        .unwrap());
}

#[test]
fn outstanding_allow_once_tokens_are_capped_and_expired_ones_collected() {
    let f = fixture();
    for _ in 0..MAX_ALLOW_ONCE {
        f.state
            .allow_once_at("game-a", DIGEST_A, "main", ISSUED)
            .unwrap();
    }
    assert_err!(
        f.state.allow_once_at("game-a", DIGEST_A, "main", ISSUED),
        Error::BudgetExceeded(_)
    );
    f.state
        .allow_once_at("game-b", DIGEST_A, "main", ISSUED)
        .unwrap();
    f.state
        .allow_once_at("game-a", DIGEST_A, "main", ISSUED + ALLOW_ONCE_TTL)
        .unwrap();
}

#[test]
fn concurrent_consumers_spend_a_token_exactly_once() {
    let f = fixture();
    let token = f.state.allow_once("game-a", DIGEST_A, "main").unwrap();
    let successes = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let db_path = f.db_path.clone();
                let token = token.clone();
                scope.spawn(move || {
                    DurableState::open(&db_path)
                        .unwrap()
                        .consume_allow_once("game-a", &token, DIGEST_A, "main")
                        .unwrap()
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|spent| *spent)
            .count()
    });
    assert_eq!(successes, 1);
}

#[test]
fn run_history_round_trips_and_is_newest_first() {
    let f = fixture();
    let mut first = run("main", 100);
    first.status = "crashed".to_owned();
    first.message = Some("trap: unreachable".to_owned());
    first.cpu_seconds = 1.5;
    first.peak_rss = 1 << 20;
    f.state.record_run("game-a", &first).unwrap();
    f.state.record_run("game-a", &run("main", 200)).unwrap();
    f.state.record_run("game-b", &run("other", 300)).unwrap();
    let runs = f.state.runs("game-a").unwrap();
    assert_eq!(runs, vec![run("main", 200), first]);
    assert_eq!(f.state.runs("game-b").unwrap(), vec![run("other", 300)]);
    assert!(f.state.runs("game-c").unwrap().is_empty());
}

#[test]
fn run_history_keeps_the_occurrence_and_trigger_of_a_job_run() {
    let f = fixture();
    let mut job_run = run("main", 100);
    job_run.occurrence = Some("sync.28333333".to_owned());
    job_run.trigger = "job".to_owned();
    f.state.record_run("game-a", &job_run).unwrap();
    assert_eq!(f.state.runs("game-a").unwrap(), vec![job_run.clone()]);
    // Both are identifiers, like `status`: no free text reaches the history.
    let mut bad = job_run.clone();
    bad.trigger = "manual job".to_owned();
    assert_err!(f.state.record_run("game-a", &bad), Error::Invalid(_));
    let mut bad = job_run;
    bad.occurrence = Some("sync @ 1".to_owned());
    assert_err!(f.state.record_run("game-a", &bad), Error::Invalid(_));
    assert_eq!(f.state.runs("game-a").unwrap().len(), 1);
}

#[test]
fn run_history_keeps_the_newest_fifty_per_xite() {
    let f = fixture();
    for index in 0..(MAX_RUNS + 7) {
        f.state.record_run("game-a", &run("main", index)).unwrap();
    }
    f.state.record_run("game-b", &run("main", 1)).unwrap();
    let runs = f.state.runs("game-a").unwrap();
    assert_eq!(runs.len(), MAX_RUNS as usize);
    assert_eq!(runs[0].started_unix, MAX_RUNS + 6);
    assert_eq!(runs[runs.len() - 1].started_unix, 7);
    assert_eq!(f.state.runs("game-b").unwrap().len(), 1);
}

#[test]
fn run_history_orders_by_completion_not_by_reported_clock() {
    let f = fixture();
    f.state.record_run("game-a", &run("main", 500)).unwrap();
    f.state.record_run("game-a", &run("main", 400)).unwrap();
    let runs = f.state.runs("game-a").unwrap();
    assert_eq!(runs[0].started_unix, 400);
    assert_eq!(runs[1].started_unix, 500);
}

#[test]
fn malformed_runs_are_rejected() {
    let f = fixture();
    let mut bad_digest = run("main", 1);
    bad_digest.declaration_digest = "nope".to_owned();
    let mut bad_artifact = run("main", 1);
    bad_artifact.artifact_sha256 = DIGEST_A.to_uppercase();
    let mut bad_input = run("main", 1);
    bad_input.input_digest = String::new();
    let mut bad_order = run("main", 10);
    bad_order.finished_unix = 9;
    let mut bad_cpu = run("main", 1);
    bad_cpu.cpu_seconds = f64::NAN;
    let mut negative_cpu = run("main", 1);
    negative_cpu.cpu_seconds = -0.5;
    let mut bad_status = run("main", 1);
    bad_status.status = "not ok".to_owned();
    let mut bad_program = run("main", 1);
    bad_program.program = "../main".to_owned();
    let mut long_message = run("main", 1);
    long_message.message = Some("x".repeat(MAX_MESSAGE + 1));
    for bad in [
        bad_digest,
        bad_artifact,
        bad_input,
        bad_order,
        bad_cpu,
        negative_cpu,
        bad_status,
        bad_program,
        long_message,
    ] {
        assert_err!(f.state.record_run("game-a", &bad), Error::Invalid(_));
    }
    assert_err!(
        f.state.record_run("../game", &run("main", 1)),
        Error::Invalid(_)
    );
    assert!(f.state.runs("game-a").unwrap().is_empty());
}

#[test]
fn reopening_keeps_xite_grant_tokens_and_runs() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let token = f.state.allow_once("game-a", DIGEST_A, "main").unwrap();
    f.state.record_run("game-a", &run("main", 1)).unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    assert_eq!(
        reopened.xite_grant("game-a").unwrap().unwrap().0,
        grant("game-a")
    );
    assert!(reopened
        .consume_allow_once("game-a", &token, DIGEST_A, "main")
        .unwrap());
    assert_eq!(reopened.runs("game-a").unwrap().len(), 1);
    assert_eq!(reopened.schema_version().unwrap(), SCHEMA_VERSION);
}

#[test]
fn database_written_by_the_milestone_one_schema_migrates_in_place() {
    let temp = tempfile::Builder::new()
        .prefix("evx-xite-migrate-")
        .tempdir()
        .unwrap();
    let db_path = temp.path().join("old.sqlite");
    {
        // Exactly what Milestone 1's `open` did: WAL, the version 1 tables and
        // no `user_version`; then a grant, a reservation and a checkpoint.
        let conn = connect(&db_path).unwrap();
        conn.pragma_update(None, "journal_mode", "WAL").unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO grants (xite, enabled, generation, limits_generation, \
             schema_generation, budget_limit, used, publication_prefix) \
             VALUES ('game-a', 1, 4, 2, 1, 20, 3, 'users/a')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO checkpoints (xite, version, value) VALUES ('game-a', 2, '{\"round\":2}')",
            [],
        )
        .unwrap();
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 0);
    }
    let state = DurableState::open(&db_path).unwrap();
    assert_eq!(state.schema_version().unwrap(), SCHEMA_VERSION);
    let policy = state.snapshot("game-a").unwrap().grant.unwrap();
    assert_eq!(
        (policy.generation, policy.limits_generation, policy.used),
        (4, 2, 3)
    );
    assert_eq!(policy.publication_prefix.as_deref(), Some("users/a"));
    assert_eq!(
        state.read_state("game-a").unwrap().value,
        json!({"round": 2})
    );
    assert_eq!(state.xite_grant("game-a").unwrap(), None);
    assert!(state.runs("game-a").unwrap().is_empty());
    assert!(state.begin("game-a", "one", None, 1).unwrap().fresh);
    let generations = state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(
        (generations.generation, generations.limits_generation),
        (5, 3)
    );
    DurableState::open(&db_path).unwrap();
    assert_eq!(state.schema_version().unwrap(), SCHEMA_VERSION);
}

#[test]
fn database_written_by_a_newer_schema_is_refused() {
    let f = fixture();
    {
        let conn = connect(&f.db_path).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
    }
    assert_err!(DurableState::open(&f.db_path), Error::Conflict(_));
}

#[test]
fn set_grant_cannot_re_enable_a_revoked_xite_grant() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    f.state.revoke_xite("game-a").unwrap();
    assert_err!(
        f.state.set_grant(
            "game-a",
            GrantPolicy {
                enabled: true,
                budget_limit: XITE_BUDGET_LIMIT,
                schema_generation: 1,
                publication_prefix: None,
            },
        ),
        Error::Conflict(_)
    );
    assert_err!(f.state.begin("game-a", "one", None, 1), Error::Denied(_));
    let (stored, read_back) = f.state.xite_grant("game-a").unwrap().unwrap();
    assert!(!stored.enabled);
    assert_eq!(read_back.generation, 2, "a refused set_grant moves nothing");
    assert!(!f.state.snapshot("game-a").unwrap().grant.unwrap().enabled);
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert!(f.state.begin("game-a", "one", None, 1).unwrap().fresh);
}

#[test]
fn set_grant_disable_is_mirrored_into_the_xite_grant() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    f.state
        .set_grant(
            "game-a",
            GrantPolicy {
                enabled: false,
                budget_limit: XITE_BUDGET_LIMIT,
                schema_generation: 1,
                publication_prefix: None,
            },
        )
        .unwrap();
    let (stored, read_back) = f.state.xite_grant("game-a").unwrap().unwrap();
    assert!(!stored.enabled, "status reports what the fences enforce");
    assert_eq!(read_back.generation, 2);
    assert_err!(f.state.begin("game-a", "one", None, 1), Error::Denied(_));
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(generations(&f.state, "game-a"), (3, 1));
    assert!(f.state.begin("game-a", "one", None, 1).unwrap().fresh);
}

#[test]
fn set_grant_can_still_lower_the_budget_of_a_granted_xite() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    f.state
        .set_grant(
            "game-a",
            GrantPolicy {
                enabled: true,
                budget_limit: 10,
                schema_generation: 1,
                publication_prefix: None,
            },
        )
        .unwrap();
    let (stored, _) = f.state.xite_grant("game-a").unwrap().unwrap();
    assert!(stored.enabled);
    assert_eq!(generations(&f.state, "game-a"), (1, 2));
    assert_eq!(
        f.state
            .snapshot("game-a")
            .unwrap()
            .grant
            .unwrap()
            .budget_limit,
        10
    );
    assert!(f.state.begin("game-a", "one", None, 1).unwrap().fresh);
}

#[test]
fn fences_consult_the_xite_grant_flag_not_only_the_policy_row() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    {
        // A torn state no API produces: the policy row says yes, the consent
        // record says no. The consent record wins.
        let conn = connect(&f.db_path).unwrap();
        conn.execute("UPDATE xite_grants SET enabled=0 WHERE xite='game-a'", [])
            .unwrap();
    }
    let error = f.state.begin("game-a", "one", None, 1).unwrap_err();
    assert!(matches!(error, Error::Denied(_)), "{error:?}");
    assert!(error.to_string().contains("xite grant disabled"), "{error}");
}

#[test]
fn expiry_check_fails_closed_when_the_clock_cannot_be_read() {
    let f = fixture();
    let mut expiring = grant("game-a");
    expiring.created_unix = 1;
    expiring.expires_unix = Some(2);
    f.state.set_xite_grant(&expiring).unwrap();
    f.state.set_xite_grant(&grant("game-b")).unwrap();
    let conn = connect(&f.db_path).unwrap();
    check_xite_grant(&conn, "game-a", 1).unwrap();
    let error = check_xite_grant(&conn, "game-a", 0).unwrap_err();
    assert!(matches!(error, Error::Denied(_)), "{error:?}");
    assert!(error.to_string().contains("expired"), "{error}");
    check_xite_grant(&conn, "game-b", 0).unwrap();
    check_xite_grant(&conn, "never-granted", 0).unwrap();
}

#[test]
fn xite_grant_reads_grant_and_generations_from_one_snapshot() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut narrower = grant("game-a");
    narrower.capabilities = BTreeSet::from([Capability::WorkspaceRead]);
    let writer = DurableState::open(&f.db_path).unwrap();
    let between_reads = |point: &str| {
        if point == "between_reads" {
            writer.set_xite_grant(&narrower).unwrap();
        }
    };
    let (stored, read_back) = f
        .state
        .xite_grant_with_failpoint("game-a", Some(&between_reads))
        .unwrap()
        .unwrap();
    assert_eq!(
        (stored, read_back.generation),
        (grant("game-a"), 1),
        "the pair belongs to one write, never the old body with the new generation"
    );
    assert_eq!(
        f.state.xite_grant("game-a").unwrap().unwrap(),
        (narrower, writer.xite_grant("game-a").unwrap().unwrap().1)
    );
    assert_eq!(generations(&f.state, "game-a"), (2, 1));
}

#[test]
fn xite_grant_with_too_many_runtime_profiles_is_rejected() {
    let f = fixture();
    let mut full = grant("game-a");
    full.runtime_profiles = (0..MAX_RUNTIME_PROFILES)
        .map(|index| format!("profile-{index}"))
        .collect();
    f.state.set_xite_grant(&full).unwrap();
    let mut over = full.clone();
    over.runtime_profiles.insert("one-more".to_owned());
    assert_err!(f.state.set_xite_grant(&over), Error::Invalid(_));
    assert_eq!(f.state.xite_grant("game-a").unwrap().unwrap().0, full);
}

#[test]
fn unknown_fields_are_refused_when_decoding_grants_and_runs() {
    let mut grant_json = serde_json::to_value(grant("game-a")).unwrap();
    assert_eq!(
        serde_json::from_value::<XiteGrant>(grant_json.clone()).unwrap(),
        grant("game-a")
    );
    grant_json["enabeld"] = json!(true);
    assert!(serde_json::from_value::<XiteGrant>(grant_json).is_err());
    let mut run_json = serde_json::to_value(run("main", 1)).unwrap();
    assert_eq!(
        serde_json::from_value::<RunRecord>(run_json.clone()).unwrap(),
        run("main", 1)
    );
    run_json["exit_code"] = json!(0);
    assert!(serde_json::from_value::<RunRecord>(run_json).is_err());
}
