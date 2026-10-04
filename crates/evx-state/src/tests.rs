//! Sacrificial persistent-state tests. No live xites, keys or destinations.
//!
//! These mirror the proof-of-concept's `test_durable_state.py` and the
//! `DurableInputTests` of `test_security_inputs.py`, plus the tests that pin
//! the authority/limits generation split. The process-crash tests re-execute
//! this test binary as a child that kills itself at a failpoint.

use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::{json, Value};

use crate::{
    canonical, digest, DeliveryStatus, Destination as _, DurableState, Effect, Error, Generations,
    GrantPolicy, InvocationStatus, MockDestination, OutboxStatus, StateUpdate,
};

const CRASH_CHILD: &str = "tests::crash_child";

struct Fixture {
    _temp: tempfile::TempDir,
    db_path: PathBuf,
    dest_path: PathBuf,
    state: DurableState,
    destination: MockDestination,
}

fn grant(budget_limit: u64, publication_prefix: Option<&str>) -> GrantPolicy {
    GrantPolicy {
        budget_limit,
        publication_prefix: publication_prefix.map(str::to_owned),
        ..GrantPolicy::default()
    }
}

fn fixture() -> Fixture {
    let temp = tempfile::Builder::new()
        .prefix("evx-state-test-")
        .tempdir()
        .unwrap();
    let db_path = temp.path().join("host.sqlite");
    let dest_path = temp.path().join("destination.sqlite");
    let state = DurableState::open(&db_path).unwrap();
    state
        .set_grant("game-a", grant(20, Some("users/player-a")))
        .unwrap();
    let destination = MockDestination::open(&dest_path).unwrap();
    Fixture {
        _temp: temp,
        db_path,
        dest_path,
        state,
        destination,
    }
}

fn input_fixture() -> Fixture {
    let fixture = fixture();
    fixture
        .state
        .set_grant("game-a", grant(20, Some("users/a")))
        .unwrap();
    fixture
        .state
        .set_grant("game-b", grant(20, Some("users/b")))
        .unwrap();
    fixture
}

fn effect(key: &str, value: i64) -> Effect {
    Effect::record(key, json!({"score": value}))
}

#[test]
fn reservations_record_whether_guest_execution_has_started() {
    let f = fixture();
    f.state.begin("game-a", "tick.1", None, 1).unwrap();
    let row = serde_json::to_value(&f.state.snapshot("game-a").unwrap().invocations[0]).unwrap();
    assert_eq!(row.get("execution_started"), Some(&json!(false)));
}

#[test]
fn execution_marker_survives_reopen_and_token_recovery() {
    let f = fixture();
    let call = f.state.begin("game-a", "tick.1", None, 1).unwrap();
    f.state.mark_execution_started(&call).unwrap();
    f.state.mark_execution_started(&call).unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    assert!(reopened.snapshot("game-a").unwrap().invocations[0].execution_started);
    let recovered = reopened.recover(&call).unwrap();
    assert!(reopened.snapshot("game-a").unwrap().invocations[0].execution_started);
    assert!(matches!(
        reopened.mark_execution_started(&call),
        Err(Error::Conflict(_))
    ));
    reopened.mark_execution_started(&recovered).unwrap();
    assert_eq!(used(&reopened, "game-a"), 1);
    reopened.commit(&recovered, &json!({}), &[], None).unwrap();
    assert!(matches!(
        reopened.mark_execution_started(&recovered),
        Err(Error::Conflict(_))
    ));
}

#[test]
fn execution_marker_refuses_revoked_and_stale_generation_handles() {
    let f = fixture();
    let call = f.state.begin("game-a", "tick.1", None, 1).unwrap();
    let mut forged = call.clone();
    forged.generation += 1;
    assert!(matches!(
        f.state.mark_execution_started(&forged),
        Err(Error::Conflict(_))
    ));
    forged = call.clone();
    forged.schema_generation += 1;
    assert!(matches!(
        f.state.mark_execution_started(&forged),
        Err(Error::Conflict(_))
    ));
    f.state.revoke("game-a").unwrap();
    assert!(matches!(
        f.state.mark_execution_started(&call),
        Err(Error::Denied(_))
    ));
    assert!(!f.state.snapshot("game-a").unwrap().invocations[0].execution_started);
}

#[test]
fn migration_treats_old_incomplete_execution_as_unknown() {
    let f = fixture();
    f.state.begin("game-a", "tick.1", None, 1).unwrap();
    let conn = rusqlite::Connection::open(&f.db_path).unwrap();
    conn.execute_batch(
        "ALTER TABLE invocations DROP COLUMN execution_started; PRAGMA user_version=5;",
    )
    .unwrap();
    drop(conn);
    let reopened = DurableState::open(&f.db_path).unwrap();
    assert!(reopened.snapshot("game-a").unwrap().invocations[0].execution_started);
    reopened.begin("game-a", "tick.2", None, 1).unwrap();
    assert!(!reopened.snapshot("game-a").unwrap().invocations[1].execution_started);
}

fn state_update(expected_version: u64, value: Value) -> Option<StateUpdate> {
    Some(StateUpdate {
        expected_version,
        value,
    })
}

fn used(state: &DurableState, xite: &str) -> u64 {
    state.snapshot(xite).unwrap().grant.unwrap().used
}

fn deep(levels: usize) -> Value {
    (0..levels).fold(Value::Null, |inner, _| json!([inner]))
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
fn missing_and_disabled_grants_never_reserve() {
    let f = fixture();
    assert_err!(f.state.begin("unknown", "one", None, 1), Error::Denied(_));
    f.state.revoke("game-a").unwrap();
    assert_err!(f.state.begin("game-a", "one", None, 1), Error::Denied(_));
    assert_eq!(used(&f.state, "game-a"), 0);
}

#[test]
fn restart_keeps_result_reservation_and_outbox() {
    let f = fixture();
    let request = json!({"round": 1});
    let call = f.state.begin("game-a", "one", Some(&request), 3).unwrap();
    assert!(call.fresh);
    let response = json!({"checkpoint": "saved"});
    f.state
        .commit(&call, &response, &[effect("round-1", 42)], None)
        .unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    let retry = reopened.begin("game-a", "one", Some(&request), 3).unwrap();
    assert!(!retry.fresh);
    assert!(retry.completed);
    assert_eq!(retry.response, Some(response.clone()));
    assert_eq!(
        reopened
            .commit(&retry, &response, &[effect("round-1", 42)], None)
            .unwrap(),
        response
    );
    assert_eq!(used(&reopened, "game-a"), 3);
    assert_eq!(reopened.snapshot("game-a").unwrap().outbox.len(), 1);
}

#[test]
fn duplicate_running_occurrence_never_starts_twice() {
    let f = fixture();
    let first = f.state.begin("game-a", "one", None, 1).unwrap();
    let retry = f.state.begin("game-a", "one", None, 1).unwrap();
    assert!(!retry.fresh);
    assert!(!retry.completed);
    assert_eq!(first.token, retry.token);
    assert_eq!(used(&f.state, "game-a"), 1);
}

#[test]
fn occurrence_payload_and_cost_are_immutable() {
    let f = fixture();
    f.state
        .begin("game-a", "one", Some(&json!({"code": "hash-a"})), 2)
        .unwrap();
    for (request, cost) in [
        (json!({"code": "hash-b"}), 2),
        (json!({"code": "hash-a"}), 3),
    ] {
        assert_err!(
            f.state.begin("game-a", "one", Some(&request), cost),
            Error::Conflict(_)
        );
    }
    assert_eq!(used(&f.state, "game-a"), 2);
}

#[test]
fn completed_response_is_immutable() {
    let f = fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&call, &json!({"score": 42}), &[], None)
        .unwrap();
    assert_err!(
        f.state.commit(&call, &json!({"score": 43}), &[], None),
        Error::Conflict(_)
    );
}

#[test]
fn canonical_key_order_produces_same_effect_identity() {
    let mut f = fixture();
    let first = f.state.begin("game-a", "one", None, 1).unwrap();
    let second = f.state.begin("game-a", "two", None, 1).unwrap();
    f.state
        .commit(
            &first,
            &json!({}),
            &[Effect::record("shared", json!({"a": 1, "b": 2}))],
            None,
        )
        .unwrap();
    f.state
        .commit(
            &second,
            &json!({}),
            &[Effect::record("shared", json!({"b": 2, "a": 1}))],
            None,
        )
        .unwrap();
    assert_eq!(f.state.snapshot("game-a").unwrap().outbox.len(), 1);
    f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(f.destination.receipt_count().unwrap(), 1);
}

#[test]
fn effect_conflict_rolls_back_whole_commit() {
    let f = fixture();
    let first = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&first, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    let second = f.state.begin("game-a", "two", None, 1).unwrap();
    assert_err!(
        f.state.commit(
            &second,
            &json!({"checkpoint": 2}),
            &[effect("a-new", 1), effect("round-1", 43)],
            state_update(0, json!({"level": 2})),
        ),
        Error::Conflict(_)
    );
    let snap = f.state.snapshot("game-a").unwrap();
    assert_eq!(snap.outbox.len(), 1);
    assert_eq!(snap.invocations[1].status, InvocationStatus::Running);
    assert_eq!(snap.invocations[1].response, None);
    let checkpoint = f.state.read_state("game-a").unwrap();
    assert_eq!((checkpoint.version, checkpoint.value), (0, Value::Null));
}

#[test]
fn checkpoint_result_and_outbox_commit_and_replay_together() {
    let f = fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    for _ in 0..2 {
        f.state
            .commit(
                &call,
                &json!({"done": true}),
                &[effect("round-1", 42)],
                state_update(0, json!({"round": 1})),
            )
            .unwrap();
    }
    let reopened = DurableState::open(&f.db_path).unwrap();
    let checkpoint = reopened.read_state("game-a").unwrap();
    assert_eq!(
        (checkpoint.version, checkpoint.value),
        (1, json!({"round": 1}))
    );
    assert_eq!(reopened.snapshot("game-a").unwrap().outbox.len(), 1);
}

#[test]
fn concurrent_checkpoint_version_blocks_lost_updates() {
    let f = fixture();
    let first = f.state.begin("game-a", "one", None, 1).unwrap();
    let second = f.state.begin("game-a", "two", None, 1).unwrap();
    f.state
        .commit(
            &first,
            &json!({}),
            &[],
            state_update(0, json!({"round": 1})),
        )
        .unwrap();
    let error = f
        .state
        .commit(
            &second,
            &json!({}),
            &[effect("round-1", 42)],
            state_update(0, json!({"round": 2})),
        )
        .unwrap_err();
    assert!(matches!(error, Error::Conflict(_)), "{error:?}");
    assert!(error.to_string().contains("checkpoint"), "{error}");
    let checkpoint = f.state.read_state("game-a").unwrap();
    assert_eq!(
        (checkpoint.version, checkpoint.value),
        (1, json!({"round": 1}))
    );
    assert!(f.state.snapshot("game-a").unwrap().outbox.is_empty());
}

#[test]
fn revoke_blocks_commit_and_queued_dispatch() {
    let mut f = fixture();
    let queued = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&queued, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    let running = f.state.begin("game-a", "two", None, 1).unwrap();
    f.state.revoke("game-a").unwrap();
    assert_err!(
        f.state
            .commit(&running, &json!({}), &[effect("round-2", 42)], None),
        Error::Denied(_)
    );
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Cancelled);
    assert_eq!(f.destination.receipt_count().unwrap(), 0);
    assert_eq!(used(&f.state, "game-a"), 2);
}

#[test]
fn regrant_never_revives_old_queued_intent() {
    let mut f = fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&call, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    f.state.revoke("game-a").unwrap();
    f.state.set_grant("game-a", grant(20, None)).unwrap();
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Cancelled);
    assert_eq!(f.destination.receipt_count().unwrap(), 0);
    assert_err!(
        f.state
            .commit(&call, &json!({}), &[effect("round-1", 42)], None),
        Error::Denied(_)
    );
}

#[test]
fn new_invocation_cannot_reuse_cancelled_intent_as_success() {
    let mut f = fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&call, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    f.state.revoke("game-a").unwrap();
    f.state.set_grant("game-a", grant(20, None)).unwrap();
    let fresh = f.state.begin("game-a", "two", None, 1).unwrap();
    assert_err!(
        f.state
            .commit(&fresh, &json!({}), &[effect("round-1", 42)], None),
        Error::Denied(_)
    );
    f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_err!(
        f.state
            .commit(&fresh, &json!({}), &[effect("round-1", 42)], None),
        Error::Denied(_)
    );
}

#[test]
fn schema_generation_blocks_old_commit_and_dispatch() {
    let mut f = fixture();
    let queued = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&queued, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    let running = f.state.begin("game-a", "two", None, 1).unwrap();
    f.state
        .set_grant(
            "game-a",
            GrantPolicy {
                budget_limit: 20,
                schema_generation: 2,
                ..GrantPolicy::default()
            },
        )
        .unwrap();
    let error = f.state.commit(&running, &json!({}), &[], None).unwrap_err();
    assert!(matches!(error, Error::Denied(_)), "{error:?}");
    assert!(error.to_string().contains("schema"), "{error}");
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Cancelled);
    assert_err!(
        f.state.set_grant(
            "game-a",
            GrantPolicy {
                schema_generation: 1,
                ..GrantPolicy::default()
            },
        ),
        Error::Conflict(_)
    );
}

#[test]
fn concurrent_reservations_do_not_overdraw() {
    let f = fixture();
    f.state.set_grant("game-a", grant(5, None)).unwrap();
    let fresh_claims = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..20)
            .map(|index| {
                let db_path = f.db_path.clone();
                scope.spawn(move || {
                    let state = DurableState::open(&db_path).unwrap();
                    match state.begin("game-a", &format!("tick-{index}"), None, 1) {
                        Ok(call) => call.fresh,
                        Err(Error::BudgetExceeded(_)) => false,
                        Err(error) => panic!("unexpected error: {error:?}"),
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|fresh| *fresh)
            .count()
    });
    assert_eq!(fresh_claims, 5);
    assert_eq!(used(&f.state, "game-a"), 5);
}

#[test]
fn concurrent_duplicate_only_one_fresh_claim() {
    let f = fixture();
    let fresh_claims = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let db_path = f.db_path.clone();
                scope.spawn(move || {
                    DurableState::open(&db_path)
                        .unwrap()
                        .begin("game-a", "same", None, 1)
                        .unwrap()
                        .fresh
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|fresh| *fresh)
            .count()
    });
    assert_eq!(fresh_claims, 1);
    assert_eq!(used(&f.state, "game-a"), 1);
}

#[test]
fn recovery_fences_old_worker_without_new_reservation() {
    let f = fixture();
    let old = f.state.begin("game-a", "one", None, 4).unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    let recovered = reopened.recover(&old).unwrap();
    assert_ne!(old.token, recovered.token);
    assert_err!(
        f.state.commit(&old, &json!({}), &[], None),
        Error::Conflict(_)
    );
    reopened
        .commit(&recovered, &json!({"resumed": true}), &[], None)
        .unwrap();
    assert_eq!(used(&reopened, "game-a"), 4);
}

/// Child-process entry point for the crash tests: never runs in the normal
/// suite. The parent re-executes this test binary with `--ignored --exact`
/// and environment variables selecting the scenario and failpoint, and the
/// child kills itself with `process::exit` (no destructors, no SQLite close)
/// at that point.
#[test]
#[ignore = "driven as a child process by the process-crash tests"]
fn crash_child() {
    let Ok(mode) = std::env::var("EVX_STATE_CRASH_MODE") else {
        return;
    };
    let db_path = std::env::var("EVX_STATE_CRASH_DB").unwrap();
    let point = std::env::var("EVX_STATE_CRASH_POINT").unwrap();
    match mode.as_str() {
        "commit" => {
            let state = DurableState::open(&db_path).unwrap();
            let call = state.begin("game-a", "crash", None, 3).unwrap();
            let crash = |at: &str| {
                if at == point {
                    std::process::exit(71);
                }
            };
            state
                .commit_with_failpoint(
                    &call,
                    &json!({"saved": true}),
                    &[effect("crash-effect", 1)],
                    state_update(0, json!({"round": 1})),
                    Some(&crash),
                )
                .unwrap();
        }
        "dispatch" => {
            let dest_path = std::env::var("EVX_STATE_CRASH_DEST").unwrap();
            let mut destination = MockDestination::open(&dest_path).unwrap();
            let crash = |at: &str| {
                if at == point {
                    std::process::exit(72);
                }
            };
            DurableState::open(&db_path)
                .unwrap()
                .dispatch_with_failpoint(&mut destination, 16, Some(&crash))
                .unwrap();
        }
        other => panic!("unknown crash mode {other}"),
    }
}

fn run_crash_child(environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--ignored", "--exact", CRASH_CHILD]);
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn crash_commit(f: &Fixture, point: &str) -> DurableState {
    let output = run_crash_child(&[
        ("EVX_STATE_CRASH_MODE", "commit"),
        ("EVX_STATE_CRASH_DB", f.db_path.to_str().unwrap()),
        ("EVX_STATE_CRASH_POINT", point),
    ]);
    assert_eq!(
        output.status.code(),
        Some(71),
        "child did not crash at {point}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    DurableState::open(&f.db_path).unwrap()
}

#[test]
fn process_crash_before_commit_leaves_reservation_only() {
    let f = fixture();
    let reopened = crash_commit(&f, "before_commit");
    let snap = reopened.snapshot("game-a").unwrap();
    assert_eq!(snap.grant.unwrap().used, 3);
    assert!(snap.outbox.is_empty());
    assert_eq!(snap.invocations.len(), 1);
    assert_eq!(snap.invocations[0].status, InvocationStatus::Running);
    let checkpoint = reopened.read_state("game-a").unwrap();
    assert_eq!((checkpoint.version, checkpoint.value), (0, Value::Null));
    let old = reopened.begin("game-a", "crash", None, 3).unwrap();
    assert!(!old.fresh);
    let recovered = reopened.recover(&old).unwrap();
    reopened
        .commit(
            &recovered,
            &json!({"saved": true}),
            &[effect("crash-effect", 1)],
            None,
        )
        .unwrap();
    assert_eq!(used(&reopened, "game-a"), 3);
}

#[test]
fn process_crash_after_commit_preserves_result_and_outbox() {
    let mut f = fixture();
    let reopened = crash_commit(&f, "after_commit");
    let retry = reopened.begin("game-a", "crash", None, 3).unwrap();
    assert!(retry.completed);
    assert_eq!(retry.response, Some(json!({"saved": true})));
    let checkpoint = reopened.read_state("game-a").unwrap();
    assert_eq!(
        (checkpoint.version, checkpoint.value),
        (1, json!({"round": 1}))
    );
    assert_eq!(reopened.snapshot("game-a").unwrap().outbox.len(), 1);
    reopened.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(f.destination.receipt_count().unwrap(), 1);
}

#[test]
fn process_crash_after_destination_reconciles_without_duplicate() {
    let mut f = fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&call, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    let output = run_crash_child(&[
        ("EVX_STATE_CRASH_MODE", "dispatch"),
        ("EVX_STATE_CRASH_DB", f.db_path.to_str().unwrap()),
        ("EVX_STATE_CRASH_DEST", f.dest_path.to_str().unwrap()),
        ("EVX_STATE_CRASH_POINT", "after_destination"),
    ]);
    assert_eq!(
        output.status.code(),
        Some(72),
        "child did not crash after destination:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(f.destination.receipt_count().unwrap(), 1);
    assert_eq!(
        f.state.snapshot("game-a").unwrap().outbox[0].status,
        OutboxStatus::Queued
    );
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Delivered);
    let first_response = outcomes[0].response.clone().unwrap();
    assert_eq!(f.destination.receipt_count().unwrap(), 1);
    let row = f.state.snapshot("game-a").unwrap().outbox.remove(0);
    assert_eq!(row.status, OutboxStatus::Delivered);
    assert_eq!(
        f.destination
            .apply(
                "game-a",
                &row.effect_key,
                &row.envelope,
                &row.payload_digest
            )
            .unwrap(),
        first_response
    );
}

#[test]
fn destination_conflicting_payload_is_rejected() {
    let mut f = fixture();
    let raw = canonical(&json!({"kind": "record", "payload": {"score": 1}})).unwrap();
    f.destination
        .apply("game-a", "shared", &raw, &digest(&raw))
        .unwrap();
    let changed = canonical(&json!({"kind": "record", "payload": {"score": 2}})).unwrap();
    assert_err!(
        f.destination
            .apply("game-a", "shared", &changed, &digest(&changed)),
        Error::Conflict(_)
    );
    assert_eq!(f.destination.receipt_count().unwrap(), 1);
}

#[test]
fn exact_publication_delta_preserves_unrelated_files() {
    let mut f = fixture();
    let mut publish = |occurrence: &str, writes: Value, deletes: Value| {
        let call = f.state.begin("game-a", occurrence, None, 1).unwrap();
        f.state
            .commit(
                &call,
                &json!({}),
                &[Effect::publish(
                    occurrence,
                    json!({"writes": writes, "deletes": deletes}),
                )],
                None,
            )
            .unwrap();
        f.state.dispatch(&mut f.destination, 16).unwrap();
    };
    publish(
        "initial",
        json!({"keep.txt": "original", "score.txt": "1", "remove.txt": "old"}),
        json!([]),
    );
    publish("update", json!({"score.txt": "2"}), json!(["remove.txt"]));
    let published = f.destination.published("game-a").unwrap();
    assert_eq!(
        published.into_iter().collect::<Vec<_>>(),
        vec![
            ("users/player-a/keep.txt".to_owned(), "original".to_owned()),
            ("users/player-a/score.txt".to_owned(), "2".to_owned()),
        ]
    );
    assert!(f.destination.published("game-b").unwrap().is_empty());
}

#[test]
fn publication_rejects_traversal_scope_override_and_overlap() {
    let f = fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    let payloads = [
        json!({"writes": {"../other.txt": "x"}, "deletes": []}),
        json!({"writes": {"/root.txt": "x"}, "deletes": []}),
        json!({"writes": {"a": "x"}, "deletes": [], "prefix": "users/other"}),
        json!({"writes": {"a": "x"}, "deletes": ["a"]}),
    ];
    for payload in payloads {
        let result = f.state.commit(
            &call,
            &json!({}),
            &[Effect::publish("bad", payload.clone())],
            None,
        );
        assert!(
            matches!(result, Err(Error::Invalid(_))),
            "{payload}: {result:?}"
        );
    }
    assert!(f.state.snapshot("game-a").unwrap().outbox.is_empty());
}

#[test]
fn publication_requires_host_grant() {
    let f = fixture();
    f.state.set_grant("game-b", grant(2, None)).unwrap();
    let call = f.state.begin("game-b", "one", None, 1).unwrap();
    assert_err!(
        f.state.commit(
            &call,
            &json!({}),
            &[Effect::publish(
                "x",
                json!({"writes": {"a": "x"}, "deletes": []})
            )],
            None,
        ),
        Error::Denied(_)
    );
}

#[test]
fn reopen_regrant_and_recovery_never_reset_budget_or_dedup() {
    let mut f = fixture();
    f.state.set_grant("game-a", grant(1, None)).unwrap();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(
            &call,
            &json!({"done": true}),
            &[effect("round-1", 42)],
            None,
        )
        .unwrap();
    f.state.dispatch(&mut f.destination, 16).unwrap();
    f.state.revoke("game-a").unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    reopened.set_grant("game-a", grant(1, None)).unwrap();
    assert_eq!(used(&reopened, "game-a"), 1);
    let retry = reopened.begin("game-a", "one", None, 1).unwrap();
    assert!(retry.completed);
    assert!(!retry.fresh);
    assert_err!(
        reopened.begin("game-a", "two", None, 1),
        Error::BudgetExceeded(_)
    );
    assert_eq!(reopened.snapshot("game-a").unwrap().outbox.len(), 1);
    assert_eq!(f.destination.receipt_count().unwrap(), 1);
}

#[test]
fn xite_namespaces_do_not_share_occurrence_or_effect_keys() {
    let mut f = fixture();
    f.state.set_grant("game-b", grant(2, None)).unwrap();
    for xite in ["game-a", "game-b"] {
        let call = f.state.begin(xite, "same", None, 1).unwrap();
        f.state
            .commit(&call, &json!({}), &[effect("same", 42)], None)
            .unwrap();
    }
    f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(f.destination.receipt_count().unwrap(), 2);
    assert_eq!(used(&f.state, "game-a"), 1);
    assert_eq!(used(&f.state, "game-b"), 1);
}

#[test]
fn payload_validation_is_bounded_and_rejects_ambiguous_numbers() {
    // NaN, infinities and non-string object keys cannot exist in a
    // `serde_json::Value` (the strict parser rejects them before this layer),
    // so the corpus covers the representable rejections.
    for value in [
        json!(1.5),
        json!("x".repeat(20_000)),
        json!(1u64 << 60),
        json!(-(1i64 << 60)),
        json!(u64::MAX),
        json!(MAX_SAFE_INTEGER_PLUS_ONE),
        deep(18),
    ] {
        assert!(
            matches!(canonical(&value), Err(Error::Invalid(_))),
            "accepted {value}"
        );
    }
    assert!(canonical(&deep(16)).is_ok());
    assert!(canonical(&json!(crate::MAX_SAFE_INTEGER)).is_ok());
    assert!(canonical(&json!(-(crate::MAX_SAFE_INTEGER as i64))).is_ok());
    assert_eq!(
        canonical(&json!({"b": [1, {"d": null, "c": true}], "a": "é\n\"x\""})).unwrap(),
        "{\"a\":\"é\\n\\\"x\\\"\",\"b\":[1,{\"c\":true,\"d\":null}]}"
    );
}

const MAX_SAFE_INTEGER_PLUS_ONE: u64 = crate::MAX_SAFE_INTEGER + 1;

// ---- DurableInputTests ----------------------------------------------------

#[test]
fn bad_occurrence_requests_do_not_reserve_budget() {
    let f = input_fixture();
    for request in [
        json!(1.25),
        json!(1u64 << 60),
        json!(-(1i64 << 60)),
        deep(18),
        json!("x".repeat(20_000)),
    ] {
        assert!(
            matches!(
                f.state.begin("game-a", "one", Some(&request), 1),
                Err(Error::Invalid(_))
            ),
            "accepted request"
        );
    }
    assert_err!(f.state.begin("game-a", "one", None, 0), Error::Invalid(_));
    assert_err!(f.state.begin("game-a", "", None, 1), Error::Invalid(_));
    assert_err!(f.state.begin("game a", "one", None, 1), Error::Invalid(_));
    let snap = f.state.snapshot("game-a").unwrap();
    assert_eq!(snap.grant.unwrap().used, 0);
    assert!(snap.invocations.is_empty());
}

#[test]
fn bad_response_and_checkpoint_never_partially_commit() {
    let f = input_fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    for value in [
        json!(1.5),
        json!("x".repeat(20_000)),
        json!(1u64 << 60),
        deep(18),
    ] {
        assert_err!(
            f.state
                .commit(&call, &value, &[Effect::record("one", json!({}))], None),
            Error::Invalid(_)
        );
        assert_err!(
            f.state.commit(
                &call,
                &json!({}),
                &[Effect::record("one", json!({}))],
                state_update(0, value.clone()),
            ),
            Error::Invalid(_)
        );
    }
    let checkpoint = f.state.read_state("game-a").unwrap();
    assert_eq!((checkpoint.version, checkpoint.value), (0, Value::Null));
    let snap = f.state.snapshot("game-a").unwrap();
    assert!(snap.outbox.is_empty());
    assert_eq!(snap.invocations[0].status, InvocationStatus::Running);
}

#[test]
fn bad_effect_shapes_rollback_checkpoint_and_result() {
    let f = input_fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    let corpus = [
        Effect::record("", json!({})),
        Effect::record("bad key", json!({})),
        Effect::record("key", json!(1.5)),
        Effect::publish("key", json!([])),
        Effect::publish("key", json!({"writes": [], "deletes": []})),
        Effect::publish("key", json!({"writes": {}, "deletes": {}})),
        Effect::publish("key", json!({"writes": {"a\u{7f}b": "x"}, "deletes": []})),
        Effect::publish("key", json!({"writes": {"save": 1}, "deletes": []})),
        Effect::publish(
            "key",
            json!({"writes": {"save": "x".repeat(2049)}, "deletes": []}),
        ),
        Effect::publish("key", json!({"writes": {}, "deletes": [null]})),
        Effect::publish("key", json!({"writes": {}, "deletes": ["a", "a"]})),
        Effect::publish(
            "key",
            json!({"writes": {}, "deletes": [], "xite": "game-b"}),
        ),
    ];
    for effect in corpus {
        let result = f.state.commit(
            &call,
            &json!({}),
            std::slice::from_ref(&effect),
            state_update(0, json!({"saved": true})),
        );
        assert!(
            matches!(result, Err(Error::Invalid(_))),
            "{effect:?}: {result:?}"
        );
    }
    let too_many: Vec<Effect> = (0..17).map(|i| effect(&format!("k{i}"), i)).collect();
    assert_err!(
        f.state.commit(&call, &json!({}), &too_many, None),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.commit(
            &call,
            &json!({}),
            &[effect("dup", 1), effect("dup", 1)],
            None
        ),
        Error::Invalid(_)
    );
    assert!(f.state.snapshot("game-a").unwrap().outbox.is_empty());
    let checkpoint = f.state.read_state("game-a").unwrap();
    assert_eq!((checkpoint.version, checkpoint.value), (0, Value::Null));
    assert_eq!(
        f.state.snapshot("game-a").unwrap().invocations[0].status,
        InvocationStatus::Running
    );
}

#[test]
fn host_selected_xite_overrides_embedded_payload_identity() {
    let f = input_fixture();
    let call = f
        .state
        .begin("game-a", "one", Some(&json!({"xite": "game-b"})), 1)
        .unwrap();
    f.state
        .commit(
            &call,
            &json!({"xite": "game-b"}),
            &[Effect::record("one", json!({"xite": "game-b"}))],
            state_update(0, json!({"xite": "game-b"})),
        )
        .unwrap();
    assert_eq!(used(&f.state, "game-a"), 1);
    assert_eq!(f.state.snapshot("game-a").unwrap().outbox.len(), 1);
    assert_eq!(used(&f.state, "game-b"), 0);
    assert!(f.state.snapshot("game-b").unwrap().outbox.is_empty());
    let checkpoint = f.state.read_state("game-b").unwrap();
    assert_eq!((checkpoint.version, checkpoint.value), (0, Value::Null));
}

#[test]
fn unicode_payload_identity_is_exact_not_visual_equivalence() {
    let f = input_fixture();
    let first = f
        .state
        .begin("game-a", "one", Some(&json!({"name": "é"})), 1)
        .unwrap();
    assert_err!(
        f.state
            .begin("game-a", "one", Some(&json!({"name": "e\u{301}"})), 1),
        Error::Conflict(_)
    );
    f.state
        .commit(
            &first,
            &json!({}),
            &[Effect::record("one", json!({"name": "é"}))],
            None,
        )
        .unwrap();
    let second = f.state.begin("game-a", "two", None, 1).unwrap();
    assert_err!(
        f.state.commit(
            &second,
            &json!({}),
            &[Effect::record("one", json!({"name": "e\u{301}"}))],
            None,
        ),
        Error::Conflict(_)
    );
    assert_ne!(
        canonical(&json!({"name": "é"})).unwrap(),
        canonical(&json!({"name": "e\u{301}"})).unwrap()
    );
}

#[test]
fn publication_payload_cannot_select_other_namespace() {
    let mut f = input_fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(
            &call,
            &json!({}),
            &[Effect::publish(
                "one",
                json!({"writes": {"users/b/score.txt": "literal relative name"}, "deletes": []}),
            )],
            None,
        )
        .unwrap();
    f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(
        f.destination
            .published("game-a")
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>(),
        vec![(
            "users/a/users/b/score.txt".to_owned(),
            "literal relative name".to_owned()
        )]
    );
    assert!(f.destination.published("game-b").unwrap().is_empty());
}

// ---- Authority / limits generation split ----------------------------------

#[test]
fn budget_change_leaves_queued_effect_deliverable() {
    let mut f = fixture();
    let call = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&call, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    let raised = f
        .state
        .set_grant("game-a", grant(50, Some("users/player-a")))
        .unwrap();
    assert_eq!(
        raised,
        Generations {
            generation: 1,
            limits_generation: 2,
            schema_generation: 1
        }
    );
    let lowered = f
        .state
        .set_grant("game-a", grant(2, Some("users/player-a")))
        .unwrap();
    assert_eq!(
        lowered,
        Generations {
            generation: 1,
            limits_generation: 3,
            schema_generation: 1
        }
    );
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].status, DeliveryStatus::Delivered);
    assert_eq!(f.destination.receipt_count().unwrap(), 1);
    let snap = f.state.snapshot("game-a").unwrap();
    assert_eq!(snap.outbox[0].status, OutboxStatus::Delivered);
    assert_eq!(snap.outbox[0].generation, 1);
    assert_eq!(snap.grant.unwrap().used, 1);
}

#[test]
fn budget_change_lets_running_invocation_commit() {
    let f = fixture();
    let running = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .set_grant("game-a", grant(50, Some("users/player-a")))
        .unwrap();
    let second = f.state.begin("game-a", "two", None, 1).unwrap();
    f.state
        .set_grant("game-a", grant(2, Some("users/player-a")))
        .unwrap();
    f.state
        .commit(
            &running,
            &json!({"done": true}),
            &[effect("round-1", 1)],
            state_update(0, json!({"round": 1})),
        )
        .unwrap();
    f.state
        .commit(&second, &json!({"done": true}), &[], None)
        .unwrap();
    let snap = f.state.snapshot("game-a").unwrap();
    let grant_row = snap.grant.unwrap();
    assert_eq!((grant_row.generation, grant_row.limits_generation), (1, 3));
    assert_eq!(grant_row.used, 2);
    assert!(snap
        .invocations
        .iter()
        .all(|row| row.status == InvocationStatus::Completed && row.generation == 1));
    assert_eq!(snap.outbox.len(), 1);
    assert_eq!(snap.outbox[0].status, OutboxStatus::Queued);
    let checkpoint = f.state.read_state("game-a").unwrap();
    assert_eq!(checkpoint.version, 1);
    // The lowered ceiling still governs new reservations: 2 used of 2.
    assert_err!(
        f.state.begin("game-a", "three", None, 1),
        Error::BudgetExceeded(_)
    );
}

#[test]
fn prefix_change_cancels_queued_effect_and_fails_running() {
    let mut f = fixture();
    let queued = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&queued, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    let running = f.state.begin("game-a", "two", None, 1).unwrap();
    let moved = f
        .state
        .set_grant("game-a", grant(20, Some("users/player-b")))
        .unwrap();
    assert_eq!(
        moved,
        Generations {
            generation: 2,
            limits_generation: 1,
            schema_generation: 1
        }
    );
    let error = f.state.commit(&running, &json!({}), &[], None).unwrap_err();
    assert!(matches!(error, Error::Denied(_)), "{error:?}");
    assert!(
        error.to_string().contains("stale grant generation"),
        "{error}"
    );
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Cancelled);
    assert_eq!(f.destination.receipt_count().unwrap(), 0);
    assert_eq!(
        f.state.snapshot("game-a").unwrap().outbox[0].status,
        OutboxStatus::Cancelled
    );
}

#[test]
fn reenable_after_revoke_with_same_prefix_still_cancels_stale_effects() {
    let mut f = fixture();
    let queued = f.state.begin("game-a", "one", None, 1).unwrap();
    f.state
        .commit(&queued, &json!({}), &[effect("round-1", 42)], None)
        .unwrap();
    let running = f.state.begin("game-a", "two", None, 1).unwrap();
    f.state.revoke("game-a").unwrap();
    let restored = f
        .state
        .set_grant("game-a", grant(20, Some("users/player-a")))
        .unwrap();
    assert_eq!(
        restored,
        Generations {
            generation: 3,
            limits_generation: 1,
            schema_generation: 1
        }
    );
    assert_err!(
        f.state.commit(&running, &json!({}), &[], None),
        Error::Denied(_)
    );
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Cancelled);
    assert_eq!(f.destination.receipt_count().unwrap(), 0);
    let fresh = f.state.begin("game-a", "three", None, 1).unwrap();
    assert_eq!(fresh.generation, 3);
    f.state
        .commit(&fresh, &json!({}), &[effect("round-3", 1)], None)
        .unwrap();
    let outcomes = f.state.dispatch(&mut f.destination, 16).unwrap();
    assert_eq!(outcomes[0].status, DeliveryStatus::Delivered);
}

#[test]
fn set_grant_generation_accounting() {
    let f = fixture();
    let prefix = Some("users/player-a");
    let generations = |generation, limits_generation, schema_generation| Generations {
        generation,
        limits_generation,
        schema_generation,
    };
    assert_eq!(
        f.state.set_grant("game-a", grant(20, prefix)).unwrap(),
        generations(1, 1, 1),
        "identical policy is a no-op"
    );
    assert_eq!(
        f.state.set_grant("game-a", grant(30, prefix)).unwrap(),
        generations(1, 2, 1),
        "budget change bumps only limits"
    );
    let with_schema = |schema_generation, enabled, prefix: Option<&str>| GrantPolicy {
        enabled,
        budget_limit: 30,
        schema_generation,
        publication_prefix: prefix.map(str::to_owned),
    };
    assert_eq!(
        f.state
            .set_grant("game-a", with_schema(2, true, prefix))
            .unwrap(),
        generations(1, 2, 2),
        "schema change bumps neither counter"
    );
    assert_eq!(
        f.state
            .set_grant("game-a", with_schema(2, true, Some("users/other")))
            .unwrap(),
        generations(2, 2, 2),
        "prefix change bumps authority"
    );
    assert_eq!(
        f.state
            .set_grant("game-a", with_schema(2, true, None))
            .unwrap(),
        generations(3, 2, 2),
        "withdrawing the prefix bumps authority"
    );
    assert_eq!(
        f.state
            .set_grant("game-a", with_schema(2, false, None))
            .unwrap(),
        generations(4, 2, 2),
        "disabling bumps authority"
    );
    f.state.revoke("game-a").unwrap();
    let row = f.state.snapshot("game-a").unwrap().grant.unwrap();
    assert_eq!((row.generation, row.limits_generation), (5, 2));
    assert!(!row.enabled);
    assert_eq!(
        f.state
            .set_grant("game-a", with_schema(2, true, None))
            .unwrap(),
        generations(6, 2, 2),
        "re-enabling bumps authority"
    );
    let row = f.state.snapshot("game-a").unwrap().grant.unwrap();
    assert_eq!(
        (
            row.enabled,
            row.generation,
            row.limits_generation,
            row.schema_generation,
            row.budget_limit,
            row.publication_prefix
        ),
        (true, 6, 2, 2, 30, None)
    );
    assert_eq!(
        f.state.set_grant("game-b", GrantPolicy::default()).unwrap(),
        generations(1, 1, 1),
        "a new row starts at 1/1"
    );
    assert_err!(
        f.state.set_grant("", GrantPolicy::default()),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.set_grant(
            "game-b",
            GrantPolicy {
                budget_limit: crate::MAX_LIMIT + 1,
                ..GrantPolicy::default()
            }
        ),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.set_grant(
            "game-b",
            GrantPolicy {
                schema_generation: 0,
                ..GrantPolicy::default()
            }
        ),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.set_grant("game-b", grant(1, Some("../escape"))),
        Error::Invalid(_)
    );
}

#[test]
fn dispatch_limit_is_bounded() {
    let mut f = fixture();
    assert_err!(f.state.dispatch(&mut f.destination, 0), Error::Invalid(_));
    assert_err!(f.state.dispatch(&mut f.destination, 65), Error::Invalid(_));
    assert!(f.state.dispatch(&mut f.destination, 64).unwrap().is_empty());
}
