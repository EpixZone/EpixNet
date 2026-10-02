//! Tests for the Milestone 3 schedule model: slot arithmetic, job
//! registration, occurrence claims and finishes, recovery listings, the
//! daily budget and the version 3 migration. No live xites, keys, clocks or
//! destinations: every `now` is a number the test chooses.

use std::collections::BTreeSet;

use evx_api::{Capability, Limits};
use evx_declaration::{Anchor, Missed, Schedule};
use serde_json::{json, Value};

use crate::{
    connect, DurableState, Error, Invocation, InvocationStatus, JobRow, JobSpec, Slot, XiteGrant,
    DAILY_RUN_RETENTION_DAYS, MAX_JOBS, MAX_JOB_CONCURRENCY, MAX_JOB_ID, SCHEMA, SCHEMA_VERSION,
    SECONDS_PER_DAY,
};

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// 2023-11-14T22:13:20Z: day 19676 since the epoch, 80000 seconds into it.
const NOW: u64 = 1_700_000_000;
const PERIOD: u64 = 60;

struct Fixture {
    _temp: tempfile::TempDir,
    db_path: std::path::PathBuf,
    state: DurableState,
}

fn fixture() -> Fixture {
    let temp = tempfile::Builder::new()
        .prefix("evx-jobs-test-")
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
        capabilities: BTreeSet::from([Capability::WorkspaceRead]),
        runtime_profiles: BTreeSet::from(["wasm-core-v1".to_owned()]),
        limits: Limits::default(),
        allow_run_once: true,
        allow_background: true,
        created_unix: NOW - 1000,
        expires_unix: None,
        label: "bradley@laptop".to_owned(),
    }
}

fn interval(seconds: u64, missed: Missed) -> Schedule {
    Schedule::Interval {
        seconds,
        anchor: Anchor::UnixEpoch,
        missed,
    }
}

fn spec(job: &str, seconds: u64, missed: Missed) -> JobSpec {
    JobSpec {
        job: job.to_owned(),
        program: "main".to_owned(),
        schedule: interval(seconds, missed),
        max_concurrency: 1,
    }
}

fn schedule_value(seconds: u64) -> Value {
    serde_json::to_value(interval(seconds, Missed::Skip)).unwrap()
}

/// A granted xite with one registered job `sync` every `PERIOD` seconds.
fn granted_job(f: &Fixture, xite: &str, missed: Missed) -> JobRow {
    f.state.set_xite_grant(&grant(xite)).unwrap();
    f.state
        .set_jobs(xite, DIGEST_A, &[spec("sync", PERIOD, missed)], NOW)
        .unwrap();
    job(&f.state, xite, "sync")
}

fn job(state: &DurableState, xite: &str, job: &str) -> JobRow {
    state
        .jobs(xite)
        .unwrap()
        .into_iter()
        .find(|row| row.job == job)
        .unwrap()
}

fn request(row: &JobRow, slot: &Slot) -> Value {
    json!({
        "job": row.job,
        "slot": slot.index,
        "program": row.program,
        "declaration_digest": row.declaration_digest,
    })
}

/// Claim the slot `now` falls in for the job, re-reading the row first the
/// way the scheduler does.
fn claim(state: &DurableState, xite: &str, name: &str, now: u64) -> crate::Result<Invocation> {
    let row = job(state, xite, name);
    let slot = DurableState::slot_at(&row.schedule, now).unwrap();
    state.claim_occurrence(xite, &row, &slot, &request(&row, &slot), now)
}

fn finish(state: &DurableState, invocation: &Invocation, failed: bool) -> crate::Result<()> {
    let next = (invocation
        .occurrence
        .rsplit('.')
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap()
        + 1)
        * PERIOD;
    state.finish_occurrence(
        invocation,
        &json!({"status": if failed { "error" } else { "ok" }}),
        Some(next),
        failed,
    )
}

fn invocation_status(state: &DurableState, xite: &str, occurrence: &str) -> InvocationStatus {
    state
        .snapshot(xite)
        .unwrap()
        .invocations
        .into_iter()
        .find(|row| row.occurrence == occurrence)
        .unwrap()
        .status
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

// Slots

#[test]
fn slot_at_puts_now_in_the_slot_the_anchor_and_period_define() {
    let slot = DurableState::slot_at(&schedule_value(60), 125).unwrap();
    assert_eq!(
        slot,
        Slot {
            index: 2,
            start_unix: 120,
            end_unix: 180
        }
    );
    let slot = DurableState::slot_at(&schedule_value(3600), NOW).unwrap();
    assert_eq!(slot.index, NOW / 3600);
    assert_eq!(slot.start_unix, (NOW / 3600) * 3600);
    assert_eq!(slot.end_unix, slot.start_unix + 3600);
    assert!(slot.start_unix <= NOW && NOW < slot.end_unix);
    let slot = DurableState::slot_at(&schedule_value(1), NOW).unwrap();
    assert_eq!(
        (slot.index, slot.start_unix, slot.end_unix),
        (NOW, NOW, NOW + 1)
    );
}

#[test]
fn slot_at_exactly_a_boundary_starts_the_new_slot() {
    let before = DurableState::slot_at(&schedule_value(60), 119).unwrap();
    let boundary = DurableState::slot_at(&schedule_value(60), 120).unwrap();
    assert_eq!((before.index, before.end_unix), (1, 120));
    assert_eq!((boundary.index, boundary.start_unix), (2, 120));
    assert_eq!(
        DurableState::slot_at(&schedule_value(60), 0).unwrap().index,
        0
    );
}

#[test]
fn slot_at_refuses_a_schedule_it_cannot_slot() {
    for bad in [
        json!({"type": "cron", "expression": "* * * * *"}),
        json!({"type": "interval", "seconds": 0, "anchor": "unix_epoch", "missed": "skip"}),
        json!({"type": "interval", "seconds": 60, "anchor": "unix_epoch"}),
        json!({"type": "interval", "seconds": 60, "anchor": "unix_epoch", "missed": "skip", "jitter": 1}),
        json!({"type": "interval", "seconds": 60, "anchor": "start", "missed": "skip"}),
        json!({"type": "interval", "seconds": 60, "anchor": "unix_epoch", "missed": "backfill"}),
        json!({"type": "interval", "seconds": 1_000_000_001, "anchor": "unix_epoch", "missed": "skip"}),
        json!("every minute"),
        Value::Null,
    ] {
        assert_err!(DurableState::slot_at(&bad, NOW), Error::Invalid(_));
    }
    assert_err!(
        DurableState::slot_at(&schedule_value(60), (1 << 53) + 1),
        Error::Invalid(_)
    );
}

#[test]
fn occurrence_id_is_the_job_and_slot_index_and_identifier_safe() {
    let slot = DurableState::slot_at(&schedule_value(60), 125).unwrap();
    assert_eq!(DurableState::occurrence_id("sync", &slot), "sync.2");
    assert_eq!(DurableState::occurrence_id("a.b-c_d", &slot), "a.b-c_d.2");
    let widest = Slot {
        index: (1 << 53) - 1,
        start_unix: 0,
        end_unix: 0,
    };
    let longest = "j".repeat(MAX_JOB_ID);
    assert!(crate::identifier(&DurableState::occurrence_id(&longest, &widest)).is_ok());
    assert!(crate::identifier(&DurableState::occurrence_id(
        &format!("{longest}x"),
        &widest
    ))
    .is_err());
}

// Registration

#[test]
fn set_jobs_registers_every_job_due_in_its_current_slot() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut second = spec("report", 3600, Missed::Coalesce);
    second.program = "report".to_owned();
    second.max_concurrency = 2;
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip), second],
            NOW,
        )
        .unwrap();
    let rows = f.state.jobs("game-a").unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].job, "report");
    assert_eq!(rows[0].program, "report");
    assert_eq!(rows[0].max_concurrency, 2);
    assert_eq!(rows[0].next_due_unix, Some((NOW / 3600) * 3600));
    assert_eq!(
        rows[0].schedule,
        json!({"type": "interval", "seconds": 3600, "anchor": "unix_epoch", "missed": "coalesce"})
    );
    let sync = &rows[1];
    assert_eq!(sync.xite, "game-a");
    assert_eq!(sync.job, "sync");
    assert_eq!(sync.declaration_digest, DIGEST_A);
    assert!(sync.enabled);
    assert_eq!(sync.paused_reason, None);
    assert_eq!(sync.next_due_unix, Some((NOW / PERIOD) * PERIOD));
    assert_eq!(sync.last_slot, None);
    assert_eq!(sync.last_occurrence, None);
    assert_eq!(sync.failures, 0);
    assert_eq!(sync.updated_unix, NOW);
    assert!(f.state.jobs("game-b").unwrap().is_empty());
}

#[test]
fn set_jobs_replaces_vanished_jobs_and_keeps_last_slot_of_kept_ones() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[
                spec("sync", PERIOD, Missed::Skip),
                spec("old", PERIOD, Missed::Skip),
            ],
            NOW,
        )
        .unwrap();
    let claimed = claim(&f.state, "game-a", "sync", NOW).unwrap();
    finish(&f.state, &claimed, true).unwrap();
    f.state
        .set_job_paused("game-a", "sync", Some("by user"))
        .unwrap();
    let mut changed = spec("sync", PERIOD, Missed::Coalesce);
    changed.program = "other".to_owned();
    f.state
        .set_jobs(
            "game-a",
            DIGEST_B,
            &[changed, spec("new", PERIOD, Missed::Skip)],
            NOW + 5,
        )
        .unwrap();
    let rows = f.state.jobs("game-a").unwrap();
    assert_eq!(
        rows.iter().map(|row| row.job.as_str()).collect::<Vec<_>>(),
        ["new", "sync"]
    );
    let sync = &rows[1];
    assert_eq!(sync.last_slot, Some(NOW / PERIOD));
    assert_eq!(
        sync.last_occurrence.as_deref(),
        Some(claimed.occurrence.as_str())
    );
    assert_eq!(sync.failures, 1);
    assert_eq!(sync.next_due_unix, Some((NOW / PERIOD + 1) * PERIOD));
    assert_eq!(sync.paused_reason.as_deref(), Some("by user"));
    assert_eq!(sync.program, "other");
    assert_eq!(sync.declaration_digest, DIGEST_B);
    assert_eq!(sync.schedule["missed"], json!("coalesce"));
    assert_eq!(sync.updated_unix, NOW + 5);
    // The vanished job's occurrences are still on record.
    assert_eq!(f.state.snapshot("game-a").unwrap().invocations.len(), 1);
}

#[test]
fn set_jobs_restarts_the_slot_bookkeeping_when_the_period_changes() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let claimed = claim(&f.state, "game-a", "sync", NOW).unwrap();
    finish(&f.state, &claimed, true).unwrap();
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", 3600, Missed::Skip)],
            NOW + 5,
        )
        .unwrap();
    let sync = job(&f.state, "game-a", "sync");
    assert_eq!(sync.last_slot, None);
    assert_eq!(sync.last_occurrence, None);
    assert_eq!(sync.failures, 1);
    assert_eq!(sync.next_due_unix, Some((NOW / 3600) * 3600));
    // Under the old period the hourly index would have read as a rollback.
    let again = claim(&f.state, "game-a", "sync", NOW + 5).unwrap();
    assert!(again.fresh);
    assert_eq!(again.occurrence, format!("sync.{}", NOW / 3600));
}

#[test]
fn set_jobs_refuses_malformed_registrations_before_any_write() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    let mut bad_job = spec("sync", PERIOD, Missed::Skip);
    bad_job.job = "-sync".to_owned();
    let mut long_job = spec("sync", PERIOD, Missed::Skip);
    long_job.job = "j".repeat(MAX_JOB_ID + 1);
    let mut bad_program = spec("sync", PERIOD, Missed::Skip);
    bad_program.program = "a b".to_owned();
    let mut zero_concurrency = spec("sync", PERIOD, Missed::Skip);
    zero_concurrency.max_concurrency = 0;
    let mut wide_concurrency = spec("sync", PERIOD, Missed::Skip);
    wide_concurrency.max_concurrency = MAX_JOB_CONCURRENCY + 1;
    let cases: Vec<(&str, &str, Vec<JobSpec>, u64)> = vec![
        (
            "a b",
            DIGEST_A,
            vec![spec("sync", PERIOD, Missed::Skip)],
            NOW,
        ),
        (
            "game-a",
            "abc",
            vec![spec("sync", PERIOD, Missed::Skip)],
            NOW,
        ),
        ("game-a", DIGEST_A, vec![bad_job], NOW),
        ("game-a", DIGEST_A, vec![long_job], NOW),
        ("game-a", DIGEST_A, vec![bad_program], NOW),
        ("game-a", DIGEST_A, vec![zero_concurrency], NOW),
        ("game-a", DIGEST_A, vec![wide_concurrency], NOW),
        ("game-a", DIGEST_A, vec![spec("sync", 0, Missed::Skip)], NOW),
        (
            "game-a",
            DIGEST_A,
            vec![
                spec("sync", PERIOD, Missed::Skip),
                spec("sync", 1, Missed::Skip),
            ],
            NOW,
        ),
        (
            "game-a",
            DIGEST_A,
            vec![spec("sync", PERIOD, Missed::Skip)],
            (1 << 53) + 1,
        ),
        (
            "game-a",
            DIGEST_A,
            (0..=MAX_JOBS)
                .map(|n| spec(&format!("job{n}"), PERIOD, Missed::Skip))
                .collect(),
            NOW,
        ),
    ];
    for (xite, digest, jobs, now) in cases {
        assert_err!(
            f.state.set_jobs(xite, digest, &jobs, now),
            Error::Invalid(_)
        );
    }
    assert!(f.state.jobs("game-a").unwrap().is_empty());
    assert!(f.state.jobs("a b").unwrap().is_empty());
}

#[test]
fn job_rows_and_specs_refuse_unknown_fields_when_decoded() {
    let f = fixture();
    let row = granted_job(&f, "game-a", Missed::Skip);
    let mut row_json = serde_json::to_value(&row).unwrap();
    assert_eq!(
        serde_json::from_value::<JobRow>(row_json.clone()).unwrap(),
        row
    );
    row_json["pause_reason"] = json!("typo");
    assert!(serde_json::from_value::<JobRow>(row_json).is_err());
    let mut spec_json = serde_json::to_value(spec("sync", PERIOD, Missed::Skip)).unwrap();
    assert_eq!(
        serde_json::from_value::<JobSpec>(spec_json.clone()).unwrap(),
        spec("sync", PERIOD, Missed::Skip)
    );
    spec_json["schedule"]["jitter"] = json!(1);
    assert!(serde_json::from_value::<JobSpec>(spec_json).is_err());
}

// Due jobs

#[test]
fn due_jobs_requires_an_enabled_grant_that_allows_background_work() {
    let f = fixture();
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    assert!(f.state.due_jobs(NOW).unwrap().is_empty(), "no grant");
    let mut foreground = grant("game-a");
    foreground.allow_background = false;
    f.state.set_xite_grant(&foreground).unwrap();
    assert!(f.state.due_jobs(NOW).unwrap().is_empty(), "no background");
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(f.state.due_jobs(NOW).unwrap().len(), 1);
    let mut disabled = grant("game-a");
    disabled.enabled = false;
    f.state.set_xite_grant(&disabled).unwrap();
    assert!(f.state.due_jobs(NOW).unwrap().is_empty(), "disabled grant");
}

#[test]
fn due_jobs_skips_a_paused_or_disabled_job() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    f.state
        .set_job_paused("game-a", "sync", Some("reconcile_required"))
        .unwrap();
    assert!(f.state.due_jobs(NOW).unwrap().is_empty());
    assert_eq!(
        job(&f.state, "game-a", "sync").paused_reason.as_deref(),
        Some("reconcile_required")
    );
    f.state.set_job_paused("game-a", "sync", None).unwrap();
    assert_eq!(f.state.due_jobs(NOW).unwrap().len(), 1);
    f.state.set_job_enabled("game-a", "sync", false).unwrap();
    assert!(f.state.due_jobs(NOW).unwrap().is_empty());
    assert!(!job(&f.state, "game-a", "sync").enabled);
    f.state.set_job_enabled("game-a", "sync", true).unwrap();
    assert_eq!(f.state.due_jobs(NOW).unwrap().len(), 1);
}

#[test]
fn due_jobs_skips_an_expired_or_revoked_grant() {
    let f = fixture();
    let mut expiring = grant("game-a");
    expiring.expires_unix = Some(NOW + 10);
    f.state.set_xite_grant(&expiring).unwrap();
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    assert_eq!(f.state.due_jobs(NOW + 9).unwrap().len(), 1);
    assert!(f.state.due_jobs(NOW + 10).unwrap().is_empty(), "expired");
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(f.state.due_jobs(NOW + 10).unwrap().len(), 1);
    f.state.revoke_xite("game-a").unwrap();
    assert!(f.state.due_jobs(NOW + 10).unwrap().is_empty(), "revoked");
}

#[test]
fn due_jobs_honours_next_due_and_orders_by_it() {
    let f = fixture();
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    f.state.set_xite_grant(&grant("game-b")).unwrap();
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    f.state
        .set_jobs(
            "game-b",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    let slot_start = (NOW / PERIOD) * PERIOD;
    assert!(f.state.due_jobs(slot_start - 1).unwrap().is_empty());
    assert_eq!(f.state.due_jobs(slot_start).unwrap().len(), 2);
    f.state
        .set_job_next_due("game-a", "sync", Some(NOW + 100))
        .unwrap();
    f.state
        .set_job_next_due("game-b", "sync", Some(NOW + 50))
        .unwrap();
    assert!(f.state.due_jobs(NOW + 49).unwrap().is_empty());
    let due = f.state.due_jobs(NOW + 100).unwrap();
    assert_eq!(
        due.iter().map(|row| row.xite.as_str()).collect::<Vec<_>>(),
        ["game-b", "game-a"]
    );
    f.state.set_job_next_due("game-a", "sync", None).unwrap();
    assert_eq!(f.state.due_jobs(NOW + 100).unwrap().len(), 1);
    assert_err!(
        f.state.set_job_next_due("game-a", "gone", None),
        Error::Conflict(_)
    );
}

// Claims

#[test]
fn claim_occurrence_reserves_the_current_slot_and_records_it_on_the_job() {
    let f = fixture();
    let row = granted_job(&f, "game-a", Missed::Skip);
    let slot = DurableState::slot_at(&row.schedule, NOW).unwrap();
    let invocation = f
        .state
        .claim_occurrence("game-a", &row, &slot, &request(&row, &slot), NOW)
        .unwrap();
    assert!(invocation.fresh);
    assert!(!invocation.completed);
    assert_eq!(invocation.occurrence, format!("sync.{}", NOW / PERIOD));
    let stored = job(&f.state, "game-a", "sync");
    assert_eq!(stored.last_slot, Some(slot.index));
    assert_eq!(
        stored.last_occurrence.as_deref(),
        Some(invocation.occurrence.as_str())
    );
    // The reservation is an ordinary invocation: the same request through
    // `begin` matches it instead of conflicting.
    let again = f
        .state
        .begin(
            "game-a",
            &invocation.occurrence,
            Some(&request(&row, &slot)),
            1,
        )
        .unwrap();
    assert!(!again.fresh);
    assert_eq!(again.token, invocation.token);
    assert_eq!(
        f.state
            .incomplete_occurrences(Some("game-a"))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn the_same_occurrence_claimed_twice_is_not_fresh_the_second_time() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let first = claim(&f.state, "game-a", "sync", NOW).unwrap();
    let second = claim(&f.state, "game-a", "sync", NOW + 30).unwrap();
    assert!(first.fresh);
    assert!(!second.fresh);
    assert_eq!(second.occurrence, first.occurrence);
    assert_eq!(second.token, first.token);
    assert_eq!(f.state.snapshot("game-a").unwrap().invocations.len(), 1);
    assert_eq!(
        job(&f.state, "game-a", "sync").last_slot,
        Some(NOW / PERIOD)
    );
}

#[test]
fn skip_policy_after_a_gap_claims_only_the_current_slot() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let first = claim(&f.state, "game-a", "sync", NOW).unwrap();
    finish(&f.state, &first, false).unwrap();
    let later = NOW + 5 * PERIOD;
    let caught_up = claim(&f.state, "game-a", "sync", later).unwrap();
    assert!(caught_up.fresh);
    assert_eq!(caught_up.occurrence, format!("sync.{}", later / PERIOD));
    // The slots in between are gone for good, not queued.
    let row = job(&f.state, "game-a", "sync");
    let missed = DurableState::slot_at(&row.schedule, NOW + 2 * PERIOD).unwrap();
    assert_err!(
        f.state
            .claim_occurrence("game-a", &row, &missed, &request(&row, &missed), later),
        Error::Conflict(_)
    );
    assert_eq!(f.state.snapshot("game-a").unwrap().invocations.len(), 2);
}

#[test]
fn coalesce_policy_after_a_gap_claims_exactly_one_catch_up() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Coalesce);
    let first = claim(&f.state, "game-a", "sync", NOW).unwrap();
    finish(&f.state, &first, false).unwrap();
    let later = NOW + 7 * PERIOD;
    let caught_up = claim(&f.state, "game-a", "sync", later).unwrap();
    assert!(caught_up.fresh);
    let once_more = claim(&f.state, "game-a", "sync", later + 1).unwrap();
    assert!(!once_more.fresh);
    finish(&f.state, &caught_up, false).unwrap();
    assert_eq!(
        job(&f.state, "game-a", "sync").next_due_unix,
        Some((later / PERIOD + 1) * PERIOD)
    );
    assert_eq!(f.state.snapshot("game-a").unwrap().invocations.len(), 2);
}

#[test]
fn clock_rollback_is_a_conflict_and_changes_nothing() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let current = claim(&f.state, "game-a", "sync", NOW).unwrap();
    let before = job(&f.state, "game-a", "sync");
    let used_before = f.state.snapshot("game-a").unwrap().grant.unwrap().used;
    assert_err!(
        claim(&f.state, "game-a", "sync", NOW - PERIOD),
        Error::Conflict(_)
    );
    assert_eq!(job(&f.state, "game-a", "sync"), before);
    let snapshot = f.state.snapshot("game-a").unwrap();
    assert_eq!(snapshot.grant.unwrap().used, used_before);
    assert_eq!(snapshot.invocations.len(), 1);
    assert_eq!(snapshot.invocations[0].occurrence, current.occurrence);
    // Once time passes the recorded slot the schedule moves on.
    assert!(
        claim(&f.state, "game-a", "sync", NOW + PERIOD)
            .unwrap()
            .fresh
    );
}

#[test]
fn claim_occurrence_refuses_a_request_or_slot_that_is_not_the_jobs() {
    let f = fixture();
    let row = granted_job(&f, "game-a", Missed::Skip);
    let slot = DurableState::slot_at(&row.schedule, NOW).unwrap();
    let mut extra = request(&row, &slot);
    extra["started"] = json!(NOW);
    let mut wrong_slot = request(&row, &slot);
    wrong_slot["slot"] = json!(slot.index + 1);
    let mut wrong_digest = request(&row, &slot);
    wrong_digest["declaration_digest"] = json!(DIGEST_B);
    for bad in [extra, wrong_slot, wrong_digest, json!(null), json!([])] {
        assert_err!(
            f.state.claim_occurrence("game-a", &row, &slot, &bad, NOW),
            Error::Invalid(_)
        );
    }
    let foreign = Slot {
        index: slot.index,
        start_unix: slot.start_unix + 1,
        end_unix: slot.end_unix,
    };
    assert_err!(
        f.state
            .claim_occurrence("game-a", &row, &foreign, &request(&row, &foreign), NOW),
        Error::Invalid(_)
    );
    assert_err!(
        f.state
            .claim_occurrence("game-b", &row, &slot, &request(&row, &slot), NOW),
        Error::Invalid(_)
    );
    assert_err!(
        f.state
            .claim_occurrence("game-a", &row, &slot, &request(&row, &slot), (1 << 53) + 1),
        Error::Invalid(_)
    );
    assert!(f.state.snapshot("game-a").unwrap().invocations.is_empty());
    assert_eq!(job(&f.state, "game-a", "sync").last_slot, None);
}

#[test]
fn claim_occurrence_denies_a_paused_disabled_or_background_less_job() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    f.state
        .set_job_paused("game-a", "sync", Some("reconcile_required"))
        .unwrap();
    assert_err!(claim(&f.state, "game-a", "sync", NOW), Error::Denied(_));
    f.state.set_job_paused("game-a", "sync", None).unwrap();
    f.state.set_job_enabled("game-a", "sync", false).unwrap();
    assert_err!(claim(&f.state, "game-a", "sync", NOW), Error::Denied(_));
    f.state.set_job_enabled("game-a", "sync", true).unwrap();
    let mut foreground = grant("game-a");
    foreground.allow_background = false;
    f.state.set_xite_grant(&foreground).unwrap();
    assert_err!(claim(&f.state, "game-a", "sync", NOW), Error::Denied(_));
    f.state.revoke_xite("game-a").unwrap();
    assert_err!(claim(&f.state, "game-a", "sync", NOW), Error::Denied(_));
    assert!(f.state.snapshot("game-a").unwrap().invocations.is_empty());
    f.state.set_xite_grant(&grant("game-a")).unwrap();
    assert!(claim(&f.state, "game-a", "sync", NOW).unwrap().fresh);
}

#[test]
fn claim_occurrence_checks_grant_expiry_at_the_schedulers_now_not_the_clock() {
    let f = fixture();
    let mut expiring = grant("game-a");
    // Long past on the wall clock: a claim that read the clock would deny
    // every claim below, a claim at `now` denies only the one at or past it.
    expiring.expires_unix = Some(NOW + 10);
    f.state.set_xite_grant(&expiring).unwrap();
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    assert_eq!(f.state.due_jobs(NOW + 9).unwrap().len(), 1);
    let claimed = claim(&f.state, "game-a", "sync", NOW + 9).unwrap();
    assert!(claimed.fresh, "due at NOW + 9 is claimable at NOW + 9");
    f.state
        .set_job_next_due("game-a", "sync", Some(NOW + PERIOD))
        .unwrap();
    assert!(f.state.due_jobs(NOW + PERIOD).unwrap().is_empty());
    assert_err!(
        claim(&f.state, "game-a", "sync", NOW + PERIOD),
        Error::Denied(_)
    );
    assert_eq!(
        f.state.snapshot("game-a").unwrap().invocations.len(),
        1,
        "an expired claim reserves nothing"
    );
    assert_eq!(
        job(&f.state, "game-a", "sync").last_slot,
        Some(NOW / PERIOD),
        "an expired claim records no slot"
    );
    // The boundary is the grant's: expiry at `expires_unix` itself.
    let mut boundary = grant("game-b");
    boundary.expires_unix = Some(NOW + 10);
    f.state.set_xite_grant(&boundary).unwrap();
    f.state
        .set_jobs(
            "game-b",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    assert_err!(
        claim(&f.state, "game-b", "sync", NOW + 10),
        Error::Denied(_)
    );
    assert!(claim(&f.state, "game-b", "sync", NOW + 9).unwrap().fresh);
}

#[test]
fn concurrent_claims_of_one_slot_start_it_exactly_once() {
    let f = fixture();
    let row = granted_job(&f, "game-a", Missed::Skip);
    let slot = DurableState::slot_at(&row.schedule, NOW).unwrap();
    let outcomes = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let db_path = f.db_path.clone();
                let row = row.clone();
                scope.spawn(move || {
                    let state = DurableState::open(&db_path).unwrap();
                    state.claim_occurrence("game-a", &row, &slot, &request(&row, &slot), NOW)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    let occurrence = DurableState::occurrence_id("sync", &slot);
    let mut fresh = 0;
    let mut token = None;
    for outcome in outcomes {
        match outcome {
            Ok(invocation) => {
                assert_eq!(invocation.occurrence, occurrence);
                assert!(!invocation.completed);
                assert_eq!(
                    *token.get_or_insert(invocation.token.clone()),
                    invocation.token
                );
                if invocation.fresh {
                    fresh += 1;
                }
            }
            Err(Error::Conflict(_)) => {}
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }
    assert_eq!(fresh, 1, "one logical occurrence starts once");
    let rows = f.state.snapshot("game-a").unwrap().invocations;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].occurrence, occurrence);
    let stored = job(&f.state, "game-a", "sync");
    assert_eq!(stored.last_slot, Some(slot.index));
    assert_eq!(stored.last_occurrence.as_deref(), Some(occurrence.as_str()));
    assert_eq!(f.state.incomplete_occurrences(None).unwrap().len(), 1);
}

#[test]
fn claim_occurrence_refuses_a_stale_job_row() {
    let f = fixture();
    let stale = granted_job(&f, "game-a", Missed::Skip);
    f.state
        .set_jobs(
            "game-a",
            DIGEST_B,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    let slot = DurableState::slot_at(&stale.schedule, NOW).unwrap();
    assert_err!(
        f.state
            .claim_occurrence("game-a", &stale, &slot, &request(&stale, &slot), NOW),
        Error::Conflict(_)
    );
    f.state.set_jobs("game-a", DIGEST_B, &[], NOW).unwrap();
    let current = {
        let mut row = stale.clone();
        row.declaration_digest = DIGEST_B.to_owned();
        row
    };
    assert_err!(
        f.state
            .claim_occurrence("game-a", &current, &slot, &request(&current, &slot), NOW),
        Error::Conflict(_)
    );
}

// Finishing and idempotency

#[test]
fn finish_occurrence_commits_the_result_and_moves_the_schedule_on() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let invocation = claim(&f.state, "game-a", "sync", NOW).unwrap();
    let next = (NOW / PERIOD + 1) * PERIOD;
    f.state
        .finish_occurrence(
            &invocation,
            &json!({"status": "ok", "value": 42}),
            Some(next),
            false,
        )
        .unwrap();
    let rows = f.state.snapshot("game-a").unwrap().invocations;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, InvocationStatus::Completed);
    assert_eq!(rows[0].response, Some(json!({"status": "ok", "value": 42})));
    let row = job(&f.state, "game-a", "sync");
    assert_eq!(row.failures, 0);
    assert_eq!(row.next_due_unix, Some(next));
    assert!(f.state.incomplete_occurrences(None).unwrap().is_empty());
    // The completed occurrence comes back as such on a later claim.
    let replay = claim(&f.state, "game-a", "sync", NOW + 1).unwrap();
    assert!(!replay.fresh);
    assert!(replay.completed);
    assert_eq!(replay.response, Some(json!({"status": "ok", "value": 42})));
}

#[test]
fn finish_occurrence_counts_failures_and_a_success_resets_them() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    for n in 0..3u64 {
        let invocation = claim(&f.state, "game-a", "sync", NOW + n * PERIOD).unwrap();
        f.state
            .finish_occurrence(
                &invocation,
                &json!({"status": "error"}),
                Some(NOW + (n + 1) * PERIOD + 30),
                true,
            )
            .unwrap();
        let row = job(&f.state, "game-a", "sync");
        assert_eq!(row.failures, n as u32 + 1);
        assert_eq!(row.next_due_unix, Some(NOW + (n + 1) * PERIOD + 30));
    }
    let invocation = claim(&f.state, "game-a", "sync", NOW + 3 * PERIOD).unwrap();
    finish(&f.state, &invocation, false).unwrap();
    assert_eq!(job(&f.state, "game-a", "sync").failures, 0);
}

#[test]
fn finishing_the_same_occurrence_twice_with_the_same_result_is_idempotent() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let invocation = claim(&f.state, "game-a", "sync", NOW).unwrap();
    f.state
        .finish_occurrence(
            &invocation,
            &json!({"status": "error"}),
            Some(NOW + 90),
            true,
        )
        .unwrap();
    f.state
        .finish_occurrence(
            &invocation,
            &json!({"status": "error"}),
            Some(NOW + 500),
            true,
        )
        .unwrap();
    let row = job(&f.state, "game-a", "sync");
    assert_eq!(row.failures, 1, "a replay counts nothing twice");
    assert_eq!(row.next_due_unix, Some(NOW + 90), "a replay moves nothing");
    assert_err!(
        f.state
            .finish_occurrence(&invocation, &json!({"status": "ok"}), Some(NOW + 90), false),
        Error::Conflict(_)
    );
    assert_eq!(job(&f.state, "game-a", "sync").failures, 1);
}

#[test]
fn finish_occurrence_refuses_a_result_that_is_not_canonical_json() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let invocation = claim(&f.state, "game-a", "sync", NOW).unwrap();
    assert_err!(
        f.state.finish_occurrence(
            &invocation,
            &json!({"supervisor_elapsed_ms": 12.5}),
            None,
            false
        ),
        Error::Invalid(_)
    );
    assert_err!(
        f.state
            .finish_occurrence(&invocation, &json!({}), Some((1 << 53) + 1), false),
        Error::Invalid(_)
    );
    let mut once = invocation.clone();
    once.occurrence = "once-0123456789abcdef".to_owned();
    assert_err!(
        f.state.finish_occurrence(&once, &json!({}), None, false),
        Error::Invalid(_)
    );
    let mut forged = invocation.clone();
    forged.token = "0".repeat(32);
    assert_err!(
        f.state.finish_occurrence(&forged, &json!({}), None, false),
        Error::Conflict(_)
    );
    assert_eq!(
        invocation_status(&f.state, "game-a", &invocation.occurrence),
        InvocationStatus::Running
    );
    assert_eq!(job(&f.state, "game-a", "sync").failures, 0);
}

#[test]
fn finish_occurrence_for_a_vanished_job_still_completes_the_reservation() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let invocation = claim(&f.state, "game-a", "sync", NOW).unwrap();
    f.state.set_jobs("game-a", DIGEST_A, &[], NOW + 1).unwrap();
    finish(&f.state, &invocation, false).unwrap();
    assert_eq!(
        invocation_status(&f.state, "game-a", &invocation.occurrence),
        InvocationStatus::Completed
    );
    assert!(f.state.jobs("game-a").unwrap().is_empty());
    // Re-registered under the same name, the slot it ran cannot run again.
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW + 2,
        )
        .unwrap();
    let again = claim(&f.state, "game-a", "sync", NOW + 2).unwrap();
    assert!(!again.fresh);
    assert!(again.completed);
}

#[test]
fn finish_occurrence_keeps_the_next_due_of_a_job_re_registered_with_a_new_period() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let running = claim(&f.state, "game-a", "sync", NOW).unwrap();
    // The publisher changes the cadence while the occurrence runs.
    f.state
        .set_jobs(
            "game-a",
            DIGEST_B,
            &[spec("sync", 3600, Missed::Skip)],
            NOW + 5,
        )
        .unwrap();
    let registered = (NOW / 3600) * 3600;
    assert_eq!(
        job(&f.state, "game-a", "sync").next_due_unix,
        Some(registered)
    );
    finish(&f.state, &running, true).unwrap();
    assert_eq!(
        invocation_status(&f.state, "game-a", &running.occurrence),
        InvocationStatus::Completed
    );
    let row = job(&f.state, "game-a", "sync");
    assert_eq!(
        row.next_due_unix,
        Some(registered),
        "the old cadence's next due does not clobber the fresh registration"
    );
    assert_eq!(row.failures, 1, "the failure still counts");
    assert_eq!(row.last_slot, None);
    assert_eq!(row.last_occurrence, None);
    // Re-registered under the same period, the row still names the
    // occurrence and the finish moves the schedule on as usual.
    let second = claim(&f.state, "game-a", "sync", NOW + 5).unwrap();
    assert!(second.fresh);
    f.state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", 3600, Missed::Skip)],
            NOW + 6,
        )
        .unwrap();
    f.state
        .finish_occurrence(
            &second,
            &json!({"status": "ok"}),
            Some(registered + 3600),
            false,
        )
        .unwrap();
    let row = job(&f.state, "game-a", "sync");
    assert_eq!(row.next_due_unix, Some(registered + 3600));
    assert_eq!(row.failures, 0);
}

// Reopen

#[test]
fn a_completed_occurrence_stays_completed_and_unclaimable_after_reopen() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let invocation = claim(&f.state, "game-a", "sync", NOW).unwrap();
    finish(&f.state, &invocation, false).unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    let again = claim(&reopened, "game-a", "sync", NOW + 10).unwrap();
    assert!(!again.fresh);
    assert!(again.completed);
    assert_eq!(again.response, Some(json!({"status": "ok"})));
    assert_eq!(
        invocation_status(&reopened, "game-a", &invocation.occurrence),
        InvocationStatus::Completed
    );
    let row = job(&reopened, "game-a", "sync");
    assert_eq!(row.last_slot, Some(NOW / PERIOD));
    assert_eq!(row.next_due_unix, Some((NOW / PERIOD + 1) * PERIOD));
}

#[test]
fn a_slot_never_repeats_across_a_reopen() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    let running = claim(&f.state, "game-a", "sync", NOW).unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    let again = claim(&reopened, "game-a", "sync", NOW + 10).unwrap();
    assert!(
        !again.fresh,
        "a restart does not start the slot a second time"
    );
    assert!(!again.completed);
    assert_eq!(again.token, running.token);
    assert_err!(
        claim(&reopened, "game-a", "sync", NOW - PERIOD),
        Error::Conflict(_)
    );
}

// Recovery

#[test]
fn incomplete_occurrences_lists_reserved_not_committed_ones_only() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    granted_job(&f, "game-b", Missed::Skip);
    let open = claim(&f.state, "game-a", "sync", NOW).unwrap();
    let done = claim(&f.state, "game-a", "sync", NOW + PERIOD).unwrap();
    finish(&f.state, &done, false).unwrap();
    let other = claim(&f.state, "game-b", "sync", NOW).unwrap();
    f.state
        .begin("game-b", "once-0123456789abcdef", None, 1)
        .unwrap();
    let all = f.state.incomplete_occurrences(None).unwrap();
    assert_eq!(
        all.iter()
            .map(|row| (row.xite.as_str(), row.occurrence.as_str()))
            .collect::<Vec<_>>(),
        [
            ("game-a", open.occurrence.as_str()),
            ("game-b", "once-0123456789abcdef"),
            ("game-b", other.occurrence.as_str()),
        ]
    );
    assert!(all
        .iter()
        .all(|row| row.status == InvocationStatus::Running && row.response.is_none()));
    let mine = f.state.incomplete_occurrences(Some("game-a")).unwrap();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].token, open.token);
    assert!(f
        .state
        .incomplete_occurrences(Some("game-c"))
        .unwrap()
        .is_empty());
    assert_err!(
        f.state.incomplete_occurrences(Some("a b")),
        Error::Invalid(_)
    );
    // Recovery retries under the same identity with a rotated token, and the
    // listing then still shows it until it is finished.
    let retried = f.state.recover(&open).unwrap();
    assert_ne!(retried.token, open.token);
    assert_eq!(
        f.state
            .incomplete_occurrences(Some("game-a"))
            .unwrap()
            .len(),
        1
    );
    f.state
        .finish_occurrence(
            &retried,
            &json!({"status": "abandoned"}),
            Some(NOW + 2 * PERIOD),
            false,
        )
        .unwrap();
    assert!(f
        .state
        .incomplete_occurrences(Some("game-a"))
        .unwrap()
        .is_empty());
    assert_err!(finish(&f.state, &open, false), Error::Conflict(_));
}

// Daily budget

#[test]
fn daily_budget_counts_and_refuses_past_the_limit() {
    let f = fixture();
    assert_eq!(f.state.daily_runs("game-a", NOW).unwrap(), 0);
    for expected in 1..=3 {
        f.state
            .reserve_daily_run("game-a", NOW + expected, 3)
            .unwrap();
        assert_eq!(f.state.daily_runs("game-a", NOW).unwrap(), expected as u32);
    }
    assert_err!(
        f.state.reserve_daily_run("game-a", NOW + 10, 3),
        Error::BudgetExceeded(_)
    );
    assert_eq!(f.state.daily_runs("game-a", NOW).unwrap(), 3);
    assert_err!(
        f.state.reserve_daily_run("game-b", NOW, 0),
        Error::BudgetExceeded(_)
    );
    assert_eq!(f.state.daily_runs("game-b", NOW).unwrap(), 0);
    assert_err!(f.state.reserve_daily_run("a b", NOW, 3), Error::Invalid(_));
    assert_err!(
        f.state.daily_runs("game-a", (1 << 53) + 1),
        Error::Invalid(_)
    );
}

#[test]
fn daily_budget_survives_a_reopen() {
    let f = fixture();
    f.state.reserve_daily_run("game-a", NOW, 2).unwrap();
    f.state.reserve_daily_run("game-a", NOW + 1, 2).unwrap();
    let reopened = DurableState::open(&f.db_path).unwrap();
    assert_eq!(reopened.daily_runs("game-a", NOW + 2).unwrap(), 2);
    assert_err!(
        reopened.reserve_daily_run("game-a", NOW + 2, 2),
        Error::BudgetExceeded(_)
    );
}

#[test]
fn daily_budget_resets_on_the_next_utc_day() {
    let f = fixture();
    let day_end = (NOW / SECONDS_PER_DAY + 1) * SECONDS_PER_DAY;
    f.state.reserve_daily_run("game-a", day_end - 1, 1).unwrap();
    assert_err!(
        f.state.reserve_daily_run("game-a", day_end - 1, 1),
        Error::BudgetExceeded(_)
    );
    assert_eq!(f.state.daily_runs("game-a", day_end).unwrap(), 0);
    f.state.reserve_daily_run("game-a", day_end, 1).unwrap();
    assert_eq!(f.state.daily_runs("game-a", day_end).unwrap(), 1);
    assert_eq!(
        f.state
            .daily_runs("game-a", day_end + SECONDS_PER_DAY - 1)
            .unwrap(),
        1
    );
    // Yesterday's count is kept: a reservation on a newer day collects only
    // days older than the retention window.
    assert_eq!(f.state.daily_runs("game-a", day_end - 1).unwrap(), 1);
}

#[test]
fn daily_budget_rolled_back_into_a_spent_day_finds_that_days_count() {
    let f = fixture();
    let day_start = (NOW / SECONDS_PER_DAY) * SECONDS_PER_DAY;
    let next_day = day_start + SECONDS_PER_DAY;
    f.state.reserve_daily_run("game-a", NOW, 2).unwrap();
    f.state.reserve_daily_run("game-a", NOW + 1, 2).unwrap();
    f.state.reserve_daily_run("game-a", next_day, 2).unwrap();
    // The clock rolls back into the spent day.
    assert_eq!(f.state.daily_runs("game-a", NOW).unwrap(), 2);
    assert_err!(
        f.state.reserve_daily_run("game-a", NOW + 2, 2),
        Error::BudgetExceeded(_)
    );
    // And from the far edge of the window, where the count is still there.
    let edge = day_start + DAILY_RUN_RETENTION_DAYS * SECONDS_PER_DAY;
    f.state.reserve_daily_run("game-a", edge, 2).unwrap();
    assert_eq!(f.state.daily_runs("game-a", next_day).unwrap(), 1);
    assert_eq!(f.state.daily_runs("game-a", NOW).unwrap(), 2);
    // One day further collects the oldest day and nothing newer.
    f.state
        .reserve_daily_run("game-a", edge + SECONDS_PER_DAY, 2)
        .unwrap();
    assert_eq!(f.state.daily_runs("game-a", NOW).unwrap(), 0);
    assert_eq!(f.state.daily_runs("game-a", next_day).unwrap(), 1);
    assert_eq!(f.state.daily_runs("game-a", edge).unwrap(), 1);
    // Another xite's rows are not the collector's business.
    f.state.reserve_daily_run("game-b", NOW, 1).unwrap();
    f.state
        .reserve_daily_run("game-a", edge + 2 * SECONDS_PER_DAY, 2)
        .unwrap();
    assert_eq!(f.state.daily_runs("game-b", NOW).unwrap(), 1);
}

#[test]
fn daily_budget_is_counted_per_xite() {
    let f = fixture();
    f.state.reserve_daily_run("game-a", NOW, 1).unwrap();
    f.state.reserve_daily_run("game-b", NOW, 1).unwrap();
    assert_err!(
        f.state.reserve_daily_run("game-a", NOW, 1),
        Error::BudgetExceeded(_)
    );
    assert_eq!(f.state.daily_runs("game-a", NOW).unwrap(), 1);
    assert_eq!(f.state.daily_runs("game-b", NOW).unwrap(), 1);
}

// Pause and enable

#[test]
fn set_job_paused_and_enabled_refuse_unknown_jobs_and_bad_reasons() {
    let f = fixture();
    granted_job(&f, "game-a", Missed::Skip);
    assert_err!(
        f.state.set_job_paused("game-a", "gone", Some("x")),
        Error::Conflict(_)
    );
    assert_err!(
        f.state.set_job_enabled("game-b", "sync", false),
        Error::Conflict(_)
    );
    assert_err!(
        f.state.set_job_paused("game-a", "sync", Some("")),
        Error::Invalid(_)
    );
    assert_err!(
        f.state
            .set_job_paused("game-a", "sync", Some("line\nbreak")),
        Error::Invalid(_)
    );
    assert_err!(
        f.state
            .set_job_paused("game-a", "sync", Some(&"r".repeat(257))),
        Error::Invalid(_)
    );
    assert_err!(
        f.state.set_job_paused("game-a", "a b", None),
        Error::Invalid(_)
    );
    let row = job(&f.state, "game-a", "sync");
    assert!(row.enabled);
    assert_eq!(row.paused_reason, None);
    f.state
        .set_job_paused("game-a", "sync", Some("unsupported: streams.presence"))
        .unwrap();
    assert_eq!(
        job(&f.state, "game-a", "sync").paused_reason.as_deref(),
        Some("unsupported: streams.presence")
    );
}

// Migration

/// A database exactly as a version 2 build left it, with a policy row, a
/// xite grant, a reservation, a run and a checkpoint.
fn version_two_database(db_path: &std::path::Path) {
    let conn = connect(db_path).unwrap();
    conn.pragma_update(None, "journal_mode", "WAL").unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    conn.execute_batch(crate::xite::SCHEMA_V2).unwrap();
    conn.execute(
        "INSERT INTO grants (xite, enabled, generation, limits_generation, \
         schema_generation, budget_limit, used, publication_prefix) \
         VALUES ('game-a', 1, 4, 2, 1, 1000000000, 3, NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO xite_grants (xite, publisher, enabled, capabilities, runtime_profiles, \
         limits, allow_run_once, allow_background, created_unix, expires_unix, label) \
         VALUES ('game-a', '1PublisherAddressXXXXXXXXXXXXXXXXX', 1, '[\"workspace.read\"]', \
         '[\"wasm-core-v1\"]', ?1, 1, 1, ?2, NULL, 'bradley@laptop')",
        rusqlite::params![
            serde_json::to_string(&Limits::default()).unwrap(),
            NOW - 1000
        ],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO invocations (xite, occurrence, token, generation, schema_generation, \
         request_digest, cost, status, response, commit_digest) \
         VALUES ('game-a', 'once-0123456789abcdef', '00112233445566778899aabbccddeeff', 4, 1, \
         ?1, 1, 'running', NULL, NULL)",
        rusqlite::params![DIGEST_A],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO runs (xite, started_unix, finished_unix, program, declaration_digest, \
         artifact_sha256, input_digest, status, message, cpu_seconds, peak_rss) \
         VALUES ('game-a', 1, 2, 'main', ?1, ?2, ?1, 'ok', NULL, 0.25, 4096)",
        rusqlite::params![DIGEST_A, DIGEST_B],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO checkpoints (xite, version, value) VALUES ('game-a', 2, '{\"round\":2}')",
        [],
    )
    .unwrap();
    conn.pragma_update(None, "user_version", 2).unwrap();
}

#[test]
fn database_written_by_the_milestone_two_schema_migrates_in_place() {
    let temp = tempfile::Builder::new()
        .prefix("evx-jobs-migrate-")
        .tempdir()
        .unwrap();
    let db_path = temp.path().join("v2.sqlite");
    version_two_database(&db_path);
    let state = DurableState::open(&db_path).unwrap();
    assert_eq!(state.schema_version().unwrap(), SCHEMA_VERSION);
    let (stored, generations) = state.xite_grant("game-a").unwrap().unwrap();
    assert_eq!(stored, grant("game-a"));
    assert_eq!(
        (generations.generation, generations.limits_generation),
        (4, 2)
    );
    assert_eq!(state.snapshot("game-a").unwrap().grant.unwrap().used, 3);
    assert_eq!(state.runs("game-a").unwrap().len(), 1);
    assert_eq!(state.read_state("game-a").unwrap().version, 2);
    let incomplete = state.incomplete_occurrences(None).unwrap();
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].occurrence, "once-0123456789abcdef");
    assert!(state.jobs("game-a").unwrap().is_empty());
    assert!(state.due_jobs(NOW).unwrap().is_empty());
    assert_eq!(state.daily_runs("game-a", NOW).unwrap(), 0);
    state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    assert_eq!(state.due_jobs(NOW).unwrap().len(), 1);
    let claimed = claim(&state, "game-a", "sync", NOW).unwrap();
    assert!(claimed.fresh);
    assert_eq!(claimed.generation, 4);
    assert_eq!(state.snapshot("game-a").unwrap().grant.unwrap().used, 4);
    state.reserve_daily_run("game-a", NOW, 288).unwrap();
    DurableState::open(&db_path).unwrap();
    assert_eq!(state.schema_version().unwrap(), SCHEMA_VERSION);
}

#[test]
fn database_written_before_versions_were_recorded_migrates_to_version_three() {
    let temp = tempfile::Builder::new()
        .prefix("evx-jobs-migrate-")
        .tempdir()
        .unwrap();
    let db_path = temp.path().join("v0.sqlite");
    {
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
        let version: u32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 0);
    }
    let state = DurableState::open(&db_path).unwrap();
    assert_eq!(state.schema_version().unwrap(), SCHEMA_VERSION);
    let policy = state.snapshot("game-a").unwrap().grant.unwrap();
    assert_eq!((policy.generation, policy.used), (4, 3));
    assert_eq!(policy.publication_prefix.as_deref(), Some("users/a"));
    assert!(state.jobs("game-a").unwrap().is_empty());
    assert!(state.incomplete_occurrences(None).unwrap().is_empty());
    assert_eq!(state.daily_runs("game-a", NOW).unwrap(), 0);
    // Jobs need the Milestone 2 consent row, which the old file lacks.
    state
        .set_jobs(
            "game-a",
            DIGEST_A,
            &[spec("sync", PERIOD, Missed::Skip)],
            NOW,
        )
        .unwrap();
    assert!(state.due_jobs(NOW).unwrap().is_empty());
    assert_err!(claim(&state, "game-a", "sync", NOW), Error::Denied(_));
    state.set_xite_grant(&grant("game-a")).unwrap();
    assert_eq!(state.due_jobs(NOW).unwrap().len(), 1);
    assert!(claim(&state, "game-a", "sync", NOW).unwrap().fresh);
}
