#![no_main]

use std::collections::{BTreeMap, BTreeSet};

use evx_api::{Capability, Limits};
use evx_declaration::{Anchor, Missed, Schedule};
use evx_state::{DurableState, Invocation, InvocationStatus, JobSpec, XiteGrant};
use libfuzzer_sys::fuzz_target;
use serde_json::json;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const XITES: [&str; 2] = ["game-one", "game-two"];

fn grant(xite: &str) -> XiteGrant {
    XiteGrant {
        xite: xite.into(),
        publisher: "fixture-publisher".into(),
        enabled: true,
        capabilities: BTreeSet::from([Capability::WorkspaceRead]),
        runtime_profiles: BTreeSet::from(["wasm-core-v1".into()]),
        limits: Limits::default(),
        allow_run_once: true,
        allow_background: true,
        created_unix: 1,
        expires_unix: None,
        label: "fixture-device".into(),
    }
}

fn register(state: &DurableState, xite: &str, period: u64, now: u64) {
    state
        .set_jobs(
            xite,
            DIGEST,
            &[JobSpec {
                job: "score".into(),
                program: "main".into(),
                schedule: Schedule::Interval {
                    seconds: period,
                    anchor: Anchor::UnixEpoch,
                    missed: Missed::Skip,
                },
                max_concurrency: 1,
            }],
            now,
        )
        .unwrap();
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 2048 {
        return;
    }
    // Every sequence owns a fresh sacrificial database. Restarts use that
    // same file; there is no model that can silently reset durable state.
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("host.sqlite");
    let mut state = DurableState::open(&path).unwrap();
    for xite in XITES {
        state.set_xite_grant(&grant(xite)).unwrap();
        register(&state, xite, 60, 0);
    }
    let mut handles: [Option<Invocation>; 2] = [None, None];
    let mut claims = BTreeSet::new();
    let mut budget = BTreeMap::<(usize, u64), u32>::new();
    let mut reconcile = [false; 2];

    for op in data.chunks_exact(4).take(512) {
        let index = (op[0] & 1) as usize;
        let xite = XITES[index];
        // Deliberately move forwards and backwards over the retention edge.
        let now = u64::from(op[1] % 24) * 86_400 + u64::from(op[2]) * 60;
        let before_other = state.snapshot(XITES[1 - index]).unwrap();
        let before_jobs = state.jobs(XITES[1 - index]).unwrap();
        let before_grant = state.xite_grant(XITES[1 - index]).unwrap();
        let before_management = state.job_management_revision(XITES[1 - index]).unwrap();
        match op[0] >> 1 {
            0..=15 => {
                if let Some(job) = state.jobs(xite).unwrap().first() {
                    let slot = DurableState::slot_at(&job.schedule, now).unwrap();
                    let request = json!({"job":job.job, "slot":slot.index,
                        "program":job.program, "declaration_digest":job.declaration_digest});
                    let result = state.claim_occurrence(xite, job, &slot, &request, now);
                    if reconcile[index] {
                        assert!(result.is_err());
                    }
                    if let Ok(invocation) = result {
                        if invocation.fresh {
                            assert!(
                                claims.insert((index, slot.end_unix - slot.start_unix, slot.index)),
                                "previously claimed schedule slot became fresh"
                            );
                        }
                        handles[index] = Some(invocation);
                    }
                }
            }
            16..=23 => {
                if let Some(h) = &handles[index] {
                    let uncertain = op[3] & 1 != 0;
                    let running = state.snapshot(xite).unwrap().invocations.iter().any(|row| {
                        row.occurrence == h.occurrence
                            && row.token == h.token
                            && row.status == InvocationStatus::Running
                    });
                    let result = json!({"status":if uncertain {"effect_unknown"} else {"ok"}});
                    if state
                        .finish_occurrence(h, &result, Some(now + 60), uncertain)
                        .is_ok()
                        && uncertain
                        && running
                    {
                        reconcile[index] = true;
                    }
                }
            }
            24..=31 => {
                if let Some(h) = &handles[index] {
                    let _ = state.mark_execution_started(h);
                }
            }
            32..=39 => {
                if let Some(h) = &handles[index] {
                    if let Ok(new) = state.recover(h) {
                        // Recovered ownership must fence the old token even
                        // while the same grant remains enabled.
                        assert_ne!(new.token, h.token);
                        assert!(state
                            .finish_occurrence(h, &json!({"status":"ok"}), None, false)
                            .is_err());
                        handles[index] = Some(new);
                    }
                }
            }
            40..=47 => {
                state.revoke_xite(xite).unwrap();
            }
            48..=55 => {
                state.set_xite_grant(&grant(xite)).unwrap();
            }
            56..=63 => {
                state.set_jobs(xite, DIGEST, &[], now).unwrap();
            }
            64..=71 => {
                register(&state, xite, [60, 120, 300][(op[3] % 3) as usize], now);
            }
            72..=79 => {
                state = DurableState::open(&path).unwrap();
            }
            80..=87 => {
                let _ = state.set_job_paused(xite, "score", Some("user"));
            }
            88..=95 => {
                let revision = state.job_management_revision(xite).unwrap();
                if op[3] & 2 != 0 && state.set_job_paused(xite, "score", Some("user")).is_ok() {
                    assert!(
                        state
                            .resume_job_at_revision(xite, "score", revision)
                            .is_err(),
                        "stale recovery cleared a newer operator pause"
                    );
                } else if state
                    .resume_job_at_revision(xite, "score", revision)
                    .is_ok()
                {
                    reconcile[index] = false;
                }
            }
            96..=103 => {
                let _ = state.set_job_enabled(xite, "score", false);
            }
            104..=111 => {
                let _ = state.set_job_enabled(xite, "score", true);
            }
            _ => {
                if state.reserve_daily_run(xite, now, 3).is_ok() {
                    let spent = budget.entry((index, now / 86_400)).or_default();
                    *spent += 1;
                    assert!(*spent <= 3, "clock rollback reset a spent daily budget");
                }
            }
        }
        assert_eq!(
            state.snapshot(XITES[1 - index]).unwrap(),
            before_other,
            "one xite's transition altered another xite's authority or journal"
        );
        assert_eq!(
            state.jobs(XITES[1 - index]).unwrap(),
            before_jobs,
            "one xite's transition altered another xite's jobs"
        );
        assert_eq!(
            state.xite_grant(XITES[1 - index]).unwrap(),
            before_grant,
            "one xite's transition altered another xite's consent"
        );
        assert_eq!(
            state.job_management_revision(XITES[1 - index]).unwrap(),
            before_management,
            "one xite's transition altered another xite's management revision"
        );
    }
});
