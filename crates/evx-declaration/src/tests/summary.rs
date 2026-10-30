//! The inspect payload lists every declared id with its usability.

use serde_json::json;

use super::{evx, parse_evx, set};
use crate::summary;

#[test]
fn summary_lists_usable_programs_and_jobs_with_their_details() {
    let decl = parse_evx(evx()).unwrap();
    let payload = summary(&decl);
    assert_eq!(payload["version"], 1);
    let presence = &payload["programs"]["presence"];
    assert_eq!(presence["usable"], true);
    assert_eq!(presence["runtime_profile"], "wasm-core-v1");
    assert_eq!(presence["entry"], "evx/presence.wasm");
    assert_eq!(presence["dependencies"], json!(["evx/lib.wasm"]));
    assert_eq!(presence["allow_run_once"], true);
    assert_eq!(
        presence["capabilities"],
        json!(["workspace.read", "workspace.write"])
    );
    assert_eq!(presence["limits"]["memory_bytes"], 2_097_152);
    assert_eq!(presence["limits"]["wall_seconds"], 2.0);
    assert_eq!(presence["reasons"], json!([]));
    let job = &payload["jobs"]["presence-every-30m"];
    assert_eq!(job["usable"], true);
    assert_eq!(job["program"], "presence");
    assert_eq!(
        job["schedule"],
        json!({ "type": "interval", "seconds": 1800, "anchor": "unix_epoch", "missed": "skip" })
    );
    assert_eq!(job["max_concurrency"], 1);
    assert_eq!(payload["unsupported"], json!([]));
}

#[test]
fn summary_shows_unsupported_programs_and_jobs_with_reasons_only() {
    let section = set(
        set(
            evx(),
            "/programs/score/capabilities",
            json!([{ "api": "data.append" }, { "api": "chain.read" }]),
        ),
        "/streams",
        json!({ "presence": {} }),
    );
    let section = set(
        section,
        "/jobs/score-hourly",
        json!({ "program": "score", "schedule": { "type": "interval", "seconds": 3600, "anchor": "unix_epoch", "missed": "skip" } }),
    );
    let payload = summary(&parse_evx(section).unwrap());
    assert_eq!(
        payload["programs"]["score"],
        json!({
            "usable": false,
            "reasons": [
                "capabilities[0]: api \"data.append\" not supported",
                "capabilities[1]: api \"chain.read\" not supported"
            ]
        })
    );
    assert_eq!(payload["programs"]["presence"]["usable"], true);
    assert_eq!(
        payload["jobs"]["score-hourly"],
        json!({ "usable": false, "reasons": ["program \"score\" is unsupported"] })
    );
    assert_eq!(payload["jobs"]["presence-every-30m"]["usable"], true);
    assert_eq!(
        payload["unsupported"],
        json!([
            { "path": "programs.score", "reason": "capabilities[0]: api \"data.append\" not supported" },
            { "path": "programs.score", "reason": "capabilities[1]: api \"chain.read\" not supported" },
            { "path": "jobs.score-hourly", "reason": "program \"score\" is unsupported" },
            { "path": "streams.presence", "reason": "retained streams not supported" }
        ])
    );
    assert!(
        payload.get("streams").is_none(),
        "streams only appear in the flat list"
    );
}

#[test]
fn summary_has_a_fixed_top_level_shape_even_when_empty() {
    let payload = summary(&parse_evx(json!({ "version": 1, "programs": {} })).unwrap());
    assert_eq!(
        payload,
        json!({ "version": 1, "programs": {}, "jobs": {}, "unsupported": [] })
    );
}
