//! Parser rules: each malformed shape fails the section, each unsupported
//! requirement disables exactly the affected program or job.

use std::collections::BTreeSet;

use evx_activation::MAX_FILES;
use evx_api::{Capability, Limits};
use serde_json::{json, Value};

use super::{content, evx, malformed, parse_evx, reasons, set, without};
use crate::{
    parse, parse_bytes, parse_optional, Anchor, Declaration, DeclarationError, Missed, Schedule,
    MAX_CAPABILITIES, MAX_JOB_CONCURRENCY,
};

#[test]
fn baseline_declaration_parses_programs_and_jobs() {
    let decl = parse_evx(evx()).unwrap();
    assert_eq!(decl.version, 1);
    assert!(decl.unsupported.is_empty());
    assert_eq!(decl.programs.len(), 2);
    let presence = &decl.programs["presence"];
    assert_eq!(presence.runtime_profile, "wasm-core-v1");
    assert_eq!(presence.entry, "evx/presence.wasm");
    assert_eq!(presence.dependencies, vec!["evx/lib.wasm".to_string()]);
    assert!(presence.allow_run_once);
    assert_eq!(
        presence.capabilities,
        BTreeSet::from([Capability::WorkspaceRead, Capability::WorkspaceWrite])
    );
    assert_eq!(presence.limits.memory_bytes, 2_097_152);
    assert_eq!(presence.limits.fuel, 500_000);
    assert_eq!(presence.limits.host_calls, Limits::default().host_calls);
    let score = &decl.programs["score"];
    assert!(score.dependencies.is_empty());
    assert!(!score.allow_run_once);
    assert_eq!(score.limits, Limits::default());
    let job = &decl.jobs["presence-every-30m"];
    assert_eq!(job.program, "presence");
    assert_eq!(
        job.schedule,
        Schedule::Interval {
            seconds: 1800,
            anchor: Anchor::UnixEpoch,
            missed: Missed::Skip
        }
    );
    assert_eq!(job.max_concurrency, 1);
}

#[test]
fn missing_section_is_missing_and_none_for_the_optional_caller() {
    let bare = json!({ "address": "epix1test", "files": {} });
    assert_eq!(parse(&bare), Err(DeclarationError::Missing));
    assert_eq!(parse_optional(&bare), Ok(None));
    assert!(parse_optional(&content(evx())).unwrap().is_some());
    assert_eq!(
        parse(&json!([])),
        Err(DeclarationError::malformed("content.json is not an object"))
    );
}

#[test]
fn section_must_be_an_object() {
    for section in [json!(null), json!([]), json!("evx"), json!(1), json!(true)] {
        let reason = malformed(section.clone());
        assert_eq!(reason, "evx: must be an object", "section {section}");
    }
}

#[test]
fn version_must_be_exactly_the_integer_one() {
    assert_eq!(malformed(without(evx(), "/version")), "version is required");
    assert!(malformed(set(evx(), "/version", json!(2))).contains("version 2 is not supported"));
    assert!(malformed(set(evx(), "/version", json!(0))).contains("version 0 is not supported"));
    for bad in [json!("1"), json!(1.0), json!(true), json!(null), json!([1])] {
        assert_eq!(
            malformed(set(evx(), "/version", bad.clone())),
            "version must be the integer 1",
            "version {bad}"
        );
    }
}

#[test]
fn unknown_top_level_field_fails_the_whole_section() {
    let reason = malformed(set(evx(), "/data_sources", json!({})));
    assert_eq!(reason, "evx: unknown field \"data_sources\"");
    let reason = malformed(set(evx(), "/Version", json!(1)));
    assert_eq!(reason, "evx: unknown field \"Version\"");
}

#[test]
fn programs_are_required_and_jobs_and_streams_are_optional() {
    assert_eq!(
        malformed(without(evx(), "/programs")),
        "evx.programs: required"
    );
    let decl = parse_evx(without(evx(), "/jobs")).unwrap();
    assert!(decl.jobs.is_empty());
    assert_eq!(decl.programs.len(), 2);
    let decl = parse_evx(json!({ "version": 1, "programs": {} })).unwrap();
    assert!(decl.programs.is_empty());
    assert!(decl.unsupported.is_empty());
    for bad in [json!([]), json!(null), json!("x")] {
        assert_eq!(
            malformed(set(evx(), "/programs", bad.clone())),
            "programs: must be an object"
        );
        assert_eq!(
            malformed(set(evx(), "/jobs", bad.clone())),
            "jobs: must be an object"
        );
        assert_eq!(
            malformed(set(evx(), "/streams", bad)),
            "streams: must be an object"
        );
    }
}

#[test]
fn duplicate_keys_anywhere_in_the_document_fail_through_parse_bytes() {
    let duplicates = [
        r#"{"files":{},"evx":{"version":1,"version":1,"programs":{}}}"#,
        r#"{"files":{},"evx":{"version":1,"programs":{}},"evx":{"version":1,"programs":{}}}"#,
        r#"{"files":{},"evx":{"version":1,"programs":{"a":{"runtime_profile":"wasm-core-v1","entry":"a.wasm","entry":"b.wasm","capabilities":[]}}}}"#,
        r#"{"files":{},"evx":{"version":1,"programs":{"a":{"runtime_profile":"wasm-core-v1","entry":"a.wasm","capabilities":[{"api":"workspace.read","api":"workspace.read"}]}}}}"#,
        r#"{"files":{},"files":{},"evx":{"version":1,"programs":{}}}"#,
    ];
    for raw in duplicates {
        assert!(
            matches!(
                parse_bytes(raw.as_bytes()),
                Err(DeclarationError::Malformed(_))
            ),
            "accepted {raw}"
        );
    }
    let clean = r#"{"files":{},"evx":{"version":1,"programs":{}}}"#;
    assert!(parse_bytes(clean.as_bytes()).unwrap().is_some());
}

#[test]
fn parse_bytes_without_a_section_is_none_and_rejects_non_objects() {
    assert_eq!(parse_bytes(br#"{"files":{}}"#), Ok(None));
    for raw in [&b"[]"[..], b"null", b"\"evx\"", b"{", b"", b"\xff"] {
        assert!(
            matches!(parse_bytes(raw), Err(DeclarationError::Malformed(_))),
            "accepted {raw:?}"
        );
    }
    let document = serde_json::to_vec(&content(evx())).unwrap();
    assert_eq!(
        parse_bytes(&document).unwrap().unwrap(),
        parse_evx(evx()).unwrap()
    );
}

#[test]
fn non_finite_and_oversized_numbers_fail() {
    let huge = r#"{"files":{},"evx":{"version":1,"programs":{"a":{"runtime_profile":"wasm-core-v1","entry":"a.wasm","capabilities":[],"limits":{"fuel":18446744073709551615}}}}}"#;
    assert!(matches!(
        parse_bytes(huge.as_bytes()),
        Err(DeclarationError::Malformed(_))
    ));
    let infinite = r#"{"files":{},"evx":{"version":1,"programs":{"a":{"runtime_profile":"wasm-core-v1","entry":"a.wasm","capabilities":[],"limits":{"wall_seconds":1e999}}}}}"#;
    assert!(matches!(
        parse_bytes(infinite.as_bytes()),
        Err(DeclarationError::Malformed(_))
    ));
    let nan = r#"{"files":{},"evx":{"version":1,"programs":{"a":{"runtime_profile":"wasm-core-v1","entry":"a.wasm","capabilities":[],"limits":{"wall_seconds":NaN}}}}}"#;
    assert!(matches!(
        parse_bytes(nan.as_bytes()),
        Err(DeclarationError::Malformed(_))
    ));
    // Through a decoded value the same overflow is refused by the strict re-decode.
    let value = set(evx(), "/programs/score/limits", json!({ "fuel": u64::MAX }));
    assert!(matches!(
        parse_evx(value),
        Err(DeclarationError::Malformed(_))
    ));
}

#[test]
fn program_ids_must_be_identifiers() {
    let program = evx()["programs"]["score"].clone();
    for bad in [
        "-score",
        "a b",
        "",
        "score~1",
        "scöre",
        ".hidden",
        "sc\u{202e}ore",
    ] {
        let section = set(evx(), &format!("/programs/{bad}"), program.clone());
        let reason = malformed(section);
        assert!(reason.starts_with("programs key"), "{bad:?}: {reason}");
    }
    let long = "x".repeat(129);
    assert!(
        malformed(set(evx(), &format!("/programs/{long}"), program.clone()))
            .starts_with("programs key")
    );
    let ok = "Game.Score_1-v2";
    let decl = parse_evx(set(evx(), &format!("/programs/{ok}"), program)).unwrap();
    assert!(decl.programs.contains_key(ok));
}

#[test]
fn program_must_be_an_object_with_known_fields_only() {
    for bad in [json!([]), json!("evx/x.wasm"), json!(null)] {
        assert_eq!(
            malformed(set(evx(), "/programs/score", bad)),
            "programs.score: must be an object"
        );
    }
    let reason = malformed(set(evx(), "/programs/score/network", json!(true)));
    assert_eq!(reason, "programs.score: unknown field \"network\"");
    let reason = malformed(set(evx(), "/programs/score/Entry", json!("x.wasm")));
    assert_eq!(reason, "programs.score: unknown field \"Entry\"");
}

#[test]
fn program_requires_profile_entry_and_capabilities() {
    assert_eq!(
        malformed(without(evx(), "/programs/score/runtime_profile")),
        "programs.score.runtime_profile: required"
    );
    assert_eq!(
        malformed(without(evx(), "/programs/score/entry")),
        "programs.score.entry: required"
    );
    assert_eq!(
        malformed(without(evx(), "/programs/score/capabilities")),
        "programs.score.capabilities: required"
    );
}

#[test]
fn runtime_profile_other_than_wasm_core_v1_is_unsupported() {
    let decl = parse_evx(set(
        evx(),
        "/programs/score/runtime_profile",
        json!("wasm-component-v1"),
    ))
    .unwrap();
    assert!(!decl.programs.contains_key("score"));
    assert!(decl.programs.contains_key("presence"));
    assert_eq!(
        reasons(&decl),
        vec![(
            "programs.score".to_string(),
            "runtime profile \"wasm-component-v1\" not supported".to_string()
        )]
    );
    assert_eq!(decl.jobs.len(), 1, "the job for the usable program stays");
    for bad in [json!(1), json!(null), json!(["wasm-core-v1"])] {
        assert_eq!(
            malformed(set(evx(), "/programs/score/runtime_profile", bad)),
            "programs.score.runtime_profile: must be a string"
        );
    }
    assert!(malformed(set(
        evx(),
        "/programs/score/runtime_profile",
        json!("wasm core")
    ))
    .starts_with("programs.score.runtime_profile:"));
}

#[test]
fn entry_must_be_a_relative_path_inside_the_xite() {
    for bad in [
        "../presence.wasm",
        "/evx/presence.wasm",
        "evx//presence.wasm",
        "evx/./presence.wasm",
        "evx\\presence.wasm",
        "evx:presence.wasm",
        "",
        "..namedfork/rsrc",
        "evx/.pending-presence.wasm",
        "evx/\u{202e}presence.wasm",
        "a/b/c/d/e/f/g/h/i.wasm",
    ] {
        let reason = malformed(set(evx(), "/programs/score/entry", json!(bad)));
        assert!(
            reason.starts_with("programs.score.entry:"),
            "{bad:?}: {reason}"
        );
    }
    assert_eq!(
        malformed(set(
            evx(),
            "/programs/score/entry",
            json!(["evx/score.wasm"])
        )),
        "programs.score.entry: must be a string"
    );
    let decl = parse_evx(set(
        evx(),
        "/programs/score/entry",
        json!("deep/é/score.wasm"),
    ))
    .unwrap();
    assert_eq!(decl.programs["score"].entry, "deep/é/score.wasm");
}

#[test]
fn dependencies_must_be_distinct_relative_paths() {
    let reason = malformed(set(
        evx(),
        "/programs/presence/dependencies",
        json!(["../lib.wasm"]),
    ));
    assert!(
        reason.starts_with("programs.presence.dependencies[0]:"),
        "{reason}"
    );
    let reason = malformed(set(
        evx(),
        "/programs/presence/dependencies",
        json!(["evx/lib.wasm", "evx/lib.wasm"]),
    ));
    assert_eq!(
        reason,
        "programs.presence.dependencies[1]: duplicate dependency"
    );
    let reason = malformed(set(
        evx(),
        "/programs/presence/dependencies",
        json!(["evx/presence.wasm"]),
    ));
    assert_eq!(
        reason,
        "programs.presence.dependencies[0]: dependency repeats the entry"
    );
    let reason = malformed(set(
        evx(),
        "/programs/presence/dependencies",
        json!(["evx/lib.wasm", 1]),
    ));
    assert_eq!(
        reason,
        "programs.presence.dependencies[1]: must be a string"
    );
    for bad in [json!("evx/lib.wasm"), json!({}), json!(null)] {
        assert_eq!(
            malformed(set(evx(), "/programs/presence/dependencies", bad)),
            "programs.presence.dependencies: must be an array"
        );
    }
    let decl = parse_evx(set(evx(), "/programs/presence/dependencies", json!([]))).unwrap();
    assert!(decl.programs["presence"].dependencies.is_empty());
}

#[test]
fn a_closure_larger_than_max_files_is_unsupported() {
    let deps: Vec<Value> = (0..MAX_FILES)
        .map(|i| json!(format!("evx/dep{i}.wasm")))
        .collect();
    let decl = parse_evx(set(evx(), "/programs/presence/dependencies", json!(deps))).unwrap();
    assert!(!decl.programs.contains_key("presence"));
    assert_eq!(
        reasons(&decl)[0],
        (
            "programs.presence".to_string(),
            format!(
                "closure of {} files exceeds the {MAX_FILES} files one activation may capture",
                MAX_FILES + 1
            )
        )
    );
    let deps: Vec<Value> = (0..MAX_FILES - 1)
        .map(|i| json!(format!("evx/dep{i}.wasm")))
        .collect();
    let decl = parse_evx(set(evx(), "/programs/presence/dependencies", json!(deps))).unwrap();
    assert_eq!(decl.programs["presence"].dependencies.len(), MAX_FILES - 1);
}

#[test]
fn allow_run_once_must_be_a_boolean_and_defaults_to_false() {
    for bad in [json!(1), json!("true"), json!(null)] {
        assert_eq!(
            malformed(set(evx(), "/programs/score/allow_run_once", bad)),
            "programs.score.allow_run_once: must be a boolean"
        );
    }
    let decl = parse_evx(evx()).unwrap();
    assert!(!decl.programs["score"].allow_run_once);
    let decl = parse_evx(set(evx(), "/programs/score/allow_run_once", json!(true))).unwrap();
    assert!(decl.programs["score"].allow_run_once);
}

#[test]
fn capability_objects_carry_exactly_an_api_field() {
    let reason = malformed(set(
        evx(),
        "/programs/score/capabilities",
        json!([{ "api": "workspace.read", "stream": "presence" }]),
    ));
    assert_eq!(
        reason,
        "programs.score.capabilities[0]: unknown field \"stream\""
    );
    let reason = malformed(set(evx(), "/programs/score/capabilities", json!([{}])));
    assert_eq!(reason, "programs.score.capabilities[0].api: required");
    let reason = malformed(set(
        evx(),
        "/programs/score/capabilities",
        json!(["workspace.read"]),
    ));
    assert_eq!(reason, "programs.score.capabilities[0]: must be an object");
    let reason = malformed(set(
        evx(),
        "/programs/score/capabilities",
        json!([{ "api": 1 }]),
    ));
    assert_eq!(
        reason,
        "programs.score.capabilities[0].api: must be a string"
    );
    let reason = malformed(set(
        evx(),
        "/programs/score/capabilities",
        json!([{ "api": "work space" }]),
    ));
    assert!(
        reason.starts_with("programs.score.capabilities[0].api:"),
        "{reason}"
    );
    for bad in [
        json!({ "api": "workspace.read" }),
        json!("workspace.read"),
        json!(null),
    ] {
        assert_eq!(
            malformed(set(evx(), "/programs/score/capabilities", bad)),
            "programs.score.capabilities: must be an array"
        );
    }
}

#[test]
fn unknown_api_is_unsupported_for_that_program_only() {
    let decl = parse_evx(set(
        evx(),
        "/programs/presence/capabilities",
        json!([{ "api": "workspace.read" }, { "api": "data.append" }, { "api": "ADMIN" }]),
    ))
    .unwrap();
    assert!(!decl.programs.contains_key("presence"));
    assert!(decl.programs.contains_key("score"));
    assert_eq!(
        reasons(&decl),
        vec![
            (
                "programs.presence".to_string(),
                "capabilities[1]: api \"data.append\" not supported".to_string()
            ),
            (
                "programs.presence".to_string(),
                "capabilities[2]: api \"ADMIN\" not supported".to_string()
            ),
            (
                "jobs.presence-every-30m".to_string(),
                "program \"presence\" is unsupported".to_string()
            ),
        ]
    );
    assert!(decl.jobs.is_empty());
}

#[test]
fn capability_names_are_case_sensitive_and_closed() {
    let decl = parse_evx(set(
        evx(),
        "/programs/score/capabilities",
        json!([{ "api": "Workspace.Read" }]),
    ))
    .unwrap();
    assert!(!decl.programs.contains_key("score"));
    let decl = parse_evx(set(
        evx(),
        "/programs/score/capabilities",
        json!([{ "api": "workspace.read" }, { "api": "workspace.write" }, { "api": "game.score.get" }]),
    ))
    .unwrap();
    assert_eq!(
        decl.programs["score"].capabilities,
        Capability::all().into_iter().collect()
    );
    let decl = parse_evx(set(evx(), "/programs/score/capabilities", json!([]))).unwrap();
    assert!(decl.programs["score"].capabilities.is_empty());
}

#[test]
fn duplicate_capabilities_and_oversized_lists_fail() {
    let reason = malformed(set(
        evx(),
        "/programs/score/capabilities",
        json!([{ "api": "workspace.read" }, { "api": "workspace.read" }]),
    ));
    assert_eq!(
        reason,
        "programs.score.capabilities[1]: duplicate capability \"workspace.read\""
    );
    let many: Vec<Value> = (0..=MAX_CAPABILITIES)
        .map(|i| json!({ "api": format!("x{i}") }))
        .collect();
    let reason = malformed(set(evx(), "/programs/score/capabilities", json!(many)));
    assert_eq!(
        reason,
        format!("programs.score.capabilities: more than {MAX_CAPABILITIES} capabilities")
    );
}

#[test]
fn limits_overlay_host_defaults_and_default_when_omitted() {
    let decl = parse_evx(evx()).unwrap();
    assert_eq!(decl.programs["score"].limits, Limits::default());
    let expected = Limits {
        memory_bytes: 2_097_152,
        fuel: 500_000,
        ..Limits::default()
    };
    assert_eq!(decl.programs["presence"].limits, expected);
    let decl = parse_evx(set(
        evx(),
        "/programs/score/limits",
        json!({ "wall_seconds": 3 }),
    ))
    .unwrap();
    assert_eq!(
        decl.programs["score"].limits.wall_seconds, 3.0,
        "integers are accepted for deadlines"
    );
    let decl = parse_evx(set(evx(), "/programs/score/limits", json!({}))).unwrap();
    assert_eq!(decl.programs["score"].limits, Limits::default());
}

#[test]
fn limits_outside_the_validated_envelope_are_unsupported() {
    let decl = parse_evx(set(
        evx(),
        "/programs/score/limits",
        json!({ "memory_bytes": 1 }),
    ))
    .unwrap();
    assert!(!decl.programs.contains_key("score"));
    assert_eq!(
        reasons(&decl),
        vec![(
            "programs.score".to_string(),
            "limits: invalid limit: memory_bytes".to_string()
        )]
    );
    let decl = parse_evx(set(
        evx(),
        "/programs/score/limits",
        json!({ "host_call_seconds": 5.0, "wall_seconds": 1.0 }),
    ))
    .unwrap();
    assert_eq!(
        reasons(&decl)[0].1,
        "limits: invalid deadline: host_call_seconds exceeds wall_seconds"
    );
    let decl = parse_evx(set(evx(), "/programs/score/limits", json!({ "fuel": 0 }))).unwrap();
    assert_eq!(reasons(&decl)[0].1, "limits: invalid limit: fuel");
}

#[test]
fn unknown_limit_names_are_unsupported_and_still_range_checked() {
    let decl = parse_evx(set(
        evx(),
        "/programs/score/limits",
        json!({ "max_run_ms": 5000, "memory_bytes": 1 }),
    ))
    .unwrap();
    assert_eq!(
        reasons(&decl),
        vec![
            (
                "programs.score".to_string(),
                "limits.max_run_ms: unknown limit".to_string()
            ),
            (
                "programs.score".to_string(),
                "limits: invalid limit: memory_bytes".to_string()
            ),
        ]
    );
}

#[test]
fn limits_with_the_wrong_type_fail() {
    for bad in [
        json!({ "memory_bytes": "1048576" }),
        json!({ "memory_bytes": -1 }),
        json!({ "memory_bytes": 1048576.0 }),
        json!({ "fuel": 1.5 }),
        json!({ "host_calls": 4294967296_u64 }),
        json!({ "wall_seconds": "2" }),
        json!({ "wall_seconds": null }),
    ] {
        let reason = malformed(set(evx(), "/programs/score/limits", bad.clone()));
        assert_eq!(
            reason, "programs.score.limits: a limit has the wrong type",
            "{bad}"
        );
    }
    for bad in [json!([]), json!(1), json!("default")] {
        assert_eq!(
            malformed(set(evx(), "/programs/score/limits", bad)),
            "programs.score.limits: must be an object"
        );
    }
}

#[test]
fn a_streams_section_is_unsupported_per_stream_and_leaves_programs_usable() {
    let decl = parse_evx(set(
        evx(),
        "/streams",
        json!({
            "presence": { "scope": "own_user", "retention_seconds": 345600, "max_bytes": 10485760 },
            "audit": {}
        }),
    ))
    .unwrap();
    assert_eq!(decl.programs.len(), 2);
    assert_eq!(decl.jobs.len(), 1);
    assert_eq!(
        reasons(&decl),
        vec![
            (
                "streams.audit".to_string(),
                "retained streams not supported".to_string()
            ),
            (
                "streams.presence".to_string(),
                "retained streams not supported".to_string()
            ),
        ]
    );
    let decl = parse_evx(set(evx(), "/streams", json!({}))).unwrap();
    assert!(decl.unsupported.is_empty());
    assert!(malformed(set(evx(), "/streams", json!({ "bad id": {} }))).starts_with("streams key"));
    assert_eq!(
        malformed(set(evx(), "/streams", json!({ "presence": "own_user" }))),
        "streams.presence: must be an object"
    );
}

#[test]
fn job_ids_and_shape_are_strict() {
    let job = evx()["jobs"]["presence-every-30m"].clone();
    assert!(malformed(set(evx(), "/jobs/every 30m", job.clone())).starts_with("jobs key"));
    assert_eq!(
        malformed(set(evx(), "/jobs/x", json!([]))),
        "jobs.x: must be an object"
    );
    let reason = malformed(set(evx(), "/jobs/presence-every-30m/retries", json!(3)));
    assert_eq!(reason, "jobs.presence-every-30m: unknown field \"retries\"");
    assert_eq!(
        malformed(without(evx(), "/jobs/presence-every-30m/program")),
        "jobs.presence-every-30m.program: required"
    );
    assert_eq!(
        malformed(without(evx(), "/jobs/presence-every-30m/schedule")),
        "jobs.presence-every-30m.schedule: required"
    );
    assert_eq!(
        malformed(set(
            evx(),
            "/jobs/presence-every-30m/program",
            json!(["presence"])
        )),
        "jobs.presence-every-30m.program: must be a string"
    );
    assert!(malformed(set(
        evx(),
        "/jobs/presence-every-30m/program",
        json!("-presence")
    ))
    .starts_with("jobs.presence-every-30m.program:"));
}

#[test]
fn a_job_for_an_undeclared_program_is_unsupported() {
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/program",
        json!("ghost"),
    ))
    .unwrap();
    assert!(decl.jobs.is_empty());
    assert_eq!(decl.programs.len(), 2, "programs stay usable");
    assert_eq!(
        reasons(&decl),
        vec![(
            "jobs.presence-every-30m".to_string(),
            "program \"ghost\" is not declared".to_string()
        )]
    );
}

#[test]
fn a_job_for_an_unsupported_program_is_unsupported() {
    let decl = parse_evx(set(
        evx(),
        "/programs/presence/runtime_profile",
        json!("wasm-gc-v1"),
    ))
    .unwrap();
    assert!(decl.jobs.is_empty());
    assert_eq!(
        reasons(&decl)[1],
        (
            "jobs.presence-every-30m".to_string(),
            "program \"presence\" is unsupported".to_string()
        )
    );
}

#[test]
fn non_interval_schedules_are_unsupported_without_interpreting_their_fields() {
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/schedule",
        json!({ "type": "cron", "expression": "*/30 * * * *", "timezone": "UTC" }),
    ))
    .unwrap();
    assert!(decl.jobs.is_empty());
    assert_eq!(
        reasons(&decl),
        vec![(
            "jobs.presence-every-30m".to_string(),
            "schedule type \"cron\" not supported".to_string()
        )]
    );
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/schedule",
        json!({ "type": "event", "source": "content_updated" }),
    ))
    .unwrap();
    assert_eq!(reasons(&decl)[0].1, "schedule type \"event\" not supported");
    assert_eq!(
        malformed(set(
            evx(),
            "/jobs/presence-every-30m/schedule",
            json!({ "seconds": 1800 })
        )),
        "jobs.presence-every-30m.schedule.type: required"
    );
    assert_eq!(
        malformed(set(
            evx(),
            "/jobs/presence-every-30m/schedule",
            json!({ "type": 1 })
        )),
        "jobs.presence-every-30m.schedule.type: must be a string"
    );
    assert_eq!(
        malformed(set(
            evx(),
            "/jobs/presence-every-30m/schedule",
            json!("interval")
        )),
        "jobs.presence-every-30m.schedule: must be an object"
    );
}

#[test]
fn interval_schedule_fields_are_exact() {
    let reason = malformed(set(
        evx(),
        "/jobs/presence-every-30m/schedule/jitter",
        json!(5),
    ));
    assert_eq!(
        reason,
        "jobs.presence-every-30m.schedule: unknown field \"jitter\""
    );
    for field in ["seconds", "anchor", "missed"] {
        assert_eq!(
            malformed(without(
                evx(),
                &format!("/jobs/presence-every-30m/schedule/{field}")
            )),
            format!("jobs.presence-every-30m.schedule.{field}: required")
        );
    }
    for bad in [json!("1800"), json!(1800.0), json!(null)] {
        assert_eq!(
            malformed(set(evx(), "/jobs/presence-every-30m/schedule/seconds", bad)),
            "jobs.presence-every-30m.schedule.seconds: must be an integer"
        );
    }
    for bad in [json!(0), json!(-1800)] {
        assert_eq!(
            malformed(set(evx(), "/jobs/presence-every-30m/schedule/seconds", bad)),
            "jobs.presence-every-30m.schedule.seconds: must be at least 1"
        );
    }
    assert_eq!(
        malformed(set(
            evx(),
            "/jobs/presence-every-30m/schedule/anchor",
            json!(0)
        )),
        "jobs.presence-every-30m.schedule.anchor: must be a string"
    );
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/schedule/seconds",
        json!(1),
    ))
    .unwrap();
    assert!(matches!(
        decl.jobs["presence-every-30m"].schedule,
        Schedule::Interval { seconds: 1, .. }
    ));
}

#[test]
fn unknown_anchor_or_missed_policy_is_unsupported() {
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/schedule/anchor",
        json!("activation"),
    ))
    .unwrap();
    assert_eq!(
        reasons(&decl),
        vec![(
            "jobs.presence-every-30m".to_string(),
            "schedule anchor \"activation\" not supported".to_string()
        )]
    );
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/schedule/missed",
        json!("replay_all"),
    ))
    .unwrap();
    assert_eq!(
        reasons(&decl),
        vec![(
            "jobs.presence-every-30m".to_string(),
            "schedule missed policy \"replay_all\" not supported".to_string()
        )]
    );
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/schedule/missed",
        json!("coalesce"),
    ))
    .unwrap();
    assert!(matches!(
        decl.jobs["presence-every-30m"].schedule,
        Schedule::Interval {
            missed: Missed::Coalesce,
            ..
        }
    ));
}

#[test]
fn max_concurrency_defaults_to_one_and_is_bounded() {
    let decl = parse_evx(without(evx(), "/jobs/presence-every-30m/max_concurrency")).unwrap();
    assert_eq!(decl.jobs["presence-every-30m"].max_concurrency, 1);
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/max_concurrency",
        json!(MAX_JOB_CONCURRENCY),
    ))
    .unwrap();
    assert_eq!(
        decl.jobs["presence-every-30m"].max_concurrency,
        MAX_JOB_CONCURRENCY
    );
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/max_concurrency",
        json!(MAX_JOB_CONCURRENCY + 1),
    ))
    .unwrap();
    assert!(decl.jobs.is_empty());
    assert_eq!(
        reasons(&decl)[0].1,
        format!(
            "max_concurrency {} exceeds {MAX_JOB_CONCURRENCY}",
            MAX_JOB_CONCURRENCY + 1
        )
    );
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m/max_concurrency",
        json!(i64::MAX),
    ))
    .unwrap();
    assert!(decl.jobs.is_empty());
    for bad in [json!(0), json!(-1)] {
        assert_eq!(
            malformed(set(evx(), "/jobs/presence-every-30m/max_concurrency", bad)),
            "jobs.presence-every-30m.max_concurrency: must be at least 1"
        );
    }
    for bad in [json!("1"), json!(1.0), json!(true)] {
        assert_eq!(
            malformed(set(evx(), "/jobs/presence-every-30m/max_concurrency", bad)),
            "jobs.presence-every-30m.max_concurrency: must be an integer"
        );
    }
}

#[test]
fn unsupported_entries_follow_document_order_programs_then_jobs_then_streams() {
    let section = set(
        set(
            set(
                evx(),
                "/programs/score/runtime_profile",
                json!("wasm-gc-v1"),
            ),
            "/jobs/aaa",
            json!({ "program": "ghost", "schedule": { "type": "cron" } }),
        ),
        "/streams",
        json!({ "presence": {} }),
    );
    let decl = parse_evx(section).unwrap();
    let paths: Vec<&str> = decl
        .unsupported
        .iter()
        .map(|item| item.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec!["programs.score", "jobs.aaa", "jobs.aaa", "streams.presence"]
    );
    assert_eq!(decl.jobs.len(), 1);
}

#[test]
fn a_job_with_several_problems_reports_all_of_them() {
    let decl = parse_evx(set(
        evx(),
        "/jobs/presence-every-30m",
        json!({
            "program": "ghost",
            "schedule": { "type": "interval", "seconds": 60, "anchor": "boot", "missed": "skip" },
            "max_concurrency": 99
        }),
    ))
    .unwrap();
    let texts: Vec<&str> = decl
        .unsupported
        .iter()
        .map(|item| item.reason.as_str())
        .collect();
    assert_eq!(
        texts,
        vec![
            "program \"ghost\" is not declared",
            "schedule anchor \"boot\" not supported",
            "max_concurrency 99 exceeds 16",
        ]
    );
}

#[test]
fn declaration_round_trips_through_serde_with_the_declared_json_names() {
    let decl = parse_evx(set(evx(), "/streams", json!({ "presence": {} }))).unwrap();
    let json = serde_json::to_value(&decl).unwrap();
    assert_eq!(
        json["programs"]["presence"]["capabilities"],
        json!(["workspace.read", "workspace.write"])
    );
    assert_eq!(
        json["jobs"]["presence-every-30m"]["schedule"],
        json!({ "type": "interval", "seconds": 1800, "anchor": "unix_epoch", "missed": "skip" })
    );
    assert_eq!(json["unsupported"][0]["path"], "streams.presence");
    let back: Declaration = serde_json::from_value(json).unwrap();
    assert_eq!(back, decl);
    assert_eq!(
        serde_json::to_value(Missed::Coalesce).unwrap(),
        json!("coalesce")
    );
    assert_eq!(
        serde_json::to_value(Anchor::UnixEpoch).unwrap(),
        json!("unix_epoch")
    );
}

#[test]
fn error_messages_name_the_rule_without_content() {
    let error = parse_evx(set(evx(), "/programs/score/entry", json!("../x"))).unwrap_err();
    assert_eq!(
        error.to_string(),
        "malformed evx section: programs.score.entry: path outside workspace"
    );
    assert_eq!(
        DeclarationError::Missing.to_string(),
        "content.json has no evx section"
    );
    assert_eq!(
        DeclarationError::UnknownProgram("x".into()).to_string(),
        "program \"x\" is not usable in this declaration"
    );
    assert_eq!(
        DeclarationError::Manifest("a: b".into()).to_string(),
        "manifest binding failed: a: b"
    );
}
