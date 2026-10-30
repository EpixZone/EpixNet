//! The inert inspect payload.
//!
//! `evxInspect` embeds this under its own keys (digest, hashes, grant status,
//! integrity). It lists every declared id, usable or not, so the consent
//! prompt and `/list` can show what the publisher asked for next to why part
//! of it is disabled. Nothing here is executed or compiled; it is a view of
//! the parsed declaration.

use serde_json::{json, Map, Value};

use crate::Declaration;

/// Render `decl` as JSON for the inspection view and the consent prompt.
///
/// Shape:
///
/// ```json
/// {
///   "version": 1,
///   "programs": {
///     "<id>": {
///       "usable": true,
///       "runtime_profile": "wasm-core-v1",
///       "entry": "evx/presence.wasm",
///       "dependencies": ["evx/lib.wasm"],
///       "allow_run_once": true,
///       "capabilities": ["workspace.read", "workspace.write"],
///       "limits": { "...": "evx_api::Limits fields" },
///       "reasons": []
///     },
///     "<unsupported id>": { "usable": false, "reasons": ["..."] }
///   },
///   "jobs": {
///     "<id>": {
///       "usable": true,
///       "program": "<id>",
///       "schedule": { "type": "interval", "seconds": 1800, "anchor": "unix_epoch", "missed": "skip" },
///       "max_concurrency": 1,
///       "reasons": []
///     },
///     "<unsupported id>": { "usable": false, "reasons": ["..."] }
///   },
///   "unsupported": [ { "path": "streams.presence", "reason": "retained streams not supported" } ]
/// }
/// ```
///
/// Unsupported programs and jobs carry only their reasons: their other
/// fields were never validated to the point of being safe to display as
/// facts about what would run.
pub fn summary(decl: &Declaration) -> Value {
    let mut programs = Map::new();
    for (id, program) in &decl.programs {
        programs.insert(
            id.clone(),
            json!({
                "usable": true,
                "runtime_profile": program.runtime_profile,
                "entry": program.entry,
                "dependencies": program.dependencies,
                "allow_run_once": program.allow_run_once,
                "capabilities": program.capabilities.iter().map(|c| c.name()).collect::<Vec<_>>(),
                "limits": serde_json::to_value(&program.limits).unwrap_or(Value::Null),
                "reasons": [],
            }),
        );
    }
    let mut jobs = Map::new();
    for (id, job) in &decl.jobs {
        jobs.insert(
            id.clone(),
            json!({
                "usable": true,
                "program": job.program,
                "schedule": serde_json::to_value(&job.schedule).unwrap_or(Value::Null),
                "max_concurrency": job.max_concurrency,
                "reasons": [],
            }),
        );
    }
    for item in &decl.unsupported {
        // Streams have no usable counterpart to attach to; they appear only
        // in the flat list below.
        let (map, id) = if let Some(id) = item.path.strip_prefix("programs.") {
            (&mut programs, id)
        } else if let Some(id) = item.path.strip_prefix("jobs.") {
            (&mut jobs, id)
        } else {
            continue;
        };
        let entry = map
            .entry(id.to_string())
            .or_insert_with(|| json!({ "usable": false, "reasons": [] }));
        if let Some(Value::Array(reasons)) = entry.get_mut("reasons") {
            reasons.push(Value::String(item.reason.clone()));
        }
    }
    json!({
        "version": decl.version,
        "programs": programs,
        "jobs": jobs,
        "unsupported": decl.unsupported.iter().map(|item| json!({ "path": item.path, "reason": item.reason })).collect::<Vec<_>>(),
    })
}
