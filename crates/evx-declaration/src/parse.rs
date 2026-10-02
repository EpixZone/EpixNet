//! The parser proper. Works on [`evx_api::strict::Value`] so duplicate keys,
//! non-finite numbers and integers beyond `i64` are refused before any rule
//! here runs, exactly as broker requests and activation envelopes are.
//!
//! Every rule is one of two kinds, and the helper names say which:
//! `Err(...)` is malformed input that fails the section, `reasons.push(...)`
//! is a well-formed requirement this host does not meet.

use std::collections::{BTreeMap, BTreeSet};

use evx_activation::MAX_FILES;
use evx_api::strict::{self, Value};
use evx_api::{validate_identifier, validate_relative_path, Capability, Limits};

use crate::{
    Anchor, Declaration, DeclarationError, Job, Missed, Program, Schedule, Unsupported,
    MAX_CAPABILITIES, MAX_JOB_CONCURRENCY, RUNTIME_PROFILE, VERSION,
};

type Object = BTreeMap<String, Value>;
type Outcome<T> = Result<T, DeclarationError>;

/// Parse the `evx` section of an already-decoded root `content.json`.
///
/// The section is re-serialised and decoded through [`evx_api::strict`] so
/// the same number rules apply as everywhere in EVX. A `serde_json::Value`
/// has already collapsed duplicate keys, so a caller holding the raw bytes
/// should prefer [`parse_bytes`], which refuses them.
///
/// A missing section is [`DeclarationError::Missing`]; see [`parse_optional`].
pub fn parse(content: &serde_json::Value) -> Outcome<Declaration> {
    let object = content
        .as_object()
        .ok_or_else(|| DeclarationError::malformed("content.json is not an object"))?;
    let section = object.get("evx").ok_or(DeclarationError::Missing)?;
    let raw = serde_json::to_vec(section)
        .map_err(|_| DeclarationError::malformed("evx section cannot be serialised"))?;
    let value =
        strict::parse(&raw).map_err(|denied| DeclarationError::malformed(denied.to_string()))?;
    parse_section(&value)
}

/// [`parse`] with a missing section mapped to `Ok(None)`, the shape the node
/// wants: no section means no declared EVX work, not an error.
pub fn parse_optional(content: &serde_json::Value) -> Outcome<Option<Declaration>> {
    match parse(content) {
        Ok(declaration) => Ok(Some(declaration)),
        Err(DeclarationError::Missing) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Parse a root `content.json` from its bytes.
///
/// The whole document goes through [`evx_api::strict`], so a duplicate key
/// anywhere in it, including two `evx` keys or two `entry` fields, refuses
/// the declaration. This is the entry point to use when the bytes are at
/// hand; [`parse`] exists for callers that only hold a decoded value.
pub fn parse_bytes(raw: &[u8]) -> Outcome<Option<Declaration>> {
    let document = strict::parse(raw).map_err(|_| {
        DeclarationError::malformed("content.json is not valid JSON without duplicate keys")
    })?;
    let object = document
        .as_object()
        .ok_or_else(|| DeclarationError::malformed("content.json is not an object"))?;
    match object.get("evx") {
        None => Ok(None),
        Some(section) => parse_section(section).map(Some),
    }
}

fn parse_section(value: &Value) -> Outcome<Declaration> {
    let section = object(value, "evx")?;
    only_fields(section, "evx", &["version", "programs", "jobs", "streams"])?;

    let version = match section.get("version") {
        Some(Value::Int(1)) => VERSION,
        Some(Value::Int(other)) => {
            return Err(DeclarationError::malformed(format!(
                "version {other} is not supported; only version {VERSION} is"
            )))
        }
        Some(_) => return Err(DeclarationError::malformed("version must be the integer 1")),
        None => return Err(DeclarationError::malformed("version is required")),
    };

    let mut unsupported = Vec::new();

    // Programs first: jobs need to know which program ids exist and which of
    // them are usable, and the order of `unsupported` follows the document.
    let declared_programs = object(required(section, "evx", "programs")?, "programs")?;
    let mut programs = BTreeMap::new();
    let mut declared_ids = BTreeSet::new();
    for (id, value) in declared_programs {
        identifier(id, &format!("programs key {id:?}"))?;
        declared_ids.insert(id.as_str());
        let path = format!("programs.{id}");
        if let Some(program) = parse_program(&path, value, &mut unsupported)? {
            programs.insert(id.clone(), program);
        }
    }

    let mut jobs = BTreeMap::new();
    if let Some(declared_jobs) = section.get("jobs") {
        for (id, value) in object(declared_jobs, "jobs")? {
            identifier(id, &format!("jobs key {id:?}"))?;
            let path = format!("jobs.{id}");
            if let Some(job) = parse_job(&path, value, &declared_ids, &programs, &mut unsupported)?
            {
                jobs.insert(id.clone(), job);
            }
        }
    }

    // Retained streams are a Milestone 4 storage API. The section is still
    // validated for shape so a malformed one does not pass as "merely
    // unsupported", but its contents are not interpreted.
    if let Some(declared_streams) = section.get("streams") {
        for (id, value) in object(declared_streams, "streams")? {
            identifier(id, &format!("streams key {id:?}"))?;
            object(value, &format!("streams.{id}"))?;
            unsupported.push(Unsupported {
                path: format!("streams.{id}"),
                reason: "retained streams not supported".to_string(),
            });
        }
    }

    Ok(Declaration {
        version,
        programs,
        jobs,
        unsupported,
    })
}

/// Parse one program. `Ok(None)` means the program is well-formed but
/// unsupported; its reasons have been appended to `unsupported`.
fn parse_program(
    path: &str,
    value: &Value,
    unsupported: &mut Vec<Unsupported>,
) -> Outcome<Option<Program>> {
    let program = object(value, path)?;
    only_fields(
        program,
        path,
        &[
            "runtime_profile",
            "entry",
            "dependencies",
            "allow_run_once",
            "capabilities",
            "limits",
        ],
    )?;
    let mut reasons = Vec::new();

    let runtime_profile = string(
        required(program, path, "runtime_profile")?,
        &format!("{path}.runtime_profile"),
    )?;
    identifier(runtime_profile, &format!("{path}.runtime_profile"))?;
    if runtime_profile != RUNTIME_PROFILE {
        reasons.push(format!("runtime profile {runtime_profile:?} not supported"));
    }

    let entry = string(required(program, path, "entry")?, &format!("{path}.entry"))?;
    relative_path(entry, &format!("{path}.entry"))?;

    let mut dependencies = Vec::new();
    if let Some(list) = program.get("dependencies") {
        let items = array(list, &format!("{path}.dependencies"))?;
        for (index, item) in items.iter().enumerate() {
            let field = format!("{path}.dependencies[{index}]");
            let dependency = string(item, &field)?;
            relative_path(dependency, &field)?;
            if dependency == entry {
                return Err(DeclarationError::malformed(format!(
                    "{field}: dependency repeats the entry"
                )));
            }
            if dependencies.iter().any(|seen: &String| seen == dependency) {
                return Err(DeclarationError::malformed(format!(
                    "{field}: duplicate dependency"
                )));
            }
            dependencies.push(dependency.to_string());
        }
    }
    if dependencies.len() + 1 > MAX_FILES {
        reasons.push(format!(
            "closure of {} files exceeds the {MAX_FILES} files one activation may capture",
            dependencies.len() + 1
        ));
    }

    let allow_run_once = match program.get("allow_run_once") {
        None => false,
        Some(value) => boolean(value, &format!("{path}.allow_run_once"))?,
    };

    let capabilities =
        parse_capabilities(path, required(program, path, "capabilities")?, &mut reasons)?;

    let limits = parse_limits(path, program.get("limits"), &mut reasons)?;

    if reasons.is_empty() {
        Ok(Some(Program {
            runtime_profile: runtime_profile.to_string(),
            entry: entry.to_string(),
            dependencies,
            allow_run_once,
            capabilities,
            limits,
        }))
    } else {
        unsupported.extend(reasons.into_iter().map(|reason| Unsupported {
            path: path.to_string(),
            reason,
        }));
        Ok(None)
    }
}

/// A capability is exactly `{"api": "<name>"}`. The shape is strict because a
/// parameterised capability (`{"api": "data.append", "stream": "presence"}`)
/// would need a schema this host does not have; silently ignoring the extra
/// field would grant something other than what was asked. The *name* being
/// outside the closed set is the one thing that is merely unsupported.
fn parse_capabilities(
    path: &str,
    value: &Value,
    reasons: &mut Vec<String>,
) -> Outcome<BTreeSet<Capability>> {
    let field = format!("{path}.capabilities");
    let items = array(value, &field)?;
    if items.len() > MAX_CAPABILITIES {
        return Err(DeclarationError::malformed(format!(
            "{field}: more than {MAX_CAPABILITIES} capabilities"
        )));
    }
    let mut capabilities = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let field = format!("{field}[{index}]");
        let item = object(item, &field)?;
        only_fields(item, &field, &["api"])?;
        let api = string(required(item, &field, "api")?, &format!("{field}.api"))?;
        identifier(api, &format!("{field}.api"))?;
        if !names.insert(api) {
            return Err(DeclarationError::malformed(format!(
                "{field}: duplicate capability {api:?}"
            )));
        }
        match Capability::parse(api) {
            Some(capability) => {
                capabilities.insert(capability);
            }
            None => reasons.push(format!("capabilities[{index}]: api {api:?} not supported")),
        }
    }
    Ok(capabilities)
}

/// Limits are host defaults overlaid with whatever the publisher names. A
/// value of the wrong type is malformed; a limit name this host does not
/// know, or a value outside [`Limits::validate`], is a requirement it cannot
/// meet and makes the program unsupported rather than silently clamped.
fn parse_limits(path: &str, value: Option<&Value>, reasons: &mut Vec<String>) -> Outcome<Limits> {
    let defaults = Limits::default();
    let Some(value) = value else {
        return Ok(defaults);
    };
    let field = format!("{path}.limits");
    let declared = object(value, &field)?;
    let serde_json::Value::Object(mut merged) = serde_json::to_value(&defaults).map_err(|_| {
        DeclarationError::malformed(format!("{field}: default limits cannot be serialised"))
    })?
    else {
        return Err(DeclarationError::malformed(format!(
            "{field}: default limits are not an object"
        )));
    };
    for (name, value) in declared {
        if !merged.contains_key(name) {
            // The program is already unsupported at this point; the known
            // values are still decoded and range-checked below so every
            // reason is reported at once.
            reasons.push(format!("limits.{name}: unknown limit"));
            continue;
        }
        let typed = serde_json::from_str::<serde_json::Value>(&strict::to_json(value))
            .map_err(|_| DeclarationError::malformed(format!("{field}.{name}: invalid value")))?;
        merged.insert(name.clone(), typed);
    }
    let limits: Limits = serde_json::from_value(serde_json::Value::Object(merged))
        .map_err(|_| DeclarationError::malformed(format!("{field}: a limit has the wrong type")))?;
    if let Err(denied) = limits.validate() {
        reasons.push(format!("limits: {denied}"));
    }
    Ok(limits)
}

fn parse_job(
    path: &str,
    value: &Value,
    declared_programs: &BTreeSet<&str>,
    usable_programs: &BTreeMap<String, Program>,
    unsupported: &mut Vec<Unsupported>,
) -> Outcome<Option<Job>> {
    let job = object(value, path)?;
    only_fields(job, path, &["program", "schedule", "max_concurrency"])?;
    let mut reasons = Vec::new();

    let program = string(required(job, path, "program")?, &format!("{path}.program"))?;
    identifier(program, &format!("{path}.program"))?;
    if !declared_programs.contains(program) {
        reasons.push(format!("program {program:?} is not declared"));
    } else if !usable_programs.contains_key(program) {
        reasons.push(format!("program {program:?} is unsupported"));
    }

    let schedule = parse_schedule(path, required(job, path, "schedule")?, &mut reasons)?;

    let max_concurrency = match job.get("max_concurrency") {
        None => 1,
        Some(value) => {
            let field = format!("{path}.max_concurrency");
            let count = integer(value, &field)?;
            if count < 1 {
                return Err(DeclarationError::malformed(format!(
                    "{field}: must be at least 1"
                )));
            }
            match u32::try_from(count) {
                Ok(count) if count <= MAX_JOB_CONCURRENCY => count,
                _ => {
                    reasons.push(format!(
                        "max_concurrency {count} exceeds {MAX_JOB_CONCURRENCY}"
                    ));
                    MAX_JOB_CONCURRENCY
                }
            }
        }
    };

    match (schedule, reasons.is_empty()) {
        (Some(schedule), true) => Ok(Some(Job {
            program: program.to_string(),
            schedule,
            max_concurrency,
        })),
        _ => {
            unsupported.extend(reasons.into_iter().map(|reason| Unsupported {
                path: path.to_string(),
                reason,
            }));
            Ok(None)
        }
    }
}

/// `Ok(None)` is a well-formed schedule of a kind this host does not run; the
/// reason has been recorded. For an unknown `type` the other fields are not
/// interpreted: their schema is unknown, so neither accepting nor rejecting
/// them would be meaningful.
fn parse_schedule(
    path: &str,
    value: &Value,
    reasons: &mut Vec<String>,
) -> Outcome<Option<Schedule>> {
    let field = format!("{path}.schedule");
    let schedule = object(value, &field)?;
    let kind = string(
        required(schedule, &field, "type")?,
        &format!("{field}.type"),
    )?;
    if kind != "interval" {
        reasons.push(format!("schedule type {kind:?} not supported"));
        return Ok(None);
    }
    only_fields(schedule, &field, &["type", "seconds", "anchor", "missed"])?;

    let seconds = integer(
        required(schedule, &field, "seconds")?,
        &format!("{field}.seconds"),
    )?;
    let seconds = u64::try_from(seconds)
        .ok()
        .filter(|seconds| *seconds >= 1)
        .ok_or_else(|| {
            DeclarationError::malformed(format!("{field}.seconds: must be at least 1"))
        })?;

    let anchor_name = string(
        required(schedule, &field, "anchor")?,
        &format!("{field}.anchor"),
    )?;
    let anchor = match anchor_name {
        "unix_epoch" => Some(Anchor::UnixEpoch),
        other => {
            reasons.push(format!("schedule anchor {other:?} not supported"));
            None
        }
    };

    let missed_name = string(
        required(schedule, &field, "missed")?,
        &format!("{field}.missed"),
    )?;
    let missed = match missed_name {
        "skip" => Some(Missed::Skip),
        "coalesce" => Some(Missed::Coalesce),
        other => {
            reasons.push(format!("schedule missed policy {other:?} not supported"));
            None
        }
    };

    Ok(match (anchor, missed) {
        (Some(anchor), Some(missed)) => Some(Schedule::Interval {
            seconds,
            anchor,
            missed,
        }),
        _ => None,
    })
}

// Shape helpers. Each names the offending field in its message and nothing
// else, so messages stay safe to display.

fn object<'a>(value: &'a Value, field: &str) -> Outcome<&'a Object> {
    value
        .as_object()
        .ok_or_else(|| DeclarationError::malformed(format!("{field}: must be an object")))
}

fn array<'a>(value: &'a Value, field: &str) -> Outcome<&'a [Value]> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(DeclarationError::malformed(format!(
            "{field}: must be an array"
        ))),
    }
}

fn string<'a>(value: &'a Value, field: &str) -> Outcome<&'a str> {
    value
        .as_str()
        .ok_or_else(|| DeclarationError::malformed(format!("{field}: must be a string")))
}

fn boolean(value: &Value, field: &str) -> Outcome<bool> {
    value
        .as_bool()
        .ok_or_else(|| DeclarationError::malformed(format!("{field}: must be a boolean")))
}

/// Whole numbers only. `1800.0` is refused even though it is integral: the
/// signed document is the publisher's statement, and a float where an
/// integer belongs is a different statement.
fn integer(value: &Value, field: &str) -> Outcome<i64> {
    value
        .as_i64()
        .ok_or_else(|| DeclarationError::malformed(format!("{field}: must be an integer")))
}

fn required<'a>(object: &'a Object, path: &str, name: &str) -> Outcome<&'a Value> {
    object
        .get(name)
        .ok_or_else(|| DeclarationError::malformed(format!("{path}.{name}: required")))
}

fn only_fields(object: &Object, path: &str, allowed: &[&str]) -> Outcome<()> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(DeclarationError::malformed(format!(
                "{path}: unknown field {key:?}"
            )));
        }
    }
    Ok(())
}

fn identifier(value: &str, field: &str) -> Outcome<()> {
    validate_identifier(value)
        .map_err(|denied| DeclarationError::malformed(format!("{field}: {denied}")))
}

fn relative_path(value: &str, field: &str) -> Outcome<()> {
    validate_relative_path(value)
        .map(|_| ())
        .map_err(|denied| DeclarationError::malformed(format!("{field}: {denied}")))
}
