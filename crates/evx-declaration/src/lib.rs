//! Strict parser and manifest binder for the signed `evx` section of a
//! xite's root `content.json`. See `docs/evx-milestone-2.md` section 1.
//!
//! A xite owner declares EVX work by adding a top-level `evx` object to the
//! root `content.json`, which the existing content signature already covers.
//! That object is a *request*: it names programs, the files they are made of,
//! the capabilities they want and the schedules they would like. Nothing here
//! grants anything. The node compares a parsed [`Declaration`] with the grant
//! the user actually stored, and the activation loader re-hashes every bound
//! file before a byte of it runs.
//!
//! # Strict, with a closed notion of "unsupported"
//!
//! Two different failure modes exist on purpose, and the line between them is
//! the whole design of this crate:
//!
//! * **Malformed** input fails the whole section with
//!   [`DeclarationError::Malformed`]. Duplicate JSON keys, non-finite or
//!   oversized numbers, unknown fields, wrong types, bad identifiers, path
//!   escapes, missing required fields and `version` other than `1` all land
//!   here. A malformed declaration cannot be partially trusted because its
//!   author's intent is unknowable, so nothing from it is usable.
//! * **Unsupported** requirements are well-formed requests this host cannot
//!   honour: an `api` outside the closed [`evx_api::Capability`] set, a
//!   runtime profile other than [`RUNTIME_PROFILE`], a `streams` section,
//!   a non-interval schedule, limits outside [`evx_api::Limits::validate`].
//!   The affected program or job is left out of [`Declaration::programs`] or
//!   [`Declaration::jobs`] and recorded in [`Declaration::unsupported`] with
//!   a reason, and the rest of the declaration stays usable. The plan's rule
//!   is that unsupported requirements disable the affected work rather than
//!   degrade it silently; a reason string is what makes the disabling visible
//!   in the consent prompt and the `/list` inspection view.
//!
//! There is no permissive fallback anywhere: an unknown schedule type is not
//! "run manually", an unknown limit is not "use the default", an unknown
//! capability is not "grant nothing and continue".
//!
//! # Binding
//!
//! [`bind`] turns a usable program into a [`BoundProgram`] whose entry and
//! dependencies are pinned to the `size` and `sha512` the owner signed in the
//! manifest's required `files` map. `files_optional` is refused because
//! optional files may be absent on this node and are not part of the
//! guaranteed download set; execution needs every byte present and verified.
//!
//! This crate performs no I/O. Reading files, verifying the content signature
//! and checking the bound hashes against real bytes belong to the caller and
//! to `evx-activation`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

mod bind;
mod digest;
mod parse;
mod summary;
#[cfg(test)]
mod tests;

pub use bind::{bind, BoundProgram, PinnedFile};
pub use digest::declaration_digest;
pub use parse::{parse, parse_bytes, parse_optional};
pub use summary::summary;

/// The only declaration schema version this crate understands. Any other
/// value fails the whole section: a newer schema may carry fields whose
/// absence or presence changes what the owner meant.
pub const VERSION: u64 = 1;

/// The only runtime profile the Milestone 1 runtime implements. A program
/// declaring another profile is unsupported, not reinterpreted.
pub const RUNTIME_PROFILE: &str = "wasm-core-v1";

/// Most capability objects one program may list. Mirrors the activation
/// loader's bound so a declaration cannot ask the parser to do unbounded work.
pub const MAX_CAPABILITIES: usize = 64;

/// Most concurrent occurrences one job may request. Higher values are a
/// requirement this host does not meet and make the job unsupported.
pub const MAX_JOB_CONCURRENCY: u32 = 16;

/// A parsed `evx` section: the usable programs and jobs plus every
/// requirement the host could not honour.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    /// Always [`VERSION`]; kept so a consumer can record what it parsed.
    pub version: u64,
    /// Programs this host can run, by declared id. Unsupported programs are
    /// absent here and present in `unsupported` under `programs.<id>`.
    pub programs: BTreeMap<String, Program>,
    /// Jobs whose program is usable and whose schedule this host understands.
    pub jobs: BTreeMap<String, Job>,
    /// Every requirement that disabled a program, job or stream, with the
    /// path it was found at and a reason suitable for display.
    pub unsupported: Vec<Unsupported>,
}

/// One declared program: a pinned closure of files plus the authority and
/// resources it asks for. All of it is the publisher's request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// Always [`RUNTIME_PROFILE`] for a usable program.
    pub runtime_profile: String,
    /// Manifest-relative path of the module that exports `run`.
    pub entry: String,
    /// Manifest-relative paths captured alongside the entry, in declared
    /// order, distinct from each other and from the entry.
    pub dependencies: Vec<String>,
    /// Whether the publisher asks that the program be runnable on demand.
    /// A request only; the grant decides.
    pub allow_run_once: bool,
    /// Capabilities requested, each one a member of the closed set.
    pub capabilities: BTreeSet<evx_api::Capability>,
    /// Requested limits, host defaults overlaid with the declared values,
    /// already validated by [`evx_api::Limits::validate`].
    pub limits: evx_api::Limits,
}

/// One declared job: a program and when the publisher would like it run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    /// Id of a usable program in the same declaration.
    pub program: String,
    /// The trigger.
    pub schedule: Schedule,
    /// Most occurrences the publisher wants running at once, `1..=16`.
    pub max_concurrency: u32,
}

/// A trigger this host understands. Only interval schedules exist in this
/// milestone; calendar and event triggers are declared with another `type`
/// and land in `unsupported`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Schedule {
    /// Run every `seconds`, counted from `anchor`.
    Interval {
        /// Period in whole seconds, at least 1. No minimum beyond that is
        /// imposed here: the plan forbids hard-coding a scheduling floor
        /// before workloads are measured, and the host clamps at run time.
        seconds: u64,
        /// Where the period is counted from.
        anchor: Anchor,
        /// What to do with occurrences that passed while the host was off.
        missed: Missed,
    },
}

/// Where an interval is anchored. The plan requires an explicit anchor so a
/// restart cannot restart the interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Anchor {
    /// Occurrences fall on multiples of the period since the Unix epoch.
    UnixEpoch,
}

/// Missed-occurrence policy for an interval schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Missed {
    /// Missed occurrences are dropped; the next one runs on schedule.
    Skip,
    /// All missed occurrences collapse into one catch-up run, then the
    /// cadence resumes. Bounded by construction: never more than one.
    Coalesce,
}

/// A requirement the host could not honour, with where it was declared.
///
/// `path` is exactly `programs.<id>`, `jobs.<id>` or `streams.<id>`; the
/// finer location (a capability index, a limit name) is in `reason`, so an
/// id containing `.` stays recoverable from the path. Several entries may
/// share one path when one program has several problems.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unsupported {
    /// Where the requirement was declared.
    pub path: String,
    /// Why it is unsupported, e.g. `retained streams not supported`.
    pub reason: String,
}

/// Why a declaration could not be parsed or bound.
///
/// Messages name the violated rule and quote only identifiers, paths and
/// field names the publisher wrote; they never include file contents, so
/// they are safe to show in the inspection view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeclarationError {
    /// `content.json` has no `evx` key. The caller treats this as "no EVX
    /// work declared" (`Ok(None)`); see [`parse_optional`].
    Missing,
    /// The section is present but malformed; nothing in it is usable.
    Malformed(String),
    /// [`bind`] was asked for a program that is not declared or is
    /// unsupported in this declaration.
    UnknownProgram(String),
    /// [`bind`] could not pin the program's files to the signed manifest.
    Manifest(String),
}

impl fmt::Display for DeclarationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeclarationError::Missing => f.write_str("content.json has no evx section"),
            DeclarationError::Malformed(reason) => write!(f, "malformed evx section: {reason}"),
            DeclarationError::UnknownProgram(program) => {
                write!(f, "program {program:?} is not usable in this declaration")
            }
            DeclarationError::Manifest(reason) => write!(f, "manifest binding failed: {reason}"),
        }
    }
}

impl std::error::Error for DeclarationError {}

impl DeclarationError {
    fn malformed(reason: impl Into<String>) -> Self {
        DeclarationError::Malformed(reason.into())
    }

    fn manifest(reason: impl Into<String>) -> Self {
        DeclarationError::Manifest(reason.into())
    }
}
