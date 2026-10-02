//! The inert EVX inspection panel of the file manager
//! (`/list/<xite>/?evx=1`). See `docs/evx-milestone-2.md` section 6.
//!
//! The panel shows what a xite's signed `evx` declaration asks for next to
//! what this node has decided about it: whether the root `content.json` is
//! signed by the xite owner, whether the core files are complete, the
//! declaration digest a grant is bound to, every program with its entry and
//! dependencies pinned to the manifest's sizes and hashes, the requested
//! capabilities, limits, jobs and schedules, every requirement this host
//! cannot honour with its reason, and whether a grant is stored.
//!
//! It is a view and nothing else. It parses the declaration with
//! `evx-declaration`, which performs no I/O, from the stored `content.json`
//! bytes the caller read; it never opens a program file, never links
//! `evx-runtime`, and links programs through the `/raw/` route, which serves
//! bytes under the noscript sandbox policy and never renders the wrapper, so
//! that following a link cannot navigate into active content. That is what
//! lets the file manager show it on any node, including a public gateway:
//! there is nothing on this page a visitor could make the node run.
//!
//! The declaration and its digest come from the stored bytes
//! (`evx_declaration::parse_bytes` / `declaration_digest_bytes`), exactly as
//! the EVX service reads them (`docs/evx-milestone-2.md` section 4), and not
//! from the decoded `AppState::content` value, in which a duplicated key has
//! already collapsed to its last value. A `content.json` carrying two `evx`
//! keys, a decoy first and the signed one last, is therefore shown as
//! malformed with no digest here, as the service reports it, rather than as
//! verified and valid. The signature check and the manifest binding use the
//! value re-decoded from bytes the strict decode accepted.
//!
//! The stored grant is never printed. The page says whether a grant is
//! stored and enabled, its authority generation and its expiry, and nothing
//! else: the record carries the operator's device label and consent history,
//! which are not the publisher's or a visitor's business. On a public gateway
//! (`ui_restrict`) the panel says nothing about the grant at all, mirroring
//! the file manager's `can_revert` gate.
//!
//! Every string that reaches the page, whether from the declaration, the
//! manifest or a parser message, goes through [`super::html_escape`]; the
//! publisher wrote all of them.

use serde_json::Value;

use super::{html_escape, url_encode};

/// The status rows the panel always carries, in order, with the exact labels
/// the spec names. A test that looks for one of these strings is looking for
/// the row, so they are constants rather than literals in the template.
pub(crate) const INTEGRITY_LABEL: &str = "Integrity verified";
/// See [`INTEGRITY_LABEL`].
pub(crate) const PROFILE_LABEL: &str = "EVX profile valid";
/// See [`INTEGRITY_LABEL`]. Absent on a restricted gateway.
pub(crate) const ENABLED_LABEL: &str = "EVX enabled for this xite";

/// What the node knows about the xite besides its stored root.
pub(crate) struct XiteFacts<'a> {
    /// The bech32 address the xite is served under; the root's signature is
    /// verified against it.
    pub address: &'a str,
    /// `AppState::xite_core_complete(address)`: every declared file is on disk.
    pub complete: bool,
    /// `AppState::evx_grant_summary(address)`: the stored grant, if any. The
    /// view reads three fields of it and prints nothing else: `enabled`
    /// (bool), `generation` (the authority generation, integer) and
    /// `expires_unix` (integer seconds, or absent/null for never).
    pub grant: Option<&'a Value>,
    /// `AppState::ui_restrict()`: a public gateway. The panel then carries
    /// no grant row and no grant section.
    pub restricted: bool,
    /// Whether program files may be linked at all: true on the loopback UI
    /// origin, where `/raw/<xite>/<path>` is served inert. On a transparent
    /// proxy host (`dashboard.epix`) every path naming another xite is sent
    /// to that xite's own origin, so there is no inert same-origin route to
    /// link and the paths are shown as text next to their pinned hashes.
    pub linkable: bool,
}

/// Whether the normal listing should offer the panel: the loaded root has an
/// `evx` key, whatever its shape. A malformed section is exactly what the
/// panel exists to explain, so the link is not gated on it parsing.
pub(crate) fn declares_evx(content: Option<&Value>) -> bool {
    content.is_some_and(|content| content.get("evx").is_some())
}

/// Render the panel from the stored root `content.json` bytes, or `None`
/// when the root has no `evx` section: a xite that declares nothing gets no
/// panel, not an empty one, so the listing stays as it was before EVX
/// existed. A root that does not decode strictly (duplicate keys) gets the
/// panel with the malformed status, since that is what the service would
/// refuse a grant for.
pub(crate) fn render(raw: &[u8], facts: &XiteFacts<'_>) -> Option<String> {
    let esc = html_escape;

    let parsed = match evx_declaration::parse_bytes(raw) {
        Ok(None) => return None,
        Ok(Some(decl)) => Ok(decl),
        Err(error) => Err(error),
    };
    let digest = evx_declaration::declaration_digest_bytes(raw);
    // The document decoded strictly (no duplicate key anywhere in it) when
    // either byte-level entry point got as far as the section. Only then is
    // a re-decoded value the same document the signature and manifest
    // describe, so only then is it verified and bound.
    let strict: Option<Value> = if parsed.is_ok() || digest.is_ok() {
        serde_json::from_slice(raw).ok()
    } else {
        None
    };
    let signed = strict
        .as_ref()
        .is_some_and(|content| epix_content::verify_signer(content, facts.address));

    let integrity = match (&strict, &parsed, signed, facts.complete) {
        (None, Err(error), _, _) => Status::bad(format!("unverifiable: {error}")),
        (None, Ok(_), _, _) => Status::bad("unverifiable: content.json could not be re-decoded"),
        (Some(_), _, false, _) => {
            Status::bad("unsigned: content.json does not carry a valid signature from the xite owner")
        }
        (Some(_), _, true, false) => Status::bad("incomplete: a declared file is missing on this node"),
        (Some(_), _, true, true) => Status::ok("verified"),
    };

    let profile = match &parsed {
        Ok(decl) if decl.unsupported.is_empty() => Status::ok("valid"),
        Ok(decl) => Status::warn(format!(
            "valid, with {} unsupported item{}",
            decl.unsupported.len(),
            if decl.unsupported.len() == 1 { "" } else { "s" }
        )),
        Err(evx_declaration::DeclarationError::Missing) => Status::bad("absent"),
        Err(error) => Status::bad(format!("malformed: {error}")),
    };

    let mut rows = vec![(INTEGRITY_LABEL, integrity), (PROFILE_LABEL, profile)];
    if !facts.restricted {
        rows.push((ENABLED_LABEL, grant_enabled(facts.grant)));
    }

    let mut body = String::new();
    body.push_str("<dl class='evx-status'>");
    for (label, status) in &rows {
        body.push_str(&format!(
            "<dt>{label}</dt><dd class='{class}'>{value}</dd>",
            label = esc(label),
            class = status.class,
            value = esc(&status.value),
        ));
    }
    body.push_str("</dl>");

    match &parsed {
        Ok(decl) => {
            let digest = match digest {
                Ok(Some(digest)) => esc(&digest),
                // The digest decodes the same bytes `parse_bytes` just
                // accepted, so neither arm can happen without a bug; say so
                // rather than hide it.
                Ok(None) => "unavailable: no evx section".to_string(),
                Err(error) => format!("unavailable: {}", esc(&error.to_string())),
            };
            body.push_str(&format!(
                "<p class='evx-digest'>Declaration digest <code>{digest}</code> \
                 (schema version {version})</p>",
                version = decl.version,
            ));
            // The same payload `evxInspect` embeds, so this page and the
            // consent prompt cannot drift apart on what is usable and why.
            let summary = evx_declaration::summary(decl);
            render_programs(&mut body, decl, &summary, strict.as_ref(), facts);
            render_jobs(&mut body, decl, &summary);
            render_unsupported(&mut body, decl);
        }
        Err(error) => {
            body.push_str(&format!(
                "<p class='evx-malformed'>The evx section cannot be used: {}</p>",
                esc(&error.to_string())
            ));
        }
    }

    if !facts.restricted {
        if let Some(grant) = facts.grant {
            render_grant(&mut body, grant);
        }
    }

    Some(format!(
        "<style>.evx{{margin:0 0 24px;padding:16px;border:1px solid var(--epix-border);border-radius:6px}}\
          .evx h2{{margin:0 0 12px;font-size:17px}} .evx h3{{margin:18px 0 8px;font-size:15px}}\
          .evx h4{{margin:12px 0 6px;font-size:14px}}\
          .evx dl{{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:0}}\
          .evx dt{{font-weight:600}} .evx dd{{margin:0;overflow-wrap:anywhere}}\
          .evx dd.ok{{color:var(--epix-success)}} .evx dd.warn{{color:var(--epix-warning)}}\
          .evx dd.bad{{color:var(--epix-text-mid)}}\
          .evx code,.evx pre{{font-size:12px;overflow-wrap:anywhere;white-space:pre-wrap}}\
          .evx table{{border-collapse:collapse;width:100%;font-size:13px}}\
          .evx th,.evx td{{text-align:left;vertical-align:top;padding:4px 8px 4px 0;overflow-wrap:anywhere}}\
          .evx ul{{margin:4px 0;padding-left:20px}}\
          .evx .reason{{color:var(--epix-text-mid)}}</style>\
         <section class='evx' id='evx-panel'><h2>EVX declaration</h2>{body}</section>"
    ))
}

/// One status row: a value and the class that colours it.
struct Status {
    class: &'static str,
    value: String,
}

impl Status {
    fn ok(value: impl Into<String>) -> Self {
        Status { class: "ok", value: value.into() }
    }

    fn warn(value: impl Into<String>) -> Self {
        Status { class: "warn", value: value.into() }
    }

    fn bad(value: impl Into<String>) -> Self {
        Status { class: "bad", value: value.into() }
    }
}

/// Whether the stored grant is enabled.
fn grant_is_enabled(grant: &Value) -> bool {
    grant.get("enabled") == Some(&Value::Bool(true))
}

/// The `EVX enabled for this xite` row.
fn grant_enabled(grant: Option<&Value>) -> Status {
    match grant {
        None => Status::bad("no: no grant is stored for this xite"),
        Some(grant) if grant_is_enabled(grant) => Status::ok("yes"),
        Some(_) => Status::bad("no: the stored grant is disabled"),
    }
}

/// The stored grant's status facts and nothing else: enabled or disabled,
/// the authority generation and the expiry. The record itself (label,
/// timestamps, limits, capability sets) never reaches the page; `evxInspect`
/// exposes grant status, not the record, and so does this view.
fn render_grant(body: &mut String, grant: &Value) {
    let generation = match grant.get("generation").and_then(Value::as_u64) {
        Some(generation) => generation.to_string(),
        None => "unknown".to_string(),
    };
    let expiry = match grant.get("expires_unix") {
        None | Some(Value::Null) => "never".to_string(),
        Some(value) => match value.as_u64() {
            Some(seconds) => format!("at unix time {seconds}"),
            None => "unknown".to_string(),
        },
    };
    body.push_str(&format!(
        "<h3>Stored grant</h3><dl class='evx-grant'>\
         <dt>Enabled</dt><dd>{enabled}</dd>\
         <dt>Authority generation</dt><dd>{generation}</dd>\
         <dt>Expires</dt><dd>{expiry}</dd></dl>",
        enabled = if grant_is_enabled(grant) { "yes" } else { "no" },
        generation = html_escape(&generation),
        expiry = html_escape(&expiry),
    ));
}

/// The programs table: usable programs with their pinned closure, requested
/// capabilities and limits; unsupported programs with their reasons only.
/// `content` is the root re-decoded from strictly accepted bytes, or `None`
/// when no such value exists, in which case nothing can be bound.
fn render_programs(
    body: &mut String,
    decl: &evx_declaration::Declaration,
    summary: &Value,
    content: Option<&Value>,
    facts: &XiteFacts<'_>,
) {
    let esc = html_escape;
    let Some(programs) = summary.get("programs").and_then(Value::as_object) else {
        return;
    };
    if programs.is_empty() {
        body.push_str("<h3>Programs</h3><p>None declared.</p>");
        return;
    }
    body.push_str("<h3>Programs</h3>");
    for (id, program) in programs {
        body.push_str(&format!("<h4><code>{}</code></h4>", esc(id)));
        let Some(declared) = decl.programs.get(id) else {
            // Unsupported: only the reasons were validated far enough to show.
            body.push_str("<p class='reason'>Unsupported:</p><ul class='reason'>");
            for reason in reasons(program) {
                body.push_str(&format!("<li>{}</li>", esc(reason)));
            }
            body.push_str("</ul>");
            continue;
        };
        let bound = match content {
            Some(content) => evx_declaration::bind(decl, id, content),
            None => Err(evx_declaration::DeclarationError::Manifest(
                "content.json could not be re-decoded".to_string(),
            )),
        };
        match bound {
            Ok(bound) => {
                body.push_str(
                    "<table><tr><th>Role</th><th>Path</th><th>Size</th><th>sha512</th></tr>",
                );
                let mut files = vec![("entry", &bound.entry)];
                files.extend(bound.dependencies.iter().map(|file| ("dependency", file)));
                for (role, file) in files {
                    let path = if facts.linkable {
                        format!(
                            "<a href='{href}' download>{path}</a>",
                            href = file_href(facts.address, &file.path),
                            path = esc(&file.path),
                        )
                    } else {
                        format!("<code>{}</code>", esc(&file.path))
                    };
                    body.push_str(&format!(
                        "<tr><td>{role}</td><td>{path}</td>\
                         <td>{size} B</td><td><code>{sha512}</code></td></tr>",
                        size = file.size,
                        sha512 = esc(&file.sha512),
                    ));
                }
                body.push_str(&format!(
                    "</table><p>{} B in all.</p>",
                    bound.total_bytes
                ));
            }
            Err(error) => {
                // The manifest does not pin the closure: the paths are still
                // shown as text (the publisher wrote them) but never linked,
                // since nothing authenticated says what is behind them.
                body.push_str(&format!(
                    "<p class='reason'>Cannot bind to the manifest: {}</p><ul>",
                    esc(&error.to_string())
                ));
                body.push_str(&format!("<li>entry <code>{}</code></li>", esc(&declared.entry)));
                for dependency in &declared.dependencies {
                    body.push_str(&format!(
                        "<li>dependency <code>{}</code></li>",
                        esc(dependency)
                    ));
                }
                body.push_str("</ul>");
            }
        }
        body.push_str("<dl>");
        body.push_str(&format!(
            "<dt>Runtime profile</dt><dd>{}</dd>",
            esc(&declared.runtime_profile)
        ));
        body.push_str(&format!(
            "<dt>Run once</dt><dd>{}</dd>",
            if declared.allow_run_once { "requested" } else { "not requested" }
        ));
        let capabilities = if declared.capabilities.is_empty() {
            "none".to_string()
        } else {
            declared
                .capabilities
                .iter()
                .map(|capability| format!("<code>{}</code>", esc(capability.name())))
                .collect::<Vec<_>>()
                .join(", ")
        };
        body.push_str(&format!("<dt>Capabilities</dt><dd>{capabilities}</dd>"));
        body.push_str(&format!("<dt>Limits</dt><dd>{}</dd>", render_limits(declared)));
        body.push_str("</dl>");
    }
}

/// The requested limits, one `name=value` per field, in the field order of
/// `evx_api::Limits`. Rendered through the struct's own serialisation so a
/// limit added there appears here without a second list to keep in step.
fn render_limits(program: &evx_declaration::Program) -> String {
    let Ok(Value::Object(fields)) = serde_json::to_value(&program.limits) else {
        return "unavailable".to_string();
    };
    fields
        .iter()
        .map(|(name, value)| format!("<code>{}={}</code>", html_escape(name), html_escape(&value.to_string())))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The jobs table, usable jobs with their schedule and unsupported ones
/// with their reasons.
fn render_jobs(body: &mut String, decl: &evx_declaration::Declaration, summary: &Value) {
    let esc = html_escape;
    let Some(jobs) = summary.get("jobs").and_then(Value::as_object) else {
        return;
    };
    if jobs.is_empty() {
        body.push_str("<h3>Jobs</h3><p>None declared.</p>");
        return;
    }
    body.push_str("<h3>Jobs</h3><table><tr><th>Job</th><th>Program</th><th>Schedule</th><th>Concurrency</th></tr>");
    for (id, job) in jobs {
        match decl.jobs.get(id) {
            Some(declared) => {
                let evx_declaration::Schedule::Interval { seconds, anchor, missed } = &declared.schedule;
                body.push_str(&format!(
                    "<tr><td><code>{id}</code></td><td><code>{program}</code></td>\
                     <td>every {seconds} s from {anchor}, missed: {missed}</td><td>{concurrency}</td></tr>",
                    id = esc(id),
                    program = esc(&declared.program),
                    anchor = esc(&wire_name(anchor)),
                    missed = esc(&wire_name(missed)),
                    concurrency = declared.max_concurrency,
                ));
            }
            None => {
                let reasons = reasons(job).map(esc).collect::<Vec<_>>().join("; ");
                body.push_str(&format!(
                    "<tr><td><code>{}</code></td><td colspan='3' class='reason'>unsupported: {reasons}</td></tr>",
                    esc(id)
                ));
            }
        }
    }
    body.push_str("</table>");
}

/// The flat list of every unsupported requirement with its path and reason,
/// including streams, which have no program or job row to hang off.
fn render_unsupported(body: &mut String, decl: &evx_declaration::Declaration) {
    let esc = html_escape;
    if decl.unsupported.is_empty() {
        return;
    }
    body.push_str("<h3>Unsupported on this node</h3><ul>");
    for item in &decl.unsupported {
        body.push_str(&format!(
            "<li><code>{}</code>: <span class='reason'>{}</span></li>",
            esc(&item.path),
            esc(&item.reason)
        ));
    }
    body.push_str("</ul>");
}

/// The snake_case name a closed enum carries on the wire (`unix_epoch`,
/// `skip`), which is also the name the publisher wrote in the declaration.
/// Serialising a fieldless enum cannot fail; the fallback is only to keep
/// this total without an `unwrap` in page rendering.
fn wire_name<T: serde::Serialize + std::fmt::Debug>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        _ => format!("{value:?}"),
    }
}

/// The `reasons` strings of one summary entry.
fn reasons(entry: &Value) -> impl Iterator<Item = &str> {
    entry
        .get("reasons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// A link to the file on the `/raw/<xite>/<path>` route, percent-encoded
/// segment by segment exactly like the listing's own links, carried in a
/// single-quoted attribute. That route serves the bytes with no wrapper and
/// under the noscript sandbox policy whatever the file is called and however
/// it is opened, so a `.html` entry middle-clicked or opened in a new tab
/// (a top-level document navigation, which ignores `download`) still never
/// renders the wrapper or runs the xite. The `download` attribute is a hint
/// for the ordinary click, not what keeps the link inert.
fn file_href(address: &str, path: &str) -> String {
    let encoded = path.split('/').map(url_encode).collect::<Vec<_>>().join("/");
    html_escape(&format!("/raw/{}/{encoded}", url_encode(address)))
}
