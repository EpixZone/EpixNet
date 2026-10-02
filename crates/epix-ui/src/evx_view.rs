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
//! `evx-declaration`, which performs no I/O, and reads the already-loaded
//! `AppState::content` value; it never opens a program file, never links
//! `evx-runtime`, and links programs as downloads so that following a link
//! cannot navigate into active content. That is what lets the file manager
//! show it on any node, including a public gateway: there is nothing on this
//! page a visitor could make the node run.
//!
//! The declaration is parsed from the decoded value, not the stored bytes,
//! so a duplicated key that `evx_declaration::parse_bytes` would refuse has
//! already collapsed here. The panel is advisory; the EVX service, which
//! decides what runs, reads the bytes (see `docs/evx-milestone-2.md` section
//! 4). The two cannot disagree on anything the user acts on, because a grant
//! is bound to the service's digest and the `evxGrant` command refuses any
//! other.
//!
//! Every string that reaches the page, whether from the declaration, the
//! manifest, a parser message or the grant, goes through
//! [`super::html_escape`]; the publisher wrote all of them.

use serde_json::Value;

use super::{html_escape, url_encode};

/// The status rows the panel always carries, in order, with the exact labels
/// the spec names. A test that looks for one of these strings is looking for
/// the row, so they are constants rather than literals in the template.
pub(crate) const INTEGRITY_LABEL: &str = "Integrity verified";
/// See [`INTEGRITY_LABEL`].
pub(crate) const PROFILE_LABEL: &str = "EVX profile valid";
/// See [`INTEGRITY_LABEL`].
pub(crate) const ENABLED_LABEL: &str = "EVX enabled for this xite";

/// What the node knows about the xite besides its declaration.
pub(crate) struct XiteFacts<'a> {
    /// The bech32 address the xite is served under.
    pub address: &'a str,
    /// `epix_content::verify_signer(content, address)`: the root is signed by
    /// the xite owner.
    pub signed: bool,
    /// `AppState::xite_core_complete(address)`: every declared file is on disk.
    pub complete: bool,
    /// `AppState::evx_grant_summary(address)`: the stored grant, if any.
    pub grant: Option<&'a Value>,
}

/// Whether the normal listing should offer the panel: the loaded root has an
/// `evx` key, whatever its shape. A malformed section is exactly what the
/// panel exists to explain, so the link is not gated on it parsing.
pub(crate) fn declares_evx(content: Option<&Value>) -> bool {
    content.is_some_and(|content| content.get("evx").is_some())
}

/// Render the panel, or `None` when the xite has no loaded root or its root
/// has no `evx` section: a xite that declares nothing gets no panel, not an
/// empty one, so the listing stays as it was before EVX existed.
pub(crate) fn render(content: Option<&Value>, facts: &XiteFacts<'_>) -> Option<String> {
    let content = content?;
    content.get("evx")?;
    let esc = html_escape;

    let integrity = match (facts.signed, facts.complete) {
        (true, true) => Status::ok("verified"),
        (false, _) => Status::bad("unsigned: content.json does not carry a valid signature from the xite owner"),
        (true, false) => Status::bad("incomplete: a declared file is missing on this node"),
    };

    let parsed = evx_declaration::parse(content);
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

    let enabled = match facts.grant {
        None => Status::bad("no: no grant is stored for this xite"),
        Some(grant) if grant.get("enabled") == Some(&Value::Bool(true)) => Status::ok("yes"),
        Some(_) => Status::bad("no: the stored grant is disabled"),
    };

    let mut body = String::new();
    body.push_str("<dl class='evx-status'>");
    for (label, status) in [
        (INTEGRITY_LABEL, &integrity),
        (PROFILE_LABEL, &profile),
        (ENABLED_LABEL, &enabled),
    ] {
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
            let digest = match evx_declaration::declaration_digest(content) {
                Ok(digest) => esc(&digest),
                // The digest decodes the same section `parse` just accepted,
                // so this cannot fail without a bug; say so rather than hide it.
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
            render_programs(&mut body, decl, &summary, content, facts.address);
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

    if let Some(grant) = facts.grant {
        let rendered = serde_json::to_string_pretty(grant).unwrap_or_else(|_| grant.to_string());
        body.push_str(&format!(
            "<h3>Stored grant</h3><pre class='evx-grant'>{}</pre>",
            esc(&rendered)
        ));
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

/// The programs table: usable programs with their pinned closure, requested
/// capabilities and limits; unsupported programs with their reasons only.
fn render_programs(
    body: &mut String,
    decl: &evx_declaration::Declaration,
    summary: &Value,
    content: &Value,
    address: &str,
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
        match evx_declaration::bind(decl, id, content) {
            Ok(bound) => {
                body.push_str(
                    "<table><tr><th>Role</th><th>Path</th><th>Size</th><th>sha512</th></tr>",
                );
                let mut files = vec![("entry", &bound.entry)];
                files.extend(bound.dependencies.iter().map(|file| ("dependency", file)));
                for (role, file) in files {
                    body.push_str(&format!(
                        "<tr><td>{role}</td><td><a href='{href}' download>{path}</a></td>\
                         <td>{size} B</td><td><code>{sha512}</code></td></tr>",
                        href = file_href(address, &file.path),
                        path = esc(&file.path),
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

/// A link to the raw file, percent-encoded segment by segment exactly like
/// the listing's own links, carried in a single-quoted attribute. The file
/// route serves it as a plain file; the `download` attribute on the anchor
/// keeps a click from navigating into it.
fn file_href(address: &str, path: &str) -> String {
    let encoded = path.split('/').map(url_encode).collect::<Vec<_>>().join("/");
    html_escape(&format!("/{}/{encoded}", url_encode(address)))
}
