//! The Backup & Restore wizard (`/Backup`): create component-selectable backup
//! archives of the node's data, list/download/delete them, and restore one -
//! including archives uploaded from another device.
//!
//! Archive format (format_version 1): a plain ZIP whose first entry is an
//! unencrypted `manifest.json` describing what the archive holds. Data entries
//! are deflate-compressed; with a password they are AES-256 encrypted (AE-2),
//! so wrong passwords and tampering are both detected, and the archive still
//! opens in standard zip tools as a disaster-recovery escape hatch. Entry names
//! always use forward slashes, so a backup made on one OS restores on any
//! other. Restoring never applies live: the selection is staged under
//! `<data_root>/restore-pending/` and applied by [`apply_pending_restore`] on
//! the next node start, before anything reads the data dir - the same
//! applies-on-restart approach as changing the data directory.

use crate::state::AppState;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// The newest backup archive format this build can restore. An archive with a
/// larger `format_version` was made by a newer EpixNet; restoring it here is
/// refused instead of guessing.
pub const SUPPORTED_BACKUP_FORMAT: u32 = 1;

/// Subdirectory of the data root where backups are stored. Excluded from the
/// archives themselves by the component whitelist.
const BACKUPS_DIR: &str = "backups";

/// Staging area for a restore awaiting the next start.
const PENDING_DIR: &str = "restore-pending";

/// The component keys, in display order.
const COMPONENTS: &[&str] = &["keys", "config", "zites"];

fn component_label(key: &str) -> &'static str {
    match key {
        "keys" => "Keys & identity",
        "config" => "Node settings",
        "zites" => "Zites & site data",
        _ => "Unknown",
    }
}

fn component_description(key: &str) -> &'static str {
    match key {
        "keys" => "Your master seed and per-site private keys (private/users.json). This is what recovers your identity.",
        "config" => "The node configuration (private/config.json).",
        "zites" => "All zite content and the served-sites list, so this node serves the same sites again.",
        _ => "",
    }
}

// --- Manifest -----------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub format_version: u32,
    pub app: String,
    pub app_version: String,
    /// ISO-8601 UTC creation time.
    pub created: String,
    pub encrypted: bool,
    /// Component key -> what the archive holds for it. Only listed files (and
    /// `data/<address>/` trees for the listed sites) are ever restored.
    pub components: BTreeMap<String, ComponentEntry>,
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ComponentEntry {
    /// Data-root-relative file paths with `/` separators.
    pub files: Vec<String>,
    /// For `zites`: the site addresses whose `data/<address>/` trees are included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<String>,
}

/// One stored backup, as listed on the page.
pub struct BackupInfo {
    pub file_name: String,
    pub size: u64,
    pub manifest: Option<Manifest>,
}

// --- Time helpers (no chrono dependency) --------------------------------------

/// (year, month, day) from days since the Unix epoch (Howard Hinnant's
/// civil_from_days).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Current UTC time as (`2026-07-22T15:30:00Z`, `20260722-153000`).
fn utc_now_strings() -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let tod = secs.rem_euclid(86_400);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    (
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"),
        format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}"),
    )
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

// --- Component enumeration ----------------------------------------------------

/// The real files a component covers right now:
/// `(absolute path, data-root-relative entry name with '/' separators)`.
/// Missing optional files are skipped.
fn component_files(data_root: &Path, component: &str) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut push_if_exists = |rel: &str| {
        let abs = join_rel(data_root, rel);
        if abs.is_file() {
            out.push((abs, rel.to_string()));
        }
    };
    match component {
        "keys" => {
            push_if_exists("private/users.json");
            push_if_exists("private/users_multi.json");
        }
        "config" => {
            push_if_exists("private/config.json");
        }
        "zites" => {
            push_if_exists("private/sites.json");
            push_if_exists("private/permissions.json");
            push_if_exists("private/filters.json");
            for addr in zite_addresses(data_root) {
                collect_files(&data_root.join("data").join(&addr), &format!("data/{addr}"), &mut out);
            }
        }
        _ => {}
    }
    out
}

/// The site addresses under `data/` (only valid `epix1…` bech32 dirs count -
/// anything else there is not zite content we can safely restore).
fn zite_addresses(data_root: &Path) -> Vec<String> {
    let mut addrs: Vec<String> = std::fs::read_dir(data_root.join("data"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| epix_crypt::is_valid_address(n))
                .collect()
        })
        .unwrap_or_default();
    addrs.sort();
    addrs
}

/// Recursively collect regular files under `dir` as `(abs, "<prefix>/rel")`
/// entries with forward slashes. Symlinks are skipped - a backup must never
/// follow a link out of the data dir.
fn collect_files(dir: &Path, prefix: &str, out: &mut Vec<(PathBuf, String)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        let Ok(name) = entry.file_name().into_string() else { continue };
        let rel = format!("{prefix}/{name}");
        if ft.is_symlink() {
            continue;
        } else if ft.is_dir() {
            collect_files(&path, &rel, out);
        } else if ft.is_file() {
            out.push((path, rel));
        }
    }
}

/// Join a relative entry name onto a base, segment by segment - never trusting
/// separators, and dropping any `.`/`..` segment outright so a hostile name
/// can't climb out even if it slipped past an earlier check.
fn join_rel(base: &Path, rel: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for seg in rel.split('/').filter(|s| !s.is_empty() && *s != "." && *s != "..") {
        p.push(seg);
    }
    p
}

/// Whether a zip entry name is safe and expected: relative, forward slashes
/// only, no `..`/empty segments, and within the whitelist - either a file
/// listed in the manifest's selected components or under a listed site's
/// `data/<address>/` tree.
fn entry_allowed(name: &str, allowed_files: &[String], allowed_sites: &[String]) -> bool {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return false;
    }
    if allowed_files.iter().any(|f| f == name) {
        return true;
    }
    allowed_sites.iter().any(|addr| {
        epix_crypt::is_valid_address(addr)
            && name.strip_prefix(&format!("data/{addr}/")).is_some_and(|rest| !rest.is_empty())
    })
}

/// A backup file name as accepted from a form: must look exactly like a name
/// we generate and exist in `backups/` (no separators, no traversal).
fn safe_backup_name(data_root: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || !name.ends_with(".zip")
    {
        return None;
    }
    let path = data_root.join(BACKUPS_DIR).join(name);
    path.is_file().then_some(path)
}

// --- Create -------------------------------------------------------------------

/// Create a backup archive of `components` under `<data_root>/backups/`.
/// Returns the archive file name. Blocking - run on a blocking thread.
pub fn create_backup(
    data_root: &Path,
    components: &[String],
    password: Option<&str>,
    app_version: &str,
    name_prefix: &str,
) -> Result<String, String> {
    let (iso, compact) = utc_now_strings();
    let mut manifest = Manifest {
        format_version: SUPPORTED_BACKUP_FORMAT,
        app: "epixnet".to_string(),
        app_version: app_version.to_string(),
        created: iso,
        encrypted: password.is_some(),
        components: BTreeMap::new(),
    };
    let mut all_files: Vec<(PathBuf, String)> = Vec::new();
    for comp in COMPONENTS {
        if !components.iter().any(|c| c == comp) {
            continue;
        }
        let files = component_files(data_root, comp);
        let entry = ComponentEntry {
            files: files
                .iter()
                .map(|(_, rel)| rel.clone())
                .filter(|rel| !rel.starts_with("data/"))
                .collect(),
            sites: if *comp == "zites" { zite_addresses(data_root) } else { Vec::new() },
        };
        manifest.components.insert(comp.to_string(), entry);
        all_files.extend(files);
    }
    if manifest.components.is_empty() {
        return Err("Select at least one thing to back up".to_string());
    }
    if all_files.is_empty() {
        return Err("Nothing to back up yet for the selected items".to_string());
    }

    let backups = data_root.join(BACKUPS_DIR);
    std::fs::create_dir_all(&backups).map_err(|e| format!("Could not create {}: {e}", backups.display()))?;
    // Pick a free file name (a second backup within the same second gets -2).
    let mut file_name = format!("{name_prefix}-{compact}.zip");
    let mut n = 1;
    while backups.join(&file_name).exists() {
        n += 1;
        file_name = format!("{name_prefix}-{compact}-{n}.zip");
    }
    let part = backups.join(format!(".{file_name}.part"));
    let result = write_archive(&part, &manifest, &all_files, password);
    match result {
        Ok(()) => {
            std::fs::rename(&part, backups.join(&file_name))
                .map_err(|e| format!("Could not finish the backup file: {e}"))?;
            Ok(file_name)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            Err(e)
        }
    }
}

fn write_archive(
    path: &Path,
    manifest: &Manifest,
    files: &[(PathBuf, String)],
    password: Option<&str>,
) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| format!("Could not create the backup file: {e}"))?;
    let mut zip = zip::ZipWriter::new(std::io::BufWriter::new(file));
    let plain = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    // The manifest stays unencrypted so the page can list an encrypted backup's
    // contents without the password (zip already exposes entry names anyway).
    zip.start_file("manifest.json", plain).map_err(|e| e.to_string())?;
    let manifest_bytes = serde_json::to_vec_pretty(manifest).map_err(|e| e.to_string())?;
    zip.write_all(&manifest_bytes).map_err(|e| e.to_string())?;
    for (abs, rel) in files {
        let mut opts = plain.large_file(true);
        if let Some(pwd) = password {
            opts = opts.with_aes_encryption(zip::AesMode::Aes256, pwd);
        }
        zip.start_file(rel.as_str(), opts).map_err(|e| e.to_string())?;
        let mut f = std::fs::File::open(abs)
            .map_err(|e| format!("Could not read {}: {e}", abs.display()))?;
        std::io::copy(&mut f, &mut zip).map_err(|e| format!("Could not pack {rel}: {e}"))?;
    }
    zip.finish().map_err(|e| e.to_string())?;
    Ok(())
}

// --- List / read --------------------------------------------------------------

/// The stored backups, newest first (by file name, which starts with the
/// timestamp for our generated names).
pub fn list_backups(data_root: &Path) -> Vec<BackupInfo> {
    let mut out: Vec<BackupInfo> = std::fs::read_dir(data_root.join(BACKUPS_DIR))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name.ends_with(".zip") && !name.starts_with('.')
                })
                .filter_map(|e| {
                    let file_name = e.file_name().into_string().ok()?;
                    let size = e.metadata().ok()?.len();
                    let manifest = read_manifest(&e.path()).ok();
                    Some(BackupInfo { file_name, size, manifest })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| {
        let key = |i: &BackupInfo| {
            i.manifest.as_ref().map(|m| m.created.clone()).unwrap_or_default()
        };
        key(b).cmp(&key(a)).then_with(|| b.file_name.cmp(&a.file_name))
    });
    out
}

/// Read and validate an archive's manifest (works without the password - the
/// manifest entry is never encrypted).
pub fn read_manifest(path: &Path) -> Result<Manifest, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|_| "Not a valid backup archive".to_string())?;
    let entry = zip
        .by_name("manifest.json")
        .map_err(|_| "Not an EpixNet backup (no manifest.json)".to_string())?;
    let mut bytes = Vec::new();
    // The manifest is small; cap the read so a hostile archive can't balloon.
    entry
        .take(1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let manifest: Manifest =
        serde_json::from_slice(&bytes).map_err(|_| "Unreadable backup manifest".to_string())?;
    if manifest.app != "epixnet" {
        return Err("Not an EpixNet backup".to_string());
    }
    Ok(manifest)
}

// --- Restore ------------------------------------------------------------------

/// What `apply_pending_restore` finds in `restore-pending/apply.json`. Written
/// last during staging, so its presence means the staging completed.
#[derive(Serialize, Deserialize)]
struct ApplyPlan {
    source: String,
    components: Vec<String>,
    /// Staged data-root-relative files to move into place.
    files: Vec<String>,
    /// `data/<address>` directories to replace wholesale (delete then move).
    replace_dirs: Vec<String>,
}

/// Stage a restore: verify + decrypt the selected components out of `backup`
/// into `<data_root>/restore-pending/`, to be applied on the next start.
/// Writes an automatic safety backup of the same components first. Blocking.
pub fn stage_restore(
    data_root: &Path,
    backup_path: &Path,
    components: &[String],
    password: Option<&str>,
    app_version: &str,
) -> Result<(), String> {
    let manifest = read_manifest(backup_path)?;
    if manifest.format_version > SUPPORTED_BACKUP_FORMAT {
        return Err(format!(
            "This backup was created by a newer EpixNet (format {}). Update EpixNet to restore it.",
            manifest.format_version
        ));
    }
    if manifest.encrypted && password.map(str::is_empty).unwrap_or(true) {
        return Err("This backup is encrypted - enter its password".to_string());
    }
    let selected: Vec<String> = components
        .iter()
        .filter(|c| manifest.components.contains_key(*c))
        .cloned()
        .collect();
    if selected.is_empty() {
        return Err("Select at least one thing to restore".to_string());
    }

    let allowed_files: Vec<String> = selected
        .iter()
        .filter_map(|c| manifest.components.get(c))
        .flat_map(|e| e.files.iter().cloned())
        .collect();
    let allowed_sites: Vec<String> = if selected.iter().any(|c| c == "zites") {
        manifest.components.get("zites").map(|e| e.sites.clone()).unwrap_or_default()
    } else {
        Vec::new()
    };

    let pending = data_root.join(PENDING_DIR);
    // A previous staging (crashed or superseded) is discarded.
    let _ = std::fs::remove_dir_all(&pending);
    std::fs::create_dir_all(&pending).map_err(|e| e.to_string())?;

    let stage = (|| -> Result<ApplyPlan, String> {
        let file = std::fs::File::open(backup_path).map_err(|e| e.to_string())?;
        let mut zip = zip::ZipArchive::new(std::io::BufReader::new(file))
            .map_err(|_| "Not a valid backup archive".to_string())?;
        let names: Vec<String> = zip.file_names().map(str::to_string).collect();
        let mut staged_files = Vec::new();
        for name in names {
            if name == "manifest.json" || !entry_allowed(&name, &allowed_files, &allowed_sites) {
                continue;
            }
            let mut entry = match password {
                Some(pwd) => zip.by_name_decrypt(&name, pwd.as_bytes()),
                None => zip.by_name(&name),
            }
            .map_err(|e| match e {
                zip::result::ZipError::InvalidPassword => "Wrong password".to_string(),
                e => format!("Could not read {name} from the backup: {e}"),
            })?;
            if entry.is_dir() || entry.is_symlink() {
                continue;
            }
            // Belt and braces on top of entry_allowed.
            if entry.enclosed_name().is_none() {
                return Err(format!("Unsafe path in backup: {name}"));
            }
            let target = join_rel(&pending, &name);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let mut out = std::fs::File::create(&target).map_err(|e| e.to_string())?;
            std::io::copy(&mut entry, &mut out).map_err(|e| {
                // A wrong AES password usually surfaces here as a failed
                // authentication / corrupt stream error.
                if manifest.encrypted {
                    "Wrong password or corrupted backup".to_string()
                } else {
                    format!("Could not unpack {name}: {e}")
                }
            })?;
            staged_files.push(name);
        }
        if staged_files.is_empty() {
            return Err("The backup holds nothing for the selected items".to_string());
        }
        let replace_dirs = allowed_sites
            .iter()
            .filter(|addr| staged_files.iter().any(|f| f.starts_with(&format!("data/{addr}/"))))
            .map(|addr| format!("data/{addr}"))
            .collect();
        Ok(ApplyPlan {
            source: backup_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            components: selected.clone(),
            files: staged_files,
            replace_dirs,
        })
    })();

    match stage {
        Ok(plan) => {
            // Safety net, made only once the archive proved restorable (a wrong
            // password must not litter the list with safety copies): snapshot
            // the node's current versions of what the restart will overwrite,
            // so a mistaken restore is recoverable from the same page.
            let has_current =
                selected.iter().any(|c| !component_files(data_root, c).is_empty());
            if has_current {
                if let Err(e) = create_backup(data_root, &selected, None, app_version, "pre-restore")
                {
                    let _ = std::fs::remove_dir_all(&pending);
                    return Err(format!("Could not create the safety backup: {e}"));
                }
            }
            let bytes = serde_json::to_vec_pretty(&plan).map_err(|e| e.to_string())?;
            // Written last: its presence marks the staging as complete.
            std::fs::write(pending.join("apply.json"), bytes).map_err(|e| e.to_string())?;
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&pending);
            Err(e)
        }
    }
}

/// Whether a completed staged restore is waiting for a restart.
pub fn restore_pending(data_root: &Path) -> Option<String> {
    let plan = std::fs::read(data_root.join(PENDING_DIR).join("apply.json")).ok()?;
    let plan: ApplyPlan = serde_json::from_slice(&plan).ok()?;
    Some(plan.source)
}

/// Discard a staged restore.
pub fn cancel_pending_restore(data_root: &Path) {
    let _ = std::fs::remove_dir_all(data_root.join(PENDING_DIR));
}

/// Apply a staged restore. Called at boot, before anything reads the data dir.
/// A `restore-pending/` without `apply.json` is a crashed staging and is just
/// cleaned up.
pub fn apply_pending_restore(data_root: &Path) {
    let pending = data_root.join(PENDING_DIR);
    if !pending.exists() {
        return;
    }
    let plan: Option<ApplyPlan> = std::fs::read(pending.join("apply.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let Some(plan) = plan else {
        eprintln!("[WARN] Discarding an incomplete staged restore at {}", pending.display());
        let _ = std::fs::remove_dir_all(&pending);
        return;
    };
    // Replaced site trees go away first, so a restored site holds exactly the
    // backup's files (no stale leftovers merged in).
    for rel in &plan.replace_dirs {
        let dir = join_rel(data_root, rel);
        if dir.starts_with(data_root) {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    let mut errors = 0;
    for rel in &plan.files {
        let from = join_rel(&pending, rel);
        let to = join_rel(data_root, rel);
        if let Some(parent) = to.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Windows can't rename over an existing file.
        let _ = std::fs::remove_file(&to);
        if std::fs::rename(&from, &to).is_err() {
            // Cross-device staging (unusual, but possible with a symlinked
            // data dir): fall back to copy.
            if std::fs::copy(&from, &to).is_err() {
                errors += 1;
                eprintln!("[ERROR] Restore could not place {}", to.display());
            }
        }
    }
    let _ = std::fs::remove_dir_all(&pending);
    if errors == 0 {
        eprintln!(
            "[INFO] Restored {} item(s) from backup {} ({})",
            plan.files.len(),
            plan.source,
            plan.components.join(", ")
        );
    } else {
        eprintln!(
            "[ERROR] Restore from {} finished with {errors} error(s); check the data dir",
            plan.source
        );
    }
}

// --- CSRF ---------------------------------------------------------------------

/// A per-boot CSRF token for the /Backup forms. A foreign page can make the
/// browser POST here (navigation is allowed through the cross-origin gate),
/// but it cannot read this page to learn the token; a xite iframe can't fetch
/// the page either (the gate blocks /Backup for non-navigation requests).
fn csrf_token() -> &'static str {
    static TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TOKEN.get_or_init(|| {
        let mut bytes = [0u8; 32];
        let _ = getrandom::fill(&mut bytes);
        hex::encode(bytes)
    })
}

// --- HTTP handlers ------------------------------------------------------------

use crate::Ctx;

/// The gates shared by every /Backup route: the page can be disabled like the
/// other admin pages, and never exists on a restricted/read-only node - a
/// public gateway visitor must not be able to download the operator's keys.
async fn backup_gate(state: &AppState) -> Result<PathBuf, Response> {
    if !state.plugin_enabled("UiBackup").await {
        return Err(
            (StatusCode::FORBIDDEN, "The backup page is disabled on this node").into_response()
        );
    }
    if state.ui_restrict().await || state.no_new_sites().await {
        return Err((
            StatusCode::FORBIDDEN,
            "Backup & restore is not available on a restricted node",
        )
            .into_response());
    }
    state.data_root_path().ok_or_else(|| {
        (StatusCode::FORBIDDEN, "This node keeps no data on disk").into_response()
    })
}

fn check_csrf(form: &std::collections::HashMap<String, String>) -> Result<(), Response> {
    if form.get("csrf").map(String::as_str) == Some(csrf_token()) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "Invalid or missing form token - reload the page").into_response())
    }
}

fn flash_redirect(ok: bool, msg: &str) -> Response {
    flash_redirect_tab("backup", ok, msg)
}

/// Redirect back to one of the page's tabs with a flash message.
fn flash_redirect_tab(tab: &str, ok: bool, msg: &str) -> Response {
    let kind = if ok { "done" } else { "error" };
    let tab_q = if tab == "restore" { "tab=restore&" } else { "" };
    Redirect::to(&format!("/Backup?{tab_q}{kind}={}", crate::url_encode(msg))).into_response()
}

/// `GET /Backup` - the wizard page; `?restore=<name>` shows the restore step.
pub(crate) async fn serve_backup_page(
    State(ctx): State<Ctx>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let data_root = match backup_gate(&ctx.state).await {
        Ok(root) => root,
        Err(resp) => return resp,
    };
    let theme = ctx.state.theme_class().await;
    let homepage = ctx.state.homepage().await.unwrap_or_default();
    let flash = if let Some(msg) = params.get("done") {
        Some((true, msg.clone()))
    } else {
        params.get("error").map(|msg| (false, msg.clone()))
    };
    let root = data_root.clone();
    if let Some(name) = params.get("restore").cloned() {
        // The restore step for one archive.
        let manifest = tokio::task::spawn_blocking(move || {
            safe_backup_name(&root, &name)
                .ok_or_else(|| "No such backup".to_string())
                .and_then(|p| read_manifest(&p))
                .map(|m| (name, m))
        })
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
        return match manifest {
            Ok((name, manifest)) => (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                render_restore_page(&name, &manifest, flash, &homepage, &theme),
            )
                .into_response(),
            Err(e) => flash_redirect(false, &e),
        };
    }
    let (backups, pending) =
        tokio::task::spawn_blocking(move || (list_backups(&root), restore_pending(&root)))
            .await
            .unwrap_or((Vec::new(), None));
    let can_restart = ctx.state.can_restart();
    let tab = match params.get("tab").map(String::as_str) {
        Some("restore") => "restore",
        _ => "backup",
    };
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        render_backup_page(tab, &backups, pending.as_deref(), can_restart, flash, &homepage, &theme),
    )
        .into_response()
}

/// `POST /Backup` - the form actions: create / delete / restore / restart /
/// cancel_restore.
pub(crate) async fn backup_post(
    State(ctx): State<Ctx>,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let data_root = match backup_gate(&ctx.state).await {
        Ok(root) => root,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_csrf(&form) {
        return resp;
    }
    let action = form.get("action").map(String::as_str).unwrap_or("");
    match action {
        "create" => {
            let components = selected_components(&form);
            let password = form.get("password").map(String::as_str).unwrap_or("");
            let confirm = form.get("password2").map(String::as_str).unwrap_or("");
            if !password.is_empty() {
                if password.len() < 8 {
                    return flash_redirect(false, "The backup password must be at least 8 characters");
                }
                if password != confirm {
                    return flash_redirect(false, "The passwords do not match");
                }
            }
            let password = (!password.is_empty()).then(|| password.to_string());
            let version = ctx.state.version.clone();
            let result = tokio::task::spawn_blocking(move || {
                create_backup(&data_root, &components, password.as_deref(), &version, "epix-backup")
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
            match result {
                Ok(name) => flash_redirect(true, &format!("Backup created: {name}")),
                Err(e) => flash_redirect(false, &e),
            }
        }
        "delete" => {
            let name = form.get("name").cloned().unwrap_or_default();
            let result = tokio::task::spawn_blocking(move || {
                let path = safe_backup_name(&data_root, &name).ok_or("No such backup")?;
                std::fs::remove_file(&path).map_err(|e| format!("Could not delete: {e}"))?;
                Ok::<String, String>(name)
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
            match result {
                Ok(name) => flash_redirect(true, &format!("Deleted {name}")),
                Err(e) => flash_redirect(false, &e),
            }
        }
        "restore" => {
            let name = form.get("name").cloned().unwrap_or_default();
            let components = selected_components(&form);
            let password = form.get("password").cloned().filter(|p| !p.is_empty());
            let version = ctx.state.version.clone();
            let name_q = name.clone();
            let result = tokio::task::spawn_blocking(move || {
                let path = safe_backup_name(&data_root, &name).ok_or("No such backup")?;
                stage_restore(&data_root, &path, &components, password.as_deref(), &version)
            })
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
            match result {
                Ok(()) => Redirect::to("/Backup?staged=1").into_response(),
                Err(e) => Redirect::to(&format!(
                    "/Backup?restore={}&error={}",
                    crate::url_encode(&name_q),
                    crate::url_encode(&e)
                ))
                .into_response(),
            }
        }
        "cancel_restore" => {
            cancel_pending_restore(&data_root);
            flash_redirect_tab("restore", true, "Staged restore discarded")
        }
        "restart" => {
            ctx.state.push_notification("info", "Restarting...", 5000);
            ctx.state.shutdown(true).await;
            let theme = ctx.state.theme_class().await;
            ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], render_restarting_page(&theme))
                .into_response()
        }
        _ => Redirect::to("/Backup").into_response(),
    }
}

fn selected_components(form: &std::collections::HashMap<String, String>) -> Vec<String> {
    COMPONENTS
        .iter()
        .filter(|c| {
            form.get(&format!("comp_{c}")).map(|v| v == "on" || v == "true").unwrap_or(false)
        })
        .map(|c| c.to_string())
        .collect()
}

/// `POST /Backup/Download` - send a stored backup as a browser download. Works
/// from a remote browser too: the bytes ride the same HTTP connection as the
/// UI. A POST (not GET) so the CSRF token never lands in a URL or history.
pub(crate) async fn backup_download(
    State(ctx): State<Ctx>,
    axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let data_root = match backup_gate(&ctx.state).await {
        Ok(root) => root,
        Err(resp) => return resp,
    };
    if let Err(resp) = check_csrf(&form) {
        return resp;
    }
    let name = form.get("name").cloned().unwrap_or_default();
    let Some(path) = safe_backup_name(&data_root, &name) else {
        return (StatusCode::NOT_FOUND, "No such backup").into_response();
    };
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => return (StatusCode::NOT_FOUND, format!("Could not open the backup: {e}")).into_response(),
    };
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    let stream = tokio_util::io::ReaderStream::new(file);
    let mut resp = axum::body::Body::from_stream(stream).into_response();
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, "application/zip".parse().unwrap());
    headers.insert(header::CONTENT_LENGTH, len.into());
    if let Ok(v) = format!("attachment; filename=\"{name}\"").parse() {
        headers.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

/// `POST /Backup/Upload?csrf=<token>` - receive a backup archive from the
/// browser (multipart form), validate it, and store it under `backups/` so it
/// can be restored like a local one. The token rides the query because the
/// body is the multipart stream.
pub(crate) async fn backup_upload(
    State(ctx): State<Ctx>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    mut multipart: axum::extract::Multipart,
) -> Response {
    let data_root = match backup_gate(&ctx.state).await {
        Ok(root) => root,
        Err(resp) => return resp,
    };
    if params.get("csrf").map(String::as_str) != Some(csrf_token()) {
        return (StatusCode::FORBIDDEN, "Invalid or missing form token - reload the page").into_response();
    }
    let backups = data_root.join(BACKUPS_DIR);
    if let Err(e) = tokio::fs::create_dir_all(&backups).await {
        return flash_redirect_tab("restore", false, &format!("Could not create the backups folder: {e}"));
    }
    let (_, compact) = utc_now_strings();
    let part_path = backups.join(format!(".incoming-{compact}.part"));

    // Stream the file field to disk (a zites backup can be huge).
    let mut wrote = false;
    while let Ok(Some(mut field)) = multipart.next_field().await {
        if field.name() != Some("file") {
            continue;
        }
        let mut out = match tokio::fs::File::create(&part_path).await {
            Ok(f) => f,
            Err(e) => return flash_redirect_tab("restore", false, &format!("Could not store the upload: {e}")),
        };
        use tokio::io::AsyncWriteExt;
        loop {
            match field.chunk().await {
                Ok(Some(chunk)) => {
                    if let Err(e) = out.write_all(&chunk).await {
                        let _ = tokio::fs::remove_file(&part_path).await;
                        return flash_redirect_tab("restore", false, &format!("Could not store the upload: {e}"));
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&part_path).await;
                    return flash_redirect_tab("restore", false, &format!("Upload failed: {e}"));
                }
            }
        }
        let _ = out.flush().await;
        wrote = true;
        break;
    }
    if !wrote {
        let _ = tokio::fs::remove_file(&part_path).await;
        return flash_redirect_tab("restore", false, "No file received");
    }

    // Validate before accepting: it must be a zip with a readable EpixNet
    // manifest (this also rejects wild non-backup zips early).
    let part = part_path.clone();
    let checked = tokio::task::spawn_blocking(move || read_manifest(&part))
        .await
        .unwrap_or_else(|e| Err(e.to_string()));
    if let Err(e) = checked {
        let _ = tokio::fs::remove_file(&part_path).await;
        return flash_redirect_tab("restore", false, &format!("Not a usable backup: {e}"));
    }
    let mut final_name = format!("uploaded-{compact}.zip");
    let mut n = 1;
    while backups.join(&final_name).exists() {
        n += 1;
        final_name = format!("uploaded-{compact}-{n}.zip");
    }
    if let Err(e) = tokio::fs::rename(&part_path, backups.join(&final_name)).await {
        let _ = tokio::fs::remove_file(&part_path).await;
        return flash_redirect_tab("restore", false, &format!("Could not store the upload: {e}"));
    }
    flash_redirect_tab("restore", true, &format!("Uploaded {final_name} - pick Restore next to it"))
}

// --- Rendering ----------------------------------------------------------------

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Page-specific styles on top of the shared PAGE_CSS tokens.
const BACKUP_CSS: &str = "<style>\
.tabs{display:flex;gap:28px;border-bottom:1px solid var(--epix-border);margin:0 0 20px}\
.tab{display:inline-block;padding:10px 2px 12px;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--epix-text-mid);text-decoration:none;border-bottom:2px solid transparent;margin-bottom:-1px}\
.tab:hover{color:var(--epix-text)}\
.tab.active{color:var(--epix-accent);border-bottom-color:var(--epix-accent)}\
.backup-row{position:relative;padding:14px 0;border-bottom:1px solid var(--epix-border)}\
.backup-row .title h3{font-size:14px;font-weight:600;margin:0;line-height:1.4;font-family:var(--epix-font-mono);overflow-wrap:anywhere}\
.backup-row .description{font-size:13px;color:var(--epix-text-mid);margin-top:2px}\
.backup-actions{margin-top:8px;display:flex;gap:14px;flex-wrap:wrap;align-items:center}\
.backup-actions form{display:inline}\
.linkbtn{background:none;border:none;padding:6px 0;font:inherit;font-size:13px;font-weight:600;color:var(--epix-link);cursor:pointer;text-decoration:none}\
.linkbtn:hover{text-decoration:underline}\
.linkbtn.danger{color:#F0224B}\
.badge{display:inline-block;font-size:11px;font-weight:600;border:1px solid var(--epix-border-strong);border-radius:5px;padding:1px 7px;margin-left:6px;color:var(--epix-text-mid);vertical-align:1px}\
.pw-row{display:flex;gap:12px;flex-wrap:wrap;margin-top:8px}\
.pw-row .input-text{flex:1;min-width:180px;width:auto}\
.warn-box{padding:12px 16px;border-radius:8px;margin:20px 0;font-size:14px;background:var(--epix-danger-soft);color:var(--epix-ink-soft)}\
.summary{font-size:13px;color:var(--epix-text-mid);margin:0 0 4px}\
.summary b{color:var(--epix-text)}\
.upload-row{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-top:12px}\
.upload-row input[type=file]{font-size:13px;color:var(--epix-text-mid);max-width:100%}\
.upload-row .button{margin-top:0;height:38px;padding:0 18px;font-size:14px}\
.create-btn{margin-top:20px}\
</style>";

const BACKUP_PAGE_JS: &str = "<script>(function(){\
var all=document.getElementById('comp-all');\
var comps=Array.prototype.slice.call(document.querySelectorAll('input[data-comp]'));\
if(all){\
function sync(){all.checked=comps.every(function(c){return c.checked;});}\
all.addEventListener('change',function(){comps.forEach(function(c){c.checked=all.checked;});});\
comps.forEach(function(c){c.addEventListener('change',sync);});\
sync();\
}\
var form=document.getElementById('create-form');\
if(form){form.addEventListener('submit',function(){\
var b=document.getElementById('create-btn');\
if(b){b.disabled=true;b.textContent='Creating backup\\u2026 this can take a while';}\
});}\
})();</script>";

fn component_checkbox_row(comp: &str, checked: bool) -> String {
    format!(
        "<div class='plugin'>\
           <div class='title'><h3>{label}</h3>\
             <div class='description'>{descr}</div></div>\
           <label class='value value-right checkbox'>\
             <input type='checkbox' name='comp_{comp}' data-comp='{comp}' {checked}/>\
             <div class='checkbox-skin'></div></label>\
         </div>",
        label = esc(component_label(comp)),
        descr = esc(component_description(comp)),
        checked = if checked { "checked" } else { "" },
    )
}

/// The BACKUP | RESTORE tab bar; `active` is "backup" or "restore".
fn tab_bar(active: &str) -> String {
    let cls = |tab: &str| if tab == active { "tab active" } else { "tab" };
    format!(
        "<div class='tabs'>\
           <a class='{b}' href='/Backup'>Backup</a>\
           <a class='{r}' href='/Backup?tab=restore'>Restore</a>\
         </div>",
        b = cls("backup"),
        r = cls("restore"),
    )
}

fn flash_html(flash: &Option<(bool, String)>) -> String {
    match flash {
        Some((ok, msg)) => format!(
            "<div class='notification notification-{kind}'>{msg}</div>",
            kind = if *ok { "done" } else { "error" },
            msg = esc(msg),
        ),
        None => String::new(),
    }
}

fn manifest_summary(info: &Manifest) -> String {
    let comps: Vec<&str> =
        info.components.keys().map(|k| component_label(k)).collect();
    let lock = if info.encrypted { " \u{1F512}" } else { "" };
    format!(
        "{created} \u{2022} {comps}{lock} \u{2022} EpixNet {version}",
        created = esc(&info.created.replace('T', " ").replace('Z', " UTC")),
        comps = esc(&comps.join(", ")),
        version = esc(&info.app_version),
    )
}

fn render_backup_page(
    tab: &str,
    backups: &[BackupInfo],
    pending_from: Option<&str>,
    can_restart: bool,
    flash: Option<(bool, String)>,
    homepage: &str,
    theme: &str,
) -> String {
    let csrf = csrf_token();
    let mut body = String::new();
    body.push_str(BACKUP_CSS);
    body.push_str(&tab_bar(tab));
    body.push_str(&flash_html(&flash));
    if tab == "restore" {
        render_restore_tab(&mut body, backups, csrf);
    } else {
        render_create_tab(&mut body, backups, csrf);
    }
    body.push_str(&pending_bar(pending_from, can_restart, csrf));
    body.push_str(BACKUP_PAGE_JS);
    crate::page_shell(
        "Backup & Restore",
        "Backup &amp; Restore",
        "Back up your keys, settings, and zites - and restore them here or on another device.",
        &body,
        homepage,
        theme,
    )
}

/// The BACKUP tab: the stored-backup list (download/delete) up top, then the
/// create form.
fn render_create_tab(body: &mut String, backups: &[BackupInfo], csrf: &str) {
    // Stored backups (managed here; restoring lives on the Restore tab).
    body.push_str("<h2 class='section-title'>Stored backups</h2>");
    if backups.is_empty() {
        body.push_str(
            "<div class='description' style='padding:12px 0'>No backups yet. \
             Create one below.</div>",
        );
    }
    for info in backups {
        let name = esc(&info.file_name);
        let detail = match &info.manifest {
            Some(m) => format!("{} \u{2022} {}", manifest_summary(m), human_size(info.size)),
            None => format!("Unreadable backup \u{2022} {}", human_size(info.size)),
        };
        let badge = backup_badge(&info.file_name);
        body.push_str(&format!(
            "<div class='backup-row'>\
               <div class='title'><h3>{name}{badge}</h3>\
                 <div class='description'>{detail}</div></div>\
               <div class='backup-actions'>\
                 <form method='post' action='/Backup/Download'>\
                   <input type='hidden' name='csrf' value='{csrf}'>\
                   <input type='hidden' name='name' value='{name}'>\
                   <button class='linkbtn' type='submit'>Download</button>\
                 </form>\
                 <form method='post' action='/Backup' \
                       onsubmit=\"return confirm('Delete this backup?')\">\
                   <input type='hidden' name='csrf' value='{csrf}'>\
                   <input type='hidden' name='action' value='delete'>\
                   <input type='hidden' name='name' value='{name}'>\
                   <button class='linkbtn danger' type='submit'>Delete</button>\
                 </form>\
               </div>\
             </div>",
        ));
    }

    // Create card.
    body.push_str(
        "<h2 class='section-title'>Create a backup</h2>\
         <form method='post' action='/Backup' id='create-form'>",
    );
    body.push_str(&format!(
        "<input type='hidden' name='csrf' value='{csrf}'>\
         <input type='hidden' name='action' value='create'>\
         <div class='config'>\
           <div class='plugin'>\
             <div class='title'><h3>Everything</h3>\
               <div class='description'>Keys, node settings, and all zites in one archive.</div></div>\
             <label class='value value-right checkbox'>\
               <input type='checkbox' id='comp-all' checked/>\
               <div class='checkbox-skin'></div></label>\
           </div>"
    ));
    for comp in COMPONENTS {
        body.push_str(&component_checkbox_row(comp, true));
    }
    body.push_str(&format!(
        "</div>\
         <div class='config-item'>\
           <div class='title'><h3>Password <span class='default'>(optional)</span></h3>\
             <div class='description'>Encrypts the backup contents (AES-256). Keep the password safe - \
              without it the backup cannot be restored. File names inside the archive stay visible.</div></div>\
           <div class='pw-row'>\
             <input class='input-text' type='password' name='password' minlength='8' \
                    placeholder='Password' autocomplete='new-password'>\
             <input class='input-text' type='password' name='password2' minlength='8' \
                    placeholder='Repeat password' autocomplete='new-password'>\
           </div>\
         </div>\
         <button class='button button-submit create-btn' id='create-btn' type='submit'>Create backup</button>\
         <div class='description' style='margin-top:8px'>The backup is saved on this device, in the \
          <b>backups</b> folder of the data directory. Download it above to keep a copy somewhere safe.</div>\
         </form>"
    ));
}

/// The RESTORE tab: pick a stored backup to restore, or upload one.
fn render_restore_tab(body: &mut String, backups: &[BackupInfo], csrf: &str) {
    body.push_str("<h2 class='section-title'>Restore a stored backup</h2>");
    let restorable: Vec<&BackupInfo> = backups.iter().filter(|b| b.manifest.is_some()).collect();
    if restorable.is_empty() {
        body.push_str(
            "<div class='description' style='padding:12px 0'>No backups on this device yet. \
             Create one on the Backup tab, or upload one below.</div>",
        );
    }
    for info in restorable {
        let name = esc(&info.file_name);
        let detail = match &info.manifest {
            Some(m) => format!("{} \u{2022} {}", manifest_summary(m), human_size(info.size)),
            None => String::new(),
        };
        let badge = backup_badge(&info.file_name);
        body.push_str(&format!(
            "<div class='backup-row'>\
               <div class='title'><h3>{name}{badge}</h3>\
                 <div class='description'>{detail}</div></div>\
               <div class='backup-actions'>\
                 <a class='linkbtn' href='/Backup?restore={q}'>Restore</a>\
               </div>\
             </div>",
            q = crate::url_encode(&info.file_name),
        ));
    }

    body.push_str(&format!(
        "<h2 class='section-title'>Restore from another device</h2>\
         <div class='description'>Upload a backup file created on another device. \
          It appears in the list above, ready to restore.</div>\
         <form method='post' action='/Backup/Upload?csrf={csrf}' enctype='multipart/form-data'>\
           <div class='upload-row'>\
             <input type='file' name='file' accept='.zip,application/zip' required>\
             <button class='button' type='submit'>Upload backup</button>\
           </div>\
         </form>"
    ));
}

fn backup_badge(file_name: &str) -> &'static str {
    if file_name.starts_with("uploaded-") {
        "<span class='badge'>uploaded</span>"
    } else if file_name.starts_with("pre-restore-") {
        "<span class='badge'>safety copy</span>"
    } else {
        ""
    }
}

/// The fixed bottom bar shown while a staged restore waits for a restart.
fn pending_bar(pending_from: Option<&str>, can_restart: bool, csrf: &str) -> String {
    let mut body = String::new();
    if let Some(source) = pending_from {
        let (title, button) = if can_restart {
            (
                format!("A restore from {} is staged and applies on restart", esc(source)),
                format!(
                    "<form method='post' action='/Backup' style='display:inline'>\
                       <input type='hidden' name='csrf' value='{csrf}'>\
                       <input type='hidden' name='action' value='restart'>\
                       <button class='button button-submit' type='submit'>Restart EpixNet</button>\
                     </form>"
                ),
            )
        } else {
            (
                format!(
                    "A restore from {} is staged - close and reopen the app to apply it",
                    esc(source)
                ),
                String::new(),
            )
        };
        body.push_str(&format!(
            "<div class='bottom bottom-restart visible'>\
               <div class='bottom-content'>\
                 <div class='title'>{title} \u{2022} \
                   <form method='post' action='/Backup' style='display:inline'>\
                     <input type='hidden' name='csrf' value='{csrf}'>\
                     <input type='hidden' name='action' value='cancel_restore'>\
                     <button class='linkbtn' type='submit'>cancel</button>\
                   </form></div>\
                 {button}\
               </div>\
             </div>"
        ));
    }
    body
}

fn render_restore_page(
    name: &str,
    manifest: &Manifest,
    flash: Option<(bool, String)>,
    homepage: &str,
    theme: &str,
) -> String {
    let csrf = csrf_token();
    let mut body = String::new();
    body.push_str(BACKUP_CSS);
    body.push_str(&tab_bar("restore"));
    body.push_str(&flash_html(&flash));
    body.push_str(&format!(
        "<p class='summary'>Backup <b>{name}</b></p>\
         <p class='summary'>{summary}</p>",
        name = esc(name),
        summary = manifest_summary(manifest),
    ));
    if manifest.format_version > SUPPORTED_BACKUP_FORMAT {
        body.push_str(&format!(
            "<div class='warn-box'>This backup was created by a newer EpixNet \
             (format {}). Update EpixNet to restore it.</div>\
             <a class='button' href='/Backup?tab=restore'>Back</a>",
            manifest.format_version
        ));
        return crate::page_shell("Restore backup", "Restore backup", "", &body, homepage, theme);
    }
    body.push_str(&format!(
        "<form method='post' action='/Backup'>\
           <input type='hidden' name='csrf' value='{csrf}'>\
           <input type='hidden' name='action' value='restore'>\
           <input type='hidden' name='name' value='{name}'>\
           <h2 class='section-title'>What to restore</h2>\
           <div class='config'>",
        name = esc(name),
    ));
    for comp in COMPONENTS {
        let Some(entry) = manifest.components.get(*comp) else { continue };
        let extra = if *comp == "zites" && !entry.sites.is_empty() {
            format!(" This backup holds {} zite(s).", entry.sites.len())
        } else {
            String::new()
        };
        body.push_str(&format!(
            "<div class='plugin'>\
               <div class='title'><h3>{label}</h3>\
                 <div class='description'>{descr}{extra}</div></div>\
               <label class='value value-right checkbox'>\
                 <input type='checkbox' name='comp_{comp}' checked/>\
                 <div class='checkbox-skin'></div></label>\
             </div>",
            label = esc(component_label(comp)),
            descr = esc(component_description(comp)),
            extra = esc(&extra),
        ));
    }
    body.push_str("</div>");
    if manifest.encrypted {
        body.push_str(
            "<div class='config-item'>\
               <div class='title'><h3>Password</h3>\
                 <div class='description'>This backup is encrypted - enter the password it was created with.</div></div>\
               <div class='pw-row'>\
                 <input class='input-text' type='password' name='password' required \
                        placeholder='Backup password' autocomplete='off'>\
               </div>\
             </div>",
        );
    }
    body.push_str(
        "<div class='warn-box'><b>This overwrites the selected data on this node.</b> \
         A safety backup of the current data is created first, so you can undo from this page. \
         The restore applies after EpixNet restarts.</div>\
         <button class='button button-submit' type='submit'>Restore</button> \
         <a class='linkbtn' href='/Backup?tab=restore' style='margin-left:14px'>Cancel</a>\
         </form>",
    );
    crate::page_shell("Restore backup", "Restore backup", "", &body, homepage, theme)
}

/// The page shown after the restart button (mirrors the Config page's), polling
/// until the node answers again, then returning to /Backup.
fn render_restarting_page(theme: &str) -> String {
    let body = "<meta http-equiv='refresh' content='6;url=/Backup'>\
        <p class='sub'>EpixNet is restarting and applying the restore. This page returns to \
        Backup &amp; Restore when the node is back - if it does not, reload it manually.</p>\
        <script>(function(){\
        var tries=0;\
        var timer=setInterval(function(){\
        tries++;\
        if(tries<3){return;}\
        if(tries>60){clearInterval(timer);return;}\
        fetch('/Backup',{cache:'no-store'}).then(function(r){\
        if(r.ok){clearInterval(timer);location.replace('/Backup?done=Restore%20applied');}\
        }).catch(function(){});\
        },1000);\
        })();</script>";
    crate::page_shell("Restarting", "Restarting EpixNet", "", body, "", theme)
}

// --- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch data root with an identity, config, and one zite.
    fn scratch_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("private")).unwrap();
        std::fs::write(root.join("private/users.json"), b"{\"seed\":\"secret\"}").unwrap();
        std::fs::write(root.join("private/config.json"), b"{\"language\":\"en\"}").unwrap();
        std::fs::write(root.join("private/sites.json"), b"{}").unwrap();
        let addr = test_addr();
        let site = root.join("data").join(&addr);
        std::fs::create_dir_all(site.join("sub")).unwrap();
        std::fs::write(site.join("content.json"), b"{}").unwrap();
        std::fs::write(site.join("sub/index.html"), b"<html>").unwrap();
        // Stuff that must never end up in a backup:
        std::fs::create_dir_all(root.join("tor")).unwrap();
        std::fs::write(root.join("tor/state"), b"x").unwrap();
        std::fs::write(root.join("content.db"), b"db").unwrap();
        std::fs::create_dir_all(root.join("backups")).unwrap();
        std::fs::write(root.join("backups/old.zip"), b"not-a-zip").unwrap();
        dir
    }

    /// A syntactically valid epix1 address for tests.
    fn test_addr() -> String {
        let mut user = epix_user::User::generate();
        let (addr, _key) = user.generate_new_identity_address().unwrap();
        addr
    }

    fn all_components() -> Vec<String> {
        COMPONENTS.iter().map(|c| c.to_string()).collect()
    }

    #[test]
    fn create_list_roundtrip_and_exclusions() {
        let dir = scratch_root();
        let root = dir.path();
        let name = create_backup(root, &all_components(), None, "0.9", "epix-backup").unwrap();
        assert!(name.starts_with("epix-backup-") && name.ends_with(".zip"));

        let backups = list_backups(root);
        // old.zip is unreadable but listed; ours parses.
        let ours = backups.iter().find(|b| b.file_name == name).unwrap();
        let m = ours.manifest.as_ref().unwrap();
        assert_eq!(m.format_version, SUPPORTED_BACKUP_FORMAT);
        assert!(!m.encrypted);
        assert_eq!(m.components.len(), 3);
        assert_eq!(m.components["zites"].sites.len(), 1);

        // No caches, no backups dir, forward slashes only.
        let f = std::fs::File::open(root.join("backups").join(&name)).unwrap();
        let mut zip = zip::ZipArchive::new(f).unwrap();
        let names: Vec<String> = zip.file_names().map(str::to_string).collect();
        assert!(names.iter().all(|n| !n.contains('\\')));
        assert!(names.iter().all(|n| !n.starts_with("backups/")));
        assert!(names.iter().all(|n| !n.starts_with("tor/")));
        assert!(!names.iter().any(|n| n == "content.db"));
        assert!(names.iter().any(|n| n == "private/users.json"));
        assert!(names.iter().any(|n| n.starts_with("data/") && n.ends_with("sub/index.html")));
        // Manifest is entry 0 (readable first even when streaming).
        assert_eq!(zip.by_index(0).unwrap().name(), "manifest.json");
    }

    #[test]
    fn selective_backup_only_holds_selected() {
        let dir = scratch_root();
        let root = dir.path();
        let name =
            create_backup(root, &["keys".to_string()], None, "0.9", "epix-backup").unwrap();
        let f = std::fs::File::open(root.join("backups").join(&name)).unwrap();
        let zip = zip::ZipArchive::new(f).unwrap();
        let names: Vec<&str> = zip.file_names().collect();
        assert_eq!(names.len(), 2); // manifest + users.json
        assert!(names.contains(&"private/users.json"));
    }

    #[test]
    fn encrypted_roundtrip_and_wrong_password() {
        let dir = scratch_root();
        let root = dir.path();
        let name =
            create_backup(root, &all_components(), Some("hunter2hunter2"), "0.9", "epix-backup")
                .unwrap();
        let path = root.join("backups").join(&name);
        // Manifest readable without the password.
        let m = read_manifest(&path).unwrap();
        assert!(m.encrypted);

        // Wrong password: refused, nothing staged.
        let err = stage_restore(root, &path, &all_components(), Some("wrong-password"), "0.9")
            .unwrap_err();
        assert!(err.to_lowercase().contains("password"), "unexpected error: {err}");
        assert!(restore_pending(root).is_none());
        // A failed attempt must not leave a stray safety backup behind.
        assert!(!list_backups(root).iter().any(|b| b.file_name.starts_with("pre-restore-")));

        // Right password: staged.
        stage_restore(root, &path, &all_components(), Some("hunter2hunter2"), "0.9").unwrap();
        assert!(restore_pending(root).is_some());
        let staged = root.join(PENDING_DIR).join("private/users.json");
        assert_eq!(std::fs::read(staged).unwrap(), b"{\"seed\":\"secret\"}");
    }

    #[test]
    fn restore_missing_password_refused() {
        let dir = scratch_root();
        let root = dir.path();
        let name =
            create_backup(root, &all_components(), Some("hunter2hunter2"), "0.9", "epix-backup")
                .unwrap();
        let path = root.join("backups").join(&name);
        let err = stage_restore(root, &path, &all_components(), None, "0.9").unwrap_err();
        assert!(err.contains("encrypted"));
    }

    #[test]
    fn newer_format_refused() {
        let dir = scratch_root();
        let root = dir.path();
        let path = root.join("backups/future.zip");
        let f = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(f);
        zip.start_file("manifest.json", zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(
            format!(
                "{{\"format_version\":{},\"app\":\"epixnet\",\"app_version\":\"9.9\",\
                 \"created\":\"2099-01-01T00:00:00Z\",\"encrypted\":false,\"components\":{{}}}}",
                SUPPORTED_BACKUP_FORMAT + 1
            )
            .as_bytes(),
        )
        .unwrap();
        zip.finish().unwrap();
        let err = stage_restore(root, &path, &all_components(), None, "0.9").unwrap_err();
        assert!(err.contains("newer EpixNet"), "unexpected error: {err}");
    }

    #[test]
    fn malicious_entries_never_staged() {
        let dir = scratch_root();
        let root = dir.path();
        let addr = zite_addresses(root).remove(0);
        let path = root.join("backups/evil.zip");
        let f = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("manifest.json", opts).unwrap();
        zip.write_all(
            format!(
                "{{\"format_version\":1,\"app\":\"epixnet\",\"app_version\":\"0.9\",\
                 \"created\":\"2026-01-01T00:00:00Z\",\"encrypted\":false,\"components\":{{\
                 \"keys\":{{\"files\":[\"private/users.json\"]}},\
                 \"zites\":{{\"files\":[],\"sites\":[\"{addr}\"]}}}}}}"
            )
            .as_bytes(),
        )
        .unwrap();
        // Hostile entries: traversal, absolute, backslash, not-in-manifest.
        for name in [
            "../evil.txt",
            "/etc/evil",
            "private\\..\\evil",
            "private/other.json",
            &format!("data/{addr}/../../escape"),
        ] {
            zip.start_file(name.to_string(), opts).unwrap();
            zip.write_all(b"evil").unwrap();
        }
        // One legitimate entry so staging has something valid.
        zip.start_file("private/users.json", opts).unwrap();
        zip.write_all(b"{\"seed\":\"restored\"}").unwrap();
        zip.start_file(format!("data/{addr}/ok.txt"), opts).unwrap();
        zip.write_all(b"ok").unwrap();
        zip.finish().unwrap();

        stage_restore(root, &path, &all_components(), None, "0.9").unwrap();
        let pending = root.join(PENDING_DIR);
        // Only the whitelisted entries got staged; the hostile ones are absent
        // everywhere (and nothing escaped the staging dir).
        assert!(pending.join("private/users.json").is_file());
        assert!(pending.join(format!("data/{addr}/ok.txt")).is_file());
        assert!(!pending.join("private/other.json").exists());
        assert!(!root.join("evil.txt").exists());
        assert!(!dir.path().parent().unwrap().join("evil.txt").exists());
        assert!(!pending.join("escape").exists());
    }

    #[test]
    fn stage_and_apply_roundtrip() {
        let dir = scratch_root();
        let root = dir.path();
        let addr = zite_addresses(root).remove(0);
        let name = create_backup(root, &all_components(), None, "0.9", "epix-backup").unwrap();
        let path = root.join("backups").join(&name);

        // Simulate later local changes that the restore must roll back.
        std::fs::write(root.join("private/users.json"), b"{\"seed\":\"changed\"}").unwrap();
        std::fs::write(root.join("data").join(&addr).join("stale.txt"), b"stale").unwrap();

        stage_restore(root, &path, &all_components(), None, "0.9").unwrap();
        // A safety backup of the current state was written.
        assert!(list_backups(root).iter().any(|b| b.file_name.starts_with("pre-restore-")));

        apply_pending_restore(root);
        assert_eq!(
            std::fs::read(root.join("private/users.json")).unwrap(),
            b"{\"seed\":\"secret\"}"
        );
        // The zite dir was replaced wholesale: stale file gone, backup files in.
        assert!(!root.join("data").join(&addr).join("stale.txt").exists());
        assert!(root.join("data").join(&addr).join("sub/index.html").is_file());
        // Staging dir cleaned up.
        assert!(!root.join(PENDING_DIR).exists());
        assert!(restore_pending(root).is_none());
    }

    #[test]
    fn selective_restore_stages_only_selected() {
        let dir = scratch_root();
        let root = dir.path();
        let name = create_backup(root, &all_components(), None, "0.9", "epix-backup").unwrap();
        let path = root.join("backups").join(&name);
        stage_restore(root, &path, &["config".to_string()], None, "0.9").unwrap();
        let pending = root.join(PENDING_DIR);
        assert!(pending.join("private/config.json").is_file());
        assert!(!pending.join("private/users.json").exists());
        assert!(!pending.join("data").exists());
    }

    #[test]
    fn crashed_staging_cleaned_up() {
        let dir = scratch_root();
        let root = dir.path();
        // A staging dir with no apply.json = crashed mid-staging.
        std::fs::create_dir_all(root.join(PENDING_DIR).join("private")).unwrap();
        std::fs::write(root.join(PENDING_DIR).join("private/users.json"), b"half").unwrap();
        apply_pending_restore(root);
        assert!(!root.join(PENDING_DIR).exists());
        // The live users.json was not touched.
        assert_eq!(
            std::fs::read(root.join("private/users.json")).unwrap(),
            b"{\"seed\":\"secret\"}"
        );
    }

    #[test]
    fn backup_name_validation() {
        let dir = scratch_root();
        let root = dir.path();
        let name = create_backup(root, &["keys".to_string()], None, "0.9", "epix-backup").unwrap();
        assert!(safe_backup_name(root, &name).is_some());
        assert!(safe_backup_name(root, "../private/users.json").is_none());
        assert!(safe_backup_name(root, "nope.zip").is_none());
        assert!(safe_backup_name(root, "a/b.zip").is_none());
        assert!(safe_backup_name(root, "").is_none());
        assert!(safe_backup_name(root, "old.zip").is_some()); // exists, unreadable but deletable
    }

    #[test]
    fn entry_allowed_rules() {
        let addr = test_addr();
        let files = vec!["private/users.json".to_string()];
        let sites = vec![addr.clone()];
        assert!(entry_allowed("private/users.json", &files, &sites));
        assert!(entry_allowed(&format!("data/{addr}/x/y.txt"), &files, &sites));
        assert!(!entry_allowed("private/other.json", &files, &sites));
        assert!(!entry_allowed(&format!("data/{addr}/../x"), &files, &sites));
        assert!(!entry_allowed("data/notanaddress/x", &files, &sites));
        assert!(!entry_allowed("/private/users.json", &files, &sites));
        assert!(!entry_allowed("private\\users.json", &files, &sites));
        assert!(!entry_allowed(&format!("data/{addr}/"), &files, &sites));
        assert!(!entry_allowed("", &files, &sites));
    }
}
