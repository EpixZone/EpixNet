//! Native launch boundary for the fixed packaged Firefox extension adapter.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const MODULES: &[(&str, &[u8])] = &[
    (
        "distribution/epix-addon-installer/chrome.manifest",
        include_bytes!("../../../packaging/firefox-addons/chrome.manifest"),
    ),
    (
        "epix-addons.cfg",
        include_bytes!("../../../packaging/firefox-addons/epix-addons.cfg"),
    ),
    (
        "defaults/pref/epix-addons.js",
        include_bytes!("../../../packaging/firefox-addons/epix-addons.js"),
    ),
    (
        "distribution/epix-addon-installer/manager.sys.mjs",
        include_bytes!("../../../packaging/firefox-addons/manager.sys.mjs"),
    ),
    (
        "distribution/epix-addon-installer/policy.sys.mjs",
        include_bytes!("../../../packaging/firefox-addons/policy.sys.mjs"),
    ),
    (
        "distribution/epix-addon-installer/manager.xhtml",
        include_bytes!("../../../packaging/firefox-addons/manager.xhtml"),
    ),
    (
        "distribution/epix-addon-installer/manager.css",
        include_bytes!("../../../packaging/firefox-addons/manager.css"),
    ),
    (
        "distribution/epix-addon-installer/compatibility.json",
        include_bytes!("../../../packaging/firefox-addons/compatibility.json"),
    ),
];
const ARCHIVE_LIMIT: u64 = 32 * 1024 * 1024;

pub(crate) fn read_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect the link itself, never its target.
        options.custom_flags(0x0020_0000);
    }
    let handle = options
        .open(path)
        .map_err(|_| "Required extension-manager file is missing or linked.".to_string())?;
    let metadata = handle
        .metadata()
        .map_err(|_| "Could not inspect extension-manager file.".to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Linked extension-manager file is unsupported.".into());
        }
    }
    if !metadata.is_file() || metadata.len() > limit {
        return Err("Extension-manager file exceeds its limit.".into());
    }
    let mut bytes = Vec::new();
    handle
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Could not read extension-manager file.".to_string())?;
    if bytes.len() as u64 > limit {
        return Err("Extension-manager file grew beyond its limit.".into());
    }
    Ok(bytes)
}
fn resources(firefox: &Path) -> Result<PathBuf, String> {
    let parent = firefox
        .parent()
        .ok_or("Firefox has no resource directory.")?;
    #[cfg(target_os = "macos")]
    let parent = parent
        .parent()
        .ok_or("Firefox has no application resources.")?
        .join("Resources");
    Ok(parent.to_path_buf())
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| "Invalid extension ownership state.".into())
}
fn addon_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@._-{}".contains(&byte))
        && !value.to_ascii_lowercase().ends_with("@epix.zone")
        && !value.eq_ignore_ascii_case("zone.epix.nmh")
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn approved_candidate<'a>(
    profile: &Path,
    mirror: &'a Value,
    profile_id: &str,
) -> Result<Option<&'a Value>, String> {
    let Some(pending) = mirror.get("pending").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    if !matches!(
        pending.get("phase").and_then(Value::as_str),
        Some("HandedOff" | "Staged" | "NeedsReconciliation")
    ) {
        return Ok(None);
    }
    let Some(candidate) = pending.get("candidate").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    if text(pending, "operation_id")? != text(candidate, "operation_id")? {
        return Err("Native consent operation differs from the pending review.".into());
    }
    let path = profile.join("epix-addons/native-consent.json");
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Could not inspect native extension consent.".into()),
        Ok(_) => {}
    }
    let consent: Value = serde_json::from_slice(&read_regular(&path, 8192)?)
        .map_err(|_| "Invalid native extension consent.")?;
    if consent.get("protocol").and_then(Value::as_u64) != Some(1)
        || text(&consent, "profile_id")? != profile_id
    {
        return Err("Invalid native extension consent identity.".into());
    }
    if text(&consent, "operation_id")? != text(candidate, "operation_id")? {
        return Ok(None);
    }
    for field in ["addon_id", "version", "archive_sha256"] {
        if text(&consent, field)? != text(candidate, field)? {
            return Err("Native consent differs from the prepared extension.".into());
        }
    }
    Ok(Some(candidate))
}

fn directory(path: &Path, required: bool) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("Extension profile directory is missing.".into()),
        Ok(value) => value,
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Linked extension profile directories are unsupported.".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("Reparse extension profile directories are unsupported.".into());
        }
    }
    Ok(())
}

fn check_firefox_resources(firefox: &Path) -> Result<(), String> {
    let root = resources(firefox)?;
    for (relative, expected) in MODULES {
        if read_regular(&root.join(relative), expected.len() as u64)? != *expected {
            return Err("The trusted extension manager is missing or changed. Reinstall the current EpixNet release before opening this profile.".into());
        }
    }
    let ini = String::from_utf8(read_regular(&root.join("application.ini"), 65536)?)
        .map_err(|_| "Invalid Firefox version metadata.")?;
    let version = ini
        .lines()
        .find_map(|line| line.strip_prefix("Version="))
        .ok_or("Firefox version is unavailable.")?;
    let mut parts = version.trim().split('.');
    if parts.next() != Some("153")
        || parts
            .next()
            .and_then(|part| part.parse::<u32>().ok())
            .is_none_or(|minor| minor < 4)
    {
        return Err("This Firefox version is not supported by the trusted extension manager. Install the current EpixNet release.".into());
    }
    let channel = String::from_utf8(read_regular(
        &root.join("defaults/pref/channel-prefs.js"),
        65536,
    )?)
    .map_err(|_| "Invalid Firefox channel metadata.")?;
    let compact: String = channel.chars().filter(|ch| !ch.is_whitespace()).collect();
    if !compact.contains("pref(\"app.update.channel\",\"esr\")") {
        return Err(
            "The managed extension profile requires the supported Firefox ESR bundle.".into(),
        );
    }
    Ok(())
}

fn pending_archive_approval<'a>(
    mirror: &'a Value,
    native_approved: Option<&Value>,
    approved: &mut HashMap<&'a str, Vec<&'a str>>,
) -> Result<Option<(&'a str, &'a str)>, String> {
    let Some(pending) = mirror.get("pending").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    if !matches!(
        pending.get("phase").and_then(Value::as_str),
        Some("HandedOff" | "Staged" | "NeedsReconciliation" | "Installed")
    ) {
        return Ok(None);
    }
    let Some(candidate) = pending.get("candidate").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let id = text(candidate, "addon_id")?;
    let hash = text(candidate, "archive_sha256")?;
    if !addon_id(id) || !digest(hash) {
        return Err("Invalid approved extension receipt.".into());
    }
    approved.entry(id).or_default();
    if native_approved == Some(candidate) {
        approved.get_mut(id).unwrap().push(hash);
    }
    if native_approved == Some(candidate)
        && matches!(
            pending.get("phase").and_then(Value::as_str),
            Some("HandedOff" | "Staged" | "NeedsReconciliation")
        )
    {
        Ok(Some((id, hash)))
    } else {
        Ok(None)
    }
}

pub fn preflight(firefox: &Path, profile: &Path, profile_id: &str) -> Result<(), String> {
    directory(profile, true)?;
    directory(&profile.join("epix-addons"), true)?;
    directory(&profile.join("extensions"), false)?;
    directory(&profile.join("extensions/staged"), false)?;
    check_firefox_resources(firefox)?;
    let mirror: Value = serde_json::from_slice(&read_regular(
        &profile.join("epix-addons/mirror.json"),
        2 * 1024 * 1024,
    )?)
    .map_err(|_| "Invalid extension ownership state.")?;
    if mirror.get("protocol").and_then(Value::as_u64) != Some(1)
        || text(&mirror, "profile_id")? != profile_id
        || !digest(profile_id)
    {
        return Err("Extension ownership belongs to another browser profile.".into());
    }
    let owners = mirror
        .get("managed")
        .and_then(Value::as_array)
        .filter(|owners| owners.len() <= 256)
        .ok_or("Invalid managed extension list.")?;
    let native_approved = approved_candidate(profile, &mirror, profile_id)?;
    let mut approved = HashMap::<&str, Vec<&str>>::new();
    for owner in owners {
        let id = text(owner, "addon_id")?;
        let hash = text(owner, "archive_sha256")?;
        if !addon_id(id) || !digest(hash) || approved.contains_key(id) {
            return Err("Invalid managed extension identity.".into());
        }
        approved.insert(id, vec![hash]);
    }
    let staged_approval = pending_archive_approval(&mirror, native_approved, &mut approved)?;
    // Firefox can promote staged updates before public install listeners run.
    // Only exact durable approved archives may cross that startup boundary.
    for (id, hashes) in approved {
        let unpacked = profile.join("extensions").join(id);
        if std::fs::symlink_metadata(unpacked).is_ok() {
            return Err("Unpacked managed extensions are unsupported.".into());
        }
        for (staged, parent) in [
            (false, profile.join("extensions")),
            (true, profile.join("extensions/staged")),
        ] {
            let path = parent.join(format!("{id}.xpi"));
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err("Could not inspect managed extension archive.".into()),
                Ok(_) => {}
            }
            let bytes = read_regular(&path, ARCHIVE_LIMIT)?;
            let actual = sha256(&bytes);
            let allowed = if staged {
                staged_approval.is_some_and(|(pending_id, hash)| pending_id == id && hash == actual)
            } else {
                hashes.iter().any(|hash| *hash == actual)
            };
            if !allowed {
                return Err("A managed extension archive does not match its approved receipt. Close Firefox and repair the extension state before reopening this profile.".into());
            }
        }
    }
    crate::addons_metadata::check(profile, &mirror, native_approved)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(not(target_os = "macos"))]
        let firefox = temp.path().join("firefox/firefox");
        #[cfg(target_os = "macos")]
        let firefox = temp.path().join("Firefox.app/Contents/MacOS/firefox");
        let root = resources(&firefox).unwrap();
        for (name, bytes) in MODULES {
            let path = root.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        std::fs::write(root.join("application.ini"), "[App]\nVersion=153.4.0\n").unwrap();
        std::fs::write(
            root.join("defaults/pref/channel-prefs.js"),
            "pref(\"app.update.channel\", \"esr\");\n",
        )
        .unwrap();
        let profile = temp.path().join("profile");
        std::fs::create_dir_all(profile.join("epix-addons")).unwrap();
        std::fs::write(profile.join("epix-addons/mirror.json"), serde_json::json!({"protocol":1,"profile_id":"a".repeat(64),"managed":[],"pending":null}).to_string()).unwrap();
        (temp, firefox, profile)
    }
    #[test]
    fn launch_requires_all_fixed_resources_and_supported_engine() {
        let (_temp, firefox, profile) = fixture();
        let id = "a".repeat(64);
        assert!(preflight(&firefox, &profile, &id).is_ok());
        let root = resources(&firefox).unwrap();
        std::fs::write(root.join("application.ini"), "Version=153.5.1\n").unwrap();
        assert!(preflight(&firefox, &profile, &id).is_ok());
        std::fs::write(root.join("application.ini"), "Version=154.0\n").unwrap();
        assert!(preflight(&firefox, &profile, &id).is_err());
        std::fs::write(root.join("application.ini"), "Version=153.4.0\n").unwrap();
        std::fs::remove_file(root.join("distribution/epix-addon-installer/manager.sys.mjs"))
            .unwrap();
        assert!(preflight(&firefox, &profile, &id).is_err());
    }
    #[test]
    fn startup_only_accepts_exact_owned_and_approved_staged_bytes() {
        let (_temp, firefox, profile) = fixture();
        let id = "a".repeat(64);
        let old = b"old approved archive";
        let new = b"new approved archive";
        let old_hash = sha256(old);
        let new_hash = sha256(new);
        let operation = "b".repeat(64);
        let mirror = serde_json::json!({"protocol":1,"profile_id":id,"managed":[{"addon_id":"qa@example.invalid","version":"1","archive_sha256":old_hash}],"pending":{"phase":"Staged","operation_id":operation,"candidate":{"operation_id":operation,"addon_id":"qa@example.invalid","version":"2","archive_sha256":new_hash}}});
        let consent = serde_json::json!({"protocol":1,"profile_id":id,"operation_id":operation,"addon_id":"qa@example.invalid","version":"2","archive_sha256":new_hash});
        std::fs::write(
            profile.join("epix-addons/native-consent.json"),
            consent.to_string(),
        )
        .unwrap();
        std::fs::write(profile.join("epix-addons/mirror.json"), mirror.to_string()).unwrap();
        std::fs::create_dir_all(profile.join("extensions/staged")).unwrap();
        std::fs::write(profile.join("extensions/qa@example.invalid.xpi"), old).unwrap();
        std::fs::write(
            profile.join("extensions/staged/qa@example.invalid.xpi"),
            new,
        )
        .unwrap();
        assert!(preflight(&firefox, &profile, &id).is_ok());
        std::fs::write(
            profile.join("extensions/staged/qa@example.invalid.xpi"),
            b"foreign stage",
        )
        .unwrap();
        assert!(preflight(&firefox, &profile, &id).is_err());
        std::fs::remove_file(profile.join("extensions/staged/qa@example.invalid.xpi")).unwrap();
        std::fs::write(profile.join("extensions/qa@example.invalid.xpi"), new).unwrap();
        assert!(preflight(&firefox, &profile, &id).is_ok());
        assert!(preflight(&firefox, &profile, &"b".repeat(64)).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn linked_profile_children_and_final_files_are_rejected_without_touching_target() {
        let (temp, firefox, profile) = fixture();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let sentinel = outside.join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&outside, profile.join("extensions")).unwrap();
        assert!(preflight(&firefox, &profile, &"a".repeat(64)).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        std::fs::remove_file(profile.join("extensions")).unwrap();
        let linked = temp.path().join("linked");
        std::os::unix::fs::symlink(&sentinel, &linked).unwrap();
        assert!(read_regular(&linked, 100).is_err());
        assert!(read_regular(&sentinel, 2).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
    }
}
