//! Request Ubuntu's per-application sandbox permission only when it is missing.

use std::path::Path;
use std::process::Command;

const HELPER: &str = include_str!("../../../packaging/linux/enable-sandbox.sh");

pub fn prepare(
    firefox: &Path,
    background: bool,
    progress: &crate::startup::Progress,
) -> Result<(), String> {
    if !Path::new("/etc/apparmor.d/abi/4.0").is_file()
        || std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .unwrap_or_default()
            .trim()
            != "1"
    {
        return Ok(());
    }
    let directory = firefox
        .parent()
        .ok_or("The browser folder was not found.")?;
    let directory = directory
        .canonicalize()
        .map_err(|e| format!("Could not locate the browser folder: {e}"))?;
    let probe = directory.join("libepix-sandbox-probe.so");
    if !probe.is_file() {
        // System Firefox and unpackaged development builds manage their own rules.
        return Ok(());
    }
    let binary = directory.join("firefox");
    ensure_sandbox(
        background,
        || {
            let status = Command::new(&binary)
                .arg("--version")
                .env("LD_PRELOAD", &probe)
                .output()
                .map_err(|e| format!("Could not check the browser sandbox: {e}"))?;
            match status.status.code() {
                Some(42) => Ok(true),
                Some(43) => Ok(false),
                _ => Err("Could not check the browser sandbox. Reinstall EpixNet.".into()),
            }
        },
        || {
            progress.report(crate::startup::Stage::Sandbox);
            println!("· requesting the one-time Firefox sandbox permission");
            // Embed the helper rather than asking root to read a user-owned file
            // or the FUSE mount. pkexec displays the desktop's authorization dialog.
            let status = Command::new("/usr/bin/pkexec")
                .args([
                    "--disable-internal-agent",
                    "/bin/bash",
                    "-c",
                    HELPER,
                    "epixnet-sandbox",
                    "--firefox-path",
                ])
                .arg(&binary)
                .status()
                .map_err(|e| format!("Could not open the system approval dialog: {e}"))?;
            match status.code() {
                Some(0) => Ok(()),
                Some(126) => Err("Setup was cancelled. Open EpixNet again and approve the browser sandbox permission.".into()),
                Some(127) => Err("The browser sandbox needs administrator approval. Open EpixNet from a desktop session with an administrator account.".into()),
                _ => Err("The system could not enable the browser sandbox. EpixNet has not opened the browser.".into()),
            }
        },
    )
}

fn ensure_sandbox(
    background: bool,
    mut check: impl FnMut() -> Result<bool, String>,
    authorize: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if check()? {
        return Ok(());
    }
    if background {
        return Err("Open EpixNet normally once to approve the browser sandbox permission.".into());
    }
    authorize()?;
    if !check()? {
        return Err("The browser sandbox is still unavailable after setup. EpixNet has not opened the browser.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn first_launch_requests_permission_and_checks_the_result() {
        let configured = Cell::new(false);
        let checks = Cell::new(0);
        ensure_sandbox(
            false,
            || {
                checks.set(checks.get() + 1);
                Ok(configured.get())
            },
            || {
                configured.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(checks.get(), 2);
        ensure_sandbox(false, || Ok(configured.get()), || panic!("prompted again")).unwrap();
    }

    #[test]
    fn background_launch_never_prompts() {
        assert!(ensure_sandbox(true, || Ok(false), || panic!("prompted at login")).is_err());
        ensure_sandbox(true, || Ok(true), || panic!("prompted at login")).unwrap();
    }

    #[test]
    fn cancellation_does_not_continue() {
        let checks = Cell::new(0);
        assert_eq!(
            ensure_sandbox(
                false,
                || {
                    checks.set(checks.get() + 1);
                    Ok(false)
                },
                || Err("cancelled".into())
            ),
            Err("cancelled".into())
        );
        assert_eq!(checks.get(), 1);
    }

    #[test]
    fn failed_setup_does_not_continue() {
        assert!(ensure_sandbox(false, || Ok(false), || Ok(())).is_err());
        assert!(ensure_sandbox(
            false,
            || Err("probe failed".into()),
            || panic!("prompted without a valid check")
        )
        .is_err());
    }
}
