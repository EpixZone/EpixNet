//! Shared build-script helpers for the Epix binaries.
//!
//! `epix-server` and `epix-browser` both need to stamp their build with a
//! version and the short git commit. Keeping that logic here (used from each
//! `build.rs` as a `[build-dependencies]`) means one copy instead of two
//! near-identical build scripts.

use std::process::Command;

/// Emit `EPIX_VERSION` and `EPIX_GIT_REV` for the calling crate, plus the
/// `rerun-if` lines so a new commit refreshes the rev.
///
/// Version precedence: the release tag (`EPIX_VERSION`, set by CI from the git
/// tag) when present; else the latest reachable git tag, so a dev build reports
/// the release line it sits on; else the crate's own Cargo version (source
/// tarballs with no git). `CARGO_PKG_VERSION` is read from the environment
/// (Cargo sets it per build script) so this reflects the *calling* crate, not
/// this helper crate.
pub fn emit_version_and_rev() {
    let rev = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=EPIX_GIT_REV={rev}");

    let version = std::env::var("EPIX_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            git(&["describe", "--tags", "--abbrev=0"])
                .map(|t| t.trim_start_matches('v').to_string())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_default());
    println!("cargo:rustc-env=EPIX_VERSION={version}");
    println!("cargo:rerun-if-env-changed=EPIX_VERSION");

    // Re-run when the checked-out commit changes so the rev doesn't go stale
    // when only a dependency changed.
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]) {
        let head = format!("{git_dir}/HEAD");
        println!("cargo:rerun-if-changed={head}");
        println!("cargo:rerun-if-changed={git_dir}/packed-refs");
        // If HEAD is a symref to a branch, that ref file moves on each commit.
        if let Ok(contents) = std::fs::read_to_string(&head) {
            if let Some(r) = contents.strip_prefix("ref: ") {
                println!("cargo:rerun-if-changed={git_dir}/{}", r.trim());
            }
        }
    }
}

/// Run `git` with `args`, returning trimmed stdout on success.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}
