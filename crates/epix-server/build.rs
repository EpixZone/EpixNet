//! Capture the short git commit at build time so the node can report it (the
//! dashboard shows it next to the version). Falls back to "unknown" outside a
//! git checkout (e.g. a source tarball).

use std::process::Command;

fn main() {
    let rev = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=EPIX_GIT_REV={rev}");

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

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!s.is_empty()).then_some(s)
}
