//! Two build-time jobs:
//!
//! 1. Stage the Epix Wallet extension. `src/ext.rs` embeds
//!    `shells/wallet-ext` via `include_dir!`, but that directory is a build
//!    artifact (the forked Keplr's `yarn build` output), not source. The exact
//!    wallet build is pinned by `shells/wallet-ext.rev` (an epix-wallet commit
//!    on its `epix` branch); this script downloads that build's immutable
//!    `wallet-<rev>` GitHub release when the staged copy is missing or does not
//!    match the pin. Pinning keeps EpixNet builds reproducible: a given EpixNet
//!    commit always embeds the same wallet, and adopting a new wallet is a
//!    deliberate one-line bump to the pin. Overrides:
//!    - `EPIX_WALLET_DIST=/path/to/build/firefox` copies a local wallet build
//!      instead (re-copied whenever it changes, for wallet development).
//!    - `EPIX_WALLET_SKIP=1` skips staging entirely (offline builds; the
//!      browser then launches without the wallet).
//!    When the staged copy already matches the pin, the build reuses it with no
//!    network access (offline-friendly). A pin bump re-fetches automatically.
//!
//! 2. Capture the short git commit so the node can report it (the dashboard
//!    shows it next to the version). Falls back to "unknown" outside a git
//!    checkout (e.g. a source tarball).

use std::path::{Path, PathBuf};

/// The epix-wallet release-download base. Each wallet build is published as an
/// immutable `wallet-<rev>` release (see the wallet repo's
/// `.github/workflows/build-dist.yml`); `wallet_dist_url` appends the pinned rev.
const WALLET_RELEASE_BASE: &str =
    "https://github.com/EpixZone/epix-wallet/releases/download";

/// The asset name inside each `wallet-<rev>` release.
const WALLET_DIST_ASSET: &str = "epix-wallet-firefox.zip";

/// The download URL for the wallet build pinned at `rev`.
fn wallet_dist_url(rev: &str) -> String {
    format!("{WALLET_RELEASE_BASE}/wallet-{rev}/{WALLET_DIST_ASSET}")
}

fn main() {
    stage_wallet_ext();
    embed_windows_icon();
    // Version + git rev (shared with epix-server via epix-build).
    epix_build::emit_version_and_rev();
}

/// Embed `packaging/windows/app.ico` in the exe so Explorer, the taskbar and
/// Add/Remove Programs show the Epix icon. Only compiled on Windows hosts
/// (winresource is a cfg(windows) build-dependency, absent elsewhere, and the
/// Windows release builds on a Windows runner); the target_os check skips
/// cross-target checks on that host. The reverse (a Windows host building a
/// non-Windows target) is unsupported: winresource resolves against the
/// target, so this cfg(windows) code would not compile. Our build matrix
/// never does that.
#[cfg(windows)]
fn embed_windows_icon() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let ico = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/windows/app.ico");
    println!("cargo:rerun-if-changed={}", ico.display());
    winresource::WindowsResource::new()
        .set_icon(ico.to_str().expect("icon path is valid utf-8"))
        .compile()
        .expect("embed packaging/windows/app.ico into epix-browser.exe");
}

#[cfg(not(windows))]
fn embed_windows_icon() {}

/// Make sure `shells/wallet-ext` holds the pinned wallet build before
/// `include_dir!` embeds it. See the module docs for the resolution order.
fn stage_wallet_ext() {
    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../shells/wallet-ext");
    let pin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../shells/wallet-ext.rev");
    // Records the rev of the staged copy, beside (not inside) the embedded dir
    // so it never lands in the XPI. Compared to the pin to detect a stale copy.
    let stamp = dest.with_file_name("wallet-ext.rev-stamp");
    println!("cargo:rerun-if-env-changed=EPIX_WALLET_DIST");
    println!("cargo:rerun-if-env-changed=EPIX_WALLET_SKIP");
    // Re-stage when the pin bumps or the staged build changes underneath us.
    println!("cargo:rerun-if-changed={}", pin.display());
    println!("cargo:rerun-if-changed={}", dest.join("manifest.json").display());

    if std::env::var_os("EPIX_WALLET_SKIP").is_some_and(|v| v == "1") {
        // Informational, not a warning: skipping is an explicit opt-in (e.g. a
        // Rust-only CI compile check). Shown under `cargo build -vv`.
        println!("epix-browser: EPIX_WALLET_SKIP=1, building without the wallet extension");
        return;
    }

    // A wallet developer's local build wins, and is re-copied whenever it
    // changes, so iterating on the wallet never leaves a stale staged copy.
    if let Some(src) = std::env::var_os("EPIX_WALLET_DIST") {
        stage_from_local(&PathBuf::from(src), &dest);
        let _ = std::fs::remove_file(&stamp); // a local copy is not a pinned fetch
        return;
    }

    let rev = std::fs::read_to_string(&pin)
        .unwrap_or_else(|e| panic!("read wallet pin {}: {e}", pin.display()))
        .trim()
        .to_string();
    if rev.is_empty() {
        panic!("wallet pin {} is empty; set it to an epix-wallet commit", pin.display());
    }

    // Reuse the staged copy when it already matches the pin: no network, so a
    // plain rebuild stays fast and works offline. A pin bump (stamp != rev)
    // or an empty staging dir falls through to the fetch.
    let staged = dest.join("manifest.json").exists();
    let stamped = std::fs::read_to_string(&stamp).ok().map(|s| s.trim().to_string());
    if staged && stamped.as_deref() == Some(rev.as_str()) {
        return;
    }

    let url = wallet_dist_url(&rev);
    println!("epix-browser: staging the Epix Wallet ({rev}) from {url}");
    if let Err(e) = download_wallet(&url, &dest) {
        panic!(
            "could not stage the pinned Epix Wallet ({rev}): {e}\n\
             - retry online (downloads {url}),\n\
             - check shells/wallet-ext.rev points at a published wallet-<rev> release,\n\
             - or stage a local build: EPIX_WALLET_DIST=/path/to/epix-wallet/apps/extension/build/firefox,\n\
             - or build without the wallet: EPIX_WALLET_SKIP=1\n\
             (see shells/wallet-ext/README.md)"
        );
    }
    let _ = std::fs::write(&stamp, &rev);
}

/// Copy a local wallet build into `shells/wallet-ext`, re-copying only when it
/// differs from what is already staged (a changed manifest.json means a new
/// wallet build). Panics if the source has no manifest.json.
fn stage_from_local(src: &Path, dest: &Path) {
    if !src.join("manifest.json").exists() {
        panic!(
            "EPIX_WALLET_DIST={} has no manifest.json; point it at the wallet's \
             apps/extension/build/firefox directory",
            src.display()
        );
    }
    if same_file(&src.join("manifest.json"), &dest.join("manifest.json")) {
        return; // already staged this build
    }
    clear_dir_keep_readme(dest);
    copy_dir(src, dest).expect("copy EPIX_WALLET_DIST into shells/wallet-ext");
}

fn download_wallet(url: &str, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = reqwest::blocking::Client::builder()
        .user_agent("epix-browser-build")
        .build()?
        .get(url)
        .send()?
        .error_for_status()?
        .bytes()?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes.as_ref()))?;
    // Extract next to the final destination, then move files in, so a failed
    // download never leaves a half-staged directory that a later build would
    // mistake for a complete one.
    let tmp = dest.with_file_name("wallet-ext.tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    zip.extract(&tmp)?;
    if !tmp.join("manifest.json").exists() {
        return Err("downloaded archive has no manifest.json at its root".into());
    }
    // Clear the previous wallet first (keeping README.md), so switching revs
    // can't leave behind files a different build renamed or dropped.
    std::fs::create_dir_all(dest)?;
    clear_dir_keep_readme(dest);
    for entry in std::fs::read_dir(&tmp)? {
        let entry = entry?;
        let to = dest.join(entry.file_name());
        std::fs::rename(entry.path(), &to)?;
    }
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

/// Remove everything in `dir` except README.md (the one git-tracked file).
fn clear_dir_keep_readme(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if entry.file_name() == "README.md" {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Whether two files exist and have identical bytes.
fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::read(a), std::fs::read(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn copy_dir(src: &Path, dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}
