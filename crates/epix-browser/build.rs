//! Two build-time jobs:
//!
//! 1. Stage the Epix Wallet extension. `src/ext.rs` embeds
//!    `shells/wallet-ext` via `include_dir!`, but that directory is a build
//!    artifact (the forked Keplr's `yarn build` output), not source. When it
//!    is not already populated, this script downloads the prebuilt artifact
//!    from the epix-wallet repo's rolling `wallet-dist` GitHub release, so a
//!    fresh clone builds with no local wallet checkout. Overrides:
//!    - `EPIX_WALLET_DIST=/path/to/build/firefox` copies a local wallet build
//!      instead (for wallet development).
//!    - `EPIX_WALLET_SKIP=1` skips staging entirely (offline builds; the
//!      browser then launches without the wallet).
//!    A populated directory is always left alone - delete the staged files in
//!    `shells/wallet-ext` (keep README.md) to force a re-fetch.
//!
//! 2. Capture the short git commit so the node can report it (the dashboard
//!    shows it next to the version). Falls back to "unknown" outside a git
//!    checkout (e.g. a source tarball).

use std::path::{Path, PathBuf};

/// The epix-wallet repo's rolling release artifact: the zipped
/// `apps/extension/build/firefox` output, republished by its CI on every push
/// to the `epix` branch (`.github/workflows/build-dist.yml` there).
const WALLET_DIST_URL: &str =
    "https://github.com/EpixZone/epix-wallet/releases/download/wallet-dist/epix-wallet-firefox.zip";

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

/// Make sure `shells/wallet-ext` holds a wallet build before `include_dir!`
/// embeds it. See the module docs for the resolution order.
fn stage_wallet_ext() {
    let dest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../shells/wallet-ext");
    println!("cargo:rerun-if-env-changed=EPIX_WALLET_DIST");
    println!("cargo:rerun-if-env-changed=EPIX_WALLET_SKIP");
    // Re-embed when the staged build changes (manifest.json is always part of
    // a wallet build, and its content hash changes with every build).
    println!("cargo:rerun-if-changed={}", dest.join("manifest.json").display());

    if std::env::var_os("EPIX_WALLET_SKIP").is_some_and(|v| v == "1") {
        // Informational, not a warning: skipping is an explicit opt-in (e.g. a
        // Rust-only CI compile check). Shown under `cargo build -vv`.
        println!("epix-browser: EPIX_WALLET_SKIP=1, building without the wallet extension");
        return;
    }
    if dest.join("manifest.json").exists() {
        return; // already staged (local build or a previous fetch)
    }
    if let Some(src) = std::env::var_os("EPIX_WALLET_DIST") {
        let src = PathBuf::from(src);
        if !src.join("manifest.json").exists() {
            panic!(
                "EPIX_WALLET_DIST={} has no manifest.json; point it at the wallet's \
                 apps/extension/build/firefox directory",
                src.display()
            );
        }
        copy_dir(&src, &dest).expect("copy EPIX_WALLET_DIST into shells/wallet-ext");
        return;
    }

    // Informational, not a warning: fetching the prebuilt wallet is the normal
    // path on a fresh checkout (the dir is a build-time staging area, gitignored
    // except its README). A plain build-script message shows only under
    // `cargo build -vv`; a real failure still panics below.
    println!("epix-browser: staging the Epix Wallet from {WALLET_DIST_URL}");
    if let Err(e) = download_wallet(&dest) {
        panic!(
            "could not stage the Epix Wallet extension: {e}\n\
             - retry online (downloads {WALLET_DIST_URL}),\n\
             - or stage a local build: EPIX_WALLET_DIST=/path/to/epix-wallet/apps/extension/build/firefox,\n\
             - or build without the wallet: EPIX_WALLET_SKIP=1\n\
             (see shells/wallet-ext/README.md)"
        );
    }
}

fn download_wallet(dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let resp = reqwest::blocking::Client::builder()
        .user_agent("epix-browser-build")
        .build()?
        .get(WALLET_DIST_URL)
        .send()?
        .error_for_status()?;
    let bytes = resp.bytes()?;
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
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(&tmp)? {
        let entry = entry?;
        let to = dest.join(entry.file_name());
        let _ = std::fs::remove_dir_all(&to);
        let _ = std::fs::remove_file(&to);
        std::fs::rename(entry.path(), &to)?;
    }
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
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
