//! Resolve the epix-iptproxy Snowflake library for the build target and tell
//! `lib.rs` how to reach it:
//!
//! - macOS / Linux / iOS: static `c-archive` `.a`, linked at build time. Needs
//!   the artifact present, so it is downloaded (or taken from `IPTPROXY_LIB_DIR`
//!   / vendored `prebuilt/<triple>/`); if absent, the crate builds the stub.
//! - Windows / Android: `c-shared` `.dll`/`.so`, loaded at runtime (sidesteps
//!   the MSVC/MinGW static wall, and Android's jniLibs convention). The library
//!   need not exist at build time; it is fetched best-effort and copied beside
//!   the executable for `cargo run` / packaging.
//!
//! The artifacts come from the companion repo's release pinned in `iptproxy.rev`.
//! Override any target with `IPTPROXY_LIB_DIR=/dir/holding/the/asset`.

use std::path::{Path, PathBuf};

const RELEASE_BASE: &str = "https://github.com/EpixZone/epix-iptproxy/releases/download";

fn main() {
    for c in ["iptproxy_static", "iptproxy_dynamic", "iptproxy_stub"] {
        println!("cargo::rustc-check-cfg=cfg({c})");
    }
    println!("cargo:rerun-if-env-changed=IPTPROXY_LIB_DIR");

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let pin = manifest.join("iptproxy.rev");
    println!("cargo:rerun-if-changed={}", pin.display());
    let rev = std::fs::read_to_string(&pin).map(|s| s.trim().to_string()).unwrap_or_default();

    let target = std::env::var("TARGET").unwrap();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Windows / Android ship a shared library loaded at runtime.
    if matches!(target_os.as_str(), "windows" | "android") {
        println!("cargo:rustc-cfg=iptproxy_dynamic");
        let ext = if target_os == "windows" { "dll" } else { "so" };
        let asset = format!("epix_snowflake-{target}.{ext}");
        // The runtime loader resolves this filename beside the executable.
        println!("cargo:rustc-env=IPTPROXY_LIB_FILENAME={asset}");
        if let Some(lib) = resolve(&rev, &target, &asset, &manifest, &out_dir) {
            copy_beside_exe(&lib, &out_dir);
        } else {
            println!(
                "cargo:warning=iptproxy-sys: no epix-iptproxy runtime library for `{target}` \
                 (rev {rev}); Snowflake will report unavailable until it is shipped beside the \
                 executable. Set IPTPROXY_LIB_DIR or publish the release."
            );
        }
        return;
    }

    // macOS / Linux / iOS static-link the archive; it must exist to link.
    let asset = format!("epix_snowflake-{target}.a");
    let Some(archive) = resolve(&rev, &target, &asset, &manifest, &out_dir) else {
        println!("cargo:rustc-cfg=iptproxy_stub");
        println!(
            "cargo:warning=iptproxy-sys: no epix-iptproxy archive for `{target}` (rev {rev}); \
             building the stub (Snowflake unavailable). Set IPTPROXY_LIB_DIR or publish the release."
        );
        return;
    };

    // rustc's `static=NAME` wants `libNAME.a` on the search path.
    let linked = out_dir.join("libepix_snowflake.a");
    if std::fs::copy(&archive, &linked).is_err() {
        println!("cargo:rustc-cfg=iptproxy_stub");
        return;
    }
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=epix_snowflake");
    println!("cargo:rustc-cfg=iptproxy_static");
    // The Go runtime the archive carries needs these platform libraries.
    match target_os.as_str() {
        "macos" | "ios" => {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
        }
        "linux" => {
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
        }
        _ => {}
    }
}

/// Locate `asset`: `IPTPROXY_LIB_DIR` override, else vendored
/// `prebuilt/<triple>/`, else a cached or fresh download of the pinned release.
fn resolve(rev: &str, target: &str, asset: &str, manifest: &Path, out_dir: &Path) -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("IPTPROXY_LIB_DIR") {
        let p = PathBuf::from(dir).join(asset);
        if p.is_file() {
            return Some(p);
        }
    }
    let vendored = manifest.join("prebuilt").join(target).join(asset);
    if vendored.is_file() {
        return Some(vendored);
    }
    let cached = out_dir.join(asset);
    if cached.is_file() {
        return Some(cached);
    }
    if rev.is_empty() {
        return None;
    }
    let url = format!("{RELEASE_BASE}/{rev}/{asset}");
    download(&url, &cached).ok().map(|()| cached)
}

fn download(url: &str, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = reqwest::blocking::Client::builder()
        .user_agent("iptproxy-sys-build")
        .build()?
        .get(url)
        .send()?
        .error_for_status()?
        .bytes()?;
    let tmp = dest.with_extension("download-tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

/// Copy a runtime library next to the built executable (…/target/<profile>/) so
/// `cargo run` and the packaged app can load it, keeping an OUT_DIR copy too.
fn copy_beside_exe(lib: &Path, out_dir: &Path) {
    let name = lib.file_name().unwrap();
    // OUT_DIR = …/target/<profile>/build/<pkg>-<hash>/out
    if let Some(profile_dir) = out_dir.ancestors().nth(3) {
        let _ = std::fs::copy(lib, profile_dir.join(name));
    }
    if lib.parent() != Some(out_dir) {
        let _ = std::fs::copy(lib, out_dir.join(name));
    }
}
