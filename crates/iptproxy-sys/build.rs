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

    // Windows / Android ship a shared library loaded at runtime; everything else
    // static-links the archive at build time.
    if matches!(target_os.as_str(), "windows" | "android") {
        link_dynamic(&rev, &target, &target_os, &manifest, &out_dir);
    } else {
        link_static(&rev, &target, &target_os, &manifest, &out_dir);
    }
}

/// Windows / Android: the shared library is loaded at runtime, so it need not
/// exist at build time. Windows fetches the DLL beside the exe; Android's .so is
/// placed in jniLibs by the build workflow.
fn link_dynamic(rev: &str, target: &str, target_os: &str, manifest: &Path, out_dir: &Path) {
    println!("cargo:rustc-cfg=iptproxy_dynamic");
    let ext = if target_os == "windows" { "dll" } else { "so" };
    let asset = format!("epix_snowflake-{target}.{ext}");
    // The runtime filename the loader opens. Android ships it in jniLibs as
    // `libepix_snowflake.so` (its packaging + dlopen expect the lib prefix);
    // Windows loads the asset by name from beside the executable.
    let runtime = if target_os == "android" { "libepix_snowflake.so" } else { asset.as_str() };
    println!("cargo:rustc-env=IPTPROXY_LIB_FILENAME={runtime}");
    if target_os != "windows" {
        return; // Android places its .so via the build workflow.
    }
    if let Some(lib) = resolve(rev, target, &asset, manifest, out_dir) {
        copy_beside_exe(&lib, out_dir);
    } else {
        println!(
            "cargo:warning=iptproxy-sys: no epix-iptproxy runtime library for `{target}` \
             (rev {rev}); Snowflake reports unavailable until it is shipped beside the \
             executable. Set IPTPROXY_LIB_DIR or publish the release."
        );
    }
}

/// macOS / Linux / iOS: static-link the archive (it must exist to link). Falls
/// back to the stub if the archive is unavailable, so the crate still builds.
fn link_static(rev: &str, target: &str, target_os: &str, manifest: &Path, out_dir: &Path) {
    let asset = format!("epix_snowflake-{target}.a");
    let Some(archive) = resolve(rev, target, &asset, manifest, out_dir) else {
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
    // Also drop it beside libepix_ffi.a (…/target/<triple>/<profile>/) so a
    // non-cargo final linker - the iOS Xcode project - can resolve
    // `-lepix_snowflake` from its existing LIBRARY_SEARCH_PATHS.
    if let Some(profile_dir) = out_dir.ancestors().nth(3) {
        let _ = std::fs::copy(&linked, profile_dir.join("libepix_snowflake.a"));
    }
    // The Go runtime the archive carries needs these platform libraries.
    match target_os {
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
    // Network-sourced copies (cached from an earlier build, or freshly
    // downloaded) must match the digest pinned in iptproxy.sha256 before they
    // are linked into the build. Operator-provided copies (IPTPROXY_LIB_DIR,
    // vendored prebuilt/) are trusted as local inputs.
    let cached = out_dir.join(asset);
    if cached.is_file() {
        verify_pinned_sha256(&cached, asset, manifest);
        return Some(cached);
    }
    if rev.is_empty() {
        return None;
    }
    let url = format!("{RELEASE_BASE}/{rev}/{asset}");
    download(&url, &cached).ok().map(|()| {
        verify_pinned_sha256(&cached, asset, manifest);
        cached
    })
}

/// Panic unless `file` matches the digest recorded for `asset` in
/// `iptproxy.sha256` (sha256sum format, updated together with iptproxy.rev).
/// Fails closed: an asset with no recorded digest refuses to build rather
/// than linking unverified downloaded code.
fn verify_pinned_sha256(file: &Path, asset: &str, manifest: &Path) {
    use sha2::Digest;

    let pins = manifest.join("iptproxy.sha256");
    println!("cargo:rerun-if-changed={}", pins.display());
    let pinned = std::fs::read_to_string(&pins).unwrap_or_default();
    let expected = pinned
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((parts.next()?, parts.next()?))
        })
        .find(|(_, name)| *name == asset)
        .map(|(digest, _)| digest.to_ascii_lowercase());
    let Some(expected) = expected else {
        panic!(
            "no pinned sha256 for {asset} in {}; add `sha256sum {asset}` output              there when bumping iptproxy.rev",
            pins.display()
        );
    };
    let bytes = std::fs::read(file).expect("read downloaded iptproxy asset");
    let digest = sha2::Sha256::digest(&bytes);
    let actual = hex_digest(&digest);
    if actual != expected {
        let _ = std::fs::remove_file(file);
        panic!(
            "downloaded {asset} does not match the digest pinned in {}:              expected {expected}, got {actual}",
            pins.display()
        );
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn download(url: &str, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // NOSONAR - the URL is a release pinned by iptproxy.rev and every caller
    // verifies the downloaded bytes against the sha256 recorded in
    // iptproxy.sha256 (verify_pinned_sha256) before they are linked; a
    // missing or mismatched digest fails the build.
    let bytes = reqwest::blocking::Client::builder() // NOSONAR: digest-verified download, see above
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
