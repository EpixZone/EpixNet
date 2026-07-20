//! Link the vendored prebuilt IPtProxy static library when one is present for
//! the target, otherwise compile a stub so the `bridges` feature still builds
//! everywhere. This lets all the Rust-side wiring land and be tested before the
//! Go artifacts are vendored per platform (plan phase 1); phase 2+ drops the
//! real `libIPtProxy.a` into `prebuilt/<triple>/` (or points `IPTPROXY_LIB_DIR`
//! at it) and the same code links for real with no source changes.

use std::path::PathBuf;

fn main() {
    // Custom cfg used by lib.rs to pick the real FFI vs the stub. Declared so
    // Rust 1.80+ does not warn about an "unexpected cfg".
    println!("cargo::rustc-check-cfg=cfg(iptproxy_stub)");

    let target = std::env::var("TARGET").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Where to look for the prebuilt archive: an explicit override wins, else
    // the vendored per-triple directory.
    let lib_dir = std::env::var_os("IPTPROXY_LIB_DIR").map(PathBuf::from).or_else(|| {
        let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let vendored = manifest.join("prebuilt").join(&target);
        has_iptproxy_lib(&vendored).then_some(vendored)
    });

    println!("cargo:rerun-if-env-changed=IPTPROXY_LIB_DIR");
    println!("cargo:rerun-if-changed=prebuilt");

    let Some(dir) = lib_dir.filter(|d| has_iptproxy_lib(d)) else {
        // No artifact for this target yet: build the stub. `start_snowflake`
        // returns an error at runtime, which the bootstrap watchdog treats like
        // any other failure, so a bridges build without the lib degrades to
        // "bridges unavailable" instead of failing to link.
        println!("cargo:rustc-cfg=iptproxy_stub");
        println!(
            "cargo:warning=iptproxy-sys: no prebuilt IPtProxy library for target `{target}`; \
             building the stub (Snowflake will be unavailable at runtime). Set IPTPROXY_LIB_DIR \
             or vendor prebuilt/<triple>/ to link the real library."
        );
        return;
    };

    println!("cargo:rustc-link-search=native={}", dir.display());
    println!("cargo:rustc-link-lib=static=IPtProxy");

    // The Go runtime IPtProxy is built from pulls in these platform libraries.
    // (Confirmed/adjusted per platform as the real artifacts are vendored.)
    match target_os.as_str() {
        "macos" | "ios" => {
            println!("cargo:rustc-link-lib=framework=CoreFoundation");
            println!("cargo:rustc-link-lib=framework=Security");
        }
        "linux" | "android" => {
            println!("cargo:rustc-link-lib=dylib=pthread");
            println!("cargo:rustc-link-lib=dylib=dl");
        }
        "windows" => {
            for l in ["winmm", "ntdll", "ws2_32", "userenv", "bcrypt"] {
                println!("cargo:rustc-link-lib=dylib={l}");
            }
        }
        _ => {}
    }
}

/// True if `dir` holds a linkable IPtProxy archive under any of the usual names.
fn has_iptproxy_lib(dir: &std::path::Path) -> bool {
    ["libIPtProxy.a", "IPtProxy.lib", "libIPtProxy.lib"]
        .iter()
        .any(|name| dir.join(name).is_file())
}
