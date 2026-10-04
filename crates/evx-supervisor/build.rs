fn main() {
    println!("cargo:rerun-if-changed=native/apple_xpc.c");
    println!("cargo:rerun-if-changed=native/apple_package.c");
    println!("cargo:rerun-if-env-changed=EPIX_EVX_TEAM_ID");
    let team = std::env::var("EPIX_EVX_TEAM_ID").unwrap_or_default();
    assert!(
        team.is_empty()
            || (team.len() == 10
                && team
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())),
        "EPIX_EVX_TEAM_ID must be a ten-character release Team ID"
    );
    println!("cargo:rustc-env=EVX_RELEASE_TEAM_ID={team}");
    if std::env::var_os("CARGO_FEATURE_APPLE_XPC").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
    {
        cc::Build::new()
            .file("native/apple_xpc.c")
            .file("native/apple_package.c")
            .define("EVX_RELEASE_TEAM_ID", Some(format!("\"{team}\"").as_str()))
            .flag("-std=c11")
            .flag("-fblocks")
            .flag("-mmacosx-version-min=12.0")
            .warnings_into_errors(true)
            .compile("evx_apple_xpc");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }
}
