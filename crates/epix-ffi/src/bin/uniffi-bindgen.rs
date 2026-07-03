//! The `uniffi-bindgen` CLI for this crate, used by the mobile build scripts to
//! emit Kotlin (Android) and Swift (iOS) bindings from the exported types.
//!
//! Build with `--features cli`, then e.g.:
//!   cargo run --features cli --bin uniffi-bindgen -- generate \
//!     --library target/aarch64-linux-android/release/libepix_ffi.so \
//!     --language kotlin --out-dir shells/android/app/src/main/java

fn main() {
    uniffi::uniffi_bindgen_main()
}
