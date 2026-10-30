//! Disposable signed-policy fixture, with no worker invocation.
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
fn main() {
    let strict = std::env::args().any(|arg| arg == "strict");
    let result = if strict {
        evx_supervisor::apple_package::ApplePackage::current()
    } else {
        evx_supervisor::apple_package::ApplePackage::current_for_fixture()
    };
    match result {
        Ok(package) => println!(
            "{}",
            serde_json::json!({"identity":package.registry.identity().unwrap(), "root":package.state_root})
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(3);
        }
    }
}
#[cfg(not(all(target_os = "macos", feature = "apple-xpc")))]
fn main() {
    panic!("Apple XPC feature required");
}
