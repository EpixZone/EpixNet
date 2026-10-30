#[cfg(target_os = "macos")]
fn main() {
    evx_supervisor::apple::service_main();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("Apple XPC requires macOS");
    std::process::exit(1);
}
