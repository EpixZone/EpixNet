//! Fixed-role worker. Only an LPAC/job-confined process accepts EVX input.
#[cfg(windows)]
fn main() {
    if let Err(error) = evx_windows::worker_main() {
        eprintln!("evx-windows-worker: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows confined execution is unavailable on this platform");
    std::process::exit(1);
}
