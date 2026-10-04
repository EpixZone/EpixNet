fn main() {
    if let Err(error) = evx_windows::acceptance_main() {
        eprintln!("Windows isolation acceptance failed: {error}");
        std::process::exit(1);
    }
}
