//! Windows LPAC/Job isolation and bounded EVX compiler/worker transport.
//!
//! The trusted embedding API compiles and runs real Wasm through a pinned
//! worker. Node admission and Windows workspace effects remain disabled.
//! Native acceptance must run on Windows; cross-checking is not that evidence.
//! See `docs/evx-windows.md` for the supported interfaces and remaining work.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(any(windows, test))]
mod denial;
#[cfg(windows)]
mod windows;

/// Run the fixed native acceptance fixture, or its private child entrypoint.
/// Never call from a node or expose this function as a guest capability.
#[cfg(windows)]
pub fn acceptance_main() -> std::io::Result<()> {
    windows::main()
}

#[cfg(not(windows))]
pub fn acceptance_main() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows native acceptance requires a real Windows host",
    ))
}

#[cfg(windows)]
pub use windows::execution::{
    worker_main, CompiledModule, NativeUsage, TrustedWorker, WindowsExecutor,
};
