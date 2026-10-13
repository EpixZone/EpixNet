//! Wasmtime engine configuration.
//!
//! The configuration is deny-by-default and deterministic. Every setting is
//! justified inline; see `outputs/evx-prior-art-reuse.md` in the planning
//! documents for the advisory each one maps to.

use wasmtime::{Config, Engine};
#[cfg(feature = "compiler")]
use wasmtime::{OptLevel, Strategy};

use crate::features;

/// Identity of the engine an artifact is bound to. Change `CONFIG_REVISION`
/// whenever [`engine_config`] changes in a way that affects compiled output.
const CONFIG_REVISION: u32 = 2;
const WASMTIME_VERSION: &str = "48.0.5";

/// Stable key for artifact caches and for the worker's refusal to load an
/// artifact produced under a different engine or configuration.
pub fn engine_key() -> String {
    format!(
        "evx-core-v1/wasmtime-{WASMTIME_VERSION}/{}/{}-{}/cfg-{CONFIG_REVISION}",
        backend_name(),
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

/// Compiled-artifact identity must distinguish native code and bytecode.
pub fn backend_name() -> &'static str {
    if cfg!(any(feature = "pulley", target_os = "ios")) {
        if cfg!(target_pointer_width = "64") {
            if cfg!(target_endian = "little") {
                "pulley64"
            } else {
                "pulley64be"
            }
        } else if cfg!(target_endian = "little") {
            "pulley32"
        } else {
            "pulley32be"
        }
    } else {
        "cranelift"
    }
}

/// Build the EVX engine configuration.
pub fn engine_config() -> Config {
    let mut c = Config::new();
    // Cranelift on desktop. Winch is excluded after a critical sandbox escape
    // (GHSA-xx5w, April 2026). Pulley is selected separately for iOS builds.
    #[cfg(feature = "compiler")]
    c.strategy(Strategy::Cranelift);
    if cfg!(any(feature = "pulley", target_os = "ios")) {
        c.target(backend_name()).expect("fixed Pulley target");
        c.signals_based_traps(false);
    }
    // Fast, small compiles; guests arrive pre-optimized. Matches the Internet
    // Computer and NEAR.
    #[cfg(feature = "compiler")]
    c.cranelift_opt_level(OptLevel::None);
    features::apply(&mut c);
    // Same float results on every host.
    #[cfg(feature = "compiler")]
    c.cranelift_nan_canonicalization(true);
    // Deterministic instruction budget per invocation.
    c.consume_fuel(true);
    // Wall-clock deadline driven by a supervisor thread; traps, never yields.
    c.epoch_interruption(true);
    c.max_wasm_stack(256 * 1024);
    // Static 4 GiB reservation with a guard region elides bounds checks and is
    // the configuration the 2023 x86_64 escape workaround relied on. Actual
    // growth is capped by the store limiter.
    if cfg!(any(feature = "pulley", target_os = "ios")) {
        // Explicit bytecode bounds checks, no signal handlers or executable
        // mappings. Reserve only the largest supported guest memory ceiling.
        c.memory_reservation(256 << 20);
        c.memory_guard_size(0);
        c.guard_before_linear_memory(false);
    } else {
        c.memory_reservation(4 << 30);
        c.memory_guard_size(32 << 20);
        c.guard_before_linear_memory(true);
    }
    c.memory_reservation_for_growth(0);
    c.memory_may_move(false);
    // No mmap of untrusted files inside the worker.
    c.memory_init_cow(false);
    c.debug_info(false);
    // Signals rather than a Mach exception port for the worker.
    c.macos_use_mach_ports(false);
    c
}

/// Create an engine with [`engine_config`].
pub fn new_engine() -> wasmtime::Result<Engine> {
    Engine::new(&engine_config())
}
