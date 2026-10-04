//! EVX trusted supervisor.
//!
//! The supervisor owns everything the guest must not: the workspace lease,
//! the grant and limits, the compiled artifact, the decision to authorize each
//! broker call, and the lifecycle of every child process. Guest-derived file
//! work runs in a separately confined, separately killable helper so a
//! blocked native call never stalls this event loop.
//!
//! Effect semantics follow the proof of concept exactly. A write is staged by
//! the helper, the supervisor rechecks the grant, the limits generation and
//! the deadlines, and only then authorizes the commit. If anything fails after
//! that authorization the result is `EffectUnknown`: the file may have changed
//! and the caller must reconcile before retrying.

pub mod apple_slots;
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub mod apple_workspace;
pub mod broker;
mod boot_session;
pub mod compile;
pub mod direct_lifecycle;
pub mod process;
mod provenance;
mod reconcile;
pub use reconcile::{reconcile_workspace, reconcile_workspace_cancellable};
pub mod supervisor;

pub use broker::Broker;
pub use compile::{
    compile_module, compile_module_cancellable, compile_text, compile_text_cancellable,
    CompiledArtifact,
};
pub use supervisor::{run_guest, run_guest_with_admission, Config, RunOptions};

/// Read-only platform capability check. It does not sandbox the calling host.
/// The child still installs and verifies all restrictions before reading input.
pub fn confinement_available() -> Result<(), evx_api::Denied> {
    #[cfg(target_os = "macos")]
    {
        Ok(())
    }
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0,
                1,
            )
        };
        if abi < 3 {
            Err(evx_api::Denied::new(
                "Linux Landlock ABI 3 or newer is required",
            ))
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        Err(evx_api::Denied::new(
            "OS confinement is unavailable on this platform",
        ))
    }
}
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub mod apple;

#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub mod apple_package;
