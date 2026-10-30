//! Win32 primitives for EVX confinement on Windows, with no EVX policy.
//!
//! RAII handles, SDDL and ACL helpers, AppContainer profiles, job objects,
//! proc-thread attribute lists, LPAC launch and token validation, named-pipe
//! pairs, process accounting and registry reads. `evx-windows` (the native
//! fixture) and the Windows arms of the supervisor build on these; nothing
//! here depends on them. The crate is empty on other targets.
//!
//! userenv, shell32 and ole32 are loaded dynamically and only by host-side
//! helpers. A confined image must never import them statically.
#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
// HANDLE and PSID are raw pointers in windows-sys but opaque kernel references
// that the OS validates on every call; nothing here dereferences them.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod environment;
mod handle;
mod job;
mod launch;
mod pipe;
mod profile;
mod registry;
mod security;
mod version;

pub use environment::{local_app_data, worker_environment};
pub use handle::{fail, ok, wide, Handle, Local, SystemLibrary};
pub use job::{
    create_job, process_dead, process_usage, terminate_job, JobLimits, ProcessUsage, TERMINATED,
};
pub use launch::{
    inherited_object, is_inheritable, launch_suspended, resume, resume_thread, verify_launched,
    verify_process, Attributes, LaunchSpec, Launched,
};
pub use pipe::{available, blocking_pipe_pair, pipe_name, pipe_pair, read_available};
pub use profile::{delete_profile, Profile};
pub use registry::{registry_dword, registry_string};
pub use security::{
    current_user_sid_text, descriptor, granted_access, grants_read, inherit_dacl,
    is_app_container, open_process_token, protect, protect_handle, sid_text, token_info,
    validate_lpac, validate_token,
};
pub use version::{os_version, OsVersion};
