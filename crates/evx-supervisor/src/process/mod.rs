//! Confined child processes: spawning, framed I/O, kernel observations and
//! bounded termination.
//!
//! Every child starts with an empty environment and only the handles it is
//! given, confines itself (Unix) or is verified confined by the host
//! (Windows) before reading input, and is reaped by the supervisor alone.
//! Resource observations come from the kernel, never from the child. The
//! shared state machine lives in `common`; `unix` and `windows` supply the
//! launch, measurement and termination mechanics.

mod common;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub use common::{child_admission_status, CleanupTimeout, Event, ObservationUnavailable, Role, Stream};
pub(crate) use common::{quarantine_child_admission, EVENT_CAPACITY, MAX_FRAMES, OUTPUT_QUOTA};

#[cfg(unix)]
pub use unix::Peer;
#[cfg(windows)]
pub use windows::{pipe_name, Peer, WORKSPACE_PREAMBLE};
#[cfg(windows)]
pub(crate) use windows::confinement_available as windows_confinement_available;
