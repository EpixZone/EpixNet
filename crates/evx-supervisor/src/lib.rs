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

pub mod broker;
pub mod compile;
pub mod process;
pub mod supervisor;

pub use broker::Broker;
pub use compile::{compile_module, CompiledArtifact};
pub use supervisor::{run_guest, Config, RunOptions};
