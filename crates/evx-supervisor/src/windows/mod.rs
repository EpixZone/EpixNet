//! The Windows backend behind `process::windows::Peer`
//! (`docs/evx-windows-backend.md`).
//!
//! - [`stage`]: the trusted worker image, pinned, hashed and staged into a
//!   host-private directory that every LPAC token may read.
//! - [`containers`]: the three AppContainer profiles of a workspace, the
//!   fixed compiler profile, and the workspace DACL that lets exactly the
//!   two helper profiles in.
//! - [`io`]: the host's end of the child's stdin pipe.
//!
//! Nothing here launches a process; `Peer::spawn` composes these pieces.

mod containers;
mod io;
mod stage;

use std::path::Path;

use evx_api::Denied;

pub(crate) use containers::{
    containers, prepare as prepare_workspace, probe as probe_profiles, Container,
};
pub(crate) use io::PipeWriter;
pub use stage::WindowsBackend;

/// The fixed compiler profile name.
pub const COMPILER_PROFILE: &str = containers::COMPILER_PROFILE;

/// The guest, file helper and file-read helper profile names of
/// `workspace`, in that order.
pub fn workspace_profile_names(workspace: &Path) -> Result<[String; 3], Denied> {
    containers::workspace_profile_names(workspace)
}

/// `%LOCALAPPDATA%\Packages\<name>`, the per-profile folder the OS creates
/// and the backend locks down.
pub fn package_folder(name: &str) -> Result<std::path::PathBuf, Denied> {
    containers::package_folder(name)
}

/// Delete the three AppContainer profiles of `workspace` and their package
/// folders, and drop them from the process-wide registry. Test fixtures
/// call this for disposable workspaces; production profiles are retained
/// forever, so the node never calls it.
pub fn forget_workspace_profiles(workspace: &Path) -> Result<(), Denied> {
    containers().forget(workspace)
}
