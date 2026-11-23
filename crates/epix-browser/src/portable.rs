//! Portable mode: a copy unzipped anywhere keeps everything in the `Data`
//! folder beside its launcher (see `epix_ui::paths::portable_data_root`).
//! Shell integration that would otherwise go to per-user folders stays in
//! that folder too: the local CA Firefox trusts and the native host manifest.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Record the portable data folder, as chosen at launch. It is the plain
/// absolute path (not the canonical `\\?\` form), which is what Firefox and
/// the registry are given.
pub fn enable(root: PathBuf) {
    let _ = ROOT.set(root);
}

/// The portable data folder, when this copy runs in portable mode.
pub fn root() -> Option<&'static Path> {
    ROOT.get().map(PathBuf::as_path)
}
