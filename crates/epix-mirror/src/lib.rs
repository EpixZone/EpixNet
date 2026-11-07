//! Complete package snapshots carried by ordinary signed xites. Repository
//! signatures and checksums remain the native package manager's trust boundary.
mod catalog;
mod export;
mod filesystem;
pub mod formats;
mod server;
mod snapshot;
mod zip_bounds;

pub use catalog::{decode, encode, fresh, timestamp, Catalog, FileInfo};
pub use export::{export, node_origin, unpack, ExportOptions};
pub use filesystem::{open_regular, regular, safe_path};
pub use server::{checked_stream, Server};
pub use snapshot::{stage, validate, StageOptions};

pub const CATALOG: &str = "epix-mirror.json";
pub const MAX_FILES: usize = 60_000;
pub const MAX_BYTES: u64 = 15 * 1024 * 1024 * 1024;
pub const MAX_FILE: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_CATALOG: u64 = 8 * 1024 * 1024;
pub const MAX_ARCHIVE: u64 = 16 * 1024 * 1024 * 1024 + 64 * 1024 * 1024;
pub const CHUNK: usize = 128 * 1024;
