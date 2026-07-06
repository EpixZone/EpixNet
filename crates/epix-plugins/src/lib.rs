//! `epix-plugins` - the standard EpixNet plugins as Rust structs.
//!
//! Each plugin implements [`epix_plugin::Plugin`], contributing WebSocket
//! commands and/or `/uimedia` client code. Register them on a
//! [`epix_plugin::PluginRegistry`] and the UI server picks up their commands and
//! media automatically.

pub mod beacon;
pub mod sidebar;

pub use beacon::BeaconPlugin;
pub use sidebar::SidebarPlugin;
