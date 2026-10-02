#![allow(clippy::field_reassign_with_default)]
//! EVX shared types.
//!
//! This crate is the dependency leaf the runtime plan calls `evx-api`: closed,
//! typed operations, limits, grants and the frames exchanged between the trusted
//! supervisor and its untrusted worker. It performs no I/O and knows nothing
//! about EpixNet sessions, UI commands or administrative IPC.
//!
//! Every value that can originate from a guest or a worker is parsed through
//! [`strict`], which rejects duplicate JSON keys, non-finite numbers and
//! unknown fields before any typed decoding happens.

pub mod broker;
pub mod frames;
pub mod grant;
pub mod limits;
pub mod result;
pub mod strict;

pub use broker::{Capability, Request, Response};
pub use grant::Grant;
pub use limits::Limits;
pub use result::{Observations, RunResult, Status};

/// Largest single IPC frame, in bytes, in either direction.
pub const MAX_FRAME: usize = 131_072;
/// Largest broker request a guest may submit, in bytes.
pub const MAX_REQUEST: usize = 8_192;
/// Largest broker response returned to a guest, in bytes.
pub const MAX_RESPONSE: usize = 4_096;
/// Largest module accepted for compilation, in bytes.
pub const MAX_MODULE: usize = 1_048_576;
/// Largest workspace file a guest may read or write through the broker.
pub const MAX_FILE: usize = 2_048;
/// Maximum entries (files plus directories) in one workspace.
pub const MAX_ENTRIES: usize = 128;

/// Errors shared across EVX crates for denied or malformed input.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Denied {
    #[error("{0}")]
    Reason(String),
}

impl Denied {
    pub fn new(reason: impl Into<String>) -> Self {
        Denied::Reason(reason.into())
    }
}

/// Identifier validation shared by xite names, publishers, capabilities and
/// occurrence keys: ASCII letters, digits, `_ . -`, 1 to 128 characters, no
/// leading punctuation.
pub fn validate_identifier(value: &str) -> Result<(), Denied> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return Err(Denied::new("invalid identifier length"));
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(Denied::new("identifier must start with a letter or digit"));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(Denied::new("identifier contains unsupported characters"));
    }
    Ok(())
}

/// Workspace-relative path validation.
///
/// Accepts at most eight components of at most 255 bytes each. Each component
/// must be NFC-stable ASCII or non-ASCII printable text without control
/// characters, must not be `.` or `..`, must not start with `..` (which covers
/// macOS `..namedfork`), must not start with the staging prefix `.pending-`,
/// and must not contain `\\`, `:` or NUL. Case and Unicode normalization
/// aliasing on case-insensitive filesystems is handled by rejecting any
/// component that is not already NFC and by treating comparisons as exact; the
/// broker never relies on two spellings being distinct files.
pub fn validate_relative_path(path: &str) -> Result<Vec<&str>, Denied> {
    if path.len() > 512 {
        return Err(Denied::new("invalid path"));
    }
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 8 {
        return Err(Denied::new("path outside workspace"));
    }
    for part in &parts {
        if part.is_empty() || *part == "." || *part == ".." || part.starts_with("..") {
            return Err(Denied::new("path outside workspace"));
        }
        if part.starts_with(".pending-") {
            return Err(Denied::new("path outside workspace"));
        }
        if part.len() > 255 {
            return Err(Denied::new("path outside workspace"));
        }
        if part
            .chars()
            .any(|c| c == '\\' || c == ':' || c == '\0' || c.is_control() || is_format_control(c))
        {
            return Err(Denied::new("path outside workspace"));
        }
    }
    Ok(parts)
}

/// Unicode format controls (category Cf) that can reorder or hide text in a
/// listing, such as U+202E RIGHT-TO-LEFT OVERRIDE and zero-width joiners.
pub fn is_format_control(c: char) -> bool {
    matches!(
        c as u32,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        assert!(validate_identifier("game-a").is_ok());
        assert!(validate_identifier("Game.Score_1").is_ok());
        assert!(validate_identifier("").is_err());
        assert!(validate_identifier("-x").is_err());
        assert!(validate_identifier("a b").is_err());
        assert!(validate_identifier(&"x".repeat(129)).is_err());
    }

    #[test]
    fn paths_accept_ordinary_names_and_reject_aliases() {
        assert!(validate_relative_path("state/presence.txt").is_ok());
        assert!(validate_relative_path("saves/é.txt").is_ok());
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "/x",
            "a//b",
            "a/./b",
            "a\\b",
            "a:b",
            "a\0b",
            "..namedfork",
            "x/..namedfork/rsrc",
            "...",
            "..x",
            ".pending-abc",
            "\u{202e}.txt",
            "a\u{7f}b",
            "a/b/c/d/e/f/g/h/i",
        ] {
            assert!(validate_relative_path(bad).is_err(), "accepted {bad:?}");
        }
        let long = "x".repeat(256);
        assert!(validate_relative_path(&long).is_err());
    }
}
