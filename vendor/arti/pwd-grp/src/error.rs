//! Error handling and error types
//!
//! Most of the interfaces return a [`std::io::Error`].
//! Usually an error means that the underlying `get*_r` call failed.
//!
//! But, there are some other obscure error cases.
//! In those situations, an [`io::Error`] will be returned
//! which has one of the errors in this module
//! as its [`source`](std::error::Error::source).

use super::*;

define_derive_deftly! {
    IntoIoError for struct, expect items:

    impl From<$ttype> for io::Error {
        fn from(us: $ttype) -> io::Error {
            io::Error::new(${tmeta(io_kind) as expr}, us)
        }
    }
}

/// Error that occurs if `getpw*_r` or `getgr*_r` return unexpected `NULL`s
///
/// This should not occur.
/// (But it doesn't seem to be entirely explicitly ruled out by the spec.)
///
/// (When the `source` of an `io::Error`, `ErrorKind` is [`Other`].)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
#[derive(Error)]
#[error("unexpected null pointer from getpw* or getgr*")]
#[derive(Deftly)]
#[derive_deftly(IntoIoError)]
#[deftly(io_kind = "Other")]
pub struct UnexpectedNullPointerError;

/// Error that occurs if an entry is unreasonably large
///
/// If a password or group entry is too large for the system's
/// address space, this error will be returned.
///
/// (When the `source` of an `io::Error`, `ErrorKind` is [`OutOfMemory`].)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
#[derive(Error)]
#[error(
    "getpw*_r or getgr*_r or getgroups required unreasonably large buffer"
)]
#[derive(Deftly)]
#[derive_deftly(IntoIoError)]
#[deftly(io_kind = "OutOfMemory")]
pub struct TooLargeBufferRequiredError;

/// Error that occurs if non-UTF-8 data is found
///
/// (When the `source` of an `io::Error`, `ErrorKind` is [`InvalidData`].)
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[non_exhaustive]
#[derive(Error)]
#[error(
    "non-UTF-8 data in system password or group database, in field {field}"
)]
#[derive(Deftly)]
#[derive_deftly(IntoIoError)]
#[deftly(io_kind = "InvalidData")]
pub struct NonUtf8Error {
    pub(crate) field: Box<str>,
}

impl NonUtf8Error {
    /// Return the libc field name that had non-UTF-8
    pub fn field(&self) -> &str {
        &self.field
    }
}

/// Error that occurs if a nul byte was passed to `get*_nam`
///
/// The C APIs do not permit nul bytes in names.
///
/// (When returned as the
/// (When the `source` of an `io::Error`, `ErrorKind` is [`InvalidInput`].)
pub type NulError = std::ffi::NulError;
