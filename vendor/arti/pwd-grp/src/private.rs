//! Internal types which are `pub` but not reachable - sealed
//!
//! "Private in public" rules mean all of this has to be `pub`
//!
//! But only `SealedString` is actually even shown publicly,
//! and even that isn't visible.

use super::*;

/// Types which are enough like `String` or `Vec<u8>` for us to work with
pub trait SealedString: Deref + TryConvertFrom<Box<[u8]>> {
    /// Get a `[u8]` (from the type's deref target)
    fn as_u8(s: &Self::Target) -> &[u8];

    /// Convert a conversion error into an `io::Error`
    fn handle_error_as_io(e: Self::Error) -> io::Error;
}

/// Like `TryFrom` but we have it for `[u]` to `str`
///
/// Implemented for various conversions between safe Rust string types.
///
/// (The raw libc pointers aren't handled by this -
/// they're in `unsafe_::Frolic`.)
pub trait TryConvertFrom<Input>: Sized {
    type Error: Sized // this + comment to avoid rustfmt deleting comments!!
        // TryConvertFrom derive needs this for infallible fields
        + From<NoError>
        // TryConvertFrom derive, needs this for error propagation;
        // the compiler can't see that this blanket impl exists unless
        // we explicitly demand it here.
        + From<Self::Error>
        // So we can wrap it in io::Error
        + std::error::Error
        + Send
        + Sync
        + 'static;
    fn try_convert_from(v: Input, f: &str) -> Result<Self, Self::Error>;
}

/// Error from infallible conversions
///
/// We must use our own type because (i) `Infallible` is hopeless
/// (ii) we want to
#[derive(Error, Debug)]
pub enum NoError {}

/// Marker type for the `__non_exhaustive` field in `Passwd` and `Groups`
///
/// We want to be able to add fields to [`Passwd`] and [`Group`]
/// without it being a semver break.
/// (Several Unix variants including MacOS have additional fields
/// which we might want to expose.)
///
/// We don't use `#[non_exhaustive]` because that prevents callers
/// from creating the struct with struct display syntax.
/// For the same reason, we must make the field `pub`.
///
/// The error message then refers to the field name,
/// so we have a note in the docs for each of the two structs.
///
/// Sadly, `NonExhaustive` must be `Default` for serde's benefit,
/// so although the user cannot name it, they could use `Default::default`
/// (but even if that weren't the case they could obtain one
/// from another `Passwd` or `Group`).
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct NonExhaustive {}

//---------- SealedDataProvider ----------

pub struct SealedData<'r>(pub(crate) &'r mock::Data);

pub trait SealedProvider {
    fn with_mocks<R>(&self, f: impl FnOnce(SealedData) -> R) -> Option<R>;
}

impl SealedProvider for generic::PwdGrp {
    #[inline]
    fn with_mocks<R>(&self, _: impl FnOnce(SealedData) -> R) -> Option<R> {
        None
    }
}

//---------- implementations of SealedString ----------

/// impl for `RawSafe`, our primary internal type
impl SealedString for Box<[u8]> {
    fn as_u8(s: &Self::Target) -> &[u8] {
        s
    }
    fn handle_error_as_io(e: Self::Error) -> io::Error {
        match e {}
    }
}

impl SealedString for String {
    fn as_u8(s: &Self::Target) -> &[u8] {
        s.as_bytes()
    }
    fn handle_error_as_io(e: Self::Error) -> io::Error {
        e.into()
    }
}
impl SealedString for Vec<u8> {
    fn as_u8(s: &Self::Target) -> &[u8] {
        s
    }
    fn handle_error_as_io(e: Self::Error) -> io::Error {
        match e {}
    }
}
impl SealedString for Box<str> {
    fn as_u8(s: &Self::Target) -> &[u8] {
        s.as_bytes()
    }
    fn handle_error_as_io(e: Self::Error) -> io::Error {
        e.into()
    }
}
