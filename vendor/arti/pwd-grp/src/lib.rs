#![cfg(unix)]
#![cfg_attr(
    all(test, feature = "test-with-lmock"),
    feature(allocator_api, vec_into_raw_parts)
)]
#![doc=include_str!("../README.md")]

// The code here has to deal with a large number of axes of
// repetion/variation:
//
//  * the fields within Passwd and within Group.
//    These are handled mostly via derive-adhoc.
//
//  * the *types* of the fields (and of the overall structures):
//    These are generally handled by traits such as TryConvertFrom,
//    FromLibc, and MockToLibc.
//
//  * public API: simple functions vs generic mockable interface.
//    This is mostly just written out twice.
//    But for get{,e,res}{uid,gid} there's `for_getid_wrappers!`
//
//  * public API: mock vs real lookups.
//    This is the MockablePwdGrpProvider (and SealedProvider)
//
//  * Internal mocks for testing, or use real libc (for testing unsafe)
//    This is the MockableLibc trait and its main definition/
//    impl in lmockable.rs`
//
//  * Different libc functions treated in the same way.
//    macro_rules macros in lmockable and with_lmocks.
//
//  * various Rust string types (Box<[u8]>, String, etc.)
//    In the public API this is handled by generics and SealedString.
//    Conversions are handled by TryConvertFrom, From/Into, TryFrom,
//    and so on.  The conversion code is generally made by
//    macro_rules macros in convert.rs.
//
//  * Lookup by id or name.
//    Generally written out both ways.
//
//  * passwd vs group:
//    The treatment varies on a case-by-case basis.
//
// This crate has quite some macro use.  This is because

use std::cmp;
use std::convert::{TryFrom, TryInto};
use std::ffi::{CStr, CString};
use std::fmt::Debug;
use std::io;
use std::io::ErrorKind::{InvalidData, InvalidInput, Other, OutOfMemory};
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::ptr::NonNull;

use libc::{c_char, c_int, c_long, size_t};
use libc::{gid_t, uid_t};

use derive_deftly::{define_derive_deftly, derive_deftly_adhoc, Deftly};
use pastey::paste;
use thiserror::Error;

#[macro_use]
mod conditional;
#[macro_use]
pub mod mock;
#[macro_use]
mod convert;
#[macro_use]
mod generic;
#[macro_use]
mod unsafe_;
#[macro_use]
mod lmockable;

#[cfg(test)]
#[macro_use]
mod test;

pub mod error;

mod private;

use convert::*;
use error::*;
use lmockable::*;
use private::*;
use unsafe_::*;

pub use generic::*;

type RawSafe = Box<[u8]>;

/// Local convenience alias.
///
/// We pun `uid_t` and `gid_t`, which will cause compilation failure
/// on any platform where they're not the same.
///
/// See also
/// <https://gitlab.torproject.org/tpo/core/rust-pwd-grp/-/issues/1>
type Id = libc::uid_t;

/// Documentation common to [`Passwd`] and [`Group`]
//
// TODO ideally we would somehow factor out all the other attributes.
// but I don't fancy generating these key structs with macro_rules!.
// Perhaps #[only_derive_adhoc]...
//
// Re the nonexhaustiveness technique, see the docs for NonExhaustive
macro_rules! common_docs { {} => { r"

Strings are represented as `S`, usually `String`.


This struct is non-exhaustive:
future versions of `pwd-grp` may add fields.
(For technical reasons this is done with a hidden field
called `__non_exhaustive`.
If you use this to bypass the restriction,
future minor updates to this crate may break your code.)

" } }

/// Information about a user in the password database
///
/// Equivalent to `struct passwd`: for full information on the
/// individual fields, see the manual pages for
/// [`getpwuid_r(3)`](https://man.freebsd.org/cgi/man.cgi?query=getpwuid&sektion=3)
/// and
/// [`passwd(5)`](https://man.freebsd.org/cgi/man.cgi?query=passwd&sektion=5)
/// on your favorite Unix-style operating system.
#[doc = common_docs!()]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Deftly)]
#[derive_deftly(TryConvertFrom, FromLibc, Lookup, Blank)]
#[cfg_attr(all(test, feature = "test-with-lmock"), derive_deftly(MockToLibc))]
#[deftly(abbrev = "pw")]
pub struct Passwd<S = String> {
    pub name: S,
    pub passwd: S,
    pub uid: Id,
    pub gid: Id,
    pub gecos: S,
    pub dir: S,
    pub shell: S,
    #[doc(hidden)]
    #[deftly(dummy)]
    #[cfg_attr(feature = "serde", serde(skip))]
    // See the doc comment for NonExhaustive
    pub __non_exhaustive: NonExhaustive,
}

/// Information about a group in the password database
///
/// Equivalent to `struct group`: for full information on
/// the individual fields, see the manual pages for
/// [`getgrgid_r(3)`](https://man7.org/linux/man-pages/man3/getgrgid.3.html)
/// and
/// [`group(5)`](https://man7.org/linux/man-pages/man5/group.5.html)
/// on your favorite Unix-style operating system.
#[doc = common_docs!()]
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Deftly)]
#[derive_deftly(TryConvertFrom, FromLibc, Lookup, Blank)]
#[cfg_attr(all(test, feature = "test-with-lmock"), derive_deftly(MockToLibc))]
#[deftly(abbrev = "gr")]
pub struct Group<S = String> {
    pub name: S,
    pub passwd: S,
    pub gid: Id,
    pub mem: Box<[S]>,
    #[doc(hidden)]
    #[deftly(dummy)]
    #[cfg_attr(feature = "serde", serde(skip))]
    // See the doc comment for NonExhaustive
    pub __non_exhaustive: NonExhaustive,
}

macro_rules! simple {
    {
        fn $getfoobar:ident($key:ident: $keytype:ty) -> $out:ty;
        $example_key:expr, $example_field:ident
    } => { paste!{
        /// Look up a
        #[doc = stringify!([< $out:lower >])]
        /// entry by
        #[doc = concat!(stringify!([< $key >]))]
        ///
        /// Returns `None` if the entry isn't found,
        /// or `Err` if an error occurred.
        ///
        /// If the entry contains strings that aren't valid UTF-8,
        /// this is treated as an error.
        /// If you need to handle non-UTF-8 password/group entries,
        /// use the generic trait methods on [`PwdGrp`].
        ///
        /// ### Example
        ///
        #[cfg_attr(target_os = "linux", doc = "```")]
        #[cfg_attr(not(target_os = "linux"), doc = "```no_run")]
        #[doc = concat!(
            "let entry = ",
            "pwd_grp::", stringify!($getfoobar),
            "(", stringify!($example_key), ")",
            ".unwrap().unwrap();"
        )]
        #[doc = concat!(
            "assert_eq!(entry.", stringify!($example_field),", 0);"
        )]
        /// ```
        pub fn $getfoobar(
            $key: $keytype,
        ) -> io::Result<Option<$out<String>>> {
            generic::PwdGrp.$getfoobar($key)
        }
    } };
}

simple! { fn getpwnam(name: impl AsRef<str>) -> Passwd;  "root", uid }
simple! { fn getpwuid(uid: Id) -> Passwd;                0,      uid }
simple! { fn getgrnam(name: impl AsRef<str>) -> Group;   "root", gid }
simple! { fn getgrgid(gid: Id) -> Group;                 0,      gid }

macro_rules! define_getid_simple { {
    $fn:ident: $id:ident. $field:ident, $doc:literal $( $real:literal )?
} => {
    define_getid_simple! { @ $fn: $id. Id, $doc }
}; {
    $fn:ident: $id:ident. ($( $f:ident )*), $doc:literal $( $real:literal )?
} => {
    define_getid_simple! { @ $fn: $id. (Id, Id, Id), $doc }
}; {
    @ $fn:ident: $id:ident. $ret:ty, $doc:literal
} => { paste!{
    /// Get the current process's
    #[doc = $doc]

    pub fn $fn() -> $ret {
        generic::PwdGrp.$fn()
    }
} } }

for_getid_wrappers! { define_getid_simple }

/// Get the current process's supplementary group list
///
/// Note that on some operating systems,
/// the output of this function contains the result of `gettegid()`,
/// and on some operating systems it does not.
/// If you are using this function,
/// you should should generally call `geteuid()` as well.
///
/// # Example
///
/// ```
/// let gg = pwd_grp::getgroups().unwrap();
/// println!("supplementary groups are: {:?}", gg);
/// ```
pub fn getgroups() -> io::Result<Vec<Id>> {
    PwdGrp.getgroups()
}

#[cfg(not(feature = "minimal-1"))]
compile_error! { "You must enable at least one pwd-grp crate feature!" }
