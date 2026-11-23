//! Define `MockableLibc` and implement it for `RealLibc`
//!
//! The output looks rather like this:
//!
//! ```text
//! trait MockableLibc: Copy + Deref<Target=MockableLibcFunctions> {}
//!
//! type LibcFn_getpwnam_r = unsafe extern "C" fn(...) -> c_int;
//!
//! struct MockableLibcFunctions {
//!     getpwnam_r: LibcFn_getpwnam_r,
//!    ..
//! }
//!
//! impl Deref for MockableLibc { ...
//!     ...
//!        static M = MockableLibcFunctions {
//!            getpwnam_r: libc::getpwnam_r,
//!        }
//! ```
//!
//! ### SAFETY
//!
//! This approach guarantees that the type and value of `mlibc.getpwnam_r`
//! are precisely those of `libc::getpwnam_r`.
//!
//! This is very important for the safety and correctness
//! of the implementation,
//! and also ensures that the tests with mocked libc are faithful.
//!
//! ### Alternative approaches
//!
//! We could have just had `getpwnam_inner` take
//! `mlibc: &'static MockableLibcFunctions`
//! but that might well result in a reified pointer.
//!
//! The present approach means the call site is monomorphised,
//! and hopefully the Deref and constant returned value are inlined
//! and vanish.

use super::*;

#[derive(Copy, Clone)]
pub(crate) struct RealLibc;

if_cfg_getresuid! {
  #[allow(non_camel_case_types)]
  pub(crate) type LibcFn_getresid<I> =
    unsafe extern "C" fn(ruid: *mut I, euid: *mut I, suid: *mut I) -> c_int;
}

#[allow(non_camel_case_types)]
pub(crate) type LibcFn_getgroups =
    unsafe extern "C" fn(ngroups_max: c_int, groups: *mut gid_t) -> c_int;

macro_rules! define_lmockable_type { {
    $function:ident, $passwd:ident, $key:ty
} => { paste!{
        #[allow(non_camel_case_types)]
        pub(crate) type [< LibcFn_ $function >] = unsafe extern "C" fn(
            $key,
            *mut libc::$passwd,
            *mut c_char,
            size_t,
            *mut *mut libc::$passwd,
        ) -> c_int;
} } }

define_lmockable_type!(getpwnam, passwd, *const c_char);
define_lmockable_type!(getpwuid, passwd, uid_t);
define_lmockable_type!(getgrnam, group, *const c_char);
define_lmockable_type!(getgrgid, group, gid_t);

#[derive(Deftly)]
#[derive_deftly_adhoc]
pub(crate) struct MockableLibcFunctions {
    pub(crate) sysconf: unsafe extern "C" fn(c_int) -> c_long,
    pub(crate) getuid: unsafe extern "C" fn() -> uid_t,
    pub(crate) geteuid: unsafe extern "C" fn() -> uid_t,
    pub(crate) getgid: unsafe extern "C" fn() -> gid_t,
    pub(crate) getegid: unsafe extern "C" fn() -> gid_t,
    // ought to be if_cfg_getresuid
    #[cfg(not(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "netbsd"
    )))]
    pub(crate) getresuid: LibcFn_getresid<uid_t>,
    // ought to be if_cfg_getresuid
    #[cfg(not(any(
        target_os = "macos",
        target_os = "tvos",
        target_os = "netbsd"
    )))]
    pub(crate) getresgid: LibcFn_getresid<gid_t>,
    pub(crate) getgroups: LibcFn_getgroups,
    pub(crate) getpwnam_r: LibcFn_getpwnam,
    pub(crate) getpwuid_r: LibcFn_getpwuid,
    pub(crate) getgrnam_r: LibcFn_getgrnam,
    pub(crate) getgrgid_r: LibcFn_getgrgid,
}

derive_deftly_adhoc! {
    MockableLibcFunctions expect items:

    impl Deref for RealLibc {
        type Target = MockableLibcFunctions;

        fn deref(&self) -> &MockableLibcFunctions {
            static M: MockableLibcFunctions = MockableLibcFunctions {
                $(
                    $fname: libc::$fname,
                )
            };
            &M
        }
    }
}

pub(crate) trait MockableLibc:
    Copy + Deref<Target = MockableLibcFunctions>
{
}

impl MockableLibc for RealLibc {}
