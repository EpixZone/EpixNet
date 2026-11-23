//! Interface generic over returned string type, for non-UTF-8 etc.

use super::*;

/// Strings that can we can work with
///
/// Implemented for `String`, which is the usual case.
/// `Box<str>` is also useable.
///
/// If you want to work with non-unicode data
/// use `Box<[u8]>` or `Vec<u8>`.
pub trait PwdGrpString: SealedString + Deref {}

impl PwdGrpString for Box<str> {}
impl PwdGrpString for Box<[u8]> {}
impl PwdGrpString for String {}
impl PwdGrpString for Vec<u8> {}

impl PwdGrpProvider for PwdGrp {}

define_derive_deftly! {
    Blank for struct, expect items:

    impl<S: Default> $tname<S> {
        /// Make a new blank entry (useful for testing)
        ///
        /// All the contained strings and arrays are empty.
        /// The contained id(s) are zero.
        pub fn blank() -> Self {
            Self { $( ${select1 fmeta(dummy) {
                $fname: NonExhaustive {},
            } else {
                $fname: Default::default(),
            }})}
        }
    }
}

/// Provider of passwd and group information, from system databases
///
/// The actual functionality is provided by methods of
/// [`PwdGrpProvider`].
///
/// These are generic over the returned string type.
/// This enables working with non-UTF-8 data in passwd/group files,
/// and also with `Box<str>`.
/// If you just want to work with `String`,
/// use the plain functions in the [module toplevel](crate).
///
/// # Examples
///
/// ```
/// use pwd_grp::Passwd;
/// use pwd_grp::PwdGrpProvider as _;
/// use pwd_grp::PwdGrp;
///
/// let pwent: Passwd<Vec<u8>> = PwdGrp.getpwuid(0).unwrap().unwrap();
/// assert_eq!(pwent.uid, 0);
/// match std::str::from_utf8(&pwent.gecos) {
///     Ok(s) => println!("root user gecos: {}", s),
///     Err(_) => println!("root user gecos is not valid UTF-8"),
/// }
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
#[allow(clippy::exhaustive_structs)] // callers use the unit constructor
pub struct PwdGrp;

/// Define a generic entry point
macro_rules! define_generic_entrypoint {
    // Handle entrypoints with plain key type (Id)
    {
        fn $getfoobar:ident($key:ident: $keytype:ty) -> $out:ty;
    } => { define_generic_entrypoint! {
        fn $getfoobar($key: $keytype, $keytype; ) -> $out { }
    } };

    // Handle entrypoints which are strings (names)
    {
        fn $getfoobar:ident($key:ident) -> $out:ty;
    } => { define_generic_entrypoint! {
        fn $getfoobar(
            $key:
            impl AsRef<str>,
            impl AsRef<<S as Deref>::Target>;
            .as_ref()
        ) -> $out {
            let $key: &[u8] = <S as SealedString>::as_u8($key.as_ref());
        }
    } };

    // Actual implementation
    {
        fn $getfoobar:ident(
            $key:ident:
            $ktsim:ty,
            $ktgen:ty;
            $( $k_as_ref:tt )*
        ) -> $out:ty {
            $( $bind_key:tt )*
        }
    } => { paste!{
        /// Look up a
        #[doc = stringify!([< $out:lower >])]
        /// entry by
        #[doc = concat!(stringify!([< $key >]), ",")]
        /// returning strings as `S`
        fn $getfoobar<S: PwdGrpString>(
            &self,
            $key: $ktgen,
        ) -> io::Result<Option<$out<S>>> {
            $( $bind_key )*

            let value = {
                if let Some(mock) = self.with_mocks(|data| {
                    data.0.[< $out:lower >].iter().find(|ent| {
                        $key == ent.$key $( $k_as_ref )*
                    }).cloned().into()
                }) {
                    mock
                } else {
                    [< $getfoobar _inner >](RealLibc, $key)?
                }
            };

            value
                .map(|v| $out::<S>::try_convert_from(v, ""))
                .transpose()
                .map_err(<S as SealedString>::handle_error_as_io)
        }
    } };
}

macro_rules! define_getid_wrapper { {
    $fn:ident: $id:ident. $f:ident, $doc:literal $( $real:literal )?
} => { define_getid_wrapper! {
    @ $fn: $id, $doc $($real)?,
    Id,
    |mock: mock::RealEffectiveSavedIds| mock.$f,
} }; {
    $fn:ident: $id:ident. ($( $f:ident )*), $doc:literal $( $real:literal )?
} => { define_getid_wrapper! {
    @ $fn: $id, $doc $($real)?,
    (Id, Id, Id),
    |mock: mock::RealEffectiveSavedIds| ( $( mock.$f, )* ),
} }; {
    @ $fn:ident: $id:ident, $doc:literal $( $want_real_warn:literal )?,
    $ret:ty,
    $if_mock:expr,
} => { paste!{
    /// Get the current process's
    #[doc = $doc]
    ///
    /// This may be mocked,
    /// via [`mock::MockPwdGrpProvider`].
    #[doc = $doc]
    $(
        /// "Real" is the Unix technical term: ruid vs euid/suid/fsuid.
        #[doc = $want_real_warn]
    )?
    fn $fn(&self) -> $ret {
        match self.with_mocks(|data| data.0.[< $id s >]) {
            Some(mock) => ($if_mock)(mock),
            None => [<$fn _inner>](RealLibc),
        }
    }
} } }

macro_rules! for_getid_wrappers { { $call:ident } => {
    $call! { getuid: uid. r, "(real) uid" ""}
    $call! { geteuid: uid. e, "effective uid"}
 if_cfg_getresuid! {
    $call! { getresuid: uid. (r e s), "real, effective and saved set-uid" ""}
 }
    $call! { getgid: gid. r, "(real) gid" ""}
    $call! { getegid: gid. e, "effective gid"}
 if_cfg_getresuid! {
    $call! { getresgid: gid. (r e s), "real, effective and saved set-gid" ""}
 }
} }

/// Provider of passwd and group information.
///
/// Normally, use [`PwdGrp`].
///
/// This may be mocked,
/// via [`mock::MockPwdGrpProvider`].
pub trait PwdGrpProvider: SealedProvider {
    define_generic_entrypoint! { fn getpwnam(name) -> Passwd; }
    define_generic_entrypoint! { fn getpwuid(uid: Id) -> Passwd; }
    define_generic_entrypoint! { fn getgrnam(name) -> Group; }
    define_generic_entrypoint! { fn getgrgid(gid: Id) -> Group; }
    for_getid_wrappers! { define_getid_wrapper }

    /// Get the current process's supplementary group list
    fn getgroups(&self) -> io::Result<Vec<Id>> {
        if let Some(mock) =
            self.with_mocks(|data| data.0.supplementary_groups.clone())
        {
            return Ok(mock);
        }

        getgroups_inner(RealLibc)
    }
}
