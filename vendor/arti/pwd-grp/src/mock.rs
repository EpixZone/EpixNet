//! Mock provider of passwd/group data
//!
//! This affects **only the methods on [`PwdGrpProvider`]**,
//! not the plain functions in the `pwd-grp` crate toplevel.

use super::*;

use std::sync::{Arc, Mutex, MutexGuard};

/// Mock provider of passwd/group data
///
/// An implementor of [`PwdGrpProvider`]
/// which doesn't look at the real system databases.
///
/// The [`Default`] contains just dummy entries for `root`.
///
/// You can pre-program it with passwd and group data.
///
/// The mock provider has interior mutability,
/// so the trait can take non`-mut` references.
///
/// Note: this affects **only the methods on [`PwdGrpProvider`]**,
/// not the plain functions in the `pwd-grp` crate toplevel.
///
/// ### Example
///
/// ```
/// use pwd_grp::Group;
/// use pwd_grp::mock::MockPwdGrpProvider;
/// use pwd_grp::PwdGrpProvider as _;
///
/// let mock = MockPwdGrpProvider::new();
//
// What a palaver.  We can't just apply #[rustversion] to the asssert,
// since "custom attributes cannot be applied to statements"
// (rust-lang/rust/issues/54727, `#![feature(proc_macro_hygiene)]
/// # type M = MockPwdGrpProvider;
/// # #[rustversion::not(since(1.63))] fn gen_check(mock: &M) {}
/// # #[rustversion::since(1.63)] fn gen_check(mock: &M) {
//
/// assert_eq!(mock.getgrnam::<String>("root").unwrap().unwrap().gid, 0);
//
/// # }
/// # gen_check(&mock);
///
/// mock.add_to_groups([Group {
///     name: "wombats".to_string(),
///     passwd: "*".to_string(),
///     gid: 42,
///     mem: vec!["alice".to_string()].into(),
///     ..Group::blank()
/// }]);
/// let grent: Group = mock.getgrgid(42).unwrap().unwrap();
/// assert_eq!(grent.passwd, "*");
/// ```
#[derive(Debug, Clone, Default)]
pub struct MockPwdGrpProvider(Arc<Mutex<Data>>);

/// Real, effective and saved set-uid ids (uids or gids)
#[derive(
    Deftly, Debug, Clone, Copy, Default, Eq, PartialEq, Ord, PartialOrd, Hash,
)]
#[derive_deftly_adhoc]
pub struct RealEffectiveSavedIds {
    pub r: Id,
    pub e: Id,
    pub s: Id,
}

derive_deftly_adhoc! {
    RealEffectiveSavedIds:
    impl From<Id> for RealEffectiveSavedIds {
        fn from(id: Id) -> Self {
            RealEffectiveSavedIds {
                $( $fname: id, )
            }
        }
    }
}

/// Data
#[derive(Debug, Clone, Deftly)]
// Not really pub - not exported, needs to be here because
// it's part of SealedProvider
#[derive_deftly_adhoc]
pub(crate) struct Data {
    #[deftly(iter)]
    pub(crate) passwd: Vec<Passwd<RawSafe>>,
    #[deftly(iter)]
    pub(crate) group: Vec<Group<RawSafe>>,
    pub(crate) uids: RealEffectiveSavedIds,
    pub(crate) gids: RealEffectiveSavedIds,
    pub(crate) supplementary_groups: Vec<Id>,
}

impl Default for Data {
    fn default() -> Self {
        let s = |s: &str| s.to_string().into_bytes().into_boxed_slice();
        Data {
            passwd: vec![Passwd {
                name: s("root"),
                passwd: s("*"),
                uid: 0,
                gid: 0,
                gecos: s("root"),
                dir: s("/root"),
                shell: s("/bin/bash"),
                ..Passwd::blank()
            }],
            group: vec![Group {
                name: s("root"),
                passwd: s("x"),
                gid: 0,
                mem: vec![].into(),
                ..Group::blank()
            }],
            uids: 1000.into(),
            gids: 1000.into(),
            supplementary_groups: vec![],
        }
    }
}

impl From<Data> for MockPwdGrpProvider {
    fn from(data: Data) -> MockPwdGrpProvider {
        MockPwdGrpProvider(Arc::new(Mutex::new(data)))
    }
}

impl MockPwdGrpProvider {
    /// Create a new `MockPwdGrpProvider` containing dummy entries for `root`
    pub fn new() -> Self {
        MockPwdGrpProvider::default()
    }

    fn lock(&self) -> MutexGuard<'_, Data> {
        self.0.lock().expect("lock poisoned")
    }
}

impl SealedProvider for MockPwdGrpProvider {
    fn with_mocks<R>(&self, f: impl FnOnce(SealedData) -> R) -> Option<R> {
        Some(f(SealedData(&self.lock())))
    }
}
impl PwdGrpProvider for MockPwdGrpProvider {}

derive_deftly_adhoc! {
    Data expect items:

    impl MockPwdGrpProvider {

        /// Create a new empty `MockPwdGrpProvider`
        ///
        /// All lookups will return `None`
        pub fn new_empty() -> Self {
            Data {
                $( $fname: Default::default(), )
            }.into()
        }

        $( ${select1 fmeta(iter) {
            /// Append entries to the mock
            #[doc = stringify!($fname)]
            /// database
            pub fn ${paste add_to_ $fname s}<I>(
                &self,
                data: impl IntoIterator<Item=I>,
            )
            where I: Into<${pascal_case $fname}<RawSafe>>,
            {
                self.lock().$fname.extend(
                    data.into_iter().map(|ent| ent.into())
                )
            }

        } else {

            /// Set the mock
            #[doc = stringify!($fname)]
            pub fn ${paste set_ $fname}(
                &self,
                $fname: $ftype,
            ) {
                self.lock().$fname = $fname;
            }

        }} )
    }
}
