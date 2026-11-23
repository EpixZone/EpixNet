//! Test with mock versions of the libc
//!
//! This is a bit hairy at times.

use super::*;

use std::alloc::{AllocError, Allocator, Layout};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ffi::c_long;
use std::iter;
use std::ptr;
use std::rc::Rc;

use libc::ENOENT;

thread_local! {
    static INSTRUCTIONS: RefCell<MockInstructions> = Default::default();
}

#[derive(Default)]
struct MockInstructions {
    sysconf: c_long,
    late_error: Option<c_int>,
    supplementary_groups: VecDeque<Result<Vec<Id>, c_int>>,
}

fn name_to_id(name: *const c_char) -> Id {
    let name = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    if name == "root" {
        0
    } else {
        name.parse().unwrap()
    }
}

type TestResult = Result<Vec<u8>, io::ErrorKind>;
type TestData<P> = (TestResult, P);

fn ts(s: &[u8]) -> Vec<u8> {
    s.to_vec()
}
fn ti(id: Id) -> Vec<u8> {
    id.to_string().into_bytes()
}

fn join<I>(delim: u8, i: impl IntoIterator<Item = I>) -> Vec<u8>
where
    I: AsRef<[u8]>,
{
    i.into_iter()
        .zip(iter::once(&b""[..]).chain(iter::repeat(&[delim][..])))
        .fold(vec![], |mut b, (i, delim)| {
            b.extend_from_slice(delim);
            b.extend_from_slice(i.as_ref());
            b
        })
}

trait TestCase: Sized {
    type Output<S>: Eq + Debug
    where
        S: Eq + Debug;

    fn test_cases() -> Vec<TestData<Self>>;
    fn got_entry_elements(ent: &Self::Output<Box<[u8]>>) -> Vec<Vec<u8>>;
    fn try_into_string(
        ent: Self::Output<Box<[u8]>>,
    ) -> Result<Self::Output<String>, NonUtf8Error>;

    fn got_to_line(ent: &Self::Output<Box<[u8]>>) -> Vec<u8> {
        join(b':', Self::got_entry_elements(ent))
    }
}

impl TestCase for Passwd<Option<Vec<u8>>> {
    type Output<S>
        = Passwd<S>
    where
        S: Eq + Debug;

    fn try_into_string(
        ent: Passwd<Box<[u8]>>,
    ) -> Result<Passwd<String>, NonUtf8Error> {
        Passwd::<Vec<u8>>::from(ent).try_into()
    }

    fn test_cases() -> Vec<TestData<Self>> {
        vec![
            (
                Ok(b"root:*:0:0:root:/root:/bin/bash".to_vec()),
                Passwd {
                    name: Some("root".into()),
                    passwd: Some("*".into()),
                    uid: 0,
                    gid: 0,
                    gecos: Some("root".into()),
                    dir: Some("/root".into()),
                    shell: Some("/bin/bash".into()),
                    ..Passwd::blank()
                },
            ),
            (
                Ok(b"user:x:20:30:User:/home/user:/bin/sh".to_vec()),
                Passwd {
                    name: Some("user".into()),
                    passwd: Some("x".into()),
                    uid: 20,
                    gid: 30,
                    gecos: Some("User".into()),
                    dir: Some("/home/user".into()),
                    shell: Some("/bin/sh".into()),
                    ..Passwd::blank()
                },
            ),
            (
                Ok(b"user:x:20:30:User \x88 !:/home/user:/bin/sh".to_vec()),
                Passwd {
                    name: Some("user".into()),
                    passwd: Some("x".into()),
                    uid: 20,
                    gid: 30,
                    gecos: Some(b"User \x88 !".to_vec()),
                    dir: Some("/home/user".into()),
                    shell: Some("/bin/sh".into()),
                    ..Passwd::blank()
                },
            ),
        ]
    }

    fn got_entry_elements(ent: &Passwd<Box<[u8]>>) -> Vec<Vec<u8>> {
        vec![
            ts(&ent.name),
            ts(&ent.passwd),
            ti(ent.uid),
            ti(ent.gid),
            ts(&ent.gecos),
            ts(&ent.dir),
            ts(&ent.shell),
        ]
    }
}

impl TestCase for Group<Option<Vec<u8>>> {
    type Output<S>
        = Group<S>
    where
        S: Eq + Debug;

    fn try_into_string(
        ent: Self::Output<Box<[u8]>>,
    ) -> Result<Self::Output<String>, NonUtf8Error> {
        Group::<Vec<u8>>::from(ent).try_into()
    }

    fn test_cases() -> Vec<TestData<Self>> {
        vec![
            (
                Ok(b"root:x:0:".to_vec()),
                Group {
                    name: Some("root".into()),
                    passwd: Some("x".into()),
                    gid: 0,
                    mem: vec![].into(),
                    ..Group::blank()
                },
            ),
            (
                Ok(b"Debian-hippotat:x:128:ian,rustcargo".to_vec()),
                Group {
                    name: Some("Debian-hippotat".into()),
                    passwd: Some("x".into()),
                    gid: 128,
                    mem: vec![Some("ian".into()), Some("rustcargo".into())]
                        .into(),
                    ..Group::blank()
                },
            ),
            (
                Err(io::ErrorKind::Other),
                Group {
                    name: Some("Debian-hippotat".into()),
                    passwd: None,
                    gid: 128,
                    mem: vec![].into(),
                    ..Group::blank()
                },
            ),
        ]
    }
    fn got_entry_elements(ent: &Group<Box<[u8]>>) -> Vec<Vec<u8>> {
        vec![
            ts(&ent.name),
            ts(&ent.passwd),
            ti(ent.gid),
            join(b',', ent.mem.iter()),
        ]
    }
}

fn run_cases<TC: TestCase>(
    sysconf: c_long,
    getid_inner: impl Fn(
        MockedLibc,
        Id,
    ) -> io::Result<Option<TC::Output<Box<[u8]>>>>,
    getnam_inner: impl Fn(
        MockedLibc,
        &[u8],
    ) -> io::Result<Option<TC::Output<Box<[u8]>>>>,
) {
    INSTRUCTIONS.with(|insns| {
        *insns.borrow_mut() = MockInstructions {
            sysconf,
            ..Default::default()
        }
    });

    //---- process the list of test cases ----

    for (i, (exp, _case)) in TC::test_cases().into_iter().enumerate() {
        let got = getid_inner(MockedLibc, i as _)
            .transpose()
            .unwrap()
            .map_err(|e| e.kind());

        let got_line = got
            .as_ref()
            .map(|ent: &TC::Output<_>| TC::got_to_line(ent))
            .map_err(|e| *e);

        let show = |answer: &TestResult| {
            answer
                .as_ref()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .map_err(|e| *e)
        };

        eprintln!("got: {:?}", show(&got_line));
        eprintln!("exp: {:?}", show(&exp));

        assert_eq!(got_line, exp);

        // UTF-8 conversion
        if let Ok(got) = got {
            let exp = exp.unwrap();

            let got: Result<TC::Output<String>, _> = TC::try_into_string(got);
            let exp = String::from_utf8(exp);

            eprintln!("utf-8 got {got:?}");
            eprintln!("utf-8 exp {exp:?}");

            assert_eq!(got.is_err(), exp.is_err());
            if let Err(got) = &got {
                assert!(got.to_string().contains("pw_gecos"), "{:?}", got);
            }
        }
    }

    //---- Special cases ----

    // Look up by name
    let got = getnam_inner(MockedLibc, b"root");
    assert_eq!(
        &TC::got_to_line(&got.unwrap().unwrap()),
        TC::test_cases()[0].0.as_ref().unwrap()
    );

    // Nonexistent user
    assert_eq!(None, getid_inner(MockedLibc, 500).unwrap());
    assert_eq!(None, getnam_inner(MockedLibc, b"500").unwrap());

    // Return an error late on, after expanding buffer etc.
    INSTRUCTIONS.with(|insns| insns.borrow_mut().late_error = Some(ENOENT));
    let got = getid_inner(MockedLibc, 0);
    assert_eq!(got.unwrap_err().kind(), io::ErrorKind::NotFound);

    // Look up by name with nul
    let got = getnam_inner(MockedLibc, b"root\0");
    let got = got.unwrap_err();
    assert_eq!(got.kind(), io::ErrorKind::InvalidInput);
    assert!(got.to_string().contains("nul byte"), "{}: {:?}", got, got);
}

//---------- run test cases ----------

#[test]
fn run_tests() {
    for sysconf in (0..10).chain([20, 30, 50, 100, 1000, -1 as _]) {
        eprintln!("starting buffer {sysconf}");

        run_cases::<Passwd<_>>(sysconf, getpwuid_inner, getpwnam_inner);
        run_cases::<Group<_>>(sysconf, getgrgid_inner, getgrnam_inner);
    }
}

#[test]
fn uid_tests() {
    macro_rules! chk { { $id:ident } => { paste!{
        let ids = [<getres $id _inner>](MockedLibc);
        let r = [<get $id _inner>](MockedLibc);
        let e = [<gete $id _inner>](MockedLibc);
        eprintln!("{}s: {:?}", stringify!($id), ids);
        assert_eq!(ids.0, r);
        assert_eq!(ids.1, e);
    } } }
    chk!(uid);
    chk!(gid);
}

#[test]
fn getgroups_tests() {
    fn test_with_lengths(
        exp: Result<usize, c_int>,
        then_errno: Option<c_int>,
        lengths: impl IntoIterator<Item = usize> + Debug,
    ) {
        let mk_data =
            |length| (0..length).map(|v| (v + 100) as _).collect::<Vec<Id>>();

        eprintln!("\ngg {exp:?} {then_errno:?} {lengths:?}");
        let program: VecDeque<_> = lengths
            .into_iter()
            .map(|l| Ok(mk_data(l)))
            .chain(then_errno.map(Err))
            .collect();

        for p in &program {
            eprintln!("gg program {p:?}");
        }
        INSTRUCTIONS.with(|insns| {
            insns.borrow_mut().supplementary_groups = program;
        });

        let got = getgroups_inner(MockedLibc);
        eprintln!("gg got {got:?}");

        match (got, exp) {
            (Ok(got), Ok(exp)) => {
                let exp = mk_data(exp);
                assert_eq!(got, exp);
            }
            (Err(got), Err(exp)) => {
                assert_eq!(got.raw_os_error(), Some(exp));
            }
            _ => panic!("wrong!"),
        }
    }

    test_with_lengths(Ok(0), None, [0]);
    test_with_lengths(Ok(4), None, [4, 4]);
    test_with_lengths(Err(5), Some(5), []);
    test_with_lengths(Ok(0), None, [1, 0]);
    test_with_lengths(Ok(3), None, [1, 100, 3]);
    test_with_lengths(Err(5), Some(5), [1, 100]);
}

//---------- conversion of test case data to libc output ----------

pub(crate) trait MockToLibc {
    type Output;
    fn to_libc(&self, a: impl Allocator + Clone) -> Result<Self::Output, ()>;
}

trait Zero {
    fn zero() -> Self;
}
impl Zero for c_char {
    fn zero() -> Self {
        0
    }
}
impl<T> Zero for *mut T {
    fn zero() -> Self {
        ptr::null_mut()
    }
}

impl<T: MockToLibc> MockToLibc for [T]
where
    T::Output: Zero,
{
    type Output = *mut T::Output;
    fn to_libc(&self, a: impl Allocator + Clone) -> Result<Self::Output, ()> {
        let l = self.len();
        let mut buffer = Vec::new_in(a.clone());
        buffer.try_reserve_exact(l + 1).map_err(|_| ())?;
        for ent in self {
            buffer.push(T::to_libc(ent, a.clone())?);
        }
        buffer.push(T::Output::zero());
        let (p, _, _, _) = Vec::into_raw_parts_with_alloc(buffer);
        Ok(p)
    }
}

impl MockToLibc for Option<Vec<u8>> {
    type Output = *mut c_char;
    fn to_libc(&self, a: impl Allocator + Clone) -> Result<Self::Output, ()> {
        let Some(s) = self else {
            return Ok(ptr::null_mut());
        };
        s.to_libc(a)
    }
}

impl MockToLibc for u8 {
    type Output = c_char;
    fn to_libc(&self, _: impl Allocator + Clone) -> Result<c_char, ()> {
        Ok(*self as _)
    }
}

impl MockToLibc for Id {
    type Output = Id;
    fn to_libc(&self, _: impl Allocator + Clone) -> Result<Id, ()> {
        Ok(*self)
    }
}

define_derive_deftly! {
    MockToLibc:

    impl crate::test::with_lmock::MockToLibc for $tname<Option<Vec<u8>>> {
        type Output = libc::${snake_case $tname};
        fn to_libc(&self, a: impl std::alloc::Allocator + Clone)
                   -> Result<Self::Output, ()>
        {
            Ok(libc::${snake_case $tname} {
                $( ${when not(fmeta(dummy))}
                    ${paste ${tmeta(abbrev) as str} _ $fname}:
                        self.$fname.to_libc(a.clone())?,
                )
            })
        }
    }
}

//---------- buffer-based memory allocator ----------

struct BufferAllocator {
    buf: *mut u8,
    remaining: usize,
}
struct BufferAllocatorWrapper(Rc<RefCell<BufferAllocator>>);

impl BufferAllocator {
    fn take(&mut self, l: usize) -> Result<NonNull<[u8]>, AllocError> {
        let ret = NonNull::new(self.buf).ok_or(AllocError)?;
        self.remaining = self.remaining.checked_sub(l).ok_or(AllocError)?;
        self.buf = unsafe { self.buf.add(l) };
        Ok(NonNull::slice_from_raw_parts(ret, l))
    }
}

unsafe impl Allocator for &'_ BufferAllocatorWrapper {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let mut a = self.0.borrow_mut();
        let pad = a.buf.align_offset(layout.align());
        let _: NonNull<[u8]> = a.take(pad)?;
        a.take(layout.size())
    }

    unsafe fn deallocate(&self, _: NonNull<u8>, _: Layout) {}
}

impl BufferAllocator {
    #[allow(clippy::new_ret_no_self)]
    fn new(buffer: *mut c_char, bufsize: size_t) -> BufferAllocatorWrapper {
        let a = BufferAllocator {
            buf: buffer as _,
            remaining: bufsize,
        };
        BufferAllocatorWrapper(Rc::new(RefCell::new(a)))
    }
}

//---------- actual mock libc entrypoints ----------

macro_rules! lmock_impls { {
    $pw:ident, $uid:ident, $passwd:ident,
} => { paste!{
    pub(super) unsafe extern "C" fn [< lmock_get $pw nam_r >](
        name: *const c_char,
        ent: *mut libc::$passwd,
        buf: *mut c_char,
        buflen: size_t,
        result: *mut *mut libc::$passwd,
    ) -> c_int {
        [< lmock_get $pw $uid _r>](
            name_to_id(name),
            ent,
            buf,
            buflen,
            result,
        )
    }

    pub unsafe extern "C" fn [< lmock_get $pw $uid _r >](
        id: [< $uid _t >],
        ent_out: *mut libc::$passwd,
        buf: *mut c_char,
        buflen: size_t,
        result: *mut *mut libc::$passwd,
    ) -> c_int {
        if let Some(err) = id.checked_sub(1000) {
            return err as _;
        }

        let test_cases = [< $passwd:camel >]::test_cases();

        let Some(ent) = test_cases.get(id as usize) else {
            result.write(ptr::null_mut());
            return 0;
        };

        let a = BufferAllocator::new(buf, buflen);
        let Ok(ent) = ent.1.to_libc(&a) else { return libc::ERANGE; };
        ent_out.write(ent);
        result.write(ent_out);

        if let Some(late_error) = INSTRUCTIONS.with(
            |insns| insns.borrow().late_error
        ){
            result.write(ptr::null_mut());
            return late_error;
        }

        return 0;
    }
} } }

pub unsafe extern "C" fn lmock_sysconf(_name: c_int) -> c_long {
    INSTRUCTIONS.with(|insns| insns.borrow().sysconf)
}

derive_deftly_adhoc! {
    RealEffectiveSavedIds expect items:

    pub unsafe extern "C" fn lmock_getresuid($( $fname: *mut Id, )) -> c_int {
        let mut x = 10;
        $(
            x += 1;
            $fname.write(x);
        )
        0
    }
    pub unsafe extern "C" fn lmock_getresgid($( $fname: *mut Id, )) -> c_int {
        let mut x = 20;
        $(
            x += 1;
            $fname.write(x);
        )
        0
    }
    pub unsafe extern "C" fn lmock_getuid() -> uid_t { 11 }
    pub unsafe extern "C" fn lmock_geteuid() -> uid_t { 12 }
    pub unsafe extern "C" fn lmock_getgid() -> gid_t { 21 }
    pub unsafe extern "C" fn lmock_getegid() -> gid_t { 22 }
}

lmock_impls! { pw, uid, passwd, }
lmock_impls! { gr, gid, group, }

pub unsafe extern "C" fn lmock_getgroups(
    ngroups_max: c_int,
    groups: *mut gid_t,
) -> c_int {
    let fail = |e| unsafe {
        libc::__errno_location().write(e);
        -1
    };

    let this_time = INSTRUCTIONS.with(|insns| {
        insns.borrow_mut().supplementary_groups.pop_front().unwrap()
    });
    let this_time = match this_time {
        Ok(y) => y,
        Err(e) => return fail(e),
    };
    let out_slice: &mut [MaybeUninit<Id>] = unsafe {
        std::slice::from_raw_parts_mut(
            groups as *mut MaybeUninit<gid_t>,
            ngroups_max.try_into().unwrap(),
        )
    };
    if this_time.len() <= out_slice.len() {
        for i in 0..this_time.len() {
            out_slice[i].write(this_time[i]);
        }
    } else if ngroups_max != 0 {
        eprintln!("lmock_getgroups(.., {ngroups_max}) => EINVAL");
        return fail(libc::EINVAL);
    }

    let r = this_time.len().try_into().unwrap();
    eprintln!("lmock_getgroups(.., {ngroups_max}) => {r}");
    r
}

#[derive(Copy, Clone, Deftly)]
struct MockedLibc;

derive_deftly_adhoc! {
    MockableLibcFunctions expect items:

    impl Deref for MockedLibc {
        type Target = MockableLibcFunctions;
        fn deref(&self) -> &MockableLibcFunctions {
            static M: MockableLibcFunctions = MockableLibcFunctions {
                $(
                    $fname: ${paste lmock_ $fname},
                )
            };
            &M
        }
    }
}

impl MockableLibc for MockedLibc {}
