//! Unsafe internal

use super::*;
//use mock::*;

/// Byte buffer, that wes pass to `get*_r`
type ByteBuffer = Vec<MaybeUninit<c_char>>;

/// Lifetime token that represents validity of borrows, for C pointers
#[must_use]
pub(crate) struct ByteBufToken {}

/// Conversion from raw libc pointer output to safe Rust types
///
/// `Input` is typically a raw pointer, such as found in `struct passwd`.
///
/// `Self` is a safe, owned, Rust type.  Typically, `Raw` aka `Box<[u8]>`.
pub(crate) trait FromLibc<Input>: Sized {
    /// Converts `Input` to `Self`
    ///
    /// ### SAFETY
    ///
    /// Any raw pointers in `Input` are guaranteed to live
    /// (only) as long as `buffer_live`.
    unsafe fn from_libc(
        input: Input,
        buffer_live: &'_ ByteBufToken,
    ) -> Result<Self, io::Error>;
}

/// Closure parameter to `call_repeatedly_with_bigger_buffer`
///
/// ### SAFETY
///
/// The returned integer must have the semantics documented in `get*_r`.
/// The buffer is for passing to `get*_r`.
type InnerCall<'c> = &'c mut dyn FnMut(
    // The byte buffer, for passing to `get*_r`
    &mut [MaybeUninit<c_char>],
) -> c_int;

/// Closure parameter to `Passwd::lookup` and `Group::lookup`
///
/// The parameters are all for passing through to `get*_r`.
///
/// `L` is the libc type: `struct passwd` or `struct group`.
///
/// ### SAFETY
///
/// The returned integer must have the semantics documented in `get*_r`.
/// The arguments must be passed to `get*_r`.
pub(crate) type LookupCall<'c, L> = &'c mut dyn FnMut(
    // `grp` or `pwd`, the output struct buffer
    *mut L,
    // `result`, where the output pointer will be stored
    *mut *mut L,
    // `buffer` - the byte buffer
    *mut c_char,
    // `bufsize` - the byte buffer length
    size_t,
) -> c_int;

/// Repeatedly calls a `get_*r` function until the buffer is big enough
///
/// ### SAFETY
///
/// `sysconf` must be a reasonable value to pass to `sysconf(2)`
///  to enquire about the initial buffer size.
///
/// `call` must have the correct semantics, as described in `InnerCall`.
///
/// On `Ok` return `call` returned zero (no error).
///
/// The `ByteBufToken` is borrowed from `buffer`:
/// all the outputs written by `call` are valid at least that long.
pub(crate) fn call_repeatedly_with_bigger_buffer<'b>(
    mlibc: impl MockableLibc,
    buffer: &'b mut ByteBuffer,
    sysconf: c_int,
    call: InnerCall,
) -> Result<&'b ByteBufToken, io::Error> {
    let mut want_size: usize = cmp::max(
        unsafe { (mlibc.sysconf)(sysconf) }.try_into().unwrap_or(0),
        100,
    );
    loop {
        buffer.resize(want_size, MaybeUninit::uninit());

        let r = call(buffer);
        if r == 0 {
            return Ok(&ByteBufToken {});
        }
        if r != libc::ERANGE {
            return Err(io::Error::from_raw_os_error(r));
        }
        want_size = buffer
            .len()
            .checked_mul(2)
            .ok_or(TooLargeBufferRequiredError)?;
    }
}

impl FromLibc<Id> for Id {
    unsafe fn from_libc(
        input: Id,
        _: &ByteBufToken,
    ) -> Result<Self, io::Error> {
        Ok(input)
    }
}

impl FromLibc<*mut c_char> for RawSafe {
    unsafe fn from_libc(
        input: *mut c_char,
        _buffer_live: &ByteBufToken,
    ) -> Result<Self, io::Error> {
        let input: *const c_char = input as _;
        if input.is_null() {
            return Err(UnexpectedNullPointerError.into());
        }
        let input = CStr::from_ptr(input);
        Ok(input.to_bytes().into())
    }
}

/// For `group.gr_mem`, the list of group member names
impl FromLibc<*mut *mut c_char> for Box<[RawSafe]> {
    unsafe fn from_libc(
        input: *mut *mut c_char,
        buffer_live: &ByteBufToken,
    ) -> Result<Self, io::Error> {
        if input.is_null() {
            return Err(UnexpectedNullPointerError.into());
        }
        let pointers = (0..)
            .map(|offset| input.offset(offset).read())
            .take_while(|pointer| !pointer.is_null());

        let mut output = Vec::with_capacity(pointers.clone().count());
        for pointer in pointers {
            output.push(FromLibc::from_libc(pointer, buffer_live)?);
        }
        Ok(output.into())
    }
}

define_derive_deftly! {
    FromLibc for struct, expect items:

    impl FromLibc<NonNull<libc::${snake_case $tname}>>
        for $tname<RawSafe>
    {
        unsafe fn from_libc(
            // Eg, `struct passwd`
            input: NonNull<libc::${snake_case $tname}>,
            buffer_live: &ByteBufToken,
        ) -> Result<Self, io::Error> {
            let input = input.as_ref();
            // Construct the output by calling FromLibc::from_libc
            // on each field in `input`.
            let output = $tname { $( ${select1 fmeta(dummy) {
                $fname: NonExhaustive {}
            } else {
                $fname: {
                    let p = input
                        // Input fields are pw_* and gr_*
                        .${paste ${tmeta(abbrev) as str} _ $fname};

                    FromLibc::from_libc(p, buffer_live)?
                },
            }})};
            Ok(output)
        }
    }
}

define_derive_deftly! {
    Lookup for struct, expect items:

    impl $tname<RawSafe> {
        /// Perform a lookup and yield a safe Rust type containing `RawSafe`
        ///
        /// ### SAFETY
        ///
        /// `call` must match the description of `LookupCall`.
        fn lookup(
            mlibc: impl MockableLibc,
            call: LookupCall<libc::${snake_case $tname}>
        ) -> io::Result<Option<Self>> {
            #[allow(non_camel_case_types)]
            type libc_struct = libc::${snake_case $tname};

            let mut buffer = Default::default();
            let mut out_buf = MaybeUninit::<libc_struct>::uninit();
            let mut result = MaybeUninit::<*mut libc_struct>::uninit();

            // SAFETY
            // MaybeUninit is Copy! It's important that we don't move these,
            // or we could give get*_r pointers to the copies.
            let out_buf = &mut out_buf;
            let result = &mut result;

            // _SC_GET_PW_R_SIZE_MAX and ..._GR_...
            let sysconf = libc::
                ${paste _SC_GET
                        ${shouty_snake_case ${tmeta(abbrev) as str}}
                        _R_SIZE_MAX};

            let buffer_live = call_repeatedly_with_bigger_buffer(
                mlibc,
                &mut buffer,
                sysconf,
                &mut |buffer| {
                    // SAFETY
                    // We convert the borrows of `buffer` and so on into the
                    // arguments to `get*_r`.  Those functions don't care
                    // about initialised data.
                    let buffer_len = buffer.len();
                    let buffer: *mut MaybeUninit<c_char> = buffer.as_mut_ptr();
                    let buffer: *mut c_char = buffer as _;
                    call(
                        out_buf.as_mut_ptr(),
                        result.as_mut_ptr(),
                        buffer,
                        buffer_len,
                    )
                },
            )?;

            // SAFETY
            // `call_repeatedly_with_bigger_buffer` only returns Ok
            // if `call` returned zero, which means `get*_r*` returned zero
            // which means they did store the answer in `result`.
            // It might be a null pointer.
            let result: *mut libc_struct = unsafe { result.assume_init() };

            let result = match NonNull::new(result) {
                None => return Ok(None),
                Some(y) => y,
            };

            // SAFETY
            // `result` did come from `getpw*_r`, as above,
            // and it's all borrwed from `buffer` (as per buffer_live).
            let result: $tname<RawSafe> = unsafe {
                FromLibc::from_libc(result, buffer_live)
            }?;

            Ok(Some(result))
        }
    }
}

pub(crate) fn getpwnam_inner<ML: MockableLibc>(
    mlibc: ML,
    name: &[u8],
) -> io::Result<Option<Passwd<RawSafe>>> {
    let name = cstring_from(name)?;

    Passwd::lookup(mlibc, &mut |out_buf, result, buf, buflen| unsafe {
        (mlibc.getpwnam_r)(name.as_ptr() as _, out_buf, buf, buflen, result)
    })
}

pub(crate) fn getpwuid_inner<ML: MockableLibc>(
    mlibc: ML,
    uid: Id,
) -> io::Result<Option<Passwd<RawSafe>>> {
    Passwd::lookup(mlibc, &mut |out_buf, result, buf, buflen| unsafe {
        (mlibc.getpwuid_r)(uid, out_buf, buf, buflen, result)
    })
}

pub(crate) fn getgrnam_inner<ML: MockableLibc>(
    mlibc: ML,
    name: &[u8],
) -> io::Result<Option<Group<RawSafe>>> {
    let name = cstring_from(name)?;

    Group::lookup(mlibc, &mut |out_buf, result, buf, buflen| unsafe {
        (mlibc.getgrnam_r)(name.as_ptr() as _, out_buf, buf, buflen, result)
    })
}

pub(crate) fn getgrgid_inner<ML: MockableLibc>(
    mlibc: ML,
    gid: Id,
) -> io::Result<Option<Group<RawSafe>>> {
    Group::lookup(mlibc, &mut |out_buf, result, buf, buflen| unsafe {
        (mlibc.getgrgid_r)(gid, out_buf, buf, buflen, result)
    })
}

pub(crate) fn getgroups_inner(
    mlibc: impl MockableLibc,
) -> io::Result<Vec<Id>> {
    // This is a bit like call_repeatedly_with_bigger_buffer
    // but getgroups has a different calling convention to get*_r
    let overflow = |_| TooLargeBufferRequiredError;

    let mut want_size = 0;
    let mut buffer: Vec<Id> = vec![];
    loop {
        buffer.reserve(want_size);
        buffer.truncate(0);
        let r = unsafe {
            let size = buffer.capacity().try_into().map_err(overflow)?;
            let list: *mut Id = buffer.as_mut_ptr();
            (mlibc.getgroups)(size, list)
        };
        if r < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINVAL) {
                // We'll go around again asking what the length should be
                want_size = 0;
                continue;
            }
            return Err(error);
        }
        let r: usize = r.try_into().map_err(overflow)?;

        if r <= buffer.capacity() {
            unsafe { buffer.set_len(r) };
            return Ok(buffer);
        }

        // Now r > buffer.capcity(), we must go around and resze
        want_size = r;
    }
}

macro_rules! define_getid_unsafe { {
    $fn:ident: $id:ident. $f:ident, $doc:literal $( $real:literal )?
} => { paste!{
    #[inline]
    pub(crate) fn [<$fn _inner>](
        mlibc: impl MockableLibc,
    ) -> Id {
        // get{,r}{uid,gid} are defined to never fail
        // https://pubs.opengroup.org/onlinepubs/9699919799/functions/getuid.html
        unsafe { (mlibc.$fn)() }
    }
} }; {
    $fn:ident: $id:ident. ($( $f:ident )*), $doc:literal $( $real:literal )?
} => { paste!{
    #[inline]
    pub(crate) fn [<$fn _inner>](
        mlibc: impl MockableLibc,
    ) -> (Id, Id, Id) {
        let mut buf: (Id, Id, Id) = Default::default();

        let r = unsafe {
            (mlibc.$fn)(
                &mut buf.0,
                &mut buf.1,
                &mut buf.2,
            )
        };
        assert!(r == 0, "getres* failed!");

        buf
    }
} } }

for_getid_wrappers! { define_getid_unsafe }
