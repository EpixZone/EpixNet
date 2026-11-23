//! Conversions and types (internal module)
//!
//! Mainly, this is implementations of `TryConvertFrom`.

use super::*;

//---------- conversions from the uninhabited NoError ----------

impl From<NoError> for io::Error {
    fn from(n: NoError) -> io::Error {
        match n {}
    }
}
impl From<NoError> for NonUtf8Error {
    fn from(n: NoError) -> NonUtf8Error {
        match n {}
    }
}

//---------- "string" type conversions - TryConvertFrom impls ----------

// Manual implementations

impl TryConvertFrom<Box<[u8]>> for String {
    type Error = NonUtf8Error;
    fn try_convert_from(v: Box<[u8]>, f: &str) -> Result<Self, Self::Error> {
        let v: Vec<u8> = v.into();
        let v = String::from_utf8(v)
            .map_err(|_| NonUtf8Error { field: f.into() })?;
        Ok(v)
    }
}
impl TryConvertFrom<Box<[u8]>> for Box<str> {
    type Error = NonUtf8Error;
    fn try_convert_from(v: Box<[u8]>, f: &str) -> Result<Self, Self::Error> {
        let v: String = TryConvertFrom::try_convert_from(v, f)?;
        Ok(v.into())
    }
}
impl TryConvertFrom<Box<str>> for Box<[u8]> {
    type Error = NoError;
    fn try_convert_from(v: Box<str>, _f: &str) -> Result<Self, Self::Error> {
        let v: String = v.into();
        let v = v.into_bytes();
        Ok(v.into())
    }
}

impl<T, U> TryConvertFrom<Box<[T]>> for Box<[U]>
where
    U: TryConvertFrom<T>,
{
    type Error = U::Error;
    fn try_convert_from(v: Box<[T]>, f: &str) -> Result<Self, Self::Error> {
        let v: Vec<_> = v.into();
        IntoIterator::into_iter(v)
            .map(|v| U::try_convert_from(v, f))
            .collect()
    }
}

// Conversions that can be derived by converting each field

define_derive_deftly! {
    /// Define `TryConvert` in terms of individual field conversions
    TryConvertFrom for struct, expect items:

    impl<T, S> TryConvertFrom<$tname<T>> for $tname<S>
    where S: TryConvertFrom<T>,
    {
        type Error = S::Error;
        fn try_convert_from(v: $tname<T>, _f: &str)
                            -> Result<Self, Self::Error>
        {
            Ok($tname { $( ${select1 fmeta(dummy) {
                $fname: NonExhaustive {},
            } else {
                $fname: TryConvertFrom::try_convert_from(
                    v.$fname,
                    stringify!(${paste ${tmeta(abbrev) as str} _ $fname}),
                )?,
            }}) })
        }
    }
}

// Infallible conversions that can use `Into`

macro_rules! impl_try_convert_from_via_into { { $T:ty, $U:ty } => {
    impl TryConvertFrom<$T> for $U {
        type Error = NoError;
        fn try_convert_from(v: $T, _f: &str) -> Result<Self, Self::Error> {
            Ok(v.into())
        }
    }
} }
macro_rules! impl_infallible_std_from_into { { $T:ty, $U:ty
                                               $(, via $VIA:ty )? } => {
    impl From<Passwd<$T>> for Passwd<$U> {
        fn from(v: Passwd<$T>) -> Passwd<$U> {
            $( let v: Passwd<$VIA> = v.into(); )?
            TryConvertFrom::try_convert_from(v, "")
                .unwrap_or_else(|e | match e { })
        }
    }

    impl From<Group<$T>> for Group<$U> {
        fn from(v: Group<$T>) -> Group<$U> {
            $( let v: Group<$VIA> = v.into(); )?
            TryConvertFrom::try_convert_from(v, "")
                .unwrap_or_else(|e | match e { })
        }
    }
} }
macro_rules! impl_infallible_conversions { { $T:ty, $U:ty } => {
    impl_try_convert_from_via_into!($T, $U);
    impl_infallible_std_from_into!($T, $U);
} }

impl_try_convert_from_via_into!(Id, Id);
impl_try_convert_from_via_into!(Box<[u8]>, Box<[u8]>);

impl_infallible_conversions!(Box<[u8]>, Vec<u8>); // make growable
impl_infallible_conversions!(Vec<u8>, Box<[u8]>); // make fixed-len
impl_infallible_conversions!(Box<str>, String); // make growable
impl_infallible_conversions!(String, Box<str>); // make fixed-len
impl_infallible_conversions!(String, Vec<u8>); // to bytes (growable)
impl_infallible_std_from_into!(Box<str>, Box<[u8]>); // to bytes (fixed)
impl_infallible_std_from_into!(String, Box<[u8]>, via Box<str>); // for mocks

// fallible From/Into between various Passwd and Group

macro_rules! impl_std_try_from_into { { $P:ident, $T:ty, $U:ty } => {
    impl TryFrom<$P<$T>> for $P<$U> {
        type Error = NonUtf8Error;
        fn try_from(v: $P<$T>) -> Result<$P<$U>, Self::Error> {
            let v: $P<RawSafe> = v.into();
            let v: $P<Box<str>> = TryConvertFrom::try_convert_from(v, "")?;
            Ok(v.into())
        }
    }
} }

impl_std_try_from_into!(Passwd, Vec<u8>, String); // growable
impl_std_try_from_into!(Passwd, Box<[u8]>, Box<str>); // fixed-len
impl_std_try_from_into!(Group, Vec<u8>, String); // growable
impl_std_try_from_into!(Group, Box<[u8]>, Box<str>); // fixed-len

//---------- helper types and functions ----------

pub(crate) fn handle_nul_in_name_as_io(e: NulError) -> io::Error {
    io::Error::new(InvalidInput, e)
}

pub(crate) fn cstring_from(name: &[u8]) -> io::Result<CString> {
    CString::new(name).map_err(handle_nul_in_name_as_io)
}
