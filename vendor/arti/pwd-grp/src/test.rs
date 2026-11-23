use super::*;

#[test]
fn basic() {
    let pwent = getpwnam("root").unwrap().unwrap();
    assert_eq!(pwent.uid, 0);
}

#[cfg(feature = "test-with-lmock")]
#[macro_use]
pub(crate) mod with_lmock;
