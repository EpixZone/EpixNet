use std::io;

pub(crate) fn denied<T>(result: io::Result<T>, operation: &str) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "{operation} failed without an access denial: {error}"
        ))),
        Ok(_) => Err(io::Error::other(format!(
            "{operation} unexpectedly succeeded"
        ))),
    }
}

pub(crate) fn descendant_denied<T>(result: io::Result<T>) -> io::Result<()> {
    // WinSDK ERROR_CHILD_PROCESS_BLOCKED. Rust's Windows decoder may classify
    // it as Uncategorized. This exception applies only to child creation.
    if matches!(&result, Err(error) if error.raw_os_error() == Some(367)) {
        return Ok(());
    }
    denied(result, "descendant creation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_policy_error_is_accepted_only_for_descendants() {
        assert!(descendant_denied::<()>(Err(io::Error::from_raw_os_error(367))).is_ok());
        assert!(denied::<()>(Err(io::Error::from_raw_os_error(367)), "file read").is_err());
        assert!(denied::<()>(Err(io::Error::from_raw_os_error(367)), "network").is_err());
    }

    #[test]
    fn unrelated_launch_failures_do_not_prove_isolation() {
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::TimedOut,
        ] {
            assert!(descendant_denied::<()>(Err(io::Error::from(kind))).is_err());
        }
        assert!(descendant_denied(Ok(())).is_err());
        assert!(
            descendant_denied::<()>(Err(io::Error::from(io::ErrorKind::PermissionDenied))).is_ok()
        );
    }

    #[cfg(windows)]
    #[test]
    fn sdk_and_rust_mapping_match_regression() {
        use windows_sys::Win32::Foundation::ERROR_CHILD_PROCESS_BLOCKED;
        assert_eq!(ERROR_CHILD_PROCESS_BLOCKED, 367);
        assert!(descendant_denied::<()>(Err(io::Error::from_raw_os_error(
            ERROR_CHILD_PROCESS_BLOCKED as i32
        )))
        .is_ok());
    }
}
