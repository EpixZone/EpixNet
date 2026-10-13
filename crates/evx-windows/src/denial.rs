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

pub(crate) fn winsock_startup_denied(status: i32, catalog: io::Result<()>) -> io::Result<()> {
    // WSASYSCALLFAILURE alone is generic, not isolation evidence. Require the
    // independent access denial for the protocol catalog as well. The host
    // positively checks this same catalog and Winsock before launching probes.
    if status != 10107 {
        return Err(io::Error::other(format!(
            "unexpected Winsock initialization failure: {status}"
        )));
    }
    denied(catalog, "Winsock protocol catalog read")
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

    #[test]
    fn winsock_failure_requires_independent_catalog_access_denial() {
        let denied_catalog = || Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(winsock_startup_denied(10107, denied_catalog()).is_ok());
        assert!(winsock_startup_denied(10107, Ok(())).is_err());
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::OutOfMemory] {
            assert!(winsock_startup_denied(10107, Err(io::Error::from(kind))).is_err());
        }
        for status in [0, 8, 10091, 10092, 10106] {
            assert!(winsock_startup_denied(status, denied_catalog()).is_err());
        }
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
        assert_eq!(windows_sys::Win32::Networking::WinSock::WSASYSCALLFAILURE, 10107);
    }
}
