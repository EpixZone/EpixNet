//! Process confinement applied by the worker to itself before it reads input.
//!
//! Two layers. Hard resource limits through `setrlimit` are portable. The
//! operating-system sandbox is per platform behind [`apply`]; a platform
//! without an implementation fails closed, so a build for an unsupported
//! target cannot run a guest unconfined.
//!
//! macOS uses the Seatbelt profile language through the public, deprecated
//! `sandbox_init` entry point. Chromium and Firefox ship on the same
//! mechanism. The profile denies everything, then allows the dynamic loader's
//! system libraries, the binary itself, `/dev/null` and the random devices,
//! and optionally one workspace directory. Network, fork, exec, Mach lookups
//! and executable file mappings are denied explicitly because `(deny default)`
//! does not cover every one of those operations.

use std::path::Path;

/// What a mode needs from the filesystem. Everything else is denied.
///
/// The macOS and Linux profiles read the fields. Other platforms refuse to
/// run before looking at them, which `-D warnings` must not mistake for dead code.
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
pub struct Spec<'a> {
    /// Workspace the process may read, and write when `writable`.
    pub workspace: Option<&'a Path>,
    pub writable: bool,
}

/// Install hard, non-raisable process limits.
pub fn apply_rlimits(cpu_seconds: u64, open_files: u64) -> Result<(), String> {
    set_limit(libc::RLIMIT_CORE, 0)?;
    set_limit(libc::RLIMIT_CPU, cpu_seconds)?;
    set_limit(libc::RLIMIT_NOFILE, open_files)?;
    Ok(())
}

/// libc's rlimit resource constants are `c_int` on macOS and the unsigned
/// `__rlimit_resource_t` on Linux glibc; take whichever the platform uses.
#[cfg(target_os = "linux")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_os = "linux"))]
type RlimitResource = libc::c_int;

fn set_limit(kind: RlimitResource, value: u64) -> Result<(), String> {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain FFI with a valid out-pointer.
    if unsafe { libc::getrlimit(kind, &mut current) } != 0 {
        return Err("getrlimit failed".into());
    }
    let hard = if current.rlim_max == libc::RLIM_INFINITY {
        value as libc::rlim_t
    } else {
        std::cmp::min(value as libc::rlim_t, current.rlim_max)
    };
    let wanted = libc::rlimit {
        rlim_cur: hard,
        rlim_max: hard,
    };
    // SAFETY: plain FFI with a valid pointer.
    if unsafe { libc::setrlimit(kind, &wanted) } != 0 {
        return Err("setrlimit failed".into());
    }
    Ok(())
}

/// Apply the OS sandbox. Fails closed on platforms without an implementation.
pub fn apply(spec: &Spec<'_>) -> Result<(), String> {
    platform::apply(spec)
}

/// Require the inherited-worker signing profile before parsing any input.
/// The launch marker is a consistency check, not authentication. Signed bundle
/// validation and the service-owned pipe establish the transport authority.
#[cfg(all(target_os = "macos", feature = "apple-xpc"))]
pub fn verify_apple_inheritance() -> Result<(), String> {
    use std::ffi::{c_char, c_void};
    type Object = *const c_void;
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecTaskCreateFromSelf(allocator: Object) -> Object;
        fn SecTaskCopyValueForEntitlement(task: Object, name: Object, error: *mut Object)
            -> Object;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            allocator: Object,
            value: *const c_char,
            encoding: u32,
        ) -> Object;
        fn CFEqual(left: Object, right: Object) -> u8;
        fn CFRelease(value: Object);
        static kCFBooleanTrue: Object;
    }
    if std::env::var("EVX_APPLE_XPC_CHILD").as_deref() != Ok("1")
        || !evx_runtime::engine::backend_name().starts_with("pulley")
    {
        return Err("Apple worker requires its signed service launcher".into());
    }
    // SAFETY: the Security and CoreFoundation objects remain valid until their
    // matching releases. Entitlements are read from this process's signature.
    let valid = unsafe {
        let task = SecTaskCreateFromSelf(std::ptr::null());
        if task.is_null() {
            false
        } else {
            let mut valid = true;
            for name in [
                c"com.apple.security.app-sandbox",
                c"com.apple.security.inherit",
            ] {
                let key = CFStringCreateWithCString(std::ptr::null(), name.as_ptr(), 0x08000100);
                if key.is_null() {
                    valid = false;
                    break;
                }
                let value = SecTaskCopyValueForEntitlement(task, key, std::ptr::null_mut());
                CFRelease(key);
                valid &= !value.is_null() && CFEqual(value, kCFBooleanTrue) != 0;
                if !value.is_null() {
                    CFRelease(value);
                }
            }
            CFRelease(task);
            valid
        }
    };
    if !valid {
        return Err("Apple worker signing profile unavailable".into());
    }
    // RLIMIT_NPROC is not enforced for root. The inherited App Sandbox may
    // permit exec, but a compromised native worker must not create descendants
    // that outlive the directly owned PID and its wait4 accounting.
    if unsafe { libc::geteuid() } == 0 {
        return Err("Apple inherited workers cannot run as root".into());
    }
    set_limit(libc::RLIMIT_NPROC, 0)?;
    Ok(())
}

#[cfg(target_os = "macos")]
mod platform {
    use super::Spec;
    use std::ffi::{c_char, c_int, CString};
    use std::path::Path;

    extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(errorbuf: *mut c_char);
    }

    /// Quote a path for the profile language. Paths come from the trusted
    /// supervisor, but they are escaped regardless.
    fn quote(path: &Path) -> Result<String, String> {
        let text = path.to_str().ok_or("non-UTF-8 path")?;
        if text.chars().any(|c| c.is_control()) {
            return Err("control character in path".into());
        }
        let mut out = String::with_capacity(text.len() + 2);
        out.push('"');
        for c in text.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                other => out.push(other),
            }
        }
        out.push('"');
        Ok(out)
    }

    fn profile(spec: &Spec<'_>) -> Result<String, String> {
        let exe = std::env::current_exe().map_err(|_| "cannot resolve executable")?;
        let exe = std::fs::canonicalize(exe).map_err(|_| "cannot resolve executable")?;
        let mut lines = vec![
            "(version 1)".to_string(),
            "(deny default)".to_string(),
            // Not covered by (deny default).
            "(deny process-info*)".to_string(),
            "(deny nvram*)".to_string(),
            "(deny iokit-get-properties)".to_string(),
            "(deny file-map-executable)".to_string(),
            "(deny mach-lookup)".to_string(),
            "(deny mach-register)".to_string(),
            "(deny process-fork)".to_string(),
            "(deny process-exec)".to_string(),
            "(deny network*)".to_string(),
            // Dynamic loader and libSystem.
            r#"(allow file-read-metadata (subpath "/"))"#.to_string(),
            concat!(
                "(allow file-read* file-map-executable ",
                r#"(subpath "/usr/lib") (subpath "/System/Library/Frameworks") "#,
                r#"(subpath "/System/Library/PrivateFrameworks") "#,
                r#"(subpath "/System/Cryptexes/OS") (subpath "/System/Volumes/Preboot/Cryptexes/OS"))"#
            )
            .to_string(),
            format!("(allow file-read* (literal {}))", quote(&exe)?),
            r#"(allow file-read* (subpath "/private/var/db/timezone") (subpath "/usr/share/zoneinfo") (subpath "/usr/share/zoneinfo.default"))"#.to_string(),
            r#"(allow file-read-data (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))"#.to_string(),
            r#"(allow file-write-data (literal "/dev/null"))"#.to_string(),
            "(allow signal (target self))".to_string(),
            "(allow process-info-pidinfo (target self))".to_string(),
            "(allow process-info-setcontrol (target self))".to_string(),
            concat!(
                "(allow sysctl-read ",
                r#"(sysctl-name "hw.ncpu") (sysctl-name "hw.activecpu") (sysctl-name "hw.logicalcpu_max") "#,
                r#"(sysctl-name "hw.pagesize_compat") (sysctl-name "hw.pagesize") (sysctl-name "hw.memsize") "#,
                r#"(sysctl-name "kern.osrelease") (sysctl-name "kern.osversion") (sysctl-name "kern.maxfilesperproc") "#,
                r#"(sysctl-name "kern.usrstack64") (sysctl-name "kern.version") (sysctl-name-prefix "hw.optional."))"#
            )
            .to_string(),
        ];
        if let Some(workspace) = spec.workspace {
            let workspace =
                std::fs::canonicalize(workspace).map_err(|_| "cannot resolve workspace")?;
            let quoted = quote(&workspace)?;
            lines.push(format!("(allow file-read* (subpath {quoted}))"));
            if spec.writable {
                lines.push(format!("(allow file-write* (subpath {quoted}))"));
            }
        }
        Ok(lines.join("\n"))
    }

    pub fn apply(spec: &Spec<'_>) -> Result<(), String> {
        let text = profile(spec)?;
        let c_profile = CString::new(text).map_err(|_| "profile encoding")?;
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: `c_profile` is a valid NUL-terminated string that outlives the
        // call, and `error` is a valid out-pointer that we free with the
        // matching libsandbox function.
        let rc = unsafe { sandbox_init(c_profile.as_ptr(), 0, &mut error) };
        if rc != 0 {
            let message = if error.is_null() {
                "sandbox_init failed".to_string()
            } else {
                // SAFETY: libsandbox returned a NUL-terminated C string.
                let text = unsafe { std::ffi::CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned();
                unsafe { sandbox_free_error(error) };
                format!("sandbox_init failed: {text}")
            };
            return Err(message);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[path = "confine_linux.rs"]
mod platform;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::Spec;

    /// No containment implementation for this platform yet. Fail closed; the
    /// supervisor reports the refusal rather than running a guest unconfined.
    pub fn apply(_spec: &Spec<'_>) -> Result<(), String> {
        Err("OS confinement is not implemented for this platform; refusing to run".into())
    }
}
