//! Linux confinement: Landlock filesystem authority plus an allowlist of
//! native system calls. Install while single threaded, before reading input.
//! Missing Landlock, seccomp, or an unrecognized architecture fails closed.

use super::Spec;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const WRITE_FILE: u64 = 1 << 1;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const TRUNCATE: u64 = 1 << 14;
// ABI 3 also mediates truncation, including O_RDONLY|O_TRUNC. Cross-directory
// rename/link stays forbidden. chmod, chown and device operations are absent
// from the syscall allowlist, including on kernels with newer ABIs.
const HANDLED_FS: u64 = (1 << 15) - 1;

#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
}
#[repr(C, packed)]
struct PathRule {
    allowed_access: u64,
    parent_fd: i32,
}

fn error(stage: &str) -> String {
    format!("{stage}: {}", std::io::Error::last_os_error())
}

fn drop_capabilities() -> Result<(), String> {
    // no_new_privs prevents gains through exec; it does not remove inherited
    // authority such as CAP_SYS_RESOURCE. A root-launched worker otherwise
    // can raise its hard resource limits through the permitted prlimit call.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(error("clear ambient capabilities"));
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // Linux capability ABI version 3 consists of two 32-bit data words.
    // This runs before any guest bytes or engine threads. The seccomp policy
    // then forbids capset, identity changes and exec, so rights cannot return.
    if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } != 0 {
        return Err(error("clear process capabilities"));
    }
    Ok(())
}

fn path_rule(ruleset: &OwnedFd, path: &Path, access: u64) -> Result<(), String> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "invalid sandbox path")?;
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(error("sandbox path open"));
    }
    // SAFETY: the syscall returned a new owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let rule = PathRule {
        allowed_access: access,
        parent_fd: fd.as_raw_fd(),
    };
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            1,
            &rule,
            0,
        )
    } < 0
    {
        return Err(error("Landlock path rule"));
    }
    Ok(())
}

fn filesystem(spec: &Spec<'_>) -> Result<(), String> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0,
            1,
        )
    };
    if abi < 3 {
        return Err(error("Landlock ABI 3 or newer required"));
    }
    let attr = Ruleset {
        handled_access_fs: HANDLED_FS,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if raw < 0 {
        return Err(error("Landlock ruleset"));
    }
    let ruleset = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    // Runtime assets only, no home, host data, keys, or served content.
    for path in ["/usr/lib", "/lib", "/lib64"] {
        let path = Path::new(path);
        if path.exists() {
            path_rule(&ruleset, path, READ_FILE | READ_DIR)?;
        }
    }
    for path in [
        "/dev/urandom",
        "/dev/random",
        "/proc/cpuinfo",
        "/proc/self/maps",
    ] {
        let path = Path::new(path);
        if path.exists() {
            path_rule(&ruleset, path, READ_FILE)?;
        }
    }
    path_rule(
        &ruleset,
        Path::new("/dev/null"),
        READ_FILE | WRITE_FILE | TRUNCATE,
    )?;
    if let Some(workspace) = spec.workspace {
        let mut access = READ_FILE | READ_DIR;
        if spec.writable {
            access |= WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG | TRUNCATE;
        }
        path_rule(&ruleset, workspace, access)?;
    }
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } < 0 {
        return Err(error("Landlock enforcement"));
    }
    Ok(())
}

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(k: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: 0x15,
        jt: yes,
        jf: no,
        k,
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn syscalls() -> Result<(), String> {
    const LOAD: u16 = 0x20;
    const RET: u16 = 0x06;
    const ALLOW: u32 = 0x7fff0000;
    const DENY: u32 = 0x00050000 | libc::EPERM as u32;
    let arch = if cfg!(target_arch = "x86_64") {
        0xc000003e
    } else {
        0xc00000b7
    };
    // seccomp_data: syscall number at 0, audit architecture at 4, args at 16.
    let mut code = vec![
        stmt(LOAD, 4),
        jump(arch, 1, 0),
        stmt(RET, 0x80000000),
        stmt(LOAD, 0),
    ];
    // glibc must fall back to clone so its flags can be inspected. clone3's
    // pointed-to structure cannot safely be inspected by seccomp BPF.
    code.extend([
        jump(libc::SYS_clone3 as u32, 0, 1),
        stmt(RET, 0x00050000 | libc::ENOSYS as u32),
    ]);
    // Allow only pthread-style clone with all shared-process flags. Fork,
    // vfork, new namespaces and separate process creation are denied.
    let required = (libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM) as u32;
    let allowed = required
        | (libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID
            | libc::CLONE_CHILD_SETTID) as u32;
    code.extend([
        jump(libc::SYS_clone as u32, 0, 11),
        stmt(LOAD, 20),
        jump(0, 1, 0),
        stmt(RET, DENY),
        stmt(LOAD, 16),
        stmt(0x54, !allowed),
        jump(0, 0, 4),
        stmt(LOAD, 16),
        stmt(0x54, required),
        jump(required, 0, 1),
        stmt(RET, ALLOW),
        stmt(RET, DENY),
        stmt(LOAD, 0),
    ]);
    // Thread signals may target only this process. General kill, ptrace,
    // process_vm_*, pidfd and all network/IPC APIs are absent.
    code.extend([
        jump(libc::SYS_tgkill as u32, 0, 4),
        stmt(LOAD, 16),
        jump(unsafe { libc::getpid() } as u32, 0, 1),
        stmt(RET, ALLOW),
        stmt(RET, DENY),
        stmt(LOAD, 0),
    ]);
    // Resource limits may only be queried or lowered for this child. Do not
    // let a compromised worker alter a same-user host process's limits.
    code.extend([
        jump(libc::SYS_prlimit64 as u32, 0, 5),
        stmt(LOAD, 16),
        jump(0, 2, 0),
        jump(unsafe { libc::getpid() } as u32, 1, 0),
        stmt(RET, DENY),
        stmt(RET, ALLOW),
        stmt(LOAD, 0),
    ]);
    // fcntl ownership, signal selection, leases and notifications can send
    // signals outside the process without kill/tgkill. Expose only ordinary
    // descriptor management, and never enable asynchronous signal delivery.
    let mut fcntl = vec![stmt(LOAD, 24)];
    for command in [
        libc::F_DUPFD,
        libc::F_DUPFD_CLOEXEC,
        libc::F_GETFD,
        libc::F_SETFD,
        libc::F_GETFL,
    ] {
        fcntl.extend([jump(command as u32, 0, 1), stmt(RET, ALLOW)]);
    }
    fcntl.extend([
        jump(libc::F_SETFL as u32, 1, 0),
        stmt(RET, DENY),
        stmt(LOAD, 32),
        stmt(0x54, libc::O_ASYNC as u32),
        jump(0, 0, 1),
        stmt(RET, ALLOW),
        stmt(RET, DENY),
    ]);
    code.push(jump(libc::SYS_fcntl as u32, 0, fcntl.len() as u8));
    code.extend(fcntl);
    code.push(stmt(LOAD, 0));
    let allowed_syscalls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_close,
        // Workspace traversal duplicates its already admitted directory
        // handle. Duplication cannot introduce a new file or socket handle.
        libc::SYS_dup,
        libc::SYS_lseek,
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_mremap,
        libc::SYS_brk,
        libc::SYS_membarrier,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getrandom,
        libc::SYS_uname,
        libc::SYS_getcwd,
        libc::SYS_getrusage,
        libc::SYS_pipe2,
        libc::SYS_ppoll,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    for number in allowed_syscalls {
        code.extend([jump(number as u32, 0, 1), stmt(RET, ALLOW)]);
    }
    code.push(stmt(RET, DENY));
    let prog = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) } != 0 {
        return Err(error("seccomp enforcement"));
    }
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn syscalls() -> Result<(), String> {
    Err("unsupported Linux sandbox architecture".into())
}

pub fn apply(spec: &Spec<'_>) -> Result<(), String> {
    // Both mechanisms are irrevocable and inherited by subsequently created
    // threads. The caller has not read input or started engine threads yet.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(error("no_new_privs"));
    }
    drop_capabilities()?;
    filesystem(spec)?;
    syscalls()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    static SIGNALLED: AtomicBool = AtomicBool::new(false);
    extern "C" fn caught(_: libc::c_int) {
        SIGNALLED.store(true, Ordering::SeqCst);
    }

    #[test]
    fn fcntl_cannot_signal_another_process() {
        const CHILD: &str = "EVX_SECCOMP_SIGNAL_FIXTURE";
        if let Ok(parent) = std::env::var(CHILD) {
            let parent: i32 = parent.parse().unwrap();
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            syscalls().unwrap();
            let mut pipe = [-1; 2];
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let flags = unsafe { libc::fcntl(pipe[0], libc::F_GETFL) };
            let owner = unsafe { libc::fcntl(pipe[0], libc::F_SETOWN, parent) };
            let async_io = unsafe {
                libc::fcntl(
                    pipe[0],
                    libc::F_SETFL,
                    flags | libc::O_ASYNC | libc::O_NONBLOCK,
                )
            };
            if owner == 0 && async_io == 0 {
                assert_eq!(unsafe { libc::write(pipe[1], b"x".as_ptr().cast(), 1) }, 1);
            }
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            assert_eq!(owner, -1, "pipe ownership must be denied");
            assert_eq!(async_io, -1, "O_ASYNC must be denied");
            return;
        }
        SIGNALLED.store(false, Ordering::SeqCst);
        let old = unsafe { libc::signal(libc::SIGIO, caught as *const () as libc::sighandler_t) };
        let name = std::thread::current().name().unwrap().to_string();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, std::process::id().to_string())
            .output()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        unsafe {
            libc::signal(libc::SIGIO, old);
        }
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !SIGNALLED.load(Ordering::SeqCst),
            "sandboxed child delivered SIGIO through async pipe ownership"
        );
    }
}

#[cfg(test)]
mod unavailable_tests {
    use super::*;
    #[test]
    fn missing_landlock_fails_closed() {
        let abi = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<u8>(),
                0,
                1,
            )
        };
        if abi >= 3 {
            return;
        }
        let error = apply(&Spec {
            workspace: None,
            writable: false,
        })
        .unwrap_err();
        assert!(
            error.contains("Landlock ABI 3 or newer required"),
            "{error}"
        );
    }
}
