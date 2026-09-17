//! Commands for the managed browser process and its owned Windows children.

use std::path::Path;
use std::process::Command;

#[derive(Clone, Copy)]
enum Platform {
    #[cfg(any(windows, test))]
    Windows,
    #[cfg(any(target_os = "macos", test))]
    Mac,
    #[cfg(any(all(unix, not(target_os = "macos")), test))]
    Linux,
}

/// Build the same fresh-instance command for initial launch and tray reopen.
pub fn browser_command(firefox: &Path, profile: &Path) -> Command {
    #[cfg(windows)]
    let platform = Platform::Windows;
    #[cfg(target_os = "macos")]
    let platform = Platform::Mac;
    #[cfg(all(unix, not(target_os = "macos")))]
    let platform = Platform::Linux;
    browser_command_for(platform, firefox, profile)
}

fn browser_command_for(platform: Platform, firefox: &Path, profile: &Path) -> Command {
    let mut command = Command::new(firefox);
    // The profile belongs to EpixNet. Skip the downgrade dialog if another
    // Firefox version touched it, and keep the instance isolated from the
    // user's other browser profiles.
    command
        .arg("--allow-downgrade")
        .arg("--profile")
        .arg(profile)
        .arg("--no-remote")
        .arg("--new-instance");
    match platform {
        #[cfg(any(windows, test))]
        Platform::Windows => {
            // Firefox's Windows launcher otherwise exits after spawning the
            // process that owns the windows, losing our process-tree handle.
            command.arg("--wait-for-browser");
        }
        #[cfg(any(target_os = "macos", test))]
        Platform::Mac => {}
        #[cfg(any(all(unix, not(target_os = "macos")), test))]
        Platform::Linux => {
            command.args(["--class", "EpixNet", "--name", "EpixNet"]);
        }
    }
    command
}

/// Stop the exact launcher we own and all of its descendants. Matching by
/// firefox.exe's image name or path could also close another user's profile.
#[cfg(windows)]
pub fn close_browser_tree(child: &mut std::process::Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    match taskkill_command(child.id()).status() {
        Ok(status) if status.success() => {}
        result => {
            eprintln!("· could not close the browser process tree: {result:?}");
            // Still reap the owned process if the OS utility is unavailable.
            let _ = child.kill();
        }
    }
    let _ = child.wait();
}

#[cfg(any(windows, test))]
fn taskkill_command(pid: u32) -> Command {
    let mut command = Command::new("taskkill.exe");
    // /F is needed for a windowless launcher, and /T includes the browser and
    // its content processes. Never broaden this to /IM firefox.exe.
    command
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: cleanup must not flash a console over the splash.
        command.creation_flags(0x08000000);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    fn args(command: &Command) -> Vec<&OsStr> {
        command.get_args().collect()
    }

    #[test]
    fn windows_launcher_must_stay_owned_until_the_browser_exits() {
        let command = browser_command_for(
            Platform::Windows,
            Path::new("Firefox Browser/firefox.exe"),
            Path::new("User Data/managed profile"),
        );
        assert!(
            command.get_args().any(|arg| arg == "--wait-for-browser"),
            "Windows launches a second browser process; the launcher must wait so tray and timeout cleanup retain ownership"
        );
        assert_eq!(command.get_program(), "Firefox Browser/firefox.exe");
        assert_eq!(args(&command)[2], "User Data/managed profile");
    }

    #[test]
    fn windows_cleanup_targets_only_the_owned_pid_and_its_descendants() {
        let command = taskkill_command(4123);
        assert_eq!(command.get_program(), "taskkill.exe");
        assert_eq!(args(&command), &["/PID", "4123", "/T", "/F"]);
    }

    #[test]
    fn native_platform_commands_preserve_profile_isolation_and_linux_window_identity() {
        for platform in [Platform::Mac, Platform::Linux] {
            let command = browser_command_for(platform, Path::new("firefox"), Path::new("profile"));
            let arguments = args(&command);
            assert_eq!(
                &arguments[..5],
                &[
                    "--allow-downgrade",
                    "--profile",
                    "profile",
                    "--no-remote",
                    "--new-instance"
                ]
            );
            assert!(!arguments.contains(&OsStr::new("--wait-for-browser")));
            if matches!(platform, Platform::Linux) {
                assert_eq!(
                    &arguments[5..],
                    &["--class", "EpixNet", "--name", "EpixNet"]
                );
            } else {
                assert_eq!(arguments.len(), 5);
            }
        }
        // Exercise the real host selection as well as the portable fixtures.
        assert_eq!(
            browser_command(Path::new("firefox"), Path::new("profile")).get_program(),
            "firefox"
        );
    }
}

#[cfg(windows)]
pub(crate) fn visible_windows(
    child: &mut std::process::Child,
) -> Vec<windows_sys::Win32::Foundation::HWND> {
    // Keep the launcher's process handle alive and reject a reaped PID before
    // consulting a snapshot. --wait-for-browser keeps Firefox's launcher alive.
    if !matches!(child.try_wait(), Ok(None)) {
        return Vec::new();
    }
    windows::visible_windows(child.id())
}

#[cfg(any(windows, test))]
fn owned_processes(root: u32, processes: &[(u32, u32)]) -> std::collections::HashSet<u32> {
    let mut owned = std::collections::HashSet::from([root]);
    loop {
        let count = owned.len();
        for &(pid, parent) in processes {
            if owned.contains(&parent) {
                owned.insert(pid);
            }
        }
        if owned.len() == count {
            return owned;
        }
    }
}

#[cfg(windows)]
mod windows {
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{CloseHandle, HWND, INVALID_HANDLE_VALUE, LPARAM};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible,
    };

    struct Windows {
        owned: std::collections::HashSet<u32>,
        windows: Vec<HWND>,
    }

    pub(super) fn visible_windows(root: u32) -> Vec<HWND> {
        // SAFETY: the snapshot is checked and closed on all paths. The OS only
        // writes into the correctly sized entry while the snapshot is open.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Vec::new();
            }
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            let mut processes = Vec::new();
            let mut found = Process32FirstW(snapshot, &mut entry);
            while found != 0 {
                processes.push((entry.th32ProcessID, entry.th32ParentProcessID));
                found = Process32NextW(snapshot, &mut entry);
            }
            CloseHandle(snapshot);
            let mut context = Windows {
                owned: super::owned_processes(root, &processes),
                windows: Vec::new(),
            };
            // EnumWindows is synchronous; context stays alive for every callback.
            EnumWindows(Some(collect_window), &mut context as *mut Windows as LPARAM);
            context.windows
        }
    }

    unsafe extern "system" fn collect_window(hwnd: HWND, data: LPARAM) -> BOOL {
        // SAFETY: data refers to the exclusive context for this enumeration.
        unsafe {
            if IsWindowVisible(hwnd) == 0 {
                return 1;
            }
            let context = &mut *(data as *mut Windows);
            let mut pid = 0;
            GetWindowThreadProcessId(hwnd, &mut pid);
            if !context.owned.contains(&pid) {
                return 1;
            }
            let mut class = [0u16; 64];
            let len = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
            if String::from_utf16_lossy(&class[..len.max(0) as usize]) == "MozillaWindowClass" {
                context.windows.push(hwnd);
            }
            1
        }
    }
}

#[cfg(test)]
mod ownership_tests {
    #[test]
    fn finds_out_of_order_descendants_and_excludes_unrelated_firefox() {
        let owned = super::owned_processes(10, &[(30, 20), (99, 1), (20, 10), (100, 99), (10, 1)]);
        assert_eq!(owned, std::collections::HashSet::from([10, 20, 30]));
    }

    #[test]
    fn malformed_parent_cycles_cannot_stall_enumeration() {
        assert_eq!(
            super::owned_processes(10, &[(10, 20), (20, 10), (99, 99)]),
            std::collections::HashSet::from([10, 20])
        );
    }
}
