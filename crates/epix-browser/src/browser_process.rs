//! Commands for the managed browser process and its owned Windows children.

use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus};

/// Firefox dimensions in logical application pixels, not physical display pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrowserWindowSize {
    width: i32,
    height: i32,
}

impl BrowserWindowSize {
    #[cfg(any(target_os = "linux", test))]
    fn new(width: i32, height: i32) -> Option<Self> {
        (width > 0 && height > 0).then_some(Self { width, height })
    }
}

#[cfg(any(target_os = "linux", test))]
fn gamescope_desktop(desktop: &str) -> bool {
    desktop
        .split(':')
        .any(|name| name.eq_ignore_ascii_case("gamescope"))
}

/// Best-effort Gamescope sizing. Call on the main thread before starting an
/// async boot, or from the tray's main-thread fresh-open path. Return only
/// copied dimensions so no GTK object crosses into the async runtime.
#[cfg(target_os = "linux")]
pub fn gamescope_window_size() -> Option<BrowserWindowSize> {
    use gtk::gdk::prelude::*;

    if !gamescope_desktop(&std::env::var("XDG_CURRENT_DESKTOP").ok()?)
        || !crate::tray::display_available()
    {
        return None;
    }
    gtk::init().ok()?;
    let display = gtk::gdk::Display::default()?;
    let monitor = display.primary_monitor().or_else(|| display.monitor(0))?;
    // GDK geometry already uses logical pixels, including GDK_SCALE.
    let geometry = monitor.geometry();
    BrowserWindowSize::new(geometry.width(), geometry.height())
}

#[cfg(not(target_os = "linux"))]
pub fn gamescope_window_size() -> Option<BrowserWindowSize> {
    None
}

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
pub fn browser_command(
    firefox: &Path,
    profile: &Path,
    window_size: Option<BrowserWindowSize>,
) -> Command {
    #[cfg(windows)]
    let platform = Platform::Windows;
    #[cfg(target_os = "macos")]
    let platform = Platform::Mac;
    #[cfg(all(unix, not(target_os = "macos")))]
    let platform = Platform::Linux;
    browser_command_for(platform, firefox, profile, window_size)
}

// Only the Linux launch sizes the window; elsewhere the size is accepted and
// ignored, so the Windows and macOS builds stay warning-free.
#[cfg_attr(not(any(all(unix, not(target_os = "macos")), test)), allow(unused_variables))]
fn browser_command_for(
    platform: Platform,
    firefox: &Path,
    profile: &Path,
    window_size: Option<BrowserWindowSize>,
) -> Command {
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
            if let Some(size) = window_size {
                command.arg("--width").arg(size.width.to_string());
                command.arg("--height").arg(size.height.to_string());
            }
        }
    }
    command
}

/// The managed browser process.
///
/// Normally this is the Firefox the launcher spawned. Firefox can replace
/// itself: it exits, and its updater or its own restart starts a new Firefox on
/// the same profile. That Firefox is not a child of this launcher. On Windows
/// `try_wait` follows the browser to it, so the launcher still has a browser to
/// watch, raise and close. Elsewhere this is the spawned child and nothing more.
pub struct BrowserChild {
    process: Process,
    #[cfg(windows)]
    restart: windows::RestartSearch,
}

enum Process {
    Spawned(std::process::Child),
    #[cfg(windows)]
    Adopted(windows::Adopted),
}

impl BrowserChild {
    /// Own a Firefox started with [`browser_command`] on `profile`.
    pub fn spawned(child: std::process::Child, #[cfg_attr(not(windows), allow(unused))] profile: &Path) -> Self {
        Self {
            #[cfg(windows)]
            restart: windows::RestartSearch::new(&child, profile),
            process: Process::Spawned(child),
        }
    }

    /// The root of the browser's process tree.
    pub fn id(&self) -> u32 {
        match &self.process {
            Process::Spawned(child) => child.id(),
            #[cfg(windows)]
            Process::Adopted(process) => process.pid(),
        }
    }

    /// The exit status once the browser is gone. `None` while it runs, and on
    /// Windows also while it restarts itself or applies an update.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = match &mut self.process {
            Process::Spawned(child) => child.try_wait()?,
            #[cfg(windows)]
            Process::Adopted(process) => process.try_wait()?,
        };
        #[cfg(windows)]
        let status = status.and_then(|exit| self.follow_restart(exit));
        Ok(status)
    }

    /// Firefox hands over to its replacement with a clean exit. Look for that
    /// replacement before reporting the exit.
    #[cfg(windows)]
    fn follow_restart(&mut self, exit: ExitStatus) -> Option<ExitStatus> {
        // A crash or a kill is the end of the browser, not a restart.
        if !exit.success() {
            return Some(exit);
        }
        match self.restart.find() {
            windows::Restart::Browser(process) => {
                println!("· Epix Browser restarted itself; following it as process {}", process.pid());
                self.process = Process::Adopted(process);
                None
            }
            windows::Restart::Waiting => None,
            windows::Restart::None => Some(exit),
        }
    }

    pub fn kill(&mut self) -> io::Result<()> {
        match &mut self.process {
            Process::Spawned(child) => child.kill(),
            #[cfg(windows)]
            Process::Adopted(process) => process.kill(),
        }
    }

    /// Block until the current browser process exits. Unlike `try_wait` this
    /// does not follow a restart.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        match &mut self.process {
            Process::Spawned(child) => child.wait(),
            #[cfg(windows)]
            Process::Adopted(process) => process.wait(),
        }
    }
}

/// How a process newer than the browser relates to it.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// A Firefox running the managed profile.
    Browser,
    /// The managed Firefox started with no arguments. Firefox starts itself
    /// this way after an in-app restart and passes the profile through the
    /// environment. It is the browser only if the profile is then in use.
    Bare,
    /// Firefox's updater. It starts Firefox again when it is done.
    Updater,
}

/// Classify a process newer than the browser that just exited. `name` is its
/// lowercased executable name and `image` its lowercased image path.
/// `firefox` is the managed firefox.exe and `profile` the profile path, both
/// lowercased.
///
/// The profile path identifies this launcher's browser: Firefox's updater is
/// given Firefox's own arguments as the command to run afterwards. Firefox's
/// content, GPU and utility processes are not browsers; they all run with
/// `-contentproc`.
#[cfg(any(windows, test))]
fn restart_role(name: &str, image: &str, command_line: &str, firefox: &str, profile: &str) -> Option<Role> {
    let line = command_line.trim().to_lowercase();
    let on_profile = !profile.is_empty() && line.contains(profile);
    if name == "updater.exe" {
        return on_profile.then_some(Role::Updater);
    }
    if firefox.is_empty() || image != firefox || line.contains("-contentproc") {
        return None;
    }
    if on_profile {
        return Some(Role::Browser);
    }
    (line.trim_matches('"') == firefox).then_some(Role::Bare)
}

/// What became of a browser that exited cleanly.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum Successor {
    /// The pid at the root of the Firefox that replaced it.
    Browser(u32),
    /// The updater is still working. Firefox comes back when it finishes.
    Updating,
    /// A Firefox with no arguments is starting and has not taken the profile.
    Starting,
    None,
}

/// Pick the browser to follow from `(pid, parent pid, role)` candidates.
/// Firefox's launcher process starts the process that owns the windows with the
/// same arguments, so both match. The one whose parent is not itself a
/// candidate browser is the root, and stopping its tree stops them all.
/// `profile_in_use` says whether some Firefox holds the managed profile.
#[cfg(any(windows, test))]
fn successor(candidates: &[(u32, u32, Role)], profile_in_use: bool) -> Successor {
    let firefox = |role: Role| role != Role::Updater;
    let child = |parent: u32| candidates.iter().any(|&(pid, _, role)| pid == parent && firefox(role));
    let roots = |wanted: Role| {
        candidates
            .iter()
            .filter(move |&&(_, parent, role)| role == wanted && !child(parent))
            .map(|&(pid, _, _)| pid)
    };
    if let Some(pid) = roots(Role::Browser).next() {
        return Successor::Browser(pid);
    }
    // Without arguments the profile lock is the only evidence. Two such
    // Firefoxes cannot be told apart, so neither is followed.
    let mut bare = roots(Role::Bare);
    match (bare.next(), bare.next()) {
        (Some(pid), None) if profile_in_use => return Successor::Browser(pid),
        (Some(_), None) => return Successor::Starting,
        _ => {}
    }
    if candidates.iter().any(|&(_, _, role)| role == Role::Updater) {
        return Successor::Updating;
    }
    Successor::None
}

/// Stop the exact launcher we own and all of its descendants. Matching by
/// firefox.exe's image name or path could also close another user's profile.
#[cfg(windows)]
pub fn close_browser_tree(child: &mut BrowserChild) {
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
            None,
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
            let command =
                browser_command_for(platform, Path::new("firefox"), Path::new("profile"), None);
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
            browser_command(Path::new("firefox"), Path::new("profile"), None).get_program(),
            "firefox"
        );
    }

    #[test]
    fn gamescope_requires_an_exact_desktop_token() {
        for desktop in ["gamescope", "GAMESCOPE", "KDE:gamescope", "gamescope:GNOME"] {
            assert!(gamescope_desktop(desktop), "{desktop}");
        }
        for desktop in [
            "",
            "GNOME",
            "SteamDeck",
            "SteamTenfoot",
            "notgamescope",
            "gamescope-session",
            "KDE gamescope",
            " gamescope ",
        ] {
            assert!(!gamescope_desktop(desktop), "{desktop}");
        }
    }

    #[test]
    fn unavailable_monitor_dimensions_do_not_produce_a_window_size() {
        for (width, height) in [(0, 800), (1280, 0), (-1, 800), (1280, -1)] {
            assert_eq!(BrowserWindowSize::new(width, height), None);
        }
    }

    #[test]
    fn linux_size_arguments_preserve_logical_pixels_and_profile_flags() {
        for (width, height) in [(1280, 800), (960, 540)] {
            let mut command = browser_command_for(
                Platform::Linux,
                Path::new("Firefox Browser/firefox"),
                Path::new("User Data/managed profile"),
                BrowserWindowSize::new(width, height),
            );
            command.arg("https://dashboard.epix/");
            let arguments = args(&command);
            assert_eq!(
                &arguments[..9],
                &[
                    "--allow-downgrade",
                    "--profile",
                    "User Data/managed profile",
                    "--no-remote",
                    "--new-instance",
                    "--class",
                    "EpixNet",
                    "--name",
                    "EpixNet",
                ]
            );
            assert_eq!(arguments[9], "--width");
            assert_eq!(arguments[10], OsStr::new(&width.to_string()));
            assert_eq!(arguments[11], "--height");
            assert_eq!(arguments[12], OsStr::new(&height.to_string()));
            assert_eq!(arguments[13], "https://dashboard.epix/");
            assert_eq!(arguments.len(), 14);
        }
    }

    #[test]
    fn other_platforms_ignore_gamescope_dimensions() {
        for platform in [Platform::Windows, Platform::Mac] {
            let original =
                browser_command_for(platform, Path::new("firefox"), Path::new("profile"), None);
            let sized = browser_command_for(
                platform,
                Path::new("firefox"),
                Path::new("profile"),
                BrowserWindowSize::new(1280, 800),
            );
            assert_eq!(args(&sized), args(&original));
        }
    }
}

#[cfg(windows)]
pub(crate) fn visible_windows(
    child: &mut BrowserChild,
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
    use super::{restart_role, successor, Role, Successor};
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::os::windows::process::ExitStatusExt;
    use std::path::Path;
    use std::process::ExitStatus;
    use std::time::{Duration, Instant};
    use windows_sys::core::BOOL;
    use windows_sys::Win32::Foundation::{
        CloseHandle, FILETIME, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM, UNICODE_STRING,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
        TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible,
    };

    /// `PROCESSINFOCLASS` value that returns a process's command line as a
    /// `UNICODE_STRING` (Windows 8.1 and later).
    #[allow(non_upper_case_globals)]
    const ProcessCommandLineInformation: i32 = 60;

    // Declared here because the windows-sys `Wdk` features are not enabled
    // for this workspace.
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process: HANDLE,
            class: i32,
            information: *mut core::ffi::c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }

    /// How long Firefox's updater may run before the browser counts as gone.
    const UPDATE_LIMIT: Duration = Duration::from_secs(600);
    /// How long a restarted Firefox may take to claim the profile.
    const START_LIMIT: Duration = Duration::from_secs(20);
    /// `ERROR_SHARING_VIOLATION`.
    const SHARING_VIOLATION: i32 = 32;

    struct Windows {
        owned: std::collections::HashSet<u32>,
        windows: Vec<HWND>,
    }

    /// One running process: its pid, its parent's pid and its lowercased
    /// executable name.
    struct Running {
        pid: u32,
        parent: u32,
        name: String,
    }

    fn running() -> Vec<Running> {
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
                let name = &entry.szExeFile;
                let len = name.iter().position(|&unit| unit == 0).unwrap_or(name.len());
                processes.push(Running {
                    pid: entry.th32ProcessID,
                    parent: entry.th32ParentProcessID,
                    name: String::from_utf16_lossy(&name[..len]).to_lowercase(),
                });
                found = Process32NextW(snapshot, &mut entry);
            }
            CloseHandle(snapshot);
            processes
        }
    }

    pub(super) fn visible_windows(root: u32) -> Vec<HWND> {
        let processes: Vec<(u32, u32)> =
            running().iter().map(|process| (process.pid, process.parent)).collect();
        let mut context = Windows {
            owned: super::owned_processes(root, &processes),
            windows: Vec::new(),
        };
        // SAFETY: EnumWindows is synchronous; context stays alive for every
        // callback.
        unsafe {
            EnumWindows(Some(collect_window), &mut context as *mut Windows as LPARAM);
        }
        context.windows
    }

    /// A process's image path, lowercased. Empty when it cannot be read.
    fn image(process: HANDLE) -> String {
        let mut buffer = [0u16; 1024];
        let mut len = buffer.len() as u32;
        // SAFETY: `len` starts as the buffer capacity and the OS writes back
        // the length it stored, so the slice stays in bounds.
        let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut len) };
        if ok == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buffer[..len as usize]).to_lowercase()
    }

    /// When a process was created, in FILETIME ticks. `None` when unreadable.
    fn created(process: HANDLE) -> Option<u64> {
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: the four out pointers are distinct, valid FILETIMEs.
        let ok = unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
        (ok != 0).then(|| (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    /// A process's command line. `None` when it cannot be read.
    fn command_line(process: HANDLE) -> Option<String> {
        let mut needed = 0u32;
        // The first call only reports the size.
        // SAFETY: a null buffer of length zero is the documented size query.
        unsafe {
            NtQueryInformationProcess(process, ProcessCommandLineInformation, std::ptr::null_mut(), 0, &mut needed);
        }
        if (needed as usize) < std::mem::size_of::<UNICODE_STRING>() {
            return None;
        }
        // u64 storage keeps the UNICODE_STRING header aligned.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let capacity = (buffer.len() * 8) as u32;
        // SAFETY: the buffer is `capacity` bytes. On success the OS stored a
        // UNICODE_STRING at its start whose Buffer points at `Length` bytes of
        // UTF-16 inside the same allocation, which outlives the slice.
        unsafe {
            let status = NtQueryInformationProcess(
                process,
                ProcessCommandLineInformation,
                buffer.as_mut_ptr().cast(),
                capacity,
                &mut needed,
            );
            if status < 0 {
                return None;
            }
            let line = &*buffer.as_ptr().cast::<UNICODE_STRING>();
            if line.Buffer.is_null() {
                return None;
            }
            let units = std::slice::from_raw_parts(line.Buffer, usize::from(line.Length) / 2);
            Some(String::from_utf16_lossy(units))
        }
    }

    /// A Firefox this launcher follows but did not spawn. The handle keeps the
    /// process object alive, so its pid is not reused while this exists.
    pub(super) struct Adopted {
        handle: OwnedHandle,
        pid: u32,
    }

    impl Adopted {
        fn open(pid: u32) -> Option<Self> {
            let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE;
            // SAFETY: OpenProcess returns null or a handle this process owns.
            let handle = unsafe { OpenProcess(access, 0, pid) };
            if handle.is_null() {
                return None;
            }
            // SAFETY: the handle is valid, open, and owned by nothing else.
            let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
            Some(Self { handle, pid })
        }

        fn raw(&self) -> HANDLE {
            self.handle.as_raw_handle()
        }

        pub(super) fn pid(&self) -> u32 {
            self.pid
        }

        pub(super) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
            // SAFETY: the handle is open with SYNCHRONIZE access.
            match unsafe { WaitForSingleObject(self.raw(), 0) } {
                WAIT_OBJECT_0 => self.exit_status().map(Some),
                WAIT_TIMEOUT => Ok(None),
                _ => Err(io::Error::last_os_error()),
            }
        }

        pub(super) fn wait(&self) -> io::Result<ExitStatus> {
            // SAFETY: the handle is open with SYNCHRONIZE access.
            match unsafe { WaitForSingleObject(self.raw(), INFINITE) } {
                WAIT_OBJECT_0 => self.exit_status(),
                _ => Err(io::Error::last_os_error()),
            }
        }

        pub(super) fn kill(&self) -> io::Result<()> {
            // SAFETY: the handle is open with TERMINATE access.
            match unsafe { TerminateProcess(self.raw(), 1) } {
                0 => Err(io::Error::last_os_error()),
                _ => Ok(()),
            }
        }

        fn exit_status(&self) -> io::Result<ExitStatus> {
            let mut code = 0u32;
            // SAFETY: the handle is open with query access and `code` is valid.
            match unsafe { GetExitCodeProcess(self.raw(), &mut code) } {
                0 => Err(io::Error::last_os_error()),
                _ => Ok(ExitStatus::from_raw(code)),
            }
        }
    }

    pub(super) enum Restart {
        Browser(Adopted),
        Waiting,
        None,
    }

    /// Finds the Firefox that replaced the managed browser.
    pub(super) struct RestartSearch {
        /// The managed firefox.exe: its lowercased path and file name.
        image: String,
        exe: String,
        /// The lowercased profile path, as it appears on Firefox's command line.
        profile: String,
        /// Firefox holds this file open, unshared, while it uses the profile.
        lock: std::path::PathBuf,
        /// When the browser being followed was created. Its replacement is newer.
        born: u64,
        /// When the browser was first seen gone with its replacement not ready.
        waiting: Option<Instant>,
    }

    impl RestartSearch {
        pub(super) fn new(child: &std::process::Child, profile: &Path) -> Self {
            let process: HANDLE = child.as_raw_handle();
            let image = image(process);
            let exe = image.rsplit('\\').next().unwrap_or_default().to_string();
            Self {
                image,
                exe,
                profile: profile.to_string_lossy().to_lowercase(),
                lock: profile.join("parent.lock"),
                // An unreadable time must not make every process look newer.
                born: created(process).unwrap_or(u64::MAX),
                waiting: None,
            }
        }

        /// Look for the Firefox that took over from the browser that just
        /// exited: a newer process on the managed profile.
        pub(super) fn find(&mut self) -> Restart {
            let mut opened = Vec::new();
            for process in running() {
                if process.name != self.exe && process.name != "updater.exe" {
                    continue;
                }
                let Some(handle) = Adopted::open(process.pid) else { continue };
                let raw = handle.raw();
                // The pid may have been reused since the snapshot. Everything
                // below is read from the process the handle refers to.
                let Some(created) = created(raw).filter(|&created| created > self.born) else { continue };
                let Some(line) = command_line(raw) else { continue };
                if let Some(role) = restart_role(&process.name, &image(raw), &line, &self.image, &self.profile) {
                    opened.push((handle, process.parent, role, created));
                }
            }
            let candidates: Vec<(u32, u32, Role)> =
                opened.iter().map(|(handle, parent, role, _)| (handle.pid(), *parent, *role)).collect();
            let in_use = matches!(
                std::fs::File::open(&self.lock),
                Err(error) if error.raw_os_error() == Some(SHARING_VIOLATION)
            );
            let limit = match successor(&candidates, in_use) {
                Successor::Browser(pid) => {
                    let index = opened.iter().position(|(handle, ..)| handle.pid() == pid).expect("picked from these");
                    let (handle, _, _, created) = opened.swap_remove(index);
                    self.born = created;
                    self.waiting = None;
                    return Restart::Browser(handle);
                }
                Successor::Updating => UPDATE_LIMIT,
                Successor::Starting => START_LIMIT,
                Successor::None => return Restart::None,
            };
            let since = *self.waiting.get_or_insert_with(|| {
                println!("· Epix Browser is restarting itself; waiting for it to come back");
                Instant::now()
            });
            if since.elapsed() < limit {
                Restart::Waiting
            } else {
                Restart::None
            }
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

#[cfg(test)]
mod restart_tests {
    use super::{restart_role, successor, Role, Successor};

    const FIREFOX: &str = r"c:\epix\firefox\firefox.exe";
    const PROFILE: &str = r"c:\users\a b\appdata\roaming\epixnet\firefox-profile";

    fn firefox(command_line: &str) -> Option<Role> {
        restart_role("firefox.exe", FIREFOX, command_line, FIREFOX, PROFILE)
    }

    #[test]
    fn a_firefox_on_the_managed_profile_is_the_browser() {
        let line = r#""C:\Epix\firefox\firefox.exe" --allow-downgrade --profile "C:\Users\A B\AppData\Roaming\EpixNet\firefox-profile" --no-remote --new-instance --wait-for-browser https://dashboard.epix/"#;
        assert_eq!(firefox(line), Some(Role::Browser));
        // Another Firefox build is never the managed browser.
        let other = r"c:\program files\mozilla firefox\firefox.exe";
        assert_eq!(restart_role("firefox.exe", other, line, FIREFOX, PROFILE), None);
    }

    #[test]
    fn firefox_helper_processes_are_not_the_browser() {
        let line = r#""C:\Epix\firefox\firefox.exe" -contentproc -isForBrowser -prefsHandle 1:2 -profile "C:\Users\A B\AppData\Roaming\EpixNet\firefox-profile" 4 tab"#;
        assert_eq!(firefox(line), None);
    }

    #[test]
    fn a_firefox_on_another_profile_is_not_followed() {
        let line = r#""C:\Epix\firefox\firefox.exe" --profile "D:\Other\firefox-profile" --no-remote"#;
        assert_eq!(firefox(line), None);
        // An unknown profile path or image matches nothing, not everything.
        assert_eq!(restart_role("firefox.exe", FIREFOX, line, FIREFOX, ""), None);
        assert_eq!(restart_role("firefox.exe", "", "", "", PROFILE), None);
    }

    #[test]
    fn a_firefox_without_arguments_may_be_an_in_app_restart() {
        // Seen from Firefox 153.7.0esr after Services.startup.quit(eRestart).
        assert_eq!(firefox(r"C:\Epix\firefox\firefox.exe"), Some(Role::Bare));
        assert_eq!(firefox(r#""C:\Epix\firefox\firefox.exe" "#), Some(Role::Bare));
        assert_eq!(firefox(r"C:\Epix\firefox\firefox.exe --ProfileManager"), None);
    }

    #[test]
    fn the_updater_is_recognized_by_the_browser_it_will_restart() {
        // patch dir, install dir, apply-to dir, pid to wait for, then the
        // working directory and command line to run afterwards.
        let line = r#""C:\ProgramData\Mozilla\updates\ABC\updates\0\updater.exe" C:\ProgramData\Mozilla\updates\ABC\updates\0 C:\Epix\firefox C:\Epix\firefox\updated 4242/replace C:\Epix C:\Epix\firefox\firefox.exe --allow-downgrade --profile "C:\Users\A B\AppData\Roaming\EpixNet\firefox-profile" --no-remote --new-instance --wait-for-browser https://dashboard.epix/"#;
        let updater = r"c:\programdata\mozilla\updates\abc\updates\0\updater.exe";
        assert_eq!(restart_role("updater.exe", updater, line, FIREFOX, PROFILE), Some(Role::Updater));
        // Some other program's updater is not ours.
        assert_eq!(restart_role("updater.exe", updater, r#""C:\Other\updater.exe" --install"#, FIREFOX, PROFILE), None);
    }

    #[test]
    fn follows_the_root_of_the_restarted_browser() {
        // The updater (40) started Firefox's launcher process (50), which
        // started the process that owns the windows (60).
        let candidates = [(60, 50, Role::Browser), (40, 20, Role::Updater), (50, 40, Role::Browser)];
        assert_eq!(successor(&candidates, false), Successor::Browser(50));
    }

    #[test]
    fn waits_while_only_the_updater_is_running() {
        assert_eq!(successor(&[(40, 20, Role::Updater)], false), Successor::Updating);
    }

    #[test]
    fn a_firefox_without_arguments_is_followed_once_it_holds_the_profile() {
        let restarted = [(70, 20, Role::Bare)];
        assert_eq!(successor(&restarted, false), Successor::Starting);
        assert_eq!(successor(&restarted, true), Successor::Browser(70));
        // One on the profile's command line wins over one without arguments.
        assert_eq!(successor(&[(70, 20, Role::Bare), (80, 1, Role::Browser)], true), Successor::Browser(80));
        // Two without arguments cannot be told apart.
        assert_eq!(successor(&[(70, 20, Role::Bare), (71, 1, Role::Bare)], true), Successor::None);
    }

    #[test]
    fn a_browser_that_simply_closed_has_no_successor() {
        assert_eq!(successor(&[], false), Successor::None);
        // The lock alone, with no Firefox to follow, is not a successor.
        assert_eq!(successor(&[], true), Successor::None);
    }
}

/// Real processes stand in for Firefox. cmd.exe is the browser and a copy of
/// it named updater.exe is the updater. Each runs a script kept inside the
/// profile directory, so the profile path is on its command line as it is on
/// Firefox's.
#[cfg(all(test, windows))]
mod restart_process_tests {
    use super::{close_browser_tree, BrowserChild};
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    /// Start cmd.exe on a script beside the running one, without waiting.
    const START_BROWSER: &str = r#"start "" /b "%ComSpec%" /d /c "%~dp0running.cmd""#;

    fn cmd() -> PathBuf {
        PathBuf::from(std::env::var_os("ComSpec").expect("ComSpec names cmd.exe"))
    }

    /// A profile directory holding the stand-in scripts.
    fn profile(scripts: &[(&str, &str)]) -> tempfile::TempDir {
        let profile = tempfile::tempdir().unwrap();
        std::fs::write(profile.path().join("running.cmd"), "@ping -n 60 127.0.0.1 >nul\r\n").unwrap();
        for (name, body) in scripts {
            std::fs::write(profile.path().join(name), format!("@echo off\r\n{body}\r\n")).unwrap();
        }
        profile
    }

    /// Launch the browser stand-in on one of the profile's scripts.
    fn browser(profile: &Path, script: &str) -> BrowserChild {
        let child = Command::new(cmd())
            .args(["/d", "/c"])
            .arg(profile.join(script))
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        BrowserChild::spawned(child, profile)
    }

    /// Poll like the launcher does until the browser reports an exit.
    fn exit_within(child: &mut BrowserChild, limit: Duration) -> Option<ExitStatus> {
        let until = Instant::now() + limit;
        while Instant::now() < until {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// Poll until the browser is a different process than the one spawned.
    /// It must never report an exit on the way.
    fn followed_within(child: &mut BrowserChild, limit: Duration) -> Duration {
        let spawned = child.id();
        let started = Instant::now();
        while child.id() == spawned {
            assert!(started.elapsed() < limit, "the restarted browser was never followed");
            assert_eq!(child.try_wait().unwrap(), None, "a restart is not an exit");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(child.try_wait().unwrap(), None, "the restarted browser is running");
        started.elapsed()
    }

    #[test]
    fn a_browser_that_closes_is_reported_as_closed() {
        let profile = profile(&[("clean.cmd", "exit 0"), ("crash.cmd", "exit 7")]);
        let mut clean = browser(profile.path(), "clean.cmd");
        assert!(exit_within(&mut clean, Duration::from_secs(10)).unwrap().success());
        let mut crashed = browser(profile.path(), "crash.cmd");
        assert_eq!(exit_within(&mut crashed, Duration::from_secs(10)).unwrap().code(), Some(7));
    }

    #[test]
    fn follows_a_browser_that_restarts_itself() {
        // The first cmd.exe starts a second on the same profile and exits at
        // once, as Firefox does when it restarts.
        let profile = profile(&[("restart.cmd", START_BROWSER)]);
        let mut child = browser(profile.path(), "restart.cmd");
        followed_within(&mut child, Duration::from_secs(15));

        // Closing the browser now closes the one that took over.
        close_browser_tree(&mut child);
        assert!(exit_within(&mut child, Duration::from_secs(10)).is_some());
    }

    #[test]
    fn a_browser_restarted_on_another_profile_is_not_followed() {
        // The stand-in on the other profile outlives the check below, then
        // ends by itself.
        let other = profile(&[("running.cmd", "ping -n 6 127.0.0.1 >nul")]);
        let start_other = format!(
            r#"start "" /b "%ComSpec%" /d /c "{}""#,
            other.path().join("running.cmd").display()
        );
        let profile = profile(&[("elsewhere.cmd", &start_other)]);
        let mut child = browser(profile.path(), "elsewhere.cmd");
        let status = exit_within(&mut child, Duration::from_secs(3));
        assert!(status.is_some_and(|status| status.success()), "followed a browser on another profile");
    }

    /// One Marionette command: a length-prefixed JSON array. Returns the reply.
    fn marionette(stream: &mut std::net::TcpStream, id: u32, name: &str, params: &str) -> String {
        use std::io::Write;
        let message = format!(r#"[0,{id},"{name}",{params}]"#);
        stream.write_all(format!("{}:{message}", message.len()).as_bytes()).unwrap();
        marionette_read(stream)
    }

    fn marionette_read(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let mut len = String::new();
        let mut byte = [0u8];
        loop {
            stream.read_exact(&mut byte).unwrap();
            if byte[0] == b':' {
                break;
            }
            len.push(byte[0] as char);
        }
        let mut body = vec![0u8; len.parse().unwrap()];
        stream.read_exact(&mut body).unwrap();
        String::from_utf8(body).unwrap()
    }

    /// Run against the packaged Firefox:
    /// EPIX_TEST_FIREFOX=/path/to/firefox.exe cargo test -p epix-browser
    /// follows_a_real_firefox_restart -- --ignored
    #[test]
    #[ignore = "requires EPIX_TEST_FIREFOX and an interactive Windows desktop"]
    fn follows_a_real_firefox_restart() {
        let firefox = PathBuf::from(std::env::var_os("EPIX_TEST_FIREFOX").expect("set EPIX_TEST_FIREFOX"));
        let profile = tempfile::tempdir().unwrap();
        // Marionette is only the way to ask this Firefox to restart itself.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        std::fs::write(
            profile.path().join("user.js"),
            format!(
                "user_pref(\"browser.aboutwelcome.enabled\", false);\n\
                 user_pref(\"browser.shell.checkDefaultBrowser\", false);\n\
                 user_pref(\"toolkit.startup.max_resumed_crashes\", -1);\n\
                 user_pref(\"marionette.port\", {port});\n"
            ),
        )
        .unwrap();
        let spawned = super::browser_command(&firefox, profile.path(), None)
            .arg("--marionette")
            .arg("about:blank")
            .spawn()
            .unwrap();
        let mut child = BrowserChild::spawned(spawned, profile.path());
        let window_within = |child: &mut BrowserChild, limit: Duration| {
            let until = Instant::now() + limit;
            while super::visible_windows(child).is_empty() {
                assert!(Instant::now() < until, "no browser window");
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        window_within(&mut child, Duration::from_secs(60));

        let until = Instant::now() + Duration::from_secs(30);
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(stream) => break stream,
                Err(error) => assert!(Instant::now() < until, "Marionette: {error}"),
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        marionette_read(&mut stream);
        marionette(&mut stream, 1, "WebDriver:NewSession", "{}");
        let reply = marionette(&mut stream, 2, "Marionette:Quit", r#"{"flags":["eRestart"]}"#);
        assert!(reply.contains("restart"), "Firefox did not agree to restart: {reply}");

        // Firefox exits and starts itself again. That is not an exit.
        followed_within(&mut child, Duration::from_secs(60));
        window_within(&mut child, Duration::from_secs(60));

        // Closing the browser closes the Firefox that took over.
        close_browser_tree(&mut child);
        assert!(exit_within(&mut child, Duration::from_secs(20)).is_some());
    }

    #[test]
    fn waits_for_the_updater_then_follows_the_browser_it_starts() {
        let tools = tempfile::tempdir().unwrap();
        let updater = tools.path().join("updater.exe");
        std::fs::copy(cmd(), &updater).unwrap();
        // The browser starts the updater and exits. The updater works for two
        // seconds, starts the browser again on the same profile, and exits.
        let start_updater = format!(r#"start "" /b "{}" /d /c "%~dp0update.cmd""#, updater.display());
        let update = format!("ping -n 3 127.0.0.1 >nul\r\n{START_BROWSER}");
        let profile = profile(&[("apply.cmd", &start_updater), ("update.cmd", &update)]);
        let mut child = browser(profile.path(), "apply.cmd");
        let waited = followed_within(&mut child, Duration::from_secs(30));
        assert!(waited > Duration::from_secs(1), "followed before the updater finished: {waited:?}");

        close_browser_tree(&mut child);
        assert!(exit_within(&mut child, Duration::from_secs(10)).is_some());
    }
}
