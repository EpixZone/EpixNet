//! Stamp the Epix icon onto the managed Firefox's windows (Windows only).
//!
//! The window/taskbar icon normally comes from firefox.exe's resources. We
//! deliberately don't patch Mozilla's binary: it is Authenticode-signed and
//! self-updating, so a resource edit would break the signature and the next
//! Firefox update would undo it anyway. Instead the launcher sets the icon on
//! Firefox's live top-level windows (`WM_SETICON`), re-applied on the tray's
//! once-a-second tick - windows the user opens later get it within a tick,
//! and a Firefox self-update can never revert it.
//!
//! Windows are matched by class (`MozillaWindowClass`) plus the owning
//! process's image path being our managed firefox.exe - not by the pid we
//! spawned: Firefox's "launcher process" exec-chains into a second
//! firefox.exe that owns the real windows, so the spawned pid never matches.
//! Path matching also leaves any separate Firefox the user runs untouched.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Shell::ExtractIconExW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowThreadProcessId, SendMessageTimeoutW, ICON_BIG,
    ICON_SMALL, SMTO_ABORTIFHUNG, WM_SETICON,
};

/// The big + small HICONs extracted from our own exe, whose resources carry
/// app.ico (embedded by winresource at build time) - so the icon needs no
/// separate file at runtime. Extracted once and kept for the process lifetime;
/// HICONs are USER handles, valid across processes in the same session, which
/// is what lets Firefox's windows display them. Stored as `isize` (the
/// handles' bit pattern) so the static is `Send + Sync`.
struct Icons {
    big: isize,
    small: isize,
}

fn icons() -> Option<&'static Icons> {
    static ICONS: OnceLock<Option<Icons>> = OnceLock::new();
    ICONS
        .get_or_init(|| {
            // Purely cosmetic: this only picks which icon to DISPLAY on the
            // browser window. No trust or security decision flows from it.
            // nosemgrep: rust.lang.security.current-exe.current-exe
            let exe = std::env::current_exe().ok()?;
            let mut wide: Vec<u16> = exe.as_os_str().encode_wide().collect();
            wide.push(0);
            let mut big = std::ptr::null_mut();
            let mut small = std::ptr::null_mut();
            // Index 0 = the exe's first icon group (our app icon).
            // SAFETY: `wide` is NUL-terminated and outlives the call; the two
            // out-pointers are valid for one HICON each, as `nicons` = 1 says.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let got = unsafe { ExtractIconExW(wide.as_ptr(), 0, &mut big, &mut small, 1) };
            (got > 0 && !big.is_null()).then(|| Icons {
                big: big as isize,
                small: (if small.is_null() { big } else { small }) as isize,
            })
        })
        .as_ref()
}

/// What the `EnumWindows` callback needs: which firefox.exe's windows to
/// stamp (lowercased full path), with what.
struct StampCtx {
    firefox: String,
    big: isize,
    small: isize,
}

/// Set the Epix icon on every top-level Mozilla window whose process runs the
/// given firefox.exe. Cheap enough to call every second; re-setting the same
/// icon is a visual no-op.
pub fn stamp_firefox_windows(firefox: &Path) {
    let Some(ic) = icons() else { return };
    // Canonicalize so junctions/symlinks compare equal to the resolved image
    // path the OS reports for the process; drop the \\?\ verbatim prefix
    // canonicalize adds, which QueryFullProcessImageNameW does not use.
    let canon = std::fs::canonicalize(firefox).unwrap_or_else(|_| firefox.to_path_buf());
    let mut path = canon.to_string_lossy().to_lowercase();
    if let Some(stripped) = path.strip_prefix(r"\\?\") {
        path = stripped.to_string();
    }
    let mut ctx = StampCtx { firefox: path, big: ic.big, small: ic.small };
    // SAFETY: `ctx` outlives the EnumWindows call (it is synchronous) and the
    // callback only reads it through the LPARAM for the call's duration.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        EnumWindows(Some(enum_cb), &mut ctx as *mut StampCtx as LPARAM);
    }
}

/// The full image path of a pid's executable, lowercased ("" when denied).
fn process_image_lower(pid: u32) -> String {
    // SAFETY: the handle is checked for null before use and closed on every
    // path; `len` starts as the buffer capacity and the OS writes back the
    // actual length, so the slice below stays in bounds.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        windows_sys::Win32::Foundation::CloseHandle(h);
        if ok == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..len as usize]).to_lowercase()
    }
}

unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let ctx = &*(lparam as *const StampCtx);
    // Only Firefox's real browser windows, not its helper/hidden windows.
    let mut class = [0u16; 64];
    let n = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
    let name = String::from_utf16_lossy(&class[..n.max(0) as usize]);
    if !name.starts_with("MozillaWindowClass") {
        return 1; // keep enumerating
    }
    let mut pid = 0u32;
    GetWindowThreadProcessId(hwnd, &mut pid);
    if pid == 0 || process_image_lower(pid) != ctx.firefox {
        return 1;
    }
    // SendMessageTimeout so a busy/hung Firefox can't wedge the tray loop.
    let mut out = 0usize;
    SendMessageTimeoutW(
        hwnd,
        WM_SETICON,
        ICON_SMALL as usize,
        ctx.small,
        SMTO_ABORTIFHUNG,
        200,
        &mut out,
    );
    SendMessageTimeoutW(
        hwnd,
        WM_SETICON,
        ICON_BIG as usize,
        ctx.big,
        SMTO_ABORTIFHUNG,
        200,
        &mut out,
    );
    1
}
