//! AppContainer profiles, managed through userenv loaded on demand.
use crate::handle::{fail, wide, SystemLibrary};
use crate::security::sid_text;
use std::{io, ptr::null};
use windows_sys::Win32::Security::{FreeSid, PSID, SID_AND_ATTRIBUTES};

type CreateProfile = unsafe extern "system" fn(
    *const u16,
    *const u16,
    *const u16,
    *const SID_AND_ATTRIBUTES,
    u32,
    *mut PSID,
) -> i32;
type DeriveSid = unsafe extern "system" fn(*const u16, *mut PSID) -> i32;
type DeleteProfile = unsafe extern "system" fn(*const u16) -> i32;

/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
const ALREADY_EXISTS: i32 = 0x800700B7_u32 as i32;

/// An AppContainer profile and its package SID.
///
/// Dropping a profile deletes it from the OS only when this object created
/// it and `retain` was not called. A profile that already existed is never
/// deleted by this object.
pub struct Profile {
    name: String,
    wide_name: Vec<u16>,
    sid: PSID,
    created: bool,
    retained: bool,
    delete: DeleteProfile,
    _library: SystemLibrary,
}

impl Profile {
    /// Create the profile `name` with `name` as display name and
    /// description, or adopt it if it already exists.
    pub fn create(name: &str) -> io::Result<Self> {
        let wide_name = wide(name)?;
        let library = userenv()?;
        // SAFETY: fixed exports from the system DLL with their Win32 ABI;
        // Profile retains the library until its deletion callback is finished.
        let create: CreateProfile =
            unsafe { std::mem::transmute(library.symbol(c"CreateAppContainerProfile")?) };
        let delete = delete_binding(&library)?;
        let mut sid = null_sid();
        let status = unsafe {
            create(
                wide_name.as_ptr(),
                wide_name.as_ptr(),
                wide_name.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        let created = match status {
            status if status >= 0 => true,
            ALREADY_EXISTS => {
                sid = derive_sid(&library, &wide_name)?;
                false
            }
            status => {
                return Err(fail(&format!(
                    "fresh AppContainer profile failed: 0x{:08x}",
                    status as u32
                )))
            }
        };
        Ok(Self {
            name: name.to_owned(),
            wide_name,
            sid,
            created,
            retained: false,
            delete,
            _library: library,
        })
    }
    /// The package SID. Valid while this object lives.
    pub fn sid(&self) -> PSID {
        self.sid
    }
    /// The package SID in SDDL text form.
    pub fn sid_text(&self) -> io::Result<String> {
        sid_text(self.sid)
    }
    /// The profile name.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Whether this object created the profile rather than adopting it.
    pub fn created(&self) -> bool {
        self.created
    }
    /// Keep the OS profile when this object drops.
    pub fn retain(&mut self) {
        self.retained = true;
    }
}

fn null_sid() -> PSID {
    std::ptr::null_mut()
}

/// Profile management belongs to the host. Loading userenv.dll in the LPAC
/// child can fail during DLL initialization before Rust runs.
fn userenv() -> io::Result<SystemLibrary> {
    SystemLibrary::open("userenv.dll")
}

fn delete_binding(library: &SystemLibrary) -> io::Result<DeleteProfile> {
    // SAFETY: fixed userenv export with its documented signature; every
    // caller keeps `library` loaded while the pointer is used.
    let delete: DeleteProfile =
        unsafe { std::mem::transmute(library.symbol(c"DeleteAppContainerProfile")?) };
    Ok(delete)
}

/// Delete the profile `name` and its package folder under
/// `%LOCALAPPDATA%\Packages`, whether or not this process created it. A
/// profile that does not exist is not an error. Production profiles are
/// retained forever; this is for test fixtures and operator cleanup.
pub fn delete_profile(name: &str) -> io::Result<()> {
    let wide_name = wide(name)?;
    let library = userenv()?;
    let delete = delete_binding(&library)?;
    // SAFETY: the name is NUL-terminated and the library stays loaded.
    let status = unsafe { delete(wide_name.as_ptr()) };
    if status < 0 {
        return Err(fail(&format!(
            "AppContainer profile deletion failed: 0x{:08x}",
            status as u32
        )));
    }
    Ok(())
}

fn derive_sid(library: &SystemLibrary, wide_name: &[u16]) -> io::Result<PSID> {
    // SAFETY: fixed userenv export with its documented signature; the library
    // stays loaded for the call.
    let derive: DeriveSid = unsafe {
        std::mem::transmute(library.symbol(c"DeriveAppContainerSidFromAppContainerName")?)
    };
    let mut sid = null_sid();
    let status = unsafe { derive(wide_name.as_ptr(), &mut sid) };
    if status < 0 || sid.is_null() {
        return Err(fail(&format!(
            "existing AppContainer profile SID unavailable: 0x{:08x}",
            status as u32
        )));
    }
    Ok(sid)
}

impl Drop for Profile {
    fn drop(&mut self) {
        // SAFETY: the name is NUL-terminated, the library is still loaded and
        // the SID came from userenv, which documents FreeSid for it.
        unsafe {
            if self.created && !self.retained {
                (self.delete)(self.wide_name.as_ptr());
            }
            FreeSid(self.sid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_profile_is_adopted_not_deleted() {
        let name = format!("Epix.EvxNativeTest.{}", std::process::id());
        let first = Profile::create(&name).unwrap();
        assert!(first.created());
        assert_eq!(first.name(), name);
        let package = first.sid_text().unwrap();
        assert!(package.starts_with("S-1-15-2-"), "{package}");
        let second = Profile::create(&name).unwrap();
        assert!(!second.created());
        assert_eq!(second.sid_text().unwrap(), package);
        drop(second);
        // The adopted object did not delete the profile: creating again still reports it.
        let third = Profile::create(&name).unwrap();
        assert!(!third.created());
        drop(third);
        drop(first);
        let fresh = Profile::create(&name).unwrap();
        assert!(fresh.created());
    }

    #[test]
    fn delete_profile_removes_a_retained_profile_and_tolerates_absence() {
        let name = format!("Epix.EvxNativeDelete.{}", std::process::id());
        let mut profile = Profile::create(&name).unwrap();
        profile.retain();
        drop(profile);
        // Retained: adoption still finds it.
        assert!(!Profile::create(&name).unwrap().created());
        delete_profile(&name).unwrap();
        delete_profile(&name).unwrap();
        let fresh = Profile::create(&name).unwrap();
        assert!(fresh.created());
    }
}
