//! Security descriptors: access control for the data folder of the service
//! and for its named pipe.

use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

use crate::adapter::Win32Error;
use crate::wide::WideString;

/// Full control for SYSTEM and Administrators, read and execute for Users,
/// inherited by files and subfolders. `P` drops the permissions inherited
/// from `C:\ProgramData`, where Users may create files.
const ADMINS_WRITE_USERS_READ: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

/// Makes a folder writable by administrators only, existing files and
/// subfolders included. The service runs as LocalSystem and trusts the
/// configuration in this folder, so other users must not change it.
pub fn restrict_to_admins(folder: &Path) -> Result<(), Win32Error> {
    let descriptor = LocalDescriptor::from_sddl(ADMINS_WRITE_USERS_READ)?;

    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `descriptor` is a valid security descriptor; the out pointers
    // are valid. The DACL points into the descriptor, which outlives it.
    let found = unsafe {
        GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut dacl, &mut defaulted)
    };
    if found == 0 {
        return Err(Win32Error::last("GetSecurityDescriptorDacl"));
    }

    let path = WideString::from_os(folder.as_os_str());
    // SAFETY: `path` is NUL-terminated, `dacl` is valid while `descriptor`
    // lives, owner, group and SACL are not changed.
    let code = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if code != ERROR_SUCCESS {
        return Err(Win32Error {
            operation: "SetNamedSecurityInfoW",
            code,
        });
    }
    Ok(())
}

/// Security descriptor allocated by Windows, freed with `LocalFree`.
pub(crate) struct LocalDescriptor(PSECURITY_DESCRIPTOR);

impl LocalDescriptor {
    /// Builds a self-relative security descriptor from SDDL text.
    pub(crate) fn from_sddl(sddl: &str) -> Result<Self, Win32Error> {
        let sddl = WideString::new(sddl);
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and outlives the call;
        // `descriptor` is a valid out pointer and the size pointer may be
        // null.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(Win32Error::last(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        Ok(Self(descriptor))
    }

    /// The descriptor, valid while `self` lives.
    pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated with `LocalAlloc` by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and is freed
        // once.
        unsafe { LocalFree(self.0) };
    }
}
