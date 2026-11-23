//! Settings of the tray, kept for each user in the registry under [`KEY`].
//! They concern the tray only; the service keeps none of its own here.

use std::{mem, ptr};

use stopinet_win::adapter::Win32Error;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_DWORD, RRF_RT_REG_DWORD, RegGetValueW, RegSetKeyValueW,
};

use crate::shell::wide;

const KEY: &str = r"Software\stop-internet";

/// 1 while the mode follows the system proxy, 0 after the user turned it
/// off.
const FOLLOW_PROXY: &str = "FollowSystemProxy";

/// Whether the mode follows the system proxy. On unless the user turned it
/// off.
pub fn follow_proxy() -> bool {
    let (key, name) = (wide(KEY), wide(FOLLOW_PROXY));
    let mut value: u32 = 1;
    let mut size = mem::size_of::<u32>() as u32;
    // SAFETY: the strings are NUL-terminated; `value` holds the DWORD that
    // RRF_RT_REG_DWORD allows, and `size` says so.
    let code = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&raw mut value).cast(),
            &mut size,
        )
    };
    code != ERROR_SUCCESS || value != 0
}

/// Remembers whether the mode follows the system proxy.
pub fn set_follow_proxy(on: bool) -> Result<(), Win32Error> {
    let (key, name) = (wide(KEY), wide(FOLLOW_PROXY));
    let value = u32::from(on);
    // SAFETY: the strings are NUL-terminated; the data is one DWORD. The
    // key is created if it does not exist yet.
    let code = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            REG_DWORD,
            (&raw const value).cast(),
            mem::size_of::<u32>() as u32,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(Win32Error {
            operation: "RegSetKeyValueW",
            code,
        });
    }
    Ok(())
}
