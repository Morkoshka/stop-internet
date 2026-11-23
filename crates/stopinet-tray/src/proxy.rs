//! The system proxy of the user: reading it and waiting until it changes.
//!
//! Windows keeps the proxy settings of each user under [`KEY`] in the
//! registry, in values of the key and in a binary record of its
//! `Connections` subkey. `WinHttpGetIEProxyConfigForCurrentUser` reads them
//! and returns the manual proxy and the proxy script only while they are
//! turned on. A change of anything under the key wakes up [`Watch::wait`].
//! Chromium follows the system proxy the same way.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::{ptr, slice};

use stopinet_win::adapter::Win32Error;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, GlobalFree};
use windows_sys::Win32::Networking::WinHttp::{
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WinHttpGetIEProxyConfigForCurrentUser,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_NOTIFY, REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
    REG_NOTIFY_THREAD_AGNOSTIC, RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW,
};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

use crate::auto::ProxySettings;
use crate::shell::{last_error, wide};

/// Internet settings of the current user.
const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// The proxy settings of the user.
pub fn read() -> Result<ProxySettings, Win32Error> {
    let mut config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    // SAFETY: `config` is a valid out pointer.
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut config) } == 0 {
        return match last_error("WinHttpGetIEProxyConfigForCurrentUser") {
            // The user has no proxy settings at all.
            Win32Error {
                code: ERROR_FILE_NOT_FOUND,
                ..
            } => Ok(ProxySettings::default()),
            error => Err(error),
        };
    }
    // SAFETY: each string of the answer is null or NUL-terminated, comes
    // from `GlobalAlloc` and is taken once.
    unsafe {
        take(config.lpszProxyBypass);
        Ok(ProxySettings {
            proxy: take(config.lpszProxy),
            script: take(config.lpszAutoConfigUrl),
        })
    }
}

/// Copies a string and frees it.
///
/// # Safety
///
/// `text` must be null or a NUL-terminated string from `GlobalAlloc` that
/// nothing else uses or frees.
unsafe fn take(text: *mut u16) -> Option<String> {
    if text.is_null() {
        return None;
    }
    let mut length = 0;
    // SAFETY: the string is NUL-terminated, and reading stops at the NUL.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` characters were just read.
    let value = String::from_utf16_lossy(unsafe { slice::from_raw_parts(text, length) });
    // SAFETY: the string is not used after this.
    unsafe { GlobalFree(text.cast()) };
    Some(value)
}

/// Waits for changes of the proxy settings. Used by one thread.
#[derive(Debug)]
pub struct Watch {
    key: Key,
    event: OwnedHandle,
}

impl Watch {
    pub fn open() -> Result<Self, Win32Error> {
        let path = wide(KEY);
        let mut key: HKEY = ptr::null_mut();
        // SAFETY: `path` is NUL-terminated, `key` is a valid out pointer.
        let code =
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_NOTIFY, &mut key) };
        if code != ERROR_SUCCESS {
            return Err(Win32Error {
                operation: "RegOpenKeyExW",
                code,
            });
        }
        let key = Key(key);
        // SAFETY: no security attributes and no name; an auto-reset event
        // that starts unsignaled.
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event.is_null() {
            return Err(last_error("CreateEventW"));
        }
        // SAFETY: a new handle that nothing else owns.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        Ok(Self { key, event })
    }

    /// Asks for one signal at the next change under the key. Call it before
    /// reading the settings, so that a change during the read is not missed.
    pub fn arm(&self) -> Result<(), Win32Error> {
        // SAFETY: the key was opened with KEY_NOTIFY and the event is ours;
        // both outlive the registration, which ends with the key.
        let code = unsafe {
            RegNotifyChangeKeyValue(
                self.key.0,
                1,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
                self.event.as_raw_handle(),
                1,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(Win32Error {
                operation: "RegNotifyChangeKeyValue",
                code,
            });
        }
        Ok(())
    }

    /// Waits for the change asked for with [`Watch::arm`].
    pub fn wait(&self) {
        // SAFETY: the event is ours and open.
        unsafe { WaitForSingleObject(self.event.as_raw_handle(), INFINITE) };
    }
}

/// An open registry key, closed on drop.
#[derive(Debug)]
struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened by `RegOpenKeyExW` and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_of_this_user_can_be_read_and_watched() {
        // Reads only; the result depends on the machine.
        assert!(read().is_ok());
        let watch = Watch::open().unwrap();
        watch.arm().unwrap();
    }
}
