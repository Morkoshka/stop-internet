//! What the installer does about the tray icon: the autostart entry for
//! every user, and closing the running icons before the program is replaced
//! or removed.

use std::path::Path;
use std::ptr;

use stopinet_core::TRAY_WINDOW_CLASS;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, REG_SZ, RegDeleteKeyValueW, RegSetKeyValueW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowExW, PostMessageW, WM_CLOSE};

use crate::adapter::Win32Error;
use crate::wide::WideString;

/// Programs started at the sign-in of every user, without elevation. Users
/// can turn the entry off in Task Manager, Startup apps.
const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "stop-internet";

/// Starts `program` at every sign-in of every user.
pub fn register_autostart(program: &Path) -> Result<(), Win32Error> {
    let key = WideString::new(RUN_KEY);
    let name = WideString::new(RUN_VALUE);
    let command = WideString::new(&autostart_command(program));
    // SAFETY: the strings are NUL-terminated and outlive the call; the data
    // is the command with its NUL, as REG_SZ expects.
    let code = unsafe {
        RegSetKeyValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            REG_SZ,
            command.as_ptr().cast(),
            command.byte_len(),
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

/// Removes the autostart entry. Returns whether there was one.
pub fn unregister_autostart() -> Result<bool, Win32Error> {
    let key = WideString::new(RUN_KEY);
    let name = WideString::new(RUN_VALUE);
    // SAFETY: the strings are NUL-terminated and outlive the call.
    match unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), name.as_ptr()) } {
        ERROR_SUCCESS => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        code => Err(Win32Error {
            operation: "RegDeleteKeyValueW",
            code,
        }),
    }
}

/// Asks every tray icon on this desktop to close. Returns how many were
/// asked; they close on their own shortly after.
pub fn close_running() -> usize {
    let class = WideString::new(TRAY_WINDOW_CLASS);
    let mut after = ptr::null_mut();
    let mut count = 0;
    loop {
        // SAFETY: top-level windows of this desktop with our class name,
        // after the previous match; the class name is NUL-terminated.
        let window = unsafe { FindWindowExW(ptr::null_mut(), after, class.as_ptr(), ptr::null()) };
        if window.is_null() {
            return count;
        }
        // SAFETY: posting to a window that is gone by now fails harmlessly.
        unsafe { PostMessageW(window, WM_CLOSE, 0, 0) };
        count += 1;
        after = window;
    }
}

/// Quoted, because the path has spaces.
fn autostart_command(program: &Path) -> String {
    format!("\"{}\"", program.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_is_quoted() {
        assert_eq!(
            autostart_command(Path::new(
                r"C:\Program Files\stop-internet\stopinet-tray.exe"
            )),
            r#""C:\Program Files\stop-internet\stopinet-tray.exe""#
        );
    }

    #[test]
    fn the_entry_is_for_every_user() {
        assert!(RUN_KEY.ends_with(r"\CurrentVersion\Run"));
        assert_eq!(RUN_VALUE, "stop-internet");
    }
}
