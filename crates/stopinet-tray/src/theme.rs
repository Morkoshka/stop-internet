//! Dark or light menus, following the app theme chosen in Windows settings.
//!
//! Win32 has no documented way to make popup menus dark. Since Windows 10
//! version 1903 (build 18362), `uxtheme.dll` exports the functions that
//! Windows itself and many programs use for it, by ordinal only:
//!
//! | Ordinal | Function |
//! |---|---|
//! | 104 | `RefreshImmersiveColorPolicyState()` |
//! | 133 | `AllowDarkModeForWindow(HWND, bool) -> bool` |
//! | 135 | `SetPreferredAppMode(PreferredAppMode) -> PreferredAppMode` |
//! | 136 | `FlushMenuThemes()` |
//!
//! They are looked up at run time, and only on build 18362 or later,
//! where these ordinals have these signatures. If anything is missing the
//! menu stays light; nothing else depends on it.

use std::ptr;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HWND};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};

/// First build where the ordinals below have the signatures used here.
const MIN_BUILD: u32 = 18362;

/// `PreferredAppMode::AllowDark`: dark when the app theme of Windows is dark.
const ALLOW_DARK: i32 = 1;

type Action = unsafe extern "system" fn();
type SetPreferredAppMode = unsafe extern "system" fn(i32) -> i32;
type AllowDarkModeForWindow = unsafe extern "system" fn(HWND, bool) -> bool;

struct Uxtheme {
    refresh: Action,
    allow_for_window: AllowDarkModeForWindow,
    set_preferred_app_mode: SetPreferredAppMode,
    flush_menus: Action,
}

static UXTHEME: OnceLock<Option<Uxtheme>> = OnceLock::new();

/// Lets the menus of `window` follow the app theme. Call once, after the
/// window exists.
pub fn follow_system(window: HWND) {
    let Some(api) = UXTHEME.get_or_init(load) else {
        return;
    };
    // SAFETY: the functions come from uxtheme.dll of a build that has these
    // signatures, see `load`; `window` belongs to this thread.
    unsafe {
        (api.set_preferred_app_mode)(ALLOW_DARK);
        (api.allow_for_window)(window, true);
        (api.refresh)();
        (api.flush_menus)();
    }
}

/// After the app theme of Windows changed (`WM_SETTINGCHANGE` with
/// "ImmersiveColorSet").
pub fn changed() {
    if let Some(Some(api)) = UXTHEME.get() {
        // SAFETY: as in `follow_system`.
        unsafe {
            (api.refresh)();
            (api.flush_menus)();
        }
    }
}

fn load() -> Option<Uxtheme> {
    if windows_build()? < MIN_BUILD {
        return None;
    }
    let name: Vec<u16> = "uxtheme.dll".encode_utf16().chain([0]).collect();
    // SAFETY: `name` is NUL-terminated; only System32 is searched. The
    // module stays loaded for the life of the process.
    let module =
        unsafe { LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return None;
    }
    let get = |ordinal: usize| {
        // SAFETY: an ordinal in the low word of the name pointer is how
        // GetProcAddress looks up a function by ordinal.
        unsafe { GetProcAddress(module, ordinal as *const u8) }
    };
    let (refresh, allow, set_mode, flush) = (get(104)?, get(133)?, get(135)?, get(136)?);
    // SAFETY: on build 18362 and later these ordinals are the functions
    // listed at the top of this module, with these signatures.
    unsafe {
        Some(Uxtheme {
            refresh: std::mem::transmute::<unsafe extern "system" fn() -> isize, Action>(refresh),
            allow_for_window: std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                AllowDarkModeForWindow,
            >(allow),
            set_preferred_app_mode: std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                SetPreferredAppMode,
            >(set_mode),
            flush_menus: std::mem::transmute::<unsafe extern "system" fn() -> isize, Action>(flush),
        })
    }
}

/// Build number of Windows, for example 22631.
fn windows_build() -> Option<u32> {
    let key: Vec<u16> = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        .encode_utf16()
        .chain([0])
        .collect();
    let value: Vec<u16> = "CurrentBuildNumber".encode_utf16().chain([0]).collect();
    let mut buffer = [0u16; 32];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: the names are NUL-terminated, `buffer` holds `size` bytes, and
    // RRF_RT_REG_SZ makes Windows terminate the string.
    let code = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if code != ERROR_SUCCESS {
        return None;
    }
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end]).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_number_can_be_read() {
        assert!(windows_build().is_some_and(|build| build > 10000));
    }
}
