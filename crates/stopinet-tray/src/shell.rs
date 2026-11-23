//! The Win32 side of the tray icon: a hidden window that owns the icon in
//! the notification area, its menu and the message loop, plus the few
//! shell calls the tray needs. All `unsafe` code of the tray is here.
//!
//! Everything about the window runs on the thread that calls [`run`].
//! Other threads only post [`Notifier::notify`] to it.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::{mem, ptr};

use stopinet_core::TRAY_WINDOW_CLASS;
use stopinet_win::adapter::Win32Error;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_CANCELLED, GetLastError, HWND, LPARAM, LRESULT, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
    DeleteObject, GetDC, HBITMAP, ReleaseDC,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_SYSTEM_AWARE, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION,
    NIN_SELECT, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW,
    Shell_NotifyIconW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    ChangeWindowMessageFilterEx, CreateIconIndirect, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW, GetMessageW,
    GetSystemMetrics, HICON, HMENU, ICONINFO, InsertMenuItemW, MB_ICONWARNING, MB_OK,
    MB_SETFOREGROUND, MENUITEMINFOW, MFS_CHECKED, MFS_DISABLED, MFT_RADIOCHECK, MFT_SEPARATOR,
    MIIM_FTYPE, MIIM_ID, MIIM_STATE, MIIM_STRING, MIIM_SUBMENU, MSG, MSGFLT_ALLOW, MessageBoxW,
    PostMessageW, PostQuitMessage, RegisterClassExW, RegisterWindowMessageW, SM_CXSMICON,
    SW_SHOWNORMAL, SetForegroundWindow, TPM_BOTTOMALIGN, TPM_NONOTIFY, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, TrackPopupMenuEx, TranslateMessage, WM_APP, WM_CONTEXTMENU, WM_DESTROY,
    WM_NULL, WM_SETTINGCHANGE, WNDCLASSEXW, WS_OVERLAPPED,
};

use crate::view::{Action, Color, Entry, View};
use crate::{icon, theme};

/// Callback message of the notification area icon.
const WM_TRAY: u32 = WM_APP + 1;
/// Another thread put a new view into the shared state.
const WM_REFRESH: u32 = WM_APP + 2;
/// `NIN_SELECT | NINF_KEY`: the icon was chosen with the keyboard.
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
const ICON_ID: u32 = 1;

/// Message that Explorer broadcasts when it has created the taskbar anew,
/// for example after a crash; the icon has to be added again.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

type Handler = Rc<dyn Fn(Action, Notifier)>;

struct App {
    window: HWND,
    icons: Icons,
    latest: Arc<Mutex<View>>,
    /// What the icon shows now.
    shown: View,
    handler: Handler,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

/// Lets other threads tell the window that the shared view changed.
#[derive(Debug, Clone, Copy)]
pub struct Notifier(usize);

impl Notifier {
    /// Returns `false` once the window is gone.
    pub fn notify(self) -> bool {
        // SAFETY: posting to a window that no longer exists fails harmlessly.
        unsafe { PostMessageW(self.0 as HWND, WM_REFRESH, 0, 0) != 0 }
    }
}

/// Holds the single-instance mutex of the session while it lives.
#[derive(Debug)]
pub struct Instance {
    _mutex: Option<OwnedHandle>,
}

/// `None` if the tray already runs in this session.
pub fn first_instance() -> Option<Instance> {
    let name = wide(&format!("Local\\{TRAY_WINDOW_CLASS}"));
    // SAFETY: `name` is NUL-terminated; no security attributes.
    let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
    // SAFETY: no preconditions; read right after the call.
    let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if handle.is_null() {
        // Without the mutex a second icon is possible, which does no harm.
        return Some(Instance { _mutex: None });
    }
    // SAFETY: a new handle that nothing else owns.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    (!existed).then_some(Instance {
        _mutex: Some(handle),
    })
}

/// Creates the window and the icon, calls `start` with a [`Notifier`] and
/// runs the message loop until the icon is closed. `handler` gets the menu
/// choices other than [`Action::Close`], on this thread.
pub fn run(
    latest: Arc<Mutex<View>>,
    start: impl FnOnce(Notifier),
    handler: impl Fn(Action, Notifier) + 'static,
) -> Result<(), Win32Error> {
    // SAFETY: no preconditions; fails harmlessly if already set.
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_SYSTEM_AWARE) };
    // SAFETY: no preconditions.
    let size = unsafe { GetSystemMetrics(SM_CXSMICON) }.max(16);
    let icons = Icons::create(size)?;

    let taskbar = wide("TaskbarCreated");
    // SAFETY: `taskbar` is NUL-terminated.
    TASKBAR_CREATED.store(
        unsafe { RegisterWindowMessageW(taskbar.as_ptr()) },
        Ordering::Relaxed,
    );
    let window = create_window()?;
    theme::follow_system(window);
    let notifier = Notifier(window as usize);

    let shown = latest
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    APP.with(|app| {
        *app.borrow_mut() = Some(App {
            window,
            icons,
            latest,
            shown,
            handler: Rc::new(handler),
        });
    });
    // At sign-in the taskbar may not exist yet; then TaskbarCreated adds
    // the icon later.
    set_icon(NIM_ADD);
    start(notifier);

    // SAFETY: `MSG` is plain data.
    let mut message: MSG = unsafe { mem::zeroed() };
    // SAFETY: `message` is a valid out pointer; the loop ends on WM_QUIT
    // (0) or an error (-1).
    while unsafe { GetMessageW(&mut message, ptr::null_mut(), 0, 0) } > 0 {
        // SAFETY: `message` came from `GetMessageW`.
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    APP.with(|app| app.borrow_mut().take());
    Ok(())
}

/// Runs `f` with the state of the window, if it exists. Must not be held
/// across a modal loop such as a menu, which dispatches messages to the
/// window again.
fn with_app<T>(f: impl FnOnce(&mut App) -> T) -> Option<T> {
    APP.with(|app| app.borrow_mut().as_mut().map(f))
}

fn create_window() -> Result<HWND, Win32Error> {
    // SAFETY: null asks for the module of this program.
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    let class = wide(TRAY_WINDOW_CLASS);
    let info = WNDCLASSEXW {
        cbSize: mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        // SAFETY: the other fields are optional and may be zero.
        ..unsafe { mem::zeroed() }
    };
    // SAFETY: `info` and the class name outlive the call.
    if unsafe { RegisterClassExW(&info) } == 0 {
        return Err(last_error("RegisterClassExW"));
    }
    let title = wide("stop-internet");
    // SAFETY: the class is registered, the strings are NUL-terminated. The
    // window is never shown: it exists for the icon, the menu and
    // `WM_CLOSE` from the installer.
    let window = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            instance,
            ptr::null(),
        )
    };
    if window.is_null() {
        return Err(last_error("CreateWindowExW"));
    }
    // If the tray runs elevated, Explorer may still announce a new taskbar.
    // SAFETY: `window` is ours; no extra filter information is asked for.
    unsafe {
        ChangeWindowMessageFilterEx(
            window,
            TASKBAR_CREATED.load(Ordering::Relaxed),
            MSGFLT_ALLOW,
            ptr::null_mut(),
        )
    };
    Ok(window)
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_TRAY => {
            // With NOTIFYICON_VERSION_4 the event is in the low word of
            // `lparam` and the anchor point in `wparam`.
            let event = (lparam & 0xffff) as u32;
            if matches!(event, WM_CONTEXTMENU | NIN_SELECT | NIN_KEYSELECT) {
                let x = i32::from((wparam & 0xffff) as u16 as i16);
                let y = i32::from(((wparam >> 16) & 0xffff) as u16 as i16);
                show_menu(window, x, y);
            }
            0
        }
        WM_REFRESH => {
            if with_app(App::take_latest) == Some(true) {
                set_icon(NIM_MODIFY);
            }
            0
        }
        WM_SETTINGCHANGE => {
            // SAFETY: for WM_SETTINGCHANGE `lparam` is null or points to the
            // NUL-terminated name of the changed setting.
            if unsafe { setting_name(lparam) }.as_deref() == Some("ImmersiveColorSet") {
                theme::changed();
            }
            0
        }
        WM_DESTROY => {
            set_icon(NIM_DELETE);
            // SAFETY: no preconditions.
            unsafe { PostQuitMessage(0) };
            0
        }
        m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
            set_icon(NIM_ADD);
            0
        }
        // SAFETY: the arguments are those of this call.
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

/// Name of the setting in a WM_SETTINGCHANGE message, if it has one.
///
/// # Safety
///
/// `lparam` must be null or point to a NUL-terminated UTF-16 string.
unsafe fn setting_name(lparam: LPARAM) -> Option<String> {
    let text = lparam as *const u16;
    if text.is_null() {
        return None;
    }
    // Names of interest are short; stop looking after 64 characters.
    let mut length = 0;
    // SAFETY: the string is NUL-terminated, and reading stops at the NUL.
    while length < 64 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: `length` characters were just read.
    let units = unsafe { std::slice::from_raw_parts(text, length) };
    Some(String::from_utf16_lossy(units))
}

impl App {
    /// Takes the latest view; returns whether it differs from the shown one.
    fn take_latest(&mut self) -> bool {
        let latest = self
            .latest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let changed = latest != self.shown;
        self.shown = latest;
        changed
    }

    /// What the notification area needs to know about the icon.
    fn icon_data(&self, command: u32) -> NOTIFYICONDATAW {
        // SAFETY: `NOTIFYICONDATAW` is plain data.
        let mut data: NOTIFYICONDATAW = unsafe { mem::zeroed() };
        data.cbSize = mem::size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.window;
        data.uID = ICON_ID;
        if command != NIM_DELETE {
            data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
            data.uCallbackMessage = WM_TRAY;
            data.hIcon = self.icons.get(self.shown.color());
            let tip: Vec<u16> = self.shown.tooltip().encode_utf16().collect();
            let length = tip.len().min(data.szTip.len() - 1);
            data.szTip[..length].copy_from_slice(&tip[..length]);
        }
        data
    }
}

/// Adds, updates or removes the icon in the notification area. The state of
/// the window is not borrowed during the call: the shell may send messages
/// to the window while it handles it.
fn set_icon(command: u32) {
    let Some(mut data) = with_app(|app| app.icon_data(command)) else {
        return;
    };
    // SAFETY: `data` describes the icon of this window.
    unsafe { Shell_NotifyIconW(command, &data) };
    if command == NIM_ADD {
        data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        // SAFETY: as above.
        unsafe { Shell_NotifyIconW(NIM_SETVERSION, &data) };
    }
}

fn show_menu(window: HWND, x: i32, y: i32) {
    let Some((view, handler)) = with_app(|app| (app.shown.clone(), Rc::clone(&app.handler))) else {
        return;
    };
    let mut actions = Vec::new();
    let Some(menu) = Menu::build(&view.menu(), &mut actions) else {
        return;
    };
    // SAFETY: `window` is ours. Without this the menu does not close when
    // the user clicks elsewhere.
    unsafe { SetForegroundWindow(window) };
    // SAFETY: `menu` is a valid popup menu and `window` its owner. The call
    // runs a modal loop and returns the chosen command or 0.
    let chosen = unsafe {
        TrackPopupMenuEx(
            menu.0,
            TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
            x,
            y,
            window,
            ptr::null(),
        )
    };
    // SAFETY: as documented for menus of notification area icons.
    unsafe { PostMessageW(window, WM_NULL, 0, 0) };
    drop(menu);

    let action = usize::try_from(chosen)
        .ok()
        .and_then(|id| id.checked_sub(1))
        .and_then(|index| actions.get(index).copied());
    match action {
        // SAFETY: `window` is ours; WM_DESTROY removes the icon.
        Some(Action::Close) => unsafe {
            DestroyWindow(window);
        },
        Some(action) => handler(action, Notifier(window as usize)),
        None => {}
    }
}

/// A popup menu, destroyed with its submenus on drop.
struct Menu(HMENU);

impl Menu {
    /// Builds the menu; item ids are positions in `actions` plus one.
    fn build(entries: &[Entry], actions: &mut Vec<Action>) -> Option<Self> {
        // SAFETY: no preconditions.
        let menu = Self(unsafe { CreatePopupMenu() });
        if menu.0.is_null() {
            return None;
        }
        for (position, entry) in entries.iter().enumerate() {
            // SAFETY: `MENUITEMINFOW` is plain data.
            let mut item: MENUITEMINFOW = unsafe { mem::zeroed() };
            item.cbSize = mem::size_of::<MENUITEMINFOW>() as u32;
            let mut label = Vec::new();
            let mut submenu = None;
            match entry {
                Entry::Separator => {
                    item.fMask = MIIM_FTYPE;
                    item.fType = MFT_SEPARATOR;
                }
                Entry::Text(text) => {
                    label = wide(text);
                    item.fMask = MIIM_STRING | MIIM_STATE;
                    item.fState = MFS_DISABLED;
                }
                Entry::Item {
                    label: text,
                    action,
                    checked,
                    enabled,
                } => {
                    actions.push(*action);
                    label = wide(text);
                    item.fMask = MIIM_ID | MIIM_STRING | MIIM_STATE | MIIM_FTYPE;
                    item.wID = actions.len() as u32;
                    item.fType = if matches!(action, Action::Choose(_)) {
                        MFT_RADIOCHECK
                    } else {
                        0
                    };
                    item.fState = state(*checked, *enabled);
                }
                Entry::Submenu {
                    label: text,
                    checked,
                    enabled,
                    entries,
                } => {
                    let inner = Self::build(entries, actions)?;
                    label = wide(text);
                    item.fMask = MIIM_SUBMENU | MIIM_STRING | MIIM_STATE;
                    item.hSubMenu = inner.0;
                    item.fState = state(*checked, *enabled);
                    submenu = Some(inner);
                }
            }
            if !label.is_empty() {
                item.dwTypeData = label.as_mut_ptr();
            }
            // SAFETY: `item` and `label` outlive the call, which copies the
            // text. Inserted by position.
            if unsafe { InsertMenuItemW(menu.0, position as u32, 1, &item) } == 0 {
                return None;
            }
            // The parent menu owns the submenu now and destroys it.
            mem::forget(submenu);
        }
        Some(menu)
    }
}

fn state(checked: bool, enabled: bool) -> u32 {
    (if checked { MFS_CHECKED } else { 0 }) | (if enabled { 0 } else { MFS_DISABLED })
}

impl Drop for Menu {
    fn drop(&mut self) {
        // SAFETY: the menu was created by `CreatePopupMenu` and is
        // destroyed once, with its submenus.
        unsafe { DestroyMenu(self.0) };
    }
}

/// The three icons, made once.
struct Icons([HICON; 3]);

impl Icons {
    fn create(size: i32) -> Result<Self, Win32Error> {
        let make = |color| make_icon(size, &icon::draw(size as u32, color));
        Ok(Self([
            make(Color::Green)?,
            make(Color::Red)?,
            make(Color::Grey)?,
        ]))
    }

    fn get(&self, color: Color) -> HICON {
        self.0[match color {
            Color::Green => 0,
            Color::Red => 1,
            Color::Grey => 2,
        }]
    }
}

impl Drop for Icons {
    fn drop(&mut self) {
        for icon in self.0 {
            // SAFETY: each icon came from `CreateIconIndirect` and is
            // destroyed once.
            unsafe { DestroyIcon(icon) };
        }
    }
}

/// An icon from `0xAARRGGBB` pixels, top row first.
fn make_icon(size: i32, pixels: &[u32]) -> Result<HICON, Win32Error> {
    // SAFETY: `BITMAPINFO` is plain data.
    let mut info: BITMAPINFO = unsafe { mem::zeroed() };
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: size,
        // Negative: the first row is the top one.
        biHeight: -size,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        // SAFETY: the other fields may be zero for an uncompressed bitmap.
        ..unsafe { mem::zeroed() }
    };
    let mut bits = ptr::null_mut();
    // SAFETY: the screen device context, released right after.
    let color = unsafe {
        let screen = GetDC(ptr::null_mut());
        let color = CreateDIBSection(screen, &info, DIB_RGB_COLORS, &mut bits, ptr::null_mut(), 0);
        ReleaseDC(ptr::null_mut(), screen);
        color
    };
    if color.is_null() || bits.is_null() {
        return Err(last_error("CreateDIBSection"));
    }
    let color = Bitmap(color);
    // SAFETY: the section holds `size * size` 32-bit pixels, which is the
    // length of `pixels`.
    unsafe { ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast(), pixels.len()) };

    // The alpha channel decides; the mask only has to exist. Rows of a
    // monochrome bitmap are padded to 16 bits.
    let mask_bits = vec![0u8; size as usize * (size as usize).div_ceil(16) * 2];
    // SAFETY: `mask_bits` holds a full monochrome bitmap of this size.
    let mask = Bitmap(unsafe { CreateBitmap(size, size, 1, 1, mask_bits.as_ptr().cast()) });
    if mask.0.is_null() {
        return Err(last_error("CreateBitmap"));
    }
    let icon_info = ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask.0,
        hbmColor: color.0,
    };
    // SAFETY: both bitmaps are valid; the icon gets copies of them.
    let icon = unsafe { CreateIconIndirect(&icon_info) };
    if icon.is_null() {
        return Err(last_error("CreateIconIndirect"));
    }
    Ok(icon)
}

/// A GDI bitmap, deleted on drop.
struct Bitmap(HBITMAP);

impl Drop for Bitmap {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the bitmap is not selected into any device context.
            unsafe { DeleteObject(self.0) };
        }
    }
}

/// Starts this program again with administrator rights, through the UAC
/// prompt. Returns `false` if the user declined. Call it on a thread of its
/// own: it waits for the prompt.
pub fn run_elevated(arguments: &str) -> Result<bool, Win32Error> {
    let program = std::env::current_exe().map_err(|e| Win32Error {
        operation: "GetModuleFileNameW",
        code: e.raw_os_error().unwrap_or_default() as u32,
    })?;
    init_com();
    let verb = wide("runas");
    let file = wide_os(program.as_os_str());
    let parameters = wide(arguments);
    // SAFETY: `SHELLEXECUTEINFOW` is plain data.
    let mut info: SHELLEXECUTEINFOW = unsafe { mem::zeroed() };
    info.cbSize = mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    // The thread may end right after the call.
    info.fMask = SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    // SAFETY: `info` and the strings it points to outlive the call.
    if unsafe { ShellExecuteExW(&mut info) } != 0 {
        return Ok(true);
    }
    match last_error("ShellExecuteExW") {
        Win32Error {
            code: ERROR_CANCELLED,
            ..
        } => Ok(false),
        error => Err(error),
    }
}

/// Opens a file with its default program, for example the log in Notepad.
pub fn open(path: &Path) -> Result<(), Win32Error> {
    init_com();
    let verb = wide("open");
    let file = wide_os(path.as_os_str());
    // SAFETY: `SHELLEXECUTEINFOW` is plain data.
    let mut info: SHELLEXECUTEINFOW = unsafe { mem::zeroed() };
    info.cbSize = mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    // SAFETY: `info` and the strings it points to outlive the call.
    if unsafe { ShellExecuteExW(&mut info) } != 0 {
        Ok(())
    } else {
        Err(last_error("ShellExecuteExW"))
    }
}

/// Shows a warning and waits until it is closed.
pub fn message_box(text: &str) {
    let text = wide(text);
    let title = wide("stop-internet");
    // SAFETY: both strings are NUL-terminated; no owner window.
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND,
        )
    };
}

/// The shell wants COM on threads that call `ShellExecuteExW`.
fn init_com() {
    // SAFETY: no reserved pointer; a second call on the same thread only
    // returns S_FALSE.
    unsafe {
        CoInitializeEx(
            ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn wide_os(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain([0]).collect()
}

fn last_error(operation: &'static str) -> Win32Error {
    // SAFETY: no preconditions.
    let code = unsafe { GetLastError() };
    Win32Error { operation, code }
}

#[cfg(test)]
mod tests {
    use stopinet_core::policy::{Mode, TunnelState};
    use stopinet_core::protocol::Status;

    use super::*;
    use crate::view::Problem;

    #[test]
    fn icons_can_be_made_in_common_sizes() {
        for size in [16, 20, 24, 32] {
            let icons = Icons::create(size).unwrap();
            assert!(icons.0.iter().all(|icon| !icon.is_null()));
        }
    }

    #[test]
    fn menus_get_one_command_per_item() {
        let view = View::Status(Status {
            mode: Mode::TunnelOnly,
            tunnel: TunnelState::Up,
            left: None,
            durations: vec![15, 60, 0],
        });
        let mut actions = Vec::new();
        assert!(Menu::build(&view.menu(), &mut actions).is_some());
        // Two modes, three durations, the log and close.
        assert_eq!(actions.len(), 7);
        assert_eq!(actions.last(), Some(&Action::Close));

        let mut actions = Vec::new();
        let view = View::Unreachable(Problem::NotRunning);
        assert!(Menu::build(&view.menu(), &mut actions).is_some());
        assert_eq!(actions.len(), 4);
    }
}
