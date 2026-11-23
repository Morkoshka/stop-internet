//! Notifications about changes of IP interfaces, so that the service reacts
//! to the tunnel at once instead of on its next periodic check.

use std::ffi::c_void;
use std::fmt;
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use crate::adapter::Win32Error;

type Callback = Box<dyn Fn() + Send + Sync>;

/// Calls a function whenever an IPv4 or IPv6 interface is added, removed or
/// changes. The registration ends when the watch is dropped.
///
/// The function runs on a thread of the system thread pool, one call at a
/// time. Keep it short, for example send a message to a channel. It does
/// not say what changed: look at the adapters again.
pub struct InterfaceWatch {
    handle: HANDLE,
    callback: *mut Callback,
}

impl InterfaceWatch {
    /// Registers `callback` for interface changes.
    pub fn start(callback: impl Fn() + Send + Sync + 'static) -> Result<Self, Win32Error> {
        let callback: *mut Callback = Box::into_raw(Box::new(Box::new(callback)));
        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: `notify` has the signature of `PIPINTERFACE_CHANGE_CALLBACK`,
        // `callback` stays valid until the registration is cancelled in
        // `drop`, and `handle` is a valid out pointer.
        let code = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(notify),
                callback.cast_const().cast(),
                false,
                &mut handle,
            )
        };
        if code != NO_ERROR {
            // SAFETY: the registration failed, so Windows keeps no copy of the
            // pointer, which came from `Box::into_raw` above.
            drop(unsafe { Box::from_raw(callback) });
            return Err(Win32Error {
                operation: "NotifyIpInterfaceChange",
                code,
            });
        }
        Ok(Self { handle, callback })
    }
}

unsafe extern "system" fn notify(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: `context` is the callback registered in `start`; it lives
    // until the registration is cancelled, which waits for this call.
    let callback = unsafe { &*context.cast::<Callback>() };
    callback();
}

impl Drop for InterfaceWatch {
    fn drop(&mut self) {
        // SAFETY: `handle` is the registration made in `start` and is
        // cancelled once. `CancelMibChangeNotify2` returns only after a
        // callback in progress has finished (which is also why calling it
        // from the callback deadlocks). That cannot happen here: the watch is
        // neither `Send` nor `Sync`, so the callback cannot own it.
        unsafe { CancelMibChangeNotify2(self.handle) };
        // SAFETY: the pointer came from `Box::into_raw` in `start`, and
        // Windows no longer calls the callback.
        drop(unsafe { Box::from_raw(self.callback) });
    }
}

impl fmt::Debug for InterfaceWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceWatch").finish_non_exhaustive()
    }
}
