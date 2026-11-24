//! Notifications about changes of IP interfaces and of their addresses, so
//! that the service reacts to the tunnel at once instead of on its next
//! periodic check.
//!
//! Interfaces and addresses are separate notifications in Windows. A VPN
//! client may bring its adapter up first and give it an address a moment
//! later; the second step changes no interface, so only the address
//! notification tells the service to put the filter for the new address in
//! place.

use std::ffi::c_void;
use std::fmt;
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
    NotifyIpInterfaceChange, NotifyUnicastIpAddressChange,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use crate::adapter::Win32Error;

type Callback = Box<dyn Fn() + Send + Sync>;

/// Calls a function whenever an IPv4 or IPv6 interface is added, removed or
/// changes, and whenever a unicast address is added to an interface,
/// removed from it or changes, for example when duplicate address detection
/// is over. The registrations end when the watch is dropped.
///
/// The function runs on threads of the system thread pool, and the two
/// kinds of notification may call it at the same time. Keep it short, for
/// example send a message to a channel. It does not say what changed: look
/// at the adapters again.
pub struct NetworkWatch {
    interfaces: HANDLE,
    addresses: HANDLE,
    callback: *mut Callback,
}

impl NetworkWatch {
    /// Registers `callback` for both kinds of change. If either
    /// registration fails, there is none.
    pub fn start(callback: impl Fn() + Send + Sync + 'static) -> Result<Self, Win32Error> {
        let callback: *mut Callback = Box::into_raw(Box::new(Box::new(callback)));
        // From here on, dropping `watch` cancels what is registered and
        // frees the callback.
        let mut watch = Self {
            interfaces: ptr::null_mut(),
            addresses: ptr::null_mut(),
            callback,
        };
        let context = callback.cast_const().cast();
        // SAFETY: `interface_changed` has the signature of
        // `PIPINTERFACE_CHANGE_CALLBACK`, `context` stays valid until the
        // registration is cancelled in `drop`, and the handle is a valid out
        // pointer.
        let code = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_changed),
                context,
                false,
                &mut watch.interfaces,
            )
        };
        check(code, "NotifyIpInterfaceChange")?;
        // SAFETY: as above, with `address_changed` for
        // `PUNICAST_IPADDRESS_CHANGE_CALLBACK`.
        let code = unsafe {
            NotifyUnicastIpAddressChange(
                AF_UNSPEC,
                Some(address_changed),
                context,
                false,
                &mut watch.addresses,
            )
        };
        check(code, "NotifyUnicastIpAddressChange")?;
        Ok(watch)
    }
}

fn check(code: WIN32_ERROR, operation: &'static str) -> Result<(), Win32Error> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(Win32Error { operation, code })
    }
}

unsafe extern "system" fn interface_changed(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: Windows passes back the context registered in `start`.
    unsafe { call(context) };
}

unsafe extern "system" fn address_changed(
    context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: Windows passes back the context registered in `start`.
    unsafe { call(context) };
}

/// # Safety
///
/// `context` must be the callback of a registration made in `start` that
/// is not cancelled yet.
unsafe fn call(context: *const c_void) {
    // SAFETY: the callback lives until both registrations are cancelled,
    // which waits for this call. It is `Sync`, so two notifications may
    // share it.
    let callback = unsafe { &*context.cast::<Callback>() };
    callback();
}

impl Drop for NetworkWatch {
    fn drop(&mut self) {
        for handle in [self.interfaces, self.addresses] {
            if !handle.is_null() {
                // SAFETY: `handle` is a registration made in `start` and is
                // cancelled once. `CancelMibChangeNotify2` returns only
                // after a callback in progress has finished (which is also
                // why calling it from the callback deadlocks). That cannot
                // happen here: the watch is neither `Send` nor `Sync`, so
                // the callback cannot own it.
                unsafe { CancelMibChangeNotify2(handle) };
            }
        }
        // SAFETY: the pointer came from `Box::into_raw` in `start`, and
        // Windows no longer calls the callback: both registrations are
        // cancelled, or were never made.
        drop(unsafe { Box::from_raw(self.callback) });
    }
}

impl fmt::Debug for NetworkWatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkWatch").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn registers_and_cancels() {
        // Changing the network here would need administrator rights, so
        // this only checks that Windows accepts both registrations and that
        // dropping the watch cancels them and frees the callback.
        let (sender, _events) = mpsc::channel::<()>();
        let watch = NetworkWatch::start(move || {
            let _ = sender.send(());
        })
        .unwrap();
        assert!(!watch.interfaces.is_null());
        assert!(!watch.addresses.is_null());
        drop(watch);
    }
}
