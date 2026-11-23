//! Thin wrapper over the WFP management API (`fwpuclnt.dll`).
//!
//! Only this module calls WFP functions. It converts [`FilterSpec`]s into
//! `FWPM_FILTER0` structures and keeps every buffer they point to alive for
//! the duration of the call.

use std::collections::HashMap;
use std::ffi::c_void;
use std::fmt;
use std::path::{Path, PathBuf};
use std::ptr;

use stopinet_core::policy::Action;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, FWP_E_ALREADY_EXISTS, FWP_E_IN_USE, FWP_E_INVALID_PARAMETER,
    FWP_E_LAYER_NOT_FOUND, FWP_E_MATCH_TYPE_MISMATCH, FWP_E_NOT_FOUND, FWP_E_TYPE_MISMATCH, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as fwp;
use windows_sys::core::GUID;

use crate::plan::{Condition, Field, FilterSpec, LOOPBACK_FLAG, Layer, MatchKind, Value};
use crate::wide::WideString;

/// Provider of every WFP object that stop-internet creates.
pub const PROVIDER_KEY: GUID = GUID::from_u128(0xee4512c1_ffd5_4cd3_bc99_c224a27d5988);

/// Sublayer that holds every filter of stop-internet.
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0x078778d7_2a5e_4f62_9eda_011b82a57eb3);

/// Highest sublayer weight: stop-internet filters are evaluated first.
const SUBLAYER_WEIGHT: u16 = u16::MAX;

/// `RPC_C_AUTHN_WINNT`: local authentication, the usual choice for WFP.
const RPC_C_AUTHN_WINNT: u32 = 10;

const _: () = assert!(LOOPBACK_FLAG == fwp::FWP_CONDITION_FLAG_IS_LOOPBACK);

/// Failed WFP call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WfpError {
    /// Name of the function that failed.
    pub operation: &'static str,
    /// Its return code.
    pub code: u32,
}

impl WfpError {
    /// The caller is not an administrator.
    pub fn is_access_denied(&self) -> bool {
        self.code == ERROR_ACCESS_DENIED
    }

    /// An object with the same key exists, usually another running instance.
    pub fn is_already_exists(&self) -> bool {
        self.code as i32 == FWP_E_ALREADY_EXISTS
    }

    fn name(&self) -> Option<&'static str> {
        let names = [
            (ERROR_ACCESS_DENIED as i32, "ERROR_ACCESS_DENIED"),
            (FWP_E_ALREADY_EXISTS, "FWP_E_ALREADY_EXISTS"),
            (FWP_E_IN_USE, "FWP_E_IN_USE"),
            (FWP_E_INVALID_PARAMETER, "FWP_E_INVALID_PARAMETER"),
            (FWP_E_LAYER_NOT_FOUND, "FWP_E_LAYER_NOT_FOUND"),
            (FWP_E_MATCH_TYPE_MISMATCH, "FWP_E_MATCH_TYPE_MISMATCH"),
            (FWP_E_NOT_FOUND, "FWP_E_NOT_FOUND"),
            (FWP_E_TYPE_MISMATCH, "FWP_E_TYPE_MISMATCH"),
        ];
        names
            .iter()
            .find(|(code, _)| *code == self.code as i32)
            .map(|(_, name)| *name)
    }
}

impl fmt::Display for WfpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed with 0x{:08X}", self.operation, self.code)?;
        if let Some(name) = self.name() {
            write!(f, " ({name})")?;
        }
        Ok(())
    }
}

impl std::error::Error for WfpError {}

fn check(operation: &'static str, code: u32) -> Result<(), WfpError> {
    if code == 0 {
        Ok(())
    } else {
        Err(WfpError { operation, code })
    }
}

/// WFP application id of an executable: its path in NT device form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppId(Vec<u8>);

impl AppId {
    /// Looks up the application id. Fails if the file does not exist.
    pub fn for_path(path: &Path) -> Result<Self, WfpError> {
        let wide = WideString::from_os(path.as_os_str());
        let mut blob: *mut fwp::FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: `wide` is a NUL-terminated string that outlives the call;
        // `blob` is a valid out pointer.
        let code = unsafe { fwp::FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
        check("FwpmGetAppIdFromFileName0", code)?;

        // SAFETY: on success WFP returns a blob of `size` bytes at `data`,
        // which we copy before releasing it with `FwpmFreeMemory0`.
        let bytes = unsafe {
            let bytes = std::slice::from_raw_parts((*blob).data, (*blob).size as usize).to_vec();
            fwp::FwpmFreeMemory0(ptr::from_mut(&mut blob).cast::<*mut c_void>());
            bytes
        };
        Ok(Self(bytes))
    }
}

/// Application ids by executable path.
pub type AppIds = HashMap<PathBuf, AppId>;

/// Open session with the Base Filtering Engine.
#[derive(Debug)]
pub struct Engine {
    handle: HANDLE,
}

impl Engine {
    /// Opens a dynamic session. The Base Filtering Engine deletes every
    /// object added through it when the session closes, including when the
    /// process exits or is killed.
    pub fn open_dynamic() -> Result<Self, WfpError> {
        let mut name = WideString::new("stop-internet");
        let mut session = fwp::FWPM_SESSION0::default();
        session.displayData.name = name.as_mut_ptr();
        session.flags = fwp::FWPM_SESSION_FLAG_DYNAMIC;

        let mut handle: HANDLE = ptr::null_mut();
        // SAFETY: all pointers are valid for the duration of the call; a null
        // server name means the local machine.
        let code = unsafe {
            fwp::FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut handle,
            )
        };
        check("FwpmEngineOpen0", code)?;
        Ok(Self { handle })
    }

    /// Runs `body` in a WFP transaction: either all of its changes apply or
    /// none of them do.
    pub fn transaction<T>(
        &self,
        body: impl FnOnce(&Self) -> Result<T, WfpError>,
    ) -> Result<T, WfpError> {
        // SAFETY: `self.handle` is an open engine handle.
        check("FwpmTransactionBegin0", unsafe {
            fwp::FwpmTransactionBegin0(self.handle, 0)
        })?;
        match body(self) {
            Ok(value) => {
                // SAFETY: a transaction is open on this handle.
                check("FwpmTransactionCommit0", unsafe {
                    fwp::FwpmTransactionCommit0(self.handle)
                })?;
                Ok(value)
            }
            Err(error) => {
                // SAFETY: a transaction is open on this handle. The abort
                // result is ignored: the original error is more useful.
                unsafe { fwp::FwpmTransactionAbort0(self.handle) };
                Err(error)
            }
        }
    }

    /// Registers the stop-internet provider.
    pub fn add_provider(&self) -> Result<(), WfpError> {
        let mut name = WideString::new("stop-internet");
        let mut description = WideString::new("Fail-closed kill switch for TUN-based VPN clients");
        let provider = fwp::FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: fwp::FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: description.as_mut_ptr(),
            },
            ..Default::default()
        };
        // SAFETY: `provider` and the strings it points to live until the call
        // returns; a null security descriptor means the default one.
        check("FwpmProviderAdd0", unsafe {
            fwp::FwpmProviderAdd0(self.handle, &provider, ptr::null_mut())
        })
    }

    /// Adds the stop-internet sublayer with the highest weight.
    pub fn add_sublayer(&self) -> Result<(), WfpError> {
        let mut name = WideString::new("stop-internet");
        let mut provider_key = PROVIDER_KEY;
        let sublayer = fwp::FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: fwp::FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            },
            providerKey: &mut provider_key,
            weight: SUBLAYER_WEIGHT,
            ..Default::default()
        };
        // SAFETY: `sublayer` and everything it points to live until the call
        // returns.
        check("FwpmSubLayerAdd0", unsafe {
            fwp::FwpmSubLayerAdd0(self.handle, &sublayer, ptr::null_mut())
        })
    }

    /// Adds one filter and returns its id. App ids of the filter's
    /// executables must be present in `apps`.
    pub fn add_filter(&self, spec: &FilterSpec, apps: &AppIds) -> Result<u64, WfpError> {
        let mut pool = Pool::default();
        let slots = spec
            .conditions
            .iter()
            .map(|condition| pool.store(condition, apps))
            .collect::<Result<Vec<_>, _>>()?;
        let mut conditions: Vec<fwp::FWPM_FILTER_CONDITION0> = spec
            .conditions
            .iter()
            .zip(slots)
            .map(|(condition, slot)| fwp::FWPM_FILTER_CONDITION0 {
                fieldKey: field_key(condition.field),
                matchType: match_type(condition.kind),
                conditionValue: pool.value(slot),
            })
            .collect();

        let mut name = WideString::new(&spec.name);
        let mut provider_key = PROVIDER_KEY;
        let mut weight = spec.weight;

        let mut filter = fwp::FWPM_FILTER0::default();
        filter.displayData.name = name.as_mut_ptr();
        filter.providerKey = &mut provider_key;
        filter.layerKey = layer_key(spec.layer);
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight.r#type = fwp::FWP_UINT64;
        filter.weight.Anonymous.uint64 = &mut weight;
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = if conditions.is_empty() {
            ptr::null_mut()
        } else {
            conditions.as_mut_ptr()
        };
        filter.action.r#type = match spec.action {
            Action::Permit => fwp::FWP_ACTION_PERMIT,
            Action::Block => fwp::FWP_ACTION_BLOCK,
        };

        let mut id = 0u64;
        // SAFETY: `filter` points to `name`, `provider_key`, `weight`,
        // `conditions` and, through them, to `pool` and `apps`. All of them
        // live until the call returns and are not modified meanwhile.
        check("FwpmFilterAdd0", unsafe {
            fwp::FwpmFilterAdd0(self.handle, &filter, ptr::null_mut(), &mut id)
        })?;
        Ok(id)
    }

    /// Deletes a filter added through this session.
    pub fn delete_filter(&self, id: u64) -> Result<(), WfpError> {
        // SAFETY: `self.handle` is an open engine handle.
        check("FwpmFilterDeleteById0", unsafe {
            fwp::FwpmFilterDeleteById0(self.handle, id)
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by `open_dynamic` and is closed only
        // here. Closing a dynamic session removes all its objects.
        unsafe { fwp::FwpmEngineClose0(self.handle) };
    }
}

/// Storage for condition values that WFP receives by pointer.
///
/// It is filled completely before any pointer is taken, so the pointers stay
/// valid while the filter is added.
#[derive(Default)]
struct Pool {
    u64s: Vec<u64>,
    ranges: Vec<fwp::FWP_RANGE0>,
    v4: Vec<fwp::FWP_V4_ADDR_AND_MASK>,
    v6: Vec<fwp::FWP_V6_ADDR_AND_MASK>,
    blobs: Vec<fwp::FWP_BYTE_BLOB>,
}

/// Where the value of one condition lives.
#[derive(Clone, Copy)]
enum Slot {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(usize),
    Range(usize),
    V4(usize),
    V6(usize),
    Blob(usize),
}

impl Pool {
    fn store(&mut self, condition: &Condition, apps: &AppIds) -> Result<Slot, WfpError> {
        Ok(match &condition.value {
            Value::U8(v) => Slot::U8(*v),
            Value::U16(v) => Slot::U16(*v),
            Value::U32(v) => Slot::U32(*v),
            Value::U64(v) => {
                self.u64s.push(*v);
                Slot::U64(self.u64s.len() - 1)
            }
            Value::U16Range(low, high) => {
                let mut range = fwp::FWP_RANGE0::default();
                range.valueLow.r#type = fwp::FWP_UINT16;
                range.valueLow.Anonymous.uint16 = *low;
                range.valueHigh.r#type = fwp::FWP_UINT16;
                range.valueHigh.Anonymous.uint16 = *high;
                self.ranges.push(range);
                Slot::Range(self.ranges.len() - 1)
            }
            Value::V4Prefix(addr, len) => {
                self.v4.push(fwp::FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_be_bytes(*addr),
                    mask: v4_mask(*len),
                });
                Slot::V4(self.v4.len() - 1)
            }
            Value::V6Prefix(addr, len) => {
                self.v6.push(fwp::FWP_V6_ADDR_AND_MASK {
                    addr: *addr,
                    prefixLength: *len,
                });
                Slot::V6(self.v6.len() - 1)
            }
            Value::AppPath(path) => {
                let app = apps.get(path).ok_or(WfpError {
                    operation: "FwpmGetAppIdFromFileName0",
                    code: FWP_E_NOT_FOUND as u32,
                })?;
                self.blobs.push(fwp::FWP_BYTE_BLOB {
                    size: app.0.len() as u32,
                    // WFP only reads the blob.
                    data: app.0.as_ptr().cast_mut(),
                });
                Slot::Blob(self.blobs.len() - 1)
            }
        })
    }

    /// Builds the C value for a slot. Must be called only after every
    /// `store`, so that the vectors no longer reallocate.
    fn value(&mut self, slot: Slot) -> fwp::FWP_CONDITION_VALUE0 {
        let mut value = fwp::FWP_CONDITION_VALUE0::default();
        // `Vec::as_mut_ptr` does not create a reference to the elements, so
        // pointers taken here stay valid across later calls.
        match slot {
            Slot::U8(v) => {
                value.r#type = fwp::FWP_UINT8;
                value.Anonymous.uint8 = v;
            }
            Slot::U16(v) => {
                value.r#type = fwp::FWP_UINT16;
                value.Anonymous.uint16 = v;
            }
            Slot::U32(v) => {
                value.r#type = fwp::FWP_UINT32;
                value.Anonymous.uint32 = v;
            }
            Slot::U64(i) => {
                value.r#type = fwp::FWP_UINT64;
                value.Anonymous.uint64 = self.u64s.as_mut_ptr().wrapping_add(i);
            }
            Slot::Range(i) => {
                value.r#type = fwp::FWP_RANGE_TYPE;
                value.Anonymous.rangeValue = self.ranges.as_mut_ptr().wrapping_add(i);
            }
            Slot::V4(i) => {
                value.r#type = fwp::FWP_V4_ADDR_MASK;
                value.Anonymous.v4AddrMask = self.v4.as_mut_ptr().wrapping_add(i);
            }
            Slot::V6(i) => {
                value.r#type = fwp::FWP_V6_ADDR_MASK;
                value.Anonymous.v6AddrMask = self.v6.as_mut_ptr().wrapping_add(i);
            }
            Slot::Blob(i) => {
                value.r#type = fwp::FWP_BYTE_BLOB_TYPE;
                value.Anonymous.byteBlob = self.blobs.as_mut_ptr().wrapping_add(i);
            }
        }
        value
    }
}

fn v4_mask(prefix: u8) -> u32 {
    match prefix {
        0 => 0,
        len => u32::MAX << (32 - u32::from(len.min(32))),
    }
}

fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => fwp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => fwp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvAcceptV4 => fwp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvAcceptV6 => fwp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        Layer::ForwardV4 => fwp::FWPM_LAYER_IPFORWARD_V4,
        Layer::ForwardV6 => fwp::FWPM_LAYER_IPFORWARD_V6,
    }
}

fn field_key(field: Field) -> GUID {
    match field {
        Field::Flags => fwp::FWPM_CONDITION_FLAGS,
        Field::LocalInterface => fwp::FWPM_CONDITION_IP_LOCAL_INTERFACE,
        Field::AppId => fwp::FWPM_CONDITION_ALE_APP_ID,
        Field::Protocol => fwp::FWPM_CONDITION_IP_PROTOCOL,
        Field::LocalPort => fwp::FWPM_CONDITION_IP_LOCAL_PORT,
        Field::RemotePort => fwp::FWPM_CONDITION_IP_REMOTE_PORT,
        Field::RemoteAddress => fwp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
    }
}

fn match_type(kind: MatchKind) -> fwp::FWP_MATCH_TYPE {
    match kind {
        MatchKind::Equal => fwp::FWP_MATCH_EQUAL,
        MatchKind::NotEqual => fwp::FWP_MATCH_NOT_EQUAL,
        MatchKind::FlagsAllSet => fwp::FWP_MATCH_FLAGS_ALL_SET,
        MatchKind::Range => fwp::FWP_MATCH_RANGE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_masks() {
        assert_eq!(v4_mask(0), 0);
        assert_eq!(v4_mask(8), 0xFF00_0000);
        assert_eq!(v4_mask(12), 0xFFF0_0000);
        assert_eq!(v4_mask(32), 0xFFFF_FFFF);
    }

    #[test]
    fn errors_show_known_names() {
        let error = WfpError {
            operation: "FwpmSubLayerAdd0",
            code: FWP_E_ALREADY_EXISTS as u32,
        };
        assert!(error.is_already_exists());
        assert_eq!(
            error.to_string(),
            "FwpmSubLayerAdd0 failed with 0x80320009 (FWP_E_ALREADY_EXISTS)"
        );
    }
}
