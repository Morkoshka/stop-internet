//! Lookup of the tunnel adapter.
//!
//! The adapter is identified by its interface alias and by the driver that
//! created it (`ComponentId` in the network class registry key), so that
//! another adapter with the same name is not mistaken for the tunnel.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use stopinet_core::config::TunnelConfig;
use stopinet_core::policy::TunnelState;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS, GetLastError};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, GetUnicastIpAddressTable, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ, RegCloseKey, RegEnumKeyExW, RegGetValueW,
    RegOpenKeyExW,
};
use windows_sys::core::GUID;

use crate::plan::Environment;
use crate::wide::{WideString, from_wide};

/// Registry key of the network adapter device class.
const NET_CLASS_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

/// What was found under the configured name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelLookup {
    /// No adapter with this alias.
    Missing,
    /// An adapter with this alias exists, but another driver created it.
    WrongDriver {
        /// Driver of the adapter that was found.
        driver: String,
    },
    /// The tunnel adapter.
    Found {
        /// Locally unique identifier of the interface.
        luid: u64,
        /// Whether the interface is operational.
        up: bool,
    },
}

/// Failed Win32 call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32Error {
    /// Name of the function that failed.
    pub operation: &'static str,
    /// Its return code.
    pub code: u32,
}

impl Win32Error {
    /// The error of the last failed call on this thread.
    pub(crate) fn last(operation: &'static str) -> Self {
        // SAFETY: no preconditions.
        let code = unsafe { GetLastError() };
        Self { operation, code }
    }
}

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed with error {}", self.operation, self.code)
    }
}

impl std::error::Error for Win32Error {}

/// Finds the adapter with this alias and driver.
pub fn find_tunnel(alias: &str, driver: &str) -> Result<TunnelLookup, Win32Error> {
    let table = InterfaceTable::load()?;
    let mut result = TunnelLookup::Missing;
    for row in table.rows() {
        if !from_wide(&row.Alias).eq_ignore_ascii_case(alias) {
            continue;
        }
        let component = component_id(&row.InterfaceGuid).unwrap_or_default();
        if !component.eq_ignore_ascii_case(driver) {
            result = TunnelLookup::WrongDriver { driver: component };
            continue;
        }
        // SAFETY: `Value` spans the whole `NET_LUID_LH` union, so every bit
        // pattern written by Windows is a valid `u64`.
        let luid = unsafe { row.InterfaceLuid.Value };
        return Ok(TunnelLookup::Found {
            luid,
            up: row.OperStatus == IfOperStatusUp,
        });
    }
    Ok(result)
}

/// The tunnel as the firewall sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Up when the adapter exists, has the configured driver and is
    /// operational.
    pub state: TunnelState,
    /// LUID of the adapter while it is up.
    pub luid: Option<u64>,
    /// Unicast addresses of the adapter while it is up, sorted.
    pub addresses: Vec<IpAddr>,
    /// Why the tunnel counts as down although an adapter was found, or why
    /// the lookup failed.
    pub note: Option<String>,
}

impl Observation {
    /// Facts for [`Plan::build`](crate::plan::Plan::build).
    pub fn environment(&self) -> Environment {
        Environment {
            tunnel_luid: self.luid,
            tunnel_addresses: self.addresses.clone(),
        }
    }
}

/// Looks at the tunnel adapter described by the configuration.
pub fn observe_tunnel(tunnel: &TunnelConfig) -> Observation {
    let mut seen = observation(
        find_tunnel(&tunnel.adapter_name, &tunnel.driver),
        &tunnel.driver,
    );
    if let Some(luid) = seen.luid {
        match unicast_addresses(luid) {
            Ok(addresses) => seen.addresses = addresses,
            Err(error) => seen.note = Some(format!("cannot read the addresses: {error}")),
        }
    }
    seen
}

fn observation(lookup: Result<TunnelLookup, Win32Error>, driver: &str) -> Observation {
    let down = |note: Option<String>| Observation {
        state: TunnelState::Down,
        luid: None,
        addresses: Vec::new(),
        note,
    };
    match lookup {
        Ok(TunnelLookup::Found { luid, up: true }) => Observation {
            state: TunnelState::Up,
            luid: Some(luid),
            addresses: Vec::new(),
            note: None,
        },
        Ok(TunnelLookup::Found { up: false, .. }) => {
            down(Some("adapter is not operational".into()))
        }
        Ok(TunnelLookup::Missing) => down(None),
        // Windows removes the registry entry of an adapter shortly before
        // the interface itself.
        Ok(TunnelLookup::WrongDriver { driver: found }) if found.is_empty() => down(Some(
            "adapter has no driver entry in the registry, probably being removed".into(),
        )),
        Ok(TunnelLookup::WrongDriver { driver: found }) => down(Some(format!(
            "adapter found, but its driver is '{found}', expected '{driver}'"
        ))),
        Err(error) => down(Some(error.to_string())),
    }
}

/// Interface table from `GetIfTable2`, freed on drop.
struct InterfaceTable(*mut MIB_IF_TABLE2);

impl InterfaceTable {
    fn load() -> Result<Self, Win32Error> {
        let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
        // SAFETY: `table` is a valid out pointer.
        let code = unsafe { GetIfTable2(&mut table) };
        if code != ERROR_SUCCESS {
            return Err(Win32Error {
                operation: "GetIfTable2",
                code,
            });
        }
        Ok(Self(table))
    }

    fn rows(&self) -> &[MIB_IF_ROW2] {
        // SAFETY: `GetIfTable2` succeeded, so the table holds `NumEntries`
        // rows starting at `Table`. The pointer is derived from the table
        // allocation itself, not from the one-element array field.
        unsafe {
            let count = (*self.0).NumEntries as usize;
            let first = ptr::addr_of!((*self.0).Table).cast::<MIB_IF_ROW2>();
            std::slice::from_raw_parts(first, count)
        }
    }
}

impl Drop for InterfaceTable {
    fn drop(&mut self) {
        // SAFETY: the table was allocated by `GetIfTable2` and is freed once.
        unsafe { FreeMibTable(self.0.cast_const().cast()) };
    }
}

/// Unicast addresses of the interface with this LUID, sorted, IPv4 first.
fn unicast_addresses(luid: u64) -> Result<Vec<IpAddr>, Win32Error> {
    let table = AddressTable::load()?;
    let mut addresses: Vec<IpAddr> = table
        .rows()
        .iter()
        // SAFETY: `Value` spans the whole `NET_LUID_LH` union, so every bit
        // pattern written by Windows is a valid `u64`.
        .filter(|row| unsafe { row.InterfaceLuid.Value } == luid)
        .filter_map(|row| socket_address(&row.Address))
        .collect();
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

fn socket_address(address: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: every member of the union starts with the address family, and
    // only the member it names is read.
    unsafe {
        match address.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// Unicast address table from `GetUnicastIpAddressTable`, freed on drop.
struct AddressTable(*mut MIB_UNICASTIPADDRESS_TABLE);

impl AddressTable {
    fn load() -> Result<Self, Win32Error> {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        // SAFETY: `table` is a valid out pointer.
        let code = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
        if code != ERROR_SUCCESS {
            return Err(Win32Error {
                operation: "GetUnicastIpAddressTable",
                code,
            });
        }
        Ok(Self(table))
    }

    fn rows(&self) -> &[MIB_UNICASTIPADDRESS_ROW] {
        // SAFETY: the call succeeded, so the table holds `NumEntries` rows
        // starting at `Table`. The pointer is derived from the table
        // allocation itself, not from the one-element array field.
        unsafe {
            let count = (*self.0).NumEntries as usize;
            let first = ptr::addr_of!((*self.0).Table).cast::<MIB_UNICASTIPADDRESS_ROW>();
            std::slice::from_raw_parts(first, count)
        }
    }
}

impl Drop for AddressTable {
    fn drop(&mut self) {
        // SAFETY: the table was allocated by `GetUnicastIpAddressTable` and is
        // freed once.
        unsafe { FreeMibTable(self.0.cast_const().cast()) };
    }
}

/// `ComponentId` of the adapter with this interface GUID, from the network
/// class key: `Wintun` for Wintun adapters, `tap0901` for TAP.
fn component_id(interface: &GUID) -> Option<String> {
    let wanted = format_guid(interface);
    let class = RegKey::open_local_machine(NET_CLASS_KEY)?;
    for index in 0.. {
        let subkey = class.subkey_name(index)?;
        let Some(instance) = class.string(&subkey, "NetCfgInstanceId") else {
            continue;
        };
        if instance.eq_ignore_ascii_case(&wanted) {
            return class.string(&subkey, "ComponentId");
        }
    }
    None
}

fn format_guid(guid: &GUID) -> String {
    let d = guid.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1, guid.data2, guid.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// Registry key opened for reading, closed on drop.
struct RegKey(HKEY);

impl RegKey {
    fn open_local_machine(path: &str) -> Option<Self> {
        let path = WideString::new(path);
        let mut key: HKEY = ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and `key` is a valid out pointer.
        let code =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
        (code == ERROR_SUCCESS).then_some(Self(key))
    }

    /// Name of the subkey at `index`, or `None` after the last one.
    fn subkey_name(&self, index: u32) -> Option<String> {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: `name` holds `len` characters; the optional arguments are null.
        let code = unsafe {
            RegEnumKeyExW(
                self.0,
                index,
                name.as_mut_ptr(),
                &mut len,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        (code == ERROR_SUCCESS).then(|| from_wide(&name[..len as usize]))
    }

    /// String value `value` of the subkey `subkey`.
    fn string(&self, subkey: &str, value: &str) -> Option<String> {
        let subkey = WideString::new(subkey);
        let value = WideString::new(value);
        let mut buffer = vec![0u16; 128];
        loop {
            let mut size = (buffer.len() * 2) as u32;
            // SAFETY: `buffer` holds `size` bytes; strings are NUL-terminated.
            let code = unsafe {
                RegGetValueW(
                    self.0,
                    subkey.as_ptr(),
                    value.as_ptr(),
                    RRF_RT_REG_SZ,
                    ptr::null_mut(),
                    buffer.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            match code {
                ERROR_SUCCESS => return Some(from_wide(&buffer)),
                ERROR_MORE_DATA => buffer.resize((size as usize).div_ceil(2) + 1, 0),
                _ => return None,
            }
        }
    }
}

impl Drop for RegKey {
    fn drop(&mut self) {
        // SAFETY: the key was opened by `RegOpenKeyExW` and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_operational_adapter_is_up() {
        let up = observation(Ok(TunnelLookup::Found { luid: 7, up: true }), "Wintun");
        assert_eq!(up.state, TunnelState::Up);
        assert_eq!(up.environment().tunnel_luid, Some(7));
        assert_eq!(up.note, None);

        let cases = [
            Ok(TunnelLookup::Found { luid: 7, up: false }),
            Ok(TunnelLookup::Missing),
            Ok(TunnelLookup::WrongDriver {
                driver: "tap0901".into(),
            }),
            Ok(TunnelLookup::WrongDriver {
                driver: String::new(),
            }),
            Err(Win32Error {
                operation: "GetIfTable2",
                code: 8,
            }),
        ];
        for lookup in cases {
            let missing = matches!(lookup, Ok(TunnelLookup::Missing));
            let seen = observation(lookup, "Wintun");
            assert_eq!(seen.state, TunnelState::Down);
            assert_eq!(seen.luid, None);
            assert_eq!(seen.note.is_none(), missing);
        }
    }

    #[test]
    fn an_adapter_without_driver_entry_is_reported_as_being_removed() {
        let seen = observation(
            Ok(TunnelLookup::WrongDriver {
                driver: String::new(),
            }),
            "Wintun",
        );
        let note = seen.note.unwrap();
        assert!(note.contains("being removed"), "{note}");
        assert!(!note.contains("''"), "{note}");
    }

    #[test]
    fn socket_addresses_become_ip_addresses() {
        use windows_sys::Win32::Networking::WinSock::{
            IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
        };

        let v4 = SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        // In memory in network order, as Windows writes it.
                        S_addr: u32::from_ne_bytes([10, 6, 7, 1]),
                    },
                },
                ..Default::default()
            },
        };
        assert_eq!(socket_address(&v4), Some(IpAddr::from([10, 6, 7, 1])));

        let bytes = [0xfd, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let v6 = SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: bytes },
                },
                ..Default::default()
            },
        };
        assert_eq!(socket_address(&v6), Some(IpAddr::from(bytes)));

        let other = SOCKADDR_INET {
            si_family: AF_UNSPEC,
        };
        assert_eq!(socket_address(&other), None);
    }

    #[test]
    fn the_addresses_of_this_computer_can_be_read() {
        // Loopback always has 127.0.0.1; any LUID with addresses shows that
        // rows and families are read. Nothing is changed.
        let table = AddressTable::load().unwrap();
        let all: Vec<IpAddr> = table
            .rows()
            .iter()
            .filter_map(|row| socket_address(&row.Address))
            .collect();
        assert!(all.contains(&IpAddr::from([127, 0, 0, 1])), "{all:?}");
        let loopback = table
            .rows()
            .iter()
            .find(|row| socket_address(&row.Address) == Some(IpAddr::from([127, 0, 0, 1])))
            .unwrap();
        // SAFETY: as in `unicast_addresses`.
        let luid = unsafe { loopback.InterfaceLuid.Value };
        assert!(
            unicast_addresses(luid)
                .unwrap()
                .contains(&IpAddr::from([127, 0, 0, 1]))
        );
    }

    #[test]
    fn guid_format_matches_the_registry() {
        let guid = GUID::from_u128(0x03e34674_ccb5_2a17_cc23_f70bcb7861e3);
        assert_eq!(format_guid(&guid), "{03E34674-CCB5-2A17-CC23-F70BCB7861E3}");
    }
}
