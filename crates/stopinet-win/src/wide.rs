//! UTF-16 strings for Windows API calls.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

/// Null-terminated UTF-16 string that owns its buffer.
#[derive(Debug, Clone)]
pub(crate) struct WideString(Vec<u16>);

impl WideString {
    pub(crate) fn new(text: &str) -> Self {
        Self(text.encode_utf16().chain([0]).collect())
    }

    pub(crate) fn from_os(text: &OsStr) -> Self {
        Self(text.encode_wide().chain([0]).collect())
    }

    pub(crate) fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }

    /// Size in bytes, the final NUL included.
    pub(crate) fn byte_len(&self) -> u32 {
        (self.0.len() * 2) as u32
    }

    /// For API structs that declare `PWSTR` but only read the string.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u16 {
        self.0.as_mut_ptr()
    }
}

/// Converts a UTF-16 buffer up to its first NUL.
pub(crate) fn from_wide(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_stops_at_nul() {
        let wide = WideString::new("happ-default-tun");
        assert_eq!(wide.0.last(), Some(&0));
        let mut buffer = [0u16; 32];
        buffer[..wide.0.len()].copy_from_slice(&wide.0);
        assert_eq!(from_wide(&buffer), "happ-default-tun");
    }
}
