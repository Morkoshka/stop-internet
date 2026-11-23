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

    /// For API structs that declare `PWSTR` but only read the string.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u16 {
        self.0.as_mut_ptr()
    }
}
