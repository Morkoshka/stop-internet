//! Local wall-clock time, for log lines.

use std::fmt;

use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

/// Local date and time, to the millisecond.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTime {
    /// Year, for example 2026.
    pub year: u16,
    /// Month, 1 to 12.
    pub month: u16,
    /// Day of the month, 1 to 31.
    pub day: u16,
    /// Hour, 0 to 23.
    pub hour: u16,
    /// Minute, 0 to 59.
    pub minute: u16,
    /// Second, 0 to 59.
    pub second: u16,
    /// Millisecond, 0 to 999.
    pub millis: u16,
}

impl LocalTime {
    /// The current local time.
    pub fn now() -> Self {
        let mut time = SYSTEMTIME::default();
        // SAFETY: `time` is a valid out pointer.
        unsafe { GetLocalTime(&mut time) };
        Self {
            year: time.wYear,
            month: time.wMonth,
            day: time.wDay,
            hour: time.wHour,
            minute: time.wMinute,
            second: time.wSecond,
            millis: time.wMilliseconds,
        }
    }
}

impl fmt::Display for LocalTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.millis
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_with_fixed_width() {
        let time = LocalTime {
            year: 2026,
            month: 1,
            day: 2,
            hour: 3,
            minute: 4,
            second: 5,
            millis: 6,
        };
        assert_eq!(time.to_string(), "2026-01-02 03:04:05.006");
    }
}
