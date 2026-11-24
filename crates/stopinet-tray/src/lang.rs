//! Language of the tray: Russian when the display language of Windows is
//! Russian, English otherwise. It is read once, at the start.

use std::sync::OnceLock;

use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;

/// Primary language id of Russian, the low 10 bits of a LANGID.
const LANG_RUSSIAN: u16 = 0x19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Russian,
    English,
}

impl Lang {
    /// The language for a Windows LANGID.
    pub fn of(langid: u16) -> Self {
        if langid & 0x3ff == LANG_RUSSIAN {
            Self::Russian
        } else {
            Self::English
        }
    }

    /// The display language of the user.
    pub fn current() -> Self {
        static CURRENT: OnceLock<Lang> = OnceLock::new();
        // SAFETY: no preconditions.
        *CURRENT.get_or_init(|| Self::of(unsafe { GetUserDefaultUILanguage() }))
    }

    /// One of two translations.
    pub fn pick<'a>(self, russian: &'a str, english: &'a str) -> &'a str {
        match self {
            Self::Russian => russian,
            Self::English => english,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn russian_in_any_country_and_english_for_the_rest() {
        assert_eq!(Lang::of(0x0419), Lang::Russian); // ru-RU
        assert_eq!(Lang::of(0x0819), Lang::Russian); // ru-MD
        assert_eq!(Lang::of(0x0409), Lang::English); // en-US
        assert_eq!(Lang::of(0x0809), Lang::English); // en-GB
        assert_eq!(Lang::of(0x0422), Lang::English); // uk-UA
        assert_eq!(Lang::of(0x0407), Lang::English); // de-DE
    }
}
