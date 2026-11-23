//! Service configuration, loaded from a TOML file.
//!
//! The installed file lives in `%ProgramData%\stop-internet\config.toml` and
//! is writable by administrators only. See `config/stopinet.example.toml`.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Data folder of the installed service: configuration and log. Writable by
/// administrators only.
pub const DATA_DIR: &str = r"C:\ProgramData\stop-internet";

/// Default location of the installed configuration file.
pub const DEFAULT_PATH: &str = r"C:\ProgramData\stop-internet\config.toml";

/// Event log of the service.
pub const LOG_PATH: &str = r"C:\ProgramData\stop-internet\service.log";

/// Longest allowed timed "normal internet" period: one day.
const MAX_DURATION_MIN: u32 = 24 * 60;

/// Complete configuration of the service.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// How to recognise the tunnel adapter.
    pub tunnel: TunnelConfig,
    /// Processes of the VPN client.
    pub client: ClientConfig,
    /// Applications that bypass the tunnel.
    #[serde(default)]
    pub direct: DirectConfig,
    /// Local network settings.
    #[serde(default)]
    pub network: NetworkConfig,
    /// Options of the "normal internet" mode.
    #[serde(default)]
    pub normal_mode: NormalModeConfig,
}

/// Identification of the tunnel adapter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// Interface alias of the adapter, for example `happ-default-tun`.
    pub adapter_name: String,
    /// Driver of the adapter as reported in its `ComponentID`, for example `Wintun`.
    pub driver: String,
}

/// Processes of the VPN client.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Processes that carry the tunnel itself. They may use the physical
    /// network only while the tunnel adapter is up.
    pub tunnel_apps: Vec<PathBuf>,
    /// Processes that carry the client's system proxy. They may use the
    /// physical network in proxy mode.
    #[serde(default)]
    pub proxy_apps: Vec<PathBuf>,
}

/// Applications that always use the physical network directly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConfig {
    /// Usually the applications that are excluded from the tunnel in the VPN
    /// client. They keep working when the tunnel goes down.
    #[serde(default)]
    pub apps: Vec<PathBuf>,
}

/// Local network settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Allow private, link-local and multicast ranges. DNS stays blocked.
    #[serde(default)]
    pub allow_lan: bool,
}

/// Options of the "normal internet" mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalModeConfig {
    /// Durations offered in the tray menu, in minutes. `0` means until reboot.
    #[serde(default = "default_durations")]
    pub durations_min: Vec<u32>,
}

impl Default for NormalModeConfig {
    fn default() -> Self {
        Self {
            durations_min: default_durations(),
        }
    }
}

fn default_durations() -> Vec<u32> {
    vec![15, 60, 0]
}

impl Config {
    /// Parses and validates a configuration.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses and validates a configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ConfigError::Io(path.to_path_buf(), e))?;
        Self::from_toml(&text)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.tunnel.adapter_name.trim().is_empty() {
            return Err(ConfigError::Invalid("tunnel.adapter_name is empty".into()));
        }
        if self.tunnel.driver.trim().is_empty() {
            return Err(ConfigError::Invalid("tunnel.driver is empty".into()));
        }
        if self.client.tunnel_apps.is_empty() {
            return Err(ConfigError::Invalid("client.tunnel_apps is empty".into()));
        }

        let apps = self
            .client
            .tunnel_apps
            .iter()
            .chain(&self.client.proxy_apps)
            .chain(&self.direct.apps);
        for app in apps {
            if !is_absolute_windows_path(app) {
                return Err(ConfigError::Invalid(format!(
                    "not an absolute path: {}",
                    app.display()
                )));
            }
        }

        if let Some(d) = self
            .normal_mode
            .durations_min
            .iter()
            .find(|&&d| d > MAX_DURATION_MIN)
        {
            return Err(ConfigError::Invalid(format!(
                "normal_mode.durations_min: {d} is longer than {MAX_DURATION_MIN} minutes"
            )));
        }

        Ok(())
    }
}

/// `C:\dir\app.exe` or `\\server\share\app.exe`.
///
/// Checked by hand instead of [`Path::is_absolute`] so that the result does
/// not depend on the platform the tests run on.
fn is_absolute_windows_path(path: &Path) -> bool {
    let text = path.to_string_lossy();
    let bytes = text.as_bytes();
    let with_drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    with_drive || text.starts_with(r"\\")
}

/// Error while loading the configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// The file cannot be read.
    Io(PathBuf, std::io::Error),
    /// The file is not valid TOML or does not match the schema.
    Parse(toml::de::Error),
    /// The values are inconsistent.
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "cannot read {}: {e}", path.display()),
            Self::Parse(e) => write!(f, "invalid configuration: {e}"),
            Self::Invalid(message) => write!(f, "invalid configuration: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(_, e) => Some(e),
            Self::Parse(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../config/stopinet.example.toml");

    fn minimal(extra: &str) -> String {
        format!(
            r#"
[tunnel]
adapter_name = "vpn-tun"
driver = "Wintun"

[client]
tunnel_apps = ['C:\vpn\daemon.exe']
{extra}"#
        )
    }

    #[test]
    fn example_config_is_valid() {
        let config = Config::from_toml(EXAMPLE).expect("example config must be valid");
        assert_eq!(config.tunnel.adapter_name, "happ-default-tun");
        assert_eq!(config.tunnel.driver, "Wintun");
        assert!(!config.network.allow_lan);
    }

    #[test]
    fn installed_files_live_in_the_data_folder() {
        for file in [DEFAULT_PATH, LOG_PATH] {
            assert_eq!(
                Path::new(file).parent(),
                Some(Path::new(DATA_DIR)),
                "{file}"
            );
        }
    }

    #[test]
    fn minimal_config_uses_safe_defaults() {
        let config = Config::from_toml(&minimal("")).unwrap();
        assert!(config.client.proxy_apps.is_empty());
        assert!(config.direct.apps.is_empty());
        assert!(!config.network.allow_lan);
        assert_eq!(config.normal_mode.durations_min, vec![15, 60, 0]);
    }

    #[test]
    fn relative_app_path_is_rejected() {
        let err = Config::from_toml(&minimal("[direct]\napps = ['game.exe']")).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "{err}");
    }

    #[test]
    fn unc_app_path_is_accepted() {
        let config =
            Config::from_toml(&minimal("[direct]\napps = ['\\\\server\\share\\game.exe']"))
                .unwrap();
        assert_eq!(config.direct.apps.len(), 1);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let err = Config::from_toml(&minimal("[network]\nallow_lan = true\nallow_all = true"))
            .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err}");
    }

    #[test]
    fn empty_tunnel_apps_are_rejected() {
        let text = "[tunnel]\nadapter_name = 'tun'\ndriver = 'Wintun'\n[client]\ntunnel_apps = []";
        let err = Config::from_toml(text).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "{err}");
    }

    #[test]
    fn too_long_normal_mode_is_rejected() {
        let err = Config::from_toml(&minimal("[normal_mode]\ndurations_min = [2000]")).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)), "{err}");
    }
}
