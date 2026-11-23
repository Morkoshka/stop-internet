//! Installation and control of the service.
//!
//! - `install` copies the programs to `C:\Program Files\stop-internet` (only
//!   administrators can change them there, which matters for a LocalSystem
//!   service), the configuration to the data folder, registers the service
//!   with restart on failure and starts it.
//! - `uninstall` removes the service, every WFP object and the programs.
//! - `panic` stops the service and removes every WFP object.
//! - `status` reads the state; it changes nothing. The mode comes from the
//!   service over its named pipe.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use stopinet_core::config::{Config, DATA_DIR, DEFAULT_PATH, LOG_PATH};
use stopinet_core::{SERVICE_NAME, SESSION_ONLY_ARG, TunnelState};
use stopinet_win::persistent::{inventory, remove_all};
use stopinet_win::security::restrict_to_admins;
use stopinet_win::{Lifetime, RemovalReport, observe_tunnel};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
    ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::{Options, explain};

const INSTALL_DIR: &str = r"C:\Program Files\stop-internet";
const SERVICE_EXE: &str = "stopinet-service.exe";
const CLI_EXE: &str = "stopinet.exe";
const DISPLAY_NAME: &str = "stop-internet";
const DESCRIPTION: &str =
    "Fail-closed kill switch for TUN-based VPN clients: blocks traffic that bypasses the tunnel.";

/// Service that owns the Base Filtering Engine.
const BFE_SERVICE: &str = "BFE";

/// Restarts after a crash or a failed start, then the counter resets.
const RESTART_DELAYS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
const FAILURE_RESET: Duration = Duration::from_secs(24 * 60 * 60);

/// How long to wait for the service to start or stop.
const STATE_TIMEOUT: Duration = Duration::from_secs(30);
const STATE_POLL: Duration = Duration::from_millis(250);

const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// Everything `install`, `uninstall` and `panic` need on the service.
const MANAGE_ACCESS: ServiceAccess = ServiceAccess::QUERY_STATUS
    .union(ServiceAccess::QUERY_CONFIG)
    .union(ServiceAccess::CHANGE_CONFIG)
    .union(ServiceAccess::START)
    .union(ServiceAccess::STOP)
    .union(ServiceAccess::DELETE);

pub fn install(options: &Options) -> Result<(), String> {
    // Check everything before changing anything.
    let new_config = match &options.config {
        Some(path) => {
            let text = fs::read_to_string(path)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            Config::from_toml(&text).map_err(|e| e.to_string())?;
            Some(text)
        }
        None => {
            Config::load(Path::new(DEFAULT_PATH))
                .map_err(|e| format!("{e}\nPass the configuration with --config <file>."))?;
            None
        }
    };
    let source_dir = current_dir()?;
    if !source_dir.join(SERVICE_EXE).is_file() {
        return Err(format!(
            "{SERVICE_EXE} is not next to {CLI_EXE}. Build both with `cargo build --release` \
             and run target\\release\\{CLI_EXE}."
        ));
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| scm_error("cannot open the service manager", &e))?;
    let existing = open_service(&manager, MANAGE_ACCESS)?;
    if let Some(service) = &existing {
        stop(service)?;
    }

    fs::create_dir_all(DATA_DIR).map_err(|e| format!("cannot create {DATA_DIR}: {e}"))?;
    restrict_to_admins(Path::new(DATA_DIR))
        .map_err(|e| format!("cannot set permissions on {DATA_DIR}: {e}"))?;
    if let Some(text) = &new_config {
        fs::write(DEFAULT_PATH, text).map_err(|e| format!("cannot write {DEFAULT_PATH}: {e}"))?;
        println!("configuration written to {DEFAULT_PATH}");
    }

    fs::create_dir_all(INSTALL_DIR).map_err(|e| format!("cannot create {INSTALL_DIR}: {e}"))?;
    for exe in [SERVICE_EXE, CLI_EXE] {
        copy_program(&source_dir.join(exe), &Path::new(INSTALL_DIR).join(exe))?;
    }
    println!("programs copied to {INSTALL_DIR}");

    if options.session_only {
        // A baseline left by a full install would keep blocking and would
        // stop the session-only service from registering its own objects.
        let report = remove_all().map_err(explain)?;
        if report.filters > 0 {
            println!("persistent baseline removed ({} filters)", report.filters);
        }
        if !report.is_complete() {
            return Err(failures("cannot remove the persistent baseline", &report));
        }
    }

    let info = service_info(options.session_only);
    let service = match existing {
        Some(service) => {
            service
                .change_config(&info)
                .map_err(|e| scm_error("cannot update the service", &e))?;
            service
        }
        None => manager
            .create_service(&info, MANAGE_ACCESS)
            .map_err(|e| scm_error("cannot create the service", &e))?,
    };
    configure(&service)?;
    println!(
        "service \"{SERVICE_NAME}\" registered{}",
        if options.session_only {
            " in session-only mode"
        } else {
            ""
        }
    );

    service
        .start::<&str>(&[])
        .map_err(|e| scm_error("cannot start the service", &e))?;
    match wait_for(&service, |s| s != ServiceState::StartPending)? {
        ServiceState::Running => {
            println!("service running. Log: {LOG_PATH}");
            Ok(())
        }
        state => Err(format!(
            "the service did not start (state {state:?}). See {LOG_PATH}"
        )),
    }
}

pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| scm_error("cannot open the service manager", &e))?;
    match open_service(&manager, MANAGE_ACCESS)? {
        Some(service) => {
            stop(&service)?;
            service
                .delete()
                .map_err(|e| scm_error("cannot remove the service", &e))?;
            println!("service removed");
        }
        None => println!("service not installed"),
    }

    let report = remove_all().map_err(explain)?;
    print_removal(&report);

    let current = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok());
    for exe in [SERVICE_EXE, CLI_EXE] {
        let path = Path::new(INSTALL_DIR).join(exe);
        if path.canonicalize().ok().is_some_and(|p| Some(p) == current) {
            println!("{} is running now; delete it by hand", path.display());
            continue;
        }
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => println!("cannot delete {}: {e}", path.display()),
        }
    }
    let _ = fs::remove_dir(INSTALL_DIR);
    println!("configuration and log kept in {DATA_DIR}");

    if report.is_complete() {
        Ok(())
    } else {
        Err(failures("some objects are left", &report))
    }
}

pub fn panic() -> Result<(), String> {
    // The session filters of the service go away only with its session, so
    // stop it first. Remove the persistent filters even if that fails.
    let mut stopped = true;
    match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(manager) => match open_service(&manager, MANAGE_ACCESS) {
            Ok(Some(service)) => {
                if let Err(error) = stop(&service) {
                    println!("{error}");
                    stopped = false;
                }
            }
            Ok(None) => {}
            Err(error) => {
                println!("{error}");
                stopped = false;
            }
        },
        Err(error) => {
            println!("{}", scm_error("cannot open the service manager", &error));
            stopped = false;
        }
    }

    let report = remove_all().map_err(explain)?;
    print_removal(&report);
    if report.is_complete() {
        println!(
            "Protection is off. It returns when the service starts again: after a restart \
             of Windows or with `sc start {SERVICE_NAME}`. To remove it for good: \
             stopinet uninstall"
        );
        Ok(())
    } else if !stopped {
        Err(failures(
            "the service could not be stopped, its session filters stay",
            &report,
        ))
    } else {
        Err(failures("some objects are left", &report))
    }
}

pub fn status(options: &Options) -> Result<(), String> {
    match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(manager) => match open_service(
            &manager,
            ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
        ) {
            Ok(Some(service)) => print_service(&service),
            Ok(None) => println!("service:  not installed"),
            Err(error) => println!("service:  {error}"),
        },
        Err(error) => println!(
            "service:  {}",
            scm_error("cannot open the service manager", &error)
        ),
    }
    println!("mode:     {}", crate::mode::line());

    match inventory() {
        Ok(found) => {
            let kind = |lifetime: Option<Lifetime>| match lifetime {
                None => "none",
                Some(Lifetime::Persistent) => "persistent",
                Some(Lifetime::Dynamic) => "session",
                Some(Lifetime::BootTime) => "boot-time",
            };
            println!(
                "wfp:      provider {}, sublayer {}",
                kind(found.provider),
                kind(found.sublayer)
            );
            println!(
                "filters:  {} persistent, {} boot-time, {} session",
                found.persistent, found.boot_time, found.dynamic
            );
        }
        Err(error) if error.is_access_denied() => {
            println!("filters:  run from an elevated terminal to see them");
        }
        Err(error) => println!("filters:  {error}"),
    }

    match Config::load(options.config_path()) {
        Ok(config) => {
            let seen = observe_tunnel(&config.tunnel);
            let state = match seen.state {
                TunnelState::Up => "up",
                TunnelState::Down => "down",
            };
            print!("tunnel:   \"{}\" {state}", config.tunnel.adapter_name);
            match &seen.note {
                Some(note) => println!(" ({note})"),
                None => println!(),
            }
        }
        Err(error) => println!("tunnel:   {error}"),
    }
    println!("log:      {LOG_PATH}");
    Ok(())
}

fn print_service(service: &Service) {
    let state = service
        .query_status()
        .map(|s| format!("{:?}", s.current_state).to_lowercase());
    let config = service.query_config();
    let start = config
        .as_ref()
        .map(|c| format!("{:?}", c.start_type))
        .unwrap_or_default();
    let session_only = config.as_ref().is_ok_and(|c| {
        c.executable_path
            .to_string_lossy()
            .contains(SESSION_ONLY_ARG)
    });
    match state {
        Ok(state) => println!(
            "service:  {state}, start {start}{}",
            if session_only { ", session-only" } else { "" }
        ),
        Err(error) => println!(
            "service:  {}",
            scm_error("cannot query the service", &error)
        ),
    }
}

fn service_info(session_only: bool) -> ServiceInfo {
    ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: Path::new(INSTALL_DIR).join(SERVICE_EXE),
        launch_arguments: if session_only {
            vec![OsString::from(SESSION_ONLY_ARG)]
        } else {
            Vec::new()
        },
        dependencies: vec![ServiceDependency::Service(BFE_SERVICE.into())],
        account_name: None,
        account_password: None,
    }
}

/// Description and recovery: restart after a crash and after a failed
/// start, which the service reports with an error exit code.
fn configure(service: &Service) -> Result<(), String> {
    service
        .set_description(DESCRIPTION)
        .map_err(|e| scm_error("cannot set the description", &e))?;
    let actions = RESTART_DELAYS
        .iter()
        .map(|&delay| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay,
        })
        .collect();
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET),
            reboot_msg: None,
            command: None,
            actions: Some(actions),
        })
        .map_err(|e| scm_error("cannot set the recovery actions", &e))?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| scm_error("cannot set the recovery actions", &e))
}

fn open_service(
    manager: &ServiceManager,
    access: ServiceAccess,
) -> Result<Option<Service>, String> {
    match manager.open_service(SERVICE_NAME, access) {
        Ok(service) => Ok(Some(service)),
        Err(error) if os_error(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => Ok(None),
        Err(error) => Err(scm_error("cannot open the service", &error)),
    }
}

/// Stops the service and waits until it has stopped.
fn stop(service: &Service) -> Result<(), String> {
    let state = service
        .query_status()
        .map_err(|e| scm_error("cannot query the service", &e))?
        .current_state;
    if state == ServiceState::Stopped {
        return Ok(());
    }
    match service.stop() {
        Ok(_) => {}
        Err(error) if os_error(&error) == Some(ERROR_SERVICE_NOT_ACTIVE) => return Ok(()),
        Err(error) => return Err(scm_error("cannot stop the service", &error)),
    }
    match wait_for(service, |s| s == ServiceState::Stopped)? {
        ServiceState::Stopped => {
            println!("service stopped");
            Ok(())
        }
        state => Err(format!(
            "the service did not stop within {} s (state {state:?})",
            STATE_TIMEOUT.as_secs()
        )),
    }
}

/// Polls the service state until `done` or the timeout; returns the last
/// state seen.
fn wait_for(
    service: &Service,
    done: impl Fn(ServiceState) -> bool,
) -> Result<ServiceState, String> {
    let deadline = Instant::now() + STATE_TIMEOUT;
    loop {
        let state = service
            .query_status()
            .map_err(|e| scm_error("cannot query the service", &e))?
            .current_state;
        if done(state) || Instant::now() >= deadline {
            return Ok(state);
        }
        thread::sleep(STATE_POLL);
    }
}

/// Copies a program unless source and target are the same file, which
/// happens when the installed `stopinet.exe` runs `install` again.
fn copy_program(source: &Path, target: &Path) -> Result<(), String> {
    let same = match (source.canonicalize(), target.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        fs::copy(source, target).map_err(|e| {
            format!(
                "cannot copy {} to {}: {e}",
                source.display(),
                target.display()
            )
        })?;
    }
    Ok(())
}

fn current_dir() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this program: {e}"))?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "cannot find the folder of this program".into())
}

fn print_removal(report: &RemovalReport) {
    println!(
        "removed {} persistent and boot-time filters{}{}",
        report.filters,
        if report.sublayer {
            ", the sublayer"
        } else {
            ""
        },
        if report.provider {
            ", the provider"
        } else {
            ""
        },
    );
}

fn failures(title: &str, report: &RemovalReport) -> String {
    let mut message = format!("{title}:");
    for failure in &report.failures {
        message.push_str("\n  ");
        message.push_str(failure);
    }
    message
}

fn os_error(error: &windows_service::Error) -> Option<i32> {
    match error {
        windows_service::Error::Winapi(error) => error.raw_os_error(),
        _ => None,
    }
}

fn scm_error(what: &str, error: &windows_service::Error) -> String {
    if os_error(error) == Some(ERROR_ACCESS_DENIED) {
        format!("{what}: administrator rights are needed, run this from an elevated terminal")
    } else {
        format!("{what}: {error}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_only_is_a_launch_argument() {
        assert!(service_info(false).launch_arguments.is_empty());
        assert_eq!(
            service_info(true).launch_arguments,
            vec![OsString::from(SESSION_ONLY_ARG)]
        );
    }

    #[test]
    fn service_waits_for_the_filtering_engine() {
        let info = service_info(false);
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert!(matches!(
            info.dependencies.as_slice(),
            [ServiceDependency::Service(name)] if name == BFE_SERVICE
        ));
    }

    #[test]
    fn programs_are_installed_where_only_admins_write() {
        assert!(
            service_info(false)
                .executable_path
                .starts_with(r"C:\Program Files")
        );
        assert!(Path::new(DEFAULT_PATH).starts_with(DATA_DIR));
    }
}
