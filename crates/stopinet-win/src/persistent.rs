//! Persistent objects of stop-internet: the baseline that the Base Filtering
//! Engine keeps across reboots and service crashes, its boot-time copies,
//! and the removal of everything for uninstall and emergencies.

use stopinet_core::policy::Scope;
use windows_sys::Win32::Foundation::FWP_E_ALREADY_EXISTS;
use windows_sys::core::GUID;

use crate::firewall::{add_filters, resolve_apps};
use crate::plan::Plan;
use crate::wfp::{Engine, FilterInfo, Lifetime, WfpError};

/// Result of installing the baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineReport {
    /// Persistent filters now installed.
    pub persistent: usize,
    /// Boot-time copies now installed.
    pub boot_time: usize,
    /// Rules, filters or copies that were left out, with the reason.
    pub warnings: Vec<String>,
}

/// Installs the persistent rules of `plan` as the baseline.
///
/// Registers the persistent provider and sublayer if needed and replaces the
/// previous persistent filters in one transaction, so there is no moment
/// without a baseline. Then replaces the boot-time copies in a second
/// transaction. The copies only cover the time between the start of the
/// TCP/IP driver and the start of the Base Filtering Engine, so a failure
/// there is reported as a warning and keeps the previous copies.
///
/// Fails with `FWP_E_ALREADY_EXISTS` while a trial owns the provider.
pub fn install_baseline(plan: &Plan) -> Result<BaselineReport, WfpError> {
    let baseline = plan.only(Scope::Persistent);
    let (apps, mut warnings) = resolve_apps(&baseline.filters);
    warnings.extend(baseline.skipped.iter().map(|s| s.reason.clone()));

    let engine = Engine::open_static()?;
    let existing = engine.provider_filters()?;

    let persistent = engine.transaction(|e| {
        match e.provider()? {
            None => e.add_provider(true)?,
            Some(Lifetime::Persistent) => {}
            Some(_) => return Err(owned_by_trial("FwpmProviderGetByKey0")),
        }
        match e.sublayer()? {
            None => e.add_sublayer(true)?,
            Some(Lifetime::Persistent) => {}
            Some(_) => return Err(owned_by_trial("FwpmSubLayerGetByKey0")),
        }
        for key in keys(&existing, Lifetime::Persistent) {
            e.delete_filter_by_key(&key)?;
        }
        add_filters(e, &baseline.filters, &apps, Lifetime::Persistent)
    })?;

    let boot_time = engine.transaction(|e| {
        for key in keys(&existing, Lifetime::BootTime) {
            e.delete_filter_by_key(&key)?;
        }
        add_filters(e, &baseline.filters, &apps, Lifetime::BootTime)
    });
    let boot_time = match boot_time {
        Ok(added) => added.len(),
        Err(error) => {
            warnings.push(format!("boot-time copies not updated: {error}"));
            0
        }
    };

    Ok(BaselineReport {
        persistent: persistent.len(),
        boot_time,
        warnings,
    })
}

/// What [`remove_all`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemovalReport {
    /// Persistent and boot-time filters removed.
    pub filters: usize,
    /// The sublayer was removed.
    pub sublayer: bool,
    /// The provider was removed.
    pub provider: bool,
    /// What could not be removed, with the reason.
    pub failures: Vec<String>,
}

impl RemovalReport {
    /// Nothing of stop-internet is left in the Base Filtering Engine.
    pub fn is_complete(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Removes every object of the stop-internet provider: persistent and
/// boot-time filters, the sublayer and the provider.
///
/// Every object is removed on its own, so one failure does not keep the
/// others, and the persistent "block everything" filters go away even if
/// something else stays. Dynamic filters belong to a running service or
/// trial and disappear only when that process exits, so stop the service
/// first.
pub fn remove_all() -> Result<RemovalReport, WfpError> {
    let engine = Engine::open_static()?;
    let mut report = RemovalReport::default();

    let mut dynamic = 0;
    for filter in engine.provider_filters()? {
        if filter.lifetime == Lifetime::Dynamic {
            dynamic += 1;
            continue;
        }
        match engine.delete_filter_by_key(&filter.key) {
            Ok(()) => report.filters += 1,
            Err(error) => report.failures.push(error.to_string()),
        }
    }
    if dynamic > 0 {
        report.failures.push(format!(
            "{dynamic} session filters belong to a running stop-internet service or trial"
        ));
    }

    if engine.sublayer()?.is_some() {
        match engine.delete_sublayer() {
            Ok(()) => report.sublayer = true,
            Err(error) => report.failures.push(error.to_string()),
        }
    }
    if engine.provider()?.is_some() {
        match engine.delete_provider() {
            Ok(()) => report.provider = true,
            Err(error) => report.failures.push(error.to_string()),
        }
    }

    report.failures.sort();
    report.failures.dedup();
    Ok(report)
}

/// Objects of stop-internet currently in the Base Filtering Engine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inventory {
    /// Lifetime of the provider, `None` if it is not registered.
    pub provider: Option<Lifetime>,
    /// Lifetime of the sublayer, `None` if it does not exist.
    pub sublayer: Option<Lifetime>,
    /// Persistent filters: the baseline.
    pub persistent: usize,
    /// Boot-time copies of the baseline.
    pub boot_time: usize,
    /// Filters of a running service or trial.
    pub dynamic: usize,
}

/// Reads what stop-internet has in the Base Filtering Engine. Changes
/// nothing.
pub fn inventory() -> Result<Inventory, WfpError> {
    let engine = Engine::open_static()?;
    let mut inventory = Inventory {
        provider: engine.provider()?,
        sublayer: engine.sublayer()?,
        ..Default::default()
    };
    for filter in engine.provider_filters()? {
        match filter.lifetime {
            Lifetime::Persistent => inventory.persistent += 1,
            Lifetime::BootTime => inventory.boot_time += 1,
            Lifetime::Dynamic => inventory.dynamic += 1,
        }
    }
    Ok(inventory)
}

fn keys(filters: &[FilterInfo], lifetime: Lifetime) -> Vec<GUID> {
    filters
        .iter()
        .filter(|f| f.lifetime == lifetime)
        .map(|f| f.key)
        .collect()
}

fn owned_by_trial(operation: &'static str) -> WfpError {
    WfpError {
        operation,
        code: FWP_E_ALREADY_EXISTS as u32,
    }
}
