//! The firewall: keeps the filters of the current plan in the Base Filtering
//! Engine and replaces them atomically when the plan changes.

use std::collections::BTreeSet;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{FWP_E_ALREADY_EXISTS, FWP_E_SUBLAYER_NOT_FOUND};

use crate::plan::{FilterSpec, Plan};
use crate::wfp::{AppId, AppIds, Engine, Lifetime, WfpError};

/// Result of applying a plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// Number of filters now active.
    pub filters: usize,
    /// Rules or filters that were left out, with the reason.
    pub warnings: Vec<String>,
}

/// Firewall backed by a dynamic WFP session.
///
/// Every filter disappears when the firewall is dropped or the process
/// exits, so a mistake cannot leave the machine offline.
#[derive(Debug)]
pub struct Firewall {
    engine: Engine,
    active: Vec<u64>,
}

impl Firewall {
    /// Opens a dynamic session and registers the provider and the sublayer
    /// in it, so that nothing of stop-internet outlives the process. Used by
    /// trials and by the service in session-only mode.
    ///
    /// Fails with `FWP_E_ALREADY_EXISTS` when the provider is already
    /// registered: by a running trial, or persistently by the service.
    pub fn open_dynamic() -> Result<Self, WfpError> {
        let engine = Engine::open_dynamic()?;
        engine.transaction(|e| {
            e.add_provider(false)?;
            e.add_sublayer(false)
        })?;
        Ok(Self {
            engine,
            active: Vec::new(),
        })
    }

    /// Opens a dynamic session for the session rules on top of the
    /// persistent baseline. The persistent provider and sublayer must exist,
    /// see [`install_baseline`](crate::persistent::install_baseline).
    pub fn attach() -> Result<Self, WfpError> {
        let engine = Engine::open_dynamic()?;
        match engine.sublayer()? {
            Some(Lifetime::Persistent) => {}
            None => {
                return Err(WfpError {
                    operation: "FwpmSubLayerGetByKey0",
                    code: FWP_E_SUBLAYER_NOT_FOUND as u32,
                });
            }
            // A trial owns the sublayer.
            Some(_) => {
                return Err(WfpError {
                    operation: "FwpmSubLayerGetByKey0",
                    code: FWP_E_ALREADY_EXISTS as u32,
                });
            }
        }
        Ok(Self {
            engine,
            active: Vec::new(),
        })
    }

    /// Replaces the active filters with the filters of `plan` in one
    /// transaction. On error the previous filters stay in place.
    pub fn apply(&mut self, plan: &Plan) -> Result<ApplyReport, WfpError> {
        let (apps, mut warnings) = resolve_apps(&plan.filters);
        warnings.extend(plan.skipped.iter().map(|s| s.reason.clone()));

        let previous = &self.active;
        let added = self.engine.transaction(|engine| {
            for &id in previous {
                engine.delete_filter(id)?;
            }
            add_filters(engine, &plan.filters, &apps, Lifetime::Dynamic)
        })?;

        self.active = added;
        Ok(ApplyReport {
            filters: self.active.len(),
            warnings,
        })
    }
}

/// Looks up the application ids of every executable the filters refer to.
/// Executables that cannot be resolved, usually because the file does not
/// exist, are reported and their filters are left out by [`add_filters`].
pub(crate) fn resolve_apps(filters: &[FilterSpec]) -> (AppIds, Vec<String>) {
    let paths: BTreeSet<&PathBuf> = filters.iter().filter_map(|f| f.app_path()).collect();
    let mut apps = AppIds::new();
    let mut warnings = Vec::new();
    for path in paths {
        match AppId::for_path(path) {
            Ok(id) => {
                apps.insert(path.clone(), id);
            }
            Err(error) => warnings.push(format!("app {} skipped: {error}", file_name(path))),
        }
    }
    (apps, warnings)
}

/// Adds the filters whose executables are resolved and returns their ids.
pub(crate) fn add_filters(
    engine: &Engine,
    filters: &[FilterSpec],
    apps: &AppIds,
    lifetime: Lifetime,
) -> Result<Vec<u64>, WfpError> {
    let mut added = Vec::with_capacity(filters.len());
    for spec in filters {
        if spec.app_path().is_some_and(|path| !apps.contains_key(path)) {
            continue;
        }
        added.push(engine.add_filter(spec, apps, lifetime)?);
    }
    Ok(added)
}

/// Only the file name, so that messages do not reveal user folders.
fn file_name(path: &std::path::Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}
