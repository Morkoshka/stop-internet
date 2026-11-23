//! The firewall: keeps the filters of the current plan in the Base Filtering
//! Engine and replaces them atomically when the plan changes.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::plan::Plan;
use crate::wfp::{AppId, AppIds, Engine, WfpError};

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
    /// Opens a dynamic session and registers the provider and the sublayer.
    pub fn open_dynamic() -> Result<Self, WfpError> {
        let engine = Engine::open_dynamic()?;
        engine.transaction(|e| {
            e.add_provider()?;
            e.add_sublayer()
        })?;
        Ok(Self {
            engine,
            active: Vec::new(),
        })
    }

    /// Replaces the active filters with the filters of `plan` in one
    /// transaction. On error the previous filters stay in place.
    pub fn apply(&mut self, plan: &Plan) -> Result<ApplyReport, WfpError> {
        let mut warnings = plan.skipped.clone();

        let paths: BTreeSet<&PathBuf> = plan.filters.iter().filter_map(|f| f.app_path()).collect();
        let mut apps = AppIds::new();
        for path in paths {
            match AppId::for_path(path) {
                Ok(id) => {
                    apps.insert(path.clone(), id);
                }
                Err(error) => warnings.push(format!("app {} skipped: {error}", file_name(path))),
            }
        }

        let previous = &self.active;
        let added = self.engine.transaction(|engine| {
            for &id in previous {
                engine.delete_filter(id)?;
            }
            let mut added = Vec::with_capacity(plan.filters.len());
            for spec in &plan.filters {
                if spec.app_path().is_some_and(|path| !apps.contains_key(path)) {
                    continue;
                }
                added.push(engine.add_filter(spec, &apps)?);
            }
            Ok(added)
        })?;

        self.active = added;
        Ok(ApplyReport {
            filters: self.active.len(),
            warnings,
        })
    }
}

/// Only the file name, so that messages do not reveal user folders.
fn file_name(path: &std::path::Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}
