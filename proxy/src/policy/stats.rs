//! Engine statistics from the existing canonical policy and shared live state.

use super::{Map, Ordering, Path, Policy, Value, fmt};

/// Reporting failures expose no policy paths or destination keys in diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineStatsError {
    PathEncoding,
    Poisoned,
}

impl fmt::Display for EngineStatsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PathEncoding => "policy statistics path is not Unicode",
            Self::Poisoned => "budget state lock poisoned",
        })
    }
}

impl std::error::Error for EngineStatsError {}

impl Policy {
    /// Report the same ordered fields as PolicyEngine.get_stats. Counts come
    /// from the canonical models, including their existing simple extraction;
    /// required addons include every configured name. Reading this report does
    /// not evaluate permissions, spend budgets or discard stale budget keys.
    pub fn engine_stats(&self) -> Result<Value, EngineStatsError> {
        let baseline = self.baseline.as_deref();
        let task = self.task.as_ref();
        let mut result = Map::new();
        result.insert(
            "baseline_path".into(),
            path_value(self.baseline_path.as_deref())?,
        );
        result.insert(
            "task_policy_path".into(),
            path_value(task.and_then(|task| task.path.as_deref()))?,
        );
        result.insert(
            "baseline_permissions".into(),
            Value::from(baseline.map_or(0, |baseline| {
                baseline.value["permissions"]
                    .as_array()
                    .expect("canonical permission array")
                    .len()
            })),
        );
        result.insert(
            "task_permissions".into(),
            Value::from(task.map_or(0, |task| {
                task.baseline.value["permissions"]
                    .as_array()
                    .expect("canonical permission array")
                    .len()
            })),
        );
        result.insert(
            "required_addons".into(),
            baseline.map_or_else(
                || Value::Array(Vec::new()),
                |baseline| baseline.value["required"].clone(),
            ),
        );
        result.insert(
            "evaluations".into(),
            Value::from(self.evaluations.load(Ordering::Relaxed)),
        );
        let budgets = self
            .budgets
            .lock()
            .map_err(|_| EngineStatsError::Poisoned)?;
        let mut budget_stats = Map::new();
        budget_stats.insert("tracked_keys".into(), Value::from(budgets.len()));
        budget_stats.insert(
            "keys".into(),
            Value::Array(budgets.keys().cloned().map(Value::String).collect()),
        );
        result.insert("budget_stats".into(), Value::Object(budget_stats));
        Ok(Value::Object(result))
    }
}

fn path_value(path: Option<&Path>) -> Result<Value, EngineStatsError> {
    let Some(path) = path else {
        return Ok(Value::Null);
    };
    let raw = path.to_str().ok_or(EngineStatsError::PathEncoding)?;
    // The supported Unix runtime uses pathlib.PosixPath: remove repeated slash
    // and '.' segments, preserve '..', and retain exactly two initial slashes.
    // This is lexical display only, never canonicalization or a filesystem read.
    let prefix = if raw.starts_with("//") && !raw.starts_with("///") {
        "//"
    } else if raw.starts_with('/') {
        "/"
    } else {
        ""
    };
    let tail = raw
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/");
    let rendered = format!("{prefix}{tail}");
    Ok(Value::String(if rendered.is_empty() {
        ".".into()
    } else {
        rendered
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Format, NetworkRequest};

    #[test]
    fn lexical_paths_match_actual_posix_path_display() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../tests/engine_stats_source.json")).unwrap();
        for row in fixture["path_rows"].as_array().unwrap() {
            assert_eq!(
                path_value(Some(Path::new(row["raw"].as_str().unwrap()))).unwrap(),
                row["display"]
            );
        }
    }

    #[test]
    fn tracker_reset_does_not_reset_the_separate_evaluation_count() {
        let policy = Policy::parse(
            r#"{"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":10}]}"#,
            Format::Json,
        ).unwrap();
        for host in ["first.invalid", "second.invalid"] {
            policy
                .evaluate(
                    NetworkRequest {
                        agent: None,
                        host,
                        port: None,
                        method: "GET",
                        path: "/",
                    },
                    1_000_000.,
                    true,
                )
                .unwrap();
        }
        let before = policy.engine_stats().unwrap();
        assert_eq!(before["budget_stats"]["tracked_keys"], 2);
        assert_eq!(before["evaluations"], 2);
        // The existing tracker owner has no public reset API yet. Clear only
        // its private state, as the shipped tracker reset_all does; no new
        // endpoint or reset behavior is introduced by statistics reporting.
        policy.budgets.lock().unwrap().clear();
        let after = policy.engine_stats().unwrap();
        assert_eq!(after["budget_stats"]["tracked_keys"], 0);
        assert_eq!(after["evaluations"], 2);
    }

    #[test]
    fn poisoned_tracker_is_an_explicit_reporting_error() {
        let policy = Policy::unconfigured();
        let copy = policy.clone();
        let result = std::panic::catch_unwind(move || {
            let _locked = copy.budgets.lock().unwrap();
            panic!("synthetic tracker owner failure");
        });
        assert!(result.is_err());
        assert_eq!(policy.engine_stats(), Err(EngineStatsError::Poisoned));
    }
}
