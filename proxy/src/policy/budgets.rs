//! Report and reset the existing shared GCRA state.

use super::{Action, BigInt, Context, Map, Policy, Value, fmt, split_destination};

/// Reporting failures retain the source exception category without exposing keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetStatsError {
    Overflow,
    InvalidClock,
    InvalidKey,
    Poisoned,
}

impl fmt::Display for BudgetStatsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Overflow => "budget report arithmetic overflow",
            Self::InvalidClock => "budget report timestamp must be finite",
            Self::InvalidKey => "budget report destination is invalid",
            Self::Poisoned => "budget state lock poisoned",
        })
    }
}

impl std::error::Error for BudgetStatsError {}

/// Reset failures never expose a supplied resource in diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetResetError {
    InvalidResource,
    Poisoned,
}

impl fmt::Display for BudgetResetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidResource => "budget reset resource is not hashable",
            Self::Poisoned => "budget state lock poisoned",
        })
    }
}

impl std::error::Error for BudgetResetError {}

impl Policy {
    /// Reset an exact tracker key, or all keys for an absent/falsy resource.
    /// Strings are neither parsed nor matched as patterns. Other truthy scalar
    /// values cannot equal the string keys created by request evaluation.
    /// Invalid containers fail before mutation. Reset shares the charge lock
    /// across clones and reloads and changes no policy or evaluation counter.
    /// The caller owns authentication, response formatting and reset evidence.
    pub fn reset_budgets(&self, resource: Option<&Value>) -> Result<(), BudgetResetError> {
        let resource = resource.filter(|value| match value {
            Value::Null => false,
            Value::Bool(value) => *value,
            Value::Number(value) => value.as_f64() != Some(0.0),
            Value::String(value) => !value.is_empty(),
            Value::Array(value) => !value.is_empty(),
            Value::Object(value) => !value.is_empty(),
        });
        if matches!(resource, Some(Value::Array(_) | Value::Object(_))) {
            return Err(BudgetResetError::InvalidResource);
        }
        let mut state = self
            .budgets
            .lock()
            .map_err(|_| BudgetResetError::Poisoned)?;
        if let Some(Value::String(key)) = resource {
            state.shift_remove(key);
        } else if resource.is_none() {
            state.clear();
        }
        Ok(())
    }

    pub(super) fn effective_network_budget(&self) -> Option<u64> {
        match (
            self.global_budget,
            self.task.as_ref().and_then(|task| task.global_budget),
        ) {
            (Some(baseline), Some(task)) => Some(baseline.min(task)),
            (baseline, task) => baseline.or(task),
        }
    }

    /// Report retained keys with the current rules and Python's empty context.
    /// Reads neither consume nor remove counters; old snapshots share the map.
    /// `now_ms` is epoch milliseconds, as in request evaluation.
    pub fn budget_stats(&self, now_ms: f64) -> Result<Value, BudgetStatsError> {
        if !now_ms.is_finite() {
            return Err(BudgetStatsError::InvalidClock);
        }
        let state = self
            .budgets
            .lock()
            .map_err(|_| BudgetStatsError::Poisoned)?;
        let mut usage = Map::new();
        for (key, tat) in state.iter() {
            let mut parts = key.splitn(3, ':');
            let (Some(namespace), Some(operation)) = (parts.next(), parts.next()) else {
                continue;
            };
            let resource = parts.next().unwrap_or("*");
            let connect = (namespace, operation) == ("network", "connect");
            let action = match (namespace, operation) {
                ("network", "request" | "connect") => Action::Network,
                ("credential", "use") => Action::Credential,
                _ => continue,
            };
            let budget = if resource == "__global__" {
                // Only the network path currently creates aggregate counters.
                match action {
                    Action::Network => self.effective_network_budget().map(BigInt::from),
                    _ => None,
                }
            } else {
                let (host, port) = match action {
                    Action::Network => {
                        split_destination(resource).map_err(|_| BudgetStatsError::InvalidKey)?
                    }
                    _ => (resource.to_owned(), None),
                };
                let context = Context {
                    port,
                    method: if connect { "CONNECT" } else { "GET" },
                    ..Default::default()
                };
                self.matching(action, &context, &format!("{host}/*"))
                    .or_else(|| self.matching(action, &context, "*"))
                    // The Python simple-permission stand-in has no budget.
                    .filter(|rule| !rule.simple())
                    .and_then(|rule| rule.reporting_budget.clone())
                    .filter(|budget| *budget != BigInt::from(0))
            };
            if let Some(budget) = budget {
                let remaining = remaining(now_ms, *tat, &budget)?;
                let mut entry = Map::new();
                entry.insert("budget_per_minute".into(), integer_value(&budget));
                entry.insert("remaining".into(), integer_value(&remaining));
                entry.insert("resource".into(), Value::String(resource.into()));
                usage.insert(key.clone(), Value::Object(entry));
            }
        }
        let mut result = Map::new();
        result.insert("tracked_keys".into(), Value::from(state.len()));
        result.insert("budgets".into(), Value::Object(usage));
        // An unrelated Any-valued timestamp prevents /policy JSON rendering,
        // but the validated integer budget submap remains reportable.
        result.insert(
            "global_budgets".into(),
            self.baseline
                .as_ref()
                .map(|baseline| baseline.value["budgets"].clone())
                .unwrap_or_else(|| Value::Object(Map::new())),
        );
        Ok(Value::Object(result))
    }
}

fn integer_value(integer: &BigInt) -> Value {
    Value::Number(
        integer
            .to_string()
            .parse()
            .expect("BigInt decimal is a JSON number"),
    )
}

fn float(integer: &BigInt) -> Result<f64, BudgetStatsError> {
    // Decimal conversion rounds to the same nearest binary64 value as Python's
    // int-to-float conversion, including arbitrary integers beyond u64.
    integer
        .to_string()
        .parse::<f64>()
        .ok()
        .filter(|number| number.is_finite())
        .ok_or(BudgetStatsError::Overflow)
}

fn remaining(now_ms: f64, tat: f64, budget: &BigInt) -> Result<BigInt, BudgetStatsError> {
    let interval = 60000.0 / float(budget)?;
    let burst = (budget / 10_u8).max(BigInt::from(1));
    let offset = interval * float(&burst)?;
    let remaining = (now_ms - (tat - offset)) / interval;
    if !remaining.is_finite() {
        return Err(BudgetStatsError::Overflow);
    }
    // Truncate before clamping. Precision zero formats this whole binary64 as
    // its exact decimal integer, retaining values too large for machine ints.
    let remaining = format!("{:.0}", remaining.trunc())
        .parse::<BigInt>()
        .expect("finite truncated float is an integer");
    Ok(remaining.min(burst).max(BigInt::from(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Effect, Format, NetworkRequest};

    #[test]
    fn reset_keeps_other_timestamps_and_does_not_consult_reporting() {
        let policy = Policy::parse_at(
            r#"{"budgets":{"network:request":1000},"permissions":[{"action":"network:request","resource":"*","effect":"budget","budget":1000}]}"#,
            Format::Json,
            1_000_000.,
        ).unwrap();
        for (host, now) in [("first.invalid", 1_000_000.), ("bad:port", 1_000_123.)] {
            assert_eq!(
                policy
                    .evaluate(
                        NetworkRequest {
                            agent: None,
                            host,
                            port: None,
                            method: "GET",
                            path: "/",
                        },
                        now,
                        true
                    )
                    .unwrap()
                    .effect,
                Effect::Allow
            );
        }
        assert_eq!(
            policy.budget_stats(1_000_123.),
            Err(BudgetStatsError::InvalidKey)
        );
        let before = policy.budgets.lock().unwrap().clone();
        policy
            .reset_budgets(Some(&Value::String("network:request:first.invalid".into())))
            .unwrap();
        {
            let after = policy.budgets.lock().unwrap();
            assert_eq!(after.len(), before.len() - 1);
            for (key, tat) in after.iter() {
                assert_eq!(tat.to_bits(), before[key].to_bits());
            }
        }
        // Exact reset can remove a retained key even when its destination makes
        // reporting fail. It does not parse the supplied key or read a clock.
        policy
            .reset_budgets(Some(&Value::String("network:request:bad:port".into())))
            .unwrap();
        assert_eq!(policy.budget_stats(1_000_123.).unwrap()["tracked_keys"], 1);
    }

    #[test]
    fn invalid_resource_precedes_poisoned_lock_without_exposing_values() {
        let policy = Policy::unconfigured();
        let copy = policy.clone();
        assert!(
            std::panic::catch_unwind(move || {
                let _lock = copy.budgets.lock().unwrap();
                panic!("synthetic budget owner failure");
            })
            .is_err()
        );
        let invalid = Value::Array(vec![Value::String("synthetic-private-input".into())]);
        assert_eq!(
            policy.reset_budgets(Some(&invalid)),
            Err(BudgetResetError::InvalidResource)
        );
        for resource in [None, Some(&Value::Null), Some(&Value::Bool(true))] {
            assert_eq!(
                policy.reset_budgets(resource),
                Err(BudgetResetError::Poisoned)
            );
        }
        for error in [
            BudgetResetError::InvalidResource,
            BudgetResetError::Poisoned,
        ] {
            assert!(!format!("{error} {error:?}").contains("synthetic-private-input"));
        }
    }

    #[test]
    fn shared_destination_parser_matches_actual_source_forms() {
        let fixtures: Value =
            serde_json::from_str(include_str!("../../tests/budgets_destinations.json")).unwrap();
        for row in fixtures["rows"].as_array().unwrap() {
            let input = row["input"].as_str().unwrap();
            let native = match split_destination(input) {
                Ok((host, port)) => serde_json::json!([host, port]),
                Err(_) => serde_json::json!({"error":"ValueError"}),
            };
            assert_eq!(native, row["result"], "{input}");
        }
    }
}
