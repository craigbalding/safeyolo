//! Read the current matcher against retained GCRA timestamps without charging.

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

impl Policy {
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
