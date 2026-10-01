//! Borrow the source circuit addon's direct fields from the canonical baseline.
//!
//! The HTTP sensor-config serializer is a separate, fallible boundary. This
//! local view neither serializes arbitrary values nor installs circuit defaults.

use super::{Map, Policy, TemporalValue, TimestampPaths, Value};

/// Settings can contain arbitrary operator values. Do not add data-bearing
/// Debug/Serialize implementations or copy this view into diagnostics.
///
/// JSON-shaped values are meaningful only together with temporal provenance:
/// a parsed date must not become an authored string or date-like object.
pub(crate) struct CircuitSettings<'a> {
    hash: String,
    values: Option<&'a Map<String, Value>>,
    timestamps: Option<&'a TimestampPaths>,
}

impl Policy {
    /// Current policy identity includes the task; circuit settings come only
    /// from baseline addons.circuit_breaker, exactly as LocalPolicyClient emits.
    /// The only owned data here is the existing computed 23-byte hash.
    pub(crate) fn circuit_settings(&self) -> CircuitSettings<'_> {
        let baseline = self.baseline.as_deref();
        CircuitSettings {
            hash: self.policy_hash(),
            values: baseline.and_then(|owner| {
                owner.value["addons"]
                    .get("circuit_breaker")
                    .map(|addon| addon.as_object().expect("canonical addon is an object"))
            }),
            timestamps: baseline.map(|owner| &owner.timestamps),
        }
    }
}

impl<'a> CircuitSettings<'a> {
    pub(crate) fn hash(&self) -> &str {
        &self.hash
    }

    /// None distinguishes an omitted addon from its explicitly configured
    /// empty form, whose canonical fields include enabled=true and settings={}.
    /// Consumers select direct fields; nested .settings is not flattened.
    pub(crate) fn values(&self) -> Option<&'a Map<String, Value>> {
        self.values
    }

    /// Paths are relative to addons.circuit_breaker; array indices use decimal
    /// strings. Return the parser-owned value without converting its type.
    pub(crate) fn temporal_value(&self, path: &[&str]) -> Option<&'a TemporalValue> {
        self.timestamps?.value_at(&absolute_path(path))
    }

    /// A temporal mapping key has a distinct identity from a quoted lookalike.
    /// Use the canonical map's key as the final relative path component.
    pub(crate) fn temporal_key(&self, path: &[&str]) -> Option<&'a TemporalValue> {
        self.timestamps?.key_at(&absolute_path(path))
    }
}

fn absolute_path<'a>(path: &[&'a str]) -> Vec<&'a str> {
    ["addons", "circuit_breaker"]
        .into_iter()
        .chain(path.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Format, NetworkRequest};
    use serde_json::json;

    fn source_rows() -> Vec<Value> {
        super::super::parse_json(
            include_str!("../../tests/circuit_settings_source.json"),
            false,
        )
        .unwrap()["rows"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn described(view: &CircuitSettings<'_>, value: &Value, path: &[&str]) -> Value {
        if let Some(temporal) = view.temporal_value(path) {
            return json!({"temporal":temporal.python_display()});
        }
        match value {
            Value::Object(values) => json!({"mapping":values.iter().map(|(key,value)| {
                let mut child=path.to_vec();
                child.push(key);
                let key=view.temporal_key(&child).map_or_else(|| json!(key),|value| json!({"temporal":value.python_display()}));
                json!({"key":key,"value":described(view,value,&child)})
            }).collect::<Vec<_>>()}),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        let index = index.to_string();
                        let mut child = path.to_vec();
                        child.push(&index);
                        described(view, value, &child)
                    })
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    fn consume(policy: &Policy) {
        let request = NetworkRequest {
            agent: None,
            host: "fixture.invalid",
            port: None,
            method: "GET",
            path: "/",
        };
        assert_eq!(
            policy.evaluate(request, 1_000_000., true).unwrap().effect,
            crate::policy::Effect::Allow
        );
    }

    #[test]
    fn direct_projection_matches_actual_local_policy_client() {
        for row in source_rows() {
            let format = match row["format"].as_str().unwrap() {
                "toml" => Format::Toml,
                "yaml" => Format::Yaml,
                "json" => Format::Json,
                _ => unreachable!(),
            };
            let policy = row["source"]
                .as_str()
                .map_or_else(Policy::unconfigured, |source| {
                    Policy::parse_at(source, format, 0.).unwrap()
                });
            if row["evaluations"] == 1 {
                consume(&policy);
            }
            let policy = row["task_source"].as_str().map_or_else(
                || policy.clone(),
                |task| policy.with_task_source(task, Format::Json).unwrap(),
            );
            let stats = policy.engine_stats().unwrap();
            let budgets = policy.budget_stats(1_000_000.).unwrap();
            let hash = policy.policy_hash();
            let view = policy.circuit_settings();
            assert_eq!(view.hash(), row["hash"], "{}", row["case"]);
            let values = view.values().map_or(Value::Null, |values| {
                described(&view, &Value::Object(values.clone()), &[])
            });
            assert_eq!(values, row["values"], "{}", row["case"]);
            assert_eq!(policy.sensor_config().is_ok(), row["http_sensor_json_ok"]);
            assert_eq!(policy.engine_stats().unwrap(), stats);
            assert_eq!(policy.budget_stats(1_000_000.).unwrap(), budgets);
            assert_eq!(policy.policy_hash(), hash);
            assert_eq!(stats["evaluations"], row["evaluations"]);
            assert_eq!(stats["budget_stats"]["tracked_keys"], row["tracked_keys"]);
        }
    }

    #[test]
    fn omitted_empty_and_nested_fields_keep_distinct_meanings() {
        let omitted = Policy::parse_at("{}", Format::Json, 0.).unwrap();
        assert!(omitted.circuit_settings().values().is_none());
        let empty = Policy::parse_at("[addons.circuit_breaker]", Format::Toml, 0.).unwrap();
        assert_eq!(
            empty.circuit_settings().values(),
            json!({"enabled":true,"settings":{}}).as_object()
        );
        let nested = Policy::parse_at(
            "[addons.circuit_breaker.settings]\nfailure_threshold=31",
            Format::Toml,
            0.,
        )
        .unwrap();
        let view = nested.circuit_settings();
        let values = view.values().unwrap();
        assert!(!values.contains_key("failure_threshold"));
        assert_eq!(values["settings"]["failure_threshold"], 31);
        assert!(std::ptr::eq(
            values,
            nested.baseline.as_ref().unwrap().value["addons"]["circuit_breaker"]
                .as_object()
                .unwrap()
        ));
        assert_ne!(
            omitted.circuit_settings().hash(),
            empty.circuit_settings().hash()
        );
    }

    #[test]
    fn temporal_provenance_is_borrowed_and_cannot_escape_the_addon() {
        let policy=Policy::parse_at("addons:\n  circuit_breaker:\n    failure_threshold: 2001-02-03\n    excluded_domains:\n      2001-02-03: true\n      '2001-02-03': false\n  unused:\n    settings: {observed: 2001-02-04}\n",Format::Yaml,0.).unwrap();
        assert!(policy.sensor_config().is_err());
        let view = policy.circuit_settings();
        assert!(std::ptr::eq(
            view.temporal_value(&["failure_threshold"]).unwrap(),
            policy
                .baseline
                .as_ref()
                .unwrap()
                .timestamps
                .value_at(&["addons", "circuit_breaker", "failure_threshold"])
                .unwrap()
        ));
        let map = view.values().unwrap()["excluded_domains"]
            .as_object()
            .unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.keys()
                .filter(|key| view.temporal_key(&["excluded_domains", key]).is_some())
                .count(),
            1
        );
        assert!(
            view.temporal_key(&["excluded_domains", "2001-02-03"])
                .is_none()
        );
        assert!(
            view.temporal_value(&["unused", "settings", "observed"])
                .is_none()
        );
        assert!(
            view.temporal_value(&["..", "unused", "settings", "observed"])
                .is_none()
        );
    }

    #[test]
    fn task_and_reload_views_preserve_shared_budget_and_evaluation_owners() {
        let rows = source_rows();
        let find = |name| rows.iter().find(|row| row["case"] == name).unwrap();
        let initial = find("charged_baseline");
        let baseline =
            Policy::parse_at(initial["source"].as_str().unwrap(), Format::Json, 0.).unwrap();
        consume(&baseline);
        let budgets = baseline.budget_stats(1_000_000.).unwrap();
        let evaluations = baseline.engine_stats().unwrap()["evaluations"].clone();
        let source_task = find("task_changes_hash_not_baseline_addon");
        let task = baseline
            .with_task_source(source_task["task_source"].as_str().unwrap(), Format::Json)
            .unwrap();
        assert_eq!(task.circuit_settings().hash(), source_task["hash"]);
        assert!(std::ptr::eq(
            task.circuit_settings().values().unwrap(),
            baseline.circuit_settings().values().unwrap()
        ));
        assert!(Arc::ptr_eq(&task.budgets, &baseline.budgets));
        let source_reload = find("valid_reload_retains_budget_and_raw_value");
        let reload = baseline
            .reload_from_source_at(source_reload["source"].as_str().unwrap(), Format::Json, 0.)
            .unwrap();
        assert_eq!(reload.circuit_settings().hash(), source_reload["hash"]);
        assert_eq!(
            reload.circuit_settings().values().unwrap()["failure_threshold"],
            "later-error"
        );
        assert!(
            reload
                .reload_from_source_at(r#"{"permissions":false}"#, Format::Json, 0.)
                .is_err()
        );
        assert_eq!(
            reload.circuit_settings().hash(),
            find("invalid_reload_retains_last_projection")["hash"]
        );
        for current in [&baseline, &task, &reload] {
            assert_eq!(current.budget_stats(1_000_000.).unwrap(), budgets);
            assert_eq!(current.engine_stats().unwrap()["evaluations"], evaluations);
            assert!(Arc::ptr_eq(&current.budgets, &baseline.budgets));
            assert!(Arc::ptr_eq(&current.evaluations, &baseline.evaluations));
        }
    }

    use std::sync::Arc;
}
