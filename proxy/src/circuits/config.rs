//! Apply the source circuit addon's direct settings to the existing state owner.
//! Omitted fields retain values; a failed exclusion update retains prior writes.

use super::{
    CircuitBreaker, CircuitValue, ErrorKind, Inner, Result, Settings, failure_kind, invalid,
};
use crate::policy::{Policy, TimestampPaths, circuit_settings::CircuitSettings};
use serde_json::{Map, Value};

impl CircuitBreaker {
    /// Refresh from the canonical policy without serializing its arbitrary values.
    /// This focused facade takes the circuit lock once. A caller that also performs
    /// a circuit operation must use `config::apply` under that same existing lock.
    pub fn apply_policy_config(&self, policy: &Policy) -> Result<bool> {
        let view = policy.circuit_settings();
        apply(&mut *self.lock()?, &view)
    }
}

/// The parent circuit module can refresh and operate without releasing Inner.
pub(super) fn apply(inner: &mut Inner, view: &CircuitSettings<'_>) -> Result<bool> {
    if view.hash() == inner.policy_hash {
        return Ok(false);
    }
    assign_and_commit(inner, view.hash(), view.values(), Some(view))
}

// Preserve the existing raw-cache shape checks as a separate compatibility
// boundary. Real Policy views have canonical mapping structure and string hashes.
pub(super) fn apply_sensor_config(circuit: &CircuitBreaker, sensor: &Value) -> Result<bool> {
    let sensor = sensor
        .as_object()
        .ok_or_else(|| invalid("sensor config must be an object"))?;
    let hash = sensor
        .get("policy_hash")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid("policy hash must be a string"))
        })
        .transpose()?
        .unwrap_or("");
    let mut inner = circuit.lock()?;
    if hash == inner.policy_hash {
        return Ok(false);
    }
    let values = sensor
        .get("addons")
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| invalid("addons must be an object"))
        })
        .transpose()?
        .and_then(|addons| addons.get("circuit_breaker"))
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| invalid("circuit settings must be an object"))
        })
        .transpose()?;
    assign_and_commit(&mut inner, hash, values, None)
}

fn assign_and_commit(
    inner: &mut Inner,
    hash: &str,
    values: Option<&Map<String, Value>>,
    view: Option<&CircuitSettings<'_>>,
) -> Result<bool> {
    if let Some(values) = values {
        assign(&mut inner.settings, values, view)?;
    }
    // Source updates the last hash only after every assignment/set update returns.
    inner.policy_hash = hash.to_owned();
    Ok(true)
}

fn assign(
    settings: &mut Settings,
    values: &Map<String, Value>,
    view: Option<&CircuitSettings<'_>>,
) -> Result<()> {
    for (name, target) in [
        ("failure_threshold", &mut settings.failure_threshold),
        ("success_threshold", &mut settings.success_threshold),
        ("timeout_seconds", &mut settings.timeout_seconds),
        (
            "half_open_max_requests",
            &mut settings.half_open_max_requests,
        ),
    ] {
        if let Some(value) = values.get(name) {
            *target = operand(value, name, view);
        }
    }
    if let Some(value) = values.get("use_exponential_backoff") {
        // This existing bool field is observed only in a Python truth test.
        settings.use_exponential_backoff =
            temporal_value(view, &["use_exponential_backoff"]) || super::truthy(value);
    }
    for (name, target) in [
        ("max_timeout_seconds", &mut settings.max_timeout_seconds),
        ("backoff_multiplier", &mut settings.backoff_multiplier),
        ("jitter_factor", &mut settings.jitter_factor),
        ("streak_decay_seconds", &mut settings.streak_decay_seconds),
    ] {
        if let Some(value) = values.get(name) {
            *target = operand(value, name, view);
        }
    }
    if let Some(value) = values.get("excluded_domains") {
        extend_exclusions(settings, value, view)?;
    }
    Ok(())
}

fn temporal_value(view: Option<&CircuitSettings<'_>>, path: &[&str]) -> bool {
    view.is_some_and(|view| view.temporal_value(path).is_some())
}

// Retain only consumed field provenance. Stop at temporal nodes: their storage
// shape is not a second ordinary Python object that can be traversed or matched.
fn operand(value: &Value, field: &str, view: Option<&CircuitSettings<'_>>) -> CircuitValue {
    let Some(view) = view else {
        return value.clone().into();
    };
    let mut annotations = TimestampPaths::default();
    let mut pending = vec![(value, vec![field.to_owned()])];
    while let Some((value, path)) = pending.pop() {
        let borrowed: Vec<_> = path.iter().map(String::as_str).collect();
        if let Some(temporal) = view.temporal_value(&borrowed) {
            annotations.insert_value(&borrowed[1..], temporal.clone());
            continue;
        }
        match value {
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    let mut child = path.clone();
                    child.push(index.to_string());
                    pending.push((value, child));
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    let mut child = path.clone();
                    child.push(key.clone());
                    let borrowed: Vec<_> = child.iter().map(String::as_str).collect();
                    if let Some(temporal) = view.temporal_key(&borrowed) {
                        annotations.insert_key(&borrowed[1..], temporal.clone());
                    }
                    pending.push((value, child));
                }
            }
            _ => {}
        }
    }
    CircuitValue::from_annotated(value.clone(), annotations)
}

fn extend_exclusions(
    settings: &mut Settings,
    value: &Value,
    view: Option<&CircuitSettings<'_>>,
) -> Result<()> {
    if temporal_value(view, &["excluded_domains"]) {
        return Err(failure_kind(
            ErrorKind::Type,
            "excluded domains are not iterable",
        ));
    }
    if !super::truthy(value) {
        return Ok(());
    }
    match value {
        Value::String(value) => settings
            .excluded_domains
            .extend(value.chars().map(|character| character.to_string())),
        Value::Object(values) => {
            // A dict update consumes keys only. Temporal keys are hashable but
            // cannot equal a string HTTP host; private storage IDs must not leak.
            for key in values.keys() {
                if view.is_none_or(|view| view.temporal_key(&["excluded_domains", key]).is_none()) {
                    settings.excluded_domains.insert(key.clone());
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let index = index.to_string();
                if temporal_value(view, &["excluded_domains", &index]) {
                    continue;
                }
                match value {
                    Value::String(value) => {
                        settings.excluded_domains.insert(value.clone());
                    }
                    Value::Array(_) | Value::Object(_) => {
                        return Err(failure_kind(
                            ErrorKind::Type,
                            "excluded domain entry is not hashable",
                        ));
                    }
                    // Other hashable scalars cannot equal a string host.
                    _ => {}
                }
            }
        }
        _ => {
            return Err(failure_kind(
                ErrorKind::Type,
                "excluded domains are not iterable",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Format, NetworkRequest};
    use serde_json::json;

    fn described_value(value: &Value, types: &TimestampPaths, path: &[&str]) -> Value {
        if let Some(value) = types.value_at(path) {
            return json!({"temporal": value.python_display()});
        }
        match value {
            Value::Object(values) => json!({"mapping": values.iter().map(|(key, value)| {
                let mut child = path.to_vec();
                child.push(key);
                let key = types.key_at(&child).map_or_else(|| json!(key), |value| json!({"temporal":value.python_display()}));
                json!({"key":key,"value":described_value(value,types,&child)})
            }).collect::<Vec<_>>()}),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        let index = index.to_string();
                        let mut child = path.to_vec();
                        child.push(&index);
                        described_value(value, types, &child)
                    })
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    fn described(value: &CircuitValue) -> Value {
        if let Some((value, types)) = value.annotated() {
            described_value(value, types, &[])
        } else {
            described_value(&value.json().unwrap(), &TimestampPaths::default(), &[])
        }
    }

    fn settings(settings: &Settings) -> Value {
        json!({
            "failure_threshold":described(&settings.failure_threshold),
            "success_threshold":described(&settings.success_threshold),
            "timeout_seconds":described(&settings.timeout_seconds),
            "half_open_max_requests":described(&settings.half_open_max_requests),
            "use_exponential_backoff":settings.use_exponential_backoff,
            "max_timeout_seconds":described(&settings.max_timeout_seconds),
            "backoff_multiplier":described(&settings.backoff_multiplier),
            "jitter_factor":described(&settings.jitter_factor),
            "streak_decay_seconds":described(&settings.streak_decay_seconds),
        })
    }

    fn error_name(kind: ErrorKind) -> &'static str {
        match kind {
            ErrorKind::Type => "TypeError",
            ErrorKind::Value => "ValueError",
            ErrorKind::Overflow => "OverflowError",
            ErrorKind::ZeroDivision => "ZeroDivisionError",
            ErrorKind::Compatibility => "Compatibility",
            ErrorKind::Invalid => "Invalid",
            ErrorKind::Audit(_) => "Audit",
        }
    }

    #[test]
    fn source_config_application_trace_and_reached_operations() {
        let fixture = crate::policy::parse_json(
            include_str!("../../tests/circuit_config_source.json"),
            false,
        )
        .unwrap();
        let mut observed_steps = 0;
        for row in fixture["rows"].as_array().unwrap() {
            let cb = CircuitBreaker::new();
            for step in row["steps"].as_array().unwrap() {
                observed_steps += 1;
                let input = &step["input"];
                let result = if let Some(raw) = input.get("raw") {
                    cb.apply_sensor_config(raw)
                } else {
                    let format = match input["format"].as_str().unwrap() {
                        "json" => Format::Json,
                        "toml" => Format::Toml,
                        "yaml" => Format::Yaml,
                        _ => unreachable!(),
                    };
                    let policy = input["source"]
                        .as_str()
                        .map_or_else(Policy::unconfigured, |source| {
                            Policy::parse_at(source, format, 0.).unwrap()
                        });
                    let before = (
                        policy.engine_stats().unwrap(),
                        policy.budget_stats(100_000.).unwrap(),
                        policy.policy_hash(),
                    );
                    let result = cb.apply_policy_config(&policy);
                    assert_eq!(
                        before,
                        (
                            policy.engine_stats().unwrap(),
                            policy.budget_stats(100_000.).unwrap(),
                            policy.policy_hash()
                        )
                    );
                    result
                };
                let name = format!("{} step {}", row["case"], step["index"]);
                if input["structural_gap"] == true {
                    assert_eq!(result.unwrap_err().kind(), ErrorKind::Invalid, "{name}");
                    assert_eq!(
                        step["error"], "AttributeError",
                        "source raw-cache structural failure differs categorically"
                    );
                } else if step["error"].is_null() {
                    assert_eq!(
                        result.unwrap(),
                        step["changed"].as_bool().unwrap(),
                        "{name}"
                    );
                } else {
                    assert_eq!(
                        error_name(result.unwrap_err().kind()),
                        step["error"].as_str().unwrap(),
                        "{name}"
                    );
                }
                if let Some(operation) = input["operation"].as_str() {
                    let result = if operation == "failure" {
                        cb.record_failure("owned.invalid", None, 100., &mut || 0.5)
                            .map(|_| Value::Null)
                    } else {
                        cb.settings()
                            .unwrap()
                            .calculate_timeout(
                                if operation == "timeout0" { 0 } else { 1 },
                                &mut || 0.5,
                            )
                            .map(|value| described(&value))
                    };
                    let actual = match result {
                        Ok(value) => json!({"value":value,"error":null}),
                        Err(error) => json!({"value":null,"error":error_name(error.kind())}),
                    };
                    assert_eq!(actual, step["operation"], "{name} operation");
                }
                let rendered = cb
                    .stats_document(true, 100., &mut || 0.5)
                    .and_then(|value| value.value.render_json(false));
                assert_eq!(
                    rendered.err().map(|error| error_name(error.kind())),
                    step["stats_json_error"].as_str(),
                    "{name} stats JSON"
                );
                let inner = cb.lock().unwrap();
                assert_eq!(
                    inner.policy_hash,
                    step["last_hash"].as_str().unwrap(),
                    "{name} hash"
                );
                assert_eq!(
                    settings(&inner.settings),
                    step["settings"],
                    "{name} settings"
                );
                assert_eq!(
                    json!(inner.settings.excluded_domains),
                    step["excluded_strings"],
                    "{name} exclusions"
                );
            }
        }
        assert_eq!(fixture["rows"].as_array().unwrap().len(), 21);
        assert_eq!(observed_steps, 44);
        assert_eq!(fixture["network_attempts"], 0);
    }

    #[test]
    fn partial_exclusion_error_keeps_all_assignments_and_does_not_commit_hash() {
        let cb = CircuitBreaker::new();
        let source = "addons: {circuit_breaker: {failure_threshold: 1, use_exponential_backoff: false, jitter_factor: 0, excluded_domains: ['first.invalid', {}, 'never.invalid']}}";
        let policy = Policy::parse_at(source, Format::Yaml, 0.).unwrap();
        assert_eq!(
            cb.apply_policy_config(&policy).unwrap_err().kind(),
            ErrorKind::Type
        );
        {
            let inner = cb.lock().unwrap();
            assert_eq!(inner.policy_hash, "");
            assert_eq!(inner.settings.failure_threshold, 1);
            assert!(!inner.settings.use_exponential_backoff);
            assert_eq!(inner.settings.jitter_factor, 0);
            assert!(inner.settings.excluded_domains.contains("first.invalid"));
            assert!(!inner.settings.excluded_domains.contains("never.invalid"));
        }
        assert_eq!(
            cb.apply_policy_config(&policy).unwrap_err().kind(),
            ErrorKind::Type,
            "failed hash must be retried"
        );
        assert_eq!(
            cb.record_failure("owned.invalid", None, 100., &mut || 0.5)
                .unwrap()
                .value
                .state,
            super::super::State::Open,
            "partially assigned threshold affects the next reached operation"
        );
    }

    #[test]
    fn locked_refresh_and_operation_use_same_state_without_policy_observations() {
        let policy=Policy::parse_at(r#"{"permissions":[{"action":"network:request","resource":"owned.invalid/*","effect":"budget","budget":1}],"addons":{"circuit_breaker":{"failure_threshold":1,"jitter_factor":0}}}"#,Format::Json,0.).unwrap();
        policy
            .evaluate(
                NetworkRequest {
                    agent: None,
                    host: "owned.invalid",
                    port: None,
                    method: "GET",
                    path: "/",
                },
                100_000.,
                true,
            )
            .unwrap();
        let before = (
            policy.engine_stats().unwrap(),
            policy.budget_stats(100_000.).unwrap(),
            policy.policy_hash(),
        );
        let cb = CircuitBreaker::new();
        let clone = cb.clone();
        let view = policy.circuit_settings();
        {
            let mut inner = cb.lock().unwrap();
            assert!(apply(&mut inner, &view).unwrap());
            let mut events = Vec::new();
            let status = super::super::failure(
                &mut inner,
                "owned.invalid",
                None,
                100.,
                &mut || 0.5,
                &mut events,
                None,
            )
            .unwrap();
            assert_eq!(status.state, super::super::State::Open);
            assert_eq!(events.len(), 1);
            assert!(!apply(&mut inner, &view).unwrap());
        }
        assert_eq!(clone.settings().unwrap().failure_threshold, 1);
        assert_eq!(
            clone
                .status("owned.invalid", 100., &mut || 0.5)
                .unwrap()
                .value
                .state,
            super::super::State::Open
        );
        assert_eq!(
            before,
            (
                policy.engine_stats().unwrap(),
                policy.budget_stats(100_000.).unwrap(),
                policy.policy_hash()
            )
        );
    }

    #[test]
    #[ignore = "requires repository Python dependencies; executes actual production config methods"]
    fn live_source_config_application_oracle() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let python = std::env::var_os("SAFEYOLO_PYTHON")
            .unwrap_or_else(|| root.join(".venv/bin/python").into_os_string());
        let output = std::process::Command::new(python)
            .arg(root.join("proxy/tests/circuit_config_source.py"))
            .arg("--check")
            .env(
                "PYTHONPATH",
                std::env::join_paths([root.to_owned(), root.join("cli/src")]).unwrap(),
            )
            .current_dir(root)
            .output()
            .expect("run actual Python config oracle");
        assert!(
            output.status.success(),
            "source config oracle failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("\"steps\": 44")
        );
    }
}
