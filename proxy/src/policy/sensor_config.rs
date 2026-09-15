//! Sensor configuration from the same canonical owners used for policy hashing.

use super::{BaselineSerializationError, Map, Policy, Value};

impl Policy {
    /// Clone only the authorized sensor fields. The API response owner must wipe
    /// this transient JSON after rendering; addon settings can contain secrets.
    pub(crate) fn sensor_config(&self) -> Result<Value, BaselineSerializationError> {
        let baseline = self.baseline.as_deref();
        let task = self.task.as_ref().map(|task| task.baseline.as_ref());
        for owner in baseline.into_iter().chain(task) {
            if ["credential_rules", "scan_patterns"]
                .iter()
                .any(|field| owner.timestamps.has_under(&[field]))
            {
                return Err(BaselineSerializationError::NonJsonTimestamp);
            }
        }
        if baseline.is_some_and(|owner| owner.timestamps.has_under(&["addons"])) {
            return Err(BaselineSerializationError::NonJsonTimestamp);
        }

        let mut response = Map::new();
        for field in ["credential_rules", "scan_patterns"] {
            let mut values = Vec::new();
            for owner in baseline.into_iter().chain(task) {
                values.extend(
                    owner.value[field]
                        .as_array()
                        .expect("canonical sensor rules are arrays")
                        .iter()
                        .cloned(),
                );
            }
            response.insert(field.into(), Value::Array(values));
        }
        response.insert(
            "addons".into(),
            baseline
                .map(|owner| owner.value["addons"].clone())
                .unwrap_or_else(|| Value::Object(Map::new())),
        );
        response.insert("policy_hash".into(), Value::String(self.policy_hash()));
        Ok(Value::Object(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Format;
    use serde_json::json;

    fn source_row(name: &str) -> Value {
        let source: Value =
            serde_json::from_str(include_str!("../../tests/sensor_config_source.json")).unwrap();
        source["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["case"] == name)
            .unwrap()
            .clone()
    }

    fn document() -> Value {
        json!({
            "permissions":[],
            "credential_rules":[{"name":"base","patterns":["fixture-[0-9]+"],"allowed_hosts":["api.fixture.invalid"]}],
            "scan_patterns":[{"name":"base","pattern":"fixture-é"}],
            "addons":{"credential_guard":{"enabled":false,"settings":{"use_default_credential_rules":false},"custom":"preserved"}}
        })
    }

    fn policy(document: &Value) -> Policy {
        Policy::parse_at(&document.to_string(), Format::Json, 0.).unwrap()
    }

    fn assert_response(policy: &Policy, case: &str) {
        let row = source_row(case);
        assert_eq!(row["response"]["status"], 200);
        let response = policy.sensor_config().unwrap();
        assert_eq!(response, row["response"]["body"], "{case}");
        let encoded = crate::python_json::encode(&response);
        let hex = encoded
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(hex, row["response"]["body_hex"].as_str().unwrap(), "{case}");
    }

    #[test]
    fn configured_defaults_and_reload_match_actual_source_responses() {
        assert_response(&Policy::unconfigured(), "initialized_without_baseline");
        let mut raw = document();
        let initial = policy(&raw);
        let before = initial.budget_stats(0.).unwrap();
        assert_response(&initial, "configured_defaults_disabled_addon_shared_scope");
        assert_response(&initial, "configured_defaults_disabled_addon_shared_scope");
        assert_eq!(initial.budget_stats(0.).unwrap(), before);

        raw["credential_rules"][0]["name"] = json!("reloaded");
        raw["addons"]["credential_guard"]["enabled"] = json!(true);
        let reloaded = initial
            .reload_from_source_at(&raw.to_string(), Format::Json, 0.)
            .unwrap();
        assert_response(&reloaded, "valid_baseline_reload_invalidates_cache");
        assert_response(&initial, "configured_defaults_disabled_addon_shared_scope");
        assert!(
            reloaded
                .reload_from_source_at(r#"{"permissions":false}"#, Format::Json, 0.)
                .is_err()
        );
        assert_response(&reloaded, "invalid_reload_retains_accepted_config");
    }

    #[test]
    fn task_projection_matches_current_core_and_separately_records_stale_source_cache() {
        let mut raw = document();
        raw["credential_rules"][0]["name"] = json!("reloaded");
        raw["addons"]["credential_guard"]["enabled"] = json!(true);
        let baseline = policy(&raw);
        let mut task = raw.clone();
        task["metadata"] = json!({"task_id":"isolated-task"});
        task["credential_rules"][0]["name"] = json!("task");
        task["scan_patterns"][0]["name"] = json!("task");
        task["addons"]["credential_guard"]["enabled"] = json!(false);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("task.json");
        std::fs::write(&path, task.to_string()).unwrap();
        let loaded = baseline.with_task_path(&path).unwrap();
        assert_response(&loaded, "task_file_load_appends_rules_not_addons");
        std::fs::write(&path, "invalid json").unwrap();
        assert!(loaded.reload_task().is_err());
        assert_response(&loaded, "task_file_load_appends_rules_not_addons");

        // Existing core snapshot operation only: there is no task-clear route
        // in this slice and no assertion that the source cache was repaired.
        let cleared = loaded.without_task();
        let source = source_row("task_clear_leaves_stale_cache");
        assert_eq!(cleared.sensor_config().unwrap(), source["live_core_config"]);
        assert_ne!(cleared.sensor_config().unwrap(), source["response"]["body"]);
        assert_eq!(loaded.sensor_config().unwrap(), source["response"]["body"]);
        assert_response(&cleared, "explicit_invalidation_after_task_clear");
    }

    #[test]
    fn arrays_append_without_deduplication_and_task_addons_are_not_projected() {
        let raw = document();
        let baseline = policy(&raw);
        let task = json!({
            "credential_rules":[raw["credential_rules"][0],raw["credential_rules"][0]],
            "scan_patterns":[raw["scan_patterns"][0],raw["scan_patterns"][0]],
            "addons":{"task_only":{"settings":{"flag":true}}}
        });
        let current = baseline
            .with_task_source(&task.to_string(), Format::Json)
            .unwrap();
        let base = baseline.sensor_config().unwrap();
        let merged = current.sensor_config().unwrap();
        for field in ["credential_rules", "scan_patterns"] {
            assert_eq!(
                merged[field].as_array().unwrap(),
                &vec![base[field][0].clone(); 3]
            );
        }
        assert_eq!(merged["addons"], base["addons"]);
        assert_eq!(merged["addons"]["credential_guard"]["enabled"], false);
        assert_ne!(merged["policy_hash"], base["policy_hash"]);
        assert_eq!(merged["policy_hash"], current.policy_hash());
    }

    #[test]
    fn only_temporal_values_in_projected_fields_prevent_json_response() {
        let outside = Policy::parse_at(
            "permissions: []\ngateway: {unused: 2024-01-01}\n",
            Format::Yaml,
            0.,
        )
        .unwrap();
        assert!(outside.baseline().is_err());
        assert_response(&outside, "timestamp_outside_config_is_hashable");
        let inside = Policy::parse_at(
            "permissions: []\naddons: {credential_guard: {settings: {unused: 2024-01-01}}}\n",
            Format::Yaml,
            0.,
        )
        .unwrap();
        assert_eq!(
            inside.sensor_config(),
            Err(BaselineSerializationError::NonJsonTimestamp)
        );
        assert_eq!(
            inside.policy_hash(),
            source_row("timestamp_inside_addon_is_handler_500")["core_policy_hash"]
        );

        for extra in [
            "addons: {credential_guard: {enabled: false, custom: 2024-01-01}}\n",
            "addons: {credential_guard: {settings: {nested: {2024-01-01: observed}}}}\n",
        ] {
            let policy = Policy::parse_at(extra, Format::Yaml, 0.).unwrap();
            assert_eq!(
                policy.sensor_config(),
                Err(BaselineSerializationError::NonJsonTimestamp)
            );
        }
        for literal in ["'2024-01-01'", "{yaml_date: '2024-01-01'}"] {
            let policy = Policy::parse_at(
                &format!("addons: {{custom: {{settings: {{observed: {literal}}}}}}}\n"),
                Format::Yaml,
                0.,
            )
            .unwrap();
            assert!(policy.sensor_config().is_ok());
        }
        assert!(
            Policy::parse_at(
                "addons: {credential_guard: {settings: {2024-01-01: observed}}}\n",
                Format::Yaml,
                0.,
            )
            .is_err()
        );
        let baseline = policy(&document());
        let task = baseline.with_task_source("addons: {task_only: {settings: {observed: 2024-01-01}}}\ngateway: {unused: 2024-01-02}\n", Format::Yaml).unwrap();
        let projected = task.sensor_config().unwrap();
        let base = baseline.sensor_config().unwrap();
        for field in ["credential_rules", "scan_patterns", "addons"] {
            assert_eq!(projected[field], base[field]);
        }
        assert_ne!(projected["policy_hash"], base["policy_hash"]);
        assert_eq!(projected["policy_hash"], task.policy_hash());
    }

    #[test]
    fn file_loader_owns_sibling_defaults_before_projection() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, document().to_string()).unwrap();
        std::fs::write(directory.path().join("addons.yaml"), "addons:\n  credential_guard:\n    enabled: true\n    settings: {sibling: yes}\n  pattern_scanner:\n    enabled: false\n").unwrap();
        let loaded = Policy::from_path_at(&path, 0.).unwrap();
        let response = loaded.sensor_config().unwrap();
        assert_eq!(
            response["addons"],
            loaded.baseline.as_ref().unwrap().value["addons"]
        );
        assert_eq!(response["addons"]["credential_guard"]["enabled"], false);
        // Source overrides each authored addon as a whole; its comment's
        // "deep merge" does not merge that addon's nested settings.
        assert_eq!(
            response["addons"]["credential_guard"]["settings"],
            json!({"use_default_credential_rules":false})
        );
        assert_eq!(response["addons"]["pattern_scanner"]["enabled"], false);
    }
}
