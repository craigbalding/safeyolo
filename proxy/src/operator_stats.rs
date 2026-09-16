//! Operator reports from the installed shared owners, in source discovery order.
//! Reading statistics does not evaluate policy or refresh lazy addon settings.

use crate::{Runtime, circuits::CircuitValue, policy::Policy, tasks::Registry};
use serde_json::json;

pub(crate) fn document(runtime: &Runtime) -> CircuitValue {
    let mut report = indexmap::IndexMap::from([("proxy".into(), json!("safeyolo").into())]);
    let discovery = match runtime
        .agent_discovery
        .get_stats(&runtime.audit, crate::circuit_runtime::now)
    {
        Ok(report) => report,
        Err(error) => discovery_failure(error.kind(), &error.to_string()),
    };
    report.insert("service-discovery".into(), discovery);
    report.insert(
        "policy-engine".into(),
        policy_stats(runtime.policy.as_ref(), &runtime.tasks),
    );
    // The temporary bridge does not install these native pipeline owners.
    if runtime.policy.is_some() {
        let network = match runtime.network_guard.stats() {
            Ok(stats) => json!({
                "enabled": runtime.config.network_guard_enabled,
                "checks": stats.checks,
                "allowed": stats.allowed,
                "blocked": stats.blocked,
                "warned": stats.warned,
                "rate_limited": stats.rate_limited,
            })
            .into(),
            Err(error) => failure("RuntimeError", &error.to_string()),
        };
        report.insert("network-guard".into(), network);
        let audit = crate::circuits::Audit::new(&runtime.audit, None, None);
        let circuits = match runtime.circuits.stats_document_with_audit(
            runtime.config.circuit_breaker_enabled,
            crate::circuit_runtime::now(),
            &mut rand::random::<f64>,
            &audit,
        ) {
            Ok(outcome) => {
                crate::circuit_runtime::record_transitions(runtime, &outcome.events, None);
                outcome.value
            }
            Err(error) => {
                // Earlier successful submissions remain committed. These are
                // development diagnostics, not a second canonical submission.
                crate::circuit_runtime::record_transitions(runtime, error.events(), None);
                circuit_failure(&error)
            }
        };
        report.insert("circuit-breaker".into(), circuits);
        let context = match runtime.test_context.stats(crate::http::declaration_time()) {
            Ok(stats) => serde_json::to_value(stats)
                .expect("fixed TestContext stats fields")
                .into(),
            Err(error) => {
                use crate::test_context::ContextErrorKind;
                let name = match error.kind() {
                    ContextErrorKind::Type => "TypeError",
                    ContextErrorKind::Value => "ValueError",
                    ContextErrorKind::Overflow => "OverflowError",
                    ContextErrorKind::Attribute => "AttributeError",
                    ContextErrorKind::Poisoned => "RuntimeError",
                };
                failure(name, &error.to_string())
            }
        };
        report.insert("test-context".into(), context);
    }
    report.insert("flow-recorder".into(), runtime.flow_recorder.stats().into());
    let logger = match runtime.request_logger.stats() {
        Ok(stats) => stats.document(),
        Err(_) => failure("RuntimeError", "request logger stats unavailable"),
    };
    report.insert("request-logger".into(), logger);
    let metrics = match runtime.metrics.get_stats() {
        Ok(stats) => stats,
        Err(error) => failure("RuntimeError", &error.to_string()),
    };
    report.insert("metrics".into(), metrics);
    CircuitValue::Object(report)
}

fn discovery_failure(kind: crate::agent_discovery::ErrorKind, message: &str) -> CircuitValue {
    use crate::agent_discovery::ErrorKind;
    let class = match kind {
        ErrorKind::Attribute => "AttributeError",
        ErrorKind::Type => "TypeError",
        ErrorKind::UnicodeDecode => "UnicodeDecodeError",
        ErrorKind::Value => "ValueError",
        ErrorKind::Permission => "PermissionError",
        ErrorKind::Io => "OSError",
        ErrorKind::Audit(crate::audit::ErrorKind::Io) => "OSError",
        ErrorKind::Audit(_) | ErrorKind::Compatibility | ErrorKind::Poisoned => "RuntimeError",
    };
    failure(class, message)
}

fn policy_stats(policy: Option<&Policy>, tasks: &Registry) -> CircuitValue {
    // PolicyClientConfigurator catches its client's complete get_stats call.
    // Preserve PDPCore's hash -> registry count -> engine report ordering.
    if let Some(policy) = policy {
        let hash = policy.policy_hash();
        if let Ok(count) = tasks.count()
            && let Ok(engine) = policy.engine_stats()
        {
            return json!({
                "engine_version": "pdp-0.1.0", "policy_hash": hash,
                "task_policies": count, "engine_stats": engine,
            })
            .into();
        }
    }
    json!({}).into()
}

fn circuit_failure(error: &crate::circuits::Error) -> CircuitValue {
    use crate::circuits::ErrorKind;
    let name = match error.kind() {
        ErrorKind::Type => "TypeError",
        ErrorKind::Value => "ValueError",
        ErrorKind::Overflow => "OverflowError",
        ErrorKind::ZeroDivision => "ZeroDivisionError",
        ErrorKind::Audit(crate::audit::ErrorKind::Io) => "OSError",
        ErrorKind::Invalid | ErrorKind::Compatibility | ErrorKind::Audit(_) => "RuntimeError",
    };
    failure(name, &error.to_string())
}

fn failure(name: &str, message: &str) -> CircuitValue {
    json!({"error": format!("{name}: {message}")}).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, os::unix::ffi::OsStringExt, sync::Arc};

    #[test]
    fn policy_wrapper_hides_its_own_reporting_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join(OsString::from_vec(b"policy-\xff.json".to_vec()));
        std::fs::write(&path, b"{}").unwrap();
        let policy = Policy::from_path(&path).unwrap();
        assert_eq!(
            policy.engine_stats().unwrap_err(),
            crate::policy::EngineStatsError::PathEncoding
        );
        let tasks = Registry::default();
        assert_eq!(
            policy_stats(Some(&policy), &tasks)
                .render_json(false)
                .unwrap(),
            "{}"
        );
        assert_eq!(policy_stats(None, &tasks).render_json(false).unwrap(), "{}");
    }

    #[test]
    fn temporary_adapter_does_not_report_uninstalled_native_owners() {
        let directory = tempfile::tempdir().unwrap();
        let config = serde_json::from_value(json!({
            "listeners":[{"agent_id":"alice","socket_path":directory.path().join("alice.sock")}],
            "temporary_policy_socket":directory.path().join("unused-bridge.sock"),
            "readiness_file":directory.path().join("ready"),
            "audit_log_path":directory.path().join("audit.jsonl"),
            "event_log":directory.path().join("events.jsonl"),
            "flow_store_enabled":false,
            "flow_store_db_path":directory.path().join("unused.sqlite3"),
            "circuit_state_file":""
        }))
        .unwrap();
        let runtime = Runtime::new(
            config,
            "owned",
            Arc::new(tokio::sync::Mutex::new(())),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            document(&runtime)
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "proxy",
                "service-discovery",
                "policy-engine",
                "flow-recorder",
                "request-logger",
                "metrics"
            ]
        );
        assert!(!directory.path().join("audit.jsonl").exists());
        assert!(!directory.path().join("unused.sqlite3").exists());
    }
}
