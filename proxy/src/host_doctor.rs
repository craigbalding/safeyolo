//! Diagnose actual native request execution through each configured agent UDS.

use std::path::Path;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Error, native_client, native_config, policy::native::control_label, trace::REQUEST_CONTROLS,
};

pub(crate) async fn pipeline(config_path: &Path) -> Value {
    let config = match native_config::read(config_path) {
        Ok(config) => config,
        Err(error) => {
            return json!({"verdict":"fail", "findings":[format!("Cannot read proxy settings: {error}")], "agents":[]});
        }
    };
    let mut agents = Vec::new();
    for listener in &config.listeners {
        let mut result = match probe(listener, &config.data_dir().join("agent_token")).await {
            Ok(result) => result,
            Err(error) => {
                json!({"verdict":"fail", "findings":[format!("Pipeline probe unavailable: {error}")]})
            }
        };
        result["agent"] = json!(listener.agent_id);
        result["socket"] = json!(listener.socket_path);
        agents.push(result);
    }
    let verdict = if agents.iter().any(|agent| agent["verdict"] == "fail") {
        "fail"
    } else if agents.is_empty() || agents.iter().any(|agent| agent["verdict"] == "warn") {
        "warn"
    } else {
        "pass"
    };
    json!({"verdict":verdict, "agents":agents,
        "findings":if config.listeners.is_empty() {vec!["No agent proxy listeners are configured; start an agent and rerun doctor"]} else {vec![]}})
}

async fn probe(listener: &crate::AgentListener, token: &Path) -> Result<Value, Error> {
    let reply = native_client::pipeline_probe(&listener.socket_path).await?;
    let Some(request_id) = &reply.request_id else {
        return Ok(json!({"verdict":"fail", "probe_status":reply.status,
            "findings":["Pipeline probe returned no valid request ID; trace unavailable"]}));
    };
    let trace = native_client::helper(
        Some(&listener.socket_path),
        token,
        &format!("/trace?request_id={request_id}"),
        Method::GET,
        Value::Null,
    )
    .await;
    let mut result = match trace {
        Ok(trace) => classify(&trace, &listener.agent_id, request_id),
        Err(error) => {
            json!({"verdict":"fail", "findings":[format!("Pipeline trace unavailable: {error}")]})
        }
    };
    result["request_id"] = json!(request_id);
    result["probe_status"] = json!(reply.status);
    if reply.status != 200 || !reply.body_complete {
        result["verdict"] = json!("fail");
        result["findings"]
            .as_array_mut()
            .expect("doctor findings")
            .push(json!(format!(
                "Pipeline probe did not complete at its local sink (HTTP {}, body_complete={})",
                reply.status, reply.body_complete
            )));
    }
    Ok(result)
}

fn classify(trace: &Value, agent: &str, request_id: &str) -> Value {
    let mut findings = Vec::new();
    let mut failed = false;
    let mut warned = false;
    if trace["agent_id"] != agent || trace["request_id"] != request_id {
        failed = true;
        findings.push("Trace identity does not match the probed agent and request".to_owned());
    }
    if trace["truncated"] != false || trace["incomplete"] != false {
        failed = true;
        findings.push("Pipeline trace is incomplete or truncated".to_owned());
    }
    let empty = Vec::new();
    let steps = trace["steps"].as_array().unwrap_or(&empty);
    let absent = trace["not_loaded"].as_array().unwrap_or(&empty);
    let expected: Vec<_> = REQUEST_CONTROLS
        .iter()
        .map(|name| control_label(name))
        .collect();
    let mut observed = Vec::new();
    for step in steps {
        let Some(control) = step["control"].as_str() else {
            failed = true;
            findings.push("Trace step has no control name".to_owned());
            continue;
        };
        if step["state"] == "error" {
            failed = true;
            findings.push(format!(
                "{control}: execution failed ({})",
                step["reason"].as_str().unwrap_or("unknown")
            ));
        }
        if step["hook"] != "request" || !expected.contains(&control) || observed.contains(&control)
        {
            continue;
        }
        observed.push(control);
        match step["state"].as_str() {
            Some("evaluated") if step["outcome"].as_str().is_some() => {}
            Some("bypassed") => match step["reason"].as_str() {
                Some("control_disabled" | "policy_disabled") => {}
                Some("prior_response") => {
                    warned = true;
                    let responder = step["details"]["preempted_by"]
                        .as_str()
                        .unwrap_or("an earlier control");
                    findings.push(format!(
                        "{control}: not reached because an earlier response exists ({responder})"
                    ));
                }
                _ => {
                    failed = true;
                    findings.push(format!("{control}: unrecognised bypass reason"));
                }
            },
            Some("not_loaded") => {
                failed = true;
                findings.push(format!("{control}: not loaded"));
            }
            Some("error") => {}
            _ => {
                failed = true;
                findings.push(format!("{control}: execution state is unavailable"));
            }
        }
    }
    for control in &expected {
        if absent
            .iter()
            .any(|step| step["control"] == *control && step["state"] == "not_loaded")
        {
            failed = true;
            if !observed.contains(control) {
                findings.push(format!("{control}: not loaded"));
            }
        } else if !observed.contains(control) {
            failed = true;
            findings.push(format!(
                "{control}: no request execution evidence; trace incomplete"
            ));
        }
    }
    let reached_in_order: Vec<_> = expected
        .iter()
        .copied()
        .filter(|control| observed.contains(control))
        .collect();
    if !warned && observed != reached_in_order {
        failed = true;
        findings.push("Request control order does not match the native pipeline".to_owned());
    }
    if !steps.iter().any(|step| {
        step["control"] == "probe-sink"
            && step["hook"] == "request"
            && step["state"] == "evaluated"
            && step["outcome"] == "probe_terminated"
    }) {
        failed = true;
        findings.push("Local probe sink was not reached".to_owned());
    }
    json!({"verdict":if failed {"fail"} else if warned {"warn"} else {"pass"},
        "findings":findings, "steps":steps, "not_loaded":absent})
}

#[cfg(test)]
mod tests;
