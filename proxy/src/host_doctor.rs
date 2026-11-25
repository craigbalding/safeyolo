//! Diagnose actual native request execution through each configured agent UDS.

use rustls::pki_types::pem::PemObject;
use std::path::Path;

use hyper::Method;
use serde_json::{Value, json};

use crate::{
    Error, native_client, native_config, policy::native::control_label, trace::REQUEST_CONTROLS,
};

fn check(
    checks: &mut Vec<Value>,
    name: &str,
    status: &str,
    message: impl ToString,
    next: &str,
    details: Value,
) {
    checks.push(json!({"name":name,"status":status,"message":message.to_string(),"next_action":next,"details":details}));
}

/// Diagnose prerequisites before their dependents. These are observations;
/// doctor never starts a service, unlocks a store or rewrites host state.
pub(crate) async fn report(path: &Path) -> Value {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        time::Duration,
    };
    let root = path.parent().unwrap_or(Path::new("."));
    let mut checks = Vec::new();
    let config = match native_config::read(path) {
        Ok(config) => {
            check(
                &mut checks,
                "Configuration",
                "pass",
                path.display(),
                "",
                Value::Null,
            );
            Some(config)
        }
        Err(error) => {
            check(
                &mut checks,
                "Configuration",
                "fail",
                format!("{}: {error}", path.display()),
                "Select the installed instance with --instance-dir PATH. For a new instance, run the installer or init.",
                Value::Null,
            );
            None
        }
    };
    if let Some(config) = &config {
        let policy = config
            .policy_file
            .as_deref()
            .ok_or_else(|| -> Error { "policy path is absent".into() })
            .and_then(|path| {
                crate::policy::Policy::from_native_path(path)
                    .map(|_| ())
                    .map_err(Error::from)
            });
        match policy {
            Ok(()) => check(
                &mut checks,
                "Saved policy",
                "pass",
                "Valid native policy",
                "",
                Value::Null,
            ),
            Err(error) => check(
                &mut checks,
                "Saved policy",
                "fail",
                error,
                "Run policy check FILE and repair the reported rule.",
                Value::Null,
            ),
        }
        let ca = config
            .tls_ca_file
            .as_deref()
            .ok_or_else(|| "TLS CA path is absent".into())
            .and_then(crate::tls::CertificateAuthority::load);
        match ca {
            Ok(_) => check(
                &mut checks,
                "TLS certificate",
                "pass",
                "CA certificate and private key can be loaded",
                "",
                Value::Null,
            ),
            Err(error) => check(
                &mut checks,
                "TLS certificate",
                "fail",
                error,
                "Inspect tls ca and restore the selected instance's CA; existing guests trust that identity.",
                Value::Null,
            ),
        }
        if let Some(path) = &config.upstream_ca_file {
            let certificates = fs::read(path)
                .map_err(crate::Error::from)
                .and_then(|bytes| {
                    let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&bytes)
                        .collect::<Result<Vec<_>, _>>()?;
                    if certs.is_empty() {
                        return Err("no PEM certificates found".into());
                    }
                    let mut store = rustls::RootCertStore::empty();
                    for cert in certs {
                        store.add(cert)?;
                    }
                    Ok(())
                });
            match certificates {
                Ok(()) => check(
                    &mut checks,
                    "Upstream CA trust",
                    "pass",
                    path.display(),
                    "",
                    Value::Null,
                ),
                Err(error) => check(
                    &mut checks,
                    "Upstream CA trust",
                    "fail",
                    error,
                    "Use tls upstream to inspect or select a valid PEM CA bundle.",
                    Value::Null,
                ),
            }
        } else {
            check(
                &mut checks,
                "Upstream CA trust",
                "pass",
                "Packaged public roots; no additional CA selected",
                "",
                Value::Null,
            );
        }
        let token_result =
            ["admin_token", "agent_token"]
                .iter()
                .try_for_each(|name| -> Result<(), Error> {
                    let path = config.data_dir().join(name);
                    let meta = fs::symlink_metadata(&path)?;
                    if !meta.is_file()
                        || meta.uid() != unsafe { libc::geteuid() }
                        || meta.permissions().mode() & 0o077 != 0
                    {
                        return Err(format!(
                            "{} must be an ordinary private file owned by your UID",
                            path.display()
                        )
                        .into());
                    }
                    if fs::read(&path)?.is_empty() {
                        return Err(format!("{} is empty", path.display()).into());
                    }
                    Ok(())
                });
        match token_result {
            Ok(()) => check(
                &mut checks,
                "Local API tokens",
                "pass",
                "Private token files are readable; contents withheld",
                "",
                Value::Null,
            ),
            Err(error) => check(
                &mut checks,
                "Local API tokens",
                "fail",
                error,
                "Inspect the named file's ownership and mode; restore its original token before retrying.",
                Value::Null,
            ),
        }
        #[cfg(target_os = "linux")]
        {
            let runtime = crate::linux_host::runsc_report();
            check(
                &mut checks,
                "Linux runtime and namespaces",
                if runtime["state"] == "ready" {
                    "pass"
                } else {
                    "fail"
                },
                runtime["version"]
                    .as_str()
                    .unwrap_or("Runtime prerequisites unavailable"),
                runtime["next_action"].as_str().unwrap_or(""),
                runtime.clone(),
            );
        }
        #[cfg(target_os = "macos")]
        for (name, file) in [
            ("Virtualization helper", "bin/safeyolo-vm"),
            ("Interactive terminal", "bin/vsock-term"),
        ] {
            let ready = root.join(file).is_file();
            check(
                &mut checks,
                name,
                if ready { "warn" } else { "fail" },
                if ready {
                    "Installed input present; execution capability is established by agent diagnostics"
                } else {
                    "Packaged helper absent"
                },
                "Inspect agent diagnostics NAME for actual guest/control capability; reinstall a matching package if the helper is absent.",
                Value::Null,
            );
        }
        match crate::guest_acquisition::inspect_boot_inputs(root) {
            Ok(inputs) => check(
                &mut checks,
                "Guest inputs",
                "pass",
                format!(
                    "Selected guest inputs and mapped ownership validated at {}",
                    inputs.display()
                ),
                "",
                Value::Null,
            ),
            Err(error) => check(
                &mut checks,
                "Guest inputs",
                "fail",
                error,
                "Run guest acquire through the matching installer to restore compatible inputs.",
                Value::Null,
            ),
        }
        match fs::read_dir(root.join("logs")) {
            Ok(_) => check(
                &mut checks,
                "Local logs",
                "pass",
                "Log directory is readable",
                "",
                Value::Null,
            ),
            Err(error) => check(
                &mut checks,
                "Local logs",
                "warn",
                error,
                "Inspect the selected instance's logs directory and permissions.",
                Value::Null,
            ),
        }
    } else {
        for name in [
            "Saved policy",
            "TLS certificate",
            "Upstream CA trust",
            "Local API tokens",
            "Guest inputs",
            "Sandbox runtime",
            "Local logs",
        ] {
            check(
                &mut checks,
                name,
                "skip",
                "Configuration prerequisite failed",
                "",
                Value::Null,
            );
        }
    }
    let live = config.is_some() && crate::host_commands::proxy_live();
    check(
        &mut checks,
        "Proxy process",
        if config.is_none() {
            "skip"
        } else if live {
            "pass"
        } else {
            "warn"
        },
        if live {
            "Owned current process verified; this does not prove agent readiness"
        } else {
            "No verified running proxy"
        },
        if live {
            ""
        } else {
            "Inspect the checks above, then run start when ready."
        },
        Value::Null,
    );
    // Probe the authenticated API even when the launch record is unavailable.
    // A record is ownership evidence, not a substitute for capability health.
    let admin = if config.is_some() {
        match native_client::admin(
            path,
            "/admin/runtime-identity",
            Method::GET,
            Value::Null,
            Duration::from_secs(5),
        )
        .await
        {
            Ok(value) if value["state"] == "active" => {
                check(
                    &mut checks,
                    "Admin API and runtime identity",
                    "pass",
                    "Authenticated current runtime responded",
                    "",
                    value,
                );
                true
            }
            Ok(value) => {
                check(
                    &mut checks,
                    "Admin API and runtime identity",
                    "unknown",
                    "Runtime did not confirm its identity",
                    "Inspect logs and selected instance before retrying.",
                    value,
                );
                false
            }
            Err(error) => {
                check(
                    &mut checks,
                    "Admin API and runtime identity",
                    if live { "fail" } else { "warn" },
                    error,
                    "Inspect logs/proxy.log and the selected configuration's Admin API endpoint. No service was started.",
                    Value::Null,
                );
                false
            }
        }
    } else {
        check(
            &mut checks,
            "Admin API and runtime identity",
            "skip",
            "Requires a verified running proxy",
            "",
            Value::Null,
        );
        false
    };
    if admin {
        let result = pipeline(path).await;
        let verdict = result["verdict"].as_str().unwrap_or("unknown").to_owned();
        check(
            &mut checks,
            "Request pipeline and egress controls",
            &verdict,
            "Local requests exercise the configured listeners and control trace; no external test traffic",
            "Inspect failed pipeline findings with doctor --json; repair the named control or listener.",
            result,
        );
        for (name, endpoint) in [
            ("Coord message plane", "/admin/coord/diagnostics"),
            ("Credential store", "/admin/credentials/status"),
            ("Pending approvals", "/admin/approvals"),
            ("Live traffic view", "/admin/traffic/flows"),
        ] {
            match native_client::admin(
                path,
                endpoint,
                Method::GET,
                Value::Null,
                Duration::from_secs(5),
            )
            .await
            {
                Ok(value) => {
                    if name == "Coord message plane" {
                        let connected = value["local_connection"] == "Connected";
                        check(
                            &mut checks,
                            name,
                            if connected { "pass" } else { "warn" },
                            if connected {
                                "Local NATS connection is connected"
                            } else {
                                "No connected local NATS client observed; saved room records are separate"
                            },
                            if connected {
                                ""
                            } else {
                                "Inspect coord status and its current endpoints before sending messages."
                            },
                            value,
                        );
                        continue;
                    }
                    let availability = value["availability"]
                        .as_str()
                        .unwrap_or("available")
                        .to_owned();
                    let status = if matches!(availability.as_str(), "locked" | "absent") {
                        "warn"
                    } else if availability == "unavailable" {
                        "unknown"
                    } else {
                        "pass"
                    };
                    check(
                        &mut checks,
                        name,
                        status,
                        availability,
                        if name == "Credential store" && status == "warn" {
                            "Only operations needing stored credentials require selection or unlock; other traffic remains available."
                        } else {
                            ""
                        },
                        value,
                    );
                }
                Err(error) => check(
                    &mut checks,
                    name,
                    "unknown",
                    error,
                    "Inspect diagnose and logs for this instance; unavailable data is not an empty result.",
                    Value::Null,
                ),
            }
        }
    } else {
        for name in [
            "Request pipeline and egress controls",
            "Coord message plane",
            "Credential store",
            "Pending approvals",
            "Live traffic view",
        ] {
            check(
                &mut checks,
                name,
                "skip",
                "Requires the authenticated Admin API",
                "",
                Value::Null,
            );
        }
    }
    if config.is_some() {
        match crate::host_lifecycle::operate("list", None).await {
            Ok(value) => {
                let uncertain = value["agents"].as_array().is_none_or(|agents| {
                    agents.iter().any(|agent| {
                        agent["runtime_state"] == "unknown" || !agent["runtime_error"].is_null()
                    })
                });
                check(
                    &mut checks,
                    "Agent runtimes",
                    if uncertain { "unknown" } else { "pass" },
                    "Current backend observations; stopped agents do not need to be started",
                    if uncertain {
                        "Run agent diagnostics NAME for the affected agent."
                    } else {
                        ""
                    },
                    value,
                );
            }
            Err(error) => check(
                &mut checks,
                "Agent runtimes",
                "unknown",
                error,
                "Inspect agent list and the saved policy.",
                Value::Null,
            ),
        }
    } else {
        check(
            &mut checks,
            "Agent runtimes",
            "skip",
            "Configuration prerequisite failed",
            "",
            Value::Null,
        );
    }
    let counts: serde_json::Map<String, Value> = ["pass", "warn", "fail", "skip", "unknown"]
        .iter()
        .map(|status| {
            (
                (*status).to_owned(),
                json!(
                    checks
                        .iter()
                        .filter(|check| check["status"] == *status)
                        .count()
                ),
            )
        })
        .collect();
    let failed = counts["fail"].as_u64().unwrap_or(0) + counts["unknown"].as_u64().unwrap_or(0) > 0;
    json!({"root":root,"checks":checks,"counts":counts,"exit_code":i32::from(failed),
        "verdict":if failed { "fail" } else if counts["warn"].as_u64().unwrap_or(0) > 0 { "warn" } else { "pass" }})
}

pub(crate) fn show(report: &Value) {
    use crate::operator_output::{field, text};
    field("Instance", &report["root"]);
    if let Some(checks) = report["checks"].as_array() {
        for check in checks {
            println!(
                "{:<7} {:<30} {}",
                text(&check["status"]).to_uppercase(),
                text(&check["name"]),
                text(&check["message"])
            );
            if check["status"] != "pass" && check["status"] != "skip" && check["next_action"] != ""
            {
                println!("        {}", text(&check["next_action"]));
            }
        }
    }
    let counts = &report["counts"];
    println!(
        "\n{} passed, {} warnings, {} failed, {} skipped, {} unknown. Overall: {}.",
        counts["pass"],
        counts["warn"],
        counts["fail"],
        counts["skip"],
        counts["unknown"],
        text(&report["verdict"])
    );
}

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
