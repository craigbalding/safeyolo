//! A safe explanation of existing authority, without changing the pending record.

use serde_json::{Value, json};

use super::{Record, Result, current_view, invalid};
use crate::{
    audit::{Event, Kind, Severity, Writer},
    policy::Policy,
};

pub(crate) fn explain(
    writer: &Writer,
    policy: &Policy,
    record: &Record,
    state: Option<&crate::RuntimeState>,
    option: Option<&str>,
) -> Result<Value> {
    let view = current_view(writer, policy, record, state)?;
    let action = &record.authority.action;
    let method = match record.authority.method.as_str() {
        method @ ("GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "CONNECT"
        | "TRACE") => method,
        _ => "[custom method omitted]",
    };
    let kind = action["kind"].as_str().unwrap_or("");
    let (stopped, non_grants, graph_node) = match kind {
        "network_allow" => (
            "The network policy required operator approval for this agent, destination and port.",
            vec![
                "No network permission for other agents, destinations or ports.",
                "No credential destination permission or service capability. Other enforcement still applies.",
            ],
            "cls.approval_networkguard",
        ),
        "credential_allow" => (
            "The credential guard required approval to send the recorded credential fingerprints to this destination.",
            vec![
                "No network permission or service capability.",
                "No permission for other credential fingerprints or destinations. This permission is shared across agents, not limited to the requester.",
            ],
            "cls.approval_credguard",
        ),
        "gateway_route" => (
            "The service risk policy required approval for the selected method and exact request path.",
            vec![
                "No service-wide write access or permission for other methods or paths.",
                "No new service capability, network permission or credential destination permission.",
                "A vaulted upstream credential stays on the host; approval does not reveal it to the guest.",
            ],
            "cls.approval_gateway_grant",
        ),
        "service_authorize" => (
            "The requested service capability requires operator authorization.",
            vec![
                "No other service capability or host-wide network permission.",
                "No approval of risky routes or contract values. Existing network and credential rules still apply.",
                "A selected vaulted credential stays on the host; the guest receives a scoped gateway token.",
            ],
            "cls.approval_gateway_grant",
        ),
        "contract_binding" => (
            "The submitted contract values require operator approval before the gateway can use them.",
            vec![
                "No service authorization, risky-route approval or network permission.",
                "No permission to replace these fixed values with different request values.",
                "A vaulted upstream credential stays on the host.",
            ],
            "cls.approval_gateway_binding",
        ),
        _ => (
            "The reason for this approval cannot be established from supported authoritative evidence.",
            vec!["No permission is granted by requesting an explanation."],
            "ev.approval_read_type_field",
        ),
    };
    let known = matches!(
        kind,
        "network_allow"
            | "credential_allow"
            | "gateway_route"
            | "service_authorize"
            | "contract_binding"
    );
    if option.is_some() && record.authority.selected_option(option).is_none() {
        return Err(invalid("select one of this approval's fixed options"));
    }
    let selected = record.authority.selected_option(option);
    let mut unknowns = vec![
        "The target resource cannot be established from safe retained metadata. Raw request paths, queries and contract values are omitted because they can contain secrets.",
    ];
    if !known {
        unknowns
            .push("The grant meaning is unknown. Use direct policy controls to inspect its scope.");
    }
    if selected.is_none() {
        unknowns.push("No approval option is selected. Select an offered option to explain the decision's effect.");
    }
    // Only fixed metadata enters this projection. Never copy raw audit events,
    // agent reasons, contract values, request headers, bodies or queries.
    let mut facts = json!({"agent":action["agent"],"agent_id":action["agent_id"],
        "destination":action["host"],"port":record.authority.port,
        "service":action["service"],"capability":action["capability"],
        "credential_reference":action["credential"],"account":action["account"],
        "request_method":method,"request_scheme":record.authority.scheme});
    if kind == "credential_allow" {
        facts["credential_fingerprints"] = action["credentials"].clone();
    }
    if matches!(kind, "service_authorize" | "contract_binding") {
        facts["request_source"] = json!(
            "Agent API gateway request; the method and scheme describe that local request, not an upstream operation"
        );
    }
    if let Some(service) = action["service"].as_str()
        && let Some(capability) = action["capability"].as_str()
        && let Some(registry) = policy.gateway().and_then(|gateway| gateway.registry())
        && let Some(definition) = registry.services.get(service)
        && let Some(capability) = definition.capabilities.get(capability)
    {
        facts["configured_routes"] = json!(
            capability
                .routes
                .iter()
                .filter(|route| {
                    kind != "gateway_route"
                        || (crate::services::method_matches(
                            &record.authority.method,
                            &route.methods,
                        ) && crate::services::resource_matches(
                            action["path"].as_str().unwrap_or(""),
                            &route.path,
                        ))
                })
                .map(|route| json!({"methods":route.methods,"path_pattern":route.path}))
                .collect::<Vec<_>>()
        );
    } else if action["service"].is_string() {
        unknowns.push("The current service definition is unavailable; route details are unknown.");
    }
    let options: Vec<_> = record
        .authority
        .options
        .iter()
        .map(|offered| {
            let mut effect = if !known {
                "Unknown grant meaning.".to_owned()
            } else if kind == "gateway_route" {
                // The host's option already owns lifetime and consumption semantics.
                // Its literal path can contain a password or bearer, so omit that value.
                match action["path"].as_str().filter(|path| !path.is_empty()) {
                    Some(path) => offered
                        .effect
                        .replace(path, "[selected exact request path; value omitted]"),
                    None => "Exact path and grant meaning unavailable.".into(),
                }
            } else {
                offered.effect.clone()
            };
            if kind == "service_authorize" {
                effect.push_str(" This also saves the service's host routing for the instance. The capability grant is only for the selected agent.");
            }
            if kind == "gateway_route" && method == "[custom method omitted]" {
                effect = effect.replace(&record.authority.method, method);
            }
            if kind == "gateway_route" && offered.id == "remembered" {
                effect.push_str(" Remembered grants survive proxy restart until expiry or revocation.");
            }
            let status = view["options"]
                .as_array()
                .and_then(|options| options.iter().find(|option| option["id"] == offered.id))
                .map(|option| &option["status"])
                .cloned()
                .unwrap_or(Value::Null);
            json!({"id":offered.id,"effect":effect,"status":status,
                "credential_expires_at":offered.parameters["expires_at"]})
        })
        .collect();
    let selection = selected
        .and_then(|selected| options.iter().find(|option| option["id"] == selected.id))
        .cloned();
    let mut result = json!({"approval_id":record.approval_id,"request_id":record.request_id,
        "authority_digest":record.authority_digest,"status":view["status"],
        "observed":facts,"why_stopped":stopped,
        "current_policy":"The recorded request still requires a decision under the current saved and active policy. Each option shows its current availability. A later decision checks the policy and credentials again.",
        "selected_option":selection,"options":options,"non_grants":non_grants,"unknowns":unknowns,
        "interpretation":"The effects describe the offered approval, not a recommendation to approve. An explanation grants no permission and does not establish the agent's intent.",
        "evidence":{"source":"canonical pending approval recorded at enforcement",
            "graph":"triage-approval-required","node":graph_node,
            "details_command":format!("safeyolo approvals show {} --json", record.approval_id)}});
    if view["status"] != "pending" {
        result["current_policy"] = json!(
            "This approval is no longer pending. The effects describe its recorded options, not an available new grant. Inspect current state before deciding."
        );
    }
    let mut event = Event::new(
        "admin.approval_explained",
        Kind::Admin,
        Severity::Low,
        format!("Approval {} explanation requested", record.approval_id),
    );
    event.request_id = Some(record.request_id.clone());
    event.agent = action["agent"].as_str().map(str::to_owned);
    event.details = json!({"approval_id":record.approval_id,"authority_digest":record.authority_digest,
        "status":view["status"],"option":selected.map(|option| &option.id),"permission_changed":false}).into();
    tokio::runtime::Handle::current()
        .block_on(writer.emit_confirmed(event))
        .map_err(|_| super::super::ApprovalError {
            kind: super::super::ErrorKind::Io,
            message: "explanation audit unavailable; no permission was changed".into(),
        })?;
    Ok(result)
}
