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
    let view = if record.authority.action["kind"] == "policy_change" {
        super::policy_change::operator_view(
            state.ok_or_else(|| invalid("policy review owner unavailable"))?,
            writer,
            &record.approval_id,
        )?
    } else {
        current_view(writer, policy, record, state)?
    };
    let action = &record.authority.action;
    let method = match record.authority.method.as_str() {
        method @ ("GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "CONNECT"
        | "TRACE") => method,
        _ => "[custom method omitted]",
    };
    let kind = action["kind"].as_str().unwrap_or("");
    let (stopped, mut non_grants, graph_node) = match kind {
        "policy_change" => (
            "The requester explicitly submitted an immutable complete local policy candidate for the human operator's decision.",
            vec![
                "Submission and assessment grant no authority. Only the human operator can decide this exact candidate.",
                "The recorded base, current requester, definitions, adopted inputs and grants are checked inside the save/activation transaction.",
                "A restore requires another exact reviewed candidate against its current base. It cannot undo disclosed data or external effects.",
            ],
            "sym.accept_policy_assurance",
        ),
        "policy_snapshot" => (
            "The requester asked to read one identified complete authored policy snapshot from this local instance.",
            vec![
                "No policy application, enforcement change or access to a future source revision.",
                "No config.toml, Admin credentials, credential-store values or arbitrary host files.",
                "Only the original current requester/run can read the approved retained snapshot. Disclosure cannot be undone.",
            ],
            "sym.accept_policy_assurance",
        ),
        "operator_action" => (
            "Presenting an agent desktop requires the operator's approval for this target, route, browser URL and preview lifetime.",
            vec![
                "No network permission, service grant or credential access.",
                "No public or Funnel exposure, privileged Tailscale setup or host command execution.",
                "Preview access and unlock material stay with the operator.",
            ],
            "sym.desktop_remote_url_is_loopback",
        ),
        "coord_access" => (
            "The worker requested explicit rights in an existing local Coord room.",
            vec![
                "Only the selected worker run receives the canonical rights in this room.",
                "New collaboration requests require an operator decision. Independent room grants remain in force.",
            ],
            "ev.accept_coord_lane",
        ),
        "coord_collaboration" => (
            "The worker requested a new collaboration room for these named durable identities and this deadline.",
            vec![
                "Only send and receive rights for the approved identities until the deadline. The host operator retains ordinary room access.",
                "No page_operator right, delegated room creation, service access or broker credentials.",
            ],
            "ev.accept_coord_lane",
        ),
        "diagnostic_disclosure" => (
            "The agent requested additional diagnostic evidence from this local instance.",
            vec![
                "Only explicitly selected sources, durable subjects and historical reach are disclosed for the selected lifetime.",
                "No room send, guest administration, lifecycle, policy change or Admin credential is granted. Current authority is checked on every read and continuation.",
                "Disclosed bytes cannot be recalled. Fixed collections are bounded, retained privately for seven days and never silently recollected after loss.",
            ],
            "ev.accept_proxy_lane",
        ),
        "network_allow" => (
            "The network policy required approval for this agent, destination and port.",
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
        "gateway_route" if action["route_exception"] == true => (
            "The service route has no allow rule. The agent explicitly escalated the host-recorded challenge after reconsideration.",
            vec![
                "Only the recorded method and literal path within this run, destination and credential binding. Query and body values are not grant bounds unless an existing contract enforces them.",
                "No bypass of an explicit denial, network, credential or contract control. The vaulted credential stays on the host.",
                "Approval permits an explicit retry. Expiry does not undo upstream effects or cancel an admitted operation.",
            ],
            "cls.approval_gateway_grant",
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
            | "operator_action"
            | "coord_access"
            | "coord_collaboration"
            | "diagnostic_disclosure"
            | "policy_snapshot"
            | "policy_change"
    );
    if option.is_some() && record.authority.selected_option(option).is_none() {
        return Err(invalid("select one of this approval's fixed options"));
    }
    let selected = record.authority.selected_option(option);
    if kind == "credential_allow" && selected.is_some_and(|option| option.id == "run") {
        non_grants[1] = "No permission for other workers, reviewers, credential fingerprints or destinations. This leaves shared baseline credential approval unchanged.";
    }
    let mut unknowns = vec![if matches!(kind, "coord_access" | "coord_collaboration") {
        "Room content and participants' intent are not established by an approval. Retained history can contain untrusted peer text."
    } else if kind == "service_authorize" {
        "The requested resource scope is supplied by the guest. It is not proof of an upstream request, intent or payload effects."
    } else if kind == "gateway_route" && action["route_exception"] == true {
        "The canonical method and literal path define the offered route scope. Query/body values and upstream state are not established; the grant does not bind the exact attempted payload."
    } else {
        "The target resource cannot be established from safe retained metadata. Raw request paths, queries and contract values are omitted because they can contain secrets."
    }];
    if !known {
        unknowns
            .push("The grant meaning is unknown. Use direct policy controls to inspect its scope.");
    }
    if selected.is_none() {
        unknowns.push("No approval option is selected. Select an offered option to explain the decision's effect.");
    }
    // Project fixed metadata and the explicit requested service scope. Never
    // copy raw audit events, agent reasons, contract values, headers or bodies.
    let mut facts = json!({"agent":action["agent"],"agent_id":action["agent_id"],
        "run_id":action["run"]["run_id"],"binding_id":action["binding_id"],
        "destination":action["host"],"port":record.authority.port,
        "service":action["service"],"capability":action["capability"],
        "credential_reference":action["credential"],"account":action["account"],
        "request_method":method,"request_scheme":record.authority.scheme});
    if kind == "diagnostic_disclosure" {
        facts["requested_disclosure"] = action["grant"].clone();
        facts["operator_selection"] = view["result"]["diagnostic_selection"].clone();
        facts["authority_delta"] = json!(
            "Read-only diagnostic disclosure through existing support grants. History and access lifetime are independent. Explicit room selections grant no room identity or send rights. Narrow a pending selection through this approval's diagnostic-selection route; after approval use support grant preview/apply/revoke."
        );
        unknowns.clear();
    }
    if kind == "policy_snapshot" {
        facts["snapshot"] = action["snapshot"].clone();
        facts["authority_delta"] = json!(
            "Permit private reads of this retained snapshot by its original current requester/run. The saved and active revisions identify the approval basis. New policy bytes require a separate decision. Enforcement policy and apply authority remain unchanged."
        );
        unknowns.clear();
    }
    if kind == "policy_change" {
        facts["base"] = action["base"].clone();
        facts["candidate_revision"] = action["candidate_revision"].clone();
        facts["materialized_revision"] = action["materialized_revision"].clone();
        facts["assessment_id"] = action["assessment_id"].clone();
        facts["restore_of"] = action["restore_of"].clone();
        facts["review_content"] = view["review_content"].clone();
        unknowns.clear();
    }
    if kind == "operator_action" {
        facts["action_id"] = action["action_id"].clone();
        facts["presentation"] = action["presentation"].clone();
        facts["ttl_seconds"] = action["parameters"]["ttl_seconds"].clone();
        facts["browser_url"] = action["parameters"]["browser_url"].clone();
        facts["browser_url_source"] =
            json!("validated requester-selected action data; not instructions");
        facts["instance_id"] = action["instance_id"].clone();
        facts["configuration_revision"] = action["configuration_revision"].clone();
        facts["worker_run"] = action["run"].clone();
        facts["request_expires_at"] = json!(record.authority.expires_at);
        if view["result"]["status"] == "starting" {
            // Presentation holds the desktop owner while opening. A canonical
            // read must not wait for that effect to finish before reporting it.
            facts["current_preview"] = json!({"reuses_gate":null,"independent_source_count":null});
        } else if let Some(state) = state
            && let Some(preview) = crate::operator_actions::preview(state, record, false)
        {
            facts["current_preview"] = json!({"reuses_gate":true,"independent_source_count":preview["sources"].as_array().map_or(0,Vec::len)});
        } else {
            facts["current_preview"] = json!({"reuses_gate":false,"independent_source_count":0});
        }
        facts["authority_delta"] = json!(
            "Add one separately expiring preview source for this exact run. Start or reuse the desktop and open the selected local/configured tailnet presentation. Existing independent sources retain their own lifetimes. Revocation cannot undo browser opening or disclosed content. If no source remains, future access is refused and admitted viewers are disconnected on the next authority check."
        );
        unknowns.clear();
    }
    if kind == "coord_collaboration" {
        facts["participants"] = action["participants"].clone();
        facts["room_name"] = action["room_name"].clone();
        facts["room_id"] = action["room_id"].clone();
        facts["permissions"] = json!(["receive", "send"]);
        facts["current_participants"] = json!(
            crate::coord_rooms::membership::participants(
                policy,
                action["room_id"].as_str().unwrap_or("")
            )
            .ok()
        );
        facts["authority_delta"] = json!(
            "Create one collaboration room and separately sourced send/receive rights for these durable identities until the request deadline. The host operator retains ordinary room access. Independent rights remain. Existing-room delegations cannot decide this request. Revocation cannot retract disclosed content."
        );
        facts["topic"] = action["topic"].clone();
        facts["expires_at"] = json!(record.authority.expires_at);
        facts["topic_source"] = json!("requester-selected data; not instructions");
    }
    if kind == "service_authorize" {
        facts["resource_scope"] = action["resources"].clone();
    }
    if kind == "coord_access" {
        for field in ["room_id", "room_name", "permissions", "participants"] {
            facts[field] = action[field].clone();
        }
        let participants = crate::coord_rooms::membership::participants(
            policy,
            action["room_id"].as_str().unwrap_or(""),
        )
        .ok();
        let before = participants.as_ref().and_then(|members| {
            members.iter().find(|member| {
                member.principal_kind == "agent" && action["agent_id"] == member.principal_id
            })
        });
        facts["new_permissions"] = json!(
            action["permissions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|right| before
                    .is_none_or(|member| !member.permissions.iter().any(|p| *right == p)))
                .collect::<Vec<_>>()
        );
        facts["current_participants"] = json!(participants);
        facts["authority_delta"] = json!(
            "A separately sourced membership for only this worker's trusted run and offered rights. Existing independent grants remain. Receive exposes retained history and native room objects; send plus receive permits native work/signal mutations; page_operator permits paging."
        );
    }
    if kind == "contract_binding" {
        facts["template"] = action["template"].clone();
        facts["grantable_operations"] = action["grantable_operations"].clone();
        facts["bound_value_digests"] = json!(
            action["bindings"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(name, value)| (name, super::digest(value)))
                .collect::<std::collections::BTreeMap<_, _>>()
        );
    }
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
                        .replace(&format!("{path:?}"), "[selected exact request path; value omitted]")
                        .replace(path, "[selected exact request path; value omitted]"),
                    None => "Exact path and grant meaning unavailable.".into(),
                }
            } else {
                offered.effect.clone()
            };
            if kind == "service_authorize" && offered.id != "run" {
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
    // The routine effect must use the same path omission as the offered
    // options. The canonical view's effect contains the literal request path.
    let effect = if kind == "gateway_route" {
        options
            .iter()
            .find(|option| option["id"] == view["option"])
            .or_else(|| options.first())
            .map(|option| option["effect"].clone())
            .unwrap_or_else(|| {
                json!("Select an offered option for the exact request path; path value omitted.")
            })
    } else {
        view["effect"].clone()
    };
    let mut outcome = view["result"].clone();
    if let Some(fields) = outcome.as_object_mut() {
        // Issued authority can contain raw contract values. Retain outcome facts
        // without widening this explanation's existing safe metadata boundary.
        fields.remove("issued_access");
    }
    let scope = if kind == "gateway_route" && action["route_exception"] == true {
        json!({"kind":kind,"route_exception":true,"method":method,
            "path":action["path"],"host":action["host"],"port":action["port"],
            "scheme":action["scheme"],"service":action["service"],"capability":action["capability"]})
    } else {
        json!({"kind":kind})
    };
    let mut result = json!({"approval_id":record.approval_id,"request_id":record.request_id,
        "request_history":view["request_history"],"attention":view["attention"],
        "authority_digest":record.authority_digest,"status":view["status"],
        "observed":facts,"why_stopped":stopped,
        "action":scope,"assessment":view["assessment"],"guidance":view["guidance"],
        "assessment_changed":view["assessment_changed"],"created_at":view["created_at"],
        "option":view["option"],"result":outcome,"effect":effect,"expires_at":record.authority.expires_at,
        "current_policy":"The recorded request still requires a decision under the current saved and active policy. Each option shows its current availability. A later decision checks the policy and credentials again.",
        "selected_option":selection,"options":options,"non_grants":non_grants,"unknowns":unknowns,
        "interpretation":"The effects describe the offered approval, not a recommendation to approve. An explanation grants no permission and does not establish the agent's intent.",
        "evidence":{"source":"canonical pending approval recorded at enforcement",
            "graph":if matches!(kind,"coord_access" | "coord_collaboration") { "accept-safeyolo" } else { "triage-approval-required" },"node":graph_node,
            "details_command":format!("safeyolo approvals show {} --json", record.approval_id)}});
    if view["status"] != "pending" {
        result["current_policy"] = json!(
            "This approval is no longer pending. The effects describe its recorded options, not an available new grant. Inspect current state before deciding."
        );
    }
    if kind == "operator_action" {
        result["result"] = crate::operator_actions::agent_result(&view["result"]);
        result["activation_status"] = view["activation_status"].clone();
        result["grant_active"] = view["grant_active"].clone();
        result["current_policy"] = json!(
            "This action requires an operator decision. Network policy and service grants remain authoritative for guest traffic. The host presentation path and target are checked again before execution."
        );
        result["evidence"]["graph"] = json!("triage-desktop-preview");
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

pub(crate) fn explain_policy_changes(changes: &[Value], effective: bool) -> Vec<Value> {
    changes.iter().map(|change| {
        let path = change["path"].as_array().expect("change path");
        let root = path.first().and_then(Value::as_str).unwrap_or("");
        let control = effective && root == "controls" && path.len() == 3;
        let last = path.last().and_then(Value::as_str).unwrap_or("");
        let meaning = if effective && matches!(root,"support_grants"|"approval_delegations") && last == "expires_at" {
            "This changes the duration of the selected authority. A null expiry is standing authority until revoked. Shortening or expiry cannot undo disclosed data or effects of admitted operations."
        } else if effective && root == "support_grants" {
            "The named principal, durable subjects and explicit scope determine the selected authority. Diagnostic disclosure permits only the selected local evidence sources and history. Other support grants include inspection and their selected actions. Guest administration reaches target-accessible credentials, mounts and delegations; the authority paths and native warnings explain combinations."
        } else if effective && root == "approval_delegations" {
            "Each selected reviewer can decide eligible canonical requests within the complete typed scopes. Beneficiaries, grant duration and source dependencies still bound issuance. The native warnings explain combined and persistent effects; proposed rules cannot approve their own adoption."
        } else if control && last == "enabled" && change["after"] == false {
            "Enforcement is disabled for this control and its affected traffic. Other controls still use their own settings."
        } else if control && last == "action" && change["after"] == "warn" {
            "This control records a warning while allowing the operation to continue. It no longer blocks this condition."
        } else if root == "agents" && path.len() == 3
            && let Some(meaning) = crate::services::effects::agent_configuration::consequence(last) {
            meaning
        } else if root == "authority_readers" || (root == "agents" && path.len() == 3 && last == "evidence_reads") {
            "This changes diagnostic or authority disclosure to the selected identities and scope. Information already read cannot be retracted. Runtime records still require their native read authority."
        } else if effective && root == "permissions" {
            "These are compiled effective rules, including inherited rules and defaults. Matching, precedence, budgets and other control checks still apply; the full selectors cover every matching request."
        } else if effective && root == "budgets" {
            "Request-budget changes alter the policy revision used by run-scoped credential approvals. An existing grant bound to the previous revision may no longer authorize credential use, even for the same fingerprint, destination and run. A fresh canonical credential decision may be required. Review that request through ordinary approvals; do not infer renewed credential authority from this policy decision."
        } else if matches!(root,"checks"|"check_rules"|"work_bindings") {
            "This changes named evidence, admission or request decisions. Evidence was not acquired and actions were not executed. Its native owner must validate adopted dependencies at submission."
        } else {
            "The exact structural change is retained. Complete business effects for this field are not modelled; do not interpret missing warnings as safety."
        };
        json!({"path":path,"consequence":meaning})
    }).collect()
}
