//! Selected peer reads belong to the existing operator-owned agent policy.

use ring::digest::{SHA256, digest};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Policy, Result, invalid};

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Read {
    Diagnostic,
    Approval,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRead {
    reader_id: String,
    agent: String,
    agent_id: String,
    request_id: String,
    reads: Vec<Read>,
}

pub(crate) fn validate_reads(value: Option<&Value>) -> Result<()> {
    if let Some(value) = value {
        let reads: Vec<EvidenceRead> = serde_json::from_value(value.clone())
            .map_err(|_| invalid("evidence_reads must contain selected reader/agent identities, request_id and reads"))?;
        for read in reads {
            if read.reader_id.is_empty()
                || read.agent.is_empty()
                || read.agent_id.is_empty()
                || !crate::approvals::pending::valid_id(&read.request_id)
                || read.reads.is_empty()
            {
                return Err(invalid(
                    "evidence_reads requires identities, a request ID and at least one read",
                ));
            }
        }
    }
    Ok(())
}

impl Policy {
    pub(crate) fn network_approval(
        &self,
        agent: Option<&str>,
        host: &str,
        port: u16,
    ) -> Option<&str> {
        let scope = crate::approvals::NetworkScope::new(host, agent, Some(port)).ok()?;
        let entry = &self.native.as_ref()?.authored["agents"][agent?]["hosts"][scope.destination()];
        (entry["egress"] == "allow")
            .then(|| entry["approval_id"].as_str())
            .flatten()
    }

    pub(crate) fn credential_approval(&self, host: &str, fingerprint: &str) -> Option<&str> {
        let entry = &self.native.as_ref()?.authored["hosts"][host];
        entry["allow"]
            .as_array()?
            .iter()
            .any(|value| value == fingerprint)
            .then(|| entry["credential_approval_ids"][fingerprint].as_str())
            .flatten()
    }
    pub(crate) fn service_credential(&self, agent: &str, service: &str) -> Option<String> {
        self.native.as_ref()?.authored["agents"][agent]["services"][service]["token"]
            .as_str()
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    }
    pub(crate) fn approval_result(
        &self,
        id: &str,
    ) -> std::result::Result<Option<Value>, &'static str> {
        let native = self.native.as_ref().ok_or("native policy unavailable")?;
        let Some(value) = native
            .authored
            .get("approval_results")
            .and_then(|results| results.get(id))
        else {
            return Ok(None);
        };
        let encoded = value.as_str().ok_or("approval receipt unavailable")?;
        serde_json::from_str(encoded)
            .map(Some)
            .map_err(|_| "approval receipt unavailable")
    }

    /// Only policy inputs for this decision family enter its revision. Evidence
    /// read sharing and approval receipts cannot invalidate a pending action.
    pub(crate) fn approval_revision(
        &self,
        agent: &str,
        kind: &str,
        service: Option<&str>,
    ) -> Option<String> {
        let native = self.native.as_ref()?;
        let credential = kind == "credential_allow";
        let relevant = |baseline: &super::Baseline| {
            let permissions: Vec<_> = baseline.value["permissions"]
                .as_array()?
                .iter()
                .filter(|permission| {
                    permission["action"].as_str().is_some_and(|action| {
                        if credential {
                            super::glob("credential:use", action)
                        } else {
                            ["gateway:request", "gateway:risky_route"]
                                .iter()
                                .any(|name| super::glob(name, action))
                        }
                    })
                })
                .filter(|permission| {
                    credential
                        || permission
                            .pointer("/condition/agent")
                            .and_then(Value::as_str)
                            .is_none_or(|pattern| super::glob(agent, pattern))
                })
                .collect();
            Some(
                json!({"permissions":permissions,"budgets":baseline.value["budgets"],
                "clients":baseline.value["clients"],"domains":baseline.value["domains"]}),
            )
        };
        let mut value = json!({"baseline":relevant(self.baseline.as_ref()?)?,
            "task":self.task.as_ref().and_then(|task| relevant(&task.baseline)),
            "controls": if credential { json!(native.controls.credentials) } else { Value::Null }});
        if let Some(service) = service {
            value.as_object_mut()?.extend(
                self.gateway_approval_definition(agent, service)?
                    .as_object()?
                    .clone(),
            );
        }
        let digest = crate::approvals::pending::digest(&value);
        crate::credentials::wipe_json(&mut value);
        Some(digest)
    }

    fn gateway_approval_definition(&self, agent: &str, service: &str) -> Option<Value> {
        let native = self.native.as_ref()?;
        let mut value = json!({});
        let gateway = self.gateway()?;
        let registry = gateway.registry()?;
        let definition = registry.services.get(service)?;
        let mut definition = definition.raw.clone();
        if let Some(fields) = definition.as_object_mut() {
            fields.shift_remove("description");
        }
        if let Some(capabilities) = definition["capabilities"].as_object_mut() {
            for capability in capabilities.values_mut() {
                if let Some(fields) = capability.as_object_mut() {
                    fields.shift_remove("description");
                }
            }
        }
        if let Some(routes) = definition["risky_routes"].as_array_mut() {
            for route in routes {
                if let Some(fields) = route.as_object_mut() {
                    fields.shift_remove("description");
                }
            }
        }
        let mut tokens: Vec<_> = gateway.canonical_gateway()["token_map"]
            .as_object()
            .into_iter()
            .flat_map(|tokens| tokens.iter())
            .filter(|(_, token)| token["agent"] == agent && token["service"] == service)
            .map(|(_, token)| token)
            .collect();
        tokens.sort_by_key(|token| crate::approvals::pending::digest(token));
        value["service"] = definition;
        value["tokens"] = json!(tokens);
        value["authorization"] = native.authored["agents"][agent]["services"][service].clone();
        value["contract_bindings"] = json!(
            native.authored["agents"][agent]["contract_bindings"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|binding| binding["service"] == service)
                .collect::<Vec<_>>()
        );
        value["grant_ttl_seconds"] = native.authored["gateway"]["grant_ttl_seconds"].clone();
        Some(value)
    }

    // The operator acknowledges the service envelope, not every independent
    // policy edit. Each request still rechecks the current policy and budgets.
    pub(crate) fn delegated_gateway_revision(&self, agent: &str, service: &str) -> Option<String> {
        let mut value = self.gateway_approval_definition(agent, service)?;
        value["host_map"] = json!(
            self.gateway()?.canonical_gateway()["host_map"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(_, target)| *target == service)
                .collect::<std::collections::BTreeMap<_, _>>()
        );
        let revision = crate::approvals::pending::digest(&value);
        crate::credentials::wipe_json(&mut value);
        Some(revision)
    }

    pub(crate) fn evidence_agent_id(&self, name: &str) -> Option<&str> {
        let agents = self.native.as_ref()?.authored.get("agents")?.as_object()?;
        let id = agents
            .get(name)?
            .get("agent_id")?
            .as_str()
            .filter(|id| !id.is_empty())?;
        (agents
            .values()
            .filter(|agent| agent["agent_id"] == id)
            .count()
            == 1)
            .then_some(id)
    }

    pub(crate) fn evidence_reader(
        &self,
        caller: &str,
        request_id: &str,
        read: Read,
    ) -> Option<String> {
        let caller_id = self.evidence_agent_id(caller)?;
        let configured = self
            .native
            .as_ref()?
            .authored
            .get("agents")?
            .get(caller)?
            .get("evidence_reads")?;
        let grants: Vec<EvidenceRead> = serde_json::from_value(configured.clone()).ok()?;
        grants
            .into_iter()
            .find(|grant| {
                grant.reader_id == caller_id
                    && grant.request_id == request_id
                    && grant.reads.contains(&read)
                    && self.evidence_agent_id(&grant.agent) == Some(grant.agent_id.as_str())
            })
            .map(|grant| grant.agent)
    }

    /// Hash the full compiled network permissions, including named-list inputs
    /// and the active task. The historical display hash loses host names and
    /// therefore cannot establish that a prepared action is still current.
    pub(crate) fn network_action_revision(&self, agent: &str) -> Option<String> {
        let native = self.native.as_ref()?;
        let network = |baseline: &super::Baseline| {
            let permissions: Vec<&Value> = baseline.value["permissions"]
                .as_array()?
                .iter()
                .filter(|permission| {
                    permission["action"]
                        .as_str()
                        .is_some_and(|action| super::glob("network:request", action))
                        && permission
                            .pointer("/condition/agent")
                            .and_then(Value::as_str)
                            .is_none_or(|pattern| super::glob(agent, pattern))
                })
                .collect();
            Some(
                json!({"permissions":permissions,"budgets":baseline.value["budgets"],
                "domains":baseline.value["domains"],"clients":baseline.value["clients"]}),
            )
        };
        let mut value = json!({"baseline":network(self.baseline.as_ref()?)?,
            "global_budget":self.global_budget,
            "task":self.task.as_ref().and_then(|task| network(&task.baseline)),
            "controls":native.controls.network});
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&value).ok()?);
        crate::credentials::wipe_json(&mut value);
        Some(
            digest(&SHA256, &bytes)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        )
    }
}
