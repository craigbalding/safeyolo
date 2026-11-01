//! Bounded deciding authority and run permissions in the native policy owner.

use super::{Policy, Result, invalid};
use crate::{
    approvals::pending::{Record, digest},
    host_runs::AgentRun,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Agent {
    pub name: String,
    pub agent_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Scope {
    NetworkEgress {
        host: String,
        ports: Vec<u16>,
        all_ports: bool,
        actions: Vec<String>,
    },
    Credential {
        host: String,
        fingerprints: Vec<String>,
    },
    ServiceAuthorization {
        service: String,
        capability: String,
        account: String,
        credential: String,
        #[serde(default)]
        credential_binding: Option<String>,
        resources: Vec<String>,
    },
    GatewayRoute {
        service: String,
        capability: String,
        binding_id: Option<String>,
        method: String,
        path: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Delegation {
    pub reviewers: Vec<Agent>,
    pub beneficiaries: Vec<Agent>,
    pub scopes: Vec<Scope>,
    pub expires_at: Option<String>,
    pub grant_seconds: Option<u64>,
    pub gateway_once: bool,
    pub acknowledgment: Option<String>,
    #[serde(default)]
    pub definition_revisions: BTreeMap<String, String>,
}

impl Delegation {
    pub fn revision(&self) -> String {
        let mut value = json!(self);
        value
            .as_object_mut()
            .expect("delegation")
            .shift_remove("acknowledgment");
        digest(&value)
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = vec!["Run access is reusable until the worker stops, the grant expires, or this delegation changes or is revoked. Any one eligible reviewer may decide. Reviewers do not need to possess the permissions they issue.".into()];
        if self.reviewers.len() > 1 {
            warnings.push("Each named reviewer can decide alone. This is not a quorum.".into());
        }
        for scope in &self.scopes {
            match scope {
                Scope::NetworkEgress { host, all_ports, .. } => {
                    if host.contains(['*','?','[']) { warnings.push(format!("Network destination pattern {host} permits matching destinations, including future matches.")); }
                    if *all_ports { warnings.push(format!("Network destination {host} permits every destination port. Port 443 does not establish safe use.")); }
                }
                Scope::Credential { .. } => warnings.push("Credential destination access permits all methods, paths and ports at the selected destination. It does not limit an API operation or grant network access.".into()),
                Scope::ServiceAuthorization { resources, .. } => {
                    warnings.push("Service authorization permits the selected capability and resource paths with the selected account and credential for the worker run. Contract binding, risky-route approval, network policy and credential resolution remain separate checks. It does not bind a request payload.".into());
                    if resources.iter().any(|path| path.contains(['*', '?', '['])) {
                        warnings.push("Service resource patterns include every matching current or future path. A capability name or GET method does not establish business safety.".into());
                    }
                }
                Scope::GatewayRoute { method, path, .. } => {
                    if method=="*" || path.contains(['*','?','[']) { warnings.push("The gateway envelope includes multiple or future matching routes. Each issued grant still binds the canonical method and exact path; payload effects remain unknown.".into()); }
                    warnings.push("A gateway route grant covers its supported method and path. It does not bind a payload or undo an upstream write. Capability and contract checks still apply.".into());
                }
            }
        }
        warnings
    }

    pub(crate) fn valid(&self) -> Result<()> {
        if self.reviewers.is_empty() || self.beneficiaries.is_empty() || self.scopes.is_empty() {
            return Err(invalid(
                "delegation requires named reviewers, beneficiaries and explicit scopes",
            ));
        }
        for agent in self.reviewers.iter().chain(&self.beneficiaries) {
            if !crate::host_platform::valid_agent_name(&agent.name) || agent.agent_id.is_empty() {
                return Err(invalid(
                    "delegation requires a valid local name and durable agent_id",
                ));
            }
        }
        if self.reviewers.iter().any(|reviewer| {
            self.beneficiaries
                .iter()
                .any(|agent| agent.agent_id == reviewer.agent_id || agent.name == reviewer.name)
        }) {
            return Err(invalid(
                "a reviewer cannot approve for itself or directly benefit from its delegation",
            ));
        }
        if self.grant_seconds.is_some_and(|seconds| {
            seconds == 0
                || i64::try_from(seconds)
                    .ok()
                    .and_then(|seconds| {
                        time::OffsetDateTime::now_utc()
                            .checked_add(time::Duration::seconds(seconds))
                    })
                    .is_none()
        }) {
            return Err(invalid(
                "grant_seconds must be positive with a representable expiry, or null for the current worker run",
            ));
        }
        if self
            .expires_at
            .as_deref()
            .is_some_and(|s| super::parse_expiry(s).is_none() || !super::expiry_has_offset(s))
        {
            return Err(invalid(
                "delegation expires_at requires an RFC3339 time with offset",
            ));
        }
        for scope in &self.scopes {
            match scope {
                Scope::NetworkEgress {
                    host,
                    ports,
                    all_ports,
                    actions,
                } => {
                    let (canonical, port) = super::split_destination(host)?;
                    if canonical != *host
                        || port.is_some()
                        || host.is_empty()
                        || ports.contains(&0)
                        || (*all_ports != ports.is_empty())
                        || actions.is_empty()
                        || actions
                            .iter()
                            .any(|s| !matches!(s.as_str(), "request" | "connect"))
                    {
                        return Err(invalid(
                            "network scope requires a canonical host pattern, ports and an explicit all_ports choice, and request/connect actions",
                        ));
                    }
                }
                Scope::Credential { host, fingerprints } => {
                    let (canonical, port) = super::split_destination(host)?;
                    if canonical != *host
                        || port.is_some()
                        || host.contains(['*', '?', '['])
                        || host.is_empty()
                        || fingerprints.is_empty()
                        || fingerprints
                            .iter()
                            .any(|s| !s.starts_with("hmac:") || s.len() <= 5)
                    {
                        return Err(invalid(
                            "credential scope requires an exact canonical destination and exact hmac fingerprints; port/method/once bounds are unsupported",
                        ));
                    }
                }
                Scope::ServiceAuthorization {
                    service,
                    capability,
                    account,
                    credential,
                    credential_binding,
                    resources,
                } => {
                    if service.is_empty()
                        || capability.is_empty()
                        || account.is_empty()
                        || resources.is_empty()
                        || resources.iter().any(|path| !valid_resource(path))
                        || (credential.is_empty() && credential_binding.is_some())
                        || (!credential.is_empty()
                            && credential_binding.as_deref().is_none_or(str::is_empty))
                    {
                        return Err(invalid(
                            "service authorization requires exact service, capability, account, credential reference and explicit resource paths or patterns",
                        ));
                    }
                }
                Scope::GatewayRoute {
                    service,
                    capability,
                    binding_id,
                    method,
                    path,
                } => {
                    if service.is_empty()
                        || capability.is_empty()
                        || method.is_empty()
                        || (method != "*" && hyper::Method::from_bytes(method.as_bytes()).is_err())
                        || method != &method.to_ascii_uppercase()
                        || !path.starts_with('/')
                        || path.contains('#')
                        || binding_id.as_ref().is_some_and(String::is_empty)
                    {
                        return Err(invalid(
                            "gateway scope requires service, capability, optional exact binding, uppercase method or *, and supported path pattern; payload bounds are unsupported",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn current(&self) -> bool {
        !expired(self.expires_at.as_deref())
    }

    pub fn contains(&self, record: &Record, option: &str) -> bool {
        self.contains_effect(&record.authority.action, option)
    }

    pub(crate) fn contains_effect(&self, a: &Value, option: &str) -> bool {
        if !self.current()
            || !self
                .beneficiaries
                .iter()
                .any(|agent| a["agent"] == agent.name && a["agent_id"] == agent.agent_id)
        {
            return false;
        }
        if !matches!(option, "run" | "delegated_once")
            || (option == "delegated_once" && !self.gateway_once)
        {
            return false;
        }
        if a["kind"] == "credential_allow" && option == "run" {
            return a["credentials"].as_array().is_some_and(|values| !values.is_empty() && values.iter().all(|value| {
                self.scopes.iter().any(|scope|matches!(scope,Scope::Credential {host,fingerprints} if a["host"]==*host && value.as_str().is_some_and(|v|fingerprints.iter().any(|p|p==v))))
            }));
        }
        if a["kind"] == "service_authorize" && option == "run" {
            return a["resources"].as_array().is_some_and(|resources| !resources.is_empty() && resources.iter().all(|resource| {
                resource.as_str().is_some_and(|resource| self.scopes.iter().any(|scope| {
                    matches!(scope, Scope::ServiceAuthorization {service, capability, account, credential, credential_binding, resources}
                        if a["service"] == *service && a["capability"] == *capability && a["account"] == *account
                            && a["credential"] == *credential && a["credential_binding"].as_str() == credential_binding.as_deref()
                            && resources.iter().any(|pattern| resource_within(resource, pattern)))
                }))
            }));
        }
        self.scopes.iter().any(|scope| match scope {
            Scope::NetworkEgress {
                host,
                ports,
                all_ports,
                actions,
            } => {
                a["kind"] == "network_allow"
                    && option == "run"
                    && a["host"]
                        .as_str()
                        .is_some_and(|target| super::glob(target, host))
                    && a["port"]
                        .as_u64()
                        .and_then(|p| u16::try_from(p).ok())
                        .is_some_and(|port| *all_ports || ports.contains(&port))
                    && actions
                        .iter()
                        .any(|action| action == a["network_action"].as_str().unwrap_or(""))
            }
            Scope::Credential { host, fingerprints } => {
                a["kind"] == "credential_allow"
                    && option == "run"
                    && a["host"] == *host
                    && a["credentials"].as_array().is_some_and(|values| {
                        !values.is_empty()
                            && values.iter().all(|value| {
                                value
                                    .as_str()
                                    .is_some_and(|v| fingerprints.iter().any(|p| p == v))
                            })
                    })
            }
            Scope::ServiceAuthorization { .. } => false,
            Scope::GatewayRoute {
                service,
                capability,
                binding_id,
                method,
                path,
            } => {
                a["kind"] == "gateway_route"
                    && a["service"] == *service
                    && a["capability"] == *capability
                    && a["binding_id"].as_str() == binding_id.as_deref()
                    && a["method"]
                        .as_str()
                        .is_some_and(|m| method == "*" || method.eq_ignore_ascii_case(m))
                    && a["path"]
                        .as_str()
                        .is_some_and(|p| crate::services::resource_matches(p, path))
            }
        })
    }
}

pub(crate) fn valid_resource(path: &str) -> bool {
    (path == "*" || path.starts_with('/'))
        && !path.contains(['#', '\r', '\n'])
        && !crate::contracts::reject_path_tricks(path)
}

// A requested pattern is supported when it is the acknowledged pattern itself.
// Exact paths can be narrower. Do not guess containment between arbitrary globs.
fn resource_within(resource: &str, pattern: &str) -> bool {
    resource == pattern
        || (!resource.contains(['*', '?', '['])
            && crate::services::resource_matches(resource, pattern))
}

pub(crate) fn expired(value: Option<&str>) -> bool {
    value.is_some_and(|s| {
        super::parse_expiry(s).is_none_or(|t| time::OffsetDateTime::now_utc() >= t)
    })
}

pub(crate) fn parse(document: &Value) -> Result<BTreeMap<String, Delegation>> {
    let mut delegations = BTreeMap::new();
    if let Some(values) = document.get("approval_delegations") {
        for (name, value) in super::object(values, "approval_delegations")? {
            let delegation: Delegation = if let Some(encoded) = value.as_str() {
                serde_json::from_str(encoded)
            } else {
                serde_json::from_value(value.clone())
            }
            .map_err(|e| invalid(format!("approval_delegations.{name}: {e}")))?;
            delegations.insert(name.clone(), delegation);
        }
    }
    for (name, delegation) in &delegations {
        if !crate::host_platform::valid_agent_name(name) {
            return Err(invalid("invalid delegation name"));
        }
        delegation.valid()?;
        if delegation.acknowledgment.as_deref() != Some(delegation.revision().as_str()) {
            return Err(invalid(format!(
                "delegation {name}: acknowledge the exact preview revision before apply"
            )));
        }
        for agent in delegation.reviewers.iter().chain(&delegation.beneficiaries) {
            if document["agents"][&agent.name]["agent_id"] != agent.agent_id
                || document["agents"]
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(_, value)| value["agent_id"] == agent.agent_id)
                    .count()
                    != 1
            {
                return Err(invalid(format!(
                    "delegation {name}: agent {} has a missing, duplicate or changed durable identity",
                    agent.name
                )));
            }
        }
    }
    Ok(delegations)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssuedAccess {
    pub delegation: String,
    pub delegation_revision: String,
    pub reviewer: Agent,
    pub beneficiary: AgentRun,
    pub approval_id: String,
    pub policy_revision: String,
    pub action: Value,
    pub expires_at: Option<String>,
    pub option: String,
}

impl IssuedAccess {
    pub fn active(&self, policy: &Policy) -> bool {
        if !self.active_snapshot(policy) || !self.stored(policy) {
            return false;
        }
        let Some(path) = policy.baseline_path.as_ref() else {
            return false;
        };
        let Ok(source) = std::fs::read_to_string(path) else {
            return false;
        };
        let Ok(saved) = policy.reload_native_source(&source, path) else {
            return false;
        };
        self.active_snapshot(&saved) && self.stored(&saved)
    }

    fn stored(&self, policy: &Policy) -> bool {
        let kind = match self.action["kind"].as_str() {
            Some("network_allow") => "network_grants",
            Some("credential_allow") => "credential_grants",
            Some("service_authorize") => "service_grants",
            // Gateway permissions belong to the gateway grant store. Its
            // caller checks the recorded grant and this authority together.
            Some("gateway_route") => return true,
            _ => return false,
        };
        policy
            .issued_access(&self.beneficiary.agent, kind)
            .iter()
            .any(|grant| grant == self)
    }

    pub(crate) fn active_snapshot(&self, policy: &Policy) -> bool {
        if self.validate().is_err()
            || !self.beneficiary.current(policy)
            || expired(self.expires_at.as_deref())
        {
            return false;
        }
        if self.delegation.is_empty() {
            return self.reviewer.name == "operator"
                && self.reviewer.agent_id == "operator"
                && crate::approvals::pending::revision(policy, &self.action).as_deref()
                    == Some(self.policy_revision.as_str());
        }
        let Some(delegation) = policy.delegations().get(&self.delegation) else {
            return false;
        };
        delegation.current()
            && delegation.revision() == self.delegation_revision
            && delegation.dependencies_current(policy)
            && delegation.contains_effect(&self.action, &self.option)
            && delegation.reviewers.contains(&self.reviewer)
            && policy.evidence_agent_id(&self.reviewer.name)
                == Some(self.reviewer.agent_id.as_str())
            && crate::approvals::pending::revision(policy, &self.action).as_deref()
                == Some(self.policy_revision.as_str())
    }
}

impl Policy {
    pub(crate) fn delegations(&self) -> &BTreeMap<String, Delegation> {
        static EMPTY: std::sync::OnceLock<BTreeMap<String, Delegation>> =
            std::sync::OnceLock::new();
        self.native
            .as_ref()
            .map(|native| &native.delegations)
            .unwrap_or_else(|| EMPTY.get_or_init(BTreeMap::new))
    }
    pub(crate) fn issued_access(&self, agent: &str, kind: &str) -> Vec<IssuedAccess> {
        self.native
            .as_ref()
            .and_then(|n| n.authored["agents"][agent][kind].as_object())
            .into_iter()
            .flat_map(|grants| grants.values())
            .filter_map(|value| {
                value
                    .as_str()
                    .and_then(|value| serde_json::from_str(value).ok())
            })
            .collect()
    }
    pub(crate) fn delegated_network(
        &self,
        run: &AgentRun,
        request: super::NetworkRequest<'_>,
    ) -> bool {
        self.issued_access(&run.agent, "network_grants")
            .iter()
            .any(|grant| {
                grant.beneficiary == *run
                    && grant.active(self)
                    && grant.action["host"] == request.host
                    && grant.action["port"].as_u64() == request.port.map(u64::from)
                    && grant.action["network_action"]
                        == if request.method.eq_ignore_ascii_case("CONNECT") {
                            "connect"
                        } else {
                            "request"
                        }
            })
    }
    pub(crate) fn delegated_credential(
        &self,
        run: &AgentRun,
        request: super::CredentialRequest<'_>,
    ) -> bool {
        self.issued_access(&run.agent, "credential_grants")
            .iter()
            .any(|grant| {
                grant.beneficiary == *run
                    && grant.active(self)
                    && grant.action["host"] == request.destination
                    && grant.action["credentials"]
                        .as_array()
                        .is_some_and(|values| {
                            values.iter().any(|value| {
                                value == &format!("hmac:{}", request.credential_hmac.unwrap_or(""))
                            })
                        })
            })
    }
}

impl Policy {
    pub(crate) fn delegation_grants(&self) -> Vec<Value> {
        let Some(native) = &self.native else {
            return vec![];
        };
        native.authored["agents"].as_object().into_iter().flat_map(|agents| agents.keys())
            .flat_map(|agent| ["network_grants","credential_grants","service_grants"].into_iter().flat_map(move |kind| {
                self.issued_access(agent,kind).into_iter().map(move |grant| json!({"kind":kind,"active":grant.active(self),"permission":grant}))
            })).collect()
    }
}

impl IssuedAccess {
    pub(crate) fn validate(&self) -> Result<()> {
        let kind = self.action["kind"].as_str().unwrap_or("");
        let allowed: &[&str] = match kind {
            "network_allow" => &[
                "kind",
                "agent",
                "agent_id",
                "host",
                "port",
                "revision",
                "run",
                "network_action",
            ],
            "credential_allow" => &["kind", "agent", "agent_id", "host", "credentials", "run"],
            "service_authorize" => &[
                "kind",
                "agent",
                "agent_id",
                "service",
                "capability",
                "host",
                "account",
                "credential",
                "credential_binding",
                "resources",
                "run",
            ],
            "gateway_route" => &[
                "kind",
                "agent",
                "agent_id",
                "service",
                "capability",
                "credential",
                "account",
                "host",
                "method",
                "path",
                "irreversible",
                "run",
                "binding_id",
            ],
            _ => return Err(invalid("unsupported issued permission type")),
        };
        if self
            .action
            .as_object()
            .is_none_or(|fields| fields.keys().any(|key| !allowed.contains(&key.as_str())))
            || self.action["agent"] != self.beneficiary.agent
            || self.action["agent_id"] != self.beneficiary.agent_id
            || serde_json::from_value::<AgentRun>(self.action["run"].clone())
                .ok()
                .as_ref()
                != Some(&self.beneficiary)
            || self.beneficiary.run_id.len() != 32
            || !self
                .beneficiary
                .run_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || !self.approval_id.starts_with("apr-")
            || !crate::approvals::pending::valid_id(&self.approval_id)
            || self.policy_revision.len() != 64
            || !matches!(self.option.as_str(), "run" | "delegated_once")
            || (self.option == "delegated_once" && kind != "gateway_route")
            || self
                .expires_at
                .as_deref()
                .is_some_and(|s| super::parse_expiry(s).is_none() || !super::expiry_has_offset(s))
        {
            return Err(invalid(
                "issued permission has unsupported scope, identity or lifetime",
            ));
        }
        if kind == "service_authorize" {
            let text = |key: &str| self.action[key].as_str();
            if ["service", "capability", "account", "host"]
                .iter()
                .any(|key| text(key).is_none_or(str::is_empty))
                || text("credential").is_none()
                || (text("credential") != Some("")
                    && text("credential_binding").is_none_or(str::is_empty))
                || self.action["resources"].as_array().is_none_or(|paths| {
                    paths.is_empty()
                        || paths
                            .iter()
                            .any(|path| path.as_str().is_none_or(|path| !valid_resource(path)))
                })
            {
                return Err(invalid(
                    "issued service authorization has unsupported credential or resource scope",
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_grants(document: &Value) -> Result<()> {
    for (agent, fields) in document["agents"].as_object().into_iter().flatten() {
        for (collection, kind) in [
            ("network_grants", "network_allow"),
            ("credential_grants", "credential_allow"),
            ("service_grants", "service_authorize"),
        ] {
            if let Some(values) = fields.get(collection) {
                for (id, value) in super::object(values, collection)? {
                    let issued: IssuedAccess =
                        serde_json::from_str(value.as_str().ok_or_else(|| {
                            invalid("issued permission must be its encoded host record")
                        })?)
                        .map_err(|e| invalid(format!("{collection}: {e}")))?;
                    issued.validate()?;
                    if issued.action["kind"] != kind
                        || issued.beneficiary.agent != *agent
                        || issued.approval_id != *id
                    {
                        return Err(invalid(
                            "issued permission stored under a different identity or type",
                        ));
                    }
                }
            }
        }
        for grant in fields["grants"].as_array().into_iter().flatten() {
            if let Some(encoded) = grant.get("delegated") {
                let issued: IssuedAccess =
                    serde_json::from_str(encoded.as_str().ok_or_else(|| {
                        invalid("gateway delegated permission must be an encoded host record")
                    })?)
                    .map_err(|e| invalid(format!("gateway delegated permission: {e}")))?;
                issued.validate()?;
                if issued.action["kind"] != "gateway_route"
                    || issued.beneficiary.agent != *agent
                    || grant["service"] != issued.action["service"]
                    || grant["method"] != issued.action["method"]
                    || grant["path"] != issued.action["path"]
                    || grant["literal_path"] != true
                    || grant["scope"]
                        != if issued.option == "delegated_once" {
                            "once"
                        } else {
                            "remembered"
                        }
                {
                    return Err(invalid(
                        "gateway grant differs from its delegated authority",
                    ));
                }
            }
        }
    }
    Ok(())
}

impl Delegation {
    pub(crate) fn reciprocal_agent_pairs(&self, policy: &Policy) -> BTreeSet<(String, String)> {
        let mut pairs = BTreeSet::new();
        for other in policy.delegations().values() {
            for reviewer in self
                .reviewers
                .iter()
                .filter(|r| other.beneficiaries.contains(r))
            {
                for beneficiary in self
                    .beneficiaries
                    .iter()
                    .filter(|b| other.reviewers.contains(b))
                {
                    pairs.insert((reviewer.agent_id.clone(), beneficiary.agent_id.clone()));
                }
            }
        }
        pairs
    }

    pub(crate) fn dependencies(&self, policy: &Policy) -> Result<BTreeMap<String, String>> {
        let mut result = BTreeMap::new();
        for scope in &self.scopes {
            if let Scope::GatewayRoute { service, .. }
            | Scope::ServiceAuthorization { service, .. } = scope
            {
                for agent in &self.beneficiaries {
                    let revision = policy
                        .delegated_gateway_revision(&agent.name, service)
                        .ok_or_else(|| {
                            invalid("gateway definition or beneficiary authorization unavailable")
                        })?;
                    result.insert(format!("{}:{service}", agent.agent_id), revision);
                }
            }
        }
        result.insert(
            "reviewer_startup".into(),
            digest(&json!(policy.reviewer_write_warnings(self))),
        );
        // Bind the reciprocal identities rather than delegation revisions.
        // Acknowledging one direction must not invalidate the other direction.
        let reciprocal = self.reciprocal_agent_pairs(policy);
        if !reciprocal.is_empty() {
            result.insert("reciprocal_reviewers".into(), digest(&json!(reciprocal)));
        }
        Ok(result)
    }
    pub(crate) fn dependencies_current(&self, policy: &Policy) -> bool {
        self.dependencies(policy)
            .is_ok_and(|current| current == self.definition_revisions)
    }
}

impl Policy {
    pub(crate) fn reviewer_write_warnings(&self, delegation: &Delegation) -> Vec<String> {
        let Some(native) = &self.native else {
            return vec![];
        };
        let mut warnings = vec![];
        for worker in &delegation.beneficiaries {
            let fields = &native.authored["agents"][&worker.name];
            let mut writable = vec![];
            if let Some(folder) = fields["folder"].as_str() {
                match std::path::Path::new(folder).canonicalize() {
                    Ok(path)=>writable.push(path),
                    Err(_)=>warnings.push(format!("Worker {} has an unavailable workspace path. Its ability to write reviewer startup files is unknown.",worker.name)),
                }
            }
            for mount in fields["mounts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                match crate::host_boot::mount(mount) {
                    Ok((path,_,false))=>writable.push(path),
                    Ok(_)=>{},
                    Err(_)=>warnings.push(format!("Worker {} has an unresolved mount. Its ability to write reviewer startup files is unknown.",worker.name)),
                }
            }
            for reviewer in &delegation.reviewers {
                let home = native
                    .identity_root
                    .join("agents")
                    .join(&reviewer.name)
                    .join("home");
                // These are the native Codex/MCP launch and configuration
                // paths staged by codex-host-setup and stage-coord-native.
                // An ordinary shared source workspace is not a startup path.
                let mut trusted = vec![
                    home.clone(),
                    home.join(".codex"),
                    home.join(".safeyolo"),
                    home.join(".safeyolo-command"),
                    home.join(".safeyolo-interactive-command"),
                ];
                if let Some(script) =
                    native.authored["agents"][&reviewer.name]["host_script"].as_str()
                {
                    trusted.push(script.into());
                }
                for target in trusted {
                    let target = target.canonicalize().unwrap_or(target);
                    if writable.iter().any(|path| target.starts_with(path)) {
                        warnings.push(format!("Worker {} can write a trusted startup path used by reviewer {}: {}. Compromise of that reviewer can exercise this entire delegation.",worker.name,reviewer.name,target.display()));
                    }
                }
            }
        }
        warnings.sort();
        warnings.dedup();
        warnings
    }
}

impl Policy {
    pub(crate) fn independent_delegation_access(&self, delegation: &Delegation) -> Vec<Value> {
        let mut access = vec![];
        for beneficiary in &delegation.beneficiaries {
            for scope in &delegation.scopes {
                match scope {
                    Scope::NetworkEgress {host,ports,all_ports,actions} if !host.contains(['*','?','[']) && !all_ports => {
                        for port in ports { for action in actions {
                            let method=if action=="connect" {"CONNECT"} else {"GET"};
                            // This is the ordinary configured policy path; it
                            // does not include any delegated run permission.
                            let effect=self.evaluate(super::NetworkRequest {agent:Some(&beneficiary.name),host,port:Some(*port),method,path:"/"},super::current_time_ms(),false);
                            access.push(json!({"beneficiary":beneficiary,"type":"network_egress","host":host,"port":port,"action":action,
                                "independent_effect_at_example_root_path":effect.ok(),
                                "limit":"Advanced method/path exceptions can differ. GET is an example, not a claim of safety. Independent policy survives delegation revocation."}));
                        }}
                    }
                    Scope::NetworkEgress {..}=>access.push(json!({"beneficiary":beneficiary,"type":"network_egress","independent_access":"Cannot enumerate all matching destinations or ports. Existing configured permissions remain authoritative and survive revocation."})),
                    Scope::Credential {..}=>access.push(json!({"beneficiary":beneficiary,"type":"credential","independent_access":"Existing shared fingerprint/type and destination permissions survive revocation. Full scope depends on the observed credential classification and current policy; this preview does not infer an API operation limit."})),
                    Scope::ServiceAuthorization {service,capability,..}=>access.push(json!({"beneficiary":beneficiary,"type":"service_authorization","service":service,"capability":capability,
                        "independent_access":"Existing operator service authorization survives delegation revocation. Contract bindings and risky-route grants do not themselves authorize service access."})),
                    Scope::GatewayRoute {service,capability,..}=>access.push(json!({"beneficiary":beneficiary,"type":"gateway_route","service":service,"capability":capability,
                        "independent_access":"Existing service authorization, contract bindings and independently sourced route grants survive revocation. A delegation does not add service authorization."})),
                }
            }
        }
        access
    }
}
