//! Explicit owner policy for disclosing typed authority, independent of repair
//! grants, room membership and broker trust.

use super::{Policy, Result, invalid};
use crate::peer_support::authority::{
    Binding, Capability, Fact, MAX_FACT_BYTES, MAX_FACTS, Principal, Snapshot, now,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Disclosure {
    pub instance_id: String,
    /// Null names the operator authenticated by that instance's Admin API.
    pub agent_id: Option<String>,
    pub peer_epoch: Option<i64>,
    pub all_agents: bool,
    pub agent_ids: Vec<String>,
    pub expires_at: Option<String>,
}

fn readers(document: &Value) -> Result<Vec<Disclosure>> {
    document.get("authority_readers").map_or(Ok(Vec::new()), |value| {
        serde_json::from_value(value.clone()).map_err(|_| invalid("authority_readers requires explicit instance, reader identity, trust epoch, subject selection and expiry"))
    })
}

pub(super) fn validate(document: &Value) -> Result<()> {
    for reader in readers(document)? {
        if reader.instance_id.is_empty()
            || reader
                .agent_id
                .as_deref()
                .is_some_and(|id| !crate::desktop_present::valid_agent_id(id))
            || reader
                .agent_ids
                .iter()
                .any(|id| !crate::desktop_present::valid_agent_id(id))
            || (!reader.all_agents && reader.agent_ids.is_empty())
            || reader
                .expires_at
                .as_deref()
                .is_some_and(|expiry| super::parse_expiry(expiry).is_none())
        {
            return Err(invalid(
                "authority_readers needs durable identities, all_agents or selected agent_ids, and RFC 3339 expiry or null",
            ));
        }
    }
    Ok(())
}

impl Policy {
    pub(crate) fn authority_disclosure(
        &self,
        source: &str,
        agent: Option<&str>,
        epoch: Option<i64>,
    ) -> Result<Disclosure> {
        let native = self
            .native
            .as_ref()
            .ok_or_else(|| invalid("native policy unavailable"))?;
        readers(&native.authored)?
            .into_iter()
            .find(|reader| {
                reader.instance_id == source
                    && reader.agent_id.as_deref() == agent
                    && reader.peer_epoch == epoch
                    && !super::delegation::expired(reader.expires_at.as_deref())
            })
            .ok_or_else(|| {
                invalid(
                    "destination has not authorized this reader's authority metadata disclosure",
                )
            })
    }

    pub(crate) fn authority_snapshot(&self, disclosure: Option<&Disclosure>) -> Result<Snapshot> {
        let instance = crate::peer_support::instance_id()
            .map_err(|_| invalid("owner identity unavailable"))?;
        let observed_at = now();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
        let selected = |id: &str| {
            disclosure
                .is_none_or(|d| d.all_agents || d.agent_ids.iter().any(|selected| selected == id))
        };
        let mut snapshot = Snapshot {
            owner_instance_id: instance.clone(),
            revision: String::new(),
            policy_revision: String::new(),
            observed_at,
            all_agents: disclosure.is_none_or(|d| d.all_agents),
            truncated: false,
            bindings: Vec::new(),
            configured_destinations: if disclosure.is_some_and(|reader| !reader.all_agents) {
                None
            } else {
                self.identity_root().and_then(|root| {
                let conn = rusqlite::Connection::open_with_flags(root.join("data/coord/v0.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
                conn.prepare("SELECT DISTINCT instance_id FROM coord_federation_homes ORDER BY instance_id LIMIT 2048").ok()?
                    .query_map([], |row| row.get::<_,String>(0)).ok()?.collect::<std::result::Result<Vec<_>,_>>().ok()
            })
            },
            facts: Vec::new(),
            known_influences: Vec::new(),
        };
        if self
            .native
            .as_ref()
            .and_then(|native| native.authored["agents"].as_object())
            .is_some_and(|agents| agents.len() > MAX_FACTS)
        {
            snapshot.truncated = true;
            snapshot.identify();
            snapshot.policy_revision = snapshot.revision.clone();
            snapshot.identify();
            return Ok(snapshot);
        }
        let mut support_bindings = std::collections::BTreeMap::new();
        for (name, id) in self
            .agent_identities()
            .into_iter()
            .filter(|(_, id)| selected(id))
        {
            if snapshot.bindings.len() >= MAX_FACTS || std::time::Instant::now() >= deadline {
                snapshot.truncated = true;
                break;
            }
            snapshot.bindings.push(Binding {
                principal: Principal::new(&instance, id),
                name: name.into(),
                execution: if self.agent_run(name).is_some() {
                    "current_host_run_binding; action readiness is not probed"
                } else {
                    "no_verified_live_run; standing authority is retained"
                }
                .into(),
            });
        }
        for (name, grant) in self.support_grants() {
            if std::time::Instant::now() >= deadline
                || serde_json::to_vec(&grant).map_or(true, |bytes| bytes.len() > MAX_FACT_BYTES)
            {
                snapshot.truncated = true;
                break;
            }
            let binding = (
                grant.support_instance_id.clone(),
                grant.support.agent_id.clone(),
                grant.support.name.clone(),
                grant.support_peer_epoch,
            );
            let holder_current = *support_bindings
                .entry(binding)
                .or_insert_with(|| crate::peer_support::support_principal(self, &grant).is_some());
            for fact in support_facts(
                self,
                &instance,
                &name,
                &grant,
                holder_current,
                false,
                observed_at,
            ) {
                let included = match &fact.capability {
                    Capability::GuestAdmin { target }
                    | Capability::Inspection { target }
                    | Capability::GuestLogs { target, .. }
                    | Capability::Lifecycle { target, .. }
                    | Capability::Notifications { target, .. } => selected(&target.agent_id),
                    Capability::FactoryDirections { recipient, .. } => {
                        recipient.as_ref().map_or_else(
                            || {
                                grant
                                    .targets
                                    .iter()
                                    .any(|target| selected(&target.agent_id))
                            },
                            |recipient| selected(&recipient.agent_id),
                        )
                    }
                    _ => false,
                };
                if included && !push(&mut snapshot, fact) {
                    break;
                }
            }
            if snapshot.truncated {
                break;
            }
        }
        for (name, delegation) in self.delegations() {
            if snapshot.truncated
                || std::time::Instant::now() >= deadline
                || serde_json::to_vec(delegation).map_or(true, |bytes| bytes.len() > MAX_FACT_BYTES)
            {
                snapshot.truncated = true;
                break;
            }
            let beneficiaries: Vec<_> = delegation
                .beneficiaries
                .iter()
                .filter(|agent| selected(&agent.agent_id))
                .map(|agent| Principal::new(&instance, &agent.agent_id))
                .collect();
            if beneficiaries.is_empty()
                && !delegation
                    .reviewers
                    .iter()
                    .any(|r| r.instance_id.is_none() && selected(&r.agent_id))
            {
                continue;
            }
            let beneficiaries = if beneficiaries.is_empty() {
                delegation
                    .beneficiaries
                    .iter()
                    .map(|agent| Principal::new(&instance, &agent.agent_id))
                    .collect()
            } else {
                beneficiaries
            };
            for fact in delegation_facts(
                self,
                &instance,
                name,
                delegation,
                beneficiaries,
                false,
                observed_at,
            ) {
                if !push(&mut snapshot, fact) {
                    break;
                }
            }
            let mut disclosed = delegation.clone();
            disclosed
                .beneficiaries
                .retain(|agent| selected(&agent.agent_id));
            snapshot
                .known_influences
                .extend(self.reviewer_write_warnings(&disclosed));
        }
        if !snapshot.truncated {
            self.authority_gateway_facts(&mut snapshot, &selected, deadline);
        }
        let grants_revision = self
            .native
            .as_ref()
            .map(|native| {
                crate::approvals::pending::digest(&json!(
                    native.authored["agents"]
                        .as_object()
                        .into_iter()
                        .flatten()
                        .filter(|(_, fields)| fields.get("grants").is_some()
                            && fields["agent_id"].as_str().is_some_and(&selected))
                        .map(|(name, fields)| (name, &fields["grants"]))
                        .collect::<std::collections::BTreeMap<_, _>>()
                ))
            })
            .unwrap_or_default();
        snapshot.policy_revision = grants_revision;
        snapshot.identify();
        snapshot.policy_revision = snapshot.revision.clone();
        snapshot.identify();
        Ok(snapshot)
    }

    fn authority_gateway_facts(
        &self,
        snapshot: &mut Snapshot,
        selected: &impl Fn(&str) -> bool,
        deadline: std::time::Instant,
    ) {
        let Some(native) = &self.native else {
            return;
        };
        for (agent, id) in self
            .agent_identities()
            .into_iter()
            .filter(|(_, id)| selected(id))
        {
            if std::time::Instant::now() >= deadline {
                snapshot.truncated = true;
                return;
            }
            let holder = Principal::new(&snapshot.owner_instance_id, id);
            for (service, config) in native.authored["agents"][agent]["services"]
                .as_object()
                .into_iter()
                .flatten()
            {
                if serde_json::to_vec(config).map_or(true, |bytes| bytes.len() > MAX_FACT_BYTES) {
                    snapshot.truncated = true;
                    return;
                }
                let capability = config.as_str().map_or_else(
                    || {
                        config
                            .get("capability")
                            .or_else(|| config.get("role"))
                            .cloned()
                            .unwrap_or(Value::Null)
                    },
                    |value| json!(value),
                );
                // Authoring stores a credential reference here, never the
                // generated gateway bearer token or a resolved vault value.
                let effect = Capability::GatewayUse {
                    service: service.clone(), capability,
                    account: config.get("account").cloned().unwrap_or(json!("agent")),
                    credential: config.get("token").cloned().unwrap_or(json!("")),
                    resources: self.gateway().into_iter().flat_map(|gateway| gateway.compiled_routes()).filter(|route| route.agent == agent && route.service == *service).map(|route| json!(route)).collect(),
                    contract_bindings: native.authored["agents"][agent]["contract_bindings"].as_array().into_iter().flatten()
                        .filter(|binding| binding["service"] == *service)
                        .map(|binding| json!({"id":binding["id"],"template":binding["template"],"revision":crate::approvals::pending::digest(binding),"grantable_operations":binding["grantable_operations"]})).collect(),
                };
                let revision = crate::approvals::pending::digest(&json!(&effect));
                let mut fact = Fact { fact_id: String::new(), owner_instance_id: snapshot.owner_instance_id.clone(), source_type: "service_authorization".into(),
                    source_id: format!("{agent}/{service}"), revision, holder: holder.clone(), capability: effect,
                    current: true, validity: "declared service use; network, contract, credential and route checks still apply".into(),
                    peer_epoch: None, expires_at: None, observed_at: snapshot.observed_at, proposed: false };
                fact.identify();
                if !push(snapshot, fact) {
                    return;
                }
            }
            for kind in [
                "network_grants",
                "credential_grants",
                "service_grants",
                "binding_grants",
                "coord_grants",
                "desktop_grants",
            ] {
                for access in self.issued_access(agent, kind) {
                    let current = access.active(self);
                    let revision = crate::approvals::pending::digest(&json!(&access));
                    let mut fact = Fact { fact_id: String::new(), owner_instance_id: snapshot.owner_instance_id.clone(), source_type: "issued_permission".into(),
                        source_id: access.approval_id.clone(), revision, holder: holder.clone(),
                        capability: Capability::IssuedPermission { permission: json!(&access) }, current,
                        validity: "issued permission is bound to its run, option, expiry and current source authority".into(),
                        peer_epoch: access.reviewer.peer_epoch, expires_at: access.expires_at.clone(), observed_at: snapshot.observed_at, proposed: false };
                    fact.identify();
                    if !push(snapshot, fact) {
                        return;
                    }
                }
            }
        }
    }
}

fn push(snapshot: &mut Snapshot, fact: Fact) -> bool {
    if snapshot.facts.len() >= MAX_FACTS {
        snapshot.truncated = true;
        false
    } else {
        snapshot.facts.push(fact);
        true
    }
}

pub(crate) fn delegation_facts(
    policy: &Policy,
    instance: &str,
    name: &str,
    delegation: &super::delegation::Delegation,
    beneficiaries: Vec<Principal>,
    proposed: bool,
    observed_at: i64,
) -> Vec<Fact> {
    let revision = delegation.revision();
    let active = delegation.current()
        && delegation.dependencies_current(policy)
        && (proposed || delegation.acknowledgment.as_deref() == Some(revision.as_str()));
    let mut facts = Vec::new();
    for reviewer in &delegation.reviewers {
        let reviewer_current =
            reviewer.principal(policy).is_some() || (proposed && reviewer.instance_id.is_some());
        for beneficiary in &beneficiaries {
            if facts.len() > MAX_FACTS {
                return facts;
            }
            let scopes: Vec<_> = delegation
                .scopes
                .iter()
                .filter(|scope| match scope {
                    super::delegation::Scope::DesktopPresent { run, .. } => {
                        run.agent_id == beneficiary.agent_id
                    }
                    _ => true,
                })
                .cloned()
                .collect();
            let current = active
                && reviewer_current
                && !scopes.is_empty()
                && delegation.beneficiaries.iter().any(|agent| {
                    agent.agent_id == beneficiary.agent_id
                        && policy.evidence_agent_id(&agent.name) == Some(&agent.agent_id)
                });
            let mut fact = Fact { fact_id: String::new(), owner_instance_id: instance.into(), source_type: "approval_delegation".into(),
                source_id: name.into(), revision: revision.clone(), holder: Principal::new(reviewer.instance_id.as_deref().unwrap_or(instance), &reviewer.agent_id),
                capability: Capability::ApprovalDecision { beneficiaries: vec![beneficiary.clone()], scopes, grant_seconds: delegation.grant_seconds, gateway_once: delegation.gateway_once },
                current, validity: if current { "current deciding scope; future eligible canonical requests only; configured actor and issuance checks remain" } else { "expired, changed binding, trust or delegation dependencies" }.into(),
                peer_epoch: reviewer.peer_epoch, expires_at: delegation.expires_at.clone(), observed_at, proposed };
            fact.identify();
            facts.push(fact);
        }
    }
    facts
}

pub(crate) fn support_facts(
    policy: &Policy,
    instance: &str,
    name: &str,
    grant: &super::support::Grant,
    holder_current: bool,
    proposed: bool,
    observed_at: i64,
) -> Vec<Fact> {
    let mut result = Vec::new();
    let holder = Principal::new(
        grant.support_instance_id.as_deref().unwrap_or(instance),
        &grant.support.agent_id,
    );
    let revision = grant.revision();
    for target in &grant.targets {
        let principal = Principal::new(instance, &target.agent_id);
        let current = grant.instance_id == instance
            && holder_current
            && (proposed || grant.active())
            && !super::delegation::expired(grant.expires_at.as_deref())
            && policy.evidence_agent_id(&target.name) == Some(&target.agent_id);
        let mut capabilities = vec![Capability::Inspection {
            target: principal.clone(),
        }];
        if grant.guest_admin {
            capabilities.push(Capability::GuestAdmin {
                target: principal.clone(),
            });
        }
        if !grant.guest_logs.is_empty() {
            capabilities.push(Capability::GuestLogs {
                target: principal.clone(),
                paths: grant.guest_logs.clone(),
            });
        }
        if !grant.lifecycle.is_empty() {
            capabilities.push(Capability::Lifecycle {
                target: principal.clone(),
                actions: grant.lifecycle.clone(),
            });
        }
        if !grant.notifications.is_empty() {
            capabilities.push(Capability::Notifications {
                target: principal.clone(),
                kinds: grant.notifications.clone(),
                signal_rooms: grant.signal_rooms.clone(),
            });
        }
        for selected in &grant.factory_directions {
            let binding = policy.identity_root().and_then(|root| {
                crate::factory::direction_binding(
                    root,
                    &selected.factory,
                    &selected.snapshot_id,
                    None,
                )
                .ok()
            });
            if let Some(binding) = &binding
                && binding.operator_agent() == target.name
            {
                capabilities.push(Capability::FactoryDirections {
                    factory: selected.factory.clone(),
                    snapshot_id: selected.snapshot_id.clone(),
                    recipient: Some(principal.clone()),
                    types: selected.types.clone(),
                    current_snapshot: true,
                });
            } else if binding.is_none() && grant.targets.first() == Some(target) {
                capabilities.push(Capability::FactoryDirections {
                    factory: selected.factory.clone(),
                    snapshot_id: selected.snapshot_id.clone(),
                    recipient: None,
                    types: selected.types.clone(),
                    current_snapshot: false,
                });
            }
        }
        for capability in capabilities {
            if result.len() > MAX_FACTS {
                return result;
            }
            let current = current
                && !matches!(
                    &capability,
                    Capability::FactoryDirections {
                        current_snapshot: false,
                        ..
                    }
                );
            let mut fact = Fact {
                fact_id: String::new(),
                owner_instance_id: instance.into(),
                source_type: "support_grant".into(),
                source_id: name.into(),
                revision: revision.clone(),
                holder: holder.clone(),
                current,
                capability,
                validity: if current {
                    "current standing authority; runtime and route availability are separate"
                } else {
                    "expired, unacknowledged, replaced identity, changed trust or stale factory snapshot"
                }
                .into(),
                peer_epoch: grant.support_peer_epoch,
                expires_at: grant.expires_at.clone(),
                observed_at,
                proposed,
            };
            fact.identify();
            result.push(fact);
        }
    }
    result
}
