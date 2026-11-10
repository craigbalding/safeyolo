//! Owner-disclosed authority facts. Reports inform an operator decision; no
//! report field participates in runtime authorization of a standing grant.

mod collection;
mod graph;

use crate::{Error, RuntimeState, policy::Policy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) use collection::{collect, metadata, remote_metadata};

pub(crate) const MAX_OWNERS: usize = 16;
pub(crate) const MAX_FACTS: usize = 2048;
pub(crate) const PAGE_FACTS: usize = 32;
pub(crate) const MAX_REPORT_BYTES: usize = 512 * 1024;
pub(crate) const MAX_FACT_BYTES: usize = 32 * 1024;
pub(crate) const METADATA_PATH: &str = "/support/authority/metadata";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Principal {
    pub instance_id: String,
    pub agent_id: String,
}

impl Principal {
    pub(crate) fn new(instance: &str, agent: &str) -> Self {
        Self {
            instance_id: instance.into(),
            agent_id: agent.into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub principal: Principal,
    pub name: String,
    pub execution: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Capability {
    GuestAdmin {
        target: Principal,
    },
    Inspection {
        target: Principal,
    },
    GuestLogs {
        target: Principal,
        paths: Vec<String>,
    },
    Lifecycle {
        target: Principal,
        actions: Vec<crate::policy::support::Lifecycle>,
    },
    Notifications {
        target: Principal,
        kinds: Vec<crate::policy::support::Notification>,
        signal_rooms: Vec<String>,
    },
    FactoryDirections {
        factory: String,
        snapshot_id: String,
        recipient: Option<Principal>,
        types: Vec<String>,
        current_snapshot: bool,
    },
    ApprovalDecision {
        beneficiaries: Vec<Principal>,
        scopes: Vec<crate::policy::delegation::Scope>,
        grant_seconds: Option<u64>,
        gateway_once: bool,
    },
    GatewayUse {
        service: String,
        capability: Value,
        account: Value,
        credential: Value,
        resources: Vec<Value>,
        contract_bindings: Vec<Value>,
    },
    IssuedPermission {
        permission: Value,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Fact {
    pub fact_id: String,
    pub owner_instance_id: String,
    pub source_type: String,
    pub source_id: String,
    pub revision: String,
    pub holder: Principal,
    pub capability: Capability,
    pub current: bool,
    pub validity: String,
    pub peer_epoch: Option<i64>,
    pub expires_at: Option<String>,
    pub observed_at: i64,
    pub proposed: bool,
}

impl Fact {
    pub(crate) fn identify(&mut self) {
        self.fact_id = crate::approvals::pending::digest(&json!([
            self.owner_instance_id,
            self.source_type,
            self.source_id,
            self.revision,
            self.holder,
            self.capability,
            self.proposed
        ]));
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Snapshot {
    pub owner_instance_id: String,
    pub revision: String,
    pub policy_revision: String,
    pub observed_at: i64,
    pub all_agents: bool,
    pub truncated: bool,
    pub bindings: Vec<Binding>,
    pub configured_destinations: Option<Vec<String>>,
    pub facts: Vec<Fact>,
    pub known_influences: Vec<String>,
}

impl Snapshot {
    pub(crate) fn identify(&mut self) {
        // Observation times and execution/route availability do not change
        // standing authority. The report still records those observations.
        let mut facts = self.facts.clone();
        for fact in &mut facts {
            fact.observed_at = 0;
        }
        self.revision = crate::approvals::pending::digest(&json!([
            self.owner_instance_id,
            self.all_agents,
            self.truncated,
            self.bindings
                .iter()
                .map(|binding| json!([binding.principal, binding.name]))
                .collect::<Vec<_>>(),
            self.policy_revision,
            facts,
            self.known_influences
        ]));
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    #[serde(default)]
    pub owners: Vec<Owner>,
    #[serde(default)]
    pub considered: Option<Value>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Owner {
    pub instance_id: String,
    /// None selects the local owner. Remote entries name an existing route.
    pub home: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct Coverage {
    pub owner: Owner,
    pub status: String,
    pub revision: Option<String>,
    pub observed_at: Option<i64>,
    pub all_agents: bool,
    pub facts: usize,
}

#[derive(Clone, Serialize)]
pub(crate) struct Effect {
    pub controller: Principal,
    pub fact_id: String,
    pub path: Vec<String>,
    pub explanation: String,
}

#[derive(Clone, Serialize)]
pub(crate) struct CommonControl {
    pub controller: Principal,
    pub reviewer: Principal,
    pub beneficiary: Principal,
    pub deciding_fact: String,
    pub reviewer_path: Vec<String>,
    pub beneficiary_path: Vec<String>,
}

#[derive(Clone, Default, Serialize)]
pub(crate) struct Reach {
    pub effects: Vec<Effect>,
    pub common_control: Vec<CommonControl>,
}

#[derive(Clone, Serialize)]
pub(crate) struct Report {
    pub report_id: String,
    pub evidence_revision: String,
    pub proposal_revision: String,
    pub inventory: Vec<Owner>,
    pub collection_started_at: i64,
    pub collection_finished_at: i64,
    pub coverage: Vec<Coverage>,
    pub snapshots: Vec<Snapshot>,
    pub proposed_facts: Vec<Fact>,
    pub before: Reach,
    pub after: Reach,
    pub added: Option<Vec<Effect>>,
    pub removed: Option<Vec<Effect>>,
    pub remaining: Vec<Effect>,
    pub unresolved_frontier: Vec<String>,
    pub summary: String,
    pub limits: String,
}

pub(crate) fn now() -> i64 {
    time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .div_euclid(1_000_000) as i64
}

pub(crate) fn local_snapshot(policy: &Policy) -> Result<Snapshot, Error> {
    Ok(policy.authority_snapshot(None)?)
}

pub(crate) fn snapshot(
    state: &RuntimeState,
    policy: &Policy,
    disclosure: Option<&crate::policy::authority::Disclosure>,
) -> Result<Snapshot, Error> {
    let mut snapshot = policy.authority_snapshot(disclosure)?;
    let store = state
        .read()
        .map_err(|_| "runtime unavailable")?
        .gateway_grants
        .clone();
    if let Some(store) = store {
        let listed = match store.current_grants_for_report(time::OffsetDateTime::now_utc()) {
            Ok(listed) => listed,
            Err(_) => {
                snapshot.truncated = true;
                snapshot.identify();
                return Ok(snapshot);
            }
        };
        for listed in listed {
            if snapshot.facts.len() >= MAX_FACTS {
                snapshot.truncated = true;
                break;
            }
            let grant = listed.grant;
            let Some(id) = policy.evidence_agent_id(&grant.agent) else {
                continue;
            };
            if disclosure.is_some_and(|reader| {
                !reader.all_agents && !reader.agent_ids.iter().any(|selected| selected == id)
            }) {
                continue;
            }
            let mut permission = json!(&grant);
            permission
                .as_object_mut()
                .expect("grant")
                .shift_remove("delegated");
            let mut current = !listed.expired;
            if let Some(encoded) = &grant.delegated {
                match serde_json::from_str::<crate::policy::delegation::IssuedAccess>(encoded)
                    .ok()
                    .filter(|access| access.validate().is_ok())
                {
                    Some(access) => {
                        current &= access.active(policy);
                        permission["source_authority"] = json!(access);
                    }
                    None => {
                        current = false;
                        permission["source_authority_status"] = json!("invalid");
                    }
                }
            }
            if serde_json::to_vec(&permission)?.len() > MAX_FACT_BYTES {
                snapshot.truncated = true;
                continue;
            }
            let mut fact = Fact { fact_id:String::new(),owner_instance_id:snapshot.owner_instance_id.clone(),source_type:"gateway_grant".into(),source_id:grant.grant_id.clone(),
                revision:crate::approvals::pending::digest(&permission),holder:Principal::new(&snapshot.owner_instance_id,id),capability:Capability::IssuedPermission {permission},current,
                validity:"issued gateway route permission; capability, contract, credential, network, reservation and source-authority checks still apply".into(),
                peer_epoch:None,expires_at:Some(grant.expires),observed_at:snapshot.observed_at,proposed:false };
            fact.identify();
            snapshot.facts.push(fact);
        }
    }
    snapshot.identify();
    Ok(snapshot)
}

pub(crate) fn read_policy(state: &RuntimeState) -> Result<Policy, Error> {
    use std::io::Read;
    let runtime = state.read().map_err(|_| "runtime unavailable")?;
    let policy = runtime.policy.as_ref().ok_or("policy unavailable")?;
    let path = runtime
        .config
        .policy_file
        .as_ref()
        .ok_or("policy path unavailable")?;
    let mut source = String::new();
    std::fs::File::open(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_string(&mut source)?;
    if source.len() > 4 * 1024 * 1024 {
        return Err(super::refuse(
            413,
            "authority metadata policy exceeds the read budget",
        ));
    }
    Ok(policy.reload_native_source(&source, path)?)
}

/// Build the same report for support and approval previews. A missing selection
/// explicitly means local coverage, never a fleet-wide independence claim.
pub(crate) async fn report(
    state: &RuntimeState,
    selection: &Selection,
    name: Option<&str>,
    grant: Option<&crate::policy::support::Grant>,
    subject: Option<Principal>,
) -> Result<Report, Error> {
    let started = now();
    let (inventory, coverage, snapshots) = collect(state, &selection.owners).await?;
    let policy = super::current_policy(state)?;
    let instance = super::instance_id()?;
    let proposal_truncated = grant.is_some_and(|grant| {
        serde_json::to_vec(grant).is_ok_and(|bytes| bytes.len() > MAX_FACT_BYTES)
    });
    let mut proposed_facts = match (name, grant.filter(|_| !proposal_truncated)) {
        (Some(name), Some(grant)) => crate::policy::authority::support_facts(
            &policy,
            &instance,
            name,
            grant,
            super::support_principal(&policy, grant).is_some()
                || grant.support_instance_id.is_some(),
            true,
            now(),
        ),
        _ => Vec::new(),
    };
    let proposal_truncated = proposal_truncated || proposed_facts.len() > MAX_FACTS;
    proposed_facts.truncate(MAX_FACTS);
    graph::calculate(
        inventory,
        coverage,
        snapshots,
        graph::Change {
            owner_instance_id: instance.clone(),
            replaced_source: name.map(|name| ("support_grant".into(), name.into())),
            proposed_facts,
            proposal_truncated,
            subject,
            revision: crate::approvals::pending::digest(&json!([
                instance,
                name,
                grant.map(|grant| grant.revision())
            ])),
        },
        started,
    )
}

pub(crate) fn attach(view: &mut Value, selection: &Selection, report: Report) {
    view["impact_summary"] = json!(&report.summary);
    view["authority"] = json!(Selection {
        owners: selection.owners.clone(),
        considered: Some(json!(report))
    });
}

pub(crate) fn acknowledged(selection: &Selection, current: &Report) -> bool {
    selection.considered.as_ref().is_some_and(|considered| {
        if !serde_json::to_vec(considered).is_ok_and(|bytes| bytes.len() <= MAX_REPORT_BYTES)
            || considered["collection_finished_at"]
                .as_i64()
                .is_none_or(|time| time > now())
        {
            return false;
        }
        let mut identified = considered.clone();
        identified["report_id"] = json!("");
        if considered["report_id"] != crate::approvals::pending::digest(&identified) {
            return false;
        }
        // Recompute the complete calculation instead of trusting client-supplied
        // paths or a claimed evidence revision. Only collection observations vary
        // when the same owner facts are read again before apply.
        observation_independent(considered.clone()) == observation_independent(json!(current))
    })
}

fn observation_independent(mut report: Value) -> Value {
    report["report_id"] = json!("");
    report["collection_started_at"] = json!(0);
    report["collection_finished_at"] = json!(0);
    for owner in report["coverage"].as_array_mut().into_iter().flatten() {
        if !owner["observed_at"].is_null() {
            owner["observed_at"] = json!(0);
        }
    }
    for owner in report["snapshots"].as_array_mut().into_iter().flatten() {
        owner["observed_at"] = json!(0);
        owner["configured_destinations"] = Value::Null;
        for binding in owner["bindings"].as_array_mut().into_iter().flatten() {
            binding["execution"] = Value::Null;
        }
        for fact in owner["facts"].as_array_mut().into_iter().flatten() {
            fact["observed_at"] = json!(0);
        }
    }
    for fact in report["proposed_facts"]
        .as_array_mut()
        .into_iter()
        .flatten()
    {
        fact["observed_at"] = json!(0);
    }
    report
}

pub(crate) async fn delegation_report(
    state: &RuntimeState,
    selection: &Selection,
    name: &str,
    delegation: &crate::policy::delegation::Delegation,
) -> Result<Report, Error> {
    let started = now();
    let (inventory, coverage, snapshots) = collect(state, &selection.owners).await?;
    let policy = super::current_policy(state)?;
    let instance = super::instance_id()?;
    let beneficiaries = delegation
        .beneficiaries
        .iter()
        .map(|agent| Principal::new(&instance, &agent.agent_id))
        .collect();
    let proposal_truncated = serde_json::to_vec(delegation)?.len() > MAX_FACT_BYTES;
    let mut proposed = if proposal_truncated {
        Vec::new()
    } else {
        crate::policy::authority::delegation_facts(
            &policy,
            &instance,
            name,
            delegation,
            beneficiaries,
            true,
            now(),
        )
    };
    let proposal_truncated = proposal_truncated || proposed.len() > MAX_FACTS;
    proposed.truncate(MAX_FACTS);
    graph::calculate(
        inventory,
        coverage,
        snapshots,
        graph::Change {
            owner_instance_id: instance.clone(),
            replaced_source: Some(("approval_delegation".into(), name.into())),
            proposed_facts: proposed,
            proposal_truncated,
            subject: None,
            revision: crate::approvals::pending::digest(&json!([
                instance,
                name,
                delegation.revision()
            ])),
        },
        started,
    )
}

pub(crate) fn local_current(policy: &Policy, report: &Report) -> bool {
    let Ok(instance) = super::instance_id() else {
        return false;
    };
    report
        .snapshots
        .iter()
        .find(|snapshot| snapshot.owner_instance_id == instance)
        .is_none_or(|considered| {
            local_snapshot(policy)
                .is_ok_and(|current| current.policy_revision == considered.policy_revision)
        })
}
