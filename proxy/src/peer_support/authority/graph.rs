//! Breadth-first guest-control paths and typed effects, with finite work and
//! one supporting path per effect. Approval decisions never create control edges.

use super::*;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_STEPS: usize = 50_000;
const MAX_EFFECTS: usize = 128;
const MAX_COMMON: usize = 64;
const MAX_DEPTH: usize = 32;

struct Graph<'a> {
    facts: Vec<&'a Fact>,
    by_holder: BTreeMap<Principal, Vec<usize>>,
}

impl<'a> Graph<'a> {
    fn new(facts: Vec<&'a Fact>) -> Self {
        let mut by_holder: BTreeMap<Principal, Vec<usize>> = BTreeMap::new();
        for (index, fact) in facts.iter().enumerate().filter(|(_, fact)| fact.current) {
            by_holder
                .entry(fact.holder.clone())
                .or_default()
                .push(index);
        }
        Self { facts, by_holder }
    }

    fn paths(
        &self,
        root: &Principal,
        steps: &mut usize,
        frontier: &mut BTreeSet<String>,
    ) -> BTreeMap<Principal, Vec<String>> {
        let mut paths = BTreeMap::from([(root.clone(), Vec::new())]);
        let mut queue = VecDeque::from([root.clone()]);
        while let Some(holder) = queue.pop_front() {
            for &index in self.by_holder.get(&holder).into_iter().flatten() {
                if *steps >= MAX_STEPS {
                    frontier.insert(
                        "traversal work budget reached; additional reach is unknown".into(),
                    );
                    return paths;
                }
                *steps += 1;
                let fact = self.facts[index];
                if let Capability::GuestAdmin { target } = &fact.capability {
                    if paths.contains_key(target) {
                        continue;
                    }
                    if paths[&holder].len() >= MAX_DEPTH {
                        frontier.insert(format!(
                            "depth budget at {}:{}; additional reach is unknown",
                            target.instance_id, target.agent_id
                        ));
                        continue;
                    }
                    let mut path = paths[&holder].clone();
                    path.push(fact.fact_id.clone());
                    paths.insert(target.clone(), path);
                    queue.push_back(target.clone());
                }
            }
        }
        paths
    }

    fn reach(&self, primary: Option<&Principal>, frontier: &mut BTreeSet<String>) -> Reach {
        let mut result = Reach::default();
        let by_id: BTreeMap<_, _> = self
            .facts
            .iter()
            .map(|fact| (fact.fact_id.as_str(), *fact))
            .collect();
        let mut steps = 0;
        let mut roots: BTreeSet<_> = self.by_holder.keys().cloned().collect();
        if let Some(primary) = primary {
            roots.insert(primary.clone());
        }
        let mut ordered = Vec::new();
        if let Some(primary) = primary {
            roots.remove(primary);
            ordered.push(primary.clone());
        }
        ordered.extend(roots);
        for root in ordered {
            let paths = self.paths(&root, &mut steps, frontier);
            if primary.is_none_or(|primary| paths.contains_key(primary)) {
                for (holder, path) in &paths {
                    for &index in self.by_holder.get(holder).into_iter().flatten() {
                        if result.effects.len() >= MAX_EFFECTS {
                            frontier.insert(
                                "effect output budget reached; additional effects are unknown"
                                    .into(),
                            );
                            break;
                        }
                        let fact = self.facts[index];
                        let mut path = path.clone();
                        path.push(fact.fact_id.clone());
                        let explanation = path
                            .iter()
                            .map(|id| {
                                let step = by_id[id.as_str()];
                                let kind = json!(&step.capability)["type"]
                                    .as_str()
                                    .unwrap_or("typed_effect")
                                    .to_owned();
                                let target = match &step.capability {
                                    Capability::GuestAdmin { target }
                                    | Capability::Inspection { target }
                                    | Capability::GuestLogs { target, .. }
                                    | Capability::Lifecycle { target, .. }
                                    | Capability::Notifications { target, .. } => {
                                        format!(" {}:{}", target.instance_id, target.agent_id)
                                    }
                                    _ => String::new(),
                                };
                                format!(
                                    "{}:{} --[{} / {}: {}]-->{}",
                                    step.holder.instance_id,
                                    step.holder.agent_id,
                                    step.owner_instance_id,
                                    step.source_id,
                                    kind,
                                    target
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("; ");
                        result.effects.push(Effect {
                            controller: root.clone(),
                            fact_id: fact.fact_id.clone(),
                            path,
                            explanation,
                        });
                    }
                }
            }
            for fact in &self.facts {
                if steps >= MAX_STEPS {
                    frontier.insert(
                        "traversal work budget reached; additional reach is unknown".into(),
                    );
                    break;
                }
                steps += 1;
                if !fact.current {
                    continue;
                }
                let Capability::ApprovalDecision { beneficiaries, .. } = &fact.capability else {
                    continue;
                };
                let Some(reviewer_path) = paths.get(&fact.holder) else {
                    continue;
                };
                for beneficiary in beneficiaries {
                    let Some(beneficiary_path) = paths.get(beneficiary) else {
                        continue;
                    };
                    if result.common_control.len() >= MAX_COMMON {
                        frontier.insert("common-control output budget reached; further common controllers are unknown".into());
                        break;
                    }
                    result.common_control.push(CommonControl {
                        controller: root.clone(),
                        reviewer: fact.holder.clone(),
                        beneficiary: beneficiary.clone(),
                        deciding_fact: fact.fact_id.clone(),
                        reviewer_path: reviewer_path.clone(),
                        beneficiary_path: beneficiary_path.clone(),
                    });
                }
            }
            if steps >= MAX_STEPS {
                break;
            }
        }
        result
    }
}

fn effect_key(effect: &Effect, facts: &BTreeMap<&str, &Fact>) -> String {
    let fact = facts[effect.fact_id.as_str()];
    crate::approvals::pending::digest(&json!([effect.controller, fact.holder, fact.capability]))
}

pub(super) struct Change {
    pub owner_instance_id: String,
    pub replaced_source: Option<(String, String)>,
    pub proposed_facts: Vec<Fact>,
    pub proposal_truncated: bool,
    pub subject: Option<Principal>,
    pub revision: String,
}

pub(super) fn calculate(
    inventory: Vec<Owner>,
    mut coverage: Vec<Coverage>,
    mut snapshots: Vec<Snapshot>,
    change: Change,
    started: i64,
) -> Result<Report, Error> {
    let local_instance = change.owner_instance_id.as_str();
    let replaced_source = change
        .replaced_source
        .as_ref()
        .map(|(kind, name)| (kind.as_str(), name.as_str()));
    let mut proposed_facts = change.proposed_facts;
    let mut proposal_truncated = change.proposal_truncated;
    let subject = change.subject;
    let proposal_revision = change.revision;
    loop {
        let mut frontier = BTreeSet::new();
        if proposal_truncated {
            frontier.insert(
                "proposal detail budget reached; additional proposed reach is unknown".into(),
            );
        }
        for owner in coverage.iter().filter(|entry| entry.status != "current") {
            frontier.insert(format!(
                "{}: {}; additional reach is unknown",
                owner.owner.instance_id, owner.status
            ));
        }
        let selected: BTreeSet<_> = inventory
            .iter()
            .map(|owner| owner.instance_id.as_str())
            .collect();
        if !selected.contains(local_instance) && replaced_source.is_some() {
            frontier.insert(format!(
                "{local_instance}: proposal owner is outside the selected inventory"
            ));
        }
        let current_binding = |fact: &&Fact| {
            snapshots
                .iter()
                .find(|snapshot| {
                    snapshot.owner_instance_id == fact.holder.instance_id
                        && snapshot.all_agents
                        && !snapshot.truncated
                })
                .is_none_or(|snapshot| {
                    snapshot
                        .bindings
                        .iter()
                        .any(|binding| binding.principal == fact.holder)
                })
        };
        let before_facts: Vec<_> = snapshots
            .iter()
            .flat_map(|snapshot| &snapshot.facts)
            .filter(current_binding)
            .collect();
        let mut after_facts: Vec<_> = before_facts
            .iter()
            .copied()
            .filter(|fact| {
                !(fact.owner_instance_id == local_instance
                    && Some((fact.source_type.as_str(), fact.source_id.as_str()))
                        == replaced_source)
            })
            .collect();
        after_facts.extend(proposed_facts.iter().filter(|fact| current_binding(fact)));
        for fact in before_facts.iter().chain(&after_facts) {
            if matches!(
                &fact.capability,
                Capability::FactoryDirections {
                    current_snapshot: false,
                    ..
                }
            ) {
                frontier.insert(format!("{} / {}: approved factory snapshot or recipient metadata changed or is unavailable; direction reach is unresolved",fact.owner_instance_id,fact.source_id));
            }
            for principal in principals(fact) {
                if !selected.contains(principal.instance_id.as_str()) {
                    frontier.insert(format!(
                        "{}: referenced owner is unselected; additional reach is unknown",
                        principal.instance_id
                    ));
                }
            }
        }
        let before = Graph::new(before_facts).reach(subject.as_ref(), &mut frontier);
        let after = Graph::new(after_facts).reach(subject.as_ref(), &mut frontier);
        let facts: BTreeMap<_, _> = snapshots
            .iter()
            .flat_map(|snapshot| &snapshot.facts)
            .chain(proposed_facts.iter())
            .map(|fact| (fact.fact_id.as_str(), fact))
            .collect();
        let old: BTreeSet<_> = before
            .effects
            .iter()
            .map(|effect| effect_key(effect, &facts))
            .collect();
        let new: BTreeSet<_> = after
            .effects
            .iter()
            .map(|effect| effect_key(effect, &facts))
            .collect();
        let added: Vec<_> = after
            .effects
            .iter()
            .filter(|effect| !old.contains(&effect_key(effect, &facts)))
            .cloned()
            .collect();
        let remaining: Vec<_> = after
            .effects
            .iter()
            .filter(|effect| old.contains(&effect_key(effect, &facts)))
            .cloned()
            .collect();
        let removed: Vec<_> = before
            .effects
            .iter()
            .filter(|effect| !new.contains(&effect_key(effect, &facts)))
            .cloned()
            .collect();
        let current_owners = coverage
            .iter()
            .filter(|owner| owner.status == "current")
            .count();
        let changes_known = !frontier.iter().any(|gap| gap.contains("budget"));
        let mut summary = format!(
            "{} new or changed typed effects in the collected facts; {} former effect descriptions removed or changed; {} remain reachable. {} of {} selected owners fully disclosed current metadata. {} common-control relationships after the proposal. Additional reach outside this evidence is unknown.",
            added.len(),
            removed.len(),
            remaining.len(),
            current_owners,
            inventory.len(),
            after.common_control.len()
        );
        if !changes_known {
            summary = format!(
                "Change totals are unknown because an analysis budget was reached. Retained before/after paths and {} common-control relationships remain inspectable. Additional reach is unknown.",
                after.common_control.len()
            );
        }
        let evidence_revision = crate::approvals::pending::digest(&json!([
            coverage
                .iter()
                .map(|entry| json!([entry.owner, entry.status, entry.revision, entry.all_agents]))
                .collect::<Vec<_>>(),
            proposal_revision,
            frontier
        ]));
        let mut report = Report {
            report_id: String::new(), evidence_revision, proposal_revision: proposal_revision.clone(), inventory: inventory.clone(),
            collection_started_at: started, collection_finished_at: now(), coverage: coverage.clone(), snapshots: snapshots.clone(), proposed_facts: proposed_facts.clone(),
            before, after, added: changes_known.then_some(added), removed: changes_known.then_some(removed), remaining, unresolved_frontier: frontier.into_iter().collect(), summary,
            limits: "Declared guest administration and scoped approval composition only. Added/removed compare exact typed scopes; a changed scope appears on both sides and does not imply an authority increase or complete revocation. One supporting path per effect; no globally atomic snapshot. Runtime, route and credential availability are separate from standing authority. Unknown owners and unmodeled guest programs, shared files or external influence prevent a claim of reviewer independence. Guest-log links may disclose any target-accessible data. Gateway use is not vault administration. Later target capabilities can expand standing authority. This report grants, prohibits and revokes nothing.".into(),
        };
        report.report_id = crate::approvals::pending::digest(&json!(&report));
        if serde_json::to_vec(&report)?.len() <= MAX_REPORT_BYTES {
            return Ok(report);
        }
        let Some(snapshot) = snapshots.pop() else {
            if proposed_facts.is_empty() {
                return Err("owner inventory exceeds the report budget".into());
            }
            proposed_facts.truncate(proposed_facts.len() / 2);
            proposal_truncated = true;
            continue;
        };
        if let Some(owner) = coverage
            .iter_mut()
            .find(|owner| owner.owner.instance_id == snapshot.owner_instance_id)
        {
            owner.status = "report_size_budget_exhausted".into();
            owner.facts = 0;
        }
    }
}

fn principals(fact: &Fact) -> Vec<&Principal> {
    let mut values = vec![&fact.holder];
    match &fact.capability {
        Capability::GuestAdmin { target }
        | Capability::Inspection { target }
        | Capability::GuestLogs { target, .. }
        | Capability::Lifecycle { target, .. }
        | Capability::Notifications { target, .. } => values.push(target),
        Capability::FactoryDirections { recipient, .. } => values.extend(recipient),
        Capability::ApprovalDecision { beneficiaries, .. } => values.extend(beneficiaries),
        Capability::GatewayUse { .. } | Capability::IssuedPermission { .. } => {}
    }
    values
}

#[cfg(test)]
#[path = "graph_tests.rs"]
mod tests;
