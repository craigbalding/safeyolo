//! Deterministic evaluation of adopted semantics over host-derived permissions.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::{Map, Value};

use super::*;

pub type ResourceScopes = BTreeMap<String, BTreeMap<String, Scope>>;

/// No observed payload or agent rationale enters this input.
#[derive(Clone, Debug, Serialize)]
pub struct Permission {
    pub id: String,
    pub operation: String,
    pub enforcement: Option<String>,
    pub bindings: Map<String, Value>,
    pub path_arguments: BTreeMap<String, Scope>,
    pub unresolved: Vec<String>,
    pub proposed: bool,
}

impl Permission {
    pub fn example(id: String, example: &GrantExample) -> Self {
        Self {
            id,
            operation: example.operation.clone(),
            enforcement: example.enforcement.clone(),
            bindings: example.bindings.clone(),
            path_arguments: BTreeMap::new(),
            unresolved: Vec::new(),
            proposed: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    Match,
    NonMatch,
    Unresolved,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectEffects {
    pub permission: Permission,
    pub method: String,
    pub path: String,
    pub coverage: Coverage,
    pub scopes: ResourceScopes,
    pub possible_effects: Vec<String>,
    pub excluded_effects: Vec<String>,
    pub unresolved_effects: Vec<String>,
    pub unresolved_conditions: Vec<String>,
    pub persistent_effects: Vec<String>,
    pub execution_authority: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Combination {
    pub status: Match,
    pub scope: BTreeMap<String, Scope>,
    pub contributing_permissions: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleAssessment {
    pub status: Match,
    pub resource: String,
    pub required_effects: Vec<String>,
    pub overlap: Overlap,
    pub consequence: String,
    pub explanation: String,
    pub combinations: Vec<Combination>,
    pub unverified_prerequisites: Vec<String>,
    pub gaps: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Assessment {
    pub effect_definitions: BTreeMap<String, NamedEffect>,
    pub sources: BTreeMap<String, Source>,
    pub direct: Vec<DirectEffects>,
    pub rules: BTreeMap<String, RuleAssessment>,
    pub unresolved_conditions: Vec<String>,
    pub limitations: Vec<String>,
}

impl Assessment {
    /// Stable authored identifiers for the existing risk policy's `enables`.
    /// Unresolved combinations are reported separately, not asserted as matches.
    pub fn enables(&self) -> Vec<String> {
        self.direct
            .iter()
            .flat_map(|direct| direct.possible_effects.iter().cloned())
            .chain(
                self.rules
                    .iter()
                    .filter(|(_, rule)| rule.status == Match::Match)
                    .map(|(id, _)| id.clone()),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

impl EffectModel {
    pub fn assess(
        &self,
        service: &ServiceDefinition,
        permissions: &[Permission],
    ) -> Result<Assessment, Error> {
        let mut direct = permissions
            .iter()
            .map(|permission| self.direct(service, permission))
            .collect::<Result<Vec<_>, _>>()?;
        direct.sort_by(|a, b| a.permission.id.cmp(&b.permission.id));
        let rules = self
            .rules
            .iter()
            .map(|(id, rule)| (id.clone(), self.assess_rule(rule, &direct)))
            .collect();
        let unresolved_conditions = direct
            .iter()
            .flat_map(|direct| direct.unresolved_conditions.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut limitations = self.gaps.clone();
        limitations.push("This intentionally partial model describes potential authority. No matching rule does not establish safety. Missing annotations remain unknown.".into());
        limitations.push("Upstream state, prior edits, job existence, runner permissions and actual execution are unverified. Expired or revoked modification access does not prove that prior edits were undone. Effects can persist after access ends; access expiry does not cancel an admitted operation.".into());
        Ok(Assessment {
            effect_definitions: self.effects.clone(),
            sources: self.sources.clone(),
            direct,
            rules,
            unresolved_conditions,
            limitations,
        })
    }

    fn direct(
        &self,
        service: &ServiceDefinition,
        permission: &Permission,
    ) -> Result<DirectEffects, Error> {
        let operation = reference(
            &self.operations,
            &permission.operation,
            "assessment operation",
        )?;
        let example = GrantExample {
            operation: permission.operation.clone(),
            enforcement: permission.enforcement.clone(),
            bindings: permission.bindings.clone(),
            observed_arguments: Map::new(),
        };
        let mut scopes = self.grant_scopes(service, &example)?;
        for (resource, identity) in &operation.resources {
            for (key, source) in identity {
                if let Identity::Argument { argument } = source
                    && let Some(scope) = permission.path_arguments.get(argument)
                {
                    scopes
                        .get_mut(resource)
                        .unwrap()
                        .insert(key.clone(), scope.clone());
                }
            }
        }
        let contract = permission
            .enforcement
            .as_ref()
            .map(|name| self.contract_operation(service, &self.enforcement[name]))
            .transpose()?;
        let mut result = DirectEffects {
            permission: permission.clone(),
            method: operation.method.clone(),
            path: operation.path.clone(),
            coverage: operation.coverage,
            scopes,
            possible_effects: Vec::new(),
            excluded_effects: Vec::new(),
            unresolved_effects: Vec::new(),
            unresolved_conditions: operation.gaps.clone(),
            persistent_effects: Vec::new(),
            execution_authority: operation.execution_authority.clone(),
        };
        result
            .unresolved_conditions
            .extend(permission.unresolved.clone());
        for scope in result.scopes.values().flat_map(|keys| keys.values()) {
            if let Scope::Unresolved { reason } = scope {
                result.unresolved_conditions.push(reason.clone());
            }
        }
        for effect in &operation.effects {
            let condition = possible(
                operation,
                contract,
                &permission.bindings,
                &permission.path_arguments,
                &effect.when,
            );
            let state = if !permission.unresolved.is_empty() && condition != Match::NonMatch {
                Match::Unresolved
            } else {
                condition
            };
            match state {
                Match::Match => result.possible_effects.push(effect.effect.clone()),
                Match::NonMatch => result.excluded_effects.push(effect.effect.clone()),
                Match::Unresolved => {
                    result.unresolved_effects.push(effect.effect.clone());
                    result.unresolved_conditions.push(format!(
                        "{}: condition for {} is unresolved",
                        permission.id, effect.effect
                    ));
                }
            }
            if state != Match::NonMatch && self.effects[&effect.effect].persists_after_access {
                result.persistent_effects.push(effect.effect.clone());
            }
        }
        Ok(result)
    }

    fn assess_rule(&self, rule: &Rule, direct: &[DirectEffects]) -> RuleAssessment {
        let RuleExpression::AllEffectsSameScope { resource, effects } = &rule.when;
        let choices: Vec<Vec<(&DirectEffects, bool)>> = effects
            .iter()
            .map(|effect| {
                direct
                    .iter()
                    .filter_map(|direct| {
                        let operation = &self.operations[&direct.permission.operation];
                        if !operation
                            .effects
                            .iter()
                            .any(|item| &item.effect == effect && &item.resource == resource)
                        {
                            return None;
                        }
                        if direct.possible_effects.contains(effect) {
                            Some((direct, false))
                        } else if direct.unresolved_effects.contains(effect) {
                            Some((direct, true))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .collect();
        let mut combinations = Vec::new();
        combine(
            &choices,
            resource,
            0,
            BTreeMap::new(),
            BTreeSet::new(),
            false,
            &mut combinations,
        );
        let matched = combinations.iter().any(|item| item.status == Match::Match);
        let unresolved = combinations
            .iter()
            .any(|item| item.status == Match::Unresolved)
            || (!matched
                && direct
                    .iter()
                    .any(|direct| direct.coverage == Coverage::Uncharacterised));
        let status = if matched {
            Match::Match
        } else if unresolved {
            Match::Unresolved
        } else {
            Match::NonMatch
        };
        let overlap = if matched {
            Overlap::Same
        } else if unresolved {
            Overlap::Unresolved
        } else if choices.iter().any(Vec::is_empty) {
            Overlap::Excluded
        } else {
            Overlap::Disjoint
        };
        RuleAssessment {
            status,
            resource: resource.clone(),
            required_effects: effects.clone(),
            overlap,
            consequence: rule.consequence.clone(),
            explanation: rule.explanation.clone(),
            combinations,
            unverified_prerequisites: rule.prerequisites.clone(),
            gaps: rule.gaps.clone(),
            evidence: rule.evidence.clone(),
        }
    }

    /// Authoring examples are observations only. They never narrow `assess`.
    pub fn observed_effects(&self, example: &GrantExample) -> Vec<String> {
        let operation = &self.operations[&example.operation];
        operation
            .effects
            .iter()
            .filter(|effect| match &effect.when {
                Condition::Always => true,
                Condition::Present { argument } => {
                    example.observed_arguments.contains_key(argument)
                }
                Condition::Equals { argument, value } => {
                    example.observed_arguments.get(argument).or_else(|| {
                        match &operation.arguments[argument].omission {
                            Omission::Default { value } => Some(value),
                            _ => None,
                        }
                    }) == Some(value)
                }
            })
            .map(|effect| effect.effect.clone())
            .collect()
    }
}

fn possible(
    operation: &Operation,
    contract: Option<&ContractOperation>,
    bindings: &Map<String, Value>,
    path_arguments: &BTreeMap<String, Scope>,
    condition: &Condition,
) -> Match {
    let (argument, expected) = match condition {
        Condition::Always => return Match::Match,
        Condition::Present { argument } => (argument, None),
        Condition::Equals { argument, value } => (argument, Some(value)),
    };
    let reference = argument;
    let argument = &operation.arguments[argument];
    if argument.location == Location::Path {
        let Some(expected) = expected else {
            return Match::Match;
        };
        let value = expected.as_str().map(|value| Scope::Known {
            value: value.into(),
        });
        let scope = path_arguments
            .get(reference)
            .cloned()
            .or_else(|| {
                contract
                    .and_then(|op| op.request.path_params.get(&argument.field))
                    .and_then(|check| bindings.get(&check.equals_var))
                    .and_then(Value::as_str)
                    .map(|value| Scope::Known {
                        value: value.into(),
                    })
            })
            .unwrap_or(Scope::Unrestricted);
        return match value.and_then(|value| intersect(&scope, &value)) {
            None => Match::NonMatch,
            Some(Scope::Unresolved { .. }) => Match::Unresolved,
            _ => Match::Match,
        };
    }
    let constraints = contract
        .filter(|op| {
            argument.location != Location::Body
                || ["POST", "PUT", "PATCH"].contains(&op.request.method.as_str())
        })
        .map(|op| match argument.location {
            Location::Query => &op.request.query,
            Location::Body => &op.request.body,
            Location::Path => &op.request.query, // Path presence is handled below.
        });
    let supplied = if argument.location == Location::Path {
        true
    } else if argument.location == Location::Body
        && contract.is_some_and(|op| {
            op.request
                .transport
                .as_ref()
                .is_some_and(|transport| transport.require_no_body)
        })
    {
        false
    } else {
        constraints.is_none_or(|constraints| {
            !constraints.deny_unknown || constraints.allow.contains_key(&argument.field)
        })
    };
    let supplied_matches = supplied
        && expected.is_none_or(|expected| {
            let check = constraints.and_then(|constraints| constraints.allow.get(&argument.field));
            check.is_none_or(|check| {
                if !check.equals_var.is_empty() {
                    bindings.get(&check.equals_var) == Some(expected)
                } else if check.integer_range.len() == 2 {
                    expected.as_i64().is_some_and(|value| {
                        value >= check.integer_range[0] && value <= check.integer_range[1]
                    })
                } else {
                    true
                }
            })
        });
    if supplied_matches {
        return Match::Match;
    }
    if let Some(expected) = expected {
        match &argument.omission {
            Omission::Default { value } if value == expected => return Match::Match,
            Omission::Unresolved { .. } => return Match::Unresolved,
            _ => (),
        }
    }
    Match::NonMatch
}

/// Intersection of possible identities. Broad known authority includes a
/// concrete job; an unresolved upstream identity never becomes that job.
pub(crate) fn intersect(a: &Scope, b: &Scope) -> Option<Scope> {
    match (a, b) {
        (Scope::Known { value: a }, Scope::Known { value: b }) if a != b => None,
        (Scope::Except { values }, Scope::Known { value })
        | (Scope::Known { value }, Scope::Except { values })
            if values.contains(value) =>
        {
            None
        }
        (Scope::Unresolved { reason }, _) | (_, Scope::Unresolved { reason }) => {
            Some(Scope::Unresolved {
                reason: reason.clone(),
            })
        }
        (Scope::Known { value }, _) | (_, Scope::Known { value }) => Some(Scope::Known {
            value: value.clone(),
        }),
        (Scope::Except { values: a }, Scope::Except { values: b }) => Some(Scope::Except {
            values: a.union(b).cloned().collect(),
        }),
        (Scope::Except { values }, _) | (_, Scope::Except { values }) => Some(Scope::Except {
            values: values.clone(),
        }),
        _ => Some(Scope::Unrestricted),
    }
}

fn combine(
    choices: &[Vec<(&DirectEffects, bool)>],
    resource: &str,
    index: usize,
    scope: BTreeMap<String, Scope>,
    permissions: BTreeSet<String>,
    unresolved: bool,
    output: &mut Vec<Combination>,
) {
    if index == choices.len() {
        output.push(Combination {
            status: if unresolved {
                Match::Unresolved
            } else {
                Match::Match
            },
            scope,
            contributing_permissions: permissions,
        });
        return;
    }
    for (direct, unknown) in &choices[index] {
        let mut next = scope.clone();
        let mut disjoint = false;
        for (key, value) in &direct.scopes[resource] {
            match next
                .get(key)
                .map_or_else(|| Some(value.clone()), |prior| intersect(prior, value))
            {
                Some(value) => {
                    next.insert(key.clone(), value);
                }
                None => {
                    disjoint = true;
                    break;
                }
            }
        }
        if disjoint {
            continue;
        }
        let unresolved = unresolved
            || *unknown
            || next
                .values()
                .any(|scope| matches!(scope, Scope::Unresolved { .. }));
        let mut permissions = permissions.clone();
        permissions.insert(direct.permission.id.clone());
        combine(
            choices,
            resource,
            index + 1,
            next,
            permissions,
            unresolved,
            output,
        );
    }
}
