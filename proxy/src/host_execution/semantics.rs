//! Host packages use the service effect evaluator and reviewed vocabulary.
//! Trusted native owners supply full authority, not a sample invocation.
use super::*;
use crate::services::effects::{
    self as effects,
    assessment::{Match, Permission, ResourceScopes, ScopedEffect},
    *,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub id: String,
    pub target_id: String,
    pub operations: BTreeMap<String, OperationScope>,
    pub proposed: bool,
}

/// An observation supplied by a trusted evidence owner, not a history store.
/// Expired grants are not evidence that these earlier effects were undone.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentEffect {
    pub id: String,
    pub observed_at: String,
    pub target_id: String,
    pub operation: String,
    pub scopes: ResourceScopes,
    pub effects: BTreeSet<String>,
    pub evidence: Vec<Source>,
}

fn argument_name(name: &str) -> String {
    format!("argument:{name}")
}

/// Logical operation paths inventory semantics. They are not exposed HTTP
/// routes or additional invocation capabilities.
pub fn service(package: &Package) -> Result<Option<ServiceDefinition>, Error> {
    package.validate()?;
    let Some(notes) = &package.semantics else {
        return Ok(None);
    };
    let mut operations = BTreeMap::new();
    let mut named_effects = BTreeMap::<String, NamedEffect>::new();
    for (id, op) in &package.operations {
        for (name, definition) in &op.effects {
            if named_effects
                .get(name)
                .is_some_and(|prior| revision(prior) != revision(definition))
            {
                return Err(format!("conflicting host effect definition: {name}").into());
            }
            named_effects.insert(name.clone(), definition.clone());
        }
        let mut arguments = BTreeMap::new();
        for (name, arg) in &op.arguments {
            arguments.insert(
                argument_name(name),
                effects::Argument {
                    location: Location::Body,
                    field: name.clone(),
                    required: arg.required,
                    omission: if let Some(default) = &arg.default {
                        Omission::Default {
                            value: default.clone(),
                        }
                    } else if arg.required {
                        Omission::Invalid
                    } else {
                        Omission::Unchanged
                    },
                    evidence: vec!["package".into()],
                },
            );
        }
        let mut resources = BTreeMap::new();
        let mut uses = Vec::new();
        let mut gaps = op.enforcement.unresolved.clone();
        gaps.extend(op.enforcement.adopted.clone());
        if let Some(semantics) = &op.semantics {
            for (name, identity) in &semantics.resources {
                resources.insert(
                    name.clone(),
                    identity
                        .iter()
                        .map(|(key, source)| {
                            let scope_reference = format!("scope:{name}:{key}");
                            let value = match source {
                                HostIdentity::Fixed { value } => Identity::Fixed {
                                    value: value.clone(),
                                },
                                HostIdentity::Unresolved { reason } => Identity::Unresolved {
                                    reason: reason.clone(),
                                },
                                _ => {
                                    arguments.insert(
                                        scope_reference.clone(),
                                        effects::Argument {
                                            location: Location::Body,
                                            field: scope_reference.clone(),
                                            required: true,
                                            omission: Omission::Invalid,
                                            evidence: vec!["package".into()],
                                        },
                                    );
                                    Identity::Argument {
                                        argument: scope_reference,
                                    }
                                }
                            };
                            (key.clone(), value)
                        })
                        .collect(),
                );
            }
            uses = semantics.effects.clone();
            for effect in &mut uses {
                match &mut effect.when {
                    Condition::Always => (),
                    Condition::Present { argument } | Condition::Equals { argument, .. } => {
                        *argument = argument_name(argument)
                    }
                }
            }
            gaps.extend(
                semantics
                    .prerequisites
                    .iter()
                    .map(|s| format!("Prerequisite: {s}")),
            );
            gaps.extend(semantics.limitations.clone());
        } else {
            gaps.push("Host operation has no reviewed resource/effect annotations; behavior remains uncharacterised.".into());
        }
        operations.insert(
            id.clone(),
            effects::Operation {
                method: "POST".into(),
                path: format!("/operations/{id}"),
                coverage: if op.semantics.is_some() {
                    Coverage::Modeled
                } else {
                    Coverage::Uncharacterised
                },
                arguments,
                resources,
                effects: uses,
                execution_authority: format!(
                    "{}; execution principal {}; broader bounds {:?}; delegated services {}. {}",
                    op.description,
                    op.execution.identity.principal,
                    op.execution.broader,
                    serde_json::to_string(&op.execution.delegated_services)?,
                    op.enforcement.adopted.join(" ")
                ),
                evidence: op
                    .semantics
                    .as_ref()
                    .map_or_else(|| vec!["package".into()], |s| s.evidence.clone()),
                gaps,
            },
        );
    }
    let mut sources = notes.sources.clone();
    sources.insert("package".into(), package.source.clone());
    let model = EffectModel {
        sources,
        resources: notes.resources.clone(),
        effects: named_effects,
        operations,
        enforcement: BTreeMap::new(),
        rules: notes.rules.clone(),
        // Native alternatives are checked against native argument/authority
        // owners below. No flat-route enforcement claim is generated for them.
        alternatives: BTreeMap::new(),
        regressions: vec![],
        gaps: notes.gaps.clone(),
    };
    let service = ServiceDefinition::from_value(
        json!({"schema_version":1,"name":format!("{}:effects",package.name),"default_host":"","capabilities":{},"effect_model":model}),
    )?;
    Ok(Some(service))
}

fn values(choices: impl Iterator<Item = String>) -> Scope {
    let values: BTreeSet<_> = choices.collect();
    match values.len() {
        0 => Scope::Unresolved {
            reason: "No represented identity value".into(),
        },
        1 => Scope::Known {
            value: values.into_iter().next().unwrap(),
        },
        _ => Scope::Values { values },
    }
}

fn identity(choices: &[Option<Value>], aliases: &BTreeMap<String, String>) -> Scope {
    let mut known = Vec::new();
    for choice in choices {
        let Some(value) = choice else {
            return Scope::Unresolved {
                reason: "Identity argument may be absent".into(),
            };
        };
        let value = value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string());
        if aliases.is_empty() {
            known.push(value);
        } else if let Some(canonical) = aliases.get(&value) {
            known.push(canonical.clone());
        } else {
            return Scope::Unresolved {
                reason: format!("Unreviewed alias: {value}"),
            };
        }
    }
    values(known.into_iter())
}

fn permissions(package: &Package, authority: &[Authority]) -> Result<Vec<Permission>, Error> {
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    for grant in authority {
        if grant.target_id.is_empty() || !ids.insert(&grant.id) {
            return Err("host authority needs a target and unique contributing ID".into());
        }
        for (id, scope) in &grant.operations {
            let op = package
                .operations
                .get(id)
                .ok_or("authority selects an unknown host operation")?;
            if scope.implementation_sha256 != op.implementation_sha256() {
                return Err("host authority assessment has a stale operation pin".into());
            }
            let mut native_arguments = BTreeMap::new();
            for (name, arg) in &op.arguments {
                let choices = scope.arguments.get(name).cloned().unwrap_or_default();
                // Native authority authorizes complete typed JSON values. A
                // default is an effective value and must itself be authorized.
                for choice in &choices {
                    if !arg.accepts(choice) {
                        return Err(
                            "native authority contains an invalid typed argument choice".into()
                        );
                    }
                }
                let mut choices: Vec<_> = choices.into_iter().map(Some).collect();
                if !arg.required && arg.default.is_none() {
                    choices.push(None);
                }
                if choices.is_empty() {
                    return Err(
                        format!("authority has no executable choice for {id}/{name}").into(),
                    );
                }
                native_arguments.insert(argument_name(name), choices);
            }
            if scope
                .arguments
                .keys()
                .any(|name| !op.arguments.contains_key(name))
            {
                return Err("host authority contains an unknown argument".into());
            }
            for resource in &scope.resources {
                if !op.resources.contains(resource) {
                    return Err("host authority contains an unadopted resource".into());
                }
                let mut path_arguments = BTreeMap::new();
                if let Some(notes) = &op.semantics {
                    for (name, mapping) in &notes.resources {
                        for (key, source) in mapping {
                            let value = match source {
                                HostIdentity::Target => Scope::Known {
                                    value: grant.target_id.clone(),
                                },
                                HostIdentity::ExecutionPrincipal => Scope::Known {
                                    value: op.execution.identity.principal.clone(),
                                },
                                HostIdentity::Resource { aliases } => {
                                    identity(&[Some(json!(resource))], aliases)
                                }
                                HostIdentity::Argument { argument, aliases } => {
                                    identity(&native_arguments[&argument_name(argument)], aliases)
                                }
                                _ => continue,
                            };
                            path_arguments.insert(format!("scope:{name}:{key}"), value);
                        }
                    }
                }
                result.push(Permission {
                    id: format!(
                        "host:{}",
                        serde_json::to_string(&(&grant.id, id, resource))?
                    ),
                    operation: id.clone(),
                    enforcement: None,
                    bindings: Map::new(),
                    path_arguments,
                    native_arguments: native_arguments.clone(),
                    unresolved: vec![],
                    proposed: grant.proposed,
                });
            }
        }
    }
    Ok(result)
}

/// One deterministic prepared value for discovery/review, challenge and
/// operator assessment. No agent rationale or policy decision enters this API.
/// `authority` must come from the native grant/ceiling owner, not request JSON.
pub fn assess(
    package: &Package,
    authority: &[Authority],
    history: &[PersistentEffect],
) -> Result<Value, Error> {
    let service = service(package)?.ok_or("host package has no adopted semantics")?;
    let model = service.effect_model.as_ref().unwrap();
    let permissions = permissions(package, authority)?;
    let mut assessment = model.assess(&service, &permissions)?;
    let mut observations = BTreeSet::new();
    for observation in history {
        if !observations.insert(&observation.id) {
            return Err("persistent observation IDs must be distinct".into());
        }
        if observation.evidence.is_empty() || observation.observed_at.is_empty() {
            return Err("persistent observation needs evidence and observation time".into());
        }
        let op = package
            .operations
            .get(&observation.operation)
            .ok_or("unknown historical operation; retain explicit historical uncertainty")?;
        if observation.effects.is_empty()
            || observation.effects.iter().any(|name| {
                !op.effects
                    .get(name)
                    .is_some_and(|e| e.persists_after_access)
            })
        {
            return Err("historical observation must select known persistent effects only".into());
        }
        let modeled = &model.operations[&observation.operation];
        if observation.scopes.len() != modeled.resources.len()
            || modeled.resources.iter().any(|(name, mapping)| {
                observation.scopes.get(name).is_none_or(|scope| {
                    scope.keys().collect::<BTreeSet<_>>() != mapping.keys().collect()
                })
            })
        {
            return Err(
                "historical observation needs complete recorded resource identities".into(),
            );
        }
        for (name, mapping) in &op
            .semantics
            .as_ref()
            .ok_or("uncharacterised historical operation")?
            .resources
        {
            for (key, source) in mapping {
                if matches!(source, HostIdentity::Target)
                    && observation.scopes[name][key]
                        != (Scope::Known {
                            value: observation.target_id.clone(),
                        })
                {
                    return Err(
                        "historical observation target differs from its recorded scope".into(),
                    );
                }
            }
        }
        let permission = Permission {
            id: format!("retained:{}", observation.id),
            operation: observation.operation.clone(),
            enforcement: None,
            bindings: Map::new(),
            path_arguments: BTreeMap::new(),
            native_arguments: BTreeMap::new(),
            unresolved: vec![],
            proposed: false,
        };
        let mut direct = model.assess(&service, &[permission])?.direct.remove(0);
        direct.scopes = observation.scopes.clone();
        direct.effects = modeled
            .effects
            .iter()
            .filter(|e| observation.effects.contains(&e.effect))
            .map(|e| ScopedEffect {
                effect: e.effect.clone(),
                resource: e.resource.clone(),
                status: Match::Match,
            })
            .collect();
        direct.possible_effects = observation.effects.iter().cloned().collect();
        direct.persistent_effects = direct.possible_effects.clone();
        direct.excluded_effects.clear();
        direct.unresolved_effects.clear();
        direct.unresolved_conditions = vec![format!(
            "Retained observation {}, recorded {}. Current existence and reversal remain unverified.",
            observation.id, observation.observed_at
        )];
        assessment.direct.push(direct);
    }
    assessment = model.assess_direct(assessment.direct);
    let alternatives = alternatives(package, authority, &service)?;
    Ok(
        json!({"package_revision":revision(package),"understanding_revision":revision(&(&package.semantics,package.operations.iter().map(|(id,op)|(id,op.semantic_revisions().understanding)).collect::<BTreeMap<_,_>>())),"model":assessment,"alternatives":alternatives,"known_persistent_effects":history,"limitations":["Only represented authority and supplied trusted observations are assessed. Historical state and ambient dependencies remain unobserved unless evidence is supplied. Expiry does not remove earlier effects.","This prepared assessment grants nothing. Existing authored allow/deny/approval policy decides acceptable risk. Native target and gateway owners must enforce the actual invocation."]}),
    )
}

fn alternatives(
    package: &Package,
    authority: &[Authority],
    service: &ServiceDefinition,
) -> Result<Value, Error> {
    let mut result = Map::new();
    for (name, recipe) in &package.semantics.as_ref().unwrap().alternatives {
        let mut steps = Vec::new();
        for step in &recipe.steps {
            let op = &package.operations[&step.operation];
            let supplied = step
                .arguments
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let arguments = op.arguments(&supplied)?;
            let matching: Vec<_> = authority
                .iter()
                .filter(|grant| {
                    grant.operations.get(&step.operation).is_some_and(|scope| {
                        !scope.resources.is_empty()
                            && arguments.iter().all(|(name, value)| {
                                scope
                                    .arguments
                                    .get(name)
                                    .is_some_and(|choices| choices.contains(value))
                            })
                    })
                })
                .collect();
            let sources = |proposed| {
                matching.iter().filter(|grant|grant.proposed==proposed).map(|grant|json!({"permission":grant.id,"target_id":grant.target_id,"resources":grant.operations[&step.operation].resources})).collect::<Vec<_>>()
            };
            steps.push(json!({"operation":step.operation,"required_arguments":arguments,"resource_choices":op.resources,"available_from":sources(false),"within_proposed_authority":sources(true),"expected_effects":step.expected_effects,"execution_principal":op.execution.identity.principal,"enforcement":op.enforcement}));
        }
        result.insert(name.clone(),json!({"steps":steps,"prerequisites":recipe.prerequisites,"unverified_prerequisites":recipe.unverified_prerequisites,"limitations":recipe.limitations,"evidence":recipe.evidence,"sources":service.effect_model.as_ref().unwrap().sources}));
    }
    Ok(Value::Object(result))
}

/// Project current target-owned grants and the local ceiling for one issuer
/// principal. This is assessment only; the existing target admission and issuer
/// risk policy remain authoritative. A proposal is assessed in full, separately
/// from what the current local ceiling would permit.
pub fn assess_target(
    target: &Target,
    issuer: &str,
    principal: &Principal,
    proposed: Option<&Grant>,
    history: &[PersistentEffect],
    now: u64,
) -> Result<Value, Error> {
    target.validate()?;
    let trust = target
        .issuers
        .get(issuer)
        .ok_or("unknown assessment issuer")?;
    let snapshot = &trust.authority;
    if snapshot.observed_at > now
        || snapshot.valid_until <= now
        || now - snapshot.observed_at > target.max_authority_age_seconds
    {
        return Err("current target authority snapshot is stale or unavailable".into());
    }
    let effective = |grant: &Grant| -> BTreeMap<String, OperationScope> {
        if !grant.verbs.contains(&Verb::Invoke) || !target.allowed_verbs.contains(&Verb::Invoke) {
            return BTreeMap::new();
        }
        grant
            .operations
            .iter()
            .filter_map(|(id, scope)| {
                let op = target.package.operations.get(id)?;
                let ceiling = target.ceiling.get(id)?;
                if scope.implementation_sha256 != op.implementation_sha256()
                    || ceiling.implementation_sha256 != op.implementation_sha256()
                    || scope.budgets.calls == 0
                    || ceiling.budgets.calls == 0
                    || scope.budgets.concurrent == 0
                    || ceiling.budgets.concurrent == 0
                    || scope.budgets.timeout_seconds == 0
                    || ceiling.budgets.timeout_seconds == 0
                    || scope.budgets.output_bytes == 0
                    || ceiling.budgets.output_bytes == 0
                {
                    return None;
                }
                let resources = scope
                    .resources
                    .intersection(&ceiling.resources)
                    .filter(|r| op.resources.contains(*r))
                    .cloned()
                    .collect::<BTreeSet<_>>();
                if resources.is_empty() {
                    return None;
                }
                let arguments: BTreeMap<_, _> = op
                    .arguments
                    .iter()
                    .map(|(name, _)| {
                        let choices = scope
                            .arguments
                            .get(name)
                            .into_iter()
                            .flatten()
                            .filter(|v| {
                                ceiling
                                    .arguments
                                    .get(name)
                                    .is_some_and(|allowed| allowed.contains(*v))
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        (name.clone(), choices)
                    })
                    .collect();
                if op.arguments.iter().any(|(name, arg)| {
                    (arg.required || arg.default.is_some()) && arguments[name].is_empty()
                }) {
                    return None;
                }
                Some((
                    id.clone(),
                    OperationScope {
                        implementation_sha256: op.implementation_sha256(),
                        resources,
                        arguments,
                        budgets: scope.budgets.clone(),
                    },
                ))
            })
            .collect()
    };
    let mut current: Vec<_> = snapshot
        .grants
        .iter()
        .filter(|(_, grant)| {
            grant.principal == *principal && grant.not_before <= now && now < grant.expires_at
        })
        .map(|(id, grant)| Authority {
            id: format!("{issuer}:{id}"),
            target_id: target.target_id.clone(),
            operations: effective(grant),
            proposed: false,
        })
        .collect();
    let requested = if let Some(grant) = proposed {
        if grant.principal != *principal {
            return Err("proposed grant selects another principal".into());
        }
        let mut requested = current.clone();
        requested.push(Authority {
            id: "proposed".into(),
            target_id: target.target_id.clone(),
            operations: grant.operations.clone(),
            proposed: true,
        });
        current.push(Authority {
            id: "proposed".into(),
            target_id: target.target_id.clone(),
            operations: effective(grant),
            proposed: true,
        });
        Some(assess(&target.package, &requested, history)?)
    } else {
        None
    };
    let effective = assess(&target.package, &current, history)?;
    let current_lifetimes:Vec<_>=snapshot.grants.iter().filter(|(_,grant)|grant.principal==*principal && grant.not_before<=now && now<grant.expires_at).map(|(id,grant)|json!({"grant_id":id,"not_before":grant.not_before,"expires_at":grant.expires_at,"verbs":grant.verbs})).collect();
    Ok(
        json!({"target_id":target.target_id,"issuer_id":issuer,"principal":principal,"current_revisions":target.revisions(issuer)?,"authority_valid_until":snapshot.valid_until,"current_grants":current_lifetimes,"proposed_grant":proposed,"full_proposed_authority":requested,"effective_authority":effective,"input_revision":revision(&(target.revisions(issuer)?,revision(&target.package),&current,proposed,history)),"limitations":["Other issuer identities are not assumed to be this principal. No future operation membership is inferred from an exact-operation grant; the adoption owner must supply the entire approved class ceiling when assessing a future class."]}),
    )
}

/// Static alternatives for the existing route challenge/private-assessment
/// consumers. A route token alone proves no native operation availability.
pub(super) fn route_guidance(package: &Package) -> Result<Value, Error> {
    let service = service(package)?.ok_or("host semantics unavailable")?;
    let alternatives = alternatives(package, &[], &service)?;
    Ok(
        json!({"alternatives":alternatives,"scope":"Native target, resource, argument and lifetime authority is unverified at this route-only boundary."}),
    )
}
