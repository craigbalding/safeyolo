//! Project current native routing authority into the adopted effect model.
//! No upstream requests or submitted payload values are used here.

use serde_json::{Value, json};

use super::{assessment::Permission, *};
use crate::{
    grants::Grant,
    policy::{Decision, Effect, GatewayRequest, Policy, RiskyRouteRequest},
};

pub(crate) fn prepared(policy: &Policy, action: &Value, grants: &[Grant]) -> Result<Value, Error> {
    let snapshot = policy.gateway().ok_or("gateway unavailable")?;
    let registry = snapshot.registry().ok_or("catalogue unavailable")?;
    let service = registry
        .services
        .get(action["service"].as_str().unwrap_or(""))
        .ok_or("service unavailable")?;
    let mut active: Vec<_> = grants
        .iter()
        .filter(|grant| {
            grant.agent == action["agent"]
                && grant.service == service.name
                && !grant.is_expired(time::OffsetDateTime::now_utc())
                && grant.delegated.as_ref().is_none_or(|encoded| {
                    serde_json::from_str::<crate::policy::delegation::IssuedAccess>(encoded)
                        .is_ok_and(|issued| {
                            issued.active(policy) && issued.action["run"] == action["run"]
                        })
                })
        })
        .cloned()
        .collect();
    active.sort_by(|a, b| a.grant_id.cmp(&b.grant_id));
    let mut result = json!({"model":null,"alternatives":[],"unresolved_conditions":[],
        "input_revision":crate::approvals::pending::digest(&json!({
            "policy":policy.approval_revision(action["agent"].as_str().unwrap_or(""),"gateway_route",Some(&service.name)),
            "temporary_grants":active})),
        "limitations":["An absent annotation or matching rule is not proof of safety. This assessment does not verify upstream state or undo persistent effects."]});
    if let Some(endpoint) = &service.docker
        && let Some(access) = service
            .capabilities
            .get(action["capability"].as_str().unwrap_or(""))
            .and_then(|capability| capability.docker_access.as_ref())
    {
        result["docker_authority"] = access.authority(endpoint.execution_boundary);
    }
    let Some(model) = &service.effect_model else {
        result["unresolved_conditions"] = json!([
            "This adopted service has no effect model; operation effects are uncharacterised."
        ]);
        result["risk_policy"] = json!(risk_decision(policy, service, action, &[]));
        return Ok(result);
    };
    let projected = project(policy, service, model, action, &active)?;
    let assessed = model.assess(service, &projected.permissions)?;
    let enables = assessed.enables_for(&projected.candidate_permissions);
    result["risk_policy"] = json!(risk_decision(policy, service, action, &enables));
    result["enables"] = json!(enables);
    result["model"] = json!(assessed);
    result["unresolved_conditions"] = json!(projected.gaps);
    result["alternatives"] = json!(alternatives(
        policy,
        service,
        model,
        action,
        &projected.permissions
    )?);
    Ok(result)
}

pub(crate) fn risk_decision(
    policy: &Policy,
    service: &ServiceDefinition,
    action: &Value,
    enables: &[String],
) -> Decision {
    let method = action["method"].as_str().unwrap_or("");
    let path = action["path"].as_str().unwrap_or("");
    let route = service
        .risky_routes
        .iter()
        .find(|route| route.matches(method, path));
    if route.is_none() && enables.is_empty() {
        return Decision {
            effect: Effect::Allow,
            matched_resource: None,
            budget_remaining: None,
        };
    }
    let mut all_enables = enables.to_vec();
    all_enables.extend(route.into_iter().flat_map(|route| route.enables.clone()));
    all_enables.sort();
    all_enables.dedup();
    let decision = policy.evaluate_risky_route(RiskyRouteRequest {
        service: &service.name,
        agent: action["agent"].as_str().unwrap_or(""),
        account: action["account"].as_str().unwrap_or(""),
        tactics: route.map_or(&[], |route| &route.tactics),
        enables: &all_enables,
        irreversible: route.is_some_and(|route| route.irreversible),
        method,
        path,
    });
    // Unannotated routes previously had no default risk prompt. Adopted effects
    // participate in explicit operator rules without inventing an uncertainty policy.
    if route.is_none() && decision.matched_resource.is_none() {
        Decision {
            effect: Effect::Allow,
            matched_resource: None,
            budget_remaining: None,
        }
    } else {
        decision
    }
}

struct RoutePermissions {
    permissions: Vec<Permission>,
    gaps: Vec<String>,
    candidate_permissions: BTreeSet<String>,
}

fn project(
    policy: &Policy,
    service: &ServiceDefinition,
    model: &EffectModel,
    action: &Value,
    grants: &[Grant],
) -> Result<RoutePermissions, Error> {
    let snapshot = policy.gateway().ok_or("gateway unavailable")?;
    let agent = action["agent"].as_str().unwrap_or("");
    let mut permissions = Vec::new();
    let mut gaps = Vec::new();
    let mut candidate_modeled = false;
    let mut candidate_permissions = BTreeSet::new();
    let candidate_scopes = candidate_scopes(model, action);
    for token in snapshot
        .tokens
        .iter()
        .filter(|token| token.agent == agent && token.service == service.name)
    {
        let Some(capability) = token
            .capability
            .as_str()
            .and_then(|name| service.capabilities.get(name))
        else {
            continue;
        };
        // Derived credentials retain their run-bound authorization at this boundary.
        let current_token = snapshot.canonical["token_map"]
            .as_object()
            .into_iter()
            .flat_map(|tokens| tokens.values())
            .any(|entry| {
                entry["agent"] == agent
                    && entry["service"] == service.name
                    && entry["capability"] == capability.name
                    && entry.get("delegated").is_none_or(|encoded| {
                        encoded.as_str().is_some_and(|encoded| {
                            serde_json::from_str::<crate::policy::delegation::IssuedAccess>(encoded)
                                .is_ok_and(|issued| issued.active(policy))
                        })
                    })
            });
        if !current_token {
            continue;
        }
        let mut bindings: Vec<Option<&crate::contracts::ContractBinding>> = snapshot
            .contracts
            .iter()
            .filter(|binding| {
                binding.agent == agent
                    && binding.service == service.name
                    && binding.capability == capability.name
            })
            .map(Some)
            .collect();
        bindings.extend(
            snapshot
                .delegated_contracts
                .iter()
                .filter(|(binding, issued)| {
                    binding.agent == agent
                        && binding.service == service.name
                        && binding.capability == capability.name
                        && issued.active(policy)
                })
                .map(|(binding, _)| Some(binding)),
        );
        if bindings.is_empty() {
            bindings.push(None);
        }
        if capability.contract.is_none() {
            bindings = vec![None];
        }
        for binding in bindings {
            let routes = super::super::compile_routes(
                service,
                token,
                &binding.into_iter().cloned().collect::<Vec<_>>(),
            );
            let derived = binding.is_some_and(|binding| {
                snapshot
                    .delegated_contracts
                    .iter()
                    .any(|(derived, _)| std::ptr::eq(binding, derived))
            });
            let scoped = derived.then(|| policy.with_gateway_routes(&routes));
            let effective = scoped.as_ref().unwrap_or(policy);
            for (name, operation) in &model.operations {
                let enforced = capability
                    .contract
                    .as_ref()
                    .filter(|contract| contract.is_grantable());
                let contract_operation = enforced.and_then(|contract| {
                    contract.grantable_operations().find(|op| op.name == *name)
                });
                if enforced.is_some() && contract_operation.is_none() {
                    continue;
                }
                let bound_path = if enforced.is_some() {
                    routes
                        .iter()
                        .find(|route| {
                            route.methods.contains(&operation.method)
                                && contract_operation.is_some_and(|op| {
                                    op.resolved_path(&binding.map_or_else(Map::new, |binding| {
                                        binding.bound_values.clone()
                                    }))
                                    .as_deref()
                                        == Some(&route.path)
                                })
                        })
                        .map(|route| route.path.clone())
                } else {
                    None
                };
                if enforced.is_some() && bound_path.is_none() {
                    continue;
                }
                let enforcement = model
                    .enforcement
                    .iter()
                    .find(|(_, mapping)| {
                        mapping.capability == capability.name && mapping.operation == *name
                    })
                    .map(|(name, _)| name.clone());
                let request = GatewayRequest {
                    agent,
                    service: &service.name,
                    capability: &capability.name,
                    method: &operation.method,
                    path: "",
                };
                let (mut patterns, mut unresolved_paths) = effective.gateway_path_patterns(request);
                patterns.extend(policy.risk_path_patterns());
                patterns.extend(service.risky_routes.iter().map(|route| route.path.clone()));
                if derived {
                    let (independent, unresolved) = policy.gateway_path_patterns(request);
                    patterns.extend(independent);
                    unresolved_paths |= unresolved;
                }
                // A known candidate job also partitions the other operations on
                // that declared resource. This can prove overlap through a
                // complex policy selector without interpreting that selector or
                // treating unresolved remainder regions as known authority.
                patterns.extend(
                    candidate_scopes
                        .iter()
                        .map(|scopes| scope_path(operation, scopes)),
                );
                let relevant: Vec<_> = grants
                    .iter()
                    .filter(|grant| {
                        grant.method.eq_ignore_ascii_case(&operation.method)
                            && grant.delegated.as_ref().is_some_and(|encoded| {
                                serde_json::from_str::<crate::policy::delegation::IssuedAccess>(
                                    encoded,
                                )
                                .is_ok_and(|issued| {
                                    issued.action["route_exception"] == true
                                        && issued.action["capability"] == capability.name
                                        && issued.action["binding_id"].as_str()
                                            == binding.map(|binding| binding.binding_id.as_str())
                                        && (issued.action["host"] == action["host"]
                                            && issued.action["port"] == action["port"]
                                            && issued.action["scheme"] == action["scheme"]
                                            && issued.action["credential"] == token.vault_token
                                            && issued.action["account"] == token.account)
                                })
                            })
                    })
                    .collect();
                patterns.extend(relevant.iter().map(|grant| grant.path.clone()));
                let candidate = capability.name == action["capability"]
                    && operation.method == action["method"]
                    && binding.map(|binding| binding.binding_id.as_str())
                        == action["binding_id"].as_str();
                if candidate {
                    patterns.push(action["path"].as_str().unwrap_or("").into());
                }
                let (cells, unknown) = cells(operation, &patterns, bound_path.as_deref());
                let unknown = unknown || unresolved_paths;
                for (path, path_arguments) in cells {
                    let original = policy.evaluate_gateway_request(GatewayRequest {
                        path: &path,
                        ..request
                    });
                    if derived
                        && original.matched_resource.is_some()
                        && original.effect != Effect::Allow
                    {
                        continue;
                    }
                    let decision = effective.evaluate_gateway_request(GatewayRequest {
                        path: &path,
                        ..request
                    });
                    if decision.matched_resource.is_some() && decision.effect != Effect::Allow {
                        continue;
                    }
                    let temporary = relevant.iter().find(|grant| {
                        if grant.literal_path {
                            grant.path == path
                        } else {
                            super::super::resource_matches(&path, &grant.path)
                        }
                    });
                    let is_candidate = candidate && action["path"] == path;
                    if is_candidate {
                        candidate_modeled = true;
                    }
                    if decision.effect != Effect::Allow
                        && temporary.is_none()
                        && !is_candidate
                        && !unknown
                    {
                        continue;
                    }
                    let mut unresolved = Vec::new();
                    if unknown
                        && path_arguments
                            .values()
                            .any(|scope| !matches!(scope, Scope::Known { .. }))
                    {
                        unresolved.push("The effective path policy contains a pattern outside the evaluator's literal/whole-segment/tail-wildcard partition. Authority in this region is unresolved.".into());
                    }
                    if enforced.is_some() && enforcement.is_none() {
                        unresolved.push("This contract operation has no reviewed semantic enforcement mapping; its parameter restrictions cannot be attributed to the effect model.".into());
                    }
                    let source = if decision.effect == Effect::Allow {
                        "baseline"
                    } else if is_candidate {
                        "candidate"
                    } else {
                        temporary.map_or("unresolved", |grant| &grant.grant_id)
                    };
                    let id = format!(
                        "{source}:{}/{}:{name}:{}",
                        capability.name,
                        binding.map_or("", |binding| binding.binding_id.as_str()),
                        crate::approvals::pending::digest(&json!(path_arguments))
                    );
                    let permission = Permission {
                        id,
                        operation: name.clone(),
                        enforcement: enforced.and(enforcement.clone()),
                        bindings: if enforced.is_some() && enforcement.is_some() {
                            binding.map_or_else(Map::new, |binding| binding.bound_values.clone())
                        } else {
                            Map::new()
                        },
                        path_arguments,
                        unresolved,
                        proposed: is_candidate
                            && decision.effect != Effect::Allow
                            && temporary.is_none(),
                    };
                    let mut permission_action = action.clone();
                    permission_action["method"] = json!(operation.method);
                    permission_action["path"] = json!(path);
                    permission_action["account"] = json!(token.account);
                    let direct = model.assess(service, std::slice::from_ref(&permission))?;
                    let risk =
                        risk_decision(policy, service, &permission_action, &direct.enables());
                    // A denied route is not baseline authority. Keep the
                    // candidate so its own prohibited effects remain visible.
                    // An unresolved partition cannot establish a whole-region
                    // denial from its representative alone.
                    if !is_candidate
                        && permission.unresolved.is_empty()
                        && !matches!(risk.effect, Effect::Allow | Effect::Prompt)
                    {
                        continue;
                    }
                    if is_candidate {
                        candidate_permissions.insert(permission.id.clone());
                    }
                    permissions.push(permission);
                }
            }
        }
    }
    if !candidate_modeled {
        gaps.push("The candidate route has no characterised operation in the adopted model or its effective binding. Missing coverage does not establish safety.".into());
    }
    permissions.sort_by(|a, b| a.id.cmp(&b.id));
    permissions.dedup_by(|a, b| a.id == b.id);
    Ok(RoutePermissions {
        permissions,
        gaps,
        candidate_permissions,
    })
}

/// Partition only model path parameters, using literal boundaries from current
/// route policy. Each supported policy pattern is constant within a cell. A
/// representative is passed to the real PDP, never to an upstream service.
type PathCell = (String, BTreeMap<String, Scope>);

fn candidate_scopes(model: &EffectModel, action: &Value) -> Vec<assessment::ResourceScopes> {
    model
        .operations
        .values()
        .filter(|operation| operation.method == action["method"])
        .flat_map(|operation| {
            let (paths, _) = cells(operation, &[], action["path"].as_str());
            paths.into_iter().map(move |(_, arguments)| {
                operation
                    .resources
                    .iter()
                    .map(|(resource, identity)| {
                        let keys = identity
                            .iter()
                            .filter_map(|(key, source)| {
                                let value = match source {
                                    Identity::Fixed { value } => Some(Scope::Known {
                                        value: value.clone(),
                                    }),
                                    Identity::Argument { argument } => {
                                        arguments.get(argument).cloned()
                                    }
                                    _ => None,
                                };
                                value.map(|value| (key.clone(), value))
                            })
                            .collect();
                        (resource.clone(), keys)
                    })
                    .collect()
            })
        })
        .collect()
}

fn scope_path(operation: &Operation, scopes: &assessment::ResourceScopes) -> String {
    operation
        .path
        .split('/')
        .map(|part| {
            if !part.starts_with('{') || !part.ends_with('}') {
                return part.to_owned();
            }
            let field = part.trim_matches(['{', '}']);
            let values: BTreeSet<_> = operation
                .resources
                .iter()
                .flat_map(|(resource, identity)| {
                    identity.iter().filter_map(|(key, source)| {
                        let Identity::Argument { argument } = source else {
                            return None;
                        };
                        let argument = &operation.arguments[argument];
                        if argument.location != Location::Path || argument.field != field {
                            return None;
                        }
                        match scopes.get(resource)?.get(key)? {
                            Scope::Known { value } => Some(value.clone()),
                            _ => None,
                        }
                    })
                })
                .collect();
            if values.len() == 1 {
                values.into_iter().next().unwrap()
            } else {
                "*".into()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn cells(operation: &Operation, patterns: &[String], bound: Option<&str>) -> (Vec<PathCell>, bool) {
    let template: Vec<_> = operation.path.trim_matches('/').split('/').collect();
    let mut values: BTreeMap<usize, BTreeSet<String>> = template
        .iter()
        .enumerate()
        .filter(|(_, part)| part.starts_with('{') && part.ends_with('}'))
        .map(|(i, _)| (i, BTreeSet::new()))
        .collect();
    if let Some(bound) = bound {
        let parts: Vec<_> = bound.trim_matches('/').split('/').collect();
        if parts.len() != template.len()
            || template
                .iter()
                .zip(&parts)
                .any(|(a, b)| !a.starts_with('{') && a != b)
        {
            return (Vec::new(), false);
        }
        let args = values
            .keys()
            .filter_map(|i| {
                let field = template[*i].trim_matches(['{', '}']);
                operation
                    .arguments
                    .iter()
                    .find(|(_, argument)| {
                        argument.location == Location::Path && argument.field == field
                    })
                    .map(|(name, _)| {
                        (
                            name.clone(),
                            Scope::Known {
                                value: parts[*i].into(),
                            },
                        )
                    })
            })
            .collect();
        return (vec![(bound.into(), args)], false);
    }
    let mut unknown = false;
    for pattern in patterns {
        let parts: Vec<_> = pattern.trim_matches('/').split('/').collect();
        if parts
            .iter()
            .any(|part| part.contains(['*', '?', '[']) && !["*", "**"].contains(part))
        {
            let prefix = pattern.split(['*', '?', '[']).next().unwrap_or("");
            let fixed = operation.path.split('{').next().unwrap_or("");
            unknown |= prefix.starts_with(fixed) || fixed.starts_with(prefix);
            continue;
        }
        // Native whole-segment stars can span slashes. Expand those stars over
        // this operation's fixed number of segments before collecting literal
        // boundaries. The ordinary PDP still decides each resulting partition.
        for expanded in expand_pattern(&parts, template.len()) {
            if expanded
                .iter()
                .enumerate()
                .any(|(i, part)| !values.contains_key(&i) && part != "*" && part != template[i])
            {
                continue;
            }
            for (i, part) in expanded.into_iter().enumerate() {
                if let Some(values) = values.get_mut(&i)
                    && part != "*"
                {
                    values.insert(part);
                }
            }
        }
    }
    let mut rows = vec![(
        template
            .iter()
            .map(|part| (*part).to_owned())
            .collect::<Vec<_>>(),
        BTreeMap::new(),
    )];
    for (index, literals) in values {
        let mut other = "safeyolo-other".to_owned();
        while literals.contains(&other) {
            other.push('x');
        }
        let choices: Vec<_> = literals
            .iter()
            .map(|value| {
                (
                    value.clone(),
                    Scope::Known {
                        value: value.clone(),
                    },
                )
            })
            .chain(std::iter::once((
                other,
                if literals.is_empty() {
                    Scope::Unrestricted
                } else {
                    Scope::Except {
                        values: literals.clone(),
                    }
                },
            )))
            .collect();
        let field = template[index].trim_matches(['{', '}']);
        let argument = operation
            .arguments
            .iter()
            .find(|(_, argument)| argument.location == Location::Path && argument.field == field)
            .map(|(name, _)| name);
        rows = rows
            .into_iter()
            .flat_map(|(path, args)| {
                choices.iter().map(move |(value, scope)| {
                    let mut path = path.clone();
                    path[index] = value.clone();
                    let mut args = args.clone();
                    if let Some(argument) = argument {
                        args.insert(argument.clone(), scope.clone());
                    }
                    (path, args)
                })
            })
            .collect();
    }
    (
        rows.into_iter()
            .map(|(parts, args)| (format!("/{}", parts.join("/")), args))
            .collect(),
        unknown,
    )
}

fn expand_pattern(parts: &[&str], width: usize) -> Vec<Vec<String>> {
    let Some((first, rest)) = parts.split_first() else {
        return if width == 0 {
            vec![Vec::new()]
        } else {
            Vec::new()
        };
    };
    if !["*", "**"].contains(first) {
        if width == 0 {
            return Vec::new();
        }
        return expand_pattern(rest, width - 1)
            .into_iter()
            .map(|mut tail| {
                tail.insert(0, (*first).into());
                tail
            })
            .collect();
    }
    let minimum = if *first == "**" && rest.is_empty() {
        0
    } else {
        1
    };
    (minimum..=width)
        .flat_map(|count| {
            expand_pattern(rest, width - count)
                .into_iter()
                .map(move |tail| {
                    std::iter::repeat_n("*".to_owned(), count)
                        .chain(tail)
                        .collect()
                })
        })
        .collect()
}

fn alternatives(
    policy: &Policy,
    service: &ServiceDefinition,
    model: &EffectModel,
    action: &Value,
    baseline: &[Permission],
) -> Result<Value, Error> {
    let mut output = Vec::new();
    for (id, alternative) in &model.alternatives {
        let current: Vec<_> = baseline
            .iter()
            .filter(|permission| !permission.proposed)
            .cloned()
            .collect();
        let mut permissions = current.clone();
        let mut steps = Vec::new();
        let mut actions = Vec::new();
        for (index, step) in alternative.steps.iter().enumerate() {
            let mapping = &model.enforcement[&step.enforcement];
            let operation = model.contract_operation(service, mapping)?;
            let modeled = &model.operations[&step.operation];
            let mut bindings = Map::new();
            for (argument, value) in &step.arguments {
                let argument = &modeled.arguments[argument];
                let constraint = match argument.location {
                    Location::Path => operation.request.path_params.get(&argument.field),
                    Location::Query => operation.request.query.allow.get(&argument.field),
                    Location::Body => operation.request.body.allow.get(&argument.field),
                };
                if let Some(check) = constraint
                    && !check.equals_var.is_empty()
                {
                    bindings.insert(check.equals_var.clone(), value.clone());
                }
            }
            let path = operation.resolved_path(&bindings);
            let binding_conditions = service.capabilities[&mapping.capability]
                .contract
                .as_ref()
                .unwrap()
                .binding_errors(&bindings, std::slice::from_ref(&step.operation));
            // A recipe can leave an optional semantic argument's contract
            // binding unspecified. Report that prerequisite and assess the
            // full possible access, rather than failing the whole challenge or
            // claiming that an uninstantiated constraint excludes an effect.
            let ready = binding_conditions.is_empty();
            let path_arguments = path
                .as_deref()
                .and_then(|path| cells(modeled, &[], Some(path)).0.into_iter().next())
                .map_or_else(BTreeMap::new, |(_, arguments)| arguments);
            let permission = Permission {
                id: format!("alternative:{id}:{index}"),
                operation: step.operation.clone(),
                enforcement: ready.then(|| step.enforcement.clone()),
                bindings: if ready { bindings.clone() } else { Map::new() },
                path_arguments,
                unresolved: Vec::new(),
                proposed: true,
            };
            let required = model.assess(service, std::slice::from_ref(&permission))?;
            let decision = path.as_deref().map(|path| {
                policy.evaluate_gateway_request(GatewayRequest {
                    agent: action["agent"].as_str().unwrap_or(""),
                    service: &service.name,
                    capability: &mapping.capability,
                    method: &modeled.method,
                    path,
                })
            });
            let denied = decision.as_ref().is_some_and(|decision| {
                decision.matched_resource.is_some() && decision.effect != Effect::Allow
            });
            let available = current
                .iter()
                .filter(|have| have.operation == step.operation && have.unresolved.is_empty())
                .any(|have| {
                    model
                        .assess(service, std::slice::from_ref(have))
                        .is_ok_and(|have| {
                            scope_contains(&have.direct[0].scopes, &required.direct[0].scopes)
                                && required.direct[0]
                                    .effects
                                    .iter()
                                    .filter(|effect| effect.status == assessment::Match::Match)
                                    .all(|effect| {
                                        have.direct[0].effects.iter().any(|available| {
                                            available.effect == effect.effect
                                                && available.resource == effect.resource
                                                && available.status == assessment::Match::Match
                                        })
                                    })
                        })
                });
            steps.push(json!({"operation":step.operation,"capability":mapping.capability,"enforcement":step.enforcement,"method":modeled.method,"path":path,
                "required_bindings":bindings,"unverified_binding_conditions":binding_conditions,
                "access":if denied { "denied" } else if available { "available" } else { "requires_access" },"modeled_effects":required}));
            let mut step_action = action.clone();
            step_action["method"] = json!(modeled.method);
            step_action["path"] = json!(path);
            actions.push(step_action);
            permissions.push(permission);
        }
        let assessment = model.assess(service, &permissions)?;
        let decisions: Vec<_> = actions
            .iter()
            .enumerate()
            .map(|(index, action)| {
                let enables = assessment.enables_for(&[format!("alternative:{id}:{index}")].into());
                risk_decision(policy, service, action, &enables)
            })
            .collect();
        for (step, decision) in steps.iter_mut().zip(&decisions) {
            if !matches!(decision.effect, Effect::Allow | Effect::Prompt) {
                step["access"] = json!("denied");
            }
        }
        output.push(json!({"id":id,"required_access":steps,"assessment":assessment,"risk_policy":decisions,
            "prerequisites":alternative.prerequisites,"unverified_prerequisites":alternative.unverified_prerequisites,
            "goal_suitability":"Unverified. Permission availability does not establish that this recipe meets the operator's goal.",
            "limitations":alternative.limitations,"evidence":alternative.evidence}));
    }
    Ok(json!(output))
}

fn scope_contains(have: &assessment::ResourceScopes, need: &assessment::ResourceScopes) -> bool {
    need.iter().all(|(resource, keys)| {
        keys.iter().all(|(key, need)| {
            have.get(resource)
                .and_then(|keys| keys.get(key))
                .is_some_and(|have| assessment::intersect(have, need).as_ref() == Some(need))
        })
    })
}
