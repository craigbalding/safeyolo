//! Gateway projections validate through the existing service-definition owner.
pub mod semantics;
#[cfg(test)]
mod semantics_tests;
use crate::services::ServiceDefinition;
pub use safeyolo_host_executor::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Projections {
    pub package_sha256: String,
    pub package_version: u64,
    pub target: BTreeMap<String, Operation>,
    pub gateway: BTreeMap<String, Value>,
    pub assessment: Option<Value>,
}

pub trait PackageGateway {
    fn projections(&self) -> Result<Projections, Error>;
    fn verify_projections(&self, projections: &Projections) -> Result<(), Error>;
    fn gateway_projection(&self, id: &str, op: &Operation) -> Value;
}
impl PackageGateway for Package {
    fn projections(&self) -> Result<Projections, Error> {
        self.validate()?;
        for (id, operation) in &self.operations {
            ServiceDefinition::from_value(self.gateway_projection(id, operation))?;
        }
        Ok(Projections {
            package_sha256: revision(self),
            package_version: self.version,
            target: self.operations.clone(),
            assessment: semantics::service(self)?.map(|service| service.raw),
            gateway: self
                .operations
                .iter()
                .map(|(id, op)| (id.clone(), self.gateway_projection(id, op)))
                .collect(),
        })
    }

    fn verify_projections(&self, projections: &Projections) -> Result<(), Error> {
        if revision(&self.projections()?) != revision(projections) {
            return Err(
                "host-execution projections differ from their common source/version".into(),
            );
        }
        Ok(())
    }

    fn gateway_projection(&self, id: &str, op: &Operation) -> Value {
        let mut bindings = Map::new();
        bindings.insert(
            "resource_id".into(),
            json!({"type":"enum","options":op.resources}),
        );
        let mut args = Map::new();
        for (name, arg) in &op.arguments {
            bindings.insert(format!("argument:{name}"), binding(arg));
            args.insert(name.clone(), constraint(arg, &format!("argument:{name}")));
        }
        let string = json!({"type":"string","required":true});
        let invocation = json!({"type":"object","required":true,"object":{"allow":{
            "operation_id":{"type":"string","required":true,"enum":[id]},
            "resource_id":{"type":"string","required":true,"equals_var":"resource_id"},
            "operation_sha256":{"type":"string","required":true,"enum":[self.operation_sha256(id).expect("operation")]},
            "implementation_sha256":{"type":"string","required":true,"enum":[op.implementation_sha256()]},
            "expected_assessment_sha256":{"type":"string","required":true},
            "arguments":{"type":"object","required":true,"object":{"allow":args,"deny_unknown":true}}
        },"deny_unknown":true}});
        let action = json!({"type":"object","required":true,"object":{"allow":{"kind":{"required":true,"enum":["invoke"]},"invocation":invocation},"deny_unknown":true}});
        let request = json!({"type":"object","required":true,"object":{"allow":{
            "version":{"required":true,"enum":[VERSION]},"required_features":{"type":"array","required":true,"items":{"type":"string"}},
            "request_id":string,"target_id":string,"issuer_id":string,"grant_id":string,
            "principal":{"type":"object","required":true},"expires_at":{"type":"integer","required":true},
            "expected":{"type":"object","required":true},"action":action,"untrusted_rationale":{"type":"string","required":true}
        },"deny_unknown":true}});
        let uses:Vec<_>=op.effects.keys().map(|effect|json!({"effect":effect,"resource":"target_resource","when":{"kind":"always"},"evidence":["package"]})).collect();
        let mut named_effects = json!(op.effects);
        for value in named_effects.as_object_mut().expect("effects").values_mut() {
            value["evidence"] = json!(["package"]);
        }
        let mut generated = json!({"schema_version":1,"name":format!("{}:{id}",self.name),"default_host":"",
        "host_execution_source":{"package_sha256":revision(self),"package_version":self.version,"operation_id":id,"implementation_sha256":op.implementation_sha256(),"semantic_revisions":self.operation_revisions(id)},
        "capabilities":{"invoke":{"routes":[{"methods":["POST"],"path":Verb::Invoke.path()}],"contract":{
            "template":format!("host-execution:{}:{id}",self.operation_sha256(id).expect("operation")),"bindings":bindings,"enforcement":{"request_shape":"enforced"},
            "operations":[{"name":"invoke","request":{"method":"POST","path":Verb::Invoke.path(),"query":{"deny_unknown":true},"body":{"allow":{"request":request,"key_id":string,"signature":string},"deny_unknown":true}}}]
        }}},"effect_model":{
            "sources":{"package":{"location":self.source.location,"version":format!("{}:{}:{}",self.source.version,self.version,revision(self))}},
            "resources":{"target_resource":{"description":"Selected target operation resource","identity":["id"]}},
            "effects":named_effects,"operations":{"invoke":{"method":"POST","path":Verb::Invoke.path(),"coverage":"modeled","arguments":{},
                "resources":{"target_resource":{"id":{"kind":"unresolved","reason":"Nested signed resource selector is enforced by the target; the current gateway effect analyser does not prove its identity."}}},
                "effects":uses,"execution_authority":"Authenticated issuer grant intersected with target adoption and local ceiling; native executor dependencies remain explicit.","evidence":["package"],"gaps":op.enforcement.unresolved}},
            "enforcement":{},"rules":{},"alternatives":{},"regressions":[],
            "gaps":["Gateway route membership grants no target invocation. Native effect analysis does not prove nested signed selectors or arbitrary executable behavior."]
        }});
        if self.semantics.is_some() {
            // Native argument/target enforcement is not a flat HTTP binding.
            // Preserve the reviewed inventory, but never infer its identity
            // from an example signed request at this route-only boundary.
            if let Ok(Some(service)) = semantics::service(self) {
                let mut model = service.raw["effect_model"].clone();
                model["operations"][id]["path"] = json!(Verb::Invoke.path());
                for operation in model["operations"].as_object_mut().unwrap().values_mut() {
                    for identity in operation["resources"].as_object_mut().unwrap().values_mut() {
                        for value in identity.as_object_mut().unwrap().values_mut() {
                            if value["kind"] == "argument" {
                                *value = json!({"kind":"unresolved","reason":"This route-only assessment has no verified native target/argument authority. Use the adopted native authority assessment; gateway invocation integration retains its own owner."});
                            }
                        }
                    }
                }
                generated["effect_model"] = model;
                generated["host_operation_guidance"] =
                    semantics::route_guidance(self).expect("validated host guidance");
            }
        }
        generated
    }
}

fn binding(arg: &Argument) -> Value {
    json!({"type":arg.kind,"options":arg.options})
}

fn constraint(arg: &Argument, name: &str) -> Value {
    let kind = match arg.kind {
        ArgumentType::String => "string",
        ArgumentType::Integer => "integer",
        ArgumentType::Boolean => "boolean",
        ArgumentType::StringList => "array",
        ArgumentType::Enum => "",
    };
    let mut constraint = json!({"type":kind,"required":arg.required,"equals_var":name});
    if let Some(default) = &arg.default {
        constraint["default"] = default.clone();
    }
    if matches!(arg.kind, ArgumentType::StringList) {
        constraint["items"] = json!({"type":"string"});
    }
    if matches!(arg.kind, ArgumentType::Enum) {
        constraint["enum"] = json!(arg.options);
    }
    constraint
}

fn catalogue_adoptions(document: &Value) -> Result<BTreeMap<String, CatalogueAdoption>, Error> {
    let Some(values) = document.get("host_catalogues") else {
        return Ok(BTreeMap::new());
    };
    let values = values
        .as_object()
        .ok_or("host_catalogues must be a table of encoded adoption documents")?;
    values
        .iter()
        .map(|(name, value)| {
            let adoption: CatalogueAdoption = serde_json::from_str(
                value
                    .as_str()
                    .ok_or("host catalogue adoption must be a JSON string")?,
            )?;
            if name != &adoption.policy.package_name {
                return Err("host catalogue key must match its adopted package name".into());
            }
            Ok((name.clone(), adoption))
        })
        .collect()
}

/// The native policy transaction owns both the adoption and the generated
/// gateway definitions. No publisher-supplied definition or invocation grant is
/// inserted. Endpoint, credential and agent/task bindings retain their owners.
pub(crate) fn catalogue_registry(
    document: &Value,
    registry: Option<std::sync::Arc<crate::services::Registry>>,
    now: u64,
) -> Result<Option<std::sync::Arc<crate::services::Registry>>, Error> {
    let adoptions = catalogue_adoptions(document)?;
    if adoptions.is_empty()
        && registry.as_ref().is_none_or(|r| {
            !r.source_by_service
                .values()
                .any(|source| source.starts_with("host-catalogue:"))
        })
    {
        return Ok(registry);
    }
    let mut definitions = Vec::new();
    for (name, adoption) in adoptions {
        let plan = gateway_plan(&adoption, now)?;
        let projections = plan.package.projections()?;
        plan.package.verify_projections(&projections)?;
        let services = projections
            .gateway
            .into_values()
            .map(|mut service| {
                service["host_catalogue_status"] = json!(plan.status);
                service
            })
            .collect();
        definitions.push((name, services));
    }
    let next = registry
        .as_deref()
        .cloned()
        .unwrap_or_default()
        .replace_host_catalogues(&definitions)?;
    if let Some(current) = &registry
        && revision(
            &current
                .services
                .iter()
                .map(|(name, s)| (name, &s.raw))
                .collect::<BTreeMap<_, _>>(),
        ) == revision(
            &next
                .services
                .iter()
                .map(|(name, s)| (name, &s.raw))
                .collect::<BTreeMap<_, _>>(),
        )
        && current.source_by_service == next.source_by_service
    {
        return Ok(registry);
    }
    Ok(Some(std::sync::Arc::new(next)))
}

fn gateway_plan(adoption: &CatalogueAdoption, now: u64) -> Result<CataloguePlan, Error> {
    let mut plan = adoption.plan(now)?;
    if plan.status.active != revision(&adoption.active.catalogue.package) {
        plan.package = adoption.active.catalogue.package.clone();
        plan.status.active = revision(&plan.package);
        plan.status.state = "qualified".into();
        plan.status.reason = "The candidate passed contract qualification; the existing policy adoption transaction must save and activate this exact revision before gateway use.".into();
    }
    Ok(plan)
}

pub fn catalogue_statuses(document: &Value, now: u64) -> Result<Value, Error> {
    let statuses = catalogue_adoptions(document)?
        .into_iter()
        .map(|(name, adoption)| Ok((name, gateway_plan(&adoption, now)?.status)))
        .collect::<Result<BTreeMap<_, _>, Error>>()?;
    Ok(json!(statuses))
}

pub(crate) fn catalogues_changed(
    document: &Value,
    registry: Option<&crate::services::Registry>,
    now: u64,
) -> Result<bool, Error> {
    let mut active = BTreeMap::new();
    if let Some(registry) = registry {
        for (service, source) in &registry.source_by_service {
            if let Some(name) = source.strip_prefix("host-catalogue:") {
                active.insert(
                    name.to_owned(),
                    registry.services[service].raw["host_catalogue_status"].clone(),
                );
            }
        }
    }
    Ok(catalogue_statuses(document, now)? != json!(active))
}

/// Automatic updates use the same save/runtime/rollback transaction as policy
/// adoption. Failed or partial activation leaves the prior source and registry.
pub(crate) fn reconcile_catalogues(state: &crate::RuntimeState) -> Result<bool, Error> {
    let (source, path) = {
        let runtime = state
            .read()
            .map_err(|_| "host catalogue runtime unavailable")?;
        let Some(source) = runtime.policy.as_ref().and_then(|p| p.native_source_text()) else {
            return Ok(false);
        };
        (source.to_owned(), runtime.config.policy_file.clone())
    };
    // Let the normal watcher consume an operator edit before automatic
    // adoption uses the old snapshot. The transaction still rechecks this race.
    if let Some(path) = path
        && std::fs::read_to_string(path)? != source
    {
        return Ok(false);
    }
    let parsed = crate::policy::parse_toml_document(&source)?;
    let mut pending = false;
    for mut adoption in catalogue_adoptions(&parsed)?.into_values() {
        let plan = adoption.plan(now())?;
        pending |= adoption.advance(&plan);
    }
    if !pending {
        return Ok(false);
    }
    crate::adopt_native_policy(
        state,
        |saved, runtime, _| {
            let policy = runtime
                .policy
                .as_ref()
                .ok_or_else(|| crate::approvals::invalid("host catalogue policy unavailable"))?;
            if policy.native_source_text() != Some(saved) {
                return Err(crate::approvals::invalid(
                    "saved and active host catalogue authority differ; reload current policy before adopting",
                ));
            }
            let parsed = crate::policy::parse_toml_document(saved)
                .map_err(|e| crate::approvals::invalid(e.to_string()))?;
            let (mut document, context) = crate::policy::parse_toml_for_edit(saved)
                .map_err(|e| crate::approvals::invalid(e.to_string()))?;
            let mut expected = BTreeMap::new();
            for (name, mut adoption) in catalogue_adoptions(&parsed)
                .map_err(|e| crate::approvals::invalid(e.to_string()))?
            {
                let plan = adoption
                    .plan(now())
                    .map_err(|e| crate::approvals::invalid(e.to_string()))?;
                if adoption.advance(&plan) {
                    document["host_catalogues"][&name] = toml_edit::value(
                        serde_json::to_string(&adoption)
                            .map_err(|e| crate::approvals::invalid(e.to_string()))?,
                    );
                    expected.insert(name, revision(&adoption.active.catalogue.package));
                }
            }
            let source =
                crate::policy::restore_large_toml_integers(&document.to_string(), &context);
            let path = runtime
                .config
                .policy_file
                .as_ref()
                .ok_or_else(|| crate::approvals::invalid("native policy path unavailable"))?;
            let compiled = policy
                .reload_native_source(&source, path)
                .map_err(|e| crate::approvals::invalid(e.to_string()))?;
            let registry = compiled
                .gateway()
                .and_then(|g| g.registry())
                .ok_or_else(|| {
                    crate::approvals::invalid("qualified host catalogue registry unavailable")
                })?;
            for (name, expected) in expected {
                let sources = registry
                    .source_by_service
                    .iter()
                    .filter(|(_, source)| **source == format!("host-catalogue:{name}"));
                if sources.clone().next().is_none()
                    || sources.into_iter().any(|(service, _)| {
                        registry.services[service].raw["host_catalogue_status"]["active"]
                            != expected
                    })
                {
                    return Err(crate::approvals::invalid(
                        "catalogue discovery changed during activation; candidate remains uncommitted",
                    ));
                }
            }
            Ok((source, compiled))
        },
        || Ok(()),
    )?;
    Ok(true)
}

/// Refresh only a known-stale preparation, never retry a possibly executed job.
/// The trusted issuer supplies the private key and retains current policy/run
/// checks. The authenticated target's real proposal route rechecks its current
/// grants, ceiling, arguments, required checks and assessment before signing the
/// fresh invocation. This function never sends Invoke.
pub fn refresh_preparation(
    original: &Request,
    stale: &Refusal,
    discovery: &Discovery,
    request_ids: (String, String),
    key_id: &str,
    key: &ring::signature::Ed25519KeyPair,
    mut propose: impl FnMut(SignedRequest) -> Result<Response, Refusal>,
) -> Result<SignedRequest, Refusal> {
    let (proposal_id, invocation_id) = request_ids;
    let invalid = |message: &str| Refusal {
        code: RefusalCode::Stale,
        message: message.into(),
    };
    if stale.code != RefusalCode::Stale
        || original.target_id != discovery.target_id
        || original.request_id == invocation_id
        || proposal_id == invocation_id
    {
        return Err(invalid(
            "refresh requires a known-stale preparation for this target and fresh request IDs; reconcile an uncertain job instead",
        ));
    }
    let mut invocation = match &original.action {
        Action::Propose { invocation } | Action::Invoke { invocation } => invocation.clone(),
        _ => return Err(invalid("only an invocation preparation can be refreshed")),
    };
    let operation = discovery
        .operations
        .iter()
        .find(|op| op.operation_id == invocation.operation_id && op.has_invocation_scope)
        .ok_or_else(|| invalid("operation has no current invocation authority"))?;
    invocation.operation_sha256 = operation.operation_sha256.clone();
    invocation.implementation_sha256 = operation.implementation_sha256.clone();
    invocation.expected_assessment_sha256 = None;
    let mut request = original.clone();
    request.request_id = proposal_id;
    request.expected = Some(operation.revisions.clone());
    request.action = Action::Propose { invocation };
    let prepared = match propose(SignedRequest::sign(request.clone(), key_id.into(), key))? {
        Response::Proposal { prepared } => prepared,
        Response::Refused { refusal } => return Err(refusal),
        _ => {
            return Err(invalid(
                "proposal response did not contain a current preparation",
            ));
        }
    };
    let Action::Propose {
        invocation: proposed,
    } = &request.action
    else {
        unreachable!()
    };
    if prepared.invocation.operation_id != proposed.operation_id
        || prepared.invocation.resource_id != proposed.resource_id
        || prepared.invocation.operation_sha256 != operation.operation_sha256
        || prepared.invocation.implementation_sha256 != operation.implementation_sha256
        || prepared.invocation.arguments != operation.definition.arguments(&proposed.arguments)?
        || prepared.revisions != operation.revisions
        || prepared.valid_until > original.expires_at
        || prepared.valid_until > discovery.authority_valid_until
    {
        return Err(invalid(
            "proposal response differs from the selected target operation, arguments or authority",
        ));
    }
    request.request_id = invocation_id;
    request.expected = Some(prepared.revisions);
    request.action = Action::Invoke {
        invocation: prepared.invocation,
    };
    Ok(SignedRequest::sign(request, key_id.into(), key))
}
