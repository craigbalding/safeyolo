//! Gateway projections validate through the existing service-definition owner.
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
            "package_sha256":{"type":"string","required":true,"enum":[revision(self)]},
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
        json!({"schema_version":1,"name":format!("{}:{id}",self.name),"default_host":"",
        "host_execution_source":{"package_sha256":revision(self),"package_version":self.version,"operation_id":id,"implementation_sha256":op.implementation_sha256()},
        "capabilities":{"invoke":{"routes":[{"methods":["POST"],"path":Verb::Invoke.path()}],"contract":{
            "template":format!("host-execution:{}:{id}",revision(self)),"bindings":bindings,"enforcement":{"request_shape":"enforced"},
            "operations":[{"name":"invoke","request":{"method":"POST","path":Verb::Invoke.path(),"query":{"deny_unknown":true},"body":{"allow":{"request":request,"key_id":string,"signature":string},"deny_unknown":true}}}]
        }}},"effect_model":{
            "sources":{"package":{"location":self.source.location,"version":format!("{}:{}:{}",self.source.version,self.version,revision(self))}},
            "resources":{"target_resource":{"description":"Selected target operation resource","identity":["id"]}},
            "effects":named_effects,"operations":{"invoke":{"method":"POST","path":Verb::Invoke.path(),"coverage":"modeled","arguments":{},
                "resources":{"target_resource":{"id":{"kind":"unresolved","reason":"Nested signed resource selector is enforced by the target; the current gateway effect analyser does not prove its identity."}}},
                "effects":uses,"execution_authority":"Authenticated issuer grant intersected with target adoption and local ceiling; native executor dependencies remain explicit.","evidence":["package"],"gaps":op.enforcement.unresolved}},
            "enforcement":{},"rules":{},"alternatives":{},"regressions":[],
            "gaps":["Gateway route membership grants no target invocation. Native effect analysis does not prove nested signed selectors or arbitrary executable behavior."]
        }})
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
