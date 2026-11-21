use super::*;
use crate::{
    Error,
    contracts::ContractTemplate,
    services::{ServiceDefinition, effects},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("x-scope" = "Versioned host-operation definitions and their complete execution scope", "x-lifetime" = "Explicit target adoption of this exact package revision", "x-effects" = "Derive target specifications and native gateway service/effect projections; loading grants no invocation or replacement authority.", "x-dependencies" = "Issuer policy and credentials, target trust/local ceiling and platform executor enforcement", "x-gaps" = "Generation proves correspondence. It does not prove executable behavior or install an executor."))]
pub struct Package {
    pub format: String,
    pub name: String,
    pub version: u64,
    pub source: effects::Source,
    pub operations: BTreeMap<String, Operation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub resources: BTreeSet<String>,
    pub arguments: BTreeMap<String, Argument>,
    pub execution: Execution,
    pub effects: BTreeMap<String, effects::NamedEffect>,
    /// Explicit adopted trust and remaining platform enforcement dependencies.
    pub enforcement: Enforcement,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    pub enforced: Vec<String>,
    pub adopted: Vec<String>,
    pub unresolved: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Argument {
    #[serde(rename = "type")]
    pub kind: ArgumentType,
    pub required: bool,
    pub default: Option<Value>,
    pub options: Vec<Value>,
}

// These are the existing request-contract binding types, not an expression language.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentType {
    String,
    Integer,
    Boolean,
    StringList,
    Enum,
}

impl Argument {
    fn binding(&self) -> Value {
        json!({"type":self.kind,"options":self.options})
    }

    fn accepts(&self, value: &Value) -> bool {
        let contract = ContractTemplate {
            bindings: Map::from_iter([("value".into(), self.binding())]),
            ..Default::default()
        };
        contract.validate_bound_value("value", value)
    }

    fn constraint(&self, name: &str) -> Value {
        let kind = match self.kind {
            ArgumentType::String => "string",
            ArgumentType::Integer => "integer",
            ArgumentType::Boolean => "boolean",
            ArgumentType::StringList => "array",
            ArgumentType::Enum => "",
        };
        let mut constraint = json!({"type":kind,"required":self.required,"equals_var":name});
        if let Some(default) = &self.default {
            constraint["default"] = default.clone();
        }
        if matches!(self.kind, ArgumentType::StringList) {
            constraint["items"] = json!({"type":"string"});
        }
        if matches!(self.kind, ArgumentType::Enum) {
            constraint["enum"] = json!(self.options);
        }
        constraint
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Word {
    Literal { value: String },
    Argument { name: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub executable: String,
    pub executable_sha256: String,
    pub argv: Vec<Word>,
    /// Exact environment. Native executors must not inherit an ambient environment.
    pub environment: BTreeMap<String, Word>,
    pub working_directory: String,
    pub identity: ExecutionIdentity,
    pub filesystem: Filesystem,
    pub network: Network,
    pub resources: ExecutionLimits,
    pub delegated_services: Vec<DelegatedService>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIdentity {
    pub principal: String,
    pub groups: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub destinations: Vec<NetworkDestination>,
    pub ipc: Vec<IpcEndpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkDestination {
    pub host: String,
    pub port: u16,
    pub transport: NetworkTransport,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum IpcEndpoint {
    UnixSocket { path: String },
    NamedPipe { path: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub executable: String,
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_directory: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DelegatedService {
    pub service: String,
    pub capability: String,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub timeout_seconds: u64,
    pub output_bytes: u64,
    pub memory_bytes: u64,
    pub processes: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Projections {
    pub package_sha256: String,
    pub package_version: u64,
    pub target: BTreeMap<String, Operation>,
    pub gateway: BTreeMap<String, Value>,
}

impl Operation {
    pub fn implementation_sha256(&self) -> String {
        revision(self)
    }

    pub fn arguments(
        &self,
        supplied: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>, Refusal> {
        require(
            supplied.keys().all(|key| self.arguments.contains_key(key)),
            RefusalCode::Arguments,
            "unknown argument",
        )?;
        let mut result = supplied.clone();
        for (name, arg) in &self.arguments {
            if !result.contains_key(name)
                && let Some(default) = &arg.default
            {
                result.insert(name.clone(), default.clone());
            }
            require(
                !arg.required || result.contains_key(name),
                RefusalCode::Arguments,
                "required argument is missing",
            )?;
            if let Some(value) = result.get(name) {
                require(
                    arg.accepts(value),
                    RefusalCode::Arguments,
                    "argument type or enum value differs",
                )?;
            }
        }
        Ok(result)
    }

    /// Render native words without a shell. Platform executors must still apply
    /// the rest of Execution and recheck the pinned executable before starting.
    pub fn command(&self, supplied: &BTreeMap<String, Value>) -> Result<Command, Refusal> {
        let arguments = self.arguments(supplied)?;
        let words = |word: &Word| -> Result<Vec<String>, Refusal> {
            let scalar = |v: &Value| {
                v.as_str().map(str::to_owned).or_else(|| {
                    (v.is_boolean() || v.as_i64().is_some() || v.as_u64().is_some())
                        .then(|| v.to_string())
                })
            };
            match word {
                Word::Literal { value } => Ok(vec![value.clone()]),
                Word::Argument { name } => {
                    let value = arguments.get(name).ok_or_else(|| Refusal {
                        code: RefusalCode::Arguments,
                        message: "missing command argument".into(),
                    })?;
                    if let Some(values) = value.as_array() {
                        values
                            .iter()
                            .map(|v| {
                                scalar(v).ok_or_else(|| Refusal {
                                    code: RefusalCode::Arguments,
                                    message: "command list needs scalar words".into(),
                                })
                            })
                            .collect()
                    } else {
                        scalar(value).map(|s| vec![s]).ok_or_else(|| Refusal {
                            code: RefusalCode::Arguments,
                            message: "command argument needs a scalar or scalar list".into(),
                        })
                    }
                }
            }
        };
        let mut argv = Vec::new();
        for word in &self.execution.argv {
            argv.extend(words(word)?);
        }
        let mut environment = BTreeMap::new();
        for (name, word) in &self.execution.environment {
            let values = words(word)?;
            require(
                values.len() == 1,
                RefusalCode::Arguments,
                "environment values need exactly one scalar word",
            )?;
            environment.insert(name.clone(), values[0].clone());
        }
        require(
            !self.execution.executable.contains('\0')
                && !self.execution.working_directory.contains('\0')
                && argv.iter().all(|s| !s.contains('\0'))
                && environment.iter().all(|(key, value)| {
                    !key.is_empty() && !key.contains(['=', '\0']) && !value.contains('\0')
                }),
            RefusalCode::Arguments,
            "native command contains a NUL or invalid environment name",
        )?;
        Ok(Command {
            executable: self.execution.executable.clone(),
            argv,
            environment,
            working_directory: self.execution.working_directory.clone(),
        })
    }
}

impl Package {
    pub fn validate(&self) -> Result<(), Error> {
        if self.format != VERSION
            || !selector(&self.name)
            || self.version == 0
            || self.source.location.is_empty()
            || self.source.version.is_empty()
            || self.operations.is_empty()
        {
            return Err("host-execution package needs the current format, stable name, version, source and operations".into());
        }
        for (id, op) in &self.operations {
            if !selector(id) || op.resources.is_empty() || !op.resources.iter().all(|s| selector(s))
            {
                return Err("operation and resource IDs must be literal selectors".into());
            }
            let e = &op.execution;
            if e.executable.is_empty()
                || !digest(&e.executable_sha256)
                || e.working_directory.is_empty()
                || e.identity.principal.is_empty()
                || e.resources.timeout_seconds == 0
                || e.resources.output_bytes == 0
                || e.resources.memory_bytes == 0
                || e.resources.processes == 0
                || op.enforcement.enforced.is_empty()
                    && op.enforcement.adopted.is_empty()
                    && op.enforcement.unresolved.is_empty()
            {
                return Err("execution requires a pinned executable, explicit scope, positive limits and enforcement disclosure".into());
            }
            if e.network
                .destinations
                .iter()
                .any(|d| d.host.is_empty() || d.port == 0)
            {
                return Err(
                    "network destinations need an explicit host, port and transport".into(),
                );
            }
            for word in e.argv.iter().chain(e.environment.values()) {
                if let Word::Argument { name } = word
                    && (!op.arguments.contains_key(name)
                        || !op.arguments[name].required && op.arguments[name].default.is_none())
                {
                    return Err(
                        "execution argument references need a required argument or a default"
                            .into(),
                    );
                }
            }
            for (name, arg) in &op.arguments {
                if !selector(name)
                    || matches!(arg.kind, ArgumentType::Enum) && arg.options.is_empty()
                    || arg
                        .default
                        .as_ref()
                        .is_some_and(|value| !arg.accepts(value))
                {
                    return Err("invalid typed argument or default".into());
                }
            }
            // Validate native effect references through their existing owner.
            ServiceDefinition::from_value(self.gateway_projection(id, op))?;
        }
        Ok(())
    }

    pub fn projections(&self) -> Result<Projections, Error> {
        self.validate()?;
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

    pub fn verify_projections(&self, projections: &Projections) -> Result<(), Error> {
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
            bindings.insert(format!("argument:{name}"), arg.binding());
            args.insert(name.clone(), arg.constraint(&format!("argument:{name}")));
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
