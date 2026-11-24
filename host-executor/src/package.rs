use super::*;
use crate::{Error, NamedEffect, Source};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("x-scope" = "Versioned host-operation definitions and their complete execution scope", "x-lifetime" = "Explicit target adoption of this exact package revision", "x-effects" = "Derive target specifications and native gateway service/effect projections; loading grants no invocation or replacement authority.", "x-dependencies" = "Issuer policy and credentials, target trust/local ceiling and platform executor enforcement", "x-gaps" = "Generation proves correspondence. It does not prove executable behavior or install an executor."))]
pub struct Package {
    pub format: String,
    pub name: String,
    pub version: u64,
    pub source: Source,
    pub operations: BTreeMap<String, Operation>,
    /// Absent means uncharacterised host semantics, not absence of effects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<HostSemantics>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<HostOperationSemantics>,
    pub resources: BTreeSet<String>,
    pub arguments: BTreeMap<String, Argument>,
    pub execution: Execution,
    pub effects: BTreeMap<String, NamedEffect>,
    /// Explicit adopted trust and remaining platform enforcement dependencies.
    pub enforcement: Enforcement,
    #[serde(default)]
    pub required_checks: BTreeSet<String>,
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
    pub fn accepts(&self, value: &Value) -> bool {
        match self.kind {
            ArgumentType::String => value.is_string(),
            ArgumentType::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            ArgumentType::Boolean => value.is_boolean(),
            ArgumentType::StringList => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            ArgumentType::Enum => self.options.contains(value),
        }
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
    /// Required guarantees remain the default contract. Each explicitly broader
    /// bound is part of the implementation digest and both authority ceilings.
    pub broader: BTreeSet<BroaderBound>,
    pub executable: String,
    pub executable_sha256: String,
    /// Content-pinned configuration, libraries and other runtime inputs. An
    /// empty map makes no claim about ambient host-owned dependencies.
    #[serde(default)]
    pub dependencies: BTreeMap<String, Dependency>,
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
pub struct Dependency {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BroaderBound {
    Memory,
    ExecutorRestart,
    Filesystem,
    Registry,
    NetworkIpc,
    DelegatedServices,
    ProcessVisibility,
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
    pub listeners: Vec<NetworkListener>,
    pub ipc: Vec<IpcEndpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkListener {
    /// The selected local binding, not an assertion of observed reachability.
    pub address: std::net::IpAddr,
    /// Zero selects kernel allocation; it does not reserve or report a port.
    pub port: u16,
    pub transport: NetworkTransport,
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

impl Operation {
    pub fn implementation_sha256(&self) -> String {
        let operation = crate::catalogue::canonical_operation(self);
        // Retain the exact definition pin: the same executable recipe cannot
        // inherit permission after defaults or understood effects change.
        revision(&operation)
    }

    pub fn authority_sha256(&self) -> String {
        let mut operation = crate::catalogue::canonical_operation(self);
        for field in ["effects", "description", "semantics"] {
            operation.as_object_mut().unwrap().remove(field);
        }
        operation["execution"]["executable_sha256"] = Value::Null;
        for dependency in operation["execution"]["dependencies"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            dependency["sha256"] = Value::Null;
        }
        revision(&operation)
    }

    pub fn assessment_sha256(&self) -> String {
        let operation = crate::catalogue::canonical_operation(self);
        revision(&(
            &operation["effects"],
            &operation["enforcement"],
            &self.required_checks,
            &self.semantics,
        ))
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
                    // Enum bindings already accept complete JSON values. Pass
                    // a structured choice as one JSON word, without a shell.
                    if matches!(self.arguments[name].kind, ArgumentType::Enum) && value.is_object()
                    {
                        return Ok(vec![value.to_string()]);
                    }
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
    pub fn operation_sha256(&self, id: &str) -> Result<String, Refusal> {
        let op = self.operations.get(id).ok_or_else(|| Refusal {
            code: RefusalCode::Selector,
            message: "operation is not adopted".into(),
        })?;
        Ok(revision(&(
            &self.format,
            &self.name,
            id,
            crate::catalogue::canonical_operation(op),
            &self.semantics,
        )))
    }

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
            if e.dependencies
                .values()
                .any(|d| !digest(&d.sha256) || d.bytes == 0)
                || op.required_checks.iter().any(|c| !selector(c))
            {
                return Err("dependencies need content digests and finite positive byte ceilings; required checks need literal names".into());
            }
            if e.network
                .destinations
                .iter()
                .any(|d| d.host.is_empty() || d.port == 0)
            {
                return Err(
                    "network destinations need an explicit host, nonzero port and transport".into(),
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
        }
        self.validate_semantics()?;
        Ok(())
    }
}
