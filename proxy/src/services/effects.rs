//! Authored possible effects. Loading validates references and enforcement;
//! assessment evaluates potential authority without asserting upstream state.

pub mod assessment;
pub(crate) mod authority;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::ServiceDefinition;
use crate::{Error, contracts::ContractOperation};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectModel {
    pub sources: BTreeMap<String, Source>,
    pub resources: BTreeMap<String, Resource>,
    pub effects: BTreeMap<String, NamedEffect>,
    pub operations: BTreeMap<String, Operation>,
    pub enforcement: BTreeMap<String, Enforcement>,
    pub rules: BTreeMap<String, Rule>,
    pub alternatives: BTreeMap<String, Alternative>,
    pub regressions: Vec<Regression>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub location: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub description: String,
    pub identity: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NamedEffect {
    pub description: String,
    pub persists_after_access: bool,
    pub evidence: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Modeled,
    Uncharacterised,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub method: String,
    pub path: String,
    pub coverage: Coverage,
    pub arguments: BTreeMap<String, Argument>,
    pub resources: BTreeMap<String, BTreeMap<String, Identity>>,
    pub effects: Vec<EffectUse>,
    pub execution_authority: String,
    pub evidence: Vec<String>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Argument {
    pub location: Location,
    pub field: String,
    /// Upstream specification requirement, not an extra SafeYolo request check.
    pub required: bool,
    pub omission: Omission,
    pub evidence: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    Path,
    Query,
    Body,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Omission {
    Invalid,
    Unchanged,
    Default { value: Value },
    Unresolved { reason: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Argument { argument: String },
    Fixed { value: String },
    Unrestricted { reason: String },
    Unresolved { reason: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectUse {
    pub effect: String,
    pub resource: String,
    pub when: Condition,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Always,
    Present { argument: String },
    Equals { argument: String, value: Value },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    pub capability: String,
    pub operation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub when: RuleExpression,
    pub prerequisites: Vec<String>,
    pub consequence: String,
    pub explanation: String,
    pub evidence: Vec<String>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleExpression {
    AllEffectsSameScope {
        resource: String,
        effects: Vec<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Alternative {
    pub steps: Vec<RecipeStep>,
    pub prerequisites: Vec<String>,
    pub unverified_prerequisites: Vec<String>,
    pub limitations: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeStep {
    pub operation: String,
    pub enforcement: String,
    pub arguments: Map<String, Value>,
    pub expected_effects: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Regression {
    pub name: String,
    pub grants: Vec<GrantExample>,
    pub expected: Vec<ExpectedGrant>,
    pub rules: BTreeMap<String, Overlap>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantExample {
    pub operation: String,
    /// Absent means route-wide access, with no contract narrowing.
    pub enforcement: Option<String>,
    pub bindings: Map<String, Value>,
    pub observed_arguments: Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedGrant {
    pub possible_effects: Vec<String>,
    /// Effects attributed to the supplied example arguments, still not execution.
    pub observed_effects: Vec<String>,
    pub excluded_effects: Vec<String>,
    pub scopes: BTreeMap<String, BTreeMap<String, Scope>>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    Known {
        value: String,
    },
    Unrestricted,
    /// A policy partition containing every value except these literal values.
    Except {
        values: BTreeSet<String>,
    },
    Unresolved {
        reason: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Overlap {
    Same,
    Disjoint,
    Unresolved,
    Excluded,
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}

fn reference<'a, T>(map: &'a BTreeMap<String, T>, name: &str, kind: &str) -> Result<&'a T, Error> {
    map.get(name)
        .ok_or_else(|| format!("Unknown {kind}: {name}").into())
}

impl EffectModel {
    fn evidence(&self, refs: &[String]) -> Result<(), Error> {
        require(!refs.is_empty(), "Effect model claim needs evidence")?;
        for name in refs {
            reference(&self.sources, name, "evidence source")?;
        }
        Ok(())
    }

    pub fn validate(&self, service: &ServiceDefinition) -> Result<(), Error> {
        for source in self.sources.values() {
            require(
                !source.location.is_empty() && !source.version.is_empty(),
                "Source needs location and version",
            )?;
        }
        for resource in self.resources.values() {
            require(
                !resource.identity.is_empty()
                    && resource.identity.iter().all(|key| !key.is_empty())
                    && resource.identity.iter().collect::<BTreeSet<_>>().len()
                        == resource.identity.len(),
                "Resource needs distinct identity keys",
            )?;
        }
        for effect in self.effects.values() {
            self.evidence(&effect.evidence)?;
        }
        let mut routes = BTreeSet::new();
        for (name, operation) in &self.operations {
            require(
                !name.is_empty()
                    && [
                        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
                    ]
                    .contains(&operation.method.as_str())
                    && operation.path.starts_with('/')
                    && routes.insert((&operation.method, &operation.path)),
                "Effect operation needs a unique method/path and stable reference",
            )?;
            self.validate_operation(operation)?;
        }
        for mapping in self.enforcement.values() {
            self.contract_operation(service, mapping)?;
        }
        for rule in self.rules.values() {
            let RuleExpression::AllEffectsSameScope { resource, effects } = &rule.when;
            reference(&self.resources, resource, "rule resource")?;
            require(
                effects.len() >= 2
                    && effects.iter().collect::<BTreeSet<_>>().len() == effects.len(),
                "Rule needs distinct effects",
            )?;
            for effect in effects {
                reference(&self.effects, effect, "rule effect")?;
                require(
                    self.operations.values().any(|op| {
                        op.effects
                            .iter()
                            .any(|item| &item.effect == effect && &item.resource == resource)
                    }),
                    "Rule effect has no operation on its resource",
                )?;
            }
            require(
                !rule.consequence.is_empty() && !rule.explanation.is_empty(),
                "Rule needs consequence and explanation",
            )?;
            self.evidence(&rule.evidence)?;
        }
        for alternative in self.alternatives.values() {
            require(
                !alternative.steps.is_empty() && !alternative.limitations.is_empty(),
                "Alternative needs steps and limitations",
            )?;
            self.evidence(&alternative.evidence)?;
            for step in &alternative.steps {
                let operation = reference(&self.operations, &step.operation, "recipe operation")?;
                let mapping =
                    reference(&self.enforcement, &step.enforcement, "recipe enforcement")?;
                require(
                    mapping.operation == step.operation,
                    "Recipe access refers to another operation",
                )?;
                self.arguments(operation, &step.arguments)?;
                require(
                    operation
                        .arguments
                        .iter()
                        .all(|(name, arg)| !arg.required || step.arguments.contains_key(name)),
                    "Recipe is missing a required argument",
                )?;
                self.operation_effects(operation, &step.expected_effects)?;
            }
        }
        let mut names = BTreeSet::new();
        for regression in &self.regressions {
            require(
                names.insert(&regression.name)
                    && !regression.name.is_empty()
                    && !regression.grants.is_empty()
                    && regression.grants.len() == regression.expected.len(),
                "Regression needs a unique name and an expectation per grant",
            )?;
            self.evidence(&regression.evidence)?;
            for name in regression.rules.keys() {
                reference(&self.rules, name, "regression rule")?;
            }
            for (grant, expected) in regression.grants.iter().zip(&regression.expected) {
                let operation =
                    reference(&self.operations, &grant.operation, "regression operation")?;
                self.arguments(operation, &grant.observed_arguments)?;
                for effects in [
                    &expected.possible_effects,
                    &expected.observed_effects,
                    &expected.excluded_effects,
                ] {
                    self.operation_effects(operation, effects)?;
                }
                require(
                    !expected
                        .possible_effects
                        .iter()
                        .any(|effect| expected.excluded_effects.contains(effect)),
                    "Effect cannot be both possible and excluded",
                )?;
                require(
                    expected.scopes == self.grant_scopes(service, grant)?,
                    "Expected scope is not supported by the identity and enforcement mapping",
                )?;
                self.evidence(&expected.evidence)?;
            }
        }
        Ok(())
    }

    fn validate_operation(&self, operation: &Operation) -> Result<(), Error> {
        self.evidence(&operation.evidence)?;
        require(
            !operation.execution_authority.is_empty(),
            "Operation needs execution authority or an explicit unresolved description",
        )?;
        if operation.coverage == Coverage::Uncharacterised {
            require(
                !operation.gaps.is_empty() && operation.effects.is_empty(),
                "Uncharacterised operation needs a gap and cannot claim effects",
            )?;
        }
        for (name, argument) in &operation.arguments {
            require(
                !name.is_empty() && !argument.field.is_empty(),
                "Argument needs a reference and field",
            )?;
            if argument.location == Location::Path {
                require(
                    operation.path.contains(&format!("{{{}}}", argument.field)),
                    "Path argument is absent from the operation path",
                )?;
            }
            self.evidence(&argument.evidence)?;
        }
        for (name, identity) in &operation.resources {
            let resource = reference(&self.resources, name, "operation resource")?;
            require(
                identity.keys().collect::<BTreeSet<_>>() == resource.identity.iter().collect(),
                "Operation must map every resource identity key",
            )?;
            for value in identity.values() {
                if let Identity::Argument { argument } = value {
                    reference(&operation.arguments, argument, "identity argument")?;
                }
            }
        }
        for effect in &operation.effects {
            reference(&self.effects, &effect.effect, "operation effect")?;
            reference(&operation.resources, &effect.resource, "effect resource")?;
            match &effect.when {
                Condition::Always => (),
                Condition::Present { argument } | Condition::Equals { argument, .. } => {
                    reference(&operation.arguments, argument, "condition argument")?;
                }
            }
            self.evidence(&effect.evidence)?;
        }
        Ok(())
    }

    fn arguments(
        &self,
        operation: &Operation,
        arguments: &Map<String, Value>,
    ) -> Result<(), Error> {
        for name in arguments.keys() {
            reference(&operation.arguments, name, "argument")?;
        }
        Ok(())
    }

    fn operation_effects(&self, operation: &Operation, names: &[String]) -> Result<(), Error> {
        for name in names {
            require(
                operation
                    .effects
                    .iter()
                    .any(|effect| &effect.effect == name),
                format!("Effect {name} is absent from operation"),
            )?;
        }
        Ok(())
    }

    fn contract_operation<'a>(
        &self,
        service: &'a ServiceDefinition,
        mapping: &Enforcement,
    ) -> Result<&'a ContractOperation, Error> {
        let modeled = reference(
            &self.operations,
            &mapping.operation,
            "enforcement operation",
        )?;
        let capability = reference(
            &service.capabilities,
            &mapping.capability,
            "enforcement capability",
        )?;
        let contract = capability
            .contract
            .as_ref()
            .ok_or("Enforcement mapping needs a request contract")?;
        let matches: Vec<_> = contract
            .grantable_operations()
            .filter(|operation| operation.name == mapping.operation)
            .collect();
        require(
            matches.len() == 1,
            "Enforcement mapping needs one supported contract operation",
        )?;
        let operation = matches[0];
        require(
            operation.request.method == modeled.method && operation.request.path == modeled.path,
            "Enforcement method/path differs from modeled operation",
        )?;
        // The executor considers every grantable operation, including names
        // absent from the approved selection. Check overlapping paths through
        // that dispatcher before attributing its checks to the named operation.
        for other in contract.grantable_operations().filter(|other| {
            other
                .request
                .method
                .eq_ignore_ascii_case(&operation.request.method)
        }) {
            if let Some(path) =
                overlapping_request_path(&operation.request.path, &other.request.path)
            {
                let selected = contract
                    .match_operation(&operation.request.method, &super::normalize_path(&path));
                require(
                    selected.is_some_and(|selected| std::ptr::eq(selected, operation)),
                    format!(
                        "Unsupported enforcement mapping {}/{}: request path {path} selects {} instead of the mapped operation",
                        mapping.capability,
                        mapping.operation,
                        selected.map_or("no operation", |selected| selected.name.as_str())
                    ),
                )?;
            }
        }
        require(
            operation.requires_enforcement.is_empty()
                || ["request_shape", "transport_hygiene"]
                    .contains(&operation.requires_enforcement.as_str()),
            "Effect mapping cannot claim state or response enforcement",
        )?;
        let raw = service.raw["capabilities"][&mapping.capability]["contract"]["operations"]
            .as_array()
            .ok_or("Missing contract operations")?;
        let matching: Vec<_> = raw
            .iter()
            .filter(|value| value["name"].as_str() == Some(&mapping.operation))
            .collect();
        require(matching.len() == 1, "Ambiguous enforcement operation")?;
        validate_request_checks(&matching[0]["request"])?;
        for constraint in operation
            .request
            .path_params
            .values()
            .chain(operation.request.query.allow.values())
            .chain(operation.request.body.allow.values())
        {
            if !constraint.equals_var.is_empty() {
                require(
                    contract.bindings.contains_key(&constraint.equals_var),
                    "Enforced constraint refers to an unknown binding",
                )?;
            }
        }
        for field in operation.request.path_params.keys() {
            require(
                operation.request.path.contains(&format!("{{{field}}}")),
                "Enforced path constraint has no matching path parameter",
            )?;
        }
        require(
            ["POST", "PUT", "PATCH"].contains(&operation.request.method.as_str())
                || operation.request.body.allow.is_empty(),
            "Body field constraints are not enforced for this method",
        )?;
        Ok(operation)
    }

    /// Check authoring examples against current path bindings. Sample arguments
    /// never narrow a future grant. This is not a consequence-rule evaluator.
    pub fn grant_scopes(
        &self,
        service: &ServiceDefinition,
        grant: &GrantExample,
    ) -> Result<BTreeMap<String, BTreeMap<String, Scope>>, Error> {
        let modeled = reference(&self.operations, &grant.operation, "grant operation")?;
        let operation = if let Some(name) = &grant.enforcement {
            let mapping = reference(&self.enforcement, name, "grant enforcement")?;
            require(
                mapping.operation == grant.operation,
                "Grant enforcement refers to another operation",
            )?;
            let operation = self.contract_operation(service, mapping)?;
            let contract = service.capabilities[&mapping.capability]
                .contract
                .as_ref()
                .unwrap();
            let errors =
                contract.binding_errors(&grant.bindings, std::slice::from_ref(&grant.operation));
            require(
                errors.is_empty(),
                format!("Invalid example binding: {}", errors.join("; ")),
            )?;
            require(
                operation.resolved_path(&grant.bindings).is_some(),
                "Example bindings cannot resolve the enforced path",
            )?;
            Some(operation)
        } else {
            require(
                grant.bindings.is_empty(),
                "Route-wide example cannot claim contract bindings",
            )?;
            None
        };
        let mut scopes = BTreeMap::new();
        for (resource, identity) in &modeled.resources {
            let mut scope = BTreeMap::new();
            for (key, source) in identity {
                let value = match source {
                    Identity::Fixed { value } => Scope::Known {
                        value: value.clone(),
                    },
                    Identity::Unrestricted { .. } => Scope::Unrestricted,
                    Identity::Unresolved { reason } => Scope::Unresolved {
                        reason: reason.clone(),
                    },
                    Identity::Argument { argument } => {
                        let argument = &modeled.arguments[argument];
                        // Query/body equals_var checks supplied fields only. They
                        // do not require presence, so cannot alone prove identity.
                        operation
                            .filter(|_| argument.location == Location::Path)
                            .and_then(|op| op.request.path_params.get(&argument.field))
                            .and_then(|check| grant.bindings.get(&check.equals_var))
                            .and_then(crate::contracts::safe_path_component)
                            .map(|value| Scope::Known { value })
                            .unwrap_or(Scope::Unrestricted)
                    }
                };
                scope.insert(key.clone(), value);
            }
            scopes.insert(resource.clone(), scope);
        }
        Ok(scopes)
    }
}

/// Find a common request path for the executor's segment templates. A native
/// `*` or `**` matches the remaining path, including an empty remainder. Native
/// specificity is constant for each matching template, so one common path per
/// pair suffices to check which operation wins; the dispatcher decides priority.
fn overlapping_request_path(left: &str, right: &str) -> Option<String> {
    let left: Vec<_> = left.split('/').filter(|part| !part.is_empty()).collect();
    let right: Vec<_> = right.split('/').filter(|part| !part.is_empty()).collect();
    let parameter = |part: &str| part.starts_with('{') && part.ends_with('}');
    let wildcard = |part: &str| ["*", "**"].contains(&part);
    let concrete = |part: &str| {
        if parameter(part) {
            "scope".into()
        } else {
            part.to_owned()
        }
    };
    let mut path: Vec<String> = Vec::new();
    for index in 0..left.len().max(right.len()) {
        let (a, b) = (left.get(index), right.get(index));
        let tail = if a.is_some_and(|part| wildcard(part)) {
            Some(&right[index..])
        } else if b.is_some_and(|part| wildcard(part)) {
            Some(&left[index..])
        } else {
            None
        };
        if let Some(tail) = tail {
            path.extend(
                tail.iter()
                    .take_while(|part| !wildcard(part))
                    .map(|part| concrete(part)),
            );
            break;
        }
        match (a, b) {
            (Some(a), Some(b)) if a == b || parameter(a) || parameter(b) => {
                path.push(concrete(if parameter(a) { b } else { a }));
            }
            _ => return None,
        }
    }
    Some(format!("/{}", path.join("/")))
}

fn keys(value: &Value, allowed: &[&str]) -> Result<(), Error> {
    let object = value
        .as_object()
        .ok_or("Enforced request constraint must be a mapping")?;
    for key in object.keys() {
        require(
            allowed.contains(&key.as_str()),
            format!("Unsupported effect-model enforcement field: {key}"),
        )?;
    }
    Ok(())
}

/// The existing contract parser retains some declarations it cannot enforce.
/// A semantic enforcement reference must use only the implemented subset.
fn validate_request_checks(request: &Value) -> Result<(), Error> {
    keys(
        request,
        &[
            "method",
            "path",
            "transport",
            "query",
            "body",
            "path_params",
        ],
    )?;
    if let Some(transport) = request.get("transport") {
        keys(
            transport,
            &[
                "require_no_body",
                "allow_headers",
                "deny_ambiguous_encoding",
            ],
        )?;
    }
    if let Some(params) = request.get("path_params") {
        for constraint in params
            .as_object()
            .ok_or("path_params must be a mapping")?
            .values()
        {
            keys(constraint, &["equals_var"])?;
        }
    }
    for location in ["query", "body"] {
        if let Some(constraints) = request.get(location) {
            keys(constraints, &["allow", "deny_unknown"])?;
            if let Some(allow) = constraints.get("allow") {
                for constraint in allow.as_object().ok_or("allow must be a mapping")?.values() {
                    keys(
                        constraint,
                        if location == "query" {
                            &["equals_var", "integer_range"]
                        } else {
                            &["equals_var"]
                        },
                    )?;
                    if let Some(range) = constraint.get("integer_range") {
                        require(
                            range.as_array().is_some_and(|values| {
                                values.len() == 2
                                    && values[0]
                                        .as_i64()
                                        .zip(values[1].as_i64())
                                        .is_some_and(|(min, max)| min <= max)
                            }),
                            "Enforced integer_range needs ordered integer bounds",
                        )?;
                        require(
                            constraint.get("equals_var").is_none(),
                            "equals_var takes precedence over integer_range; do not claim both",
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}
