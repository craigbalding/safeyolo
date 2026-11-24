//! Shared authored effect vocabulary. These declarations grant no authority.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub description: String,
    pub identity: Vec<String>,
}

pub use crate::NamedEffect;

#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Modeled,
    Uncharacterised,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
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

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Argument {
    pub location: Location,
    pub field: String,
    /// Upstream specification requirement, not an extra SafeYolo request check.
    pub required: bool,
    pub omission: Omission,
    pub evidence: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    Path,
    Query,
    Body,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Omission {
    Invalid,
    Unchanged,
    Default { value: Value },
    Unresolved { reason: String },
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Identity {
    Argument { argument: String },
    Fixed { value: String },
    Unrestricted { reason: String },
    Unresolved { reason: String },
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectUse {
    pub effect: String,
    pub resource: String,
    pub when: Condition,
    pub evidence: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    Always,
    Present { argument: String },
    Equals { argument: String, value: Value },
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    pub capability: String,
    pub operation: String,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub when: RuleExpression,
    pub prerequisites: Vec<String>,
    pub consequence: String,
    pub explanation: String,
    pub evidence: Vec<String>,
    pub gaps: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleExpression {
    AllEffectsSameScope {
        resource: String,
        effects: Vec<String>,
    },
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Alternative {
    pub steps: Vec<RecipeStep>,
    pub prerequisites: Vec<String>,
    pub unverified_prerequisites: Vec<String>,
    pub limitations: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeStep {
    pub operation: String,
    pub enforcement: String,
    pub arguments: Map<String, Value>,
    pub expected_effects: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Regression {
    pub name: String,
    pub grants: Vec<GrantExample>,
    pub expected: Vec<ExpectedGrant>,
    pub rules: BTreeMap<String, Overlap>,
    pub evidence: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantExample {
    pub operation: String,
    /// Absent means route-wide access, with no contract narrowing.
    pub enforcement: Option<String>,
    pub bindings: Map<String, Value>,
    pub observed_arguments: Map<String, Value>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedGrant {
    pub possible_effects: Vec<String>,
    /// Effects attributed to the supplied example arguments, still not execution.
    pub observed_effects: Vec<String>,
    pub excluded_effects: Vec<String>,
    pub scopes: BTreeMap<String, BTreeMap<String, Scope>>,
    pub evidence: Vec<String>,
}

#[derive(schemars::JsonSchema, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    Known {
        value: String,
    },
    /// A finite native grant can authorize several canonical identities.
    Values {
        values: BTreeSet<String>,
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

#[derive(schemars::JsonSchema, Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Overlap {
    Same,
    Disjoint,
    Unresolved,
    Excluded,
}
