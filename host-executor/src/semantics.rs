//! Prepared host understanding stays with the operation package. The service
//! effect evaluator consumes this vocabulary; it does not authorize execution.
use crate::{
    Error, Operation, Package, Source,
    effects::{Alternative, Condition, EffectUse, Resource, Rule, RuleExpression},
    revision,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostSemantics {
    pub sources: BTreeMap<String, Source>,
    pub resources: BTreeMap<String, Resource>,
    pub rules: BTreeMap<String, Rule>,
    pub alternatives: BTreeMap<String, Alternative>,
    pub gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostOperationSemantics {
    pub resources: BTreeMap<String, BTreeMap<String, HostIdentity>>,
    pub effects: Vec<EffectUse>,
    pub prerequisites: Vec<String>,
    pub limitations: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostIdentity {
    Target,
    Resource {
        aliases: BTreeMap<String, String>,
    },
    ExecutionPrincipal,
    Argument {
        argument: String,
        aliases: BTreeMap<String, String>,
    },
    Fixed {
        value: String,
    },
    Unresolved {
        reason: String,
    },
}

/// These revisions describe different kinds of change. The existing exact
/// operation pin still binds the entire definition for admission.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostOperationRevisions {
    pub implementation: String,
    pub authority: String,
    pub understanding: String,
    pub description: String,
}

impl Operation {
    pub fn semantic_revisions(&self) -> HostOperationRevisions {
        HostOperationRevisions {
            implementation: revision(&crate::catalogue::canonical_operation(self)["execution"]),
            authority: self.authority_sha256(),
            understanding: self.assessment_sha256(),
            description: revision(&self.description),
        }
    }
}

impl Package {
    pub fn operation_revisions(&self, id: &str) -> Option<HostOperationRevisions> {
        let mut revisions = self.operations.get(id)?.semantic_revisions();
        revisions.understanding = revision(&(&revisions.understanding, &self.semantics));
        Some(revisions)
    }

    pub(crate) fn validate_semantics(&self) -> Result<(), Error> {
        let Some(model) = &self.semantics else {
            if self.operations.values().any(|op| op.semantics.is_some()) {
                return Err("host operation annotations need package semantics".into());
            }
            return Ok(());
        };
        let evidence = |refs: &[String]| -> Result<(), Error> {
            if refs.is_empty()
                || refs
                    .iter()
                    .any(|name| name != "package" && !model.sources.contains_key(name))
            {
                return Err("host semantic claim needs known evidence sources".into());
            }
            Ok(())
        };
        if model
            .sources
            .values()
            .any(|source| source.location.is_empty() || source.version.is_empty())
        {
            return Err("host semantic source needs a location and version".into());
        }
        if model.resources.values().any(|resource| {
            resource.identity.is_empty()
                || resource.identity.iter().any(String::is_empty)
                || resource
                    .identity
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != resource.identity.len()
        }) {
            return Err("host resource needs distinct nonempty identity keys".into());
        }
        let mut named_effects = BTreeMap::new();
        for op in self.operations.values() {
            for (name, effect) in &op.effects {
                evidence(&effect.evidence)?;
                if named_effects
                    .insert(name, effect)
                    .is_some_and(|prior| revision(prior) != revision(effect))
                {
                    return Err("conflicting host effect definitions".into());
                }
            }
            let Some(notes) = &op.semantics else { continue };
            if notes.evidence.is_empty() || notes.limitations.is_empty() {
                return Err("host semantics need evidence and limitations".into());
            }
            evidence(&notes.evidence)?;
            for (name, identity) in &notes.resources {
                let resource = model.resources.get(name).ok_or("unknown host resource")?;
                if identity.keys().collect::<std::collections::BTreeSet<_>>()
                    != resource.identity.iter().collect()
                {
                    return Err("host semantics must map every resource identity key".into());
                }
                for source in identity.values() {
                    if let HostIdentity::Argument { argument, aliases } = source {
                        if !op.arguments.contains_key(argument) {
                            return Err("host identity refers to an unknown argument".into());
                        }
                        if alias_chain(aliases) {
                            return Err(
                                "host aliases must map directly to canonical identities".into()
                            );
                        }
                    }
                    if let HostIdentity::Resource { aliases } = source {
                        if alias_chain(aliases) {
                            return Err(
                                "host aliases must map directly to canonical identities".into()
                            );
                        }
                    }
                }
            }
            for effect in &notes.effects {
                evidence(&effect.evidence)?;
                if !op.effects.contains_key(&effect.effect)
                    || !notes.resources.contains_key(&effect.resource)
                {
                    return Err("host effect refers to an unknown effect or resource".into());
                }
                if let Condition::Present { argument } | Condition::Equals { argument, .. } =
                    &effect.when
                {
                    if !op.arguments.contains_key(argument) {
                        return Err("host effect condition refers to an unknown argument".into());
                    }
                }
            }
            if op
                .effects
                .keys()
                .any(|name| !notes.effects.iter().any(|effect| &effect.effect == name))
            {
                return Err("host effect annotation must account for every declared effect".into());
            }
        }
        for rule in model.rules.values() {
            evidence(&rule.evidence)?;
            if rule.consequence.is_empty() || rule.explanation.is_empty() {
                return Err("host composition rule needs a consequence and explanation".into());
            }
            let RuleExpression::AllEffectsSameScope { resource, effects } = &rule.when;
            if !model.resources.contains_key(resource)
                || effects.len() < 2
                || effects
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != effects.len()
                || effects.iter().any(|effect| {
                    !self.operations.values().any(|op| {
                        op.semantics.as_ref().is_some_and(|notes| {
                            notes
                                .effects
                                .iter()
                                .any(|e| &e.effect == effect && &e.resource == resource)
                        })
                    })
                })
            {
                return Err("host composition rule needs distinct represented effects on one known resource".into());
            }
        }
        for recipe in model.alternatives.values() {
            evidence(&recipe.evidence)?;
            if recipe.steps.is_empty() || recipe.limitations.is_empty() {
                return Err("host alternative needs steps and limitations".into());
            }
            for step in &recipe.steps {
                let op = self
                    .operations
                    .get(&step.operation)
                    .ok_or("unknown host alternative operation")?;
                if step.enforcement != step.operation
                    || step
                        .expected_effects
                        .iter()
                        .any(|effect| !op.effects.contains_key(effect))
                {
                    return Err(
                        "host alternative needs the same native operation and known effects".into(),
                    );
                }
                let supplied = step
                    .arguments
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                op.arguments(&supplied)?;
            }
        }
        Ok(())
    }
}

fn alias_chain(aliases: &BTreeMap<String, String>) -> bool {
    aliases
        .values()
        .any(|canonical| aliases.get(canonical).is_some_and(|next| next != canonical))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_models_load_in_the_standalone_native_package_owner() {
        let package: Package =
            serde_json::from_str(include_str!("../examples/windows-starter.json")).unwrap();
        package.validate().unwrap();
        assert_eq!(package.operations.len(), 20);
        for (name, op) in &package.operations {
            let arguments = op
                .arguments
                .iter()
                .filter_map(|(name, arg)| {
                    arg.default.clone().map(|v| (name.clone(), v)).or_else(|| {
                        arg.required
                            .then(|| (name.clone(), serde_json::json!("fixture content")))
                    })
                })
                .collect();
            let command = op.command(&arguments).unwrap();
            assert!(!command.argv.is_empty(), "{name}");
            assert!(op.semantics.is_some(), "{name}");
        }
        let mut invalid = package.clone();
        invalid
            .operations
            .get_mut("registry-query-user")
            .unwrap()
            .semantics
            .as_mut()
            .unwrap()
            .evidence = vec!["missing evidence".into()];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn native_alias_chains_do_not_silently_split_equivalent_resources() {
        assert!(!alias_chain(&BTreeMap::from([
            ("HKCU".into(), "user".into()),
            ("user".into(), "user".into())
        ])));
        assert!(alias_chain(&BTreeMap::from([
            ("HKCU".into(), "user".into()),
            ("user".into(), "another-user".into())
        ])));
    }

    #[test]
    fn catalogue_revisions_separate_wording_code_and_shared_consequences() {
        let original: Package =
            serde_json::from_str(include_str!("../examples/windows-starter.json")).unwrap();
        let before = &original.operations["service-restart"];
        let mut wording = before.clone();
        wording.description.push_str(" Reviewed wording.");
        assert_eq!(
            crate::compare_operations(before, &wording).comparison,
            crate::Comparison::Equivalent
        );
        assert!(
            !crate::compare_operations(before, &wording)
                .differences
                .is_empty()
        );
        assert_eq!(before.authority_sha256(), wording.authority_sha256());
        assert_eq!(before.assessment_sha256(), wording.assessment_sha256());
        let mut adopted = before.clone();
        adopted.enforcement.unresolved.clear();
        let rule = crate::UpdateRule {
            ceiling: adopted.clone(),
            allow_narrower: false,
            allow_implementation_updates: false,
        };
        adopted.description.push_str(" Reviewed wording.");
        assert!(rule.allows(&adopted));
        let mut executable = before.clone();
        executable.execution.executable_sha256 = "b".repeat(64);
        assert_eq!(executable.description, before.description);
        assert_ne!(
            executable.semantic_revisions().implementation,
            before.semantic_revisions().implementation
        );
        assert_ne!(
            crate::compare_operations(before, &executable).comparison,
            crate::Comparison::Equivalent
        );
        let mut model = original.clone();
        model
            .semantics
            .as_mut()
            .unwrap()
            .rules
            .get_mut("changed_service_execution")
            .unwrap()
            .explanation
            .push_str(" Corrected consequence.");
        assert_eq!(
            model
                .operation_revisions("service-restart")
                .unwrap()
                .implementation,
            original
                .operation_revisions("service-restart")
                .unwrap()
                .implementation
        );
        assert_eq!(
            model
                .operation_revisions("service-restart")
                .unwrap()
                .authority,
            original
                .operation_revisions("service-restart")
                .unwrap()
                .authority
        );
        assert_ne!(
            model
                .operation_revisions("service-restart")
                .unwrap()
                .understanding,
            original
                .operation_revisions("service-restart")
                .unwrap()
                .understanding
        );
        assert_ne!(
            model.operation_sha256("service-restart").unwrap(),
            original.operation_sha256("service-restart").unwrap()
        );
    }
}
