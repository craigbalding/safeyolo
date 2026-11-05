use safeyolo_proxy::services::{
    ServiceDefinition,
    effects::{
        Coverage, Scope,
        assessment::{Match, Permission},
    },
};
use serde_json::json;

fn service() -> ServiceDefinition {
    ServiceDefinition::from_yaml(include_str!(
        "fixtures/service-authoring/job.generated.yaml"
    ))
    .unwrap()
}

#[test]
fn every_shared_authoring_expectation_executes_in_the_evaluator() {
    let service = service();
    let model = service.effect_model.as_ref().unwrap();
    for regression in &model.regressions {
        let permissions: Vec<_> = regression
            .grants
            .iter()
            .map(|grant| Permission::example(grant.operation.clone(), grant))
            .collect();
        let assessed = model.assess(&service, &permissions).unwrap();
        for (grant, expected) in regression.grants.iter().zip(&regression.expected) {
            let actual = assessed
                .direct
                .iter()
                .find(|item| item.permission.operation == grant.operation)
                .unwrap();
            assert_eq!(
                actual.possible_effects, expected.possible_effects,
                "{} {}",
                regression.name, grant.operation
            );
            assert_eq!(
                actual.excluded_effects, expected.excluded_effects,
                "{} {}",
                regression.name, grant.operation
            );
            assert_eq!(
                actual.scopes, expected.scopes,
                "{} {}",
                regression.name, grant.operation
            );
            assert_eq!(
                model.observed_effects(grant),
                expected.observed_effects,
                "{} {}",
                regression.name,
                grant.operation
            );
        }
        for (rule, overlap) in &regression.rules {
            assert_eq!(
                assessed.rules[rule].overlap, *overlap,
                "{}",
                regression.name
            );
        }
        let mut reversed = permissions.clone();
        reversed.reverse();
        assert_eq!(
            json!(assessed),
            json!(model.assess(&service, &reversed).unwrap()),
            "{}",
            regression.name
        );
    }
}

#[test]
fn namespaces_direct_effects_unknown_coverage_and_persistent_state_are_separate() {
    let service = service();
    let model = service.effect_model.as_ref().unwrap();
    let grants = &model.regressions[0].grants;
    let mut permissions: Vec<_> = grants
        .iter()
        .map(|grant| Permission::example(grant.operation.clone(), grant))
        .collect();
    permissions[1]
        .bindings
        .insert("project".into(), json!("another-project"));
    let result = model.assess(&service, &permissions).unwrap();
    assert_eq!(
        result.rules["changed_job_execution"].status,
        Match::NonMatch
    );
    assert!(result.direct.iter().any(|direct| {
        direct
            .persistent_effects
            .contains(&"executable_changed".into())
    }));
    assert!(
        result
            .limitations
            .iter()
            .any(|limit| limit.contains("does not prove that prior edits were undone"))
    );
    permissions[0].operation = "status".into();
    permissions[0].enforcement = None;
    permissions[0].bindings.clear();
    let result = model.assess(&service, &permissions).unwrap();
    let unknown = result
        .direct
        .iter()
        .find(|direct| direct.permission.operation == "status")
        .unwrap();
    assert_eq!(unknown.coverage, Coverage::Uncharacterised);
    assert!(!unknown.unresolved_conditions.is_empty());
    assert_eq!(
        result.rules["changed_job_execution"].status,
        Match::Unresolved
    );
    permissions.remove(0);
    let result = model.assess(&service, &permissions).unwrap();
    assert_eq!(
        result.rules["changed_job_execution"].status,
        Match::NonMatch
    );
    assert!(
        result.direct[0]
            .possible_effects
            .contains(&"executed".into())
    );
}

#[test]
fn explicit_path_exclusions_remove_only_the_denied_job_from_overlap() {
    let service = service();
    let model = service.effect_model.as_ref().unwrap();
    let mut permissions: Vec<_> = model.regressions[7]
        .grants
        .iter()
        .map(|grant| Permission::example(grant.operation.clone(), grant))
        .collect();
    permissions[0].path_arguments.insert(
        "path.job".into(),
        Scope::Except {
            values: ["beta".into()].into(),
        },
    );
    assert_eq!(
        model.assess(&service, &permissions).unwrap().rules["changed_job_execution"].status,
        Match::NonMatch
    );
    permissions[0]
        .path_arguments
        .insert("path.job".into(), Scope::Unrestricted);
    assert_eq!(
        model.assess(&service, &permissions).unwrap().rules["changed_job_execution"].status,
        Match::Match
    );
}

#[test]
fn conditional_effect_status_cannot_cross_resource_annotations() {
    let original = service();
    let mut grants = original.effect_model.as_ref().unwrap().regressions[0]
        .grants
        .clone();
    grants[0].operation = "edit_definition".into();
    grants[0].enforcement = Some("description_only".into());
    let permissions: Vec<_> = grants
        .iter()
        .map(|grant| Permission::example(grant.operation.clone(), grant))
        .collect();
    for (condition, expected) in [
        (json!({"kind":"always"}), Match::Match),
        (
            json!({"kind":"equals","argument":"body.secondary","value":"changed"}),
            Match::Unresolved,
        ),
    ] {
        let mut source = original.raw.clone();
        let model = &mut source["effect_model"];
        model["regressions"] = json!([]);
        model["resources"]["secondary_job"] = model["resources"]["job"].clone();
        let edit = &mut model["operations"]["edit_definition"];
        edit["resources"]["secondary_job"] = edit["resources"]["job"].clone();
        edit["arguments"]["body.secondary"] = json!({
            "location":"body", "field":"secondary", "required":false,
            "omission":{"kind":"unresolved","reason":"Unverified secondary default"},
            "evidence":["spec","semantics"]
        });
        edit["effects"].as_array_mut().unwrap().push(json!({
            "effect":"executable_changed", "resource":"secondary_job",
            "when":condition, "evidence":["spec","semantics"]
        }));
        let loaded = ServiceDefinition::from_yaml(&source.to_string()).unwrap();
        let result = loaded
            .effect_model
            .as_ref()
            .unwrap()
            .assess(&loaded, &permissions)
            .unwrap();
        let edit = result
            .direct
            .iter()
            .find(|item| item.method == "PATCH")
            .unwrap();
        assert!(edit.effects.iter().any(|effect| {
            effect.effect == "executable_changed"
                && effect.resource == "job"
                && effect.status == Match::NonMatch
        }));
        assert!(edit.effects.iter().any(|effect| {
            effect.effect == "executable_changed"
                && effect.resource == "secondary_job"
                && effect.status == expected
        }));
        assert_eq!(
            result.rules["changed_job_execution"].status,
            Match::NonMatch
        );

        // The same valid multi-resource definition can still satisfy the rule
        // when the effect on its actual job resource is possible.
        source["effect_model"]["operations"]["edit_definition"]["effects"][0]["when"] =
            json!({"kind":"always"});
        let loaded = ServiceDefinition::from_yaml(&source.to_string()).unwrap();
        let result = loaded
            .effect_model
            .as_ref()
            .unwrap()
            .assess(&loaded, &permissions)
            .unwrap();
        assert_eq!(result.rules["changed_job_execution"].status, Match::Match);
    }
}
