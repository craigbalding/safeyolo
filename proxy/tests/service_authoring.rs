use safeyolo_proxy::{
    contracts::{ContractBinding, ContractRequest, enforce_request},
    services::{
        Registry, ServiceDefinition,
        authoring::generate,
        effects::{Coverage, Omission, Overlap, Scope},
    },
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SPEC: &str = include_str!("fixtures/service-authoring/job.openapi.json");

fn generated() -> Value {
    generate(SPEC).unwrap()
}

fn loaded() -> ServiceDefinition {
    ServiceDefinition::from_value(generated()).unwrap()
}

fn competing_edit_spec(path: &str, method: &str, before: bool) -> Value {
    let mut spec: Value = serde_json::from_str(SPEC).unwrap();
    spec["paths"][path][method] = json!({
        "operationId":"other_edit", "responses":{"200":{"description":"fixture"}}
    });
    let operations =
        spec["x-safeyolo-service"]["capabilities"]["describe_job"]["contract"]["operations"]
            .as_array_mut()
            .unwrap();
    let other = json!({"name":"other_edit", "request":{
        "body":{"deny_unknown":false,"allow":{}},
        "query":{"deny_unknown":true,"allow":{}},
        "transport":{"require_no_body":false}
    }});
    if before {
        operations.insert(0, other);
    } else {
        operations.push(other);
    }
    spec
}

#[test]
fn semantic_mapping_accounts_for_operation_selection_across_future_bindings() {
    for (path, method, before, shadowed) in [
        ("/projects/demo/jobs/alpha/definition", "patch", false, true),
        // Current description-only examples use alpha. A future beta binding
        // must not silently lose the same advertised executable-edit exclusion.
        ("/projects/demo/jobs/beta/definition", "patch", false, true),
        (
            "/projects/demo/jobs/alpha/definition/",
            "patch",
            false,
            true,
        ),
        (
            "/projects/{other_project}/jobs/{other_job}/definition",
            "patch",
            true,
            true,
        ),
        (
            "/{section}/demo/{resource}/alpha/definition",
            "patch",
            true,
            true,
        ),
        (
            "/projects/{other_project}/jobs/{other_job}/definition",
            "patch",
            false,
            false,
        ),
        ("/projects/**", "patch", true, false),
        ("/projects/**", "patch", false, false),
        ("/projects/{project}/jobs/{job}/other", "patch", true, false),
        (
            "/other/{project}/jobs/{job}/definition",
            "patch",
            true,
            false,
        ),
        (
            "/projects/{project}/jobs/{job}/definition/detail",
            "patch",
            true,
            false,
        ),
        ("/projects/demo/jobs/alpha/definition", "post", true, false),
    ] {
        let result = generate(&competing_edit_spec(path, method, before).to_string());
        if shadowed {
            let problem = result.unwrap_err().to_string();
            assert!(
                problem.contains("Unsupported enforcement mapping describe_job/edit_definition")
                    && problem.contains("selects other_edit"),
                "{path}: {problem}"
            );
        } else {
            result.unwrap_or_else(|error| panic!("{method} {path}: {error}"));
        }
    }
    let mut spec = competing_edit_spec("/projects/demo/jobs/alpha/definition", "patch", true);
    spec["x-safeyolo-service"]["capabilities"]["describe_job"]["contract"]["operations"][0]["requires_enforcement"] =
        json!("state_enforcement");
    // The executor cannot select this unsupported operation.
    generate(&spec.to_string()).unwrap();
}

#[test]
fn loader_rejects_a_mapping_shadowed_by_an_operation_outside_the_approved_selection() {
    let path = "/projects/demo/jobs/alpha/definition";
    let mut raw = generated();
    let mut other = raw["effect_model"]["operations"]["status"].clone();
    other["method"] = json!("PATCH");
    other["path"] = json!(path);
    raw["effect_model"]["operations"]["other_edit"] = other;
    raw["capabilities"]["describe_job"]["contract"]["operations"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "name":"other_edit", "request":{"method":"PATCH", "path":path,
                "body":{"deny_unknown":false,"allow":{}},
                "query":{"deny_unknown":true,"allow":{}},
                "transport":{"require_no_body":false}}
        }));
    let error = ServiceDefinition::from_yaml(&raw.to_string())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("Unsupported enforcement mapping describe_job/edit_definition"),
        "{error}"
    );

    // Keep the existing executor boundary visible: a route compiled from only
    // edit_definition can dispatch to the more specific, unselected operation.
    raw.as_object_mut().unwrap().remove("effect_model");
    let service = ServiceDefinition::from_value(raw).unwrap();
    let contract = service.capabilities["describe_job"]
        .contract
        .as_ref()
        .unwrap();
    let binding = ContractBinding {
        binding_id: "fixture".into(),
        agent: "fixture-agent".into(),
        service: service.name.clone(),
        capability: "describe_job".into(),
        template: contract.template.clone(),
        bound_values: json!({"project":"demo","job":"alpha"})
            .as_object()
            .unwrap()
            .clone(),
        grantable_operations: vec!["edit_definition".into()],
    };
    let token = safeyolo_proxy::services::TokenBinding {
        token: safeyolo_proxy::credentials::Secret::new("synthetic-test-token"),
        agent: json!("fixture-agent"),
        service: json!(service.name),
        capability: json!("describe_job"),
        vault_token: json!("synthetic-credential-reference"),
        account: json!("fixture"),
    };
    let routes =
        safeyolo_proxy::services::compile_routes(&service, &token, std::slice::from_ref(&binding));
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].path, path);
    let headers = vec![("Content-Type".into(), "application/json".into())];
    let result = enforce_request(
        contract,
        Some(&binding),
        "Authorization",
        ContractRequest {
            method: "PATCH",
            target: &routes[0].path,
            headers: &headers,
            body: br#"{"steps":["execute"]}"#,
        },
    )
    .unwrap();
    assert_eq!(result.operation, "other_edit");
    assert_eq!(result.body.unwrap()["steps"], json!(["execute"]));
}

#[test]
fn generated_fixture_loads_through_the_current_catalogue() {
    let generated = generated();
    let source = serde_json::to_string_pretty(&generated).unwrap();
    let registry = Registry::from_sources(&[("job.yaml".into(), source.clone())], &[]).unwrap();
    let service = &registry.services["job-authoring-fixture"];
    let model = service.effect_model.as_ref().unwrap();
    assert_eq!(model.operations.len(), 6);
    assert_eq!(
        model.operations["status"].coverage,
        Coverage::Uncharacterised
    );
    assert!(!model.operations["status"].gaps.is_empty());
    assert_eq!(model.rules.len(), 1);
    for name in ["replace_definition", "edit_definition"] {
        assert!(
            model.operations[name]
                .effects
                .iter()
                .any(|effect| effect.effect == "executable_changed")
        );
    }
    assert!(model.effects["executable_changed"].persists_after_access);
    assert!(model.effects["executed"].persists_after_access);
    assert!(model.gaps.iter().any(|gap| gap.contains("undocumented")));
    let recipe = &model.alternatives["inspect_stored_definition"];
    assert_eq!(recipe.steps[0].operation, "inspect_definition");
    assert!(!recipe.unverified_prerequisites.is_empty());
    assert!(
        recipe
            .limitations
            .iter()
            .any(|limit| limit.contains("persist after access expiry"))
    );
    assert_eq!(service.raw, generated);
    // JSON output is also valid YAML for the normal operator catalogue.
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/service-authoring/job.generated.yaml"
    ))
    .unwrap();
    assert_eq!(
        ServiceDefinition::from_yaml(&committed).unwrap().raw,
        generated
    );
}

#[test]
fn regression_inputs_keep_orders_arguments_scope_defaults_and_gaps() {
    let service = loaded();
    let model = service.effect_model.as_ref().unwrap();
    let cases: BTreeMap<_, _> = model
        .regressions
        .iter()
        .map(|case| (case.name.as_str(), case))
        .collect();
    for producer in ["replacement", "step-edit"] {
        let first = cases[format!("{producer}-then-execute-same-job").as_str()];
        let second = cases[format!("execute-then-{producer}-same-job").as_str()];
        assert_eq!(first.grants[0].operation, second.grants[1].operation);
        assert_eq!(first.rules["changed_job_execution"], Overlap::Same);
        assert_eq!(first.rules, second.rules);
    }
    assert_eq!(
        cases["disjoint-jobs"].rules["changed_job_execution"],
        Overlap::Disjoint
    );
    let broad = cases["observed-job-does-not-limit-route-wide-grant"];
    assert_eq!(broad.grants[0].observed_arguments["path.job"], "alpha");
    assert_eq!(broad.expected[0].scopes["job"]["job"], Scope::Unrestricted);
    let unresolved = cases["unresolved-alias-identity"];
    assert!(matches!(
        unresolved.expected[1].scopes["job"]["job"],
        Scope::Unresolved { .. }
    ));
    assert_eq!(
        unresolved.rules["changed_job_execution"],
        Overlap::Unresolved
    );
    let description = cases["enforced-description-only-excludes-executable-edit"];
    assert_eq!(
        description.expected[0].excluded_effects,
        ["executable_changed"]
    );
    let sample = cases["descriptive-sample-does-not-limit-edit-grant"];
    assert_eq!(sample.expected[0].observed_effects, ["description_changed"]);
    assert!(
        sample.expected[0]
            .possible_effects
            .contains(&"executable_changed".into())
    );
    assert!(matches!(
        model.operations["replace_definition"].arguments["body.steps"].omission,
        Omission::Default { .. }
    ));
    assert!(matches!(
        model.operations["edit_definition"].arguments["body.steps"].omission,
        Omission::Unchanged
    ));
    assert!(
        matches!(&model.operations["execute_job"].arguments["query.mode"].omission, Omission::Default { value } if value == "execute")
    );
    let preview = cases["preview-value-does-not-enforce-presence"];
    assert_eq!(preview.expected[1].observed_effects, ["previewed"]);
    assert!(
        preview.expected[1]
            .possible_effects
            .contains(&"executed".into())
    );
}

#[test]
fn actual_request_checks_exclude_steps_but_do_not_require_the_preview_argument() {
    let service = loaded();
    let model = service.effect_model.as_ref().unwrap();
    let exercise =
        |capability: &str, op: &str, target: &str, method: &str, body: &[u8], values: Value| {
            let contract = service.capabilities[capability].contract.as_ref().unwrap();
            let binding = ContractBinding {
                binding_id: "fixture".into(),
                agent: "fixture-agent".into(),
                service: service.name.clone(),
                capability: capability.into(),
                template: contract.template.clone(),
                bound_values: values.as_object().unwrap().clone(),
                grantable_operations: vec![op.into()],
            };
            let headers = vec![("Content-Type".into(), "application/json".into())];
            enforce_request(
                contract,
                Some(&binding),
                "Authorization",
                ContractRequest {
                    method,
                    target,
                    headers: &headers,
                    body,
                },
            )
        };
    let bindings = json!({"project":"demo", "job":"alpha"});
    assert!(
        exercise(
            "describe_job",
            "edit_definition",
            "/projects/demo/jobs/alpha/definition",
            "PATCH",
            br#"{"description":"text"}"#,
            bindings.clone()
        )
        .is_ok()
    );
    assert!(
        exercise(
            "describe_job",
            "edit_definition",
            "/projects/demo/jobs/alpha/definition",
            "PATCH",
            br#"{"steps":["execute"]}"#,
            bindings.clone()
        )
        .is_err()
    );
    assert!(
        exercise(
            "edit_job",
            "edit_definition",
            "/projects/demo/jobs/alpha/definition",
            "PATCH",
            br#"{"steps":["execute"]}"#,
            bindings.clone()
        )
        .is_ok()
    );
    assert!(
        exercise(
            "edit_job",
            "edit_definition",
            "/projects/demo/jobs/beta/definition",
            "PATCH",
            b"{}",
            bindings.clone()
        )
        .is_err()
    );
    // No body field is required by the existing allowlist. The modeled API
    // leaves omitted PATCH fields unchanged and defaults omitted PUT steps.
    assert!(
        exercise(
            "describe_job",
            "edit_definition",
            "/projects/demo/jobs/alpha/definition",
            "PATCH",
            b"{}",
            bindings.clone()
        )
        .is_ok()
    );
    assert!(
        exercise(
            "replace_job",
            "replace_definition",
            "/projects/demo/jobs/alpha/definition",
            "PUT",
            b"{}",
            bindings.clone()
        )
        .is_ok()
    );
    let preview = json!({"project":"demo", "job":"alpha", "mode":"preview"});
    assert!(
        exercise(
            "execute_job",
            "execute_job",
            "/projects/demo/jobs/alpha/run?mode=preview",
            "POST",
            b"",
            preview.clone()
        )
        .is_ok()
    );
    assert!(
        exercise(
            "execute_job",
            "execute_job",
            "/projects/demo/jobs/alpha/run?mode=execute",
            "POST",
            b"",
            preview.clone()
        )
        .is_err()
    );
    assert!(
        exercise(
            "execute_job",
            "execute_job",
            "/projects/demo/jobs/alpha/run",
            "POST",
            b"",
            preview
        )
        .is_ok()
    );
    // Resolve and execute the loaded recipe through its actual access mapping.
    let step = &model.alternatives["inspect_stored_definition"].steps[0];
    let mapping = &model.enforcement[&step.enforcement];
    let operation = &model.operations[&step.operation];
    let mut target = operation.path.clone();
    for (argument, value) in &step.arguments {
        let field = &operation.arguments[argument].field;
        target = target.replace(&format!("{{{field}}}"), value.as_str().unwrap());
    }
    assert!(
        exercise(
            &mapping.capability,
            &step.operation,
            &target,
            &operation.method,
            b"",
            bindings
        )
        .is_ok()
    );
    assert!(model.effects["inspected"].persists_after_access);
}

#[test]
fn malformed_references_and_unsupported_expressions_are_rejected_by_the_loader() {
    let valid = generated();
    let failures = [
        (
            "/effect_model/enforcement/edit_scoped/operation",
            json!("missing"),
            "enforcement operation",
        ),
        (
            "/effect_model/enforcement/edit_scoped/capability",
            json!("missing"),
            "enforcement capability",
        ),
        (
            "/effect_model/rules/changed_job_execution/when/effects/0",
            json!("missing"),
            "rule effect",
        ),
        (
            "/effect_model/rules/changed_job_execution/when/kind",
            json!("arbitrary_expression"),
            "unknown variant",
        ),
        (
            "/effect_model/operations/edit_definition/effects/0/when/kind",
            json!("eval"),
            "unknown variant",
        ),
        (
            "/effect_model/operations/edit_definition/effects/0/when/argument",
            json!("body.missing"),
            "condition argument",
        ),
        (
            "/effect_model/alternatives/inspect_stored_definition/steps/0/operation",
            json!("missing"),
            "recipe operation",
        ),
        (
            "/effect_model/alternatives/inspect_stored_definition/steps/0/arguments",
            json!({"path.job":"alpha"}),
            "missing a required argument",
        ),
        (
            "/effect_model/regressions/0/grants/0/bindings/job",
            json!("alpha/beta"),
            "cannot resolve the enforced path",
        ),
        (
            "/effect_model/regressions/0/rules",
            json!({"missing":"same"}),
            "regression rule",
        ),
        (
            "/effect_model/regressions/0/expected/0/evidence/0",
            json!("missing"),
            "evidence source",
        ),
        (
            "/effect_model/regressions/7/expected/0/scopes/job/job",
            json!({"kind":"known","value":"alpha"}),
            "Expected scope",
        ),
    ];
    for (path, replacement, error) in failures {
        let mut candidate = valid.clone();
        *candidate.pointer_mut(path).unwrap() = replacement;
        let problem = ServiceDefinition::from_value(candidate)
            .unwrap_err()
            .to_string();
        assert!(problem.contains(error), "{path}: {problem}");
    }
}

#[test]
fn semantic_enforcement_references_reject_declarations_the_executor_does_not_implement() {
    let valid = generated();
    for (location, constraint) in [
        ("body", json!({"type":"string"})),
        ("body", json!({"integer_range":[0, 1]})),
        ("query", json!({"in_state_set":"prior-response"})),
        ("query", json!({"regex":".*"})),
        ("query", json!({"integer_range":[2, 1]})),
        ("query", json!({"equals_var":"missing"})),
    ] {
        let mut candidate = valid.clone();
        candidate["capabilities"]["describe_job"]["contract"]["operations"][0]["request"]
            [location]["allow"]["description"] = constraint;
        assert!(
            ServiceDefinition::from_value(candidate).is_err(),
            "{location}"
        );
    }
    let mut candidate = valid;
    candidate["capabilities"]["describe_job"]["contract"]["operations"][0]["request"]["method"] =
        json!("PUT");
    assert!(
        ServiceDefinition::from_value(candidate)
            .unwrap_err()
            .to_string()
            .contains("method/path")
    );
}

#[test]
fn unused_or_unimplemented_request_constraints_cannot_claim_enforcement() {
    let valid = generated();
    for (capability, path, replacement, error) in [
        (
            "inspect_job",
            "/request/body/allow",
            json!({"description":{"equals_var":"job"}}),
            "not enforced for this method",
        ),
        (
            "edit_job",
            "/request/path_params",
            json!({"project":{"equals_var":"project"},"absent":{"equals_var":"job"}}),
            "no matching path parameter",
        ),
        (
            "edit_job",
            "/requires_enforcement",
            json!("response_validators"),
            "one supported contract operation",
        ),
    ] {
        let mut candidate = valid.clone();
        let op = &mut candidate["capabilities"][capability]["contract"]["operations"][0];
        if path == "/requires_enforcement" {
            op["requires_enforcement"] = replacement;
        } else {
            *op.pointer_mut(path).unwrap() = replacement;
        }
        assert!(
            ServiceDefinition::from_value(candidate)
                .unwrap_err()
                .to_string()
                .contains(error),
            "{capability}{path}"
        );
    }
}

#[test]
fn effect_models_grant_no_routes_and_unknown_identity_adds_no_denial() {
    let with_model = loaded();
    let mut raw = with_model.raw.clone();
    raw.as_object_mut().unwrap().remove("effect_model");
    let without_model = ServiceDefinition::from_value(raw).unwrap();
    for (capability, operation, values) in [
        (
            "inspect_job",
            "inspect_definition",
            json!({"project":"demo","job":"alpha"}),
        ),
        (
            "execute_alias",
            "execute_alias",
            json!({"project":"demo","alias":"nightly"}),
        ),
    ] {
        let token = safeyolo_proxy::services::TokenBinding {
            token: safeyolo_proxy::credentials::Secret::new("synthetic-test-token"),
            agent: json!("fixture-agent"),
            service: json!(with_model.name),
            capability: json!(capability),
            vault_token: json!("synthetic-credential-reference"),
            account: json!("fixture"),
        };
        assert!(safeyolo_proxy::services::compile_routes(&with_model, &token, &[]).is_empty());
        let contract = with_model.capabilities[capability]
            .contract
            .as_ref()
            .unwrap();
        let binding = ContractBinding {
            binding_id: "fixture".into(),
            agent: "fixture-agent".into(),
            service: with_model.name.clone(),
            capability: capability.into(),
            template: contract.template.clone(),
            bound_values: values.as_object().unwrap().clone(),
            grantable_operations: vec![operation.into()],
        };
        let routes = safeyolo_proxy::services::compile_routes(
            &with_model,
            &token,
            std::slice::from_ref(&binding),
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes,
            safeyolo_proxy::services::compile_routes(&without_model, &token, &[binding])
        );
    }
}

#[test]
fn generation_rejects_unresolved_inputs_and_preserves_uncharacterised_inventory() {
    let valid: Value = serde_json::from_str(SPEC).unwrap();
    for (path, replacement, error) in [
        (
            "/paths/~1status/get/operationId",
            json!("execute_job"),
            "Duplicate operationId",
        ),
        (
            "/paths/~1status/get/operationId",
            Value::Null,
            "stable operationId",
        ),
        (
            "/paths/~1status/get/responses/200",
            json!({"$ref":"remote"}),
            "does not resolve",
        ),
        (
            "/paths/~1projects~1{project}~1jobs~1{job}~1definition/patch/x-safeyolo/arguments",
            json!({"body.missing":{}}),
            "unknown OpenAPI argument",
        ),
        (
            "/paths/~1projects~1{project}~1jobs~1{job}~1run/post/parameters/0/schema/default",
            json!("preview"),
            "",
        ),
    ] {
        let mut source = valid.clone();
        *source.pointer_mut(path).unwrap() = replacement;
        let result = generate(&source.to_string());
        if error.is_empty() {
            assert_eq!(
                result.unwrap()["effect_model"]["operations"]["execute_job"]["arguments"]["query.mode"]
                    ["omission"]["value"],
                "preview"
            );
        } else {
            assert!(result.unwrap_err().to_string().contains(error), "{path}");
        }
    }
    let mut source = valid.clone();
    source["paths"]["/projects/{project}/jobs/{job}/run"]["post"]["x-safeyolo"]["arguments"]["query.mode"] =
        json!({"omission":{"kind":"default","value":"preview"}});
    assert!(
        generate(&source.to_string())
            .unwrap_err()
            .to_string()
            .contains("contradicts")
    );
    let mut source = valid.clone();
    source["paths"]["/status"]["get"]["callbacks"] = json!({});
    assert!(
        generate(&source.to_string())
            .unwrap_err()
            .to_string()
            .contains("callback operations")
    );
    let mut source = valid.clone();
    source["webhooks"] = json!({});
    assert!(
        generate(&source.to_string())
            .unwrap_err()
            .to_string()
            .contains("webhook semantics")
    );
    let mut source = valid;
    source["paths"]["/projects/{project}/jobs/{job}/definition"]["put"]["requestBody"]["content"]
        ["application/json"]["schema"]["required"] = json!(["steps"]);
    assert!(
        generate(&source.to_string())
            .unwrap_err()
            .to_string()
            .contains("body-presence semantics")
    );
}
