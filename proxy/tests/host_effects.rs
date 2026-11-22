//! Native loading and authority assessment; no Windows host operation executes.
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, KeyPair};
use safeyolo_proxy::{
    host_execution::{
        semantics::{self, Authority, PersistentEffect},
        *,
    },
    policy::{Effect, Format, Policy, RiskyRouteRequest},
    services::{
        Registry, ServiceDefinition,
        authoring::{check, generate},
        effects::{Scope, assessment::ResourceScopes},
    },
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};

const SOURCE: &str = include_str!("../../host-executor/examples/windows-starter.json");

fn package() -> Package {
    serde_json::from_str(SOURCE).unwrap()
}

fn scope(package: &Package, id: &str) -> OperationScope {
    let op = &package.operations[id];
    OperationScope {
        implementation_sha256: op.implementation_sha256(),
        resources: op.resources.clone(),
        arguments: op
            .arguments
            .iter()
            .map(|(name, arg)| {
                let values = if !arg.options.is_empty() {
                    arg.options.clone()
                } else {
                    vec![arg.default.clone().unwrap_or(json!("fixture value"))]
                };
                (name.clone(), values)
            })
            .collect(),
        budgets: Budgets {
            calls: 10,
            concurrent: 1,
            timeout_seconds: 30,
            output_bytes: 65536,
        },
    }
}

fn permission(package: &Package, grant: &str, target: &str, operation: &str) -> Authority {
    Authority {
        id: grant.into(),
        target_id: target.into(),
        operations: BTreeMap::from([(operation.into(), scope(package, operation))]),
        proposed: false,
    }
}

fn assess(package: &Package, grants: &[Authority]) -> Value {
    semantics::assess(package, grants, &[]).unwrap()
}

#[test]
fn complete_windows_inventory_loads_and_generation_is_reproducible() {
    let package = package();
    package.validate().unwrap();
    let projections = package.projections().unwrap();
    package.verify_projections(&projections).unwrap();
    assert_eq!(json!(projections), generate(SOURCE).unwrap());
    assert_eq!(json!(projections), generate(SOURCE).unwrap());
    let registry = Registry::from_sources(
        &projections
            .gateway
            .iter()
            .map(|(name, value)| (name.clone(), value.to_string()))
            .collect::<Vec<_>>(),
        &[],
    )
    .unwrap();
    assert_eq!(registry.services.len(), package.operations.len());
    assert!(
        check(SOURCE, Some(&serde_json::to_string(&projections).unwrap()))
            .unwrap()
            .contains("match")
    );
    let mut altered = projections.clone();
    altered.assessment.as_mut().unwrap()["effect_model"]["rules"]["changed_service_execution"]["consequence"] =
        json!("concealed");
    assert!(package.verify_projections(&altered).is_err());
    for name in [
        "service-enumerate",
        "service-status",
        "service-start",
        "service-stop",
        "service-restart",
        "event-log-query",
        "registry-query-machine",
        "registry-query-user",
        "process-inspect",
        "system-inventory",
        "software-inventory",
        "update-inventory",
        "file-inspect",
        "network-diagnostics",
        "scheduled-task-inspect",
        "fixed-executable",
    ] {
        let op = &package.operations[name];
        assert!(op.semantics.is_some(), "{name}");
        let mut sample: BTreeMap<_, _> = op
            .arguments
            .iter()
            .filter_map(|(k, a)| a.default.clone().map(|v| (k.clone(), v)))
            .collect();
        op.command(&sample).unwrap();
        for (argument, contract) in &op.arguments {
            for choice in &contract.options {
                sample.insert(argument.clone(), choice.clone());
                op.command(&sample).unwrap();
            }
            sample.insert(argument.clone(), json!({"unexpected":"object"}));
            assert!(op.arguments(&sample).is_err(), "{name}/{argument}");
            sample.insert(argument.clone(), contract.default.clone().unwrap());
        }
        let value = assess(
            &package,
            &[permission(&package, "current", "windows-a", name)],
        );
        assert!(
            value["model"]["direct"][0]["unresolved_conditions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s.as_str().unwrap().contains("broader"))
        );
    }
}

#[test]
fn service_verbs_have_distinct_authority_and_queries_do_not_grant_mutation() {
    let package = package();
    let effects = |operation: &str| {
        assess(
            &package,
            &[permission(&package, "current", "windows-a", operation)],
        )["model"]["direct"][0]["possible_effects"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        effects("service-status"),
        vec!["service_status", "disclosure"]
    );
    assert!(!effects("service-stop").contains(&"execute".into()));
    assert!(effects("service-start").contains(&"execute".into()));
    assert!(effects("service-restart").contains(&"service_stop".into()));
    assert!(effects("network-diagnostics").contains(&"network_probe".into()));
    for operation in [
        "event-log-query",
        "registry-query-user",
        "registry-query-machine",
        "scheduled-task-inspect",
        "process-inspect",
    ] {
        assert!(
            !effects(operation)
                .iter()
                .any(|e| e == "execute" || e == "write_executable" || e == "service_start")
        );
    }
    let model = assess(&package, &[]);
    let steps = &model["alternatives"]["service-status-before-control"]["steps"];
    assert_eq!(steps[0]["operation"], "service-status");
    assert_eq!(steps[0]["required_arguments"]["service"], "Demo");
    assert_eq!(steps[0]["available_from"], json!([]));
}

#[test]
fn composition_covers_both_orders_target_identity_aliases_and_unknowns() {
    let mut package = package();
    let mut grants = vec![
        permission(&package, "writer", "windows-a", "write-service-config"),
        permission(&package, "runner", "windows-a", "service-restart"),
    ];
    grants[0]
        .operations
        .get_mut("write-service-config")
        .unwrap()
        .resources = ["service:Demo".into()].into();
    grants[1]
        .operations
        .get_mut("service-restart")
        .unwrap()
        .resources = ["service:demo".into()].into();
    let same = assess(&package, &grants);
    assert_eq!(
        same["model"]["rules"]["changed_service_execution"]["status"],
        "match"
    );
    assert_eq!(
        same["model"]["rules"]["changed_service_execution"]["combinations"][0]["scope"]["id"],
        json!({"kind":"known","value":"service:demo"})
    );
    grants.reverse();
    assert_eq!(assess(&package, &grants), same);
    grants[0].target_id = "windows-b".into();
    assert_eq!(
        assess(&package, &grants)["model"]["rules"]["changed_service_execution"]["status"],
        "non_match"
    );
    grants[0].target_id = "windows-a".into();
    let op = package.operations.get_mut("service-restart").unwrap();
    op.resources = ["service:other".into()].into();
    op.arguments.get_mut("service").unwrap().options = vec![json!("Other")];
    op.arguments.get_mut("service").unwrap().default = Some(json!("Other"));
    op.semantics
        .as_mut()
        .unwrap()
        .resources
        .get_mut("service")
        .unwrap()
        .insert(
            "id".into(),
            HostIdentity::Resource {
                aliases: BTreeMap::new(),
            },
        );
    grants[0] = permission(&package, "runner", "windows-a", "service-restart");
    assert_eq!(
        assess(&package, &grants)["model"]["rules"]["changed_service_execution"]["status"],
        "non_match"
    );
    let mut package = crate::package();
    if let HostIdentity::Resource { aliases } = package
        .operations
        .get_mut("write-service-config")
        .unwrap()
        .semantics
        .as_mut()
        .unwrap()
        .resources
        .get_mut("service")
        .unwrap()
        .get_mut("id")
        .unwrap()
    {
        aliases.remove("service:Demo");
    }
    let mut writer = permission(&package, "writer", "windows-a", "write-service-config");
    writer
        .operations
        .get_mut("write-service-config")
        .unwrap()
        .resources = ["service:Demo".into()].into();
    let runner = permission(&package, "runner", "windows-a", "service-restart");
    assert_eq!(
        assess(&package, &[writer, runner])["model"]["rules"]["changed_service_execution"]["status"],
        "unresolved"
    );
}

#[test]
fn registry_aliases_defaults_actual_user_and_views_preserve_identity() {
    let package = package();
    for operation in ["registry-query-machine", "registry-query-user"] {
        let mut grant = permission(&package, "registry", "windows-a", operation);
        let scope = grant.operations.get_mut(operation).unwrap();
        scope.arguments.get_mut("hive").unwrap().truncate(1);
        scope.arguments.get_mut("key").unwrap().truncate(1);
        scope.arguments.get_mut("value").unwrap().truncate(1);
        scope.arguments.insert("view".into(), vec![json!("32")]);
        let first = assess(&package, std::slice::from_ref(&grant));
        for name in ["hive", "key", "value"] {
            scope_from(&mut grant, operation).arguments.insert(
                name.into(),
                vec![package.operations[operation].arguments[name].options[1].clone()],
            );
        }
        let alias = assess(&package, std::slice::from_ref(&grant));
        assert_eq!(
            first["model"]["direct"][0]["scopes"],
            alias["model"]["direct"][0]["scopes"]
        );
        scope_from(&mut grant, operation)
            .arguments
            .insert("view".into(), vec![json!("64")]);
        let second = assess(&package, std::slice::from_ref(&grant));
        let identity = &second["model"]["direct"][0]["scopes"]["registry"];
        if operation.ends_with("user") {
            assert_eq!(
                first["model"]["direct"][0]["scopes"],
                second["model"]["direct"][0]["scopes"]
            );
            assert_eq!(
                identity["user"]["value"],
                package.operations[operation].execution.identity.principal
            );
            assert_eq!(identity["view"]["value"], "shared");
        } else {
            assert_ne!(
                first["model"]["direct"][0]["scopes"],
                second["model"]["direct"][0]["scopes"]
            );
        }
        assert_eq!(
            package.operations[operation]
                .arguments(&BTreeMap::new())
                .unwrap()["view"],
            "64"
        );
    }
}

fn scope_from<'a>(grant: &'a mut Authority, operation: &str) -> &'a mut OperationScope {
    grant.operations.get_mut(operation).unwrap()
}

#[test]
fn the_full_argument_envelope_and_default_authority_drive_conditional_effects() {
    use safeyolo_proxy::services::effects::{Condition, EffectUse};
    let mut package = package();
    let op = package.operations.get_mut("file-inspect").unwrap();
    op.effects.insert(
        "file_contents".into(),
        NamedEffect {
            description: "Disclose file contents, beyond metadata".into(),
            persists_after_access: true,
            evidence: vec!["package".into()],
        },
    );
    op.semantics.as_mut().unwrap().effects.push(EffectUse {
        effect: "file_contents".into(),
        resource: "file".into(),
        when: Condition::Equals {
            argument: "content".into(),
            value: json!(true),
        },
        evidence: vec!["package".into()],
    });
    let mut grant = permission(&package, "file", "windows-a", "file-inspect");
    scope_from(&mut grant, "file-inspect")
        .arguments
        .insert("content".into(), vec![json!(false)]);
    let narrow = assess(&package, std::slice::from_ref(&grant));
    assert!(
        narrow["model"]["direct"][0]["excluded_effects"]
            .as_array()
            .unwrap()
            .contains(&json!("file_contents"))
    );
    scope_from(&mut grant, "file-inspect")
        .arguments
        .insert("content".into(), vec![json!(false), json!(true)]);
    let full = assess(&package, std::slice::from_ref(&grant));
    assert!(
        full["model"]["direct"][0]["possible_effects"]
            .as_array()
            .unwrap()
            .contains(&json!("file_contents"))
    );
    // Omitting content normalizes to false. An observed metadata-only request
    // cannot exclude true when the complete grant permits it.
    assert_eq!(
        package.operations["file-inspect"]
            .arguments(&BTreeMap::new())
            .unwrap()["content"],
        false
    );
    scope_from(&mut grant, "file-inspect")
        .arguments
        .insert("content".into(), vec![]);
    assert!(semantics::assess(&package, &[grant], &[]).is_err());
}

#[test]
fn retained_writes_compose_after_expiry_without_recreating_current_write_permission() {
    let package = package();
    let writer = permission(&package, "writer", "windows-a", "write-service-config");
    let runner = permission(&package, "runner", "windows-a", "service-restart");
    let known = assess(&package, &[writer]);
    let scopes: ResourceScopes =
        serde_json::from_value(known["model"]["direct"][0]["scopes"].clone()).unwrap();
    let observation = PersistentEffect {
        id: "write-before-expiry".into(),
        observed_at: "2026-11-21T12:00:00Z".into(),
        target_id: "windows-a".into(),
        operation: "write-service-config".into(),
        scopes,
        effects: ["write_executable".into()].into(),
        evidence: vec![Source {
            location: "trusted fixture observation".into(),
            version: "1".into(),
        }],
    };
    let retained = semantics::assess(&package, &[runner], &[observation]).unwrap();
    assert_eq!(
        retained["model"]["rules"]["changed_service_execution"]["status"],
        "match"
    );
    assert!(
        retained["model"]["direct"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["permission"]["id"] == "retained:write-before-expiry")
    );
    assert!(
        retained["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("Historical state"))
    );
    for (a, b, rule) in [
        ("file-inspect", "transmit-data", "data_transmission"),
        (
            "reviewer-status",
            "reviewer-restart",
            "reviewer_independence",
        ),
    ] {
        let grants = [
            permission(&package, "one", "windows-a", a),
            permission(&package, "two", "windows-a", b),
        ];
        assert_eq!(
            assess(&package, &grants)["model"]["rules"][rule]["status"],
            "match"
        );
    }
}

#[test]
fn description_executable_authority_and_understanding_revisions_are_distinct() {
    let original = package();
    let op = &original.operations["service-restart"];
    let revisions = op.semantic_revisions();
    let mut description = op.clone();
    description.description.push_str(" Reviewed wording.");
    let revised = description.semantic_revisions();
    assert_eq!(revised.implementation, revisions.implementation);
    assert_eq!(revised.authority, revisions.authority);
    assert_eq!(revised.understanding, revisions.understanding);
    assert_ne!(revised.description, revisions.description);
    let mut executable = op.clone();
    executable.execution.executable_sha256 = "b".repeat(64);
    assert_eq!(executable.description, op.description);
    assert_ne!(
        executable.semantic_revisions().implementation,
        revisions.implementation
    );
    let mut arguments = op.clone();
    arguments.arguments.get_mut("service").unwrap().default = Some(json!("demo"));
    assert_eq!(
        arguments.semantic_revisions().implementation,
        revisions.implementation
    );
    assert_ne!(
        arguments.semantic_revisions().authority,
        revisions.authority
    );
    let mut understanding = op.clone();
    understanding
        .effects
        .get_mut("execute")
        .unwrap()
        .description
        .push_str(" Corrected account consequence.");
    assert_eq!(
        understanding.semantic_revisions().implementation,
        revisions.implementation
    );
    assert_eq!(
        understanding.semantic_revisions().authority,
        revisions.authority
    );
    assert_ne!(
        understanding.semantic_revisions().understanding,
        revisions.understanding
    );
}

fn principal() -> Principal {
    Principal {
        run: AgentRun {
            agent: "alice".into(),
            agent_id: "ag-alice".into(),
            run_id: "11111111111111111111111111111111".into(),
        },
        task_id: Some("investigation".into()),
    }
}
fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[24; 32]).unwrap()
}
fn target() -> Target {
    let package = package();
    let operations: BTreeMap<_, _> = ["service-status", "service-restart", "write-service-config"]
        .into_iter()
        .map(|id| (id.into(), scope(&package, id)))
        .collect();
    let grant = Grant {
        principal: principal(),
        not_before: 90,
        expires_at: 130,
        verbs: [Verb::Discover, Verb::Propose, Verb::Invoke].into(),
        operations: operations.clone(),
    };
    Target {
        target_id: "windows-a".into(),
        ceiling_revision: "1".into(),
        allowed_verbs: grant.verbs.clone(),
        max_authority_age_seconds: 30,
        ceiling: operations,
        package,
        issuers: BTreeMap::from([(
            "issuer".into(),
            IssuerTrust {
                revision: "1".into(),
                public_keys: BTreeMap::from([(
                    "key".into(),
                    STANDARD.encode(key().public_key().as_ref()),
                )]),
                authority: IssuerAuthority {
                    revision: "1".into(),
                    assessment_revision: "1".into(),
                    observed_at: 95,
                    valid_until: 125,
                    grants: BTreeMap::from([("current".into(), grant)]),
                },
            },
        )]),
    }
}

#[test]
fn native_discovery_and_proposal_bind_understanding_even_without_executable_change() {
    let mut target = target();
    target.validate().unwrap();
    let request = |target: &Target, action| Request {
        version: VERSION.into(),
        required_features: vec![],
        request_id: "model-proof".into(),
        target_id: target.target_id.clone(),
        issuer_id: "issuer".into(),
        grant_id: "current".into(),
        principal: principal(),
        expires_at: 120,
        expected: Some(target.revisions("issuer").unwrap()),
        action,
        untrusted_rationale: "Untrusted rationale cannot change the assessment.".into(),
    };
    let signed =
        |request| serde_json::to_vec(&SignedRequest::sign(request, "key".into(), &key())).unwrap();
    let bytes = signed(request(&target, Action::Discover));
    let authenticated = target
        .authenticate("POST", Verb::Discover.path(), &bytes, 100)
        .unwrap();
    let discovery = target.discover(&authenticated).unwrap();
    assert!(
        discovery
            .operations
            .iter()
            .find(|op| op.operation_id == "service-restart")
            .unwrap()
            .definition
            .semantics
            .is_some()
    );
    let mut invocation = Invocation {
        operation_id: "service-restart".into(),
        resource_id: "service:demo".into(),
        package_sha256: revision(&target.package),
        implementation_sha256: target.package.operations["service-restart"].implementation_sha256(),
        arguments: BTreeMap::new(),
        expected_assessment_sha256: None,
    };
    let bytes = signed(request(
        &target,
        Action::Propose {
            invocation: invocation.clone(),
        },
    ));
    let authenticated = target
        .authenticate("POST", Verb::Propose.path(), &bytes, 100)
        .unwrap();
    let prepared = target.prepare(&authenticated, Usage::default()).unwrap();
    invocation = prepared.invocation;
    let before = target.package.operations["service-restart"]
        .semantic_revisions()
        .implementation;
    target
        .package
        .semantics
        .as_mut()
        .unwrap()
        .rules
        .get_mut("changed_service_execution")
        .unwrap()
        .explanation
        .push_str(" Corrected understanding.");
    assert_eq!(
        before,
        target.package.operations["service-restart"]
            .semantic_revisions()
            .implementation
    );
    let bytes = signed(request(
        &target,
        Action::Propose {
            invocation: invocation.clone(),
        },
    ));
    let authenticated = target
        .authenticate("POST", Verb::Propose.path(), &bytes, 100)
        .unwrap();
    assert_eq!(
        target
            .prepare(&authenticated, Usage::default())
            .unwrap_err()
            .code,
        RefusalCode::Stale
    );
    invocation.package_sha256 = revision(&target.package);
    let bytes = signed(request(&target, Action::Propose { invocation }));
    let authenticated = target
        .authenticate("POST", Verb::Propose.path(), &bytes, 100)
        .unwrap();
    assert_eq!(
        target
            .prepare(&authenticated, Usage::default())
            .unwrap_err()
            .code,
        RefusalCode::Stale
    );
}

#[test]
fn target_owned_full_grants_and_ceiling_are_assessed_without_changing_admission_or_risk_policy() {
    let mut target = target();
    let before = revision(&target);
    let proposed = target.issuers["issuer"].authority.grants["current"].clone();
    let assessment =
        semantics::assess_target(&target, "issuer", &principal(), Some(&proposed), &[], 100)
            .unwrap();
    assert_eq!(
        assessment["effective_authority"]["model"]["rules"]["changed_service_execution"]["status"],
        "match"
    );
    assert_eq!(before, revision(&target));
    target.ceiling.remove("write-service-config");
    let narrower =
        semantics::assess_target(&target, "issuer", &principal(), Some(&proposed), &[], 100)
            .unwrap();
    assert_eq!(
        narrower["full_proposed_authority"]["model"]["rules"]["changed_service_execution"]["status"],
        "match"
    );
    assert_eq!(
        narrower["effective_authority"]["model"]["rules"]["changed_service_execution"]["status"],
        "non_match"
    );
    assert_ne!(assessment["input_revision"], narrower["input_revision"]);
    assert!(semantics::assess_target(&target, "issuer", &principal(), None, &[], 126).is_err());
    let enables = vec!["changed_service_execution".into()];
    for (decision, expected) in [
        ("allow", Effect::Allow),
        ("deny", Effect::Deny),
        ("require_approval", Effect::Prompt),
    ] {
        let source = format!(
            "budget=100\n[[risk]]\nenables=['changed_service_execution']\ndecision='{decision}'\n"
        );
        let policy = Policy::parse(&source, Format::Toml).unwrap();
        assert_eq!(
            policy
                .evaluate_risky_route(RiskyRouteRequest {
                    service: "windows-starter",
                    agent: "alice",
                    account: "agent",
                    tactics: &[],
                    enables: &enables,
                    irreversible: false,
                    method: "POST",
                    path: Verb::Invoke.path()
                })
                .effect,
            expected
        );
    }
    // Loading every generated model creates no gateway permission.
    let registry = Arc::new(
        Registry::from_sources(
            &target
                .package
                .projections()
                .unwrap()
                .gateway
                .into_iter()
                .map(|(name, value)| (name, value.to_string()))
                .collect::<Vec<_>>(),
            &[],
        )
        .unwrap(),
    );
    let policy =
        Policy::parse_with_registry_at("budget=100", Format::Toml, Some(registry), 100000.)
            .unwrap();
    assert_eq!(
        policy
            .evaluate_gateway_request(safeyolo_proxy::policy::GatewayRequest {
                agent: "alice",
                service: "windows-starter:service-restart",
                capability: "invoke",
                method: "POST",
                path: Verb::Invoke.path()
            })
            .effect,
        Effect::Deny
    );
}

#[test]
fn model_errors_and_stale_or_invalid_native_scope_remain_explicit() {
    let package = package();
    let mut grant = permission(&package, "bad", "windows-a", "service-restart");
    grant
        .operations
        .get_mut("service-restart")
        .unwrap()
        .arguments
        .insert("service".into(), vec![json!("*")]);
    assert!(semantics::assess(&package, &[grant], &[]).is_err());
    let mut grant = permission(&package, "stale", "windows-a", "service-restart");
    grant
        .operations
        .get_mut("service-restart")
        .unwrap()
        .implementation_sha256 = "b".repeat(64);
    assert!(semantics::assess(&package, &[grant], &[]).is_err());
    let mut invalid = package.clone();
    invalid
        .operations
        .get_mut("service-restart")
        .unwrap()
        .semantics
        .as_mut()
        .unwrap()
        .effects[0]
        .effect = "log-clearing".into();
    assert!(invalid.validate().is_err());
    assert!(invalid.projections().is_err());
    let gateway = &package.projections().unwrap().gateway["service-restart"];
    let loaded = ServiceDefinition::from_value(gateway.clone()).unwrap();
    assert!(loaded.effect_model.unwrap().enforcement.is_empty());
    assert_eq!(
        gateway["host_operation_guidance"]["alternatives"]["service-status-before-control"]["steps"]
            [0]["available_from"],
        json!([])
    );
}
