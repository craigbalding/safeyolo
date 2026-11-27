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
        effects::assessment::ResourceScopes,
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
        updates: None,
        checks: Default::default(),
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

fn task_package() -> Package {
    let mut package = package();
    let mut operation = package.operations["fixed-executable"].clone();
    operation.arguments.clear();
    operation.resources = ["task:workspace".into()].into();
    operation.execution.argv = vec![Word::Literal {
        value: "untrusted task".into(),
    }];
    operation.execution.environment.clear();
    operation.execution.identity.principal = "task-account".into();
    operation.execution.resources.processes = 2;
    operation.execution.filesystem = Filesystem {
        read: vec!["/selected/input".into()],
        write: vec!["/selected/work".into()],
    };
    operation.execution.network = Network {
        destinations: vec![NetworkDestination {
            host: "selected.example".into(),
            port: 443,
            transport: NetworkTransport::Tcp,
        }],
        listeners: vec![NetworkListener {
            address: "0.0.0.0".parse().unwrap(),
            port: 8080,
            transport: NetworkTransport::Tcp,
        }],
        listener_handoff: None,
        ipc: vec![],
    };
    operation.execution.broader = [BroaderBound::NetworkIpc].into();
    operation.execution.delegated_services.clear();
    operation.effects.clear();
    operation.semantics = None;
    package.operations = BTreeMap::from([("task:inspect".into(), operation)]);
    package.semantics = None;
    package.validate().unwrap();
    package
}

#[test]
fn native_task_authority_is_assessed_without_program_annotations_or_intent() {
    let mut package = task_package();
    let grants = [permission(
        &package,
        "current",
        "selected-host",
        "task:inspect",
    )];
    let result = assess(&package, &grants);
    assert_eq!(result["model"]["status"], "uncharacterised");
    let model = &result["native_authority"]["model"];
    let effects = model["direct"][0]["possible_effects"].as_array().unwrap();
    for effect in [
        "read_files",
        "write_files",
        "execute",
        "connect",
        "listen",
        "children",
    ] {
        assert!(effects.contains(&json!(effect)), "{model}");
    }
    assert_eq!(
        model["rules"]["file_disclosure_listener"]["status"],
        "match"
    );
    assert_eq!(
        model["direct"][0]["scopes"]["account"]["target"],
        json!({"kind":"known","value":"selected-host"})
    );
    assert!(
        model["direct"][0]["execution_authority"]
            .as_str()
            .unwrap()
            .contains("/selected/input")
    );
    assert!(
        model["direct"][0]["unresolved_conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("reach remain unobserved"))
    );
    // Empty or favorable program annotations cannot remove native potential.
    package.semantics = Some(HostSemantics {
        sources: Default::default(),
        resources: Default::default(),
        rules: Default::default(),
        alternatives: Default::default(),
        gaps: vec![],
    });
    let annotated = assess(
        &package,
        &[permission(
            &package,
            "current",
            "selected-host",
            "task:inspect",
        )],
    );
    assert_eq!(annotated["native_authority"], result["native_authority"]);
    package
        .operations
        .get_mut("task:inspect")
        .unwrap()
        .execution
        .filesystem
        .read
        .push("/changed/input".into());
    assert!(
        semantics::assess(&package, &grants, &[])
            .unwrap_err()
            .to_string()
            .contains("stale operation pin")
    );
}

#[test]
fn native_broader_channels_are_assessed_with_empty_selectors() {
    let mut package = package();
    package.semantics = None;
    for operation in package.operations.values_mut() {
        operation.semantics = None;
    }
    // The maintained Windows operations use account permissions rather than
    // selector confinement. Challenge every operation with that same shape.
    for (id, operation) in &package.operations {
        let e = &operation.execution;
        assert!(e.network.destinations.is_empty());
        assert!(e.network.listeners.is_empty());
        assert!(e.network.ipc.is_empty());
        assert!(e.delegated_services.is_empty());
        let result = assess(
            &package,
            &[permission(&package, "current", "windows-host", id)],
        );
        let model = &result["native_authority"]["model"];
        let effects = model["direct"][0]["possible_effects"].as_array().unwrap();
        for effect in [
            "read_files",
            "broader_network_ipc",
            "broader_delegated_services",
        ] {
            assert!(effects.contains(&json!(effect)), "{id}: {model}");
        }
        for effect in ["connect", "listen", "ipc"] {
            assert!(!effects.contains(&json!(effect)), "{id}: {model}");
        }
        for rule in [
            "file_disclosure_broader_network_ipc",
            "file_disclosure_broader_delegated_services",
        ] {
            assert_eq!(model["rules"][rule]["status"], "match", "{id}: {model}");
        }
    }
    // Broader flags do not invent specific directions on a backend that
    // qualifies them more narrowly. With no such flags there is no potential
    // broader-channel disclosure at all.
    let mut bounded = task_package();
    let operation = bounded.operations.get_mut("task:inspect").unwrap();
    operation.execution.network = Network {
        destinations: vec![],
        listeners: vec![],
        listener_handoff: None,
        ipc: vec![],
    };
    operation.execution.broader = [BroaderBound::NetworkIpc].into();
    let result = assess(
        &bounded,
        &[permission(&bounded, "current", "unix-host", "task:inspect")],
    );
    let effects = result["native_authority"]["model"]["direct"][0]["possible_effects"]
        .as_array()
        .unwrap();
    assert!(effects.contains(&json!("broader_network_ipc")));
    assert!(!effects.contains(&json!("connect")));
    assert!(!effects.contains(&json!("listen")));
    bounded
        .operations
        .get_mut("task:inspect")
        .unwrap()
        .execution
        .broader
        .clear();
    let result = assess(
        &bounded,
        &[permission(&bounded, "current", "unix-host", "task:inspect")],
    );
    for rule in [
        "file_disclosure_broader_network_ipc",
        "file_disclosure_broader_delegated_services",
    ] {
        assert!(result["native_authority"]["model"]["rules"][rule].is_null());
    }
}

#[test]
fn native_task_composition_preserves_target_account_and_disconnected_bounds() {
    let mut package = task_package();
    let mut reader = package.operations["task:inspect"].clone();
    reader.execution.filesystem.write.clear();
    reader.execution.network.destinations.clear();
    reader.execution.network.listeners.clear();
    reader.execution.broader.clear();
    reader.execution.resources.processes = 1;
    let mut listener = reader.clone();
    listener.execution.filesystem.read.clear();
    listener.execution.network = package.operations["task:inspect"].execution.network.clone();
    listener.execution.network.destinations.clear();
    listener.execution.broader.insert(BroaderBound::NetworkIpc);
    package.operations = BTreeMap::from([("read".into(), reader), ("listen".into(), listener)]);
    let mut grants = vec![
        permission(&package, "reader", "host-a", "read"),
        permission(&package, "listener", "host-a", "listen"),
    ];
    let rule = |package: &Package, grants: &[Authority]| {
        assess(package,grants)["native_authority"]["model"]["rules"]["file_disclosure_listener"]["status"].clone()
    };
    assert_eq!(rule(&package, &grants), "match");
    grants[1].target_id = "host-b".into();
    assert_eq!(rule(&package, &grants), "non_match");
    grants[1].target_id = "host-a".into();
    package
        .operations
        .get_mut("listen")
        .unwrap()
        .execution
        .identity
        .principal = "other-account".into();
    grants[1]
        .operations
        .insert("listen".into(), scope(&package, "listen"));
    assert_eq!(rule(&package, &grants), "non_match");
    let disconnected = assess(&package, &grants[..1]);
    assert_eq!(
        disconnected["native_authority"]["model"]["direct"][0]["possible_effects"],
        json!(["execute", "read_files"])
    );
    assert_eq!(rule(&package, &[]), "non_match");
}

#[test]
fn unannotated_future_task_class_is_included_without_an_adopted_member() {
    let mut target = target();
    target.package = task_package();
    let mut ceiling = target.package.operations["task:inspect"].clone();
    let ceiling_scope = scope(&target.package, "task:inspect");
    let family = OperationFamily {
        prefix: "task:".into(),
        excluded: Default::default(),
        rule: UpdateRule {
            ceiling: ceiling.clone(),
            allow_narrower: true,
            allow_implementation_updates: false,
            allow_agent_code: true,
            agent_dependency_bytes: 1024,
        },
        scope: ceiling_scope,
    };
    ceiling.execution.network.destinations.clear();
    ceiling.execution.network.listeners.clear();
    ceiling.execution.broader.clear();
    target
        .package
        .operations
        .insert("task:inspect".into(), ceiling);
    let current_scope = scope(&target.package, "task:inspect");
    target.ceiling = BTreeMap::from([("task:inspect".into(), current_scope.clone())]);
    target.families = vec![family.clone()];
    let trust = target.issuers.get_mut("issuer").unwrap();
    let grant = trust.authority.grants.get_mut("current").unwrap();
    grant.operations = target.ceiling.clone();
    grant.families = vec![family];
    let result = semantics::assess_target(&target, "issuer", &principal(), None, &[], 100).unwrap();
    assert_eq!(
        result["future_family_ceilings"].as_array().unwrap().len(),
        1
    );
    assert!(result["effective_authority"]["native_authority"]["model"]["rules"]["file_disclosure_listener"].is_null());
    assert_eq!(
        result["standing_potential_authority"]["native_authority"]["model"]["rules"]["file_disclosure_listener"]
            ["status"],
        "match"
    );
    assert_ne!(
        result["effective_authority"]["native_authority"]["model_revision"],
        result["standing_potential_authority"]["native_authority"]["model_revision"]
    );
    assert!(semantics::assess_target(&target, "issuer", &principal(), None, &[], 126).is_err());
    assert!(
        target
            .package
            .operations
            .keys()
            .all(|name| !name.starts_with("assessment:"))
    );
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
    let mut package = self::package();
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

#[test]
fn registry_composition_uses_the_full_view_set_and_actual_user_namespace() {
    for operation in ["registry-query-machine", "registry-query-user"] {
        let mut package = package();
        let mut other = package.operations[operation].clone();
        let effect = NamedEffect {
            description: "Read the same selected registry value for a second query".into(),
            persists_after_access: false,
            evidence: vec!["package".into()],
        };
        other.effects = BTreeMap::from([("registry_confirmation".into(), effect)]);
        other.semantics.as_mut().unwrap().effects[0].effect = "registry_confirmation".into();
        package.operations.insert("registry-confirm".into(), other);
        package.semantics.as_mut().unwrap().rules.insert("registry_same_scope".into(),serde_json::from_value(json!({"when":{"kind":"all_effects_same_scope","resource":"registry","effects":["disclosure","registry_confirmation"]},"prerequisites":["Selected key view and aliases have been reviewed"],"consequence":"Both permissions can query the same selected registry value.","explanation":"Compare complete view choices, target and actual user namespace.","evidence":["package"],"gaps":[]})).unwrap());
        let mut first = permission(&package, "first", "windows-a", operation);
        let mut second = permission(&package, "second", "windows-a", "registry-confirm");
        scope_from(&mut second, "registry-confirm")
            .arguments
            .insert("view".into(), vec![json!("64")]);
        assert_eq!(
            assess(&package, &[first.clone(), second.clone()])["model"]["rules"]["registry_same_scope"]
                ["status"],
            "match"
        );
        scope_from(&mut first, operation)
            .arguments
            .insert("view".into(), vec![json!("32")]);
        assert_eq!(
            assess(&package, &[first.clone(), second.clone()])["model"]["rules"]["registry_same_scope"]
                ["status"],
            if operation.ends_with("machine") {
                "non_match"
            } else {
                "match"
            }
        );
        let other = package.operations.get_mut("registry-confirm").unwrap();
        other.execution.identity.principal = "S-1-5-21-100-200-300-1002".into();
        second = permission(&package, "second", "windows-a", "registry-confirm");
        assert_eq!(
            assess(
                &package,
                &[
                    permission(&package, "first", "windows-a", operation),
                    second
                ]
            )["model"]["rules"]["registry_same_scope"]["status"],
            if operation.ends_with("user") {
                "non_match"
            } else {
                "match"
            }
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
    let retained =
        semantics::assess(&package, &[runner], std::slice::from_ref(&observation)).unwrap();
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
    let mut target = target();
    let grants = &mut target.issuers.get_mut("issuer").unwrap().authority.grants;
    let mut expired = grants["current"].clone();
    expired.expires_at = 99;
    expired
        .operations
        .retain(|id, _| id == "write-service-config");
    grants
        .get_mut("current")
        .unwrap()
        .operations
        .remove("write-service-config");
    grants.insert("expired-writer".into(), expired);
    let target_assessment =
        semantics::assess_target(&target, "issuer", &principal(), None, &[observation], 100)
            .unwrap();
    assert_eq!(
        target_assessment["effective_authority"]["model"]["rules"]["changed_service_execution"]["status"],
        "match"
    );
    assert!(
        target_assessment["current_grants"]
            .as_array()
            .unwrap()
            .iter()
            .all(|grant| grant["grant_id"] != "expired-writer")
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
            agent_id: "ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
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
        allow_run_refresh: false,
        families: Vec::new(),
        principal: principal(),
        not_before: 90,
        expires_at: 130,
        verbs: [Verb::Discover, Verb::Propose, Verb::Invoke].into(),
        operations: operations.clone(),
    };
    Target {
        families: Vec::new(),
        catalogue: None,
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
        expected: Some(
            target
                .request_revisions("issuer", "current", &action)
                .unwrap(),
        ),
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
        operation_sha256: target.package.operation_sha256("service-restart").unwrap(),
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
    invocation.operation_sha256 = target.package.operation_sha256("service-restart").unwrap();
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
    let mut unavailable = target.clone();
    unavailable
        .ceiling
        .get_mut("service-restart")
        .unwrap()
        .budgets
        .timeout_seconds = 0;
    let unavailable =
        semantics::assess_target(&unavailable, "issuer", &principal(), None, &[], 100).unwrap();
    assert!(
        unavailable["effective_authority"]["model"]["direct"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["permission"]["operation"] != "service-restart")
    );
    let mut proposal = permission(&target.package, "proposal", "windows-a", "service-status");
    proposal.proposed = true;
    let proposal = assess(&target.package, &[proposal]);
    assert_eq!(
        proposal["alternatives"]["service-status-before-control"]["steps"][0]["available_from"],
        json!([])
    );
    assert_eq!(proposal["alternatives"]["service-status-before-control"]["steps"][0]["within_proposed_authority"].as_array().unwrap().len(),1);
    let enables = vec!["changed_service_execution".into()];
    for (decision, expected) in [
        ("allow", Effect::Allow),
        ("deny", Effect::Deny),
        ("require_approval", Effect::Prompt),
    ] {
        let source = format!(
            "budget=100\n[hosts]\n[[risk]]\nenables=['changed_service_execution']\ndecision='{decision}'\n"
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
fn family_assessment_includes_the_future_ceiling_and_preserves_current_target_checks() {
    let mut target = target();
    target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("current")
        .unwrap()
        .operations
        .remove("write-service-config");
    let mut proposed = target.issuers["issuer"].authority.grants["current"].clone();
    let mut writer = target.package.operations["write-service-config"].clone();
    writer.enforcement.unresolved.clear();
    target
        .package
        .operations
        .insert("future:write".into(), writer.clone());
    proposed.families.push(OperationFamily {
        prefix: "future:".into(),
        excluded: Default::default(),
        rule: UpdateRule {
            ceiling: writer,
            allow_narrower: true,
            allow_implementation_updates: true,
            allow_agent_code: false,
            agent_dependency_bytes: 0,
        },
        scope: scope(&target.package, "future:write"),
    });
    let assessment =
        semantics::assess_target(&target, "issuer", &principal(), Some(&proposed), &[], 100)
            .unwrap();
    assert_eq!(assessment["future_family_ceilings"][0]["prefix"], "future:");
    assert_eq!(
        assessment["full_proposed_authority"]["model"]["rules"]["changed_service_execution"]["status"],
        "match"
    );
    assert_eq!(
        assessment["effective_authority"]["model"]["rules"]["changed_service_execution"]["status"],
        "non_match"
    );
    // No currently published family member is needed to expose that ceiling.
    target.package.operations.remove("future:write");
    let assessment =
        semantics::assess_target(&target, "issuer", &principal(), Some(&proposed), &[], 100)
            .unwrap();
    assert_eq!(
        assessment["full_proposed_authority"]["model"]["rules"]["changed_service_execution"]["status"],
        "match"
    );
    // A model cannot supply absent native qualification evidence.
    target
        .package
        .operations
        .get_mut("service-restart")
        .unwrap()
        .required_checks
        .insert("qualified".into());
    let pinned = scope(&target.package, "service-restart");
    target
        .ceiling
        .insert("service-restart".into(), pinned.clone());
    target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("current")
        .unwrap()
        .operations
        .insert("service-restart".into(), pinned);
    assert!(
        !target
            .effective_operations(&target.issuers["issuer"].authority.grants["current"])
            .contains_key("service-restart")
    );
    target
        .ceiling
        .get_mut("service-restart")
        .unwrap()
        .checks
        .insert("qualified".into());
    target
        .issuers
        .get_mut("issuer")
        .unwrap()
        .authority
        .grants
        .get_mut("current")
        .unwrap()
        .operations
        .get_mut("service-restart")
        .unwrap()
        .checks
        .insert("qualified".into());
    assert!(
        target
            .effective_operations(&target.issuers["issuer"].authority.grants["current"])
            .contains_key("service-restart")
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

#[test]
fn current_private_policy_assessment_uses_the_adopted_host_explanations_and_alternatives() {
    use safeyolo_proxy::{
        policy::capabilities,
        services::effects::policy::{self, Candidate},
    };
    let package = package();
    let mut definition = package.projections().unwrap().gateway["service-restart"].clone();
    definition["default_host"] = json!("windows.example.invalid");
    let registry = Arc::new(
        Registry::from_sources(&[("host.yaml".into(), definition.to_string())], &[]).unwrap(),
    );
    let source = "budget=100\n[hosts.'windows.example.invalid']\nservice='windows-starter:service-restart'\negress='allow'\n[agents.alice]\nagent_id='ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[agents.alice.services.'windows-starter:service-restart']\ncapability='invoke'\ntoken='ref'\n";
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("policy.toml");
    std::fs::write(&path, source).unwrap();
    let adopted = Policy::from_native_path(&path).unwrap();
    let snapshot = adopted
        .full_snapshot(
            source,
            &path,
            "sy-11111111111111111111111111111111",
            &principal().run,
        )
        .unwrap();
    let candidate:Candidate=serde_json::from_value(json!({"snapshot_request_id":"req-fixture","source":source,"definition_version":capabilities::discover()["definition_version"]})).unwrap();
    let report = policy::assess(&snapshot, &candidate, Some(registry), &[]).unwrap();
    assert_eq!(report["valid"], true, "{report}");
    let services = report["services"]["after"].as_array().unwrap();
    let host = services
        .iter()
        .find(|entry| entry["service"] == "windows-starter:service-restart")
        .unwrap();
    assert_eq!(
        host["model"]["effect_definitions"]["execute"],
        definition["effect_model"]["effects"]["execute"]
    );
    let recipe = host["alternatives"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == "service-status-before-control")
        .unwrap();
    assert_eq!(
        recipe["steps"][0]["required_arguments"],
        json!({"service":"Demo"})
    );
    assert_eq!(recipe["access"], "unverified_native_authority");
    definition["host_operation_guidance"]["alternatives"]["service-status-before-control"] =
        json!(false);
    let malformed = Arc::new(
        Registry::from_sources(&[("host.yaml".into(), definition.to_string())], &[]).unwrap(),
    );
    assert!(
        policy::assess(&snapshot, &candidate, Some(malformed), &[])
            .unwrap_err()
            .to_string()
            .contains("host alternative")
    );
}
