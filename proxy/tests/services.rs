use safeyolo_proxy::{
    contracts::{ContractBinding, ContractRequest},
    services::*,
};
use serde_json::{Value, json};

fn documents() -> Vec<(String, String)> {
    ["minifuse", "gmail", "slack"]
        .into_iter()
        .map(|name| {
            (
                format!("{name}.yaml"),
                std::fs::read_to_string(format!(
                    "{}/../cli/src/safeyolo/services/{name}.yaml",
                    env!("CARGO_MANIFEST_DIR")
                ))
                .unwrap(),
            )
        })
        .collect()
}
fn registry() -> Registry {
    Registry::from_sources(&documents(), &[]).unwrap()
}
fn token(service: &str, capability: &str) -> TokenBinding {
    TokenBinding {
        token: "sgw_synthetic".into(),
        agent: "alice".into(),
        service: service.into(),
        capability: capability.into(),
        vault_token: "synthetic-credential-ref".into(),
        account: "test-account".into(),
    }
}
fn binding(service: &str, capability: &str) -> ContractBinding {
    ContractBinding {
        binding_id: "test-binding".into(),
        agent: "alice".into(),
        service: service.into(),
        capability: capability.into(),
        template: format!("{service}.{capability}.v1"),
        bound_values: json!({"approved_category_id":137,"approved_category":"CATEGORY_PROMOTIONS"})
            .as_object()
            .unwrap()
            .clone(),
        grantable_operations: [
            "list_feeds",
            "list_entries",
            "create_feed",
            "list_messages",
            "get_message",
        ]
        .map(str::to_owned)
        .into(),
    }
}
#[allow(clippy::too_many_arguments)]
fn decision(
    registry: &Registry,
    token: &TokenBinding,
    identity: TrustedIdentity<'_>,
    host: &str,
    target: &str,
    method: &str,
    headers: &[(String, String)],
    bindings: &[ContractBinding],
) -> GatewayDecision {
    let hosts = [
        ("api.example".into(), token.service.clone()),
        ("slack.com".into(), "slack".into()),
    ]
    .into();
    select_route(
        registry,
        &hosts,
        std::slice::from_ref(token),
        bindings,
        GatewayRequest {
            identity,
            host,
            route_mode: RouteMode::CompiledPolicy,
            request: ContractRequest {
                method,
                target,
                headers,
                body: b"",
            },
        },
    )
}
fn code(decision: GatewayDecision) -> String {
    match decision {
        GatewayDecision::PassThrough => "pass".into(),
        GatewayDecision::Selected { .. } => "selected".into(),
        GatewayDecision::Deny { code, .. } => code,
    }
}

#[test]
fn shipped_schema_preserves_risk_groups_and_declared_contract_fields() {
    let registry = registry();
    assert_eq!(registry.services.len(), 3);
    let gmail = &registry.services["gmail"];
    assert_eq!(gmail.auth.as_ref().unwrap().header, "Authorization");
    assert!(gmail.auth.as_ref().unwrap().refresh_on_401);
    let route = gmail
        .risky_routes
        .iter()
        .find(|route| route.path.ends_with("messages/*/trash"))
        .unwrap();
    assert!(!route.irreversible);
    assert_eq!(route.tactics, ["impact", "defense_evasion"]);
    assert_eq!(route.group.as_deref(), Some("Destructive actions"));
    assert!(gmail.raw["capabilities"]["read_messages"]["contract"]["operations"][1]["response"]["validators"].is_array());
    let minifuse = &registry.services["minifuse"];
    let contract = minifuse.capabilities["category_manager"]
        .contract
        .as_ref()
        .unwrap();
    assert_eq!(
        contract
            .grantable_operations()
            .map(|operation| operation.name.as_str())
            .collect::<Vec<_>>(),
        ["list_feeds", "list_entries", "create_feed"]
    );
    assert!(
        contract
            .grantable_operations()
            .all(|operation| !operation.is_prebinding_grantable())
    );
}

#[test]
fn strict_snapshot_override_and_invalid_reload_leave_previous_candidate_usable() {
    let documents = documents();
    let original = Registry::from_sources(&documents, &[]).unwrap();
    let replacement = "schema_version: 1\nname: gmail\ncapabilities: {}\n".to_owned();
    let overridden = Registry::from_sources(
        &documents,
        &[("user/gmail.yaml".into(), replacement.clone())],
    )
    .unwrap();
    assert!(overridden.services["gmail"].capabilities.is_empty());
    assert!(
        Registry::from_sources(
            &documents,
            &[("bad.yaml".into(), "schema_version: 2\nname: gmail".into())]
        )
        .is_err()
    );
    assert!(!original.services["gmail"].capabilities.is_empty());
    assert!(
        Registry::from_sources(
            &[
                ("a.yaml".into(), replacement.clone()),
                ("b.yaml".into(), replacement)
            ],
            &[]
        )
        .is_err()
    );
}

#[test]
fn token_scope_checks_precede_route_and_credential_selection() {
    let registry = registry();
    let token = token("minifuse", "reader");
    let headers = vec![("X-Auth-Token".into(), "sgw_synthetic".into())];
    assert_eq!(
        code(decision(
            &registry,
            &token,
            TrustedIdentity::Agent("alice"),
            "api.example",
            "/v1/feeds?name=chosen&%6Eame=forbidden",
            "GET",
            &headers,
            &[]
        )),
        "selected"
    );
    for (identity, expected) in [
        (TrustedIdentity::Missing, "AGENT_IDENTITY_REQUIRED"),
        (TrustedIdentity::Conflict, "AGENT_IDENTITY_CONFLICT"),
        (TrustedIdentity::Agent("bob"), "AGENT_MISMATCH"),
        (TrustedIdentity::Agent("alice"), "selected"),
    ] {
        assert_eq!(
            code(decision(
                &registry,
                &token,
                identity,
                "API.EXAMPLE",
                "/v1/feeds",
                "GET",
                &headers,
                &[]
            )),
            expected
        );
    }
    assert_eq!(
        code(decision(
            &registry,
            &token,
            TrustedIdentity::Agent("alice"),
            "api.example.",
            "/v1/feeds",
            "GET",
            &headers,
            &[]
        )),
        "GATEWAY_CONFIGURATION_ERROR"
    );
    assert_eq!(
        code(decision(
            &registry,
            &token,
            TrustedIdentity::Agent("alice"),
            "api.example",
            "/v1/feeds",
            "DELETE",
            &headers,
            &[]
        )),
        "ROUTE_DENIED"
    );
    let unknown = vec![("X-Auth-Token".into(), "sgw_unknown".into())];
    assert_eq!(
        code(decision(
            &registry,
            &token,
            TrustedIdentity::Missing,
            "api.example",
            "/v1/feeds",
            "GET",
            &unknown,
            &[]
        )),
        "INVALID_TOKEN"
    );
    let ordinary = vec![("Authorization".into(), "Bearer ordinary-credential".into())];
    assert_eq!(
        code(decision(
            &registry,
            &token,
            TrustedIdentity::Missing,
            "other.example",
            "/bad//path",
            "GET",
            &ordinary,
            &[]
        )),
        "pass"
    );
    let misplaced = vec![("X-Unrelated".into(), "Bearer sgw_synthetic".into())];
    let result = decision(
        &registry,
        &token,
        TrustedIdentity::Agent("alice"),
        "other.example",
        "/v1/feeds",
        "GET",
        &misplaced,
        &[],
    );
    assert!(
        matches!(result,GatewayDecision::Deny {status:503,strip_headers,..} if strip_headers == ["X-Unrelated"])
    );
}

#[test]
fn selection_returns_reference_and_risk_without_authorizing_injection() {
    let registry = registry();
    let token = token("gmail", "read_and_send");
    let headers = vec![("Authorization".into(), "Anything sgw_synthetic".into())];
    let GatewayDecision::Selected { credential } = decision(
        &registry,
        &token,
        TrustedIdentity::Agent("alice"),
        "api.example",
        "/gmail/v1/users/me/messages/send",
        "POST",
        &headers,
        &[],
    ) else {
        panic!("expected selection")
    };
    assert_eq!(credential.vault_token, "synthetic-credential-ref");
    assert!(!credential.allow_http);
    assert_eq!(credential.auth_scheme, "Bearer");
    assert!(credential.risky_route.unwrap().irreversible);
}

#[test]
fn compiled_contract_scope_preserves_names_values_templates_and_agent() {
    let registry = registry();
    let service = &registry.services["minifuse"];
    let token = token("minifuse", "category_manager");
    assert!(compile_routes(service, &token, &[]).is_empty());
    let mut binding = binding("minifuse", "category_manager");
    binding.grantable_operations =
        vec!["list_feeds".into(), "list_feeds".into(), "get_feed".into()];
    let routes = compile_routes(service, &token, &[binding.clone()]);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].path, "/v1/categories/137/feeds");
    binding.agent = "bob".into();
    assert!(compile_routes(service, &token, &[binding.clone()]).is_empty());
    binding.agent = "alice".into();
    binding.template = "old-template".into();
    assert!(compile_routes(service, &token, &[binding.clone()]).is_empty());
    binding.template = "minifuse.category_manager.v1".into();
    for value in [
        json!("*"),
        json!("../137"),
        json!(null),
        json!("137/feeds"),
        json!([137]),
    ] {
        binding
            .bound_values
            .insert("approved_category_id".into(), value);
        assert!(compile_routes(service, &token, &[binding.clone()]).is_empty());
    }
}

#[test]
fn path_matching_preserves_source_case_and_wildcard_behavior() {
    assert!(!resource_matches(
        "/api/chat.postMessage",
        "/api/chat.postMessage"
    ));
    assert!(resource_matches(
        "/api/chat.postmessage",
        "/api/chat.postMessage"
    ));
    assert!(!resource_matches(
        "slack:/api/chat.postMessage",
        "slack:/api/chat.postMessage"
    ));
    assert!(resource_matches(
        "SLACK:/api/chat.postmessage",
        "slack:/api/chat.postMessage"
    ));
    assert!(resource_matches("/a/b/c", "/a/*"));
    assert!(resource_matches("/a", "/a/**"));
    assert!(!resource_matches("/a", "/a/*"));
    assert_eq!(normalize_path("/a/%2E%2E/b/"), "/b");
    assert_eq!(normalize_path("/ａ／ｂ"), "/a/b");
    assert_eq!(normalize_path("/%FF%C3%A9"), "/%FFé");
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON to the baseline environment"]
fn differential_shipped_routes_compiler_and_resource_normalization() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let registry = registry();
    let mut scenarios = Vec::new();
    let paths = [
        "/v1/feeds",
        "/v1/feeds/42",
        "/v1/categories/137/feeds",
        "/v1/categories/138/feeds",
        "/v1/categories/137/entries",
        "/gmail/v1/users/me/messages",
        "/gmail/v1/users/me/messages/42",
        "/gmail/v1/users/me/labels",
        "/gmail/v1/users/me/settings/forwardingAddresses",
        "/api/chat.postMessage",
        "/api/chat.postmessage",
        "/api/conversations.list",
        "/api/admin.invite",
        "//v1//feeds/",
        "/v1/../v1/feeds",
        "/v1/%66eeds",
    ];
    for (name, service) in &registry.services {
        for capability in service.capabilities.keys() {
            for variant in [
                "none",
                "valid",
                "other-agent",
                "old-template",
                "missing-value",
                "one-operation",
            ] {
                let mut state = binding(name, capability);
                match variant {
                    "other-agent" => state.agent = "bob".into(),
                    "old-template" => state.template = "old".into(),
                    "missing-value" => state.bound_values.clear(),
                    "one-operation" => state.grantable_operations = vec!["list_feeds".into()],
                    _ => {}
                }
                let states = if variant == "none" {
                    vec![]
                } else {
                    vec![state]
                };
                let requests: Vec<_> = paths
                    .iter()
                    .flat_map(|path| {
                        ["GET", "POST", "DELETE", "get"]
                            .map(|method| json!({"path":path,"method":method}))
                    })
                    .collect();
                scenarios.push(json!({"service":name,"capability":capability,"bindings":states,"requests":requests}));
            }
        }
    }
    let normalization = [
        "/A",
        "/%41",
        "/%2E/a",
        "/a/%2E%2E/b",
        "/a/../b",
        "/a//b/",
        "/a%2Fb",
        "/%FF",
        "/%C3%A9",
        "/%FF%C3%A9",
        "/a\\b",
        "/a?x=1#x",
        "/ａ／ｂ",
        "foo",
        "/a%25bb",
        "/a%2F../b",
        "/a/%2F../b",
        "/a/%2E%2F../b",
    ];
    let input =
        json!({"documents":documents(),"scenarios":scenarios,"normalization":normalization});
    let script = r#"
import json,sys,tempfile,pathlib
from types import SimpleNamespace
from unittest.mock import patch
import yaml
from safeyolo.core.service_loader import ServiceDefinition
from safeyolo.detection.matching import normalize_path, matches_resource_pattern
from safeyolo.policy.compiler import _compile_capability_routes
from safeyolo.policy.engine import PolicyEngine
x=json.load(sys.stdin)
services={}
for filename,document in x['documents']:
 s=ServiceDefinition.from_dict(yaml.safe_load(document)); services[s.name]=s
registry=SimpleNamespace(get_service=services.get)
output=[]
for scenario in x['scenarios']:
 service=services[scenario['service']]; capability=service.capabilities[scenario['capability']]
 states=[state for state in scenario['bindings'] if state['agent']=='alice']
 permissions=[]
 with patch('safeyolo.policy.compiler._get_service_registry',return_value=registry):
  _compile_capability_routes({'synthetic':{'agent':'alice','service':service.name,'capability':capability.name}}, {'alice':{'contract_bindings':states}},permissions)
 with tempfile.TemporaryDirectory() as directory:
  path=pathlib.Path(directory)/'policy.json'; path.write_text(json.dumps({'permissions':permissions}))
  engine=PolicyEngine(baseline_path=path); engine._loader.stop_watcher()
  outcomes=[]
  for r in scenario['requests']:
   compiled=engine.evaluate_gateway_request(service.name,capability.name,'alice',r['method'],r['path']).effect=='allow'
   fallback=any(('*' in route.methods or r['method'].upper() in route.methods) and matches_resource_pattern(r['path'],route.path) for route in capability.routes)
   risky=next((route.path for route in service.risky_routes if ('*' in route.methods or r['method'].upper() in route.methods) and matches_resource_pattern(r['path'],route.path)),None)
   outcomes.append([compiled,fallback,risky])
  engine.done()
 output.append({'routes':[{'methods':p['condition']['method'],'path':p['resource'].split(':',1)[1]} for p in permissions], 'outcomes':outcomes})
json.dump({'scenarios':output,'normalization':[normalize_path(p) for p in x['normalization']]},sys.stdout)
"#;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child = Command::new(
        std::env::var_os("SAFEYOLO_POLICY_PYTHON").expect("set SAFEYOLO_POLICY_PYTHON"),
    )
    .args(["-c", script])
    .env(
        "PYTHONPATH",
        format!("{}:{}", root.join("cli/src").display(), root.display()),
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&input).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    for (index, scenario) in scenarios.iter().enumerate() {
        let name = scenario["service"].as_str().unwrap();
        let cap = scenario["capability"].as_str().unwrap();
        let service = &registry.services[name];
        let token = token(name, cap);
        let states: Vec<ContractBinding> =
            serde_json::from_value(scenario["bindings"].clone()).unwrap();
        let routes = compile_routes(service, &token, &states);
        let actual: Vec<_> = routes
            .iter()
            .map(|route| json!({"methods":route.methods,"path":route.path}))
            .collect();
        assert_eq!(
            json!(actual),
            expected["scenarios"][index]["routes"],
            "routes {scenario}"
        );
        for (request_index, request) in scenario["requests"].as_array().unwrap().iter().enumerate()
        {
            let path = request["path"].as_str().unwrap();
            let method = request["method"].as_str().unwrap();
            let compiled = routes.iter().any(|route| {
                method_matches(method, &route.methods)
                    && resource_matches(
                        &format!("{name}:{path}"),
                        &format!("{name}:{}", route.path),
                    )
            });
            let fallback = service.capabilities[cap].routes.iter().any(|route| {
                method_matches(method, &route.methods) && resource_matches(path, &route.path)
            });
            let risky = service
                .risky_routes
                .iter()
                .find(|route| {
                    method_matches(method, &route.methods) && resource_matches(path, &route.path)
                })
                .map(|route| route.path.as_str());
            assert_eq!(
                json!([compiled, fallback, risky]),
                expected["scenarios"][index]["outcomes"][request_index],
                "{name}/{cap} scenario {index}: {request}"
            );
        }
    }
    for (index, path) in normalization.iter().enumerate() {
        assert_eq!(
            json!(normalize_path(path)),
            expected["normalization"][index],
            "path {path}"
        );
    }
    eprintln!(
        "Compared {} shipped service/compiler scenarios, {} route requests and {} normalized paths with Python",
        scenarios.len(),
        scenarios.len() * paths.len() * 4,
        normalization.len()
    );
}
