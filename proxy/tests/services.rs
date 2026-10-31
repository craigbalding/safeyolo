use safeyolo_proxy::{
    contracts::{ContractBinding, ContractRequest},
    credentials::Secret,
    policy::{Format, Policy},
    services::*,
};
use serde_json::{Value, json};

fn documents() -> Vec<(String, String)> {
    ["minifuse", "gmail", "slack", "codex", "claude"]
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
        token: Secret::new("sgw_synthetic"),
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
        ("api.example".into(), token.service.as_str().unwrap().into()),
        ("slack.com".into(), "slack".into()),
    ]
    .into();
    let routes = registry
        .services
        .get(token.service.as_str().unwrap())
        .map_or_else(Vec::new, |service| compile_routes(service, token, bindings));
    let policy = Policy::parse("{\"permissions\":[]}", Format::Json)
        .unwrap()
        .with_gateway_routes(&routes);
    select_route(
        registry,
        &hosts,
        std::slice::from_ref(token),
        bindings,
        GatewayRequest {
            identity,
            host,
            route_mode: RouteMode::CompiledPolicy(&policy),
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
        GatewayDecision::Compatibility { field } => format!("compatibility:{field:?}"),
    }
}

#[test]
fn shipped_schema_preserves_risk_groups_and_declared_contract_fields() {
    let registry = registry();
    assert_eq!(registry.services.len(), 5);
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
fn native_subscription_services_select_only_their_inference_operations() {
    let registry = registry();
    for (service, host, paths, refused) in [
        (
            "codex",
            "chatgpt.com",
            [
                "/backend-api/codex/responses",
                "/backend-api/codex/responses/compact",
            ],
            "/backend-api/accounts",
        ),
        (
            "claude",
            "api.anthropic.com",
            ["/v1/messages?beta=true", "/v1/messages/count_tokens"],
            "/api/oauth/claude_cli/create_api_key",
        ),
    ] {
        let definition = &registry.services[service];
        assert_eq!(definition.default_host, host);
        let auth = definition.auth.as_ref().unwrap();
        assert_eq!(auth.kind, "bearer");
        assert!(!auth.allow_http);
        assert!(auth.refresh_on_401);
        let token = token(service, "inference");
        let headers = [("Authorization".into(), "Bearer sgw_synthetic".into())];
        for path in paths {
            assert_eq!(
                code(decision(
                    &registry,
                    &token,
                    TrustedIdentity::Agent("alice"),
                    "api.example",
                    path,
                    "POST",
                    &headers,
                    &[]
                )),
                "selected"
            );
            assert_eq!(
                code(decision(
                    &registry,
                    &token,
                    TrustedIdentity::Agent("alice"),
                    "api.example",
                    path,
                    "GET",
                    &headers,
                    &[]
                )),
                "ROUTE_DENIED"
            );
        }
        assert_eq!(
            code(decision(
                &registry,
                &token,
                TrustedIdentity::Agent("alice"),
                "api.example",
                refused,
                "POST",
                &headers,
                &[]
            )),
            "ROUTE_DENIED"
        );
    }
}

#[test]
fn claude_startup_configuration_keeps_gateway_routes_scoped() {
    let registry = registry();
    let token = token("claude", "inference");
    let headers = [("Authorization".into(), "Bearer sgw_synthetic".into())];
    for (method, path) in [
        ("GET", "/api/claude_cli/bootstrap"),
        ("GET", "/api/claude_code/policy_limits"),
        ("GET", "/api/claude_code/settings"),
        ("POST", "/api/eval/sdk-zAZezfDKGoZuXXKe"),
    ] {
        for candidate in ["GET", "POST", "PUT"] {
            assert_eq!(
                code(decision(
                    &registry,
                    &token,
                    TrustedIdentity::Agent("alice"),
                    "api.example",
                    path,
                    candidate,
                    &headers,
                    &[],
                )),
                if candidate == method {
                    "selected"
                } else {
                    "ROUTE_DENIED"
                },
                "{candidate} {path}",
            );
        }
    }
    for path in [
        "/api/eval/another-client",
        "/api/eval/sdk-zazezfdkgozuxxke",
        "/api/eval-authed/sdk-zAZezfDKGoZuXXKe",
        "/api/claude_code/settings/other",
        "/api/oauth/claude_cli/create_api_key",
    ] {
        for method in ["GET", "POST"] {
            assert_eq!(
                code(decision(
                    &registry,
                    &token,
                    TrustedIdentity::Agent("alice"),
                    "api.example",
                    path,
                    method,
                    &headers,
                    &[],
                )),
                "ROUTE_DENIED",
                "{method} {path}",
            );
        }
    }
}

#[test]
fn yaml_merge_keys_retain_binding_constraints_and_authored_precedence() {
    let source = r#"schema_version: 1
name: example
default_host: api.example
auth: {type: bearer}
project_constraint: &project_constraint {equals_var: project}
other_constraint: &other_constraint {equals_var: other}
capabilities:
  read:
    routes: []
    contract:
      template: restricted-project
      bindings:
        project: {type: string}
        other: {type: string}
      enforcement: {request_shape: enforced}
      operations:
        - name: read
          request:
            method: GET
            path: /items
            query:
              allow:
                project: {MERGE}
"#;
    let token = token("example", "read");
    let binding = ContractBinding {
        binding_id: "merged-binding".into(),
        agent: "alice".into(),
        service: "example".into(),
        capability: "read".into(),
        template: "restricted-project".into(),
        bound_values: json!({"project":"approved","other":"other"})
            .as_object()
            .unwrap()
            .clone(),
        grantable_operations: vec!["read".into()],
    };
    let headers = [("authorization".into(), "Bearer sgw_synthetic".into())];
    for (merge, allowed) in [
        ("<<: *project_constraint", "approved"),
        ("<<: [*project_constraint, *other_constraint]", "approved"),
        ("<<: *project_constraint, equals_var: other", "other"),
        ("equals_var: other, <<: *project_constraint", "other"),
    ] {
        let registry = Registry::from_sources(
            &[("example.yaml".into(), source.replace("MERGE", merge))],
            &[],
        )
        .unwrap();
        for value in ["approved", "other", "forbidden"] {
            let target = format!("/items?project={value}");
            let selected = decision(
                &registry,
                &token,
                TrustedIdentity::Agent("alice"),
                "api.example",
                &target,
                "GET",
                &headers,
                std::slice::from_ref(&binding),
            );
            assert_eq!(
                code(selected),
                if value == allowed {
                    "selected"
                } else {
                    "CONTRACT_VIOLATION"
                },
                "{merge}: {value}"
            );
            let unbound = decision(
                &registry,
                &token,
                TrustedIdentity::Agent("alice"),
                "api.example",
                &target,
                "GET",
                &headers,
                &[],
            );
            // Compiled routes require resolved binding values before the
            // contract checker is reached.
            assert_eq!(code(unbound), "ROUTE_DENIED", "{merge}: {value}");
        }
    }
    assert!(ServiceDefinition::from_yaml(&source.replace("MERGE", "<<: 12")).is_err());
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
    assert_eq!(credential.auth_kind.as_deref(), Some("bearer"));
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
fn retained_stateful_names_never_compile_routes_in_a_mixed_contract() {
    let service = ServiceDefinition::from_value(json!({
        "schema_version":1,"name":"mixed","capabilities":{"test":{
            "routes":[{"methods":"*","path":"/**"}],
            "contract":{
                "template":"mixed.test.v1",
                "operations":[
                    {"name":"read","request":{"path":"/read"}},
                    {"name":"path_state","request":{"path":"/path/{id}","path_params":{"id":{"in_state_set":"ids"}}}},
                    {"name":"query_state","request":{"path":"/query","query":{"allow":{"id":{"in_state_set":"ids"}}}}},
                    {"name":"body_state","request":{"method":"POST","path":"/body","body":{"allow":{"id":{"in_state_set":"ids"}}}}},
                    {"name":"capture","requires_enforcement":"state_capture","request":{"path":"/capture"}},
                    {"name":"enforce","requires_enforcement":"state_enforcement","request":{"path":"/enforce"}}
                ],
                "enforcement":{"request_shape":"enforced","state_capture":"enforced","state_enforcement":"enforced"}
            }
        }}
    })).unwrap();
    let token = token("mixed", "test");
    let mut retained = binding("mixed", "test");
    retained.grantable_operations = [
        "read",
        "path_state",
        "query_state",
        "body_state",
        "capture",
        "enforce",
    ]
    .map(str::to_owned)
    .into();
    for bindings in [&[][..], std::slice::from_ref(&retained)] {
        let routes = compile_routes(&service, &token, bindings);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/read");
        assert_eq!(routes[0].methods, ["GET"]);
    }
}

#[test]
fn path_matching_preserves_source_case_and_wildcard_behavior() {
    assert!(resource_matches(
        "/api/chat.postMessage",
        "/api/chat.postMessage"
    ));
    assert!(!resource_matches(
        "/api/chat.postmessage",
        "/api/chat.postMessage"
    ));
    assert!(resource_matches(
        "slack:/api/chat.postMessage",
        "slack:/api/chat.postMessage"
    ));
    assert!(!resource_matches(
        "SLACK:/api/chat.postmessage",
        "slack:/api/chat.postMessage"
    ));
    assert!(resource_matches(
        "SLACK:/api/chat.postMessage",
        "slack:/api/chat.postMessage"
    ));
    assert!(resource_matches("/a/b/c", "/a/*"));
    assert!(resource_matches("/a", "/a/**"));
    assert!(!resource_matches("/a", "/a/*"));
    assert_eq!(normalize_path("/a/%2E%2E/b/"), "/b");
    assert_eq!(normalize_path("/ａ／ｂ"), "/a/b");
    assert_eq!(normalize_path("/%FF%C3%A9"), "/%FFé");
}
