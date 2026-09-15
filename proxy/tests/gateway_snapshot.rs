use std::sync::Arc;

use safeyolo_proxy::{
    contracts::ContractRequest,
    policy::{Effect, Format, NetworkRequest, Policy},
    services::{
        GatewayCompatibility, GatewayDecision, GatewayRequest, Registry, RouteMode, TrustedIdentity,
    },
};
use serde_json::{Value, json};

fn definition() -> Value {
    json!({"schema_version":1,"name":"demo","auth":{"type":"bearer"},"capabilities":{"reader":{"routes":[{"methods":["GET"],"path":"/read"}]},"writer":{"routes":[{"methods":["POST"],"path":"/write"}]}}})
}
fn registry() -> Arc<Registry> {
    Arc::new(Registry::from_sources(&definitions(), &[]).unwrap())
}
fn definitions() -> Vec<(String, String)> {
    vec![
        ("demo.yaml".into(), definition().to_string()),
        (
            "minifuse.yaml".into(),
            std::fs::read_to_string(format!(
                "{}/../cli/src/safeyolo/services/minifuse.yaml",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        ),
    ]
}
fn document() -> Value {
    json!({"hosts":{"z.invalid":{"service":"demo","egress":"allow"},"a.invalid":{"service":"demo","egress":"allow"}},"agents":{"alice":{"services":{"demo":{"capability":"reader","token":"fixture-ref","account":"operator"}}},"bob":{"services":{"demo":"writer"}}}})
}
fn load(document: &Value, registry: Option<Arc<Registry>>) -> Policy {
    Policy::parse_with_registry_at(&document.to_string(), Format::Json, registry, 0.).unwrap()
}
fn environment(policy: &Policy, agent: &str) -> Value {
    let secret = policy
        .gateway()
        .unwrap()
        .agent_environment_json(agent)
        .unwrap();
    serde_json::from_str(secret.expose_secret()).unwrap()
}
fn token(policy: &Policy, agent: &str) -> String {
    environment(policy, agent)["demo"].as_str().unwrap().into()
}
fn select(
    policy: &Policy,
    agent: TrustedIdentity<'_>,
    token: &str,
    method: &str,
    path: &str,
) -> GatewayDecision {
    select_with_header(policy, agent, token, method, path, "Authorization", true)
}
fn select_with_header(
    policy: &Policy,
    agent: TrustedIdentity<'_>,
    token: &str,
    method: &str,
    path: &str,
    header: &str,
    bearer: bool,
) -> GatewayDecision {
    let headers = vec![(
        header.into(),
        format!("{}{token}", if bearer { "Bearer " } else { "" }),
    )];
    policy.gateway().unwrap().select(GatewayRequest {
        identity: agent,
        host: "z.invalid",
        route_mode: RouteMode::CompiledPolicy(policy),
        request: ContractRequest {
            method,
            target: path,
            headers: &headers,
            body: b"",
        },
    })
}
fn code(result: GatewayDecision) -> String {
    match result {
        GatewayDecision::PassThrough => "pass".into(),
        GatewayDecision::Selected { .. } => "selected".into(),
        GatewayDecision::Deny { code, .. } => code,
        GatewayDecision::Compatibility { field } => format!("compatibility:{field:?}"),
    }
}
fn network(policy: &Policy) -> Effect {
    policy
        .evaluate(
            NetworkRequest {
                agent: Some("alice"),
                host: "z.invalid",
                port: Some(443),
                method: "GET",
                path: "/read",
            },
            0.,
            false,
        )
        .unwrap()
        .effect
}

#[test]
fn accepted_load_owns_tokens_views_routes_and_empty_reload_revokes() {
    let raw = document();
    let first = load(&raw, Some(registry()));
    let alice = token(&first, "alice");
    let bob = token(&first, "bob");
    assert!(alice != bob);
    assert!(
        alice.len() == 68
            && alice.starts_with("sgw_")
            && alice[4..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    for _ in 0..4 {
        assert!(token(&first, "alice") == alice);
        let services = first
            .gateway()
            .unwrap()
            .agent_services_json("alice")
            .unwrap();
        let view: Value = serde_json::from_str(services.expose_secret()).unwrap();
        assert!(view["demo"]["token"] == alice);
        // Last source insertion is a.invalid; a sorted-map last would be wrong.
        assert_eq!(view["demo"]["host"], "a.invalid");
        assert_eq!(view["demo"]["account"], "operator");
        assert_eq!(first.gateway().unwrap().compiled_routes().len(), 2);
    }
    assert_eq!(
        code(select(
            &first,
            TrustedIdentity::Agent("alice"),
            &alice,
            "GET",
            "/read?opaque=%2B"
        )),
        "selected"
    );
    assert_eq!(
        code(select(
            &first,
            TrustedIdentity::Agent("bob"),
            &alice,
            "GET",
            "/read"
        )),
        "AGENT_MISMATCH"
    );
    assert_eq!(
        code(select(
            &first,
            TrustedIdentity::Agent("alice"),
            &alice,
            "POST",
            "/write"
        )),
        "ROUTE_DENIED"
    );
    let second = first
        .reload_from_source_at(&raw.to_string(), Format::Json, 0.)
        .unwrap();
    assert!(token(&second, "alice") != alice);
    assert_eq!(
        code(select(
            &second,
            TrustedIdentity::Agent("alice"),
            &alice,
            "GET",
            "/read"
        )),
        "INVALID_TOKEN"
    );
    assert!(second.gateway().unwrap().registry().is_some());
    let mut removal = raw.clone();
    removal["agents"]["alice"]["services"] = json!({});
    removal["agents"]["bob"]["services"] = json!({});
    // An authored allow cannot rescue a revoked token: source defect D43.
    removal["hosts"]["z.invalid"]["rules"] =
        json!([{"action":"gateway:request","resource":"*","effect":"allow"}]);
    let removed = second
        .reload_from_source_at(&removal.to_string(), Format::Json, 0.)
        .unwrap();
    assert_eq!(environment(&removed, "alice"), json!({}));
    assert_eq!(
        removed
            .gateway()
            .unwrap()
            .agent_services_json("alice")
            .unwrap()
            .expose_secret(),
        "{}"
    );
    assert!(removed.gateway().unwrap().compiled_routes().is_empty());
    assert_eq!(
        code(select(
            &removed,
            TrustedIdentity::Agent("alice"),
            &alice,
            "GET",
            "/read"
        )),
        "INVALID_TOKEN"
    );
    assert!(
        first
            .reload_from_source_at("{\"permissions\":false}", Format::Json, 0.)
            .is_err()
    );
    assert_eq!(
        code(select(
            &first,
            TrustedIdentity::Agent("alice"),
            &alice,
            "GET",
            "/read"
        )),
        "selected"
    );
}

#[test]
fn registry_absence_empty_and_definition_replacement_are_explicit() {
    let raw = document();
    let absent = load(&raw, None);
    let empty = load(&raw, Some(Arc::new(Registry::default())));
    assert!(absent.gateway().unwrap().registry().is_none());
    assert!(empty.gateway().unwrap().registry().is_some());
    for policy in [&absent, &empty] {
        assert!(policy.gateway().unwrap().compiled_routes().is_empty());
        assert_eq!(
            code(select(
                policy,
                TrustedIdentity::Agent("alice"),
                &token(policy, "alice"),
                "GET",
                "/read"
            )),
            "GATEWAY_CONFIGURATION_ERROR"
        );
        assert_eq!(network(policy), Effect::Allow);
    }
    let first = load(&raw, Some(registry()));
    let old = token(&first, "alice");
    let mut changed = definition();
    changed["capabilities"]["reader"]["routes"][0]["path"] = "/changed".into();
    let changed = Arc::new(
        Registry::from_sources(&[("demo.yaml".into(), changed.to_string())], &[]).unwrap(),
    );
    let next = load(&raw, Some(changed));
    let new = token(&next, "alice");
    assert!(new != old);
    assert_eq!(
        code(select(
            &next,
            TrustedIdentity::Agent("alice"),
            &new,
            "GET",
            "/read"
        )),
        "ROUTE_DENIED"
    );
    assert_eq!(
        code(select(
            &next,
            TrustedIdentity::Agent("alice"),
            &new,
            "GET",
            "/changed"
        )),
        "selected"
    );
}

#[test]
fn authored_gateway_policy_is_the_only_compiled_route_decision() {
    let mut raw = document();
    raw["hosts"]["z.invalid"]["rules"] = json!([
        {"action":"gateway:request","resource":"demo:/read","effect":"deny","condition":{"agent":"alice","method":"GET","capability":"reader"}},
        {"action":"gateway:request","resource":"demo:/extra","effect":"allow","condition":{"agent":"alice","method":"GET","capability":"reader"}}
    ]);
    let policy = load(&raw, Some(registry()));
    let token = token(&policy, "alice");
    assert_eq!(
        code(select(
            &policy,
            TrustedIdentity::Agent("alice"),
            &token,
            "GET",
            "/read"
        )),
        "ROUTE_DENIED"
    );
    assert_eq!(
        code(select(
            &policy,
            TrustedIdentity::Agent("alice"),
            &token,
            "GET",
            "/extra"
        )),
        "selected"
    );
    for effect in ["deny", "prompt", "budget"] {
        let raw = json!({"permissions":[{"action":"gateway:request","resource":"*","effect":effect,"budget":1}],"gateway":{"host_map":{"z.invalid":"demo"},"token_map":{"sgw_synthetic":{"agent":"alice","service":"demo","capability":"reader","token":"fixture","account":"agent"}}}});
        let policy = load(&raw, Some(registry()));
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Agent("alice"),
                "sgw_synthetic",
                "GET",
                "/read"
            )),
            "ROUTE_DENIED"
        );
        // Only an explicit absence of PolicyClient selects the historical fallback.
        let headers = vec![("Authorization".into(), "Bearer sgw_synthetic".into())];
        assert_eq!(
            code(policy.gateway().unwrap().select(GatewayRequest {
                identity: TrustedIdentity::Agent("alice"),
                host: "z.invalid",
                route_mode: RouteMode::LocalFallback,
                request: ContractRequest {
                    method: "GET",
                    target: "/read",
                    headers: &headers,
                    body: b""
                }
            })),
            "selected"
        );
    }
}

#[test]
fn accepted_raw_binding_values_reach_only_their_actual_source_gate() {
    let base = json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"},{"action":"gateway:request","resource":"*","effect":"allow"}],"gateway":{"host_map":{"z.invalid":"demo"},"token_map":{"sgw_synthetic":{"agent":"alice","service":"demo","capability":"reader","token":"fixture","account":"agent"}}}});
    for (field, value, expected) in [
        ("agent", json!(3), "AGENT_MISMATCH"),
        ("agent", json!([]), "AGENT_MISMATCH"),
        ("service", json!(3), "SERVICE_NOT_FOUND"),
        ("service", Value::Null, "SERVICE_NOT_FOUND"),
        ("capability", json!(3), "CAPABILITY_NOT_FOUND"),
        ("capability", Value::Null, "CAPABILITY_NOT_FOUND"),
        ("service", json!([]), "compatibility:ServiceLookup"),
        ("capability", json!([]), "compatibility:CapabilityLookup"),
        ("token", json!(3), "compatibility:VaultReference"),
        ("account", json!(3), "compatibility:Account"),
    ] {
        let mut raw = base.clone();
        raw["gateway"]["token_map"]["sgw_synthetic"][field] = value;
        let policy = load(&raw, Some(registry()));
        assert_eq!(network(&policy), Effect::Allow);
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Agent("alice"),
                "sgw_synthetic",
                "GET",
                "/read"
            )),
            expected
        );
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Conflict,
                "sgw_synthetic",
                "GET",
                "/read"
            )),
            "AGENT_IDENTITY_CONFLICT"
        );
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Agent("alice"),
                "sgw_unknown",
                "GET",
                "/read"
            )),
            "INVALID_TOKEN"
        );
    }
    let mut raw = base.clone();
    raw["gateway"]["token_map"]["sgw_synthetic"]["account"] = json!([3]);
    raw["permissions"][1]["effect"] = "deny".into();
    let policy = load(&raw, Some(registry()));
    assert_eq!(
        code(select(
            &policy,
            TrustedIdentity::Agent("alice"),
            "sgw_synthetic",
            "GET",
            "/read"
        )),
        "ROUTE_DENIED"
    );
    for value in [
        json!({"host_map":{"z.invalid":3}}),
        json!({"token_map":[1]}),
        json!({"agent_env":{"alice":3}}),
    ] {
        let mut raw = base.clone();
        raw["gateway"] = value;
        assert_eq!(network(&load(&raw, Some(registry()))), Effect::Allow);
    }
    let mut raw = document();
    raw["agents"]["alice"]["services"]["demo"]["capability"] = json!(3);
    let policy = load(&raw, Some(registry()));
    assert_eq!(
        code(select(
            &policy,
            TrustedIdentity::Agent("alice"),
            &token(&policy, "alice"),
            "GET",
            "/read"
        )),
        "CAPABILITY_NOT_FOUND"
    );
    for value in [json!(false), Value::Null, json!([]), json!({})] {
        raw["agents"]["alice"]["services"]["demo"]["capability"] = value;
        assert_eq!(
            environment(&load(&raw, Some(registry())), "alice"),
            json!({})
        );
    }
    raw["agents"]["alice"]["services"]["demo"]["capability"] = json!(["reader"]);
    assert!(
        Policy::parse_with_registry_at(&raw.to_string(), Format::Json, Some(registry()), 0.)
            .is_err()
    );
    assert!(Policy::parse_with_registry_at(&raw.to_string(), Format::Json, None, 0.).is_ok());
}

#[test]
fn raw_marker_objects_are_preserved_and_never_coerced_to_binding_strings() {
    let raw = r#"{"permissions":[{"action":"gateway:request","resource":"*","effect":"allow"}],"gateway":{"host_map":{"z.invalid":"demo"},"token_map":{"sgw_synthetic":{"agent":"alice","service":"demo","capability":"reader","token":{"$serde_json::private::Number":"3"},"account":"agent"}}}}"#;
    let policy = Policy::parse_with_registry_at(raw, Format::Json, Some(registry()), 0.).unwrap();
    assert!(matches!(
        select(
            &policy,
            TrustedIdentity::Agent("alice"),
            "sgw_synthetic",
            "GET",
            "/read"
        ),
        GatewayDecision::Compatibility {
            field: GatewayCompatibility::VaultReference
        }
    ));
}

#[test]
fn yaml_timestamp_capability_never_matches_a_quoted_capability_name() {
    let mut definition = definition();
    definition["capabilities"] =
        json!({"2024-01-01T00:00:00Z":{"routes":[{"methods":["GET"],"path":"/read"}]}});
    let registry = Arc::new(
        Registry::from_sources(&[("demo.yaml".into(), definition.to_string())], &[]).unwrap(),
    );
    for (value, expected) in [
        ("'2024-01-01T00:00:00Z'", "selected"),
        ("2024-01-01T00:00:00Z", "CAPABILITY_NOT_FOUND"),
    ] {
        let source = format!(
            "hosts:\n  z.invalid: {{service: demo, egress: allow}}\nagents:\n  alice:\n    services:\n      demo:\n        capability: {value}\n        token: fixture\n"
        );
        let policy =
            Policy::parse_with_registry_at(&source, Format::Yaml, Some(registry.clone()), 0.)
                .unwrap();
        let token = token(&policy, "alice");
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Agent("alice"),
                &token,
                "GET",
                "/read"
            )),
            expected
        );
    }
}

#[test]
fn python_control_whitespace_is_contained_in_both_token_extraction_paths() {
    let absent = load(&document(), None);
    let present = load(&document(), Some(registry()));
    for control in '\u{1c}'..='\u{1f}' {
        for bearer in [false, true] {
            for policy in [&absent, &present] {
                let known = token(policy, "alice");
                let value = format!(
                    "{}{control}{known}{control}",
                    if bearer { "Bearer " } else { "" }
                );
                // This is a component contract, not a claim of current HTTP wire
                // acceptance. Hyper's header type rejects these actual controls.
                assert!(hyper::header::HeaderValue::from_str(&value).is_err());
                let headers = vec![("Authorization".into(), value)];
                let result = policy.gateway().unwrap().select(GatewayRequest {
                    identity: TrustedIdentity::Agent("alice"),
                    host: "z.invalid",
                    route_mode: RouteMode::CompiledPolicy(policy),
                    request: ContractRequest {
                        method: "GET",
                        target: "/read",
                        headers: &headers,
                        body: b"",
                    },
                });
                if policy.gateway().unwrap().registry().is_some() {
                    assert_eq!(code(result), "selected");
                } else {
                    assert!(
                        matches!(result,GatewayDecision::Deny {status:503,ref code,ref strip_headers,..} if code=="GATEWAY_CONFIGURATION_ERROR" && strip_headers==&["Authorization"])
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_callback_prefix_is_an_explicit_inactive_compatibility_gap() {
    let binding = json!({"agent":"alice","service":"demo","capability":"reader","token":"fixture","account":"agent"});
    let raw = json!({"permissions":[{"action":"network:request","resource":"*","effect":"allow"},{"action":"gateway:request","resource":"*","effect":"allow"}],"gateway":{"host_map":{"z.invalid":"demo"},"token_map":{"sgw_first":binding,"sgw_malformed":{},"sgw_last":binding}}});
    let policy = load(&raw, Some(registry()));
    assert_eq!(network(&policy), Effect::Allow);
    // The actual Python callback publishes the valid prefix before its error:
    // first reaches missing-vault 503, last/malformed/unknown get INVALID_TOKEN.
    // Native retains canonical source data but cannot activate a partial map.
    for known in ["sgw_first", "sgw_last"] {
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Agent("alice"),
                known,
                "GET",
                "/read"
            )),
            "compatibility:Binding"
        );
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Conflict,
                known,
                "GET",
                "/read"
            )),
            "AGENT_IDENTITY_CONFLICT"
        );
    }
    for unknown in ["sgw_malformed", "sgw_unknown"] {
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Agent("alice"),
                unknown,
                "GET",
                "/read"
            )),
            "INVALID_TOKEN"
        );
    }
}

#[test]
fn bound_routes_and_runtime_contracts_share_the_same_loaded_document() {
    let source = std::fs::read_to_string(format!(
        "{}/../cli/src/safeyolo/services/minifuse.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let registry =
        Arc::new(Registry::from_sources(&[("minifuse.yaml".into(), source)], &[]).unwrap());
    let binding = json!({"binding_id":"fixture","service":"minifuse","capability":"category_manager","template":"minifuse.category_manager.v1","bound_values":{"approved_category_id":137},"grantable_operations":["list_feeds","list_feeds","unknown"]});
    let raw = json!({"hosts":{"z.invalid":{"service":"minifuse","egress":"allow"}},"agents":{"alice":{"services":{"minifuse":"category_manager"},"contract_bindings":[binding]}}});
    let policy = load(&raw, Some(registry.clone()));
    let known = environment(&policy, "alice")["minifuse"]
        .as_str()
        .unwrap()
        .to_owned();
    let routes = policy.gateway().unwrap().compiled_routes();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].path, "/v1/categories/137/feeds");
    assert_eq!(
        code(select_with_header(
            &policy,
            TrustedIdentity::Agent("alice"),
            &known,
            "GET",
            "/v1/categories/137/feeds",
            "X-Auth-Token",
            false
        )),
        "selected"
    );
    assert_eq!(
        code(select_with_header(
            &policy,
            TrustedIdentity::Agent("alice"),
            &known,
            "GET",
            "/v1/categories/138/feeds",
            "X-Auth-Token",
            false
        )),
        "ROUTE_DENIED"
    );
    let mut duplicate = raw.clone();
    let mut second = binding.clone();
    second["bound_values"]["approved_category_id"] = json!(138);
    duplicate["agents"]["alice"]["contract_bindings"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let policy = load(&duplicate, Some(registry.clone()));
    let known = environment(&policy, "alice")["minifuse"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        policy.gateway().unwrap().compiled_routes()[0].path,
        "/v1/categories/137/feeds"
    );
    assert_ne!(
        code(select_with_header(
            &policy,
            TrustedIdentity::Agent("alice"),
            &known,
            "GET",
            "/v1/categories/137/feeds",
            "X-Auth-Token",
            false
        )),
        "selected"
    );
    let mut malformed = raw.clone();
    malformed["agents"]["alice"]["contract_bindings"][0]["bound_values"] = json!(3);
    let policy = load(&malformed, Some(registry.clone()));
    assert!(policy.gateway().unwrap().compiled_routes().is_empty());
    assert_eq!(network(&policy), Effect::Allow);
    malformed["hosts"]["z.invalid"]["rules"] =
        json!([{"action":"gateway:request","resource":"*","effect":"allow"}]);
    let policy = load(&malformed, Some(registry));
    let known = environment(&policy, "alice")["minifuse"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        code(select_with_header(
            &policy,
            TrustedIdentity::Agent("alice"),
            &known,
            "GET",
            "/v1/categories/137/feeds",
            "X-Auth-Token",
            false
        )),
        "compatibility:ContractBinding"
    );
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON to the baseline environment"]
fn differential_gateway_compilation_views_and_scalar_admission() {
    use std::{
        collections::BTreeMap,
        io::Write,
        process::{Command, Stdio},
    };
    fn redact(value: &mut Value, labels: &mut BTreeMap<String, String>) {
        match value {
            Value::String(text) if text.starts_with("sgw_") => {
                let next = format!("opaque-generation-{}", labels.len());
                *text = labels.entry(text.clone()).or_insert(next).clone();
            }
            Value::Array(values) => {
                for value in values {
                    redact(value, labels);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    redact(value, labels);
                }
            }
            _ => {}
        }
    }
    let mut scenarios = Vec::new();
    for registry in ["absent", "empty", "present"] {
        for variant in [
            "normal",
            "empty-agents",
            "no-services",
            "legacy",
            "role",
            "numeric-capability",
            "false-capability",
            "list-capability",
            "numeric-account",
            "unknown-service",
            "unknown-capability",
            "bound-valid",
            "bound-duplicate",
            "bound-malformed",
        ] {
            let mut raw = document();
            match variant {
                "empty-agents" => raw["agents"] = json!({}),
                "no-services" => raw["agents"] = json!({"alice":{}}),
                "legacy" => raw["agents"]["alice"]["services"]["demo"] = "reader".into(),
                "role" => raw["agents"]["alice"]["services"]["demo"] = json!({"role":"reader"}),
                "numeric-capability" => {
                    raw["agents"]["alice"]["services"]["demo"]["capability"] = json!(3)
                }
                "false-capability" => {
                    raw["agents"]["alice"]["services"]["demo"]["capability"] = json!(false)
                }
                "list-capability" => {
                    raw["agents"]["alice"]["services"]["demo"]["capability"] = json!(["reader"])
                }
                "numeric-account" => {
                    raw["agents"]["alice"]["services"]["demo"]["account"] = json!(3)
                }
                "unknown-service" => {
                    raw["agents"]["alice"]["services"] = json!({"unknown":"reader"})
                }
                "unknown-capability" => {
                    raw["agents"]["alice"]["services"]["demo"]["capability"] = "unknown".into()
                }
                variant if variant.starts_with("bound-") => {
                    let binding = json!({"service":"minifuse","capability":"category_manager","template":"minifuse.category_manager.v1","bound_values":{"approved_category_id":137},"grantable_operations":["list_feeds","list_feeds","unknown"]});
                    raw = json!({"hosts":{"z.invalid":{"service":"minifuse","egress":"allow"}},"agents":{"alice":{"services":{"minifuse":"category_manager"},"contract_bindings":[binding]}}});
                    if variant == "bound-duplicate" {
                        let mut second = binding.clone();
                        second["bound_values"]["approved_category_id"] = json!(138);
                        raw["agents"]["alice"]["contract_bindings"]
                            .as_array_mut()
                            .unwrap()
                            .push(second);
                    } else if variant == "bound-malformed" {
                        raw["agents"]["alice"]["contract_bindings"][0]["bound_values"] = json!(3);
                    }
                }
                _ => {}
            }
            scenarios.push(json!({"registry":registry,"variant":variant,"document":raw}));
        }
    }
    let script = r#"
import contextlib,itertools,json,logging,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from safeyolo.policy.compiler import compile_policy
from safeyolo.policy.models import UnifiedPolicy
from safeyolo.core.service_loader import ServiceRegistry
from safeyolo.mitm_addons.service_gateway import ServiceGateway
logging.disable(logging.CRITICAL)
payload=json.load(sys.stdin);rows=[]
def normalize(value,labels):
 if isinstance(value,str) and value.startswith('sgw_'):
  if value not in labels:labels[value]='opaque-generation-'+str(len(labels))
  return labels[value]
 if isinstance(value,list):return [normalize(item,labels) for item in value]
 if isinstance(value,dict):return {key:normalize(item,labels) for key,item in value.items()}
 return value
with tempfile.TemporaryDirectory() as temporary:
 root=Path(temporary);user=root/'user';user.mkdir();builtin=root/'builtin';builtin.mkdir()
 for filename,source in payload['definitions']:(user/filename).write_text(source)
 registry=ServiceRegistry(user,builtin_dir=builtin);registry.load(strict=True)
 empty=ServiceRegistry(builtin,builtin_dir=builtin);empty.load(strict=True)
 for case in payload['cases']:
  selected={'absent':None,'empty':empty,'present':registry}[case['registry']]
  counter=itertools.count()
  with patch('safeyolo.policy.compiler._get_service_registry',return_value=selected),patch('safeyolo.policy.compiler.mint_gateway_token',side_effect=lambda:'sgw_'+format(next(counter),'064x')):
   try: compiled=compile_policy(case['document']);policy=UnifiedPolicy.model_validate(compiled)
   except Exception:rows.append({'loaded':False});continue
  config=policy.gateway
  with patch('pdp.is_policy_client_configured',return_value=True),patch('pdp.get_policy_client',return_value=SimpleNamespace(get_gateway_config=lambda:config)):
   addon=ServiceGateway();addon._mint_tokens_from_policy();services=addon.get_agent_services()
  routes=[]
  for rule in compiled['permissions']:
   if rule['action']=='gateway:request':
    condition=rule['condition'];name,path=rule['resource'].split(':',1)
    routes.append({'agent':condition['agent'],'service':name,'capability':condition['capability'],'methods':condition['method'],'path':path})
  row={'loaded':True,'environment':{name:config.get('agent_env',{}).get(name,{}) for name in ['alice','bob']},'services':{name:services.get(name,{}) for name in ['alice','bob']},'routes':routes}
  rows.append(normalize(row,{}))
json.dump(rows,sys.stdout)
"#;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let python = std::env::var("SAFEYOLO_POLICY_PYTHON").expect("Python oracle interpreter");
    let mut child = Command::new(python)
        .args(["-c", script])
        .current_dir(root)
        .env(
            "PYTHONPATH",
            format!("{}/cli/src:{}", root.display(), root.display()),
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
        .write_all(
            json!({"definitions":definitions(),"cases":scenarios})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "source oracle failed without printing token-bearing state"
    );
    let expected: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(expected.len(), scenarios.len());
    for (case, expected) in scenarios.iter().zip(expected) {
        let selected = match case["registry"].as_str().unwrap() {
            "absent" => None,
            "empty" => Some(Arc::new(Registry::default())),
            _ => Some(registry()),
        };
        let result = Policy::parse_with_registry_at(
            &case["document"].to_string(),
            Format::Json,
            selected,
            0.,
        );
        let mut actual = match result {
            Err(_) => json!({"loaded":false}),
            Ok(policy) => {
                let snapshot = policy.gateway().unwrap();
                let mut services = serde_json::Map::new();
                let mut env = serde_json::Map::new();
                for agent in ["alice", "bob"] {
                    services.insert(
                        agent.into(),
                        serde_json::from_str::<Value>(
                            snapshot.agent_services_json(agent).unwrap().expose_secret(),
                        )
                        .unwrap(),
                    );
                    env.insert(agent.into(), environment(&policy, agent));
                }
                json!({"loaded":true,"environment":env,"services":services,"routes":snapshot.compiled_routes()})
            }
        };
        redact(&mut actual, &mut BTreeMap::new());
        assert_eq!(
            actual, expected,
            "{} / {}",
            case["registry"], case["variant"]
        );
    }
    eprintln!(
        "Compared {} gateway snapshot load/view/route cases with the actual Python compiler and addon",
        scenarios.len()
    );
}

fn temporal_definition() -> Value {
    json!({"schema_version":1,"name":"demo","auth":{"type":"bearer"},"capabilities":{"reader":{"routes":[{"methods":"*","path":"/**"}],"contract":{"template":"temporal.v1","bindings":{"approved":{"type":"string"}},"operations":[{"name":"write","request":{"method":"POST","path":"/items","query":{"allow":{"name":{"equals_var":"approved"}}},"body":{"allow":{"name":{"equals_var":"approved"}}}}},{"name":"path","request":{"method":"GET","path":"/items/{id}","path_params":{"id":{"equals_var":"approved"}}}},{"name":"discover","request":{"method":"GET","path":"/discovery"}}],"enforcement":{"request_shape":"enforced","transport_hygiene":"enforced"}}}}})
}
fn temporal_cases() -> Vec<Value> {
    let make = |name: &str,
                values: &str,
                method: &str,
                target: &str,
                headers: Value,
                body: &str,
                expected: &str,
                field: Option<&str>| {
        json!({"name":name,"values":values,"method":method,"target":target,"headers":headers,"body":body,"expected":{"code":expected,"field":field}})
    };
    let json_headers = json!([["Content-Type", "application/json"]]);
    let mut cases = vec![
        make(
            "quoted body",
            "{approved: '2024-01-01T00:00:00Z'}",
            "POST",
            "/items",
            json_headers.clone(),
            r#"{"name":"2024-01-01T00:00:00Z"}"#,
            "selected",
            None,
        ),
        make(
            "typed body",
            "{approved: 2024-01-01T00:00:00Z}",
            "POST",
            "/items",
            json_headers.clone(),
            r#"{"name":"2024-01-01T00:00:00Z"}"#,
            "CONTRACT_VIOLATION",
            Some("name"),
        ),
        make(
            "typed query",
            "{approved: 2024-01-01T00:00:00Z}",
            "POST",
            "/items?name=2024-01-01T00%3A00%3A00Z",
            json!([]),
            "",
            "CONTRACT_VIOLATION",
            Some("name"),
        ),
        make(
            "quoted query",
            "{approved: '2024-01-01T00:00:00Z'}",
            "POST",
            "/items?name=2024-01-01T00%3A00%3A00Z",
            json!([]),
            "",
            "selected",
            None,
        ),
        make(
            "nested body",
            "{approved: {nested: 2024-01-01T00:00:00Z}}",
            "POST",
            "/items",
            json_headers.clone(),
            r#"{"name":{"nested":"2024-01-01T00:00:00Z"}}"#,
            "CONTRACT_VIOLATION",
            Some("name"),
        ),
        make(
            "body unknown first",
            "{approved: 2024-01-01T00:00:00Z}",
            "POST",
            "/items",
            json_headers.clone(),
            r#"{"unknown":1,"name":"2024-01-01T00:00:00Z"}"#,
            "CONTRACT_VIOLATION",
            Some("unknown"),
        ),
        make(
            "query unknown first",
            "{approved: 2024-01-01T00:00:00Z}",
            "POST",
            "/items?unknown=x&name=2024-01-01T00%3A00%3A00Z",
            json!([]),
            "",
            "CONTRACT_VIOLATION",
            Some("unknown"),
        ),
        make(
            "content type first",
            "{approved: 2024-01-01T00:00:00Z}",
            "POST",
            "/items",
            json!([["Content-Type", "text/plain"]]),
            r#"{"name":"2024-01-01T00:00:00Z"}"#,
            "TRANSPORT_CONTENT_TYPE",
            None,
        ),
        make(
            "header first",
            "{approved: 2024-01-01T00:00:00Z}",
            "POST",
            "/items?name=x",
            json!([["X-Unknown", "x"]]),
            "",
            "TRANSPORT_HEADER_DENIED",
            None,
        ),
        make(
            "unused timestamp",
            "{approved: chosen, unused: 2024-01-01T00:00:00Z}",
            "POST",
            "/items?name=chosen",
            json!([]),
            "",
            "selected",
            None,
        ),
        make(
            "date path display",
            "{approved: 2024-01-01}",
            "GET",
            "/items/2024-01-01",
            json!([]),
            "",
            "selected",
            None,
        ),
        make(
            "date path mismatch",
            "{approved: 2024-01-01}",
            "GET",
            "/items/2024-01-02",
            json!([]),
            "",
            "CONTRACT_VIOLATION",
            Some("id"),
        ),
        make(
            "typed structured path gap",
            "{approved: [2024-01-01]}",
            "GET",
            "/items/[datetime.date(2024, 1, 1)]",
            json!([]),
            "",
            "compatibility:ContractBinding",
            None,
        ),
        make(
            "malformed mapping unused",
            "3",
            "GET",
            "/discovery",
            json!([]),
            "",
            "selected",
            None,
        ),
        make(
            "malformed mapping lookup",
            "3",
            "POST",
            "/items?name=x",
            json!([]),
            "",
            "compatibility:ContractBinding",
            None,
        ),
        make(
            "malformed mapping header first",
            "3",
            "POST",
            "/items?name=x",
            json!([["X-Unknown", "x"]]),
            "",
            "TRANSPORT_HEADER_DENIED",
            None,
        ),
        make(
            "malformed mapping unknown first",
            "3",
            "POST",
            "/items?unknown=x&name=x",
            json!([]),
            "",
            "CONTRACT_VIOLATION",
            Some("unknown"),
        ),
        make(
            "malformed mapping content type first",
            "3",
            "POST",
            "/items",
            json!([["Content-Type", "text/plain"]]),
            "{}",
            "TRANSPORT_CONTENT_TYPE",
            None,
        ),
    ];
    for field in ["template", "grantable_operations"] {
        let mut case = make(
            "compiler-only malformed field",
            "{approved: chosen}",
            "POST",
            "/items?name=chosen",
            json!([]),
            "",
            "selected",
            None,
        );
        case["compiler_field"] = json!(field);
        cases.push(case);
    }
    for malformed in [
        json!({"service":[],"capability":"reader"}),
        json!({}),
        json!(3),
    ] {
        let mut case = make(
            "callback failure skips later binding",
            "{approved: chosen}",
            "POST",
            "/items?name=chosen",
            json!([]),
            "",
            "CONTRACT_NOT_BOUND",
            None,
        );
        case["malformed_record"] = malformed;
        cases.push(case);
    }
    let mut case = make(
        "callback keeps valid prefix",
        "{approved: earlier}",
        "POST",
        "/items?name=chosen",
        json!([]),
        "",
        "CONTRACT_VIOLATION",
        Some("name"),
    );
    case["keep_prefix"] = json!(true);
    cases.push(case);
    cases
}
fn temporal_source(case: &Value) -> String {
    let template = if case["compiler_field"] == "template" {
        "2024-01-01"
    } else {
        "temporal.v1"
    };
    let operations = if case["compiler_field"] == "grantable_operations" {
        "3"
    } else {
        "[write, path, discover]"
    };
    let mut source = format!(
        "hosts:\n  z.invalid:\n    service: demo\n    egress: allow\n    rules: [{{action: 'gateway:request', resource: '*', effect: allow}}]\nagents:\n  alice:\n    services: {{demo: reader}}\n    contract_bindings:\n      - service: demo\n        capability: reader\n        template: {template}\n        bound_values: {}\n        grantable_operations: {operations}\n",
        case["values"].as_str().unwrap()
    );
    if let Some(malformed) = case.get("malformed_record") {
        source = source.replace(
            "    contract_bindings:\n",
            &format!("    contract_bindings:\n      - {}\n", malformed),
        );
    }
    if case["keep_prefix"] == true {
        source.push_str("      - {}\n      - service: demo\n        capability: reader\n        template: temporal.v1\n        bound_values: {approved: chosen}\n        grantable_operations: [write, path, discover]\n");
    }
    source
}
fn temporal_result(case: &Value) -> Value {
    let registry = Arc::new(
        Registry::from_sources(
            &[("demo.yaml".into(), temporal_definition().to_string())],
            &[],
        )
        .unwrap(),
    );
    let policy =
        Policy::parse_with_registry_at(&temporal_source(case), Format::Yaml, Some(registry), 0.)
            .unwrap();
    let known = token(&policy, "alice");
    let mut headers: Vec<(String, String)> =
        serde_json::from_value(case["headers"].clone()).unwrap();
    headers.push(("Authorization".into(), format!("Bearer {known}")));
    let result = policy.gateway().unwrap().select(GatewayRequest {
        identity: TrustedIdentity::Agent("alice"),
        host: "z.invalid",
        route_mode: RouteMode::CompiledPolicy(&policy),
        request: ContractRequest {
            method: case["method"].as_str().unwrap(),
            target: case["target"].as_str().unwrap(),
            headers: &headers,
            body: case["body"].as_str().unwrap().as_bytes(),
        },
    });
    let result = match result {
        GatewayDecision::Deny { code, field, .. } => json!({"code":code,"field":field}),
        other => json!({"code":code(other),"field":null}),
    };
    json!({"result":result,"routes":policy.gateway().unwrap().compiled_routes()})
}
#[test]
fn typed_bound_values_preserve_constraint_order_and_compiler_scope() {
    for case in temporal_cases() {
        let actual = temporal_result(&case);
        assert_eq!(actual["result"], case["expected"], "{}", case["name"]);
        // Python rejects temporal path components at compile time, while an
        // authored permission can still reach scalar display equality at runtime.
        if case["name"].as_str().unwrap().starts_with("date path") {
            assert!(
                !actual["routes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|route| route["path"].as_str().unwrap().starts_with("/items/"))
            );
        }
    }
}

#[test]
#[ignore = "historical Python oracle; set SAFEYOLO_POLICY_PYTHON to the baseline environment"]
fn differential_typed_bound_values_and_failure_order() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let cases = temporal_cases();
    let input: Vec<Value> = cases
        .iter()
        .map(|case| json!({"request":case,"source":temporal_source(case)}))
        .collect();
    let script = r#"
import json,sys,tempfile,logging
from pathlib import Path
from unittest.mock import patch
import yaml,tomlkit
from mitmproxy.http import Headers
from mitmproxy.test import tflow
from safeyolo.core.service_loader import ServiceRegistry
from safeyolo.mitm_addons.service_gateway import ServiceGateway
from safeyolo.policy.compiler import compile_policy
logging.disable(logging.CRITICAL)
x=json.load(sys.stdin); results=[]
with tempfile.TemporaryDirectory() as temporary:
 p=Path(temporary); (p/'user').mkdir(); (p/'builtin').mkdir(); (p/'user'/'demo.yaml').write_text(json.dumps(x['definition']))
 registry=ServiceRegistry(p/'user',builtin_dir=p/'builtin');registry.load(strict=True)
 service=registry.get_service('demo');cap=service.capabilities['reader']
 for case in x['cases']:
  raw=yaml.safe_load(case['source']);request=case['request']
  policy_path=p/'policy.toml';policy_path.write_text(tomlkit.dumps(raw))
  gateway=ServiceGateway();gateway._get_policy_path=lambda:policy_path
  gateway._load_contract_bindings_from_policy()
  state=gateway.get_contract_binding('alice','demo','reader')
  with patch('safeyolo.policy.compiler._get_service_registry',return_value=registry),patch('safeyolo.policy.compiler.mint_gateway_token',return_value='sgw_synthetic'):
   compiled=compile_policy(raw)
  routes=[]
  for rule in compiled['permissions']:
   if rule['action']=='gateway:request' and rule['resource']!='*':
    condition=rule['condition'];name,path=rule['resource'].split(':',1)
    routes.append(dict(agent=condition['agent'],service=name,capability=condition['capability'],methods=condition['method'],path=path))
  flow=tflow.tflow();flow.request.method=request['method'];flow.request.path=request['target'];flow.request.host='z.invalid';flow.request.scheme='https';flow.request.headers=Headers([(k.encode(),v.encode()) for k,v in request['headers']]+[(b'Authorization',b'Bearer sgw_synthetic')]);flow.request.content=request['body'].encode();flow.response=None
  outcome={}
  def deny(flow,status,reason,code,**kw):outcome.update(code=code,field=kw.get('field'))
  gateway._deny=deny
  try:
   if gateway._enforce_contract(flow,state,service,cap,request['method'],request['target'].split('?',1)[0]):outcome=dict(code='selected',field=None)
  except AttributeError:outcome=dict(code='source:AttributeError',field=None)
  results.append(dict(result=outcome,routes=routes))
json.dump(results,sys.stdout)
"#;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let mut child =
        Command::new(std::env::var("SAFEYOLO_POLICY_PYTHON").expect("Python source environment"))
            .args(["-c", script])
            .current_dir(root)
            .env(
                "PYTHONPATH",
                format!("{}/cli/src:{}", root.display(), root.display()),
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
        .write_all(
            json!({"definition":temporal_definition(),"cases":input})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "source temporal oracle failed without printing state"
    );
    let source: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(source.len(), cases.len());
    for (case, mut source) in cases.iter().zip(source) {
        // These remain explicit inactive gaps at the actually reached source
        // lookup, never ordinary denials or fallback to another route matcher.
        if case["name"] == "typed structured path gap" {
            assert_eq!(source["result"]["code"], "selected");
            source["result"]["code"] = json!("compatibility:ContractBinding");
        } else if case["name"] == "malformed mapping lookup" {
            assert_eq!(source["result"]["code"], "source:AttributeError");
            source["result"]["code"] = json!("compatibility:ContractBinding");
        }
        assert_eq!(temporal_result(case), source, "{}", case["name"]);
    }
    eprintln!(
        "Compared {} actual Python temporal contract/compiler cases (two explicitly asserted compatibility gaps)",
        cases.len()
    );
}

#[test]
fn temporal_agent_keys_never_become_string_contract_scopes() {
    let definition = temporal_definition();
    let registry = Arc::new(
        Registry::from_sources(&[("demo.yaml".into(), definition.to_string())], &[]).unwrap(),
    );
    // This intentionally tries the parser's current private spelling as an
    // ordinary caller string. It must not inherit the temporal agent's binding.
    for (scope, expected) in [
        ("2024-01-01", "AGENT_MISMATCH"),
        ("\0temporal-key-0", "CONTRACT_NOT_BOUND"),
    ] {
        let source = r#"
permissions: [{action: 'gateway:request', resource: '*', effect: allow}]
gateway:
  host_map: {z.invalid: demo}
  token_map:
    sgw_synthetic: {agent: "\0temporal-key-0", service: demo, capability: reader, token: fixture, account: agent}
agents:
  2024-01-01:
    contract_bindings:
      - {service: demo, capability: reader, template: temporal.v1, bound_values: {approved: chosen}, grantable_operations: [write]}
"#;
        let policy =
            Policy::parse_with_registry_at(source, Format::Yaml, Some(registry.clone()), 0.)
                .unwrap();
        assert_eq!(
            code(select(
                &policy,
                TrustedIdentity::Agent(scope),
                "sgw_synthetic",
                "POST",
                "/items?name=chosen"
            )),
            expected
        );
    }
    // A malformed record under a temporal agent still stops the source callback
    // before it can publish a later ordinary agent's contract binding.
    let source = r#"
hosts: {z.invalid: {service: demo, egress: allow, rules: [{action: 'gateway:request', resource: '*', effect: allow}]}}
agents:
  2024-01-01:
    contract_bindings: [{}]
  alice:
    services: {demo: reader}
    contract_bindings:
      - {service: demo, capability: reader, template: temporal.v1, bound_values: {approved: chosen}, grantable_operations: [write]}
"#;
    let policy = Policy::parse_with_registry_at(source, Format::Yaml, Some(registry), 0.).unwrap();
    assert_eq!(
        code(select(
            &policy,
            TrustedIdentity::Agent("alice"),
            &token(&policy, "alice"),
            "POST",
            "/items?name=chosen"
        )),
        "CONTRACT_NOT_BOUND"
    );
}
